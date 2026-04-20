package tls

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/secscan/backend/internal/models"
)

// Scanner checks TLS/SSL configuration quality.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }
func (s *Scanner) Name() string { return "TLS_SSL" }

// Deprecated or weak TLS versions
var weakVersions = map[uint16]string{
	tls.VersionSSL30: "SSL 3.0",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
}

func (s *Scanner) Run(targetURL string) models.ModuleResult {
	result := models.ModuleResult{
		Module:   s.Name(),
		Findings: []models.Finding{},
		Score:    100,
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		result.Status = "failed"
		result.Score = 0
		return result
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			// If not HTTPS, flag it and try 443 anyway
			result.Score -= 20
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       "Target Not Using HTTPS",
				Severity:    models.SeverityHigh,
				Description: "The target URL uses HTTP instead of HTTPS. All communication is unencrypted.",
				Remediation: "Enable HTTPS with a valid TLS certificate. Use services like Let's Encrypt for free certificates.",
			})
			port = "443"
		}
	}

	addr := net.JoinHostPort(host, port)

	// Try connecting with modern TLS
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: false,
		},
	)
	if err != nil {
		// Try with InsecureSkipVerify to check if cert is self-signed
		conn2, err2 := tls.DialWithDialer(
			&net.Dialer{Timeout: 10 * time.Second},
			"tcp",
			addr,
			&tls.Config{
				InsecureSkipVerify: true,
			},
		)
		if err2 != nil {
			result.Status = "failed"
			result.Score -= 30
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       "TLS Connection Failed",
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Could not establish TLS connection: %v", err),
			})
			return result
		}
		defer conn2.Close()

		result.Score -= 30
		result.Findings = append(result.Findings, models.Finding{
			Module:      s.Name(),
			Title:       "Invalid or Self-Signed Certificate",
			Severity:    models.SeverityHigh,
			Description: fmt.Sprintf("TLS certificate validation failed: %v", err),
			Remediation: "Use a certificate signed by a trusted Certificate Authority.",
		})

		checkConnectionState(conn2, &result)
	} else {
		defer conn.Close()
		checkConnectionState(conn, &result)
	}

	// Check for deprecated TLS versions
	for ver, name := range weakVersions {
		weakConn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 5 * time.Second},
			"tcp",
			addr,
			&tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         ver,
				MaxVersion:         ver,
			},
		)
		if err == nil {
			weakConn.Close()
			result.Score -= 15
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       fmt.Sprintf("Deprecated Protocol Supported: %s", name),
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Server accepts connections using %s, which is deprecated and insecure.", name),
				Remediation: fmt.Sprintf("Disable %s on the server. Only TLS 1.2+ should be enabled.", name),
			})
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	if result.Score >= 80 {
		result.Status = "passed"
	} else if result.Score >= 50 {
		result.Status = "warning"
	} else {
		result.Status = "failed"
	}

	return result
}

func checkConnectionState(conn *tls.Conn, result *models.ModuleResult) {
	state := conn.ConnectionState()

	// Check negotiated TLS version
	switch state.Version {
	case tls.VersionTLS13:
		result.Findings = append(result.Findings, models.Finding{
			Module:      result.Module,
			Title:       "TLS 1.3 Negotiated",
			Severity:    models.SeverityInfo,
			Description: "Server negotiated TLS 1.3, which is the latest and most secure version.",
		})
	case tls.VersionTLS12:
		result.Findings = append(result.Findings, models.Finding{
			Module:      result.Module,
			Title:       "TLS 1.2 Negotiated",
			Severity:    models.SeverityInfo,
			Description: "Server negotiated TLS 1.2, which is acceptable but TLS 1.3 is preferred.",
		})
	}

	// Check certificate expiry
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		daysUntilExpiry := time.Until(cert.NotAfter).Hours() / 24

		if daysUntilExpiry < 0 {
			result.Score -= 30
			result.Findings = append(result.Findings, models.Finding{
				Module:      result.Module,
				Title:       "Certificate Expired",
				Severity:    models.SeverityCritical,
				Description: fmt.Sprintf("Certificate expired on %s.", cert.NotAfter.Format("2006-01-02")),
				Remediation: "Renew the TLS certificate immediately.",
			})
		} else if daysUntilExpiry < 30 {
			result.Score -= 10
			result.Findings = append(result.Findings, models.Finding{
				Module:      result.Module,
				Title:       "Certificate Expiring Soon",
				Severity:    models.SeverityMedium,
				Description: fmt.Sprintf("Certificate expires in %.0f days (%s).", daysUntilExpiry, cert.NotAfter.Format("2006-01-02")),
				Remediation: "Renew the certificate before it expires. Consider using auto-renewal.",
			})
		}
	}
}
