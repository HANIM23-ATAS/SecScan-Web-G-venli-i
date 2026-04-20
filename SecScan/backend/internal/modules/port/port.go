package port

import (
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/secscan/backend/internal/models"
)

// Scanner performs lightweight TCP port scanning (similar to nmap -sT).
type Scanner struct{}

func New() *Scanner { return &Scanner{} }
func (s *Scanner) Name() string { return "PortDiscovery" }

// Common ports to scan with their typical services
var commonPorts = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
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

	var wg sync.WaitGroup
	var mu sync.Mutex
	openPorts := []int{}

	for portNum := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", host, p)
			conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(portNum)
	}

	wg.Wait()

	// Analyze open ports
	dangerousPorts := map[int]bool{
		21: true, 23: true, 445: true, 3389: true, 5900: true,
		6379: true, 27017: true, 3306: true, 5432: true, 1433: true,
	}

	for _, p := range openPorts {
		serviceName := commonPorts[p]
		severity := models.SeverityInfo

		if dangerousPorts[p] {
			severity = models.SeverityHigh
			result.Score -= 15
		} else {
			severity = models.SeverityLow
		}

		result.Findings = append(result.Findings, models.Finding{
			Module:      s.Name(),
			Title:       fmt.Sprintf("Open Port: %d (%s)", p, serviceName),
			Severity:    severity,
			Description: fmt.Sprintf("Port %d (%s) is open and accepting connections.", p, serviceName),
			Remediation: func() string {
				if dangerousPorts[p] {
					return fmt.Sprintf("Port %d (%s) should not be publicly accessible. Restrict access using firewall rules.", p, serviceName)
				}
				return "Ensure this service is intentionally exposed and properly secured."
			}(),
		})
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
