package jwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/secscan/backend/internal/models"
)

// Scanner audits JWT tokens and cookie security attributes.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }
func (s *Scanner) Name() string { return "JWT_Cookie" }

func (s *Scanner) Run(targetURL string) models.ModuleResult {
	result := models.ModuleResult{
		Module:   s.Name(),
		Findings: []models.Finding{},
		Score:    100,
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		result.Status = "failed"
		result.Score = 0
		result.Findings = append(result.Findings, models.Finding{
			Module:      s.Name(),
			Title:       "Connection Failed",
			Severity:    models.SeverityInfo,
			Description: fmt.Sprintf("Could not connect to target: %v", err),
		})
		return result
	}
	defer resp.Body.Close()

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		result.Status = "passed"
		result.Findings = append(result.Findings, models.Finding{
			Module:      s.Name(),
			Title:       "No Cookies Set",
			Severity:    models.SeverityInfo,
			Description: "No cookies were set by the server on the initial response.",
		})
		return result
	}

	for _, cookie := range cookies {
		// Check Secure flag
		if !cookie.Secure {
			result.Score -= 10
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       fmt.Sprintf("Cookie '%s' Missing Secure Flag", cookie.Name),
				Severity:    models.SeverityMedium,
				Description: "Cookie can be transmitted over unencrypted HTTP connections.",
				Remediation: "Set the Secure flag on all cookies to ensure they are only sent over HTTPS.",
			})
		}

		// Check HttpOnly flag
		if !cookie.HttpOnly {
			result.Score -= 10
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       fmt.Sprintf("Cookie '%s' Missing HttpOnly Flag", cookie.Name),
				Severity:    models.SeverityMedium,
				Description: "Cookie is accessible via JavaScript, making it vulnerable to XSS-based theft.",
				Remediation: "Set the HttpOnly flag to prevent client-side script access to cookies.",
			})
		}

		// Check SameSite attribute
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == http.SameSiteNoneMode {
			result.Score -= 10
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       fmt.Sprintf("Cookie '%s' Weak SameSite Policy", cookie.Name),
				Severity:    models.SeverityMedium,
				Description: "Cookie SameSite attribute is not set to Strict or Lax, which may allow CSRF attacks.",
				Remediation: "Set SameSite=Strict or SameSite=Lax on all cookies.",
			})
		}

		// Check if cookie value looks like a JWT (starts with eyJ)
		if strings.HasPrefix(cookie.Value, "eyJ") {
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       fmt.Sprintf("JWT Token Detected in Cookie '%s'", cookie.Name),
				Severity:    models.SeverityInfo,
				Description: "A JWT token was found stored in a cookie. Ensure the token uses a strong signing algorithm (e.g., RS256) and is not using 'none' algorithm.",
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
