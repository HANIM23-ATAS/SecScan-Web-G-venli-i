package serverinfo

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/secscan/backend/internal/models"
)

// Scanner checks if the server discloses version information.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }
func (s *Scanner) Name() string { return "ServerDisclosure" }

// Headers that commonly leak server/version info
var disclosureHeaders = []string{
	"Server",
	"X-Powered-By",
	"X-AspNet-Version",
	"X-AspNetMvc-Version",
	"X-Generator",
	"X-Drupal-Cache",
	"X-Varnish",
}

func (s *Scanner) Run(targetURL string) models.ModuleResult {
	result := models.ModuleResult{
		Module:   s.Name(),
		Findings: []models.Finding{},
		Score:    100,
	}

	client := &http.Client{Timeout: 10 * time.Second}
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

	for _, header := range disclosureHeaders {
		val := resp.Header.Get(header)
		if val != "" {
			severity := models.SeverityLow
			// If the value contains a version number, raise severity
			if containsVersion(val) {
				severity = models.SeverityMedium
			}

			result.Score -= 15
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       fmt.Sprintf("Information Disclosure: %s", header),
				Severity:    severity,
				Description: fmt.Sprintf("Header '%s: %s' reveals server technology information.", header, val),
				Remediation: fmt.Sprintf("Remove or obfuscate the '%s' header to prevent information disclosure.", header),
			})
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	if len(result.Findings) == 0 {
		result.Status = "passed"
	} else if result.Score >= 60 {
		result.Status = "warning"
	} else {
		result.Status = "failed"
	}

	return result
}

func containsVersion(val string) bool {
	// Check for common version patterns like "1.2", "/2.4.6", etc.
	for i, c := range val {
		if c >= '0' && c <= '9' {
			// Look for digit followed by dot followed by digit
			rest := val[i:]
			if len(rest) >= 3 && strings.Contains(rest[:3], ".") {
				return true
			}
		}
	}
	return false
}
