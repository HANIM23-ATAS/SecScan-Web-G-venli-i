package headers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/secscan/backend/internal/models"
)

// Scanner checks security headers against best-practice recommendations.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }
func (s *Scanner) Name() string { return "SecurityHeaders" }

// requiredHeaders maps header name -> description of what it protects
var requiredHeaders = map[string]string{
	"Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
	"Content-Security-Policy":   "Prevents XSS and data injection attacks",
	"X-Content-Type-Options":    "Prevents MIME-type sniffing",
	"X-Frame-Options":           "Prevents clickjacking attacks",
	"Referrer-Policy":           "Controls referrer information leakage",
	"Permissions-Policy":        "Controls browser feature permissions",
	"X-XSS-Protection":         "Legacy XSS filter (deprecated but still checked)",
}

func (s *Scanner) Run(targetURL string) models.ModuleResult {
	result := models.ModuleResult{
		Module:   s.Name(),
		Findings: []models.Finding{},
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

	score := 100
	perHeader := 100 / len(requiredHeaders)

	for header, description := range requiredHeaders {
		val := resp.Header.Get(header)
		if val == "" {
			score -= perHeader
			severity := models.SeverityMedium
			if header == "Strict-Transport-Security" || header == "Content-Security-Policy" {
				severity = models.SeverityHigh
			}
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       fmt.Sprintf("Missing Header: %s", header),
				Severity:    severity,
				Description: fmt.Sprintf("%s header is missing. %s.", header, description),
				Remediation: fmt.Sprintf("Add the '%s' header to your server responses.", header),
			})
		} else {
			// Check for weak values
			if header == "X-Frame-Options" && strings.ToUpper(val) == "ALLOWALL" {
				score -= perHeader / 2
				result.Findings = append(result.Findings, models.Finding{
					Module:      s.Name(),
					Title:       "Weak X-Frame-Options",
					Severity:    models.SeverityMedium,
					Description: "X-Frame-Options is set to ALLOWALL which provides no protection.",
					Remediation: "Set X-Frame-Options to DENY or SAMEORIGIN.",
				})
			}
		}
	}

	if score < 0 {
		score = 0
	}

	if score >= 85 {
		result.Status = "passed"
	} else if score >= 50 {
		result.Status = "warning"
	} else {
		result.Status = "failed"
	}
	result.Score = score

	return result
}
