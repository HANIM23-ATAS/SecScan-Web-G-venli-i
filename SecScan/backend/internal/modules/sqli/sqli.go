package sqli

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/secscan/backend/internal/models"
)

// Scanner tests for basic SQL injection vulnerabilities using pattern matching.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }
func (s *Scanner) Name() string { return "SQLi" }

// Common SQLi test payloads
var payloads = []string{
	"' OR '1'='1",
	"\" OR \"1\"=\"1",
	"'; DROP TABLE users;--",
	"1' AND '1'='1",
	"1 UNION SELECT NULL--",
	"' OR 1=1--",
}

// Error signatures that indicate SQL injection vulnerability
var errorSignatures = []string{
	"you have an error in your sql syntax",
	"warning: mysql",
	"unclosed quotation mark",
	"quoted string not properly terminated",
	"sql syntax",
	"microsoft ole db provider",
	"odbc microsoft access driver",
	"oracle error",
	"pg_query",
	"sqlite3.operationalerror",
	"psycopg2.errors",
	"sqlstate",
}

func (s *Scanner) Run(targetURL string) models.ModuleResult {
	result := models.ModuleResult{
		Module:   s.Name(),
		Findings: []models.Finding{},
		Score:    100,
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, payload := range payloads {
		testURL := appendPayload(targetURL, payload)
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100)) // Read max 100KB
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(string(body))
		for _, sig := range errorSignatures {
			if strings.Contains(bodyLower, sig) {
				result.Score -= 25
				result.Findings = append(result.Findings, models.Finding{
					Module:      s.Name(),
					Title:       "Potential SQL Injection Detected",
					Severity:    models.SeverityCritical,
					Description: fmt.Sprintf("SQL error signature '%s' found in response when testing payload: %s", sig, payload),
					Remediation: "Use parameterized queries (prepared statements) instead of string concatenation. Implement input validation and use an ORM.",
				})
				break // One finding per payload is enough
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	if len(result.Findings) == 0 {
		result.Status = "passed"
	} else {
		result.Status = "failed"
	}

	return result
}

func appendPayload(targetURL, payload string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	q := u.Query()
	q.Set("id", payload)
	q.Set("q", payload)
	u.RawQuery = q.Encode()
	return u.String()
}
