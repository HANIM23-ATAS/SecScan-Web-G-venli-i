package xss

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/secscan/backend/internal/models"
)

// Scanner tests for reflected XSS vulnerabilities using pattern matching.
type Scanner struct{}

func New() *Scanner { return &Scanner{} }
func (s *Scanner) Name() string { return "XSS" }

// Payloads that, if reflected unescaped, indicate XSS
var payloads = []struct {
	Input    string
	Reflect  string // what to look for in the response
}{
	{`<script>alert('xss')</script>`, `<script>alert('xss')</script>`},
	{`"><img src=x onerror=alert(1)>`, `onerror=alert(1)`},
	{`javascript:alert(1)`, `javascript:alert(1)`},
	{`<svg onload=alert(1)>`, `<svg onload=alert(1)>`},
	{`'-alert(1)-'`, `'-alert(1)-'`},
}

func (s *Scanner) Run(targetURL string) models.ModuleResult {
	result := models.ModuleResult{
		Module:   s.Name(),
		Findings: []models.Finding{},
		Score:    100,
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for _, p := range payloads {
		testURL := appendPayload(targetURL, p.Input)
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*100))
		resp.Body.Close()
		if err != nil {
			continue
		}

		bodyStr := string(body)
		if strings.Contains(bodyStr, p.Reflect) {
			result.Score -= 25
			result.Findings = append(result.Findings, models.Finding{
				Module:      s.Name(),
				Title:       "Reflected XSS Detected",
				Severity:    models.SeverityHigh,
				Description: fmt.Sprintf("Payload '%s' was reflected unescaped in the response body.", p.Input),
				Remediation: "Sanitize and HTML-encode all user input before rendering. Implement a Content-Security-Policy header.",
			})
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
	q.Set("q", payload)
	u.RawQuery = q.Encode()
	return u.String()
}
