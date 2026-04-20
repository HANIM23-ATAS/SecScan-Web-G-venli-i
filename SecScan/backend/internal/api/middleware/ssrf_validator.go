package middleware

import (
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

type ScanRequest struct {
	TargetURL string `json:"url" binding:"required,url"`
}

// SSRFValidator acts as the first line of defense blocking obvious bad inputs.
// The safehttp client (DialContext) handles DNS rebinding and internal IP resolutions.
func SSRFValidator() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req ScanRequest
		// Use ShouldBindBodyWith or extract properly, but here we can just bind to struct
		// Alternatively, read raw JSON
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON or URL format. Provide a valid 'url'."})
			c.Abort()
			return
		}

		parsed, err := url.Parse(req.TargetURL)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse URL"})
			c.Abort()
			return
		}

		// Enforce HTTP/HTTPS schemes
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Only HTTP and HTTPS schemes are allowed"})
			c.Abort()
			return
		}

		hostname := strings.ToLower(parsed.Hostname())
		
		// Basic static checks
		if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
			log.Printf("Security Alert: Blocked basic SSRF attempt targeting %s\n", hostname)
			c.JSON(http.StatusForbidden, gin.H{"error": "Targeting local or private network is forbidden"})
			c.Abort()
			return
		}

		// Save the validated URL in the context so the handler doesn't have to re-bind
		c.Set("validated_url", req.TargetURL)

		c.Next()
	}
}
