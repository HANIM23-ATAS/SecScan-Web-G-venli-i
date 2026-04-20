package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/secscan/backend/internal/engine"
)

// ScanHandler manages scan-related API endpoints.
type ScanHandler struct {
	Engine *engine.ScannerEngine
}

func NewScanHandler(eng *engine.ScannerEngine) *ScanHandler {
	return &ScanHandler{Engine: eng}
}

// StartScan triggers all 7 security modules concurrently and returns a scan ID.
func (h *ScanHandler) StartScan(c *gin.Context) {
	validatedURL, exists := c.Get("validated_url")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal context error"})
		return
	}

	targetURL := validatedURL.(string)
	scanID := uuid.New().String()

	// Launch the scan asynchronously
	go h.Engine.Run(scanID, targetURL)

	c.JSON(http.StatusAccepted, gin.H{
		"scan_id": scanID,
		"status":  "processing",
		"target":  targetURL,
		"message": "Security scan has been queued. Use GET /api/v1/report/" + scanID + " to retrieve results.",
	})
}

// GetReport returns the results for a given scan ID.
func (h *ScanHandler) GetReport(c *gin.Context) {
	scanID := c.Param("scan_id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan_id is required"})
		return
	}

	report, found := h.Engine.GetStore().Get(scanID)
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found. Invalid scan_id or scan expired."})
		return
	}

	c.JSON(http.StatusOK, report)
}
