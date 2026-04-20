package router

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/secscan/backend/internal/api/handlers"
	"github.com/secscan/backend/internal/api/middleware"
	"github.com/secscan/backend/internal/engine"
)

// Setup creates and configures the Gin router with all endpoints.
func Setup(eng *engine.ScannerEngine) *gin.Engine {
	r := gin.Default()

	// CORS for Next.js frontend
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept"},
		AllowCredentials: true,
	}))

	scanHandler := handlers.NewScanHandler(eng)

	// API v1 routes
	v1 := r.Group("/api/v1")
	{
		v1.POST("/scan", middleware.SSRFValidator(), scanHandler.StartScan)
		v1.GET("/report/:scan_id", scanHandler.GetReport)
	}

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok", "service": "SecScan API"})
	})

	return r
}
