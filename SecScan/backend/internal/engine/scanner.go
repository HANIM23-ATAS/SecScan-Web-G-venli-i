package engine

import (
	"log"
	"sync"
	"time"

	"github.com/secscan/backend/internal/models"
	"github.com/secscan/backend/internal/modules"
	"github.com/secscan/backend/internal/modules/headers"
	"github.com/secscan/backend/internal/modules/jwt"
	"github.com/secscan/backend/internal/modules/port"
	"github.com/secscan/backend/internal/modules/serverinfo"
	"github.com/secscan/backend/internal/modules/sqli"
	tlsmod "github.com/secscan/backend/internal/modules/tls"
	"github.com/secscan/backend/internal/modules/xss"
	"github.com/secscan/backend/internal/store"
)

// ScannerEngine orchestrates 7 security modules concurrently.
type ScannerEngine struct {
	modules []modules.Scanner
	store   *store.ScanStore
}

// NewScannerEngine wires up all security modules.
func NewScannerEngine() *ScannerEngine {
	return &ScannerEngine{
		modules: []modules.Scanner{
			sqli.New(),
			xss.New(),
			headers.New(),
			jwt.New(),
			tlsmod.New(),
			serverinfo.New(),
			port.New(),
		},
		store: store.GetStore(),
	}
}

// Run starts scans for all modules concurrently using goroutines.
func (e *ScannerEngine) Run(scanID string, targetURL string) {
	log.Printf("[Scan %s] Started scanning target: %s\n", scanID, targetURL)

	// Create initial report and persist it
	now := time.Now()
	report := &models.ScanReport{
		ScanID:    scanID,
		TargetURL: targetURL,
		Status:    models.StatusProcessing,
		StartedAt: now,
		Results:   []models.ModuleResult{},
	}
	e.store.Save(report)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, mod := range e.modules {
		wg.Add(1)
		go func(scanner modules.Scanner) {
			defer wg.Done()

			log.Printf("[Scan %s] Module '%s' starting...\n", scanID, scanner.Name())
			result := scanner.Run(targetURL)
			log.Printf("[Scan %s] Module '%s' completed. Score: %d\n", scanID, scanner.Name(), result.Score)

			mu.Lock()
			report.Results = append(report.Results, result)
			mu.Unlock()
		}(mod)
	}

	// Wait for completion in a separate goroutine
	go func() {
		wg.Wait()
		finishedAt := time.Now()

		mu.Lock()
		report.Status = models.StatusCompleted
		report.FinishedAt = &finishedAt

		// Calculate overall score
		totalScore := 0
		for _, r := range report.Results {
			totalScore += r.Score
		}
		if len(report.Results) > 0 {
			report.OverallScore = totalScore / len(report.Results)
		}
		mu.Unlock()

		log.Printf("[Scan %s] All 7 modules completed. Overall Score: %d/100. Duration: %v\n",
			scanID, report.OverallScore, finishedAt.Sub(report.StartedAt))
	}()
}

// GetStore exposes the store for the handler layer
func (e *ScannerEngine) GetStore() *store.ScanStore {
	return e.store
}
