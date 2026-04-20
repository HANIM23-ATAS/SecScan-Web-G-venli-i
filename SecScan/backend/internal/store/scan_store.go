package store

import (
	"sync"

	"github.com/secscan/backend/internal/models"
)

// ScanStore is a thread-safe in-memory store for scan reports.
// Can be replaced with Redis/PostgreSQL later without changing the interface.
type ScanStore struct {
	mu    sync.RWMutex
	scans map[string]*models.ScanReport
}

var instance *ScanStore
var once sync.Once

// GetStore returns the singleton ScanStore instance
func GetStore() *ScanStore {
	once.Do(func() {
		instance = &ScanStore{
			scans: make(map[string]*models.ScanReport),
		}
	})
	return instance
}

func (s *ScanStore) Save(report *models.ScanReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans[report.ScanID] = report
}

func (s *ScanStore) Get(scanID string) (*models.ScanReport, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	report, ok := s.scans[scanID]
	return report, ok
}

func (s *ScanStore) UpdateResult(scanID string, result models.ModuleResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if report, ok := s.scans[scanID]; ok {
		report.Results = append(report.Results, result)
	}
}
