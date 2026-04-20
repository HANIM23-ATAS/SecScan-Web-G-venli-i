package modules

import "github.com/secscan/backend/internal/models"

// Scanner is the interface every security module must implement.
type Scanner interface {
	Name() string
	Run(targetURL string) models.ModuleResult
}
