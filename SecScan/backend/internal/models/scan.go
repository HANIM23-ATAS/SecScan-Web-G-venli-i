package models

import "time"

// Severity levels for findings
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// ScanStatus represents the current state of a scan
type ScanStatus string

const (
	StatusProcessing ScanStatus = "processing"
	StatusCompleted  ScanStatus = "completed"
	StatusFailed     ScanStatus = "failed"
)

// Finding represents a single security issue discovered by a module
type Finding struct {
	Module      string   `json:"module"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
}

// ModuleResult holds the output of a single security module
type ModuleResult struct {
	Module   string    `json:"module"`
	Status   string    `json:"status"` // "passed", "warning", "failed"
	Score    int       `json:"score"`  // 0-100
	Findings []Finding `json:"findings"`
}

// ScanReport is the full report returned for a scan_id
type ScanReport struct {
	ScanID     string         `json:"scan_id"`
	TargetURL  string         `json:"target_url"`
	Status     ScanStatus     `json:"status"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	Results    []ModuleResult `json:"results,omitempty"`
	OverallScore int          `json:"overall_score"`
}
