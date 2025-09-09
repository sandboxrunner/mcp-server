package tools

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// FileOperationAuditor tracks and logs file operations for security and compliance
type FileOperationAuditor struct {
	entries    []FileOperationAudit
	mu         sync.RWMutex
	maxEntries int
}

// FileOperationAudit represents a single file operation audit entry
type FileOperationAudit struct {
	ID          string                 `json:"id"`
	Operation   string                 `json:"operation"`
	SandboxID   string                 `json:"sandbox_id"`
	ContainerID string                 `json:"container_id,omitempty"`
	Path        string                 `json:"path"`
	Size        int64                  `json:"size"`
	Encoding    string                 `json:"encoding,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Checksum    string                 `json:"checksum,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	SourceIP    string                 `json:"source_ip,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Duration    time.Duration          `json:"duration"`
}

// NewFileOperationAuditor creates a new file operation auditor
func NewFileOperationAuditor() *FileOperationAuditor {
	return &FileOperationAuditor{
		entries:    make([]FileOperationAudit, 0),
		maxEntries: 10000, // Keep last 10k operations
	}
}

// LogOperation logs a file operation with audit details
func (foa *FileOperationAuditor) LogOperation(entry *FileOperationAudit) {
	foa.mu.Lock()
	defer foa.mu.Unlock()

	// Generate unique ID if not provided
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("audit-%d-%s", time.Now().UnixNano(), entry.SandboxID[:8])
	}

	// Add to in-memory storage
	foa.entries = append(foa.entries, *entry)

	// Maintain size limit
	if len(foa.entries) > foa.maxEntries {
		// Remove oldest entries
		foa.entries = foa.entries[len(foa.entries)-foa.maxEntries:]
	}

	// Log to structured logger
	logger := log.With().
		Str("audit_id", entry.ID).
		Str("operation", entry.Operation).
		Str("sandbox_id", entry.SandboxID).
		Str("path", entry.Path).
		Bool("success", entry.Success).
		Logger()

	if entry.Success {
		logger.Info().
			Int64("size", entry.Size).
			Str("checksum", entry.Checksum).
			Dur("duration", entry.Duration).
			Msg("File operation completed")
	} else {
		logger.Error().
			Str("error", entry.Error).
			Dur("duration", entry.Duration).
			Msg("File operation failed")
	}
}

// GetAuditEntries returns audit entries with optional filtering
func (foa *FileOperationAuditor) GetAuditEntries(sandboxID string, operation string, limit int) []FileOperationAudit {
	foa.mu.RLock()
	defer foa.mu.RUnlock()

	var filtered []FileOperationAudit
	count := 0

	// Iterate in reverse order to get most recent entries first
	for i := len(foa.entries) - 1; i >= 0 && (limit == 0 || count < limit); i-- {
		entry := foa.entries[i]

		// Apply filters
		if sandboxID != "" && entry.SandboxID != sandboxID {
			continue
		}
		if operation != "" && entry.Operation != operation {
			continue
		}

		filtered = append(filtered, entry)
		count++
	}

	return filtered
}

// GetAuditSummary returns summary statistics for audit entries
func (foa *FileOperationAuditor) GetAuditSummary(sandboxID string) *AuditSummary {
	foa.mu.RLock()
	defer foa.mu.RUnlock()

	summary := &AuditSummary{
		SandboxID:   sandboxID,
		TotalOps:    0,
		SuccessOps:  0,
		FailedOps:   0,
		Operations:  make(map[string]int),
		TotalSize:   0,
		AvgDuration: 0,
		FirstOp:     time.Time{},
		LastOp:      time.Time{},
	}

	var totalDuration time.Duration
	for _, entry := range foa.entries {
		if sandboxID != "" && entry.SandboxID != sandboxID {
			continue
		}

		summary.TotalOps++
		if entry.Success {
			summary.SuccessOps++
		} else {
			summary.FailedOps++
		}

		summary.Operations[entry.Operation]++
		summary.TotalSize += entry.Size
		totalDuration += entry.Duration

		if summary.FirstOp.IsZero() || entry.Timestamp.Before(summary.FirstOp) {
			summary.FirstOp = entry.Timestamp
		}
		if entry.Timestamp.After(summary.LastOp) {
			summary.LastOp = entry.Timestamp
		}
	}

	if summary.TotalOps > 0 {
		summary.AvgDuration = totalDuration / time.Duration(summary.TotalOps)
	}

	return summary
}

// ExportAuditLog exports audit entries as JSON
func (foa *FileOperationAuditor) ExportAuditLog(sandboxID string) ([]byte, error) {
	entries := foa.GetAuditEntries(sandboxID, "", 0)
	return json.MarshalIndent(entries, "", "  ")
}

// ClearAuditLog clears audit entries for a specific sandbox or all
func (foa *FileOperationAuditor) ClearAuditLog(sandboxID string) {
	foa.mu.Lock()
	defer foa.mu.Unlock()

	if sandboxID == "" {
		// Clear all entries
		foa.entries = make([]FileOperationAudit, 0)
		return
	}

	// Filter out entries for specific sandbox
	filtered := make([]FileOperationAudit, 0)
	for _, entry := range foa.entries {
		if entry.SandboxID != sandboxID {
			filtered = append(filtered, entry)
		}
	}
	foa.entries = filtered
}

// AuditSummary provides summary statistics for audit operations
type AuditSummary struct {
	SandboxID   string         `json:"sandbox_id"`
	TotalOps    int            `json:"total_operations"`
	SuccessOps  int            `json:"successful_operations"`
	FailedOps   int            `json:"failed_operations"`
	Operations  map[string]int `json:"operations_by_type"`
	TotalSize   int64          `json:"total_size_bytes"`
	AvgDuration time.Duration  `json:"average_duration"`
	FirstOp     time.Time      `json:"first_operation"`
	LastOp      time.Time      `json:"last_operation"`
}

// GetSecurityAlerts analyzes audit log for potential security issues
func (foa *FileOperationAuditor) GetSecurityAlerts(sandboxID string, timeWindow time.Duration) []SecurityAlert {
	foa.mu.RLock()
	defer foa.mu.RUnlock()

	var alerts []SecurityAlert
	since := time.Now().Add(-timeWindow)

	// Track suspicious patterns
	pathAccess := make(map[string]int)
	failedOps := 0
	largeFiles := 0

	for _, entry := range foa.entries {
		if sandboxID != "" && entry.SandboxID != sandboxID {
			continue
		}
		if entry.Timestamp.Before(since) {
			continue
		}

		pathAccess[entry.Path]++

		if !entry.Success {
			failedOps++
		}

		if entry.Size > 50*1024*1024 { // 50MB+
			largeFiles++
		}
	}

	// Generate alerts based on patterns
	if failedOps > 10 {
		alerts = append(alerts, SecurityAlert{
			Type:      "HIGH_FAILURE_RATE",
			Severity:  "MEDIUM",
			Message:   fmt.Sprintf("High number of failed operations: %d", failedOps),
			SandboxID: sandboxID,
			Timestamp: time.Now(),
		})
	}

	if largeFiles > 5 {
		alerts = append(alerts, SecurityAlert{
			Type:      "LARGE_FILE_UPLOADS",
			Severity:  "LOW",
			Message:   fmt.Sprintf("Multiple large file uploads: %d", largeFiles),
			SandboxID: sandboxID,
			Timestamp: time.Now(),
		})
	}

	for path, count := range pathAccess {
		if count > 20 {
			alerts = append(alerts, SecurityAlert{
				Type:      "FREQUENT_PATH_ACCESS",
				Severity:  "LOW",
				Message:   fmt.Sprintf("Frequent access to path %s: %d times", path, count),
				SandboxID: sandboxID,
				Timestamp: time.Now(),
			})
		}
	}

	return alerts
}

// SecurityAlert represents a security alert from audit analysis
type SecurityAlert struct {
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"` // LOW, MEDIUM, HIGH, CRITICAL
	Message   string                 `json:"message"`
	SandboxID string                 `json:"sandbox_id"`
	Timestamp time.Time              `json:"timestamp"`
	Path      string                 `json:"path,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}
