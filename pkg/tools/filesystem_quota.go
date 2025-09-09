package tools

import (
	"fmt"
	"sync"
)

// QuotaManager manages filesystem quotas for sandboxes
type QuotaManager struct {
	quotas map[string]*SandboxQuota
	mu     sync.RWMutex
}

// SandboxQuota represents quota information for a sandbox
type SandboxQuota struct {
	SandboxID     string `json:"sandbox_id"`
	MaxSize       int64  `json:"max_size"`        // Maximum total size in bytes
	CurrentSize   int64  `json:"current_size"`    // Current usage in bytes
	MaxFiles      int64  `json:"max_files"`       // Maximum number of files
	CurrentFiles  int64  `json:"current_files"`   // Current number of files
	MaxInodeUsage int64  `json:"max_inode_usage"` // Maximum inode usage
	CurrentInodes int64  `json:"current_inodes"`  // Current inode usage
}

// NewQuotaManager creates a new quota manager
func NewQuotaManager() *QuotaManager {
	return &QuotaManager{
		quotas: make(map[string]*SandboxQuota),
	}
}

// SetQuota sets quota limits for a sandbox
func (qm *QuotaManager) SetQuota(sandboxID string, maxSize, maxFiles, maxInodes int64) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	qm.quotas[sandboxID] = &SandboxQuota{
		SandboxID:     sandboxID,
		MaxSize:       maxSize,
		CurrentSize:   0,
		MaxFiles:      maxFiles,
		CurrentFiles:  0,
		MaxInodeUsage: maxInodes,
		CurrentInodes: 0,
	}
}

// CheckQuota checks if an operation would exceed quota limits
func (qm *QuotaManager) CheckQuota(sandboxID string, additionalSize int64) error {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	quota, exists := qm.quotas[sandboxID]
	if !exists {
		// If no quota set, allow the operation (unlimited)
		return nil
	}

	// Check size quota
	if quota.MaxSize > 0 && (quota.CurrentSize+additionalSize) > quota.MaxSize {
		return fmt.Errorf("size quota exceeded: current=%d, additional=%d, max=%d",
			quota.CurrentSize, additionalSize, quota.MaxSize)
	}

	// Check file count quota
	if quota.MaxFiles > 0 && (quota.CurrentFiles+1) > quota.MaxFiles {
		return fmt.Errorf("file count quota exceeded: current=%d, max=%d",
			quota.CurrentFiles, quota.MaxFiles)
	}

	return nil
}

// UpdateUsage updates quota usage after an operation
func (qm *QuotaManager) UpdateUsage(sandboxID string, sizeChange int64) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	quota, exists := qm.quotas[sandboxID]
	if !exists {
		return
	}

	quota.CurrentSize += sizeChange
	if sizeChange > 0 {
		quota.CurrentFiles++
	}
}

// GetUsage returns current quota usage for a sandbox
func (qm *QuotaManager) GetUsage(sandboxID string) *SandboxQuota {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	quota, exists := qm.quotas[sandboxID]
	if !exists {
		return nil
	}

	// Return a copy to avoid race conditions
	return &SandboxQuota{
		SandboxID:     quota.SandboxID,
		MaxSize:       quota.MaxSize,
		CurrentSize:   quota.CurrentSize,
		MaxFiles:      quota.MaxFiles,
		CurrentFiles:  quota.CurrentFiles,
		MaxInodeUsage: quota.MaxInodeUsage,
		CurrentInodes: quota.CurrentInodes,
	}
}

// RemoveQuota removes quota tracking for a sandbox
func (qm *QuotaManager) RemoveQuota(sandboxID string) {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	delete(qm.quotas, sandboxID)
}

// GetQuotaStatus returns quota status for all sandboxes
func (qm *QuotaManager) GetQuotaStatus() map[string]*SandboxQuota {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	result := make(map[string]*SandboxQuota)
	for id, quota := range qm.quotas {
		result[id] = &SandboxQuota{
			SandboxID:     quota.SandboxID,
			MaxSize:       quota.MaxSize,
			CurrentSize:   quota.CurrentSize,
			MaxFiles:      quota.MaxFiles,
			CurrentFiles:  quota.CurrentFiles,
			MaxInodeUsage: quota.MaxInodeUsage,
			CurrentInodes: quota.CurrentInodes,
		}
	}

	return result
}
