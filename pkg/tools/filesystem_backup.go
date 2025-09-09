package tools

import (
	"context"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
)

// BackupManager handles file backups before destructive operations
type BackupManager struct {
	containerFS runtime.ContainerFS
	backups     map[string]*BackupEntry
	mu          sync.RWMutex
	maxBackups  int
}

// BackupEntry represents a file backup
type BackupEntry struct {
	ID           string                 `json:"id"`
	OriginalPath string                 `json:"original_path"`
	BackupPath   string                 `json:"backup_path"`
	ContainerID  string                 `json:"container_id"`
	Size         int64                  `json:"size"`
	Checksum     string                 `json:"checksum"`
	Timestamp    time.Time              `json:"timestamp"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// BackupPolicy defines backup behavior
type BackupPolicy struct {
	EnableBackup     bool          `json:"enable_backup"`
	MaxBackupAge     time.Duration `json:"max_backup_age"`
	MaxBackupSize    int64         `json:"max_backup_size"`
	BackupDirectory  string        `json:"backup_directory"`
	CompressionLevel int           `json:"compression_level"`
}

// NewBackupManager creates a new backup manager
func NewBackupManager(containerFS runtime.ContainerFS) *BackupManager {
	return &BackupManager{
		containerFS: containerFS,
		backups:     make(map[string]*BackupEntry),
		maxBackups:  1000, // Keep last 1000 backups per container
	}
}

// CreateBackup creates a backup of a file before modification
func (bm *BackupManager) CreateBackup(ctx context.Context, containerID, filePath string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	// Check if file exists
	fileInfo, err := bm.containerFS.StatFile(ctx, containerID, filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file for backup: %w", err)
	}

	if fileInfo.IsDir {
		return fmt.Errorf("cannot backup directory: %s", filePath)
	}

	// Generate backup path
	timestamp := time.Now().Format("20060102-150405")
	backupPath := path.Join("/.backups", containerID, fmt.Sprintf("%s.%s.bak",
		path.Base(filePath), timestamp))

	// Ensure backup directory exists
	backupDir := path.Dir(backupPath)
	if err := bm.containerFS.MakeDir(ctx, containerID, backupDir, 0755); err != nil {
		log.Debug().Err(err).Str("backup_dir", backupDir).Msg("Failed to create backup directory, continuing anyway")
	}

	// Copy file to backup location
	if err := bm.containerFS.CopyFile(ctx, containerID, filePath, backupPath); err != nil {
		return fmt.Errorf("failed to copy file to backup location: %w", err)
	}

	// Calculate checksum of original file
	originalData, err := bm.containerFS.ReadFile(ctx, containerID, filePath)
	if err != nil {
		log.Warn().Err(err).Str("file_path", filePath).Msg("Failed to read file for checksum calculation")
	}

	// Create backup entry
	backupID := fmt.Sprintf("backup-%d-%s", time.Now().UnixNano(), containerID[:8])
	entry := &BackupEntry{
		ID:           backupID,
		OriginalPath: filePath,
		BackupPath:   backupPath,
		ContainerID:  containerID,
		Size:         fileInfo.Size,
		Checksum:     calculateChecksum(originalData),
		Timestamp:    time.Now(),
		Metadata: map[string]interface{}{
			"original_mode":     fileInfo.Mode.String(),
			"original_mod_time": fileInfo.ModTime,
			"original_owner":    fileInfo.Owner,
			"original_group":    fileInfo.Group,
		},
	}

	bm.backups[backupID] = entry

	// Clean up old backups
	bm.cleanupOldBackups(containerID)

	log.Info().
		Str("container_id", containerID).
		Str("original_path", filePath).
		Str("backup_path", backupPath).
		Str("backup_id", backupID).
		Msg("File backup created successfully")

	return nil
}

// RestoreBackup restores a file from backup
func (bm *BackupManager) RestoreBackup(ctx context.Context, backupID string) error {
	bm.mu.RLock()
	backup, exists := bm.backups[backupID]
	bm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("backup not found: %s", backupID)
	}

	// Check if backup file exists
	if _, err := bm.containerFS.StatFile(ctx, backup.ContainerID, backup.BackupPath); err != nil {
		return fmt.Errorf("backup file no longer exists: %w", err)
	}

	// Copy backup file back to original location
	if err := bm.containerFS.CopyFile(ctx, backup.ContainerID, backup.BackupPath, backup.OriginalPath); err != nil {
		return fmt.Errorf("failed to restore from backup: %w", err)
	}

	// Restore original metadata if possible
	if mode, ok := backup.Metadata["original_mode"].(string); ok {
		// Note: In a real implementation, you'd parse the mode string
		log.Debug().Str("mode", mode).Msg("Would restore file mode")
	}

	log.Info().
		Str("backup_id", backupID).
		Str("container_id", backup.ContainerID).
		Str("original_path", backup.OriginalPath).
		Str("backup_path", backup.BackupPath).
		Msg("File restored from backup successfully")

	return nil
}

// ListBackups lists all backups for a container
func (bm *BackupManager) ListBackups(containerID string) []*BackupEntry {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	var backups []*BackupEntry
	for _, backup := range bm.backups {
		if containerID == "" || backup.ContainerID == containerID {
			// Return a copy to avoid race conditions
			backupCopy := *backup
			backups = append(backups, &backupCopy)
		}
	}

	return backups
}

// DeleteBackup removes a backup entry and file
func (bm *BackupManager) DeleteBackup(ctx context.Context, backupID string) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	backup, exists := bm.backups[backupID]
	if !exists {
		return fmt.Errorf("backup not found: %s", backupID)
	}

	// Delete backup file
	if err := bm.containerFS.DeleteFile(ctx, backup.ContainerID, backup.BackupPath); err != nil {
		log.Warn().Err(err).Str("backup_path", backup.BackupPath).Msg("Failed to delete backup file")
	}

	// Remove from tracking
	delete(bm.backups, backupID)

	log.Info().
		Str("backup_id", backupID).
		Str("container_id", backup.ContainerID).
		Str("backup_path", backup.BackupPath).
		Msg("Backup deleted successfully")

	return nil
}

// CleanupBackups removes old backups based on policy
func (bm *BackupManager) CleanupBackups(ctx context.Context, containerID string, maxAge time.Duration) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	cutoffTime := time.Now().Add(-maxAge)
	var toDelete []string

	for id, backup := range bm.backups {
		if (containerID == "" || backup.ContainerID == containerID) && backup.Timestamp.Before(cutoffTime) {
			toDelete = append(toDelete, id)
		}
	}

	// Delete old backups
	for _, id := range toDelete {
		backup := bm.backups[id]
		if err := bm.containerFS.DeleteFile(ctx, backup.ContainerID, backup.BackupPath); err != nil {
			log.Warn().Err(err).Str("backup_path", backup.BackupPath).Msg("Failed to delete old backup file")
		}
		delete(bm.backups, id)
	}

	log.Info().
		Str("container_id", containerID).
		Int("deleted_count", len(toDelete)).
		Dur("max_age", maxAge).
		Msg("Backup cleanup completed")

	return nil
}

// GetBackupStats returns statistics about backups
func (bm *BackupManager) GetBackupStats(containerID string) *BackupStats {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	stats := &BackupStats{
		ContainerID:  containerID,
		TotalBackups: 0,
		TotalSize:    0,
		OldestBackup: time.Time{},
		NewestBackup: time.Time{},
	}

	for _, backup := range bm.backups {
		if containerID != "" && backup.ContainerID != containerID {
			continue
		}

		stats.TotalBackups++
		stats.TotalSize += backup.Size

		if stats.OldestBackup.IsZero() || backup.Timestamp.Before(stats.OldestBackup) {
			stats.OldestBackup = backup.Timestamp
		}
		if backup.Timestamp.After(stats.NewestBackup) {
			stats.NewestBackup = backup.Timestamp
		}
	}

	return stats
}

// cleanupOldBackups removes old backups to maintain size limits
func (bm *BackupManager) cleanupOldBackups(containerID string) {
	var backupsForContainer []*BackupEntry
	for _, backup := range bm.backups {
		if backup.ContainerID == containerID {
			backupsForContainer = append(backupsForContainer, backup)
		}
	}

	if len(backupsForContainer) <= bm.maxBackups {
		return
	}

	// Sort by timestamp (oldest first) and remove excess
	// For simplicity, just remove oldest entries beyond limit
	excess := len(backupsForContainer) - bm.maxBackups
	for i := 0; i < excess; i++ {
		oldest := backupsForContainer[0]
		for _, backup := range backupsForContainer {
			if backup.Timestamp.Before(oldest.Timestamp) {
				oldest = backup
			}
		}

		delete(bm.backups, oldest.ID)
		log.Debug().
			Str("backup_id", oldest.ID).
			Str("container_id", containerID).
			Msg("Removed old backup due to limit")
	}
}

// BackupStats provides statistics about backups
type BackupStats struct {
	ContainerID  string    `json:"container_id"`
	TotalBackups int       `json:"total_backups"`
	TotalSize    int64     `json:"total_size_bytes"`
	OldestBackup time.Time `json:"oldest_backup"`
	NewestBackup time.Time `json:"newest_backup"`
}

// calculateChecksum calculates a simple checksum for backup verification
func calculateChecksum(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// Simple checksum - in production you might want something more robust
	var checksum uint32
	for _, b := range data {
		checksum = checksum*31 + uint32(b)
	}
	return fmt.Sprintf("%08x", checksum)
}
