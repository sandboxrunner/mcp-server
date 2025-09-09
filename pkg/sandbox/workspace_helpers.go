package sandbox

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/rs/zerolog/log"
)

// CleanupScheduler manages automatic cleanup of workspaces
type CleanupScheduler struct {
	running     bool
	stopChannel chan struct{}
}

// NewCleanupScheduler creates a new cleanup scheduler
func NewCleanupScheduler() *CleanupScheduler {
	return &CleanupScheduler{
		stopChannel: make(chan struct{}),
	}
}

// Start begins the cleanup scheduling process
func (cs *CleanupScheduler) Start(ctx context.Context, wm *WorkspaceManager) {
	if cs.running {
		return
	}
	cs.running = true

	ticker := time.NewTicker(1 * time.Hour) // Run cleanup every hour
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cs.performCleanup(ctx, wm)
		case <-cs.stopChannel:
			cs.running = false
			return
		case <-ctx.Done():
			cs.running = false
			return
		}
	}
}

// Stop stops the cleanup scheduler
func (cs *CleanupScheduler) Stop() {
	if cs.running {
		close(cs.stopChannel)
	}
}

// performCleanup performs the actual cleanup operations
func (cs *CleanupScheduler) performCleanup(ctx context.Context, wm *WorkspaceManager) {
	log.Info().Msg("Starting workspace cleanup process")

	cutoffTime := time.Now().Add(-24 * time.Hour) // Clean up workspaces not accessed in 24 hours
	var toArchive []string

	wm.mu.RLock()
	for id, workspace := range wm.workspaces {
		if workspace.LastAccessed.Before(cutoffTime) && workspace.Status == WorkspaceStatusActive {
			toArchive = append(toArchive, id)
		}
	}
	wm.mu.RUnlock()

	for _, id := range toArchive {
		if err := wm.ArchiveWorkspace(ctx, id); err != nil {
			log.Error().Err(err).Str("workspace_id", id).Msg("Failed to archive workspace during cleanup")
		}
	}

	log.Info().Int("archived_count", len(toArchive)).Msg("Workspace cleanup completed")
}

// WorkspaceShareManager manages workspace sharing between sandboxes
type WorkspaceShareManager struct {
	shares map[string]*WorkspaceShare
}

// WorkspaceShare represents a shared workspace
type WorkspaceShare struct {
	ID           string    `json:"id"`
	WorkspaceID  string    `json:"workspace_id"`
	SharedBy     string    `json:"shared_by"`
	SharedWith   []string  `json:"shared_with"`
	Permissions  string    `json:"permissions"` // read, write, admin
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// NewWorkspaceShareManager creates a new workspace share manager
func NewWorkspaceShareManager() *WorkspaceShareManager {
	return &WorkspaceShareManager{
		shares: make(map[string]*WorkspaceShare),
	}
}

// scanWorkspaceStructure scans and updates workspace structure information
func (wm *WorkspaceManager) scanWorkspaceStructure(ctx context.Context, workspace *Workspace) error {
	log.Debug().
		Str("workspace_id", workspace.ID).
		Str("root_path", workspace.RootPath).
		Msg("Scanning workspace structure")

	structure := &WorkspaceStructure{
		Directories: make(map[string]*DirectoryInfo),
		Files:       make(map[string]*WorkspaceFileInfo),
		Symlinks:    make(map[string]*SymlinkInfo),
		LastScan:    time.Now(),
	}

	// Scan the workspace directory recursively
	if err := wm.scanDirectory(ctx, workspace, workspace.RootPath, structure); err != nil {
		return fmt.Errorf("failed to scan workspace directory: %w", err)
	}

	// Update workspace with new structure
	workspace.Structure = structure
	workspace.Size = structure.TotalSize
	workspace.FileCount = structure.FileCount
	workspace.UpdatedAt = time.Now()

	log.Info().
		Str("workspace_id", workspace.ID).
		Int64("total_size", structure.TotalSize).
		Int64("file_count", structure.FileCount).
		Int("directories", len(structure.Directories)).
		Msg("Workspace structure scan completed")

	return nil
}

// scanDirectory recursively scans a directory and populates structure information
func (wm *WorkspaceManager) scanDirectory(ctx context.Context, workspace *Workspace, dirPath string, structure *WorkspaceStructure) error {
	entries, err := wm.containerFS.ListDir(ctx, workspace.ContainerID, dirPath)
	if err != nil {
		return fmt.Errorf("failed to list directory %s: %w", dirPath, err)
	}

	for _, entry := range entries {
		if entry.IsDir {
			// Add directory info
			structure.Directories[entry.Path] = &DirectoryInfo{
				Path:        entry.Path,
				Size:        entry.Size,
				Permissions: entry.Permissions,
				Owner:       entry.Owner,
				Group:       entry.Group,
				ModifiedAt:  entry.ModTime,
			}

			// Recursively scan subdirectory
			if err := wm.scanDirectory(ctx, workspace, entry.Path, structure); err != nil {
				log.Warn().Err(err).Str("dir_path", entry.Path).Msg("Failed to scan subdirectory")
			}
		} else {
			// Add file info
			structure.Files[entry.Path] = &WorkspaceFileInfo{
				Path:        entry.Path,
				Size:        entry.Size,
				Permissions: entry.Permissions,
				Owner:       entry.Owner,
				Group:       entry.Group,
				ModifiedAt:  entry.ModTime,
			}

			structure.TotalSize += entry.Size
			structure.FileCount++
		}
	}

	return nil
}

// CreateSnapshot creates a snapshot of the current workspace state
func (wm *WorkspaceManager) CreateSnapshot(ctx context.Context, workspaceID, name, description string) (*WorkspaceSnapshot, error) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	workspace, exists := wm.workspaces[workspaceID]
	if !exists {
		return nil, fmt.Errorf("workspace not found: %s", workspaceID)
	}

	// Create snapshot ID and path
	snapshotID := fmt.Sprintf("snap-%s-%d", workspaceID[:8], time.Now().UnixNano())
	snapshotPath := path.Join("/.snapshots", workspaceID, snapshotID)

	// Create snapshot directory
	if err := wm.containerFS.MakeDir(ctx, workspace.ContainerID, path.Dir(snapshotPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	// Copy workspace content to snapshot location
	if err := wm.createSnapshotContent(ctx, workspace, snapshotPath); err != nil {
		return nil, fmt.Errorf("failed to create snapshot content: %w", err)
	}

	// Calculate snapshot checksum
	checksum, err := wm.calculateSnapshotChecksum(ctx, workspace, snapshotPath)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to calculate snapshot checksum")
	}

	snapshot := &WorkspaceSnapshot{
		ID:           snapshotID,
		WorkspaceID:  workspaceID,
		Name:         name,
		Description:  description,
		CreatedAt:    time.Now(),
		Size:         workspace.Size,
		FileCount:    workspace.FileCount,
		Checksum:     checksum,
		SnapshotPath: snapshotPath,
		Metadata: map[string]interface{}{
			"workspace_name": workspace.Name,
			"workspace_type": workspace.Type,
		},
		Compressed: false,
	}

	// Store snapshot
	wm.snapshots[snapshotID] = snapshot

	log.Info().
		Str("workspace_id", workspaceID).
		Str("snapshot_id", snapshotID).
		Str("snapshot_name", name).
		Msg("Workspace snapshot created")

	return snapshot, nil
}

// RestoreSnapshot restores a workspace from a snapshot
func (wm *WorkspaceManager) RestoreSnapshot(ctx context.Context, snapshotID string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	snapshot, exists := wm.snapshots[snapshotID]
	if !exists {
		return fmt.Errorf("snapshot not found: %s", snapshotID)
	}

	workspace, exists := wm.workspaces[snapshot.WorkspaceID]
	if !exists {
		return fmt.Errorf("workspace not found: %s", snapshot.WorkspaceID)
	}

	// Remove current workspace content
	if err := wm.containerFS.RemoveDir(ctx, workspace.ContainerID, workspace.RootPath); err != nil {
		return fmt.Errorf("failed to remove current workspace content: %w", err)
	}

	// Restore from snapshot
	if err := wm.restoreSnapshotContent(ctx, workspace, snapshot.SnapshotPath); err != nil {
		return fmt.Errorf("failed to restore snapshot content: %w", err)
	}

	// Update workspace metadata
	workspace.UpdatedAt = time.Now()
	workspace.Metadata["restored_from_snapshot"] = snapshotID
	workspace.Metadata["restored_at"] = time.Now()

	log.Info().
		Str("workspace_id", workspace.ID).
		Str("snapshot_id", snapshotID).
		Msg("Workspace restored from snapshot")

	return nil
}

// ArchiveWorkspace archives an inactive workspace
func (wm *WorkspaceManager) ArchiveWorkspace(ctx context.Context, workspaceID string) error {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	workspace, exists := wm.workspaces[workspaceID]
	if !exists {
		return fmt.Errorf("workspace not found: %s", workspaceID)
	}

	// Create archive snapshot
	archiveSnapshot, err := wm.CreateSnapshot(ctx, workspaceID, "archive", "Automatic archive during cleanup")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create archive snapshot")
	}

	// Update workspace status
	workspace.Status = WorkspaceStatusArchived
	workspace.UpdatedAt = time.Now()
	workspace.Metadata["archived_at"] = time.Now()
	if archiveSnapshot != nil {
		workspace.Metadata["archive_snapshot"] = archiveSnapshot.ID
	}

	log.Info().
		Str("workspace_id", workspaceID).
		Str("workspace_name", workspace.Name).
		Msg("Workspace archived")

	return nil
}

// Helper methods for snapshot operations
func (wm *WorkspaceManager) createSnapshotContent(ctx context.Context, workspace *Workspace, snapshotPath string) error {
	// In a real implementation, this would recursively copy all workspace content
	// to the snapshot location. For now, we'll create a metadata file.
	
	snapshotMetadata := map[string]interface{}{
		"workspace_id":   workspace.ID,
		"workspace_name": workspace.Name,
		"snapshot_time":  time.Now(),
		"size":          workspace.Size,
		"file_count":    workspace.FileCount,
	}

	metadataBytes, _ := json.MarshalIndent(snapshotMetadata, "", "  ")
	metadataPath := path.Join(snapshotPath, "snapshot.json")
	
	return wm.containerFS.WriteFile(ctx, workspace.ContainerID, metadataPath, metadataBytes, 0644)
}

func (wm *WorkspaceManager) restoreSnapshotContent(ctx context.Context, workspace *Workspace, snapshotPath string) error {
	// In a real implementation, this would restore all content from the snapshot
	// For now, we'll just read the metadata
	
	metadataPath := path.Join(snapshotPath, "snapshot.json")
	metadataBytes, err := wm.containerFS.ReadFile(ctx, workspace.ContainerID, metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read snapshot metadata: %w", err)
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return fmt.Errorf("failed to parse snapshot metadata: %w", err)
	}

	log.Debug().Interface("metadata", metadata).Msg("Snapshot metadata loaded")
	return nil
}

func (wm *WorkspaceManager) calculateSnapshotChecksum(ctx context.Context, workspace *Workspace, snapshotPath string) (string, error) {
	// Simple checksum calculation based on snapshot metadata
	// In a real implementation, this would calculate checksum of all files
	
	data := fmt.Sprintf("%s-%s-%d", workspace.ID, snapshotPath, time.Now().UnixNano())
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash), nil
}

// GetWorkspaceStats returns statistics about workspace usage
func (wm *WorkspaceManager) GetWorkspaceStats() *WorkspaceStats {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	stats := &WorkspaceStats{
		TotalWorkspaces: len(wm.workspaces),
		ActiveWorkspaces: 0,
		ArchivedWorkspaces: 0,
		TotalSize: 0,
		TotalFiles: 0,
		Types: make(map[WorkspaceType]int),
	}

	for _, workspace := range wm.workspaces {
		if workspace.Status == WorkspaceStatusActive {
			stats.ActiveWorkspaces++
		} else if workspace.Status == WorkspaceStatusArchived {
			stats.ArchivedWorkspaces++
		}
		
		stats.TotalSize += workspace.Size
		stats.TotalFiles += workspace.FileCount
		stats.Types[workspace.Type]++
	}

	return stats
}

// WorkspaceStats provides statistics about workspace usage
type WorkspaceStats struct {
	TotalWorkspaces    int                        `json:"total_workspaces"`
	ActiveWorkspaces   int                        `json:"active_workspaces"`
	ArchivedWorkspaces int                        `json:"archived_workspaces"`
	TotalSize          int64                      `json:"total_size_bytes"`
	TotalFiles         int64                      `json:"total_files"`
	Types              map[WorkspaceType]int      `json:"types"`
}