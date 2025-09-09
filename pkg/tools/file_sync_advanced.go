package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ConflictResolver handles file conflicts during synchronization
type ConflictResolver struct {
	strategies map[ConflictStrategy]ConflictResolverFunc
	mu         sync.RWMutex
}

// ConflictResolverFunc defines the signature for conflict resolution functions
type ConflictResolverFunc func(ctx context.Context, conflict *FileConflict) (*ConflictResolution, error)

// FileConflict represents a conflict between source and target files
type FileConflict struct {
	Path         string                 `json:"path"`
	SourceFile   *FileEntry             `json:"source_file"`
	TargetFile   *FileEntry             `json:"target_file"`
	ConflictType ConflictType           `json:"conflict_type"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ConflictResolution represents the resolution of a file conflict
type ConflictResolution struct {
	Strategy     ConflictStrategy       `json:"strategy"`
	Action       ResolutionAction       `json:"action"`
	NewPath      string                 `json:"new_path,omitempty"`
	MergeContent []byte                 `json:"merge_content,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ConflictType defines the type of conflict
type ConflictType string

const (
	ConflictTypeBothChanged   ConflictType = "both_changed"
	ConflictTypeDeletedSource ConflictType = "deleted_source"
	ConflictTypeDeletedTarget ConflictType = "deleted_target"
	ConflictTypeTypeChanged   ConflictType = "type_changed" // file <-> directory
	ConflictTypePermission    ConflictType = "permission"
)

// ResolutionAction defines what action to take for conflict resolution
type ResolutionAction string

const (
	ResolutionActionSkip      ResolutionAction = "skip"
	ResolutionActionOverwrite ResolutionAction = "overwrite"
	ResolutionActionRename    ResolutionAction = "rename"
	ResolutionActionMerge     ResolutionAction = "merge"
	ResolutionActionPrompt    ResolutionAction = "prompt"
)

// NewConflictResolver creates a new conflict resolver with built-in strategies
func NewConflictResolver() *ConflictResolver {
	cr := &ConflictResolver{
		strategies: make(map[ConflictStrategy]ConflictResolverFunc),
	}

	// Register built-in strategies
	cr.RegisterStrategy(ConflictStrategySkip, cr.resolveBySkipping)
	cr.RegisterStrategy(ConflictStrategyOverwrite, cr.resolveByOverwriting)
	cr.RegisterStrategy(ConflictStrategyRename, cr.resolveByRenaming)
	cr.RegisterStrategy(ConflictStrategyMerge, cr.resolveByMerging)
	cr.RegisterStrategy(ConflictStrategyPrompt, cr.resolveByPrompting)

	return cr
}

// RegisterStrategy registers a custom conflict resolution strategy
func (cr *ConflictResolver) RegisterStrategy(strategy ConflictStrategy, resolverFunc ConflictResolverFunc) {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	cr.strategies[strategy] = resolverFunc
}

// ResolveConflict resolves a file conflict using the specified strategy
func (cr *ConflictResolver) ResolveConflict(ctx context.Context, conflict *FileConflict, strategy ConflictStrategy) (*ConflictResolution, error) {
	cr.mu.RLock()
	resolverFunc, exists := cr.strategies[strategy]
	cr.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("unknown conflict resolution strategy: %s", strategy)
	}

	resolution, err := resolverFunc(ctx, conflict)
	if err != nil {
		return nil, fmt.Errorf("conflict resolution failed: %w", err)
	}

	log.Info().
		Str("path", conflict.Path).
		Str("conflict_type", string(conflict.ConflictType)).
		Str("strategy", string(strategy)).
		Str("action", string(resolution.Action)).
		Msg("Conflict resolved")

	return resolution, nil
}

// Built-in conflict resolution strategies
func (cr *ConflictResolver) resolveBySkipping(ctx context.Context, conflict *FileConflict) (*ConflictResolution, error) {
	return &ConflictResolution{
		Strategy: ConflictStrategySkip,
		Action:   ResolutionActionSkip,
		Metadata: map[string]interface{}{
			"reason": "conflict skipped as per strategy",
		},
	}, nil
}

func (cr *ConflictResolver) resolveByOverwriting(ctx context.Context, conflict *FileConflict) (*ConflictResolution, error) {
	return &ConflictResolution{
		Strategy: ConflictStrategyOverwrite,
		Action:   ResolutionActionOverwrite,
		Metadata: map[string]interface{}{
			"source_wins":   true,
			"backup_target": true,
		},
	}, nil
}

func (cr *ConflictResolver) resolveByRenaming(ctx context.Context, conflict *FileConflict) (*ConflictResolution, error) {
	// Generate unique name for conflicted file
	dir := path.Dir(conflict.Path)
	base := path.Base(conflict.Path)
	ext := path.Ext(base)
	name := strings.TrimSuffix(base, ext)

	timestamp := time.Now().Format("20060102-150405")
	newName := fmt.Sprintf("%s.conflict.%s%s", name, timestamp, ext)
	newPath := path.Join(dir, newName)

	return &ConflictResolution{
		Strategy: ConflictStrategyRename,
		Action:   ResolutionActionRename,
		NewPath:  newPath,
		Metadata: map[string]interface{}{
			"original_path": conflict.Path,
			"renamed_path":  newPath,
		},
	}, nil
}

func (cr *ConflictResolver) resolveByMerging(ctx context.Context, conflict *FileConflict) (*ConflictResolution, error) {
	// Simple merge strategy - for text files, attempt to merge content
	if conflict.ConflictType != ConflictTypeBothChanged {
		// Can't merge non-content conflicts
		return cr.resolveByRenaming(ctx, conflict)
	}

	// For now, just concatenate content with conflict markers
	// In a real implementation, you'd want proper 3-way merge
	mergedContent := fmt.Sprintf(`<<<<<<< SOURCE
%s
=======
%s
>>>>>>> TARGET
`, "source content placeholder", "target content placeholder")

	return &ConflictResolution{
		Strategy:     ConflictStrategyMerge,
		Action:       ResolutionActionMerge,
		MergeContent: []byte(mergedContent),
		Metadata: map[string]interface{}{
			"merge_type":    "simple_concatenation",
			"has_conflicts": true,
		},
	}, nil
}

func (cr *ConflictResolver) resolveByPrompting(ctx context.Context, conflict *FileConflict) (*ConflictResolution, error) {
	// In a real implementation, this would present options to the user
	// For now, fall back to rename strategy
	return cr.resolveByRenaming(ctx, conflict)
}

// ProgressReporter tracks and reports synchronization progress
type ProgressReporter struct {
	progressCallbacks map[string]ProgressCallback
	mu                sync.RWMutex
}

// ProgressCallback defines the signature for progress callbacks
type ProgressCallback func(sessionID string, progress *SyncProgress)

// NewProgressReporter creates a new progress reporter
func NewProgressReporter() *ProgressReporter {
	return &ProgressReporter{
		progressCallbacks: make(map[string]ProgressCallback),
	}
}

// RegisterCallback registers a progress callback for a session
func (pr *ProgressReporter) RegisterCallback(sessionID string, callback ProgressCallback) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.progressCallbacks[sessionID] = callback
}

// UnregisterCallback removes a progress callback
func (pr *ProgressReporter) UnregisterCallback(sessionID string) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	delete(pr.progressCallbacks, sessionID)
}

// ReportProgress reports progress for a sync session
func (pr *ProgressReporter) ReportProgress(sessionID string, progress *SyncProgress) {
	pr.mu.RLock()
	callback, exists := pr.progressCallbacks[sessionID]
	pr.mu.RUnlock()

	if exists && callback != nil {
		callback(sessionID, progress)
	}

	// Calculate additional progress metrics
	pr.updateProgressMetrics(progress)
}

// updateProgressMetrics calculates derived progress metrics
func (pr *ProgressReporter) updateProgressMetrics(progress *SyncProgress) {
	if progress.TotalFiles > 0 {
		progress.ProcessedFiles = min(progress.ProcessedFiles, progress.TotalFiles)
	}

	if progress.TotalBytes > 0 {
		progress.ProcessedBytes = min(progress.ProcessedBytes, progress.TotalBytes)
	}

	// Calculate transfer rate
	elapsed := time.Since(progress.StartTime)
	if elapsed > 0 && progress.ProcessedBytes > 0 {
		progress.TransferRate = progress.ProcessedBytes / int64(elapsed.Seconds())
	}

	// Estimate completion time
	if progress.TotalBytes > 0 && progress.ProcessedBytes > 0 && progress.TransferRate > 0 {
		remainingBytes := progress.TotalBytes - progress.ProcessedBytes
		remainingSeconds := remainingBytes / progress.TransferRate
		estimatedEnd := time.Now().Add(time.Duration(remainingSeconds) * time.Second)
		progress.EstimatedEnd = &estimatedEnd
	}
}

// SyncScheduler manages scheduled synchronization tasks
type SyncScheduler struct {
	schedules map[string]*SyncSchedule
	ticker    *time.Ticker
	mu        sync.RWMutex
	running   bool
}

// SyncSchedule represents a scheduled sync operation
type SyncSchedule struct {
	ID          string        `json:"id"`
	SessionID   string        `json:"session_id"`
	CronExpr    string        `json:"cron_expression"`
	Interval    time.Duration `json:"interval"`
	NextRun     time.Time     `json:"next_run"`
	LastRun     *time.Time    `json:"last_run,omitempty"`
	Enabled     bool          `json:"enabled"`
	MaxRuns     int           `json:"max_runs"` // 0 for unlimited
	CurrentRuns int           `json:"current_runs"`
	OnConflict  string        `json:"on_conflict"` // skip, queue, replace
}

// NewSyncScheduler creates a new sync scheduler
func NewSyncScheduler() *SyncScheduler {
	return &SyncScheduler{
		schedules: make(map[string]*SyncSchedule),
		ticker:    time.NewTicker(1 * time.Minute), // Check every minute
	}
}

// Start begins the sync scheduler
func (ss *SyncScheduler) Start(ctx context.Context, engine *FileSyncEngine) {
	if ss.running {
		return
	}
	ss.running = true

	log.Info().Msg("Sync scheduler started")

	for {
		select {
		case <-ss.ticker.C:
			ss.checkScheduledSyncs(ctx, engine)
		case <-ctx.Done():
			ss.running = false
			ss.ticker.Stop()
			return
		}
	}
}

// AddSchedule adds a new sync schedule
func (ss *SyncScheduler) AddSchedule(schedule *SyncSchedule) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.schedules[schedule.ID] = schedule

	log.Info().
		Str("schedule_id", schedule.ID).
		Str("session_id", schedule.SessionID).
		Dur("interval", schedule.Interval).
		Msg("Sync schedule added")
}

// RemoveSchedule removes a sync schedule
func (ss *SyncScheduler) RemoveSchedule(scheduleID string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.schedules, scheduleID)

	log.Info().Str("schedule_id", scheduleID).Msg("Sync schedule removed")
}

// checkScheduledSyncs checks and executes scheduled syncs
func (ss *SyncScheduler) checkScheduledSyncs(ctx context.Context, engine *FileSyncEngine) {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	now := time.Now()
	for _, schedule := range ss.schedules {
		if schedule.Enabled && now.After(schedule.NextRun) {
			if schedule.MaxRuns > 0 && schedule.CurrentRuns >= schedule.MaxRuns {
				continue // Max runs reached
			}

			go ss.executeScheduledSync(ctx, engine, schedule)
		}
	}
}

// executeScheduledSync executes a scheduled sync
func (ss *SyncScheduler) executeScheduledSync(ctx context.Context, engine *FileSyncEngine, schedule *SyncSchedule) {
	log.Info().
		Str("schedule_id", schedule.ID).
		Str("session_id", schedule.SessionID).
		Msg("Executing scheduled sync")

	if err := engine.StartSync(ctx, schedule.SessionID); err != nil {
		log.Error().
			Err(err).
			Str("schedule_id", schedule.ID).
			Str("session_id", schedule.SessionID).
			Msg("Failed to start scheduled sync")
		return
	}

	// Update schedule
	ss.mu.Lock()
	now := time.Now()
	schedule.LastRun = &now
	schedule.CurrentRuns++
	schedule.NextRun = now.Add(schedule.Interval)
	ss.mu.Unlock()
}

// SyncMetrics collects and provides synchronization metrics
type SyncMetrics struct {
	sessions      map[string]*SessionMetrics
	globalMetrics *GlobalSyncMetrics
	mu            sync.RWMutex
}

// SessionMetrics tracks metrics for individual sync sessions
type SessionMetrics struct {
	SessionID       string        `json:"session_id"`
	TotalSyncs      int64         `json:"total_syncs"`
	SuccessfulSyncs int64         `json:"successful_syncs"`
	FailedSyncs     int64         `json:"failed_syncs"`
	TotalBytes      int64         `json:"total_bytes_synced"`
	TotalFiles      int64         `json:"total_files_synced"`
	AverageRate     float64       `json:"average_rate_bps"`
	AverageDuration time.Duration `json:"average_duration"`
	LastSync        time.Time     `json:"last_sync"`
	ConflictCount   int64         `json:"total_conflicts"`
}

// GlobalSyncMetrics tracks system-wide sync metrics
type GlobalSyncMetrics struct {
	TotalSessions  int64     `json:"total_sessions"`
	ActiveSessions int64     `json:"active_sessions"`
	TotalSyncs     int64     `json:"total_syncs"`
	TotalBytes     int64     `json:"total_bytes"`
	TotalFiles     int64     `json:"total_files"`
	AverageRate    float64   `json:"average_rate_bps"`
	UptimeStart    time.Time `json:"uptime_start"`
	LastActivity   time.Time `json:"last_activity"`
}

// NewSyncMetrics creates a new sync metrics collector
func NewSyncMetrics() *SyncMetrics {
	return &SyncMetrics{
		sessions: make(map[string]*SessionMetrics),
		globalMetrics: &GlobalSyncMetrics{
			UptimeStart: time.Now(),
		},
	}
}

// StartCollection begins metrics collection
func (sm *SyncMetrics) StartCollection(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.updateMetrics()
		case <-ctx.Done():
			return
		}
	}
}

// RecordSync records metrics for a completed sync session
func (sm *SyncMetrics) RecordSync(session *SyncSession) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sessionMetrics, exists := sm.sessions[session.ID]
	if !exists {
		sessionMetrics = &SessionMetrics{
			SessionID: session.ID,
		}
		sm.sessions[session.ID] = sessionMetrics
	}

	// Update session metrics
	sessionMetrics.TotalSyncs++
	if session.Status == SyncStatusCompleted {
		sessionMetrics.SuccessfulSyncs++
	} else {
		sessionMetrics.FailedSyncs++
	}

	sessionMetrics.TotalBytes += session.Progress.ProcessedBytes
	sessionMetrics.TotalFiles += session.Progress.ProcessedFiles
	sessionMetrics.ConflictCount += session.Progress.ConflictCount
	sessionMetrics.LastSync = session.LastSync

	// Calculate averages
	if sessionMetrics.TotalSyncs > 0 {
		duration := time.Since(session.Progress.StartTime)
		sessionMetrics.AverageDuration = time.Duration(
			(int64(sessionMetrics.AverageDuration)*sessionMetrics.TotalSyncs + int64(duration)) / (sessionMetrics.TotalSyncs + 1))

		if duration > 0 {
			rate := float64(session.Progress.ProcessedBytes) / duration.Seconds()
			sessionMetrics.AverageRate = (sessionMetrics.AverageRate*float64(sessionMetrics.TotalSyncs) + rate) / float64(sessionMetrics.TotalSyncs+1)
		}
	}

	// Update global metrics
	sm.globalMetrics.TotalSyncs++
	sm.globalMetrics.TotalBytes += session.Progress.ProcessedBytes
	sm.globalMetrics.TotalFiles += session.Progress.ProcessedFiles
	sm.globalMetrics.LastActivity = time.Now()
}

// updateMetrics performs periodic metrics updates
func (sm *SyncMetrics) updateMetrics() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Update global averages
	if sm.globalMetrics.TotalSyncs > 0 {
		totalDuration := time.Since(sm.globalMetrics.UptimeStart)
		if totalDuration > 0 {
			sm.globalMetrics.AverageRate = float64(sm.globalMetrics.TotalBytes) / totalDuration.Seconds()
		}
	}
}

// GetSessionMetrics returns metrics for a specific session
func (sm *SyncMetrics) GetSessionMetrics(sessionID string) *SessionMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if metrics, exists := sm.sessions[sessionID]; exists {
		// Return a copy
		return &SessionMetrics{
			SessionID:       metrics.SessionID,
			TotalSyncs:      metrics.TotalSyncs,
			SuccessfulSyncs: metrics.SuccessfulSyncs,
			FailedSyncs:     metrics.FailedSyncs,
			TotalBytes:      metrics.TotalBytes,
			TotalFiles:      metrics.TotalFiles,
			AverageRate:     metrics.AverageRate,
			AverageDuration: metrics.AverageDuration,
			LastSync:        metrics.LastSync,
			ConflictCount:   metrics.ConflictCount,
		}
	}

	return nil
}

// GetGlobalMetrics returns global sync metrics
func (sm *SyncMetrics) GetGlobalMetrics() *GlobalSyncMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return &GlobalSyncMetrics{
		TotalSessions:  sm.globalMetrics.TotalSessions,
		ActiveSessions: sm.globalMetrics.ActiveSessions,
		TotalSyncs:     sm.globalMetrics.TotalSyncs,
		TotalBytes:     sm.globalMetrics.TotalBytes,
		TotalFiles:     sm.globalMetrics.TotalFiles,
		AverageRate:    sm.globalMetrics.AverageRate,
		UptimeStart:    sm.globalMetrics.UptimeStart,
		LastActivity:   sm.globalMetrics.LastActivity,
	}
}

// DeltaSync provides incremental synchronization with delta compression
type DeltaSync struct {
	chunkSize        int64
	compressionLevel int
}

// NewDeltaSync creates a new delta sync processor
func NewDeltaSync(chunkSize int64, compressionLevel int) *DeltaSync {
	return &DeltaSync{
		chunkSize:        chunkSize,
		compressionLevel: compressionLevel,
	}
}

// CreateDelta creates a delta between two file versions
func (ds *DeltaSync) CreateDelta(oldContent, newContent []byte) (*Delta, error) {
	// Simple delta implementation - in practice you'd use a proper diff algorithm
	delta := &Delta{
		ChunkSize: ds.chunkSize,
		Chunks:    make([]*DeltaChunk, 0),
	}

	// Calculate checksums
	oldChecksum := ds.calculateChecksum(oldContent)
	newChecksum := ds.calculateChecksum(newContent)

	if oldChecksum == newChecksum {
		// No changes
		return delta, nil
	}

	// For simplicity, treat entire file as changed
	chunk := &DeltaChunk{
		Type:     ChunkTypeReplace,
		Offset:   0,
		Length:   int64(len(newContent)),
		Data:     newContent,
		Checksum: newChecksum,
	}

	delta.Chunks = append(delta.Chunks, chunk)
	delta.TotalSize = int64(len(newContent))

	return delta, nil
}

// ApplyDelta applies a delta to create a new file version
func (ds *DeltaSync) ApplyDelta(originalContent []byte, delta *Delta) ([]byte, error) {
	if len(delta.Chunks) == 0 {
		return originalContent, nil
	}

	// For this simple implementation, just return the replacement data
	if len(delta.Chunks) == 1 && delta.Chunks[0].Type == ChunkTypeReplace {
		return delta.Chunks[0].Data, nil
	}

	return originalContent, nil
}

// calculateChecksum calculates a checksum for content
func (ds *DeltaSync) calculateChecksum(content []byte) string {
	hasher := sha256.New()
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

// Delta represents a difference between two file versions
type Delta struct {
	ChunkSize int64         `json:"chunk_size"`
	TotalSize int64         `json:"total_size"`
	Chunks    []*DeltaChunk `json:"chunks"`
}

// DeltaChunk represents a chunk of changes
type DeltaChunk struct {
	Type     ChunkType `json:"type"`
	Offset   int64     `json:"offset"`
	Length   int64     `json:"length"`
	Data     []byte    `json:"data,omitempty"`
	Checksum string    `json:"checksum"`
}

// ChunkType defines the type of delta chunk
type ChunkType string

const (
	ChunkTypeUnchanged ChunkType = "unchanged"
	ChunkTypeReplace   ChunkType = "replace"
	ChunkTypeInsert    ChunkType = "insert"
	ChunkTypeDelete    ChunkType = "delete"
)

// Helper function for min
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
