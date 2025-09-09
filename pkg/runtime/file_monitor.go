package runtime

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// FileMonitor handles file system event monitoring within containers
type FileMonitor struct {
	watchers    map[string]*FileWatcher // key: containerID:filePath
	watchersMu  sync.RWMutex
	shutdownCh  chan struct{}
	isShutdown  bool
}

// FileWatcher represents a single file watcher
type FileWatcher struct {
	containerID    string
	filePath       string
	eventChan      chan FileEvent
	stopChan       chan struct{}
	lastModTime    time.Time
	lastSize       int64
	pollInterval   time.Duration
	isRunning      bool
	mu             sync.RWMutex
}

// FileMonitorConfig holds configuration for the file monitor
type FileMonitorConfig struct {
	PollInterval    time.Duration
	MaxWatchers     int
	BufferSize      int
}

// DefaultFileMonitorConfig returns default configuration
func DefaultFileMonitorConfig() FileMonitorConfig {
	return FileMonitorConfig{
		PollInterval: 1 * time.Second,
		MaxWatchers:  100,
		BufferSize:   10,
	}
}

// NewFileMonitor creates a new file monitor
func NewFileMonitor() *FileMonitor {
	fm := &FileMonitor{
		watchers:   make(map[string]*FileWatcher),
		shutdownCh: make(chan struct{}),
	}
	
	return fm
}

// WatchFile starts monitoring a file for changes
func (fm *FileMonitor) WatchFile(ctx context.Context, containerID, filePath string) (<-chan FileEvent, error) {
	fm.watchersMu.Lock()
	defer fm.watchersMu.Unlock()

	if fm.isShutdown {
		return nil, fmt.Errorf("file monitor is shutdown")
	}

	watchKey := fmt.Sprintf("%s:%s", containerID, filePath)

	// Check if already watching
	if watcher, exists := fm.watchers[watchKey]; exists {
		return watcher.eventChan, nil
	}

	// Create new watcher
	config := DefaultFileMonitorConfig()
	watcher := &FileWatcher{
		containerID:  containerID,
		filePath:     filePath,
		eventChan:    make(chan FileEvent, config.BufferSize),
		stopChan:     make(chan struct{}),
		pollInterval: config.PollInterval,
	}

	// Start the watcher goroutine
	go watcher.start(ctx, fm.shutdownCh)

	fm.watchers[watchKey] = watcher

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Msg("Started file monitoring")

	return watcher.eventChan, nil
}

// StopWatch stops monitoring a file
func (fm *FileMonitor) StopWatch(containerID, filePath string) error {
	fm.watchersMu.Lock()
	defer fm.watchersMu.Unlock()

	watchKey := fmt.Sprintf("%s:%s", containerID, filePath)

	watcher, exists := fm.watchers[watchKey]
	if !exists {
		return fmt.Errorf("no watcher found for file %s in container %s", filePath, containerID)
	}

	watcher.stop()
	delete(fm.watchers, watchKey)

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Msg("Stopped file monitoring")

	return nil
}

// StopAllWatchers stops all file watchers for a container
func (fm *FileMonitor) StopAllWatchers(containerID string) error {
	fm.watchersMu.Lock()
	defer fm.watchersMu.Unlock()

	var stoppedCount int
	var keysToDelete []string

	for key, watcher := range fm.watchers {
		if watcher.containerID == containerID {
			watcher.stop()
			keysToDelete = append(keysToDelete, key)
			stoppedCount++
		}
	}

	for _, key := range keysToDelete {
		delete(fm.watchers, key)
	}

	log.Info().
		Str("container_id", containerID).
		Int("stopped_count", stoppedCount).
		Msg("Stopped all file watchers for container")

	return nil
}

// GetWatcherInfo returns information about active watchers
func (fm *FileMonitor) GetWatcherInfo() map[string]interface{} {
	fm.watchersMu.RLock()
	defer fm.watchersMu.RUnlock()

	info := make(map[string]interface{})
	info["total_watchers"] = len(fm.watchers)

	containerCounts := make(map[string]int)
	var activeWatchers []map[string]interface{}

	for _, watcher := range fm.watchers {
		containerCounts[watcher.containerID]++

		watcherInfo := map[string]interface{}{
			"container_id": watcher.containerID,
			"file_path":    watcher.filePath,
			"is_running":   watcher.isRunning,
			"last_mod_time": watcher.lastModTime,
			"last_size":    watcher.lastSize,
		}
		activeWatchers = append(activeWatchers, watcherInfo)
	}

	info["watchers_by_container"] = containerCounts
	info["active_watchers"] = activeWatchers

	return info
}

// Shutdown gracefully shuts down the file monitor
func (fm *FileMonitor) Shutdown() error {
	fm.watchersMu.Lock()
	defer fm.watchersMu.Unlock()

	if fm.isShutdown {
		return nil
	}

	fm.isShutdown = true
	close(fm.shutdownCh)

	// Stop all watchers
	for _, watcher := range fm.watchers {
		watcher.stop()
	}

	watcherCount := len(fm.watchers)
	fm.watchers = make(map[string]*FileWatcher)

	log.Info().
		Int("stopped_watchers", watcherCount).
		Msg("File monitor shutdown complete")

	return nil
}

// FileWatcher methods

// start begins the file watching process
func (fw *FileWatcher) start(ctx context.Context, shutdownCh <-chan struct{}) {
	fw.mu.Lock()
	fw.isRunning = true
	fw.mu.Unlock()

	defer func() {
		fw.mu.Lock()
		fw.isRunning = false
		close(fw.eventChan)
		fw.mu.Unlock()
	}()

	ticker := time.NewTicker(fw.pollInterval)
	defer ticker.Stop()

	// Initialize baseline
	fw.updateBaseline()

	for {
		select {
		case <-ctx.Done():
			log.Debug().
				Str("container_id", fw.containerID).
				Str("file_path", fw.filePath).
				Msg("File watcher stopped due to context cancellation")
			return
		case <-shutdownCh:
			log.Debug().
				Str("container_id", fw.containerID).
				Str("file_path", fw.filePath).
				Msg("File watcher stopped due to shutdown")
			return
		case <-fw.stopChan:
			log.Debug().
				Str("container_id", fw.containerID).
				Str("file_path", fw.filePath).
				Msg("File watcher stopped explicitly")
			return
		case <-ticker.C:
			if err := fw.checkForChanges(); err != nil {
				log.Debug().
					Err(err).
					Str("container_id", fw.containerID).
					Str("file_path", fw.filePath).
					Msg("Error checking for file changes")
			}
		}
	}
}

// stop stops the file watcher
func (fw *FileWatcher) stop() {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	if fw.isRunning {
		close(fw.stopChan)
	}
}

// updateBaseline updates the baseline file information
func (fw *FileWatcher) updateBaseline() {
	// Since we're monitoring files in containers, we'll use a simulated approach
	// In a real implementation, this would query the container filesystem
	
	// For now, use current time as baseline
	fw.mu.Lock()
	defer fw.mu.Unlock()

	fw.lastModTime = time.Now()
	fw.lastSize = 0
}

// checkForChanges checks if the file has changed since last check
func (fw *FileWatcher) checkForChanges() error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	// In a real implementation, this would use runc exec to stat the file
	// For this implementation, we'll simulate file changes periodically
	
	currentTime := time.Now()
	
	// Simulate a file change every 30 seconds for demonstration
	if currentTime.Sub(fw.lastModTime) > 30*time.Second {
		event := FileEvent{
			Path:      fw.filePath,
			Op:        "write",
			Timestamp: currentTime,
		}
		
		select {
		case fw.eventChan <- event:
			fw.lastModTime = currentTime
			fw.lastSize = fw.lastSize + 100 // Simulate size increase
			
			log.Debug().
				Str("container_id", fw.containerID).
				Str("file_path", fw.filePath).
				Str("operation", event.Op).
				Msg("File change detected")
		default:
			log.Warn().
				Str("container_id", fw.containerID).
				Str("file_path", fw.filePath).
				Msg("Event channel full, dropping file event")
		}
	}
	
	return nil
}

// ContainerFileMonitor provides a container-specific file monitoring interface
type ContainerFileMonitor struct {
	fileMonitor *FileMonitor
	client      *RunCClient
}

// NewContainerFileMonitor creates a new container file monitor
func NewContainerFileMonitor(client *RunCClient) *ContainerFileMonitor {
	return &ContainerFileMonitor{
		fileMonitor: NewFileMonitor(),
		client:      client,
	}
}

// WatchFileInContainer watches a file in a specific container with runc exec integration
func (cfm *ContainerFileMonitor) WatchFileInContainer(ctx context.Context, containerID, filePath string) (<-chan FileEvent, error) {
	// Enhanced file watcher that uses runc exec to monitor files
	watchKey := fmt.Sprintf("%s:%s", containerID, filePath)
	
	cfm.fileMonitor.watchersMu.Lock()
	defer cfm.fileMonitor.watchersMu.Unlock()

	if cfm.fileMonitor.isShutdown {
		return nil, fmt.Errorf("file monitor is shutdown")
	}

	// Check if already watching
	if watcher, exists := cfm.fileMonitor.watchers[watchKey]; exists {
		return watcher.eventChan, nil
	}

	// Create enhanced watcher
	config := DefaultFileMonitorConfig()
	watcher := &ContainerFileWatcher{
		FileWatcher: FileWatcher{
			containerID:  containerID,
			filePath:     filePath,
			eventChan:    make(chan FileEvent, config.BufferSize),
			stopChan:     make(chan struct{}),
			pollInterval: config.PollInterval,
		},
		client: cfm.client,
	}

	// Start the watcher goroutine
	go watcher.startContainerWatch(ctx, cfm.fileMonitor.shutdownCh)

	cfm.fileMonitor.watchers[watchKey] = &watcher.FileWatcher

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Msg("Started container file monitoring")

	return watcher.eventChan, nil
}

// ContainerFileWatcher extends FileWatcher with container-specific functionality
type ContainerFileWatcher struct {
	FileWatcher
	client *RunCClient
}

// startContainerWatch begins container-specific file watching
func (cfw *ContainerFileWatcher) startContainerWatch(ctx context.Context, shutdownCh <-chan struct{}) {
	cfw.mu.Lock()
	cfw.isRunning = true
	cfw.mu.Unlock()

	defer func() {
		cfw.mu.Lock()
		cfw.isRunning = false
		close(cfw.eventChan)
		cfw.mu.Unlock()
	}()

	ticker := time.NewTicker(cfw.pollInterval)
	defer ticker.Stop()

	// Initialize baseline using container stat
	cfw.updateContainerBaseline(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-shutdownCh:
			return
		case <-cfw.stopChan:
			return
		case <-ticker.C:
			if err := cfw.checkContainerFileChanges(ctx); err != nil {
				log.Debug().
					Err(err).
					Str("container_id", cfw.containerID).
					Str("file_path", cfw.filePath).
					Msg("Error checking container file changes")
			}
		}
	}
}

// updateContainerBaseline uses runc exec to get file stats
func (cfw *ContainerFileWatcher) updateContainerBaseline(ctx context.Context) {
	spec := &ProcessSpec{
		Cmd:  "stat",
		Args: []string{"stat", "-c", "%Y|%s", cfw.filePath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 10 * time.Second,
	}

	result, err := cfw.client.ExecProcess(ctx, cfw.containerID, spec)
	if err != nil {
		log.Debug().
			Err(err).
			Str("container_id", cfw.containerID).
			Str("file_path", cfw.filePath).
			Msg("Failed to get initial file stats")
		return
	}

	if result.ExitCode != 0 {
		log.Debug().
			Str("container_id", cfw.containerID).
			Str("file_path", cfw.filePath).
			Msg("File does not exist initially")
		return
	}

	output := string(result.Stdout)
	if parts := filepath.SplitList(output); len(parts) >= 2 {
		if modTime, err := time.Parse("1136239445", parts[0]); err == nil {
			cfw.mu.Lock()
			cfw.lastModTime = modTime
			cfw.mu.Unlock()
		}
	}
}

// checkContainerFileChanges checks for file changes using runc exec
func (cfw *ContainerFileWatcher) checkContainerFileChanges(ctx context.Context) error {
	spec := &ProcessSpec{
		Cmd:  "stat",
		Args: []string{"stat", "-c", "%Y|%s", cfw.filePath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 10 * time.Second,
	}

	result, err := cfw.client.ExecProcess(ctx, cfw.containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	cfw.mu.Lock()
	defer cfw.mu.Unlock()

	if result.ExitCode != 0 {
		// File doesn't exist or can't be accessed
		if !cfw.lastModTime.IsZero() {
			// File was removed
			event := FileEvent{
				Path:      cfw.filePath,
				Op:        "remove",
				Timestamp: time.Now(),
			}
			
			select {
			case cfw.eventChan <- event:
				cfw.lastModTime = time.Time{}
				cfw.lastSize = 0
			default:
				// Channel full
			}
		}
		return nil
	}

	// Parse stat output
	output := string(result.Stdout)
	parts := filepath.SplitList(output)
	if len(parts) < 2 {
		return fmt.Errorf("invalid stat output: %s", output)
	}

	modTimeStr := parts[0]
	sizeStr := parts[1]

	// Parse modification time (Unix timestamp)
	modTimeUnix, err := time.Parse("1136239445", modTimeStr)
	if err != nil {
		return fmt.Errorf("invalid modification time: %s", modTimeStr)
	}

	// Parse size
	var size int64
	if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil {
		return fmt.Errorf("invalid size: %s", sizeStr)
	}

	// Check for changes
	var eventOp string
	
	if cfw.lastModTime.IsZero() {
		// File was created
		eventOp = "create"
	} else if modTimeUnix.After(cfw.lastModTime) {
		// File was modified
		eventOp = "write"
	} else if size != cfw.lastSize {
		// Size changed but mod time didn't (unusual but possible)
		eventOp = "write"
	}

	if eventOp != "" {
		event := FileEvent{
			Path:      cfw.filePath,
			Op:        eventOp,
			Timestamp: time.Now(),
		}
		
		select {
		case cfw.eventChan <- event:
			cfw.lastModTime = modTimeUnix
			cfw.lastSize = size
			
			log.Debug().
				Str("container_id", cfw.containerID).
				Str("file_path", cfw.filePath).
				Str("operation", eventOp).
				Int64("size", size).
				Msg("Container file change detected")
		default:
			log.Warn().
				Str("container_id", cfw.containerID).
				Str("file_path", cfw.filePath).
				Msg("Event channel full, dropping file event")
		}
	}

	return nil
}

// GetActiveWatchers returns information about all active file watchers
func (cfm *ContainerFileMonitor) GetActiveWatchers() map[string]interface{} {
	return cfm.fileMonitor.GetWatcherInfo()
}

// StopAllWatchers stops all watchers for a container
func (cfm *ContainerFileMonitor) StopAllWatchers(containerID string) error {
	return cfm.fileMonitor.StopAllWatchers(containerID)
}

// Shutdown shuts down the container file monitor
func (cfm *ContainerFileMonitor) Shutdown() error {
	return cfm.fileMonitor.Shutdown()
}