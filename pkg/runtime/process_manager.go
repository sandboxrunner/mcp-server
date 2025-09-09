package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// ProcessManager manages the lifecycle of processes in containers
type ProcessManager struct {
	mu              sync.RWMutex
	processes       map[string]*ManagedProcess
	runCClient      *RunCClient
	eventBus        *ProcessEventBus
	resourceMonitor *ResourceMonitor
	
	// Configuration
	config *ProcessManagerConfig
	
	// Lifecycle management
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	shutdownOnce    sync.Once
	
	// Cleanup and maintenance
	cleanupInterval time.Duration
	zombieReaper    *ZombieReaper
	
	// Metrics and monitoring
	metrics *ProcessManagerMetrics
}

// ProcessManagerConfig holds configuration for the ProcessManager
type ProcessManagerConfig struct {
	// Cleanup settings
	CleanupInterval    time.Duration `json:"cleanupInterval"`
	ZombieReapInterval time.Duration `json:"zombieReapInterval"`
	
	// Process limits
	MaxProcesses       int           `json:"maxProcesses"`
	DefaultTimeout     time.Duration `json:"defaultTimeout"`
	KillTimeout        time.Duration `json:"killTimeout"`
	
	// Signal handling
	GracefulShutdownTimeout time.Duration `json:"gracefulShutdownTimeout"`
	TerminationSignal       os.Signal     `json:"-"` // Not JSON serializable
	KillSignal              os.Signal     `json:"-"` // Not JSON serializable
	
	// Event and monitoring
	EnableEvents         bool `json:"enableEvents"`
	EnableResourceMonitor bool `json:"enableResourceMonitor"`
	EventBufferSize      int  `json:"eventBufferSize"`
	
	// Resource monitoring
	ResourceMonitorConfig *ResourceMonitorConfig `json:"resourceMonitorConfig,omitempty"`
}

// ProcessManagerMetrics tracks ProcessManager performance and state
type ProcessManagerMetrics struct {
	mu sync.RWMutex
	
	// Process statistics
	ProcessesStarted   int64 `json:"processesStarted"`
	ProcessesCompleted int64 `json:"processesCompleted"`
	ProcessesFailed    int64 `json:"processesFailed"`
	ProcessesKilled    int64 `json:"processesKilled"`
	ProcessesActive    int   `json:"processesActive"`
	ProcessesZombie    int   `json:"processesZombie"`
	
	// Performance metrics
	AverageStartTime   time.Duration `json:"averageStartTime"`
	AverageRunTime     time.Duration `json:"averageRunTime"`
	
	// Error tracking
	StartErrors        int64 `json:"startErrors"`
	StopErrors         int64 `json:"stopErrors"`
	KillErrors         int64 `json:"killErrors"`
	
	// System statistics
	LastCleanupTime    time.Time `json:"lastCleanupTime"`
	ZombiesReaped      int64     `json:"zombiesReaped"`
	CleanupCycles      int64     `json:"cleanupCycles"`
}

// ZombieReaper handles cleanup of zombie processes
type ZombieReaper struct {
	mu       sync.RWMutex
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	metrics  *ZombieReaperMetrics
	
	// Process tracking
	trackedPIDs map[int32]string // PID -> ProcessID mapping
}

// ZombieReaperMetrics tracks zombie reaper performance
type ZombieReaperMetrics struct {
	mu sync.RWMutex
	
	ZombiesDetected int64     `json:"zombiesDetected"`
	ZombiesReaped   int64     `json:"zombiesReaped"`
	ReapErrors      int64     `json:"reapErrors"`
	LastReapTime    time.Time `json:"lastReapTime"`
	ReapCycles      int64     `json:"reapCycles"`
}

// ProcessStartOptions holds options for starting a process
type ProcessStartOptions struct {
	// Process specification
	Spec *ProcessSpec
	
	// Container context
	ContainerID string
	
	// Execution options
	Async   bool          // Start process asynchronously
	Timeout time.Duration // Override default timeout
	
	// Event callbacks
	OnStart func(*ManagedProcess)
	OnExit  func(*ManagedProcess, int32)
	OnError func(*ManagedProcess, error)
	
	// Context for cancellation
	Context context.Context
}

// DefaultProcessManagerConfig returns default configuration
func DefaultProcessManagerConfig() *ProcessManagerConfig {
	return &ProcessManagerConfig{
		CleanupInterval:         30 * time.Second,
		ZombieReapInterval:      10 * time.Second,
		MaxProcesses:            100,
		DefaultTimeout:          30 * time.Second,
		KillTimeout:             5 * time.Second,
		GracefulShutdownTimeout: 30 * time.Second,
		TerminationSignal:       syscall.SIGTERM,
		KillSignal:              syscall.SIGKILL,
		EnableEvents:            true,
		EnableResourceMonitor:   true,
		EventBufferSize:         1000,
		ResourceMonitorConfig:   DefaultResourceMonitorConfig(),
	}
}

// NewProcessManager creates a new ProcessManager
func NewProcessManager(runCClient *RunCClient, config *ProcessManagerConfig) (*ProcessManager, error) {
	if runCClient == nil {
		return nil, errors.New("runCClient cannot be nil")
	}
	
	if config == nil {
		config = DefaultProcessManagerConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pm := &ProcessManager{
		processes:       make(map[string]*ManagedProcess),
		runCClient:      runCClient,
		config:          config,
		ctx:             ctx,
		cancel:          cancel,
		cleanupInterval: config.CleanupInterval,
		metrics: &ProcessManagerMetrics{
			LastCleanupTime: time.Now(),
		},
	}
	
	// Initialize event bus if enabled
	if config.EnableEvents {
		pm.eventBus = NewProcessEventBus(config.EventBufferSize)
	}
	
	// Initialize resource monitor if enabled
	if config.EnableResourceMonitor {
		pm.resourceMonitor = NewResourceMonitor(config.ResourceMonitorConfig, pm.eventBus)
	}
	
	// Initialize zombie reaper
	pm.zombieReaper = NewZombieReaper(config.ZombieReapInterval)
	
	// Start background routines
	pm.wg.Add(1)
	go pm.cleanupRoutine()
	
	pm.wg.Add(1)
	go pm.signalHandler()
	
	log.Info().
		Int("max_processes", config.MaxProcesses).
		Dur("cleanup_interval", config.CleanupInterval).
		Bool("events_enabled", config.EnableEvents).
		Bool("resource_monitor_enabled", config.EnableResourceMonitor).
		Msg("Process manager initialized")
	
	return pm, nil
}

// Start starts a new process with the given options
func (pm *ProcessManager) Start(options ProcessStartOptions) (*ManagedProcess, error) {
	if options.Spec == nil {
		return nil, errors.New("process spec is required")
	}
	
	if options.ContainerID == "" {
		return nil, errors.New("container ID is required")
	}
	
	// Check process limits
	pm.mu.RLock()
	currentCount := len(pm.processes)
	pm.mu.RUnlock()
	
	if currentCount >= pm.config.MaxProcesses {
		return nil, fmt.Errorf("maximum number of processes (%d) exceeded", pm.config.MaxProcesses)
	}
	
	// Generate process ID
	processID := pm.generateProcessID()
	
	// Set default timeout if not provided
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = pm.config.DefaultTimeout
	}
	
	// Update spec with timeout
	specCopy := *options.Spec
	specCopy.Timeout = timeout
	
	// Create managed process
	process := NewManagedProcess(processID, options.ContainerID, &specCopy)
	
	// Set up context for process execution
	execCtx := pm.ctx
	if options.Context != nil {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithCancel(options.Context)
		process.SetCancel(cancel)
	}
	
	// Add to tracking
	pm.mu.Lock()
	pm.processes[processID] = process
	pm.mu.Unlock()
	
	// Update metrics
	pm.metrics.mu.Lock()
	pm.metrics.ProcessesStarted++
	pm.metrics.ProcessesActive++
	pm.metrics.mu.Unlock()
	
	log.Info().
		Str("process_id", processID).
		Str("container_id", options.ContainerID).
		Strs("args", options.Spec.Args).
		Dur("timeout", timeout).
		Msg("Starting process")
	
	// Execute the process
	startTime := time.Now()
	
	if options.Async {
		// Start asynchronously
		pm.wg.Add(1)
		go pm.executeProcessAsync(execCtx, process, options, startTime)
	} else {
		// Start synchronously
		if err := pm.executeProcess(execCtx, process, options, startTime); err != nil {
			// Remove from tracking on failure
			pm.mu.Lock()
			delete(pm.processes, processID)
			pm.mu.Unlock()
			
			pm.metrics.mu.Lock()
			pm.metrics.StartErrors++
			pm.metrics.ProcessesActive--
			pm.metrics.mu.Unlock()
			
			return nil, err
		}
	}
	
	// Publish start event
	if pm.eventBus != nil {
		pm.eventBus.PublishStart(processID, options.ContainerID, process.PID, &specCopy)
	}
	
	// Add to resource monitoring
	if pm.resourceMonitor != nil && process.PID > 0 {
		pm.resourceMonitor.AddProcess(process)
	}
	
	// Add to zombie reaper tracking
	if process.PID > 0 {
		pm.zombieReaper.TrackPID(process.PID, processID)
	}
	
	return process, nil
}

// Stop gracefully stops a process
func (pm *ProcessManager) Stop(processID string) error {
	pm.mu.RLock()
	process, exists := pm.processes[processID]
	pm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("process %s not found", processID)
	}
	
	if process.IsTerminal() {
		return fmt.Errorf("process %s is already terminated", processID)
	}
	
	log.Info().
		Str("process_id", processID).
		Int32("pid", process.PID).
		Msg("Stopping process gracefully")
	
	// Send termination signal
	if process.PID > 0 {
		if err := pm.sendSignal(process.PID, pm.config.TerminationSignal); err != nil {
			pm.metrics.mu.Lock()
			pm.metrics.StopErrors++
			pm.metrics.mu.Unlock()
			
			log.Error().
				Err(err).
				Str("process_id", processID).
				Int32("pid", process.PID).
				Msg("Failed to send termination signal")
			
			return fmt.Errorf("failed to send termination signal: %w", err)
		}
	}
	
	// Cancel context
	process.Cancel()
	
	// Wait for graceful shutdown with timeout
	select {
	case <-process.Wait():
		log.Info().
			Str("process_id", processID).
			Msg("Process stopped gracefully")
		
		return pm.setProcessStopped(process, 0)
		
	case <-time.After(pm.config.GracefulShutdownTimeout):
		log.Warn().
			Str("process_id", processID).
			Dur("timeout", pm.config.GracefulShutdownTimeout).
			Msg("Graceful shutdown timeout, killing process")
		
		return pm.Kill(processID)
	}
}

// Kill forcefully kills a process
func (pm *ProcessManager) Kill(processID string) error {
	pm.mu.RLock()
	process, exists := pm.processes[processID]
	pm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("process %s not found", processID)
	}
	
	if process.IsTerminal() {
		return fmt.Errorf("process %s is already terminated", processID)
	}
	
	log.Warn().
		Str("process_id", processID).
		Int32("pid", process.PID).
		Msg("Killing process forcefully")
	
	// Send kill signal
	if process.PID > 0 {
		if err := pm.sendSignal(process.PID, pm.config.KillSignal); err != nil {
			pm.metrics.mu.Lock()
			pm.metrics.KillErrors++
			pm.metrics.mu.Unlock()
			
			return fmt.Errorf("failed to send kill signal: %w", err)
		}
		
		// Publish kill event
		if pm.eventBus != nil {
			signalName := pm.getSignalName(pm.config.KillSignal)
			pm.eventBus.PublishKill(processID, process.ContainerID, process.PID, signalName)
		}
	}
	
	// Cancel context
	process.Cancel()
	
	// Wait briefly for kill to take effect
	select {
	case <-process.Wait():
		// Process terminated
	case <-time.After(pm.config.KillTimeout):
		// Kill timeout - process might be stuck
		log.Error().
			Str("process_id", processID).
			Int32("pid", process.PID).
			Msg("Process did not respond to kill signal")
	}
	
	pm.metrics.mu.Lock()
	pm.metrics.ProcessesKilled++
	pm.metrics.mu.Unlock()
	
	return pm.setProcessFailed(process, fmt.Errorf("process killed"))
}

// Wait waits for a process to complete
func (pm *ProcessManager) Wait(processID string, ctx context.Context) error {
	pm.mu.RLock()
	process, exists := pm.processes[processID]
	pm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("process %s not found", processID)
	}
	
	if process.IsTerminal() {
		return nil
	}
	
	select {
	case <-process.Wait():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetStatus returns the current status of a process
func (pm *ProcessManager) GetStatus(processID string) (ProcessState, error) {
	pm.mu.RLock()
	process, exists := pm.processes[processID]
	pm.mu.RUnlock()
	
	if !exists {
		return ProcessStateUnknown, fmt.Errorf("process %s not found", processID)
	}
	
	return process.GetState(), nil
}

// GetProcess returns a managed process by ID
func (pm *ProcessManager) GetProcess(processID string) (*ManagedProcess, error) {
	pm.mu.RLock()
	process, exists := pm.processes[processID]
	pm.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("process %s not found", processID)
	}
	
	return process, nil
}

// ListProcesses returns all currently managed processes
func (pm *ProcessManager) ListProcesses() []*ManagedProcess {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	processes := make([]*ManagedProcess, 0, len(pm.processes))
	for _, process := range pm.processes {
		processes = append(processes, process)
	}
	
	return processes
}

// GetMetrics returns ProcessManager metrics
func (pm *ProcessManager) GetMetrics() ProcessManagerMetrics {
	pm.metrics.mu.RLock()
	defer pm.metrics.mu.RUnlock()
	
	// Update active count
	pm.mu.RLock()
	pm.metrics.ProcessesActive = len(pm.processes)
	pm.mu.RUnlock()
	
	return *pm.metrics
}

// Shutdown gracefully shuts down the ProcessManager
func (pm *ProcessManager) Shutdown(ctx context.Context) error {
	var shutdownErr error
	
	pm.shutdownOnce.Do(func() {
		log.Info().Msg("Shutting down process manager")
		
		// Cancel main context
		pm.cancel()
		
		// Stop all running processes
		pm.mu.RLock()
		processes := make([]*ManagedProcess, 0, len(pm.processes))
		for _, process := range pm.processes {
			if !process.IsTerminal() {
				processes = append(processes, process)
			}
		}
		pm.mu.RUnlock()
		
		// Stop processes with timeout
		stopCtx, stopCancel := context.WithTimeout(ctx, pm.config.GracefulShutdownTimeout)
		defer stopCancel()
		
		var stopWg sync.WaitGroup
		for _, process := range processes {
			stopWg.Add(1)
			go func(p *ManagedProcess) {
				defer stopWg.Done()
				if err := pm.Stop(p.ID); err != nil {
					log.Error().
						Err(err).
						Str("process_id", p.ID).
						Msg("Error stopping process during shutdown")
				}
			}(process)
		}
		
		// Wait for processes to stop
		done := make(chan struct{})
		go func() {
			stopWg.Wait()
			close(done)
		}()
		
		select {
		case <-done:
			log.Info().Msg("All processes stopped gracefully")
		case <-stopCtx.Done():
			log.Warn().Msg("Timeout waiting for processes to stop, forcing shutdown")
		}
		
		// Shutdown components
		if pm.resourceMonitor != nil {
			if err := pm.resourceMonitor.Shutdown(ctx); err != nil {
				log.Error().Err(err).Msg("Error shutting down resource monitor")
				shutdownErr = err
			}
		}
		
		if pm.zombieReaper != nil {
			if err := pm.zombieReaper.Shutdown(ctx); err != nil {
				log.Error().Err(err).Msg("Error shutting down zombie reaper")
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}
		
		if pm.eventBus != nil {
			if err := pm.eventBus.Shutdown(ctx); err != nil {
				log.Error().Err(err).Msg("Error shutting down event bus")
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}
		
		// Wait for background routines
		waitDone := make(chan struct{})
		go func() {
			pm.wg.Wait()
			close(waitDone)
		}()
		
		select {
		case <-waitDone:
			log.Info().Msg("Process manager shutdown complete")
		case <-ctx.Done():
			log.Error().Msg("Timeout waiting for process manager shutdown")
			if shutdownErr == nil {
				shutdownErr = ctx.Err()
			}
		}
	})
	
	return shutdownErr
}

// executeProcess executes a process synchronously
func (pm *ProcessManager) executeProcess(ctx context.Context, process *ManagedProcess, options ProcessStartOptions, startTime time.Time) error {
	// Set process to running state
	if err := process.SetState(ProcessStateRunning, "Process started"); err != nil {
		return fmt.Errorf("failed to set running state: %w", err)
	}
	
	// Execute using runC client
	result, err := pm.runCClient.ExecProcess(ctx, options.ContainerID, options.Spec)
	
	// Update start time metrics
	pm.updateStartTimeMetrics(time.Since(startTime))
	
	if err != nil {
		process.SetError(err)
		if setErr := pm.setProcessFailed(process, err); setErr != nil {
			log.Error().Err(setErr).Msg("Failed to set process failed state")
		}
		
		// Call error callback
		if options.OnError != nil {
			options.OnError(process, err)
		}
		
		return err
	}
	
	// Update process with result
	if result.Process != nil && result.Process.PID > 0 {
		process.SetPID(result.Process.PID)
	}
	
	if result.ExitCode != 0 {
		process.SetExitCode(result.ExitCode)
		if setErr := pm.setProcessFailed(process, fmt.Errorf("process exited with code %d", result.ExitCode)); setErr != nil {
			log.Error().Err(setErr).Msg("Failed to set process failed state")
		}
	} else {
		process.SetExitCode(result.ExitCode)
		if setErr := pm.setProcessStopped(process, result.ExitCode); setErr != nil {
			log.Error().Err(setErr).Msg("Failed to set process stopped state")
		}
	}
	
	// Call appropriate callback
	if result.ExitCode == 0 && options.OnExit != nil {
		options.OnExit(process, result.ExitCode)
	} else if result.ExitCode != 0 && options.OnError != nil {
		options.OnError(process, fmt.Errorf("process exited with code %d", result.ExitCode))
	}
	
	return nil
}

// executeProcessAsync executes a process asynchronously
func (pm *ProcessManager) executeProcessAsync(ctx context.Context, process *ManagedProcess, options ProcessStartOptions, startTime time.Time) {
	defer pm.wg.Done()
	
	// Call start callback
	if options.OnStart != nil {
		options.OnStart(process)
	}
	
	// Execute the process
	if err := pm.executeProcess(ctx, process, options, startTime); err != nil {
		log.Error().
			Err(err).
			Str("process_id", process.ID).
			Msg("Async process execution failed")
	}
}

// setProcessStopped sets a process to stopped state
func (pm *ProcessManager) setProcessStopped(process *ManagedProcess, exitCode int32) error {
	if err := process.SetState(ProcessStateStopped, "Process completed"); err != nil {
		return err
	}
	
	process.SetExitCode(exitCode)
	
	// Update metrics
	pm.metrics.mu.Lock()
	pm.metrics.ProcessesCompleted++
	pm.metrics.ProcessesActive--
	pm.metrics.mu.Unlock()
	
	// Publish exit event
	if pm.eventBus != nil {
		pm.eventBus.PublishExit(process.ID, process.ContainerID, process.PID, exitCode, process.Duration())
	}
	
	// Remove from resource monitoring
	if pm.resourceMonitor != nil {
		pm.resourceMonitor.RemoveProcess(process.ID)
	}
	
	// Untrack from zombie reaper
	pm.zombieReaper.UntrackPID(process.PID)
	
	return nil
}

// setProcessFailed sets a process to failed state
func (pm *ProcessManager) setProcessFailed(process *ManagedProcess, err error) error {
	if setErr := process.SetState(ProcessStateFailed, err.Error()); setErr != nil {
		return setErr
	}
	
	process.SetError(err)
	
	// Update metrics
	pm.metrics.mu.Lock()
	pm.metrics.ProcessesFailed++
	pm.metrics.ProcessesActive--
	pm.metrics.mu.Unlock()
	
	// Publish error event
	if pm.eventBus != nil {
		pm.eventBus.PublishError(process.ID, process.ContainerID, process.PID, err)
	}
	
	// Remove from resource monitoring
	if pm.resourceMonitor != nil {
		pm.resourceMonitor.RemoveProcess(process.ID)
	}
	
	// Untrack from zombie reaper
	pm.zombieReaper.UntrackPID(process.PID)
	
	return nil
}

// sendSignal sends a signal to a process
func (pm *ProcessManager) sendSignal(pid int32, sig os.Signal) error {
	process, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, err)
	}
	
	return process.Signal(sig)
}

// getSignalName returns the name of a signal
func (pm *ProcessManager) getSignalName(sig os.Signal) string {
	switch sig {
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGQUIT:
		return "SIGQUIT"
	default:
		return fmt.Sprintf("SIG%d", sig)
	}
}

// updateStartTimeMetrics updates average start time metrics
func (pm *ProcessManager) updateStartTimeMetrics(duration time.Duration) {
	pm.metrics.mu.Lock()
	defer pm.metrics.mu.Unlock()
	
	if pm.metrics.AverageStartTime == 0 {
		pm.metrics.AverageStartTime = duration
	} else {
		pm.metrics.AverageStartTime = (pm.metrics.AverageStartTime + duration) / 2
	}
}

// generateProcessID generates a unique process ID
func (pm *ProcessManager) generateProcessID() string {
	return fmt.Sprintf("proc-%s", uuid.New().String()[:8])
}

// cleanupRoutine runs periodic cleanup of terminated processes
func (pm *ProcessManager) cleanupRoutine() {
	defer pm.wg.Done()
	
	ticker := time.NewTicker(pm.cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			pm.performCleanup()
		case <-pm.ctx.Done():
			return
		}
	}
}

// performCleanup removes terminated processes from tracking
func (pm *ProcessManager) performCleanup() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	var toRemove []string
	for id, process := range pm.processes {
		if process.IsTerminal() {
			// Keep processes for a while for potential queries
			if process.EndTime != nil && time.Since(*process.EndTime) > time.Hour {
				toRemove = append(toRemove, id)
			}
		}
	}
	
	for _, id := range toRemove {
		delete(pm.processes, id)
		log.Debug().Str("process_id", id).Msg("Cleaned up terminated process")
	}
	
	// Update metrics
	pm.metrics.mu.Lock()
	pm.metrics.LastCleanupTime = time.Now()
	pm.metrics.CleanupCycles++
	pm.metrics.mu.Unlock()
	
	if len(toRemove) > 0 {
		log.Debug().Int("cleaned", len(toRemove)).Msg("Process cleanup completed")
	}
}

// signalHandler handles system signals for graceful shutdown
func (pm *ProcessManager) signalHandler() {
	defer pm.wg.Done()
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	
	select {
	case sig := <-sigChan:
		log.Info().
			Str("signal", sig.String()).
			Msg("Received shutdown signal")
		
		// Trigger graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), pm.config.GracefulShutdownTimeout)
		defer cancel()
		
		if err := pm.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Error during signal-triggered shutdown")
		}
		
	case <-pm.ctx.Done():
		return
	}
}

// NewZombieReaper creates a new zombie reaper
func NewZombieReaper(interval time.Duration) *ZombieReaper {
	ctx, cancel := context.WithCancel(context.Background())
	
	reaper := &ZombieReaper{
		interval:    interval,
		ctx:         ctx,
		cancel:      cancel,
		trackedPIDs: make(map[int32]string),
		metrics:     &ZombieReaperMetrics{},
	}
	
	// Start reaping goroutine
	reaper.wg.Add(1)
	go reaper.reapRoutine()
	
	return reaper
}

// TrackPID adds a PID to be tracked for zombie cleanup
func (zr *ZombieReaper) TrackPID(pid int32, processID string) {
	zr.mu.Lock()
	defer zr.mu.Unlock()
	
	zr.trackedPIDs[pid] = processID
}

// UntrackPID removes a PID from zombie tracking
func (zr *ZombieReaper) UntrackPID(pid int32) {
	zr.mu.Lock()
	defer zr.mu.Unlock()
	
	delete(zr.trackedPIDs, pid)
}

// GetMetrics returns zombie reaper metrics
func (zr *ZombieReaper) GetMetrics() ZombieReaperMetrics {
	zr.metrics.mu.RLock()
	defer zr.metrics.mu.RUnlock()
	
	return *zr.metrics
}

// Shutdown gracefully shuts down the zombie reaper
func (zr *ZombieReaper) Shutdown(ctx context.Context) error {
	zr.cancel()
	
	done := make(chan struct{})
	go func() {
		zr.wg.Wait()
		close(done)
	}()
	
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		log.Info().Msg("Zombie reaper shut down successfully")
		return nil
	}
}

// reapRoutine runs the zombie reaping loop
func (zr *ZombieReaper) reapRoutine() {
	defer zr.wg.Done()
	
	ticker := time.NewTicker(zr.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			zr.performReap()
		case <-zr.ctx.Done():
			return
		}
	}
}

// performReap checks for and reaps zombie processes
func (zr *ZombieReaper) performReap() {
	zr.mu.RLock()
	trackedPIDs := make(map[int32]string)
	for pid, processID := range zr.trackedPIDs {
		trackedPIDs[pid] = processID
	}
	zr.mu.RUnlock()
	
	if len(trackedPIDs) == 0 {
		return
	}
	
	zr.metrics.mu.Lock()
	zr.metrics.ReapCycles++
	zr.metrics.mu.Unlock()
	
	for pid, processID := range trackedPIDs {
		if zr.isZombie(pid) {
			zr.metrics.mu.Lock()
			zr.metrics.ZombiesDetected++
			zr.metrics.mu.Unlock()
			
			if zr.reapZombie(pid) {
				zr.metrics.mu.Lock()
				zr.metrics.ZombiesReaped++
				zr.metrics.LastReapTime = time.Now()
				zr.metrics.mu.Unlock()
				
				// Remove from tracking
				zr.UntrackPID(pid)
				
				log.Debug().
					Int32("pid", pid).
					Str("process_id", processID).
					Msg("Reaped zombie process")
			}
		}
	}
}

// isZombie checks if a process is a zombie
func (zr *ZombieReaper) isZombie(pid int32) bool {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		// Process might have already been reaped
		return false
	}
	
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return false
	}
	
	// Field 2 is the process state: Z indicates zombie
	state := strings.Trim(fields[2], "()")
	return state == "Z"
}

// reapZombie attempts to reap a zombie process
func (zr *ZombieReaper) reapZombie(pid int32) bool {
	// Try to wait for the process to clean it up
	process, err := os.FindProcess(int(pid))
	if err != nil {
		return false
	}
	
	// Non-blocking wait to reap the zombie
	state, err := process.Wait()
	if err != nil {
		zr.metrics.mu.Lock()
		zr.metrics.ReapErrors++
		zr.metrics.mu.Unlock()
		return false
	}
	
	log.Debug().
		Int32("pid", pid).
		Bool("success", state.Success()).
		Msg("Successfully reaped zombie process")
	
	return true
}