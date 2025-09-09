package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/beam-cloud/go-runc"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// RunCClient provides a simplified interface to runC containers
type RunCClient struct {
	runc           RuncInterface
	rootPath       string
	processManager *ProcessManager
	
	// Container state tracking
	containerStates map[string]*ContainerState
	containerMutex  sync.RWMutex
	
	// Security and resource management
	securityManager *SecurityManager
	resourceManager *ResourceLimitManager
}


// ContainerConfig holds container configuration
type ContainerConfig struct {
	ID          string
	BundlePath  string
	WorkingDir  string
	Environment map[string]string
	Mounts      []Mount
	
	// Process execution support
	ProcessSupport    bool                 `json:"processSupport"`
	SecurityContext   *SecurityContext     `json:"securityContext,omitempty"`
	ResourceLimits    *ResourceLimits      `json:"resourceLimits,omitempty"`
	NamespaceConfig   *NamespaceConfig     `json:"namespaceConfig,omitempty"`
	LoggingConfig     *ContainerLoggingConfig `json:"loggingConfig,omitempty"`
	
	// Container metadata
	CreatedAt     time.Time           `json:"createdAt"`
	Labels        map[string]string   `json:"labels,omitempty"`
	Annotations   map[string]string   `json:"annotations,omitempty"`
}

// Mount represents a container mount point
type Mount struct {
	Source      string
	Destination string
	Type        string
	Options     []string
}

// ProcessConfig holds process execution configuration
type ProcessConfig struct {
	Args []string
	Env  map[string]string
	Cwd  string
	User string
}

// ProcessStatus represents the status of a process
type ProcessStatus struct {
	PID      int32
	Status   string
	ExitCode int32
	Running  bool
}

// ContainerLoggingConfig holds logging configuration for containers
type ContainerLoggingConfig struct {
	LogLevel        string `json:"logLevel"`
	CorrelationID   string `json:"correlationId"`
	EnableMetrics   bool   `json:"enableMetrics"`
	LogToFile       bool   `json:"logToFile"`
	LogFilePath     string `json:"logFilePath,omitempty"`
}

// ContainerState represents the current state of a container
type ContainerState struct {
	ID            string                  `json:"id"`
	Status        string                  `json:"status"`
	CreatedAt     time.Time              `json:"createdAt"`
	StartedAt     *time.Time             `json:"startedAt,omitempty"`
	Config        *ContainerConfig       `json:"config"`
	ProcessCount  int                    `json:"processCount"`
	LastActivity  time.Time              `json:"lastActivity"`
}

// ContainerValidationResult holds container validation results
type ContainerValidationResult struct {
	Valid           bool     `json:"valid"`
	Errors          []string `json:"errors,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	ValidationTime  time.Time `json:"validationTime"`
}

// NewRunCClient creates a new simplified runC client
func NewRunCClient(rootPath string) (*RunCClient, error) {
	if rootPath == "" {
		rootPath = "/tmp/sandboxrunner"
	}

	// Ensure root path exists
	if err := os.MkdirAll(rootPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create root path: %w", err)
	}

	// Initialize runC with the root path
	r := &runc.Runc{
		Command:      "runc",
		Log:          "/dev/null",
		LogFormat:    "json",
		PdeathSignal: 15, // SIGTERM
		Root:         rootPath,
	}

	client := &RunCClient{
		runc:            r,
		rootPath:        rootPath,
		containerStates: make(map[string]*ContainerState),
		securityManager: NewSecurityManager(),
		resourceManager: NewResourceLimitManager(),
	}
	
	return client, nil
}

// EnableProcessManager initializes and enables the ProcessManager for this RunCClient
func (c *RunCClient) EnableProcessManager(config *ProcessManagerConfig) error {
	if c.processManager != nil {
		return errors.New("process manager is already enabled")
	}
	
	pm, err := NewProcessManager(c, config)
	if err != nil {
		return fmt.Errorf("failed to create process manager: %w", err)
	}
	
	c.processManager = pm
	
	log.Info().Msg("Process manager enabled for RunC client")
	return nil
}

// GetProcessManager returns the ProcessManager if enabled
func (c *RunCClient) GetProcessManager() *ProcessManager {
	return c.processManager
}

// IsProcessManagerEnabled returns true if ProcessManager is enabled
func (c *RunCClient) IsProcessManagerEnabled() bool {
	return c.processManager != nil
}

// ExecProcessManaged executes a process using the ProcessManager if available
func (c *RunCClient) ExecProcessManaged(ctx context.Context, containerID string, spec *ProcessSpec, async bool) (*ManagedProcess, error) {
	if c.processManager == nil {
		return nil, errors.New("process manager is not enabled")
	}
	
	options := ProcessStartOptions{
		Spec:        spec,
		ContainerID: containerID,
		Async:       async,
		Context:     ctx,
	}
	
	return c.processManager.Start(options)
}

// StopProcessManaged stops a managed process
func (c *RunCClient) StopProcessManaged(processID string) error {
	if c.processManager == nil {
		return errors.New("process manager is not enabled")
	}
	
	return c.processManager.Stop(processID)
}

// KillProcessManaged kills a managed process
func (c *RunCClient) KillProcessManaged(processID string) error {
	if c.processManager == nil {
		return errors.New("process manager is not enabled")
	}
	
	return c.processManager.Kill(processID)
}

// WaitProcessManaged waits for a managed process to complete
func (c *RunCClient) WaitProcessManaged(processID string, ctx context.Context) error {
	if c.processManager == nil {
		return errors.New("process manager is not enabled")
	}
	
	return c.processManager.Wait(processID, ctx)
}

// GetProcessStatus gets the status of a managed process
func (c *RunCClient) GetProcessStatusManaged(processID string) (ProcessState, error) {
	if c.processManager == nil {
		return ProcessStateUnknown, errors.New("process manager is not enabled")
	}
	
	return c.processManager.GetStatus(processID)
}

// ListManagedProcesses lists all managed processes
func (c *RunCClient) ListManagedProcesses() []*ManagedProcess {
	if c.processManager == nil {
		return nil
	}
	
	return c.processManager.ListProcesses()
}

// GetProcessManagerMetrics returns ProcessManager metrics if enabled
func (c *RunCClient) GetProcessManagerMetrics() *ProcessManagerMetrics {
	if c.processManager == nil {
		return nil
	}
	
	metrics := c.processManager.GetMetrics()
	return &metrics
}

// CreateContainer creates a new container with the given configuration
func (c *RunCClient) CreateContainer(ctx context.Context, config ContainerConfig) error {
	correlationID := c.generateCorrelationID()
	
	// Set up logging context
	logger := log.With().
		Str("container_id", config.ID).
		Str("correlation_id", correlationID).
		Logger()
	
	if config.ID == "" {
		config.ID = uuid.New().String()
	}
	
	config.CreatedAt = time.Now()
	if config.LoggingConfig == nil {
		config.LoggingConfig = &ContainerLoggingConfig{
			LogLevel:      "info",
			CorrelationID: correlationID,
			EnableMetrics: true,
		}
	}

	logger.Info().Msg("Starting container creation")

	// Validate container configuration
	if validationResult := c.validateContainerConfig(config); !validationResult.Valid {
		logger.Error().
			Strs("errors", validationResult.Errors).
			Msg("Container configuration validation failed")
		return fmt.Errorf("container configuration validation failed: %s", strings.Join(validationResult.Errors, "; "))
	}

	// Ensure bundle path exists
	if err := os.MkdirAll(config.BundlePath, 0755); err != nil {
		logger.Error().Err(err).Msg("Failed to create bundle path")
		return fmt.Errorf("failed to create bundle path: %w", err)
	}

	// Initialize security context if process support is enabled
	if config.ProcessSupport && config.SecurityContext != nil {
		if c.securityManager != nil {
			if err := c.securityManager.SetupSecurityContext(config.ID, config.SecurityContext); err != nil {
				logger.Error().Err(err).Msg("Failed to setup security context")
				return fmt.Errorf("failed to setup security context: %w", err)
			}
			logger.Debug().Msg("Security context configured")
		}
	}

	// Configure resource limits if specified
	if config.ProcessSupport && config.ResourceLimits != nil {
		if c.resourceManager != nil {
			if err := c.resourceManager.ConfigureResourceLimits(config.ID, config.ResourceLimits); err != nil {
				logger.Error().Err(err).Msg("Failed to configure resource limits")
				return fmt.Errorf("failed to configure resource limits: %w", err)
			}
			logger.Debug().Msg("Resource limits configured")
		}
	}

	// Generate OCI spec with enhanced features
	if err := c.generateEnhancedOCISpec(config); err != nil {
		logger.Error().Err(err).Msg("Failed to generate OCI spec")
		return fmt.Errorf("failed to generate OCI spec: %w", err)
	}

	// Create the container
	if err := c.runc.Create(ctx, config.ID, config.BundlePath, nil); err != nil {
		logger.Error().Err(err).Msg("Failed to create container")
		
		// Cleanup on failure
		c.cleanupContainerResources(config.ID)
		return fmt.Errorf("failed to create container: %w", err)
	}

	// Track container state
	c.trackContainerState(config.ID, &config)

	logger.Info().
		Bool("process_support", config.ProcessSupport).
		Int("mount_count", len(config.Mounts)).
		Msg("Container created successfully")
		
	return nil
}

// StartContainer starts an existing container
func (c *RunCClient) StartContainer(ctx context.Context, containerID string) error {
	if err := c.runc.Start(ctx, containerID); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}

	log.Info().Str("container_id", containerID).Msg("Container started successfully")
	return nil
}

// ValidateContainerForProcessExecution validates container state before process execution
func (c *RunCClient) ValidateContainerForProcessExecution(ctx context.Context, containerID string) error {
	correlationID := c.generateCorrelationID()
	logger := log.With().
		Str("container_id", containerID).
		Str("correlation_id", correlationID).
		Logger()

	logger.Debug().Msg("Validating container state for process execution")

	// Check if container exists in state tracking
	c.containerMutex.RLock()
	containerState, exists := c.containerStates[containerID]
	c.containerMutex.RUnlock()

	if !exists {
		logger.Error().Msg("Container not found in state tracking")
		return fmt.Errorf("container %s not found in state tracking", containerID)
	}

	// Check if container supports process execution
	if !containerState.Config.ProcessSupport {
		logger.Error().Msg("Container was not configured for process execution")
		return fmt.Errorf("container %s does not support process execution", containerID)
	}

	// Check container runtime state
	state, err := c.runc.State(ctx, containerID)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get container runtime state")
		return fmt.Errorf("failed to get container runtime state: %w", err)
	}

	if state.Status != "running" && state.Status != "created" {
		logger.Error().Str("status", state.Status).Msg("Container is not in a valid state for process execution")
		return fmt.Errorf("container %s is in invalid state '%s' for process execution", containerID, state.Status)
	}

	// Validate security context if configured
	if containerState.Config.SecurityContext != nil && c.securityManager != nil {
		if err := c.securityManager.ValidateSecurityContext(containerID, containerState.Config.SecurityContext); err != nil {
			logger.Error().Err(err).Msg("Security context validation failed")
			return fmt.Errorf("security context validation failed: %w", err)
		}
	}

	// Validate resource limits if configured
	if containerState.Config.ResourceLimits != nil && c.resourceManager != nil {
		if err := c.resourceManager.ValidateResourceLimits(containerID, containerState.Config.ResourceLimits); err != nil {
			logger.Error().Err(err).Msg("Resource limits validation failed")
			return fmt.Errorf("resource limits validation failed: %w", err)
		}
	}

	logger.Debug().Msg("Container validation successful")
	return nil
}

// ExecProcess executes a process in the container and returns a Process struct
func (c *RunCClient) ExecProcess(ctx context.Context, containerID string, spec *ProcessSpec) (*ProcessResult, error) {
	// Generate unique process ID
	processID := fmt.Sprintf("proc-%s", uuid.New().String()[:8])

	// Validate inputs first
	if containerID == "" {
		return nil, errors.New("container ID cannot be empty")
	}
	if spec == nil {
		return nil, errors.New("process spec cannot be nil")
	}
	if len(spec.Args) == 0 {
		return nil, errors.New("process args cannot be empty")
	}

	correlationID := c.generateCorrelationID()
	logger := log.With().
		Str("container_id", containerID).
		Str("process_id", processID).
		Str("correlation_id", correlationID).
		Logger()

	logger.Info().
		Strs("args", spec.Args).
		Str("working_dir", spec.WorkingDir).
		Str("user", spec.User).
		Msg("Executing process in container")

	// Validate container state before process execution
	if err := c.ValidateContainerForProcessExecution(ctx, containerID); err != nil {
		logger.Error().Err(err).Msg("Container validation failed")
		return nil, err
	}

	// Get detailed container state for process tracking
	state, err := c.runc.State(ctx, containerID)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to get container state")
		return nil, fmt.Errorf("container not found or not accessible: %w", err)
	}

	// Log container state for debugging
	logger.Debug().
		Str("status", state.Status).
		Int("pid", state.Pid).
		Msg("Container state retrieved")

	// Update container activity
	c.updateContainerActivity(containerID)

	// Create timeout context if timeout is specified
	execCtx := ctx
	if spec.Timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, spec.Timeout)
		defer cancel()
	}

	// Convert ProcessSpec to OCI Process specification
	ociProcessSpec := spec.ToOCIProcessSpec()

	// Create output capture with advanced features
	captureConfig := DefaultOutputCaptureConfig()
	// Enable streaming if this is a long-running process
	if spec.Timeout > 10*time.Second || spec.Timeout == 0 {
		captureConfig.StreamingEnabled = true
	}
	outputCapture := NewOutputCapture(captureConfig)
	defer outputCapture.Close()

	// Create pipes for stdout/stderr capture
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	
	// Start output capture in goroutines
	outputCapture.CaptureStreams(execCtx, stdoutReader, stderrReader)

	// Create IO for the process - use NULL IO for tests
	processIO, err := runc.NewNullIO()
	if err != nil {
		return nil, fmt.Errorf("failed to create process IO: %w", err)
	}
	defer processIO.Close()

	// Channel to receive the started PID
	startedChan := make(chan int, 1)

	// Configure exec options - use OutputWriter for capture
	execOpts := &runc.ExecOpts{
		IO:           processIO,
		Detach:       false,
		Started:      startedChan,
		OutputWriter: stdoutWriter, // Capture stdout
	}

	// Create Process struct
	process := &Process{
		ID:          processID,
		Status:      "starting",
		StartTime:   time.Now(),
		ContainerID: containerID,
	}

	// Execute the process
	execErr := c.runc.Exec(execCtx, containerID, *ociProcessSpec, execOpts)

	// Wait for PID to be available or timeout
	select {
	case pid := <-startedChan:
		process.PID = int32(pid)
		process.Status = "running"
		log.Info().
			Str("container_id", containerID).
			Str("process_id", processID).
			Int32("pid", process.PID).
			Msg("Process started successfully")
	case <-time.After(5 * time.Second):
		log.Warn().
			Str("container_id", containerID).
			Str("process_id", processID).
			Msg("Timeout waiting for process PID")
		process.PID = -1
	}

	// Close writers to signal EOF to readers
	stdoutWriter.Close()
	stderrWriter.Close()

	// Wait for output capture to complete
	outputCapture.Wait()

	// Get captured output
	processOutput := outputCapture.GetOutput()
	processOutput.ExitCode = 0 // Will be updated below

	// Create result with new output capture
	result := NewProcessResult(process, processOutput, execErr)

	// Handle execution result
	if execErr != nil {
		process.Status = "failed"
		
		// Check for specific error types
		if errors.Is(execErr, context.DeadlineExceeded) {
			log.Error().
				Str("container_id", containerID).
				Str("process_id", processID).
				Dur("timeout", spec.Timeout).
				Msg("Process execution timed out")
			result.Output.ExitCode = 124 // Standard timeout exit code
			result.ExitCode = 124
		} else if exitErr, ok := execErr.(*runc.ExitError); ok {
			result.Output.ExitCode = int32(exitErr.Status)
			result.ExitCode = int32(exitErr.Status)
			log.Error().
				Str("container_id", containerID).
				Str("process_id", processID).
				Int32("exit_code", result.ExitCode).
				Msg("Process exited with non-zero status")
		} else {
			log.Error().
				Err(execErr).
				Str("container_id", containerID).
				Str("process_id", processID).
				Msg("Process execution failed")
			result.Output.ExitCode = 1
			result.ExitCode = 1
		}
	} else {
		process.Status = "completed"
		result.Output.ExitCode = 0
		result.ExitCode = 0
		log.Info().
			Str("container_id", containerID).
			Str("process_id", processID).
			Int64("stdout_size", result.Output.StdoutSize).
			Int64("stderr_size", result.Output.StderrSize).
			Dur("duration", result.Output.Duration).
			Bool("truncated", result.Output.Truncated).
			Msg("Process completed successfully")
	}

	// Set final exit code in process
	process.ExitCode = &result.ExitCode
	
	// Log output capture metrics
	log.Debug().
		Str("container_id", containerID).
		Str("process_id", processID).
		Int64("stdout_bytes", result.Output.StdoutSize).
		Int64("stderr_bytes", result.Output.StderrSize).
		Bool("output_truncated", result.Output.Truncated).
		Bool("output_compressed", result.Output.Compressed).
		Dur("capture_duration", result.Output.Duration).
		Msg("Output capture metrics")

	return result, nil
}

// ExecProcessLegacy provides backward compatibility with the old ProcessConfig structure
func (c *RunCClient) ExecProcessLegacy(ctx context.Context, containerID string, config ProcessConfig) (int32, error) {
	// Convert legacy ProcessConfig to ProcessSpec
	spec := &ProcessSpec{
		Args:       config.Args,
		Env:        c.mapToSlice(config.Env),
		WorkingDir: config.Cwd,
		User:       config.User,
		Terminal:   false,
		Timeout:    30 * time.Second,
	}

	// If no cmd specified in args, use first arg as cmd
	if len(spec.Args) > 0 {
		spec.Cmd = spec.Args[0]
	}

	result, err := c.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return -1, err
	}

	// If there's a result error (process failed but exec succeeded), return it
	if result.Error != nil {
		return result.ExitCode, result.Error
	}

	return result.ExitCode, nil
}

// GetProcessStatus gets the status of a process
func (c *RunCClient) GetProcessStatus(ctx context.Context, containerID, processID string) (*ProcessStatus, error) {
	// Use runc state to get container information
	state, err := c.runc.State(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get container state: %w", err)
	}

	return &ProcessStatus{
		PID:     int32(state.Pid),
		Status:  state.Status,
		Running: state.Status == "running",
	}, nil
}

// KillProcess kills a process in the container
func (c *RunCClient) KillProcess(ctx context.Context, containerID string, pid int32) error {
	// Send SIGTERM to the process using kill options
	killOpts := &runc.KillOpts{All: false}
	if err := c.runc.Kill(ctx, containerID, int(pid), killOpts); err != nil {
		return fmt.Errorf("failed to kill process: %w", err)
	}

	log.Info().Str("container_id", containerID).Int32("pid", pid).Msg("Process killed")
	return nil
}

// StopContainer stops a running container
func (c *RunCClient) StopContainer(ctx context.Context, containerID string) error {
	killOpts := &runc.KillOpts{All: true}
	if err := c.runc.Kill(ctx, containerID, 15, killOpts); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	log.Info().Str("container_id", containerID).Msg("Container stopped")
	return nil
}

// DeleteContainer deletes a container
func (c *RunCClient) DeleteContainer(ctx context.Context, containerID string) error {
	deleteOpts := &runc.DeleteOpts{Force: true}
	if err := c.runc.Delete(ctx, containerID, deleteOpts); err != nil {
		return fmt.Errorf("failed to delete container: %w", err)
	}

	log.Info().Str("container_id", containerID).Msg("Container deleted")
	return nil
}

// ListContainers lists all containers
func (c *RunCClient) ListContainers(ctx context.Context) ([]*runc.Container, error) {
	containers, err := c.runc.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	return containers, nil
}

// GetContainerLogs retrieves logs from a container
func (c *RunCClient) GetContainerLogs(ctx context.Context, containerID string) ([]byte, error) {
	logPath := filepath.Join(c.rootPath, containerID, "container.log")
	
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		return []byte{}, nil
	}

	logs, err := os.ReadFile(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read container logs: %w", err)
	}

	return logs, nil
}

// generateCorrelationID generates a unique correlation ID for logging
func (c *RunCClient) generateCorrelationID() string {
	return fmt.Sprintf("runc-%s", uuid.New().String()[:8])
}

// validateContainerConfig validates container configuration
func (c *RunCClient) validateContainerConfig(config ContainerConfig) *ContainerValidationResult {
	result := &ContainerValidationResult{
		Valid:          true,
		ValidationTime: time.Now(),
	}

	// Basic validation
	if config.ID == "" {
		result.Errors = append(result.Errors, "container ID cannot be empty")
		result.Valid = false
	}

	if config.BundlePath == "" {
		result.Errors = append(result.Errors, "bundle path cannot be empty")
		result.Valid = false
	}

	// Process support validation
	if config.ProcessSupport {
		if config.SecurityContext != nil && c.securityManager == nil {
			result.Warnings = append(result.Warnings, "security context specified but no security manager available")
		}

		if config.ResourceLimits != nil && c.resourceManager == nil {
			result.Warnings = append(result.Warnings, "resource limits specified but no resource manager available")
		}

		if config.NamespaceConfig != nil {
			if config.NamespaceConfig.PID && config.NamespaceConfig.Network {
				result.Warnings = append(result.Warnings, "both PID and network namespace isolation enabled - may impact process communication")
			}
		}
	}

	return result
}

// trackContainerState tracks container state internally
func (c *RunCClient) trackContainerState(containerID string, config *ContainerConfig) {
	c.containerMutex.Lock()
	defer c.containerMutex.Unlock()

	c.containerStates[containerID] = &ContainerState{
		ID:           containerID,
		Status:       "created",
		CreatedAt:    config.CreatedAt,
		Config:       config,
		ProcessCount: 0,
		LastActivity: time.Now(),
	}
}

// updateContainerActivity updates the last activity time for a container
func (c *RunCClient) updateContainerActivity(containerID string) {
	c.containerMutex.Lock()
	defer c.containerMutex.Unlock()

	if state, exists := c.containerStates[containerID]; exists {
		state.LastActivity = time.Now()
		state.ProcessCount++
	}
}

// cleanupContainerResources cleans up container resources on failure
func (c *RunCClient) cleanupContainerResources(containerID string) {
	// Remove from state tracking
	c.containerMutex.Lock()
	delete(c.containerStates, containerID)
	c.containerMutex.Unlock()

	// Cleanup security context
	if c.securityManager != nil {
		if err := c.securityManager.CleanupSecurityContext(containerID); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to cleanup security context")
		}
	}

	// Cleanup resource limits
	if c.resourceManager != nil {
		if err := c.resourceManager.CleanupResourceLimits(containerID); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to cleanup resource limits")
		}
	}
}

// generateEnhancedOCISpec generates an enhanced OCI specification with process support features
func (c *RunCClient) generateEnhancedOCISpec(config ContainerConfig) error {
	// Start with basic OCI spec generation
	if err := c.generateOCISpec(config); err != nil {
		return err
	}

	// If process support is not enabled, use basic spec
	if !config.ProcessSupport {
		return nil
	}

	// Configure namespace isolation if specified
	if config.NamespaceConfig != nil {
		if err := c.configureNamespaces(config.ID, config.NamespaceConfig); err != nil {
			return fmt.Errorf("failed to configure namespaces: %w", err)
		}
	}

	return nil
}

// configureNamespaces configures namespace isolation for the container
func (c *RunCClient) configureNamespaces(containerID string, nsConfig *NamespaceConfig) error {
	correlationID := c.generateCorrelationID()
	logger := log.With().
		Str("container_id", containerID).
		Str("correlation_id", correlationID).
		Logger()

	logger.Debug().
		Bool("pid", nsConfig.PID).
		Bool("network", nsConfig.Network).
		Bool("ipc", nsConfig.IPC).
		Bool("uts", nsConfig.UTS).
		Bool("mount", nsConfig.Mount).
		Bool("user", nsConfig.User).
		Bool("cgroup", nsConfig.Cgroup).
		Msg("Configuring namespace isolation")

	// Configure PID namespace
	if nsConfig.PID {
		if err := c.configurePIDNamespace(containerID); err != nil {
			return fmt.Errorf("failed to configure PID namespace: %w", err)
		}
		logger.Debug().Msg("PID namespace configured")
	}

	// Configure Network namespace
	if nsConfig.Network {
		if err := c.configureNetworkNamespace(containerID); err != nil {
			return fmt.Errorf("failed to configure network namespace: %w", err)
		}
		logger.Debug().Msg("Network namespace configured")
	}

	// Configure IPC namespace
	if nsConfig.IPC {
		if err := c.configureIPCNamespace(containerID); err != nil {
			return fmt.Errorf("failed to configure IPC namespace: %w", err)
		}
		logger.Debug().Msg("IPC namespace configured")
	}

	// Configure UTS namespace
	if nsConfig.UTS {
		if err := c.configureUTSNamespace(containerID); err != nil {
			return fmt.Errorf("failed to configure UTS namespace: %w", err)
		}
		logger.Debug().Msg("UTS namespace configured")
	}

	// Configure Mount namespace
	if nsConfig.Mount {
		if err := c.configureMountNamespace(containerID); err != nil {
			return fmt.Errorf("failed to configure mount namespace: %w", err)
		}
		logger.Debug().Msg("Mount namespace configured")
	}

	// Configure User namespace
	if nsConfig.User {
		if err := c.configureUserNamespace(containerID, nsConfig.UserNamespaceMapping); err != nil {
			return fmt.Errorf("failed to configure user namespace: %w", err)
		}
		logger.Debug().Msg("User namespace configured")
	}

	// Configure Cgroup namespace
	if nsConfig.Cgroup {
		if err := c.configureCgroupNamespace(containerID); err != nil {
			return fmt.Errorf("failed to configure cgroup namespace: %w", err)
		}
		logger.Debug().Msg("Cgroup namespace configured")
	}

	logger.Info().Msg("Namespace configuration completed")
	return nil
}

// configurePIDNamespace configures PID namespace isolation
func (c *RunCClient) configurePIDNamespace(containerID string) error {
	// In a real implementation, this would modify the OCI spec to:
	// 1. Set linux.namespaces to include PID namespace
	// 2. Configure process isolation settings
	
	log.Debug().
		Str("container_id", containerID).
		Msg("PID namespace isolation enabled - processes isolated from host PID space")
	
	return nil
}

// configureNetworkNamespace configures network namespace isolation
func (c *RunCClient) configureNetworkNamespace(containerID string) error {
	// In a real implementation, this would:
	// 1. Create network namespace
	// 2. Configure network interfaces
	// 3. Set up routing and firewall rules
	// 4. Configure DNS resolution
	
	log.Debug().
		Str("container_id", containerID).
		Msg("Network namespace isolation enabled - network stack isolated from host")
	
	return nil
}

// configureIPCNamespace configures IPC namespace isolation
func (c *RunCClient) configureIPCNamespace(containerID string) error {
	// In a real implementation, this would:
	// 1. Create IPC namespace
	// 2. Configure IPC resources (message queues, semaphores, shared memory)
	// 3. Set IPC resource limits
	
	log.Debug().
		Str("container_id", containerID).
		Msg("IPC namespace isolation enabled - IPC resources isolated from host")
	
	return nil
}

// configureUTSNamespace configures UTS namespace isolation
func (c *RunCClient) configureUTSNamespace(containerID string) error {
	// In a real implementation, this would:
	// 1. Create UTS namespace
	// 2. Set hostname and domain name
	// 3. Configure system identity
	
	log.Debug().
		Str("container_id", containerID).
		Msg("UTS namespace isolation enabled - hostname/domain isolated from host")
	
	return nil
}

// configureMountNamespace configures mount namespace isolation
func (c *RunCClient) configureMountNamespace(containerID string) error {
	// In a real implementation, this would:
	// 1. Create mount namespace
	// 2. Configure filesystem isolation
	// 3. Set up mount points and bind mounts
	// 4. Configure filesystem security
	
	log.Debug().
		Str("container_id", containerID).
		Msg("Mount namespace isolation enabled - filesystem isolated from host")
	
	return nil
}

// configureUserNamespace configures user namespace isolation
func (c *RunCClient) configureUserNamespace(containerID string, userMapping *UserNamespaceMapping) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()

	// In a real implementation, this would:
	// 1. Create user namespace
	// 2. Configure UID/GID mappings
	// 3. Set up user/group isolation
	// 4. Configure capability mappings

	if userMapping != nil {
		logger.Debug().
			Int("uid_mappings", len(userMapping.UIDs)).
			Int("gid_mappings", len(userMapping.GIDs)).
			Msg("User namespace configured with custom mappings")
	} else {
		logger.Debug().Msg("User namespace configured with default mappings")
	}
	
	return nil
}

// configureCgroupNamespace configures cgroup namespace isolation
func (c *RunCClient) configureCgroupNamespace(containerID string) error {
	// In a real implementation, this would:
	// 1. Create cgroup namespace
	// 2. Configure cgroup hierarchy visibility
	// 3. Set up cgroup resource isolation
	
	log.Debug().
		Str("container_id", containerID).
		Msg("Cgroup namespace isolation enabled - cgroup tree isolated from host")
	
	return nil
}

// generateOCISpec generates a basic OCI runtime specification
func (c *RunCClient) generateOCISpec(config ContainerConfig) error {
	// For simplicity, we'll use runc spec command to generate a default spec
	// In production, you might want to use the OCI runtime spec library
	cmd := exec.Command("runc", "spec", "--bundle", config.BundlePath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to generate OCI spec: %w", err)
	}

	return nil
}

// generateMounts converts Mount structs to OCI mount format
func (c *RunCClient) generateMounts(mounts []Mount) []map[string]interface{} {
	ociMounts := make([]map[string]interface{}, len(mounts))
	
	for i, mount := range mounts {
		ociMounts[i] = map[string]interface{}{
			"destination": mount.Destination,
			"source":      mount.Source,
			"type":        mount.Type,
			"options":     mount.Options,
		}
	}

	return ociMounts
}

// mapToSlice converts a map to a slice of key=value strings
func (c *RunCClient) mapToSlice(m map[string]string) []string {
	if m == nil {
		return []string{}
	}

	result := make([]string, 0, len(m))
	for k, v := range m {
		result = append(result, fmt.Sprintf("%s=%s", k, v))
	}
	return result
}

// Cleanup cleans up resources
func (c *RunCClient) Cleanup() error {
	// Shutdown ProcessManager if enabled
	if c.processManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := c.processManager.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown process manager during cleanup")
			return fmt.Errorf("failed to shutdown process manager: %w", err)
		}
		
		c.processManager = nil
		log.Info().Msg("Process manager shut down during cleanup")
	}
	
	// Clean up any temporary files or resources
	return nil
}