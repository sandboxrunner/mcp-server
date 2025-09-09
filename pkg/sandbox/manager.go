package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
)

// SandboxStatus represents the current state of a sandbox
type SandboxStatus string

const (
	SandboxStatusCreating SandboxStatus = "creating"
	SandboxStatusRunning  SandboxStatus = "running"
	SandboxStatusStopped  SandboxStatus = "stopped"
	SandboxStatusError    SandboxStatus = "error"
)

// Common errors
var (
	ErrSandboxNotFound = errors.New("sandbox not found")
)

// Sandbox represents a sandbox instance
type Sandbox struct {
	ID          string                 `json:"id"`
	ContainerID string                 `json:"container_id"`
	Status      SandboxStatus          `json:"status"`
	WorkingDir  string                 `json:"working_dir"`
	Environment map[string]string      `json:"environment"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Config      SandboxConfig          `json:"config"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SandboxConfig holds sandbox configuration
type SandboxConfig struct {
	Image         string                 `json:"image"`
	WorkspaceDir  string                 `json:"workspace_dir"`
	Environment   map[string]string      `json:"environment"`
	Mounts        []MountConfig          `json:"mounts"`
	Resources     ResourceLimits         `json:"resources"`
	NetworkMode   string                 `json:"network_mode"`
	EnableLogging bool                   `json:"enable_logging"`
	
	// Phase 2.1: Enhanced configuration
	NetworkConfig   *runtime.NetworkConfig `json:"network_config,omitempty"`
	RecoveryPolicy  *RecoveryPolicy        `json:"recovery_policy,omitempty"`
	EnableRecovery  bool                   `json:"enable_recovery"`
}

// MountConfig represents a mount configuration
type MountConfig struct {
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Options     []string `json:"options"`
}

// ResourceLimits defines resource constraints
type ResourceLimits struct {
	CPULimit    string `json:"cpu_limit"`
	MemoryLimit string `json:"memory_limit"`
	DiskLimit   string `json:"disk_limit"`
}

// Manager manages sandbox instances
type Manager struct {
	db           *sql.DB
	runcClient   *runtime.RunCClient
	workspaceDir string
	sandboxes    map[string]*Sandbox
	mu           sync.RWMutex
	
	// Phase 2.1: Container Lifecycle Management
	stateMachine     *StateMachine
	healthChecker    *HealthChecker
	eventBus         *EventBus
	metricsCollector *MetricsCollector
	
	// Phase 2.1: Recovery and Networking
	recoveryManager  *RecoveryManager
	networkManager   *runtime.NetworkManager
}

// NewManager creates a new sandbox manager
func NewManager(dbPath, workspaceDir string) (*Manager, error) {
	// Create workspace directory
	if err := os.MkdirAll(workspaceDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// Initialize SQLite database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables
	if err := createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	// Initialize runC client
	runcClient, err := runtime.NewRunCClient(filepath.Join(workspaceDir, "runc"))
	if err != nil {
		return nil, fmt.Errorf("failed to create runc client: %w", err)
	}

	manager := &Manager{
		db:           db,
		runcClient:   runcClient,
		workspaceDir: workspaceDir,
		sandboxes:    make(map[string]*Sandbox),
	}

	// Initialize state machine
	stateMachine, err := NewStateMachine(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create state machine: %w", err)
	}
	manager.stateMachine = stateMachine

	// Initialize event bus with database persistence
	eventPersistence, err := NewDatabaseEventPersistence(db)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create event persistence, using in-memory only")
		eventPersistence = nil
	}
	manager.eventBus = NewEventBus(1000, eventPersistence)

	// Initialize health checker
	healthConfig := DefaultHealthCheckConfig()
	healthChecker, err := NewHealthChecker(db, runcClient, healthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create health checker: %w", err)
	}
	manager.healthChecker = healthChecker

	// Wire up event handlers
	manager.setupEventHandlers()

	// Initialize metrics collector
	metricsCollector := NewMetricsCollector(manager, 30*time.Second)
	manager.metricsCollector = metricsCollector

	// Initialize recovery manager
	recoveryManager, err := NewRecoveryManager(db, runcClient, stateMachine, manager.eventBus)
	if err != nil {
		return nil, fmt.Errorf("failed to create recovery manager: %w", err)
	}
	manager.recoveryManager = recoveryManager

	// Initialize network manager
	networkConfig := runtime.DefaultNetworkManagerConfig()
	networkConfig.NetnsPath = filepath.Join(workspaceDir, "netns")
	networkManager, err := runtime.NewNetworkManager(networkConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create network manager: %w", err)
	}
	manager.networkManager = networkManager

	// Load existing sandboxes from database
	if err := manager.loadSandboxes(); err != nil {
		log.Warn().Err(err).Msg("Failed to load existing sandboxes")
	}

	return manager, nil
}

// setupEventHandlers wires up event handlers for state changes and health alerts
func (m *Manager) setupEventHandlers() {
	// Register state change callback
	m.stateMachine.RegisterCallback(func(transition StateTransition) {
		// Publish state change event
		event := NewStateChangeEvent(transition.ContainerID, "sandbox-manager", transition)
		m.eventBus.Publish(event)

		// Update sandbox status to match state machine
		m.mu.Lock()
		if sandbox, exists := m.sandboxes[transition.ContainerID]; exists {
			switch transition.To {
			case ContainerStateCreating:
				sandbox.Status = SandboxStatusCreating
			case ContainerStateRunning:
				sandbox.Status = SandboxStatusRunning
			case ContainerStateStopped:
				sandbox.Status = SandboxStatusStopped
			case ContainerStateFailed:
				sandbox.Status = SandboxStatusError
			}
			sandbox.UpdatedAt = time.Now()
			m.saveSandbox(sandbox)
		}
		m.mu.Unlock()
	})

	// Register health alert callback
	m.healthChecker.RegisterAlertCallback(func(result HealthCheckResult) {
		// Publish health alert event
		event := NewHealthAlertEvent(result.ContainerID, "health-checker", result)
		m.eventBus.Publish(event)

		// If container is unhealthy, update state machine
		if result.Status == HealthStatusUnhealthy {
			if result.CheckType == HealthCheckTypeLiveness {
				// Liveness failure means container is likely failed
				m.stateMachine.SetState(result.ContainerID, ContainerStateFailed, 
					"Health check failure", map[string]interface{}{
						"check_type": result.CheckType,
						"message": result.Message,
					})
			}
		}
	})
}

// CreateSandbox creates a new sandbox with the given configuration
func (m *Manager) CreateSandbox(ctx context.Context, config SandboxConfig) (*Sandbox, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandboxID := uuid.New().String()
	containerID := fmt.Sprintf("sandbox-%s", sandboxID[:8])
	
	sandbox := &Sandbox{
		ID:          sandboxID,
		ContainerID: containerID,
		Status:      SandboxStatusCreating,
		WorkingDir:  filepath.Join(m.workspaceDir, sandboxID),
		Environment: config.Environment,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Config:      config,
		Metadata:    make(map[string]interface{}),
	}

	// Initialize state machine tracking
	err := m.stateMachine.SetState(containerID, ContainerStateCreating, "Sandbox creation started", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to set initial container state: %w", err)
	}

	// Create sandbox workspace directory
	if err := os.MkdirAll(sandbox.WorkingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create sandbox workspace: %w", err)
	}

	// Create container configuration
	containerConfig := runtime.ContainerConfig{
		ID:         containerID,
		BundlePath: filepath.Join(sandbox.WorkingDir, "bundle"),
		WorkingDir: config.WorkspaceDir,
		Environment: config.Environment,
		Mounts:     m.convertMounts(config.Mounts, sandbox.WorkingDir),
	}

	// Create rootfs directory
	rootfsPath := filepath.Join(containerConfig.BundlePath, "rootfs")
	if err := os.MkdirAll(rootfsPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create rootfs: %w", err)
	}

	// Create basic filesystem structure
	if err := m.createBasicFilesystem(rootfsPath); err != nil {
		return nil, fmt.Errorf("failed to create basic filesystem: %w", err)
	}

	// Create the container
	if err := m.runcClient.CreateContainer(ctx, containerConfig); err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	// Start the container
	if err := m.runcClient.StartContainer(ctx, containerID); err != nil {
		// Update state to failed on start failure
		m.stateMachine.SetStateWithError(containerID, ContainerStateFailed, "Container start failed", 
			err.Error(), nil)
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Update state machine to running
	err = m.stateMachine.SetState(containerID, ContainerStateRunning, "Container started successfully", nil)
	if err != nil {
		log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to update state machine")
	}

	sandbox.Status = SandboxStatusRunning
	sandbox.UpdatedAt = time.Now()

	// Store in memory and database
	m.sandboxes[sandboxID] = sandbox
	if err := m.saveSandbox(sandbox); err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandboxID).Msg("Failed to save sandbox to database")
	}

	// Setup container networking
	if config.NetworkConfig != nil {
		if err := m.networkManager.SetupContainerNetwork(ctx, containerID, config.NetworkConfig); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to setup container networking")
		}
	}

	// Configure recovery if enabled
	if config.EnableRecovery {
		if err := m.recoveryManager.EnableRecovery(containerID); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to enable recovery")
		}
		
		// Set custom recovery policy if provided
		if config.RecoveryPolicy != nil {
			if err := m.recoveryManager.SetRecoveryPolicy(containerID, config.RecoveryPolicy); err != nil {
				log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to set recovery policy")
			}
		}
	}

	// Add container to health monitoring
	m.healthChecker.AddContainer(containerID, nil)

	log.Info().Str("sandbox_id", sandboxID).Str("container_id", containerID).Msg("Sandbox created and started")
	return sandbox, nil
}

// GetSandbox retrieves a sandbox by ID
func (m *Manager) GetSandbox(sandboxID string) (*Sandbox, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sandbox, exists := m.sandboxes[sandboxID]
	if !exists {
		return nil, ErrSandboxNotFound
	}

	return sandbox, nil
}

// ListSandboxes returns all sandboxes
func (m *Manager) ListSandboxes() ([]*Sandbox, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sandboxes := make([]*Sandbox, 0, len(m.sandboxes))
	for _, sandbox := range m.sandboxes {
		sandboxes = append(sandboxes, sandbox)
	}

	return sandboxes, nil
}

// StopSandbox stops a running sandbox
func (m *Manager) StopSandbox(ctx context.Context, sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandbox, exists := m.sandboxes[sandboxID]
	if !exists {
		return fmt.Errorf("sandbox not found: %s", sandboxID)
	}

	if sandbox.Status != SandboxStatusRunning {
		return fmt.Errorf("sandbox is not running: %s", sandboxID)
	}

	// Stop the container
	if err := m.runcClient.StopContainer(ctx, sandbox.ContainerID); err != nil {
		// Update state to failed on stop failure
		m.stateMachine.SetStateWithError(sandbox.ContainerID, ContainerStateFailed, "Container stop failed", 
			err.Error(), nil)
		return fmt.Errorf("failed to stop container: %w", err)
	}

	// Update state machine to stopped
	err := m.stateMachine.SetState(sandbox.ContainerID, ContainerStateStopped, "Container stopped", nil)
	if err != nil {
		log.Warn().Err(err).Str("container_id", sandbox.ContainerID).Msg("Failed to update state machine")
	}

	sandbox.Status = SandboxStatusStopped
	sandbox.UpdatedAt = time.Now()

	// Update database
	if err := m.saveSandbox(sandbox); err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandboxID).Msg("Failed to update sandbox in database")
	}

	log.Info().Str("sandbox_id", sandboxID).Msg("Sandbox stopped")
	return nil
}

// DeleteSandbox removes a sandbox
func (m *Manager) DeleteSandbox(ctx context.Context, sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandbox, exists := m.sandboxes[sandboxID]
	if !exists {
		return fmt.Errorf("sandbox not found: %s", sandboxID)
	}

	// Stop container if running
	if sandbox.Status == SandboxStatusRunning {
		if err := m.runcClient.StopContainer(ctx, sandbox.ContainerID); err != nil {
			log.Warn().Err(err).Str("sandbox_id", sandboxID).Msg("Failed to stop container before deletion")
		}
	}

	// Delete container
	if err := m.runcClient.DeleteContainer(ctx, sandbox.ContainerID); err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandboxID).Msg("Failed to delete container")
	}

	// Remove workspace directory
	if err := os.RemoveAll(sandbox.WorkingDir); err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandboxID).Msg("Failed to remove workspace directory")
	}

	// Cleanup container networking
	if err := m.networkManager.CleanupContainerNetwork(ctx, sandbox.ContainerID); err != nil {
		log.Warn().Err(err).Str("container_id", sandbox.ContainerID).Msg("Failed to cleanup container networking")
	}

	// Cleanup recovery management
	if err := m.recoveryManager.CleanupContainer(sandbox.ContainerID); err != nil {
		log.Warn().Err(err).Str("container_id", sandbox.ContainerID).Msg("Failed to cleanup recovery state")
	}

	// Remove from health monitoring
	m.healthChecker.RemoveContainer(sandbox.ContainerID)

	// Remove from state machine
	err := m.stateMachine.RemoveContainer(sandbox.ContainerID)
	if err != nil {
		log.Warn().Err(err).Str("container_id", sandbox.ContainerID).Msg("Failed to remove container from state machine")
	}

	// Remove from memory and database
	delete(m.sandboxes, sandboxID)
	if err := m.deleteSandboxFromDB(sandboxID); err != nil {
		log.Warn().Err(err).Str("sandbox_id", sandboxID).Msg("Failed to delete sandbox from database")
	}

	log.Info().Str("sandbox_id", sandboxID).Msg("Sandbox deleted")
	return nil
}

// GetSandboxLogs retrieves logs from a sandbox
func (m *Manager) GetSandboxLogs(ctx context.Context, sandboxID string) ([]byte, error) {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return nil, err
	}

	return m.runcClient.GetContainerLogs(ctx, sandbox.ContainerID)
}

// UpdateSandboxMetadata updates sandbox metadata
func (m *Manager) UpdateSandboxMetadata(sandboxID string, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandbox, exists := m.sandboxes[sandboxID]
	if !exists {
		return fmt.Errorf("sandbox not found: %s", sandboxID)
	}

	// Merge metadata
	if sandbox.Metadata == nil {
		sandbox.Metadata = make(map[string]interface{})
	}

	for k, v := range metadata {
		sandbox.Metadata[k] = v
	}

	sandbox.UpdatedAt = time.Now()

	// Update database
	if err := m.saveSandbox(sandbox); err != nil {
		return fmt.Errorf("failed to update sandbox metadata: %w", err)
	}

	return nil
}

// GetRuntimeClient returns the underlying runtime client for direct access
func (m *Manager) GetRuntimeClient() *runtime.RunCClient {
	return m.runcClient
}

// Phase 2.1: New methods for container lifecycle management

// GetContainerState returns the current state of a container
func (m *Manager) GetContainerState(containerID string) (ContainerState, bool) {
	return m.stateMachine.GetState(containerID)
}

// GetContainerStateTransitions returns all state transitions for a container
func (m *Manager) GetContainerStateTransitions(containerID string) []StateTransition {
	return m.stateMachine.GetTransitions(containerID)
}

// GetContainerHealth returns the health status of a container
func (m *Manager) GetContainerHealth(containerID string) (HealthStatus, map[HealthCheckType]HealthCheckResult, error) {
	return m.healthChecker.GetContainerHealth(containerID)
}

// CheckContainerHealth performs an immediate health check on a container
func (m *Manager) CheckContainerHealth(ctx context.Context, containerID string, checkType HealthCheckType) (*HealthCheckResult, error) {
	return m.healthChecker.CheckHealth(ctx, containerID, checkType)
}

// GetEvents returns recent events from the event bus
func (m *Manager) GetEvents(limit int) []Event {
	return m.eventBus.GetEventHistory(limit)
}

// SubscribeToEvents allows clients to subscribe to events
func (m *Manager) SubscribeToEvents(handler EventHandler, filter EventFilter, eventTypes ...EventType) string {
	return m.eventBus.Subscribe(handler, filter, eventTypes...)
}

// UnsubscribeFromEvents removes an event subscription
func (m *Manager) UnsubscribeFromEvents(subscriptionID string) {
	m.eventBus.Unsubscribe(subscriptionID)
}

// GetStateStatistics returns statistics about container states
func (m *Manager) GetStateStatistics() map[ContainerState]int {
	return m.stateMachine.GetStateStatistics()
}

// GetHealthStatistics returns health monitoring statistics
func (m *Manager) GetHealthStatistics() map[string]interface{} {
	return m.healthChecker.GetHealthStatistics()
}

// PauseContainer pauses a running container
func (m *Manager) PauseContainer(ctx context.Context, sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandbox, exists := m.sandboxes[sandboxID]
	if !exists {
		return fmt.Errorf("sandbox not found: %s", sandboxID)
	}

	if sandbox.Status != SandboxStatusRunning {
		return fmt.Errorf("sandbox is not running: %s", sandboxID)
	}

	// Update state machine to paused
	err := m.stateMachine.SetState(sandbox.ContainerID, ContainerStatePaused, "Container paused", nil)
	if err != nil {
		return fmt.Errorf("failed to update container state: %w", err)
	}

	log.Info().Str("sandbox_id", sandboxID).Msg("Sandbox paused")
	return nil
}

// ResumeContainer resumes a paused container
func (m *Manager) ResumeContainer(ctx context.Context, sandboxID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sandbox, exists := m.sandboxes[sandboxID]
	if !exists {
		return fmt.Errorf("sandbox not found: %s", sandboxID)
	}

	// Update state machine to running
	err := m.stateMachine.SetState(sandbox.ContainerID, ContainerStateRunning, "Container resumed", nil)
	if err != nil {
		return fmt.Errorf("failed to update container state: %w", err)
	}

	log.Info().Str("sandbox_id", sandboxID).Msg("Sandbox resumed")
	return nil
}

// GetSystemMetrics returns comprehensive system metrics
func (m *Manager) GetSystemMetrics() *SystemMetrics {
	if m.metricsCollector != nil {
		return m.metricsCollector.GetMetrics()
	}
	return nil
}

// GetAlertRules returns all configured alert rules
func (m *Manager) GetAlertRules() []AlertRule {
	if m.metricsCollector != nil {
		return m.metricsCollector.GetAlertRules()
	}
	return nil
}

// AddAlertRule adds a new alert rule
func (m *Manager) AddAlertRule(rule AlertRule) {
	if m.metricsCollector != nil {
		m.metricsCollector.AddAlertRule(rule)
	}
}

// UpdateAlertRule updates an existing alert rule
func (m *Manager) UpdateAlertRule(ruleID string, rule AlertRule) bool {
	if m.metricsCollector != nil {
		return m.metricsCollector.UpdateAlertRule(ruleID, rule)
	}
	return false
}

// RemoveAlertRule removes an alert rule
func (m *Manager) RemoveAlertRule(ruleID string) bool {
	if m.metricsCollector != nil {
		return m.metricsCollector.RemoveAlertRule(ruleID)
	}
	return false
}

// Phase 2.1: New methods for recovery management

// TriggerSandboxRecovery manually triggers recovery for a sandbox
func (m *Manager) TriggerSandboxRecovery(sandboxID string, failureType FailureType, reason string) error {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return err
	}
	
	return m.recoveryManager.TriggerRecovery(sandbox.ContainerID, failureType, reason)
}

// GetSandboxRecoveryState returns recovery state for a sandbox
func (m *Manager) GetSandboxRecoveryState(sandboxID string) (*RecoveryState, error) {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return nil, err
	}
	
	return m.recoveryManager.GetRecoveryState(sandbox.ContainerID)
}

// SetSandboxRecoveryPolicy sets recovery policy for a sandbox
func (m *Manager) SetSandboxRecoveryPolicy(sandboxID string, policy *RecoveryPolicy) error {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return err
	}
	
	return m.recoveryManager.SetRecoveryPolicy(sandbox.ContainerID, policy)
}

// EnableSandboxRecovery enables recovery for a sandbox
func (m *Manager) EnableSandboxRecovery(sandboxID string) error {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return err
	}
	
	return m.recoveryManager.EnableRecovery(sandbox.ContainerID)
}

// DisableSandboxRecovery disables recovery for a sandbox
func (m *Manager) DisableSandboxRecovery(sandboxID string) error {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return err
	}
	
	return m.recoveryManager.DisableRecovery(sandbox.ContainerID)
}

// GetRecoveryMetrics returns recovery metrics
func (m *Manager) GetRecoveryMetrics() *RecoveryMetrics {
	return m.recoveryManager.GetRecoveryMetrics()
}

// Phase 2.1: New methods for network management

// GetSandboxNetworkState returns network state for a sandbox
func (m *Manager) GetSandboxNetworkState(sandboxID string) (*runtime.ContainerNetworkState, error) {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return nil, err
	}
	
	return m.networkManager.GetContainerNetworkState(sandbox.ContainerID)
}

// UpdateSandboxNetworkFirewallRules updates firewall rules for a sandbox
func (m *Manager) UpdateSandboxNetworkFirewallRules(ctx context.Context, sandboxID string, rules []runtime.FirewallRule) error {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return err
	}
	
	return m.networkManager.UpdateFirewallRules(ctx, sandbox.ContainerID, rules)
}

// UpdateSandboxNetworkBandwidthLimits updates bandwidth limits for a sandbox
func (m *Manager) UpdateSandboxNetworkBandwidthLimits(ctx context.Context, sandboxID string, limits *runtime.BandwidthLimit) error {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return err
	}
	
	return m.networkManager.UpdateBandwidthLimits(ctx, sandbox.ContainerID, limits)
}

// GetSandboxNetworkStatistics returns network statistics for a sandbox
func (m *Manager) GetSandboxNetworkStatistics(sandboxID string) (map[string]interface{}, error) {
	sandbox, err := m.GetSandbox(sandboxID)
	if err != nil {
		return nil, err
	}
	
	return m.networkManager.GetNetworkStatistics(sandbox.ContainerID)
}

// ListSandboxNetworks returns network states for all sandboxes
func (m *Manager) ListSandboxNetworks() map[string]*runtime.ContainerNetworkState {
	return m.networkManager.ListContainerNetworks()
}

// Close cleans up manager resources
func (m *Manager) Close() error {
	log.Info().Msg("Shutting down sandbox manager")

	// Stop recovery manager
	if m.recoveryManager != nil {
		m.recoveryManager.Stop()
	}

	// Stop health checker
	if m.healthChecker != nil {
		m.healthChecker.Stop()
	}

	// Stop state machine
	if m.stateMachine != nil {
		m.stateMachine.Stop()
	}

	// Stop metrics collector
	if m.metricsCollector != nil {
		m.metricsCollector.Stop()
	}

	// Stop event bus
	if m.eventBus != nil {
		m.eventBus.Stop()
	}

	// Cleanup runc client
	if m.runcClient != nil {
		m.runcClient.Cleanup()
	}

	// Close database
	if m.db != nil {
		return m.db.Close()
	}

	return nil
}

// Helper methods

func (m *Manager) convertMounts(mounts []MountConfig, workspaceDir string) []runtime.Mount {
	runtimeMounts := make([]runtime.Mount, len(mounts))
	
	for i, mount := range mounts {
		runtimeMounts[i] = runtime.Mount{
			Source:      mount.Source,
			Destination: mount.Destination,
			Type:        mount.Type,
			Options:     mount.Options,
		}
	}

	// Add default workspace mount
	runtimeMounts = append(runtimeMounts, runtime.Mount{
		Source:      workspaceDir,
		Destination: "/workspace",
		Type:        "bind",
		Options:     []string{"rw"},
	})

	return runtimeMounts
}

func (m *Manager) createBasicFilesystem(rootfsPath string) error {
	// Create basic directories
	dirs := []string{
		"bin", "etc", "lib", "lib64", "usr/bin", "usr/lib", "usr/lib64",
		"tmp", "var/tmp", "proc", "sys", "dev", "workspace",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(rootfsPath, dir), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func (m *Manager) saveSandbox(sandbox *Sandbox) error {
	configJSON, _ := json.Marshal(sandbox.Config)
	metadataJSON, _ := json.Marshal(sandbox.Metadata)

	query := `INSERT OR REPLACE INTO sandboxes 
		(id, container_id, status, working_dir, environment, created_at, updated_at, config, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	envJSON, _ := json.Marshal(sandbox.Environment)

	_, err := m.db.Exec(query,
		sandbox.ID, sandbox.ContainerID, string(sandbox.Status),
		sandbox.WorkingDir, string(envJSON), sandbox.CreatedAt, sandbox.UpdatedAt,
		string(configJSON), string(metadataJSON))

	return err
}

func (m *Manager) loadSandboxes() error {
	query := `SELECT id, container_id, status, working_dir, environment, created_at, updated_at, config, metadata FROM sandboxes`
	
	rows, err := m.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var sandbox Sandbox
		var statusStr, envJSON, configJSON, metadataJSON string

		err := rows.Scan(
			&sandbox.ID, &sandbox.ContainerID, &statusStr,
			&sandbox.WorkingDir, &envJSON, &sandbox.CreatedAt, &sandbox.UpdatedAt,
			&configJSON, &metadataJSON)
		if err != nil {
			continue
		}

		sandbox.Status = SandboxStatus(statusStr)
		json.Unmarshal([]byte(envJSON), &sandbox.Environment)
		json.Unmarshal([]byte(configJSON), &sandbox.Config)
		json.Unmarshal([]byte(metadataJSON), &sandbox.Metadata)

		m.sandboxes[sandbox.ID] = &sandbox
	}

	return nil
}

func (m *Manager) deleteSandboxFromDB(sandboxID string) error {
	query := `DELETE FROM sandboxes WHERE id = ?`
	_, err := m.db.Exec(query, sandboxID)
	return err
}

func createTables(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS sandboxes (
		id TEXT PRIMARY KEY,
		container_id TEXT NOT NULL,
		status TEXT NOT NULL,
		working_dir TEXT NOT NULL,
		environment TEXT,
		created_at DATETIME NOT NULL,
		updated_at DATETIME NOT NULL,
		config TEXT,
		metadata TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_sandboxes_status ON sandboxes(status);
	CREATE INDEX IF NOT EXISTS idx_sandboxes_created_at ON sandboxes(created_at);
	`

	_, err := db.Exec(query)
	return err
}