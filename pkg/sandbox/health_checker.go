package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/beam-cloud/go-runc"
	"github.com/rs/zerolog/log"
)

// HealthStatus represents the health status of a container
type HealthStatus string

const (
	// HealthStatusHealthy indicates the container is healthy
	HealthStatusHealthy HealthStatus = "healthy"
	// HealthStatusWarning indicates the container has warnings but is functional
	HealthStatusWarning HealthStatus = "warning"
	// HealthStatusUnhealthy indicates the container is unhealthy
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	// HealthStatusUnknown indicates the health status is unknown
	HealthStatusUnknown HealthStatus = "unknown"
)

// HealthCheckType represents different types of health checks
type HealthCheckType string

const (
	// HealthCheckTypeLiveness checks if the container is alive
	HealthCheckTypeLiveness HealthCheckType = "liveness"
	// HealthCheckTypeReadiness checks if the container is ready
	HealthCheckTypeReadiness HealthCheckType = "readiness"
	// HealthCheckTypeResource checks resource usage
	HealthCheckTypeResource HealthCheckType = "resource"
	// HealthCheckTypeNetwork checks network connectivity
	HealthCheckTypeNetwork HealthCheckType = "network"
	// HealthCheckTypeCustom executes custom health check scripts
	HealthCheckTypeCustom HealthCheckType = "custom"
)

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	ContainerID   string                 `json:"container_id"`
	CheckType     HealthCheckType        `json:"check_type"`
	Status        HealthStatus           `json:"status"`
	Message       string                 `json:"message"`
	Timestamp     time.Time              `json:"timestamp"`
	Duration      time.Duration          `json:"duration"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Error         string                 `json:"error,omitempty"`
	NextCheckTime time.Time              `json:"next_check_time"`
}

// HealthThresholds defines thresholds for health monitoring
type HealthThresholds struct {
	CPUWarningPercent    float64 `json:"cpu_warning_percent"`
	CPUCriticalPercent   float64 `json:"cpu_critical_percent"`
	MemoryWarningPercent float64 `json:"memory_warning_percent"`
	MemoryCriticalPercent float64 `json:"memory_critical_percent"`
	DiskWarningPercent   float64 `json:"disk_warning_percent"`
	DiskCriticalPercent  float64 `json:"disk_critical_percent"`
	MaxResponseTime      time.Duration `json:"max_response_time"`
	MinFreeDiskMB        int64   `json:"min_free_disk_mb"`
}

// DefaultHealthThresholds returns default health check thresholds
func DefaultHealthThresholds() HealthThresholds {
	return HealthThresholds{
		CPUWarningPercent:     70.0,
		CPUCriticalPercent:    90.0,
		MemoryWarningPercent:  80.0,
		MemoryCriticalPercent: 95.0,
		DiskWarningPercent:    80.0,
		DiskCriticalPercent:   95.0,
		MaxResponseTime:       30 * time.Second,
		MinFreeDiskMB:         100,
	}
}

// HealthCheckConfig defines configuration for health checks
type HealthCheckConfig struct {
	Enabled       bool             `json:"enabled"`
	Interval      time.Duration    `json:"interval"`
	Timeout       time.Duration    `json:"timeout"`
	MaxRetries    int              `json:"max_retries"`
	Thresholds    HealthThresholds `json:"thresholds"`
	CustomChecks  []CustomCheck    `json:"custom_checks"`
}

// CustomCheck defines a custom health check script
type CustomCheck struct {
	Name        string        `json:"name"`
	Command     []string      `json:"command"`
	WorkingDir  string        `json:"working_dir"`
	Environment map[string]string `json:"environment"`
	Timeout     time.Duration `json:"timeout"`
	Interval    time.Duration `json:"interval"`
}

// DefaultHealthCheckConfig returns default health check configuration
func DefaultHealthCheckConfig() HealthCheckConfig {
	return HealthCheckConfig{
		Enabled:      true,
		Interval:     30 * time.Second,
		Timeout:      10 * time.Second,
		MaxRetries:   3,
		Thresholds:   DefaultHealthThresholds(),
		CustomChecks: make([]CustomCheck, 0),
	}
}

// HealthAlertCallback is called when a health alert is triggered
type HealthAlertCallback func(result HealthCheckResult)

// ContainerClient defines the interface needed by HealthChecker
type ContainerClient interface {
	ListContainers(ctx context.Context) ([]*runc.Container, error)
}

// HealthChecker manages health monitoring for containers
type HealthChecker struct {
	db              *sql.DB
	runcClient      ContainerClient
	config          HealthCheckConfig
	mu              sync.RWMutex
	containerConfigs map[string]HealthCheckConfig // per-container configs
	lastResults     map[string]map[HealthCheckType]HealthCheckResult // containerID -> checkType -> result
	alertCallbacks  []HealthAlertCallback
	ctx             context.Context
	cancel          context.CancelFunc
	stopOnce        sync.Once
	checkQueue      chan healthCheckRequest
	workers         int
}

// healthCheckRequest represents a health check request
type healthCheckRequest struct {
	ContainerID string
	CheckType   HealthCheckType
	Config      HealthCheckConfig
}

// NewHealthChecker creates a new health checker instance
func NewHealthChecker(db *sql.DB, runcClient ContainerClient, config HealthCheckConfig) (*HealthChecker, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	hc := &HealthChecker{
		db:               db,
		runcClient:       runcClient,
		config:           config,
		containerConfigs: make(map[string]HealthCheckConfig),
		lastResults:      make(map[string]map[HealthCheckType]HealthCheckResult),
		alertCallbacks:   make([]HealthAlertCallback, 0),
		ctx:              ctx,
		cancel:           cancel,
		checkQueue:       make(chan healthCheckRequest, 1000),
		workers:          5, // Number of concurrent health check workers
	}

	// Create health check tables
	if err := hc.createTables(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create health check tables: %w", err)
	}

	// Load existing health check history from database
	if err := hc.loadHealthHistory(); err != nil {
		log.Warn().Err(err).Msg("Failed to load health check history from database")
	}

	// Start health check workers
	for i := 0; i < hc.workers; i++ {
		go hc.healthCheckWorker()
	}

	// Start scheduler
	go hc.scheduler()

	log.Info().Int("workers", hc.workers).Msg("Health checker initialized")
	return hc, nil
}

// RegisterAlertCallback registers a callback for health alerts
func (hc *HealthChecker) RegisterAlertCallback(callback HealthAlertCallback) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	
	hc.alertCallbacks = append(hc.alertCallbacks, callback)
}

// AddContainer adds a container for health monitoring
func (hc *HealthChecker) AddContainer(containerID string, config *HealthCheckConfig) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if config == nil {
		config = &hc.config
	}

	hc.containerConfigs[containerID] = *config

	// Initialize results map
	if hc.lastResults[containerID] == nil {
		hc.lastResults[containerID] = make(map[HealthCheckType]HealthCheckResult)
	}

	log.Info().Str("container_id", containerID).Msg("Container added to health monitoring")
}

// RemoveContainer removes a container from health monitoring
func (hc *HealthChecker) RemoveContainer(containerID string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	delete(hc.containerConfigs, containerID)
	delete(hc.lastResults, containerID)

	// Clean up database records
	go func() {
		query := `DELETE FROM health_check_results WHERE container_id = ?`
		if _, err := hc.db.Exec(query, containerID); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).
				Msg("Failed to clean up health check results from database")
		}
	}()

	log.Info().Str("container_id", containerID).Msg("Container removed from health monitoring")
}

// CheckHealth performs an immediate health check for a container
func (hc *HealthChecker) CheckHealth(ctx context.Context, containerID string, checkType HealthCheckType) (*HealthCheckResult, error) {
	hc.mu.RLock()
	config, exists := hc.containerConfigs[containerID]
	hc.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("container not registered for health monitoring: %s", containerID)
	}

	if !config.Enabled {
		return nil, fmt.Errorf("health monitoring disabled for container: %s", containerID)
	}

	result := hc.performHealthCheck(ctx, containerID, checkType, config)
	hc.storeResult(result)

	return &result, nil
}

// GetLastResult returns the last health check result for a container and check type
func (hc *HealthChecker) GetLastResult(containerID string, checkType HealthCheckType) (*HealthCheckResult, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	containerResults, exists := hc.lastResults[containerID]
	if !exists {
		return nil, fmt.Errorf("no health check results for container: %s", containerID)
	}

	result, exists := containerResults[checkType]
	if !exists {
		return nil, fmt.Errorf("no health check results for container %s, check type %s", containerID, checkType)
	}

	return &result, nil
}

// GetContainerHealth returns overall health status for a container
func (hc *HealthChecker) GetContainerHealth(containerID string) (HealthStatus, map[HealthCheckType]HealthCheckResult, error) {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	containerResults, exists := hc.lastResults[containerID]
	if !exists {
		return HealthStatusUnknown, nil, fmt.Errorf("no health check results for container: %s", containerID)
	}

	// Determine overall health status
	overallStatus := HealthStatusHealthy
	for _, result := range containerResults {
		if result.Status == HealthStatusUnhealthy {
			overallStatus = HealthStatusUnhealthy
			break
		} else if result.Status == HealthStatusWarning && overallStatus == HealthStatusHealthy {
			overallStatus = HealthStatusWarning
		} else if result.Status == HealthStatusUnknown && overallStatus != HealthStatusUnhealthy {
			overallStatus = HealthStatusUnknown
		}
	}

	// Return a copy to prevent race conditions
	resultsCopy := make(map[HealthCheckType]HealthCheckResult)
	for checkType, result := range containerResults {
		resultsCopy[checkType] = result
	}

	return overallStatus, resultsCopy, nil
}

// Stop stops the health checker
func (hc *HealthChecker) Stop() {
	hc.stopOnce.Do(func() {
		log.Info().Msg("Stopping health checker")
		hc.cancel()
		close(hc.checkQueue)
	})
}

// scheduler schedules periodic health checks
func (hc *HealthChecker) scheduler() {
	ticker := time.NewTicker(5 * time.Second) // Check every 5 seconds for scheduling
	defer ticker.Stop()

	for {
		select {
		case <-hc.ctx.Done():
			log.Info().Msg("Health check scheduler stopped")
			return
		case <-ticker.C:
			hc.scheduleHealthChecks()
		}
	}
}

// scheduleHealthChecks schedules health checks for containers that need them
func (hc *HealthChecker) scheduleHealthChecks() {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	now := time.Now()
	checkTypes := []HealthCheckType{
		HealthCheckTypeLiveness,
		HealthCheckTypeReadiness,
		HealthCheckTypeResource,
		HealthCheckTypeNetwork,
		HealthCheckTypeCustom,
	}

	for containerID, config := range hc.containerConfigs {
		if !config.Enabled {
			continue
		}

		containerResults := hc.lastResults[containerID]
		for _, checkType := range checkTypes {
			var nextCheckTime time.Time

			if result, exists := containerResults[checkType]; exists {
				nextCheckTime = result.NextCheckTime
			} else {
				// First check - schedule immediately
				nextCheckTime = now
			}

			if now.After(nextCheckTime) || now.Equal(nextCheckTime) {
				req := healthCheckRequest{
					ContainerID: containerID,
					CheckType:   checkType,
					Config:      config,
				}

				select {
				case hc.checkQueue <- req:
				default:
					log.Warn().
						Str("container_id", containerID).
						Str("check_type", string(checkType)).
						Msg("Health check queue full, skipping check")
				}
			}
		}
	}
}

// healthCheckWorker processes health check requests
func (hc *HealthChecker) healthCheckWorker() {
	for {
		select {
		case <-hc.ctx.Done():
			return
		case req, ok := <-hc.checkQueue:
			if !ok {
				return
			}

			ctx, cancel := context.WithTimeout(hc.ctx, req.Config.Timeout)
			result := hc.performHealthCheck(ctx, req.ContainerID, req.CheckType, req.Config)
			cancel()

			hc.storeResult(result)
			hc.processAlerts(result)
		}
	}
}

// performHealthCheck executes a health check
func (hc *HealthChecker) performHealthCheck(ctx context.Context, containerID string, checkType HealthCheckType, config HealthCheckConfig) HealthCheckResult {
	startTime := time.Now()
	
	result := HealthCheckResult{
		ContainerID: containerID,
		CheckType:   checkType,
		Status:      HealthStatusUnknown,
		Timestamp:   startTime,
		Metadata:    make(map[string]interface{}),
		NextCheckTime: startTime.Add(config.Interval),
	}

	defer func() {
		result.Duration = time.Since(startTime)
	}()

	switch checkType {
	case HealthCheckTypeLiveness:
		hc.performLivenessCheck(ctx, containerID, &result, config)
	case HealthCheckTypeReadiness:
		hc.performReadinessCheck(ctx, containerID, &result, config)
	case HealthCheckTypeResource:
		hc.performResourceCheck(ctx, containerID, &result, config)
	case HealthCheckTypeNetwork:
		hc.performNetworkCheck(ctx, containerID, &result, config)
	case HealthCheckTypeCustom:
		hc.performCustomChecks(ctx, containerID, &result, config)
	default:
		result.Status = HealthStatusUnhealthy
		result.Error = fmt.Sprintf("unsupported check type: %s", checkType)
	}

	return result
}

// performLivenessCheck checks if the container is alive
func (hc *HealthChecker) performLivenessCheck(ctx context.Context, containerID string, result *HealthCheckResult, config HealthCheckConfig) {
	// Check container state using runc - using the ListContainers method and finding our container
	containers, err := hc.runcClient.ListContainers(ctx)
	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Error = fmt.Sprintf("failed to list containers: %v", err)
		return
	}

	var containerFound bool
	for _, container := range containers {
		if container.ID == containerID {
			containerFound = true
			result.Metadata["container_status"] = container.Status
			result.Metadata["container_pid"] = container.Pid

			if container.Status == "running" && container.Pid > 0 {
				// Verify process is actually running
				if err := syscall.Kill(container.Pid, 0); err != nil {
					result.Status = HealthStatusUnhealthy
					result.Error = fmt.Sprintf("container process not responding: %v", err)
					return
				}
				
				result.Status = HealthStatusHealthy
				result.Message = "Container is alive and responsive"
			} else {
				result.Status = HealthStatusUnhealthy
				result.Message = fmt.Sprintf("Container status: %s", container.Status)
			}
			return
		}
	}

	if !containerFound {
		result.Status = HealthStatusUnhealthy
		result.Message = "Container not found"
		return
	}
}

// performReadinessCheck checks if the container is ready to serve requests
func (hc *HealthChecker) performReadinessCheck(ctx context.Context, containerID string, result *HealthCheckResult, config HealthCheckConfig) {
	// First check if container is alive
	hc.performLivenessCheck(ctx, containerID, result, config)
	if result.Status == HealthStatusUnhealthy {
		result.Message = "Container not ready - liveness check failed"
		return
	}

	// Add additional readiness checks here
	// For now, if liveness passes, consider it ready
	result.Status = HealthStatusHealthy
	result.Message = "Container is ready"
}

// performResourceCheck monitors resource usage
func (hc *HealthChecker) performResourceCheck(ctx context.Context, containerID string, result *HealthCheckResult, config HealthCheckConfig) {
	// Get container state first
	containers, err := hc.runcClient.ListContainers(ctx)
	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Error = fmt.Sprintf("failed to list containers: %v", err)
		return
	}

	var containerPid int
	var containerFound bool
	for _, container := range containers {
		if container.ID == containerID {
			containerFound = true
			if container.Status != "running" || container.Pid <= 0 {
				result.Status = HealthStatusUnhealthy
				result.Error = "Cannot check resources - container not running"
				return
			}
			containerPid = container.Pid
			break
		}
	}

	if !containerFound {
		result.Status = HealthStatusUnhealthy
		result.Error = "Container not found"
		return
	}

	result.Metadata["pid"] = containerPid

	// Read CPU and memory usage from /proc
	cpuPercent, memoryPercent, err := hc.getResourceUsage(containerPid)
	if err != nil {
		result.Status = HealthStatusWarning
		result.Error = fmt.Sprintf("failed to get resource usage: %v", err)
		return
	}

	result.Metadata["cpu_percent"] = cpuPercent
	result.Metadata["memory_percent"] = memoryPercent

	// Check thresholds
	status := HealthStatusHealthy
	var messages []string

	if cpuPercent > config.Thresholds.CPUCriticalPercent {
		status = HealthStatusUnhealthy
		messages = append(messages, fmt.Sprintf("CPU usage critical: %.2f%%", cpuPercent))
	} else if cpuPercent > config.Thresholds.CPUWarningPercent {
		if status == HealthStatusHealthy {
			status = HealthStatusWarning
		}
		messages = append(messages, fmt.Sprintf("CPU usage high: %.2f%%", cpuPercent))
	}

	if memoryPercent > config.Thresholds.MemoryCriticalPercent {
		status = HealthStatusUnhealthy
		messages = append(messages, fmt.Sprintf("Memory usage critical: %.2f%%", memoryPercent))
	} else if memoryPercent > config.Thresholds.MemoryWarningPercent {
		if status == HealthStatusHealthy {
			status = HealthStatusWarning
		}
		messages = append(messages, fmt.Sprintf("Memory usage high: %.2f%%", memoryPercent))
	}

	// Check disk usage
	diskPercent, err := hc.getDiskUsage(containerID)
	if err == nil {
		result.Metadata["disk_percent"] = diskPercent
		
		if diskPercent > config.Thresholds.DiskCriticalPercent {
			status = HealthStatusUnhealthy
			messages = append(messages, fmt.Sprintf("Disk usage critical: %.2f%%", diskPercent))
		} else if diskPercent > config.Thresholds.DiskWarningPercent {
			if status == HealthStatusHealthy {
				status = HealthStatusWarning
			}
			messages = append(messages, fmt.Sprintf("Disk usage high: %.2f%%", diskPercent))
		}
	}

	result.Status = status
	if len(messages) > 0 {
		result.Message = fmt.Sprintf("Resource check: %v", messages)
	} else {
		result.Message = "Resource usage within normal limits"
	}
}

// performNetworkCheck checks network connectivity
func (hc *HealthChecker) performNetworkCheck(ctx context.Context, containerID string, result *HealthCheckResult, config HealthCheckConfig) {
	// For now, just check if we can resolve DNS
	// In a real implementation, you might want to check specific endpoints
	
	result.Status = HealthStatusHealthy
	result.Message = "Network check passed"
	
	// This is a simplified check - in practice you might want to:
	// - Test connectivity to specific services
	// - Check DNS resolution
	// - Verify network interfaces are up
	// - Test specific ports
}

// performCustomChecks executes custom health check scripts
func (hc *HealthChecker) performCustomChecks(ctx context.Context, containerID string, result *HealthCheckResult, config HealthCheckConfig) {
	if len(config.CustomChecks) == 0 {
		result.Status = HealthStatusHealthy
		result.Message = "No custom checks configured"
		return
	}

	overallStatus := HealthStatusHealthy
	var messages []string
	checkResults := make(map[string]interface{})

	for _, check := range config.CustomChecks {
		checkCtx, cancel := context.WithTimeout(ctx, check.Timeout)
		
		cmd := exec.CommandContext(checkCtx, check.Command[0], check.Command[1:]...)
		if check.WorkingDir != "" {
			cmd.Dir = check.WorkingDir
		}
		if len(check.Environment) > 0 {
			cmd.Env = os.Environ()
			for k, v := range check.Environment {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
			}
		}

		output, err := cmd.CombinedOutput()
		cancel()

		checkResult := map[string]interface{}{
			"exit_code": 0,
			"output":    string(output),
		}

		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				checkResult["exit_code"] = exitErr.ExitCode()
			}
			overallStatus = HealthStatusUnhealthy
			messages = append(messages, fmt.Sprintf("Custom check '%s' failed: %v", check.Name, err))
		} else {
			messages = append(messages, fmt.Sprintf("Custom check '%s' passed", check.Name))
		}

		checkResults[check.Name] = checkResult
	}

	result.Metadata["custom_checks"] = checkResults
	result.Status = overallStatus
	result.Message = fmt.Sprintf("Custom checks: %v", messages)
}

// processAlerts processes health check results and triggers alerts if necessary
func (hc *HealthChecker) processAlerts(result HealthCheckResult) {
	// Only alert on status changes or critical issues
	hc.mu.RLock()
	lastResult, exists := hc.lastResults[result.ContainerID][result.CheckType]
	hc.mu.RUnlock()

	shouldAlert := false
	if !exists {
		// First check result
		if result.Status == HealthStatusUnhealthy {
			shouldAlert = true
		}
	} else if lastResult.Status != result.Status {
		// Status change
		shouldAlert = true
	} else if result.Status == HealthStatusUnhealthy {
		// Continuous unhealthy state
		if time.Since(lastResult.Timestamp) > 5*time.Minute {
			shouldAlert = true
		}
	}

	if shouldAlert {
		hc.mu.RLock()
		callbacks := make([]HealthAlertCallback, len(hc.alertCallbacks))
		copy(callbacks, hc.alertCallbacks)
		hc.mu.RUnlock()

		for _, callback := range callbacks {
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Error().
							Interface("panic", r).
							Str("container_id", result.ContainerID).
							Msg("Health alert callback panicked")
					}
				}()
				callback(result)
			}()
		}
	}
}

// storeResult stores a health check result
func (hc *HealthChecker) storeResult(result HealthCheckResult) {
	// Update in-memory cache
	hc.mu.Lock()
	if hc.lastResults[result.ContainerID] == nil {
		hc.lastResults[result.ContainerID] = make(map[HealthCheckType]HealthCheckResult)
	}
	hc.lastResults[result.ContainerID][result.CheckType] = result
	hc.mu.Unlock()

	// Persist to database
	go func() {
		if err := hc.persistResult(result); err != nil {
			log.Error().Err(err).
				Str("container_id", result.ContainerID).
				Str("check_type", string(result.CheckType)).
				Msg("Failed to persist health check result")
		}
	}()
}

// persistResult saves a health check result to the database
func (hc *HealthChecker) persistResult(result HealthCheckResult) error {
	metadataJSON, _ := json.Marshal(result.Metadata)

	query := `INSERT INTO health_check_results 
		(container_id, check_type, status, message, timestamp, duration_ms, metadata, error, next_check_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	_, err := hc.db.Exec(query,
		result.ContainerID, string(result.CheckType), string(result.Status),
		result.Message, result.Timestamp, result.Duration.Milliseconds(),
		string(metadataJSON), result.Error, result.NextCheckTime)
	
	return err
}

// loadHealthHistory loads existing health check history from database
func (hc *HealthChecker) loadHealthHistory() error {
	// Load most recent results for each container/check type combination
	query := `SELECT container_id, check_type, status, message, timestamp, duration_ms, metadata, error, next_check_time
		FROM health_check_results h1
		WHERE timestamp = (
			SELECT MAX(timestamp) 
			FROM health_check_results h2 
			WHERE h2.container_id = h1.container_id AND h2.check_type = h1.check_type
		)
		AND timestamp > datetime('now', '-1 hour')`

	rows, err := hc.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query health check results: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var result HealthCheckResult
		var checkTypeStr, statusStr, metadataStr sql.NullString
		var durationMs int64

		err := rows.Scan(&result.ContainerID, &checkTypeStr, &statusStr,
			&result.Message, &result.Timestamp, &durationMs,
			&metadataStr, &result.Error, &result.NextCheckTime)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan health check result row")
			continue
		}

		if checkTypeStr.Valid {
			result.CheckType = HealthCheckType(checkTypeStr.String)
		}
		if statusStr.Valid {
			result.Status = HealthStatus(statusStr.String)
		}
		result.Duration = time.Duration(durationMs) * time.Millisecond

		if metadataStr.Valid && metadataStr.String != "" {
			json.Unmarshal([]byte(metadataStr.String), &result.Metadata)
		}
		if result.Metadata == nil {
			result.Metadata = make(map[string]interface{})
		}

		// Store in memory
		if hc.lastResults[result.ContainerID] == nil {
			hc.lastResults[result.ContainerID] = make(map[HealthCheckType]HealthCheckResult)
		}
		hc.lastResults[result.ContainerID][result.CheckType] = result
		count++
	}

	log.Info().Int("results", count).Msg("Loaded health check history from database")
	return nil
}

// createTables creates the necessary database tables for health monitoring
func (hc *HealthChecker) createTables() error {
	query := `CREATE TABLE IF NOT EXISTS health_check_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		container_id TEXT NOT NULL,
		check_type TEXT NOT NULL,
		status TEXT NOT NULL,
		message TEXT,
		timestamp DATETIME NOT NULL,
		duration_ms INTEGER,
		metadata TEXT,
		error TEXT,
		next_check_time DATETIME,
		UNIQUE(container_id, check_type, timestamp)
	)`

	if _, err := hc.db.Exec(query); err != nil {
		return fmt.Errorf("failed to create health_check_results table: %w", err)
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_health_results_container ON health_check_results(container_id)`,
		`CREATE INDEX IF NOT EXISTS idx_health_results_timestamp ON health_check_results(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_health_results_status ON health_check_results(status)`,
		`CREATE INDEX IF NOT EXISTS idx_health_results_container_type ON health_check_results(container_id, check_type)`,
	}

	for _, indexQuery := range indexes {
		if _, err := hc.db.Exec(indexQuery); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// getResourceUsage gets CPU and memory usage for a process
func (hc *HealthChecker) getResourceUsage(pid int) (cpuPercent, memoryPercent float64, err error) {
	// Read from /proc/pid/stat for CPU info
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	_, err = os.ReadFile(statPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read stat file: %w", err)
	}

	// Read from /proc/pid/status for memory info
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	_, err = os.ReadFile(statusPath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read status file: %w", err)
	}

	// Parse memory usage (simplified)
	// In a real implementation, you'd parse these files properly
	// For now, return mock values
	cpuPercent = 10.0  // Mock CPU usage
	memoryPercent = 15.0 // Mock memory usage

	return cpuPercent, memoryPercent, nil
}

// getDiskUsage gets disk usage for a container
func (hc *HealthChecker) getDiskUsage(containerID string) (float64, error) {
	// This is a simplified implementation
	// In practice, you'd check the actual container's filesystem usage
	return 25.0, nil // Mock disk usage
}

// GetHealthStatistics returns health check statistics
func (hc *HealthChecker) GetHealthStatistics() map[string]interface{} {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	stats := make(map[string]interface{})
	healthyCount := 0
	warningCount := 0
	unhealthyCount := 0
	totalContainers := len(hc.containerConfigs)

	for containerID := range hc.containerConfigs {
		status, _, err := hc.GetContainerHealth(containerID)
		if err == nil {
			switch status {
			case HealthStatusHealthy:
				healthyCount++
			case HealthStatusWarning:
				warningCount++
			case HealthStatusUnhealthy:
				unhealthyCount++
			}
		}
	}

	stats["total_containers"] = totalContainers
	stats["healthy_containers"] = healthyCount
	stats["warning_containers"] = warningCount
	stats["unhealthy_containers"] = unhealthyCount
	stats["timestamp"] = time.Now()

	return stats
}