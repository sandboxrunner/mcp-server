package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// HealthStatus represents the health status of a component
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// CheckType represents the type of health check
type CheckType string

const (
	CheckTypeLiveness    CheckType = "liveness"
	CheckTypeReadiness   CheckType = "readiness"
	CheckTypeStartup     CheckType = "startup"
	CheckTypeDatabase    CheckType = "database"
	CheckTypeExternal    CheckType = "external"
	CheckTypeResource    CheckType = "resource"
	CheckTypeCustom      CheckType = "custom"
)

// HealthConfig configuration for health monitoring
type HealthConfig struct {
	Enabled               bool                     `json:"enabled"`
	LivenessPath          string                   `json:"liveness_path"`
	ReadinessPath         string                   `json:"readiness_path"`
	HealthPath            string                   `json:"health_path"`
	Port                  int                      `json:"port"`
	Timeout               time.Duration            `json:"timeout"`
	CheckInterval         time.Duration            `json:"check_interval"`
	MaxConcurrentChecks   int                      `json:"max_concurrent_checks"`
	RetryAttempts         int                      `json:"retry_attempts"`
	RetryDelay            time.Duration            `json:"retry_delay"`
	GracefulShutdown      time.Duration            `json:"graceful_shutdown"`
	EnableDetailedStatus  bool                     `json:"enable_detailed_status"`
	EnableMetrics         bool                     `json:"enable_metrics"`
	EnableHistory         bool                     `json:"enable_history"`
	HistorySize           int                      `json:"history_size"`
	AlertingConfig        *HealthAlertingConfig    `json:"alerting_config,omitempty"`
	ComponentConfigs      map[string]ComponentConfig `json:"component_configs"`
	ExternalChecks        []ExternalCheckConfig    `json:"external_checks"`
	ResourceThresholds    *ResourceThresholds      `json:"resource_thresholds,omitempty"`
}

// ComponentConfig configuration for individual components
type ComponentConfig struct {
	Enabled       bool          `json:"enabled"`
	CheckTypes    []CheckType   `json:"check_types"`
	Timeout       time.Duration `json:"timeout"`
	Interval      time.Duration `json:"interval"`
	RetryAttempts int           `json:"retry_attempts"`
	Critical      bool          `json:"critical"`      // If true, failure affects overall health
	Dependencies  []string      `json:"dependencies"`  // Other components this depends on
	Tags          []string      `json:"tags"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// ExternalCheckConfig configuration for external health checks
type ExternalCheckConfig struct {
	Name        string                 `json:"name"`
	URL         string                 `json:"url"`
	Method      string                 `json:"method"`
	Headers     map[string]string      `json:"headers"`
	Body        string                 `json:"body,omitempty"`
	Timeout     time.Duration          `json:"timeout"`
	Interval    time.Duration          `json:"interval"`
	ExpectedStatus int                 `json:"expected_status"`
	ExpectedBody   string              `json:"expected_body,omitempty"`
	Critical    bool                   `json:"critical"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ResourceThresholds thresholds for resource-based health checks
type ResourceThresholds struct {
	CPUWarning    float64 `json:"cpu_warning"`
	CPUCritical   float64 `json:"cpu_critical"`
	MemoryWarning float64 `json:"memory_warning"`
	MemoryCritical float64 `json:"memory_critical"`
	DiskWarning   float64 `json:"disk_warning"`
	DiskCritical  float64 `json:"disk_critical"`
	LoadWarning   float64 `json:"load_warning"`
	LoadCritical  float64 `json:"load_critical"`
}

// HealthAlertingConfig configuration for health alerting
type HealthAlertingConfig struct {
	Enabled            bool                 `json:"enabled"`
	AlertOnStatus      []HealthStatus       `json:"alert_on_status"`
	AlertAfterDuration time.Duration        `json:"alert_after_duration"`
	AlertChannels      []AlertChannelConfig `json:"alert_channels"`
	Escalation         *EscalationConfig    `json:"escalation,omitempty"`
}

// AlertChannelConfig configuration for alert channels
type AlertChannelConfig struct {
	Type   string                 `json:"type"`   // "webhook", "email", "slack", "pagerduty"
	Config map[string]interface{} `json:"config"`
}

// EscalationConfig configuration for alert escalation
type EscalationConfig struct {
	Enabled    bool          `json:"enabled"`
	Levels     []EscalationLevel `json:"levels"`
	MaxRetries int           `json:"max_retries"`
}

// EscalationLevel represents an escalation level
type EscalationLevel struct {
	Level       int           `json:"level"`
	Duration    time.Duration `json:"duration"`
	Channels    []string      `json:"channels"`
	Recipients  []string      `json:"recipients"`
}

// HealthCheckResult represents the result of a health check
type HealthCheckResult struct {
	Name        string                 `json:"name"`
	Status      HealthStatus           `json:"status"`
	CheckType   CheckType              `json:"check_type"`
	Message     string                 `json:"message"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration"`
	Error       string                 `json:"error,omitempty"`
	Retries     int                    `json:"retries"`
	Tags        []string               `json:"tags,omitempty"`
	Critical    bool                   `json:"critical"`
}

// OverallHealth represents the overall health status
type OverallHealth struct {
	Status          HealthStatus                   `json:"status"`
	Message         string                         `json:"message"`
	Timestamp       time.Time                      `json:"timestamp"`
	Uptime          time.Duration                  `json:"uptime"`
	Version         string                         `json:"version"`
	ComponentHealth map[string]HealthCheckResult   `json:"component_health"`
	Summary         *HealthSummary                 `json:"summary"`
	History         []HealthHistoryEntry           `json:"history,omitempty"`
}

// HealthSummary summarizes health check results
type HealthSummary struct {
	TotalChecks    int                      `json:"total_checks"`
	HealthyChecks  int                      `json:"healthy_checks"`
	DegradedChecks int                      `json:"degraded_checks"`
	UnhealthyChecks int                     `json:"unhealthy_checks"`
	CriticalChecks int                      `json:"critical_checks"`
	LastUpdate     time.Time                `json:"last_update"`
	StatusCounts   map[HealthStatus]int     `json:"status_counts"`
	CheckTypeCounts map[CheckType]int       `json:"check_type_counts"`
}

// HealthHistoryEntry represents a historical health entry
type HealthHistoryEntry struct {
	Timestamp time.Time    `json:"timestamp"`
	Status    HealthStatus `json:"status"`
	Message   string       `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// HealthChecker interface for health checks
type HealthChecker interface {
	Name() string
	Check(ctx context.Context) HealthCheckResult
	CheckType() CheckType
	IsCritical() bool
}

// HealthRegistry manages health checks and monitoring
type HealthRegistry struct {
	config         *HealthConfig
	checkers       map[string]HealthChecker
	results        map[string]HealthCheckResult
	history        []HealthHistoryEntry
	alerting       *HealthAlerting
	metrics        *MetricsRegistry
	logger         *CorrelatedLogger
	mu             sync.RWMutex
	startTime      time.Time
	stopChan       chan struct{}
	httpServer     *http.Server
}

// DefaultHealthConfig returns default health configuration
func DefaultHealthConfig() *HealthConfig {
	return &HealthConfig{
		Enabled:              true,
		LivenessPath:         "/health/live",
		ReadinessPath:        "/health/ready",
		HealthPath:           "/health",
		Port:                 8080,
		Timeout:              30 * time.Second,
		CheckInterval:        30 * time.Second,
		MaxConcurrentChecks:  10,
		RetryAttempts:        3,
		RetryDelay:           5 * time.Second,
		GracefulShutdown:     30 * time.Second,
		EnableDetailedStatus: true,
		EnableMetrics:        true,
		EnableHistory:        true,
		HistorySize:          100,
		ComponentConfigs:     make(map[string]ComponentConfig),
		ExternalChecks:       make([]ExternalCheckConfig, 0),
		ResourceThresholds: &ResourceThresholds{
			CPUWarning:     70.0,
			CPUCritical:    90.0,
			MemoryWarning:  80.0,
			MemoryCritical: 95.0,
			DiskWarning:    80.0,
			DiskCritical:   95.0,
			LoadWarning:    1.0,
			LoadCritical:   2.0,
		},
		AlertingConfig: &HealthAlertingConfig{
			Enabled:            true,
			AlertOnStatus:      []HealthStatus{HealthStatusUnhealthy, HealthStatusDegraded},
			AlertAfterDuration: 5 * time.Minute,
			AlertChannels:      make([]AlertChannelConfig, 0),
		},
	}
}

// NewHealthRegistry creates a new health registry
func NewHealthRegistry(config *HealthConfig, metrics *MetricsRegistry, logger *CorrelatedLogger) (*HealthRegistry, error) {
	if config == nil {
		config = DefaultHealthConfig()
	}

	if !config.Enabled {
		log.Info().Msg("Health monitoring disabled")
		return &HealthRegistry{config: config}, nil
	}

	hr := &HealthRegistry{
		config:    config,
		checkers:  make(map[string]HealthChecker),
		results:   make(map[string]HealthCheckResult),
		history:   make([]HealthHistoryEntry, 0, config.HistorySize),
		metrics:   metrics,
		logger:    logger,
		startTime: time.Now(),
		stopChan:  make(chan struct{}),
	}

	// Initialize alerting
	if config.AlertingConfig != nil && config.AlertingConfig.Enabled {
		hr.alerting = NewHealthAlerting(config.AlertingConfig, logger)
	}

	// Register default health checkers
	if err := hr.registerDefaultCheckers(); err != nil {
		return nil, fmt.Errorf("failed to register default checkers: %w", err)
	}

	// Register external checkers
	if err := hr.registerExternalCheckers(); err != nil {
		return nil, fmt.Errorf("failed to register external checkers: %w", err)
	}

	// Start periodic health checks
	go hr.runPeriodicChecks()

	// Start HTTP server for health endpoints
	if err := hr.startHTTPServer(); err != nil {
		return nil, fmt.Errorf("failed to start HTTP server: %w", err)
	}

	log.Info().
		Int("port", config.Port).
		Dur("check_interval", config.CheckInterval).
		Int("registered_checkers", len(hr.checkers)).
		Msg("Health monitoring initialized successfully")

	return hr, nil
}

// registerDefaultCheckers registers default health checkers
func (hr *HealthRegistry) registerDefaultCheckers() error {
	// Database checker
	if config, exists := hr.config.ComponentConfigs["database"]; exists && config.Enabled {
		checker := &DatabaseHealthChecker{
			name:    "database",
			config:  config,
			timeout: config.Timeout,
		}
		hr.RegisterChecker(checker)
	}

	// Memory checker
	if config, exists := hr.config.ComponentConfigs["memory"]; exists && config.Enabled {
		checker := &MemoryHealthChecker{
			name:       "memory",
			config:     config,
			thresholds: hr.config.ResourceThresholds,
		}
		hr.RegisterChecker(checker)
	}

	// CPU checker
	if config, exists := hr.config.ComponentConfigs["cpu"]; exists && config.Enabled {
		checker := &CPUHealthChecker{
			name:       "cpu",
			config:     config,
			thresholds: hr.config.ResourceThresholds,
		}
		hr.RegisterChecker(checker)
	}

	// Disk checker
	if config, exists := hr.config.ComponentConfigs["disk"]; exists && config.Enabled {
		checker := &DiskHealthChecker{
			name:       "disk",
			config:     config,
			thresholds: hr.config.ResourceThresholds,
		}
		hr.RegisterChecker(checker)
	}

	return nil
}

// registerExternalCheckers registers external health checkers
func (hr *HealthRegistry) registerExternalCheckers() error {
	for _, extConfig := range hr.config.ExternalChecks {
		checker := &ExternalHealthChecker{
			name:    extConfig.Name,
			config:  extConfig,
			client:  &http.Client{Timeout: extConfig.Timeout},
		}
		hr.RegisterChecker(checker)
	}
	return nil
}

// RegisterChecker registers a health checker
func (hr *HealthRegistry) RegisterChecker(checker HealthChecker) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	// Initialize checkers map if not already done (e.g., when disabled)
	if hr.checkers == nil {
		hr.checkers = make(map[string]HealthChecker)
	}

	hr.checkers[checker.Name()] = checker
	
	if hr.logger != nil {
		hr.logger.Info("Health checker registered",
			map[string]interface{}{
				"checker": checker.Name(),
				"type":    string(checker.CheckType()),
				"critical": checker.IsCritical(),
			})
	}
}

// UnregisterChecker unregisters a health checker
func (hr *HealthRegistry) UnregisterChecker(name string) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	// Handle case when maps are nil (e.g., when disabled)
	if hr.checkers != nil {
		delete(hr.checkers, name)
	}
	if hr.results != nil {
		delete(hr.results, name)
	}
	
	if hr.logger != nil {
		hr.logger.Info("Health checker unregistered",
			map[string]interface{}{"checker": name})
	}
}

// CheckHealth performs health checks and returns overall health
func (hr *HealthRegistry) CheckHealth(ctx context.Context, checkTypes ...CheckType) (*OverallHealth, error) {
	hr.mu.RLock()
	checkers := make(map[string]HealthChecker)
	for name, checker := range hr.checkers {
		// Filter by check type if specified
		if len(checkTypes) > 0 {
			match := false
			for _, ct := range checkTypes {
				if checker.CheckType() == ct {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}
		checkers[name] = checker
	}
	hr.mu.RUnlock()

	// Perform checks concurrently
	results := hr.runCheckers(ctx, checkers)

	// Update stored results
	hr.mu.Lock()
	// Initialize results map if not already done (e.g., when disabled)
	if hr.results == nil {
		hr.results = make(map[string]HealthCheckResult)
	}
	for name, result := range results {
		hr.results[name] = result
	}
	hr.mu.Unlock()

	// Determine overall health
	overallHealth := hr.calculateOverallHealth(results)

	// Add to history
	if hr.config.EnableHistory {
		hr.addToHistory(overallHealth)
	}

	// Update metrics
	if hr.config.EnableMetrics && hr.metrics != nil {
		hr.updateMetrics(overallHealth)
	}

	// Check alerting
	if hr.alerting != nil {
		hr.alerting.ProcessHealthStatus(overallHealth)
	}

	return overallHealth, nil
}

// runCheckers runs health checkers concurrently
func (hr *HealthRegistry) runCheckers(ctx context.Context, checkers map[string]HealthChecker) map[string]HealthCheckResult {
	results := make(map[string]HealthCheckResult)
	resultsChan := make(chan HealthCheckResult, len(checkers))
	semaphore := make(chan struct{}, hr.config.MaxConcurrentChecks)

	// Start checks
	var wg sync.WaitGroup
	for _, checker := range checkers {
		wg.Add(1)
		go func(c HealthChecker) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Perform check with retries
			result := hr.performCheckWithRetries(ctx, c)
			resultsChan <- result
		}(checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for result := range resultsChan {
		results[result.Name] = result
	}

	return results
}

// performCheckWithRetries performs health check with retry logic
func (hr *HealthRegistry) performCheckWithRetries(ctx context.Context, checker HealthChecker) HealthCheckResult {
	var lastResult HealthCheckResult
	
	for attempt := 0; attempt <= hr.config.RetryAttempts; attempt++ {
		// Create timeout context
		checkCtx, cancel := context.WithTimeout(ctx, hr.config.Timeout)
		
		// Perform check
		startTime := time.Now()
		result := checker.Check(checkCtx)
		result.Duration = time.Since(startTime)
		result.Retries = attempt
		
		cancel()
		
		lastResult = result
		
		// If check succeeded or this is the last attempt, return result
		if result.Status == HealthStatusHealthy || attempt == hr.config.RetryAttempts {
			break
		}
		
		// Wait before retry
		if attempt < hr.config.RetryAttempts {
			select {
			case <-ctx.Done():
				lastResult.Error = "Context cancelled during retry"
				return lastResult
			case <-time.After(hr.config.RetryDelay):
			}
		}
	}
	
	return lastResult
}

// calculateOverallHealth calculates overall health from component results
func (hr *HealthRegistry) calculateOverallHealth(results map[string]HealthCheckResult) *OverallHealth {
	now := time.Now()
	uptime := time.Since(hr.startTime)
	
	summary := &HealthSummary{
		TotalChecks:     len(results),
		LastUpdate:      now,
		StatusCounts:    make(map[HealthStatus]int),
		CheckTypeCounts: make(map[CheckType]int),
	}
	
	overallStatus := HealthStatusHealthy
	var criticalIssues []string
	var degradedIssues []string
	
	for _, result := range results {
		// Update summary
		summary.StatusCounts[result.Status]++
		summary.CheckTypeCounts[result.CheckType]++
		
		switch result.Status {
		case HealthStatusHealthy:
			summary.HealthyChecks++
		case HealthStatusDegraded:
			summary.DegradedChecks++
			degradedIssues = append(degradedIssues, result.Name)
			if overallStatus == HealthStatusHealthy {
				overallStatus = HealthStatusDegraded
			}
		case HealthStatusUnhealthy:
			summary.UnhealthyChecks++
			if result.Critical {
				summary.CriticalChecks++
				criticalIssues = append(criticalIssues, result.Name)
				overallStatus = HealthStatusUnhealthy
			} else {
				degradedIssues = append(degradedIssues, result.Name)
				if overallStatus == HealthStatusHealthy {
					overallStatus = HealthStatusDegraded
				}
			}
		}
	}
	
	// Generate message
	message := hr.generateHealthMessage(overallStatus, criticalIssues, degradedIssues)
	
	health := &OverallHealth{
		Status:          overallStatus,
		Message:         message,
		Timestamp:       now,
		Uptime:          uptime,
		Version:         "1.0.0", // This would come from build info
		ComponentHealth: results,
		Summary:         summary,
	}
	
	// Add history if enabled
	if hr.config.EnableHistory {
		hr.mu.RLock()
		health.History = make([]HealthHistoryEntry, len(hr.history))
		copy(health.History, hr.history)
		hr.mu.RUnlock()
	}
	
	return health
}

// generateHealthMessage generates a human-readable health message
func (hr *HealthRegistry) generateHealthMessage(status HealthStatus, criticalIssues, degradedIssues []string) string {
	switch status {
	case HealthStatusHealthy:
		return "All health checks passing"
	case HealthStatusDegraded:
		if len(degradedIssues) > 0 {
			return fmt.Sprintf("Degraded performance detected in: %s", strings.Join(degradedIssues, ", "))
		}
		return "System performance degraded"
	case HealthStatusUnhealthy:
		if len(criticalIssues) > 0 {
			return fmt.Sprintf("Critical issues detected in: %s", strings.Join(criticalIssues, ", "))
		}
		return "System unhealthy"
	default:
		return "Health status unknown"
	}
}

// addToHistory adds health status to history
func (hr *HealthRegistry) addToHistory(health *OverallHealth) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	
	// Initialize history if not already done (e.g., when disabled)
	if hr.history == nil {
		hr.history = make([]HealthHistoryEntry, 0, hr.config.HistorySize)
	}
	
	entry := HealthHistoryEntry{
		Timestamp: health.Timestamp,
		Status:    health.Status,
		Message:   health.Message,
		Details: map[string]interface{}{
			"total_checks":    health.Summary.TotalChecks,
			"healthy_checks":  health.Summary.HealthyChecks,
			"degraded_checks": health.Summary.DegradedChecks,
			"unhealthy_checks": health.Summary.UnhealthyChecks,
			"critical_checks": health.Summary.CriticalChecks,
		},
	}
	
	hr.history = append(hr.history, entry)
	
	// Trim history if it exceeds max size
	if len(hr.history) > hr.config.HistorySize {
		hr.history = hr.history[len(hr.history)-hr.config.HistorySize:]
	}
}

// updateMetrics updates health-related metrics
func (hr *HealthRegistry) updateMetrics(health *OverallHealth) {
	// This would update metrics like:
	// - health_check_status (gauge with labels for component, status)
	// - health_check_duration (histogram with labels for component)
	// - health_check_total (counter with labels for component, status)
	// - overall_health_status (gauge)
	
	if hr.logger != nil {
		hr.logger.Debug("Health metrics updated",
			map[string]interface{}{
				"overall_status":  string(health.Status),
				"total_checks":    health.Summary.TotalChecks,
				"healthy_checks":  health.Summary.HealthyChecks,
				"degraded_checks": health.Summary.DegradedChecks,
				"unhealthy_checks": health.Summary.UnhealthyChecks,
			})
	}
}

// runPeriodicChecks runs health checks periodically
func (hr *HealthRegistry) runPeriodicChecks() {
	ticker := time.NewTicker(hr.config.CheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-hr.stopChan:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), hr.config.Timeout)
			if _, err := hr.CheckHealth(ctx); err != nil && hr.logger != nil {
				hr.logger.Error("Periodic health check failed", err)
			}
			cancel()
		}
	}
}

// startHTTPServer starts the HTTP server for health endpoints
func (hr *HealthRegistry) startHTTPServer() error {
	mux := http.NewServeMux()
	
	// Liveness probe - minimal check
	mux.HandleFunc(hr.config.LivenessPath, hr.handleLiveness)
	
	// Readiness probe - full check
	mux.HandleFunc(hr.config.ReadinessPath, hr.handleReadiness)
	
	// General health check with detailed info
	mux.HandleFunc(hr.config.HealthPath, hr.handleHealth)
	
	hr.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", hr.config.Port),
		Handler: mux,
	}
	
	go func() {
		if err := hr.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			if hr.logger != nil {
				hr.logger.Error("Health HTTP server failed", err)
			}
		}
	}()
	
	return nil
}

// handleLiveness handles liveness probe requests
func (hr *HealthRegistry) handleLiveness(w http.ResponseWriter, r *http.Request) {
	// Simple liveness check - just verify the service is running
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"uptime":    time.Since(hr.startTime).String(),
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}

// handleReadiness handles readiness probe requests
func (hr *HealthRegistry) handleReadiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), hr.config.Timeout)
	defer cancel()
	
	// Check readiness-specific components
	health, err := hr.CheckHealth(ctx, CheckTypeReadiness)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	
	switch health.Status {
	case HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case HealthStatusDegraded:
		w.WriteHeader(http.StatusOK) // Still ready, but degraded
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	json.NewEncoder(w).Encode(health)
}

// handleHealth handles general health check requests
func (hr *HealthRegistry) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), hr.config.Timeout)
	defer cancel()
	
	// Perform full health check
	health, err := hr.CheckHealth(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	
	// Determine HTTP status based on health
	switch health.Status {
	case HealthStatusHealthy:
		w.WriteHeader(http.StatusOK)
	case HealthStatusDegraded:
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	
	// Return detailed or simple response based on configuration
	if hr.config.EnableDetailedStatus {
		json.NewEncoder(w).Encode(health)
	} else {
		simple := map[string]interface{}{
			"status":    health.Status,
			"message":   health.Message,
			"timestamp": health.Timestamp,
		}
		json.NewEncoder(w).Encode(simple)
	}
}

// GetHealth returns current health status
func (hr *HealthRegistry) GetHealth() *OverallHealth {
	hr.mu.RLock()
	defer hr.mu.RUnlock()
	
	results := make(map[string]HealthCheckResult)
	for name, result := range hr.results {
		results[name] = result
	}
	
	return hr.calculateOverallHealth(results)
}

// GetHealthHistory returns health history
func (hr *HealthRegistry) GetHealthHistory() []HealthHistoryEntry {
	hr.mu.RLock()
	defer hr.mu.RUnlock()
	
	history := make([]HealthHistoryEntry, len(hr.history))
	copy(history, hr.history)
	return history
}

// Shutdown gracefully shuts down the health registry
func (hr *HealthRegistry) Shutdown(ctx context.Context) error {
	close(hr.stopChan)
	
	if hr.httpServer != nil {
		if err := hr.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown HTTP server: %w", err)
		}
	}
	
	if hr.logger != nil {
		hr.logger.Info("Health monitoring shut down successfully")
	}
	
	return nil
}

// Health checker implementations

// DatabaseHealthChecker checks database connectivity
type DatabaseHealthChecker struct {
	name    string
	config  ComponentConfig
	timeout time.Duration
}

func (dhc *DatabaseHealthChecker) Name() string                 { return dhc.name }
func (dhc *DatabaseHealthChecker) CheckType() CheckType         { return CheckTypeDatabase }
func (dhc *DatabaseHealthChecker) IsCritical() bool             { return dhc.config.Critical }

func (dhc *DatabaseHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      dhc.name,
		CheckType: dhc.CheckType(),
		Timestamp: time.Now(),
		Critical:  dhc.IsCritical(),
		Tags:      dhc.config.Tags,
	}
	
	// Simplified database check - in real implementation, would test actual connection
	// For now, simulate a check
	time.Sleep(10 * time.Millisecond) // Simulate check time
	
	result.Status = HealthStatusHealthy
	result.Message = "Database connection successful"
	result.Details = map[string]interface{}{
		"connection_pool_size": 10,
		"active_connections":   5,
		"query_time_ms":       10,
	}
	
	return result
}

// MemoryHealthChecker checks memory usage
type MemoryHealthChecker struct {
	name       string
	config     ComponentConfig
	thresholds *ResourceThresholds
}

func (mhc *MemoryHealthChecker) Name() string       { return mhc.name }
func (mhc *MemoryHealthChecker) CheckType() CheckType { return CheckTypeResource }
func (mhc *MemoryHealthChecker) IsCritical() bool   { return mhc.config.Critical }

func (mhc *MemoryHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      mhc.name,
		CheckType: mhc.CheckType(),
		Timestamp: time.Now(),
		Critical:  mhc.IsCritical(),
		Tags:      mhc.config.Tags,
	}
	
	// Simplified memory check - would use actual system metrics
	memoryUsage := 75.0 // Simulate 75% usage
	
	result.Details = map[string]interface{}{
		"memory_usage_percent": memoryUsage,
		"memory_total_mb":      8192,
		"memory_used_mb":       6144,
		"memory_free_mb":       2048,
	}
	
	if memoryUsage >= mhc.thresholds.MemoryCritical {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("Memory usage critical: %.1f%%", memoryUsage)
	} else if memoryUsage >= mhc.thresholds.MemoryWarning {
		result.Status = HealthStatusDegraded
		result.Message = fmt.Sprintf("Memory usage high: %.1f%%", memoryUsage)
	} else {
		result.Status = HealthStatusHealthy
		result.Message = fmt.Sprintf("Memory usage normal: %.1f%%", memoryUsage)
	}
	
	return result
}

// CPUHealthChecker checks CPU usage
type CPUHealthChecker struct {
	name       string
	config     ComponentConfig
	thresholds *ResourceThresholds
}

func (chc *CPUHealthChecker) Name() string       { return chc.name }
func (chc *CPUHealthChecker) CheckType() CheckType { return CheckTypeResource }
func (chc *CPUHealthChecker) IsCritical() bool   { return chc.config.Critical }

func (chc *CPUHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      chc.name,
		CheckType: chc.CheckType(),
		Timestamp: time.Now(),
		Critical:  chc.IsCritical(),
		Tags:      chc.config.Tags,
	}
	
	// Simplified CPU check
	cpuUsage := 45.0 // Simulate 45% usage
	
	result.Details = map[string]interface{}{
		"cpu_usage_percent": cpuUsage,
		"cpu_cores":         8,
		"load_average_1m":   1.2,
		"load_average_5m":   1.1,
		"load_average_15m":  1.0,
	}
	
	if cpuUsage >= chc.thresholds.CPUCritical {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("CPU usage critical: %.1f%%", cpuUsage)
	} else if cpuUsage >= chc.thresholds.CPUWarning {
		result.Status = HealthStatusDegraded
		result.Message = fmt.Sprintf("CPU usage high: %.1f%%", cpuUsage)
	} else {
		result.Status = HealthStatusHealthy
		result.Message = fmt.Sprintf("CPU usage normal: %.1f%%", cpuUsage)
	}
	
	return result
}

// DiskHealthChecker checks disk usage
type DiskHealthChecker struct {
	name       string
	config     ComponentConfig
	thresholds *ResourceThresholds
}

func (dhc *DiskHealthChecker) Name() string       { return dhc.name }
func (dhc *DiskHealthChecker) CheckType() CheckType { return CheckTypeResource }
func (dhc *DiskHealthChecker) IsCritical() bool   { return dhc.config.Critical }

func (dhc *DiskHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      dhc.name,
		CheckType: dhc.CheckType(),
		Timestamp: time.Now(),
		Critical:  dhc.IsCritical(),
		Tags:      dhc.config.Tags,
	}
	
	// Simplified disk check
	diskUsage := 65.0 // Simulate 65% usage
	
	result.Details = map[string]interface{}{
		"disk_usage_percent": diskUsage,
		"disk_total_gb":      1000,
		"disk_used_gb":       650,
		"disk_free_gb":       350,
		"inodes_usage_percent": 25.0,
	}
	
	if diskUsage >= dhc.thresholds.DiskCritical {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("Disk usage critical: %.1f%%", diskUsage)
	} else if diskUsage >= dhc.thresholds.DiskWarning {
		result.Status = HealthStatusDegraded
		result.Message = fmt.Sprintf("Disk usage high: %.1f%%", diskUsage)
	} else {
		result.Status = HealthStatusHealthy
		result.Message = fmt.Sprintf("Disk usage normal: %.1f%%", diskUsage)
	}
	
	return result
}

// ExternalHealthChecker checks external services
type ExternalHealthChecker struct {
	name   string
	config ExternalCheckConfig
	client *http.Client
}

func (ehc *ExternalHealthChecker) Name() string       { return ehc.name }
func (ehc *ExternalHealthChecker) CheckType() CheckType { return CheckTypeExternal }
func (ehc *ExternalHealthChecker) IsCritical() bool   { return ehc.config.Critical }

func (ehc *ExternalHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      ehc.name,
		CheckType: ehc.CheckType(),
		Timestamp: time.Now(),
		Critical:  ehc.IsCritical(),
	}
	
	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, ehc.config.Method, ehc.config.URL, nil)
	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Error = fmt.Sprintf("Failed to create request: %v", err)
		return result
	}
	
	// Add headers
	for key, value := range ehc.config.Headers {
		req.Header.Set(key, value)
	}
	
	// Perform request
	resp, err := ehc.client.Do(req)
	if err != nil {
		result.Status = HealthStatusUnhealthy
		result.Error = fmt.Sprintf("Request failed: %v", err)
		return result
	}
	defer resp.Body.Close()
	
	result.Details = map[string]interface{}{
		"url":           ehc.config.URL,
		"method":        ehc.config.Method,
		"status_code":   resp.StatusCode,
		"response_time": "50ms", // Would measure actual response time
	}
	
	// Check status code
	if resp.StatusCode == ehc.config.ExpectedStatus {
		result.Status = HealthStatusHealthy
		result.Message = fmt.Sprintf("External service %s responded successfully", ehc.config.URL)
	} else {
		result.Status = HealthStatusUnhealthy
		result.Message = fmt.Sprintf("External service %s returned status %d, expected %d", 
			ehc.config.URL, resp.StatusCode, ehc.config.ExpectedStatus)
	}
	
	return result
}

// HealthAlerting handles health-based alerting
type HealthAlerting struct {
	config      *HealthAlertingConfig
	logger      *CorrelatedLogger
	alertStates map[string]*AlertState
	mu          sync.RWMutex
}

// AlertState tracks the state of an alert
type AlertState struct {
	FirstSeen    time.Time
	LastSeen     time.Time
	AlertLevel   int
	Escalated    bool
	Acknowledged bool
}

// NewHealthAlerting creates a new health alerting system
func NewHealthAlerting(config *HealthAlertingConfig, logger *CorrelatedLogger) *HealthAlerting {
	return &HealthAlerting{
		config:      config,
		logger:      logger,
		alertStates: make(map[string]*AlertState),
	}
}

// ProcessHealthStatus processes health status for alerting
func (ha *HealthAlerting) ProcessHealthStatus(health *OverallHealth) {
	ha.mu.Lock()
	defer ha.mu.Unlock()
	
	// Check if we should alert on this status
	shouldAlert := false
	for _, alertStatus := range ha.config.AlertOnStatus {
		if health.Status == alertStatus {
			shouldAlert = true
			break
		}
	}
	
	if !shouldAlert {
		// Clear alert state if status is now healthy
		if health.Status == HealthStatusHealthy {
			delete(ha.alertStates, "overall")
		}
		return
	}
	
	// Check alert state
	alertKey := "overall"
	state, exists := ha.alertStates[alertKey]
	if !exists {
		state = &AlertState{
			FirstSeen: health.Timestamp,
			LastSeen:  health.Timestamp,
		}
		ha.alertStates[alertKey] = state
	} else {
		state.LastSeen = health.Timestamp
	}
	
	// Check if we should fire alert
	if time.Since(state.FirstSeen) >= ha.config.AlertAfterDuration {
		ha.fireAlert(health, state)
	}
}

// fireAlert fires an alert
func (ha *HealthAlerting) fireAlert(health *OverallHealth, state *AlertState) {
	alert := map[string]interface{}{
		"status":     health.Status,
		"message":    health.Message,
		"timestamp":  health.Timestamp,
		"first_seen": state.FirstSeen,
		"duration":   time.Since(state.FirstSeen),
		"summary":    health.Summary,
	}
	
	if ha.logger != nil {
		ha.logger.Warn("Health alert fired", alert)
	}
	
	// Here you would send alerts to configured channels
	// (webhook, email, Slack, PagerDuty, etc.)
}