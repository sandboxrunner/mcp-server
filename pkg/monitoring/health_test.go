package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultHealthConfig(t *testing.T) {
	config := DefaultHealthConfig()
	
	assert.True(t, config.Enabled)
	assert.Equal(t, "/health/live", config.LivenessPath)
	assert.Equal(t, "/health/ready", config.ReadinessPath)
	assert.Equal(t, "/health", config.HealthPath)
	assert.Equal(t, 8080, config.Port)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 30*time.Second, config.CheckInterval)
	assert.Equal(t, 10, config.MaxConcurrentChecks)
	assert.Equal(t, 3, config.RetryAttempts)
	assert.NotNil(t, config.ResourceThresholds)
	assert.NotNil(t, config.AlertingConfig)
}

func TestNewHealthRegistry_Disabled(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, hr)
	assert.Equal(t, config, hr.config)
}

func TestNewHealthRegistry_Enabled(t *testing.T) {
	config := DefaultHealthConfig()
	config.Port = 0 // Use random port for testing
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, hr)
	assert.NotNil(t, hr.checkers)
	assert.NotNil(t, hr.results)
	assert.NotNil(t, hr.history)
}

func TestHealthRegistry_RegisterChecker(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false // Disable to avoid starting servers
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	checker := &MockHealthChecker{
		name:     "test_checker",
		checkType: CheckTypeLiveness,
		critical: true,
	}
	
	hr.RegisterChecker(checker)
	
	assert.Len(t, hr.checkers, 1)
	assert.Contains(t, hr.checkers, "test_checker")
	assert.Equal(t, checker, hr.checkers["test_checker"])
}

func TestHealthRegistry_UnregisterChecker(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	checker := &MockHealthChecker{name: "test_checker"}
	hr.RegisterChecker(checker)
	
	assert.Len(t, hr.checkers, 1)
	
	hr.UnregisterChecker("test_checker")
	
	assert.Len(t, hr.checkers, 0)
	assert.NotContains(t, hr.checkers, "test_checker")
}

func TestHealthRegistry_CheckHealth(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	config.EnableHistory = true
	config.HistorySize = 10
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	// Register test checkers
	hr.RegisterChecker(&MockHealthChecker{
		name:     "healthy_checker",
		status:   HealthStatusHealthy,
		checkType: CheckTypeLiveness,
		critical: true,
	})
	
	hr.RegisterChecker(&MockHealthChecker{
		name:     "degraded_checker",
		status:   HealthStatusDegraded,
		checkType: CheckTypeReadiness,
		critical: false,
	})
	
	ctx := context.Background()
	health, err := hr.CheckHealth(ctx)
	require.NoError(t, err)
	
	assert.NotNil(t, health)
	assert.Equal(t, HealthStatusDegraded, health.Status) // Degraded due to one degraded checker
	assert.Contains(t, health.Message, "degraded_checker")
	assert.Len(t, health.ComponentHealth, 2)
	assert.NotNil(t, health.Summary)
	assert.Equal(t, 2, health.Summary.TotalChecks)
	assert.Equal(t, 1, health.Summary.HealthyChecks)
	assert.Equal(t, 1, health.Summary.DegradedChecks)
	assert.Equal(t, 0, health.Summary.UnhealthyChecks)
}

func TestHealthRegistry_CheckHealth_CriticalFailure(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	// Register critical unhealthy checker
	hr.RegisterChecker(&MockHealthChecker{
		name:     "critical_checker",
		status:   HealthStatusUnhealthy,
		checkType: CheckTypeLiveness,
		critical: true,
	})
	
	ctx := context.Background()
	health, err := hr.CheckHealth(ctx)
	require.NoError(t, err)
	
	assert.Equal(t, HealthStatusUnhealthy, health.Status)
	assert.Contains(t, health.Message, "critical_checker")
	assert.Equal(t, 1, health.Summary.CriticalChecks)
}

func TestHealthRegistry_CheckHealth_WithCheckTypes(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	// Register checkers with different types
	hr.RegisterChecker(&MockHealthChecker{
		name:     "liveness_checker",
		status:   HealthStatusHealthy,
		checkType: CheckTypeLiveness,
	})
	
	hr.RegisterChecker(&MockHealthChecker{
		name:     "readiness_checker",
		status:   HealthStatusHealthy,
		checkType: CheckTypeReadiness,
	})
	
	ctx := context.Background()
	
	// Check only liveness
	health, err := hr.CheckHealth(ctx, CheckTypeLiveness)
	require.NoError(t, err)
	assert.Len(t, health.ComponentHealth, 1)
	assert.Contains(t, health.ComponentHealth, "liveness_checker")
	
	// Check only readiness
	health, err = hr.CheckHealth(ctx, CheckTypeReadiness)
	require.NoError(t, err)
	assert.Len(t, health.ComponentHealth, 1)
	assert.Contains(t, health.ComponentHealth, "readiness_checker")
	
	// Check all
	health, err = hr.CheckHealth(ctx)
	require.NoError(t, err)
	assert.Len(t, health.ComponentHealth, 2)
}

func TestHealthRegistry_CheckHealth_WithRetries(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	config.RetryAttempts = 2
	config.RetryDelay = 10 * time.Millisecond
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	// Register checker that fails first attempt but succeeds on retry
	checker := &MockHealthChecker{
		name:       "retry_checker",
		checkType:  CheckTypeLiveness,
		failCount:  1, // Fail first attempt
		targetStatus: HealthStatusHealthy,
	}
	
	hr.RegisterChecker(checker)
	
	ctx := context.Background()
	health, err := hr.CheckHealth(ctx)
	require.NoError(t, err)
	
	result := health.ComponentHealth["retry_checker"]
	assert.Equal(t, HealthStatusHealthy, result.Status)
	assert.Equal(t, 1, result.Retries) // Should have retried once
}

func TestHealthRegistry_PerformCheckWithRetries_ContextCancelled(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	config.RetryAttempts = 3
	config.RetryDelay = 100 * time.Millisecond
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	checker := &MockHealthChecker{
		name:      "slow_checker",
		status:    HealthStatusUnhealthy,
		delay:     50 * time.Millisecond,
		checkType: CheckTypeLiveness,
	}
	
	// Cancel context after first attempt
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	
	result := hr.performCheckWithRetries(ctx, checker)
	
	assert.Equal(t, HealthStatusUnhealthy, result.Status)
	assert.Contains(t, result.Error, "Context cancelled")
}

func TestHealthRegistry_AddToHistory(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	config.EnableHistory = true
	config.HistorySize = 3
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	// Add multiple health entries
	for i := 0; i < 5; i++ {
		health := &OverallHealth{
			Status:    HealthStatusHealthy,
			Message:   fmt.Sprintf("Test message %d", i),
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			Summary: &HealthSummary{
				TotalChecks:   1,
				HealthyChecks: 1,
			},
		}
		hr.addToHistory(health)
	}
	
	// Should only keep last 3 entries
	assert.Len(t, hr.history, 3)
	
	// Should be the last 3 entries (2, 3, 4)
	assert.Contains(t, hr.history[0].Message, "Test message 2")
	assert.Contains(t, hr.history[1].Message, "Test message 3")
	assert.Contains(t, hr.history[2].Message, "Test message 4")
}

func TestHealthRegistry_GetHealth(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	hr.RegisterChecker(&MockHealthChecker{
		name:     "test_checker",
		status:   HealthStatusHealthy,
		checkType: CheckTypeLiveness,
	})
	
	// First check to populate results
	ctx := context.Background()
	_, err = hr.CheckHealth(ctx)
	require.NoError(t, err)
	
	// Get cached health
	health := hr.GetHealth()
	assert.NotNil(t, health)
	assert.Len(t, health.ComponentHealth, 1)
}

func TestHealthRegistry_GetHealthHistory(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	config.EnableHistory = true
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	// Add some history
	health := &OverallHealth{
		Status:    HealthStatusHealthy,
		Message:   "Test",
		Timestamp: time.Now(),
		Summary:   &HealthSummary{TotalChecks: 1},
	}
	hr.addToHistory(health)
	
	history := hr.GetHealthHistory()
	assert.Len(t, history, 1)
	assert.Equal(t, "Test", history[0].Message)
}

func TestHealthRegistry_HTTPEndpoints(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	hr.RegisterChecker(&MockHealthChecker{
		name:     "test_checker",
		status:   HealthStatusHealthy,
		checkType: CheckTypeLiveness,
	})
	
	// Test liveness endpoint
	req := httptest.NewRequest("GET", config.LivenessPath, nil)
	w := httptest.NewRecorder()
	hr.handleLiveness(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	
	var response map[string]interface{}
	err = json.NewDecoder(w.Body).Decode(&response)
	require.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
	
	// Test readiness endpoint
	req = httptest.NewRequest("GET", config.ReadinessPath, nil)
	w = httptest.NewRecorder()
	hr.handleReadiness(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
	
	// Test health endpoint
	req = httptest.NewRequest("GET", config.HealthPath, nil)
	w = httptest.NewRecorder()
	hr.handleHealth(w, req)
	
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHealthRegistry_HTTPEndpoints_Unhealthy(t *testing.T) {
	config := DefaultHealthConfig()
	config.Enabled = false
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	hr.RegisterChecker(&MockHealthChecker{
		name:     "unhealthy_checker",
		status:   HealthStatusUnhealthy,
		checkType: CheckTypeReadiness,
		critical: true,
	})
	
	// Test readiness endpoint with unhealthy checker
	req := httptest.NewRequest("GET", config.ReadinessPath, nil)
	w := httptest.NewRecorder()
	hr.handleReadiness(w, req)
	
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	
	// Test health endpoint with unhealthy checker
	req = httptest.NewRequest("GET", config.HealthPath, nil)
	w = httptest.NewRecorder()
	hr.handleHealth(w, req)
	
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHealthRegistry_Shutdown(t *testing.T) {
	config := DefaultHealthConfig()
	config.Port = 0 // Use random port
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(t, err)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = hr.Shutdown(ctx)
	assert.NoError(t, err)
}

// Test health checker implementations

func TestDatabaseHealthChecker(t *testing.T) {
	config := ComponentConfig{
		Critical: true,
		Tags:     []string{"database", "primary"},
	}
	
	checker := &DatabaseHealthChecker{
		name:    "database",
		config:  config,
		timeout: 10 * time.Second,
	}
	
	assert.Equal(t, "database", checker.Name())
	assert.Equal(t, CheckTypeDatabase, checker.CheckType())
	assert.True(t, checker.IsCritical())
	
	ctx := context.Background()
	result := checker.Check(ctx)
	
	assert.Equal(t, "database", result.Name)
	assert.Equal(t, CheckTypeDatabase, result.CheckType)
	assert.Equal(t, HealthStatusHealthy, result.Status)
	assert.True(t, result.Critical)
	assert.Equal(t, config.Tags, result.Tags)
	assert.Contains(t, result.Message, "successful")
	assert.NotNil(t, result.Details)
}

func TestMemoryHealthChecker(t *testing.T) {
	config := ComponentConfig{Critical: false}
	thresholds := &ResourceThresholds{
		MemoryWarning:  80.0,
		MemoryCritical: 95.0,
	}
	
	checker := &MemoryHealthChecker{
		name:       "memory",
		config:     config,
		thresholds: thresholds,
	}
	
	assert.Equal(t, "memory", checker.Name())
	assert.Equal(t, CheckTypeResource, checker.CheckType())
	assert.False(t, checker.IsCritical())
	
	ctx := context.Background()
	result := checker.Check(ctx)
	
	assert.Equal(t, "memory", result.Name)
	assert.Equal(t, CheckTypeResource, result.CheckType)
	assert.NotEmpty(t, result.Message)
	assert.NotNil(t, result.Details)
	
	// Check that memory usage is reported
	memoryUsage, exists := result.Details["memory_usage_percent"]
	assert.True(t, exists)
	assert.IsType(t, float64(0), memoryUsage)
}

func TestCPUHealthChecker(t *testing.T) {
	config := ComponentConfig{Critical: false}
	thresholds := &ResourceThresholds{
		CPUWarning:  70.0,
		CPUCritical: 90.0,
	}
	
	checker := &CPUHealthChecker{
		name:       "cpu",
		config:     config,
		thresholds: thresholds,
	}
	
	ctx := context.Background()
	result := checker.Check(ctx)
	
	assert.Equal(t, "cpu", result.Name)
	assert.Equal(t, CheckTypeResource, result.CheckType)
	assert.NotEmpty(t, result.Message)
	
	// Check that CPU usage is reported
	cpuUsage, exists := result.Details["cpu_usage_percent"]
	assert.True(t, exists)
	assert.IsType(t, float64(0), cpuUsage)
}

func TestDiskHealthChecker(t *testing.T) {
	config := ComponentConfig{Critical: true}
	thresholds := &ResourceThresholds{
		DiskWarning:  80.0,
		DiskCritical: 95.0,
	}
	
	checker := &DiskHealthChecker{
		name:       "disk",
		config:     config,
		thresholds: thresholds,
	}
	
	ctx := context.Background()
	result := checker.Check(ctx)
	
	assert.Equal(t, "disk", result.Name)
	assert.Equal(t, CheckTypeResource, result.CheckType)
	assert.True(t, result.Critical)
	assert.NotEmpty(t, result.Message)
	
	// Check that disk usage is reported
	diskUsage, exists := result.Details["disk_usage_percent"]
	assert.True(t, exists)
	assert.IsType(t, float64(0), diskUsage)
}

func TestExternalHealthChecker(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()
	
	config := ExternalCheckConfig{
		Name:           "external_api",
		URL:            server.URL,
		Method:         "GET",
		ExpectedStatus: http.StatusOK,
		Critical:       true,
		Timeout:        5 * time.Second,
	}
	
	checker := &ExternalHealthChecker{
		name:   config.Name,
		config: config,
		client: &http.Client{Timeout: config.Timeout},
	}
	
	assert.Equal(t, "external_api", checker.Name())
	assert.Equal(t, CheckTypeExternal, checker.CheckType())
	assert.True(t, checker.IsCritical())
	
	ctx := context.Background()
	result := checker.Check(ctx)
	
	assert.Equal(t, "external_api", result.Name)
	assert.Equal(t, CheckTypeExternal, result.CheckType)
	assert.Equal(t, HealthStatusHealthy, result.Status)
	assert.Contains(t, result.Message, "responded successfully")
	assert.NotNil(t, result.Details)
}

func TestExternalHealthChecker_Failure(t *testing.T) {
	// Create test server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	
	config := ExternalCheckConfig{
		Name:           "failing_api",
		URL:            server.URL,
		Method:         "GET",
		ExpectedStatus: http.StatusOK,
		Critical:       true,
		Timeout:        5 * time.Second,
	}
	
	checker := &ExternalHealthChecker{
		name:   config.Name,
		config: config,
		client: &http.Client{Timeout: config.Timeout},
	}
	
	ctx := context.Background()
	result := checker.Check(ctx)
	
	assert.Equal(t, HealthStatusUnhealthy, result.Status)
	assert.Contains(t, result.Message, "returned status 500")
}

// Test health alerting

func TestNewHealthAlerting(t *testing.T) {
	config := &HealthAlertingConfig{
		Enabled:            true,
		AlertOnStatus:      []HealthStatus{HealthStatusUnhealthy},
		AlertAfterDuration: 5 * time.Minute,
	}
	
	alerting := NewHealthAlerting(config, nil)
	assert.NotNil(t, alerting)
	assert.Equal(t, config, alerting.config)
	assert.NotNil(t, alerting.alertStates)
}

func TestHealthAlerting_ProcessHealthStatus(t *testing.T) {
	config := &HealthAlertingConfig{
		Enabled:            true,
		AlertOnStatus:      []HealthStatus{HealthStatusUnhealthy},
		AlertAfterDuration: 100 * time.Millisecond,
	}
	
	alerting := NewHealthAlerting(config, nil)
	
	health := &OverallHealth{
		Status:    HealthStatusUnhealthy,
		Message:   "System unhealthy",
		Timestamp: time.Now(),
		Summary:   &HealthSummary{},
	}
	
	// First call - should not alert yet
	alerting.ProcessHealthStatus(health)
	assert.Len(t, alerting.alertStates, 1)
	
	// Wait for alert duration and process again
	time.Sleep(150 * time.Millisecond)
	alerting.ProcessHealthStatus(health)
	// Alert should be fired (tested via logs in real implementation)
}

func TestHealthAlerting_ProcessHealthStatus_Healthy(t *testing.T) {
	config := &HealthAlertingConfig{
		Enabled:       true,
		AlertOnStatus: []HealthStatus{HealthStatusUnhealthy},
	}
	
	alerting := NewHealthAlerting(config, nil)
	
	// Add existing alert state
	alerting.alertStates["overall"] = &AlertState{
		FirstSeen: time.Now().Add(-time.Hour),
	}
	
	health := &OverallHealth{
		Status:    HealthStatusHealthy,
		Message:   "System healthy",
		Timestamp: time.Now(),
		Summary:   &HealthSummary{},
	}
	
	alerting.ProcessHealthStatus(health)
	
	// Alert state should be cleared for healthy status
	assert.Len(t, alerting.alertStates, 0)
}

// Mock health checker for testing

type MockHealthChecker struct {
	name         string
	status       HealthStatus
	checkType    CheckType
	critical     bool
	delay        time.Duration
	failCount    int
	currentFails int
	targetStatus HealthStatus
	message      string
	details      map[string]interface{}
	err          error
}

func (m *MockHealthChecker) Name() string {
	return m.name
}

func (m *MockHealthChecker) CheckType() CheckType {
	return m.checkType
}

func (m *MockHealthChecker) IsCritical() bool {
	return m.critical
}

func (m *MockHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      m.name,
		CheckType: m.checkType,
		Timestamp: time.Now(),
		Critical:  m.critical,
	}
	
	// Simulate delay
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			result.Status = HealthStatusUnhealthy
			result.Error = "Context cancelled during retry"
			return result
		case <-time.After(m.delay):
		}
	}
	
	// Handle failure count for retry testing
	if m.failCount > 0 && m.currentFails < m.failCount {
		m.currentFails++
		result.Status = HealthStatusUnhealthy
		result.Message = "Simulated failure"
		result.Error = "Mock failure"
		return result
	}
	
	// Use target status if set and failures are done
	if m.targetStatus != "" && m.currentFails >= m.failCount {
		result.Status = m.targetStatus
	} else {
		result.Status = m.status
	}
	
	if m.message != "" {
		result.Message = m.message
	} else {
		result.Message = fmt.Sprintf("Mock checker status: %s", result.Status)
	}
	
	if m.details != nil {
		result.Details = m.details
	}
	
	if m.err != nil {
		result.Error = m.err.Error()
	}
	
	return result
}

// Benchmark tests

func BenchmarkHealthRegistry_CheckHealth(b *testing.B) {
	config := DefaultHealthConfig()
	config.Enabled = false
	config.EnableHistory = false
	config.EnableMetrics = false
	
	hr, err := NewHealthRegistry(config, nil, nil)
	require.NoError(b, err)
	
	// Register multiple checkers
	for i := 0; i < 10; i++ {
		hr.RegisterChecker(&MockHealthChecker{
			name:     fmt.Sprintf("checker_%d", i),
			status:   HealthStatusHealthy,
			checkType: CheckTypeLiveness,
		})
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hr.CheckHealth(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDatabaseHealthChecker_Check(b *testing.B) {
	checker := &DatabaseHealthChecker{
		name:    "database",
		config:  ComponentConfig{},
		timeout: 10 * time.Second,
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check(ctx)
	}
}

func BenchmarkMemoryHealthChecker_Check(b *testing.B) {
	checker := &MemoryHealthChecker{
		name:       "memory",
		config:     ComponentConfig{},
		thresholds: DefaultHealthConfig().ResourceThresholds,
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checker.Check(ctx)
	}
}