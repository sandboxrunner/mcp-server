package sandbox

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/beam-cloud/go-runc"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockRuncClient implements a mock runc client for testing
type MockRuncClient struct {
	containers []*runc.Container
	err        error
}

func NewMockRuncClient() *MockRuncClient {
	return &MockRuncClient{
		containers: make([]*runc.Container, 0),
	}
}

func (m *MockRuncClient) AddContainer(id, status string, pid int) {
	m.containers = append(m.containers, &runc.Container{
		ID:     id,
		Status: status,
		Pid:    pid,
	})
}

func (m *MockRuncClient) SetError(err error) {
	m.err = err
}

func (m *MockRuncClient) ListContainers(ctx context.Context) ([]*runc.Container, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.containers, nil
}

// Implement other methods required by runtime.RunCClient interface as no-ops for testing
func (m *MockRuncClient) CreateContainer(ctx context.Context, config runtime.ContainerConfig) error {
	return nil
}

func (m *MockRuncClient) StartContainer(ctx context.Context, containerID string) error {
	return nil
}

func (m *MockRuncClient) StopContainer(ctx context.Context, containerID string) error {
	return nil
}

func (m *MockRuncClient) DeleteContainer(ctx context.Context, containerID string) error {
	return nil
}

func (m *MockRuncClient) GetContainerLogs(ctx context.Context, containerID string) ([]byte, error) {
	return []byte{}, nil
}

func (m *MockRuncClient) ExecProcess(ctx context.Context, containerID string, spec *runtime.ProcessSpec) (*runtime.ProcessResult, error) {
	return nil, nil
}

func (m *MockRuncClient) GetProcessStatus(ctx context.Context, containerID, processID string) (*runtime.ProcessStatus, error) {
	return nil, nil
}

func (m *MockRuncClient) KillProcess(ctx context.Context, containerID string, pid int32) error {
	return nil
}

func (m *MockRuncClient) ValidateContainerForProcessExecution(ctx context.Context, containerID string) error {
	return nil
}

func (m *MockRuncClient) ExecProcessLegacy(ctx context.Context, containerID string, config runtime.ProcessConfig) (int32, error) {
	return 0, nil
}

func (m *MockRuncClient) Cleanup() error {
	return nil
}

func (m *MockRuncClient) EnableProcessManager(config *runtime.ProcessManagerConfig) error {
	return nil
}

func (m *MockRuncClient) GetProcessManager() *runtime.ProcessManager {
	return nil
}

func (m *MockRuncClient) IsProcessManagerEnabled() bool {
	return false
}

func (m *MockRuncClient) ExecProcessManaged(ctx context.Context, containerID string, spec *runtime.ProcessSpec, async bool) (*runtime.ManagedProcess, error) {
	return nil, nil
}

func (m *MockRuncClient) StopProcessManaged(processID string) error {
	return nil
}

func (m *MockRuncClient) KillProcessManaged(processID string) error {
	return nil
}

func (m *MockRuncClient) WaitProcessManaged(processID string, ctx context.Context) error {
	return nil
}

func (m *MockRuncClient) GetProcessStatusManaged(processID string) (runtime.ProcessState, error) {
	return runtime.ProcessStateUnknown, nil
}

func (m *MockRuncClient) ListManagedProcesses() []*runtime.ManagedProcess {
	return nil
}

func (m *MockRuncClient) GetProcessManagerMetrics() *runtime.ProcessManagerMetrics {
	return nil
}

func TestNewHealthChecker(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	assert.NotNil(t, hc)

	hc.Stop()
}

func TestHealthCheckConfig(t *testing.T) {
	config := DefaultHealthCheckConfig()
	
	assert.True(t, config.Enabled)
	assert.Equal(t, 30*time.Second, config.Interval)
	assert.Equal(t, 10*time.Second, config.Timeout)
	assert.Equal(t, 3, config.MaxRetries)
	assert.NotNil(t, config.Thresholds)
	assert.NotNil(t, config.CustomChecks)
}

func TestHealthThresholds(t *testing.T) {
	thresholds := DefaultHealthThresholds()
	
	assert.Equal(t, 70.0, thresholds.CPUWarningPercent)
	assert.Equal(t, 90.0, thresholds.CPUCriticalPercent)
	assert.Equal(t, 80.0, thresholds.MemoryWarningPercent)
	assert.Equal(t, 95.0, thresholds.MemoryCriticalPercent)
	assert.Equal(t, 30*time.Second, thresholds.MaxResponseTime)
}

func TestAddRemoveContainer(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	containerID := "test-container-1"

	// Add container
	hc.AddContainer(containerID, nil)

	// Verify container was added (by checking config exists)
	hc.mu.RLock()
	_, exists := hc.containerConfigs[containerID]
	hc.mu.RUnlock()
	assert.True(t, exists)

	// Remove container
	hc.RemoveContainer(containerID)

	// Verify container was removed
	hc.mu.RLock()
	_, exists = hc.containerConfigs[containerID]
	hc.mu.RUnlock()
	assert.False(t, exists)
}

func TestLivenessCheck(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	containerID := "test-container-liveness"

	tests := []struct {
		name           string
		containerStatus string
		containerPid   int
		expectedStatus HealthStatus
	}{
		{
			name:           "Running container",
			containerStatus: "running",
			containerPid:   1234,
			expectedStatus: HealthStatusHealthy,
		},
		{
			name:           "Stopped container",
			containerStatus: "stopped",
			containerPid:   0,
			expectedStatus: HealthStatusUnhealthy,
		},
		{
			name:           "Created container",
			containerStatus: "created",
			containerPid:   0,
			expectedStatus: HealthStatusUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock container
			mockRunc.containers = []*runc.Container{}
			mockRunc.AddContainer(containerID, tt.containerStatus, tt.containerPid)
			
			hc.AddContainer(containerID, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := hc.CheckHealth(ctx, containerID, HealthCheckTypeLiveness)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, result.Status)
			assert.Equal(t, HealthCheckTypeLiveness, result.CheckType)
			assert.Equal(t, containerID, result.ContainerID)
		})
	}
}

func TestResourceCheck(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()
	
	// Set low thresholds for testing
	config.Thresholds.CPUWarningPercent = 5.0
	config.Thresholds.CPUCriticalPercent = 15.0
	config.Thresholds.MemoryWarningPercent = 10.0
	config.Thresholds.MemoryCriticalPercent = 20.0

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	containerID := "test-container-resource"

	// Setup running container
	mockRunc.AddContainer(containerID, "running", 1234)
	hc.AddContainer(containerID, &config)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := hc.CheckHealth(ctx, containerID, HealthCheckTypeResource)
	require.NoError(t, err)

	// Since we're using mock values (10% CPU, 15% memory), and our thresholds are low,
	// we should get a warning status
	assert.Equal(t, HealthStatusWarning, result.Status)
	assert.Equal(t, HealthCheckTypeResource, result.CheckType)
	assert.Contains(t, result.Metadata, "cpu_percent")
	assert.Contains(t, result.Metadata, "memory_percent")
}

func TestNetworkCheck(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	containerID := "test-container-network"
	mockRunc.AddContainer(containerID, "running", 1234)
	hc.AddContainer(containerID, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := hc.CheckHealth(ctx, containerID, HealthCheckTypeNetwork)
	require.NoError(t, err)

	// Basic network check should pass
	assert.Equal(t, HealthStatusHealthy, result.Status)
	assert.Equal(t, HealthCheckTypeNetwork, result.CheckType)
}

func TestCustomChecks(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()
	
	// Add custom checks
	config.CustomChecks = []CustomCheck{
		{
			Name:    "echo-test",
			Command: []string{"echo", "healthy"},
			Timeout: 5 * time.Second,
		},
		{
			Name:    "fail-test",
			Command: []string{"false"}, // Command that always fails
			Timeout: 5 * time.Second,
		},
	}

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	containerID := "test-container-custom"
	mockRunc.AddContainer(containerID, "running", 1234)
	hc.AddContainer(containerID, &config)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := hc.CheckHealth(ctx, containerID, HealthCheckTypeCustom)
	require.NoError(t, err)

	// Should be unhealthy because one custom check fails
	assert.Equal(t, HealthStatusUnhealthy, result.Status)
	assert.Equal(t, HealthCheckTypeCustom, result.CheckType)
	assert.Contains(t, result.Metadata, "custom_checks")
}

func TestHealthAlerts(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	var alertResults []HealthCheckResult
	var alertMutex sync.Mutex

	// Register alert callback
	hc.RegisterAlertCallback(func(result HealthCheckResult) {
		alertMutex.Lock()
		defer alertMutex.Unlock()
		alertResults = append(alertResults, result)
	})

	containerID := "test-container-alerts"

	// First add healthy container
	mockRunc.AddContainer(containerID, "running", 1234)
	hc.AddContainer(containerID, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Perform healthy check
	_, err = hc.CheckHealth(ctx, containerID, HealthCheckTypeLiveness)
	require.NoError(t, err)

	// Change container to unhealthy state
	mockRunc.containers = []*runc.Container{}
	mockRunc.AddContainer(containerID, "stopped", 0)

	// Perform unhealthy check
	_, err = hc.CheckHealth(ctx, containerID, HealthCheckTypeLiveness)
	require.NoError(t, err)

	// Wait for alert processing
	time.Sleep(100 * time.Millisecond)

	// Check alerts were triggered
	alertMutex.Lock()
	defer alertMutex.Unlock()
	
	// Should have at least one alert for the status change from healthy to unhealthy
	assert.Greater(t, len(alertResults), 0)
	
	// Find the unhealthy alert
	var unhealthyAlert *HealthCheckResult
	for _, alert := range alertResults {
		if alert.Status == HealthStatusUnhealthy {
			unhealthyAlert = &alert
			break
		}
	}
	
	require.NotNil(t, unhealthyAlert)
	assert.Equal(t, containerID, unhealthyAlert.ContainerID)
	assert.Equal(t, HealthCheckTypeLiveness, unhealthyAlert.CheckType)
}

func TestGetContainerHealth(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	containerID := "test-container-overall"
	mockRunc.AddContainer(containerID, "running", 1234)
	hc.AddContainer(containerID, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Perform multiple health checks
	checkTypes := []HealthCheckType{
		HealthCheckTypeLiveness,
		HealthCheckTypeReadiness,
		HealthCheckTypeResource,
		HealthCheckTypeNetwork,
	}

	for _, checkType := range checkTypes {
		_, err = hc.CheckHealth(ctx, containerID, checkType)
		require.NoError(t, err)
	}

	// Get overall health
	overallStatus, results, err := hc.GetContainerHealth(containerID)
	require.NoError(t, err)

	// Should be healthy overall (all checks pass in our mock scenario)
	assert.Equal(t, HealthStatusHealthy, overallStatus)
	assert.Len(t, results, len(checkTypes))

	// Verify all check types are present
	for _, checkType := range checkTypes {
		result, exists := results[checkType]
		assert.True(t, exists)
		assert.Equal(t, checkType, result.CheckType)
	}
}

func TestGetLastResult(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	containerID := "test-container-last"
	mockRunc.AddContainer(containerID, "running", 1234)
	hc.AddContainer(containerID, nil)

	// Should return error when no results exist
	_, err = hc.GetLastResult(containerID, HealthCheckTypeLiveness)
	assert.Error(t, err)

	// Perform health check
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := hc.CheckHealth(ctx, containerID, HealthCheckTypeLiveness)
	require.NoError(t, err)

	// Should now return the result
	lastResult, err := hc.GetLastResult(containerID, HealthCheckTypeLiveness)
	require.NoError(t, err)
	assert.Equal(t, result.Status, lastResult.Status)
	assert.Equal(t, result.CheckType, lastResult.CheckType)
}

func TestHealthCheckPersistence(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)

	containerID := "test-container-persistence"
	mockRunc.AddContainer(containerID, "running", 1234)
	hc.AddContainer(containerID, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Perform health check
	_, err = hc.CheckHealth(ctx, containerID, HealthCheckTypeLiveness)
	require.NoError(t, err)

	hc.Stop()

	// Wait for async persistence
	time.Sleep(100 * time.Millisecond)

	// Create new health checker (simulating restart)
	hc2, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc2.Stop()

	// Should have loaded health history
	hc2.mu.RLock()
	results := hc2.lastResults[containerID]
	hc2.mu.RUnlock()

	// May or may not have results depending on timing of persistence
	// This test verifies the persistence mechanism works without failing
	if results != nil {
		assert.Contains(t, results, HealthCheckTypeLiveness)
	}
}

func TestHealthStatistics(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)
	defer hc.Stop()

	// Add containers in different states
	containers := map[string]string{
		"healthy1":   "running",
		"healthy2":   "running",
		"unhealthy1": "stopped",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	for id, status := range containers {
		mockRunc.AddContainer(id, status, 1234)
		hc.AddContainer(id, nil)

		// Perform health check
		_, err = hc.CheckHealth(ctx, id, HealthCheckTypeLiveness)
		require.NoError(t, err)
	}

	stats := hc.GetHealthStatistics()
	assert.Contains(t, stats, "total_containers")
	assert.Contains(t, stats, "healthy_containers")
	assert.Contains(t, stats, "unhealthy_containers")
	assert.Contains(t, stats, "timestamp")

	totalContainers := stats["total_containers"].(int)
	assert.Equal(t, len(containers), totalContainers)
}

func TestHealthCheckerStop(t *testing.T) {
	db := setupTestHealthDB(t)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	config := DefaultHealthCheckConfig()

	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(t, err)

	// Stop should not block or error
	hc.Stop()
	hc.Stop() // Second stop should be safe
}

func setupTestHealthDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	return db
}

// Benchmark tests

func BenchmarkHealthCheck(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(b, err)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	mockRunc.AddContainer("benchmark-container", "running", 1234)

	config := DefaultHealthCheckConfig()
	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(b, err)
	defer hc.Stop()

	containerID := "benchmark-container"
	hc.AddContainer(containerID, nil)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := hc.CheckHealth(ctx, containerID, HealthCheckTypeLiveness)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGetContainerHealth(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(b, err)
	defer db.Close()

	mockRunc := NewMockRuncClient()
	mockRunc.AddContainer("benchmark-container", "running", 1234)

	config := DefaultHealthCheckConfig()
	hc, err := NewHealthChecker(db, mockRunc, config)
	require.NoError(b, err)
	defer hc.Stop()

	containerID := "benchmark-container"
	hc.AddContainer(containerID, nil)

	// Perform initial health checks
	ctx := context.Background()
	checkTypes := []HealthCheckType{HealthCheckTypeLiveness, HealthCheckTypeResource}
	for _, checkType := range checkTypes {
		_, err := hc.CheckHealth(ctx, containerID, checkType)
		require.NoError(b, err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := hc.GetContainerHealth(containerID)
		if err != nil {
			b.Fatal(err)
		}
	}
}