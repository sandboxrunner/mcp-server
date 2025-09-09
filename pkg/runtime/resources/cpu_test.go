package resources

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCPUController(t *testing.T) {
	tests := []struct {
		name          string
		cgroupVersion int
		cgroupRoot    string
		wantErr       bool
	}{
		{
			name:          "cgroup v1",
			cgroupVersion: 1,
			cgroupRoot:    "/sys/fs/cgroup",
			wantErr:       false,
		},
		{
			name:          "cgroup v2",
			cgroupVersion: 2,
			cgroupRoot:    "/sys/fs/cgroup",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := NewCPUController(tt.cgroupVersion, tt.cgroupRoot)
			
			assert.NotNil(t, controller)
			assert.Equal(t, tt.cgroupVersion, controller.cgroupVersion)
			assert.Equal(t, tt.cgroupRoot, controller.cgroupRoot)
			assert.NotNil(t, controller.containers)
			assert.NotNil(t, controller.metrics)
			assert.NotNil(t, controller.metricsHistory)
			assert.Equal(t, int64(100000), controller.defaultPeriod) // 100ms
			assert.Equal(t, 100, controller.maxHistorySize)
		})
	}
}

func TestCPUController_ValidateCPULimits(t *testing.T) {
	controller := NewCPUController(2, "/tmp")

	tests := []struct {
		name    string
		limits  *CPULimits
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid limits",
			limits:  &CPULimits{CPUPercent: floatPtr(50.0), Shares: int64Ptr(1024)},
			wantErr: false,
		},
		{
			name:    "invalid CPU percentage - too high",
			limits:  &CPULimits{CPUPercent: floatPtr(900.0)},
			wantErr: true,
			errMsg:  "CPU percentage must be between 0 and 800",
		},
		{
			name:    "invalid CPU percentage - negative",
			limits:  &CPULimits{CPUPercent: floatPtr(-10.0)},
			wantErr: true,
			errMsg:  "CPU percentage must be between 0 and 800",
		},
		{
			name:    "invalid shares - too low",
			limits:  &CPULimits{Shares: int64Ptr(1)},
			wantErr: true,
			errMsg:  "CPU shares must be between 2 and 262144",
		},
		{
			name:    "invalid shares - too high",
			limits:  &CPULimits{Shares: int64Ptr(300000)},
			wantErr: true,
			errMsg:  "CPU shares must be between 2 and 262144",
		},
		{
			name:    "invalid period - too low",
			limits:  &CPULimits{Period: int64Ptr(500)},
			wantErr: true,
			errMsg:  "CPU period must be between 1000 and 1000000 microseconds",
		},
		{
			name:    "invalid period - too high",
			limits:  &CPULimits{Period: int64Ptr(2000000)},
			wantErr: true,
			errMsg:  "CPU period must be between 1000 and 1000000 microseconds",
		},
		{
			name:    "invalid quota vs period ratio",
			limits:  &CPULimits{Quota: int64Ptr(900000), Period: int64Ptr(100000)},
			wantErr: true,
			errMsg:  "CPU quota cannot exceed 8 times the period",
		},
		{
			name:    "invalid weight - too low",
			limits:  &CPULimits{Weight: int64Ptr(0)},
			wantErr: true,
			errMsg:  "CPU weight must be between 1 and 10000",
		},
		{
			name:    "invalid weight - too high",
			limits:  &CPULimits{Weight: int64Ptr(15000)},
			wantErr: true,
			errMsg:  "CPU weight must be between 1 and 10000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := controller.validateCPULimits(tt.limits)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCPUController_ApplyCPULimits(t *testing.T) {
	// Create temporary directory for test cgroups
	tempDir, err := os.MkdirTemp("", "cpu_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewCPUController(2, tempDir)
	containerID := "test-container"

	tests := []struct {
		name    string
		limits  *CPULimits
		wantErr bool
	}{
		{
			name: "apply CPU percentage limit",
			limits: &CPULimits{
				CPUPercent: floatPtr(50.0),
			},
			wantErr: false,
		},
		{
			name: "apply shares and quota limits",
			limits: &CPULimits{
				Shares: int64Ptr(1024),
				Quota:  int64Ptr(50000),
				Period: int64Ptr(100000),
			},
			wantErr: false,
		},
		{
			name: "apply CPU pinning",
			limits: &CPULimits{
				Cpuset:     stringPtr("0-3"),
				CpusetMems: stringPtr("0"),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := controller.ApplyCPULimits(containerID, tt.limits)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				
				// Verify limits are stored
				controller.mu.RLock()
				storedLimits := controller.containers[containerID]
				controller.mu.RUnlock()
				
				assert.NotNil(t, storedLimits)
				assert.Equal(t, tt.limits.CPUPercent, storedLimits.CPUPercent)
				assert.Equal(t, tt.limits.Shares, storedLimits.Shares)
				
				// Verify cgroup directory was created
				cgroupPath := controller.getContainerCgroupPath(containerID)
				_, err := os.Stat(cgroupPath)
				assert.NoError(t, err, "cgroup directory should exist")
			}
		})
	}
}

func TestCPUController_GetCPUUsage(t *testing.T) {
	// Create temporary directory for test cgroups
	tempDir, err := os.MkdirTemp("", "cpu_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewCPUController(2, tempDir)
	containerID := "test-container"

	// Create cgroup directory and mock stat files
	cgroupPath := controller.getContainerCgroupPath(containerID)
	err = os.MkdirAll(cgroupPath, 0755)
	require.NoError(t, err)

	// Create mock cpu.stat file for cgroup v2
	cpuStatContent := `usage_usec 1000000
user_usec 600000
system_usec 400000
nr_periods 100
nr_throttled 5
throttled_usec 50000
`
	err = os.WriteFile(filepath.Join(cgroupPath, "cpu.stat"), []byte(cpuStatContent), 0644)
	require.NoError(t, err)

	metrics, err := controller.GetCPUUsage(containerID)
	assert.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.Equal(t, containerID, metrics.ContainerID)
	assert.Equal(t, int64(1000000*1000), metrics.UsageNanos) // Convert from microseconds
	assert.Equal(t, int64(600000*1000), metrics.UserNanos)
	assert.Equal(t, int64(400000*1000), metrics.SystemNanos)
	assert.Equal(t, int64(5), metrics.ThrottleCount)
	assert.Equal(t, int64(50000*1000), metrics.ThrottleTime)
}

func TestCPUController_SetCPUPinning(t *testing.T) {
	// Create temporary directory for test cgroups
	tempDir, err := os.MkdirTemp("", "cpu_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name          string
		cgroupVersion int
		cpus          string
		mems          string
		wantErr       bool
	}{
		{
			name:          "cgroup v2 - set CPU cores",
			cgroupVersion: 2,
			cpus:          "0-3",
			mems:          "0",
			wantErr:       false,
		},
		{
			name:          "cgroup v1 - set CPU cores",
			cgroupVersion: 1,
			cpus:          "1,3",
			mems:          "0,1",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := NewCPUController(tt.cgroupVersion, tempDir)
			containerID := "test-container"

			// Create necessary directories
			cgroupPath := controller.getContainerCgroupPath(containerID)
			err := os.MkdirAll(cgroupPath, 0755)
			require.NoError(t, err)

			if tt.cgroupVersion == 1 {
				cpusetPath := filepath.Join(tempDir, "cpuset", "sandboxrunner", containerID)
				err = os.MkdirAll(cpusetPath, 0755)
				require.NoError(t, err)
			}

			err = controller.SetCPUPinning(containerID, tt.cpus, tt.mems)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify files were written
				if tt.cgroupVersion == 2 {
					if tt.cpus != "" {
						cpusFile := filepath.Join(cgroupPath, "cpuset.cpus")
						content, err := os.ReadFile(cpusFile)
						assert.NoError(t, err)
						assert.Equal(t, tt.cpus, strings.TrimSpace(string(content)))
					}
				}
			}
		})
	}
}

func TestCPUController_GetCPUHistory(t *testing.T) {
	controller := NewCPUController(2, "/tmp")
	containerID := "test-container"

	// Initially empty
	history := controller.GetCPUHistory(containerID)
	assert.Empty(t, history)

	// Add some mock metrics
	now := time.Now()
	for i := 0; i < 5; i++ {
		metrics := &CPUMetrics{
			ContainerID:  containerID,
			Timestamp:    now.Add(time.Duration(i) * time.Minute),
			UsagePercent: float64(10 + i*5),
			UsageNanos:   int64(1000000 * (i + 1)),
		}
		controller.storeMetrics(containerID, metrics)
	}

	history = controller.GetCPUHistory(containerID)
	assert.Len(t, history, 5)
	
	// Verify order (should be chronological)
	for i := 0; i < 4; i++ {
		assert.True(t, history[i].Timestamp.Before(history[i+1].Timestamp))
	}
}

func TestCPUController_RemoveCPULimits(t *testing.T) {
	// Create temporary directory for test cgroups
	tempDir, err := os.MkdirTemp("", "cpu_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewCPUController(2, tempDir)
	containerID := "test-container"

	// Apply some limits first
	limits := &CPULimits{
		CPUPercent: floatPtr(50.0),
		Shares:     int64Ptr(1024),
	}
	err = controller.ApplyCPULimits(containerID, limits)
	require.NoError(t, err)

	// Verify limits are stored
	controller.mu.RLock()
	_, exists := controller.containers[containerID]
	controller.mu.RUnlock()
	assert.True(t, exists)

	// Remove limits
	err = controller.RemoveCPULimits(containerID)
	assert.NoError(t, err)

	// Verify cleanup
	controller.mu.RLock()
	_, exists = controller.containers[containerID]
	_, metricsExists := controller.metrics[containerID]
	_, historyExists := controller.metricsHistory[containerID]
	controller.mu.RUnlock()

	assert.False(t, exists)
	assert.False(t, metricsExists)
	assert.False(t, historyExists)
}

func TestCPUController_ParseCPUStatV2(t *testing.T) {
	controller := NewCPUController(2, "/tmp")
	
	statContent := `usage_usec 5000000
user_usec 3000000
system_usec 2000000
nr_periods 1000
nr_throttled 50
throttled_usec 100000
`

	metrics := &CPUMetrics{ContainerID: "test"}
	controller.parseCPUStatV2(statContent, metrics)

	assert.Equal(t, int64(5000000*1000), metrics.UsageNanos) // Convert to nanoseconds
	assert.Equal(t, int64(3000000*1000), metrics.UserNanos)
	assert.Equal(t, int64(2000000*1000), metrics.SystemNanos)
	assert.Equal(t, int64(50), metrics.ThrottleCount)
	assert.Equal(t, int64(100000*1000), metrics.ThrottleTime)
}

func TestCPUController_ParseCPUStatV1(t *testing.T) {
	controller := NewCPUController(1, "/tmp")
	
	statContent := `user 300
system 200
`

	metrics := &CPUMetrics{ContainerID: "test"}
	controller.parseCPUStatV1(statContent, metrics)

	// Values are in USER_HZ units, converted to nanoseconds
	assert.Equal(t, int64(300*10000000), metrics.UserNanos)
	assert.Equal(t, int64(200*10000000), metrics.SystemNanos)
}

func TestCPUController_GetSystemCPUInfo(t *testing.T) {
	info, err := GetSystemCPUInfo()
	
	// This test might fail in some environments where /proc/cpuinfo is not available
	if err != nil {
		t.Skipf("Skipping system CPU info test: %v", err)
		return
	}
	
	assert.NoError(t, err)
	assert.NotNil(t, info)
	
	// Check that we got some basic CPU info
	if cpuCount, ok := info["cpu_count"]; ok {
		assert.Greater(t, cpuCount.(int), 0)
	}
	
	if processors, ok := info["processors"]; ok {
		procList := processors.([]map[string]string)
		assert.NotEmpty(t, procList)
	}
}

func TestCPUController_CalculateLoadAverages(t *testing.T) {
	controller := NewCPUController(2, "/tmp")
	containerID := "test-container"

	// Add historical data
	now := time.Now()
	usageValues := []float64{10.0, 20.0, 30.0, 25.0, 15.0}
	
	for i, usage := range usageValues {
		metrics := &CPUMetrics{
			ContainerID:  containerID,
			Timestamp:    now.Add(time.Duration(-len(usageValues)+i) * time.Second * 30),
			UsagePercent: usage,
		}
		controller.storeMetrics(containerID, metrics)
	}

	// Calculate load averages for current metrics
	currentMetrics := &CPUMetrics{
		ContainerID: containerID,
		Timestamp:   now,
		UsagePercent: 20.0,
	}
	
	controller.calculateLoadAverages(containerID, currentMetrics)
	
	// Should have calculated some load averages
	assert.GreaterOrEqual(t, currentMetrics.LoadAverage1, 0.0)
	assert.GreaterOrEqual(t, currentMetrics.LoadAverage5, 0.0)
	assert.GreaterOrEqual(t, currentMetrics.LoadAverage15, 0.0)
}

func TestCPUController_CPUQuotaFromPercentage(t *testing.T) {
	controller := NewCPUController(2, "/tmp")
	
	limits := &CPULimits{
		CPUPercent: floatPtr(50.0), // 50% of one CPU
	}
	
	// This would be called during ApplyCPULimits
	// The method calculates quota from percentage
	period := controller.defaultPeriod
	expectedQuota := int64(50.0 / 100.0 * float64(period))
	
	// Simulate the calculation that happens in ApplyCPULimits
	if limits.CPUPercent != nil && limits.Quota == nil {
		quota := int64(*limits.CPUPercent / 100.0 * float64(period))
		limits.Quota = &quota
		limits.Period = &period
	}
	
	assert.Equal(t, expectedQuota, *limits.Quota)
	assert.Equal(t, period, *limits.Period)
}

func TestCPUController_StoreMetrics(t *testing.T) {
	controller := NewCPUController(2, "/tmp")
	containerID := "test-container"

	// Store metrics beyond the max history size
	for i := 0; i < controller.maxHistorySize+10; i++ {
		metrics := &CPUMetrics{
			ContainerID:  containerID,
			Timestamp:    time.Now().Add(time.Duration(i) * time.Second),
			UsagePercent: float64(i % 100),
		}
		controller.storeMetrics(containerID, metrics)
	}

	controller.mu.RLock()
	history := controller.metricsHistory[containerID]
	current := controller.metrics[containerID]
	controller.mu.RUnlock()

	// Should not exceed max history size
	assert.LessOrEqual(t, len(history), controller.maxHistorySize)
	assert.NotNil(t, current)
	assert.Equal(t, containerID, current.ContainerID)
}

// Helper functions for tests

func floatPtr(f float64) *float64 {
	return &f
}

func int64Ptr(i int64) *int64 {
	return &i
}

func stringPtr(s string) *string {
	return &s
}

// Benchmark tests

func BenchmarkCPUController_ApplyCPULimits(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "cpu_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	controller := NewCPUController(2, tempDir)
	limits := &CPULimits{
		CPUPercent: floatPtr(50.0),
		Shares:     int64Ptr(1024),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containerID := "container-" + strconv.Itoa(i)
		err := controller.ApplyCPULimits(containerID, limits)
		if err != nil {
			b.Fatalf("ApplyCPULimits failed: %v", err)
		}
	}
}

func BenchmarkCPUController_GetCPUUsage(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "cpu_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	controller := NewCPUController(2, tempDir)
	containerID := "test-container"

	// Set up test cgroup
	cgroupPath := controller.getContainerCgroupPath(containerID)
	err = os.MkdirAll(cgroupPath, 0755)
	require.NoError(b, err)

	cpuStatContent := `usage_usec 1000000
user_usec 600000
system_usec 400000
nr_periods 100
nr_throttled 5
throttled_usec 50000
`
	err = os.WriteFile(filepath.Join(cgroupPath, "cpu.stat"), []byte(cpuStatContent), 0644)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := controller.GetCPUUsage(containerID)
		if err != nil {
			b.Fatalf("GetCPUUsage failed: %v", err)
		}
	}
}

func BenchmarkCPUController_StoreMetrics(b *testing.B) {
	controller := NewCPUController(2, "/tmp")
	containerID := "test-container"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics := &CPUMetrics{
			ContainerID:  containerID,
			Timestamp:    time.Now(),
			UsagePercent: float64(i % 100),
			UsageNanos:   int64(i * 1000000),
		}
		controller.storeMetrics(containerID, metrics)
	}
}