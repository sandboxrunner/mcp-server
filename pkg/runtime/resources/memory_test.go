package resources

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemoryController(t *testing.T) {
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
			controller := NewMemoryController(tt.cgroupVersion, tt.cgroupRoot)
			
			assert.NotNil(t, controller)
			assert.Equal(t, tt.cgroupVersion, controller.cgroupVersion)
			assert.Equal(t, tt.cgroupRoot, controller.cgroupRoot)
			assert.NotNil(t, controller.containers)
			assert.NotNil(t, controller.metrics)
			assert.NotNil(t, controller.metricsHistory)
			assert.True(t, controller.oomNotifyEnabled)
			assert.NotNil(t, controller.oomEventChan)
			assert.Equal(t, 100, controller.maxHistorySize)
		})
	}
}

func TestMemoryController_ValidateMemoryLimits(t *testing.T) {
	controller := NewMemoryController(2, "/tmp")

	tests := []struct {
		name    string
		limits  *MemoryLimits
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid limits",
			limits:  &MemoryLimits{Limit: int64Ptr(1024 * 1024 * 1024), Reservation: int64Ptr(512 * 1024 * 1024)},
			wantErr: false,
		},
		{
			name:    "negative memory limit",
			limits:  &MemoryLimits{Limit: int64Ptr(-1)},
			wantErr: true,
			errMsg:  "memory limit cannot be negative",
		},
		{
			name:    "negative memory reservation",
			limits:  &MemoryLimits{Reservation: int64Ptr(-1)},
			wantErr: true,
			errMsg:  "memory reservation cannot be negative",
		},
		{
			name:    "swap limit less than memory limit",
			limits:  &MemoryLimits{Limit: int64Ptr(1024), Swap: int64Ptr(512)},
			wantErr: true,
			errMsg:  "swap limit cannot be less than memory limit",
		},
		{
			name:    "invalid swappiness - too low",
			limits:  &MemoryLimits{Swappiness: int64Ptr(-1)},
			wantErr: true,
			errMsg:  "swappiness must be between 0 and 100",
		},
		{
			name:    "invalid swappiness - too high",
			limits:  &MemoryLimits{Swappiness: int64Ptr(101)},
			wantErr: true,
			errMsg:  "swappiness must be between 0 and 100",
		},
		{
			name:    "memory high exceeds limit",
			limits:  &MemoryLimits{Limit: int64Ptr(1024), High: int64Ptr(2048)},
			wantErr: true,
			errMsg:  "memory high cannot exceed memory limit",
		},
		{
			name:    "memory low exceeds high",
			limits:  &MemoryLimits{High: int64Ptr(1024), Low: int64Ptr(2048)},
			wantErr: true,
			errMsg:  "memory low cannot exceed memory high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := controller.validateMemoryLimits(tt.limits)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMemoryController_ApplyMemoryLimits(t *testing.T) {
	// Create temporary directory for test cgroups
	tempDir, err := os.MkdirTemp("", "memory_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewMemoryController(2, tempDir)
	containerID := "test-container"

	tests := []struct {
		name    string
		limits  *MemoryLimits
		wantErr bool
	}{
		{
			name: "apply memory limit",
			limits: &MemoryLimits{
				Limit: int64Ptr(1024 * 1024 * 1024), // 1GB
			},
			wantErr: false,
		},
		{
			name: "apply memory with reservation",
			limits: &MemoryLimits{
				Limit:       int64Ptr(2048 * 1024 * 1024), // 2GB
				Reservation: int64Ptr(1024 * 1024 * 1024),  // 1GB
			},
			wantErr: false,
		},
		{
			name: "apply swap limit",
			limits: &MemoryLimits{
				Limit: int64Ptr(1024 * 1024 * 1024), // 1GB
				Swap:  int64Ptr(2048 * 1024 * 1024), // 2GB total (1GB memory + 1GB swap)
			},
			wantErr: false,
		},
		{
			name: "apply swappiness",
			limits: &MemoryLimits{
				Limit:      int64Ptr(1024 * 1024 * 1024), // 1GB
				Swappiness: int64Ptr(10),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := controller.ApplyMemoryLimits(containerID, tt.limits)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				
				// Verify limits are stored
				controller.mu.RLock()
				storedLimits := controller.containers[containerID]
				controller.mu.RUnlock()
				
				assert.NotNil(t, storedLimits)
				assert.Equal(t, tt.limits.Limit, storedLimits.Limit)
				assert.Equal(t, tt.limits.Reservation, storedLimits.Reservation)
				
				// Verify cgroup directory was created
				cgroupPath := controller.getContainerCgroupPath(containerID)
				_, err := os.Stat(cgroupPath)
				assert.NoError(t, err, "cgroup directory should exist")
			}
		})
	}
}

func TestMemoryController_GetMemoryUsage(t *testing.T) {
	// Create temporary directory for test cgroups
	tempDir, err := os.MkdirTemp("", "memory_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewMemoryController(2, tempDir)
	containerID := "test-container"

	// Create cgroup directory and mock stat files
	cgroupPath := controller.getContainerCgroupPath(containerID)
	err = os.MkdirAll(cgroupPath, 0755)
	require.NoError(t, err)

	// Create mock memory.current file for cgroup v2
	err = os.WriteFile(filepath.Join(cgroupPath, "memory.current"), []byte("536870912"), 0644) // 512MB
	require.NoError(t, err)

	// Create mock memory.max file
	err = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644) // 1GB
	require.NoError(t, err)

	// Create mock memory.stat file
	memoryStatContent := `anon 268435456
file 268435456
kernel_stack 65536
slab 1048576
sock 32768
pgfault 1000
pgmajfault 50
`
	err = os.WriteFile(filepath.Join(cgroupPath, "memory.stat"), []byte(memoryStatContent), 0644)
	require.NoError(t, err)

	// Create mock memory.events file
	memoryEventsContent := `low 0
high 0
max 0
oom 2
oom_kill 2
`
	err = os.WriteFile(filepath.Join(cgroupPath, "memory.events"), []byte(memoryEventsContent), 0644)
	require.NoError(t, err)

	metrics, err := controller.GetMemoryUsage(containerID)
	assert.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.Equal(t, containerID, metrics.ContainerID)
	assert.Equal(t, int64(536870912), metrics.UsageBytes) // 512MB
	assert.Equal(t, int64(1073741824), metrics.LimitBytes) // 1GB
	assert.Equal(t, 50.0, metrics.UsagePercent) // 512MB / 1GB * 100%
	assert.Equal(t, int64(268435456), metrics.RSSBytes) // anon
	assert.Equal(t, int64(268435456), metrics.CacheBytes) // file
	assert.Equal(t, int64(1000), metrics.PageFaults)
	assert.Equal(t, int64(50), metrics.MajorPageFaults)
	assert.Equal(t, int64(2), metrics.OOMKillCount)
}

func TestMemoryController_GetMemoryStats(t *testing.T) {
	// Create temporary directory for test cgroups
	tempDir, err := os.MkdirTemp("", "memory_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name          string
		cgroupVersion int
		setupFiles    func(cgroupPath string) error
	}{
		{
			name:          "cgroup v1",
			cgroupVersion: 1,
			setupFiles: func(cgroupPath string) error {
				// Create v1 files
				files := map[string]string{
					"memory.usage_in_bytes":     "536870912", // 512MB
					"memory.max_usage_in_bytes": "1073741824", // 1GB
					"memory.limit_in_bytes":     "2147483648", // 2GB
					"memory.failcnt":            "5",
					"memory.stat": `cache 134217728
rss 402653184
rss_huge 0
mapped_file 67108864
swap 0
pgfault 2000
pgmajfault 100
hierarchical_memory_limit 2147483648
hierarchical_memsw_limit 4294967296
`,
				}
				
				for filename, content := range files {
					if err := os.WriteFile(filepath.Join(cgroupPath, filename), []byte(content), 0644); err != nil {
						return err
					}
				}
				return nil
			},
		},
		{
			name:          "cgroup v2",
			cgroupVersion: 2,
			setupFiles: func(cgroupPath string) error {
				// Create v2 files
				files := map[string]string{
					"memory.current": "536870912", // 512MB
					"memory.peak":    "1073741824", // 1GB
					"memory.max":     "2147483648", // 2GB
					"memory.events": `low 0
high 0
max 0
oom 3
`,
					"memory.stat": `anon 402653184
file 134217728
kernel_stack 65536
slab 1048576
sock 32768
pgfault 2000
pgmajfault 100
`,
				}
				
				for filename, content := range files {
					if err := os.WriteFile(filepath.Join(cgroupPath, filename), []byte(content), 0644); err != nil {
						return err
					}
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			controller := NewMemoryController(tt.cgroupVersion, tempDir)
			containerID := "test-container"

			// Create cgroup directory and mock files
			cgroupPath := controller.getContainerCgroupPath(containerID)
			err = os.MkdirAll(cgroupPath, 0755)
			require.NoError(t, err)

			err = tt.setupFiles(cgroupPath)
			require.NoError(t, err)

			stats, err := controller.GetMemoryStats(containerID)
			assert.NoError(t, err)
			assert.NotNil(t, stats)
			assert.Equal(t, int64(536870912), stats.Usage) // 512MB
			assert.Greater(t, stats.MaxUsage, int64(0))
			assert.Greater(t, stats.Limit, int64(0))
			assert.NotNil(t, stats.Stats)
			
			if tt.cgroupVersion == 1 {
				assert.Equal(t, int64(5), stats.Failcnt)
			} else {
				assert.Equal(t, int64(3), stats.Failcnt)
			}
		})
	}
}

func TestMemoryController_DetectMemoryLeaks(t *testing.T) {
	controller := NewMemoryController(2, "/tmp")
	containerID := "test-container"

	config := &MemoryLeakDetection{
		Enabled:         true,
		CheckInterval:   time.Minute,
		GrowthThreshold: 10.0, // 10% growth threshold
		SampleWindow:    5,
		AlertThreshold:  3, // 3 consecutive alerts
	}

	// Test with insufficient samples
	isLeaking, err := controller.DetectMemoryLeaks(containerID, config)
	assert.NoError(t, err)
	assert.False(t, isLeaking)

	// Add memory usage history with growing trend
	baseUsage := int64(100 * 1024 * 1024) // 100MB
	now := time.Now()
	
	for i := 0; i < 6; i++ {
		// Simulate 15% growth each sample
		usage := baseUsage + int64(float64(baseUsage)*0.15*float64(i))
		metrics := &MemoryMetrics{
			ContainerID: containerID,
			Timestamp:   now.Add(time.Duration(i) * config.CheckInterval),
			UsageBytes:  usage,
		}
		controller.storeMetrics(containerID, metrics)
	}

	// Should detect leak with consistent growth
	isLeaking, err = controller.DetectMemoryLeaks(containerID, config)
	assert.NoError(t, err)
	assert.True(t, isLeaking)

	// Test with disabled detection
	config.Enabled = false
	isLeaking, err = controller.DetectMemoryLeaks(containerID, config)
	assert.NoError(t, err)
	assert.False(t, isLeaking)
}

func TestMemoryController_GetMemoryHistory(t *testing.T) {
	controller := NewMemoryController(2, "/tmp")
	containerID := "test-container"

	// Initially empty
	history := controller.GetMemoryHistory(containerID)
	assert.Empty(t, history)

	// Add some mock metrics
	now := time.Now()
	for i := 0; i < 5; i++ {
		metrics := &MemoryMetrics{
			ContainerID:  containerID,
			Timestamp:    now.Add(time.Duration(i) * time.Minute),
			UsageBytes:   int64(100*1024*1024 + i*10*1024*1024), // Growing usage
			UsagePercent: float64(10 + i*2),
		}
		controller.storeMetrics(containerID, metrics)
	}

	history = controller.GetMemoryHistory(containerID)
	assert.Len(t, history, 5)
	
	// Verify order (should be chronological)
	for i := 0; i < 4; i++ {
		assert.True(t, history[i].Timestamp.Before(history[i+1].Timestamp))
		assert.Less(t, history[i].UsageBytes, history[i+1].UsageBytes)
	}
}

func TestMemoryController_RemoveMemoryLimits(t *testing.T) {
	// Create temporary directory for test cgroups
	tempDir, err := os.MkdirTemp("", "memory_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	controller := NewMemoryController(2, tempDir)
	containerID := "test-container"

	// Apply some limits first
	limits := &MemoryLimits{
		Limit: int64Ptr(1024 * 1024 * 1024), // 1GB
		Swap:  int64Ptr(2048 * 1024 * 1024), // 2GB
	}
	err = controller.ApplyMemoryLimits(containerID, limits)
	require.NoError(t, err)

	// Verify limits are stored
	controller.mu.RLock()
	_, exists := controller.containers[containerID]
	controller.mu.RUnlock()
	assert.True(t, exists)

	// Remove limits
	err = controller.RemoveMemoryLimits(containerID)
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

func TestMemoryController_ParseMemoryStatV2(t *testing.T) {
	controller := NewMemoryController(2, "/tmp")
	
	statContent := `anon 268435456
file 134217728
kernel_stack 65536
slab 1048576
sock 32768
pgfault 1000
pgmajfault 50
pgscan 2000
pgsteal 500
`

	metrics := &MemoryMetrics{ContainerID: "test"}
	controller.parseMemoryStatV2(statContent, metrics)

	assert.Equal(t, int64(268435456), metrics.RSSBytes) // anon
	assert.Equal(t, int64(134217728), metrics.CacheBytes) // file
	assert.Equal(t, int64(32768), metrics.KernelTCPUsage) // sock
	assert.Equal(t, int64(1000), metrics.PageFaults)
	assert.Equal(t, int64(50), metrics.MajorPageFaults)
}

func TestMemoryController_ParseMemoryStatV1(t *testing.T) {
	controller := NewMemoryController(1, "/tmp")
	
	statContent := `cache 134217728
rss 268435456
rss_huge 0
mapped_file 67108864
swap 0
pgfault 1000
pgmajfault 50
hierarchical_memory_limit 2147483648
hierarchical_memsw_limit 4294967296
`

	metrics := &MemoryMetrics{ContainerID: "test"}
	controller.parseMemoryStatV1(statContent, metrics)

	assert.Equal(t, int64(134217728), metrics.CacheBytes)
	assert.Equal(t, int64(268435456), metrics.RSSBytes)
	assert.Equal(t, int64(0), metrics.SwapBytes)
	assert.Equal(t, int64(1000), metrics.PageFaults)
	assert.Equal(t, int64(50), metrics.MajorPageFaults)
	assert.Equal(t, int64(2147483648), metrics.HierarchicalMemoryLimit)
	assert.Equal(t, int64(4294967296), metrics.HierarchicalMemswLimit)
}

func TestMemoryController_ParseMemoryPressureV2(t *testing.T) {
	controller := NewMemoryController(2, "/tmp")
	
	pressureContent := `some avg10=1.23 avg60=2.34 avg300=3.45 total=123456789
full avg10=0.12 avg60=0.23 avg300=0.34 total=12345678
`

	metrics := &MemoryMetrics{ContainerID: "test"}
	controller.parseMemoryPressureV2(pressureContent, metrics)

	assert.Equal(t, 1.23, metrics.PressureAvg10)
	assert.Equal(t, 2.34, metrics.PressureAvg60)
	assert.Equal(t, 3.45, metrics.PressureAvg300)
	assert.Equal(t, int64(123456789), metrics.PressureTotal)
}

func TestMemoryController_ParseMemoryEventsV2(t *testing.T) {
	controller := NewMemoryController(2, "/tmp")
	
	eventsContent := `low 0
high 5
max 2
oom 3
oom_kill 3
`

	metrics := &MemoryMetrics{ContainerID: "test"}
	controller.parseMemoryEventsV2(eventsContent, metrics)

	assert.Equal(t, int64(3), metrics.OOMKillCount)
}

func TestMemoryController_GetSystemMemoryInfo(t *testing.T) {
	info, err := GetSystemMemoryInfo()
	
	// This test might fail in some environments where /proc/meminfo is not available
	if err != nil {
		t.Skipf("Skipping system memory info test: %v", err)
		return
	}
	
	assert.NoError(t, err)
	assert.NotNil(t, info)
	
	// Check that we got basic memory info
	if meminfo, ok := info["meminfo"]; ok {
		meminfoMap := meminfo.(map[string]int64)
		assert.Contains(t, meminfoMap, "MemTotal")
		assert.Contains(t, meminfoMap, "MemFree")
		assert.Greater(t, meminfoMap["MemTotal"], int64(0))
	}
}

func TestMemoryController_StoreMetrics(t *testing.T) {
	controller := NewMemoryController(2, "/tmp")
	containerID := "test-container"

	// Store metrics beyond the max history size
	for i := 0; i < controller.maxHistorySize+10; i++ {
		metrics := &MemoryMetrics{
			ContainerID:  containerID,
			Timestamp:    time.Now().Add(time.Duration(i) * time.Second),
			UsageBytes:   int64((i % 100) * 1024 * 1024),
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

func TestMemoryController_CalculateAverage(t *testing.T) {
	controller := NewMemoryController(2, "/tmp")
	
	tests := []struct {
		name     string
		values   []float64
		expected float64
	}{
		{
			name:     "empty values",
			values:   []float64{},
			expected: 0.0,
		},
		{
			name:     "single value",
			values:   []float64{5.0},
			expected: 5.0,
		},
		{
			name:     "multiple values",
			values:   []float64{1.0, 2.0, 3.0, 4.0, 5.0},
			expected: 3.0,
		},
		{
			name:     "floating point values",
			values:   []float64{1.5, 2.5, 3.5},
			expected: 2.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := controller.calculateAverage(tt.values)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Benchmark tests

func BenchmarkMemoryController_ApplyMemoryLimits(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "memory_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	controller := NewMemoryController(2, tempDir)
	limits := &MemoryLimits{
		Limit:       int64Ptr(1024 * 1024 * 1024), // 1GB
		Reservation: int64Ptr(512 * 1024 * 1024),  // 512MB
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containerID := "container-" + strconv.Itoa(i)
		err := controller.ApplyMemoryLimits(containerID, limits)
		if err != nil {
			b.Fatalf("ApplyMemoryLimits failed: %v", err)
		}
	}
}

func BenchmarkMemoryController_GetMemoryUsage(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "memory_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	controller := NewMemoryController(2, tempDir)
	containerID := "test-container"

	// Set up test cgroup
	cgroupPath := controller.getContainerCgroupPath(containerID)
	err = os.MkdirAll(cgroupPath, 0755)
	require.NoError(b, err)

	// Create mock files
	err = os.WriteFile(filepath.Join(cgroupPath, "memory.current"), []byte("536870912"), 0644)
	require.NoError(b, err)
	err = os.WriteFile(filepath.Join(cgroupPath, "memory.max"), []byte("1073741824"), 0644)
	require.NoError(b, err)

	memoryStatContent := `anon 268435456
file 268435456
pgfault 1000
pgmajfault 50
`
	err = os.WriteFile(filepath.Join(cgroupPath, "memory.stat"), []byte(memoryStatContent), 0644)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := controller.GetMemoryUsage(containerID)
		if err != nil {
			b.Fatalf("GetMemoryUsage failed: %v", err)
		}
	}
}

func BenchmarkMemoryController_DetectMemoryLeaks(b *testing.B) {
	controller := NewMemoryController(2, "/tmp")
	containerID := "test-container"

	config := &MemoryLeakDetection{
		Enabled:         true,
		GrowthThreshold: 10.0,
		SampleWindow:    5,
		AlertThreshold:  3,
	}

	// Set up historical data
	baseUsage := int64(100 * 1024 * 1024)
	now := time.Now()
	
	for i := 0; i < 10; i++ {
		usage := baseUsage + int64(float64(baseUsage)*0.05*float64(i))
		metrics := &MemoryMetrics{
			ContainerID: containerID,
			Timestamp:   now.Add(time.Duration(i) * time.Minute),
			UsageBytes:  usage,
		}
		controller.storeMetrics(containerID, metrics)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := controller.DetectMemoryLeaks(containerID, config)
		if err != nil {
			b.Fatalf("DetectMemoryLeaks failed: %v", err)
		}
	}
}