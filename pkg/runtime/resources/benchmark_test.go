package resources

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// BenchmarkResourceControllers tests the performance of all resource controllers together
func BenchmarkResourceControllers_Full(b *testing.B) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "resource_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	// Initialize controllers
	cpuController := NewCPUController(2, tempDir)
	memController := NewMemoryController(2, tempDir)
	diskController := NewDiskController(tempDir)

	// Define test limits
	cpuLimits := &CPULimits{
		CPUPercent: floatPtr(25.0),
		Shares:     int64Ptr(512),
	}
	
	memLimits := &MemoryLimits{
		Limit:       int64Ptr(512 * 1024 * 1024), // 512MB
		Reservation: int64Ptr(256 * 1024 * 1024), // 256MB
	}
	
	diskLimits := &DiskLimits{
		SoftLimit: int64Ptr(100 * 1024 * 1024), // 100MB
		HardLimit: int64Ptr(200 * 1024 * 1024), // 200MB
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		containerID := "benchmark-container-" + string(rune(i%1000))

		// Apply all limits
		cpuController.ApplyCPULimits(containerID, cpuLimits)
		memController.ApplyMemoryLimits(containerID, memLimits)
		diskController.ApplyDiskLimits(containerID, diskLimits)

		// Get usage metrics
		cpuController.GetCPUUsage(containerID)
		memController.GetMemoryUsage(containerID)
		diskController.GetDiskUsage(containerID)

		// Cleanup
		cpuController.RemoveCPULimits(containerID)
		memController.RemoveMemoryLimits(containerID)
		diskController.RemoveDiskLimits(containerID)
	}
}

func BenchmarkResourceControllers_ConcurrentAccess(b *testing.B) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "resource_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	// Initialize controllers
	cpuController := NewCPUController(2, tempDir)
	memController := NewMemoryController(2, tempDir)
	diskController := NewDiskController(tempDir)

	// Number of concurrent goroutines
	numGoroutines := runtime.NumCPU() * 2

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for j := 0; j < numGoroutines; j++ {
			go func(goroutineID int) {
				defer wg.Done()

				containerID := "concurrent-container-" + string(rune(goroutineID))

				// CPU operations
				cpuLimits := &CPULimits{
					CPUPercent: floatPtr(float64(10 + goroutineID%20)),
					Shares:     int64Ptr(int64(512 + goroutineID*100)),
				}
				cpuController.ApplyCPULimits(containerID, cpuLimits)
				cpuController.GetCPUUsage(containerID)

				// Memory operations
				memLimits := &MemoryLimits{
					Limit: int64Ptr(int64((100 + goroutineID*50) * 1024 * 1024)),
				}
				memController.ApplyMemoryLimits(containerID, memLimits)
				memController.GetMemoryUsage(containerID)

				// Disk operations
				diskLimits := &DiskLimits{
					SoftLimit: int64Ptr(int64((50 + goroutineID*25) * 1024 * 1024)),
				}
				diskController.ApplyDiskLimits(containerID, diskLimits)
				diskController.GetDiskUsage(containerID)

				// Cleanup
				cpuController.RemoveCPULimits(containerID)
				memController.RemoveMemoryLimits(containerID)
				diskController.RemoveDiskLimits(containerID)
			}(j)
		}

		wg.Wait()
	}
}

func BenchmarkResourceControllers_MetricsCollection(b *testing.B) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "resource_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	// Initialize controllers
	cpuController := NewCPUController(2, tempDir)
	memController := NewMemoryController(2, tempDir)
	diskController := NewDiskController(tempDir)

	// Set up containers
	numContainers := 100
	containerIDs := make([]string, numContainers)

	for i := 0; i < numContainers; i++ {
		containerID := "metrics-container-" + string(rune(i))
		containerIDs[i] = containerID

		// Create cgroup directories for realistic metrics collection
		cpuPath := cpuController.getContainerCgroupPath(containerID)
		memPath := memController.getContainerCgroupPath(containerID)
		
		os.MkdirAll(cpuPath, 0755)
		os.MkdirAll(memPath, 0755)
		os.MkdirAll(filepath.Join(tempDir, containerID), 0755)

		// Create mock stat files
		cpuStatContent := `usage_usec 5000000
user_usec 3000000
system_usec 2000000
nr_periods 1000
nr_throttled 50
throttled_usec 100000
`
		os.WriteFile(filepath.Join(cpuPath, "cpu.stat"), []byte(cpuStatContent), 0644)

		memStatContent := `anon 268435456
file 134217728
pgfault 1000
pgmajfault 50
`
		os.WriteFile(filepath.Join(memPath, "memory.stat"), []byte(memStatContent), 0644)
		os.WriteFile(filepath.Join(memPath, "memory.current"), []byte("536870912"), 0644)
		os.WriteFile(filepath.Join(memPath, "memory.max"), []byte("1073741824"), 0644)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Collect metrics from all containers
		for _, containerID := range containerIDs {
			cpuController.GetCPUUsage(containerID)
			memController.GetMemoryUsage(containerID)
			diskController.GetDiskUsage(containerID)
		}
	}

	// Cleanup
	for _, containerID := range containerIDs {
		cpuController.RemoveCPULimits(containerID)
		memController.RemoveMemoryLimits(containerID)
		diskController.RemoveDiskLimits(containerID)
	}
}

func BenchmarkResourceControllers_HistoryManagement(b *testing.B) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "resource_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	cpuController := NewCPUController(2, tempDir)
	memController := NewMemoryController(2, tempDir)
	diskController := NewDiskController(tempDir)

	containerID := "history-container"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Store metrics for history
		cpuMetrics := &CPUMetrics{
			ContainerID:  containerID,
			Timestamp:    time.Now(),
			UsagePercent: float64(i % 100),
			UsageNanos:   int64(i * 1000000),
		}
		cpuController.storeMetrics(containerID, cpuMetrics)

		memMetrics := &MemoryMetrics{
			ContainerID:  containerID,
			Timestamp:    time.Now(),
			UsageBytes:   int64((i % 1000) * 1024 * 1024),
			UsagePercent: float64(i % 100),
		}
		memController.storeMetrics(containerID, memMetrics)

		diskMetrics := &DiskMetrics{
			ContainerID:  containerID,
			Timestamp:    time.Now(),
			UsedBytes:    int64((i % 500) * 1024 * 1024),
			UsagePercent: float64(i % 100),
		}
		diskController.storeMetrics(containerID, diskMetrics)

		// Periodically retrieve history
		if i%10 == 0 {
			cpuController.GetCPUHistory(containerID)
			memController.GetMemoryHistory(containerID)
			diskController.GetDiskHistory(containerID)
		}
	}
}

func BenchmarkMemoryController_LeakDetection(b *testing.B) {
	controller := NewMemoryController(2, "/tmp")
	containerID := "leak-test-container"

	config := &MemoryLeakDetection{
		Enabled:         true,
		GrowthThreshold: 10.0,
		SampleWindow:    10,
		AlertThreshold:  5,
	}

	// Pre-populate history
	baseUsage := int64(100 * 1024 * 1024)
	now := time.Now()
	
	for i := 0; i < 20; i++ {
		usage := baseUsage + int64(float64(baseUsage)*0.05*float64(i))
		metrics := &MemoryMetrics{
			ContainerID: containerID,
			Timestamp:   now.Add(time.Duration(i) * time.Minute),
			UsageBytes:  usage,
		}
		controller.storeMetrics(containerID, metrics)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		controller.DetectMemoryLeaks(containerID, config)
	}
}

func BenchmarkDiskController_Cleanup(b *testing.B) {
	// Create temporary directory for tests
	tempDir, err := os.MkdirTemp("", "disk_cleanup_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	controller := NewDiskController(tempDir)
	containerID := "cleanup-container"

	// Set up container directory with many files
	containerPath := filepath.Join(tempDir, containerID)
	tmpDir := filepath.Join(containerPath, "tmp")
	err = os.MkdirAll(tmpDir, 0755)
	require.NoError(b, err)

	// Create many files for cleanup testing
	numFiles := 1000
	oldTime := time.Now().Add(-48 * time.Hour)
	
	for i := 0; i < numFiles; i++ {
		filename := filepath.Join(tmpDir, "file"+string(rune(i%100))+".tmp")
		err = os.WriteFile(filename, []byte("test content"), 0644)
		require.NoError(b, err)
		err = os.Chtimes(filename, oldTime, oldTime)
		require.NoError(b, err)
	}

	policy := &CleanupPolicy{
		Enabled:         true,
		RetentionPeriod: 24 * time.Hour,
		FilePatterns:    []string{"*.tmp"},
		Directories:     []string{"tmp"},
		PreserveCount:   10,
		SortBy:          "mtime",
		DryRun:          true, // Dry run for benchmarking
	}

	controller.SetupCleanupPolicy(containerID, policy)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		controller.RunCleanup(containerID)
	}
}

// BenchmarkResourcePool_Operations tests resource pool performance
func BenchmarkResourcePool_Operations(b *testing.B) {
	// Skip this benchmark as it depends on ResourcePool being in sandbox package
	b.Skip("ResourcePool benchmarks require sandbox package integration")
}

func BenchmarkResourcePool_ConcurrentOperations(b *testing.B) {
	b.Skip("ResourcePool benchmarks require sandbox package integration")
}

func BenchmarkResourcePool_Statistics(b *testing.B) {
	b.Skip("ResourcePool benchmarks require sandbox package integration")
}

// Memory allocation benchmarks
func BenchmarkResourceControllers_MemoryAllocation(b *testing.B) {
	b.Run("CPU Metrics Creation", func(b *testing.B) {
		containerID := "test-container"
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = &CPUMetrics{
				ContainerID:     containerID,
				Timestamp:       time.Now(),
				UsagePercent:    50.0,
				UsageNanos:      int64(i * 1000000),
				ThrottleCount:   int64(i % 10),
				PerCoreUsage:    []int64{int64(i), int64(i * 2), int64(i * 3), int64(i * 4)},
				LoadAverage1:    1.5,
				LoadAverage5:    2.0,
				LoadAverage15:   2.5,
			}
		}
	})

	b.Run("Memory Metrics Creation", func(b *testing.B) {
		containerID := "test-container"
		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			_ = &MemoryMetrics{
				ContainerID:     containerID,
				Timestamp:       time.Now(),
				UsageBytes:      int64(i * 1024 * 1024),
				LimitBytes:      int64(2048 * 1024 * 1024),
				UsagePercent:    float64(i % 100),
				RSSBytes:        int64(i * 512 * 1024),
				CacheBytes:      int64(i * 256 * 1024),
				PageFaults:      int64(i * 1000),
				MajorPageFaults: int64(i * 10),
			}
		}
	})

	b.Run("Resource Pool Request Creation", func(b *testing.B) {
		b.Skip("ResourcePool types require sandbox package integration")
	})
}

// Integration benchmark - tests realistic usage patterns
func BenchmarkResourceManagement_IntegratedWorkload(b *testing.B) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "integrated_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	// Initialize all controllers
	cpuController := NewCPUController(2, tempDir)
	memController := NewMemoryController(2, tempDir)
	diskController := NewDiskController(tempDir)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		containerID := "integrated-container-" + string(rune(i%50))

		// Apply individual resource limits
		cpuLimits := &CPULimits{
			CPUPercent: floatPtr(12.5),
			Shares:     int64Ptr(512),
		}
		cpuController.ApplyCPULimits(containerID, cpuLimits)

		memLimits := &MemoryLimits{
			Limit: int64Ptr(512 * 1024 * 1024),
		}
		memController.ApplyMemoryLimits(containerID, memLimits)

		diskLimits := &DiskLimits{
			SoftLimit: int64Ptr(800 * 1024 * 1024),
			HardLimit: int64Ptr(1024 * 1024 * 1024),
		}
		diskController.ApplyDiskLimits(containerID, diskLimits)

		// Collect metrics (simulating monitoring)
		if i%5 == 0 { // Collect metrics every 5th iteration
			cpuController.GetCPUUsage(containerID)
			memController.GetMemoryUsage(containerID)
			diskController.GetDiskUsage(containerID)
		}

		// Cleanup individual controllers
		cpuController.RemoveCPULimits(containerID)
		memController.RemoveMemoryLimits(containerID)
		diskController.RemoveDiskLimits(containerID)
	}
}

// Profile-specific benchmarks for different workload patterns
func BenchmarkResourceManagement_WorkloadProfiles(b *testing.B) {
	tempDir, err := os.MkdirTemp("", "profile_bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	b.Run("CPU-Intensive", func(b *testing.B) {
		controller := NewCPUController(2, tempDir)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			containerID := "cpu-intensive-" + string(rune(i%100))
			limits := &CPULimits{
				CPUPercent: floatPtr(75.0), // High CPU usage
				Shares:     int64Ptr(2048),
				Cpuset:     stringPtr("0-3"),
			}
			
			controller.ApplyCPULimits(containerID, limits)
			controller.GetCPUUsage(containerID)
			controller.RemoveCPULimits(containerID)
		}
	})

	b.Run("Memory-Intensive", func(b *testing.B) {
		controller := NewMemoryController(2, tempDir)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			containerID := "mem-intensive-" + string(rune(i%100))
			limits := &MemoryLimits{
				Limit:       int64Ptr(4 * 1024 * 1024 * 1024), // 4GB
				Reservation: int64Ptr(2 * 1024 * 1024 * 1024), // 2GB reserved
				Swap:        int64Ptr(6 * 1024 * 1024 * 1024), // 6GB total
			}
			
			controller.ApplyMemoryLimits(containerID, limits)
			controller.GetMemoryUsage(containerID)
			controller.RemoveMemoryLimits(containerID)
		}
	})

	b.Run("IO-Intensive", func(b *testing.B) {
		controller := NewDiskController(tempDir)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			containerID := "io-intensive-" + string(rune(i%100))
			limits := &DiskLimits{
				SoftLimit:     int64Ptr(1 * 1024 * 1024 * 1024),   // 1GB
				HardLimit:     int64Ptr(2 * 1024 * 1024 * 1024),   // 2GB
				ReadBPS:       int64Ptr(100 * 1024 * 1024),        // 100MB/s
				WriteBPS:      int64Ptr(50 * 1024 * 1024),         // 50MB/s
				EnableCleanup: boolPtr(true),
			}
			
			controller.ApplyDiskLimits(containerID, limits)
			controller.GetDiskUsage(containerID)
			controller.RemoveDiskLimits(containerID)
		}
	})
}

// Helper functions for benchmarks are defined in other test files