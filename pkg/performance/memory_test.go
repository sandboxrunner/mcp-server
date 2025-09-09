package performance

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// MemoryStats tracks memory usage during tests
type MemoryStats struct {
	HeapAlloc      uint64    // bytes allocated on heap
	HeapSys        uint64    // bytes obtained from OS
	HeapIdle       uint64    // bytes in idle spans
	HeapInuse      uint64    // bytes in in-use spans
	HeapReleased   uint64    // bytes released to OS
	StackInuse     uint64    // bytes used by stack spans
	StackSys       uint64    // bytes obtained from OS for stack
	MSpanInuse     uint64    // bytes used by mspan structures
	MCacheInuse    uint64    // bytes used by mcache structures
	GCSys          uint64    // bytes used for GC metadata
	NextGC         uint64    // next collection will happen when HeapAlloc ≥ this amount
	NumGC          uint32    // number of GC cycles
	PauseTotal     uint64    // cumulative nanoseconds in GC stop-the-world pauses
	NumGoroutine   int       // number of goroutines
	Timestamp      time.Time // when this measurement was taken
}

// GetCurrentMemoryStats captures current memory statistics
func GetCurrentMemoryStats() MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	return MemoryStats{
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		HeapIdle:     m.HeapIdle,
		HeapInuse:    m.HeapInuse,
		HeapReleased: m.HeapReleased,
		StackInuse:   m.StackInuse,
		StackSys:     m.StackSys,
		MSpanInuse:   m.MSpanInuse,
		MCacheInuse:  m.MCacheInuse,
		GCSys:        m.GCSys,
		NextGC:       m.NextGC,
		NumGC:        m.NumGC,
		PauseTotal:   m.PauseTotalNs,
		NumGoroutine: runtime.NumGoroutine(),
		Timestamp:    time.Now(),
	}
}

// MemoryProfiler tracks memory usage over time
type MemoryProfiler struct {
	stats   []MemoryStats
	mutex   sync.RWMutex
	running bool
	done    chan struct{}
}

// NewMemoryProfiler creates a new memory profiler
func NewMemoryProfiler() *MemoryProfiler {
	return &MemoryProfiler{
		stats: make([]MemoryStats, 0),
		done:  make(chan struct{}),
	}
}

// Start begins memory profiling with specified interval
func (mp *MemoryProfiler) Start(interval time.Duration) {
	mp.mutex.Lock()
	mp.running = true
	mp.mutex.Unlock()
	
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				mp.mutex.Lock()
				if mp.running {
					mp.stats = append(mp.stats, GetCurrentMemoryStats())
				}
				mp.mutex.Unlock()
			case <-mp.done:
				return
			}
		}
	}()
}

// Stop stops memory profiling
func (mp *MemoryProfiler) Stop() {
	mp.mutex.Lock()
	if mp.running {
		mp.running = false
		close(mp.done)
	}
	mp.mutex.Unlock()
}

// GetStats returns captured memory statistics
func (mp *MemoryProfiler) GetStats() []MemoryStats {
	mp.mutex.RLock()
	defer mp.mutex.RUnlock()
	
	result := make([]MemoryStats, len(mp.stats))
	copy(result, mp.stats)
	return result
}

// AnalyzeMemoryUsage analyzes memory usage patterns
func (mp *MemoryProfiler) AnalyzeMemoryUsage() map[string]interface{} {
	stats := mp.GetStats()
	if len(stats) == 0 {
		return map[string]interface{}{"error": "no statistics available"}
	}
	
	var (
		minHeapAlloc, maxHeapAlloc uint64 = stats[0].HeapAlloc, stats[0].HeapAlloc
		totalHeapAlloc             uint64
		minGoroutines, maxGoroutines       = stats[0].NumGoroutine, stats[0].NumGoroutine
		totalGoroutines            int
		gcCount                    uint32
		memoryLeakDetected         bool
		growthRate                 float64
	)
	
	baseline := stats[0].HeapAlloc
	
	for i, stat := range stats {
		if stat.HeapAlloc < minHeapAlloc {
			minHeapAlloc = stat.HeapAlloc
		}
		if stat.HeapAlloc > maxHeapAlloc {
			maxHeapAlloc = stat.HeapAlloc
		}
		totalHeapAlloc += stat.HeapAlloc
		
		if stat.NumGoroutine < minGoroutines {
			minGoroutines = stat.NumGoroutine
		}
		if stat.NumGoroutine > maxGoroutines {
			maxGoroutines = stat.NumGoroutine
		}
		totalGoroutines += stat.NumGoroutine
		
		if i == len(stats)-1 {
			gcCount = stat.NumGC - stats[0].NumGC
			// Simple memory leak detection: if final memory is significantly higher than baseline
			if stat.HeapAlloc > baseline*2 {
				memoryLeakDetected = true
			}
			// Calculate growth rate (bytes per measurement)
			if len(stats) > 1 {
				growthRate = float64(stat.HeapAlloc-baseline) / float64(len(stats)-1)
			}
		}
	}
	
	avgHeapAlloc := totalHeapAlloc / uint64(len(stats))
	avgGoroutines := float64(totalGoroutines) / float64(len(stats))
	
	return map[string]interface{}{
		"measurements":        len(stats),
		"duration_seconds":    stats[len(stats)-1].Timestamp.Sub(stats[0].Timestamp).Seconds(),
		"heap_alloc_min_mb":   float64(minHeapAlloc) / 1024 / 1024,
		"heap_alloc_max_mb":   float64(maxHeapAlloc) / 1024 / 1024,
		"heap_alloc_avg_mb":   float64(avgHeapAlloc) / 1024 / 1024,
		"goroutines_min":      minGoroutines,
		"goroutines_max":      maxGoroutines,
		"goroutines_avg":      avgGoroutines,
		"gc_cycles":           gcCount,
		"memory_leak":         memoryLeakDetected,
		"growth_rate_bytes":   growthRate,
		"baseline_mb":         float64(baseline) / 1024 / 1024,
		"final_mb":            float64(stats[len(stats)-1].HeapAlloc) / 1024 / 1024,
	}
}

// TestSandboxMemoryUsage tests memory usage per sandbox
func TestSandboxMemoryUsage(t *testing.T) {
	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	testCases := []struct {
		name         string
		numSandboxes int
		maxMemoryMB  float64
	}{
		{"single_sandbox", 1, 50.0},
		{"multiple_sandboxes", 10, 500.0}, // 50MB * 10
		{"many_sandboxes", 25, 1250.0},    // 50MB * 25
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GC()
			runtime.GC() // Force GC twice to clean up
			
			initialStats := GetCurrentMemoryStats()
			
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			
			var sandboxes []*sandbox.Sandbox
			
			// Create sandboxes
			for i := 0; i < tc.numSandboxes; i++ {
				sandboxConfig := sandbox.SandboxConfig{
					Image:        "ubuntu:22.04",
					WorkspaceDir: "/workspace",
					Resources: sandbox.ResourceLimits{
						CPULimit:    "0.2",
						MemoryLimit: "64m",
					},
				}
				
				sb, err := manager.CreateSandbox(ctx, sandboxConfig)
				if err != nil {
					t.Fatalf("Failed to create sandbox %d: %v", i+1, err)
				}
				sandboxes = append(sandboxes, sb)
			}
			
			// Let sandboxes settle
			time.Sleep(2 * time.Second)
			runtime.GC()
			runtime.GC()
			
			finalStats := GetCurrentMemoryStats()
			
			memoryUsedMB := float64(finalStats.HeapAlloc-initialStats.HeapAlloc) / 1024 / 1024
			memoryPerSandboxMB := memoryUsedMB / float64(tc.numSandboxes)
			
			t.Logf("Memory usage:")
			t.Logf("  Initial: %.2f MB", float64(initialStats.HeapAlloc)/1024/1024)
			t.Logf("  Final: %.2f MB", float64(finalStats.HeapAlloc)/1024/1024)
			t.Logf("  Used: %.2f MB", memoryUsedMB)
			t.Logf("  Per sandbox: %.2f MB", memoryPerSandboxMB)
			t.Logf("  Goroutines: %d -> %d", initialStats.NumGoroutine, finalStats.NumGoroutine)
			
			// Validate memory usage targets
			if memoryUsedMB > tc.maxMemoryMB {
				t.Errorf("Total memory usage %.2f MB exceeds target %.2f MB", memoryUsedMB, tc.maxMemoryMB)
			}
			
			if memoryPerSandboxMB > 50.0 {
				t.Errorf("Memory per sandbox %.2f MB exceeds target 50 MB", memoryPerSandboxMB)
			}
			
			// Cleanup
			for _, sb := range sandboxes {
				manager.DeleteSandbox(ctx, sb.ID)
			}
		})
	}
}

// TestMemoryLeakDetection tests for memory leaks during operations
func TestMemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	profiler := NewMemoryProfiler()
	profiler.Start(500 * time.Millisecond)
	defer profiler.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Perform repetitive operations that might leak memory
	for cycle := 0; cycle < 100; cycle++ {
		// Create and destroy sandbox
		sandboxConfig := sandbox.SandboxConfig{
			Image:        "ubuntu:22.04",
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "0.1",
				MemoryLimit: "32m",
			},
		}
		
		sb, err := manager.CreateSandbox(ctx, sandboxConfig)
		if err != nil {
			t.Fatalf("Failed to create sandbox in cycle %d: %v", cycle, err)
		}
		
		// Perform various operations
		operations := []func() error{
			func() error { return executeCommand(ctx, manager, sb.ID, "echo", []string{"test"}) },
			func() error { return writeFile(ctx, manager, sb.ID, "/workspace/temp.txt") },
			func() error { return readFile(ctx, manager, sb.ID, "/workspace/temp.txt") },
			func() error { return listFiles(ctx, manager, sb.ID, "/workspace") },
		}
		
		for _, op := range operations {
			if err := op(); err != nil {
				t.Logf("Operation failed in cycle %d: %v", cycle, err)
			}
		}
		
		// Cleanup
		if err := manager.DeleteSandbox(ctx, sb.ID); err != nil {
			t.Logf("Failed to terminate sandbox in cycle %d: %v", cycle, err)
		}
		
		// Force GC periodically
		if cycle%10 == 0 {
			runtime.GC()
			t.Logf("Completed cycle %d", cycle)
		}
	}

	// Force final cleanup
	runtime.GC()
	runtime.GC()
	time.Sleep(time.Second)

	// Analyze memory usage
	analysis := profiler.AnalyzeMemoryUsage()
	t.Logf("Memory leak analysis:")
	for key, value := range analysis {
		t.Logf("  %s: %v", key, value)
	}

	// Check for memory leaks
	if memoryLeak, ok := analysis["memory_leak"].(bool); ok && memoryLeak {
		t.Errorf("Memory leak detected: final memory significantly higher than baseline")
	}
	
	if growthRate, ok := analysis["growth_rate_bytes"].(float64); ok && growthRate > 1024*1024 { // 1MB growth per measurement
		t.Errorf("High memory growth rate detected: %.2f bytes per measurement", growthRate)
	}
}

// TestGoroutineLeakDetection tests for goroutine leaks
func TestGoroutineLeakDetection(t *testing.T) {
	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial goroutines: %d", initialGoroutines)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Perform operations that might leak goroutines
	for i := 0; i < 50; i++ {
		sandboxConfig := sandbox.SandboxConfig{
			Image:        "ubuntu:22.04",
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "0.1",
				MemoryLimit: "32m",
			},
		}
		
		sb, err := manager.CreateSandbox(ctx, sandboxConfig)
		if err != nil {
			t.Fatalf("Failed to create sandbox %d: %v", i, err)
		}
		
		// Do some work
		executeCommand(ctx, manager, sb.ID, "sleep", []string{"1"})
		
		// Cleanup
		manager.DeleteSandbox(ctx, sb.ID)
		
		if i%10 == 0 {
			currentGoroutines := runtime.NumGoroutine()
			t.Logf("Cycle %d: %d goroutines", i, currentGoroutines)
		}
	}

	// Give some time for cleanup
	time.Sleep(2 * time.Second)
	finalGoroutines := runtime.NumGoroutine()
	
	t.Logf("Final goroutines: %d", finalGoroutines)
	t.Logf("Goroutine difference: %d", finalGoroutines-initialGoroutines)
	
	// Allow some leeway for background goroutines
	if finalGoroutines > initialGoroutines+10 {
		t.Errorf("Potential goroutine leak: %d additional goroutines", finalGoroutines-initialGoroutines)
	}
}

// TestConcurrentMemoryUsage tests memory usage under concurrent load
func TestConcurrentMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent memory test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	profiler := NewMemoryProfiler()
	profiler.Start(time.Second)
	defer profiler.Stop()

	concurrencyLevels := []int{5, 10, 20}
	
	for _, concurrency := range concurrencyLevels {
		t.Run(fmt.Sprintf("concurrent_%d", concurrency), func(t *testing.T) {
			runtime.GC()
			runtime.GC()
			
			initialStats := GetCurrentMemoryStats()
			
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			
			var wg sync.WaitGroup
			errors := make(chan error, concurrency)
			
			for i := 0; i < concurrency; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()
					
					sandboxConfig := sandbox.SandboxConfig{
						Image:        "ubuntu:22.04",
						WorkspaceDir: "/workspace",
						Resources: sandbox.ResourceLimits{
							CPULimit:    "0.1",
							MemoryLimit: "64m",
						},
					}
					
					sb, err := manager.CreateSandbox(ctx, sandboxConfig)
					if err != nil {
						errors <- fmt.Errorf("worker %d: %w", workerID, err)
						return
					}
					defer manager.DeleteSandbox(ctx, sb.ID)
					
					// Perform memory-intensive operations
					for j := 0; j < 20; j++ {
						if err := writeFile(ctx, manager, sb.ID, fmt.Sprintf("/workspace/file_%d_%d.txt", workerID, j)); err != nil {
							errors <- fmt.Errorf("worker %d operation %d: %w", workerID, j, err)
							return
						}
						
						if err := readFile(ctx, manager, sb.ID, fmt.Sprintf("/workspace/file_%d_%d.txt", workerID, j)); err != nil {
							errors <- fmt.Errorf("worker %d read %d: %w", workerID, j, err)
						}
					}
				}(i)
			}
			
			wg.Wait()
			close(errors)
			
			// Check for errors
			errorCount := 0
			for err := range errors {
				if err != nil {
					t.Logf("Concurrent operation error: %v", err)
					errorCount++
				}
			}
			
			// Force cleanup and measurement
			runtime.GC()
			runtime.GC()
			time.Sleep(time.Second)
			
			finalStats := GetCurrentMemoryStats()
			memoryUsedMB := float64(finalStats.HeapAlloc-initialStats.HeapAlloc) / 1024 / 1024
			
			t.Logf("Concurrent memory test (concurrency=%d):", concurrency)
			t.Logf("  Memory used: %.2f MB", memoryUsedMB)
			t.Logf("  Errors: %d/%d", errorCount, concurrency)
			t.Logf("  Goroutines: %d -> %d", initialStats.NumGoroutine, finalStats.NumGoroutine)
			
			// Memory usage should scale reasonably with concurrency
			expectedMaxMemoryMB := float64(concurrency) * 50.0 // 50MB per concurrent operation
			if memoryUsedMB > expectedMaxMemoryMB {
				t.Errorf("Memory usage %.2f MB exceeds expected max %.2f MB for concurrency %d", 
					memoryUsedMB, expectedMaxMemoryMB, concurrency)
			}
		})
	}
}

// TestLargeDataHandling tests memory efficiency with large data operations
func TestLargeDataHandling(t *testing.T) {
	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	
	sandboxConfig := sandbox.SandboxConfig{
		Image:        "ubuntu:22.04",
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "0.5",
			MemoryLimit: "512m",
		},
	}
	
	sb, err := manager.CreateSandbox(ctx, sandboxConfig)
	if err != nil {
		t.Fatalf("Failed to create sandbox: %v", err)
	}
	defer manager.DeleteSandbox(ctx, sb.ID)

	dataSizes := []struct {
		name string
		size int
	}{
		{"1MB", 1024 * 1024},
		{"10MB", 10 * 1024 * 1024},
		{"100MB", 100 * 1024 * 1024},
	}

	for _, ds := range dataSizes {
		t.Run(ds.name, func(t *testing.T) {
			runtime.GC()
			runtime.GC()
			
			initialStats := GetCurrentMemoryStats()
			
			// Create large data content
			content := make([]byte, ds.size)
			for i := range content {
				content[i] = byte('a' + (i % 26))
			}
			
			// Test writing large data
			tool := tools.NewWriteFileTool(manager)
			
			params := map[string]interface{}{
				"sandbox_id": sb.ID,
				"file_path":  fmt.Sprintf("/workspace/large_file_%s.txt", ds.name),
				"content":    string(content),
			}
			
			start := time.Now()
			_, err := tool.Execute(ctx, params)
			writeDuration := time.Since(start)
			
			if err != nil {
				t.Errorf("Failed to write large file (%s): %v", ds.name, err)
				return
			}
			
			t.Logf("Write %s took %v", ds.name, writeDuration)
			
			// Test reading large data back
			readTool := tools.NewReadFileTool(manager)
			
			readParams := map[string]interface{}{
				"sandbox_id": sb.ID,
				"file_path":  fmt.Sprintf("/workspace/large_file_%s.txt", ds.name),
			}
			
			start = time.Now()
			_, err = readTool.Execute(ctx, readParams)
			readDuration := time.Since(start)
			
			if err != nil {
				t.Errorf("Failed to read large file (%s): %v", ds.name, err)
				return
			}
			
			t.Logf("Read %s took %v", ds.name, readDuration)
			
			// Check memory usage after operations
			runtime.GC()
			runtime.GC()
			finalStats := GetCurrentMemoryStats()
			
			memoryUsedMB := float64(finalStats.HeapAlloc-initialStats.HeapAlloc) / 1024 / 1024
			
			t.Logf("Memory usage for %s: %.2f MB", ds.name, memoryUsedMB)
			
			// Memory usage should be reasonable compared to data size
			dataSizeMB := float64(ds.size) / 1024 / 1024
			if memoryUsedMB > dataSizeMB*3 { // Allow 3x overhead
				t.Errorf("Memory usage %.2f MB too high for data size %.2f MB", memoryUsedMB, dataSizeMB)
			}
			
			// Performance should be reasonable
			writeSpeedMBps := dataSizeMB / writeDuration.Seconds()
			readSpeedMBps := dataSizeMB / readDuration.Seconds()
			
			t.Logf("Write speed: %.2f MB/s", writeSpeedMBps)
			t.Logf("Read speed: %.2f MB/s", readSpeedMBps)
			
			if writeSpeedMBps < 1.0 { // At least 1 MB/s
				t.Errorf("Write speed %.2f MB/s too slow", writeSpeedMBps)
			}
			if readSpeedMBps < 5.0 { // At least 5 MB/s for reading
				t.Errorf("Read speed %.2f MB/s too slow", readSpeedMBps)
			}
		})
	}
}