package performance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// ProfileConfig holds configuration for performance profiling
type ProfileConfig struct {
	CPUProfile     bool
	MemProfile     bool
	BlockProfile   bool
	MutexProfile   bool
	GoroutineProfile bool
	Trace          bool
	OutputDir      string
	Duration       time.Duration
}

// Profiler manages performance profiling during tests
type Profiler struct {
	config     ProfileConfig
	outputDir  string
	cpuFile    *os.File
	memFile    *os.File
	traceFile  *os.File
	running    bool
	mutex      sync.Mutex
}

// NewProfiler creates a new performance profiler
func NewProfiler(config ProfileConfig) *Profiler {
	if config.OutputDir == "" {
		config.OutputDir = filepath.Join(os.TempDir(), fmt.Sprintf("sandbox-profiles-%d", time.Now().Unix()))
	}
	
	os.MkdirAll(config.OutputDir, 0755)
	
	return &Profiler{
		config:    config,
		outputDir: config.OutputDir,
	}
}

// Start begins profiling
func (p *Profiler) Start() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	if p.running {
		return fmt.Errorf("profiling already running")
	}
	
	var err error
	
	// CPU profiling
	if p.config.CPUProfile {
		p.cpuFile, err = os.Create(filepath.Join(p.outputDir, "cpu.prof"))
		if err != nil {
			return fmt.Errorf("could not create CPU profile: %w", err)
		}
		
		if err := pprof.StartCPUProfile(p.cpuFile); err != nil {
			p.cpuFile.Close()
			return fmt.Errorf("could not start CPU profile: %w", err)
		}
	}
	
	// Execution tracer
	if p.config.Trace {
		p.traceFile, err = os.Create(filepath.Join(p.outputDir, "trace.out"))
		if err != nil {
			return fmt.Errorf("could not create trace file: %w", err)
		}
		
		if err := trace.Start(p.traceFile); err != nil {
			p.traceFile.Close()
			return fmt.Errorf("could not start trace: %w", err)
		}
	}
	
	// Block profiling
	if p.config.BlockProfile {
		runtime.SetBlockProfileRate(1)
	}
	
	// Mutex profiling
	if p.config.MutexProfile {
		runtime.SetMutexProfileFraction(1)
	}
	
	p.running = true
	return nil
}

// Stop ends profiling and writes profile data
func (p *Profiler) Stop() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	if !p.running {
		return fmt.Errorf("profiling not running")
	}
	
	// Stop CPU profiling
	if p.config.CPUProfile && p.cpuFile != nil {
		pprof.StopCPUProfile()
		p.cpuFile.Close()
	}
	
	// Stop execution tracer
	if p.config.Trace && p.traceFile != nil {
		trace.Stop()
		p.traceFile.Close()
	}
	
	// Write memory profile
	if p.config.MemProfile {
		memFile, err := os.Create(filepath.Join(p.outputDir, "mem.prof"))
		if err != nil {
			return fmt.Errorf("could not create memory profile: %w", err)
		}
		defer memFile.Close()
		
		runtime.GC() // Get up-to-date statistics
		if err := pprof.WriteHeapProfile(memFile); err != nil {
			return fmt.Errorf("could not write memory profile: %w", err)
		}
	}
	
	// Write block profile
	if p.config.BlockProfile {
		blockFile, err := os.Create(filepath.Join(p.outputDir, "block.prof"))
		if err != nil {
			return fmt.Errorf("could not create block profile: %w", err)
		}
		defer blockFile.Close()
		
		if err := pprof.Lookup("block").WriteTo(blockFile, 0); err != nil {
			return fmt.Errorf("could not write block profile: %w", err)
		}
	}
	
	// Write mutex profile
	if p.config.MutexProfile {
		mutexFile, err := os.Create(filepath.Join(p.outputDir, "mutex.prof"))
		if err != nil {
			return fmt.Errorf("could not create mutex profile: %w", err)
		}
		defer mutexFile.Close()
		
		if err := pprof.Lookup("mutex").WriteTo(mutexFile, 0); err != nil {
			return fmt.Errorf("could not write mutex profile: %w", err)
		}
	}
	
	// Write goroutine profile
	if p.config.GoroutineProfile {
		goroutineFile, err := os.Create(filepath.Join(p.outputDir, "goroutine.prof"))
		if err != nil {
			return fmt.Errorf("could not create goroutine profile: %w", err)
		}
		defer goroutineFile.Close()
		
		if err := pprof.Lookup("goroutine").WriteTo(goroutineFile, 0); err != nil {
			return fmt.Errorf("could not write goroutine profile: %w", err)
		}
	}
	
	p.running = false
	return nil
}

// GetOutputDir returns the directory where profile files are stored
func (p *Profiler) GetOutputDir() string {
	return p.outputDir
}

// TestCPUProfiling tests CPU usage patterns during various operations
func TestCPUProfiling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CPU profiling test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	profileConfig := ProfileConfig{
		CPUProfile: true,
		MemProfile: true,
		Trace:      true,
		Duration:   2 * time.Minute,
	}
	
	profiler := NewProfiler(profileConfig)
	
	if err := profiler.Start(); err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer func() {
		if err := profiler.Stop(); err != nil {
			t.Errorf("Failed to stop profiler: %v", err)
		} else {
			t.Logf("Profile data written to: %s", profiler.GetOutputDir())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), profileConfig.Duration)
	defer cancel()

	// Test different CPU-intensive workloads
	testWorkloads := []struct {
		name string
		work func() error
	}{
		{
			"sandbox_creation", func() error {
				sandboxConfig := sandbox.SandboxConfig{
					Image:        "ubuntu:22.04",
					WorkspaceDir: "/workspace",
					Resources: sandbox.ResourceLimits{
						CPULimit:    "0.5",
						MemoryLimit: "128m",
					},
				}
				
				sb, err := manager.CreateSandbox(ctx, sandboxConfig)
				if err != nil {
					return err
				}
				
				return manager.DeleteSandbox(ctx, sb.ID)
			},
		},
		{
			"code_execution", func() error {
				sandboxConfig := sandbox.SandboxConfig{
					Image:        "ubuntu:22.04",
					WorkspaceDir: "/workspace",
					Resources: sandbox.ResourceLimits{
						CPULimit:    "0.5",
						MemoryLimit: "128m",
					},
				}
				
				sb, err := manager.CreateSandbox(ctx, sandboxConfig)
				if err != nil {
					return err
				}
				defer manager.DeleteSandbox(ctx, sb.ID)
				
				// CPU intensive command
				return executeCommand(ctx, manager, sb.ID, "yes", []string{"|", "head", "-n", "1000"})
			},
		},
		{
			"file_operations", func() error {
				sandboxConfig := sandbox.SandboxConfig{
					Image:        "ubuntu:22.04",
					WorkspaceDir: "/workspace",
					Resources: sandbox.ResourceLimits{
						CPULimit:    "0.5",
						MemoryLimit: "128m",
					},
				}
				
				sb, err := manager.CreateSandbox(ctx, sandboxConfig)
				if err != nil {
					return err
				}
				defer manager.DeleteSandbox(ctx, sb.ID)
				
				// Write and read large files
				for i := 0; i < 10; i++ {
					content := fmt.Sprintf("Large content for file %d: %s", i, generateLargeString(10*1024))
					if err := writeFile(ctx, manager, sb.ID, fmt.Sprintf("/workspace/file%d.txt", i)); err != nil {
						return err
					}
					if err := readFile(ctx, manager, sb.ID, fmt.Sprintf("/workspace/file%d.txt", i)); err != nil {
						return err
					}
				}
				return nil
			},
		},
	}

	// Run workloads concurrently to generate CPU load
	var wg sync.WaitGroup
	errors := make(chan error, len(testWorkloads)*5)
	
	startTime := time.Now()
	for time.Since(startTime) < profileConfig.Duration-30*time.Second {
		for _, workload := range testWorkloads {
			wg.Add(1)
			go func(w struct {
				name string
				work func() error
			}) {
				defer wg.Done()
				if err := w.work(); err != nil {
					errors <- fmt.Errorf("workload %s failed: %w", w.name, err)
				}
			}(workload)
		}
		
		wg.Wait()
		
		select {
		case err := <-errors:
			t.Logf("Workload error: %v", err)
		default:
		}
		
		time.Sleep(100 * time.Millisecond)
	}
	
	close(errors)
	
	// Report any errors that occurred
	errorCount := 0
	for err := range errors {
		if err != nil {
			t.Logf("Error during profiling: %v", err)
			errorCount++
		}
	}
	
	t.Logf("Profiling completed with %d errors", errorCount)
}

// TestMemoryProfiling profiles memory allocation patterns
func TestMemoryProfiling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory profiling test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	profileConfig := ProfileConfig{
		MemProfile:       true,
		GoroutineProfile: true,
		Duration:         3 * time.Minute,
	}
	
	profiler := NewProfiler(profileConfig)
	
	if err := profiler.Start(); err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer func() {
		if err := profiler.Stop(); err != nil {
			t.Errorf("Failed to stop profiler: %v", err)
		} else {
			t.Logf("Memory profile data written to: %s", profiler.GetOutputDir())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), profileConfig.Duration)
	defer cancel()

	// Create many sandboxes to stress memory allocation
	var sandboxes []*sandbox.Sandbox
	var wg sync.WaitGroup
	
	// Phase 1: Gradual allocation
	t.Log("Phase 1: Creating sandboxes gradually")
	for i := 0; i < 50; i++ {
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
			t.Logf("Failed to create sandbox %d: %v", i, err)
			break
		}
		
		sandboxes = append(sandboxes, sb)
		
		// Concurrent operations on each sandbox
		wg.Add(1)
		go func(sandbox *sandbox.Sandbox, index int) {
			defer wg.Done()
			
			// Perform memory-intensive operations
			for j := 0; j < 5; j++ {
				largeContent := generateLargeString(100 * 1024) // 100KB strings
				writeFile(ctx, manager, sandbox.ID, fmt.Sprintf("/workspace/large_%d_%d.txt", index, j))
				_ = largeContent // Keep reference to prevent early GC
			}
		}(sb, i)
		
		if i%10 == 0 {
			t.Logf("Created %d sandboxes", i+1)
			runtime.GC() // Periodic GC to see allocation patterns
		}
		
		time.Sleep(100 * time.Millisecond)
	}
	
	// Phase 2: Memory pressure
	t.Log("Phase 2: Creating memory pressure")
	time.Sleep(30 * time.Second) // Let memory allocations settle
	
	// Phase 3: Cleanup and observe deallocation
	t.Log("Phase 3: Cleaning up sandboxes")
	for i, sb := range sandboxes {
		manager.DeleteSandbox(ctx, sb.ID)
		if i%10 == 0 {
			runtime.GC()
			t.Logf("Cleaned up %d sandboxes", i+1)
		}
	}
	
	wg.Wait()
	
	// Final GC to clean up
	runtime.GC()
	runtime.GC()
	
	t.Log("Memory profiling test completed")
}

// TestConcurrencyProfiling profiles goroutines and blocking behavior
func TestConcurrencyProfiling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency profiling test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	profileConfig := ProfileConfig{
		BlockProfile:     true,
		MutexProfile:     true,
		GoroutineProfile: true,
		Duration:         2 * time.Minute,
	}
	
	profiler := NewProfiler(profileConfig)
	
	if err := profiler.Start(); err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer func() {
		if err := profiler.Stop(); err != nil {
			t.Errorf("Failed to stop profiler: %v", err)
		} else {
			t.Logf("Concurrency profile data written to: %s", profiler.GetOutputDir())
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), profileConfig.Duration)
	defer cancel()

	// Test high concurrency scenarios that may cause blocking
	concurrencyLevels := []int{10, 25, 50, 100}
	
	for _, concurrency := range concurrencyLevels {
		t.Logf("Testing concurrency level: %d", concurrency)
		
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, concurrency/2) // Limit to create some blocking
		
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				// Acquire semaphore (may block)
				semaphore <- struct{}{}
				defer func() { <-semaphore }()
				
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
					t.Logf("Worker %d failed to create sandbox: %v", workerID, err)
					return
				}
				
				// Perform operations that may involve locking
				operations := []func() error{
					func() error { return executeCommand(ctx, manager, sb.ID, "echo", []string{"test"}) },
					func() error { return listFiles(ctx, manager, sb.ID, "/workspace") },
					func() error { 
						return writeFile(ctx, manager, sb.ID, fmt.Sprintf("/workspace/worker_%d.txt", workerID)) 
					},
				}
				
				for _, op := range operations {
					if err := op(); err != nil {
						t.Logf("Worker %d operation failed: %v", workerID, err)
					}
				}
				
				manager.DeleteSandbox(ctx, sb.ID)
			}(i)
		}
		
		wg.Wait()
		
		// Brief pause between concurrency levels
		time.Sleep(5 * time.Second)
	}
	
	t.Log("Concurrency profiling test completed")
}

// TestBenchmarkWithProfiling runs benchmarks with profiling enabled
func TestBenchmarkWithProfiling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark profiling test in short mode")
	}

	// Run a subset of benchmarks with profiling enabled
	profileConfig := ProfileConfig{
		CPUProfile:   true,
		MemProfile:   true,
		Trace:        true,
		Duration:     5 * time.Minute,
	}
	
	profiler := NewProfiler(profileConfig)
	
	if err := profiler.Start(); err != nil {
		t.Fatalf("Failed to start profiler: %v", err)
	}
	defer func() {
		if err := profiler.Stop(); err != nil {
			t.Errorf("Failed to stop profiler: %v", err)
		} else {
			t.Logf("Benchmark profile data written to: %s", profiler.GetOutputDir())
		}
	}()

	// Run performance-critical code paths under profiling
	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	// Simulate benchmark-like workload
	iterations := 100
	startTime := time.Now()
	
	for i := 0; i < iterations; i++ {
		// Container lifecycle benchmark
		sandboxConfig := sandbox.SandboxConfig{
			Image:        "ubuntu:22.04",
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "0.5",
				MemoryLimit: "128m",
			},
		}
		
		sb, err := manager.CreateSandbox(ctx, sandboxConfig)
		if err != nil {
			t.Logf("Iteration %d: Failed to create sandbox: %v", i, err)
			continue
		}
		
		// Perform operations
		operations := []func() error{
			func() error { return executeCommand(ctx, manager, sb.ID, "echo", []string{"benchmark"}) },
			func() error { return writeFile(ctx, manager, sb.ID, "/workspace/bench.txt") },
			func() error { return readFile(ctx, manager, sb.ID, "/workspace/bench.txt") },
		}
		
		for _, op := range operations {
			if err := op(); err != nil {
				t.Logf("Iteration %d: Operation failed: %v", i, err)
			}
		}
		
		manager.DeleteSandbox(ctx, sb.ID)
		
		if i%10 == 0 {
			elapsed := time.Since(startTime)
			rate := float64(i+1) / elapsed.Seconds()
			t.Logf("Completed %d iterations, rate: %.2f ops/sec", i+1, rate)
		}
	}
	
	totalTime := time.Since(startTime)
	avgTime := totalTime / time.Duration(iterations)
	
	t.Logf("Benchmark profiling completed:")
	t.Logf("  Total iterations: %d", iterations)
	t.Logf("  Total time: %v", totalTime)
	t.Logf("  Average time per iteration: %v", avgTime)
	t.Logf("  Operations per second: %.2f", float64(iterations)/totalTime.Seconds())
}

// generateLargeString creates a large string for memory testing
func generateLargeString(size int) string {
	content := make([]byte, size)
	for i := range content {
		content[i] = byte('a' + (i % 26))
	}
	return string(content)
}

// TestProfileAnalysis demonstrates how to analyze profile data programmatically
func TestProfileAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping profile analysis test in short mode")
	}

	// This test demonstrates integration with Go's profiling analysis tools
	// In practice, you would use `go tool pprof` to analyze the generated profiles
	
	profileDir := filepath.Join(os.TempDir(), fmt.Sprintf("sandbox-analysis-%d", time.Now().Unix()))
	os.MkdirAll(profileDir, 0755)
	
	t.Logf("Profile analysis guidance:")
	t.Logf("After running profiled tests, analyze results with:")
	t.Logf("  CPU profile: go tool pprof %s/cpu.prof", profileDir)
	t.Logf("  Memory profile: go tool pprof %s/mem.prof", profileDir)
	t.Logf("  Block profile: go tool pprof %s/block.prof", profileDir)
	t.Logf("  Mutex profile: go tool pprof %s/mutex.prof", profileDir)
	t.Logf("  Execution trace: go tool trace %s/trace.out", profileDir)
	t.Logf("")
	t.Logf("Common pprof commands:")
	t.Logf("  (pprof) top10          # Show top 10 functions by CPU usage")
	t.Logf("  (pprof) list main      # Show source code with annotations")
	t.Logf("  (pprof) web            # Generate SVG graph")
	t.Logf("  (pprof) png > cpu.png  # Generate PNG graph")
	t.Logf("")
	t.Logf("Performance optimization targets:")
	t.Logf("  - Container startup < 500ms")
	t.Logf("  - Command execution overhead < 100ms")
	t.Logf("  - Memory usage < 50MB per sandbox")
	t.Logf("  - Support 100+ concurrent sandboxes")
	t.Logf("  - API response time p99 < 200ms")
}