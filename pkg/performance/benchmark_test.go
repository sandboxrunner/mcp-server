package performance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	sbruntime "github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/storage"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// BenchmarkConfig holds configuration for performance benchmarks
type BenchmarkConfig struct {
	TempDir         string
	StorageDir      string
	ContainerImage  string
	TimeoutDuration time.Duration
	MaxConcurrency  int
}

var (
	benchConfig *BenchmarkConfig
	setupOnce   sync.Once
)

// setupBenchmark initializes the benchmark environment
func setupBenchmark(b *testing.B) *BenchmarkConfig {
	setupOnce.Do(func() {
		tempDir := os.TempDir()
		storageDir := filepath.Join(tempDir, fmt.Sprintf("sandbox-bench-%d", time.Now().Unix()))
		
		if err := os.MkdirAll(storageDir, 0755); err != nil {
			b.Fatalf("Failed to create storage dir: %v", err)
		}
		
		benchConfig = &BenchmarkConfig{
			TempDir:         tempDir,
			StorageDir:      storageDir,
			ContainerImage:  "ubuntu:22.04",
			TimeoutDuration: 30 * time.Second,
			MaxConcurrency:  runtime.NumCPU() * 2,
		}
	})
	return benchConfig
}

// createTestManager creates a sandbox manager for benchmarking
func createTestManager(b *testing.B, config *BenchmarkConfig) *sandbox.Manager {
	// Initialize storage
	store, err := storage.NewSQLiteStore(&storage.Config{
		DatabasePath: filepath.Join(config.StorageDir, "test.db"),
	})
	if err != nil {
		b.Fatalf("Failed to create storage: %v", err)
	}

	// Initialize runtime
	rt, err := sbruntime.NewRunCClient(filepath.Join(config.StorageDir, "runc"))
	if err != nil {
		b.Fatalf("Failed to create runtime: %v", err)
	}

	// Create manager
	manager, err := sandbox.NewManager(filepath.Join(config.StorageDir, "test.db"), filepath.Join(config.StorageDir, "workspace"))
	if err != nil {
		b.Fatalf("Failed to create manager: %v", err)
	}

	return manager
}

// BenchmarkContainerLifecycle benchmarks full container lifecycle
func BenchmarkContainerLifecycle(b *testing.B) {
	config := setupBenchmark(b)
	manager := createTestManager(b, config)
	defer manager.Close()

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), config.TimeoutDuration)
		
		// Create sandbox
		sandboxConfig := sandbox.SandboxConfig{
			Image:        config.ContainerImage,
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "0.5",
				MemoryLimit: "128m",
				DiskLimit:   "1g",
			},
			NetworkMode: "none",
		}
		
		start := time.Now()
		sb, err := manager.CreateSandbox(ctx, sandboxConfig)
		createDuration := time.Since(start)
		
		if err != nil {
			b.Errorf("Failed to create sandbox: %v", err)
			cancel()
			continue
		}
		
		// Verify creation time meets target (< 500ms)
		if createDuration > 500*time.Millisecond {
			b.Errorf("Container startup took %v, target is < 500ms", createDuration)
		}
		
		// Terminate sandbox
		if err := manager.DeleteSandbox(ctx, sb.ID); err != nil {
			b.Errorf("Failed to terminate sandbox: %v", err)
		}
		
		cancel()
	}
}

// BenchmarkContainerStartup benchmarks just container startup time
func BenchmarkContainerStartup(b *testing.B) {
	config := setupBenchmark(b)
	manager := createTestManager(b, config)
	defer manager.Close()

	sandboxConfig := sandbox.SandboxConfig{
		Image:        config.ContainerImage,
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "0.5",
			MemoryLimit: "64m",
		},
		NetworkMode: "none",
	}

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), config.TimeoutDuration)
		
		start := time.Now()
		sb, err := manager.CreateSandbox(ctx, sandboxConfig)
		duration := time.Since(start)
		
		if err != nil {
			b.Errorf("Sandbox creation failed: %v", err)
			cancel()
			continue
		}
		
		// Record startup time
		b.ReportMetric(float64(duration.Nanoseconds())/1e6, "startup_ms")
		
		// Cleanup
		manager.DeleteSandbox(ctx, sb.ID)
		cancel()
	}
}

// BenchmarkToolExecution benchmarks MCP tool execution overhead
func BenchmarkToolExecution(b *testing.B) {
	config := setupBenchmark(b)
	manager := createTestManager(b, config)
	defer manager.Close()
	
	// Create a persistent sandbox for tool testing
	ctx := context.Background()
	sandboxConfig := sandbox.SandboxConfig{
		Image:        config.ContainerImage,
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "1.0",
			MemoryLimit: "256m",
		},
	}
	
	sb, err := manager.CreateSandbox(ctx, sandboxConfig)
	if err != nil {
		b.Fatalf("Failed to create test sandbox: %v", err)
	}
	defer manager.DeleteSandbox(ctx, sb.ID)

	// Test different tools
	testCases := []struct {
		name     string
		toolName string
		params   map[string]interface{}
	}{
		{
			name:     "exec_command",
			toolName: "exec_command",
			params: map[string]interface{}{
				"sandbox_id": sb.ID,
				"command":    "echo",
				"args":       []string{"hello"},
			},
		},
		{
			name:     "write_file",
			toolName: "write_file",
			params: map[string]interface{}{
				"sandbox_id": sb.ID,
				"file_path":  "/workspace/test.txt",
				"content":    "test content",
			},
		},
		{
			name:     "read_file",
			toolName: "read_file",
			params: map[string]interface{}{
				"sandbox_id": sb.ID,
				"file_path":  "/workspace/test.txt",
			},
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			var tool tools.Tool
			switch tc.toolName {
			case "exec_command":
				tool = tools.NewExecCommandTool(manager)
			case "write_file":
				tool = tools.NewWriteFileTool(manager)
			case "read_file":
				tool = tools.NewReadFileTool(manager)
			default:
				b.Fatalf("Unknown tool: %s", tc.toolName)
			}
			
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				start := time.Now()
				_, err := tool.Execute(ctx, tc.params)
				duration := time.Since(start)
				
				if err != nil {
					b.Errorf("Tool execution failed: %v", err)
					continue
				}
				
				// Verify execution overhead meets target (< 100ms)
				if duration > 100*time.Millisecond {
					b.Errorf("Tool execution took %v, target is < 100ms", duration)
				}
				
				b.ReportMetric(float64(duration.Nanoseconds())/1e6, "execution_ms")
			}
		})
	}
}

// BenchmarkLanguageExecution benchmarks language-specific code execution
func BenchmarkLanguageExecution(b *testing.B) {
	config := setupBenchmark(b)
	manager := createTestManager(b, config)
	defer manager.Close()
	
	ctx := context.Background()
	sandboxConfig := sandbox.SandboxConfig{
		Image:        "sandboxrunner/multi-lang:latest",
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "1.0",
			MemoryLimit: "512m",
		},
	}
	
	sb, err := manager.CreateSandbox(ctx, sandboxConfig)
	if err != nil {
		b.Fatalf("Failed to create test sandbox: %v", err)
	}
	defer manager.DeleteSandbox(ctx, sb.ID)

	testCases := []struct {
		name     string
		toolName string
		code     string
	}{
		{
			name:     "python",
			toolName: "run_python",
			code:     "print('Hello, World!')",
		},
		{
			name:     "javascript",
			toolName: "run_javascript",
			code:     "console.log('Hello, World!');",
		},
		{
			name:     "go",
			toolName: "run_go",
			code: `package main
import "fmt"
func main() {
	fmt.Println("Hello, World!")
}`,
		},
		{
			name:     "shell",
			toolName: "run_shell",
			code:     "echo 'Hello, World!'",
		},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			var tool tools.Tool
			switch tc.toolName {
			case "run_python":
				tool = tools.NewRunCodeTool(manager, nil)
			case "run_javascript":
				tool = tools.NewRunCodeTool(manager, nil)
			case "run_go":
				tool = tools.NewRunCodeTool(manager, nil)
			case "run_shell":
				tool = tools.NewRunCodeTool(manager, nil)
			default:
				b.Skip("Tool not available: " + tc.toolName)
			}
			
			params := map[string]interface{}{
				"sandbox_id": sb.ID,
				"code":       tc.code,
			}
			
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				start := time.Now()
				result, err := tool.Execute(ctx, params)
				duration := time.Since(start)
				
				if err != nil {
					b.Errorf("Code execution failed: %v", err)
					continue
				}
				
				if result.Success != true {
					b.Errorf("Code execution unsuccessful: %v", result.Error)
					continue
				}
				
				b.ReportMetric(float64(duration.Nanoseconds())/1e6, "execution_ms")
			}
		})
	}
}

// BenchmarkFileOperations benchmarks file I/O operations
func BenchmarkFileOperations(b *testing.B) {
	config := setupBenchmark(b)
	manager := createTestManager(b, config)
	defer manager.Close()
	
	ctx := context.Background()
	sandboxConfig := sandbox.SandboxConfig{
		Image:        config.ContainerImage,
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "0.5",
			MemoryLimit: "128m",
		},
	}
	
	sb, err := manager.CreateSandbox(ctx, sandboxConfig)
	if err != nil {
		b.Fatalf("Failed to create test sandbox: %v", err)
	}
	defer manager.DeleteSandbox(ctx, sb.ID)

	// Test different file sizes
	testSizes := []struct {
		name string
		size int
	}{
		{"small_1kb", 1024},
		{"medium_10kb", 10 * 1024},
		{"large_100kb", 100 * 1024},
		{"xlarge_1mb", 1024 * 1024},
	}

	for _, ts := range testSizes {
		b.Run(fmt.Sprintf("write_%s", ts.name), func(b *testing.B) {
			content := make([]byte, ts.size)
			for i := range content {
				content[i] = byte('a' + (i % 26))
			}
			
			writeTool := tools.NewWriteFileTool(manager)
			params := map[string]interface{}{
				"sandbox_id": sb.ID,
				"file_path":  fmt.Sprintf("/workspace/test_%s.txt", ts.name),
				"content":    string(content),
			}
			
			b.SetBytes(int64(ts.size))
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				_, err := writeTool.Execute(ctx, params)
				if err != nil {
					b.Errorf("Write failed: %v", err)
				}
			}
		})
		
		b.Run(fmt.Sprintf("read_%s", ts.name), func(b *testing.B) {
			// First write the file
			content := make([]byte, ts.size)
			for i := range content {
				content[i] = byte('a' + (i % 26))
			}
			
			writeTool := tools.NewWriteFileTool(manager)
			writeParams := map[string]interface{}{
				"sandbox_id": sb.ID,
				"file_path":  fmt.Sprintf("/workspace/read_test_%s.txt", ts.name),
				"content":    string(content),
			}
			writeTool.Execute(ctx, writeParams)
			
			// Now benchmark reading
			readTool := tools.NewReadFileTool(manager)
			readParams := map[string]interface{}{
				"sandbox_id": sb.ID,
				"file_path":  fmt.Sprintf("/workspace/read_test_%s.txt", ts.name),
			}
			
			b.SetBytes(int64(ts.size))
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				_, err := readTool.Execute(ctx, readParams)
				if err != nil {
					b.Errorf("Read failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkConcurrentSandboxes benchmarks concurrent sandbox operations
func BenchmarkConcurrentSandboxes(b *testing.B) {
	config := setupBenchmark(b)
	manager := createTestManager(b, config)
	defer manager.Close()

	concurrencyLevels := []int{1, 5, 10, 25, 50, 100}

	for _, concurrency := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrent_%d", concurrency), func(b *testing.B) {
			if concurrency > config.MaxConcurrency {
				b.Skipf("Concurrency %d exceeds max %d", concurrency, config.MaxConcurrency)
			}
			
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				errors := make(chan error, concurrency)
				
				start := time.Now()
				
				for j := 0; j < concurrency; j++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						
						ctx, cancel := context.WithTimeout(context.Background(), config.TimeoutDuration)
						defer cancel()
						
						sandboxConfig := sandbox.SandboxConfig{
							Image:        config.ContainerImage,
							WorkspaceDir: "/workspace",
							Resources: sandbox.ResourceLimits{
								CPULimit:    "0.2",
								MemoryLimit: "64m",
							},
						}
						
						sb, err := manager.CreateSandbox(ctx, sandboxConfig)
						if err != nil {
							errors <- err
							return
						}
						
						manager.DeleteSandbox(ctx, sb.ID)
					}()
				}
				
				wg.Wait()
				close(errors)
				
				duration := time.Since(start)
				
				// Check for errors
				for err := range errors {
					if err != nil {
						b.Errorf("Concurrent operation failed: %v", err)
						break
					}
				}
				
				b.ReportMetric(float64(duration.Nanoseconds())/1e6, "total_ms")
				b.ReportMetric(float64(duration.Nanoseconds())/1e6/float64(concurrency), "per_sandbox_ms")
			}
		})
	}
}

// BenchmarkAPIResponseTime benchmarks API response times
func BenchmarkAPIResponseTime(b *testing.B) {
	config := setupBenchmark(b)
	manager := createTestManager(b, config)
	defer manager.Close()
	
	// Create a test sandbox
	ctx := context.Background()
	sandboxConfig := sandbox.SandboxConfig{
		Image:        config.ContainerImage,
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "0.5",
			MemoryLimit: "128m",
		},
	}
	
	sb, err := manager.CreateSandbox(ctx, sandboxConfig)
	if err != nil {
		b.Fatalf("Failed to create test sandbox: %v", err)
	}
	defer manager.DeleteSandbox(ctx, sb.ID)

	// Test various API operations
	apiOperations := []struct {
		name     string
		toolName string
		params   map[string]interface{}
	}{
		{
			name:     "list_sandboxes",
			toolName: "list_sandboxes",
			params:   map[string]interface{}{},
		},
		{
			name:     "list_files",
			toolName: "list_files",
			params: map[string]interface{}{
				"sandbox_id": sb.ID,
				"path":       "/workspace",
			},
		},
		{
			name:     "exec_simple_command",
			toolName: "exec_command",
			params: map[string]interface{}{
				"sandbox_id": sb.ID,
				"command":    "pwd",
			},
		},
	}

	for _, op := range apiOperations {
		b.Run(op.name, func(b *testing.B) {
			var tool tools.Tool
			switch op.toolName {
			case "list_sandboxes":
				tool = tools.NewListSandboxesTool(manager)
			case "list_files":
				tool = tools.NewListFilesTool(manager)
			case "exec_command":
				tool = tools.NewExecCommandTool(manager)
			default:
				b.Fatalf("Unknown tool: %s", op.toolName)
			}
			
			b.ResetTimer()
			
			responseTimes := make([]time.Duration, b.N)
			
			for i := 0; i < b.N; i++ {
				start := time.Now()
				_, err := tool.Execute(ctx, op.params)
				responseTimes[i] = time.Since(start)
				
				if err != nil {
					b.Errorf("API operation failed: %v", err)
				}
			}
			
			// Calculate percentiles
			if len(responseTimes) > 0 {
				// Sort response times for percentile calculation
				for i := 0; i < len(responseTimes)-1; i++ {
					for j := i + 1; j < len(responseTimes); j++ {
						if responseTimes[i] > responseTimes[j] {
							responseTimes[i], responseTimes[j] = responseTimes[j], responseTimes[i]
						}
					}
				}
				
				p50 := responseTimes[len(responseTimes)*50/100]
				p95 := responseTimes[len(responseTimes)*95/100]
				p99 := responseTimes[len(responseTimes)*99/100]
				
				b.ReportMetric(float64(p50.Nanoseconds())/1e6, "p50_ms")
				b.ReportMetric(float64(p95.Nanoseconds())/1e6, "p95_ms")
				b.ReportMetric(float64(p99.Nanoseconds())/1e6, "p99_ms")
				
				// Verify p99 meets target (< 200ms)
				if p99 > 200*time.Millisecond {
					b.Errorf("P99 response time %v exceeds target of 200ms", p99)
				}
			}
		})
	}
}

// BenchmarkMemoryEfficiency tests memory usage per sandbox
func BenchmarkMemoryEfficiency(b *testing.B) {
	config := setupBenchmark(b)
	manager := createTestManager(b, config)
	defer manager.Close()

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		var m1, m2 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m1)
		
		ctx, cancel := context.WithTimeout(context.Background(), config.TimeoutDuration)
		
		sandboxConfig := sandbox.SandboxConfig{
			Image:        config.ContainerImage,
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "0.2",
				MemoryLimit: "64m",
			},
		}
		
		sb, err := manager.CreateSandbox(ctx, sandboxConfig)
		if err != nil {
			b.Errorf("Failed to create sandbox: %v", err)
			cancel()
			continue
		}
		
		runtime.GC()
		runtime.ReadMemStats(&m2)
		
		memoryUsed := m2.Alloc - m1.Alloc
		b.ReportMetric(float64(memoryUsed)/1024/1024, "memory_mb")
		
		// Verify memory usage meets target (< 50MB per sandbox)
		if memoryUsed > 50*1024*1024 {
			b.Errorf("Memory usage %d bytes (%.2f MB) exceeds target of 50MB", 
				memoryUsed, float64(memoryUsed)/1024/1024)
		}
		
		manager.DeleteSandbox(ctx, sb.ID)
		cancel()
	}
}