package performance

import (
	"context"
	"fmt"
	"math/rand"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// LoadTestMetrics tracks metrics during load testing
type LoadTestMetrics struct {
	TotalRequests     int64
	SuccessfulOps     int64
	FailedOps         int64
	TotalResponseTime time.Duration
	MinResponseTime   time.Duration
	MaxResponseTime   time.Duration
	ResponseTimes     []time.Duration
	ErrorRate         float64
	mutex             sync.RWMutex
}

// AddResult records a load test result
func (m *LoadTestMetrics) AddResult(duration time.Duration, success bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	atomic.AddInt64(&m.TotalRequests, 1)
	m.TotalResponseTime += duration
	m.ResponseTimes = append(m.ResponseTimes, duration)
	
	if m.MinResponseTime == 0 || duration < m.MinResponseTime {
		m.MinResponseTime = duration
	}
	if duration > m.MaxResponseTime {
		m.MaxResponseTime = duration
	}
	
	if success {
		atomic.AddInt64(&m.SuccessfulOps, 1)
	} else {
		atomic.AddInt64(&m.FailedOps, 1)
	}
}

// GetStats calculates final statistics
func (m *LoadTestMetrics) GetStats() map[string]interface{} {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	totalRequests := atomic.LoadInt64(&m.TotalRequests)
	successfulOps := atomic.LoadInt64(&m.SuccessfulOps)
	failedOps := atomic.LoadInt64(&m.FailedOps)
	
	var avgResponseTime time.Duration
	if totalRequests > 0 {
		avgResponseTime = m.TotalResponseTime / time.Duration(totalRequests)
	}
	
	errorRate := float64(failedOps) / float64(totalRequests) * 100
	
	// Calculate percentiles
	var p50, p95, p99 time.Duration
	if len(m.ResponseTimes) > 0 {
		// Simple sort for percentile calculation
		sortedTimes := make([]time.Duration, len(m.ResponseTimes))
		copy(sortedTimes, m.ResponseTimes)
		
		for i := 0; i < len(sortedTimes)-1; i++ {
			for j := i + 1; j < len(sortedTimes); j++ {
				if sortedTimes[i] > sortedTimes[j] {
					sortedTimes[i], sortedTimes[j] = sortedTimes[j], sortedTimes[i]
				}
			}
		}
		
		p50 = sortedTimes[len(sortedTimes)*50/100]
		p95 = sortedTimes[len(sortedTimes)*95/100]
		p99 = sortedTimes[len(sortedTimes)*99/100]
	}
	
	return map[string]interface{}{
		"total_requests":      totalRequests,
		"successful_ops":      successfulOps,
		"failed_ops":          failedOps,
		"error_rate_percent":  errorRate,
		"avg_response_time":   avgResponseTime,
		"min_response_time":   m.MinResponseTime,
		"max_response_time":   m.MaxResponseTime,
		"p50_response_time":   p50,
		"p95_response_time":   p95,
		"p99_response_time":   p99,
		"throughput_rps":      float64(totalRequests) / float64(m.TotalResponseTime.Seconds()),
	}
}

// TestSustainedHighLoad tests system under sustained high load
func TestSustainedHighLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sustained load test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	testCases := []struct {
		name           string
		concurrency    int
		duration       time.Duration
		maxErrorRate   float64
		targetThroughput float64 // requests per second
	}{
		{
			name:           "moderate_load",
			concurrency:    10,
			duration:       30 * time.Second,
			maxErrorRate:   5.0,  // 5% error rate max
			targetThroughput: 50, // 50 RPS
		},
		{
			name:           "high_load",
			concurrency:    50,
			duration:       60 * time.Second,
			maxErrorRate:   10.0, // 10% error rate max
			targetThroughput: 200, // 200 RPS
		},
		{
			name:           "extreme_load",
			concurrency:    100,
			duration:       30 * time.Second,
			maxErrorRate:   15.0,  // 15% error rate max
			targetThroughput: 300, // 300 RPS
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := &LoadTestMetrics{}
			
			ctx, cancel := context.WithTimeout(context.Background(), tc.duration+30*time.Second)
			defer cancel()
			
			var wg sync.WaitGroup
			stopChan := make(chan struct{})
			
			// Start load generators
			for i := 0; i < tc.concurrency; i++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()
					loadWorker(ctx, manager, metrics, stopChan, workerID)
				}(i)
			}
			
			// Run for specified duration
			time.Sleep(tc.duration)
			close(stopChan)
			wg.Wait()
			
			// Analyze results
			stats := metrics.GetStats()
			t.Logf("Load Test Results for %s:", tc.name)
			for key, value := range stats {
				t.Logf("  %s: %v", key, value)
			}
			
			// Validate requirements
			errorRate := stats["error_rate_percent"].(float64)
			if errorRate > tc.maxErrorRate {
				t.Errorf("Error rate %.2f%% exceeds maximum %.2f%%", errorRate, tc.maxErrorRate)
			}
			
			throughput := stats["throughput_rps"].(float64)
			if throughput < tc.targetThroughput {
				t.Errorf("Throughput %.2f RPS below target %.2f RPS", throughput, tc.targetThroughput)
			}
			
			// Validate p99 response time
			p99 := stats["p99_response_time"].(time.Duration)
			if p99 > 200*time.Millisecond {
				t.Errorf("P99 response time %v exceeds 200ms target", p99)
			}
		})
	}
}

// loadWorker simulates realistic user behavior
func loadWorker(ctx context.Context, manager *sandbox.Manager, metrics *LoadTestMetrics, stopChan <-chan struct{}, workerID int) {
	// Create a worker-specific sandbox
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
		return
	}
	defer manager.DeleteSandbox(ctx, sb.ID)
	
	// Operation mix mimicking real usage patterns
	operations := []struct {
		name   string
		weight int
		op     func() error
	}{
		{"exec_command", 40, func() error {
			return executeCommand(ctx, manager, sb.ID, "echo", []string{"test"})
		}},
		{"write_file", 25, func() error {
			return writeFile(ctx, manager, sb.ID, fmt.Sprintf("/workspace/worker_%d_%d.txt", workerID, rand.Int()))
		}},
		{"read_file", 20, func() error {
			return readFile(ctx, manager, sb.ID, fmt.Sprintf("/workspace/worker_%d_%d.txt", workerID, rand.Int()))
		}},
		{"list_files", 10, func() error {
			return listFiles(ctx, manager, sb.ID, "/workspace")
		}},
		{"run_code", 5, func() error {
			return runPythonCode(ctx, manager, sb.ID, "print('Hello from worker')")
		}},
	}
	
	// Build weighted operation selector
	var weightedOps []func() error
	for _, op := range operations {
		for i := 0; i < op.weight; i++ {
			weightedOps = append(weightedOps, op.op)
		}
	}

	for {
		select {
		case <-stopChan:
			return
		case <-ctx.Done():
			return
		default:
			// Select random operation
			operation := weightedOps[rand.Intn(len(weightedOps))]
			
			start := time.Now()
			err := operation()
			duration := time.Since(start)
			
			metrics.AddResult(duration, err == nil)
			
			// Small random delay to simulate realistic usage
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)
		}
	}
}

// TestBurstTrafficPatterns tests handling of traffic bursts
func TestBurstTrafficPatterns(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping burst traffic test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	testPatterns := []struct {
		name           string
		burstSize      int
		burstDuration  time.Duration
		restDuration   time.Duration
		numBursts      int
		maxErrorRate   float64
	}{
		{
			name:          "small_bursts",
			burstSize:     20,
			burstDuration: 5 * time.Second,
			restDuration:  5 * time.Second,
			numBursts:     5,
			maxErrorRate:  5.0,
		},
		{
			name:          "large_bursts",
			burstSize:     100,
			burstDuration: 10 * time.Second,
			restDuration:  10 * time.Second,
			numBursts:     3,
			maxErrorRate:  10.0,
		},
	}

	for _, pattern := range testPatterns {
		t.Run(pattern.name, func(t *testing.T) {
			metrics := &LoadTestMetrics{}
			
			for burst := 0; burst < pattern.numBursts; burst++ {
				t.Logf("Starting burst %d/%d", burst+1, pattern.numBursts)
				
				ctx, cancel := context.WithTimeout(context.Background(), pattern.burstDuration+10*time.Second)
				
				var wg sync.WaitGroup
				stopChan := make(chan struct{})
				
				// Launch burst workers
				for i := 0; i < pattern.burstSize; i++ {
					wg.Add(1)
					go func(workerID int) {
						defer wg.Done()
						burstWorker(ctx, manager, metrics, stopChan, workerID)
					}(i)
				}
				
				// Run burst for specified duration
				time.Sleep(pattern.burstDuration)
				close(stopChan)
				wg.Wait()
				cancel()
				
				// Rest period between bursts
				if burst < pattern.numBursts-1 {
					t.Logf("Resting for %v", pattern.restDuration)
					time.Sleep(pattern.restDuration)
				}
			}
			
			// Analyze burst test results
			stats := metrics.GetStats()
			t.Logf("Burst Test Results for %s:", pattern.name)
			for key, value := range stats {
				t.Logf("  %s: %v", key, value)
			}
			
			errorRate := stats["error_rate_percent"].(float64)
			if errorRate > pattern.maxErrorRate {
				t.Errorf("Error rate %.2f%% exceeds maximum %.2f%%", errorRate, pattern.maxErrorRate)
			}
		})
	}
}

// burstWorker performs intensive operations during burst periods
func burstWorker(ctx context.Context, manager *sandbox.Manager, metrics *LoadTestMetrics, stopChan <-chan struct{}, workerID int) {
	// Rapid-fire operations during burst
	for {
		select {
		case <-stopChan:
			return
		case <-ctx.Done():
			return
		default:
			start := time.Now()
			
			// Quick sandbox lifecycle test
			sandboxConfig := sandbox.SandboxConfig{
				Image:        "ubuntu:22.04",
				WorkspaceDir: "/workspace",
				Resources: sandbox.ResourceLimits{
					CPULimit:    "0.1",
					MemoryLimit: "32m",
				},
			}
			
			sb, err := manager.CreateSandbox(ctx, sandboxConfig)
			success := err == nil
			
			if success {
				manager.DeleteSandbox(ctx, sb.ID)
			}
			
			duration := time.Since(start)
			metrics.AddResult(duration, success)
		}
	}
}

// TestMemoryPressure tests system behavior under memory pressure
func TestMemoryPressure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory pressure test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	testCases := []struct {
		name           string
		numSandboxes   int
		memoryPerSB    string
		maxErrorRate   float64
	}{
		{"moderate_memory", 20, "64m", 5.0},
		{"high_memory", 50, "128m", 10.0},
		{"extreme_memory", 100, "256m", 15.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			var sandboxes []*sandbox.Sandbox
			successCount := 0
			
			// Create sandboxes until we hit limits
			for i := 0; i < tc.numSandboxes; i++ {
				sandboxConfig := sandbox.SandboxConfig{
					Image:        "ubuntu:22.04",
					WorkspaceDir: "/workspace",
					Resources: sandbox.ResourceLimits{
						CPULimit:    "0.1",
						MemoryLimit: tc.memoryPerSB,
					},
				}
				
				sb, err := manager.CreateSandbox(ctx, sandboxConfig)
				if err != nil {
					t.Logf("Failed to create sandbox %d: %v", i+1, err)
					break
				}
				
				sandboxes = append(sandboxes, sb)
				successCount++
			}
			
			t.Logf("Successfully created %d/%d sandboxes", successCount, tc.numSandboxes)
			
			errorRate := float64(tc.numSandboxes-successCount) / float64(tc.numSandboxes) * 100
			if errorRate > tc.maxErrorRate {
				t.Errorf("Error rate %.2f%% exceeds maximum %.2f%%", errorRate, tc.maxErrorRate)
			}
			
			// Test that existing sandboxes still work
			workingSandboxes := 0
			for _, sb := range sandboxes {
				if err := executeCommand(ctx, manager, sb.ID, "echo", []string{"test"}); err == nil {
					workingSandboxes++
				}
			}
			
			t.Logf("Working sandboxes: %d/%d", workingSandboxes, len(sandboxes))
			
			// Cleanup
			for _, sb := range sandboxes {
				manager.DeleteSandbox(ctx, sb.ID)
			}
		})
	}
}

// TestResourceExhaustionRecovery tests recovery from resource exhaustion
func TestResourceExhaustionRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resource exhaustion test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Phase 1: Exhaust resources
	t.Log("Phase 1: Exhausting system resources")
	var sandboxes []*sandbox.Sandbox
	
	for i := 0; i < 200; i++ { // Try to create way more than should be possible
		sandboxConfig := sandbox.SandboxConfig{
			Image:        "ubuntu:22.04",
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "0.1",
				MemoryLimit: "128m",
			},
		}
		
		sb, err := manager.CreateSandbox(ctx, sandboxConfig)
		if err != nil {
			t.Logf("Resource exhaustion reached at %d sandboxes: %v", i, err)
			break
		}
		sandboxes = append(sandboxes, sb)
		
		if i%10 == 0 {
			t.Logf("Created %d sandboxes", i+1)
		}
	}
	
	exhaustedCount := len(sandboxes)
	t.Logf("Total sandboxes at exhaustion: %d", exhaustedCount)
	
	// Phase 2: Cleanup half the sandboxes
	t.Log("Phase 2: Cleaning up half the sandboxes")
	cleanupCount := exhaustedCount / 2
	for i := 0; i < cleanupCount; i++ {
		if i < len(sandboxes) {
			manager.DeleteSandbox(ctx, sandboxes[i].ID)
		}
	}
	
	// Remove cleaned up sandboxes from slice
	sandboxes = sandboxes[cleanupCount:]
	
	// Phase 3: Test recovery by creating new sandboxes
	t.Log("Phase 3: Testing recovery")
	recoveryCount := 0
	for i := 0; i < cleanupCount; i++ {
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
			t.Logf("Recovery failed at %d new sandboxes: %v", i, err)
			break
		}
		
		sandboxes = append(sandboxes, sb)
		recoveryCount++
	}
	
	t.Logf("Recovery: created %d new sandboxes", recoveryCount)
	
	// Test that system is functional
	functionalCount := 0
	for _, sb := range sandboxes {
		if err := executeCommand(ctx, manager, sb.ID, "echo", []string{"recovery test"}); err == nil {
			functionalCount++
		}
	}
	
	t.Logf("Functional sandboxes after recovery: %d/%d", functionalCount, len(sandboxes))
	
	// Verify recovery effectiveness
	recoveryRate := float64(recoveryCount) / float64(cleanupCount) * 100
	if recoveryRate < 80.0 {
		t.Errorf("Recovery rate %.2f%% below expected 80%%", recoveryRate)
	}
	
	// Cleanup all remaining sandboxes
	for _, sb := range sandboxes {
		manager.DeleteSandbox(ctx, sb.ID)
	}
}

// TestLongRunningOperations tests system stability with long-running operations
func TestLongRunningOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long running operations test in short mode")
	}

	config := setupBenchmark(&testing.B{})
	manager := createTestManager(&testing.B{}, config)
	defer manager.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Create a sandbox for long-running operations
	sandboxConfig := sandbox.SandboxConfig{
		Image:        "ubuntu:22.04",
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "0.5",
			MemoryLimit: "256m",
		},
	}
	
	sb, err := manager.CreateSandbox(ctx, sandboxConfig)
	if err != nil {
		t.Fatalf("Failed to create sandbox: %v", err)
	}
	defer manager.DeleteSandbox(ctx, sb.ID)

	longRunningOperations := []struct {
		name     string
		duration time.Duration
		command  string
		args     []string
	}{
		{"cpu_intensive", 2 * time.Minute, "yes", []string{">", "/dev/null"}},
		{"memory_write", 1 * time.Minute, "dd", []string{"if=/dev/zero", "of=/workspace/largefile", "bs=1M", "count=100"}},
		{"file_operations", 3 * time.Minute, "find", []string{"/", "-name", "*.txt", "-type", "f"}},
	}

	for _, op := range longRunningOperations {
		t.Run(op.name, func(t *testing.T) {
			opCtx, opCancel := context.WithTimeout(ctx, op.duration+30*time.Second)
			defer opCancel()
			
			start := time.Now()
			err := executeCommand(opCtx, manager, sb.ID, op.command, op.args)
			duration := time.Since(start)
			
			t.Logf("Operation %s took %v", op.name, duration)
			
			if err != nil && duration < op.duration-10*time.Second {
				t.Errorf("Long-running operation %s failed prematurely: %v", op.name, err)
			}
			
			// Test that sandbox is still responsive
			if err := executeCommand(ctx, manager, sb.ID, "echo", []string{"responsive"}); err != nil {
				t.Errorf("Sandbox became unresponsive after %s operation: %v", op.name, err)
			}
		})
	}
}

// Helper functions for load testing

func executeCommand(ctx context.Context, manager *sandbox.Manager, sandboxID, command string, args []string) error {
	tool := tools.NewExecCommandTool(manager)
	
	params := map[string]interface{}{
		"sandbox_id": sandboxID,
		"command":    command,
		"args":       args,
	}
	
	_, err := tool.Execute(ctx, params)
	return err
}

func writeFile(ctx context.Context, manager *sandbox.Manager, sandboxID, filePath string) error {
	tool := tools.NewWriteFileTool(manager)
	
	params := map[string]interface{}{
		"sandbox_id": sandboxID,
		"file_path":  filePath,
		"content":    fmt.Sprintf("Test content written at %v", time.Now()),
	}
	
	_, err := tool.Execute(ctx, params)
	return err
}

func readFile(ctx context.Context, manager *sandbox.Manager, sandboxID, filePath string) error {
	tool := tools.NewReadFileTool(manager)
	
	params := map[string]interface{}{
		"sandbox_id": sandboxID,
		"file_path":  filePath,
	}
	
	_, err := tool.Execute(ctx, params)
	return err
}

func listFiles(ctx context.Context, manager *sandbox.Manager, sandboxID, path string) error {
	tool := tools.NewListFilesTool(manager)
	
	params := map[string]interface{}{
		"sandbox_id": sandboxID,
		"path":       path,
	}
	
	_, err := tool.Execute(ctx, params)
	return err
}

func runPythonCode(ctx context.Context, manager *sandbox.Manager, sandboxID, code string) error {
	tool := tools.NewRunCodeTool(manager, nil)
	
	params := map[string]interface{}{
		"sandbox_id": sandboxID,
		"code":       code,
	}
	
	_, err := tool.Execute(ctx, params)
	return err
}