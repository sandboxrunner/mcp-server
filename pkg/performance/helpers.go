package performance

import (
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
)

// TestEnvironment provides a managed test environment for performance tests
type TestEnvironment struct {
	Config  *Config
	Manager *sandbox.Manager
	TempDir string
	mutex   sync.RWMutex
}

// NewTestEnvironment creates a new test environment
func NewTestEnvironment(t *testing.T, config *Config) (*TestEnvironment, error) {
	if config == nil {
		var err error
		config, err = LoadConfig("")
		if err != nil {
			// Fall back to default config
			config = DefaultConfig()
		}
	}
	
	// Create temporary directory for this test environment
	tempDir := fmt.Sprintf("%s/perf-test-%d", config.TempDir, time.Now().UnixNano())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	
	// Note: Storage is initialized internally by the sandbox manager
	
	// Note: Runtime is initialized internally by the sandbox manager
	
	// Create manager
	manager, err := sandbox.NewManager(fmt.Sprintf("%s/test.db", tempDir), fmt.Sprintf("%s/workspace", tempDir))
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %w", err)
	}
	
	return &TestEnvironment{
		Config:  config,
		Manager: manager,
		TempDir: tempDir,
	}, nil
}

// Cleanup cleans up the test environment
func (te *TestEnvironment) Cleanup() error {
	te.mutex.Lock()
	defer te.mutex.Unlock()
	
	if te.Manager != nil {
		te.Manager.Close()
	}
	
	// Clean up temp directory
	return os.RemoveAll(te.TempDir)
}

// CreateSandbox creates a test sandbox with default configuration
func (te *TestEnvironment) CreateSandbox(ctx context.Context, options ...SandboxOption) (*sandbox.Sandbox, error) {
	config := sandbox.SandboxConfig{
		Image:        te.Config.ContainerImage,
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    te.Config.DefaultCPULimit,
			MemoryLimit: te.Config.DefaultMemoryLimit,
			DiskLimit:   te.Config.DefaultDiskLimit,
		},
		NetworkMode: te.Config.NetworkMode,
	}
	
	// Apply options
	for _, option := range options {
		option(&config)
	}
	
	return te.Manager.CreateSandbox(ctx, config)
}

// SandboxOption allows customization of sandbox configuration
type SandboxOption func(*sandbox.SandboxConfig)

// WithImage sets the container image
func WithImage(image string) SandboxOption {
	return func(config *sandbox.SandboxConfig) {
		config.Image = image
	}
}

// WithResources sets resource limits
func WithResources(cpu, memory, disk string) SandboxOption {
	return func(config *sandbox.SandboxConfig) {
		config.Resources = sandbox.ResourceLimits{
			CPULimit:    cpu,
			MemoryLimit: memory,
			DiskLimit:   disk,
		}
	}
}

// WithWorkspaceDir sets the workspace directory
func WithWorkspaceDir(dir string) SandboxOption {
	return func(config *sandbox.SandboxConfig) {
		config.WorkspaceDir = dir
	}
}

// WithNetworkMode sets the network mode
func WithNetworkMode(mode string) SandboxOption {
	return func(config *sandbox.SandboxConfig) {
		config.NetworkMode = mode
	}
}

// PerformanceAssertion helps validate performance targets
type PerformanceAssertion struct {
	t       *testing.T
	targets PerformanceTargets
}

// NewPerformanceAssertion creates a new performance assertion helper
func NewPerformanceAssertion(t *testing.T, targets PerformanceTargets) *PerformanceAssertion {
	return &PerformanceAssertion{
		t:       t,
		targets: targets,
	}
}

// AssertContainerStartup validates container startup time
func (pa *PerformanceAssertion) AssertContainerStartup(duration time.Duration) {
	target := time.Duration(pa.targets.ContainerStartupMs) * time.Millisecond
	if duration > target {
		pa.t.Errorf("Container startup time %v exceeds target %v", duration, target)
	}
}

// AssertCommandOverhead validates command execution overhead
func (pa *PerformanceAssertion) AssertCommandOverhead(duration time.Duration) {
	target := time.Duration(pa.targets.CommandOverheadMs) * time.Millisecond
	if duration > target {
		pa.t.Errorf("Command overhead %v exceeds target %v", duration, target)
	}
}

// AssertMemoryUsage validates memory usage per sandbox
func (pa *PerformanceAssertion) AssertMemoryUsage(memoryMB float64) {
	if memoryMB > pa.targets.MemoryPerSandboxMB {
		pa.t.Errorf("Memory usage %.2f MB exceeds target %.2f MB", memoryMB, pa.targets.MemoryPerSandboxMB)
	}
}

// AssertAPIResponseTime validates API response time percentiles
func (pa *PerformanceAssertion) AssertAPIResponseTime(responseTimes []time.Duration) {
	if len(responseTimes) == 0 {
		pa.t.Error("No response times provided")
		return
	}
	
	// Calculate P99
	p99 := calculatePercentile(responseTimes, 99)
	target := time.Duration(pa.targets.APIResponseP99Ms) * time.Millisecond
	
	if p99 > target {
		pa.t.Errorf("P99 response time %v exceeds target %v", p99, target)
	}
}

// AssertThroughput validates throughput requirements
func (pa *PerformanceAssertion) AssertThroughput(rps float64) {
	if rps < pa.targets.ThroughputRPS {
		pa.t.Errorf("Throughput %.2f RPS below target %.2f RPS", rps, pa.targets.ThroughputRPS)
	}
}

// AssertErrorRate validates error rate requirements
func (pa *PerformanceAssertion) AssertErrorRate(errorRate float64) {
	if errorRate > pa.targets.ErrorRatePercent {
		pa.t.Errorf("Error rate %.2f%% exceeds target %.2f%%", errorRate, pa.targets.ErrorRatePercent)
	}
}

// calculatePercentile calculates the nth percentile of a slice of durations
func calculatePercentile(durations []time.Duration, percentile int) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	// Sort durations
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})
	
	// Calculate index
	index := int(math.Ceil(float64(percentile)/100.0*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	
	return sorted[index]
}

// ResourceMonitor monitors system resources during tests
type ResourceMonitor struct {
	interval    time.Duration
	running     bool
	done        chan struct{}
	samples     []ResourceSample
	mutex       sync.RWMutex
}

// ResourceSample represents a resource usage sample
type ResourceSample struct {
	Timestamp   time.Time
	CPUPercent  float64
	MemoryMB    float64
	Goroutines  int
	HeapAllocMB float64
	GCCycles    uint32
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(interval time.Duration) *ResourceMonitor {
	return &ResourceMonitor{
		interval: interval,
		done:     make(chan struct{}),
		samples:  make([]ResourceSample, 0),
	}
}

// Start begins resource monitoring
func (rm *ResourceMonitor) Start() {
	rm.mutex.Lock()
	if rm.running {
		rm.mutex.Unlock()
		return
	}
	rm.running = true
	rm.mutex.Unlock()
	
	go func() {
		ticker := time.NewTicker(rm.interval)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				sample := rm.takeSample()
				rm.mutex.Lock()
				rm.samples = append(rm.samples, sample)
				rm.mutex.Unlock()
			case <-rm.done:
				return
			}
		}
	}()
}

// Stop stops resource monitoring
func (rm *ResourceMonitor) Stop() {
	rm.mutex.Lock()
	if !rm.running {
		rm.mutex.Unlock()
		return
	}
	rm.running = false
	rm.mutex.Unlock()
	
	close(rm.done)
}

// takeSample captures current resource usage
func (rm *ResourceMonitor) takeSample() ResourceSample {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	return ResourceSample{
		Timestamp:   time.Now(),
		CPUPercent:  0.0, // Would need OS-specific implementation
		MemoryMB:    float64(m.Sys) / 1024 / 1024,
		Goroutines:  runtime.NumGoroutine(),
		HeapAllocMB: float64(m.HeapAlloc) / 1024 / 1024,
		GCCycles:    m.NumGC,
	}
}

// GetSamples returns all collected resource samples
func (rm *ResourceMonitor) GetSamples() []ResourceSample {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	
	samples := make([]ResourceSample, len(rm.samples))
	copy(samples, rm.samples)
	return samples
}

// GetSummary returns a summary of resource usage
func (rm *ResourceMonitor) GetSummary() ResourceSummary {
	samples := rm.GetSamples()
	if len(samples) == 0 {
		return ResourceSummary{}
	}
	
	var (
		totalCPU     float64
		totalMemory  float64
		totalHeap    float64
		minMemory    = samples[0].MemoryMB
		maxMemory    = samples[0].MemoryMB
		minHeap      = samples[0].HeapAllocMB
		maxHeap      = samples[0].HeapAllocMB
		minGoroutines = samples[0].Goroutines
		maxGoroutines = samples[0].Goroutines
		gcCycles      = samples[len(samples)-1].GCCycles - samples[0].GCCycles
	)
	
	for _, sample := range samples {
		totalCPU += sample.CPUPercent
		totalMemory += sample.MemoryMB
		totalHeap += sample.HeapAllocMB
		
		if sample.MemoryMB < minMemory {
			minMemory = sample.MemoryMB
		}
		if sample.MemoryMB > maxMemory {
			maxMemory = sample.MemoryMB
		}
		
		if sample.HeapAllocMB < minHeap {
			minHeap = sample.HeapAllocMB
		}
		if sample.HeapAllocMB > maxHeap {
			maxHeap = sample.HeapAllocMB
		}
		
		if sample.Goroutines < minGoroutines {
			minGoroutines = sample.Goroutines
		}
		if sample.Goroutines > maxGoroutines {
			maxGoroutines = sample.Goroutines
		}
	}
	
	duration := samples[len(samples)-1].Timestamp.Sub(samples[0].Timestamp)
	
	return ResourceSummary{
		Duration:        duration,
		Samples:         len(samples),
		AvgCPUPercent:   totalCPU / float64(len(samples)),
		AvgMemoryMB:     totalMemory / float64(len(samples)),
		MinMemoryMB:     minMemory,
		MaxMemoryMB:     maxMemory,
		AvgHeapMB:       totalHeap / float64(len(samples)),
		MinHeapMB:       minHeap,
		MaxHeapMB:       maxHeap,
		MinGoroutines:   minGoroutines,
		MaxGoroutines:   maxGoroutines,
		GCCycles:        gcCycles,
	}
}

// ResourceSummary summarizes resource usage over time
type ResourceSummary struct {
	Duration      time.Duration
	Samples       int
	AvgCPUPercent float64
	AvgMemoryMB   float64
	MinMemoryMB   float64
	MaxMemoryMB   float64
	AvgHeapMB     float64
	MinHeapMB     float64
	MaxHeapMB     float64
	MinGoroutines int
	MaxGoroutines int
	GCCycles      uint32
}

// TestReporter helps generate performance test reports
type TestReporter struct {
	config   *Config
	results  []TestResult
	mutex    sync.RWMutex
}

// TestResult represents the result of a performance test
type TestResult struct {
	TestName        string
	TestType        string
	StartTime       time.Time
	Duration        time.Duration
	Success         bool
	Error           error
	Metrics         map[string]interface{}
	ResourceSummary *ResourceSummary
}

// NewTestReporter creates a new test reporter
func NewTestReporter(config *Config) *TestReporter {
	return &TestReporter{
		config:  config,
		results: make([]TestResult, 0),
	}
}

// RecordResult records a test result
func (tr *TestReporter) RecordResult(result TestResult) {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()
	tr.results = append(tr.results, result)
}

// GenerateReport generates a performance test report
func (tr *TestReporter) GenerateReport() string {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()
	
	report := fmt.Sprintf("Performance Test Report\n")
	report += fmt.Sprintf("=====================\n\n")
	report += fmt.Sprintf("Configuration:\n")
	report += fmt.Sprintf("  Container Image: %s\n", tr.config.ContainerImage)
	report += fmt.Sprintf("  Performance Targets:\n")
	report += fmt.Sprintf("    Container Startup: < %d ms\n", tr.config.Targets.ContainerStartupMs)
	report += fmt.Sprintf("    Command Overhead: < %d ms\n", tr.config.Targets.CommandOverheadMs)
	report += fmt.Sprintf("    Memory per Sandbox: < %.1f MB\n", tr.config.Targets.MemoryPerSandboxMB)
	report += fmt.Sprintf("    Max Concurrent Sandboxes: %d\n", tr.config.Targets.MaxConcurrentSandboxes)
	report += fmt.Sprintf("    API Response P99: < %d ms\n", tr.config.Targets.APIResponseP99Ms)
	report += fmt.Sprintf("    Throughput: > %.1f RPS\n", tr.config.Targets.ThroughputRPS)
	report += fmt.Sprintf("    Error Rate: < %.1f%%\n\n", tr.config.Targets.ErrorRatePercent)
	
	// Group results by test type
	typeGroups := make(map[string][]TestResult)
	for _, result := range tr.results {
		typeGroups[result.TestType] = append(typeGroups[result.TestType], result)
	}
	
	for testType, results := range typeGroups {
		report += fmt.Sprintf("%s Tests:\n", testType)
		report += fmt.Sprintf("----------\n")
		
		successCount := 0
		totalDuration := time.Duration(0)
		
		for _, result := range results {
			status := "PASS"
			if !result.Success {
				status = "FAIL"
			} else {
				successCount++
			}
			
			totalDuration += result.Duration
			report += fmt.Sprintf("  %s: %s (%v)\n", result.TestName, status, result.Duration)
			
			if result.Error != nil {
				report += fmt.Sprintf("    Error: %v\n", result.Error)
			}
			
			// Add metrics if available
			if len(result.Metrics) > 0 {
				for key, value := range result.Metrics {
					report += fmt.Sprintf("    %s: %v\n", key, value)
				}
			}
		}
		
		successRate := float64(successCount) / float64(len(results)) * 100
		avgDuration := totalDuration / time.Duration(len(results))
		
		report += fmt.Sprintf("  Summary: %d/%d tests passed (%.1f%%), avg duration: %v\n\n",
			successCount, len(results), successRate, avgDuration)
	}
	
	return report
}

// SaveReport saves the performance test report to a file
func (tr *TestReporter) SaveReport(filename string) error {
	report := tr.GenerateReport()
	filepath := tr.config.GetOutputPath(filename)
	
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()
	
	_, err = file.WriteString(report)
	return err
}

// SkipIfShort skips a test if testing.Short() is true
func SkipIfShort(t *testing.T, reason string) {
	if testing.Short() {
		if reason == "" {
			reason = "test requires long execution time"
		}
		t.Skipf("Skipping test in short mode: %s", reason)
	}
}

// SkipIfCI skips a test if running in CI environment
func SkipIfCI(t *testing.T, reason string) {
	if os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" {
		if reason == "" {
			reason = "test requires local resources"
		}
		t.Skipf("Skipping test in CI: %s", reason)
	}
}

// WaitForCondition waits for a condition to be met with timeout
func WaitForCondition(condition func() bool, timeout time.Duration, interval time.Duration) error {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		if condition() {
			return nil
		}
		time.Sleep(interval)
	}
	
	return fmt.Errorf("condition not met within timeout %v", timeout)
}