package benchmarks

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/beam-cloud/go-runc"

	"github.com/sandboxrunner/mcp-server/pkg/cache"
	runtimePkg "github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// PerformanceBenchmarks provides comprehensive performance analysis for all components
type PerformanceBenchmarks struct {
	config *BenchmarkConfig
	results map[string]*BenchmarkResult
	mu     sync.RWMutex
}

// BenchmarkConfig contains configuration for performance benchmarks
type BenchmarkConfig struct {
	Duration      time.Duration `json:"duration"`       // Benchmark duration
	Concurrency   int           `json:"concurrency"`    // Number of concurrent goroutines
	Iterations    int           `json:"iterations"`     // Number of iterations per benchmark
	WarmupTime    time.Duration `json:"warmup_time"`    // Warmup time before measurements
	Profiling     bool          `json:"profiling"`      // Enable profiling data collection
	ReportFormat  string        `json:"report_format"`  // Output format (json, csv, text)
}

// BenchmarkResult contains the results of a performance benchmark
type BenchmarkResult struct {
	Name              string        `json:"name"`
	Duration          time.Duration `json:"duration"`
	Operations        int64         `json:"operations"`
	OperationsPerSec  float64       `json:"operations_per_sec"`
	AverageLatency    time.Duration `json:"average_latency"`
	MinLatency        time.Duration `json:"min_latency"`
	MaxLatency        time.Duration `json:"max_latency"`
	P50Latency        time.Duration `json:"p50_latency"`
	P95Latency        time.Duration `json:"p95_latency"`
	P99Latency        time.Duration `json:"p99_latency"`
	ThroughputMBps    float64       `json:"throughput_mbps"`
	MemoryUsageBytes  int64         `json:"memory_usage_bytes"`
	AllocationsCount  int64         `json:"allocations_count"`
	GCPauses          int64         `json:"gc_pauses"`
	CPUUtilization    float64       `json:"cpu_utilization"`
	ErrorRate         float64       `json:"error_rate"`
	Timestamp         time.Time     `json:"timestamp"`
}

// PerformanceReport contains comprehensive performance analysis
type PerformanceReport struct {
	Summary      *BenchmarkSummary            `json:"summary"`
	Components   map[string]*ComponentMetrics `json:"components"`
	Comparisons  []*ComponentComparison       `json:"comparisons"`
	Bottlenecks  []*BottleneckAnalysis        `json:"bottlenecks"`
	Recommendations []*OptimizationRecommendation `json:"recommendations"`
	Timestamp    time.Time                    `json:"timestamp"`
}

// BenchmarkSummary provides overall performance summary
type BenchmarkSummary struct {
	TotalDuration        time.Duration `json:"total_duration"`
	TotalOperations      int64         `json:"total_operations"`
	OverallThroughput    float64       `json:"overall_throughput"`
	AverageLatency       time.Duration `json:"average_latency"`
	PeakMemoryUsage      int64         `json:"peak_memory_usage"`
	TotalGCPauses        int64         `json:"total_gc_pauses"`
	OverallCPUUtil       float64       `json:"overall_cpu_util"`
	ComponentCount       int           `json:"component_count"`
}

// ComponentMetrics contains performance metrics for a specific component
type ComponentMetrics struct {
	ComponentName     string                   `json:"component_name"`
	BenchmarkResults  []*BenchmarkResult       `json:"benchmark_results"`
	AverageLatency    time.Duration            `json:"average_latency"`
	Throughput        float64                  `json:"throughput"`
	ResourceUsage     *ResourceUsageMetrics    `json:"resource_usage"`
	ScalabilityMetrics *ScalabilityMetrics     `json:"scalability_metrics"`
	PerformanceGrade  string                   `json:"performance_grade"`
}

// ResourceUsageMetrics tracks resource consumption
type ResourceUsageMetrics struct {
	PeakMemoryMB     float64 `json:"peak_memory_mb"`
	AvgMemoryMB      float64 `json:"avg_memory_mb"`
	CPUTimeSeconds   float64 `json:"cpu_time_seconds"`
	GoroutineCount   int     `json:"goroutine_count"`
	AllocationsRate  float64 `json:"allocations_rate"`
	GCPressure       float64 `json:"gc_pressure"`
}

// ScalabilityMetrics measures how components scale with load
type ScalabilityMetrics struct {
	LinearScaleFactor    float64 `json:"linear_scale_factor"`    // How linearly does it scale
	SaturationPoint      int     `json:"saturation_point"`       // At what concurrency does it saturate
	EfficiencyAtScale    float64 `json:"efficiency_at_scale"`    // Efficiency at high concurrency
	BottleneckFactor     float64 `json:"bottleneck_factor"`      // Degree of bottleneck
}

// ComponentComparison compares performance between components
type ComponentComparison struct {
	ComponentA       string  `json:"component_a"`
	ComponentB       string  `json:"component_b"`
	ThroughputRatio  float64 `json:"throughput_ratio"`  // A/B ratio
	LatencyRatio     float64 `json:"latency_ratio"`     // A/B ratio
	MemoryRatio      float64 `json:"memory_ratio"`      // A/B ratio
	Winner           string  `json:"winner"`            // Which is better overall
	Recommendation   string  `json:"recommendation"`    // When to use which
}

// BottleneckAnalysis identifies performance bottlenecks
type BottleneckAnalysis struct {
	ComponentName    string                 `json:"component_name"`
	BottleneckType   string                 `json:"bottleneck_type"`   // CPU, Memory, IO, Contention
	SeverityLevel    string                 `json:"severity_level"`    // Low, Medium, High, Critical
	Description      string                 `json:"description"`
	ImpactMetrics    map[string]float64     `json:"impact_metrics"`
	RootCauses       []string               `json:"root_causes"`
	DetectionMethod  string                 `json:"detection_method"`
}

// OptimizationRecommendation provides actionable optimization advice
type OptimizationRecommendation struct {
	ComponentName      string    `json:"component_name"`
	RecommendationType string    `json:"recommendation_type"` // Configuration, Algorithm, Architecture
	Priority           string    `json:"priority"`            // Low, Medium, High, Critical
	Title              string    `json:"title"`
	Description        string    `json:"description"`
	ExpectedImpact     string    `json:"expected_impact"`     // Performance improvement description
	Implementation     string    `json:"implementation"`      // How to implement
	RiskLevel          string    `json:"risk_level"`          // Low, Medium, High
	EffortEstimate     string    `json:"effort_estimate"`     // Time/complexity estimate
}

// NewPerformanceBenchmarks creates a new performance benchmark suite
func NewPerformanceBenchmarks(config *BenchmarkConfig) *PerformanceBenchmarks {
	if config == nil {
		config = &BenchmarkConfig{
			Duration:     30 * time.Second,
			Concurrency:  runtime.NumCPU(),
			Iterations:   10000,
			WarmupTime:   5 * time.Second,
			Profiling:    true,
			ReportFormat: "json",
		}
	}
	
	return &PerformanceBenchmarks{
		config:  config,
		results: make(map[string]*BenchmarkResult),
	}
}

// RunComprehensiveAnalysis runs all performance benchmarks and generates a report
func (pb *PerformanceBenchmarks) RunComprehensiveAnalysis() (*PerformanceReport, error) {
	fmt.Println("Starting comprehensive performance analysis...")
	startTime := time.Now()
	
	// Run benchmarks for all components
	results := make(map[string]*BenchmarkResult)
	
	// Connection Pool Benchmarks
	if poolResult, err := pb.BenchmarkConnectionPool(); err == nil {
		results["connection_pool"] = poolResult
	}
	
	// Multi-Level Cache Benchmarks
	if cacheResult, err := pb.BenchmarkMultiLevelCache(); err == nil {
		results["multi_level_cache"] = cacheResult
	}
	
	// Batch Processing Benchmarks
	if batchResult, err := pb.BenchmarkBatchProcessor(); err == nil {
		results["batch_processor"] = batchResult
	}
	
	// Concurrent Execution Benchmarks
	if concurrentResult, err := pb.BenchmarkConcurrentExecutor(); err == nil {
		results["concurrent_executor"] = concurrentResult
	}
	
	// Store results
	pb.mu.Lock()
	pb.results = results
	pb.mu.Unlock()
	
	// Generate comprehensive report
	report := pb.generatePerformanceReport()
	
	fmt.Printf("Performance analysis completed in %v\n", time.Since(startTime))
	return report, nil
}

// BenchmarkConnectionPool performs comprehensive connection pool benchmarks
func (pb *PerformanceBenchmarks) BenchmarkConnectionPool() (*BenchmarkResult, error) {
	fmt.Println("Benchmarking Connection Pool...")
	
	config := runtimePkg.DefaultPoolConfig()
	config.MaxSize = pb.config.Concurrency * 2
	config.MinSize = pb.config.Concurrency
	
	// Create a mock connection factory for testing
	factory := func(ctx context.Context) (runtimePkg.RuncInterface, error) {
		return &MockRuncForBench{}, nil
	}
	
	pool, err := runtimePkg.NewConnectionPool(config, factory)
	if err != nil {
		return nil, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()
	
	// Warmup
	pb.warmupConnectionPool(pool)
	
	// Benchmark metrics
	var operations int64
	var totalLatency time.Duration
	var latencies []time.Duration
	var mu sync.Mutex
	
	startTime := time.Now()
	endTime := startTime.Add(pb.config.Duration)
	
	// Memory stats before
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	
	// Run concurrent benchmark
	var wg sync.WaitGroup
	for i := 0; i < pb.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			ctx := context.Background()
			for time.Now().Before(endTime) {
				start := time.Now()
				
				conn, err := pool.Get(ctx)
				if err != nil {
					continue
				}
				
				// Simulate work
				time.Sleep(time.Microsecond)
				
				err = pool.Put(conn)
				if err != nil {
					continue
				}
				
				latency := time.Since(start)
				
				atomic.AddInt64(&operations, 1)
				mu.Lock()
				totalLatency += latency
				latencies = append(latencies, latency)
				mu.Unlock()
			}
		}()
	}
	
	wg.Wait()
	actualDuration := time.Since(startTime)
	
	// Memory stats after
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	
	return pb.calculateBenchmarkResult("connection_pool", operations, actualDuration, 
		latencies, &memBefore, &memAfter), nil
}

// BenchmarkMultiLevelCache performs comprehensive cache benchmarks
func (pb *PerformanceBenchmarks) BenchmarkMultiLevelCache() (*BenchmarkResult, error) {
	fmt.Println("Benchmarking Multi-Level Cache...")
	
	config := cache.DefaultCacheConfig()
	config.L1Config.MaxSize = 50 * 1024 * 1024 // 50MB
	config.L2Config.Enabled = false            // Disable L2/L3 for cleaner benchmark
	config.L3Config.Enabled = false
	
	mlCache, err := cache.NewMultiLevelCache(config)
	if err != nil {
		return nil, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		mlCache.Close(ctx)
	}()
	
	// Benchmark metrics
	var operations int64
	var totalLatency time.Duration
	var latencies []time.Duration
	var mu sync.Mutex
	
	startTime := time.Now()
	endTime := startTime.Add(pb.config.Duration)
	
	// Memory stats before
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	
	// Run concurrent benchmark
	var wg sync.WaitGroup
	ctx := context.Background()
	
	for i := 0; i < pb.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for time.Now().Before(endTime) {
				start := time.Now()
				key := fmt.Sprintf("bench_key_%d_%d", workerID, time.Now().UnixNano()%1000)
				value := fmt.Sprintf("bench_value_%d", workerID)
				
				// Mix of set and get operations
				if time.Now().UnixNano()%2 == 0 {
					mlCache.Set(ctx, key, value, time.Minute)
				} else {
					mlCache.Get(ctx, key)
				}
				
				latency := time.Since(start)
				
				atomic.AddInt64(&operations, 1)
				mu.Lock()
				totalLatency += latency
				latencies = append(latencies, latency)
				mu.Unlock()
			}
		}(i)
	}
	
	wg.Wait()
	actualDuration := time.Since(startTime)
	
	// Memory stats after
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	
	return pb.calculateBenchmarkResult("multi_level_cache", operations, actualDuration,
		latencies, &memBefore, &memAfter), nil
}

// BenchmarkBatchProcessor performs comprehensive batch processing benchmarks
func (pb *PerformanceBenchmarks) BenchmarkBatchProcessor() (*BenchmarkResult, error) {
	fmt.Println("Benchmarking Batch Processor...")
	
	config := tools.DefaultBatchConfig()
	config.MaxWorkers = pb.config.Concurrency * 2
	config.MinWorkers = pb.config.Concurrency
	config.MetricsEnabled = false // Disable for cleaner benchmark
	
	processor, err := tools.NewBatchProcessor(config)
	if err != nil {
		return nil, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()
	
	// Benchmark metrics
	var operations int64
	var totalLatency time.Duration
	var latencies []time.Duration
	var mu sync.Mutex
	
	startTime := time.Now()
	endTime := startTime.Add(pb.config.Duration)
	
	// Memory stats before
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	
	// Run concurrent benchmark
	var wg sync.WaitGroup
	ctx := context.Background()
	
	for i := 0; i < pb.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for time.Now().Before(endTime) {
				start := time.Now()
				
				request := &tools.BatchRequest{
					ID:       fmt.Sprintf("bench_req_%d_%d", workerID, time.Now().UnixNano()),
					Type:     tools.BatchTypeCommand,
					Priority: 5,
					Payload:  "benchmark_command",
					Timeout:  5 * time.Second,
				}
				
				_, err := processor.Submit(ctx, request)
				if err != nil {
					continue
				}
				
				latency := time.Since(start)
				
				atomic.AddInt64(&operations, 1)
				mu.Lock()
				totalLatency += latency
				latencies = append(latencies, latency)
				mu.Unlock()
			}
		}(i)
	}
	
	wg.Wait()
	actualDuration := time.Since(startTime)
	
	// Memory stats after
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	
	return pb.calculateBenchmarkResult("batch_processor", operations, actualDuration,
		latencies, &memBefore, &memAfter), nil
}

// BenchmarkConcurrentExecutor performs comprehensive concurrent execution benchmarks
func (pb *PerformanceBenchmarks) BenchmarkConcurrentExecutor() (*BenchmarkResult, error) {
	fmt.Println("Benchmarking Concurrent Executor...")
	
	config := runtimePkg.DefaultExecutorConfig()
	config.MaxWorkers = pb.config.Concurrency * 2
	config.MinWorkers = pb.config.Concurrency
	config.MetricsEnabled = false // Disable for cleaner benchmark
	
	executor, err := runtimePkg.NewConcurrentExecutor(config)
	if err != nil {
		return nil, err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()
	
	// Benchmark metrics
	var operations int64
	var totalLatency time.Duration
	var latencies []time.Duration
	var mu sync.Mutex
	
	startTime := time.Now()
	endTime := startTime.Add(pb.config.Duration)
	
	// Memory stats before
	var memBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	
	// Run concurrent benchmark
	var wg sync.WaitGroup
	ctx := context.Background()
	
	for i := 0; i < pb.config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for time.Now().Before(endTime) {
				start := time.Now()
				
				task := runtimePkg.NewSimpleTask(
					fmt.Sprintf("bench_task_%d_%d", workerID, time.Now().UnixNano()),
					func(ctx context.Context) (interface{}, error) {
						// Minimal work to focus on concurrency overhead
						return "benchmark_result", nil
					},
				)
				
				_, err := executor.Execute(ctx, task)
				if err != nil {
					continue
				}
				
				latency := time.Since(start)
				
				atomic.AddInt64(&operations, 1)
				mu.Lock()
				totalLatency += latency
				latencies = append(latencies, latency)
				mu.Unlock()
			}
		}(i)
	}
	
	wg.Wait()
	actualDuration := time.Since(startTime)
	
	// Memory stats after
	var memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memAfter)
	
	return pb.calculateBenchmarkResult("concurrent_executor", operations, actualDuration,
		latencies, &memBefore, &memAfter), nil
}

// Helper methods

func (pb *PerformanceBenchmarks) warmupConnectionPool(pool runtimePkg.ConnectionPool) {
	fmt.Print("  Warming up connection pool...")
	ctx := context.Background()
	
	// Perform warmup operations
	for i := 0; i < 100; i++ {
		if conn, err := pool.Get(ctx); err == nil {
			pool.Put(conn)
		}
	}
	
	time.Sleep(pb.config.WarmupTime)
	fmt.Println(" done")
}

func (pb *PerformanceBenchmarks) calculateBenchmarkResult(name string, operations int64, 
	duration time.Duration, latencies []time.Duration, memBefore, memAfter *runtime.MemStats) *BenchmarkResult {
	
	result := &BenchmarkResult{
		Name:             name,
		Duration:         duration,
		Operations:       operations,
		OperationsPerSec: float64(operations) / duration.Seconds(),
		Timestamp:        time.Now(),
	}
	
	if len(latencies) > 0 {
		// Calculate latency statistics
		result.AverageLatency = time.Duration(int64(result.Duration) / operations)
		
		// Sort for percentiles
		sortedLatencies := make([]time.Duration, len(latencies))
		copy(sortedLatencies, latencies)
		
		// Simple sort implementation
		for i := 0; i < len(sortedLatencies); i++ {
			for j := i + 1; j < len(sortedLatencies); j++ {
				if sortedLatencies[i] > sortedLatencies[j] {
					sortedLatencies[i], sortedLatencies[j] = sortedLatencies[j], sortedLatencies[i]
				}
			}
		}
		
		result.MinLatency = sortedLatencies[0]
		result.MaxLatency = sortedLatencies[len(sortedLatencies)-1]
		result.P50Latency = sortedLatencies[len(sortedLatencies)/2]
		result.P95Latency = sortedLatencies[int(float64(len(sortedLatencies))*0.95)]
		result.P99Latency = sortedLatencies[int(float64(len(sortedLatencies))*0.99)]
	}
	
	// Memory statistics
	result.MemoryUsageBytes = int64(memAfter.Alloc - memBefore.Alloc)
	result.AllocationsCount = int64(memAfter.Mallocs - memBefore.Mallocs)
	result.GCPauses = int64(memAfter.NumGC - memBefore.NumGC)
	
	return result
}

func (pb *PerformanceBenchmarks) generatePerformanceReport() *PerformanceReport {
	pb.mu.RLock()
	defer pb.mu.RUnlock()
	
	report := &PerformanceReport{
		Components:      make(map[string]*ComponentMetrics),
		Comparisons:     make([]*ComponentComparison, 0),
		Bottlenecks:     make([]*BottleneckAnalysis, 0),
		Recommendations: make([]*OptimizationRecommendation, 0),
		Timestamp:       time.Now(),
	}
	
	// Generate summary
	summary := &BenchmarkSummary{
		ComponentCount: len(pb.results),
	}
	
	var totalOps int64
	var totalDuration time.Duration
	var peakMemory int64
	
	for name, result := range pb.results {
		totalOps += result.Operations
		if result.Duration > totalDuration {
			totalDuration = result.Duration
		}
		if result.MemoryUsageBytes > peakMemory {
			peakMemory = result.MemoryUsageBytes
		}
		summary.TotalGCPauses += result.GCPauses
		
		// Create component metrics
		component := &ComponentMetrics{
			ComponentName:    name,
			BenchmarkResults: []*BenchmarkResult{result},
			AverageLatency:   result.AverageLatency,
			Throughput:       result.OperationsPerSec,
			ResourceUsage: &ResourceUsageMetrics{
				PeakMemoryMB: float64(result.MemoryUsageBytes) / (1024 * 1024),
				AllocationsRate: float64(result.AllocationsCount) / result.Duration.Seconds(),
			},
			PerformanceGrade: pb.calculatePerformanceGrade(result),
		}
		
		report.Components[name] = component
	}
	
	summary.TotalOperations = totalOps
	summary.TotalDuration = totalDuration
	summary.OverallThroughput = float64(totalOps) / totalDuration.Seconds()
	summary.PeakMemoryUsage = peakMemory
	
	report.Summary = summary
	
	// Generate comparisons and recommendations
	pb.generateComparisons(report)
	pb.generateBottleneckAnalysis(report)
	pb.generateOptimizationRecommendations(report)
	
	return report
}

func (pb *PerformanceBenchmarks) calculatePerformanceGrade(result *BenchmarkResult) string {
	// Simple grading based on throughput and latency
	throughput := result.OperationsPerSec
	
	switch {
	case throughput > 10000:
		return "A+"
	case throughput > 5000:
		return "A"
	case throughput > 1000:
		return "B+"
	case throughput > 500:
		return "B"
	case throughput > 100:
		return "C+"
	case throughput > 50:
		return "C"
	default:
		return "D"
	}
}

func (pb *PerformanceBenchmarks) generateComparisons(report *PerformanceReport) {
	components := make([]string, 0, len(report.Components))
	for name := range report.Components {
		components = append(components, name)
	}
	
	// Compare each pair of components
	for i := 0; i < len(components); i++ {
		for j := i + 1; j < len(components); j++ {
			compA := report.Components[components[i]]
			compB := report.Components[components[j]]
			
			comparison := &ComponentComparison{
				ComponentA:      components[i],
				ComponentB:      components[j],
				ThroughputRatio: compA.Throughput / compB.Throughput,
				LatencyRatio:    float64(compA.AverageLatency) / float64(compB.AverageLatency),
				MemoryRatio:     compA.ResourceUsage.PeakMemoryMB / compB.ResourceUsage.PeakMemoryMB,
			}
			
			// Determine winner based on throughput (primary) and latency (secondary)
			if comparison.ThroughputRatio > 1.1 && comparison.LatencyRatio < 1.1 {
				comparison.Winner = components[i]
			} else if comparison.ThroughputRatio < 0.9 && comparison.LatencyRatio > 0.9 {
				comparison.Winner = components[j]
			} else {
				comparison.Winner = "tie"
			}
			
			comparison.Recommendation = fmt.Sprintf("Use %s for high-throughput scenarios, %s for low-latency needs", 
				components[i], components[j])
			
			report.Comparisons = append(report.Comparisons, comparison)
		}
	}
}

func (pb *PerformanceBenchmarks) generateBottleneckAnalysis(report *PerformanceReport) {
	for name, component := range report.Components {
		result := component.BenchmarkResults[0]
		
		// Analyze for different types of bottlenecks
		if result.OperationsPerSec < 1000 {
			bottleneck := &BottleneckAnalysis{
				ComponentName:   name,
				BottleneckType:  "Throughput",
				SeverityLevel:   "High",
				Description:     "Low throughput indicates potential scalability issues",
				ImpactMetrics:   map[string]float64{"throughput": result.OperationsPerSec},
				RootCauses:      []string{"Contention", "Inefficient algorithms", "Resource constraints"},
				DetectionMethod: "Throughput analysis",
			}
			report.Bottlenecks = append(report.Bottlenecks, bottleneck)
		}
		
		if result.P99Latency > 100*time.Millisecond {
			bottleneck := &BottleneckAnalysis{
				ComponentName:   name,
				BottleneckType:  "Latency",
				SeverityLevel:   "Medium",
				Description:     "High P99 latency indicates tail latency issues",
				ImpactMetrics:   map[string]float64{"p99_latency_ms": float64(result.P99Latency.Milliseconds())},
				RootCauses:      []string{"GC pressure", "Lock contention", "Resource exhaustion"},
				DetectionMethod: "Latency distribution analysis",
			}
			report.Bottlenecks = append(report.Bottlenecks, bottleneck)
		}
		
		if result.MemoryUsageBytes > 100*1024*1024 { // 100MB
			bottleneck := &BottleneckAnalysis{
				ComponentName:   name,
				BottleneckType:  "Memory",
				SeverityLevel:   "Medium",
				Description:     "High memory usage may indicate memory leaks or inefficient data structures",
				ImpactMetrics:   map[string]float64{"memory_usage_mb": float64(result.MemoryUsageBytes) / (1024 * 1024)},
				RootCauses:      []string{"Memory leaks", "Large object allocations", "Inefficient caching"},
				DetectionMethod: "Memory usage analysis",
			}
			report.Bottlenecks = append(report.Bottlenecks, bottleneck)
		}
	}
}

func (pb *PerformanceBenchmarks) generateOptimizationRecommendations(report *PerformanceReport) {
	for name, component := range report.Components {
		result := component.BenchmarkResults[0]
		
		// Generate recommendations based on performance characteristics
		if result.OperationsPerSec < 5000 {
			recommendation := &OptimizationRecommendation{
				ComponentName:      name,
				RecommendationType: "Configuration",
				Priority:           "High",
				Title:              "Increase Worker Pool Size",
				Description:        "Consider increasing the number of workers to improve throughput",
				ExpectedImpact:     "20-50% throughput improvement",
				Implementation:     "Adjust MaxWorkers configuration parameter",
				RiskLevel:          "Low",
				EffortEstimate:     "Low (configuration change)",
			}
			report.Recommendations = append(report.Recommendations, recommendation)
		}
		
		if result.P95Latency > 10*time.Millisecond {
			recommendation := &OptimizationRecommendation{
				ComponentName:      name,
				RecommendationType: "Algorithm",
				Priority:           "Medium",
				Title:              "Optimize Critical Path",
				Description:        "Profile and optimize the critical path to reduce latency",
				ExpectedImpact:     "10-30% latency reduction",
				Implementation:     "Profile code and optimize hot spots",
				RiskLevel:          "Medium",
				EffortEstimate:     "Medium (requires profiling and code changes)",
			}
			report.Recommendations = append(report.Recommendations, recommendation)
		}
		
		if result.GCPauses > 100 {
			recommendation := &OptimizationRecommendation{
				ComponentName:      name,
				RecommendationType: "Architecture",
				Priority:           "Medium",
				Title:              "Reduce GC Pressure",
				Description:        "Reduce object allocations and optimize memory usage patterns",
				ExpectedImpact:     "Reduced tail latency and more consistent performance",
				Implementation:     "Object pooling, reduced allocations, tune GC parameters",
				RiskLevel:          "Medium",
				EffortEstimate:     "High (architectural changes)",
			}
			report.Recommendations = append(report.Recommendations, recommendation)
		}
	}
}

// Mock implementation for benchmarking
type MockRuncForBench struct{}

func (m *MockRuncForBench) State(ctx context.Context, id string) (*runc.Container, error) {
	return &runc.Container{ID: id}, nil
}

func (m *MockRuncForBench) Exec(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
	return nil
}

func (m *MockRuncForBench) Create(ctx context.Context, id, bundle string, opts *runc.CreateOpts) error {
	return nil
}

func (m *MockRuncForBench) Start(ctx context.Context, id string) error {
	return nil
}

func (m *MockRuncForBench) Kill(ctx context.Context, id string, sig int, opts *runc.KillOpts) error {
	return nil
}

func (m *MockRuncForBench) Delete(ctx context.Context, id string, opts *runc.DeleteOpts) error {
	return nil
}

func (m *MockRuncForBench) List(ctx context.Context) ([]*runc.Container, error) {
	return []*runc.Container{}, nil
}