package languages

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// PerformanceMonitor tracks and analyzes execution performance
type PerformanceMonitor struct {
	metrics     map[string]*MetricSeries
	benchmarks  map[Language]*BenchmarkResult
	thresholds  *PerformanceThresholds
	alerts      []PerformanceAlert
	mu          sync.RWMutex
	started     time.Time
}

// MetricSeries stores time-series performance data
type MetricSeries struct {
	Name        string              `json:"name"`
	Values      []MetricValue       `json:"values"`
	Statistics  *MetricStatistics   `json:"statistics"`
	MaxEntries  int                 `json:"max_entries"`
	mu          sync.Mutex          `json:"-"`
}

// MetricValue represents a single metric measurement
type MetricValue struct {
	Timestamp time.Time   `json:"timestamp"`
	Value     float64     `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	Context   string      `json:"context,omitempty"`
}

// MetricStatistics contains statistical analysis of metrics
type MetricStatistics struct {
	Count       int64     `json:"count"`
	Min         float64   `json:"min"`
	Max         float64   `json:"max"`
	Mean        float64   `json:"mean"`
	Median      float64   `json:"median"`
	P95         float64   `json:"p95"`
	P99         float64   `json:"p99"`
	StdDev      float64   `json:"std_dev"`
	LastValue   float64   `json:"last_value"`
	LastUpdated time.Time `json:"last_updated"`
}

// BenchmarkResult contains benchmark results for a language
type BenchmarkResult struct {
	Language           Language      `json:"language"`
	ExecutionTime      time.Duration `json:"execution_time"`
	CompilationTime    time.Duration `json:"compilation_time"`
	MemoryUsage        int64         `json:"memory_usage"`
	CPUUsage           float64       `json:"cpu_usage"`
	ThroughputOps      int64         `json:"throughput_ops"`
	ThroughputDuration time.Duration `json:"throughput_duration"`
	BenchmarkCode      string        `json:"benchmark_code"`
	Timestamp          time.Time     `json:"timestamp"`
	SystemInfo         *SystemInfo   `json:"system_info"`
}

// SystemInfo contains system information for benchmarks
type SystemInfo struct {
	OS            string  `json:"os"`
	Architecture  string  `json:"architecture"`
	CPUCores      int     `json:"cpu_cores"`
	CPUModel      string  `json:"cpu_model"`
	MemoryTotal   int64   `json:"memory_total"`
	MemoryAvailable int64 `json:"memory_available"`
	GoVersion     string  `json:"go_version"`
}

// PerformanceThresholds defines performance alert thresholds
type PerformanceThresholds struct {
	MaxExecutionTime     time.Duration `json:"max_execution_time"`
	MaxCompilationTime   time.Duration `json:"max_compilation_time"`
	MaxMemoryUsage       int64         `json:"max_memory_usage"`
	MaxCPUUsage          float64       `json:"max_cpu_usage"`
	MinSuccessRate       float64       `json:"min_success_rate"`
	MaxErrorRate         float64       `json:"max_error_rate"`
	MaxAverageLatency    time.Duration `json:"max_average_latency"`
}

// PerformanceAlert represents a performance alert
type PerformanceAlert struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"` // threshold, anomaly, trend
	Severity    string                 `json:"severity"` // info, warning, error, critical
	Message     string                 `json:"message"`
	Metric      string                 `json:"metric"`
	Value       float64                `json:"value"`
	Threshold   float64                `json:"threshold,omitempty"`
	Language    Language               `json:"language,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Acknowledged bool                  `json:"acknowledged"`
}

// BenchmarkSuite contains a collection of benchmarks
type BenchmarkSuite struct {
	Name        string                    `json:"name"`
	Benchmarks  map[Language]*Benchmark   `json:"benchmarks"`
	Results     map[Language]*BenchmarkResult `json:"results"`
	CreatedAt   time.Time                 `json:"created_at"`
	UpdatedAt   time.Time                 `json:"updated_at"`
}

// Benchmark defines a single benchmark test
type Benchmark struct {
	Name        string        `json:"name"`
	Language    Language      `json:"language"`
	Code        string        `json:"code"`
	ExpectedOutput string     `json:"expected_output,omitempty"`
	Timeout     time.Duration `json:"timeout"`
	Iterations  int           `json:"iterations"`
	WarmupRuns  int           `json:"warmup_runs"`
	Description string        `json:"description"`
}

// NewPerformanceMonitor creates a new performance monitor
func NewPerformanceMonitor() *PerformanceMonitor {
	return &PerformanceMonitor{
		metrics:    make(map[string]*MetricSeries),
		benchmarks: make(map[Language]*BenchmarkResult),
		thresholds: getDefaultThresholds(),
		alerts:     []PerformanceAlert{},
		started:    time.Now(),
	}
}

// RecordMetric records a performance metric
func (pm *PerformanceMonitor) RecordMetric(name string, value float64, labels map[string]string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.metrics[name]; !exists {
		pm.metrics[name] = &MetricSeries{
			Name:       name,
			Values:     []MetricValue{},
			MaxEntries: 10000, // Keep last 10k entries
		}
	}

	metric := pm.metrics[name]
	metric.mu.Lock()
	defer metric.mu.Unlock()

	// Add new value
	metricValue := MetricValue{
		Timestamp: time.Now(),
		Value:     value,
		Labels:    labels,
	}
	
	metric.Values = append(metric.Values, metricValue)

	// Trim old values if needed
	if len(metric.Values) > metric.MaxEntries {
		metric.Values = metric.Values[len(metric.Values)-metric.MaxEntries:]
	}

	// Update statistics
	pm.updateStatistics(metric)

	// Check thresholds
	pm.checkThresholds(name, value, labels)
}

// RecordExecutionMetrics records metrics from an execution result
func (pm *PerformanceMonitor) RecordExecutionMetrics(language Language, result *EnhancedExecutionResult) {
	labels := map[string]string{
		"language":       string(language),
		"execution_path": result.ExecutionPath,
	}

	// Record execution time
	pm.RecordMetric("execution_time_ms", float64(result.PerformanceMetrics.ExecutionTime.Nanoseconds())/1e6, labels)

	// Record total time
	pm.RecordMetric("total_time_ms", float64(result.PerformanceMetrics.TotalTime.Nanoseconds())/1e6, labels)

	// Record compilation time if available
	if result.PerformanceMetrics.CompilationTime > 0 {
		pm.RecordMetric("compilation_time_ms", float64(result.PerformanceMetrics.CompilationTime.Nanoseconds())/1e6, labels)
	}

	// Record preprocessing time if available
	if result.PerformanceMetrics.PreprocessingTime > 0 {
		pm.RecordMetric("preprocessing_time_ms", float64(result.PerformanceMetrics.PreprocessingTime.Nanoseconds())/1e6, labels)
	}

	// Record success/failure
	successValue := 1.0
	if result.ExecutionResult.ExitCode != 0 {
		successValue = 0.0
	}
	pm.RecordMetric("execution_success", successValue, labels)

	// Record cache hits
	cacheValue := 0.0
	if result.PerformanceMetrics.CacheHit {
		cacheValue = 1.0
	}
	pm.RecordMetric("cache_hit", cacheValue, labels)

	// Record memory usage if available
	if result.PerformanceMetrics.MemoryUsage > 0 {
		pm.RecordMetric("memory_usage_bytes", float64(result.PerformanceMetrics.MemoryUsage), labels)
	}

	// Record CPU usage if available
	if result.PerformanceMetrics.CPUUsage > 0 {
		pm.RecordMetric("cpu_usage_percent", result.PerformanceMetrics.CPUUsage, labels)
	}

	// Record security warnings count
	if len(result.SecurityWarnings) > 0 {
		pm.RecordMetric("security_warnings", float64(len(result.SecurityWarnings)), labels)
	}
}

// RunBenchmark runs a benchmark for a specific language
func (pm *PerformanceMonitor) RunBenchmark(ctx context.Context, executionManager *ExecutionManager, benchmark *Benchmark) (*BenchmarkResult, error) {
	result := &BenchmarkResult{
		Language:      benchmark.Language,
		BenchmarkCode: benchmark.Code,
		Timestamp:     time.Now(),
		SystemInfo:    getSystemInfo(),
	}

	// Warmup runs
	for i := 0; i < benchmark.WarmupRuns; i++ {
		_, _ = pm.runSingleBenchmark(ctx, executionManager, benchmark)
	}

	// Benchmark runs
	var totalExecutionTime time.Duration
	var totalCompilationTime time.Duration
	var totalMemoryUsage int64
	var totalCPUUsage float64
	successfulRuns := 0

	for i := 0; i < benchmark.Iterations; i++ {
		benchResult, err := pm.runSingleBenchmark(ctx, executionManager, benchmark)
		if err != nil {
			continue
		}

		if benchResult.ExecutionResult.ExitCode == 0 {
			successfulRuns++
			totalExecutionTime += benchResult.PerformanceMetrics.ExecutionTime
			totalCompilationTime += benchResult.PerformanceMetrics.CompilationTime
			totalMemoryUsage += benchResult.PerformanceMetrics.MemoryUsage
			totalCPUUsage += benchResult.PerformanceMetrics.CPUUsage
		}
	}

	if successfulRuns == 0 {
		return result, fmt.Errorf("no successful benchmark runs")
	}

	// Calculate averages
	result.ExecutionTime = totalExecutionTime / time.Duration(successfulRuns)
	result.CompilationTime = totalCompilationTime / time.Duration(successfulRuns)
	result.MemoryUsage = totalMemoryUsage / int64(successfulRuns)
	result.CPUUsage = totalCPUUsage / float64(successfulRuns)
	result.ThroughputOps = int64(successfulRuns)
	result.ThroughputDuration = time.Since(result.Timestamp)

	// Store result
	pm.mu.Lock()
	pm.benchmarks[benchmark.Language] = result
	pm.mu.Unlock()

	return result, nil
}

// GetMetrics returns current performance metrics
func (pm *PerformanceMonitor) GetMetrics() map[string]*MetricStatistics {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	metrics := make(map[string]*MetricStatistics)
	for name, series := range pm.metrics {
		series.mu.Lock()
		if series.Statistics != nil {
			// Create a copy
			stats := *series.Statistics
			metrics[name] = &stats
		}
		series.mu.Unlock()
	}

	return metrics
}

// GetBenchmarkResults returns all benchmark results
func (pm *PerformanceMonitor) GetBenchmarkResults() map[Language]*BenchmarkResult {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	results := make(map[Language]*BenchmarkResult)
	for lang, result := range pm.benchmarks {
		// Create a copy
		resultCopy := *result
		results[lang] = &resultCopy
	}

	return results
}

// GetAlerts returns current performance alerts
func (pm *PerformanceMonitor) GetAlerts() []PerformanceAlert {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Create a copy of alerts
	alerts := make([]PerformanceAlert, len(pm.alerts))
	copy(alerts, pm.alerts)

	return alerts
}

// AcknowledgeAlert marks an alert as acknowledged
func (pm *PerformanceMonitor) AcknowledgeAlert(alertID string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := range pm.alerts {
		if pm.alerts[i].ID == alertID {
			pm.alerts[i].Acknowledged = true
			return nil
		}
	}

	return fmt.Errorf("alert not found: %s", alertID)
}

// ClearOldAlerts removes old acknowledged alerts
func (pm *PerformanceMonitor) ClearOldAlerts(maxAge time.Duration) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	filteredAlerts := []PerformanceAlert{}

	for _, alert := range pm.alerts {
		if !alert.Acknowledged || alert.Timestamp.After(cutoff) {
			filteredAlerts = append(filteredAlerts, alert)
		}
	}

	pm.alerts = filteredAlerts
}

// Private helper methods

func (pm *PerformanceMonitor) updateStatistics(metric *MetricSeries) {
	if len(metric.Values) == 0 {
		return
	}

	values := make([]float64, len(metric.Values))
	for i, v := range metric.Values {
		values[i] = v.Value
	}

	stats := &MetricStatistics{
		Count:       int64(len(values)),
		LastValue:   values[len(values)-1],
		LastUpdated: time.Now(),
	}

	// Calculate min, max, and sum
	stats.Min = values[0]
	stats.Max = values[0]
	sum := 0.0

	for _, v := range values {
		if v < stats.Min {
			stats.Min = v
		}
		if v > stats.Max {
			stats.Max = v
		}
		sum += v
	}

	// Calculate mean
	stats.Mean = sum / float64(len(values))

	// Calculate median and percentiles
	sortedValues := make([]float64, len(values))
	copy(sortedValues, values)
	quickSort(sortedValues)

	stats.Median = percentile(sortedValues, 50)
	stats.P95 = percentile(sortedValues, 95)
	stats.P99 = percentile(sortedValues, 99)

	// Calculate standard deviation
	variance := 0.0
	for _, v := range values {
		diff := v - stats.Mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	stats.StdDev = sqrt(variance)

	metric.Statistics = stats
}

func (pm *PerformanceMonitor) checkThresholds(metricName string, value float64, labels map[string]string) {
	var alertType string
	var threshold float64
	var exceeded bool

	switch metricName {
	case "execution_time_ms":
		threshold = float64(pm.thresholds.MaxExecutionTime.Nanoseconds()) / 1e6
		exceeded = value > threshold
		alertType = "execution_time_threshold"
	case "compilation_time_ms":
		threshold = float64(pm.thresholds.MaxCompilationTime.Nanoseconds()) / 1e6
		exceeded = value > threshold
		alertType = "compilation_time_threshold"
	case "memory_usage_bytes":
		threshold = float64(pm.thresholds.MaxMemoryUsage)
		exceeded = value > threshold
		alertType = "memory_usage_threshold"
	case "cpu_usage_percent":
		threshold = pm.thresholds.MaxCPUUsage
		exceeded = value > threshold
		alertType = "cpu_usage_threshold"
	case "execution_success":
		// Check success rate over recent executions
		if series, exists := pm.metrics["execution_success"]; exists {
			series.mu.Lock()
			if series.Statistics != nil && series.Statistics.Mean < pm.thresholds.MinSuccessRate {
				exceeded = true
				threshold = pm.thresholds.MinSuccessRate
				alertType = "success_rate_threshold"
			}
			series.mu.Unlock()
		}
	}

	if exceeded {
		alert := PerformanceAlert{
			ID:        fmt.Sprintf("%s_%d", alertType, time.Now().Unix()),
			Type:      "threshold",
			Severity:  pm.getSeverity(metricName, value, threshold),
			Message:   fmt.Sprintf("Metric %s exceeded threshold: %.2f > %.2f", metricName, value, threshold),
			Metric:    metricName,
			Value:     value,
			Threshold: threshold,
			Timestamp: time.Now(),
			Context: map[string]interface{}{
				"labels": labels,
			},
		}

		if lang, exists := labels["language"]; exists {
			alert.Language = Language(lang)
		}

		pm.alerts = append(pm.alerts, alert)

		// Trim old alerts
		if len(pm.alerts) > 1000 {
			pm.alerts = pm.alerts[len(pm.alerts)-1000:]
		}
	}
}

func (pm *PerformanceMonitor) getSeverity(metricName string, value, threshold float64) string {
	ratio := value / threshold
	
	if ratio > 2.0 {
		return "critical"
	} else if ratio > 1.5 {
		return "error"
	} else if ratio > 1.2 {
		return "warning"
	}
	
	return "info"
}

func (pm *PerformanceMonitor) runSingleBenchmark(ctx context.Context, executionManager *ExecutionManager, benchmark *Benchmark) (*EnhancedExecutionResult, error) {
	request := &EnhancedExecutionRequest{
		ExecutionRequest: &ExecutionRequest{
			Code:     benchmark.Code,
			Language: benchmark.Language,
			Timeout:  benchmark.Timeout,
		},
		UseNewExecutors: true,
	}

	return executionManager.Execute(ctx, request)
}

func getDefaultThresholds() *PerformanceThresholds {
	return &PerformanceThresholds{
		MaxExecutionTime:   30 * time.Second,
		MaxCompilationTime: 60 * time.Second,
		MaxMemoryUsage:     512 * 1024 * 1024, // 512MB
		MaxCPUUsage:        80.0,               // 80%
		MinSuccessRate:     0.95,               // 95%
		MaxErrorRate:       0.05,               // 5%
		MaxAverageLatency:  1 * time.Second,
	}
}

func getSystemInfo() *SystemInfo {
	var memStats runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memStats)

	return &SystemInfo{
		OS:              runtime.GOOS,
		Architecture:    runtime.GOARCH,
		CPUCores:        runtime.NumCPU(),
		MemoryTotal:     int64(memStats.Sys),
		MemoryAvailable: int64(memStats.Frees),
		GoVersion:       runtime.Version(),
	}
}

// Utility functions for statistics

func quickSort(arr []float64) {
	if len(arr) <= 1 {
		return
	}
	
	pivot := partition(arr)
	quickSort(arr[:pivot])
	quickSort(arr[pivot+1:])
}

func partition(arr []float64) int {
	pivotValue := arr[len(arr)-1]
	i := -1
	
	for j := 0; j < len(arr)-1; j++ {
		if arr[j] <= pivotValue {
			i++
			arr[i], arr[j] = arr[j], arr[i]
		}
	}
	
	arr[i+1], arr[len(arr)-1] = arr[len(arr)-1], arr[i+1]
	return i + 1
}

func percentile(sortedValues []float64, p float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}
	
	index := (p / 100.0) * float64(len(sortedValues)-1)
	lower := int(index)
	upper := lower + 1
	
	if upper >= len(sortedValues) {
		return sortedValues[len(sortedValues)-1]
	}
	
	weight := index - float64(lower)
	return sortedValues[lower]*(1-weight) + sortedValues[upper]*weight
}

func sqrt(x float64) float64 {
	if x == 0 {
		return 0
	}
	
	// Newton's method for square root
	z := x
	for i := 0; i < 10; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}