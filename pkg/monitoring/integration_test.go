package monitoring

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

// Integration tests for the complete monitoring stack

func TestMonitoringStack_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Setup complete monitoring stack
	metricsConfig := DefaultMetricsConfig()
	metricsConfig.Port = 0 // Use random port

	tracingConfig := DefaultTracingConfig()
	tracingConfig.Exporter = TracingExporterStdout

	loggingConfig := DefaultLoggingConfig()
	loggingConfig.EnableTraceIntegration = true

	healthConfig := DefaultHealthConfig()
	healthConfig.Port = 0 // Use random port
	healthConfig.CheckInterval = 100 * time.Millisecond

	// Initialize components
	metricsRegistry := NewMetricsRegistry(metricsConfig)
	tracingManager, err := NewTracingManager(tracingConfig)
	require.NoError(t, err)

	logger, err := NewCorrelatedLogger(loggingConfig, tracingManager)
	require.NoError(t, err)

	healthRegistry, err := NewHealthRegistry(healthConfig, metricsRegistry, logger)
	require.NoError(t, err)

	// Test integration between components
	t.Run("MetricsWithTracing", func(t *testing.T) {
		testMetricsWithTracing(t, metricsRegistry, tracingManager)
	})

	t.Run("LoggingWithTracing", func(t *testing.T) {
		testLoggingWithTracing(t, logger, tracingManager)
	})

	t.Run("HealthWithMetrics", func(t *testing.T) {
		testHealthWithMetrics(t, healthRegistry, metricsRegistry)
	})

	t.Run("EndToEndWorkflow", func(t *testing.T) {
		testEndToEndWorkflow(t, metricsRegistry, tracingManager, logger, healthRegistry)
	})

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tracingManager.Shutdown(ctx)
	logger.Shutdown(ctx)
	healthRegistry.Shutdown(ctx)
}

func testMetricsWithTracing(t *testing.T, metrics *MetricsRegistry, tracing *TracingManager) {
	// Create a counter metric
	counter, err := metrics.NewCounter("integration_requests_total", "Integration test requests", "operation", "status")
	require.NoError(t, err)

	// Create a traced operation that updates metrics
	ctx := context.Background()
	err = tracing.TraceOperation(ctx, "metrics_integration_test", func(ctx context.Context) error {
		counter.Inc("test", "success")
		counter.Add(5, "test", "error")
		return nil
	}, attribute.String("test.type", "metrics_integration"))

	assert.NoError(t, err)

	// Verify metrics were recorded
	assert.Equal(t, float64(1), counter.Get("test", "success"))
	assert.Equal(t, float64(5), counter.Get("test", "error"))

	// Verify metrics can be gathered
	gatheredMetrics, err := metrics.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, gatheredMetrics)

	// Find our counter in the gathered metrics
	found := false
	for _, metric := range gatheredMetrics {
		if metric.Name == "sandboxrunner_integration_requests_total" {
			found = true
			assert.Equal(t, MetricTypeCounter, metric.Type)
			assert.NotEmpty(t, metric.Values)
			break
		}
	}
	assert.True(t, found, "Counter metric not found in gathered metrics")
}

func testLoggingWithTracing(t *testing.T, logger *CorrelatedLogger, tracing *TracingManager) {
	ctx := context.Background()

	// Create a traced operation with logging
	err := tracing.TraceOperation(ctx, "logging_integration_test", func(ctx context.Context) error {
		// Get span context for correlation
		spanCtx := tracing.GetSpanContext(ctx)
		require.NotNil(t, spanCtx)

		// Create logger with context
		contextLogger := logger.WithContext(ctx)

		// Log with correlation
		contextLogger.Info("Integration test log message", map[string]interface{}{
			"test_type": "logging_integration",
			"trace_id":  spanCtx.TraceID,
		})

		contextLogger.Debug("Debug message with trace context")

		// Test error logging
		testErr := fmt.Errorf("test error for integration")
		contextLogger.Error("Test error occurred", testErr, map[string]interface{}{
			"error_type": "integration_test",
		})

		return nil
	}, attribute.String("test.type", "logging_integration"))

	assert.NoError(t, err)
}

func testHealthWithMetrics(t *testing.T, health *HealthRegistry, metrics *MetricsRegistry) {
	// Register a test health checker
	checker := &IntegrationHealthChecker{
		name:     "integration_test_service",
		healthy:  true,
		checkType: CheckTypeLiveness,
		critical: true,
	}
	health.RegisterChecker(checker)

	// Perform health check
	ctx := context.Background()
	healthResult, err := health.CheckHealth(ctx)
	require.NoError(t, err)

	assert.Equal(t, HealthStatusHealthy, healthResult.Status)
	assert.Contains(t, healthResult.ComponentHealth, "integration_test_service")

	// Test unhealthy scenario
	checker.healthy = false
	healthResult, err = health.CheckHealth(ctx)
	require.NoError(t, err)

	assert.Equal(t, HealthStatusUnhealthy, healthResult.Status)

	// Verify metrics were updated (if metrics integration is enabled)
	if health.config.EnableMetrics {
		gatheredMetrics, err := metrics.Gather()
		require.NoError(t, err)
		assert.NotEmpty(t, gatheredMetrics)
	}
}

func testEndToEndWorkflow(t *testing.T, metrics *MetricsRegistry, tracing *TracingManager, logger *CorrelatedLogger, health *HealthRegistry) {
	// Simulate a complete request workflow with monitoring
	ctx := context.Background()

	// Create metrics for the workflow
	requestCounter, err := metrics.NewCounter("workflow_requests_total", "Workflow requests", "status")
	require.NoError(t, err)

	requestDuration, err := metrics.NewHistogram("workflow_request_duration_seconds", "Request duration", nil)
	require.NoError(t, err)

	// Execute traced workflow
	err = tracing.TraceOperation(ctx, "end_to_end_workflow", func(ctx context.Context) error {
		start := time.Now()
		
		// Log start
		contextLogger := logger.WithContext(ctx).WithCorrelationID("integration-test-123")
		contextLogger.Info("Starting end-to-end workflow", map[string]interface{}{
			"workflow_type": "integration_test",
		})

		// Simulate sub-operations
		err := tracing.TraceOperation(ctx, "workflow_step_1", func(ctx context.Context) error {
			contextLogger.Info("Executing workflow step 1")
			requestCounter.Inc("processing")
			time.Sleep(10 * time.Millisecond) // Simulate work
			return nil
		})
		if err != nil {
			return err
		}

		err = tracing.TraceOperation(ctx, "workflow_step_2", func(ctx context.Context) error {
			contextLogger.Info("Executing workflow step 2")
			time.Sleep(5 * time.Millisecond) // Simulate work
			return nil
		})
		if err != nil {
			return err
		}

		// Check health during workflow
		healthResult, err := health.CheckHealth(ctx)
		if err != nil {
			contextLogger.Error("Health check failed during workflow", err)
			requestCounter.Inc("health_error")
			return err
		}

		if healthResult.Status != HealthStatusHealthy {
			contextLogger.Warn("System not healthy during workflow", map[string]interface{}{
				"health_status": string(healthResult.Status),
				"health_message": healthResult.Message,
			})
		}

		// Record success metrics
		duration := time.Since(start)
		requestDuration.Observe(duration.Seconds())
		requestCounter.Inc("success")

		contextLogger.Info("End-to-end workflow completed successfully", map[string]interface{}{
			"duration_ms": duration.Milliseconds(),
			"steps_completed": 2,
		})

		return nil
	}, 
		attribute.String("workflow.type", "integration_test"),
		attribute.Int("workflow.steps", 2),
	)

	assert.NoError(t, err)

	// Verify all components recorded data
	assert.Equal(t, float64(1), requestCounter.Get("processing"))
	assert.Equal(t, float64(1), requestCounter.Get("success"))

	// Verify histogram recorded observation
	histogramKey := buildLabelsKey([]string{}, []string{})
	histogramValue, exists := requestDuration.values[histogramKey]
	assert.True(t, exists)
	assert.Equal(t, uint64(1), histogramValue.count)
	assert.Greater(t, histogramValue.sum, 0.0)
}

func TestConcurrentMonitoring(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	// Setup monitoring components
	metricsConfig := DefaultMetricsConfig()
	tracingConfig := DefaultTracingConfig()
	tracingConfig.Exporter = TracingExporterStdout

	metrics := NewMetricsRegistry(metricsConfig)
	tracing, err := NewTracingManager(tracingConfig)
	require.NoError(t, err)

	// Create metrics
	requestCounter, err := metrics.NewCounter("concurrent_requests_total", "Concurrent requests", "worker")
	require.NoError(t, err)

	requestDuration, err := metrics.NewHistogram("concurrent_request_duration_seconds", "Request duration", nil, "worker")
	require.NoError(t, err)

	// Run concurrent operations
	const numWorkers = 10
	const opsPerWorker = 100

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			workerName := fmt.Sprintf("worker_%d", workerID)
			ctx := context.Background()

			for j := 0; j < opsPerWorker; j++ {
				err := tracing.TraceOperation(ctx, "concurrent_operation", func(ctx context.Context) error {
					start := time.Now()

					// Simulate work
					time.Sleep(time.Millisecond)

					// Update metrics
					requestCounter.Inc(workerName)
					requestDuration.Observe(time.Since(start).Seconds(), workerName)

					return nil
				}, 
					attribute.String("worker.id", workerName),
					attribute.Int("operation.sequence", j),
				)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all operations were recorded
	totalRequests := float64(0)
	for i := 0; i < numWorkers; i++ {
		workerName := fmt.Sprintf("worker_%d", i)
		workerRequests := requestCounter.Get(workerName)
		assert.Equal(t, float64(opsPerWorker), workerRequests)
		totalRequests += workerRequests
	}

	assert.Equal(t, float64(numWorkers*opsPerWorker), totalRequests)

	// Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tracing.Shutdown(ctx)
}

func TestMonitoringOverhead(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping overhead test in short mode")
	}

	// Test performance impact of monitoring
	const iterations = 1000

	// Baseline: operation without monitoring
	baselineStart := time.Now()
	for i := 0; i < iterations; i++ {
		// Simulate a simple operation
		time.Sleep(time.Microsecond)
	}
	baselineDuration := time.Since(baselineStart)

	// With monitoring
	metricsConfig := DefaultMetricsConfig()
	tracingConfig := DefaultTracingConfig()
	tracingConfig.Exporter = TracingExporterStdout
	loggingConfig := DefaultLoggingConfig()

	metrics := NewMetricsRegistry(metricsConfig)
	tracing, err := NewTracingManager(tracingConfig)
	require.NoError(t, err)

	logger, err := NewCorrelatedLogger(loggingConfig, tracing)
	require.NoError(t, err)

	counter, err := metrics.NewCounter("overhead_test_ops", "Overhead test operations")
	require.NoError(t, err)

	monitoredStart := time.Now()
	ctx := context.Background()
	
	for i := 0; i < iterations; i++ {
		err := tracing.TraceOperation(ctx, "overhead_test_operation", func(ctx context.Context) error {
			contextLogger := logger.WithContext(ctx)
			contextLogger.Debug("Overhead test operation")
			
			counter.Inc()
			
			// Simulate the same operation
			time.Sleep(time.Microsecond)
			return nil
		})
		assert.NoError(t, err)
	}
	monitoredDuration := time.Since(monitoredStart)

	// Calculate overhead
	overhead := monitoredDuration - baselineDuration
	overheadPercentage := float64(overhead) / float64(baselineDuration) * 100

	t.Logf("Baseline duration: %v", baselineDuration)
	t.Logf("Monitored duration: %v", monitoredDuration)
	t.Logf("Overhead: %v (%.2f%%)", overhead, overheadPercentage)

	// Verify operations were recorded
	assert.Equal(t, float64(iterations), counter.Get())

	// Overhead should be reasonable (less than 100% in most cases)
	// This is a rough check - actual overhead depends on system and implementation
	assert.Less(t, overheadPercentage, 200.0, "Monitoring overhead is too high")

	// Cleanup
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tracing.Shutdown(cleanupCtx)
	logger.Shutdown(cleanupCtx)
}

func TestMemoryUsageAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory analysis in short mode")
	}

	// Test memory usage of monitoring components
	runtime.GC()
	var startMemStats runtime.MemStats
	runtime.ReadMemStats(&startMemStats)

	// Create monitoring components
	metricsConfig := DefaultMetricsConfig()
	tracingConfig := DefaultTracingConfig()
	tracingConfig.Exporter = TracingExporterStdout

	metrics := NewMetricsRegistry(metricsConfig)
	tracing, err := NewTracingManager(tracingConfig)
	require.NoError(t, err)

	// Create many metrics to test memory usage
	const numMetrics = 1000
	counters := make([]*Counter, numMetrics)
	gauges := make([]*Gauge, numMetrics)

	for i := 0; i < numMetrics; i++ {
		counter, err := metrics.NewCounter(fmt.Sprintf("memory_test_counter_%d", i), "Memory test counter", "label")
		require.NoError(t, err)
		counters[i] = counter

		gauge, err := metrics.NewGauge(fmt.Sprintf("memory_test_gauge_%d", i), "Memory test gauge", "label")
		require.NoError(t, err)
		gauges[i] = gauge
	}

	// Use the metrics
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		err := tracing.TraceOperation(ctx, "memory_test_operation", func(ctx context.Context) error {
			for j := 0; j < numMetrics; j++ {
				counters[j].Inc("test")
				gauges[j].Set(float64(i*j), "test")
			}
			return nil
		})
		assert.NoError(t, err)
	}

	// Force garbage collection and measure memory
	runtime.GC()
	var endMemStats runtime.MemStats
	runtime.ReadMemStats(&endMemStats)

	memoryIncrease := endMemStats.Alloc - startMemStats.Alloc
	t.Logf("Memory increase: %d bytes (%.2f MB)", memoryIncrease, float64(memoryIncrease)/(1024*1024))
	t.Logf("Total allocations: %d", endMemStats.TotalAlloc-startMemStats.TotalAlloc)
	t.Logf("GC cycles: %d", endMemStats.NumGC-startMemStats.NumGC)

	// Memory usage should be reasonable for the number of metrics created
	// This is a rough check - adjust based on expected usage
	maxExpectedMemory := uint64(50 * 1024 * 1024) // 50MB
	assert.Less(t, memoryIncrease, maxExpectedMemory, "Memory usage is too high")

	// Cleanup
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tracing.Shutdown(cleanupCtx)
}

func TestMonitoringResilience(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping resilience test in short mode")
	}

	// Test monitoring system resilience to failures
	metricsConfig := DefaultMetricsConfig()
	tracingConfig := DefaultTracingConfig()
	tracingConfig.Exporter = TracingExporterStdout
	healthConfig := DefaultHealthConfig()
	healthConfig.Port = 0
	healthConfig.RetryAttempts = 2
	healthConfig.RetryDelay = 10 * time.Millisecond

	metrics := NewMetricsRegistry(metricsConfig)
	tracing, err := NewTracingManager(tracingConfig)
	require.NoError(t, err)

	health, err := NewHealthRegistry(healthConfig, metrics, nil)
	require.NoError(t, err)

	// Register a flaky health checker
	flakyChecker := &FlakyHealthChecker{
		name:        "flaky_service",
		failureRate: 0.3, // 30% failure rate
		checkType:   CheckTypeLiveness,
	}
	health.RegisterChecker(flakyChecker)

	// Test operations with failures
	counter, err := metrics.NewCounter("resilience_test_ops", "Resilience test operations", "status")
	require.NoError(t, err)

	ctx := context.Background()
	successCount := 0
	errorCount := 0

	for i := 0; i < 100; i++ {
		err := tracing.TraceOperation(ctx, "resilience_test", func(ctx context.Context) error {
			// Perform health check
			healthResult, err := health.CheckHealth(ctx)
			if err != nil {
				counter.Inc("health_error")
				return fmt.Errorf("health check failed: %w", err)
			}

			// Simulate operation based on health
			if healthResult.Status == HealthStatusHealthy {
				counter.Inc("success")
				successCount++
			} else {
				counter.Inc("degraded")
			}

			return nil
		})

		if err != nil {
			errorCount++
		}
	}

	t.Logf("Success count: %d", successCount)
	t.Logf("Error count: %d", errorCount)
	t.Logf("Success rate: %.2f%%", float64(successCount)/100*100)

	// System should handle failures gracefully
	assert.Greater(t, successCount, 50, "Success rate too low")
	assert.Equal(t, float64(successCount), counter.Get("success"))

	// Cleanup
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tracing.Shutdown(cleanupCtx)
	health.Shutdown(cleanupCtx)
}

// Helper types for integration tests

type IntegrationHealthChecker struct {
	name      string
	healthy   bool
	checkType CheckType
	critical  bool
}

func (ihc *IntegrationHealthChecker) Name() string                 { return ihc.name }
func (ihc *IntegrationHealthChecker) CheckType() CheckType         { return ihc.checkType }
func (ihc *IntegrationHealthChecker) IsCritical() bool             { return ihc.critical }

func (ihc *IntegrationHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      ihc.name,
		CheckType: ihc.checkType,
		Timestamp: time.Now(),
		Critical:  ihc.critical,
	}

	if ihc.healthy {
		result.Status = HealthStatusHealthy
		result.Message = "Integration test service is healthy"
	} else {
		result.Status = HealthStatusUnhealthy
		result.Message = "Integration test service is unhealthy"
	}

	return result
}

type FlakyHealthChecker struct {
	name        string
	failureRate float64
	checkType   CheckType
}

func (fhc *FlakyHealthChecker) Name() string       { return fhc.name }
func (fhc *FlakyHealthChecker) CheckType() CheckType { return fhc.checkType }
func (fhc *FlakyHealthChecker) IsCritical() bool   { return true }

func (fhc *FlakyHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      fhc.name,
		CheckType: fhc.checkType,
		Timestamp: time.Now(),
		Critical:  true,
	}

	// Simulate random failures
	if time.Now().UnixNano()%100 < int64(fhc.failureRate*100) {
		result.Status = HealthStatusUnhealthy
		result.Message = "Flaky service temporarily unavailable"
		result.Error = "Simulated failure"
	} else {
		result.Status = HealthStatusHealthy
		result.Message = "Flaky service is working"
	}

	return result
}

// Benchmark integration tests

func BenchmarkFullMonitoringStack(b *testing.B) {
	// Setup complete monitoring stack
	metricsConfig := DefaultMetricsConfig()
	tracingConfig := DefaultTracingConfig()
	tracingConfig.Exporter = TracingExporterStdout

	metrics := NewMetricsRegistry(metricsConfig)
	tracing, err := NewTracingManager(tracingConfig)
	require.NoError(b, err)

	counter, err := metrics.NewCounter("benchmark_operations", "Benchmark operations")
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := tracing.TraceOperation(ctx, "benchmark_operation", func(ctx context.Context) error {
			counter.Inc()
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConcurrentMonitoring(b *testing.B) {
	metricsConfig := DefaultMetricsConfig()
	tracingConfig := DefaultTracingConfig()
	tracingConfig.Exporter = TracingExporterStdout

	metrics := NewMetricsRegistry(metricsConfig)
	tracing, err := NewTracingManager(tracingConfig)
	require.NoError(b, err)

	counter, err := metrics.NewCounter("concurrent_benchmark_operations", "Concurrent benchmark operations", "worker")
	require.NoError(b, err)

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		workerID := fmt.Sprintf("worker_%d", time.Now().UnixNano()%1000)
		for pb.Next() {
			err := tracing.TraceOperation(ctx, "concurrent_benchmark_operation", func(ctx context.Context) error {
				counter.Inc(workerID)
				return nil
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}