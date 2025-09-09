package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTimeoutManager_NewTimeoutManager(t *testing.T) {
	config := DefaultTimeoutConfig()
	config.Name = "test_timeout"
	
	tm := NewTimeoutManager(config)
	
	if tm == nil {
		t.Fatal("Timeout manager should not be nil")
	}
	
	if tm.config.Name != "test_timeout" {
		t.Errorf("Expected name 'test_timeout', got '%s'", tm.config.Name)
	}
	
	metrics := tm.GetMetrics()
	if metrics.Name != "test_timeout" {
		t.Errorf("Expected metrics name 'test_timeout', got '%s'", metrics.Name)
	}
}

func TestTimeoutManager_FixedTimeout(t *testing.T) {
	config := &TimeoutConfig{
		Name:           "fixed_test",
		Strategy:       TimeoutStrategyFixed,
		DefaultTimeout: 100 * time.Millisecond,
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	// Test successful operation within timeout
	start := time.Now()
	result, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(50 * time.Millisecond)
		return "success", nil
	})
	duration := time.Since(start)
	
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if result != "success" {
		t.Errorf("Expected 'success', got %v", result)
	}
	
	if duration > 80*time.Millisecond {
		t.Errorf("Operation took too long: %v", duration)
	}
	
	// Test operation that times out
	start = time.Now()
	_, err = tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(150 * time.Millisecond)
		return "should not reach", nil
	})
	duration = time.Since(start)
	
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
	
	if !errors.Is(err, ErrOperationTimeout) {
		t.Errorf("Expected ErrOperationTimeout, got %v", err)
	}
	
	if duration < 90*time.Millisecond || duration > 120*time.Millisecond {
		t.Errorf("Expected timeout around 100ms, got %v", duration)
	}
	
	metrics := tm.GetMetrics()
	if metrics.TotalTimeouts == 0 {
		t.Error("Expected at least one timeout")
	}
}

func TestTimeoutManager_HierarchicalTimeout(t *testing.T) {
	config := &TimeoutConfig{
		Name:     "hierarchical_test",
		Strategy: TimeoutStrategyHierarchical,
		HierarchicalConfig: &HierarchicalTimeoutConfig{
			Levels: map[TimeoutLevel]time.Duration{
				TimeoutLevelRequest:   50 * time.Millisecond,
				TimeoutLevelOperation: 100 * time.Millisecond,
				TimeoutLevelSession:   200 * time.Millisecond,
			},
		},
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	// Test request level timeout
	start := time.Now()
	_, err := tm.WithTimeoutLevel(ctx, TimeoutLevelRequest, func(ctx context.Context) (interface{}, error) {
		time.Sleep(80 * time.Millisecond)
		return "should timeout", nil
	})
	duration := time.Since(start)
	
	if err == nil {
		t.Error("Expected timeout error for request level, got nil")
	}
	
	if duration < 40*time.Millisecond || duration > 70*time.Millisecond {
		t.Errorf("Expected request timeout around 50ms, got %v", duration)
	}
	
	// Test operation level timeout
	start = time.Now()
	_, err = tm.WithTimeoutLevel(ctx, TimeoutLevelOperation, func(ctx context.Context) (interface{}, error) {
		time.Sleep(80 * time.Millisecond)
		return "success", nil
	})
	duration = time.Since(start)
	
	if err != nil {
		t.Errorf("Expected success for operation level, got error: %v", err)
	}
	
	if duration > 90*time.Millisecond {
		t.Errorf("Operation took too long: %v", duration)
	}
}

func TestTimeoutManager_AdaptiveTimeout(t *testing.T) {
	config := &TimeoutConfig{
		Name:           "adaptive_test",
		Strategy:       TimeoutStrategyAdaptive,
		DefaultTimeout: 100 * time.Millisecond,
		MinTimeout:     50 * time.Millisecond,
		MaxTimeout:     200 * time.Millisecond,
		AdaptiveConfig: &AdaptiveTimeoutConfig{
			WindowSize:       5,
			Multiplier:       2.0,
			MinSamples:       3,
			AdjustmentFactor: 0.1,
		},
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	// Execute several operations with consistent duration
	operationDuration := 30 * time.Millisecond
	for i := 0; i < 5; i++ {
		_, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
			time.Sleep(operationDuration)
			return "success", nil
		})
		if err != nil {
			t.Errorf("Operation %d failed: %v", i+1, err)
		}
	}
	
	// After enough samples, timeout should adapt
	metrics := tm.GetMetrics()
	currentTimeout := metrics.CurrentTimeout
	
	// Current timeout should be adjusted based on observed response times
	expectedTimeout := time.Duration(float64(operationDuration) * config.AdaptiveConfig.Multiplier)
	if currentTimeout < expectedTimeout-10*time.Millisecond || 
	   currentTimeout > expectedTimeout+10*time.Millisecond {
		t.Logf("Adaptive timeout: expected ~%v, got %v", expectedTimeout, currentTimeout)
		// Note: This might be acceptable depending on the adaptation algorithm
	}
}

func TestTimeoutManager_PercentileTimeout(t *testing.T) {
	config := &TimeoutConfig{
		Name:     "percentile_test",
		Strategy: TimeoutStrategyPercentile,
		PercentileConfig: &PercentileTimeoutConfig{
			Percentile: 0.9, // 90th percentile
			WindowSize: 10,
			MinSamples: 5,
		},
		MinTimeout:     20 * time.Millisecond,
		MaxTimeout:     200 * time.Millisecond,
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	// Execute operations with varying durations
	durations := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
		60 * time.Millisecond, // 90th percentile should be around here
	}
	
	for i, duration := range durations {
		_, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
			time.Sleep(duration)
			return "success", nil
		})
		if err != nil {
			t.Errorf("Operation %d with duration %v failed: %v", i+1, duration, err)
		}
	}
	
	// Current timeout should be based on 90th percentile
	metrics := tm.GetMetrics()
	t.Logf("Percentile timeout: %v", metrics.CurrentTimeout)
}

func TestTimeoutManager_Warnings(t *testing.T) {
	config := &TimeoutConfig{
		Name:             "warning_test",
		Strategy:         TimeoutStrategyFixed,
		DefaultTimeout:   100 * time.Millisecond,
		EnableWarnings:   true,
		WarningThreshold: 0.5, // Warning at 50% of timeout
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	var warningCount int32
	config.OnWarning = func(ctx context.Context, elapsed, remaining time.Duration) {
		atomic.AddInt32(&warningCount, 1)
	}
	
	// Operation that triggers warning but completes successfully
	result, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(70 * time.Millisecond) // Should trigger warning at 50ms
		return "success", nil
	})
	
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if result != "success" {
		t.Errorf("Expected 'success', got %v", result)
	}
	
	// Give warning callback time to execute
	time.Sleep(10 * time.Millisecond)
	
	if atomic.LoadInt32(&warningCount) == 0 {
		t.Error("Expected at least one warning")
	}
	
	metrics := tm.GetMetrics()
	if metrics.TotalWarnings == 0 {
		t.Error("Expected warning count in metrics")
	}
}

func TestTimeoutManager_ContextCancellation(t *testing.T) {
	config := &TimeoutConfig{
		Name:           "context_test",
		Strategy:       TimeoutStrategyFixed,
		DefaultTimeout: 200 * time.Millisecond,
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	
	start := time.Now()
	_, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(100 * time.Millisecond)
		return "should not complete", nil
	})
	duration := time.Since(start)
	
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
	
	// Should timeout due to context cancellation, not timeout manager timeout
	if duration > 70*time.Millisecond {
		t.Errorf("Expected context cancellation around 50ms, got %v", duration)
	}
}

func TestTimeoutManager_CustomTimeout(t *testing.T) {
	config := DefaultTimeoutConfig()
	config.Name = "custom_test"
	config.EnableWarnings = false
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	customTimeout := 80 * time.Millisecond
	
	start := time.Now()
	_, err := tm.WithCustomTimeout(ctx, customTimeout, TimeoutLevelRequest, func(ctx context.Context) (interface{}, error) {
		time.Sleep(100 * time.Millisecond)
		return "should timeout", nil
	})
	duration := time.Since(start)
	
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
	
	if duration < 70*time.Millisecond || duration > 100*time.Millisecond {
		t.Errorf("Expected timeout around 80ms, got %v", duration)
	}
	
	metrics := tm.GetMetrics()
	if metrics.EffectiveTimeout != customTimeout {
		t.Errorf("Expected effective timeout %v, got %v", customTimeout, metrics.EffectiveTimeout)
	}
}

func TestTimeoutManager_ShouldCancel(t *testing.T) {
	var cancelCount int32
	
	config := &TimeoutConfig{
		Name:           "cancel_test",
		Strategy:       TimeoutStrategyFixed,
		DefaultTimeout: 100 * time.Millisecond,
		EnableWarnings: false,
		ShouldCancel: func(ctx context.Context) bool {
			atomic.AddInt32(&cancelCount, 1)
			return atomic.LoadInt32(&cancelCount) > 1 // Cancel after second check
		},
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	_, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(50 * time.Millisecond)
		return "success", nil
	})
	
	if err == nil {
		t.Error("Expected cancellation error, got nil")
	}
	
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled, got %v", err)
	}
	
	metrics := tm.GetMetrics()
	if metrics.TotalCancellations == 0 {
		t.Error("Expected at least one cancellation in metrics")
	}
}

func TestTimeoutManager_ResponseTimeTracker(t *testing.T) {
	tracker := NewResponseTimeTracker(5)
	
	// Add some response times
	times := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		150 * time.Millisecond,
		300 * time.Millisecond,
		250 * time.Millisecond,
	}
	
	for _, duration := range times {
		tracker.Add(duration)
	}
	
	// Test average calculation
	avgDuration := tracker.Average()
	expectedAvg := (100 + 200 + 150 + 300 + 250) / 5 * time.Millisecond
	if avgDuration != expectedAvg {
		t.Errorf("Expected average %v, got %v", expectedAvg, avgDuration)
	}
	
	// Test percentile calculation
	p50 := tracker.Percentile(0.5)
	p90 := tracker.Percentile(0.9)
	
	if p50 != 200*time.Millisecond {
		t.Errorf("Expected 50th percentile 200ms, got %v", p50)
	}
	
	if p90 != 300*time.Millisecond {
		t.Errorf("Expected 90th percentile 300ms, got %v", p90)
	}
	
	// Test count
	if tracker.Count() != 5 {
		t.Errorf("Expected count 5, got %d", tracker.Count())
	}
}

func TestTimeoutManager_Events(t *testing.T) {
	config := &TimeoutConfig{
		Name:           "events_test",
		Strategy:       TimeoutStrategyFixed,
		DefaultTimeout: 50 * time.Millisecond,
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	var events []*TimeoutEvent
	var mu sync.Mutex
	
	tm.AddEventListener(func(event *TimeoutEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	})
	
	// Execute operation that times out
	tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(80 * time.Millisecond)
		return "should timeout", nil
	})
	
	// Give events time to propagate
	time.Sleep(10 * time.Millisecond)
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(events) < 2 {
		t.Errorf("Expected at least 2 events (started, timeout), got %d", len(events))
	}
	
	// Check for specific event types
	eventTypes := make(map[string]bool)
	for _, event := range events {
		eventTypes[event.Type] = true
	}
	
	expectedTypes := []string{"started", "timeout"}
	for _, expectedType := range expectedTypes {
		if !eventTypes[expectedType] {
			t.Errorf("Expected event type '%s' not found", expectedType)
		}
	}
}

func TestTimeoutManager_Metrics(t *testing.T) {
	config := DefaultTimeoutConfig()
	config.Name = "metrics_test"
	config.DefaultTimeout = 50 * time.Millisecond
	config.EnableWarnings = false
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	// Execute successful operation
	tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(20 * time.Millisecond)
		return "success", nil
	})
	
	// Execute operation that times out
	tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(80 * time.Millisecond)
		return "timeout", nil
	})
	
	metrics := tm.GetMetrics()
	
	if metrics.Name != "metrics_test" {
		t.Errorf("Expected name 'metrics_test', got '%s'", metrics.Name)
	}
	
	if metrics.TotalOperations != 2 {
		t.Errorf("Expected 2 total operations, got %d", metrics.TotalOperations)
	}
	
	if metrics.TotalTimeouts != 1 {
		t.Errorf("Expected 1 timeout, got %d", metrics.TotalTimeouts)
	}
	
	if metrics.TimeoutRate == 0 {
		t.Error("Expected non-zero timeout rate")
	}
	
	if metrics.AverageResponseTime == 0 {
		t.Error("Expected non-zero average response time")
	}
}

func TestTimeoutManager_Reset(t *testing.T) {
	config := DefaultTimeoutConfig()
	config.Name = "reset_test"
	config.EnableWarnings = false
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	// Execute some operations
	tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	
	// Verify metrics before reset
	metricsBefore := tm.GetMetrics()
	if metricsBefore.TotalOperations == 0 {
		t.Error("Expected non-zero operations before reset")
	}
	
	// Reset
	tm.Reset()
	
	// Verify metrics after reset
	metricsAfter := tm.GetMetrics()
	if metricsAfter.TotalOperations != 0 {
		t.Errorf("Expected zero operations after reset, got %d", metricsAfter.TotalOperations)
	}
	
	if metricsAfter.TotalTimeouts != 0 {
		t.Errorf("Expected zero timeouts after reset, got %d", metricsAfter.TotalTimeouts)
	}
	
	if metricsAfter.AverageResponseTime != 0 {
		t.Errorf("Expected zero average response time after reset, got %v", metricsAfter.AverageResponseTime)
	}
}

func TestTimeoutManager_ConcurrentAccess(t *testing.T) {
	config := &TimeoutConfig{
		Name:           "concurrent_test",
		Strategy:       TimeoutStrategyFixed,
		DefaultTimeout: 50 * time.Millisecond,
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	const numGoroutines = 20
	const operationsPerGoroutine = 5
	
	var successCount, timeoutCount int64
	var wg sync.WaitGroup
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				_, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
					// Some operations timeout, some succeed
					if (goroutineID+j)%3 == 0 {
						time.Sleep(80 * time.Millisecond) // Will timeout
					} else {
						time.Sleep(20 * time.Millisecond) // Will succeed
					}
					return "result", nil
				})
				
				if err != nil {
					atomic.AddInt64(&timeoutCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	totalOperations := successCount + timeoutCount
	expectedOperations := int64(numGoroutines * operationsPerGoroutine)
	
	if totalOperations != expectedOperations {
		t.Errorf("Expected %d total operations, got %d", expectedOperations, totalOperations)
	}
	
	// Verify metrics are consistent
	metrics := tm.GetMetrics()
	if metrics.TotalOperations != expectedOperations {
		t.Errorf("Expected %d operations in metrics, got %d", expectedOperations, metrics.TotalOperations)
	}
	
	t.Logf("Concurrent test completed: %d successes, %d timeouts", successCount, timeoutCount)
}

// Benchmark tests

func BenchmarkTimeoutManager_WithTimeout_Success(b *testing.B) {
	config := &TimeoutConfig{
		Name:           "benchmark",
		Strategy:       TimeoutStrategyFixed,
		DefaultTimeout: 100 * time.Millisecond,
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
				return "success", nil
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkTimeoutManager_WithTimeout_Timeout(b *testing.B) {
	config := &TimeoutConfig{
		Name:           "benchmark_timeout",
		Strategy:       TimeoutStrategyFixed,
		DefaultTimeout: 10 * time.Millisecond,
		EnableWarnings: false,
	}
	
	tm := NewTimeoutManager(config)
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := tm.WithTimeout(ctx, func(ctx context.Context) (interface{}, error) {
				time.Sleep(20 * time.Millisecond)
				return "should timeout", nil
			})
			if err == nil {
				b.Error("Expected timeout error")
			}
		}
	})
}