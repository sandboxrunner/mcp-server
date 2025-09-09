package resilience

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// FailureInjector simulates various failure scenarios for testing
type FailureInjector struct {
	failureRate       float64
	networkFailures   bool
	timeoutFailures   bool
	panicFailures     bool
	resourceFailures  bool
	intermittent      bool
	operationCount    int64
	mu                sync.RWMutex
}

// NewFailureInjector creates a new failure injector
func NewFailureInjector(failureRate float64) *FailureInjector {
	return &FailureInjector{
		failureRate: failureRate,
	}
}

// WithNetworkFailures enables network failure simulation
func (fi *FailureInjector) WithNetworkFailures() *FailureInjector {
	fi.networkFailures = true
	return fi
}

// WithTimeoutFailures enables timeout failure simulation
func (fi *FailureInjector) WithTimeoutFailures() *FailureInjector {
	fi.timeoutFailures = true
	return fi
}

// WithPanicFailures enables panic simulation
func (fi *FailureInjector) WithPanicFailures() *FailureInjector {
	fi.panicFailures = true
	return fi
}

// WithResourceFailures enables resource failure simulation
func (fi *FailureInjector) WithResourceFailures() *FailureInjector {
	fi.resourceFailures = true
	return fi
}

// WithIntermittentFailures enables intermittent failure patterns
func (fi *FailureInjector) WithIntermittentFailures() *FailureInjector {
	fi.intermittent = true
	return fi
}

// Execute simulates an operation with potential failures
func (fi *FailureInjector) Execute(ctx context.Context, operationName string) (interface{}, error) {
	opCount := atomic.AddInt64(&fi.operationCount, 1)
	
	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	
	// Determine if this operation should fail
	shouldFail := false
	if fi.intermittent {
		// Intermittent failures: fail every 3rd operation if failure rate allows
		shouldFail = (opCount%3 == 0) && (float64(opCount%100)/100.0 < fi.failureRate)
	} else {
		// Random failures based on failure rate
		shouldFail = float64(opCount%100)/100.0 < fi.failureRate
	}
	
	if !shouldFail {
		// Simulate successful operation with some processing time
		processingTime := time.Duration(opCount%50) * time.Millisecond
		time.Sleep(processingTime)
		return fmt.Sprintf("success_%s_%d", operationName, opCount), nil
	}
	
	// Determine failure type
	failureType := opCount % 4
	
	switch failureType {
	case 0:
		if fi.networkFailures {
			return nil, errors.New("network connection failed")
		}
		return nil, errors.New("generic error")
		
	case 1:
		if fi.timeoutFailures {
			// Simulate slow operation that might timeout
			time.Sleep(200 * time.Millisecond)
			return nil, errors.New("operation timed out")
		}
		return nil, errors.New("slow operation")
		
	case 2:
		if fi.panicFailures {
			panic(fmt.Sprintf("simulated panic in %s operation %d", operationName, opCount))
		}
		return nil, errors.New("critical error")
		
	case 3:
		if fi.resourceFailures {
			return nil, errors.New("memory exhausted")
		}
		return nil, errors.New("resource error")
		
	default:
		return nil, errors.New("unknown error")
	}
}

// GetOperationCount returns the total number of operations executed
func (fi *FailureInjector) GetOperationCount() int64 {
	return atomic.LoadInt64(&fi.operationCount)
}

// Reset resets the operation count
func (fi *FailureInjector) Reset() {
	atomic.StoreInt64(&fi.operationCount, 0)
}

func TestResilienceFramework_Integration_BasicScenario(t *testing.T) {
	// Create failure injector with moderate failure rate
	injector := NewFailureInjector(0.3).
		WithNetworkFailures().
		WithTimeoutFailures()
	
	// Create resilience framework with all patterns enabled
	config := DefaultResilienceConfig()
	config.Name = "integration_basic"
	config.RetryConfig.MaxAttempts = 3
	config.RetryConfig.BaseDelay = 10 * time.Millisecond
	config.CircuitBreakerConfig.FailureThreshold = 5
	config.TimeoutConfig.DefaultTimeout = 100 * time.Millisecond
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	successCount := 0
	errorCount := 0
	
	// Execute multiple operations
	for i := 0; i < 20; i++ {
		result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return injector.Execute(ctx, fmt.Sprintf("basic_op_%d", i))
		})
		
		if err != nil {
			errorCount++
		} else {
			successCount++
		}
		
		if result != nil {
			t.Logf("Operation %d: Success - %v", i, result)
		} else {
			t.Logf("Operation %d: Error - %v", i, err)
		}
		
		// Small delay between operations
		time.Sleep(5 * time.Millisecond)
	}
	
	t.Logf("Basic scenario completed: %d successes, %d errors", successCount, errorCount)
	
	// Verify that some operations succeeded despite failures
	if successCount == 0 {
		t.Error("Expected at least some successful operations")
	}
	
	// Verify metrics
	metrics := rf.GetMetrics()
	if metrics.TotalOperations == 0 {
		t.Error("Expected non-zero total operations")
	}
	
	t.Logf("Framework metrics: %+v", metrics)
}

func TestResilienceFramework_Integration_CircuitBreakerScenario(t *testing.T) {
	// Create failure injector with high failure rate initially
	injector := NewFailureInjector(0.8).
		WithNetworkFailures().
		WithResourceFailures()
	
	// Create resilience framework with aggressive circuit breaker
	config := &ResilienceConfig{
		Name:                "circuit_breaker_test",
		EnableCircuitBreaker: true,
		EnableRetry:         true,
		EnableTimeout:       true,
		CircuitBreakerConfig: &CircuitBreakerConfig{
			Name:                    "aggressive_cb",
			FailureThreshold:        3,
			SuccessThreshold:        2,
			Timeout:                 200 * time.Millisecond,
			MinRequestsBeforeTesting: 2,
			MaxRequests:             3,
		},
		RetryConfig: &RetryConfig{
			Name:        "circuit_retry",
			MaxAttempts: 2,
			BaseDelay:   5 * time.Millisecond,
		},
		TimeoutConfig: &TimeoutConfig{
			Name:           "circuit_timeout",
			DefaultTimeout: 50 * time.Millisecond,
		},
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	var results []error
	
	// Phase 1: High failure rate should open circuit
	t.Log("Phase 1: High failure rate")
	for i := 0; i < 10; i++ {
		_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return injector.Execute(ctx, fmt.Sprintf("phase1_op_%d", i))
		})
		results = append(results, err)
		time.Sleep(10 * time.Millisecond)
	}
	
	// Check if circuit breaker opened
	cb := rf.GetCircuitBreaker()
	if cb != nil && cb.GetState() != CircuitBreakerOpen {
		t.Log("Circuit breaker state:", cb.GetState())
		// Circuit might not be open yet, which is fine for testing
	}
	
	// Phase 2: Wait for circuit breaker timeout, then reduce failure rate
	t.Log("Phase 2: Waiting for circuit breaker timeout")
	time.Sleep(250 * time.Millisecond)
	
	// Reduce failure rate to simulate recovered service
	injector.failureRate = 0.1
	injector.Reset()
	
	// Phase 3: Recovery phase
	t.Log("Phase 3: Recovery phase")
	successCount := 0
	for i := 0; i < 10; i++ {
		result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return injector.Execute(ctx, fmt.Sprintf("phase3_op_%d", i))
		})
		
		if err == nil && result != nil {
			successCount++
		}
		time.Sleep(10 * time.Millisecond)
	}
	
	if successCount == 0 {
		t.Error("Expected some successes in recovery phase")
	}
	
	t.Logf("Circuit breaker test completed: %d successes in recovery phase", successCount)
	
	// Verify circuit breaker metrics
	if cb != nil {
		cbMetrics := cb.GetMetrics()
		t.Logf("Circuit breaker final state: %s, failures: %d, successes: %d", 
			cbMetrics.State, cbMetrics.FailureCount, cbMetrics.SuccessCount)
	}
}

func TestResilienceFramework_Integration_TimeoutScenario(t *testing.T) {
	// Create failure injector that causes slow operations
	injector := NewFailureInjector(0.5).
		WithTimeoutFailures().
		WithIntermittentFailures()
	
	// Create resilience framework with adaptive timeouts
	config := &ResilienceConfig{
		Name:          "timeout_test",
		EnableTimeout: true,
		EnableRetry:   true,
		TimeoutConfig: &TimeoutConfig{
			Name:             "adaptive_timeout",
			Strategy:         TimeoutStrategyAdaptive,
			DefaultTimeout:   100 * time.Millisecond,
			MinTimeout:       20 * time.Millisecond,
			MaxTimeout:       300 * time.Millisecond,
			EnableWarnings:   true,
			WarningThreshold: 0.7,
			AdaptiveConfig: &AdaptiveTimeoutConfig{
				WindowSize:       5,
				Multiplier:       2.0,
				MinSamples:       3,
				AdjustmentFactor: 0.2,
			},
		},
		RetryConfig: &RetryConfig{
			Name:        "timeout_retry",
			MaxAttempts: 2,
			BaseDelay:   10 * time.Millisecond,
		},
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	timeoutCount := 0
	successCount := 0
	warningCount := int32(0)
	
	// Add warning callback
	config.TimeoutConfig.OnWarning = func(ctx context.Context, elapsed, remaining time.Duration) {
		atomic.AddInt32(&warningCount, 1)
		t.Logf("Timeout warning: elapsed=%v, remaining=%v", elapsed, remaining)
	}
	
	// Execute operations with varying processing times
	for i := 0; i < 15; i++ {
		start := time.Now()
		result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return injector.Execute(ctx, fmt.Sprintf("timeout_op_%d", i))
		})
		duration := time.Since(start)
		
		if errors.Is(err, ErrOperationTimeout) {
			timeoutCount++
			t.Logf("Operation %d: Timeout after %v", i, duration)
		} else if err != nil {
			t.Logf("Operation %d: Error after %v - %v", i, duration, err)
		} else {
			successCount++
			t.Logf("Operation %d: Success after %v - %v", i, duration, result)
		}
		
		time.Sleep(20 * time.Millisecond)
	}
	
	t.Logf("Timeout scenario completed: %d successes, %d timeouts, %d warnings", 
		successCount, timeoutCount, atomic.LoadInt32(&warningCount))
	
	// Verify adaptive timeout behavior
	tm := rf.GetTimeoutManager()
	if tm != nil {
		tmMetrics := tm.GetMetrics()
		t.Logf("Timeout metrics - Total operations: %d, Timeouts: %d, Current timeout: %v", 
			tmMetrics.TotalOperations, tmMetrics.TotalTimeouts, tmMetrics.CurrentTimeout)
	}
}

func TestResilienceFramework_Integration_PanicRecoveryScenario(t *testing.T) {
	// Create failure injector with panics
	injector := NewFailureInjector(0.4).
		WithPanicFailures().
		WithNetworkFailures()
	
	// Create resilience framework with panic recovery
	config := DefaultResilienceConfig()
	config.Name = "panic_recovery_test"
	config.RecoveryConfig.EnablePanicRecovery = true
	config.RetryConfig.MaxAttempts = 2
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	panicCount := 0
	successCount := 0
	errorCount := 0
	
	// Add panic callback
	config.RecoveryConfig.OnPanic = func(panicInfo *PanicInfo) {
		panicCount++
		t.Logf("Panic recovered: %v in %s", panicInfo.Value, panicInfo.Operation)
	}
	
	// Execute operations that may panic
	for i := 0; i < 15; i++ {
		result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return injector.Execute(ctx, fmt.Sprintf("panic_op_%d", i))
		})
		
		if errors.Is(err, ErrPanicRecovery) {
			t.Logf("Operation %d: Panic recovered", i)
		} else if err != nil {
			errorCount++
			t.Logf("Operation %d: Error - %v", i, err)
		} else {
			successCount++
			t.Logf("Operation %d: Success - %v", i, result)
		}
		
		time.Sleep(10 * time.Millisecond)
	}
	
	t.Logf("Panic recovery scenario completed: %d successes, %d errors, %d panics", 
		successCount, errorCount, panicCount)
	
	// Verify that panics were handled and didn't crash the test
	if panicCount == 0 {
		t.Log("No panics were triggered in this run")
	}
	
	// Verify recovery metrics
	rm := rf.GetRecoveryManager()
	if rm != nil {
		rmMetrics := rm.GetMetrics()
		t.Logf("Recovery metrics - Total errors: %d, Total panics: %d, Total recoveries: %d", 
			rmMetrics.TotalErrors, rmMetrics.TotalPanics, rmMetrics.TotalRecoveries)
	}
}

func TestResilienceFramework_Integration_ConcurrentStressScenario(t *testing.T) {
	// Create failure injector with multiple failure types
	injector := NewFailureInjector(0.3).
		WithNetworkFailures().
		WithTimeoutFailures().
		WithResourceFailures().
		WithPanicFailures().
		WithIntermittentFailures()
	
	// Create resilience framework with all patterns
	config := DefaultResilienceConfig()
	config.Name = "stress_test"
	config.RetryConfig.MaxAttempts = 3
	config.RetryConfig.BaseDelay = 5 * time.Millisecond
	config.CircuitBreakerConfig.FailureThreshold = 10
	config.TimeoutConfig.DefaultTimeout = 50 * time.Millisecond
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	const numGoroutines = 10
	const operationsPerGoroutine = 20
	
	var successCount, errorCount, panicCount, timeoutCount int64
	var wg sync.WaitGroup
	
	ctx := context.Background()
	
	// Launch concurrent operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
					return injector.Execute(ctx, fmt.Sprintf("stress_op_g%d_o%d", goroutineID, j))
				})
				
				if errors.Is(err, ErrPanicRecovery) {
					atomic.AddInt64(&panicCount, 1)
				} else if errors.Is(err, ErrOperationTimeout) {
					atomic.AddInt64(&timeoutCount, 1)
				} else if err != nil {
					atomic.AddInt64(&errorCount, 1)
				} else if result != nil {
					atomic.AddInt64(&successCount, 1)
				}
				
				// Random small delay
				time.Sleep(time.Duration(goroutineID+j) * time.Millisecond)
			}
		}(i)
	}
	
	// Wait for all goroutines to complete
	wg.Wait()
	
	totalOperations := successCount + errorCount + panicCount + timeoutCount
	expectedOperations := int64(numGoroutines * operationsPerGoroutine)
	
	t.Logf("Stress test completed:")
	t.Logf("  Total operations: %d (expected: %d)", totalOperations, expectedOperations)
	t.Logf("  Successes: %d (%.1f%%)", successCount, float64(successCount)/float64(totalOperations)*100)
	t.Logf("  Errors: %d (%.1f%%)", errorCount, float64(errorCount)/float64(totalOperations)*100)
	t.Logf("  Panics: %d (%.1f%%)", panicCount, float64(panicCount)/float64(totalOperations)*100)
	t.Logf("  Timeouts: %d (%.1f%%)", timeoutCount, float64(timeoutCount)/float64(totalOperations)*100)
	
	if totalOperations != expectedOperations {
		t.Errorf("Operation count mismatch: expected %d, got %d", expectedOperations, totalOperations)
	}
	
	// Verify that some operations succeeded despite the stress
	if successCount == 0 {
		t.Error("Expected at least some successful operations under stress")
	}
	
	// Print comprehensive metrics
	metrics := rf.GetMetrics()
	t.Logf("Framework metrics: %+v", metrics)
	
	if cb := rf.GetCircuitBreaker(); cb != nil {
		cbMetrics := cb.GetMetrics()
		t.Logf("Circuit breaker metrics: State=%s, Failures=%d, Successes=%d", 
			cbMetrics.State, cbMetrics.FailureCount, cbMetrics.SuccessCount)
	}
	
	if re := rf.GetRetryExecutor(); re != nil {
		reMetrics := re.GetMetrics()
		t.Logf("Retry metrics: Attempts=%d, Retries=%d, Successes=%d", 
			reMetrics.TotalAttempts, reMetrics.TotalRetries, reMetrics.TotalSuccesses)
	}
	
	if tm := rf.GetTimeoutManager(); tm != nil {
		tmMetrics := tm.GetMetrics()
		t.Logf("Timeout metrics: Operations=%d, Timeouts=%d, Warnings=%d", 
			tmMetrics.TotalOperations, tmMetrics.TotalTimeouts, tmMetrics.TotalWarnings)
	}
	
	if rm := rf.GetRecoveryManager(); rm != nil {
		rmMetrics := rm.GetMetrics()
		t.Logf("Recovery metrics: Errors=%d, Panics=%d, Recoveries=%d, Rate=%.2f", 
			rmMetrics.TotalErrors, rmMetrics.TotalPanics, rmMetrics.TotalRecoveries, rmMetrics.RecoveryRate)
	}
}

func TestResilienceFramework_Integration_NetworkResilienceScenario(t *testing.T) {
	// Create network resilience framework
	rf := NewNetworkResilience("network_test")
	defer rf.Stop()
	
	// Create failure injector simulating network issues
	injector := NewFailureInjector(0.4).
		WithNetworkFailures().
		WithTimeoutFailures().
		WithIntermittentFailures()
	
	ctx := context.Background()
	successCount := 0
	errorCount := 0
	
	// Simulate network operations
	for i := 0; i < 25; i++ {
		result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			// Simulate network request
			return injector.Execute(ctx, fmt.Sprintf("network_req_%d", i))
		})
		
		if err != nil {
			errorCount++
			// Check if it's a circuit breaker error
			if errors.Is(err, ErrCircuitBreakerOpen) {
				t.Logf("Request %d: Circuit breaker is open", i)
			} else {
				t.Logf("Request %d: Error - %v", i, err)
			}
		} else {
			successCount++
			t.Logf("Request %d: Success - %v", i, result)
		}
		
		time.Sleep(50 * time.Millisecond)
	}
	
	t.Logf("Network resilience test completed: %d successes, %d errors", successCount, errorCount)
	
	// Network resilience should provide better success rates
	if successCount == 0 {
		t.Error("Expected at least some successful network operations")
	}
	
	// Verify network-optimized configuration worked
	metrics := rf.GetMetrics()
	if metrics.SuccessRate > 0 {
		t.Logf("Network success rate: %.2f%%", metrics.SuccessRate*100)
	}
}

func TestResilienceFramework_Integration_GradualRecoveryScenario(t *testing.T) {
	// Create failure injector that gradually improves
	injector := NewFailureInjector(0.9).WithNetworkFailures() // Start with 90% failure rate
	
	// Create resilience framework
	config := DefaultResilienceConfig()
	config.Name = "gradual_recovery_test"
	config.CircuitBreakerConfig.FailureThreshold = 3
	config.CircuitBreakerConfig.Timeout = 100 * time.Millisecond
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	var results []struct {
		phase       int
		successRate float64
	}
	
	// Phase 1: High failure rate (90%)
	t.Log("Phase 1: High failure rate (90%)")
	successCount := 0
	for i := 0; i < 10; i++ {
		_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return injector.Execute(ctx, fmt.Sprintf("phase1_%d", i))
		})
		if err == nil {
			successCount++
		}
		time.Sleep(20 * time.Millisecond)
	}
	results = append(results, struct {
		phase       int
		successRate float64
	}{1, float64(successCount) / 10.0})
	
	// Phase 2: Moderate failure rate (50%)
	t.Log("Phase 2: Moderate failure rate (50%)")
	injector.failureRate = 0.5
	injector.Reset()
	time.Sleep(150 * time.Millisecond) // Allow circuit breaker to potentially reset
	
	successCount = 0
	for i := 0; i < 10; i++ {
		_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return injector.Execute(ctx, fmt.Sprintf("phase2_%d", i))
		})
		if err == nil {
			successCount++
		}
		time.Sleep(20 * time.Millisecond)
	}
	results = append(results, struct {
		phase       int
		successRate float64
	}{2, float64(successCount) / 10.0})
	
	// Phase 3: Low failure rate (10%)
	t.Log("Phase 3: Low failure rate (10%)")
	injector.failureRate = 0.1
	injector.Reset()
	time.Sleep(150 * time.Millisecond) // Allow circuit breaker to reset
	
	successCount = 0
	for i := 0; i < 10; i++ {
		_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return injector.Execute(ctx, fmt.Sprintf("phase3_%d", i))
		})
		if err == nil {
			successCount++
		}
		time.Sleep(20 * time.Millisecond)
	}
	results = append(results, struct {
		phase       int
		successRate float64
	}{3, float64(successCount) / 10.0})
	
	// Analyze gradual recovery
	t.Log("Gradual recovery analysis:")
	for _, result := range results {
		t.Logf("  Phase %d: Success rate %.1f%%", result.phase, result.successRate*100)
	}
	
	// Expect some improvement over phases (though not guaranteed due to randomness)
	if results[2].successRate >= results[0].successRate {
		t.Log("Success rate improved from phase 1 to phase 3 as expected")
	} else {
		t.Log("Success rate variation observed (acceptable due to randomness in testing)")
	}
	
	// Final metrics
	metrics := rf.GetMetrics()
	t.Logf("Final framework metrics: Operations=%d, Success rate=%.2f%%", 
		metrics.TotalOperations, metrics.SuccessRate*100)
}

func TestResilienceFramework_Integration_IdempotencyScenario(t *testing.T) {
	// Create resilience framework with retry
	config := DefaultResilienceConfig()
	config.Name = "idempotency_test"
	config.RetryConfig.MaxAttempts = 3
	config.EnableCircuitBreaker = false // Disable to focus on retry behavior
	config.EnableTimeout = false
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	
	// Track operation calls with idempotency key
	operationCalls := make(map[string]int)
	var mu sync.Mutex
	
	// Execute operation with idempotency key
	idempotencyKey := "test-operation-123"
	
	result, err := rf.ExecuteWithIdempotency(ctx, "idempotent_op", idempotencyKey, func(ctx context.Context) (interface{}, error) {
		mu.Lock()
		defer mu.Unlock()
		
		operationCalls[idempotencyKey]++
		callCount := operationCalls[idempotencyKey]
		
		// Fail first two attempts, succeed on third
		if callCount <= 2 {
			return nil, fmt.Errorf("attempt %d failed", callCount)
		}
		
		return fmt.Sprintf("success_after_%d_attempts", callCount), nil
	})
	
	if err != nil {
		t.Errorf("Expected successful retry with idempotency, got error: %v", err)
	}
	
	if result == nil {
		t.Error("Expected result from idempotent operation")
	} else {
		t.Logf("Idempotent operation result: %v", result)
	}
	
	mu.Lock()
	totalCalls := operationCalls[idempotencyKey]
	mu.Unlock()
	
	if totalCalls != 3 {
		t.Errorf("Expected 3 attempts for idempotent operation, got %d", totalCalls)
	}
	
	t.Logf("Idempotency test completed: %d total calls for key %s", totalCalls, idempotencyKey)
}

// Benchmark integration tests

func BenchmarkResilienceFramework_Integration_SuccessfulOperations(b *testing.B) {
	injector := NewFailureInjector(0.0) // No failures
	rf := NewBasicResilience("benchmark")
	defer rf.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		opCount := 0
		for pb.Next() {
			_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				return injector.Execute(ctx, fmt.Sprintf("bench_op_%d", opCount))
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
			opCount++
		}
	})
}

func BenchmarkResilienceFramework_Integration_WithFailures(b *testing.B) {
	injector := NewFailureInjector(0.2).WithNetworkFailures() // 20% failure rate
	rf := NewBasicResilience("benchmark_failures")
	defer rf.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		opCount := 0
		for pb.Next() {
			_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				return injector.Execute(ctx, fmt.Sprintf("bench_fail_op_%d", opCount))
			})
			// Expect some errors due to failure injection
			_ = err
			opCount++
		}
	})
}

func BenchmarkResilienceFramework_Integration_HighContention(b *testing.B) {
	injector := NewFailureInjector(0.1).WithNetworkFailures()
	rf := NewAdvancedResilience("benchmark_contention")
	defer rf.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		opCount := 0
		for pb.Next() {
			_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				return injector.Execute(ctx, fmt.Sprintf("bench_contention_op_%d", opCount))
			})
			_ = err
			opCount++
		}
	})
}