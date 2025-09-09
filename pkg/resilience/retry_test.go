package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryExecutor_NewRetryExecutor(t *testing.T) {
	config := DefaultRetryConfig()
	config.Name = "test_retry"
	
	re := NewRetryExecutor(config)
	
	if re == nil {
		t.Fatal("Retry executor should not be nil")
	}
	
	if re.config.Name != "test_retry" {
		t.Errorf("Expected name 'test_retry', got '%s'", re.config.Name)
	}
	
	metrics := re.GetMetrics()
	if metrics.Name != "test_retry" {
		t.Errorf("Expected metrics name 'test_retry', got '%s'", metrics.Name)
	}
}

func TestRetryExecutor_ExponentialBackoff(t *testing.T) {
	config := &RetryConfig{
		Name:        "backoff_test",
		MaxAttempts: 4,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    1 * time.Second,
		Multiplier:  2.0,
		Policy:      RetryPolicyExponential,
		Jitter:      false, // Disable jitter for predictable delays
		IsRetryable: func(err error) bool {
			return err != nil && err.Error() == "retryable"
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	var attemptTimes []time.Time
	var mu sync.Mutex
	
	start := time.Now()
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		mu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		mu.Unlock()
		return nil, errors.New("retryable")
	})
	
	if err == nil {
		t.Error("Expected error after max attempts, got nil")
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(attemptTimes) != 4 {
		t.Errorf("Expected 4 attempts, got %d", len(attemptTimes))
	}
	
	// Verify exponential backoff delays (approximately)
	if len(attemptTimes) >= 2 {
		firstDelay := attemptTimes[1].Sub(attemptTimes[0])
		if firstDelay < 90*time.Millisecond || firstDelay > 110*time.Millisecond {
			t.Errorf("Expected first delay ~100ms, got %v", firstDelay)
		}
	}
	
	if len(attemptTimes) >= 3 {
		secondDelay := attemptTimes[2].Sub(attemptTimes[1])
		if secondDelay < 180*time.Millisecond || secondDelay > 220*time.Millisecond {
			t.Errorf("Expected second delay ~200ms, got %v", secondDelay)
		}
	}
	
	totalDuration := time.Since(start)
	expectedMinDuration := 100*time.Millisecond + 200*time.Millisecond + 400*time.Millisecond
	if totalDuration < expectedMinDuration {
		t.Errorf("Total duration %v is less than expected minimum %v", totalDuration, expectedMinDuration)
	}
}

func TestRetryExecutor_FixedDelay(t *testing.T) {
	config := &RetryConfig{
		Name:        "fixed_test",
		MaxAttempts: 3,
		BaseDelay:   50 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		Jitter:      false,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	var attemptTimes []time.Time
	var mu sync.Mutex
	
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		mu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		mu.Unlock()
		return nil, errors.New("test error")
	})
	
	if err == nil {
		t.Error("Expected error after max attempts, got nil")
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(attemptTimes) != 3 {
		t.Errorf("Expected 3 attempts, got %d", len(attemptTimes))
	}
	
	// Verify fixed delays
	for i := 1; i < len(attemptTimes); i++ {
		delay := attemptTimes[i].Sub(attemptTimes[i-1])
		if delay < 45*time.Millisecond || delay > 55*time.Millisecond {
			t.Errorf("Expected delay ~50ms, got %v for attempt %d", delay, i)
		}
	}
}

func TestRetryExecutor_Success(t *testing.T) {
	config := &RetryConfig{
		Name:        "success_test",
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	attemptCount := 0
	result, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		attemptCount++
		if attemptCount == 2 {
			return "success_result", nil
		}
		return nil, errors.New("retry_error")
	})
	
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if result != "success_result" {
		t.Errorf("Expected 'success_result', got %v", result)
	}
	
	if attemptCount != 2 {
		t.Errorf("Expected 2 attempts, got %d", attemptCount)
	}
	
	metrics := re.GetMetrics()
	if metrics.TotalSuccesses != 1 {
		t.Errorf("Expected 1 success, got %d", metrics.TotalSuccesses)
	}
	
	if metrics.TotalRetries != 1 {
		t.Errorf("Expected 1 retry, got %d", metrics.TotalRetries)
	}
}

func TestRetryExecutor_NonRetryableError(t *testing.T) {
	config := &RetryConfig{
		Name:        "non_retryable_test",
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err.Error() != "non_retryable"
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	attemptCount := 0
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		attemptCount++
		return nil, errors.New("non_retryable")
	})
	
	if err == nil {
		t.Error("Expected error, got nil")
	}
	
	if !errors.Is(err, ErrNotRetryable) {
		t.Errorf("Expected ErrNotRetryable, got %v", err)
	}
	
	if attemptCount != 1 {
		t.Errorf("Expected 1 attempt, got %d", attemptCount)
	}
	
	metrics := re.GetMetrics()
	if metrics.TotalRetries != 0 {
		t.Errorf("Expected 0 retries for non-retryable error, got %d", metrics.TotalRetries)
	}
}

func TestRetryExecutor_BudgetExceeded(t *testing.T) {
	config := &RetryConfig{
		Name:        "budget_test",
		MaxAttempts: 10,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    200 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		Budget:      250 * time.Millisecond, // Should allow ~2 retries
		Jitter:      false,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	attemptCount := 0
	start := time.Now()
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		attemptCount++
		return nil, errors.New("test error")
	})
	
	duration := time.Since(start)
	
	if err == nil {
		t.Error("Expected error, got nil")
	}
	
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("Expected ErrBudgetExceeded, got %v", err)
	}
	
	// Should have attempted at least once but not all 10 times
	if attemptCount == 0 {
		t.Error("Expected at least 1 attempt")
	}
	
	if attemptCount >= 10 {
		t.Errorf("Expected fewer than 10 attempts due to budget, got %d", attemptCount)
	}
	
	// Duration should be close to budget
	if duration > 400*time.Millisecond {
		t.Errorf("Duration %v exceeded reasonable budget bounds", duration)
	}
	
	metrics := re.GetMetrics()
	if metrics.TotalBudgetExceeded == 0 {
		t.Error("Expected budget exceeded count > 0")
	}
}

func TestRetryExecutor_ContextCancellation(t *testing.T) {
	config := &RetryConfig{
		Name:        "context_test",
		MaxAttempts: 5,
		BaseDelay:   50 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err != nil && !errors.Is(err, context.Canceled)
		},
	}
	
	re := NewRetryExecutor(config)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	
	attemptCount := 0
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		attemptCount++
		return nil, errors.New("test error")
	})
	
	if err == nil {
		t.Error("Expected error due to context cancellation, got nil")
	}
	
	if !errors.Is(err, ErrRetryContextCanceled) {
		t.Errorf("Expected ErrRetryContextCanceled, got %v", err)
	}
	
	// Should have made at least one attempt but not all 5
	if attemptCount == 0 {
		t.Error("Expected at least 1 attempt")
	}
	
	if attemptCount >= 5 {
		t.Errorf("Expected fewer than 5 attempts due to context cancellation, got %d", attemptCount)
	}
}

func TestRetryExecutor_LinearBackoff(t *testing.T) {
	config := &RetryConfig{
		Name:        "linear_test",
		MaxAttempts: 3,
		BaseDelay:   50 * time.Millisecond,
		Policy:      RetryPolicyLinear,
		Jitter:      false,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	var attemptTimes []time.Time
	var mu sync.Mutex
	
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		mu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		mu.Unlock()
		return nil, errors.New("test error")
	})
	
	if err == nil {
		t.Error("Expected error after max attempts, got nil")
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(attemptTimes) != 3 {
		t.Errorf("Expected 3 attempts, got %d", len(attemptTimes))
	}
	
	// Verify linear backoff: delays should be 50ms, 100ms
	if len(attemptTimes) >= 2 {
		firstDelay := attemptTimes[1].Sub(attemptTimes[0])
		if firstDelay < 45*time.Millisecond || firstDelay > 55*time.Millisecond {
			t.Errorf("Expected first delay ~50ms, got %v", firstDelay)
		}
	}
	
	if len(attemptTimes) >= 3 {
		secondDelay := attemptTimes[2].Sub(attemptTimes[1])
		if secondDelay < 95*time.Millisecond || secondDelay > 105*time.Millisecond {
			t.Errorf("Expected second delay ~100ms, got %v", secondDelay)
		}
	}
}

func TestRetryExecutor_CustomDelayFunction(t *testing.T) {
	config := &RetryConfig{
		Name:        "custom_test",
		MaxAttempts: 3,
		Policy:      RetryPolicyCustom,
		Jitter:      false,
		DelayFunc: func(attempt int) time.Duration {
			return time.Duration(attempt*attempt) * 20 * time.Millisecond // Quadratic backoff
		},
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	var attemptTimes []time.Time
	var mu sync.Mutex
	
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		mu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		mu.Unlock()
		return nil, errors.New("test error")
	})
	
	if err == nil {
		t.Error("Expected error after max attempts, got nil")
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(attemptTimes) != 3 {
		t.Errorf("Expected 3 attempts, got %d", len(attemptTimes))
	}
	
	// Verify custom quadratic delays: attempt 1 -> 20ms, attempt 2 -> 80ms
	if len(attemptTimes) >= 2 {
		firstDelay := attemptTimes[1].Sub(attemptTimes[0])
		if firstDelay < 15*time.Millisecond || firstDelay > 25*time.Millisecond {
			t.Errorf("Expected first delay ~20ms, got %v", firstDelay)
		}
	}
	
	if len(attemptTimes) >= 3 {
		secondDelay := attemptTimes[2].Sub(attemptTimes[1])
		if secondDelay < 75*time.Millisecond || secondDelay > 85*time.Millisecond {
			t.Errorf("Expected second delay ~80ms, got %v", secondDelay)
		}
	}
}

func TestRetryExecutor_Jitter(t *testing.T) {
	config := &RetryConfig{
		Name:        "jitter_test",
		MaxAttempts: 10,
		BaseDelay:   100 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		Jitter:      true,
		JitterRange: 0.5, // 50% jitter range
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	var delays []time.Duration
	var attemptTimes []time.Time
	var mu sync.Mutex
	
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		mu.Lock()
		attemptTimes = append(attemptTimes, time.Now())
		mu.Unlock()
		return nil, errors.New("test error")
	})
	
	if err == nil {
		t.Error("Expected error after max attempts, got nil")
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	// Calculate delays
	for i := 1; i < len(attemptTimes); i++ {
		delays = append(delays, attemptTimes[i].Sub(attemptTimes[i-1]))
	}
	
	if len(delays) < 2 {
		t.Error("Not enough delays to test jitter")
		return
	}
	
	// With jitter, delays should vary
	allSame := true
	firstDelay := delays[0]
	for _, delay := range delays[1:] {
		if delay != firstDelay {
			allSame = false
			break
		}
	}
	
	if allSame {
		t.Error("Expected delays to vary due to jitter, but they were all the same")
	}
	
	// All delays should be within reasonable bounds (50ms to 150ms with 50% jitter)
	for i, delay := range delays {
		if delay < 50*time.Millisecond || delay > 150*time.Millisecond {
			t.Errorf("Delay %d (%v) is outside expected jitter bounds", i, delay)
		}
	}
}

func TestRetryExecutor_Events(t *testing.T) {
	config := &RetryConfig{
		Name:        "events_test",
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	var events []*RetryEvent
	var mu sync.Mutex
	
	re.AddEventListener(func(event *RetryEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	})
	
	attemptCount := 0
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		attemptCount++
		if attemptCount == 2 {
			return "success", nil
		}
		return nil, errors.New("test error")
	})
	
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	// Give events time to propagate
	time.Sleep(20 * time.Millisecond)
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(events) < 2 {
		t.Errorf("Expected at least 2 events (started, retry, success), got %d", len(events))
	}
	
	// Check for specific event types
	eventTypes := make(map[string]bool)
	for _, event := range events {
		eventTypes[event.Type] = true
	}
	
	expectedTypes := []string{"started", "success"}
	for _, expectedType := range expectedTypes {
		if !eventTypes[expectedType] {
			t.Errorf("Expected event type '%s' not found", expectedType)
		}
	}
}

func TestRetryExecutor_Callbacks(t *testing.T) {
	var beforeRetryCount, afterRetryCount, onRetryCount int
	var mu sync.Mutex
	
	config := &RetryConfig{
		Name:        "callbacks_test",
		MaxAttempts: 3,
		BaseDelay:   5 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err != nil
		},
		BeforeRetry: func(ctx context.Context) error {
			mu.Lock()
			beforeRetryCount++
			mu.Unlock()
			return nil
		},
		AfterRetry: func(ctx context.Context, err error) {
			mu.Lock()
			afterRetryCount++
			mu.Unlock()
		},
		OnRetry: func(attempt int, err error) {
			mu.Lock()
			onRetryCount++
			mu.Unlock()
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	if err == nil {
		t.Error("Expected error after max attempts, got nil")
	}
	
	mu.Lock()
	defer mu.Unlock()
	
	if beforeRetryCount != 3 {
		t.Errorf("Expected 3 beforeRetry calls, got %d", beforeRetryCount)
	}
	
	if afterRetryCount != 3 {
		t.Errorf("Expected 3 afterRetry calls, got %d", afterRetryCount)
	}
	
	if onRetryCount != 2 { // Called only on actual retries, not the first attempt
		t.Errorf("Expected 2 onRetry calls, got %d", onRetryCount)
	}
}

func TestRetryExecutor_IdempotencyKey(t *testing.T) {
	config := &RetryConfig{
		Name:        "idempotency_test",
		MaxAttempts: 3,
		BaseDelay:   10 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	// Execute with idempotency key
	result, err := re.ExecuteWithIdempotencyKey(ctx, "test-key-123", func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if result != "success" {
		t.Errorf("Expected 'success', got %v", result)
	}
	
	metrics := re.GetMetrics()
	if metrics.TotalAttempts == 0 {
		t.Error("Expected non-zero attempts")
	}
}

func TestRetryExecutor_Reset(t *testing.T) {
	config := DefaultRetryConfig()
	config.Name = "reset_test"
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	// Execute some operations to generate metrics
	re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	
	re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	// Verify metrics before reset
	metricsBefore := re.GetMetrics()
	if metricsBefore.TotalAttempts == 0 {
		t.Error("Expected non-zero attempts before reset")
	}
	
	// Reset
	re.Reset()
	
	// Verify metrics after reset
	metricsAfter := re.GetMetrics()
	if metricsAfter.TotalAttempts != 0 {
		t.Errorf("Expected zero attempts after reset, got %d", metricsAfter.TotalAttempts)
	}
	
	if metricsAfter.TotalSuccesses != 0 {
		t.Errorf("Expected zero successes after reset, got %d", metricsAfter.TotalSuccesses)
	}
	
	if metricsAfter.TotalFailures != 0 {
		t.Errorf("Expected zero failures after reset, got %d", metricsAfter.TotalFailures)
	}
}

func TestRetryExecutor_ConcurrentAccess(t *testing.T) {
	config := &RetryConfig{
		Name:        "concurrent_test",
		MaxAttempts: 3,
		BaseDelay:   1 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	const numGoroutines = 50
	const operationsPerGoroutine = 10
	
	var successCount, errorCount int64
	var wg sync.WaitGroup
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
					// Simulate 50% success rate
					if (goroutineID+j)%2 == 0 {
						return "success", nil
					}
					return nil, errors.New("simulated error")
				})
				
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	totalOperations := successCount + errorCount
	expectedOperations := int64(numGoroutines * operationsPerGoroutine)
	
	if totalOperations != expectedOperations {
		t.Errorf("Expected %d total operations, got %d", expectedOperations, totalOperations)
	}
	
	// Verify metrics are consistent
	metrics := re.GetMetrics()
	if metrics.TotalAttempts == 0 {
		t.Error("Expected non-zero total attempts after concurrent operations")
	}
	
	t.Logf("Concurrent test completed: %d successes, %d errors, total attempts: %d", 
		successCount, errorCount, metrics.TotalAttempts)
}

// Benchmark tests

func BenchmarkRetryExecutor_Success(b *testing.B) {
	config := &RetryConfig{
		Name:        "benchmark",
		MaxAttempts: 3,
		BaseDelay:   1 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				return "success", nil
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkRetryExecutor_WithRetries(b *testing.B) {
	config := &RetryConfig{
		Name:        "benchmark_retry",
		MaxAttempts: 3,
		BaseDelay:   1 * time.Millisecond,
		Policy:      RetryPolicyFixed,
		IsRetryable: func(err error) bool {
			return err != nil
		},
	}
	
	re := NewRetryExecutor(config)
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			attemptCount := 0
			_, err := re.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				attemptCount++
				if attemptCount == 2 { // Succeed on second attempt
					return "success", nil
				}
				return nil, errors.New("retry error")
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

// Convenience function tests

func TestWithExponentialBackoff(t *testing.T) {
	re := WithExponentialBackoff("test", 3, 10*time.Millisecond, 100*time.Millisecond)
	
	if re == nil {
		t.Fatal("Expected retry executor, got nil")
	}
	
	if re.config.Policy != RetryPolicyExponential {
		t.Errorf("Expected exponential policy, got %s", re.config.Policy)
	}
	
	if re.config.MaxAttempts != 3 {
		t.Errorf("Expected 3 max attempts, got %d", re.config.MaxAttempts)
	}
}

func TestWithFixedDelay(t *testing.T) {
	re := WithFixedDelay("test", 5, 50*time.Millisecond)
	
	if re == nil {
		t.Fatal("Expected retry executor, got nil")
	}
	
	if re.config.Policy != RetryPolicyFixed {
		t.Errorf("Expected fixed policy, got %s", re.config.Policy)
	}
	
	if re.config.MaxAttempts != 5 {
		t.Errorf("Expected 5 max attempts, got %d", re.config.MaxAttempts)
	}
	
	if re.config.BaseDelay != 50*time.Millisecond {
		t.Errorf("Expected 50ms base delay, got %v", re.config.BaseDelay)
	}
}

func TestWithCircuitBreaker(t *testing.T) {
	re := WithCircuitBreaker("test", 3, 10*time.Millisecond, 100*time.Millisecond)
	
	if re == nil {
		t.Fatal("Expected retry executor, got nil")
	}
	
	if !re.config.EnableCircuitBreaker {
		t.Error("Expected circuit breaker to be enabled")
	}
	
	if re.GetCircuitBreaker() == nil {
		t.Error("Expected circuit breaker instance, got nil")
	}
}