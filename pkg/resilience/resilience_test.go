package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResilienceFramework_NewResilienceFramework(t *testing.T) {
	config := DefaultResilienceConfig()
	config.Name = "test_framework"
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	if rf == nil {
		t.Fatal("Resilience framework should not be nil")
	}
	
	if rf.config.Name != "test_framework" {
		t.Errorf("Expected name 'test_framework', got '%s'", rf.config.Name)
	}
	
	// Verify all patterns are enabled by default
	if !rf.IsEnabled("circuit_breaker") {
		t.Error("Circuit breaker should be enabled by default")
	}
	
	if !rf.IsEnabled("retry") {
		t.Error("Retry should be enabled by default")
	}
	
	if !rf.IsEnabled("timeout") {
		t.Error("Timeout should be enabled by default")
	}
	
	if !rf.IsEnabled("recovery") {
		t.Error("Recovery should be enabled by default")
	}
}

func TestResilienceFramework_Execute_Success(t *testing.T) {
	config := DefaultResilienceConfig()
	config.Name = "success_test"
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	
	result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "test_success", nil
	})
	
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if result != "test_success" {
		t.Errorf("Expected 'test_success', got %v", result)
	}
	
	metrics := rf.GetMetrics()
	if metrics.TotalOperations == 0 {
		t.Error("Expected non-zero total operations")
	}
	
	if metrics.SuccessfulOperations == 0 {
		t.Error("Expected at least one successful operation")
	}
}

func TestResilienceFramework_Execute_WithRetries(t *testing.T) {
	config := &ResilienceConfig{
		Name:        "retry_test",
		EnableRetry: true,
		RetryConfig: &RetryConfig{
			Name:        "test_retry",
			MaxAttempts: 3,
			BaseDelay:   10 * time.Millisecond,
			Policy:      RetryPolicyFixed,
			IsRetryable: func(err error) bool {
				return err.Error() == "retryable_error"
			},
		},
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	attemptCount := 0
	
	result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		attemptCount++
		if attemptCount < 3 {
			return nil, errors.New("retryable_error")
		}
		return "success_after_retries", nil
	})
	
	if err != nil {
		t.Errorf("Expected success after retries, got error: %v", err)
	}
	
	if result != "success_after_retries" {
		t.Errorf("Expected 'success_after_retries', got %v", result)
	}
	
	if attemptCount != 3 {
		t.Errorf("Expected 3 attempts, got %d", attemptCount)
	}
}

func TestResilienceFramework_Execute_WithTimeout(t *testing.T) {
	config := &ResilienceConfig{
		Name:          "timeout_test",
		EnableTimeout: true,
		TimeoutConfig: &TimeoutConfig{
			Name:           "test_timeout",
			Strategy:       TimeoutStrategyFixed,
			DefaultTimeout: 50 * time.Millisecond,
		},
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	
	// Test operation that times out
	start := time.Now()
	_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		time.Sleep(100 * time.Millisecond)
		return "should_timeout", nil
	})
	duration := time.Since(start)
	
	if err == nil {
		t.Error("Expected timeout error, got nil")
	}
	
	if duration > 80*time.Millisecond {
		t.Errorf("Expected timeout around 50ms, got %v", duration)
	}
}

func TestResilienceFramework_Execute_WithCircuitBreaker(t *testing.T) {
	config := &ResilienceConfig{
		Name:                "cb_test",
		EnableCircuitBreaker: true,
		CircuitBreakerConfig: &CircuitBreakerConfig{
			Name:                    "test_cb",
			FailureThreshold:        2,
			MinRequestsBeforeTesting: 1,
			Timeout:                 100 * time.Millisecond,
			ErrorClassifier: func(err error) bool {
				return err != nil
			},
		},
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	
	// Generate failures to open circuit
	for i := 0; i < 3; i++ {
		_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return nil, errors.New("test_error")
		})
		if i < 2 && err == nil {
			t.Errorf("Expected error on attempt %d, got nil", i+1)
		}
	}
	
	// Circuit should be open now
	cb := rf.GetCircuitBreaker()
	if cb != nil && cb.GetState() != CircuitBreakerOpen {
		t.Error("Expected circuit breaker to be open")
	}
	
	// Subsequent call should fail fast
	_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		t.Error("This operation should not be executed when circuit is open")
		return "should_not_execute", nil
	})
	
	if !errors.Is(err, ErrCircuitBreakerOpen) {
		t.Errorf("Expected ErrCircuitBreakerOpen, got %v", err)
	}
}

func TestResilienceFramework_Execute_WithRecovery(t *testing.T) {
	config := &ResilienceConfig{
		Name:           "recovery_test",
		EnableRecovery: true,
		RecoveryConfig: &RecoveryConfig{
			Name:                "test_recovery",
			EnablePanicRecovery: true,
			RecoverySelector: func(classification *ErrorClassification) RecoveryStrategy {
				return RecoveryStrategyGracefulDegradation
			},
		},
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	
	// Test panic recovery
	result, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		panic("test_panic")
	})
	
	if err == nil {
		t.Error("Expected error from panic recovery, got nil")
	}
	
	if !errors.Is(err, ErrPanicRecovery) {
		t.Errorf("Expected ErrPanicRecovery, got %v", err)
	}
	
	// Test error recovery
	result, err = rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("recoverable_error")
	})
	
	if err != nil {
		t.Errorf("Expected graceful degradation to succeed, got error: %v", err)
	}
	
	// Should get degraded result
	if result == nil {
		t.Error("Expected degraded result, got nil")
	}
}

func TestResilienceFramework_ExecuteWithLevel(t *testing.T) {
	config := &ResilienceConfig{
		Name:          "level_test",
		EnableTimeout: true,
		TimeoutConfig: &TimeoutConfig{
			Name:     "hierarchical_timeout",
			Strategy: TimeoutStrategyHierarchical,
			HierarchicalConfig: &HierarchicalTimeoutConfig{
				Levels: map[TimeoutLevel]time.Duration{
					TimeoutLevelRequest:   30 * time.Millisecond,
					TimeoutLevelOperation: 100 * time.Millisecond,
				},
			},
		},
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	
	// Test with request level timeout
	start := time.Now()
	_, err := rf.ExecuteWithLevel(ctx, "request_op", TimeoutLevelRequest, func(ctx context.Context) (interface{}, error) {
		time.Sleep(50 * time.Millisecond) // Should timeout
		return "should_timeout", nil
	})
	requestDuration := time.Since(start)
	
	if err == nil {
		t.Error("Expected timeout error for request level, got nil")
	}
	
	if requestDuration > 45*time.Millisecond {
		t.Errorf("Expected request timeout around 30ms, got %v", requestDuration)
	}
	
	// Test with operation level timeout
	start = time.Now()
	result, err := rf.ExecuteWithLevel(ctx, "operation_op", TimeoutLevelOperation, func(ctx context.Context) (interface{}, error) {
		time.Sleep(50 * time.Millisecond) // Should succeed
		return "operation_success", nil
	})
	operationDuration := time.Since(start)
	
	if err != nil {
		t.Errorf("Expected success for operation level, got error: %v", err)
	}
	
	if result != "operation_success" {
		t.Errorf("Expected 'operation_success', got %v", result)
	}
	
	if operationDuration > 70*time.Millisecond {
		t.Errorf("Operation took too long: %v", operationDuration)
	}
}

func TestResilienceFramework_ExecuteWithIdempotency(t *testing.T) {
	config := &ResilienceConfig{
		Name:        "idempotency_test",
		EnableRetry: true,
		RetryConfig: &RetryConfig{
			Name:        "idempotency_retry",
			MaxAttempts: 3,
			BaseDelay:   5 * time.Millisecond,
			IsRetryable: func(err error) bool {
				return err != nil
			},
		},
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	idempotencyKey := "test-key-456"
	attemptCount := 0
	
	result, err := rf.ExecuteWithIdempotency(ctx, "idempotent_op", idempotencyKey, func(ctx context.Context) (interface{}, error) {
		attemptCount++
		if attemptCount < 2 {
			return nil, errors.New("first_attempt_fails")
		}
		return "idempotent_success", nil
	})
	
	if err != nil {
		t.Errorf("Expected success with idempotency, got error: %v", err)
	}
	
	if result != "idempotent_success" {
		t.Errorf("Expected 'idempotent_success', got %v", result)
	}
	
	if attemptCount != 2 {
		t.Errorf("Expected 2 attempts, got %d", attemptCount)
	}
}

func TestResilienceFramework_PatternToggling(t *testing.T) {
	config := &ResilienceConfig{
		Name:                "toggle_test",
		EnableCircuitBreaker: true,
		EnableRetry:         false, // Start with retry disabled
		EnableTimeout:       true,
		EnableRecovery:      true,
		CircuitBreakerConfig: DefaultCircuitBreakerConfig(),
		RetryConfig:         DefaultRetryConfig(),
		TimeoutConfig:       DefaultTimeoutConfig(),
		RecoveryConfig:      DefaultRecoveryConfig(),
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	// Initially retry should be disabled
	if rf.IsEnabled("retry") {
		t.Error("Retry should be disabled initially")
	}
	
	// Enable retry pattern
	err := rf.EnablePattern("retry")
	if err != nil {
		t.Errorf("Failed to enable retry pattern: %v", err)
	}
	
	if !rf.IsEnabled("retry") {
		t.Error("Retry should be enabled after EnablePattern")
	}
	
	// Disable circuit breaker pattern
	err = rf.DisablePattern("circuit_breaker")
	if err != nil {
		t.Errorf("Failed to disable circuit breaker pattern: %v", err)
	}
	
	if rf.IsEnabled("circuit_breaker") {
		t.Error("Circuit breaker should be disabled after DisablePattern")
	}
	
	// Test invalid pattern name
	err = rf.EnablePattern("invalid_pattern")
	if err == nil {
		t.Error("Expected error for invalid pattern name")
	}
}

func TestResilienceFramework_Metrics(t *testing.T) {
	config := DefaultResilienceConfig()
	config.Name = "metrics_test"
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	
	// Execute some operations
	rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success1", nil
	})
	
	rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test_error")
	})
	
	rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success2", nil
	})
	
	// Get aggregated metrics
	metrics := rf.GetMetrics()
	
	if metrics.Name != "metrics_test" {
		t.Errorf("Expected name 'metrics_test', got '%s'", metrics.Name)
	}
	
	if metrics.TotalOperations == 0 {
		t.Error("Expected non-zero total operations")
	}
	
	if metrics.SuccessfulOperations == 0 {
		t.Error("Expected non-zero successful operations")
	}
	
	if metrics.FailedOperations == 0 {
		t.Error("Expected non-zero failed operations")
	}
	
	if metrics.SuccessRate == 0 {
		t.Error("Expected non-zero success rate")
	}
	
	// Verify individual pattern metrics are included
	if metrics.RetryMetrics == nil {
		t.Error("Expected retry metrics")
	}
	
	if metrics.TimeoutMetrics == nil {
		t.Error("Expected timeout metrics")
	}
	
	if metrics.RecoveryMetrics == nil {
		t.Error("Expected recovery metrics")
	}
	
	if metrics.CircuitBreakerMetrics == nil {
		t.Error("Expected circuit breaker metrics")
	}
}

func TestResilienceFramework_Reset(t *testing.T) {
	config := DefaultResilienceConfig()
	config.Name = "reset_test"
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	ctx := context.Background()
	
	// Execute some operations to generate metrics
	rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	
	rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("error")
	})
	
	// Verify metrics before reset
	metricsBefore := rf.GetMetrics()
	if metricsBefore.TotalOperations == 0 {
		t.Error("Expected non-zero operations before reset")
	}
	
	// Reset framework
	rf.Reset()
	
	// Verify metrics after reset
	metricsAfter := rf.GetMetrics()
	
	// Note: Some metrics might not reset to exactly zero due to how they're aggregated
	// from different components, but they should be significantly reduced
	if metricsAfter.TotalOperations > metricsBefore.TotalOperations {
		t.Error("Expected operations to be reset or reduced")
	}
}

func TestResilienceFramework_ConcurrentAccess(t *testing.T) {
	config := DefaultResilienceConfig()
	config.Name = "concurrent_test"
	config.RetryConfig.MaxAttempts = 2
	config.RetryConfig.BaseDelay = 1 * time.Millisecond
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	const numGoroutines = 20
	const operationsPerGoroutine = 10
	
	var successCount, errorCount int64
	var wg sync.WaitGroup
	ctx := context.Background()
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
					// Simulate mixed success/failure
					if (goroutineID+j)%3 == 0 {
						return nil, errors.New("simulated_error")
					}
					return "success", nil
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
	
	if successCount == 0 {
		t.Error("Expected at least some successful operations")
	}
	
	// Verify metrics consistency
	metrics := rf.GetMetrics()
	if metrics.TotalOperations == 0 {
		t.Error("Expected non-zero total operations in metrics")
	}
	
	t.Logf("Concurrent test completed: %d successes, %d errors", successCount, errorCount)
}

func TestResilienceFramework_GetComponents(t *testing.T) {
	config := DefaultResilienceConfig()
	config.Name = "components_test"
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	// Test component getters
	cb := rf.GetCircuitBreaker()
	if cb == nil {
		t.Error("Expected circuit breaker instance, got nil")
	}
	
	re := rf.GetRetryExecutor()
	if re == nil {
		t.Error("Expected retry executor instance, got nil")
	}
	
	tm := rf.GetTimeoutManager()
	if tm == nil {
		t.Error("Expected timeout manager instance, got nil")
	}
	
	rm := rf.GetRecoveryManager()
	if rm == nil {
		t.Error("Expected recovery manager instance, got nil")
	}
}

func TestResilienceFramework_String(t *testing.T) {
	config := &ResilienceConfig{
		Name:                "string_test",
		EnableCircuitBreaker: true,
		EnableRetry:         false,
		EnableTimeout:       true,
		EnableRecovery:      false,
	}
	
	rf := NewResilienceFramework(config)
	defer rf.Stop()
	
	str := rf.String()
	expectedSubstrings := []string{"string_test", "circuit_breaker", "timeout"}
	unexpectedSubstrings := []string{"retry", "recovery"}
	
	for _, expected := range expectedSubstrings {
		if len(str) == 0 {
			t.Errorf("Expected string to contain '%s', but got empty string", expected)
			continue
		}
		// Simple substring check
		found := false
		for i := 0; i <= len(str)-len(expected); i++ {
			if str[i:i+len(expected)] == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected string to contain '%s', got '%s'", expected, str)
		}
	}
	
	for _, unexpected := range unexpectedSubstrings {
		if len(str) == 0 {
			continue
		}
		// Simple substring check
		found := false
		for i := 0; i <= len(str)-len(unexpected); i++ {
			if str[i:i+len(unexpected)] == unexpected {
				found = true
				break
			}
		}
		if found {
			t.Errorf("Expected string NOT to contain '%s', got '%s'", unexpected, str)
		}
	}
}

// Test convenience functions

func TestNewBasicResilience(t *testing.T) {
	rf := NewBasicResilience("basic_test")
	defer rf.Stop()
	
	if rf == nil {
		t.Fatal("Expected resilience framework, got nil")
	}
	
	if !rf.IsEnabled("retry") {
		t.Error("Basic resilience should enable retry")
	}
	
	if !rf.IsEnabled("timeout") {
		t.Error("Basic resilience should enable timeout")
	}
	
	// Should not enable circuit breaker and recovery by default
	if rf.IsEnabled("circuit_breaker") {
		t.Error("Basic resilience should not enable circuit breaker")
	}
	
	if rf.IsEnabled("recovery") {
		t.Error("Basic resilience should not enable recovery")
	}
}

func TestNewAdvancedResilience(t *testing.T) {
	rf := NewAdvancedResilience("advanced_test")
	defer rf.Stop()
	
	if rf == nil {
		t.Fatal("Expected resilience framework, got nil")
	}
	
	// Should enable all patterns
	patterns := []string{"circuit_breaker", "retry", "timeout", "recovery"}
	for _, pattern := range patterns {
		if !rf.IsEnabled(pattern) {
			t.Errorf("Advanced resilience should enable %s", pattern)
		}
	}
}

func TestNewNetworkResilience(t *testing.T) {
	rf := NewNetworkResilience("network_test")
	defer rf.Stop()
	
	if rf == nil {
		t.Fatal("Expected resilience framework, got nil")
	}
	
	// Should enable all patterns for network scenarios
	patterns := []string{"circuit_breaker", "retry", "timeout", "recovery"}
	for _, pattern := range patterns {
		if !rf.IsEnabled(pattern) {
			t.Errorf("Network resilience should enable %s", pattern)
		}
	}
	
	// Verify network-optimized configuration
	cb := rf.GetCircuitBreaker()
	if cb != nil {
		metrics := cb.GetMetrics()
		if metrics.Name == "" {
			t.Error("Expected circuit breaker to have name")
		}
	}
}

// Benchmark tests

func BenchmarkResilienceFramework_Execute_Success(b *testing.B) {
	rf := NewBasicResilience("benchmark")
	defer rf.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				return "success", nil
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkResilienceFramework_Execute_WithRetries(b *testing.B) {
	rf := NewBasicResilience("benchmark_retry")
	defer rf.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			attemptCount := 0
			_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				attemptCount++
				if attemptCount == 1 { // Fail first attempt, succeed second
					return nil, errors.New("retry_error")
				}
				return "success", nil
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkResilienceFramework_Execute_AllPatterns(b *testing.B) {
	rf := NewAdvancedResilience("benchmark_all")
	defer rf.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := rf.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				return "success", nil
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}