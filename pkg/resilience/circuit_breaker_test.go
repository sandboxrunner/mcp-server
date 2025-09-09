package resilience

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCircuitBreaker_NewCircuitBreaker(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "test_circuit_breaker"
	
	cb := NewCircuitBreaker(config)
	
	if cb == nil {
		t.Fatal("Circuit breaker should not be nil")
	}
	
	if cb.config.Name != "test_circuit_breaker" {
		t.Errorf("Expected name 'test_circuit_breaker', got '%s'", cb.config.Name)
	}
	
	if cb.GetState() != CircuitBreakerClosed {
		t.Errorf("Circuit breaker should start in CLOSED state, got %s", cb.GetState())
	}
}

func TestCircuitBreaker_StateTransitions(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:                    "test_cb",
		MaxRequests:             2,
		FailureThreshold:        2,
		SuccessThreshold:        2,
		Timeout:                 100 * time.Millisecond,
		MinRequestsBeforeTesting: 1,
		ErrorClassifier: func(err error) bool {
			return err != nil
		},
	}
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	// Test CLOSED -> OPEN transition
	// First failure
	_, err := cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Circuit breaker should still be CLOSED after first failure")
	}
	
	// Second failure should open circuit
	_, err = cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit breaker should be OPEN after reaching failure threshold")
	}
	
	// Subsequent calls should fail fast
	_, err = cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		t.Error("Operation should not be executed when circuit is OPEN")
		return nil, nil
	})
	if !errors.Is(err, ErrCircuitBreakerOpen) {
		t.Errorf("Expected ErrCircuitBreakerOpen, got %v", err)
	}
	
	// Wait for timeout to transition to HALF_OPEN
	time.Sleep(150 * time.Millisecond)
	
	// First request should transition to HALF_OPEN
	_, err = cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	if err != nil {
		t.Errorf("Expected success in HALF_OPEN state, got %v", err)
	}
	if cb.GetState() != CircuitBreakerHalfOpen {
		t.Error("Circuit breaker should be HALF_OPEN after timeout")
	}
	
	// Second success should close circuit
	_, err = cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	if err != nil {
		t.Errorf("Expected success, got %v", err)
	}
	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Circuit breaker should be CLOSED after reaching success threshold")
	}
}

func TestCircuitBreaker_MaxRequestsInHalfOpen(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:                    "test_cb",
		MaxRequests:             2,
		FailureThreshold:        1,
		SuccessThreshold:        1,
		Timeout:                 50 * time.Millisecond,
		MinRequestsBeforeTesting: 1,
		ErrorClassifier: func(err error) bool {
			return err != nil
		},
	}
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	// Open the circuit
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit breaker should be OPEN")
	}
	
	// Wait for timeout
	time.Sleep(60 * time.Millisecond)
	
	// Execute max requests in HALF_OPEN state
	for i := 0; i < 2; i++ {
		_, err := cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			time.Sleep(10 * time.Millisecond) // Simulate work
			return "success", nil
		})
		if err != nil {
			t.Errorf("Request %d should succeed in HALF_OPEN state, got %v", i+1, err)
		}
	}
	
	// Third request should be rejected
	_, err := cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		t.Error("This request should not be executed")
		return "success", nil
	})
	if !errors.Is(err, ErrCircuitBreakerMaxRequests) {
		t.Errorf("Expected ErrCircuitBreakerMaxRequests, got %v", err)
	}
}

func TestCircuitBreaker_Metrics(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "metrics_test"
	config.FailureThreshold = 2
	config.MinRequestsBeforeTesting = 1
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	// Execute some operations
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	metrics := cb.GetMetrics()
	
	if metrics.Name != "metrics_test" {
		t.Errorf("Expected name 'metrics_test', got '%s'", metrics.Name)
	}
	
	if metrics.TotalRequests < 2 {
		t.Errorf("Expected at least 2 total requests, got %d", metrics.TotalRequests)
	}
	
	if metrics.SuccessCount != 1 {
		t.Errorf("Expected 1 success, got %d", metrics.SuccessCount)
	}
	
	if metrics.FailureCount != 1 {
		t.Errorf("Expected 1 failure, got %d", metrics.FailureCount)
	}
	
	if metrics.State != "CLOSED" {
		t.Errorf("Expected state CLOSED, got %s", metrics.State)
	}
}

func TestCircuitBreaker_Events(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "events_test"
	config.FailureThreshold = 1
	config.MinRequestsBeforeTesting = 1
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	var events []*CircuitBreakerEvent
	var mu sync.Mutex
	
	// Add event listener
	cb.AddEventListener(func(event *CircuitBreakerEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	})
	
	// Execute operations to trigger events
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	// Give events time to propagate
	time.Sleep(10 * time.Millisecond)
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(events) < 3 { // created, success, failure, state_change
		t.Errorf("Expected at least 3 events, got %d", len(events))
	}
	
	// Check for specific event types
	eventTypes := make(map[string]bool)
	for _, event := range events {
		eventTypes[event.Type] = true
	}
	
	expectedTypes := []string{"created", "success", "failure", "state_change"}
	for _, expectedType := range expectedTypes {
		if !eventTypes[expectedType] {
			t.Errorf("Expected event type '%s' not found", expectedType)
		}
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:                    "reset_test",
		FailureThreshold:        1,
		MinRequestsBeforeTesting: 1,
		ErrorClassifier: func(err error) bool {
			return err != nil
		},
	}
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	// Execute operation to generate metrics
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	// Verify metrics before reset
	metrics := cb.GetMetrics()
	if metrics.TotalRequests == 0 {
		t.Error("Expected non-zero total requests before reset")
	}
	
	// Reset circuit breaker
	cb.Reset()
	
	// Verify metrics after reset
	metricsAfter := cb.GetMetrics()
	if metricsAfter.TotalRequests != 0 {
		t.Errorf("Expected zero total requests after reset, got %d", metricsAfter.TotalRequests)
	}
	
	if metricsAfter.State != "CLOSED" {
		t.Errorf("Expected CLOSED state after reset, got %s", metricsAfter.State)
	}
}

func TestCircuitBreaker_ForceStateChanges(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "force_test"
	
	cb := NewCircuitBreaker(config)
	
	// Force open
	cb.ForceOpen("manual test")
	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit breaker should be OPEN after ForceOpen")
	}
	
	// Force close
	cb.ForceClose("manual test")
	if cb.GetState() != CircuitBreakerClosed {
		t.Error("Circuit breaker should be CLOSED after ForceClose")
	}
}

func TestCircuitBreaker_FallbackFunction(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:                    "fallback_test",
		FailureThreshold:        1,
		MinRequestsBeforeTesting: 1,
		Timeout:                 50 * time.Millisecond,
		ErrorClassifier: func(err error) bool {
			return err != nil
		},
		FallbackFunc: func(ctx context.Context) (interface{}, error) {
			return "fallback_result", nil
		},
	}
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	// Open circuit
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	if cb.GetState() != CircuitBreakerOpen {
		t.Error("Circuit breaker should be OPEN")
	}
	
	// Execute operation while circuit is open - should use fallback
	result, err := cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		t.Error("This should not be executed when circuit is OPEN")
		return nil, nil
	})
	
	if err != nil {
		t.Errorf("Expected fallback to succeed, got error: %v", err)
	}
	
	if result != "fallback_result" {
		t.Errorf("Expected 'fallback_result', got %v", result)
	}
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	config := &CircuitBreakerConfig{
		Name:                    "concurrent_test",
		MaxRequests:             10,
		FailureThreshold:        5,
		SuccessThreshold:        3,
		MinRequestsBeforeTesting: 1,
		ErrorClassifier: func(err error) bool {
			return err != nil
		},
	}
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	const numGoroutines = 50
	const operationsPerGoroutine = 10
	
	var wg sync.WaitGroup
	var successCount, errorCount int64
	var mu sync.Mutex
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				_, err := cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
					// Simulate varying success/failure
					if (goroutineID+j)%3 == 0 {
						return nil, errors.New("simulated error")
					}
					return "success", nil
				})
				
				mu.Lock()
				if err != nil {
					errorCount++
				} else {
					successCount++
				}
				mu.Unlock()
			}
		}(i)
	}
	
	wg.Wait()
	
	mu.Lock()
	totalOperations := successCount + errorCount
	mu.Unlock()
	
	if totalOperations != numGoroutines*operationsPerGoroutine {
		t.Errorf("Expected %d total operations, got %d", 
			numGoroutines*operationsPerGoroutine, totalOperations)
	}
	
	// Verify circuit breaker metrics are consistent
	metrics := cb.GetMetrics()
	if metrics.TotalRequests == 0 {
		t.Error("Expected non-zero total requests after concurrent operations")
	}
	
	t.Logf("Concurrent test completed: %d successes, %d errors, state: %s", 
		successCount, errorCount, metrics.State)
}

func TestCircuitBreaker_OnStateChangeCallback(t *testing.T) {
	var stateChanges []string
	var mu sync.Mutex
	
	config := &CircuitBreakerConfig{
		Name:                    "callback_test",
		FailureThreshold:        1,
		MinRequestsBeforeTesting: 1,
		Timeout:                 50 * time.Millisecond,
		ErrorClassifier: func(err error) bool {
			return err != nil
		},
		OnStateChange: func(from, to CircuitBreakerState) {
			mu.Lock()
			defer mu.Unlock()
			stateChanges = append(stateChanges, fmt.Sprintf("%s->%s", from, to))
		},
	}
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	// Trigger state change to OPEN
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	// Wait for timeout and trigger transition to HALF_OPEN
	time.Sleep(60 * time.Millisecond)
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	
	// Give callbacks time to execute
	time.Sleep(10 * time.Millisecond)
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(stateChanges) < 2 {
		t.Errorf("Expected at least 2 state changes, got %d: %v", len(stateChanges), stateChanges)
	}
	
	// Should have CLOSED->OPEN and OPEN->HALF_OPEN transitions
	expectedTransitions := []string{"CLOSED->OPEN", "OPEN->HALF_OPEN"}
	for _, expected := range expectedTransitions {
		found := false
		for _, actual := range stateChanges {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected state transition '%s' not found in %v", expected, stateChanges)
		}
	}
}

// Benchmark tests

func BenchmarkCircuitBreaker_Execute_Success(b *testing.B) {
	config := DefaultCircuitBreakerConfig()
	config.Name = "benchmark"
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				return "success", nil
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkCircuitBreaker_Execute_OpenCircuit(b *testing.B) {
	config := &CircuitBreakerConfig{
		Name:                    "benchmark_open",
		FailureThreshold:        1,
		MinRequestsBeforeTesting: 1,
		ErrorClassifier: func(err error) bool {
			return err != nil
		},
		FallbackFunc: func(ctx context.Context) (interface{}, error) {
			return "fallback", nil
		},
	}
	
	cb := NewCircuitBreaker(config)
	ctx := context.Background()
	
	// Open the circuit
	cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := cb.Execute(ctx, func(ctx context.Context) (interface{}, error) {
				b.Error("This should not be executed")
				return nil, nil
			})
			if err != nil && !errors.Is(err, ErrCircuitBreakerOpen) {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}