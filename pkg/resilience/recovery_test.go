package resilience

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRecoveryManager_NewRecoveryManager(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "test_recovery"
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	
	if rm == nil {
		t.Fatal("Recovery manager should not be nil")
	}
	
	if rm.config.Name != "test_recovery" {
		t.Errorf("Expected name 'test_recovery', got '%s'", rm.config.Name)
	}
	
	metrics := rm.GetMetrics()
	if metrics.Name != "test_recovery" {
		t.Errorf("Expected metrics name 'test_recovery', got '%s'", metrics.Name)
	}
}

func TestRecoveryManager_PanicRecovery(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "panic_test"
	config.EnablePanicRecovery = true
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	var panicReceived bool
	var panicValue interface{}
	var mu sync.Mutex
	
	config.OnPanic = func(panicInfo *PanicInfo) {
		mu.Lock()
		defer mu.Unlock()
		panicReceived = true
		panicValue = panicInfo.Value
	}
	
	// Execute operation that panics
	result, err := rm.WithRecoveryAndName(ctx, "panic_op", func(ctx context.Context) (interface{}, error) {
		panic("test panic")
	})
	
	if err == nil {
		t.Error("Expected error from panic recovery, got nil")
	}
	
	if result != nil {
		t.Errorf("Expected nil result from panic, got %v", result)
	}
	
	if !errors.Is(err, ErrPanicRecovery) {
		t.Errorf("Expected ErrPanicRecovery, got %v", err)
	}
	
	// Give panic handler time to process
	time.Sleep(10 * time.Millisecond)
	
	mu.Lock()
	defer mu.Unlock()
	
	if !panicReceived {
		t.Error("Expected panic to be received by callback")
	}
	
	if panicValue != "test panic" {
		t.Errorf("Expected panic value 'test panic', got %v", panicValue)
	}
	
	metrics := rm.GetMetrics()
	if metrics.TotalPanics == 0 {
		t.Error("Expected at least one panic in metrics")
	}
}

func TestRecoveryManager_ErrorClassification(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "classification_test"
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	var classifications []*ErrorClassification
	var mu sync.Mutex
	
	config.OnError = func(classification *ErrorClassification) {
		mu.Lock()
		defer mu.Unlock()
		classifications = append(classifications, classification)
	}
	
	// Execute operation with different types of errors
	testErrors := []struct {
		name        string
		error       error
		expectedCat ErrorCategory
	}{
		{"network", errors.New("connection failed"), ErrorCategoryNetwork},
		{"timeout", context.DeadlineExceeded, ErrorCategoryTimeout},
		{"validation", errors.New("invalid input format"), ErrorCategoryValidation},
		{"resource", errors.New("memory exhausted"), ErrorCategoryResource},
		{"permission", errors.New("access denied"), ErrorCategoryPermission},
	}
	
	for _, testCase := range testErrors {
		rm.WithRecoveryAndName(ctx, testCase.name, func(ctx context.Context) (interface{}, error) {
			return nil, testCase.error
		})
	}
	
	// Give error handler time to process
	time.Sleep(10 * time.Millisecond)
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(classifications) != len(testErrors) {
		t.Errorf("Expected %d classifications, got %d", len(testErrors), len(classifications))
	}
	
	// Check classification categories
	for i, classification := range classifications {
		if i < len(testErrors) {
			expected := testErrors[i].expectedCat
			if classification.Category != expected {
				t.Errorf("Test %s: expected category %s, got %s", 
					testErrors[i].name, expected, classification.Category)
			}
		}
	}
}

func TestRecoveryManager_GracefulDegradation(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "degradation_test"
	config.RecoverySelector = func(classification *ErrorClassification) RecoveryStrategy {
		return RecoveryStrategyGracefulDegradation
	}
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	// Test network error degradation
	result, err := rm.WithRecoveryAndName(ctx, "network_op", func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("network connection failed")
	})
	
	if err != nil {
		t.Errorf("Expected graceful degradation to succeed, got error: %v", err)
	}
	
	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Errorf("Expected map result from graceful degradation, got %T", result)
	} else {
		if resultMap["status"] != "degraded" {
			t.Errorf("Expected degraded status, got %v", resultMap["status"])
		}
		
		if resultMap["reason"] != "network_error" {
			t.Errorf("Expected network_error reason, got %v", resultMap["reason"])
		}
	}
	
	metrics := rm.GetMetrics()
	if metrics.TotalRecoveries == 0 {
		t.Error("Expected at least one recovery in metrics")
	}
}

func TestRecoveryManager_FallbackRecovery(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "fallback_test"
	config.RecoverySelector = func(classification *ErrorClassification) RecoveryStrategy {
		return RecoveryStrategyFallback
	}
	config.OnFallback = func(ctx context.Context, err error) (interface{}, error) {
		return "fallback_result", nil
	}
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	result, err := rm.WithRecoveryAndName(ctx, "fallback_op", func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("operation failed")
	})
	
	if err != nil {
		t.Errorf("Expected fallback to succeed, got error: %v", err)
	}
	
	if result != "fallback_result" {
		t.Errorf("Expected 'fallback_result', got %v", result)
	}
	
	metrics := rm.GetMetrics()
	if metrics.TotalRecoveries == 0 {
		t.Error("Expected at least one recovery in metrics")
	}
}

func TestRecoveryManager_ErrorAggregator(t *testing.T) {
	aggregator := NewErrorAggregator(10)
	
	// Add some errors
	now := time.Now()
	errors := []*ErrorClassification{
		{
			Error:     errors.New("error 1"),
			Category:  ErrorCategoryNetwork,
			Severity:  ErrorSeverityMedium,
			Timestamp: now.Add(-5 * time.Minute),
		},
		{
			Error:     errors.New("error 2"),
			Category:  ErrorCategoryTimeout,
			Severity:  ErrorSeverityHigh,
			Timestamp: now.Add(-2 * time.Minute),
		},
		{
			Error:     errors.New("error 3"),
			Category:  ErrorCategoryNetwork,
			Severity:  ErrorSeverityLow,
			Timestamp: now.Add(-30 * time.Second),
		},
	}
	
	for _, err := range errors {
		aggregator.Add(err)
	}
	
	// Test getting errors in interval
	recentErrors := aggregator.GetErrorsInInterval(3 * time.Minute)
	if len(recentErrors) != 2 {
		t.Errorf("Expected 2 recent errors, got %d", len(recentErrors))
	}
	
	// Test error rate calculation
	rate := aggregator.GetErrorRate(time.Hour)
	if rate == 0 {
		t.Error("Expected non-zero error rate")
	}
}

func TestRecoveryManager_Events(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "events_test"
	config.RecoverySelector = func(classification *ErrorClassification) RecoveryStrategy {
		if classification.Category == ErrorCategoryNetwork {
			return RecoveryStrategyGracefulDegradation
		}
		return RecoveryStrategyFail
	}
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	var events []*RecoveryEvent
	var mu sync.Mutex
	
	rm.AddEventListener(func(event *RecoveryEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, event)
	})
	
	// Execute operation that triggers recovery
	rm.WithRecoveryAndName(ctx, "event_op", func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("network connection failed")
	})
	
	// Execute operation that panics
	rm.WithRecoveryAndName(ctx, "panic_op", func(ctx context.Context) (interface{}, error) {
		panic("test panic")
	})
	
	// Give events time to propagate
	time.Sleep(50 * time.Millisecond)
	
	mu.Lock()
	defer mu.Unlock()
	
	if len(events) == 0 {
		t.Error("Expected at least some recovery events")
	}
	
	// Check for specific event types
	eventTypes := make(map[string]bool)
	for _, event := range events {
		eventTypes[event.Type] = true
	}
	
	expectedTypes := []string{"recovery_attempt", "recovery_completed"}
	foundTypes := 0
	for _, expectedType := range expectedTypes {
		if eventTypes[expectedType] {
			foundTypes++
		}
	}
	
	if foundTypes == 0 {
		t.Errorf("Expected recovery event types, found types: %v", eventTypes)
	}
}

func TestRecoveryManager_Metrics(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "metrics_test"
	config.EnableErrorAggregation = true
	config.RecoverySelector = func(classification *ErrorClassification) RecoveryStrategy {
		if classification.Recoverable {
			return RecoveryStrategyGracefulDegradation
		}
		return RecoveryStrategyFail
	}
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	// Execute operations with different outcomes
	rm.WithRecoveryAndName(ctx, "success_op", func(ctx context.Context) (interface{}, error) {
		return "success", nil
	})
	
	rm.WithRecoveryAndName(ctx, "error_op", func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("network failure")
	})
	
	rm.WithRecoveryAndName(ctx, "panic_op", func(ctx context.Context) (interface{}, error) {
		panic("test panic")
	})
	
	// Give time for processing
	time.Sleep(20 * time.Millisecond)
	
	metrics := rm.GetMetrics()
	
	if metrics.Name != "metrics_test" {
		t.Errorf("Expected name 'metrics_test', got '%s'", metrics.Name)
	}
	
	if metrics.TotalErrors == 0 {
		t.Error("Expected at least one error in metrics")
	}
	
	if metrics.TotalPanics == 0 {
		t.Error("Expected at least one panic in metrics")
	}
	
	if metrics.TotalRecoveries == 0 {
		t.Error("Expected at least one recovery in metrics")
	}
	
	// Check error categorization
	if len(metrics.ErrorsByCategory) == 0 {
		t.Error("Expected errors by category")
	}
	
	if len(metrics.ErrorsBySeverity) == 0 {
		t.Error("Expected errors by severity")
	}
	
	if len(metrics.RecoveriesByStrategy) == 0 {
		t.Error("Expected recoveries by strategy")
	}
	
	if metrics.RecoveryRate == 0 {
		t.Error("Expected non-zero recovery rate")
	}
}

func TestRecoveryManager_Reset(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "reset_test"
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	// Execute some operations to generate metrics
	rm.WithRecoveryAndName(ctx, "error_op", func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("test error")
	})
	
	// Verify metrics before reset
	metricsBefore := rm.GetMetrics()
	if metricsBefore.TotalErrors == 0 {
		t.Error("Expected non-zero errors before reset")
	}
	
	// Reset
	rm.Reset()
	
	// Verify metrics after reset
	metricsAfter := rm.GetMetrics()
	if metricsAfter.TotalErrors != 0 {
		t.Errorf("Expected zero errors after reset, got %d", metricsAfter.TotalErrors)
	}
	
	if metricsAfter.TotalPanics != 0 {
		t.Errorf("Expected zero panics after reset, got %d", metricsAfter.TotalPanics)
	}
	
	if metricsAfter.TotalRecoveries != 0 {
		t.Errorf("Expected zero recoveries after reset, got %d", metricsAfter.TotalRecoveries)
	}
	
	if len(metricsAfter.ErrorsByCategory) != 0 {
		t.Error("Expected empty error categories after reset")
	}
}

func TestRecoveryManager_ConcurrentAccess(t *testing.T) {
	config := DefaultRecoveryConfig()
	config.Name = "concurrent_test"
	config.RecoverySelector = func(classification *ErrorClassification) RecoveryStrategy {
		return RecoveryStrategyGracefulDegradation
	}
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	const numGoroutines = 10
	const operationsPerGoroutine = 5
	
	var successCount, errorCount, panicCount int64
	var wg sync.WaitGroup
	
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				opType := (goroutineID + j) % 3
				
				result, err := rm.WithRecoveryAndName(ctx, "concurrent_op", func(ctx context.Context) (interface{}, error) {
					switch opType {
					case 0:
						return "success", nil
					case 1:
						return nil, errors.New("simulated error")
					case 2:
						panic("simulated panic")
					}
					return nil, nil
				})
				
				if errors.Is(err, ErrPanicRecovery) {
					atomic.AddInt64(&panicCount, 1)
				} else if err != nil {
					atomic.AddInt64(&errorCount, 1)
				} else if result != nil {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	totalOperations := successCount + errorCount + panicCount
	expectedOperations := int64(numGoroutines * operationsPerGoroutine)
	
	if totalOperations != expectedOperations {
		t.Errorf("Expected %d total operations, got %d", expectedOperations, totalOperations)
	}
	
	// Give time for async processing
	time.Sleep(100 * time.Millisecond)
	
	// Verify metrics are consistent
	metrics := rm.GetMetrics()
	if metrics.TotalErrors == 0 && errorCount > 0 {
		t.Error("Expected non-zero error count in metrics")
	}
	
	if metrics.TotalPanics == 0 && panicCount > 0 {
		t.Error("Expected non-zero panic count in metrics")
	}
	
	t.Logf("Concurrent test completed: %d successes, %d errors, %d panics", 
		successCount, errorCount, panicCount)
}

func TestErrorClassification_DefaultClassifier(t *testing.T) {
	testCases := []struct {
		error       error
		expectedCat ErrorCategory
		expectedSev ErrorSeverity
	}{
		{context.DeadlineExceeded, ErrorCategoryTimeout, ErrorSeverityMedium},
		{context.Canceled, ErrorCategoryTimeout, ErrorSeverityMedium},
		{errors.New("network connection failed"), ErrorCategoryNetwork, ErrorSeverityMedium},
		{errors.New("memory exhausted"), ErrorCategoryResource, ErrorSeverityHigh},
		{errors.New("invalid format"), ErrorCategoryValidation, ErrorSeverityLow},
		{errors.New("permission denied"), ErrorCategoryPermission, ErrorSeverityHigh},
		{errors.New("unknown error"), ErrorCategoryInternal, ErrorSeverityMedium},
	}
	
	for _, testCase := range testCases {
		classification := DefaultErrorClassifier(testCase.error)
		
		if classification.Category != testCase.expectedCat {
			t.Errorf("Error '%v': expected category %s, got %s", 
				testCase.error, testCase.expectedCat, classification.Category)
		}
		
		if classification.Severity != testCase.expectedSev {
			t.Errorf("Error '%v': expected severity %s, got %s", 
				testCase.error, testCase.expectedSev, classification.Severity)
		}
		
		if classification.Error != testCase.error {
			t.Errorf("Classification should contain original error")
		}
		
		if classification.Timestamp.IsZero() {
			t.Error("Classification should have timestamp")
		}
	}
}

func TestRecoveryStrategy_DefaultSelector(t *testing.T) {
	testCases := []struct {
		category         ErrorCategory
		recoverable      bool
		retryable        bool
		expectedStrategy RecoveryStrategy
	}{
		{ErrorCategoryNetwork, true, true, RecoveryStrategyRetry},
		{ErrorCategoryNetwork, true, false, RecoveryStrategyFallback},
		{ErrorCategoryTimeout, true, false, RecoveryStrategyGracefulDegradation},
		{ErrorCategoryResource, true, false, RecoveryStrategyCircuitBreaker},
		{ErrorCategoryValidation, false, false, RecoveryStrategyFail},
		{ErrorCategoryPermission, false, false, RecoveryStrategyFail},
		{ErrorCategoryInternal, true, true, RecoveryStrategyRetry},
		{ErrorCategoryInternal, false, false, RecoveryStrategyFail},
		{ErrorCategoryExternal, true, false, RecoveryStrategyCircuitBreaker},
		{ErrorCategoryPanic, true, false, RecoveryStrategyGracefulDegradation},
	}
	
	for _, testCase := range testCases {
		classification := &ErrorClassification{
			Category:    testCase.category,
			Recoverable: testCase.recoverable,
			Retryable:   testCase.retryable,
		}
		
		strategy := DefaultRecoverySelector(classification)
		if strategy != testCase.expectedStrategy {
			t.Errorf("Category %s (recoverable=%t, retryable=%t): expected strategy %s, got %s",
				testCase.category, testCase.recoverable, testCase.retryable, 
				testCase.expectedStrategy, strategy)
		}
	}
}

func TestDefaultPanicHandler(t *testing.T) {
	panicInfo := &PanicInfo{
		Value:     "test panic",
		Stack:     "test stack trace",
		Timestamp: time.Now(),
		Operation: "test_operation",
	}
	
	err := DefaultPanicHandler(panicInfo)
	
	if err == nil {
		t.Error("Expected error from default panic handler, got nil")
	}
	
	expectedMsg := "panic recovered: test panic"
	if err.Error() != expectedMsg {
		t.Errorf("Expected error message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestHelperFunctions_ErrorClassification(t *testing.T) {
	testCases := []struct {
		errMsg   string
		function func(string) bool
		expected bool
	}{
		{"connection failed", isNetworkError, true},
		{"network timeout", isNetworkError, true},
		{"dns resolution failed", isNetworkError, true},
		{"file not found", isNetworkError, false},
		{"memory exhausted", isResourceError, true},
		{"disk full", isResourceError, true},
		{"cpu limit exceeded", isResourceError, true},
		{"normal error", isResourceError, false},
		{"invalid format", isValidationError, true},
		{"parse error", isValidationError, true},
		{"malformed data", isValidationError, true},
		{"normal error", isValidationError, false},
		{"permission denied", isPermissionError, true},
		{"access forbidden", isPermissionError, true},
		{"unauthorized", isPermissionError, true},
		{"normal error", isPermissionError, false},
	}
	
	for _, testCase := range testCases {
		result := testCase.function(testCase.errMsg)
		if result != testCase.expected {
			t.Errorf("Error message '%s': expected %t, got %t", 
				testCase.errMsg, testCase.expected, result)
		}
	}
}

// Benchmark tests

func BenchmarkRecoveryManager_WithRecovery_Success(b *testing.B) {
	config := DefaultRecoveryConfig()
	config.Name = "benchmark"
	config.EnablePanicRecovery = true
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := rm.WithRecovery(ctx, func(ctx context.Context) (interface{}, error) {
				return "success", nil
			})
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}

func BenchmarkRecoveryManager_WithRecovery_Error(b *testing.B) {
	config := DefaultRecoveryConfig()
	config.Name = "benchmark_error"
	config.RecoverySelector = func(classification *ErrorClassification) RecoveryStrategy {
		return RecoveryStrategyGracefulDegradation
	}
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := rm.WithRecovery(ctx, func(ctx context.Context) (interface{}, error) {
				return nil, errors.New("benchmark error")
			})
			if err != nil {
				b.Errorf("Expected recovery to succeed, got error: %v", err)
			}
		}
	})
}

func BenchmarkRecoveryManager_WithRecovery_Panic(b *testing.B) {
	config := DefaultRecoveryConfig()
	config.Name = "benchmark_panic"
	config.EnablePanicRecovery = true
	
	rm := NewRecoveryManager(config)
	defer rm.Stop()
	ctx := context.Background()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := rm.WithRecovery(ctx, func(ctx context.Context) (interface{}, error) {
				panic("benchmark panic")
			})
			if err == nil {
				b.Error("Expected error from panic recovery")
			}
		}
	})
}

func BenchmarkDefaultErrorClassifier(b *testing.B) {
	testError := errors.New("network connection failed")
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			classification := DefaultErrorClassifier(testError)
			if classification == nil {
				b.Error("Expected classification, got nil")
			}
		}
	})
}