package resilience

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity int

const (
	// ErrorSeverityLow - minor errors that don't affect system operation
	ErrorSeverityLow ErrorSeverity = iota
	// ErrorSeverityMedium - errors that may affect performance but system can continue
	ErrorSeverityMedium
	// ErrorSeverityHigh - serious errors that require immediate attention
	ErrorSeverityHigh
	// ErrorSeverityCritical - critical errors that may cause system failure
	ErrorSeverityCritical
)

func (s ErrorSeverity) String() string {
	switch s {
	case ErrorSeverityLow:
		return "LOW"
	case ErrorSeverityMedium:
		return "MEDIUM"
	case ErrorSeverityHigh:
		return "HIGH"
	case ErrorSeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ErrorCategory represents different categories of errors
type ErrorCategory string

const (
	// ErrorCategoryNetwork - network-related errors
	ErrorCategoryNetwork ErrorCategory = "network"
	// ErrorCategoryTimeout - timeout-related errors  
	ErrorCategoryTimeout ErrorCategory = "timeout"
	// ErrorCategoryResource - resource exhaustion errors
	ErrorCategoryResource ErrorCategory = "resource"
	// ErrorCategoryValidation - validation errors
	ErrorCategoryValidation ErrorCategory = "validation"
	// ErrorCategoryPermission - permission/authorization errors
	ErrorCategoryPermission ErrorCategory = "permission"
	// ErrorCategoryInternal - internal system errors
	ErrorCategoryInternal ErrorCategory = "internal"
	// ErrorCategoryExternal - external dependency errors
	ErrorCategoryExternal ErrorCategory = "external"
	// ErrorCategoryPanic - panic recovery errors
	ErrorCategoryPanic ErrorCategory = "panic"
)

// ErrorClassification represents a classified error
type ErrorClassification struct {
	Error        error         `json:"error"`
	Category     ErrorCategory `json:"category"`
	Severity     ErrorSeverity `json:"severity"`
	Recoverable  bool          `json:"recoverable"`
	Retryable    bool          `json:"retryable"`
	Temporary    bool          `json:"temporary"`
	Message      string        `json:"message"`
	Code         string        `json:"code,omitempty"`
	Component    string        `json:"component,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
	StackTrace   string        `json:"stack_trace,omitempty"`
}

// RecoveryStrategy defines different recovery strategies
type RecoveryStrategy string

const (
	// RecoveryStrategyRetry - retry the operation
	RecoveryStrategyRetry RecoveryStrategy = "retry"
	// RecoveryStrategyFallback - use fallback mechanism
	RecoveryStrategyFallback RecoveryStrategy = "fallback"
	// RecoveryStrategyCircuitBreaker - use circuit breaker
	RecoveryStrategyCircuitBreaker RecoveryStrategy = "circuit_breaker"
	// RecoveryStrategyGracefulDegradation - degrade gracefully
	RecoveryStrategyGracefulDegradation RecoveryStrategy = "graceful_degradation"
	// RecoveryStrategyFail - fail immediately
	RecoveryStrategyFail RecoveryStrategy = "fail"
	// RecoveryStrategyIgnore - ignore the error
	RecoveryStrategyIgnore RecoveryStrategy = "ignore"
)

// PanicInfo contains information about a panic
type PanicInfo struct {
	Value      interface{} `json:"value"`
	Stack      string      `json:"stack"`
	Goroutine  string      `json:"goroutine"`
	Timestamp  time.Time   `json:"timestamp"`
	Component  string      `json:"component,omitempty"`
	Operation  string      `json:"operation,omitempty"`
}

// RecoveryConfig configuration for error recovery
type RecoveryConfig struct {
	Name                    string        `json:"name"`
	EnablePanicRecovery     bool          `json:"enable_panic_recovery"`
	EnableErrorAggregation  bool          `json:"enable_error_aggregation"`
	EnableMetrics          bool          `json:"enable_metrics"`
	MaxErrorsPerInterval   int           `json:"max_errors_per_interval"`
	ErrorInterval          time.Duration `json:"error_interval"`
	PanicBufferSize        int           `json:"panic_buffer_size"`
	ErrorBufferSize        int           `json:"error_buffer_size"`
	
	// Classification functions
	ErrorClassifier        func(error) *ErrorClassification `json:"-"`
	RecoverySelector       func(*ErrorClassification) RecoveryStrategy `json:"-"`
	PanicHandler          func(*PanicInfo) error `json:"-"`
	
	// Callbacks
	OnError               func(*ErrorClassification) `json:"-"`
	OnPanic               func(*PanicInfo) `json:"-"`
	OnRecovery            func(*ErrorClassification, RecoveryStrategy) `json:"-"`
	OnFallback            func(context.Context, error) (interface{}, error) `json:"-"`
}

// DefaultRecoveryConfig returns default recovery configuration
func DefaultRecoveryConfig() *RecoveryConfig {
	return &RecoveryConfig{
		Name:                   "default",
		EnablePanicRecovery:    true,
		EnableErrorAggregation: true,
		EnableMetrics:         true,
		MaxErrorsPerInterval:  100,
		ErrorInterval:         time.Minute,
		PanicBufferSize:       50,
		ErrorBufferSize:       200,
		ErrorClassifier:       DefaultErrorClassifier,
		RecoverySelector:      DefaultRecoverySelector,
		PanicHandler:          DefaultPanicHandler,
	}
}

// RecoveryMetrics tracks recovery statistics
type RecoveryMetrics struct {
	Name                     string                    `json:"name"`
	TotalErrors              int64                     `json:"total_errors"`
	TotalPanics              int64                     `json:"total_panics"`
	TotalRecoveries          int64                     `json:"total_recoveries"`
	ErrorsByCategory         map[ErrorCategory]int64   `json:"errors_by_category"`
	ErrorsBySeverity         map[ErrorSeverity]int64   `json:"errors_by_severity"`
	RecoveriesByStrategy     map[RecoveryStrategy]int64 `json:"recoveries_by_strategy"`
	ErrorRate                float64                   `json:"error_rate"`
	RecoveryRate            float64                   `json:"recovery_rate"`
	LastErrorTime           time.Time                 `json:"last_error_time,omitempty"`
	LastPanicTime           time.Time                 `json:"last_panic_time,omitempty"`
	LastRecoveryTime        time.Time                 `json:"last_recovery_time,omitempty"`
	AverageRecoveryTime     time.Duration             `json:"average_recovery_time"`
}

// RecoveryEvent represents events from error recovery
type RecoveryEvent struct {
	Type             string                 `json:"type"`
	Name             string                 `json:"name"`
	Classification   *ErrorClassification   `json:"classification,omitempty"`
	PanicInfo        *PanicInfo            `json:"panic_info,omitempty"`
	Strategy         RecoveryStrategy      `json:"strategy,omitempty"`
	RecoveryTime     time.Duration         `json:"recovery_time,omitempty"`
	Success          bool                  `json:"success"`
	Reason           string                `json:"reason"`
	Timestamp        time.Time             `json:"timestamp"`
	Metrics          *RecoveryMetrics      `json:"metrics,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// ErrorAggregator aggregates errors for analysis
type ErrorAggregator struct {
	errors      []*ErrorClassification
	maxSize     int
	index       int
	full        bool
	mu          sync.RWMutex
	intervalMap map[time.Time]int
}

// NewErrorAggregator creates a new error aggregator
func NewErrorAggregator(maxSize int) *ErrorAggregator {
	return &ErrorAggregator{
		errors:      make([]*ErrorClassification, maxSize),
		maxSize:     maxSize,
		intervalMap: make(map[time.Time]int),
	}
}

// Add adds an error to the aggregator
func (ea *ErrorAggregator) Add(classification *ErrorClassification) {
	ea.mu.Lock()
	defer ea.mu.Unlock()
	
	ea.errors[ea.index] = classification
	ea.index = (ea.index + 1) % ea.maxSize
	if ea.index == 0 {
		ea.full = true
	}
	
	// Track errors by interval (truncated to minute)
	interval := classification.Timestamp.Truncate(time.Minute)
	ea.intervalMap[interval]++
}

// GetErrorsInInterval returns errors within the specified interval
func (ea *ErrorAggregator) GetErrorsInInterval(duration time.Duration) []*ErrorClassification {
	ea.mu.RLock()
	defer ea.mu.RUnlock()
	
	cutoff := time.Now().Add(-duration)
	var result []*ErrorClassification
	
	size := ea.maxSize
	if !ea.full {
		size = ea.index
	}
	
	for i := 0; i < size; i++ {
		if ea.errors[i] != nil && ea.errors[i].Timestamp.After(cutoff) {
			result = append(result, ea.errors[i])
		}
	}
	
	return result
}

// GetErrorRate returns the error rate for the specified interval
func (ea *ErrorAggregator) GetErrorRate(duration time.Duration) float64 {
	errors := ea.GetErrorsInInterval(duration)
	return float64(len(errors)) / duration.Seconds()
}

// RecoveryManager manages error recovery and panic handling
type RecoveryManager struct {
	config           *RecoveryConfig
	retryExecutor    *RetryExecutor
	circuitBreaker   *CircuitBreaker
	timeoutManager   *TimeoutManager
	errorAggregator  *ErrorAggregator
	metrics          *RecoveryMetrics
	panicChannel     chan *PanicInfo
	mu               sync.RWMutex
	eventListeners   []func(*RecoveryEvent)
	eventMu          sync.RWMutex
	stopChan         chan struct{}
}

// Common recovery errors
var (
	ErrRecoveryFailed    = errors.New("error recovery failed")
	ErrPanicRecovery     = errors.New("panic recovery")
	ErrNoRecoveryStrategy = errors.New("no recovery strategy available")
	ErrRecoveryTimeout   = errors.New("recovery operation timed out")
)

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(config *RecoveryConfig) *RecoveryManager {
	if config == nil {
		config = DefaultRecoveryConfig()
	}
	
	// Validate configuration
	if config.MaxErrorsPerInterval <= 0 {
		config.MaxErrorsPerInterval = 100
	}
	if config.ErrorInterval <= 0 {
		config.ErrorInterval = time.Minute
	}
	if config.PanicBufferSize <= 0 {
		config.PanicBufferSize = 50
	}
	if config.ErrorBufferSize <= 0 {
		config.ErrorBufferSize = 200
	}
	
	rm := &RecoveryManager{
		config: config,
		metrics: &RecoveryMetrics{
			Name:                 config.Name,
			ErrorsByCategory:     make(map[ErrorCategory]int64),
			ErrorsBySeverity:     make(map[ErrorSeverity]int64),
			RecoveriesByStrategy: make(map[RecoveryStrategy]int64),
		},
		panicChannel:   make(chan *PanicInfo, config.PanicBufferSize),
		eventListeners: make([]func(*RecoveryEvent), 0),
		stopChan:       make(chan struct{}),
	}
	
	// Initialize error aggregator
	if config.EnableErrorAggregation {
		rm.errorAggregator = NewErrorAggregator(config.ErrorBufferSize)
	}
	
	// Initialize integrations
	rm.retryExecutor = WithExponentialBackoff(
		fmt.Sprintf("%s_retry", config.Name),
		3,
		100*time.Millisecond,
		30*time.Second,
	)
	
	cbConfig := DefaultCircuitBreakerConfig()
	cbConfig.Name = fmt.Sprintf("%s_circuit_breaker", config.Name)
	rm.circuitBreaker = NewCircuitBreaker(cbConfig)
	
	tmConfig := DefaultTimeoutConfig()
	tmConfig.Name = fmt.Sprintf("%s_timeout", config.Name)
	rm.timeoutManager = NewTimeoutManager(tmConfig)
	
	// Start panic handler goroutine
	if config.EnablePanicRecovery {
		go rm.panicHandler()
	}
	
	log.Info().
		Str("name", config.Name).
		Bool("panic_recovery", config.EnablePanicRecovery).
		Bool("error_aggregation", config.EnableErrorAggregation).
		Msg("Recovery manager created")
	
	return rm
}

// WithRecovery executes an operation with recovery protection
func (rm *RecoveryManager) WithRecovery(ctx context.Context, operation func(context.Context) (interface{}, error)) (result interface{}, err error) {
	return rm.WithRecoveryAndName(ctx, "unknown", operation)
}

// WithRecoveryAndName executes an operation with recovery protection and operation name
func (rm *RecoveryManager) WithRecoveryAndName(ctx context.Context, operationName string, operation func(context.Context) (interface{}, error)) (result interface{}, err error) {
	startTime := time.Now()
	
	// Panic recovery wrapper
	defer func() {
		if r := recover(); r != nil {
			panicInfo := &PanicInfo{
				Value:     r,
				Stack:     string(debug.Stack()),
				Goroutine: rm.getCurrentGoroutineInfo(),
				Timestamp: time.Now(),
				Operation: operationName,
			}
			
			atomic.AddInt64(&rm.metrics.TotalPanics, 1)
			rm.metrics.LastPanicTime = time.Now()
			
			// Send panic to handler
			select {
			case rm.panicChannel <- panicInfo:
			default:
				// Channel full, log directly
				log.Error().
					Interface("panic", r).
					Str("operation", operationName).
					Msg("Panic channel full, dropping panic info")
			}
			
			// Call panic callback
			if rm.config.OnPanic != nil {
				rm.config.OnPanic(panicInfo)
			}
			
			// Handle panic recovery
			if rm.config.PanicHandler != nil {
				if recoveryErr := rm.config.PanicHandler(panicInfo); recoveryErr != nil {
					err = fmt.Errorf("%w: %v", ErrPanicRecovery, recoveryErr)
				} else {
					err = fmt.Errorf("%w: %v", ErrPanicRecovery, r)
				}
			} else {
				err = fmt.Errorf("%w: %v", ErrPanicRecovery, r)
			}
			
			rm.emitEvent(&RecoveryEvent{
				Type:         "panic",
				Name:         rm.config.Name,
				PanicInfo:    panicInfo,
				Success:      err == nil,
				RecoveryTime: time.Since(startTime),
				Reason:       "panic occurred and was recovered",
				Timestamp:    time.Now(),
				Metrics:      rm.GetMetrics(),
				Metadata: map[string]interface{}{
					"operation": operationName,
				},
			})
		}
	}()
	
	// Execute operation and handle errors
	result, err = operation(ctx)
	
	if err != nil {
		// Classify error
		classification := rm.classifyError(err, operationName)
		
		atomic.AddInt64(&rm.metrics.TotalErrors, 1)
		rm.metrics.LastErrorTime = time.Now()
		
		// Update category and severity metrics
		rm.mu.Lock()
		rm.metrics.ErrorsByCategory[classification.Category]++
		rm.metrics.ErrorsBySeverity[classification.Severity]++
		rm.mu.Unlock()
		
		// Add to aggregator
		if rm.errorAggregator != nil {
			rm.errorAggregator.Add(classification)
		}
		
		// Call error callback
		if rm.config.OnError != nil {
			rm.config.OnError(classification)
		}
		
		// Attempt recovery
		recoveryResult, recoveryErr := rm.attemptRecovery(ctx, classification)
		if recoveryErr == nil {
			atomic.AddInt64(&rm.metrics.TotalRecoveries, 1)
			rm.metrics.LastRecoveryTime = time.Now()
			
			return recoveryResult, nil
		}
		
		// Recovery failed, return original error
		return nil, err
	}
	
	return result, nil
}

// classifyError classifies an error
func (rm *RecoveryManager) classifyError(err error, component string) *ErrorClassification {
	if rm.config.ErrorClassifier != nil {
		classification := rm.config.ErrorClassifier(err)
		if classification.Component == "" {
			classification.Component = component
		}
		return classification
	}
	
	return DefaultErrorClassifier(err)
}

// attemptRecovery attempts to recover from an error
func (rm *RecoveryManager) attemptRecovery(ctx context.Context, classification *ErrorClassification) (interface{}, error) {
	if !classification.Recoverable {
		return nil, fmt.Errorf("%w: error is not recoverable", ErrRecoveryFailed)
	}
	
	strategy := RecoveryStrategyFail
	if rm.config.RecoverySelector != nil {
		strategy = rm.config.RecoverySelector(classification)
	}
	
	startTime := time.Now()
	
	// Update strategy metrics
	rm.mu.Lock()
	rm.metrics.RecoveriesByStrategy[strategy]++
	rm.mu.Unlock()
	
	// Call recovery callback
	if rm.config.OnRecovery != nil {
		rm.config.OnRecovery(classification, strategy)
	}
	
	rm.emitEvent(&RecoveryEvent{
		Type:           "recovery_attempt",
		Name:           rm.config.Name,
		Classification: classification,
		Strategy:       strategy,
		Reason:         "attempting error recovery",
		Timestamp:      startTime,
		Metrics:        rm.GetMetrics(),
	})
	
	var result interface{}
	var err error
	
	switch strategy {
	case RecoveryStrategyRetry:
		result, err = rm.retryRecovery(ctx, classification)
		
	case RecoveryStrategyFallback:
		result, err = rm.fallbackRecovery(ctx, classification)
		
	case RecoveryStrategyCircuitBreaker:
		result, err = rm.circuitBreakerRecovery(ctx, classification)
		
	case RecoveryStrategyGracefulDegradation:
		result, err = rm.gracefulDegradationRecovery(ctx, classification)
		
	case RecoveryStrategyIgnore:
		result, err = nil, nil // Ignore the error
		
	case RecoveryStrategyFail:
		fallthrough
	default:
		err = fmt.Errorf("%w: strategy %s", ErrRecoveryFailed, strategy)
	}
	
	recoveryTime := time.Since(startTime)
	success := err == nil
	
	// Update average recovery time
	rm.updateAverageRecoveryTime(recoveryTime)
	
	rm.emitEvent(&RecoveryEvent{
		Type:           "recovery_completed",
		Name:           rm.config.Name,
		Classification: classification,
		Strategy:       strategy,
		Success:        success,
		RecoveryTime:   recoveryTime,
		Reason:         fmt.Sprintf("recovery %s", map[bool]string{true: "succeeded", false: "failed"}[success]),
		Timestamp:      time.Now(),
		Metrics:        rm.GetMetrics(),
	})
	
	return result, err
}

// retryRecovery implements retry-based recovery
func (rm *RecoveryManager) retryRecovery(ctx context.Context, classification *ErrorClassification) (interface{}, error) {
	if !classification.Retryable {
		return nil, fmt.Errorf("%w: error is not retryable", ErrRecoveryFailed)
	}
	
	// Use retry executor (this would need the original operation, which we don't have here)
	// In a real implementation, you'd need to store the operation or use a different approach
	return nil, fmt.Errorf("%w: retry recovery not implemented", ErrRecoveryFailed)
}

// fallbackRecovery implements fallback-based recovery
func (rm *RecoveryManager) fallbackRecovery(ctx context.Context, classification *ErrorClassification) (interface{}, error) {
	if rm.config.OnFallback != nil {
		return rm.config.OnFallback(ctx, classification.Error)
	}
	
	return nil, fmt.Errorf("%w: no fallback function configured", ErrRecoveryFailed)
}

// circuitBreakerRecovery implements circuit breaker-based recovery
func (rm *RecoveryManager) circuitBreakerRecovery(ctx context.Context, classification *ErrorClassification) (interface{}, error) {
	// This would integrate with the circuit breaker
	// The actual operation would need to be re-executed through the circuit breaker
	return nil, fmt.Errorf("%w: circuit breaker recovery not implemented", ErrRecoveryFailed)
}

// gracefulDegradationRecovery implements graceful degradation recovery
func (rm *RecoveryManager) gracefulDegradationRecovery(ctx context.Context, classification *ErrorClassification) (interface{}, error) {
	// Return a degraded result based on the error type
	switch classification.Category {
	case ErrorCategoryNetwork:
		return map[string]interface{}{"status": "degraded", "reason": "network_error"}, nil
	case ErrorCategoryTimeout:
		return map[string]interface{}{"status": "degraded", "reason": "timeout"}, nil
	case ErrorCategoryResource:
		return map[string]interface{}{"status": "degraded", "reason": "resource_exhausted"}, nil
	default:
		return map[string]interface{}{"status": "degraded", "reason": "unknown_error"}, nil
	}
}

// panicHandler handles panics in a separate goroutine
func (rm *RecoveryManager) panicHandler() {
	for {
		select {
		case panicInfo := <-rm.panicChannel:
			rm.processPanicInfo(panicInfo)
		case <-rm.stopChan:
			return
		}
	}
}

// processPanicInfo processes panic information
func (rm *RecoveryManager) processPanicInfo(panicInfo *PanicInfo) {
	log.Error().
		Interface("panic_value", panicInfo.Value).
		Str("stack", panicInfo.Stack).
		Str("component", panicInfo.Component).
		Str("operation", panicInfo.Operation).
		Time("timestamp", panicInfo.Timestamp).
		Msg("Panic recovered")
	
	rm.emitEvent(&RecoveryEvent{
		Type:      "panic_processed",
		Name:      rm.config.Name,
		PanicInfo: panicInfo,
		Reason:    "panic information processed",
		Timestamp: time.Now(),
		Metrics:   rm.GetMetrics(),
	})
}

// getCurrentGoroutineInfo returns information about the current goroutine
func (rm *RecoveryManager) getCurrentGoroutineInfo() string {
	buf := make([]byte, 1024)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// updateAverageRecoveryTime updates the average recovery time
func (rm *RecoveryManager) updateAverageRecoveryTime(recoveryTime time.Duration) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	totalRecoveries := atomic.LoadInt64(&rm.metrics.TotalRecoveries)
	if totalRecoveries > 0 {
		currentAvg := rm.metrics.AverageRecoveryTime
		rm.metrics.AverageRecoveryTime = time.Duration(
			(int64(currentAvg)*(totalRecoveries-1) + int64(recoveryTime)) / totalRecoveries,
		)
	}
}

// GetMetrics returns current recovery metrics
func (rm *RecoveryManager) GetMetrics() *RecoveryMetrics {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	totalErrors := atomic.LoadInt64(&rm.metrics.TotalErrors)
	totalRecoveries := atomic.LoadInt64(&rm.metrics.TotalRecoveries)
	
	metrics := &RecoveryMetrics{
		Name:                 rm.metrics.Name,
		TotalErrors:          totalErrors,
		TotalPanics:          atomic.LoadInt64(&rm.metrics.TotalPanics),
		TotalRecoveries:      totalRecoveries,
		ErrorsByCategory:     make(map[ErrorCategory]int64),
		ErrorsBySeverity:     make(map[ErrorSeverity]int64),
		RecoveriesByStrategy: make(map[RecoveryStrategy]int64),
		LastErrorTime:        rm.metrics.LastErrorTime,
		LastPanicTime:        rm.metrics.LastPanicTime,
		LastRecoveryTime:     rm.metrics.LastRecoveryTime,
		AverageRecoveryTime:  rm.metrics.AverageRecoveryTime,
	}
	
	// Copy maps
	for k, v := range rm.metrics.ErrorsByCategory {
		metrics.ErrorsByCategory[k] = v
	}
	for k, v := range rm.metrics.ErrorsBySeverity {
		metrics.ErrorsBySeverity[k] = v
	}
	for k, v := range rm.metrics.RecoveriesByStrategy {
		metrics.RecoveriesByStrategy[k] = v
	}
	
	// Calculate rates
	if totalErrors > 0 {
		metrics.RecoveryRate = float64(totalRecoveries) / float64(totalErrors)
	}
	
	if rm.errorAggregator != nil {
		metrics.ErrorRate = rm.errorAggregator.GetErrorRate(rm.config.ErrorInterval)
	}
	
	return metrics
}

// Reset resets the recovery manager metrics
func (rm *RecoveryManager) Reset() {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	atomic.StoreInt64(&rm.metrics.TotalErrors, 0)
	atomic.StoreInt64(&rm.metrics.TotalPanics, 0)
	atomic.StoreInt64(&rm.metrics.TotalRecoveries, 0)
	
	// Reset maps
	rm.metrics.ErrorsByCategory = make(map[ErrorCategory]int64)
	rm.metrics.ErrorsBySeverity = make(map[ErrorSeverity]int64)
	rm.metrics.RecoveriesByStrategy = make(map[RecoveryStrategy]int64)
	
	rm.metrics.LastErrorTime = time.Time{}
	rm.metrics.LastPanicTime = time.Time{}
	rm.metrics.LastRecoveryTime = time.Time{}
	rm.metrics.AverageRecoveryTime = 0
	
	// Reset aggregator
	if rm.errorAggregator != nil {
		rm.errorAggregator = NewErrorAggregator(rm.config.ErrorBufferSize)
	}
	
	// Reset integrated components
	if rm.retryExecutor != nil {
		rm.retryExecutor.Reset()
	}
	if rm.circuitBreaker != nil {
		rm.circuitBreaker.Reset()
	}
	if rm.timeoutManager != nil {
		rm.timeoutManager.Reset()
	}
	
	rm.emitEvent(&RecoveryEvent{
		Type:      "reset",
		Name:      rm.config.Name,
		Reason:    "recovery manager reset",
		Timestamp: time.Now(),
		Metrics:   rm.metrics,
	})
	
	log.Info().
		Str("name", rm.config.Name).
		Msg("Recovery manager reset")
}

// Stop stops the recovery manager
func (rm *RecoveryManager) Stop() {
	close(rm.stopChan)
	log.Info().
		Str("name", rm.config.Name).
		Msg("Recovery manager stopped")
}

// AddEventListener adds an event listener for recovery events
func (rm *RecoveryManager) AddEventListener(listener func(*RecoveryEvent)) {
	rm.eventMu.Lock()
	defer rm.eventMu.Unlock()
	
	rm.eventListeners = append(rm.eventListeners, listener)
}

// RemoveEventListener removes an event listener
func (rm *RecoveryManager) RemoveEventListener(listener func(*RecoveryEvent)) {
	rm.eventMu.Lock()
	defer rm.eventMu.Unlock()
	
	var filtered []func(*RecoveryEvent)
	for _, l := range rm.eventListeners {
		if &l != &listener {
			filtered = append(filtered, l)
		}
	}
	rm.eventListeners = filtered
}

// emitEvent emits an event to all registered listeners
func (rm *RecoveryManager) emitEvent(event *RecoveryEvent) {
	rm.eventMu.RLock()
	listeners := make([]func(*RecoveryEvent), len(rm.eventListeners))
	copy(listeners, rm.eventListeners)
	rm.eventMu.RUnlock()
	
	// Emit events asynchronously
	for _, listener := range listeners {
		go func(l func(*RecoveryEvent)) {
			defer func() {
				if r := recover(); r != nil {
					log.Error().
						Interface("panic", r).
						Str("recovery_manager", rm.config.Name).
						Msg("Panic in recovery event listener")
				}
			}()
			l(event)
		}(listener)
	}
}

// String returns a string representation of the recovery manager
func (rm *RecoveryManager) String() string {
	metrics := rm.GetMetrics()
	return fmt.Sprintf("RecoveryManager{name=%s, errors=%d, panics=%d, recoveries=%d, recovery_rate=%.2f}",
		metrics.Name, metrics.TotalErrors, metrics.TotalPanics, metrics.TotalRecoveries, metrics.RecoveryRate)
}

// Default error classification and recovery functions

// DefaultErrorClassifier provides default error classification
func DefaultErrorClassifier(err error) *ErrorClassification {
	classification := &ErrorClassification{
		Error:       err,
		Message:     err.Error(),
		Timestamp:   time.Now(),
		Metadata:    make(map[string]interface{}),
		StackTrace:  string(debug.Stack()),
	}
	
	// Simple error classification based on error message
	errMsg := err.Error()
	
	switch {
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		classification.Category = ErrorCategoryTimeout
		classification.Severity = ErrorSeverityMedium
		classification.Retryable = false
		classification.Recoverable = true
		classification.Temporary = true
		
	case isNetworkError(errMsg):
		classification.Category = ErrorCategoryNetwork
		classification.Severity = ErrorSeverityMedium
		classification.Retryable = true
		classification.Recoverable = true
		classification.Temporary = true
		
	case isResourceError(errMsg):
		classification.Category = ErrorCategoryResource
		classification.Severity = ErrorSeverityHigh
		classification.Retryable = false
		classification.Recoverable = true
		classification.Temporary = true
		
	case isValidationError(errMsg):
		classification.Category = ErrorCategoryValidation
		classification.Severity = ErrorSeverityLow
		classification.Retryable = false
		classification.Recoverable = false
		classification.Temporary = false
		
	case isPermissionError(errMsg):
		classification.Category = ErrorCategoryPermission
		classification.Severity = ErrorSeverityHigh
		classification.Retryable = false
		classification.Recoverable = false
		classification.Temporary = false
		
	default:
		classification.Category = ErrorCategoryInternal
		classification.Severity = ErrorSeverityMedium
		classification.Retryable = true
		classification.Recoverable = true
		classification.Temporary = false
	}
	
	return classification
}

// DefaultRecoverySelector provides default recovery strategy selection
func DefaultRecoverySelector(classification *ErrorClassification) RecoveryStrategy {
	switch classification.Category {
	case ErrorCategoryNetwork:
		if classification.Retryable {
			return RecoveryStrategyRetry
		}
		return RecoveryStrategyFallback
		
	case ErrorCategoryTimeout:
		return RecoveryStrategyGracefulDegradation
		
	case ErrorCategoryResource:
		return RecoveryStrategyCircuitBreaker
		
	case ErrorCategoryValidation:
		return RecoveryStrategyFail
		
	case ErrorCategoryPermission:
		return RecoveryStrategyFail
		
	case ErrorCategoryInternal:
		if classification.Recoverable {
			return RecoveryStrategyRetry
		}
		return RecoveryStrategyFail
		
	case ErrorCategoryExternal:
		return RecoveryStrategyCircuitBreaker
		
	case ErrorCategoryPanic:
		return RecoveryStrategyGracefulDegradation
		
	default:
		return RecoveryStrategyFail
	}
}

// DefaultPanicHandler provides default panic handling
func DefaultPanicHandler(panicInfo *PanicInfo) error {
	log.Error().
		Interface("panic", panicInfo.Value).
		Str("stack", panicInfo.Stack).
		Str("operation", panicInfo.Operation).
		Msg("Panic recovered with default handler")
	
	// For default handling, we just log and return the panic as an error
	return fmt.Errorf("panic recovered: %v", panicInfo.Value)
}

// Helper functions for error classification

func isNetworkError(errMsg string) bool {
	networkKeywords := []string{"connection", "network", "timeout", "dns", "tcp", "udp", "http"}
	for _, keyword := range networkKeywords {
		if len(errMsg) > 0 && errMsg != "" {
			// Simple substring check (in production, you'd use better pattern matching)
			for i := 0; i < len(errMsg)-len(keyword)+1; i++ {
				if errMsg[i:i+len(keyword)] == keyword {
					return true
				}
			}
		}
	}
	return false
}

func isResourceError(errMsg string) bool {
	resourceKeywords := []string{"memory", "disk", "cpu", "resource", "exhausted", "limit", "quota"}
	for _, keyword := range resourceKeywords {
		if len(errMsg) > 0 && errMsg != "" {
			for i := 0; i < len(errMsg)-len(keyword)+1; i++ {
				if errMsg[i:i+len(keyword)] == keyword {
					return true
				}
			}
		}
	}
	return false
}

func isValidationError(errMsg string) bool {
	validationKeywords := []string{"validation", "invalid", "malformed", "parse", "format"}
	for _, keyword := range validationKeywords {
		if len(errMsg) > 0 && errMsg != "" {
			for i := 0; i < len(errMsg)-len(keyword)+1; i++ {
				if errMsg[i:i+len(keyword)] == keyword {
					return true
				}
			}
		}
	}
	return false
}

func isPermissionError(errMsg string) bool {
	permissionKeywords := []string{"permission", "denied", "unauthorized", "forbidden", "access"}
	for _, keyword := range permissionKeywords {
		if len(errMsg) > 0 && errMsg != "" {
			for i := 0; i < len(errMsg)-len(keyword)+1; i++ {
				if errMsg[i:i+len(keyword)] == keyword {
					return true
				}
			}
		}
	}
	return false
}