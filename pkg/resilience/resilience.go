// Package resilience provides comprehensive error handling and reliability patterns
// including circuit breakers, retry mechanisms, timeout management, and error recovery.
package resilience

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ResilienceConfig combines all resilience pattern configurations
type ResilienceConfig struct {
	Name                string           `json:"name"`
	EnableCircuitBreaker bool            `json:"enable_circuit_breaker"`
	EnableRetry         bool             `json:"enable_retry"`
	EnableTimeout       bool             `json:"enable_timeout"`
	EnableRecovery      bool             `json:"enable_recovery"`
	
	// Individual configurations
	CircuitBreakerConfig *CircuitBreakerConfig `json:"circuit_breaker_config,omitempty"`
	RetryConfig         *RetryConfig          `json:"retry_config,omitempty"`
	TimeoutConfig       *TimeoutConfig        `json:"timeout_config,omitempty"`
	RecoveryConfig      *RecoveryConfig       `json:"recovery_config,omitempty"`
}

// DefaultResilienceConfig returns a default configuration with all patterns enabled
func DefaultResilienceConfig() *ResilienceConfig {
	return &ResilienceConfig{
		Name:                "default",
		EnableCircuitBreaker: true,
		EnableRetry:         true,
		EnableTimeout:       true,
		EnableRecovery:      true,
		CircuitBreakerConfig: DefaultCircuitBreakerConfig(),
		RetryConfig:         DefaultRetryConfig(),
		TimeoutConfig:       DefaultTimeoutConfig(),
		RecoveryConfig:      DefaultRecoveryConfig(),
	}
}

// ResilienceFramework integrates all resilience patterns
type ResilienceFramework struct {
	config         *ResilienceConfig
	circuitBreaker *CircuitBreaker
	retryExecutor  *RetryExecutor
	timeoutManager *TimeoutManager
	recoveryManager *RecoveryManager
	mu             sync.RWMutex
}

// ResilienceMetrics aggregates metrics from all resilience patterns
type ResilienceMetrics struct {
	Name                 string                  `json:"name"`
	CircuitBreakerMetrics *CircuitBreakerMetrics `json:"circuit_breaker_metrics,omitempty"`
	RetryMetrics         *RetryMetrics           `json:"retry_metrics,omitempty"`
	TimeoutMetrics       *TimeoutMetrics         `json:"timeout_metrics,omitempty"`
	RecoveryMetrics      *RecoveryMetrics        `json:"recovery_metrics,omitempty"`
	TotalOperations      int64                   `json:"total_operations"`
	SuccessfulOperations int64                   `json:"successful_operations"`
	FailedOperations     int64                   `json:"failed_operations"`
	SuccessRate          float64                 `json:"success_rate"`
	LastOperationTime    time.Time               `json:"last_operation_time"`
}

// NewResilienceFramework creates a new resilience framework
func NewResilienceFramework(config *ResilienceConfig) *ResilienceFramework {
	if config == nil {
		config = DefaultResilienceConfig()
	}
	
	rf := &ResilienceFramework{
		config: config,
	}
	
	// Initialize enabled components
	if config.EnableCircuitBreaker && config.CircuitBreakerConfig != nil {
		if config.CircuitBreakerConfig.Name == "" {
			config.CircuitBreakerConfig.Name = fmt.Sprintf("%s_circuit_breaker", config.Name)
		}
		rf.circuitBreaker = NewCircuitBreaker(config.CircuitBreakerConfig)
		log.Debug().Str("component", "circuit_breaker").Msg("Circuit breaker initialized")
	}
	
	if config.EnableRetry && config.RetryConfig != nil {
		if config.RetryConfig.Name == "" {
			config.RetryConfig.Name = fmt.Sprintf("%s_retry", config.Name)
		}
		rf.retryExecutor = NewRetryExecutor(config.RetryConfig)
		log.Debug().Str("component", "retry").Msg("Retry executor initialized")
	}
	
	if config.EnableTimeout && config.TimeoutConfig != nil {
		if config.TimeoutConfig.Name == "" {
			config.TimeoutConfig.Name = fmt.Sprintf("%s_timeout", config.Name)
		}
		rf.timeoutManager = NewTimeoutManager(config.TimeoutConfig)
		log.Debug().Str("component", "timeout").Msg("Timeout manager initialized")
	}
	
	if config.EnableRecovery && config.RecoveryConfig != nil {
		if config.RecoveryConfig.Name == "" {
			config.RecoveryConfig.Name = fmt.Sprintf("%s_recovery", config.Name)
		}
		rf.recoveryManager = NewRecoveryManager(config.RecoveryConfig)
		log.Debug().Str("component", "recovery").Msg("Recovery manager initialized")
	}
	
	log.Info().
		Str("name", config.Name).
		Bool("circuit_breaker", config.EnableCircuitBreaker).
		Bool("retry", config.EnableRetry).
		Bool("timeout", config.EnableTimeout).
		Bool("recovery", config.EnableRecovery).
		Msg("Resilience framework initialized")
	
	return rf
}

// Execute executes an operation through all enabled resilience patterns
func (rf *ResilienceFramework) Execute(ctx context.Context, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	return rf.ExecuteWithName(ctx, "unknown", operation)
}

// ExecuteWithName executes an operation with a specific name through all enabled resilience patterns
func (rf *ResilienceFramework) ExecuteWithName(ctx context.Context, operationName string, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	// Create operation wrapper that chains all patterns
	chainedOperation := operation
	
	// Wrap with recovery (outermost)
	if rf.recoveryManager != nil {
		recoveryOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.recoveryManager.WithRecoveryAndName(ctx, operationName, recoveryOp)
		}
	}
	
	// Wrap with timeout
	if rf.timeoutManager != nil {
		timeoutOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.timeoutManager.WithTimeout(ctx, timeoutOp)
		}
	}
	
	// Wrap with circuit breaker
	if rf.circuitBreaker != nil {
		cbOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.circuitBreaker.Execute(ctx, cbOp)
		}
	}
	
	// Execute with retry (innermost executable)
	if rf.retryExecutor != nil {
		return rf.retryExecutor.Execute(ctx, chainedOperation)
	}
	
	// Execute directly if no patterns are enabled
	return chainedOperation(ctx)
}

// ExecuteWithLevel executes an operation with timeout level specification
func (rf *ResilienceFramework) ExecuteWithLevel(ctx context.Context, operationName string, level TimeoutLevel, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	// Create operation wrapper that chains all patterns
	chainedOperation := operation
	
	// Wrap with recovery (outermost)
	if rf.recoveryManager != nil {
		recoveryOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.recoveryManager.WithRecoveryAndName(ctx, operationName, recoveryOp)
		}
	}
	
	// Wrap with timeout (with level)
	if rf.timeoutManager != nil {
		timeoutOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.timeoutManager.WithTimeoutLevel(ctx, level, timeoutOp)
		}
	}
	
	// Wrap with circuit breaker
	if rf.circuitBreaker != nil {
		cbOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.circuitBreaker.Execute(ctx, cbOp)
		}
	}
	
	// Execute with retry
	if rf.retryExecutor != nil {
		return rf.retryExecutor.Execute(ctx, chainedOperation)
	}
	
	// Execute directly if no patterns are enabled
	return chainedOperation(ctx)
}

// ExecuteWithIdempotency executes an operation with idempotency key
func (rf *ResilienceFramework) ExecuteWithIdempotency(ctx context.Context, operationName, idempotencyKey string, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	// Create operation wrapper that chains all patterns
	chainedOperation := operation
	
	// Wrap with recovery (outermost)
	if rf.recoveryManager != nil {
		recoveryOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.recoveryManager.WithRecoveryAndName(ctx, operationName, recoveryOp)
		}
	}
	
	// Wrap with timeout
	if rf.timeoutManager != nil {
		timeoutOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.timeoutManager.WithTimeout(ctx, timeoutOp)
		}
	}
	
	// Wrap with circuit breaker
	if rf.circuitBreaker != nil {
		cbOp := chainedOperation
		chainedOperation = func(ctx context.Context) (interface{}, error) {
			return rf.circuitBreaker.Execute(ctx, cbOp)
		}
	}
	
	// Execute with retry and idempotency
	if rf.retryExecutor != nil {
		return rf.retryExecutor.ExecuteWithIdempotencyKey(ctx, idempotencyKey, chainedOperation)
	}
	
	// Execute directly if no patterns are enabled
	return chainedOperation(ctx)
}

// GetMetrics returns aggregated metrics from all patterns
func (rf *ResilienceFramework) GetMetrics() *ResilienceMetrics {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	
	metrics := &ResilienceMetrics{
		Name: rf.config.Name,
	}
	
	if rf.circuitBreaker != nil {
		metrics.CircuitBreakerMetrics = rf.circuitBreaker.GetMetrics()
	}
	
	if rf.retryExecutor != nil {
		metrics.RetryMetrics = rf.retryExecutor.GetMetrics()
	}
	
	if rf.timeoutManager != nil {
		metrics.TimeoutMetrics = rf.timeoutManager.GetMetrics()
	}
	
	if rf.recoveryManager != nil {
		metrics.RecoveryMetrics = rf.recoveryManager.GetMetrics()
	}
	
	// Aggregate total operations and success rate
	if metrics.RetryMetrics != nil {
		metrics.TotalOperations = metrics.RetryMetrics.TotalAttempts
		metrics.SuccessfulOperations = metrics.RetryMetrics.TotalSuccesses
		metrics.FailedOperations = metrics.RetryMetrics.TotalFailures
		metrics.LastOperationTime = metrics.RetryMetrics.LastAttemptTime
		
		if metrics.TotalOperations > 0 {
			metrics.SuccessRate = float64(metrics.SuccessfulOperations) / float64(metrics.TotalOperations)
		}
	} else if metrics.TimeoutMetrics != nil {
		metrics.TotalOperations = metrics.TimeoutMetrics.TotalOperations
		successfulOps := metrics.TotalOperations - metrics.TimeoutMetrics.TotalTimeouts
		metrics.SuccessfulOperations = successfulOps
		metrics.FailedOperations = metrics.TimeoutMetrics.TotalTimeouts
		
		if metrics.TotalOperations > 0 {
			metrics.SuccessRate = float64(metrics.SuccessfulOperations) / float64(metrics.TotalOperations)
		}
	} else if metrics.RecoveryMetrics != nil {
		metrics.TotalOperations = metrics.RecoveryMetrics.TotalErrors + 1 // Approximation
		metrics.SuccessfulOperations = metrics.RecoveryMetrics.TotalRecoveries
		metrics.FailedOperations = metrics.RecoveryMetrics.TotalErrors - metrics.RecoveryMetrics.TotalRecoveries
		metrics.LastOperationTime = metrics.RecoveryMetrics.LastErrorTime
		
		if metrics.TotalOperations > 0 {
			metrics.SuccessRate = float64(metrics.SuccessfulOperations) / float64(metrics.TotalOperations)
		}
	}
	
	return metrics
}

// Reset resets all enabled resilience patterns
func (rf *ResilienceFramework) Reset() {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	
	if rf.circuitBreaker != nil {
		rf.circuitBreaker.Reset()
	}
	
	if rf.retryExecutor != nil {
		rf.retryExecutor.Reset()
	}
	
	if rf.timeoutManager != nil {
		rf.timeoutManager.Reset()
	}
	
	if rf.recoveryManager != nil {
		rf.recoveryManager.Reset()
	}
	
	log.Info().
		Str("name", rf.config.Name).
		Msg("Resilience framework reset")
}

// Stop stops all background operations
func (rf *ResilienceFramework) Stop() {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	
	if rf.recoveryManager != nil {
		rf.recoveryManager.Stop()
	}
	
	log.Info().
		Str("name", rf.config.Name).
		Msg("Resilience framework stopped")
}

// GetCircuitBreaker returns the circuit breaker instance
func (rf *ResilienceFramework) GetCircuitBreaker() *CircuitBreaker {
	return rf.circuitBreaker
}

// GetRetryExecutor returns the retry executor instance
func (rf *ResilienceFramework) GetRetryExecutor() *RetryExecutor {
	return rf.retryExecutor
}

// GetTimeoutManager returns the timeout manager instance
func (rf *ResilienceFramework) GetTimeoutManager() *TimeoutManager {
	return rf.timeoutManager
}

// GetRecoveryManager returns the recovery manager instance
func (rf *ResilienceFramework) GetRecoveryManager() *RecoveryManager {
	return rf.recoveryManager
}

// IsEnabled checks if a specific pattern is enabled
func (rf *ResilienceFramework) IsEnabled(pattern string) bool {
	switch pattern {
	case "circuit_breaker":
		return rf.config.EnableCircuitBreaker && rf.circuitBreaker != nil
	case "retry":
		return rf.config.EnableRetry && rf.retryExecutor != nil
	case "timeout":
		return rf.config.EnableTimeout && rf.timeoutManager != nil
	case "recovery":
		return rf.config.EnableRecovery && rf.recoveryManager != nil
	default:
		return false
	}
}

// EnablePattern enables a specific resilience pattern at runtime
func (rf *ResilienceFramework) EnablePattern(pattern string) error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	
	switch pattern {
	case "circuit_breaker":
		if !rf.config.EnableCircuitBreaker {
			rf.config.EnableCircuitBreaker = true
			if rf.circuitBreaker == nil && rf.config.CircuitBreakerConfig != nil {
				rf.circuitBreaker = NewCircuitBreaker(rf.config.CircuitBreakerConfig)
			}
		}
	case "retry":
		if !rf.config.EnableRetry {
			rf.config.EnableRetry = true
			if rf.retryExecutor == nil && rf.config.RetryConfig != nil {
				rf.retryExecutor = NewRetryExecutor(rf.config.RetryConfig)
			}
		}
	case "timeout":
		if !rf.config.EnableTimeout {
			rf.config.EnableTimeout = true
			if rf.timeoutManager == nil && rf.config.TimeoutConfig != nil {
				rf.timeoutManager = NewTimeoutManager(rf.config.TimeoutConfig)
			}
		}
	case "recovery":
		if !rf.config.EnableRecovery {
			rf.config.EnableRecovery = true
			if rf.recoveryManager == nil && rf.config.RecoveryConfig != nil {
				rf.recoveryManager = NewRecoveryManager(rf.config.RecoveryConfig)
			}
		}
	default:
		return fmt.Errorf("unknown resilience pattern: %s", pattern)
	}
	
	log.Info().
		Str("pattern", pattern).
		Str("framework", rf.config.Name).
		Msg("Resilience pattern enabled")
	
	return nil
}

// DisablePattern disables a specific resilience pattern at runtime
func (rf *ResilienceFramework) DisablePattern(pattern string) error {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	
	switch pattern {
	case "circuit_breaker":
		rf.config.EnableCircuitBreaker = false
	case "retry":
		rf.config.EnableRetry = false
	case "timeout":
		rf.config.EnableTimeout = false
	case "recovery":
		rf.config.EnableRecovery = false
		if rf.recoveryManager != nil {
			rf.recoveryManager.Stop()
		}
	default:
		return fmt.Errorf("unknown resilience pattern: %s", pattern)
	}
	
	log.Info().
		Str("pattern", pattern).
		Str("framework", rf.config.Name).
		Msg("Resilience pattern disabled")
	
	return nil
}

// String returns a string representation of the resilience framework
func (rf *ResilienceFramework) String() string {
	patterns := make([]string, 0, 4)
	if rf.config.EnableCircuitBreaker {
		patterns = append(patterns, "circuit_breaker")
	}
	if rf.config.EnableRetry {
		patterns = append(patterns, "retry")
	}
	if rf.config.EnableTimeout {
		patterns = append(patterns, "timeout")
	}
	if rf.config.EnableRecovery {
		patterns = append(patterns, "recovery")
	}
	
	return fmt.Sprintf("ResilienceFramework{name=%s, patterns=%v}", rf.config.Name, patterns)
}

// Convenience functions for creating pre-configured resilience frameworks

// NewBasicResilience creates a basic resilience framework with retry and timeout
func NewBasicResilience(name string) *ResilienceFramework {
	config := &ResilienceConfig{
		Name:          name,
		EnableRetry:   true,
		EnableTimeout: true,
		RetryConfig: &RetryConfig{
			Name:        fmt.Sprintf("%s_retry", name),
			MaxAttempts: 3,
			BaseDelay:   100 * time.Millisecond,
			MaxDelay:    5 * time.Second,
			Policy:      RetryPolicyExponential,
			Jitter:      true,
		},
		TimeoutConfig: &TimeoutConfig{
			Name:           fmt.Sprintf("%s_timeout", name),
			Strategy:       TimeoutStrategyFixed,
			DefaultTimeout: 30 * time.Second,
		},
	}
	return NewResilienceFramework(config)
}

// NewAdvancedResilience creates an advanced resilience framework with all patterns
func NewAdvancedResilience(name string) *ResilienceFramework {
	config := DefaultResilienceConfig()
	config.Name = name
	return NewResilienceFramework(config)
}

// NewNetworkResilience creates a resilience framework optimized for network operations
func NewNetworkResilience(name string) *ResilienceFramework {
	config := &ResilienceConfig{
		Name:                name,
		EnableCircuitBreaker: true,
		EnableRetry:         true,
		EnableTimeout:       true,
		EnableRecovery:      true,
		CircuitBreakerConfig: &CircuitBreakerConfig{
			Name:             fmt.Sprintf("%s_circuit_breaker", name),
			MaxRequests:      5,
			FailureThreshold: 3,
			SuccessThreshold: 2,
			Timeout:          30 * time.Second,
			Interval:         60 * time.Second,
		},
		RetryConfig: &RetryConfig{
			Name:        fmt.Sprintf("%s_retry", name),
			MaxAttempts: 5,
			BaseDelay:   200 * time.Millisecond,
			MaxDelay:    10 * time.Second,
			Policy:      RetryPolicyExponential,
			Multiplier:  2.0,
			Jitter:      true,
		},
		TimeoutConfig: &TimeoutConfig{
			Name:           fmt.Sprintf("%s_timeout", name),
			Strategy:       TimeoutStrategyAdaptive,
			DefaultTimeout: 10 * time.Second,
			MinTimeout:     1 * time.Second,
			MaxTimeout:     60 * time.Second,
		},
		RecoveryConfig: &RecoveryConfig{
			Name:                fmt.Sprintf("%s_recovery", name),
			EnablePanicRecovery: true,
			MaxErrorsPerInterval: 50,
			ErrorInterval:       time.Minute,
		},
	}
	return NewResilienceFramework(config)
}