package resilience

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// RetryPolicy defines different retry strategies
type RetryPolicy string

const (
	// RetryPolicyFixed uses fixed delay between retries
	RetryPolicyFixed RetryPolicy = "fixed"
	// RetryPolicyExponential uses exponential backoff
	RetryPolicyExponential RetryPolicy = "exponential"
	// RetryPolicyLinear uses linear backoff
	RetryPolicyLinear RetryPolicy = "linear"
	// RetryPolicyCustom uses custom delay function
	RetryPolicyCustom RetryPolicy = "custom"
)

// RetryConfig configuration for retry mechanisms
type RetryConfig struct {
	Name                string        `json:"name"`
	MaxAttempts         int           `json:"max_attempts"`          // Maximum number of retry attempts
	BaseDelay           time.Duration `json:"base_delay"`            // Base delay for first retry
	MaxDelay            time.Duration `json:"max_delay"`             // Maximum delay between retries
	Multiplier          float64       `json:"multiplier"`            // Multiplier for exponential backoff
	Jitter              bool          `json:"jitter"`                // Whether to add jitter to delays
	JitterRange         float64       `json:"jitter_range"`          // Jitter range (0.0 to 1.0)
	Policy              RetryPolicy   `json:"policy"`                // Retry policy to use
	Budget              time.Duration `json:"budget"`                // Total time budget for all retries
	EnableCircuitBreaker bool         `json:"enable_circuit_breaker"`// Whether to use circuit breaker
	
	// Functions
	IsRetryable         func(error) bool                    `json:"-"` // Function to determine if error is retryable
	DelayFunc           func(attempt int) time.Duration     `json:"-"` // Custom delay function
	OnRetry             func(attempt int, err error)        `json:"-"` // Callback on each retry
	BeforeRetry         func(ctx context.Context) error     `json:"-"` // Called before each retry
	AfterRetry          func(ctx context.Context, err error) `json:"-"` // Called after each retry
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		Name:        "default",
		MaxAttempts: 3,
		BaseDelay:   100 * time.Millisecond,
		MaxDelay:    30 * time.Second,
		Multiplier:  2.0,
		Jitter:      true,
		JitterRange: 0.1,
		Policy:      RetryPolicyExponential,
		Budget:      5 * time.Minute,
		IsRetryable: func(err error) bool {
			// By default, all errors except context errors are retryable
			return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
		},
	}
}

// RetryMetrics tracks retry statistics
type RetryMetrics struct {
	Name              string        `json:"name"`
	TotalAttempts     int64         `json:"total_attempts"`
	TotalRetries      int64         `json:"total_retries"`
	TotalSuccesses    int64         `json:"total_successes"`
	TotalFailures     int64         `json:"total_failures"`
	TotalBudgetExceeded int64       `json:"total_budget_exceeded"`
	AverageAttempts   float64       `json:"average_attempts"`
	AverageDelay      time.Duration `json:"average_delay"`
	LastAttemptTime   time.Time     `json:"last_attempt_time"`
	TotalDelay        time.Duration `json:"total_delay"`
}

// RetryAttempt represents a single retry attempt
type RetryAttempt struct {
	Number    int           `json:"number"`
	Delay     time.Duration `json:"delay"`
	Error     error         `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
	Duration  time.Duration `json:"duration"`
}

// RetryEvent represents events from the retry mechanism
type RetryEvent struct {
	Type        string         `json:"type"`
	Name        string         `json:"name"`
	Attempt     *RetryAttempt  `json:"attempt,omitempty"`
	TotalDelay  time.Duration  `json:"total_delay"`
	Reason      string         `json:"reason"`
	Timestamp   time.Time      `json:"timestamp"`
	Metrics     *RetryMetrics  `json:"metrics,omitempty"`
	Error       string         `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// BudgetTracker tracks retry budget usage
type BudgetTracker struct {
	totalBudget time.Duration
	used        time.Duration
	startTime   time.Time
	mu          sync.RWMutex
}

// NewBudgetTracker creates a new budget tracker
func NewBudgetTracker(budget time.Duration) *BudgetTracker {
	return &BudgetTracker{
		totalBudget: budget,
		startTime:   time.Now(),
	}
}

// Use attempts to use the specified duration from the budget
func (bt *BudgetTracker) Use(duration time.Duration) bool {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	
	if bt.used+duration > bt.totalBudget {
		return false
	}
	
	bt.used += duration
	return true
}

// Remaining returns the remaining budget
func (bt *BudgetTracker) Remaining() time.Duration {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	
	return bt.totalBudget - bt.used
}

// Used returns the used budget
func (bt *BudgetTracker) Used() time.Duration {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	
	return bt.used
}

// RetryExecutor executes operations with retry logic
type RetryExecutor struct {
	config         *RetryConfig
	circuitBreaker *CircuitBreaker
	metrics        *RetryMetrics
	mu             sync.RWMutex
	eventListeners []func(*RetryEvent)
	eventMu        sync.RWMutex
}

// Common retry errors
var (
	ErrMaxAttemptsExceeded = errors.New("maximum retry attempts exceeded")
	ErrBudgetExceeded      = errors.New("retry budget exceeded")
	ErrNotRetryable        = errors.New("error is not retryable")
	ErrRetryContextCanceled = errors.New("retry context canceled")
)

// NewRetryExecutor creates a new retry executor
func NewRetryExecutor(config *RetryConfig) *RetryExecutor {
	if config == nil {
		config = DefaultRetryConfig()
	}
	
	// Validate configuration
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 3
	}
	if config.BaseDelay <= 0 {
		config.BaseDelay = 100 * time.Millisecond
	}
	if config.MaxDelay <= 0 {
		config.MaxDelay = 30 * time.Second
	}
	if config.Multiplier <= 0 {
		config.Multiplier = 2.0
	}
	if config.JitterRange < 0 || config.JitterRange > 1 {
		config.JitterRange = 0.1
	}
	if config.Budget <= 0 {
		config.Budget = 5 * time.Minute
	}
	if config.IsRetryable == nil {
		config.IsRetryable = func(err error) bool {
			return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
		}
	}
	
	re := &RetryExecutor{
		config: config,
		metrics: &RetryMetrics{
			Name: config.Name,
		},
		eventListeners: make([]func(*RetryEvent), 0),
	}
	
	// Create circuit breaker if enabled
	if config.EnableCircuitBreaker {
		cbConfig := DefaultCircuitBreakerConfig()
		cbConfig.Name = fmt.Sprintf("%s_circuit_breaker", config.Name)
		re.circuitBreaker = NewCircuitBreaker(cbConfig)
	}
	
	log.Info().
		Str("name", config.Name).
		Int("max_attempts", config.MaxAttempts).
		Dur("base_delay", config.BaseDelay).
		Str("policy", string(config.Policy)).
		Msg("Retry executor created")
	
	return re
}

// Execute executes an operation with retry logic
func (re *RetryExecutor) Execute(ctx context.Context, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	return re.ExecuteWithIdempotencyKey(ctx, "", operation)
}

// ExecuteWithIdempotencyKey executes an operation with retry logic and idempotency checking
func (re *RetryExecutor) ExecuteWithIdempotencyKey(ctx context.Context, idempotencyKey string, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	budgetTracker := NewBudgetTracker(re.config.Budget)
	attempts := make([]*RetryAttempt, 0, re.config.MaxAttempts)
	startTime := time.Now()
	
	// Update metrics
	atomic.AddInt64(&re.metrics.TotalAttempts, 1)
	re.metrics.LastAttemptTime = startTime
	
	re.emitEvent(&RetryEvent{
		Type:      "started",
		Name:      re.config.Name,
		Reason:    "retry execution started",
		Timestamp: startTime,
		Metrics:   re.GetMetrics(),
		Metadata: map[string]interface{}{
			"idempotency_key": idempotencyKey,
		},
	})
	
	// Execute with circuit breaker if enabled
	if re.circuitBreaker != nil {
		return re.circuitBreaker.Execute(ctx, func(ctx context.Context) (interface{}, error) {
			return re.executeWithRetries(ctx, operation, budgetTracker, attempts)
		})
	}
	
	return re.executeWithRetries(ctx, operation, budgetTracker, attempts)
}

// executeWithRetries performs the actual retry logic
func (re *RetryExecutor) executeWithRetries(ctx context.Context, operation func(context.Context) (interface{}, error), budgetTracker *BudgetTracker, attempts []*RetryAttempt) (interface{}, error) {
	var lastErr error
	
	for attempt := 1; attempt <= re.config.MaxAttempts; attempt++ {
		// Check context
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrRetryContextCanceled, ctx.Err())
		default:
		}
		
		// Call before retry hook
		if re.config.BeforeRetry != nil {
			if err := re.config.BeforeRetry(ctx); err != nil {
				return nil, fmt.Errorf("before retry hook failed: %w", err)
			}
		}
		
		attemptStart := time.Now()
		
		// Execute operation
		result, err := operation(ctx)
		
		attemptDuration := time.Since(attemptStart)
		attemptInfo := &RetryAttempt{
			Number:    attempt,
			Error:     err,
			Timestamp: attemptStart,
			Duration:  attemptDuration,
		}
		attempts = append(attempts, attemptInfo)
		
		// Call after retry hook
		if re.config.AfterRetry != nil {
			re.config.AfterRetry(ctx, err)
		}
		
		if err == nil {
			// Success
			atomic.AddInt64(&re.metrics.TotalSuccesses, 1)
			re.updateAverageMetrics(attempt)
			
			re.emitEvent(&RetryEvent{
				Type:      "success",
				Name:      re.config.Name,
				Attempt:   attemptInfo,
				TotalDelay: time.Since(re.metrics.LastAttemptTime) - attemptDuration,
				Reason:    "operation succeeded",
				Timestamp: time.Now(),
				Metrics:   re.GetMetrics(),
			})
			
			return result, nil
		}
		
		lastErr = err
		atomic.AddInt64(&re.metrics.TotalRetries, 1)
		
		// Check if error is retryable
		if !re.config.IsRetryable(err) {
			atomic.AddInt64(&re.metrics.TotalFailures, 1)
			
			re.emitEvent(&RetryEvent{
				Type:      "non_retryable",
				Name:      re.config.Name,
				Attempt:   attemptInfo,
				Reason:    "error is not retryable",
				Timestamp: time.Now(),
				Error:     err.Error(),
				Metrics:   re.GetMetrics(),
			})
			
			return nil, fmt.Errorf("%w: %v", ErrNotRetryable, err)
		}
		
		// Don't delay after the last attempt
		if attempt == re.config.MaxAttempts {
			break
		}
		
		// Calculate delay
		delay := re.calculateDelay(attempt)
		attemptInfo.Delay = delay
		
		// Check budget
		if !budgetTracker.Use(delay) {
			atomic.AddInt64(&re.metrics.TotalBudgetExceeded, 1)
			atomic.AddInt64(&re.metrics.TotalFailures, 1)
			
			re.emitEvent(&RetryEvent{
				Type:       "budget_exceeded",
				Name:       re.config.Name,
				Attempt:    attemptInfo,
				TotalDelay: budgetTracker.Used(),
				Reason:     "retry budget exceeded",
				Timestamp:  time.Now(),
				Error:      err.Error(),
				Metrics:    re.GetMetrics(),
			})
			
			return nil, fmt.Errorf("%w: remaining budget %v, needed %v", 
				ErrBudgetExceeded, budgetTracker.Remaining(), delay)
		}
		
		// Call on retry callback
		if re.config.OnRetry != nil {
			re.config.OnRetry(attempt, err)
		}
		
		re.emitEvent(&RetryEvent{
			Type:      "retry",
			Name:      re.config.Name,
			Attempt:   attemptInfo,
			TotalDelay: budgetTracker.Used(),
			Reason:    fmt.Sprintf("retrying after attempt %d", attempt),
			Timestamp: time.Now(),
			Error:     err.Error(),
			Metrics:   re.GetMetrics(),
		})
		
		// Wait for delay
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %v", ErrRetryContextCanceled, ctx.Err())
		}
	}
	
	// All attempts failed
	atomic.AddInt64(&re.metrics.TotalFailures, 1)
	re.updateAverageMetrics(re.config.MaxAttempts)
	
	re.emitEvent(&RetryEvent{
		Type:       "max_attempts_exceeded",
		Name:       re.config.Name,
		TotalDelay: budgetTracker.Used(),
		Reason:     "maximum retry attempts exceeded",
		Timestamp:  time.Now(),
		Error:      lastErr.Error(),
		Metrics:    re.GetMetrics(),
		Metadata: map[string]interface{}{
			"attempts": attempts,
		},
	})
	
	return nil, fmt.Errorf("%w after %d attempts: %v", ErrMaxAttemptsExceeded, re.config.MaxAttempts, lastErr)
}

// calculateDelay calculates the delay for a given attempt
func (re *RetryExecutor) calculateDelay(attempt int) time.Duration {
	var delay time.Duration
	
	switch re.config.Policy {
	case RetryPolicyFixed:
		delay = re.config.BaseDelay
		
	case RetryPolicyLinear:
		delay = time.Duration(int64(re.config.BaseDelay) * int64(attempt))
		
	case RetryPolicyExponential:
		delay = time.Duration(float64(re.config.BaseDelay) * math.Pow(re.config.Multiplier, float64(attempt-1)))
		
	case RetryPolicyCustom:
		if re.config.DelayFunc != nil {
			delay = re.config.DelayFunc(attempt)
		} else {
			// Fallback to exponential
			delay = time.Duration(float64(re.config.BaseDelay) * math.Pow(re.config.Multiplier, float64(attempt-1)))
		}
		
	default:
		// Default to exponential
		delay = time.Duration(float64(re.config.BaseDelay) * math.Pow(re.config.Multiplier, float64(attempt-1)))
	}
	
	// Apply maximum delay
	if delay > re.config.MaxDelay {
		delay = re.config.MaxDelay
	}
	
	// Apply jitter if enabled
	if re.config.Jitter {
		delay = re.addJitter(delay)
	}
	
	return delay
}

// addJitter adds jitter to the delay
func (re *RetryExecutor) addJitter(delay time.Duration) time.Duration {
	if re.config.JitterRange <= 0 {
		return delay
	}
	
	// Calculate jitter range
	jitterAmount := float64(delay) * re.config.JitterRange
	
	// Apply random jitter (can be positive or negative)
	jitter := (rand.Float64() - 0.5) * 2 * jitterAmount
	newDelay := float64(delay) + jitter
	
	// Ensure delay is not negative
	if newDelay < 0 {
		newDelay = float64(delay) * 0.1 // Minimum 10% of original delay
	}
	
	return time.Duration(newDelay)
}

// updateAverageMetrics updates the average metrics
func (re *RetryExecutor) updateAverageMetrics(attempts int) {
	re.mu.Lock()
	defer re.mu.Unlock()
	
	// Update average attempts (simple moving average)
	totalAttempts := atomic.LoadInt64(&re.metrics.TotalAttempts)
	if totalAttempts > 0 {
		re.metrics.AverageAttempts = ((re.metrics.AverageAttempts * float64(totalAttempts-1)) + float64(attempts)) / float64(totalAttempts)
	}
}

// GetMetrics returns current retry metrics
func (re *RetryExecutor) GetMetrics() *RetryMetrics {
	re.mu.RLock()
	defer re.mu.RUnlock()
	
	return &RetryMetrics{
		Name:                re.metrics.Name,
		TotalAttempts:       atomic.LoadInt64(&re.metrics.TotalAttempts),
		TotalRetries:        atomic.LoadInt64(&re.metrics.TotalRetries),
		TotalSuccesses:      atomic.LoadInt64(&re.metrics.TotalSuccesses),
		TotalFailures:       atomic.LoadInt64(&re.metrics.TotalFailures),
		TotalBudgetExceeded: atomic.LoadInt64(&re.metrics.TotalBudgetExceeded),
		AverageAttempts:     re.metrics.AverageAttempts,
		AverageDelay:        re.metrics.AverageDelay,
		LastAttemptTime:     re.metrics.LastAttemptTime,
		TotalDelay:          re.metrics.TotalDelay,
	}
}

// Reset resets the retry executor metrics
func (re *RetryExecutor) Reset() {
	re.mu.Lock()
	defer re.mu.Unlock()
	
	atomic.StoreInt64(&re.metrics.TotalAttempts, 0)
	atomic.StoreInt64(&re.metrics.TotalRetries, 0)
	atomic.StoreInt64(&re.metrics.TotalSuccesses, 0)
	atomic.StoreInt64(&re.metrics.TotalFailures, 0)
	atomic.StoreInt64(&re.metrics.TotalBudgetExceeded, 0)
	re.metrics.AverageAttempts = 0
	re.metrics.AverageDelay = 0
	re.metrics.LastAttemptTime = time.Time{}
	re.metrics.TotalDelay = 0
	
	if re.circuitBreaker != nil {
		re.circuitBreaker.Reset()
	}
	
	re.emitEvent(&RetryEvent{
		Type:      "reset",
		Name:      re.config.Name,
		Reason:    "retry executor reset",
		Timestamp: time.Now(),
		Metrics:   re.metrics,
	})
	
	log.Info().
		Str("name", re.config.Name).
		Msg("Retry executor reset")
}

// GetCircuitBreaker returns the associated circuit breaker (if any)
func (re *RetryExecutor) GetCircuitBreaker() *CircuitBreaker {
	return re.circuitBreaker
}

// AddEventListener adds an event listener for retry events
func (re *RetryExecutor) AddEventListener(listener func(*RetryEvent)) {
	re.eventMu.Lock()
	defer re.eventMu.Unlock()
	
	re.eventListeners = append(re.eventListeners, listener)
}

// RemoveEventListener removes an event listener
func (re *RetryExecutor) RemoveEventListener(listener func(*RetryEvent)) {
	re.eventMu.Lock()
	defer re.eventMu.Unlock()
	
	var filtered []func(*RetryEvent)
	for _, l := range re.eventListeners {
		if &l != &listener {
			filtered = append(filtered, l)
		}
	}
	re.eventListeners = filtered
}

// emitEvent emits an event to all registered listeners
func (re *RetryExecutor) emitEvent(event *RetryEvent) {
	re.eventMu.RLock()
	listeners := make([]func(*RetryEvent), len(re.eventListeners))
	copy(listeners, re.eventListeners)
	re.eventMu.RUnlock()
	
	// Emit events asynchronously
	for _, listener := range listeners {
		go func(l func(*RetryEvent)) {
			defer func() {
				if r := recover(); r != nil {
					log.Error().
						Interface("panic", r).
						Str("retry_executor", re.config.Name).
						Msg("Panic in retry event listener")
				}
			}()
			l(event)
		}(listener)
	}
}

// String returns a string representation of the retry executor
func (re *RetryExecutor) String() string {
	metrics := re.GetMetrics()
	return fmt.Sprintf("RetryExecutor{name=%s, attempts=%d, successes=%d, failures=%d}",
		metrics.Name, metrics.TotalAttempts, metrics.TotalSuccesses, metrics.TotalFailures)
}

// Convenience functions for common retry patterns

// WithExponentialBackoff creates a retry executor with exponential backoff
func WithExponentialBackoff(name string, maxAttempts int, baseDelay, maxDelay time.Duration) *RetryExecutor {
	config := &RetryConfig{
		Name:        name,
		MaxAttempts: maxAttempts,
		BaseDelay:   baseDelay,
		MaxDelay:    maxDelay,
		Multiplier:  2.0,
		Jitter:      true,
		JitterRange: 0.1,
		Policy:      RetryPolicyExponential,
		Budget:      5 * time.Minute,
		IsRetryable: func(err error) bool {
			return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
		},
	}
	return NewRetryExecutor(config)
}

// WithFixedDelay creates a retry executor with fixed delay
func WithFixedDelay(name string, maxAttempts int, delay time.Duration) *RetryExecutor {
	config := &RetryConfig{
		Name:        name,
		MaxAttempts: maxAttempts,
		BaseDelay:   delay,
		MaxDelay:    delay,
		Policy:      RetryPolicyFixed,
		Budget:      5 * time.Minute,
		IsRetryable: func(err error) bool {
			return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
		},
	}
	return NewRetryExecutor(config)
}

// WithCircuitBreaker creates a retry executor with circuit breaker integration
func WithCircuitBreaker(name string, maxAttempts int, baseDelay, maxDelay time.Duration) *RetryExecutor {
	config := &RetryConfig{
		Name:                 name,
		MaxAttempts:         maxAttempts,
		BaseDelay:           baseDelay,
		MaxDelay:            maxDelay,
		Multiplier:          2.0,
		Jitter:              true,
		JitterRange:         0.1,
		Policy:              RetryPolicyExponential,
		Budget:              5 * time.Minute,
		EnableCircuitBreaker: true,
		IsRetryable: func(err error) bool {
			return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
		},
	}
	return NewRetryExecutor(config)
}