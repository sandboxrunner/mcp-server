package resilience

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int32

const (
	// CircuitBreakerClosed - normal operation, requests are allowed
	CircuitBreakerClosed CircuitBreakerState = iota
	// CircuitBreakerOpen - circuit is open, requests are rejected immediately
	CircuitBreakerOpen
	// CircuitBreakerHalfOpen - testing state, limited requests are allowed
	CircuitBreakerHalfOpen
)

func (s CircuitBreakerState) String() string {
	switch s {
	case CircuitBreakerClosed:
		return "CLOSED"
	case CircuitBreakerOpen:
		return "OPEN"
	case CircuitBreakerHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// CircuitBreakerConfig configuration for circuit breaker
type CircuitBreakerConfig struct {
	Name                    string        `json:"name"`
	MaxRequests             int64         `json:"max_requests"`              // Max requests in half-open state
	MaxRetries              int           `json:"max_retries"`               // Max retries before opening
	Interval                time.Duration `json:"interval"`                  // Interval for clearing counts
	Timeout                 time.Duration `json:"timeout"`                   // Timeout duration in open state
	FailureThreshold        int64         `json:"failure_threshold"`         // Number of failures to open circuit
	SuccessThreshold        int64         `json:"success_threshold"`         // Number of successes to close circuit
	MinRequestsBeforeTesting int64        `json:"min_requests_before_testing"` // Min requests before considering stats
	ErrorClassifier         func(error) bool `json:"-"`                     // Function to classify errors as failures
	FallbackFunc            func(context.Context) (interface{}, error) `json:"-"` // Fallback function when circuit is open
	OnStateChange          func(from, to CircuitBreakerState) `json:"-"` // Callback for state changes
}

// DefaultCircuitBreakerConfig returns default configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		Name:                    "default",
		MaxRequests:             5,
		MaxRetries:              3,
		Interval:                60 * time.Second,
		Timeout:                 60 * time.Second,
		FailureThreshold:        5,
		SuccessThreshold:        3,
		MinRequestsBeforeTesting: 10,
		ErrorClassifier: func(err error) bool {
			// By default, all errors are considered failures
			return err != nil
		},
		FallbackFunc: func(ctx context.Context) (interface{}, error) {
			return nil, ErrCircuitBreakerOpen
		},
	}
}

// CircuitBreakerMetrics tracks circuit breaker statistics
type CircuitBreakerMetrics struct {
	Name            string        `json:"name"`
	State           string        `json:"state"`
	TotalRequests   int64         `json:"total_requests"`
	SuccessCount    int64         `json:"success_count"`
	FailureCount    int64         `json:"failure_count"`
	ConsecutiveFailures int64     `json:"consecutive_failures"`
	ConsecutiveSuccesses int64    `json:"consecutive_successes"`
	RequestsInHalfOpen int64      `json:"requests_in_half_open"`
	LastStateChange time.Time     `json:"last_state_change"`
	LastFailureTime time.Time     `json:"last_failure_time,omitempty"`
	LastSuccessTime time.Time     `json:"last_success_time,omitempty"`
	OpenDuration    time.Duration `json:"open_duration,omitempty"`
}

// CircuitBreakerEvent represents events from the circuit breaker
type CircuitBreakerEvent struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	FromState   string                 `json:"from_state,omitempty"`
	ToState     string                 `json:"to_state,omitempty"`
	Reason      string                 `json:"reason"`
	Timestamp   time.Time              `json:"timestamp"`
	Metrics     *CircuitBreakerMetrics `json:"metrics,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config  *CircuitBreakerConfig
	state   CircuitBreakerState
	mu      sync.RWMutex
	
	// Metrics
	totalRequests          int64
	successCount          int64  
	failureCount          int64
	consecutiveFailures   int64
	consecutiveSuccesses  int64
	requestsInHalfOpen    int64
	
	// Timestamps
	lastStateChange       time.Time
	lastFailureTime       time.Time
	lastSuccessTime       time.Time
	intervalStartTime     time.Time
	
	// Event handling
	eventListeners []func(*CircuitBreakerEvent)
	eventMu        sync.RWMutex
}

// Common circuit breaker errors
var (
	ErrCircuitBreakerOpen         = errors.New("circuit breaker is open")
	ErrCircuitBreakerTimeout      = errors.New("circuit breaker timeout")
	ErrCircuitBreakerMaxRequests  = errors.New("circuit breaker max requests exceeded")
	ErrCircuitBreakerInvalidState = errors.New("circuit breaker invalid state")
)

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config == nil {
		config = DefaultCircuitBreakerConfig()
	}
	
	// Validate configuration
	if config.MaxRequests <= 0 {
		config.MaxRequests = 5
	}
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = 3
	}
	if config.Interval <= 0 {
		config.Interval = 60 * time.Second
	}
	if config.Timeout <= 0 {
		config.Timeout = 60 * time.Second
	}
	if config.ErrorClassifier == nil {
		config.ErrorClassifier = func(err error) bool { return err != nil }
	}
	
	now := time.Now()
	cb := &CircuitBreaker{
		config:            config,
		state:             CircuitBreakerClosed,
		lastStateChange:   now,
		intervalStartTime: now,
		eventListeners:    make([]func(*CircuitBreakerEvent), 0),
	}
	
	cb.emitEvent(&CircuitBreakerEvent{
		Type:      "created",
		Name:      config.Name,
		Reason:    "circuit breaker created",
		Timestamp: now,
		Metrics:   cb.GetMetrics(),
	})
	
	log.Info().
		Str("name", config.Name).
		Str("state", cb.state.String()).
		Msg("Circuit breaker created")
	
	return cb
}

// Execute executes the given function with circuit breaker protection
func (cb *CircuitBreaker) Execute(ctx context.Context, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	// Check if we can proceed
	if err := cb.beforeRequest(); err != nil {
		return cb.handleFallback(ctx, err)
	}
	
	// Execute the operation
	result, err := operation(ctx)
	
	// Record the result
	cb.afterRequest(err)
	
	return result, err
}

// beforeRequest checks if a request can proceed based on circuit breaker state
func (cb *CircuitBreaker) beforeRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	atomic.AddInt64(&cb.totalRequests, 1)
	
	now := time.Now()
	
	// Reset counters if interval has passed
	if now.Sub(cb.intervalStartTime) >= cb.config.Interval {
		cb.resetCounts()
		cb.intervalStartTime = now
	}
	
	switch cb.state {
	case CircuitBreakerClosed:
		return nil
		
	case CircuitBreakerOpen:
		// Check if timeout period has elapsed
		if now.Sub(cb.lastStateChange) >= cb.config.Timeout {
			cb.changeState(CircuitBreakerHalfOpen, "timeout period elapsed")
			return nil
		}
		return ErrCircuitBreakerOpen
		
	case CircuitBreakerHalfOpen:
		// Limit requests in half-open state
		if atomic.LoadInt64(&cb.requestsInHalfOpen) >= cb.config.MaxRequests {
			return ErrCircuitBreakerMaxRequests
		}
		atomic.AddInt64(&cb.requestsInHalfOpen, 1)
		return nil
		
	default:
		return ErrCircuitBreakerInvalidState
	}
}

// afterRequest records the result and updates circuit breaker state
func (cb *CircuitBreaker) afterRequest(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	now := time.Now()
	isFailure := cb.config.ErrorClassifier(err)
	
	if isFailure {
		atomic.AddInt64(&cb.failureCount, 1)
		atomic.AddInt64(&cb.consecutiveFailures, 1)
		atomic.StoreInt64(&cb.consecutiveSuccesses, 0)
		cb.lastFailureTime = now
		
		cb.emitEvent(&CircuitBreakerEvent{
			Type:      "failure",
			Name:      cb.config.Name,
			Reason:    "operation failed",
			Timestamp: now,
			Error:     err.Error(),
			Metrics:   cb.getMetricsUnsafe(),
		})
		
		// Check if we should open the circuit
		if cb.shouldOpen() {
			cb.changeState(CircuitBreakerOpen, fmt.Sprintf("failure threshold reached: %d failures", cb.consecutiveFailures))
		}
	} else {
		atomic.AddInt64(&cb.successCount, 1)
		atomic.AddInt64(&cb.consecutiveSuccesses, 1)
		atomic.StoreInt64(&cb.consecutiveFailures, 0)
		cb.lastSuccessTime = now
		
		cb.emitEvent(&CircuitBreakerEvent{
			Type:      "success",
			Name:      cb.config.Name,
			Reason:    "operation succeeded",
			Timestamp: now,
			Metrics:   cb.getMetricsUnsafe(),
		})
		
		// Check if we should close the circuit (only in half-open state)
		if cb.state == CircuitBreakerHalfOpen && cb.shouldClose() {
			cb.changeState(CircuitBreakerClosed, fmt.Sprintf("success threshold reached: %d successes", cb.consecutiveSuccesses))
		}
	}
}

// shouldOpen determines if the circuit should be opened
func (cb *CircuitBreaker) shouldOpen() bool {
	// Only consider opening if we have enough requests
	if cb.totalRequests < cb.config.MinRequestsBeforeTesting {
		return false
	}
	
	// Open if we've reached the failure threshold
	return cb.state == CircuitBreakerClosed && 
		atomic.LoadInt64(&cb.consecutiveFailures) >= cb.config.FailureThreshold
}

// shouldClose determines if the circuit should be closed (from half-open)
func (cb *CircuitBreaker) shouldClose() bool {
	return atomic.LoadInt64(&cb.consecutiveSuccesses) >= cb.config.SuccessThreshold
}

// changeState changes the circuit breaker state and triggers events
func (cb *CircuitBreaker) changeState(newState CircuitBreakerState, reason string) {
	if cb.state == newState {
		return
	}
	
	oldState := cb.state
	cb.state = newState
	cb.lastStateChange = time.Now()
	
	// Reset half-open counter when leaving half-open state
	if oldState == CircuitBreakerHalfOpen {
		atomic.StoreInt64(&cb.requestsInHalfOpen, 0)
	}
	
	// Trigger state change callback
	if cb.config.OnStateChange != nil {
		go cb.config.OnStateChange(oldState, newState)
	}
	
	cb.emitEvent(&CircuitBreakerEvent{
		Type:      "state_change",
		Name:      cb.config.Name,
		FromState: oldState.String(),
		ToState:   newState.String(),
		Reason:    reason,
		Timestamp: cb.lastStateChange,
		Metrics:   cb.getMetricsUnsafe(),
	})
	
	log.Info().
		Str("name", cb.config.Name).
		Str("from", oldState.String()).
		Str("to", newState.String()).
		Str("reason", reason).
		Msg("Circuit breaker state changed")
}

// resetCounts resets the counters for the new interval
func (cb *CircuitBreaker) resetCounts() {
	// Keep consecutive counts but reset interval-based counts
	atomic.StoreInt64(&cb.totalRequests, 0)
	atomic.StoreInt64(&cb.successCount, 0)
	atomic.StoreInt64(&cb.failureCount, 0)
}

// handleFallback handles fallback logic when circuit is open
func (cb *CircuitBreaker) handleFallback(ctx context.Context, originalErr error) (interface{}, error) {
	if cb.config.FallbackFunc != nil {
		result, err := cb.config.FallbackFunc(ctx)
		
		cb.emitEvent(&CircuitBreakerEvent{
			Type:      "fallback",
			Name:      cb.config.Name,
			Reason:    "fallback executed",
			Timestamp: time.Now(),
			Error:     originalErr.Error(),
			Metadata: map[string]interface{}{
				"fallback_error": err,
			},
		})
		
		return result, err
	}
	
	return nil, originalErr
}

// GetState returns the current circuit breaker state
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	return CircuitBreakerState(atomic.LoadInt32((*int32)(&cb.state)))
}

// GetMetrics returns current circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() *CircuitBreakerMetrics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.getMetricsUnsafe()
}

// getMetricsUnsafe returns metrics without locking (caller must hold lock)
func (cb *CircuitBreaker) getMetricsUnsafe() *CircuitBreakerMetrics {
	metrics := &CircuitBreakerMetrics{
		Name:                     cb.config.Name,
		State:                    cb.state.String(),
		TotalRequests:           atomic.LoadInt64(&cb.totalRequests),
		SuccessCount:            atomic.LoadInt64(&cb.successCount),
		FailureCount:            atomic.LoadInt64(&cb.failureCount),
		ConsecutiveFailures:     atomic.LoadInt64(&cb.consecutiveFailures),
		ConsecutiveSuccesses:    atomic.LoadInt64(&cb.consecutiveSuccesses),
		RequestsInHalfOpen:      atomic.LoadInt64(&cb.requestsInHalfOpen),
		LastStateChange:         cb.lastStateChange,
	}
	
	if !cb.lastFailureTime.IsZero() {
		metrics.LastFailureTime = cb.lastFailureTime
	}
	if !cb.lastSuccessTime.IsZero() {
		metrics.LastSuccessTime = cb.lastSuccessTime
	}
	
	if cb.state == CircuitBreakerOpen {
		metrics.OpenDuration = time.Since(cb.lastStateChange)
	}
	
	return metrics
}

// Reset resets the circuit breaker to its initial state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	now := time.Now()
	
	atomic.StoreInt64(&cb.totalRequests, 0)
	atomic.StoreInt64(&cb.successCount, 0)
	atomic.StoreInt64(&cb.failureCount, 0)
	atomic.StoreInt64(&cb.consecutiveFailures, 0)
	atomic.StoreInt64(&cb.consecutiveSuccesses, 0)
	atomic.StoreInt64(&cb.requestsInHalfOpen, 0)
	
	cb.state = CircuitBreakerClosed
	cb.lastStateChange = now
	cb.intervalStartTime = now
	cb.lastFailureTime = time.Time{}
	cb.lastSuccessTime = time.Time{}
	
	cb.emitEvent(&CircuitBreakerEvent{
		Type:      "reset",
		Name:      cb.config.Name,
		Reason:    "circuit breaker reset",
		Timestamp: now,
		Metrics:   cb.getMetricsUnsafe(),
	})
	
	log.Info().
		Str("name", cb.config.Name).
		Msg("Circuit breaker reset")
}

// ForceOpen forces the circuit breaker to open state
func (cb *CircuitBreaker) ForceOpen(reason string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if reason == "" {
		reason = "manually forced open"
	}
	
	cb.changeState(CircuitBreakerOpen, reason)
}

// ForceClose forces the circuit breaker to closed state
func (cb *CircuitBreaker) ForceClose(reason string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	
	if reason == "" {
		reason = "manually forced closed"
	}
	
	cb.changeState(CircuitBreakerClosed, reason)
	
	// Reset consecutive failures when manually closing
	atomic.StoreInt64(&cb.consecutiveFailures, 0)
}

// AddEventListener adds an event listener for circuit breaker events
func (cb *CircuitBreaker) AddEventListener(listener func(*CircuitBreakerEvent)) {
	cb.eventMu.Lock()
	defer cb.eventMu.Unlock()
	
	cb.eventListeners = append(cb.eventListeners, listener)
}

// RemoveEventListener removes an event listener (note: this removes all identical listeners)
func (cb *CircuitBreaker) RemoveEventListener(listener func(*CircuitBreakerEvent)) {
	cb.eventMu.Lock()
	defer cb.eventMu.Unlock()
	
	// Note: This is a simple implementation. In production, you might want
	// to use a more sophisticated approach to identify specific listeners.
	var filtered []func(*CircuitBreakerEvent)
	for _, l := range cb.eventListeners {
		if &l != &listener {
			filtered = append(filtered, l)
		}
	}
	cb.eventListeners = filtered
}

// emitEvent emits an event to all registered listeners
func (cb *CircuitBreaker) emitEvent(event *CircuitBreakerEvent) {
	cb.eventMu.RLock()
	listeners := make([]func(*CircuitBreakerEvent), len(cb.eventListeners))
	copy(listeners, cb.eventListeners)
	cb.eventMu.RUnlock()
	
	// Emit events asynchronously to avoid blocking
	for _, listener := range listeners {
		go func(l func(*CircuitBreakerEvent)) {
			defer func() {
				if r := recover(); r != nil {
					log.Error().
						Interface("panic", r).
						Str("circuit_breaker", cb.config.Name).
						Msg("Panic in circuit breaker event listener")
				}
			}()
			l(event)
		}(listener)
	}
}

// String returns a string representation of the circuit breaker
func (cb *CircuitBreaker) String() string {
	metrics := cb.GetMetrics()
	return fmt.Sprintf("CircuitBreaker{name=%s, state=%s, failures=%d, successes=%d}", 
		metrics.Name, metrics.State, metrics.ConsecutiveFailures, metrics.ConsecutiveSuccesses)
}