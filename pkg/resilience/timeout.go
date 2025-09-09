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

// TimeoutStrategy defines different timeout strategies
type TimeoutStrategy string

const (
	// TimeoutStrategyFixed uses a fixed timeout duration
	TimeoutStrategyFixed TimeoutStrategy = "fixed"
	// TimeoutStrategyAdaptive adjusts timeout based on historical data
	TimeoutStrategyAdaptive TimeoutStrategy = "adaptive"
	// TimeoutStrategyPercentile uses percentile-based timeout
	TimeoutStrategyPercentile TimeoutStrategy = "percentile"
	// TimeoutStrategyHierarchical uses hierarchical timeouts
	TimeoutStrategyHierarchical TimeoutStrategy = "hierarchical"
)

// TimeoutLevel represents different levels in hierarchical timeout
type TimeoutLevel string

const (
	// TimeoutLevelRequest - individual request timeout
	TimeoutLevelRequest TimeoutLevel = "request"
	// TimeoutLevelOperation - operation timeout (multiple requests)
	TimeoutLevelOperation TimeoutLevel = "operation"
	// TimeoutLevelSession - session timeout (multiple operations)
	TimeoutLevelSession TimeoutLevel = "session"
	// TimeoutLevelGlobal - global timeout (entire workflow)
	TimeoutLevelGlobal TimeoutLevel = "global"
)

// TimeoutConfig configuration for timeout management
type TimeoutConfig struct {
	Name                  string                    `json:"name"`
	Strategy              TimeoutStrategy           `json:"strategy"`
	DefaultTimeout        time.Duration             `json:"default_timeout"`
	MinTimeout            time.Duration             `json:"min_timeout"`
	MaxTimeout            time.Duration             `json:"max_timeout"`
	AdaptiveConfig        *AdaptiveTimeoutConfig    `json:"adaptive_config,omitempty"`
	PercentileConfig      *PercentileTimeoutConfig  `json:"percentile_config,omitempty"`
	HierarchicalConfig    *HierarchicalTimeoutConfig `json:"hierarchical_config,omitempty"`
	WarningThreshold      float64                   `json:"warning_threshold"`      // Percentage of timeout to trigger warning
	EnableWarnings        bool                      `json:"enable_warnings"`
	EnableMetrics         bool                      `json:"enable_metrics"`
	OnTimeout             func(context.Context, time.Duration) `json:"-"` // Callback on timeout
	OnWarning             func(context.Context, time.Duration, time.Duration) `json:"-"` // Callback on warning
	ShouldCancel          func(context.Context) bool `json:"-"` // Function to determine if operation should be canceled
}

// AdaptiveTimeoutConfig configuration for adaptive timeout strategy
type AdaptiveTimeoutConfig struct {
	WindowSize       int     `json:"window_size"`       // Size of the sliding window for calculations
	Multiplier       float64 `json:"multiplier"`        // Multiplier applied to average response time
	SuccessRate      float64 `json:"success_rate"`      // Required success rate to maintain current timeout
	AdjustmentFactor float64 `json:"adjustment_factor"` // Factor for timeout adjustments
	MinSamples       int     `json:"min_samples"`       // Minimum samples before adjustments
}

// PercentileTimeoutConfig configuration for percentile-based timeout
type PercentileTimeoutConfig struct {
	Percentile   float64 `json:"percentile"`    // Percentile to use (e.g., 0.95 for 95th percentile)
	WindowSize   int     `json:"window_size"`   // Size of the sliding window
	MinSamples   int     `json:"min_samples"`   // Minimum samples for percentile calculation
}

// HierarchicalTimeoutConfig configuration for hierarchical timeouts
type HierarchicalTimeoutConfig struct {
	Levels map[TimeoutLevel]time.Duration `json:"levels"` // Timeout for each level
}

// DefaultTimeoutConfig returns default timeout configuration
func DefaultTimeoutConfig() *TimeoutConfig {
	return &TimeoutConfig{
		Name:             "default",
		Strategy:         TimeoutStrategyFixed,
		DefaultTimeout:   30 * time.Second,
		MinTimeout:       1 * time.Second,
		MaxTimeout:       5 * time.Minute,
		WarningThreshold: 0.8, // 80% of timeout
		EnableWarnings:   true,
		EnableMetrics:    true,
		AdaptiveConfig: &AdaptiveTimeoutConfig{
			WindowSize:       100,
			Multiplier:       1.5,
			SuccessRate:      0.95,
			AdjustmentFactor: 0.1,
			MinSamples:       10,
		},
		PercentileConfig: &PercentileTimeoutConfig{
			Percentile: 0.95,
			WindowSize: 100,
			MinSamples: 10,
		},
		HierarchicalConfig: &HierarchicalTimeoutConfig{
			Levels: map[TimeoutLevel]time.Duration{
				TimeoutLevelRequest:   10 * time.Second,
				TimeoutLevelOperation: 60 * time.Second,
				TimeoutLevelSession:   10 * time.Minute,
				TimeoutLevelGlobal:    30 * time.Minute,
			},
		},
	}
}

// TimeoutMetrics tracks timeout statistics
type TimeoutMetrics struct {
	Name                 string        `json:"name"`
	TotalOperations      int64         `json:"total_operations"`
	TotalTimeouts        int64         `json:"total_timeouts"`
	TotalWarnings        int64         `json:"total_warnings"`
	TotalCancellations   int64         `json:"total_cancellations"`
	AverageResponseTime  time.Duration `json:"average_response_time"`
	CurrentTimeout       time.Duration `json:"current_timeout"`
	EffectiveTimeout     time.Duration `json:"effective_timeout"`
	TimeoutRate          float64       `json:"timeout_rate"`
	WarningRate          float64       `json:"warning_rate"`
	LastTimeoutTime      time.Time     `json:"last_timeout_time,omitempty"`
	LastAdjustmentTime   time.Time     `json:"last_adjustment_time,omitempty"`
}

// TimeoutEvent represents events from timeout management
type TimeoutEvent struct {
	Type           string                 `json:"type"`
	Name           string                 `json:"name"`
	Level          string                 `json:"level,omitempty"`
	Timeout        time.Duration          `json:"timeout"`
	Elapsed        time.Duration          `json:"elapsed"`
	Remaining      time.Duration          `json:"remaining,omitempty"`
	Reason         string                 `json:"reason"`
	Timestamp      time.Time              `json:"timestamp"`
	Metrics        *TimeoutMetrics        `json:"metrics,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// ResponseTimeTracker tracks response times for adaptive timeouts
type ResponseTimeTracker struct {
	times      []time.Duration
	windowSize int
	index      int
	full       bool
	mu         sync.RWMutex
}

// NewResponseTimeTracker creates a new response time tracker
func NewResponseTimeTracker(windowSize int) *ResponseTimeTracker {
	return &ResponseTimeTracker{
		times:      make([]time.Duration, windowSize),
		windowSize: windowSize,
	}
}

// Add adds a response time to the tracker
func (rtt *ResponseTimeTracker) Add(duration time.Duration) {
	rtt.mu.Lock()
	defer rtt.mu.Unlock()
	
	rtt.times[rtt.index] = duration
	rtt.index = (rtt.index + 1) % rtt.windowSize
	if rtt.index == 0 {
		rtt.full = true
	}
}

// Average returns the average response time
func (rtt *ResponseTimeTracker) Average() time.Duration {
	rtt.mu.RLock()
	defer rtt.mu.RUnlock()
	
	size := rtt.windowSize
	if !rtt.full {
		size = rtt.index
	}
	
	if size == 0 {
		return 0
	}
	
	var total time.Duration
	for i := 0; i < size; i++ {
		total += rtt.times[i]
	}
	
	return total / time.Duration(size)
}

// Percentile returns the specified percentile of response times
func (rtt *ResponseTimeTracker) Percentile(p float64) time.Duration {
	rtt.mu.RLock()
	defer rtt.mu.RUnlock()
	
	size := rtt.windowSize
	if !rtt.full {
		size = rtt.index
	}
	
	if size == 0 {
		return 0
	}
	
	// Copy and sort times
	times := make([]time.Duration, size)
	copy(times, rtt.times[:size])
	
	// Simple sort implementation
	for i := 0; i < len(times); i++ {
		for j := i + 1; j < len(times); j++ {
			if times[i] > times[j] {
				times[i], times[j] = times[j], times[i]
			}
		}
	}
	
	index := int(float64(size-1) * p)
	return times[index]
}

// Count returns the current number of samples
func (rtt *ResponseTimeTracker) Count() int {
	rtt.mu.RLock()
	defer rtt.mu.RUnlock()
	
	if rtt.full {
		return rtt.windowSize
	}
	return rtt.index
}

// TimeoutManager manages timeouts with different strategies
type TimeoutManager struct {
	config         *TimeoutConfig
	responseTracker *ResponseTimeTracker
	metrics        *TimeoutMetrics
	mu             sync.RWMutex
	eventListeners []func(*TimeoutEvent)
	eventMu        sync.RWMutex
}

// Common timeout errors
var (
	ErrOperationTimeout     = errors.New("operation timeout")
	ErrTimeoutExceeded      = errors.New("timeout exceeded")
	ErrInvalidTimeoutLevel  = errors.New("invalid timeout level")
	ErrTimeoutNotSupported  = errors.New("timeout strategy not supported")
)

// NewTimeoutManager creates a new timeout manager
func NewTimeoutManager(config *TimeoutConfig) *TimeoutManager {
	if config == nil {
		config = DefaultTimeoutConfig()
	}
	
	// Validate configuration
	if config.DefaultTimeout <= 0 {
		config.DefaultTimeout = 30 * time.Second
	}
	if config.MinTimeout <= 0 {
		config.MinTimeout = 1 * time.Second
	}
	if config.MaxTimeout <= 0 {
		config.MaxTimeout = 5 * time.Minute
	}
	if config.WarningThreshold <= 0 || config.WarningThreshold >= 1 {
		config.WarningThreshold = 0.8
	}
	
	// Initialize adaptive config if needed
	if config.Strategy == TimeoutStrategyAdaptive && config.AdaptiveConfig == nil {
		config.AdaptiveConfig = DefaultTimeoutConfig().AdaptiveConfig
	}
	
	// Initialize percentile config if needed  
	if config.Strategy == TimeoutStrategyPercentile && config.PercentileConfig == nil {
		config.PercentileConfig = DefaultTimeoutConfig().PercentileConfig
	}
	
	// Initialize hierarchical config if needed
	if config.Strategy == TimeoutStrategyHierarchical && config.HierarchicalConfig == nil {
		config.HierarchicalConfig = DefaultTimeoutConfig().HierarchicalConfig
	}
	
	tm := &TimeoutManager{
		config: config,
		metrics: &TimeoutMetrics{
			Name:           config.Name,
			CurrentTimeout: config.DefaultTimeout,
		},
		eventListeners: make([]func(*TimeoutEvent), 0),
	}
	
	// Initialize response tracker for adaptive/percentile strategies
	if config.Strategy == TimeoutStrategyAdaptive {
		tm.responseTracker = NewResponseTimeTracker(config.AdaptiveConfig.WindowSize)
	} else if config.Strategy == TimeoutStrategyPercentile {
		tm.responseTracker = NewResponseTimeTracker(config.PercentileConfig.WindowSize)
	}
	
	log.Info().
		Str("name", config.Name).
		Str("strategy", string(config.Strategy)).
		Dur("default_timeout", config.DefaultTimeout).
		Msg("Timeout manager created")
	
	return tm
}

// WithTimeout executes an operation with timeout management
func (tm *TimeoutManager) WithTimeout(ctx context.Context, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	return tm.WithTimeoutLevel(ctx, TimeoutLevelRequest, operation)
}

// WithTimeoutLevel executes an operation with timeout management at specified level
func (tm *TimeoutManager) WithTimeoutLevel(ctx context.Context, level TimeoutLevel, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	timeout := tm.calculateTimeout(level)
	return tm.WithCustomTimeout(ctx, timeout, level, operation)
}

// WithCustomTimeout executes an operation with a custom timeout
func (tm *TimeoutManager) WithCustomTimeout(ctx context.Context, timeout time.Duration, level TimeoutLevel, operation func(context.Context) (interface{}, error)) (interface{}, error) {
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	// Update metrics
	atomic.AddInt64(&tm.metrics.TotalOperations, 1)
	tm.metrics.EffectiveTimeout = timeout
	
	startTime := time.Now()
	
	tm.emitEvent(&TimeoutEvent{
		Type:      "started",
		Name:      tm.config.Name,
		Level:     string(level),
		Timeout:   timeout,
		Reason:    "operation started with timeout",
		Timestamp: startTime,
		Metrics:   tm.GetMetrics(),
	})
	
	// Channel to receive result or timeout
	resultChan := make(chan struct {
		result interface{}
		err    error
	}, 1)
	
	// Start operation in goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resultChan <- struct {
					result interface{}
					err    error
				}{nil, fmt.Errorf("panic in timeout operation: %v", r)}
			}
		}()
		
		result, err := operation(timeoutCtx)
		resultChan <- struct {
			result interface{}
			err    error
		}{result, err}
	}()
	
	// Start warning timer if enabled
	var warningTimer *time.Timer
	if tm.config.EnableWarnings && tm.config.WarningThreshold > 0 {
		warningDelay := time.Duration(float64(timeout) * tm.config.WarningThreshold)
		warningTimer = time.AfterFunc(warningDelay, func() {
			elapsed := time.Since(startTime)
			remaining := timeout - elapsed
			
			atomic.AddInt64(&tm.metrics.TotalWarnings, 1)
			
			if tm.config.OnWarning != nil {
				tm.config.OnWarning(timeoutCtx, elapsed, remaining)
			}
			
			tm.emitEvent(&TimeoutEvent{
				Type:      "warning",
				Name:      tm.config.Name,
				Level:     string(level),
				Timeout:   timeout,
				Elapsed:   elapsed,
				Remaining: remaining,
				Reason:    "operation approaching timeout",
				Timestamp: time.Now(),
				Metrics:   tm.GetMetrics(),
			})
		})
		defer warningTimer.Stop()
	}
	
	// Wait for result or timeout
	select {
	case result := <-resultChan:
		// Operation completed
		elapsed := time.Since(startTime)
		
		// Update response time tracker
		if tm.responseTracker != nil {
			tm.responseTracker.Add(elapsed)
		}
		
		// Update average response time
		tm.updateAverageResponseTime(elapsed)
		
		// Check if we should cancel (even on success)
		if tm.config.ShouldCancel != nil && tm.config.ShouldCancel(timeoutCtx) {
			atomic.AddInt64(&tm.metrics.TotalCancellations, 1)
			
			tm.emitEvent(&TimeoutEvent{
				Type:      "cancelled",
				Name:      tm.config.Name,
				Level:     string(level),
				Timeout:   timeout,
				Elapsed:   elapsed,
				Reason:    "operation cancelled by policy",
				Timestamp: time.Now(),
				Metrics:   tm.GetMetrics(),
			})
			
			return nil, context.Canceled
		}
		
		// Adjust timeout if using adaptive strategy
		if tm.config.Strategy == TimeoutStrategyAdaptive {
			tm.adjustAdaptiveTimeout(result.err == nil)
		}
		
		tm.emitEvent(&TimeoutEvent{
			Type:      "completed",
			Name:      tm.config.Name,
			Level:     string(level),
			Timeout:   timeout,
			Elapsed:   elapsed,
			Reason:    "operation completed",
			Timestamp: time.Now(),
			Metrics:   tm.GetMetrics(),
		})
		
		return result.result, result.err
		
	case <-timeoutCtx.Done():
		// Operation timed out
		elapsed := time.Since(startTime)
		atomic.AddInt64(&tm.metrics.TotalTimeouts, 1)
		tm.metrics.LastTimeoutTime = time.Now()
		
		if tm.config.OnTimeout != nil {
			tm.config.OnTimeout(timeoutCtx, elapsed)
		}
		
		// Adjust timeout if using adaptive strategy
		if tm.config.Strategy == TimeoutStrategyAdaptive {
			tm.adjustAdaptiveTimeout(false)
		}
		
		tm.emitEvent(&TimeoutEvent{
			Type:      "timeout",
			Name:      tm.config.Name,
			Level:     string(level),
			Timeout:   timeout,
			Elapsed:   elapsed,
			Reason:    "operation timed out",
			Timestamp: time.Now(),
			Metrics:   tm.GetMetrics(),
		})
		
		return nil, fmt.Errorf("%w: elapsed %v, timeout %v", ErrOperationTimeout, elapsed, timeout)
	}
}

// calculateTimeout calculates the appropriate timeout based on strategy and level
func (tm *TimeoutManager) calculateTimeout(level TimeoutLevel) time.Duration {
	switch tm.config.Strategy {
	case TimeoutStrategyFixed:
		return tm.config.DefaultTimeout
		
	case TimeoutStrategyAdaptive:
		return tm.calculateAdaptiveTimeout()
		
	case TimeoutStrategyPercentile:
		return tm.calculatePercentileTimeout()
		
	case TimeoutStrategyHierarchical:
		return tm.calculateHierarchicalTimeout(level)
		
	default:
		return tm.config.DefaultTimeout
	}
}

// calculateAdaptiveTimeout calculates timeout based on adaptive strategy
func (tm *TimeoutManager) calculateAdaptiveTimeout() time.Duration {
	if tm.responseTracker == nil || tm.responseTracker.Count() < tm.config.AdaptiveConfig.MinSamples {
		return tm.config.DefaultTimeout
	}
	
	avg := tm.responseTracker.Average()
	timeout := time.Duration(float64(avg) * tm.config.AdaptiveConfig.Multiplier)
	
	// Apply bounds
	if timeout < tm.config.MinTimeout {
		timeout = tm.config.MinTimeout
	} else if timeout > tm.config.MaxTimeout {
		timeout = tm.config.MaxTimeout
	}
	
	tm.mu.Lock()
	tm.metrics.CurrentTimeout = timeout
	tm.mu.Unlock()
	
	return timeout
}

// calculatePercentileTimeout calculates timeout based on percentile strategy
func (tm *TimeoutManager) calculatePercentileTimeout() time.Duration {
	if tm.responseTracker == nil || tm.responseTracker.Count() < tm.config.PercentileConfig.MinSamples {
		return tm.config.DefaultTimeout
	}
	
	timeout := tm.responseTracker.Percentile(tm.config.PercentileConfig.Percentile)
	
	// Apply bounds
	if timeout < tm.config.MinTimeout {
		timeout = tm.config.MinTimeout
	} else if timeout > tm.config.MaxTimeout {
		timeout = tm.config.MaxTimeout
	}
	
	tm.mu.Lock()
	tm.metrics.CurrentTimeout = timeout
	tm.mu.Unlock()
	
	return timeout
}

// calculateHierarchicalTimeout calculates timeout based on hierarchical strategy
func (tm *TimeoutManager) calculateHierarchicalTimeout(level TimeoutLevel) time.Duration {
	if tm.config.HierarchicalConfig == nil {
		return tm.config.DefaultTimeout
	}
	
	if timeout, exists := tm.config.HierarchicalConfig.Levels[level]; exists {
		return timeout
	}
	
	return tm.config.DefaultTimeout
}

// adjustAdaptiveTimeout adjusts the timeout based on operation success
func (tm *TimeoutManager) adjustAdaptiveTimeout(success bool) {
	if tm.config.Strategy != TimeoutStrategyAdaptive || tm.config.AdaptiveConfig == nil {
		return
	}
	
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	current := tm.metrics.CurrentTimeout
	factor := tm.config.AdaptiveConfig.AdjustmentFactor
	
	if success {
		// Decrease timeout slightly on success (more aggressive)
		newTimeout := time.Duration(float64(current) * (1 - factor*0.5))
		if newTimeout >= tm.config.MinTimeout {
			tm.metrics.CurrentTimeout = newTimeout
		}
	} else {
		// Increase timeout on failure
		newTimeout := time.Duration(float64(current) * (1 + factor))
		if newTimeout <= tm.config.MaxTimeout {
			tm.metrics.CurrentTimeout = newTimeout
		}
	}
	
	tm.metrics.LastAdjustmentTime = time.Now()
}

// updateAverageResponseTime updates the average response time metric
func (tm *TimeoutManager) updateAverageResponseTime(elapsed time.Duration) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	totalOps := atomic.LoadInt64(&tm.metrics.TotalOperations)
	if totalOps > 0 {
		// Simple moving average
		currentAvg := tm.metrics.AverageResponseTime
		tm.metrics.AverageResponseTime = time.Duration(
			(int64(currentAvg)*(totalOps-1) + int64(elapsed)) / totalOps,
		)
	}
}

// GetMetrics returns current timeout metrics
func (tm *TimeoutManager) GetMetrics() *TimeoutMetrics {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	totalOps := atomic.LoadInt64(&tm.metrics.TotalOperations)
	metrics := &TimeoutMetrics{
		Name:                tm.metrics.Name,
		TotalOperations:     totalOps,
		TotalTimeouts:       atomic.LoadInt64(&tm.metrics.TotalTimeouts),
		TotalWarnings:       atomic.LoadInt64(&tm.metrics.TotalWarnings),
		TotalCancellations:  atomic.LoadInt64(&tm.metrics.TotalCancellations),
		AverageResponseTime: tm.metrics.AverageResponseTime,
		CurrentTimeout:      tm.metrics.CurrentTimeout,
		EffectiveTimeout:    tm.metrics.EffectiveTimeout,
		LastTimeoutTime:     tm.metrics.LastTimeoutTime,
		LastAdjustmentTime:  tm.metrics.LastAdjustmentTime,
	}
	
	if totalOps > 0 {
		metrics.TimeoutRate = float64(atomic.LoadInt64(&tm.metrics.TotalTimeouts)) / float64(totalOps)
		metrics.WarningRate = float64(atomic.LoadInt64(&tm.metrics.TotalWarnings)) / float64(totalOps)
	}
	
	return metrics
}

// Reset resets the timeout manager metrics
func (tm *TimeoutManager) Reset() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	atomic.StoreInt64(&tm.metrics.TotalOperations, 0)
	atomic.StoreInt64(&tm.metrics.TotalTimeouts, 0)
	atomic.StoreInt64(&tm.metrics.TotalWarnings, 0)
	atomic.StoreInt64(&tm.metrics.TotalCancellations, 0)
	tm.metrics.AverageResponseTime = 0
	tm.metrics.CurrentTimeout = tm.config.DefaultTimeout
	tm.metrics.LastTimeoutTime = time.Time{}
	tm.metrics.LastAdjustmentTime = time.Time{}
	
	if tm.responseTracker != nil {
		tm.responseTracker = NewResponseTimeTracker(tm.responseTracker.windowSize)
	}
	
	tm.emitEvent(&TimeoutEvent{
		Type:      "reset",
		Name:      tm.config.Name,
		Reason:    "timeout manager reset",
		Timestamp: time.Now(),
		Metrics:   tm.metrics,
	})
	
	log.Info().
		Str("name", tm.config.Name).
		Msg("Timeout manager reset")
}

// AddEventListener adds an event listener for timeout events
func (tm *TimeoutManager) AddEventListener(listener func(*TimeoutEvent)) {
	tm.eventMu.Lock()
	defer tm.eventMu.Unlock()
	
	tm.eventListeners = append(tm.eventListeners, listener)
}

// RemoveEventListener removes an event listener
func (tm *TimeoutManager) RemoveEventListener(listener func(*TimeoutEvent)) {
	tm.eventMu.Lock()
	defer tm.eventMu.Unlock()
	
	var filtered []func(*TimeoutEvent)
	for _, l := range tm.eventListeners {
		if &l != &listener {
			filtered = append(filtered, l)
		}
	}
	tm.eventListeners = filtered
}

// emitEvent emits an event to all registered listeners
func (tm *TimeoutManager) emitEvent(event *TimeoutEvent) {
	tm.eventMu.RLock()
	listeners := make([]func(*TimeoutEvent), len(tm.eventListeners))
	copy(listeners, tm.eventListeners)
	tm.eventMu.RUnlock()
	
	// Emit events asynchronously
	for _, listener := range listeners {
		go func(l func(*TimeoutEvent)) {
			defer func() {
				if r := recover(); r != nil {
					log.Error().
						Interface("panic", r).
						Str("timeout_manager", tm.config.Name).
						Msg("Panic in timeout event listener")
				}
			}()
			l(event)
		}(listener)
	}
}

// String returns a string representation of the timeout manager
func (tm *TimeoutManager) String() string {
	metrics := tm.GetMetrics()
	return fmt.Sprintf("TimeoutManager{name=%s, strategy=%s, timeout=%v, operations=%d, timeouts=%d}",
		metrics.Name, tm.config.Strategy, metrics.CurrentTimeout, metrics.TotalOperations, metrics.TotalTimeouts)
}