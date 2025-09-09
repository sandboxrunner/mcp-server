package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"
	
	"github.com/rs/zerolog/log"
)

// ProcessEventType represents the type of process event
type ProcessEventType string

const (
	// ProcessEventStart indicates a process has started
	ProcessEventStart ProcessEventType = "start"
	// ProcessEventExit indicates a process has exited
	ProcessEventExit ProcessEventType = "exit"
	// ProcessEventError indicates a process encountered an error
	ProcessEventError ProcessEventType = "error"
	// ProcessEventStateChange indicates a process state has changed
	ProcessEventStateChange ProcessEventType = "state_change"
	// ProcessEventResourceUpdate indicates resource usage has been updated
	ProcessEventResourceUpdate ProcessEventType = "resource_update"
	// ProcessEventKill indicates a process is being killed
	ProcessEventKill ProcessEventType = "kill"
	// ProcessEventTimeout indicates a process has timed out
	ProcessEventTimeout ProcessEventType = "timeout"
)

// ProcessEvent represents an event that occurs during process lifecycle
type ProcessEvent struct {
	// Event identification
	ID        string           `json:"id"`
	Type      ProcessEventType `json:"type"`
	Timestamp time.Time        `json:"timestamp"`
	
	// Process information
	ProcessID   string `json:"processId"`
	ContainerID string `json:"containerId"`
	PID         int32  `json:"pid,omitempty"`
	
	// Event details
	Message    string                 `json:"message,omitempty"`
	Data       map[string]interface{} `json:"data,omitempty"`
	Error      string                 `json:"error,omitempty"`
	
	// State change specific fields
	OldState ProcessState `json:"oldState,omitempty"`
	NewState ProcessState `json:"newState,omitempty"`
	
	// Resource usage (for resource update events)
	ResourceUsage *ProcessResourceUsage `json:"resourceUsage,omitempty"`
	
	// Exit code (for exit events)
	ExitCode *int32 `json:"exitCode,omitempty"`
}

// ProcessEventHandler is a function that handles process events
type ProcessEventHandler func(event *ProcessEvent)

// ProcessEventSubscription represents an event subscription
type ProcessEventSubscription struct {
	ID       string
	Types    []ProcessEventType
	Handler  ProcessEventHandler
	Filter   func(*ProcessEvent) bool
	Created  time.Time
	LastUsed time.Time
	Active   bool
}

// ProcessEventBus manages process event distribution
type ProcessEventBus struct {
	mu            sync.RWMutex
	subscriptions map[string]*ProcessEventSubscription
	eventBuffer   []*ProcessEvent
	bufferSize    int
	metrics       *EventBusMetrics
	shutdown      chan struct{}
	wg            sync.WaitGroup
}

// EventBusMetrics tracks event bus performance
type EventBusMetrics struct {
	mu                 sync.RWMutex
	EventsPublished    int64     `json:"eventsPublished"`
	EventsDelivered    int64     `json:"eventsDelivered"`
	EventsDropped      int64     `json:"eventsDropped"`
	ActiveSubscribers  int       `json:"activeSubscribers"`
	LastEventTime      time.Time `json:"lastEventTime"`
	AverageLatency     time.Duration `json:"averageLatency"`
	HandlerErrors      int64     `json:"handlerErrors"`
	SubscriptionCount  int64     `json:"subscriptionCount"`
}

// NewProcessEventBus creates a new process event bus
func NewProcessEventBus(bufferSize int) *ProcessEventBus {
	if bufferSize <= 0 {
		bufferSize = 1000 // Default buffer size
	}
	
	bus := &ProcessEventBus{
		subscriptions: make(map[string]*ProcessEventSubscription),
		eventBuffer:   make([]*ProcessEvent, 0, bufferSize),
		bufferSize:    bufferSize,
		metrics: &EventBusMetrics{
			LastEventTime: time.Now(),
		},
		shutdown: make(chan struct{}),
	}
	
	// Start background cleanup goroutine
	bus.wg.Add(1)
	go bus.cleanupRoutine()
	
	return bus
}

// Subscribe creates a new subscription for process events
func (bus *ProcessEventBus) Subscribe(types []ProcessEventType, handler ProcessEventHandler) string {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	
	subscriptionID := generateSubscriptionID()
	subscription := &ProcessEventSubscription{
		ID:       subscriptionID,
		Types:    types,
		Handler:  handler,
		Created:  time.Now(),
		LastUsed: time.Now(),
		Active:   true,
	}
	
	bus.subscriptions[subscriptionID] = subscription
	bus.metrics.SubscriptionCount++
	
	log.Debug().
		Str("subscription_id", subscriptionID).
		Strs("event_types", eventTypesToStrings(types)).
		Msg("Created process event subscription")
	
	return subscriptionID
}

// SubscribeWithFilter creates a new subscription with a custom filter
func (bus *ProcessEventBus) SubscribeWithFilter(types []ProcessEventType, handler ProcessEventHandler, filter func(*ProcessEvent) bool) string {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	
	subscriptionID := generateSubscriptionID()
	subscription := &ProcessEventSubscription{
		ID:       subscriptionID,
		Types:    types,
		Handler:  handler,
		Filter:   filter,
		Created:  time.Now(),
		LastUsed: time.Now(),
		Active:   true,
	}
	
	bus.subscriptions[subscriptionID] = subscription
	bus.metrics.SubscriptionCount++
	
	log.Debug().
		Str("subscription_id", subscriptionID).
		Strs("event_types", eventTypesToStrings(types)).
		Bool("has_filter", filter != nil).
		Msg("Created process event subscription with filter")
	
	return subscriptionID
}

// Unsubscribe removes a subscription
func (bus *ProcessEventBus) Unsubscribe(subscriptionID string) bool {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	
	if subscription, exists := bus.subscriptions[subscriptionID]; exists {
		subscription.Active = false
		delete(bus.subscriptions, subscriptionID)
		
		log.Debug().
			Str("subscription_id", subscriptionID).
			Msg("Removed process event subscription")
		
		return true
	}
	
	return false
}

// Publish publishes an event to all matching subscriptions
func (bus *ProcessEventBus) Publish(event *ProcessEvent) {
	if event == nil {
		return
	}
	
	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	
	// Generate ID if not set
	if event.ID == "" {
		event.ID = generateEventID()
	}
	
	bus.mu.Lock()
	
	// Add to buffer
	bus.addToBuffer(event)
	
	// Update metrics
	bus.metrics.mu.Lock()
	bus.metrics.EventsPublished++
	bus.metrics.LastEventTime = event.Timestamp
	bus.metrics.ActiveSubscribers = len(bus.subscriptions)
	bus.metrics.mu.Unlock()
	
	// Get matching subscriptions
	var matchingSubscriptions []*ProcessEventSubscription
	for _, subscription := range bus.subscriptions {
		if subscription.Active && bus.eventMatches(event, subscription) {
			matchingSubscriptions = append(matchingSubscriptions, subscription)
			subscription.LastUsed = time.Now()
		}
	}
	
	bus.mu.Unlock()
	
	// Deliver events asynchronously to avoid blocking
	bus.wg.Add(1)
	go bus.deliverEvent(event, matchingSubscriptions)
	
	log.Debug().
		Str("event_id", event.ID).
		Str("event_type", string(event.Type)).
		Str("process_id", event.ProcessID).
		Int("subscribers", len(matchingSubscriptions)).
		Msg("Published process event")
}

// PublishStart publishes a process start event
func (bus *ProcessEventBus) PublishStart(processID, containerID string, pid int32, spec *ProcessSpec) {
	event := &ProcessEvent{
		Type:        ProcessEventStart,
		ProcessID:   processID,
		ContainerID: containerID,
		PID:         pid,
		Message:     "Process started",
		Data: map[string]interface{}{
			"command":     spec.Cmd,
			"args":        spec.Args,
			"working_dir": spec.WorkingDir,
			"user":        spec.User,
		},
	}
	
	bus.Publish(event)
}

// PublishExit publishes a process exit event
func (bus *ProcessEventBus) PublishExit(processID, containerID string, pid int32, exitCode int32, duration time.Duration) {
	event := &ProcessEvent{
		Type:        ProcessEventExit,
		ProcessID:   processID,
		ContainerID: containerID,
		PID:         pid,
		ExitCode:    &exitCode,
		Message:     fmt.Sprintf("Process exited with code %d", exitCode),
		Data: map[string]interface{}{
			"duration": duration.String(),
		},
	}
	
	bus.Publish(event)
}

// PublishError publishes a process error event
func (bus *ProcessEventBus) PublishError(processID, containerID string, pid int32, err error) {
	event := &ProcessEvent{
		Type:        ProcessEventError,
		ProcessID:   processID,
		ContainerID: containerID,
		PID:         pid,
		Error:       err.Error(),
		Message:     "Process error",
		Data: map[string]interface{}{
			"error_type": fmt.Sprintf("%T", err),
		},
	}
	
	bus.Publish(event)
}

// PublishStateChange publishes a process state change event
func (bus *ProcessEventBus) PublishStateChange(processID, containerID string, pid int32, oldState, newState ProcessState, reason string) {
	event := &ProcessEvent{
		Type:        ProcessEventStateChange,
		ProcessID:   processID,
		ContainerID: containerID,
		PID:         pid,
		OldState:    oldState,
		NewState:    newState,
		Message:     fmt.Sprintf("Process state changed from %s to %s", oldState, newState),
		Data: map[string]interface{}{
			"reason": reason,
		},
	}
	
	bus.Publish(event)
}

// PublishResourceUpdate publishes a resource usage update event
func (bus *ProcessEventBus) PublishResourceUpdate(processID, containerID string, pid int32, usage *ProcessResourceUsage) {
	event := &ProcessEvent{
		Type:          ProcessEventResourceUpdate,
		ProcessID:     processID,
		ContainerID:   containerID,
		PID:           pid,
		ResourceUsage: usage,
		Message:       "Resource usage updated",
		Data: map[string]interface{}{
			"cpu_percent":    usage.CPUPercent,
			"memory_rss":     usage.MemoryRSS,
			"memory_percent": usage.MemoryPercent,
		},
	}
	
	bus.Publish(event)
}

// PublishKill publishes a process kill event
func (bus *ProcessEventBus) PublishKill(processID, containerID string, pid int32, signal string) {
	event := &ProcessEvent{
		Type:        ProcessEventKill,
		ProcessID:   processID,
		ContainerID: containerID,
		PID:         pid,
		Message:     fmt.Sprintf("Process killed with signal %s", signal),
		Data: map[string]interface{}{
			"signal": signal,
		},
	}
	
	bus.Publish(event)
}

// PublishTimeout publishes a process timeout event
func (bus *ProcessEventBus) PublishTimeout(processID, containerID string, pid int32, timeout time.Duration) {
	event := &ProcessEvent{
		Type:        ProcessEventTimeout,
		ProcessID:   processID,
		ContainerID: containerID,
		PID:         pid,
		Message:     fmt.Sprintf("Process timed out after %s", timeout),
		Data: map[string]interface{}{
			"timeout": timeout.String(),
		},
	}
	
	bus.Publish(event)
}

// GetMetrics returns a copy of the event bus metrics
func (bus *ProcessEventBus) GetMetrics() EventBusMetrics {
	bus.metrics.mu.RLock()
	defer bus.metrics.mu.RUnlock()
	
	return *bus.metrics
}

// GetRecentEvents returns recent events from the buffer
func (bus *ProcessEventBus) GetRecentEvents(limit int) []*ProcessEvent {
	bus.mu.RLock()
	defer bus.mu.RUnlock()
	
	if limit <= 0 || limit > len(bus.eventBuffer) {
		limit = len(bus.eventBuffer)
	}
	
	// Return the most recent events
	start := len(bus.eventBuffer) - limit
	events := make([]*ProcessEvent, limit)
	copy(events, bus.eventBuffer[start:])
	
	return events
}

// Shutdown gracefully shuts down the event bus
func (bus *ProcessEventBus) Shutdown(ctx context.Context) error {
	close(bus.shutdown)
	
	done := make(chan struct{})
	go func() {
		bus.wg.Wait()
		close(done)
	}()
	
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		log.Info().Msg("Process event bus shut down successfully")
		return nil
	}
}

// eventMatches checks if an event matches a subscription
func (bus *ProcessEventBus) eventMatches(event *ProcessEvent, subscription *ProcessEventSubscription) bool {
	// Check event type
	typeMatches := false
	for _, eventType := range subscription.Types {
		if event.Type == eventType {
			typeMatches = true
			break
		}
	}
	
	if !typeMatches {
		return false
	}
	
	// Apply custom filter if present
	if subscription.Filter != nil {
		return subscription.Filter(event)
	}
	
	return true
}

// deliverEvent delivers an event to all matching subscriptions
func (bus *ProcessEventBus) deliverEvent(event *ProcessEvent, subscriptions []*ProcessEventSubscription) {
	defer bus.wg.Done()
	
	startTime := time.Now()
	
	for _, subscription := range subscriptions {
		if !subscription.Active {
			continue
		}
		
		// Call handler with timeout and error recovery
		bus.callHandler(event, subscription)
		
		bus.metrics.mu.Lock()
		bus.metrics.EventsDelivered++
		bus.metrics.mu.Unlock()
	}
	
	// Update average latency
	latency := time.Since(startTime)
	bus.metrics.mu.Lock()
	if bus.metrics.AverageLatency == 0 {
		bus.metrics.AverageLatency = latency
	} else {
		bus.metrics.AverageLatency = (bus.metrics.AverageLatency + latency) / 2
	}
	bus.metrics.mu.Unlock()
}

// callHandler calls an event handler with error recovery
func (bus *ProcessEventBus) callHandler(event *ProcessEvent, subscription *ProcessEventSubscription) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Str("subscription_id", subscription.ID).
				Str("event_id", event.ID).
				Interface("panic", r).
				Msg("Event handler panicked")
			
			bus.metrics.mu.Lock()
			bus.metrics.HandlerErrors++
			bus.metrics.mu.Unlock()
		}
	}()
	
	// Call the handler with a timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		subscription.Handler(event)
	}()
	
	select {
	case <-done:
		// Handler completed successfully
	case <-time.After(5 * time.Second):
		// Handler timed out
		log.Warn().
			Str("subscription_id", subscription.ID).
			Str("event_id", event.ID).
			Msg("Event handler timed out")
		
		bus.metrics.mu.Lock()
		bus.metrics.HandlerErrors++
		bus.metrics.mu.Unlock()
	}
}

// addToBuffer adds an event to the circular buffer
func (bus *ProcessEventBus) addToBuffer(event *ProcessEvent) {
	if len(bus.eventBuffer) >= bus.bufferSize {
		// Remove oldest event
		copy(bus.eventBuffer, bus.eventBuffer[1:])
		bus.eventBuffer[len(bus.eventBuffer)-1] = event
	} else {
		bus.eventBuffer = append(bus.eventBuffer, event)
	}
}

// cleanupRoutine runs periodic cleanup of inactive subscriptions
func (bus *ProcessEventBus) cleanupRoutine() {
	defer bus.wg.Done()
	
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			bus.performCleanup()
		case <-bus.shutdown:
			return
		}
	}
}

// performCleanup removes inactive subscriptions
func (bus *ProcessEventBus) performCleanup() {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	
	now := time.Now()
	inactiveThreshold := 1 * time.Hour
	
	for id, subscription := range bus.subscriptions {
		if subscription.Active && now.Sub(subscription.LastUsed) > inactiveThreshold {
			log.Debug().
				Str("subscription_id", id).
				Dur("inactive_duration", now.Sub(subscription.LastUsed)).
				Msg("Removing inactive subscription")
			
			subscription.Active = false
			delete(bus.subscriptions, id)
		}
	}
}

// Helper functions

func generateEventID() string {
	return fmt.Sprintf("event-%d", time.Now().UnixNano())
}

func generateSubscriptionID() string {
	return fmt.Sprintf("sub-%d", time.Now().UnixNano())
}

func eventTypesToStrings(types []ProcessEventType) []string {
	strings := make([]string, len(types))
	for i, t := range types {
		strings[i] = string(t)
	}
	return strings
}