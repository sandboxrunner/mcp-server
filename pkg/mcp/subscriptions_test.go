package mcp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscriptionManager_NewSubscriptionManager(t *testing.T) {
	config := SubscriptionConfig{
		MaxSubscribers:     100,
		DefaultBatchSize:   10,
		DefaultBatchWait:   time.Second,
		EnableBatching:     true,
		EnableReconnection: true,
		EnableMetrics:      true,
		CleanupInterval:    time.Minute,
		EventTTL:           time.Hour,
	}

	sm := NewSubscriptionManager(config)
	assert.NotNil(t, sm)
	assert.Equal(t, config, sm.config)
	assert.NotNil(t, sm.registry)
	assert.NotNil(t, sm.transport)
	assert.NotNil(t, sm.filters)
	assert.NotNil(t, sm.subscriptions)
	assert.NotNil(t, sm.batching)
	assert.NotNil(t, sm.reconnection)
	assert.NotNil(t, sm.metrics)
}

func TestSubscriptionManager_Subscribe(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{
		MaxSubscribers: 100,
		EnableBatching: true,
		EnableMetrics:  true,
	})

	ctx := context.Background()
	eventTypes := []string{"test.event", "user.action"}
	filter := &EventFilter{
		EventTypes: eventTypes,
		Priorities: []EventPriority{EventPriorityNormal, EventPriorityHigh},
	}

	subscriber, err := sm.Subscribe(ctx, "client-1", eventTypes, filter, "websocket", "ws://localhost:8080")
	assert.NoError(t, err)
	_ = subscriber // Use the variable to avoid "declared and not used" error
	assert.NotNil(t, subscriber)
	assert.NotEmpty(t, subscriber.ID)
	assert.Equal(t, "client-1", subscriber.ClientID)
	assert.Equal(t, eventTypes, subscriber.EventTypes)
	assert.Equal(t, filter, subscriber.Filter)
	assert.Equal(t, "websocket", subscriber.Transport)
	assert.Equal(t, SubscriberStatusActive, subscriber.Status)
	assert.NotNil(t, subscriber.BatchConfig)
	assert.True(t, subscriber.BatchConfig.Enabled)

	// Verify subscriptions were created
	sm.mu.RLock()
	subscriptionCount := len(sm.subscriptions)
	sm.mu.RUnlock()
	assert.Equal(t, len(eventTypes), subscriptionCount)
}

func TestSubscriptionManager_Unsubscribe(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{
		MaxSubscribers: 100,
		EnableMetrics:  true,
	})

	ctx := context.Background()
	eventTypes := []string{"test.event"}

	subscriber, err := sm.Subscribe(ctx, "client-1", eventTypes, nil, "websocket", "")
	require.NoError(t, err)

	// Verify subscription exists
	sm.mu.RLock()
	initialCount := len(sm.subscriptions)
	sm.mu.RUnlock()
	assert.Equal(t, 1, initialCount)

	// Unsubscribe
	err = sm.Unsubscribe(ctx, subscriber.ID)
	assert.NoError(t, err)

	// Verify subscriptions were removed
	sm.mu.RLock()
	finalCount := len(sm.subscriptions)
	sm.mu.RUnlock()
	assert.Equal(t, 0, finalCount)
}

func TestSubscriptionManager_PublishEvent(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{
		MaxSubscribers: 100,
		EnableBatching: false, // Disable batching for immediate delivery
		EnableMetrics:  true,
	})

	ctx := context.Background()
	eventTypes := []string{"test.event"}

	subscriber, err := sm.Subscribe(ctx, "client-1", eventTypes, nil, "websocket", "")
	require.NoError(t, err)
	_ = subscriber // Use the variable to avoid "declared and not used" error

	event := &Event{
		ID:        "event-1",
		Type:      "test.event",
		Source:    "test-source",
		Data:      map[string]interface{}{"message": "hello world"},
		Metadata:  map[string]interface{}{"priority": "normal"},
		Timestamp: time.Now(),
		Priority:  EventPriorityNormal,
		TTL:       time.Hour,
	}

	err = sm.PublishEvent(ctx, event)
	assert.NoError(t, err)

	// Verify metrics were updated
	metrics := sm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(1), metrics.TotalEvents)
	assert.True(t, metrics.EventsDelivered > 0)
	assert.Contains(t, metrics.EventTypeMetrics, "test.event")
}

func TestSubscriptionManager_GetSubscriptions(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{MaxSubscribers: 100})

	ctx := context.Background()

	// Create multiple subscriptions
	eventTypes1 := []string{"type1", "type2"}
	eventTypes2 := []string{"type2", "type3"}

	subscriber1, err := sm.Subscribe(ctx, "client-1", eventTypes1, nil, "websocket", "")
	require.NoError(t, err)
	_ = subscriber1 // Use the variable to avoid "declared and not used" error

	subscriber2, err := sm.Subscribe(ctx, "client-2", eventTypes2, nil, "websocket", "")
	require.NoError(t, err)
	_ = subscriber2 // Use the variable to avoid "declared and not used" error

	// Get all subscriptions
	allSubs, err := sm.GetSubscriptions(ctx, nil)
	assert.NoError(t, err)
	assert.Len(t, allSubs, 4) // 2 + 2 event types

	// Filter subscriptions by event type
	filter := &EventFilter{EventTypes: []string{"type2"}}
	filteredSubs, err := sm.GetSubscriptions(ctx, filter)
	assert.NoError(t, err)
	assert.Len(t, filteredSubs, 2) // Both subscribers have type2
}

func TestEventRegistry_RegisterEventType(t *testing.T) {
	registry := NewEventRegistry(RegistryConfig{
		MaxEventTypes:   100,
		MaxSubscribers:  100,
		DefaultEventTTL: time.Hour,
	})

	eventType := &EventType{
		Name:        "user.signup",
		Description: "User signup event",
		Schema:      map[string]interface{}{"type": "object"},
		Category:    "user",
		Priority:    EventPriorityNormal,
		TTL:         time.Hour,
		Metadata:    map[string]interface{}{"version": "1.0"},
	}

	err := registry.RegisterEventType(eventType)
	assert.NoError(t, err)

	// Verify event type was registered
	registry.mu.RLock()
	registered, exists := registry.events[eventType.Name]
	registry.mu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, eventType.Name, registered.Name)
	assert.Equal(t, eventType.Description, registered.Description)
	assert.Equal(t, eventType.Category, registered.Category)
}

func TestEventRegistry_AddRemoveSubscriber(t *testing.T) {
	registry := NewEventRegistry(RegistryConfig{
		MaxEventTypes:  100,
		MaxSubscribers: 100,
	})

	subscriber := &EventSubscriber{
		ID:         "sub-1",
		ClientID:   "client-1",
		EventTypes: []string{"test.event"},
		Status:     SubscriberStatusActive,
		CreatedAt:  time.Now(),
	}

	err := registry.AddSubscriber(subscriber)
	assert.NoError(t, err)

	// Verify subscriber was added
	registry.mu.RLock()
	subscribers, exists := registry.subscribers["test.event"]
	registry.mu.RUnlock()

	assert.True(t, exists)
	assert.Contains(t, subscribers, subscriber.ID)

	// Remove subscriber
	err = registry.RemoveSubscriber(subscriber.ID)
	assert.NoError(t, err)

	// Verify subscriber was removed
	registry.mu.RLock()
	subscribers, exists = registry.subscribers["test.event"]
	registry.mu.RUnlock()

	assert.True(t, exists) // Event type still exists
	assert.NotContains(t, subscribers, subscriber.ID)
}

func TestEventRegistry_FindSubscribers(t *testing.T) {
	registry := NewEventRegistry(RegistryConfig{
		MaxEventTypes:  100,
		MaxSubscribers: 100,
	})

	// Add subscribers with different filters
	subscriber1 := &EventSubscriber{
		ID:         "sub-1",
		EventTypes: []string{"test.event"},
		Filter:     &EventFilter{Priorities: []EventPriority{EventPriorityHigh}},
		Status:     SubscriberStatusActive,
	}

	subscriber2 := &EventSubscriber{
		ID:         "sub-2",
		EventTypes: []string{"test.event"},
		Filter:     &EventFilter{Priorities: []EventPriority{EventPriorityNormal}},
		Status:     SubscriberStatusActive,
	}

	err := registry.AddSubscriber(subscriber1)
	require.NoError(t, err)
	err = registry.AddSubscriber(subscriber2)
	require.NoError(t, err)

	// Test finding subscribers for high priority event
	highPriorityEvent := &Event{
		Type:     "test.event",
		Priority: EventPriorityHigh,
	}

	matchingSubscribers := registry.FindSubscribers(highPriorityEvent)
	assert.Len(t, matchingSubscribers, 1)
	assert.Equal(t, "sub-1", matchingSubscribers[0].ID)

	// Test finding subscribers for normal priority event
	normalPriorityEvent := &Event{
		Type:     "test.event",
		Priority: EventPriorityNormal,
	}

	matchingSubscribers = registry.FindSubscribers(normalPriorityEvent)
	assert.Len(t, matchingSubscribers, 1)
	assert.Equal(t, "sub-2", matchingSubscribers[0].ID)
}

func TestEventRegistry_ProcessEvent(t *testing.T) {
	registry := NewEventRegistry(RegistryConfig{
		EnableMiddleware: true,
	})

	// Register handlers
	registry.RegisterHandler("logging", &LoggingHandler{})
	registry.RegisterHandler("metrics", &MetricsHandler{})

	// Register middleware
	registry.RegisterMiddleware(&ValidationMiddleware{})
	registry.RegisterMiddleware(&TransformationMiddleware{})

	event := &Event{
		ID:        "event-1",
		Type:      "test.event",
		Source:    "test",
		Data:      "test data",
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	err := registry.ProcessEvent(ctx, event)
	assert.NoError(t, err)

	// Verify transformation middleware added metadata
	assert.NotNil(t, event.Metadata)
	assert.Contains(t, event.Metadata, "processed_at")
}

func TestBuiltinHandlers(t *testing.T) {
	ctx := context.Background()
	event := &Event{
		ID:        "test-event",
		Type:      "test.type",
		Source:    "test-source",
		Data:      "test data",
		Timestamp: time.Now(),
	}

	// Test LoggingHandler
	loggingHandler := &LoggingHandler{}
	info := loggingHandler.GetInfo()
	assert.Equal(t, "logging", info.Name)
	assert.Contains(t, info.EventTypes, "*")

	err := loggingHandler.Handle(ctx, event)
	assert.NoError(t, err)

	// Test MetricsHandler
	metricsHandler := &MetricsHandler{}
	metricsInfo := metricsHandler.GetInfo()
	assert.Equal(t, "metrics", metricsInfo.Name)
	assert.Contains(t, metricsInfo.EventTypes, "*")

	err = metricsHandler.Handle(ctx, event)
	assert.NoError(t, err)
}

func TestBuiltinMiddleware(t *testing.T) {
	ctx := context.Background()
	
	// Test ValidationMiddleware
	validationMW := &ValidationMiddleware{}
	
	validEvent := &Event{
		ID:   "valid-event",
		Type: "test.type",
		Data: "test data",
	}

	err := validationMW.Process(ctx, validEvent, func(ctx context.Context, e *Event) error {
		return nil
	})
	assert.NoError(t, err)

	invalidEvent := &Event{} // Missing required fields

	err = validationMW.Process(ctx, invalidEvent, func(ctx context.Context, e *Event) error {
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid event")

	// Test TransformationMiddleware
	transformationMW := &TransformationMiddleware{}
	
	event := &Event{
		ID:   "transform-event",
		Type: "test.type",
		Data: "test data",
	}

	err = transformationMW.Process(ctx, event, func(ctx context.Context, e *Event) error {
		return nil
	})
	assert.NoError(t, err)
	assert.NotNil(t, event.Metadata)
	assert.Contains(t, event.Metadata, "processed_at")
}

func TestSubscriptionManager_MaxSubscribers(t *testing.T) {
	maxSubs := 2
	sm := NewSubscriptionManager(SubscriptionConfig{
		MaxSubscribers: maxSubs,
	})

	ctx := context.Background()

	// Create maximum allowed subscribers
	for i := 0; i < maxSubs; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		_, err := sm.Subscribe(ctx, clientID, []string{"test.event"}, nil, "websocket", "")
		assert.NoError(t, err)
	}

	// Try to create one more subscriber - should fail
	_, err := sm.Subscribe(ctx, "client-overflow", []string{"test.event"}, nil, "websocket", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum subscribers reached")
}

func TestSubscriptionManager_ConcurrentSubscriptions(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{
		MaxSubscribers: 100,
		EnableMetrics:  true,
	})

	ctx := context.Background()
	const numSubscribers = 10
	const numEvents = 5

	var wg sync.WaitGroup
	wg.Add(numSubscribers)

	// Create concurrent subscribers
	for i := 0; i < numSubscribers; i++ {
		go func(id int) {
			defer wg.Done()

			clientID := fmt.Sprintf("client-%d", id)
			eventTypes := []string{fmt.Sprintf("event.%d", id%3)} // Distribute across 3 event types

			_, err := sm.Subscribe(ctx, clientID, eventTypes, nil, "websocket", "")
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Publish events concurrently
	wg.Add(numEvents)
	for i := 0; i < numEvents; i++ {
		go func(id int) {
			defer wg.Done()

			event := &Event{
				ID:        fmt.Sprintf("event-%d", id),
				Type:      fmt.Sprintf("event.%d", id%3),
				Source:    "test",
				Data:      fmt.Sprintf("data-%d", id),
				Timestamp: time.Now(),
				Priority:  EventPriorityNormal,
			}

			err := sm.PublishEvent(ctx, event)
			assert.NoError(t, err)
		}(i)
	}

	wg.Wait()

	// Verify metrics
	metrics := sm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(numSubscribers), metrics.TotalSubscribers)
	assert.Equal(t, int64(numEvents), metrics.TotalEvents)
}

func TestSubscriptionManager_EventFiltering(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{
		MaxSubscribers: 100,
		EnableBatching: false,
	})

	ctx := context.Background()

	// Create subscriber with time range filter
	timeRangeStart := time.Now()
	timeRangeEnd := timeRangeStart.Add(time.Hour)
	
	filter := &EventFilter{
		EventTypes: []string{"filtered.event"},
		Priorities: []EventPriority{EventPriorityHigh},
		TimeRange: &TimeRange{
			Start: &timeRangeStart,
			End:   &timeRangeEnd,
		},
		Metadata: map[string]interface{}{
			"category": "important",
		},
	}

	_, err := sm.Subscribe(ctx, "filtered-client", []string{"filtered.event"}, filter, "websocket", "")
	require.NoError(t, err)

	// Event that should match the filter
	matchingEvent := &Event{
		ID:        "matching-event",
		Type:      "filtered.event",
		Priority:  EventPriorityHigh,
		Timestamp: timeRangeStart.Add(time.Minute * 30),
		Metadata:  map[string]interface{}{"category": "important"},
		Data:      "matching data",
	}

	err = sm.PublishEvent(ctx, matchingEvent)
	assert.NoError(t, err)

	// Event that should not match the filter (wrong priority)
	nonMatchingEvent := &Event{
		ID:        "non-matching-event",
		Type:      "filtered.event",
		Priority:  EventPriorityLow, // Wrong priority
		Timestamp: timeRangeStart.Add(time.Minute * 30),
		Metadata:  map[string]interface{}{"category": "important"},
		Data:      "non-matching data",
	}

	err = sm.PublishEvent(ctx, nonMatchingEvent)
	assert.NoError(t, err)

	// The filtering is handled in the registry's FindSubscribers method
	// We can't easily test the actual filtering without more complex setup
	// But we can verify the events were processed
	metrics := sm.GetMetrics()
	assert.Equal(t, int64(2), metrics.TotalEvents)
}

func TestSubscriptionManager_Metrics(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{
		MaxSubscribers: 100,
		EnableMetrics:  true,
	})

	ctx := context.Background()

	// Create subscribers and publish events
	for i := 0; i < 3; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		eventType := fmt.Sprintf("event.type.%d", i)
		
		_, err := sm.Subscribe(ctx, clientID, []string{eventType}, nil, "websocket", "")
		require.NoError(t, err)

		event := &Event{
			ID:        fmt.Sprintf("event-%d", i),
			Type:      eventType,
			Source:    "test",
			Data:      fmt.Sprintf("data-%d", i),
			Timestamp: time.Now(),
			Priority:  EventPriorityNormal,
		}

		err = sm.PublishEvent(ctx, event)
		require.NoError(t, err)
	}

	metrics := sm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(3), metrics.TotalSubscribers)
	assert.Equal(t, int64(3), metrics.TotalEvents)
	assert.True(t, len(metrics.EventTypeMetrics) > 0)
	assert.NotZero(t, metrics.LastUpdated)
}

func TestSubscriptionManager_StartStop(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{
		MaxSubscribers: 100,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Start the subscription manager
	err := sm.Start(ctx)
	assert.NoError(t, err)

	// Stop the subscription manager
	err = sm.Stop()
	assert.NoError(t, err)
}

func TestEventValidation(t *testing.T) {
	sm := NewSubscriptionManager(SubscriptionConfig{MaxSubscribers: 100})

	ctx := context.Background()

	// Test invalid events
	invalidEvents := []*Event{
		{Type: "test", Data: "data"}, // Missing ID
		{ID: "1", Data: "data"},      // Missing Type
		{ID: "1", Type: "test"},      // Missing Data
	}

	for i, event := range invalidEvents {
		err := sm.PublishEvent(ctx, event)
		assert.Error(t, err, fmt.Sprintf("Event %d should be invalid", i))
		assert.Contains(t, err.Error(), "invalid event")
	}

	// Test valid event
	validEvent := &Event{
		ID:        "valid-event",
		Type:      "test.event",
		Data:      "test data",
		Timestamp: time.Now(),
		Priority:  EventPriorityNormal,
	}

	err := sm.PublishEvent(ctx, validEvent)
	assert.NoError(t, err)
}