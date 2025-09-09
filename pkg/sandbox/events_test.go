package sandbox

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventTypes(t *testing.T) {
	tests := []struct {
		name      string
		eventType EventType
	}{
		{"StateChange", EventTypeStateChange},
		{"HealthAlert", EventTypeHealthAlert},
		{"MetricsUpdate", EventTypeMetricsUpdate},
		{"SystemAlert", EventTypeSystemAlert},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, string(tt.eventType))
		})
	}
}

func TestEventSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity EventSeverity
	}{
		{"Info", EventSeverityInfo},
		{"Warning", EventSeverityWarning},
		{"Critical", EventSeverityCritical},
		{"Error", EventSeverityError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, string(tt.severity))
		})
	}
}

func TestNewEventBus(t *testing.T) {
	db := setupTestEventsDB(t)
	defer db.Close()

	persistence, err := NewDatabaseEventPersistence(db)
	require.NoError(t, err)

	bus := NewEventBus(100, persistence)
	assert.NotNil(t, bus)

	bus.Stop()
}

func TestEventBusSubscription(t *testing.T) {
	bus := NewEventBus(10, nil)
	defer bus.Stop()

	var receivedEvents []Event
	var eventMutex sync.Mutex

	handler := func(event Event) error {
		eventMutex.Lock()
		defer eventMutex.Unlock()
		receivedEvents = append(receivedEvents, event)
		return nil
	}

	// Subscribe to state change events only
	subscriptionID := bus.Subscribe(handler, nil, EventTypeStateChange)
	assert.NotEmpty(t, subscriptionID)

	// Publish a state change event
	event := Event{
		Type:        EventTypeStateChange,
		Severity:    EventSeverityInfo,
		Source:      "test",
		ContainerID: "container1",
		Title:       "Test State Change",
		Message:     "Container state changed for testing",
		Timestamp:   time.Now(),
	}

	bus.Publish(event)

	// Wait for event processing
	time.Sleep(100 * time.Millisecond)

	// Check event was received
	eventMutex.Lock()
	defer eventMutex.Unlock()
	assert.Len(t, receivedEvents, 1)
	assert.Equal(t, event.Type, receivedEvents[0].Type)
	assert.Equal(t, event.ContainerID, receivedEvents[0].ContainerID)
}

func TestEventBusFiltering(t *testing.T) {
	bus := NewEventBus(10, nil)
	defer bus.Stop()

	var stateChangeEvents []Event
	var healthAlertEvents []Event
	var eventMutex sync.Mutex

	// Subscribe to state changes only
	stateHandler := func(event Event) error {
		eventMutex.Lock()
		defer eventMutex.Unlock()
		stateChangeEvents = append(stateChangeEvents, event)
		return nil
	}
	bus.Subscribe(stateHandler, nil, EventTypeStateChange)

	// Subscribe to health alerts only
	healthHandler := func(event Event) error {
		eventMutex.Lock()
		defer eventMutex.Unlock()
		healthAlertEvents = append(healthAlertEvents, event)
		return nil
	}
	bus.Subscribe(healthHandler, nil, EventTypeHealthAlert)

	// Publish different event types
	events := []Event{
		{Type: EventTypeStateChange, Severity: EventSeverityInfo, Source: "test", Title: "State Change", Message: "Test"},
		{Type: EventTypeHealthAlert, Severity: EventSeverityWarning, Source: "test", Title: "Health Alert", Message: "Test"},
		{Type: EventTypeMetricsUpdate, Severity: EventSeverityInfo, Source: "test", Title: "Metrics", Message: "Test"},
	}

	for _, event := range events {
		bus.Publish(event)
	}

	// Wait for event processing
	time.Sleep(200 * time.Millisecond)

	// Check filtering worked
	eventMutex.Lock()
	defer eventMutex.Unlock()
	assert.Len(t, stateChangeEvents, 1)
	assert.Len(t, healthAlertEvents, 1)
	assert.Equal(t, EventTypeStateChange, stateChangeEvents[0].Type)
	assert.Equal(t, EventTypeHealthAlert, healthAlertEvents[0].Type)
}

func TestEventBusCustomFilter(t *testing.T) {
	bus := NewEventBus(10, nil)
	defer bus.Stop()

	var criticalEvents []Event
	var eventMutex sync.Mutex

	// Filter for critical events only
	criticalFilter := func(event Event) bool {
		return event.Severity == EventSeverityCritical
	}

	handler := func(event Event) error {
		eventMutex.Lock()
		defer eventMutex.Unlock()
		criticalEvents = append(criticalEvents, event)
		return nil
	}

	bus.Subscribe(handler, criticalFilter)

	// Publish events with different severities
	events := []Event{
		{Type: EventTypeSystemAlert, Severity: EventSeverityInfo, Source: "test", Title: "Info", Message: "Test"},
		{Type: EventTypeSystemAlert, Severity: EventSeverityWarning, Source: "test", Title: "Warning", Message: "Test"},
		{Type: EventTypeSystemAlert, Severity: EventSeverityCritical, Source: "test", Title: "Critical", Message: "Test"},
		{Type: EventTypeSystemAlert, Severity: EventSeverityError, Source: "test", Title: "Error", Message: "Test"},
	}

	for _, event := range events {
		bus.Publish(event)
	}

	// Wait for event processing
	time.Sleep(200 * time.Millisecond)

	// Check only critical events were received
	eventMutex.Lock()
	defer eventMutex.Unlock()
	assert.Len(t, criticalEvents, 1)
	assert.Equal(t, EventSeverityCritical, criticalEvents[0].Severity)
}

func TestEventBusUnsubscribe(t *testing.T) {
	bus := NewEventBus(10, nil)
	defer bus.Stop()

	var receivedEvents []Event
	var eventMutex sync.Mutex

	handler := func(event Event) error {
		eventMutex.Lock()
		defer eventMutex.Unlock()
		receivedEvents = append(receivedEvents, event)
		return nil
	}

	// Subscribe
	subscriptionID := bus.Subscribe(handler, nil, EventTypeStateChange)

	// Publish event
	event1 := Event{Type: EventTypeStateChange, Severity: EventSeverityInfo, Source: "test", Title: "Event 1", Message: "Test"}
	bus.Publish(event1)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Unsubscribe
	bus.Unsubscribe(subscriptionID)

	// Publish another event
	event2 := Event{Type: EventTypeStateChange, Severity: EventSeverityInfo, Source: "test", Title: "Event 2", Message: "Test"}
	bus.Publish(event2)

	// Wait for processing
	time.Sleep(100 * time.Millisecond)

	// Should only have received first event
	eventMutex.Lock()
	defer eventMutex.Unlock()
	assert.Len(t, receivedEvents, 1)
	assert.Equal(t, "Event 1", receivedEvents[0].Title)
}

func TestEventHistory(t *testing.T) {
	bus := NewEventBus(5, nil) // Small buffer for testing
	defer bus.Stop()

	// Publish more events than buffer size
	for i := 0; i < 8; i++ {
		event := Event{
			Type:     EventTypeSystemAlert,
			Severity: EventSeverityInfo,
			Source:   "test",
			Title:    fmt.Sprintf("Event %d", i),
			Message:  "Test event",
		}
		bus.Publish(event)
	}

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Get history
	history := bus.GetEventHistory(10)
	
	// Should have at most buffer size events
	assert.LessOrEqual(t, len(history), 5)
	
	if len(history) > 0 {
		// Events should be in chronological order
		for i := 1; i < len(history); i++ {
			assert.False(t, history[i].Timestamp.Before(history[i-1].Timestamp))
		}
	}
}

func TestDatabaseEventPersistence(t *testing.T) {
	db := setupTestEventsDB(t)
	defer db.Close()

	persistence, err := NewDatabaseEventPersistence(db)
	require.NoError(t, err)

	// Test saving event
	event := Event{
		ID:          "test-event-1",
		Type:        EventTypeStateChange,
		Severity:    EventSeverityInfo,
		Source:      "test",
		ContainerID: "container1",
		Title:       "Test Event",
		Message:     "Test event message",
		Timestamp:   time.Now(),
		Metadata:    map[string]interface{}{"key": "value"},
		Tags:        []string{"tag1", "tag2"},
	}

	err = persistence.SaveEvent(event)
	assert.NoError(t, err)

	// Test loading events
	events, err := persistence.LoadEvents(nil, 10)
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, event.ID, events[0].ID)
	assert.Equal(t, event.Type, events[0].Type)
	assert.Equal(t, event.ContainerID, events[0].ContainerID)
}

func TestDatabaseEventPersistenceFilter(t *testing.T) {
	db := setupTestEventsDB(t)
	defer db.Close()

	persistence, err := NewDatabaseEventPersistence(db)
	require.NoError(t, err)

	// Save multiple events
	events := []Event{
		{ID: "event1", Type: EventTypeStateChange, Severity: EventSeverityInfo, Source: "test", Title: "Event 1", Message: "Test", Timestamp: time.Now()},
		{ID: "event2", Type: EventTypeHealthAlert, Severity: EventSeverityCritical, Source: "test", Title: "Event 2", Message: "Test", Timestamp: time.Now()},
		{ID: "event3", Type: EventTypeStateChange, Severity: EventSeverityWarning, Source: "test", Title: "Event 3", Message: "Test", Timestamp: time.Now()},
	}

	for _, event := range events {
		err = persistence.SaveEvent(event)
		require.NoError(t, err)
	}

	// Test filter for state changes only
	stateFilter := func(event Event) bool {
		return event.Type == EventTypeStateChange
	}

	filteredEvents, err := persistence.LoadEvents(stateFilter, 10)
	require.NoError(t, err)
	assert.Len(t, filteredEvents, 2)
	for _, event := range filteredEvents {
		assert.Equal(t, EventTypeStateChange, event.Type)
	}
}

func TestEventCleanup(t *testing.T) {
	db := setupTestEventsDB(t)
	defer db.Close()

	persistence, err := NewDatabaseEventPersistence(db)
	require.NoError(t, err)

	// Save old and new events
	oldTime := time.Now().Add(-48 * time.Hour)
	newTime := time.Now()

	events := []Event{
		{ID: "old1", Type: EventTypeStateChange, Severity: EventSeverityInfo, Source: "test", Title: "Old Event 1", Message: "Test", Timestamp: oldTime},
		{ID: "old2", Type: EventTypeStateChange, Severity: EventSeverityInfo, Source: "test", Title: "Old Event 2", Message: "Test", Timestamp: oldTime},
		{ID: "new1", Type: EventTypeStateChange, Severity: EventSeverityInfo, Source: "test", Title: "New Event 1", Message: "Test", Timestamp: newTime},
	}

	for _, event := range events {
		err = persistence.SaveEvent(event)
		require.NoError(t, err)
	}

	// Clean up events older than 24 hours
	err = persistence.CleanupOldEvents(24 * time.Hour)
	assert.NoError(t, err)

	// Should only have new events left
	remainingEvents, err := persistence.LoadEvents(nil, 10)
	require.NoError(t, err)
	assert.Len(t, remainingEvents, 1)
	assert.Equal(t, "new1", remainingEvents[0].ID)
}

func TestEventHelpers(t *testing.T) {
	containerID := "test-container"
	source := "test-source"

	// Test state change event helper
	transition := StateTransition{
		ContainerID: containerID,
		From:        ContainerStateCreating,
		To:          ContainerStateRunning,
		Reason:      "Test transition",
		Timestamp:   time.Now(),
	}
	
	stateEvent := NewStateChangeEvent(containerID, source, transition)
	assert.Equal(t, EventTypeStateChange, stateEvent.Type)
	assert.Equal(t, containerID, stateEvent.ContainerID)
	assert.Equal(t, source, stateEvent.Source)
	assert.Contains(t, stateEvent.Tags, "state-change")
	assert.Contains(t, stateEvent.Tags, string(ContainerStateCreating))
	assert.Contains(t, stateEvent.Tags, string(ContainerStateRunning))

	// Test health alert event helper
	healthResult := HealthCheckResult{
		ContainerID: containerID,
		CheckType:   HealthCheckTypeLiveness,
		Status:      HealthStatusUnhealthy,
		Message:     "Container unhealthy",
		Timestamp:   time.Now(),
	}
	
	healthEvent := NewHealthAlertEvent(containerID, source, healthResult)
	assert.Equal(t, EventTypeHealthAlert, healthEvent.Type)
	assert.Equal(t, EventSeverityCritical, healthEvent.Severity)
	assert.Equal(t, containerID, healthEvent.ContainerID)
	assert.Contains(t, healthEvent.Tags, "health-alert")

	// Test metrics update event helper
	metrics := map[string]interface{}{
		"cpu_usage":    45.2,
		"memory_usage": 67.8,
	}
	
	metricsEvent := NewMetricsUpdateEvent(source, metrics)
	assert.Equal(t, EventTypeMetricsUpdate, metricsEvent.Type)
	assert.Equal(t, source, metricsEvent.Source)
	assert.Equal(t, metrics, metricsEvent.Metadata)

	// Test system alert event helper
	systemEvent := NewSystemAlertEvent(source, "System Error", "Critical system error occurred", EventSeverityError)
	assert.Equal(t, EventTypeSystemAlert, systemEvent.Type)
	assert.Equal(t, EventSeverityError, systemEvent.Severity)
	assert.Equal(t, "System Error", systemEvent.Title)
}

func TestEventFilters(t *testing.T) {
	containerID := "test-container"
	
	events := []Event{
		{ContainerID: containerID, Type: EventTypeStateChange, Severity: EventSeverityInfo, Source: "source1", Timestamp: time.Now().Add(-1 * time.Hour)},
		{ContainerID: "other-container", Type: EventTypeHealthAlert, Severity: EventSeverityCritical, Source: "source2", Timestamp: time.Now()},
		{ContainerID: containerID, Type: EventTypeHealthAlert, Severity: EventSeverityWarning, Source: "source1", Timestamp: time.Now()},
	}

	// Test container filter
	containerFilter := ContainerFilter(containerID)
	filteredCount := 0
	for _, event := range events {
		if containerFilter(event) {
			filteredCount++
		}
	}
	assert.Equal(t, 2, filteredCount)

	// Test severity filter
	severityFilter := SeverityFilter(EventSeverityCritical, EventSeverityWarning)
	filteredCount = 0
	for _, event := range events {
		if severityFilter(event) {
			filteredCount++
		}
	}
	assert.Equal(t, 2, filteredCount)

	// Test source filter
	sourceFilter := SourceFilter("source1")
	filteredCount = 0
	for _, event := range events {
		if sourceFilter(event) {
			filteredCount++
		}
	}
	assert.Equal(t, 2, filteredCount)

	// Test time range filter
	start := time.Now().Add(-2 * time.Hour)
	end := time.Now().Add(-30 * time.Minute)
	timeFilter := TimeRangeFilter(start, end)
	filteredCount = 0
	for _, event := range events {
		if timeFilter(event) {
			filteredCount++
		}
	}
	assert.Equal(t, 1, filteredCount)
}

func TestEventBusGetSubscriptions(t *testing.T) {
	bus := NewEventBus(10, nil)
	defer bus.Stop()

	// Initially no subscriptions
	subs := bus.GetSubscriptions()
	assert.Len(t, subs, 0)

	// Add subscriptions
	handler := func(event Event) error { return nil }
	sub1 := bus.Subscribe(handler, nil, EventTypeStateChange)
	sub2 := bus.Subscribe(handler, nil, EventTypeHealthAlert, EventTypeMetricsUpdate)

	subs = bus.GetSubscriptions()
	assert.Len(t, subs, 2)

	// Find subscriptions
	var foundSub1, foundSub2 *EventSubscription
	for _, sub := range subs {
		if sub.ID == sub1 {
			foundSub1 = sub
		} else if sub.ID == sub2 {
			foundSub2 = sub
		}
	}

	require.NotNil(t, foundSub1)
	require.NotNil(t, foundSub2)
	assert.Len(t, foundSub1.Types, 1)
	assert.Len(t, foundSub2.Types, 2)
}

func setupTestEventsDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	return db
}

// Benchmark tests

func BenchmarkEventPublish(b *testing.B) {
	bus := NewEventBus(1000, nil)
	defer bus.Stop()

	event := Event{
		Type:     EventTypeStateChange,
		Severity: EventSeverityInfo,
		Source:   "benchmark",
		Title:    "Benchmark Event",
		Message:  "Test event for benchmarking",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bus.Publish(event)
	}
}

func BenchmarkEventSubscription(b *testing.B) {
	bus := NewEventBus(100, nil)
	defer bus.Stop()

	handler := func(event Event) error { return nil }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		subID := bus.Subscribe(handler, nil, EventTypeStateChange)
		bus.Unsubscribe(subID)
	}
}

func BenchmarkEventPersistence(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(b, err)
	defer db.Close()

	persistence, err := NewDatabaseEventPersistence(db)
	require.NoError(b, err)

	event := Event{
		ID:       "benchmark-event",
		Type:     EventTypeStateChange,
		Severity: EventSeverityInfo,
		Source:   "benchmark",
		Title:    "Benchmark Event",
		Message:  "Test event for benchmarking",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.ID = fmt.Sprintf("benchmark-event-%d", i)
		err := persistence.SaveEvent(event)
		if err != nil {
			b.Fatal(err)
		}
	}
}