package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// EventType represents the type of event
type EventType string

const (
	// EventTypeStateChange represents a container state change event
	EventTypeStateChange EventType = "state_change"
	// EventTypeHealthAlert represents a health alert event
	EventTypeHealthAlert EventType = "health_alert"
	// EventTypeMetricsUpdate represents a metrics update event
	EventTypeMetricsUpdate EventType = "metrics_update"
	// EventTypeSystemAlert represents a system-wide alert
	EventTypeSystemAlert EventType = "system_alert"
	// EventTypeRecovery represents a container recovery event
	EventTypeRecovery EventType = "recovery"
)

// EventSeverity represents the severity level of an event
type EventSeverity string

const (
	// EventSeverityInfo represents informational events
	EventSeverityInfo EventSeverity = "info"
	// EventSeverityWarning represents warning events
	EventSeverityWarning EventSeverity = "warning"
	// EventSeverityCritical represents critical events
	EventSeverityCritical EventSeverity = "critical"
	// EventSeverityError represents error events
	EventSeverityError EventSeverity = "error"
)

// Event represents a system event
type Event struct {
	ID          string                 `json:"id"`
	Type        EventType              `json:"type"`
	Severity    EventSeverity          `json:"severity"`
	Source      string                 `json:"source"`
	ContainerID string                 `json:"container_id,omitempty"`
	Title       string                 `json:"title"`
	Message     string                 `json:"message"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
}

// EventHandler defines a function that handles events
type EventHandler func(event Event) error

// EventFilter defines a function that filters events
type EventFilter func(event Event) bool

// EventSubscription represents an event subscription
type EventSubscription struct {
	ID       string       `json:"id"`
	Filter   EventFilter  `json:"-"` // Not serializable
	Handler  EventHandler `json:"-"` // Not serializable
	Types    []EventType  `json:"types"`
	Created  time.Time    `json:"created"`
	LastUsed time.Time    `json:"last_used"`
	Count    int64        `json:"count"`
	Active   bool         `json:"active"`
}

// EventBus manages event publishing and subscriptions
type EventBus struct {
	mu             sync.RWMutex
	subscriptions  map[string]*EventSubscription
	eventBuffer    []Event
	bufferSize     int
	eventQueue     chan Event
	ctx            context.Context
	cancel         context.CancelFunc
	stopOnce       sync.Once
	workerCount    int
	persistence    EventPersistence
}

// EventPersistence interface for persisting events
type EventPersistence interface {
	SaveEvent(event Event) error
	LoadEvents(filter EventFilter, limit int) ([]Event, error)
	CleanupOldEvents(olderThan time.Duration) error
}

// DatabaseEventPersistence implements EventPersistence using SQLite
type DatabaseEventPersistence struct {
	db *sql.DB
}

// NewDatabaseEventPersistence creates a new database event persistence
func NewDatabaseEventPersistence(db *sql.DB) (*DatabaseEventPersistence, error) {
	dep := &DatabaseEventPersistence{db: db}
	
	if err := dep.createTables(); err != nil {
		return nil, fmt.Errorf("failed to create event tables: %w", err)
	}
	
	return dep, nil
}

// SaveEvent saves an event to the database
func (dep *DatabaseEventPersistence) SaveEvent(event Event) error {
	metadataJSON, _ := json.Marshal(event.Metadata)
	tagsJSON, _ := json.Marshal(event.Tags)

	query := `INSERT INTO events 
		(id, type, severity, source, container_id, title, message, timestamp, metadata, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	_, err := dep.db.Exec(query,
		event.ID, string(event.Type), string(event.Severity), event.Source,
		event.ContainerID, event.Title, event.Message, event.Timestamp,
		string(metadataJSON), string(tagsJSON))
	
	return err
}

// LoadEvents loads events from the database
func (dep *DatabaseEventPersistence) LoadEvents(filter EventFilter, limit int) ([]Event, error) {
	query := `SELECT id, type, severity, source, container_id, title, message, timestamp, metadata, tags
		FROM events ORDER BY timestamp DESC`
	
	if limit > 0 {
		query = fmt.Sprintf("%s LIMIT %d", query, limit)
	}

	rows, err := dep.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var event Event
		var typeStr, severityStr, metadataStr, tagsStr sql.NullString

		err := rows.Scan(&event.ID, &typeStr, &severityStr, &event.Source,
			&event.ContainerID, &event.Title, &event.Message, &event.Timestamp,
			&metadataStr, &tagsStr)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan event row")
			continue
		}

		if typeStr.Valid {
			event.Type = EventType(typeStr.String)
		}
		if severityStr.Valid {
			event.Severity = EventSeverity(severityStr.String)
		}
		if metadataStr.Valid && metadataStr.String != "" {
			json.Unmarshal([]byte(metadataStr.String), &event.Metadata)
		}
		if tagsStr.Valid && tagsStr.String != "" {
			json.Unmarshal([]byte(tagsStr.String), &event.Tags)
		}

		// Apply filter if provided
		if filter == nil || filter(event) {
			events = append(events, event)
		}
	}

	return events, nil
}

// CleanupOldEvents removes old events from the database
func (dep *DatabaseEventPersistence) CleanupOldEvents(olderThan time.Duration) error {
	cutoff := time.Now().Add(-olderThan)
	
	query := `DELETE FROM events WHERE timestamp < ?`
	result, err := dep.db.Exec(query, cutoff)
	if err != nil {
		return err
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Info().Int64("rows_deleted", rowsAffected).Msg("Cleaned up old events")
	}

	return nil
}

// createTables creates the event tables
func (dep *DatabaseEventPersistence) createTables() error {
	query := `CREATE TABLE IF NOT EXISTS events (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		source TEXT NOT NULL,
		container_id TEXT,
		title TEXT NOT NULL,
		message TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		metadata TEXT,
		tags TEXT
	)`

	if _, err := dep.db.Exec(query); err != nil {
		return fmt.Errorf("failed to create events table: %w", err)
	}

	// Create indexes
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_type ON events(type)`,
		`CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_events_container ON events(container_id)`,
		`CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)`,
	}

	for _, indexQuery := range indexes {
		if _, err := dep.db.Exec(indexQuery); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// NewEventBus creates a new event bus
func NewEventBus(bufferSize int, persistence EventPersistence) *EventBus {
	ctx, cancel := context.WithCancel(context.Background())
	
	eb := &EventBus{
		subscriptions: make(map[string]*EventSubscription),
		eventBuffer:   make([]Event, 0, bufferSize),
		bufferSize:    bufferSize,
		eventQueue:    make(chan Event, bufferSize*2),
		ctx:           ctx,
		cancel:        cancel,
		workerCount:   3,
		persistence:   persistence,
	}

	// Start event processing workers
	for i := 0; i < eb.workerCount; i++ {
		go eb.eventWorker()
	}

	// Start cleanup worker
	go eb.cleanupWorker()

	log.Info().
		Int("buffer_size", bufferSize).
		Int("workers", eb.workerCount).
		Msg("Event bus initialized")
	
	return eb
}

// Subscribe subscribes to events with optional filter
func (eb *EventBus) Subscribe(handler EventHandler, filter EventFilter, eventTypes ...EventType) string {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	subscription := &EventSubscription{
		ID:       fmt.Sprintf("sub-%d", time.Now().UnixNano()),
		Handler:  handler,
		Filter:   filter,
		Types:    eventTypes,
		Created:  time.Now(),
		LastUsed: time.Now(),
		Active:   true,
	}

	eb.subscriptions[subscription.ID] = subscription

	log.Info().
		Str("subscription_id", subscription.ID).
		Int("event_types", len(eventTypes)).
		Msg("Event subscription created")

	return subscription.ID
}

// Unsubscribe removes a subscription
func (eb *EventBus) Unsubscribe(subscriptionID string) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	if sub, exists := eb.subscriptions[subscriptionID]; exists {
		sub.Active = false
		delete(eb.subscriptions, subscriptionID)
		log.Info().Str("subscription_id", subscriptionID).Msg("Event subscription removed")
	}
}

// Publish publishes an event to all matching subscribers
func (eb *EventBus) Publish(event Event) {
	if event.ID == "" {
		event.ID = fmt.Sprintf("evt-%d", time.Now().UnixNano())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case eb.eventQueue <- event:
		log.Debug().
			Str("event_id", event.ID).
			Str("event_type", string(event.Type)).
			Str("severity", string(event.Severity)).
			Msg("Event queued for processing")
	default:
		log.Warn().
			Str("event_id", event.ID).
			Msg("Event queue full, dropping event")
	}
}

// GetSubscriptions returns all active subscriptions
func (eb *EventBus) GetSubscriptions() []*EventSubscription {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	subscriptions := make([]*EventSubscription, 0, len(eb.subscriptions))
	for _, sub := range eb.subscriptions {
		if sub.Active {
			// Create a copy without the handler/filter functions
			subCopy := *sub
			subCopy.Handler = nil
			subCopy.Filter = nil
			subscriptions = append(subscriptions, &subCopy)
		}
	}

	return subscriptions
}

// GetEventHistory returns recent events from the buffer
func (eb *EventBus) GetEventHistory(limit int) []Event {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if limit <= 0 || limit > len(eb.eventBuffer) {
		limit = len(eb.eventBuffer)
	}

	// Return most recent events (from the end of the buffer)
	start := len(eb.eventBuffer) - limit
	if start < 0 {
		start = 0
	}

	history := make([]Event, limit)
	copy(history, eb.eventBuffer[start:])
	return history
}

// Stop stops the event bus
func (eb *EventBus) Stop() {
	eb.stopOnce.Do(func() {
		log.Info().Msg("Stopping event bus")
		eb.cancel()
		close(eb.eventQueue)
	})
}

// eventWorker processes events from the queue
func (eb *EventBus) eventWorker() {
	for {
		select {
		case <-eb.ctx.Done():
			return
		case event, ok := <-eb.eventQueue:
			if !ok {
				return
			}
			eb.processEvent(event)
		}
	}
}

// processEvent processes a single event
func (eb *EventBus) processEvent(event Event) {
	// Add to buffer
	eb.mu.Lock()
	if len(eb.eventBuffer) >= eb.bufferSize {
		// Remove oldest event
		copy(eb.eventBuffer, eb.eventBuffer[1:])
		eb.eventBuffer[len(eb.eventBuffer)-1] = event
	} else {
		eb.eventBuffer = append(eb.eventBuffer, event)
	}
	eb.mu.Unlock()

	// Persist event if persistence is available
	if eb.persistence != nil {
		if err := eb.persistence.SaveEvent(event); err != nil {
			log.Error().Err(err).Str("event_id", event.ID).Msg("Failed to persist event")
		}
	}

	// Notify subscribers
	eb.notifySubscribers(event)
}

// notifySubscribers notifies all matching subscribers about an event
func (eb *EventBus) notifySubscribers(event Event) {
	eb.mu.RLock()
	subscriptions := make([]*EventSubscription, 0, len(eb.subscriptions))
	for _, sub := range eb.subscriptions {
		if sub.Active {
			subscriptions = append(subscriptions, sub)
		}
	}
	eb.mu.RUnlock()

	for _, sub := range subscriptions {
		if eb.matchesSubscription(event, sub) {
			go eb.callHandler(event, sub)
		}
	}
}

// matchesSubscription checks if an event matches a subscription
func (eb *EventBus) matchesSubscription(event Event, sub *EventSubscription) bool {
	// Check event types filter
	if len(sub.Types) > 0 {
		matched := false
		for _, eventType := range sub.Types {
			if event.Type == eventType {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check custom filter
	if sub.Filter != nil && !sub.Filter(event) {
		return false
	}

	return true
}

// callHandler calls a subscription handler
func (eb *EventBus) callHandler(event Event, sub *EventSubscription) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Interface("panic", r).
				Str("subscription_id", sub.ID).
				Str("event_id", event.ID).
				Msg("Event handler panicked")
		}
	}()

	if sub.Handler != nil {
		if err := sub.Handler(event); err != nil {
			log.Error().
				Err(err).
				Str("subscription_id", sub.ID).
				Str("event_id", event.ID).
				Msg("Event handler returned error")
		} else {
			// Update subscription stats
			eb.mu.Lock()
			sub.LastUsed = time.Now()
			sub.Count++
			eb.mu.Unlock()
		}
	}
}

// cleanupWorker periodically cleans up old events
func (eb *EventBus) cleanupWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-eb.ctx.Done():
			return
		case <-ticker.C:
			if eb.persistence != nil {
				if err := eb.persistence.CleanupOldEvents(24 * time.Hour * 7); err != nil {
					log.Error().Err(err).Msg("Failed to cleanup old events")
				}
			}
		}
	}
}

// Helper functions for creating common events

// NewStateChangeEvent creates a state change event
func NewStateChangeEvent(containerID, source string, transition StateTransition) Event {
	severity := EventSeverityInfo
	if transition.To == ContainerStateFailed {
		severity = EventSeverityError
	}

	return Event{
		Type:        EventTypeStateChange,
		Severity:    severity,
		Source:      source,
		ContainerID: containerID,
		Title:       fmt.Sprintf("Container state changed: %s → %s", transition.From, transition.To),
		Message:     fmt.Sprintf("Container %s transitioned from %s to %s. Reason: %s", containerID, transition.From, transition.To, transition.Reason),
		Timestamp:   transition.Timestamp,
		Metadata: map[string]interface{}{
			"transition": transition,
		},
		Tags: []string{"state-change", string(transition.From), string(transition.To)},
	}
}

// NewHealthAlertEvent creates a health alert event
func NewHealthAlertEvent(containerID, source string, result HealthCheckResult) Event {
	severity := EventSeverityInfo
	switch result.Status {
	case HealthStatusWarning:
		severity = EventSeverityWarning
	case HealthStatusUnhealthy:
		severity = EventSeverityCritical
	}

	return Event{
		Type:        EventTypeHealthAlert,
		Severity:    severity,
		Source:      source,
		ContainerID: containerID,
		Title:       fmt.Sprintf("Health check %s: %s", result.CheckType, result.Status),
		Message:     fmt.Sprintf("Container %s health check (%s) status: %s. %s", containerID, result.CheckType, result.Status, result.Message),
		Timestamp:   result.Timestamp,
		Metadata: map[string]interface{}{
			"health_result": result,
		},
		Tags: []string{"health-alert", string(result.CheckType), string(result.Status)},
	}
}

// NewMetricsUpdateEvent creates a metrics update event
func NewMetricsUpdateEvent(source string, metrics map[string]interface{}) Event {
	return Event{
		Type:      EventTypeMetricsUpdate,
		Severity:  EventSeverityInfo,
		Source:    source,
		Title:     "System metrics updated",
		Message:   "System metrics have been updated",
		Timestamp: time.Now(),
		Metadata:  metrics,
		Tags:      []string{"metrics", "system"},
	}
}

// NewSystemAlertEvent creates a system alert event
func NewSystemAlertEvent(source, title, message string, severity EventSeverity) Event {
	return Event{
		Type:      EventTypeSystemAlert,
		Severity:  severity,
		Source:    source,
		Title:     title,
		Message:   message,
		Timestamp: time.Now(),
		Tags:      []string{"system", "alert"},
	}
}

// NewRecoveryEvent creates a new recovery event
func NewRecoveryEvent(containerID, source string, data map[string]interface{}) Event {
	title := "Container Recovery"
	message := "Container recovery operation"
	severity := EventSeverityInfo
	
	if success, ok := data["success"].(bool); ok && !success {
		severity = EventSeverityError
		message = "Container recovery failed"
	}
	
	return Event{
		Type:        EventTypeRecovery,
		Severity:    severity,
		Source:      source,
		ContainerID: containerID,
		Title:       title,
		Message:     message,
		Metadata:    data,
		Timestamp:   time.Now(),
		Tags:        []string{"recovery", "container"},
	}
}

// EventFilters contains common event filters

// ContainerFilter creates a filter for events related to a specific container
func ContainerFilter(containerID string) EventFilter {
	return func(event Event) bool {
		return event.ContainerID == containerID
	}
}

// SeverityFilter creates a filter for events of specific severity levels
func SeverityFilter(severities ...EventSeverity) EventFilter {
	severityMap := make(map[EventSeverity]bool)
	for _, s := range severities {
		severityMap[s] = true
	}
	
	return func(event Event) bool {
		return severityMap[event.Severity]
	}
}

// SourceFilter creates a filter for events from specific sources
func SourceFilter(sources ...string) EventFilter {
	sourceMap := make(map[string]bool)
	for _, s := range sources {
		sourceMap[s] = true
	}
	
	return func(event Event) bool {
		return sourceMap[event.Source]
	}
}

// TimeRangeFilter creates a filter for events within a time range
func TimeRangeFilter(start, end time.Time) EventFilter {
	return func(event Event) bool {
		return event.Timestamp.After(start) && event.Timestamp.Before(end)
	}
}