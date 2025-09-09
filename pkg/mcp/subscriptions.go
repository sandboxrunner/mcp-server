package mcp

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SubscriptionManager manages event subscriptions and notifications
type SubscriptionManager struct {
	registry        *EventRegistry
	transport       SubscriptionTransport
	filters         map[string]*EventFilter
	subscriptions   map[string]*Subscription
	batching        *BatchingManager
	reconnection    *ReconnectionManager
	mu              sync.RWMutex
	config          SubscriptionConfig
	metrics         *SubscriptionMetrics
}

// EventRegistry manages event types and their subscribers
type EventRegistry struct {
	events       map[string]*EventType
	subscribers  map[string]map[string]*EventSubscriber
	handlers     map[string]EventHandler
	middleware   []EventMiddleware
	mu           sync.RWMutex
	config       RegistryConfig
}

// EventType defines a type of event that can be subscribed to
type EventType struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Schema      map[string]interface{} `json:"schema"`
	Category    string                 `json:"category"`
	Priority    EventPriority          `json:"priority"`
	TTL         time.Duration          `json:"ttl"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"createdAt"`
}

// EventPriority defines event priority levels
type EventPriority int

const (
	EventPriorityLow      EventPriority = 1
	EventPriorityNormal   EventPriority = 2
	EventPriorityHigh     EventPriority = 3
	EventPriorityCritical EventPriority = 4
)

// EventSubscriber represents a subscriber to events
type EventSubscriber struct {
	ID             string            `json:"id"`
	ClientID       string            `json:"clientId"`
	EventTypes     []string          `json:"eventTypes"`
	Filter         *EventFilter      `json:"filter"`
	Transport      string            `json:"transport"`
	Endpoint       string            `json:"endpoint,omitempty"`
	Connection     interface{}       `json:"-"`
	Status         SubscriberStatus  `json:"status"`
	CreatedAt      time.Time         `json:"createdAt"`
	LastEventAt    *time.Time        `json:"lastEventAt,omitempty"`
	EventCount     int64             `json:"eventCount"`
	BatchConfig    *BatchConfig      `json:"batchConfig,omitempty"`
	ReconnectCount int               `json:"reconnectCount"`
	MaxReconnects  int               `json:"maxReconnects"`
	mu             sync.RWMutex
}

// EventFilter defines criteria for filtering events
type EventFilter struct {
	EventTypes    []string                 `json:"eventTypes,omitempty"`
	Categories    []string                 `json:"categories,omitempty"`
	Priorities    []EventPriority          `json:"priorities,omitempty"`
	Metadata      map[string]interface{}   `json:"metadata,omitempty"`
	TimeRange     *TimeRange               `json:"timeRange,omitempty"`
	Conditions    []FilterCondition        `json:"conditions,omitempty"`
	Logic         FilterLogic              `json:"logic,omitempty"`
}

// FilterCondition defines a single filter condition
type FilterCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Type     string      `json:"type,omitempty"`
}

// FilterLogic defines how multiple conditions are combined
type FilterLogic string

const (
	FilterLogicAND FilterLogic = "AND"
	FilterLogicOR  FilterLogic = "OR"
)

// TimeRange defines a time range filter
type TimeRange struct {
	Start *time.Time `json:"start,omitempty"`
	End   *time.Time `json:"end,omitempty"`
}

// SubscriberStatus defines subscriber status
type SubscriberStatus string

const (
	SubscriberStatusActive      SubscriberStatus = "active"
	SubscriberStatusPaused      SubscriberStatus = "paused"
	SubscriberStatusDisconnected SubscriberStatus = "disconnected"
	SubscriberStatusError       SubscriberStatus = "error"
)

// Subscription represents an active subscription
type Subscription struct {
	ID           string           `json:"id"`
	SubscriberID string           `json:"subscriberId"`
	EventType    string           `json:"eventType"`
	Filter       *EventFilter     `json:"filter"`
	Status       SubscriberStatus `json:"status"`
	CreatedAt    time.Time        `json:"createdAt"`
	UpdatedAt    time.Time        `json:"updatedAt"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// Event represents an event to be published
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
	Priority  EventPriority          `json:"priority"`
	TTL       time.Duration          `json:"ttl,omitempty"`
}

// EventHandler defines how to handle events
type EventHandler interface {
	Handle(ctx context.Context, event *Event) error
	GetInfo() HandlerInfo
}

// HandlerInfo provides information about an event handler
type HandlerInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	EventTypes  []string `json:"eventTypes"`
	Version     string   `json:"version"`
}

// EventMiddleware defines middleware for event processing
type EventMiddleware interface {
	Process(ctx context.Context, event *Event, next func(context.Context, *Event) error) error
}

// SubscriptionTransport defines the transport layer for subscriptions
type SubscriptionTransport interface {
	Start(ctx context.Context) error
	Stop() error
	SendEvent(subscriberID string, event *Event) error
	AddSubscriber(subscriber *EventSubscriber) error
	RemoveSubscriber(subscriberID string) error
	GetInfo() TransportInfo
}

// TransportInfo provides information about a transport
type TransportInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Protocols   []string `json:"protocols"`
	Version     string   `json:"version"`
}

// BatchingManager handles event batching
type BatchingManager struct {
	batches     map[string]*EventBatch
	config      BatchingConfig
	mu          sync.RWMutex
}

// EventBatch represents a batch of events
type EventBatch struct {
	ID           string    `json:"id"`
	SubscriberID string    `json:"subscriberId"`
	Events       []*Event  `json:"events"`
	CreatedAt    time.Time `json:"createdAt"`
	MaxSize      int       `json:"maxSize"`
	MaxWait      time.Duration `json:"maxWait"`
	Timer        *time.Timer `json:"-"`
}

// BatchConfig defines batching configuration for a subscriber
type BatchConfig struct {
	Enabled     bool          `json:"enabled"`
	MaxSize     int           `json:"maxSize"`
	MaxWait     time.Duration `json:"maxWait"`
	FlushOnType []string      `json:"flushOnType,omitempty"`
}

// ReconnectionManager handles automatic reconnection
type ReconnectionManager struct {
	reconnectQueue chan string
	config         ReconnectionConfig
	mu             sync.RWMutex
}

// WebSocketTransport implements WebSocket-based subscription transport
type WebSocketTransport struct {
	server      *http.Server
	connections map[string]interface{} // WebSocket connections
	config      WebSocketConfig
	mu          sync.RWMutex
}

// Configuration types
type SubscriptionConfig struct {
	MaxSubscribers      int           `json:"maxSubscribers"`
	DefaultBatchSize    int           `json:"defaultBatchSize"`
	DefaultBatchWait    time.Duration `json:"defaultBatchWait"`
	EnableBatching      bool          `json:"enableBatching"`
	EnableReconnection  bool          `json:"enableReconnection"`
	EnableMetrics       bool          `json:"enableMetrics"`
	CleanupInterval     time.Duration `json:"cleanupInterval"`
	EventTTL            time.Duration `json:"eventTTL"`
}

type RegistryConfig struct {
	MaxEventTypes       int           `json:"maxEventTypes"`
	MaxSubscribers      int           `json:"maxSubscribers"`
	DefaultEventTTL     time.Duration `json:"defaultEventTTL"`
	EnableMiddleware    bool          `json:"enableMiddleware"`
	EnableValidation    bool          `json:"enableValidation"`
}

type BatchingConfig struct {
	DefaultMaxSize      int           `json:"defaultMaxSize"`
	DefaultMaxWait      time.Duration `json:"defaultMaxWait"`
	MaxBatchesPerSub    int           `json:"maxBatchesPerSub"`
	CleanupInterval     time.Duration `json:"cleanupInterval"`
}

type ReconnectionConfig struct {
	MaxRetries      int           `json:"maxRetries"`
	InitialDelay    time.Duration `json:"initialDelay"`
	MaxDelay        time.Duration `json:"maxDelay"`
	Multiplier      float64       `json:"multiplier"`
	EnableJitter    bool          `json:"enableJitter"`
}

type WebSocketConfig struct {
	Address         string        `json:"address"`
	Port            int           `json:"port"`
	Path            string        `json:"path"`
	ReadTimeout     time.Duration `json:"readTimeout"`
	WriteTimeout    time.Duration `json:"writeTimeout"`
	PingInterval    time.Duration `json:"pingInterval"`
	MaxMessageSize  int64         `json:"maxMessageSize"`
}

// SubscriptionMetrics tracks subscription performance
type SubscriptionMetrics struct {
	TotalSubscribers    int64              `json:"totalSubscribers"`
	ActiveSubscribers   int64              `json:"activeSubscribers"`
	TotalEvents         int64              `json:"totalEvents"`
	EventsPerSecond     float64            `json:"eventsPerSecond"`
	EventsDelivered     int64              `json:"eventsDelivered"`
	EventsDropped       int64              `json:"eventsDropped"`
	BatchesProcessed    int64              `json:"batchesProcessed"`
	ReconnectionAttempts int64             `json:"reconnectionAttempts"`
	EventTypeMetrics    map[string]int64   `json:"eventTypeMetrics"`
	SubscriberMetrics   map[string]int64   `json:"subscriberMetrics"`
	TransportMetrics    map[string]int64   `json:"transportMetrics"`
	LastUpdated         time.Time          `json:"lastUpdated"`
	mu                  sync.RWMutex
}

// Built-in event handlers and middleware
type LoggingHandler struct{}
type MetricsHandler struct{}
type ValidationMiddleware struct{}
type TransformationMiddleware struct{}

// NewSubscriptionManager creates a new subscription manager
func NewSubscriptionManager(config SubscriptionConfig) *SubscriptionManager {
	sm := &SubscriptionManager{
		registry: NewEventRegistry(RegistryConfig{
			MaxEventTypes:   1000,
			MaxSubscribers:  config.MaxSubscribers,
			DefaultEventTTL: config.EventTTL,
			EnableMiddleware: true,
			EnableValidation: true,
		}),
		filters:       make(map[string]*EventFilter),
		subscriptions: make(map[string]*Subscription),
		config:        config,
		metrics: &SubscriptionMetrics{
			EventTypeMetrics:  make(map[string]int64),
			SubscriberMetrics: make(map[string]int64),
			TransportMetrics:  make(map[string]int64),
			LastUpdated:       time.Now(),
		},
	}

	// Initialize batching if enabled
	if config.EnableBatching {
		sm.batching = NewBatchingManager(BatchingConfig{
			DefaultMaxSize:   config.DefaultBatchSize,
			DefaultMaxWait:   config.DefaultBatchWait,
			MaxBatchesPerSub: 100,
			CleanupInterval:  time.Minute,
		})
	}

	// Initialize reconnection if enabled
	if config.EnableReconnection {
		sm.reconnection = NewReconnectionManager(ReconnectionConfig{
			MaxRetries:   5,
			InitialDelay: time.Second,
			MaxDelay:     time.Minute,
			Multiplier:   2.0,
			EnableJitter: true,
		})
	}

	// Initialize WebSocket transport by default
	sm.transport = NewWebSocketTransport(WebSocketConfig{
		Address:        "0.0.0.0",
		Port:           8080,
		Path:           "/ws",
		ReadTimeout:    time.Second * 30,
		WriteTimeout:   time.Second * 10,
		PingInterval:   time.Second * 30,
		MaxMessageSize: 1024 * 1024, // 1MB
	})

	// Register built-in handlers
	sm.registry.RegisterHandler("logging", &LoggingHandler{})
	sm.registry.RegisterHandler("metrics", &MetricsHandler{})

	// Register built-in middleware
	if config.EnableMetrics {
		sm.registry.RegisterMiddleware(&ValidationMiddleware{})
		sm.registry.RegisterMiddleware(&TransformationMiddleware{})
	}

	return sm
}

// Subscribe creates a new event subscription
func (sm *SubscriptionManager) Subscribe(ctx context.Context, clientID string, eventTypes []string, filter *EventFilter, transport string, endpoint string) (*EventSubscriber, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if len(sm.subscriptions) >= sm.config.MaxSubscribers {
		return nil, fmt.Errorf("maximum subscribers reached")
	}

	subscriberID := sm.generateSubscriberID()
	
	subscriber := &EventSubscriber{
		ID:            subscriberID,
		ClientID:      clientID,
		EventTypes:    eventTypes,
		Filter:        filter,
		Transport:     transport,
		Endpoint:      endpoint,
		Status:        SubscriberStatusActive,
		CreatedAt:     time.Now(),
		EventCount:    0,
		MaxReconnects: 5,
	}

	// Set up batching if enabled
	if sm.config.EnableBatching {
		subscriber.BatchConfig = &BatchConfig{
			Enabled: true,
			MaxSize: sm.config.DefaultBatchSize,
			MaxWait: sm.config.DefaultBatchWait,
		}
	}

	// Register with event registry
	if err := sm.registry.AddSubscriber(subscriber); err != nil {
		return nil, fmt.Errorf("failed to register subscriber: %w", err)
	}

	// Add to transport
	if err := sm.transport.AddSubscriber(subscriber); err != nil {
		return nil, fmt.Errorf("failed to add subscriber to transport: %w", err)
	}

	// Create subscriptions for each event type
	for _, eventType := range eventTypes {
		subscription := &Subscription{
			ID:           sm.generateSubscriptionID(),
			SubscriberID: subscriberID,
			EventType:    eventType,
			Filter:       filter,
			Status:       SubscriberStatusActive,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
			Metadata:     make(map[string]interface{}),
		}
		
		sm.subscriptions[subscription.ID] = subscription
	}

	// Update metrics
	if sm.config.EnableMetrics {
		sm.updateSubscriberMetrics(1)
	}

	log.Info().
		Str("subscriber_id", subscriberID).
		Str("client_id", clientID).
		Strs("event_types", eventTypes).
		Str("transport", transport).
		Msg("Subscriber created")

	return subscriber, nil
}

// Unsubscribe removes an event subscription
func (sm *SubscriptionManager) Unsubscribe(ctx context.Context, subscriberID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Remove from registry
	if err := sm.registry.RemoveSubscriber(subscriberID); err != nil {
		return fmt.Errorf("failed to remove subscriber from registry: %w", err)
	}

	// Remove from transport
	if err := sm.transport.RemoveSubscriber(subscriberID); err != nil {
		return fmt.Errorf("failed to remove subscriber from transport: %w", err)
	}

	// Remove subscriptions
	for subID, subscription := range sm.subscriptions {
		if subscription.SubscriberID == subscriberID {
			delete(sm.subscriptions, subID)
		}
	}

	// Clean up batches if enabled
	if sm.config.EnableBatching && sm.batching != nil {
		sm.batching.CleanupSubscriber(subscriberID)
	}

	// Update metrics
	if sm.config.EnableMetrics {
		sm.updateSubscriberMetrics(-1)
	}

	log.Info().
		Str("subscriber_id", subscriberID).
		Msg("Subscriber removed")

	return nil
}

// PublishEvent publishes an event to all relevant subscribers
func (sm *SubscriptionManager) PublishEvent(ctx context.Context, event *Event) error {
	start := time.Now()

	// Validate event
	if err := sm.validateEvent(event); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}

	// Process through middleware
	if err := sm.registry.ProcessEvent(ctx, event); err != nil {
		return fmt.Errorf("middleware processing failed: %w", err)
	}

	// Find matching subscribers
	subscribers := sm.findMatchingSubscribers(event)

	// Send to subscribers
	delivered := 0
	dropped := 0

	for _, subscriber := range subscribers {
		if sm.shouldBatch(subscriber) && sm.batching != nil {
			// Add to batch
			if err := sm.batching.AddToBatch(subscriber.ID, event); err != nil {
				log.Warn().Err(err).Str("subscriber_id", subscriber.ID).Msg("Failed to add event to batch")
				dropped++
			} else {
				delivered++
			}
		} else {
			// Send immediately
			if err := sm.transport.SendEvent(subscriber.ID, event); err != nil {
				log.Warn().Err(err).Str("subscriber_id", subscriber.ID).Msg("Failed to send event")
				dropped++
			} else {
				delivered++
				sm.updateSubscriberEvent(subscriber.ID)
			}
		}
	}

	// Update metrics
	if sm.config.EnableMetrics {
		duration := time.Since(start)
		sm.updateEventMetrics(event.Type, delivered, dropped, duration)
	}

	log.Debug().
		Str("event_id", event.ID).
		Str("event_type", event.Type).
		Int("delivered", delivered).
		Int("dropped", dropped).
		Msg("Event published")

	return nil
}

// GetSubscriptions returns all active subscriptions
func (sm *SubscriptionManager) GetSubscriptions(ctx context.Context, filter *EventFilter) ([]*Subscription, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var subscriptions []*Subscription
	for _, sub := range sm.subscriptions {
		if filter == nil || sm.matchesSubscriptionFilter(sub, filter) {
			subscriptions = append(subscriptions, sub)
		}
	}

	return subscriptions, nil
}

// Start starts the subscription manager
func (sm *SubscriptionManager) Start(ctx context.Context) error {
	// Start transport
	if err := sm.transport.Start(ctx); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}

	// Start reconnection manager if enabled
	if sm.config.EnableReconnection && sm.reconnection != nil {
		go sm.reconnection.Start(ctx, sm)
	}

	// Start cleanup routine
	go sm.startCleanupRoutine(ctx)

	log.Info().Msg("Subscription manager started")
	return nil
}

// Stop stops the subscription manager
func (sm *SubscriptionManager) Stop() error {
	// Stop transport
	if err := sm.transport.Stop(); err != nil {
		return fmt.Errorf("failed to stop transport: %w", err)
	}

	// Stop reconnection manager
	if sm.reconnection != nil {
		sm.reconnection.Stop()
	}

	log.Info().Msg("Subscription manager stopped")
	return nil
}

// GetMetrics returns subscription metrics
func (sm *SubscriptionManager) GetMetrics() *SubscriptionMetrics {
	if !sm.config.EnableMetrics {
		return nil
	}

	sm.metrics.mu.RLock()
	defer sm.metrics.mu.RUnlock()

	// Create a copy to avoid concurrent access
	metrics := &SubscriptionMetrics{
		TotalSubscribers:     sm.metrics.TotalSubscribers,
		ActiveSubscribers:    sm.metrics.ActiveSubscribers,
		TotalEvents:          sm.metrics.TotalEvents,
		EventsPerSecond:      sm.metrics.EventsPerSecond,
		EventsDelivered:      sm.metrics.EventsDelivered,
		EventsDropped:        sm.metrics.EventsDropped,
		BatchesProcessed:     sm.metrics.BatchesProcessed,
		ReconnectionAttempts: sm.metrics.ReconnectionAttempts,
		EventTypeMetrics:     make(map[string]int64),
		SubscriberMetrics:    make(map[string]int64),
		TransportMetrics:     make(map[string]int64),
		LastUpdated:          sm.metrics.LastUpdated,
	}

	for k, v := range sm.metrics.EventTypeMetrics {
		metrics.EventTypeMetrics[k] = v
	}
	for k, v := range sm.metrics.SubscriberMetrics {
		metrics.SubscriberMetrics[k] = v
	}
	for k, v := range sm.metrics.TransportMetrics {
		metrics.TransportMetrics[k] = v
	}

	return metrics
}

// Private helper methods

func (sm *SubscriptionManager) generateSubscriberID() string {
	return fmt.Sprintf("sub_%d", time.Now().UnixNano())
}

func (sm *SubscriptionManager) generateSubscriptionID() string {
	return fmt.Sprintf("subscription_%d", time.Now().UnixNano())
}

func (sm *SubscriptionManager) validateEvent(event *Event) error {
	if event.ID == "" {
		return fmt.Errorf("event ID is required")
	}
	if event.Type == "" {
		return fmt.Errorf("event type is required")
	}
	if event.Data == nil {
		return fmt.Errorf("event data is required")
	}
	return nil
}

func (sm *SubscriptionManager) findMatchingSubscribers(event *Event) []*EventSubscriber {
	return sm.registry.FindSubscribers(event)
}

func (sm *SubscriptionManager) shouldBatch(subscriber *EventSubscriber) bool {
	return sm.config.EnableBatching && 
		   subscriber.BatchConfig != nil && 
		   subscriber.BatchConfig.Enabled
}

func (sm *SubscriptionManager) matchesSubscriptionFilter(sub *Subscription, filter *EventFilter) bool {
	// Simple filtering - in production, implement comprehensive filtering
	if len(filter.EventTypes) > 0 {
		found := false
		for _, eventType := range filter.EventTypes {
			if sub.EventType == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (sm *SubscriptionManager) updateSubscriberEvent(subscriberID string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if subscriber := sm.registry.GetSubscriber(subscriberID); subscriber != nil {
		subscriber.mu.Lock()
		subscriber.EventCount++
		now := time.Now()
		subscriber.LastEventAt = &now
		subscriber.mu.Unlock()
	}
}

func (sm *SubscriptionManager) updateSubscriberMetrics(delta int64) {
	if !sm.config.EnableMetrics {
		return
	}

	sm.metrics.mu.Lock()
	sm.metrics.TotalSubscribers += delta
	if delta > 0 {
		sm.metrics.ActiveSubscribers++
	} else {
		sm.metrics.ActiveSubscribers--
	}
	sm.metrics.LastUpdated = time.Now()
	sm.metrics.mu.Unlock()
}

func (sm *SubscriptionManager) updateEventMetrics(eventType string, delivered, dropped int, duration time.Duration) {
	if !sm.config.EnableMetrics {
		return
	}

	sm.metrics.mu.Lock()
	sm.metrics.TotalEvents++
	sm.metrics.EventsDelivered += int64(delivered)
	sm.metrics.EventsDropped += int64(dropped)
	sm.metrics.EventTypeMetrics[eventType]++
	
	// Update events per second
	if sm.metrics.TotalEvents > 0 {
		totalDuration := time.Since(sm.metrics.LastUpdated).Seconds()
		if totalDuration > 0 {
			sm.metrics.EventsPerSecond = float64(sm.metrics.TotalEvents) / totalDuration
		}
	}
	
	sm.metrics.LastUpdated = time.Now()
	sm.metrics.mu.Unlock()
}

func (sm *SubscriptionManager) startCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(sm.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.performCleanup()
		}
	}
}

func (sm *SubscriptionManager) performCleanup() {
	// Clean up expired batches
	if sm.batching != nil {
		sm.batching.CleanupExpired()
	}

	// Clean up disconnected subscribers
	sm.cleanupDisconnectedSubscribers()

	log.Debug().Msg("Cleanup completed")
}

func (sm *SubscriptionManager) cleanupDisconnectedSubscribers() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	disconnectedSubs := []string{}
	
	for _, subscription := range sm.subscriptions {
		if subscriber := sm.registry.GetSubscriber(subscription.SubscriberID); subscriber != nil {
			if subscriber.Status == SubscriberStatusDisconnected {
				disconnectedSubs = append(disconnectedSubs, subscriber.ID)
			}
		}
	}

	for _, subID := range disconnectedSubs {
		sm.Unsubscribe(context.Background(), subID)
	}
}

// EventRegistry implementation

func NewEventRegistry(config RegistryConfig) *EventRegistry {
	return &EventRegistry{
		events:      make(map[string]*EventType),
		subscribers: make(map[string]map[string]*EventSubscriber),
		handlers:    make(map[string]EventHandler),
		middleware:  []EventMiddleware{},
		config:      config,
	}
}

func (er *EventRegistry) RegisterEventType(eventType *EventType) error {
	er.mu.Lock()
	defer er.mu.Unlock()

	if len(er.events) >= er.config.MaxEventTypes {
		return fmt.Errorf("maximum event types reached")
	}

	er.events[eventType.Name] = eventType
	er.subscribers[eventType.Name] = make(map[string]*EventSubscriber)

	log.Info().
		Str("event_type", eventType.Name).
		Str("category", eventType.Category).
		Msg("Event type registered")

	return nil
}

func (er *EventRegistry) RegisterHandler(name string, handler EventHandler) {
	er.mu.Lock()
	defer er.mu.Unlock()

	er.handlers[name] = handler

	log.Info().
		Str("handler", name).
		Msg("Event handler registered")
}

func (er *EventRegistry) RegisterMiddleware(middleware EventMiddleware) {
	er.mu.Lock()
	defer er.mu.Unlock()

	er.middleware = append(er.middleware, middleware)

	log.Info().Msg("Event middleware registered")
}

func (er *EventRegistry) AddSubscriber(subscriber *EventSubscriber) error {
	er.mu.Lock()
	defer er.mu.Unlock()

	for _, eventType := range subscriber.EventTypes {
		if _, exists := er.events[eventType]; !exists {
			// Auto-register event type
			er.events[eventType] = &EventType{
				Name:        eventType,
				Description: fmt.Sprintf("Auto-registered event type: %s", eventType),
				Category:    "general",
				Priority:    EventPriorityNormal,
				TTL:         er.config.DefaultEventTTL,
				CreatedAt:   time.Now(),
			}
			er.subscribers[eventType] = make(map[string]*EventSubscriber)
		}

		if er.subscribers[eventType] == nil {
			er.subscribers[eventType] = make(map[string]*EventSubscriber)
		}

		er.subscribers[eventType][subscriber.ID] = subscriber
	}

	return nil
}

func (er *EventRegistry) RemoveSubscriber(subscriberID string) error {
	er.mu.Lock()
	defer er.mu.Unlock()

	for eventType := range er.subscribers {
		delete(er.subscribers[eventType], subscriberID)
	}

	return nil
}

func (er *EventRegistry) FindSubscribers(event *Event) []*EventSubscriber {
	er.mu.RLock()
	defer er.mu.RUnlock()

	var matchingSubscribers []*EventSubscriber

	if subscribers, exists := er.subscribers[event.Type]; exists {
		for _, subscriber := range subscribers {
			if er.matchesFilter(event, subscriber.Filter) {
				matchingSubscribers = append(matchingSubscribers, subscriber)
			}
		}
	}

	return matchingSubscribers
}

func (er *EventRegistry) GetSubscriber(subscriberID string) *EventSubscriber {
	er.mu.RLock()
	defer er.mu.RUnlock()

	for _, subscribers := range er.subscribers {
		if subscriber, exists := subscribers[subscriberID]; exists {
			return subscriber
		}
	}

	return nil
}

func (er *EventRegistry) ProcessEvent(ctx context.Context, event *Event) error {
	// Process through middleware chain
	var processFunc func(context.Context, *Event) error
	processFunc = func(ctx context.Context, e *Event) error {
		// Run handlers
		for _, handler := range er.handlers {
			if err := handler.Handle(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}

	// Apply middleware in reverse order
	for i := len(er.middleware) - 1; i >= 0; i-- {
		middleware := er.middleware[i]
		nextFunc := processFunc
		processFunc = func(ctx context.Context, e *Event) error {
			return middleware.Process(ctx, e, nextFunc)
		}
	}

	return processFunc(ctx, event)
}

func (er *EventRegistry) matchesFilter(event *Event, filter *EventFilter) bool {
	if filter == nil {
		return true
	}

	// Check event types
	if len(filter.EventTypes) > 0 {
		found := false
		for _, eventType := range filter.EventTypes {
			if event.Type == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check priorities
	if len(filter.Priorities) > 0 {
		found := false
		for _, priority := range filter.Priorities {
			if event.Priority == priority {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check time range
	if filter.TimeRange != nil {
		if filter.TimeRange.Start != nil && event.Timestamp.Before(*filter.TimeRange.Start) {
			return false
		}
		if filter.TimeRange.End != nil && event.Timestamp.After(*filter.TimeRange.End) {
			return false
		}
	}

	// Check metadata filters
	for key, value := range filter.Metadata {
		if eventValue, exists := event.Metadata[key]; !exists || eventValue != value {
			return false
		}
	}

	return true
}

// Built-in handler implementations

func (lh *LoggingHandler) Handle(ctx context.Context, event *Event) error {
	log.Info().
		Str("event_id", event.ID).
		Str("event_type", event.Type).
		Str("source", event.Source).
		Time("timestamp", event.Timestamp).
		Msg("Event processed by logging handler")
	return nil
}

func (lh *LoggingHandler) GetInfo() HandlerInfo {
	return HandlerInfo{
		Name:        "logging",
		Description: "Logs all events",
		EventTypes:  []string{"*"},
		Version:     "1.0.0",
	}
}

func (mh *MetricsHandler) Handle(ctx context.Context, event *Event) error {
	// Update metrics - in production, integrate with metrics system
	log.Debug().
		Str("event_type", event.Type).
		Msg("Event processed by metrics handler")
	return nil
}

func (mh *MetricsHandler) GetInfo() HandlerInfo {
	return HandlerInfo{
		Name:        "metrics",
		Description: "Collects event metrics",
		EventTypes:  []string{"*"},
		Version:     "1.0.0",
	}
}

// Built-in middleware implementations

func (vm *ValidationMiddleware) Process(ctx context.Context, event *Event, next func(context.Context, *Event) error) error {
	// Validate event
	if event.ID == "" || event.Type == "" {
		return fmt.Errorf("invalid event: missing required fields")
	}

	return next(ctx, event)
}

func (tm *TransformationMiddleware) Process(ctx context.Context, event *Event, next func(context.Context, *Event) error) error {
	// Transform event if needed
	if event.Metadata == nil {
		event.Metadata = make(map[string]interface{})
	}
	event.Metadata["processed_at"] = time.Now()

	return next(ctx, event)
}

// Placeholder implementations for batching and other components
// These would be fully implemented in a production system

func NewBatchingManager(config BatchingConfig) *BatchingManager {
	return &BatchingManager{
		batches: make(map[string]*EventBatch),
		config:  config,
	}
}

func (bm *BatchingManager) AddToBatch(subscriberID string, event *Event) error {
	// Implementation would add event to subscriber's batch
	return nil
}

func (bm *BatchingManager) CleanupSubscriber(subscriberID string) {
	// Implementation would clean up subscriber's batches
}

func (bm *BatchingManager) CleanupExpired() {
	// Implementation would clean up expired batches
}

func NewReconnectionManager(config ReconnectionConfig) *ReconnectionManager {
	return &ReconnectionManager{
		reconnectQueue: make(chan string, 1000),
		config:         config,
	}
}

func (rm *ReconnectionManager) Start(ctx context.Context, sm *SubscriptionManager) {
	// Implementation would handle reconnection logic
}

func (rm *ReconnectionManager) Stop() {
	// Implementation would stop reconnection manager
}

func NewWebSocketTransport(config WebSocketConfig) *WebSocketTransport {
	return &WebSocketTransport{
		connections: make(map[string]interface{}),
		config:      config,
	}
}

func (wst *WebSocketTransport) Start(ctx context.Context) error {
	// Implementation would start WebSocket server
	return nil
}

func (wst *WebSocketTransport) Stop() error {
	// Implementation would stop WebSocket server
	return nil
}

func (wst *WebSocketTransport) SendEvent(subscriberID string, event *Event) error {
	// Implementation would send event via WebSocket
	return nil
}

func (wst *WebSocketTransport) AddSubscriber(subscriber *EventSubscriber) error {
	// Implementation would add WebSocket subscriber
	return nil
}

func (wst *WebSocketTransport) RemoveSubscriber(subscriberID string) error {
	// Implementation would remove WebSocket subscriber
	return nil
}

func (wst *WebSocketTransport) GetInfo() TransportInfo {
	return TransportInfo{
		Name:        "websocket",
		Description: "WebSocket-based event transport",
		Protocols:   []string{"ws", "wss"},
		Version:     "1.0.0",
	}
}