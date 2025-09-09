package mcp

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// StreamManager manages streaming operations for long-running MCP operations
type StreamManager struct {
	streams       map[string]*Stream
	multiplexer   *StreamMultiplexer
	backpressure  *BackpressureManager
	mu            sync.RWMutex
	config        StreamConfig
	metrics       *StreamMetrics
	cancellation  *CancellationManager
}

// Stream represents a single streaming operation
type Stream struct {
	ID             string                 `json:"id"`
	Type           StreamType             `json:"type"`
	Status         StreamStatus           `json:"status"`
	Progress       float64                `json:"progress"`
	Total          *float64               `json:"total,omitempty"`
	StartTime      time.Time              `json:"startTime"`
	LastUpdate     time.Time              `json:"lastUpdate"`
	Writer         io.Writer              `json:"-"`
	Context        context.Context        `json:"-"`
	CancelFunc     context.CancelFunc     `json:"-"`
	ChunkSize      int                    `json:"chunkSize"`
	BytesWritten   int64                  `json:"bytesWritten"`
	TotalBytes     int64                  `json:"totalBytes"`
	Metadata       map[string]interface{} `json:"metadata"`
	Subscribers    []string               `json:"subscribers"`
	BufferSize     int                    `json:"bufferSize"`
	Priority       StreamPriority         `json:"priority"`
	mu             sync.RWMutex
}

// StreamType defines the type of streaming operation
type StreamType string

const (
	StreamTypeToolExecution StreamType = "tool_execution"
	StreamTypeFileTransfer  StreamType = "file_transfer"
	StreamTypeLogStreaming  StreamType = "log_streaming"
	StreamTypeDataStream    StreamType = "data_stream"
	StreamTypeProgress      StreamType = "progress"
	StreamTypeCustom        StreamType = "custom"
)

// StreamStatus defines the current status of a stream
type StreamStatus string

const (
	StreamStatusPending   StreamStatus = "pending"
	StreamStatusActive    StreamStatus = "active"
	StreamStatusPaused    StreamStatus = "paused"
	StreamStatusCompleted StreamStatus = "completed"
	StreamStatusCancelled StreamStatus = "cancelled"
	StreamStatusError     StreamStatus = "error"
)

// StreamPriority defines the priority level of a stream
type StreamPriority int

const (
	StreamPriorityLow    StreamPriority = 1
	StreamPriorityNormal StreamPriority = 2
	StreamPriorityHigh   StreamPriority = 3
	StreamPriorityCritical StreamPriority = 4
)

// StreamMultiplexer handles multiple concurrent streams
type StreamMultiplexer struct {
	streams      map[string]*Stream
	channels     map[string]chan StreamChunk
	subscribers  map[string]map[string]*StreamSubscriber
	config       MultiplexerConfig
	metrics      *MultiplexerMetrics
	mu           sync.RWMutex
}

// StreamChunk represents a chunk of streaming data
type StreamChunk struct {
	StreamID    string                 `json:"streamId"`
	Sequence    int64                  `json:"sequence"`
	Data        []byte                 `json:"data"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timestamp   time.Time              `json:"timestamp"`
	IsLast      bool                   `json:"isLast"`
	Checksum    string                 `json:"checksum,omitempty"`
	Encoding    string                 `json:"encoding,omitempty"`
}

// StreamSubscriber represents a subscriber to a stream
type StreamSubscriber struct {
	ID       string              `json:"id"`
	Channel  chan StreamChunk    `json:"-"`
	Filter   StreamFilter        `json:"filter"`
	Buffer   []StreamChunk       `json:"buffer"`
	MaxBuffer int               `json:"maxBuffer"`
	LastSeq  int64              `json:"lastSeq"`
	mu       sync.RWMutex
}

// StreamFilter defines filtering criteria for stream data
type StreamFilter struct {
	Types      []StreamType           `json:"types,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	MinProgress *float64              `json:"minProgress,omitempty"`
	MaxProgress *float64              `json:"maxProgress,omitempty"`
}

// BackpressureManager handles backpressure control
type BackpressureManager struct {
	maxStreams          int
	maxBytesPerSecond   int64
	currentBandwidth    int64
	activeStreams       int
	mu                  sync.RWMutex
	config              BackpressureConfig
	throttleStrategies  map[string]ThrottleStrategy
}

// ThrottleStrategy defines how to handle backpressure
type ThrottleStrategy interface {
	ShouldThrottle(ctx context.Context, stream *Stream, metrics *StreamMetrics) bool
	GetDelay(ctx context.Context, stream *Stream) time.Duration
}

// CancellationManager handles stream cancellation
type CancellationManager struct {
	cancellations map[string]context.CancelFunc
	mu           sync.RWMutex
}

// StreamConfig holds streaming configuration
type StreamConfig struct {
	MaxConcurrentStreams int           `json:"maxConcurrentStreams"`
	DefaultChunkSize     int           `json:"defaultChunkSize"`
	MaxChunkSize         int           `json:"maxChunkSize"`
	BufferSize           int           `json:"bufferSize"`
	ProgressInterval     time.Duration `json:"progressInterval"`
	EnableBackpressure   bool          `json:"enableBackpressure"`
	EnableMultiplexing   bool          `json:"enableMultiplexing"`
	EnableMetrics        bool          `json:"enableMetrics"`
	MaxRetries           int           `json:"maxRetries"`
	RetryDelay           time.Duration `json:"retryDelay"`
}

// MultiplexerConfig holds multiplexer configuration
type MultiplexerConfig struct {
	MaxSubscribers     int           `json:"maxSubscribers"`
	SubscriberBuffer   int           `json:"subscriberBuffer"`
	CleanupInterval    time.Duration `json:"cleanupInterval"`
	EnableCompression  bool          `json:"enableCompression"`
	EnableEncryption   bool          `json:"enableEncryption"`
}

// BackpressureConfig holds backpressure configuration
type BackpressureConfig struct {
	MaxBandwidth      int64         `json:"maxBandwidth"`
	ThrottleThreshold float64       `json:"throttleThreshold"`
	RecoveryThreshold float64       `json:"recoveryThreshold"`
	MonitorInterval   time.Duration `json:"monitorInterval"`
}

// StreamMetrics tracks streaming performance
type StreamMetrics struct {
	TotalStreams       int64              `json:"totalStreams"`
	ActiveStreams      int64              `json:"activeStreams"`
	CompletedStreams   int64              `json:"completedStreams"`
	CancelledStreams   int64              `json:"cancelledStreams"`
	ErrorStreams       int64              `json:"errorStreams"`
	BytesStreamed      int64              `json:"bytesStreamed"`
	ChunksProcessed    int64              `json:"chunksProcessed"`
	AverageLatency     float64            `json:"averageLatency"`
	ThroughputBPS      int64              `json:"throughputBPS"`
	BackpressureEvents int64              `json:"backpressureEvents"`
	StreamDurations    map[string]float64 `json:"streamDurations"`
	LastUpdated        time.Time          `json:"lastUpdated"`
	mu                 sync.RWMutex
}

// MultiplexerMetrics tracks multiplexer performance
type MultiplexerMetrics struct {
	TotalSubscribers   int64     `json:"totalSubscribers"`
	ActiveSubscribers  int64     `json:"activeSubscribers"`
	MessagesRouted     int64     `json:"messagesRouted"`
	RoutingLatency     float64   `json:"routingLatency"`
	DroppedMessages    int64     `json:"droppedMessages"`
	LastUpdated        time.Time `json:"lastUpdated"`
	mu                 sync.RWMutex
}

// Built-in throttle strategies
type AdaptiveThrottleStrategy struct{}
type FixedThrottleStrategy struct{ Delay time.Duration }
type BandwidthThrottleStrategy struct{}

// NewStreamManager creates a new stream manager
func NewStreamManager(config StreamConfig) *StreamManager {
	sm := &StreamManager{
		streams:      make(map[string]*Stream),
		config:       config,
		cancellation: &CancellationManager{
			cancellations: make(map[string]context.CancelFunc),
		},
		metrics: &StreamMetrics{
			StreamDurations: make(map[string]float64),
			LastUpdated:     time.Now(),
		},
	}

	// Initialize multiplexer if enabled
	if config.EnableMultiplexing {
		sm.multiplexer = NewStreamMultiplexer(MultiplexerConfig{
			MaxSubscribers:   1000,
			SubscriberBuffer: config.BufferSize,
			CleanupInterval:  time.Minute,
		})
	}

	// Initialize backpressure manager if enabled
	if config.EnableBackpressure {
		sm.backpressure = NewBackpressureManager(BackpressureConfig{
			MaxBandwidth:      1024 * 1024 * 10, // 10 MB/s
			ThrottleThreshold: 0.8,
			RecoveryThreshold: 0.6,
			MonitorInterval:   time.Second,
		})

		// Register built-in throttle strategies
		sm.backpressure.RegisterStrategy("adaptive", &AdaptiveThrottleStrategy{})
		sm.backpressure.RegisterStrategy("fixed", &FixedThrottleStrategy{Delay: time.Millisecond * 100})
		sm.backpressure.RegisterStrategy("bandwidth", &BandwidthThrottleStrategy{})
	}

	return sm
}

// CreateStream creates a new streaming operation
func (sm *StreamManager) CreateStream(ctx context.Context, streamType StreamType, writer io.Writer, metadata map[string]interface{}) (*Stream, error) {
	if !sm.canCreateStream() {
		return nil, fmt.Errorf("maximum concurrent streams reached")
	}

	streamID := sm.generateStreamID()
	ctx, cancelFunc := context.WithCancel(ctx)

	stream := &Stream{
		ID:           streamID,
		Type:         streamType,
		Status:       StreamStatusPending,
		Progress:     0.0,
		StartTime:    time.Now(),
		LastUpdate:   time.Now(),
		Writer:       writer,
		Context:      ctx,
		CancelFunc:   cancelFunc,
		ChunkSize:    sm.config.DefaultChunkSize,
		BytesWritten: 0,
		TotalBytes:   0,
		Metadata:     metadata,
		Subscribers:  []string{},
		BufferSize:   sm.config.BufferSize,
		Priority:     StreamPriorityNormal,
	}

	sm.mu.Lock()
	sm.streams[streamID] = stream
	sm.cancellation.mu.Lock()
	sm.cancellation.cancellations[streamID] = cancelFunc
	sm.cancellation.mu.Unlock()
	sm.mu.Unlock()

	// Update metrics
	if sm.config.EnableMetrics {
		sm.updateStreamMetrics()
	}

	// Register with multiplexer if enabled
	if sm.config.EnableMultiplexing && sm.multiplexer != nil {
		if err := sm.multiplexer.RegisterStream(stream); err != nil {
			log.Warn().Err(err).Str("stream_id", streamID).Msg("Failed to register stream with multiplexer")
		}
	}

	log.Info().
		Str("stream_id", streamID).
		Str("type", string(streamType)).
		Msg("Stream created")

	return stream, nil
}

// WriteChunk writes a chunk of data to a stream
func (sm *StreamManager) WriteChunk(streamID string, data []byte, metadata map[string]interface{}, isLast bool) error {
	sm.mu.RLock()
	stream, exists := sm.streams[streamID]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	// Check if stream is cancelled
	select {
	case <-stream.Context.Done():
		return fmt.Errorf("stream cancelled: %s", streamID)
	default:
	}

	// Apply backpressure if enabled
	if sm.config.EnableBackpressure && sm.backpressure != nil {
		if sm.backpressure.ShouldThrottle(stream.Context, stream, sm.metrics) {
			delay := sm.backpressure.GetThrottleDelay(stream)
			select {
			case <-time.After(delay):
				// Continue after delay
			case <-stream.Context.Done():
				return fmt.Errorf("stream cancelled during throttling: %s", streamID)
			}
		}
	}

	// Create chunk
	var sequence int64
	if stream.ChunkSize > 0 {
		sequence = stream.BytesWritten / int64(stream.ChunkSize)
	}
	
	chunk := StreamChunk{
		StreamID:  streamID,
		Sequence:  sequence,
		Data:      data,
		Metadata:  metadata,
		Timestamp: time.Now(),
		IsLast:    isLast,
		Encoding:  "raw",
	}

	// Write to stream writer
	if stream.Writer != nil {
		if _, err := stream.Writer.Write(data); err != nil {
			sm.setStreamError(streamID, err)
			return fmt.Errorf("failed to write to stream: %w", err)
		}
	}

	// Send to multiplexer if enabled
	if sm.config.EnableMultiplexing && sm.multiplexer != nil {
		if err := sm.multiplexer.RouteChunk(chunk); err != nil {
			log.Warn().Err(err).Str("stream_id", streamID).Msg("Failed to route chunk")
		}
	}

	// Update stream state
	stream.mu.Lock()
	stream.BytesWritten += int64(len(data))
	stream.LastUpdate = time.Now()
	if stream.TotalBytes > 0 {
		stream.Progress = float64(stream.BytesWritten) / float64(stream.TotalBytes)
	}
	if isLast {
		stream.Status = StreamStatusCompleted
	} else {
		stream.Status = StreamStatusActive
	}
	stream.mu.Unlock()

	// Update metrics
	if sm.config.EnableMetrics {
		sm.updateChunkMetrics(len(data))
	}

	// Send progress notification if configured
	if sm.shouldSendProgress(stream) {
		sm.sendProgressNotification(stream)
	}

	log.Debug().
		Str("stream_id", streamID).
		Int("chunk_size", len(data)).
		Bool("is_last", isLast).
		Float64("progress", stream.Progress).
		Msg("Chunk written")

	return nil
}

// GetStream retrieves a stream by ID
func (sm *StreamManager) GetStream(streamID string) (*Stream, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stream, exists := sm.streams[streamID]
	if !exists {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

	return stream, nil
}

// ListStreams returns all active streams
func (sm *StreamManager) ListStreams(filter StreamFilter) []*Stream {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var streams []*Stream
	for _, stream := range sm.streams {
		if sm.matchesFilter(stream, filter) {
			streams = append(streams, stream)
		}
	}

	return streams
}

// CancelStream cancels a streaming operation
func (sm *StreamManager) CancelStream(streamID string) error {
	sm.cancellation.mu.RLock()
	cancelFunc, exists := sm.cancellation.cancellations[streamID]
	sm.cancellation.mu.RUnlock()

	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	cancelFunc()

	sm.mu.Lock()
	if stream, exists := sm.streams[streamID]; exists {
		stream.Status = StreamStatusCancelled
	}
	sm.mu.Unlock()

	// Clean up cancellation tracking
	sm.cancellation.mu.Lock()
	delete(sm.cancellation.cancellations, streamID)
	sm.cancellation.mu.Unlock()

	// Update metrics
	if sm.config.EnableMetrics {
		sm.updateCancellationMetrics()
	}

	log.Info().
		Str("stream_id", streamID).
		Msg("Stream cancelled")

	return nil
}

// PauseStream pauses a streaming operation
func (sm *StreamManager) PauseStream(streamID string) error {
	sm.mu.RLock()
	stream, exists := sm.streams[streamID]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	stream.mu.Lock()
	if stream.Status == StreamStatusActive {
		stream.Status = StreamStatusPaused
	}
	stream.mu.Unlock()

	log.Info().
		Str("stream_id", streamID).
		Msg("Stream paused")

	return nil
}

// ResumeStream resumes a paused streaming operation
func (sm *StreamManager) ResumeStream(streamID string) error {
	sm.mu.RLock()
	stream, exists := sm.streams[streamID]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("stream not found: %s", streamID)
	}

	stream.mu.Lock()
	if stream.Status == StreamStatusPaused {
		stream.Status = StreamStatusActive
	}
	stream.mu.Unlock()

	log.Info().
		Str("stream_id", streamID).
		Msg("Stream resumed")

	return nil
}

// CleanupCompletedStreams removes completed streams
func (sm *StreamManager) CleanupCompletedStreams() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for streamID, stream := range sm.streams {
		if stream.Status == StreamStatusCompleted || 
		   stream.Status == StreamStatusCancelled || 
		   stream.Status == StreamStatusError {
			
			// Calculate duration for metrics
			duration := time.Since(stream.StartTime).Seconds()
			if sm.config.EnableMetrics {
				sm.metrics.mu.Lock()
				sm.metrics.StreamDurations[streamID] = duration
				sm.metrics.mu.Unlock()
			}

			delete(sm.streams, streamID)
			
			// Clean up cancellation tracking
			sm.cancellation.mu.Lock()
			delete(sm.cancellation.cancellations, streamID)
			sm.cancellation.mu.Unlock()

			// Unregister from multiplexer
			if sm.config.EnableMultiplexing && sm.multiplexer != nil {
				sm.multiplexer.UnregisterStream(streamID)
			}

			log.Debug().
				Str("stream_id", streamID).
				Str("status", string(stream.Status)).
				Float64("duration", duration).
				Msg("Stream cleaned up")
		}
	}
}

// GetMetrics returns current streaming metrics
func (sm *StreamManager) GetMetrics() *StreamMetrics {
	if !sm.config.EnableMetrics {
		return nil
	}

	sm.metrics.mu.RLock()
	defer sm.metrics.mu.RUnlock()

	// Create a copy to avoid concurrent access
	metrics := &StreamMetrics{
		TotalStreams:       sm.metrics.TotalStreams,
		ActiveStreams:      sm.metrics.ActiveStreams,
		CompletedStreams:   sm.metrics.CompletedStreams,
		CancelledStreams:   sm.metrics.CancelledStreams,
		ErrorStreams:       sm.metrics.ErrorStreams,
		BytesStreamed:      sm.metrics.BytesStreamed,
		ChunksProcessed:    sm.metrics.ChunksProcessed,
		AverageLatency:     sm.metrics.AverageLatency,
		ThroughputBPS:      sm.metrics.ThroughputBPS,
		BackpressureEvents: sm.metrics.BackpressureEvents,
		StreamDurations:    make(map[string]float64),
		LastUpdated:        sm.metrics.LastUpdated,
	}

	for k, v := range sm.metrics.StreamDurations {
		metrics.StreamDurations[k] = v
	}

	return metrics
}

// Private helper methods

func (sm *StreamManager) generateStreamID() string {
	return fmt.Sprintf("stream_%d", time.Now().UnixNano())
}

func (sm *StreamManager) canCreateStream() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.streams) < sm.config.MaxConcurrentStreams
}

func (sm *StreamManager) matchesFilter(stream *Stream, filter StreamFilter) bool {
	// Check type filter
	if len(filter.Types) > 0 {
		found := false
		for _, t := range filter.Types {
			if stream.Type == t {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check progress filter
	if filter.MinProgress != nil && stream.Progress < *filter.MinProgress {
		return false
	}
	if filter.MaxProgress != nil && stream.Progress > *filter.MaxProgress {
		return false
	}

	// Check metadata filter
	for key, value := range filter.Metadata {
		if streamValue, exists := stream.Metadata[key]; !exists || streamValue != value {
			return false
		}
	}

	return true
}

func (sm *StreamManager) shouldSendProgress(stream *Stream) bool {
	return time.Since(stream.LastUpdate) >= sm.config.ProgressInterval
}

func (sm *StreamManager) sendProgressNotification(stream *Stream) {
	// In a real implementation, this would send a progress notification to the client
	log.Debug().
		Str("stream_id", stream.ID).
		Float64("progress", stream.Progress).
		Int64("bytes_written", stream.BytesWritten).
		Msg("Progress notification")
}

func (sm *StreamManager) setStreamError(streamID string, err error) {
	sm.mu.RLock()
	stream, exists := sm.streams[streamID]
	sm.mu.RUnlock()

	if exists {
		stream.mu.Lock()
		stream.Status = StreamStatusError
		stream.Metadata["error"] = err.Error()
		stream.mu.Unlock()

		// Update metrics
		if sm.config.EnableMetrics {
			sm.metrics.mu.Lock()
			sm.metrics.ErrorStreams++
			sm.metrics.mu.Unlock()
		}
	}
}

func (sm *StreamManager) updateStreamMetrics() {
	if !sm.config.EnableMetrics {
		return
	}

	sm.metrics.mu.Lock()
	defer sm.metrics.mu.Unlock()

	sm.metrics.TotalStreams++
	sm.metrics.ActiveStreams = int64(len(sm.streams))
	sm.metrics.LastUpdated = time.Now()
}

func (sm *StreamManager) updateChunkMetrics(chunkSize int) {
	if !sm.config.EnableMetrics {
		return
	}

	sm.metrics.mu.Lock()
	defer sm.metrics.mu.Unlock()

	sm.metrics.ChunksProcessed++
	sm.metrics.BytesStreamed += int64(chunkSize)
	sm.metrics.LastUpdated = time.Now()

	// Calculate throughput
	if sm.metrics.TotalStreams > 0 {
		duration := time.Since(sm.metrics.LastUpdated).Seconds()
		if duration > 0 {
			sm.metrics.ThroughputBPS = int64(float64(sm.metrics.BytesStreamed) / duration)
		}
	}
}

func (sm *StreamManager) updateCancellationMetrics() {
	if !sm.config.EnableMetrics {
		return
	}

	sm.metrics.mu.Lock()
	sm.metrics.CancelledStreams++
	sm.metrics.LastUpdated = time.Now()
	sm.metrics.mu.Unlock()
}

// StreamMultiplexer implementation

func NewStreamMultiplexer(config MultiplexerConfig) *StreamMultiplexer {
	return &StreamMultiplexer{
		streams:     make(map[string]*Stream),
		channels:    make(map[string]chan StreamChunk),
		subscribers: make(map[string]map[string]*StreamSubscriber),
		config:      config,
		metrics: &MultiplexerMetrics{
			LastUpdated: time.Now(),
		},
	}
}

func (sm *StreamMultiplexer) RegisterStream(stream *Stream) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.streams[stream.ID] = stream
	sm.channels[stream.ID] = make(chan StreamChunk, 100)
	sm.subscribers[stream.ID] = make(map[string]*StreamSubscriber)

	return nil
}

func (sm *StreamMultiplexer) UnregisterStream(streamID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.streams, streamID)
	
	if ch, exists := sm.channels[streamID]; exists {
		close(ch)
		delete(sm.channels, streamID)
	}
	
	delete(sm.subscribers, streamID)
}

func (sm *StreamMultiplexer) RouteChunk(chunk StreamChunk) error {
	sm.mu.RLock()
	subscribers, exists := sm.subscribers[chunk.StreamID]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("stream not registered: %s", chunk.StreamID)
	}

	// Route to all subscribers
	for _, subscriber := range subscribers {
		select {
		case subscriber.Channel <- chunk:
			// Chunk sent successfully
		default:
			// Channel full, drop message
			if sm.config.MaxSubscribers > 0 {
				sm.updateDroppedMetrics()
			}
		}
	}

	sm.updateRoutingMetrics()
	return nil
}

func (sm *StreamMultiplexer) Subscribe(streamID, subscriberID string, filter StreamFilter) (*StreamSubscriber, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.streams[streamID]; !exists {
		return nil, fmt.Errorf("stream not found: %s", streamID)
	}

	subscriber := &StreamSubscriber{
		ID:        subscriberID,
		Channel:   make(chan StreamChunk, sm.config.SubscriberBuffer),
		Filter:    filter,
		Buffer:    make([]StreamChunk, 0),
		MaxBuffer: sm.config.SubscriberBuffer,
		LastSeq:   0,
	}

	if sm.subscribers[streamID] == nil {
		sm.subscribers[streamID] = make(map[string]*StreamSubscriber)
	}

	sm.subscribers[streamID][subscriberID] = subscriber

	sm.updateSubscriberMetrics()
	return subscriber, nil
}

func (sm *StreamMultiplexer) Unsubscribe(streamID, subscriberID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if subscribers, exists := sm.subscribers[streamID]; exists {
		if subscriber, exists := subscribers[subscriberID]; exists {
			close(subscriber.Channel)
			delete(subscribers, subscriberID)
			sm.updateSubscriberMetrics()
			return nil
		}
	}

	return fmt.Errorf("subscriber not found: %s", subscriberID)
}

func (sm *StreamMultiplexer) updateRoutingMetrics() {
	sm.metrics.mu.Lock()
	sm.metrics.MessagesRouted++
	sm.metrics.LastUpdated = time.Now()
	sm.metrics.mu.Unlock()
}

func (sm *StreamMultiplexer) updateDroppedMetrics() {
	sm.metrics.mu.Lock()
	sm.metrics.DroppedMessages++
	sm.metrics.LastUpdated = time.Now()
	sm.metrics.mu.Unlock()
}

func (sm *StreamMultiplexer) updateSubscriberMetrics() {
	sm.metrics.mu.Lock()
	sm.metrics.TotalSubscribers = int64(len(sm.subscribers))
	sm.metrics.LastUpdated = time.Now()
	sm.metrics.mu.Unlock()
}

// BackpressureManager implementation

func NewBackpressureManager(config BackpressureConfig) *BackpressureManager {
	bm := &BackpressureManager{
		maxStreams:         100,
		maxBytesPerSecond:  config.MaxBandwidth,
		currentBandwidth:   0,
		activeStreams:      0,
		config:             config,
		throttleStrategies: make(map[string]ThrottleStrategy),
	}

	return bm
}

func (bm *BackpressureManager) RegisterStrategy(name string, strategy ThrottleStrategy) {
	bm.throttleStrategies[name] = strategy
}

func (bm *BackpressureManager) ShouldThrottle(ctx context.Context, stream *Stream, metrics *StreamMetrics) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	// Check bandwidth usage
	if metrics.ThroughputBPS > int64(float64(bm.maxBytesPerSecond)*bm.config.ThrottleThreshold) {
		return true
	}

	// Check active stream count
	if metrics.ActiveStreams > int64(float64(bm.maxStreams)*bm.config.ThrottleThreshold) {
		return true
	}

	return false
}

func (bm *BackpressureManager) GetThrottleDelay(stream *Stream) time.Duration {
	// Apply adaptive throttle strategy by default
	if strategy, exists := bm.throttleStrategies["adaptive"]; exists {
		return strategy.GetDelay(stream.Context, stream)
	}

	// Fallback to fixed delay
	return time.Millisecond * 100
}

// Built-in throttle strategy implementations

func (ats *AdaptiveThrottleStrategy) ShouldThrottle(ctx context.Context, stream *Stream, metrics *StreamMetrics) bool {
	// Adaptive logic based on stream priority and system load
	if stream.Priority >= StreamPriorityCritical {
		return false // Never throttle critical streams
	}

	if metrics.ActiveStreams > 50 {
		return true
	}

	return false
}

func (ats *AdaptiveThrottleStrategy) GetDelay(ctx context.Context, stream *Stream) time.Duration {
	// Adaptive delay based on stream priority
	switch stream.Priority {
	case StreamPriorityLow:
		return time.Millisecond * 200
	case StreamPriorityNormal:
		return time.Millisecond * 100
	case StreamPriorityHigh:
		return time.Millisecond * 50
	default:
		return time.Millisecond * 10
	}
}

func (fts *FixedThrottleStrategy) ShouldThrottle(ctx context.Context, stream *Stream, metrics *StreamMetrics) bool {
	return metrics.ActiveStreams > 10 // Simple fixed threshold
}

func (fts *FixedThrottleStrategy) GetDelay(ctx context.Context, stream *Stream) time.Duration {
	return fts.Delay
}

func (bts *BandwidthThrottleStrategy) ShouldThrottle(ctx context.Context, stream *Stream, metrics *StreamMetrics) bool {
	// Throttle based on bandwidth usage
	return metrics.ThroughputBPS > 1024*1024*5 // 5 MB/s threshold
}

func (bts *BandwidthThrottleStrategy) GetDelay(ctx context.Context, stream *Stream) time.Duration {
	// Delay proportional to current bandwidth usage
	return time.Millisecond * 50
}