package mcp

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStreamManager_NewStreamManager(t *testing.T) {
	config := StreamConfig{
		MaxConcurrentStreams: 10,
		DefaultChunkSize:     1024,
		MaxChunkSize:         8192,
		BufferSize:           512,
		ProgressInterval:     time.Second,
		EnableBackpressure:   true,
		EnableMultiplexing:   true,
		EnableMetrics:        true,
		MaxRetries:           3,
		RetryDelay:           time.Millisecond * 100,
	}

	sm := NewStreamManager(config)
	assert.NotNil(t, sm)
	assert.Equal(t, config, sm.config)
	assert.NotNil(t, sm.streams)
	assert.NotNil(t, sm.cancellation)
	assert.NotNil(t, sm.metrics)
	assert.NotNil(t, sm.multiplexer)
	assert.NotNil(t, sm.backpressure)
}

func TestStreamManager_CreateStream(t *testing.T) {
	sm := NewStreamManager(StreamConfig{
		MaxConcurrentStreams: 5,
		EnableMetrics:        true,
	})

	ctx := context.Background()
	var buffer bytes.Buffer
	metadata := map[string]interface{}{
		"source": "test",
		"type":   "data",
	}

	stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, metadata)
	assert.NoError(t, err)
	assert.NotNil(t, stream)
	assert.NotEmpty(t, stream.ID)
	assert.Equal(t, StreamTypeDataStream, stream.Type)
	assert.Equal(t, StreamStatusPending, stream.Status)
	assert.Equal(t, metadata, stream.Metadata)
	assert.NotZero(t, stream.StartTime)

	// Verify stream is registered
	sm.mu.RLock()
	_, exists := sm.streams[stream.ID]
	sm.mu.RUnlock()
	assert.True(t, exists)
}

func TestStreamManager_WriteChunk(t *testing.T) {
	sm := NewStreamManager(StreamConfig{
		MaxConcurrentStreams: 5,
		EnableMetrics:        true,
	})

	ctx := context.Background()
	var buffer bytes.Buffer

	stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
	require.NoError(t, err)

	// Write first chunk
	data1 := []byte("Hello, ")
	metadata1 := map[string]interface{}{"seq": 1}
	err = sm.WriteChunk(stream.ID, data1, metadata1, false)
	assert.NoError(t, err)

	// Verify chunk was written to buffer
	assert.Equal(t, string(data1), buffer.String())

	// Verify stream state
	stream, err = sm.GetStream(stream.ID)
	require.NoError(t, err)
	assert.Equal(t, StreamStatusActive, stream.Status)
	assert.Equal(t, int64(len(data1)), stream.BytesWritten)

	// Write final chunk
	data2 := []byte("World!")
	metadata2 := map[string]interface{}{"seq": 2}
	err = sm.WriteChunk(stream.ID, data2, metadata2, true)
	assert.NoError(t, err)

	// Verify final state
	stream, err = sm.GetStream(stream.ID)
	require.NoError(t, err)
	assert.Equal(t, StreamStatusCompleted, stream.Status)
	assert.Equal(t, int64(len(data1)+len(data2)), stream.BytesWritten)
	assert.Equal(t, "Hello, World!", buffer.String())
}

func TestStreamManager_GetStream(t *testing.T) {
	sm := NewStreamManager(StreamConfig{MaxConcurrentStreams: 5})

	ctx := context.Background()
	var buffer bytes.Buffer

	originalStream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
	require.NoError(t, err)

	// Test getting existing stream
	retrievedStream, err := sm.GetStream(originalStream.ID)
	assert.NoError(t, err)
	assert.Equal(t, originalStream.ID, retrievedStream.ID)
	assert.Equal(t, originalStream.Type, retrievedStream.Type)

	// Test getting non-existent stream
	_, err = sm.GetStream("nonexistent-stream")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stream not found")
}

func TestStreamManager_ListStreams(t *testing.T) {
	sm := NewStreamManager(StreamConfig{MaxConcurrentStreams: 10})

	ctx := context.Background()
	var buffer bytes.Buffer

	// Create streams of different types
	streamTypes := []StreamType{
		StreamTypeDataStream,
		StreamTypeFileTransfer,
		StreamTypeLogStreaming,
	}

	var createdStreams []*Stream
	for i, streamType := range streamTypes {
		metadata := map[string]interface{}{"index": i}
		stream, err := sm.CreateStream(ctx, streamType, &buffer, metadata)
		require.NoError(t, err)
		createdStreams = append(createdStreams, stream)
	}

	// Test listing all streams
	allStreams := sm.ListStreams(StreamFilter{})
	assert.Len(t, allStreams, 3)

	// Test filtering by type
	filter := StreamFilter{Types: []StreamType{StreamTypeDataStream}}
	filteredStreams := sm.ListStreams(filter)
	assert.Len(t, filteredStreams, 1)
	assert.Equal(t, StreamTypeDataStream, filteredStreams[0].Type)
}

func TestStreamManager_CancelStream(t *testing.T) {
	sm := NewStreamManager(StreamConfig{MaxConcurrentStreams: 5})

	ctx := context.Background()
	var buffer bytes.Buffer

	stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
	require.NoError(t, err)

	// Cancel the stream
	err = sm.CancelStream(stream.ID)
	assert.NoError(t, err)

	// Verify stream is cancelled
	updatedStream, err := sm.GetStream(stream.ID)
	require.NoError(t, err)
	assert.Equal(t, StreamStatusCancelled, updatedStream.Status)

	// Verify context is cancelled
	select {
	case <-updatedStream.Context.Done():
		// Context is cancelled as expected
	default:
		t.Error("Stream context should be cancelled")
	}
}

func TestStreamManager_PauseResumeStream(t *testing.T) {
	sm := NewStreamManager(StreamConfig{MaxConcurrentStreams: 5})

	ctx := context.Background()
	var buffer bytes.Buffer

	stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
	require.NoError(t, err)

	// Start streaming
	err = sm.WriteChunk(stream.ID, []byte("data"), nil, false)
	require.NoError(t, err)

	// Pause the stream
	err = sm.PauseStream(stream.ID)
	assert.NoError(t, err)

	stream, err = sm.GetStream(stream.ID)
	require.NoError(t, err)
	assert.Equal(t, StreamStatusPaused, stream.Status)

	// Resume the stream
	err = sm.ResumeStream(stream.ID)
	assert.NoError(t, err)

	stream, err = sm.GetStream(stream.ID)
	require.NoError(t, err)
	assert.Equal(t, StreamStatusActive, stream.Status)
}

func TestStreamManager_CleanupCompletedStreams(t *testing.T) {
	sm := NewStreamManager(StreamConfig{
		MaxConcurrentStreams: 5,
		EnableMetrics:        true,
	})

	ctx := context.Background()
	var buffer bytes.Buffer

	// Create and complete a stream
	stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
	require.NoError(t, err)

	err = sm.WriteChunk(stream.ID, []byte("data"), nil, true)
	require.NoError(t, err)

	// Verify stream exists before cleanup
	sm.mu.RLock()
	_, exists := sm.streams[stream.ID]
	sm.mu.RUnlock()
	assert.True(t, exists)

	// Perform cleanup
	sm.CleanupCompletedStreams()

	// Verify stream is removed after cleanup
	sm.mu.RLock()
	_, exists = sm.streams[stream.ID]
	sm.mu.RUnlock()
	assert.False(t, exists)
}

func TestStreamManager_Metrics(t *testing.T) {
	sm := NewStreamManager(StreamConfig{
		MaxConcurrentStreams: 5,
		EnableMetrics:        true,
	})

	ctx := context.Background()
	var buffer bytes.Buffer

	// Create multiple streams
	for i := 0; i < 3; i++ {
		stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
		require.NoError(t, err)

		// Write data to stream
		data := []byte(fmt.Sprintf("stream-%d-data", i))
		err = sm.WriteChunk(stream.ID, data, nil, true)
		require.NoError(t, err)
	}

	metrics := sm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(3), metrics.TotalStreams)
	assert.True(t, metrics.BytesStreamed > 0)
	assert.True(t, metrics.ChunksProcessed > 0)
}

func TestStreamManager_ConcurrentStreams(t *testing.T) {
	sm := NewStreamManager(StreamConfig{
		MaxConcurrentStreams: 10,
		EnableMetrics:        true,
	})

	ctx := context.Background()
	const numStreams = 5
	const chunksPerStream = 10

	var wg sync.WaitGroup
	wg.Add(numStreams)

	// Create concurrent streams
	for i := 0; i < numStreams; i++ {
		go func(streamID int) {
			defer wg.Done()

			var buffer bytes.Buffer
			stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
			assert.NoError(t, err)

			// Write multiple chunks
			for j := 0; j < chunksPerStream; j++ {
				data := []byte(fmt.Sprintf("stream-%d-chunk-%d", streamID, j))
				isLast := j == chunksPerStream-1
				err := sm.WriteChunk(stream.ID, data, nil, isLast)
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()

	// Verify all streams were created
	allStreams := sm.ListStreams(StreamFilter{})
	assert.Len(t, allStreams, numStreams)

	// Check metrics
	metrics := sm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(numStreams), metrics.TotalStreams)
	assert.Equal(t, int64(numStreams*chunksPerStream), metrics.ChunksProcessed)
}

func TestStreamManager_MaxConcurrentStreams(t *testing.T) {
	maxStreams := 2
	sm := NewStreamManager(StreamConfig{
		MaxConcurrentStreams: maxStreams,
	})

	ctx := context.Background()
	var buffer bytes.Buffer

	// Create maximum allowed streams
	var streams []*Stream
	for i := 0; i < maxStreams; i++ {
		stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
		assert.NoError(t, err)
		streams = append(streams, stream)
	}

	// Try to create one more stream - should fail
	_, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum concurrent streams reached")

	// Complete one stream
	err = sm.WriteChunk(streams[0].ID, []byte("data"), nil, true)
	require.NoError(t, err)
	sm.CleanupCompletedStreams()

	// Now should be able to create a new stream
	_, err = sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
	assert.NoError(t, err)
}

func TestStreamMultiplexer_RegisterStream(t *testing.T) {
	config := MultiplexerConfig{
		MaxSubscribers:   10,
		SubscriberBuffer: 100,
		CleanupInterval:  time.Minute,
	}

	multiplexer := NewStreamMultiplexer(config)

	stream := &Stream{
		ID:   "test-stream",
		Type: StreamTypeDataStream,
	}

	err := multiplexer.RegisterStream(stream)
	assert.NoError(t, err)

	// Verify stream is registered
	multiplexer.mu.RLock()
	_, exists := multiplexer.streams[stream.ID]
	_, channelExists := multiplexer.channels[stream.ID]
	_, subscribersExist := multiplexer.subscribers[stream.ID]
	multiplexer.mu.RUnlock()

	assert.True(t, exists)
	assert.True(t, channelExists)
	assert.True(t, subscribersExist)
}

func TestStreamMultiplexer_Subscribe(t *testing.T) {
	multiplexer := NewStreamMultiplexer(MultiplexerConfig{
		MaxSubscribers:   10,
		SubscriberBuffer: 100,
	})

	stream := &Stream{
		ID:   "test-stream",
		Type: StreamTypeDataStream,
	}

	err := multiplexer.RegisterStream(stream)
	require.NoError(t, err)

	filter := StreamFilter{
		Types: []StreamType{StreamTypeDataStream},
	}

	subscriber, err := multiplexer.Subscribe(stream.ID, "subscriber-1", filter)
	assert.NoError(t, err)
	assert.NotNil(t, subscriber)
	assert.Equal(t, "subscriber-1", subscriber.ID)
	assert.Equal(t, filter, subscriber.Filter)
	assert.NotNil(t, subscriber.Channel)
}

func TestStreamMultiplexer_RouteChunk(t *testing.T) {
	multiplexer := NewStreamMultiplexer(MultiplexerConfig{
		MaxSubscribers:   10,
		SubscriberBuffer: 100,
	})

	stream := &Stream{
		ID:   "test-stream",
		Type: StreamTypeDataStream,
	}

	err := multiplexer.RegisterStream(stream)
	require.NoError(t, err)

	subscriber, err := multiplexer.Subscribe(stream.ID, "subscriber-1", StreamFilter{})
	require.NoError(t, err)

	chunk := StreamChunk{
		StreamID:  stream.ID,
		Sequence:  1,
		Data:      []byte("test data"),
		Timestamp: time.Now(),
		IsLast:    false,
	}

	err = multiplexer.RouteChunk(chunk)
	assert.NoError(t, err)

	// Verify chunk was routed to subscriber
	select {
	case receivedChunk := <-subscriber.Channel:
		assert.Equal(t, chunk.StreamID, receivedChunk.StreamID)
		assert.Equal(t, chunk.Data, receivedChunk.Data)
	case <-time.After(time.Second):
		t.Error("Chunk not received by subscriber")
	}
}

func TestBackpressureManager_ShouldThrottle(t *testing.T) {
	config := BackpressureConfig{
		MaxBandwidth:      1024 * 1024, // 1MB/s
		ThrottleThreshold: 0.8,
		RecoveryThreshold: 0.6,
	}

	bm := NewBackpressureManager(config)

	stream := &Stream{
		ID:       "test-stream",
		Priority: StreamPriorityNormal,
	}

	metrics := &StreamMetrics{
		ThroughputBPS: 1024 * 800, // Below threshold
		ActiveStreams: 10,
	}

	ctx := context.Background()

	// Should not throttle under normal conditions
	shouldThrottle := bm.ShouldThrottle(ctx, stream, metrics)
	assert.False(t, shouldThrottle)

	// Should throttle when bandwidth exceeds threshold
	metrics.ThroughputBPS = 1024 * 900 // Above threshold
	shouldThrottle = bm.ShouldThrottle(ctx, stream, metrics)
	assert.True(t, shouldThrottle)
}

func TestThrottleStrategies(t *testing.T) {
	ctx := context.Background()

	// Test AdaptiveThrottleStrategy
	adaptive := &AdaptiveThrottleStrategy{}
	
	lowPriorityStream := &Stream{Priority: StreamPriorityLow}
	delay := adaptive.GetDelay(ctx, lowPriorityStream)
	assert.Equal(t, time.Millisecond*200, delay)

	highPriorityStream := &Stream{Priority: StreamPriorityHigh}
	delay = adaptive.GetDelay(ctx, highPriorityStream)
	assert.Equal(t, time.Millisecond*50, delay)

	criticalStream := &Stream{Priority: StreamPriorityCritical}
	delay = adaptive.GetDelay(ctx, criticalStream)
	assert.Equal(t, time.Millisecond*10, delay)

	// Test FixedThrottleStrategy
	fixedDelay := time.Millisecond * 150
	fixed := &FixedThrottleStrategy{Delay: fixedDelay}
	delay = fixed.GetDelay(ctx, lowPriorityStream)
	assert.Equal(t, fixedDelay, delay)

	// Test BandwidthThrottleStrategy
	bandwidth := &BandwidthThrottleStrategy{}
	metrics := &StreamMetrics{ThroughputBPS: 1024 * 1024 * 6} // 6 MB/s
	shouldThrottle := bandwidth.ShouldThrottle(ctx, lowPriorityStream, metrics)
	assert.True(t, shouldThrottle)

	delay = bandwidth.GetDelay(ctx, lowPriorityStream)
	assert.Equal(t, time.Millisecond*50, delay)
}

func TestStreamManager_WriteToNonExistentStream(t *testing.T) {
	sm := NewStreamManager(StreamConfig{MaxConcurrentStreams: 5})

	err := sm.WriteChunk("nonexistent-stream", []byte("data"), nil, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stream not found")
}

func TestStreamManager_WriteToCancelledStream(t *testing.T) {
	sm := NewStreamManager(StreamConfig{MaxConcurrentStreams: 5})

	ctx := context.Background()
	var buffer bytes.Buffer

	stream, err := sm.CreateStream(ctx, StreamTypeDataStream, &buffer, nil)
	require.NoError(t, err)

	// Cancel the stream
	err = sm.CancelStream(stream.ID)
	require.NoError(t, err)

	// Try to write to cancelled stream
	err = sm.WriteChunk(stream.ID, []byte("data"), nil, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stream cancelled")
}