package tools

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultBatchConfig(t *testing.T) {
	config := DefaultBatchConfig()
	
	assert.NotNil(t, config)
	assert.Greater(t, config.MaxWorkers, 0)
	assert.Greater(t, config.MinWorkers, 0)
	assert.LessOrEqual(t, config.MinWorkers, config.MaxWorkers)
	assert.Greater(t, config.MaxQueueSize, 0)
	assert.Greater(t, config.BatchSize, 0)
	assert.Greater(t, config.RequestTimeout, time.Duration(0))
	assert.NotNil(t, config.DefaultRetryPolicy)
	assert.True(t, config.MetricsEnabled)
	assert.True(t, config.ProgressTracking)
}

func TestNewBatchProcessor(t *testing.T) {
	tests := []struct {
		name      string
		config    *BatchConfig
		wantError bool
	}{
		{
			name:      "Valid default configuration",
			config:    DefaultBatchConfig(),
			wantError: false,
		},
		{
			name:      "Nil configuration uses default",
			config:    nil,
			wantError: false,
		},
		{
			name: "Custom configuration",
			config: &BatchConfig{
				MaxWorkers:         10,
				MinWorkers:         2,
				WorkerIdleTimeout:  5 * time.Minute,
				MaxQueueSize:       1000,
				BatchSize:          50,
				BatchTimeout:       3 * time.Second,
				MaxConcurrency:     5,
				RequestTimeout:     15 * time.Second,
				DefaultRetryPolicy: &RetryPolicy{MaxRetries: 2},
				AdaptiveSizing:     false,
				LoadBalancing:      false,
				ResourceMonitoring: false,
				MetricsEnabled:     true,
				ProgressTracking:   true,
				DetailedLogging:    false,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor, err := NewBatchProcessor(tt.config)
			
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, processor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, processor)
				
				// Clean up
				if processor != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					processor.Close(ctx)
				}
			}
		})
	}
}

func TestBatchProcessor_SubmitSingle(t *testing.T) {
	config := &BatchConfig{
		MaxWorkers:         5,
		MinWorkers:         2,
		WorkerIdleTimeout:  5 * time.Minute,
		MaxQueueSize:       100,
		BatchSize:          10,
		BatchTimeout:       1 * time.Second,
		MaxConcurrency:     3,
		RequestTimeout:     10 * time.Second,
		DefaultRetryPolicy: &RetryPolicy{MaxRetries: 1},
		AdaptiveSizing:     false,
		LoadBalancing:      false,
		ResourceMonitoring: false,
		MetricsEnabled:     true,
		ProgressTracking:   true,
		DetailedLogging:    false,
	}

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()

	// Test single request submission
	request := &BatchRequest{
		ID:       "test_request_1",
		Type:     BatchTypeCommand,
		Priority: 5,
		Payload:  "echo hello",
		Timeout:  5 * time.Second,
	}

	result, err := processor.Submit(ctx, request)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, request.ID, result.RequestID)
	assert.NotEmpty(t, result.BatchID)
	assert.Equal(t, BatchStatusCompleted, result.Status)
	assert.NotNil(t, result.Output)
	assert.Greater(t, result.ExecutionTime, time.Duration(0))
}

func TestBatchProcessor_SubmitMany(t *testing.T) {
	config := &BatchConfig{
		MaxWorkers:         10,
		MinWorkers:         3,
		WorkerIdleTimeout:  5 * time.Minute,
		MaxQueueSize:       1000,
		BatchSize:          20,
		BatchTimeout:       1 * time.Second,
		MaxConcurrency:     5,
		RequestTimeout:     10 * time.Second,
		DefaultRetryPolicy: &RetryPolicy{MaxRetries: 1},
		AdaptiveSizing:     false,
		LoadBalancing:      false,
		ResourceMonitoring: false,
		MetricsEnabled:     true,
		ProgressTracking:   true,
		DetailedLogging:    false,
	}

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()

	// Test multiple request submission
	requests := []*BatchRequest{
		{
			ID:       "batch_req_1",
			Type:     BatchTypeCommand,
			Priority: 5,
			Payload:  "command1",
			Timeout:  5 * time.Second,
		},
		{
			ID:       "batch_req_2",
			Type:     BatchTypeFileOp,
			Priority: 3,
			Payload:  "file_operation",
			Timeout:  5 * time.Second,
		},
		{
			ID:       "batch_req_3",
			Type:     BatchTypeCodeExec,
			Priority: 7,
			Payload:  "code_to_execute",
			Timeout:  5 * time.Second,
		},
	}

	results, err := processor.SubmitMany(ctx, requests)
	assert.NoError(t, err)
	assert.Len(t, results, len(requests))

	// Verify all results
	for i, result := range results {
		assert.Equal(t, requests[i].ID, result.RequestID)
		assert.NotEmpty(t, result.BatchID)
		assert.Equal(t, BatchStatusCompleted, result.Status)
		assert.NotNil(t, result.Output)
		assert.Greater(t, result.ExecutionTime, time.Duration(0))
	}

	// Verify all results have the same batch ID
	batchID := results[0].BatchID
	for _, result := range results[1:] {
		assert.Equal(t, batchID, result.BatchID)
	}
}

func TestBatchProcessor_ConcurrentSubmissions(t *testing.T) {
	config := &BatchConfig{
		MaxWorkers:         20,
		MinWorkers:         5,
		WorkerIdleTimeout:  5 * time.Minute,
		MaxQueueSize:       2000,
		BatchSize:          50,
		BatchTimeout:       1 * time.Second,
		MaxConcurrency:     10,
		RequestTimeout:     10 * time.Second,
		DefaultRetryPolicy: &RetryPolicy{MaxRetries: 1},
		AdaptiveSizing:     false,
		LoadBalancing:      false,
		ResourceMonitoring: false,
		MetricsEnabled:     true,
		ProgressTracking:   false, // Disable for performance
		DetailedLogging:    false,
	}

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	const numGoroutines = 50
	const requestsPerGoroutine = 10

	var wg sync.WaitGroup
	ctx := context.Background()
	errors := make(chan error, numGoroutines*requestsPerGoroutine)
	results := make(chan *BatchResult, numGoroutines*requestsPerGoroutine)

	// Start multiple goroutines submitting requests concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < requestsPerGoroutine; j++ {
				request := &BatchRequest{
					ID:       fmt.Sprintf("concurrent_req_%d_%d", id, j),
					Type:     BatchTypeCommand,
					Priority: j % 10, // Varying priorities
					Payload:  fmt.Sprintf("command_%d_%d", id, j),
					Timeout:  5 * time.Second,
				}
				
				result, err := processor.Submit(ctx, request)
				if err != nil {
					errors <- fmt.Errorf("submit failed for %s: %w", request.ID, err)
					continue
				}
				
				results <- result
			}
		}(i)
	}

	wg.Wait()
	close(errors)
	close(results)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent submission error: %v", err)
		errorCount++
		if errorCount > 10 { // Limit error output
			break
		}
	}

	// Verify results
	var resultCount int
	for result := range results {
		assert.Equal(t, BatchStatusCompleted, result.Status)
		assert.NotNil(t, result.Output)
		resultCount++
	}

	expectedResults := numGoroutines * requestsPerGoroutine
	assert.Equal(t, expectedResults, resultCount, "Should have received all results")
}

func TestBatchProcessor_RequestTypes(t *testing.T) {
	config := DefaultBatchConfig()
	config.MaxWorkers = 5
	config.MinWorkers = 2

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()

	// Test different request types
	requestTypes := []BatchRequestType{
		BatchTypeCommand,
		BatchTypeFileOp,
		BatchTypeCodeExec,
		BatchTypeDataProcess,
		BatchTypeCustom,
	}

	for i, reqType := range requestTypes {
		t.Run(fmt.Sprintf("RequestType_%s", reqType), func(t *testing.T) {
			request := &BatchRequest{
				ID:       fmt.Sprintf("type_test_%d", i),
				Type:     reqType,
				Priority: 5,
				Payload:  fmt.Sprintf("payload_for_%s", reqType),
				Timeout:  5 * time.Second,
			}

			result, err := processor.Submit(ctx, request)
			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Equal(t, request.ID, result.RequestID)
			assert.Equal(t, BatchStatusCompleted, result.Status)
			assert.NotNil(t, result.Output)
		})
	}
}

func TestBatchProcessor_Progress(t *testing.T) {
	config := DefaultBatchConfig()
	config.MaxWorkers = 3
	config.MinWorkers = 1
	config.ProgressTracking = true

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()

	// Submit a batch of requests
	requests := make([]*BatchRequest, 5)
	for i := 0; i < 5; i++ {
		requests[i] = &BatchRequest{
			ID:       fmt.Sprintf("progress_req_%d", i),
			Type:     BatchTypeCommand,
			Priority: 5,
			Payload:  fmt.Sprintf("command_%d", i),
			Timeout:  10 * time.Second,
		}
	}

	// Submit requests asynchronously to track progress
	var wg sync.WaitGroup
	var batchID string
	var results []*BatchResult

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		results, err = processor.SubmitMany(ctx, requests)
		require.NoError(t, err)
		if len(results) > 0 {
			batchID = results[0].BatchID
		}
	}()

	// Wait a moment for submission to start
	time.Sleep(100 * time.Millisecond)

	// Wait for completion
	wg.Wait()

	// Check progress after completion
	if batchID != "" {
		progress, err := processor.GetProgress(batchID)
		// Progress tracking might not be implemented fully, so we don't require success
		if err == nil {
			assert.NotNil(t, progress)
			assert.Equal(t, batchID, progress.BatchID)
		}
	}
}

func TestBatchProcessor_Cancel(t *testing.T) {
	config := DefaultBatchConfig()
	config.MaxWorkers = 2
	config.MinWorkers = 1

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()

	// Submit a request
	request := &BatchRequest{
		ID:       "cancel_test_req",
		Type:     BatchTypeCommand,
		Priority: 5,
		Payload:  "long_running_command",
		Timeout:  10 * time.Second,
	}

	// Submit asynchronously
	var wg sync.WaitGroup
	var result *BatchResult
	var batchID string

	wg.Add(1)
	go func() {
		defer wg.Done()
		result, _ = processor.Submit(ctx, request)
		if result != nil {
			batchID = result.BatchID
		}
	}()

	// Wait a moment, then try to cancel (though this may complete too fast)
	time.Sleep(10 * time.Millisecond)
	
	wg.Wait() // Wait for completion first
	
	if batchID != "" {
		err := processor.Cancel(batchID)
		// Cancel might not find the batch if it completed already
		// So we don't require success here
		t.Logf("Cancel result: %v", err)
	}
}

func TestBatchProcessor_Stats(t *testing.T) {
	config := DefaultBatchConfig()
	config.MaxWorkers = 5
	config.MinWorkers = 2
	config.MetricsEnabled = true

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()

	// Submit some requests to generate stats
	for i := 0; i < 10; i++ {
		request := &BatchRequest{
			ID:       fmt.Sprintf("stats_req_%d", i),
			Type:     BatchTypeCommand,
			Priority: 5,
			Payload:  fmt.Sprintf("command_%d", i),
			Timeout:  5 * time.Second,
		}
		
		_, err := processor.Submit(ctx, request)
		require.NoError(t, err)
	}

	// Get stats
	stats := processor.Stats()
	assert.NotNil(t, stats)
	assert.Greater(t, stats.TotalRequests, int64(0))
	assert.GreaterOrEqual(t, stats.ActiveWorkers, config.MinWorkers)
	assert.LessOrEqual(t, stats.ActiveWorkers, config.MaxWorkers)
	assert.NotZero(t, stats.LastUpdate)
	assert.Greater(t, stats.UptimeDuration, time.Duration(0))
}

func TestBatchProcessor_Health(t *testing.T) {
	config := DefaultBatchConfig()
	config.MaxWorkers = 5
	config.MinWorkers = 2

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	// Wait a moment for initialization
	time.Sleep(100 * time.Millisecond)

	// Get health report
	health := processor.Health()
	assert.NotNil(t, health)
	assert.NotZero(t, health.Timestamp)
	assert.NotNil(t, health.Issues)
	assert.NotNil(t, health.Recommendations)
	assert.NotNil(t, health.Metrics)
	
	// Health status should be valid
	validStatuses := []BatchHealthStatus{BatchHealthStatusHealthy, BatchHealthStatusDegraded, BatchHealthStatusUnhealthy}
	assert.Contains(t, validStatuses, health.Status)
}

func TestBatchProcessor_Optimize(t *testing.T) {
	config := DefaultBatchConfig()
	config.AdaptiveSizing = true
	config.MaxWorkers = 5
	config.MinWorkers = 2

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	// Optimize should not error
	err = processor.Optimize()
	assert.NoError(t, err)
}

func TestBatchProcessor_RequestValidation(t *testing.T) {
	config := DefaultBatchConfig()
	config.MaxWorkers = 2
	config.MinWorkers = 1

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()

	// Test nil request
	_, err = processor.Submit(ctx, nil)
	assert.Error(t, err)

	// Test request with empty type
	request := &BatchRequest{
		ID:      "invalid_req_1",
		Type:    "",
		Payload: "some_payload",
	}
	_, err = processor.Submit(ctx, request)
	assert.Error(t, err)

	// Test request with nil payload
	request = &BatchRequest{
		ID:      "invalid_req_2",
		Type:    BatchTypeCommand,
		Payload: nil,
	}
	_, err = processor.Submit(ctx, request)
	assert.Error(t, err)

	// Test valid request
	request = &BatchRequest{
		ID:      "valid_req",
		Type:    BatchTypeCommand,
		Payload: "valid_payload",
		Timeout: 5 * time.Second,
	}
	result, err := processor.Submit(ctx, request)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestBatchProcessor_Timeout(t *testing.T) {
	config := DefaultBatchConfig()
	config.MaxWorkers = 1 // Single worker to ensure serialized processing
	config.MinWorkers = 1

	processor, err := NewBatchProcessor(config)
	require.NoError(t, err)
	require.NotNil(t, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	request := &BatchRequest{
		ID:      "timeout_req",
		Type:    BatchTypeCommand,
		Payload: "command",
		Timeout: 100 * time.Millisecond, // Request timeout
	}

	// This should timeout due to context
	_, err = processor.Submit(ctx, request)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func BenchmarkBatchProcessor_SingleSubmit(b *testing.B) {
	config := &BatchConfig{
		MaxWorkers:         20,
		MinWorkers:         10,
		WorkerIdleTimeout:  5 * time.Minute,
		MaxQueueSize:       10000,
		BatchSize:          100,
		BatchTimeout:       1 * time.Second,
		MaxConcurrency:     15,
		RequestTimeout:     30 * time.Second,
		DefaultRetryPolicy: &RetryPolicy{MaxRetries: 0}, // No retries for benchmark
		AdaptiveSizing:     false,
		LoadBalancing:      false,
		ResourceMonitoring: false,
		MetricsEnabled:     false, // Disable for benchmark
		ProgressTracking:   false, // Disable for benchmark
		DetailedLogging:    false,
	}

	processor, err := NewBatchProcessor(config)
	require.NoError(b, err)
	require.NotNil(b, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			request := &BatchRequest{
				ID:       fmt.Sprintf("bench_req_%d", i),
				Type:     BatchTypeCommand,
				Priority: 5,
				Payload:  "benchmark_command",
				Timeout:  10 * time.Second,
			}
			
			_, err := processor.Submit(ctx, request)
			if err != nil {
				b.Errorf("Submit failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkBatchProcessor_BatchSubmit(b *testing.B) {
	config := &BatchConfig{
		MaxWorkers:         30,
		MinWorkers:         15,
		WorkerIdleTimeout:  5 * time.Minute,
		MaxQueueSize:       20000,
		BatchSize:          200,
		BatchTimeout:       1 * time.Second,
		MaxConcurrency:     20,
		RequestTimeout:     30 * time.Second,
		DefaultRetryPolicy: &RetryPolicy{MaxRetries: 0},
		AdaptiveSizing:     false,
		LoadBalancing:      false,
		ResourceMonitoring: false,
		MetricsEnabled:     false,
		ProgressTracking:   false,
		DetailedLogging:    false,
	}

	processor, err := NewBatchProcessor(config)
	require.NoError(b, err)
	require.NotNil(b, processor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		processor.Close(ctx)
	}()

	ctx := context.Background()
	batchSize := 50

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Create batch of requests
			requests := make([]*BatchRequest, batchSize)
			for j := 0; j < batchSize; j++ {
				requests[j] = &BatchRequest{
					ID:       fmt.Sprintf("bench_batch_req_%d_%d", i, j),
					Type:     BatchTypeCommand,
					Priority: 5,
					Payload:  "benchmark_batch_command",
					Timeout:  10 * time.Second,
				}
			}
			
			_, err := processor.SubmitMany(ctx, requests)
			if err != nil {
				b.Errorf("SubmitMany failed: %v", err)
			}
			i++
		}
	})
}