package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func TestDefaultTracingConfig(t *testing.T) {
	config := DefaultTracingConfig()
	
	assert.True(t, config.Enabled)
	assert.Equal(t, "sandboxrunner", config.ServiceName)
	assert.Equal(t, "1.0.0", config.ServiceVersion)
	assert.Equal(t, "development", config.Environment)
	assert.Equal(t, TracingExporterJaeger, config.Exporter)
	assert.Equal(t, 1.0, config.SamplingRatio)
	assert.NotNil(t, config.JaegerConfig)
	assert.NotNil(t, config.OTLPConfig)
	assert.NotEmpty(t, config.SpanProcessors)
}

func TestNewTracingManager_Disabled(t *testing.T) {
	config := DefaultTracingConfig()
	config.Enabled = false
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	assert.NotNil(t, tm)
	assert.Equal(t, config, tm.config)
	assert.Nil(t, tm.tracer)
}

func TestNewTracingManager_StdoutExporter(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	assert.NotNil(t, tm)
	assert.NotNil(t, tm.tracer)
	assert.NotNil(t, tm.tracerProvider)
	assert.NotNil(t, tm.propagator)
}

func TestNewTracingManager_InvalidExporter(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporter("invalid")
	
	_, err := NewTracingManager(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported exporter type")
}

func TestTracingManager_StartSpan(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	spanCtx, span := tm.StartSpan(ctx, "test_operation")
	
	assert.NotEqual(t, ctx, spanCtx)
	assert.NotNil(t, span)
	assert.True(t, span.IsRecording())
	
	span.End()
}

func TestTracingManager_StartSpan_Disabled(t *testing.T) {
	config := DefaultTracingConfig()
	config.Enabled = false
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	spanCtx, span := tm.StartSpan(ctx, "test_operation")
	
	assert.Equal(t, ctx, spanCtx)
	assert.NotNil(t, span) // Should return NoOp span
	assert.False(t, span.IsRecording())
}

func TestTracingManager_SpanOperations(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	ctx, span := tm.StartSpan(ctx, "test_operation",
		trace.WithAttributes(
			attribute.String("test.key", "test.value"),
			attribute.Int("test.number", 42),
		),
	)
	defer span.End()
	
	// Test RecordError
	testErr := assert.AnError
	tm.RecordError(ctx, testErr)
	
	// Test AddEvent
	tm.AddEvent(ctx, "test_event",
		trace.WithAttributes(
			attribute.String("event.type", "test"),
		),
	)
	
	// Test SetAttributes
	tm.SetAttributes(ctx,
		attribute.String("additional.key", "additional.value"),
	)
	
	// Test SetStatus
	tm.SetStatus(ctx, codes.Ok, "Operation completed successfully")
	
	// These operations should not panic or error
	assert.True(t, span.IsRecording())
}

func TestTracingManager_GetSpanContext(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	ctx, span := tm.StartSpan(ctx, "test_operation")
	defer span.End()
	
	spanCtx := tm.GetSpanContext(ctx)
	assert.NotNil(t, spanCtx)
	assert.NotEmpty(t, spanCtx.TraceID)
	assert.NotEmpty(t, spanCtx.SpanID)
}

func TestTracingManager_GetSpanContext_NoSpan(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	spanCtx := tm.GetSpanContext(ctx)
	assert.Nil(t, spanCtx)
}

func TestTracingManager_TraceOperation(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	executed := false
	
	// Test successful operation
	err = tm.TraceOperation(ctx, "test_operation", func(ctx context.Context) error {
		executed = true
		span := trace.SpanFromContext(ctx)
		assert.True(t, span.IsRecording())
		return nil
	}, attribute.String("test.key", "test.value"))
	
	assert.NoError(t, err)
	assert.True(t, executed)
	
	// Test failed operation
	testErr := assert.AnError
	err = tm.TraceOperation(ctx, "failing_operation", func(ctx context.Context) error {
		return testErr
	})
	
	assert.Error(t, err)
	assert.Equal(t, testErr, err)
}

func TestTracingManager_TraceOperation_Disabled(t *testing.T) {
	config := DefaultTracingConfig()
	config.Enabled = false
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	executed := false
	
	err = tm.TraceOperation(ctx, "test_operation", func(ctx context.Context) error {
		executed = true
		return nil
	})
	
	assert.NoError(t, err)
	assert.True(t, executed)
}

func TestTracingManager_TraceAsync(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	ctx, span := tm.StartSpan(ctx, "parent_operation")
	defer span.End()
	
	executed := make(chan bool, 1)
	
	tm.TraceAsync(ctx, "async_operation", func(ctx context.Context) {
		span := trace.SpanFromContext(ctx)
		assert.True(t, span.IsRecording())
		executed <- true
	}, attribute.String("async.key", "async.value"))
	
	// Wait for async operation to complete
	select {
	case <-executed:
		// Success
	case <-time.After(time.Second):
		t.Fatal("Async operation did not complete")
	}
}

func TestTracingManager_CreateSpanFromRemoteContext(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	traceID := "12345678901234567890123456789012"
	spanID := "1234567890123456"
	
	spanCtx, span, err := tm.CreateSpanFromRemoteContext(
		ctx, traceID, spanID, "remote_operation",
		attribute.String("remote.key", "remote.value"),
	)
	
	require.NoError(t, err)
	assert.NotEqual(t, ctx, spanCtx)
	assert.NotNil(t, span)
	assert.True(t, span.IsRecording())
	
	span.End()
}

func TestTracingManager_CreateSpanFromRemoteContext_Disabled(t *testing.T) {
	config := DefaultTracingConfig()
	config.Enabled = false
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	traceID := "12345678901234567890123456789012"
	spanID := "1234567890123456"
	
	_, _, err = tm.CreateSpanFromRemoteContext(ctx, traceID, spanID, "remote_operation")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tracer not initialized")
}

func TestTracingManager_CorrelationID(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	ctx, span := tm.StartSpan(ctx, "test_operation")
	defer span.End()
	
	correlationID := tm.CorrelationIDFromContext(ctx)
	assert.NotEmpty(t, correlationID)
	
	// Test with correlation ID
	newCtx := tm.WithCorrelationID(ctx, "test-correlation-id")
	assert.NotNil(t, newCtx)
}

func TestTracingManager_GetTraceAnalytics(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	analytics, err := tm.GetTraceAnalytics(time.Hour)
	require.NoError(t, err)
	assert.NotNil(t, analytics)
	assert.Greater(t, analytics.TotalSpans, int64(0))
	assert.GreaterOrEqual(t, analytics.ErrorRate, 0.0)
	assert.NotEmpty(t, analytics.TopOperations)
}

func TestTracingManager_HTTPMiddleware(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	middleware := tm.NewHTTPMiddleware()
	assert.NotNil(t, middleware)
	assert.Equal(t, tm.tracer, middleware.tracer)
	assert.Equal(t, tm.config, middleware.config)
}

func TestHTTPMiddleware_Handler(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	middleware := tm.NewHTTPMiddleware()
	
	// Create test handler
	called := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		
		// Verify span is in context
		span := trace.SpanFromContext(r.Context())
		assert.True(t, span.IsRecording())
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// Wrap with middleware
	wrappedHandler := middleware.Handler(testHandler)
	
	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	
	// Execute request
	wrappedHandler.ServeHTTP(w, req)
	
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestHTTPMiddleware_Handler_Disabled(t *testing.T) {
	config := DefaultTracingConfig()
	config.Enabled = false
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	middleware := tm.NewHTTPMiddleware()
	
	// Create test handler
	called := false
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	
	// Wrap with middleware
	wrappedHandler := middleware.Handler(testHandler)
	
	// Create test request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	
	// Execute request
	wrappedHandler.ServeHTTP(w, req)
	
	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHTTPMiddleware_StatusCodes(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	middleware := tm.NewHTTPMiddleware()
	
	tests := []struct {
		name       string
		statusCode int
	}{
		{"success", http.StatusOK},
		{"not_found", http.StatusNotFound},
		{"server_error", http.StatusInternalServerError},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.statusCode)
			})
			
			wrappedHandler := middleware.Handler(testHandler)
			
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			
			wrappedHandler.ServeHTTP(w, req)
			
			assert.Equal(t, test.statusCode, w.Code)
		})
	}
}

func TestWrappedResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	wrapped := &wrappedResponseWriter{
		ResponseWriter: w,
		statusCode:     200,
	}
	
	// Test WriteHeader
	wrapped.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, wrapped.statusCode)
	assert.Equal(t, http.StatusNotFound, w.Code)
	
	// Test Write
	wrapped.Write([]byte("test"))
	assert.Equal(t, "test", w.Body.String())
}

func TestTracingManager_Shutdown(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = tm.Shutdown(ctx)
	assert.NoError(t, err)
}

func TestTracingManager_Shutdown_Disabled(t *testing.T) {
	config := DefaultTracingConfig()
	config.Enabled = false
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	
	ctx := context.Background()
	err = tm.Shutdown(ctx)
	assert.NoError(t, err)
}

// Test configuration validation

func TestTracingConfig_SpanProcessors(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	config.SpanProcessors = []SpanProcessorConfig{
		{
			Type:          "batch",
			MaxQueueSize:  1000,
			MaxPacketSize: 100,
			BatchTimeout:  time.Second,
			ExportTimeout: 10 * time.Second,
		},
		{
			Type: "simple",
		},
	}
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	assert.NotNil(t, tm)
	assert.Len(t, tm.spanProcessors, 2) // One for each processor config
}

func TestTracingConfig_InvalidSpanProcessor(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	config.SpanProcessors = []SpanProcessorConfig{
		{
			Type: "invalid",
		},
	}
	
	_, err := NewTracingManager(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported span processor type")
}

func TestTracingConfig_CustomAttributes(t *testing.T) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	config.CustomAttributes = map[string]string{
		"environment": "test",
		"team":        "platform",
		"version":     "1.2.3",
	}
	
	tm, err := NewTracingManager(config)
	require.NoError(t, err)
	assert.NotNil(t, tm)
}

func TestTracingConfig_SamplingRatio(t *testing.T) {
	tests := []struct {
		name          string
		samplingRatio float64
	}{
		{"no_sampling", 0.0},
		{"partial_sampling", 0.5},
		{"full_sampling", 1.0},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultTracingConfig()
			config.Exporter = TracingExporterStdout
			config.SamplingRatio = test.samplingRatio
			
			tm, err := NewTracingManager(config)
			require.NoError(t, err)
			assert.NotNil(t, tm)
		})
	}
}

// Benchmark tests

func BenchmarkTracingManager_StartSpan(b *testing.B) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(b, err)
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, span := tm.StartSpan(ctx, "benchmark_operation")
		span.End()
	}
}

func BenchmarkTracingManager_TraceOperation(b *testing.B) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(b, err)
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := tm.TraceOperation(ctx, "benchmark_operation", func(ctx context.Context) error {
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHTTPMiddleware_Handler(b *testing.B) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(b, err)
	
	middleware := tm.NewHTTPMiddleware()
	
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	
	wrappedHandler := middleware.Handler(handler)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)
	}
}

func BenchmarkTracingManager_SetAttributes(b *testing.B) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(b, err)
	
	ctx := context.Background()
	ctx, span := tm.StartSpan(ctx, "benchmark_operation")
	defer span.End()
	
	attrs := []attribute.KeyValue{
		attribute.String("key1", "value1"),
		attribute.Int("key2", 42),
		attribute.Bool("key3", true),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.SetAttributes(ctx, attrs...)
	}
}

func BenchmarkTracingManager_AddEvent(b *testing.B) {
	config := DefaultTracingConfig()
	config.Exporter = TracingExporterStdout
	
	tm, err := NewTracingManager(config)
	require.NoError(b, err)
	
	ctx := context.Background()
	ctx, span := tm.StartSpan(ctx, "benchmark_operation")
	defer span.End()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.AddEvent(ctx, "benchmark_event")
	}
}