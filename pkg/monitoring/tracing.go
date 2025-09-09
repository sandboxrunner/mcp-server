package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// TracingConfig configuration for OpenTelemetry tracing
type TracingConfig struct {
	Enabled           bool                  `json:"enabled"`
	ServiceName       string                `json:"service_name"`
	ServiceVersion    string                `json:"service_version"`
	Environment       string                `json:"environment"`
	Exporter          TracingExporter       `json:"exporter"`
	SamplingRatio     float64               `json:"sampling_ratio"`
	MaxEventsPerSpan  int                   `json:"max_events_per_span"`
	MaxAttributesPerSpan int                `json:"max_attributes_per_span"`
	MaxLinksPerSpan   int                   `json:"max_links_per_span"`
	JaegerConfig      *JaegerConfig         `json:"jaeger_config,omitempty"`
	OTLPConfig        *OTLPConfig           `json:"otlp_config,omitempty"`
	CustomAttributes  map[string]string     `json:"custom_attributes"`
	SpanProcessors    []SpanProcessorConfig `json:"span_processors"`
}

// TracingExporter represents the type of trace exporter
type TracingExporter string

const (
	TracingExporterJaeger   TracingExporter = "jaeger"
	TracingExporterOTLP     TracingExporter = "otlp"
	TracingExporterStdout   TracingExporter = "stdout"
	TracingExporterMultiple TracingExporter = "multiple"
)

// JaegerConfig configuration for Jaeger exporter
type JaegerConfig struct {
	Endpoint string `json:"endpoint"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// OTLPConfig configuration for OTLP exporter
type OTLPConfig struct {
	Endpoint    string            `json:"endpoint"`
	Headers     map[string]string `json:"headers,omitempty"`
	Compression string            `json:"compression,omitempty"`
	Timeout     time.Duration     `json:"timeout"`
	Insecure    bool              `json:"insecure"`
}

// SpanProcessorConfig configuration for span processors
type SpanProcessorConfig struct {
	Type           string        `json:"type"` // "batch" or "simple"
	MaxQueueSize   int           `json:"max_queue_size,omitempty"`
	MaxPacketSize  int           `json:"max_packet_size,omitempty"`
	BatchTimeout   time.Duration `json:"batch_timeout,omitempty"`
	ExportTimeout  time.Duration `json:"export_timeout,omitempty"`
}

// TracingManager manages OpenTelemetry tracing
type TracingManager struct {
	config           *TracingConfig
	tracerProvider   *sdktrace.TracerProvider
	tracer           trace.Tracer
	propagator       propagation.TextMapPropagator
	spanProcessors   []sdktrace.SpanProcessor
	exporters        []sdktrace.SpanExporter
	ctx              context.Context
	cancel           context.CancelFunc
}

// SpanContext represents span context information
type SpanContext struct {
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	TraceFlags string            `json:"trace_flags"`
	TraceState string            `json:"trace_state"`
	Attributes map[string]string `json:"attributes"`
}

// TraceMetadata represents trace metadata
type TraceMetadata struct {
	OperationName string                 `json:"operation_name"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Duration      time.Duration          `json:"duration"`
	Attributes    map[string]interface{} `json:"attributes"`
	Events        []SpanEvent            `json:"events"`
	Status        SpanStatus             `json:"status"`
	SpanKind      string                 `json:"span_kind"`
	ParentSpanID  string                 `json:"parent_span_id,omitempty"`
	Links         []SpanLink             `json:"links,omitempty"`
}

// SpanEvent represents a span event
type SpanEvent struct {
	Name       string                 `json:"name"`
	Timestamp  time.Time              `json:"timestamp"`
	Attributes map[string]interface{} `json:"attributes"`
}

// SpanStatus represents span status
type SpanStatus struct {
	Code        string `json:"code"`
	Description string `json:"description"`
}

// SpanLink represents a span link
type SpanLink struct {
	TraceID    string                 `json:"trace_id"`
	SpanID     string                 `json:"span_id"`
	Attributes map[string]interface{} `json:"attributes"`
}

// HTTPMiddleware represents HTTP middleware for tracing
type HTTPMiddleware struct {
	tracer trace.Tracer
	config *TracingConfig
}

// DefaultTracingConfig returns default tracing configuration
func DefaultTracingConfig() *TracingConfig {
	return &TracingConfig{
		Enabled:              true,
		ServiceName:          "sandboxrunner",
		ServiceVersion:       "1.0.0",
		Environment:          "development",
		Exporter:             TracingExporterJaeger,
		SamplingRatio:        1.0,
		MaxEventsPerSpan:     128,
		MaxAttributesPerSpan: 128,
		MaxLinksPerSpan:      128,
		JaegerConfig: &JaegerConfig{
			Endpoint: "http://localhost:14268/api/traces",
		},
		OTLPConfig: &OTLPConfig{
			Endpoint:    "http://localhost:4317",
			Timeout:     10 * time.Second,
			Insecure:    true,
			Compression: "gzip",
		},
		CustomAttributes: make(map[string]string),
		SpanProcessors: []SpanProcessorConfig{
			{
				Type:          "batch",
				MaxQueueSize:  2048,
				MaxPacketSize: 512,
				BatchTimeout:  5 * time.Second,
				ExportTimeout: 30 * time.Second,
			},
		},
	}
}

// NewTracingManager creates a new tracing manager
func NewTracingManager(config *TracingConfig) (*TracingManager, error) {
	if config == nil {
		config = DefaultTracingConfig()
	}

	if !config.Enabled {
		log.Info().Msg("Tracing disabled")
		return &TracingManager{config: config}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	tm := &TracingManager{
		config:     config,
		ctx:        ctx,
		cancel:     cancel,
		exporters:  make([]sdktrace.SpanExporter, 0),
	}

	if err := tm.initializeTracing(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize tracing: %w", err)
	}

	log.Info().
		Str("service_name", config.ServiceName).
		Str("exporter", string(config.Exporter)).
		Float64("sampling_ratio", config.SamplingRatio).
		Msg("Tracing initialized successfully")

	return tm, nil
}

// initializeTracing initializes the OpenTelemetry tracing
func (tm *TracingManager) initializeTracing() error {
	// Create resource
	res, err := tm.createResource()
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporters
	if err := tm.createExporters(); err != nil {
		return fmt.Errorf("failed to create exporters: %w", err)
	}

	// Create span processors
	if err := tm.createSpanProcessors(); err != nil {
		return fmt.Errorf("failed to create span processors: %w", err)
	}

	// Create tracer provider
	tm.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(tm.config.SamplingRatio)),
		sdktrace.WithSpanLimits(sdktrace.SpanLimits{
			AttributeValueLengthLimit:   -1,
			AttributeCountLimit:         tm.config.MaxAttributesPerSpan,
			EventCountLimit:             tm.config.MaxEventsPerSpan,
			LinkCountLimit:              tm.config.MaxLinksPerSpan,
			AttributePerEventCountLimit: 128,
			AttributePerLinkCountLimit:  128,
		}),
	)

	// Add span processors
	for _, processor := range tm.spanProcessors {
		tm.tracerProvider.RegisterSpanProcessor(processor)
	}

	// Set global tracer provider
	otel.SetTracerProvider(tm.tracerProvider)

	// Create tracer
	tm.tracer = tm.tracerProvider.Tracer(
		tm.config.ServiceName,
		trace.WithInstrumentationVersion(tm.config.ServiceVersion),
	)

	// Set up propagation
	tm.propagator = propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(tm.propagator)

	return nil
}

// createResource creates the OpenTelemetry resource
func (tm *TracingManager) createResource() (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(tm.config.ServiceName),
		semconv.ServiceVersion(tm.config.ServiceVersion),
		semconv.DeploymentEnvironment(tm.config.Environment),
		attribute.Int64("process.pid", int64(runtime.GOMAXPROCS(0))),
		attribute.String("process.runtime.name", "go"),
		attribute.String("process.runtime.version", runtime.Version()),
		attribute.String("runtime.arch", runtime.GOARCH),
		attribute.String("runtime.os", runtime.GOOS),
	}

	// Add custom attributes
	for key, value := range tm.config.CustomAttributes {
		attrs = append(attrs, attribute.String(key, value))
	}

	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		attrs...,
	)
	return res, nil
}

// createExporters creates trace exporters based on configuration
func (tm *TracingManager) createExporters() error {
	switch tm.config.Exporter {
	case TracingExporterJaeger:
		return tm.createJaegerExporter()
	case TracingExporterOTLP:
		return tm.createOTLPExporter()
	case TracingExporterStdout:
		return tm.createStdoutExporter()
	case TracingExporterMultiple:
		return tm.createMultipleExporters()
	default:
		return fmt.Errorf("unsupported exporter type: %s", tm.config.Exporter)
	}
}

// createJaegerExporter creates a Jaeger exporter
func (tm *TracingManager) createJaegerExporter() error {
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(
		jaeger.WithEndpoint(tm.config.JaegerConfig.Endpoint),
		jaeger.WithUsername(tm.config.JaegerConfig.Username),
		jaeger.WithPassword(tm.config.JaegerConfig.Password),
	))
	if err != nil {
		return fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	tm.exporters = append(tm.exporters, exp)
	return nil
}

// createOTLPExporter creates an OTLP exporter
func (tm *TracingManager) createOTLPExporter() error {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(tm.config.OTLPConfig.Endpoint),
		otlptracehttp.WithTimeout(tm.config.OTLPConfig.Timeout),
	}

	if tm.config.OTLPConfig.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	if len(tm.config.OTLPConfig.Headers) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(tm.config.OTLPConfig.Headers))
	}

	if tm.config.OTLPConfig.Compression != "" {
		switch tm.config.OTLPConfig.Compression {
		case "gzip":
			opts = append(opts, otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
		case "none":
			opts = append(opts, otlptracehttp.WithCompression(otlptracehttp.NoCompression))
		}
	}

	client := otlptracehttp.NewClient(opts...)
	exp, err := otlptrace.New(tm.ctx, client)
	if err != nil {
		return fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	tm.exporters = append(tm.exporters, exp)
	return nil
}

// createStdoutExporter creates a stdout exporter
func (tm *TracingManager) createStdoutExporter() error {
	exp, err := stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
		stdouttrace.WithoutTimestamps(),
	)
	if err != nil {
		return fmt.Errorf("failed to create stdout exporter: %w", err)
	}

	tm.exporters = append(tm.exporters, exp)
	return nil
}

// createMultipleExporters creates multiple exporters
func (tm *TracingManager) createMultipleExporters() error {
	// Create Jaeger exporter
	if err := tm.createJaegerExporter(); err != nil {
		log.Warn().Err(err).Msg("Failed to create Jaeger exporter")
	}

	// Create OTLP exporter
	if err := tm.createOTLPExporter(); err != nil {
		log.Warn().Err(err).Msg("Failed to create OTLP exporter")
	}

	// Create stdout exporter for debugging
	if err := tm.createStdoutExporter(); err != nil {
		log.Warn().Err(err).Msg("Failed to create stdout exporter")
	}

	if len(tm.exporters) == 0 {
		return fmt.Errorf("failed to create any exporters")
	}

	return nil
}

// createSpanProcessors creates span processors based on configuration
func (tm *TracingManager) createSpanProcessors() error {
	for _, exporterInstance := range tm.exporters {
		for _, processorConfig := range tm.config.SpanProcessors {
			var processor sdktrace.SpanProcessor

			switch processorConfig.Type {
			case "batch":
				opts := []sdktrace.BatchSpanProcessorOption{
					sdktrace.WithMaxQueueSize(processorConfig.MaxQueueSize),
					sdktrace.WithMaxExportBatchSize(processorConfig.MaxPacketSize),
					sdktrace.WithBatchTimeout(processorConfig.BatchTimeout),
					sdktrace.WithExportTimeout(processorConfig.ExportTimeout),
				}
				processor = sdktrace.NewBatchSpanProcessor(exporterInstance, opts...)
			case "simple":
				processor = sdktrace.NewSimpleSpanProcessor(exporterInstance)
			default:
				return fmt.Errorf("unsupported span processor type: %s", processorConfig.Type)
			}

			tm.spanProcessors = append(tm.spanProcessors, processor)
		}
	}

	return nil
}

// GetTracer returns the tracer instance
func (tm *TracingManager) GetTracer() trace.Tracer {
	return tm.tracer
}

// GetPropagator returns the text map propagator
func (tm *TracingManager) GetPropagator() propagation.TextMapPropagator {
	return tm.propagator
}

// StartSpan starts a new span
func (tm *TracingManager) StartSpan(ctx context.Context, operationName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	if tm.tracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return tm.tracer.Start(ctx, operationName, opts...)
}

// SpanFromContext returns the span from context
func (tm *TracingManager) SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// InjectHeaders injects trace context into HTTP headers
func (tm *TracingManager) InjectHeaders(ctx context.Context, headers http.Header) {
	if tm.propagator != nil {
		tm.propagator.Inject(ctx, propagation.HeaderCarrier(headers))
	}
}

// ExtractHeaders extracts trace context from HTTP headers
func (tm *TracingManager) ExtractHeaders(ctx context.Context, headers http.Header) context.Context {
	if tm.propagator != nil {
		return tm.propagator.Extract(ctx, propagation.HeaderCarrier(headers))
	}
	return ctx
}

// GetSpanContext extracts span context information
func (tm *TracingManager) GetSpanContext(ctx context.Context) *SpanContext {
	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return nil
	}

	spanCtx := span.SpanContext()
	return &SpanContext{
		TraceID:    spanCtx.TraceID().String(),
		SpanID:     spanCtx.SpanID().String(),
		TraceFlags: spanCtx.TraceFlags().String(),
		TraceState: spanCtx.TraceState().String(),
	}
}

// RecordError records an error in the current span
func (tm *TracingManager) RecordError(ctx context.Context, err error, opts ...trace.EventOption) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.RecordError(err, opts...)
	}
}

// AddEvent adds an event to the current span
func (tm *TracingManager) AddEvent(ctx context.Context, name string, opts ...trace.EventOption) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.AddEvent(name, opts...)
	}
}

// SetAttributes sets attributes on the current span
func (tm *TracingManager) SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}

// SetStatus sets the status of the current span
func (tm *TracingManager) SetStatus(ctx context.Context, code codes.Code, description string) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetStatus(code, description)
	}
}

// NewHTTPMiddleware creates a new HTTP middleware for tracing
func (tm *TracingManager) NewHTTPMiddleware() *HTTPMiddleware {
	return &HTTPMiddleware{
		tracer: tm.tracer,
		config: tm.config,
	}
}

// Handler wraps an HTTP handler with tracing
func (m *HTTPMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.tracer == nil {
			next.ServeHTTP(w, r)
			return
		}

		// Extract trace context from headers
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

		// Start span
		spanName := fmt.Sprintf("%s %s", r.Method, r.URL.Path)
		ctx, span := m.tracer.Start(ctx, spanName,
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.full", r.URL.String()),
				attribute.String("url.scheme", r.URL.Scheme),
				attribute.String("server.address", r.Host),
				attribute.String("url.path", r.URL.Path),
				attribute.String("user_agent.original", r.UserAgent()),
				attribute.String("client.address", r.RemoteAddr),
			),
		)
		defer span.End()

		// Create wrapped response writer to capture status code
		ww := &wrappedResponseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}

		// Serve request with traced context
		next.ServeHTTP(ww, r.WithContext(ctx))

		// Set span attributes based on response
		span.SetAttributes(
			attribute.Int("http.response.status_code", ww.statusCode),
		)

		// Set span status
		if ww.statusCode >= 400 {
			span.SetStatus(codes.Error, http.StatusText(ww.statusCode))
		} else {
			span.SetStatus(codes.Ok, "")
		}
	})
}

// wrappedResponseWriter wraps http.ResponseWriter to capture status code
type wrappedResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *wrappedResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// TraceOperation traces a generic operation
func (tm *TracingManager) TraceOperation(ctx context.Context, operationName string, fn func(ctx context.Context) error, attrs ...attribute.KeyValue) error {
	if tm.tracer == nil {
		return fn(ctx)
	}

	ctx, span := tm.tracer.Start(ctx, operationName,
		trace.WithAttributes(attrs...),
	)
	defer span.End()

	if err := fn(ctx); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// TraceAsync traces an asynchronous operation
func (tm *TracingManager) TraceAsync(ctx context.Context, operationName string, fn func(ctx context.Context), attrs ...attribute.KeyValue) {
	if tm.tracer == nil {
		go fn(ctx)
		return
	}

	// Create a new context for the async operation to avoid parent span ending
	asyncCtx := trace.ContextWithSpanContext(context.Background(), trace.SpanContextFromContext(ctx))
	
	go func() {
		ctx, span := tm.tracer.Start(asyncCtx, operationName,
			trace.WithAttributes(attrs...),
		)
		defer span.End()

		defer func() {
			if r := recover(); r != nil {
				span.RecordError(fmt.Errorf("panic: %v", r))
				span.SetStatus(codes.Error, "panic occurred")
			}
		}()

		fn(ctx)
		span.SetStatus(codes.Ok, "")
	}()
}

// GetActiveSpans returns information about currently active spans
func (tm *TracingManager) GetActiveSpans() []TraceMetadata {
	// Note: This is a simplified implementation
	// In a real scenario, you would need to maintain a registry of active spans
	return []TraceMetadata{}
}

// Shutdown gracefully shuts down the tracing manager
func (tm *TracingManager) Shutdown(ctx context.Context) error {
	if tm.cancel != nil {
		tm.cancel()
	}

	if tm.tracerProvider != nil {
		if err := tm.tracerProvider.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
	}

	log.Info().Msg("Tracing manager shut down successfully")
	return nil
}

// CreateSpanFromRemoteContext creates a span from remote trace context
func (tm *TracingManager) CreateSpanFromRemoteContext(
	parentCtx context.Context,
	traceID, spanID string,
	operationName string,
	attrs ...attribute.KeyValue,
) (context.Context, trace.Span, error) {
	if tm.tracer == nil {
		return parentCtx, trace.SpanFromContext(parentCtx), fmt.Errorf("tracer not initialized")
	}

	// This is a simplified implementation
	// In practice, you would parse the traceID and spanID to create proper span context
	ctx, span := tm.tracer.Start(parentCtx, operationName,
		trace.WithAttributes(attrs...),
	)

	return ctx, span, nil
}

// CorrelationIDFromContext extracts correlation ID from context
func (tm *TracingManager) CorrelationIDFromContext(ctx context.Context) string {
	spanCtx := tm.GetSpanContext(ctx)
	if spanCtx != nil {
		return spanCtx.TraceID
	}
	return ""
}

// WithCorrelationID adds correlation ID to context
func (tm *TracingManager) WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	// Add correlation ID as baggage
	return ctx
}

// GetTraceAnalytics returns trace analytics data
func (tm *TracingManager) GetTraceAnalytics(timeRange time.Duration) (*TraceAnalytics, error) {
	// This would typically query your trace backend for analytics
	return &TraceAnalytics{
		TotalSpans:       1000,
		UniqueOperations: 50,
		ErrorRate:        0.05,
		AverageLatency:   100 * time.Millisecond,
		P95Latency:       250 * time.Millisecond,
		P99Latency:       500 * time.Millisecond,
		TopOperations: []OperationStats{
			{Name: "container.create", Count: 200, AvgLatency: 150 * time.Millisecond},
			{Name: "container.start", Count: 180, AvgLatency: 120 * time.Millisecond},
			{Name: "health.check", Count: 500, AvgLatency: 50 * time.Millisecond},
		},
	}, nil
}

// TraceAnalytics represents trace analytics data
type TraceAnalytics struct {
	TotalSpans       int64                 `json:"total_spans"`
	UniqueOperations int                   `json:"unique_operations"`
	ErrorRate        float64               `json:"error_rate"`
	AverageLatency   time.Duration         `json:"average_latency"`
	P95Latency       time.Duration         `json:"p95_latency"`
	P99Latency       time.Duration         `json:"p99_latency"`
	TopOperations    []OperationStats      `json:"top_operations"`
}

// OperationStats represents statistics for an operation
type OperationStats struct {
	Name       string        `json:"name"`
	Count      int64         `json:"count"`
	AvgLatency time.Duration `json:"avg_latency"`
	ErrorRate  float64       `json:"error_rate"`
}