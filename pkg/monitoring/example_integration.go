package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel/attribute"
)

// MonitoringStack represents a complete monitoring solution
type MonitoringStack struct {
	Metrics    *MetricsRegistry
	Tracing    *TracingManager
	Logging    *CorrelatedLogger
	Health     *HealthRegistry
	Dashboards *DashboardConfig
}

// MonitoringConfig combines all monitoring configurations
type MonitoringConfig struct {
	Metrics    *MetricsConfig
	Tracing    *TracingConfig
	Logging    *LoggingConfig
	Health     *HealthConfig
	Dashboards *DashboardConfig
}

// NewMonitoringStack creates a complete monitoring solution
func NewMonitoringStack(config *MonitoringConfig) (*MonitoringStack, error) {
	if config == nil {
		config = &MonitoringConfig{
			Metrics: DefaultMetricsConfig(),
			Tracing: DefaultTracingConfig(),
			Logging: DefaultLoggingConfig(),
			Health:  DefaultHealthConfig(),
		}
	}

	// Initialize metrics registry
	metricsRegistry := NewMetricsRegistry(config.Metrics)

	// Initialize tracing manager
	tracingManager, err := NewTracingManager(config.Tracing)
	if err != nil {
		return nil, fmt.Errorf("failed to create tracing manager: %w", err)
	}

	// Initialize correlated logger
	logger, err := NewCorrelatedLogger(config.Logging, tracingManager)
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}

	// Initialize health registry
	healthRegistry, err := NewHealthRegistry(config.Health, metricsRegistry, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create health registry: %w", err)
	}

	// Initialize dashboard configuration if provided
	var dashboards *DashboardConfig
	if config.Dashboards != nil {
		dashboards = config.Dashboards
	}

	stack := &MonitoringStack{
		Metrics:    metricsRegistry,
		Tracing:    tracingManager,
		Logging:    logger,
		Health:     healthRegistry,
		Dashboards: dashboards,
	}

	// Register monitoring stack health checker
	healthRegistry.RegisterChecker(&MonitoringStackHealthChecker{
		stack: stack,
	})

	log.Info().Msg("Monitoring stack initialized successfully")
	return stack, nil
}

// StartServices starts all monitoring services
func (ms *MonitoringStack) StartServices(ctx context.Context) error {
	// Start metrics server
	if ms.Metrics.config.Enabled {
		go func() {
			if err := ms.Metrics.StartMetricsServer(ctx); err != nil {
				log.Error().Err(err).Msg("Failed to start metrics server")
			}
		}()
	}

	// Tracing is already initialized and running

	// Health monitoring is already running

	log.Info().Msg("All monitoring services started")
	return nil
}

// Shutdown gracefully shuts down all monitoring components
func (ms *MonitoringStack) Shutdown(ctx context.Context) error {
	var lastErr error

	// Shutdown tracing
	if err := ms.Tracing.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to shutdown tracing")
		lastErr = err
	}

	// Shutdown logging
	if err := ms.Logging.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to shutdown logging")
		lastErr = err
	}

	// Shutdown health monitoring
	if err := ms.Health.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("Failed to shutdown health monitoring")
		lastErr = err
	}

	log.Info().Msg("Monitoring stack shut down successfully")
	return lastErr
}

// CreateStandardMetrics creates a standard set of metrics for applications
func (ms *MonitoringStack) CreateStandardMetrics() error {
	// HTTP request metrics
	_, err := ms.Metrics.NewCounter(
		"http_requests_total",
		"Total number of HTTP requests",
		"method", "endpoint", "status_code",
	)
	if err != nil {
		return fmt.Errorf("failed to create http_requests_total: %w", err)
	}

	_, err = ms.Metrics.NewHistogram(
		"http_request_duration_seconds",
		"HTTP request duration in seconds",
		[]float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		"method", "endpoint",
	)
	if err != nil {
		return fmt.Errorf("failed to create http_request_duration_seconds: %w", err)
	}

	// Application metrics
	_, err = ms.Metrics.NewGauge(
		"active_connections",
		"Number of active connections",
		"type",
	)
	if err != nil {
		return fmt.Errorf("failed to create active_connections: %w", err)
	}

	_, err = ms.Metrics.NewCounter(
		"application_errors_total",
		"Total number of application errors",
		"type", "severity",
	)
	if err != nil {
		return fmt.Errorf("failed to create application_errors_total: %w", err)
	}

	// Business metrics
	_, err = ms.Metrics.NewCounter(
		"sandbox_operations_total",
		"Total number of sandbox operations",
		"operation", "status",
	)
	if err != nil {
		return fmt.Errorf("failed to create sandbox_operations_total: %w", err)
	}

	_, err = ms.Metrics.NewHistogram(
		"sandbox_operation_duration_seconds",
		"Sandbox operation duration in seconds",
		nil,
		"operation",
	)
	if err != nil {
		return fmt.Errorf("failed to create sandbox_operation_duration_seconds: %w", err)
	}

	log.Info().Msg("Standard metrics created successfully")
	return nil
}

// CreateHTTPMiddleware creates HTTP middleware with full monitoring
func (ms *MonitoringStack) CreateHTTPMiddleware() func(http.Handler) http.Handler {
	// Get tracing middleware
	tracingMiddleware := ms.Tracing.NewHTTPMiddleware()

	// Get metrics
	requestCounter, _ := ms.Metrics.NewCounter(
		"http_requests_total",
		"Total HTTP requests",
		"method", "endpoint", "status",
	)
	requestDuration, _ := ms.Metrics.NewHistogram(
		"http_request_duration_seconds",
		"HTTP request duration",
		nil,
		"method", "endpoint",
	)

	return func(next http.Handler) http.Handler {
		// First apply tracing middleware
		tracedHandler := tracingMiddleware.Handler(next)

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create correlated logger for this request
			ctx := r.Context()
			logger := ms.Logging.WithContext(ctx)

			// Log request start
			logger.Info("HTTP request started", map[string]interface{}{
				"method":     r.Method,
				"path":       r.URL.Path,
				"remote_addr": r.RemoteAddr,
				"user_agent": r.UserAgent(),
			})

			// Wrap response writer to capture status code
			ww := &wrappedResponseWriter{
				ResponseWriter: w,
				statusCode:     200,
			}

			// Execute request with tracing
			tracedHandler.ServeHTTP(ww, r.WithContext(ctx))

			// Record metrics
			duration := time.Since(start)
			method := r.Method
			path := r.URL.Path
			status := fmt.Sprintf("%d", ww.statusCode)

			if requestCounter != nil {
				requestCounter.Inc(method, path, status)
			}
			if requestDuration != nil {
				requestDuration.Observe(duration.Seconds(), method, path)
			}

			// Log request completion
			logLevel := "info"
			if ww.statusCode >= 500 {
				logLevel = "error"
			} else if ww.statusCode >= 400 {
				logLevel = "warn"
			}

			logFields := map[string]interface{}{
				"method":      method,
				"path":        path,
				"status_code": ww.statusCode,
				"duration_ms": duration.Milliseconds(),
			}

			switch logLevel {
			case "error":
				logger.Error("HTTP request completed with error", nil, logFields)
			case "warn":
				logger.Warn("HTTP request completed with warning", logFields)
			default:
				logger.Info("HTTP request completed", logFields)
			}
		})
	}
}

// MonitorOperation wraps an operation with complete monitoring
func (ms *MonitoringStack) MonitorOperation(
	ctx context.Context,
	operationName string,
	operation func(ctx context.Context) error,
	attrs ...attribute.KeyValue,
) error {
	// Create correlated logger
	logger := ms.Logging.WithContext(ctx)

	// Start timing
	start := time.Now()

	// Log operation start
	logger.Info(fmt.Sprintf("Starting operation: %s", operationName), map[string]interface{}{
		"operation": operationName,
	})

	// Execute with tracing
	err := ms.Tracing.TraceOperation(ctx, operationName, func(ctx context.Context) error {
		// Add additional context
		ms.Tracing.SetAttributes(ctx, attrs...)

		// Execute operation
		return operation(ctx)
	}, attrs...)

	// Record duration
	duration := time.Since(start)

	// Update metrics if available
	if counter, _ := ms.Metrics.NewCounter(
		"monitored_operations_total",
		"Total monitored operations",
		"operation", "status",
	); counter != nil {
		status := "success"
		if err != nil {
			status = "error"
		}
		counter.Inc(operationName, status)
	}

	if histogram, _ := ms.Metrics.NewHistogram(
		"monitored_operation_duration_seconds",
		"Monitored operation duration",
		nil,
		"operation",
	); histogram != nil {
		histogram.Observe(duration.Seconds(), operationName)
	}

	// Log completion
	logFields := map[string]interface{}{
		"operation":   operationName,
		"duration_ms": duration.Milliseconds(),
	}

	if err != nil {
		logger.Error(fmt.Sprintf("Operation failed: %s", operationName), err, logFields)
	} else {
		logger.Info(fmt.Sprintf("Operation completed: %s", operationName), logFields)
	}

	return err
}

// GetOverallHealth returns the overall system health including monitoring stack
func (ms *MonitoringStack) GetOverallHealth(ctx context.Context) (*OverallHealth, error) {
	return ms.Health.CheckHealth(ctx)
}

// ExportMetrics exports metrics in the specified format
func (ms *MonitoringStack) ExportMetrics(format string) (string, error) {
	switch format {
	case "prometheus":
		return ms.Metrics.GatherPrometheusFormat()
	case "json":
		return ms.Metrics.GatherJSONFormat()
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// GetTraceAnalytics returns trace analytics data
func (ms *MonitoringStack) GetTraceAnalytics(timeRange time.Duration) (*TraceAnalytics, error) {
	return ms.Tracing.GetTraceAnalytics(timeRange)
}

// GetLogAnalytics returns log analytics data
func (ms *MonitoringStack) GetLogAnalytics(timeRange time.Duration) (*LogAnalytics, error) {
	return ms.Logging.GetLogAnalytics(timeRange)
}

// MonitoringStackHealthChecker checks the health of the monitoring stack itself
type MonitoringStackHealthChecker struct {
	stack *MonitoringStack
}

func (mshc *MonitoringStackHealthChecker) Name() string {
	return "monitoring_stack"
}

func (mshc *MonitoringStackHealthChecker) CheckType() CheckType {
	return CheckTypeLiveness
}

func (mshc *MonitoringStackHealthChecker) IsCritical() bool {
	return false // Monitoring stack failure shouldn't bring down the whole system
}

func (mshc *MonitoringStackHealthChecker) Check(ctx context.Context) HealthCheckResult {
	result := HealthCheckResult{
		Name:      mshc.Name(),
		CheckType: mshc.CheckType(),
		Timestamp: time.Now(),
		Critical:  mshc.IsCritical(),
		Details:   make(map[string]interface{}),
	}

	// Check metrics component
	metricsHealthy := mshc.stack.Metrics != nil
	result.Details["metrics_enabled"] = metricsHealthy

	// Check tracing component
	tracingHealthy := mshc.stack.Tracing != nil && mshc.stack.Tracing.tracer != nil
	result.Details["tracing_enabled"] = tracingHealthy

	// Check logging component
	loggingHealthy := mshc.stack.Logging != nil
	result.Details["logging_enabled"] = loggingHealthy

	// Check health component
	healthHealthy := mshc.stack.Health != nil
	result.Details["health_enabled"] = healthHealthy

	// Overall status
	if metricsHealthy && tracingHealthy && loggingHealthy && healthHealthy {
		result.Status = HealthStatusHealthy
		result.Message = "All monitoring components are functional"
	} else {
		result.Status = HealthStatusDegraded
		result.Message = "Some monitoring components are not functional"
	}

	return result
}

// Example usage function
func ExampleUsage() error {
	// Create monitoring configuration
	config := &MonitoringConfig{
		Metrics: &MetricsConfig{
			Enabled:   true,
			Port:      9090,
			Namespace: "myapp",
		},
		Tracing: &TracingConfig{
			Enabled:     true,
			ServiceName: "my-service",
			Exporter:    TracingExporterJaeger,
		},
		Logging: &LoggingConfig{
			Enabled:                true,
			Level:                  LogLevelInfo,
			Format:                 LogFormatJSON,
			EnableCorrelationID:    true,
			EnableTraceIntegration: true,
		},
		Health: &HealthConfig{
			Enabled:       true,
			Port:          8080,
			CheckInterval: 30 * time.Second,
		},
	}

	// Initialize monitoring stack
	stack, err := NewMonitoringStack(config)
	if err != nil {
		return fmt.Errorf("failed to create monitoring stack: %w", err)
	}

	// Start services
	ctx := context.Background()
	if err := stack.StartServices(ctx); err != nil {
		return fmt.Errorf("failed to start monitoring services: %w", err)
	}

	// Create standard metrics
	if err := stack.CreateStandardMetrics(); err != nil {
		return fmt.Errorf("failed to create standard metrics: %w", err)
	}

	// Example: Monitor an operation
	err = stack.MonitorOperation(ctx, "example_operation", func(ctx context.Context) error {
		// Simulate some work
		time.Sleep(100 * time.Millisecond)
		return nil
	}, attribute.String("example.type", "demo"))

	if err != nil {
		return fmt.Errorf("monitored operation failed: %w", err)
	}

	// Example: Check health
	health, err := stack.GetOverallHealth(ctx)
	if err != nil {
		return fmt.Errorf("failed to get health status: %w", err)
	}

	log.Info().
		Str("status", string(health.Status)).
		Str("message", health.Message).
		Msg("System health check completed")

	// Example: Export metrics
	metricsData, err := stack.ExportMetrics("prometheus")
	if err != nil {
		return fmt.Errorf("failed to export metrics: %w", err)
	}

	log.Info().
		Int("metrics_size", len(metricsData)).
		Msg("Metrics exported successfully")

	// Shutdown gracefully
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := stack.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shutdown monitoring stack: %w", err)
	}

	return nil
}

// Example HTTP server with monitoring
func ExampleHTTPServer(stack *MonitoringStack) *http.Server {
	mux := http.NewServeMux()

	// Add monitoring middleware
	middleware := stack.CreateHTTPMiddleware()

	// Example handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Use monitoring within handler
		err := stack.MonitorOperation(ctx, "handle_request", func(ctx context.Context) error {
			// Simulate some business logic
			time.Sleep(50 * time.Millisecond)
			
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Hello, monitored world!"))
			return nil
		}, attribute.String("handler.path", r.URL.Path))

		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	})

	// Apply middleware
	mux.Handle("/", middleware(handler))

	// Health endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		health, err := stack.GetOverallHealth(r.Context())
		if err != nil {
			http.Error(w, "Health check failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if health.Status == HealthStatusHealthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(health)
	})

	// Metrics endpoint (delegated to metrics registry)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		data, err := stack.ExportMetrics("prometheus")
		if err != nil {
			http.Error(w, "Failed to export metrics", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write([]byte(data))
	})

	return &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
}