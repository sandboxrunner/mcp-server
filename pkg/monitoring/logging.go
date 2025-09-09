package monitoring

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// LogLevel represents log levels
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
	LogLevelPanic LogLevel = "panic"
)

// LogOutput represents log output destinations
type LogOutput string

const (
	LogOutputStdout   LogOutput = "stdout"
	LogOutputStderr   LogOutput = "stderr"
	LogOutputFile     LogOutput = "file"
	LogOutputSyslog   LogOutput = "syslog"
	LogOutputRemote   LogOutput = "remote"
	LogOutputMultiple LogOutput = "multiple"
)

// LogFormat represents log formats
type LogFormat string

const (
	LogFormatJSON    LogFormat = "json"
	LogFormatConsole LogFormat = "console"
	LogFormatLogfmt  LogFormat = "logfmt"
	LogFormatCustom  LogFormat = "custom"
)

// LoggingConfig configuration for enhanced logging
type LoggingConfig struct {
	Enabled                bool                    `json:"enabled"`
	Level                  LogLevel                `json:"level"`
	Format                 LogFormat               `json:"format"`
	Output                 LogOutput               `json:"output"`
	EnableCaller           bool                    `json:"enable_caller"`
	EnableStackTrace       bool                    `json:"enable_stack_trace"`
	EnableCorrelationID    bool                    `json:"enable_correlation_id"`
	EnableTraceIntegration bool                    `json:"enable_trace_integration"`
	TimeFormat             string                  `json:"time_format"`
	FileConfig             *FileLogConfig          `json:"file_config,omitempty"`
	SyslogConfig           *SyslogConfig           `json:"syslog_config,omitempty"`
	RemoteConfig           *RemoteLogConfig        `json:"remote_config,omitempty"`
	SamplingConfig         *LogSamplingConfig      `json:"sampling_config,omitempty"`
	FieldMappings          map[string]string       `json:"field_mappings"`
	GlobalFields           map[string]interface{}  `json:"global_fields"`
	Hooks                  []LogHookConfig         `json:"hooks"`
	BufferConfig           *LogBufferConfig        `json:"buffer_config,omitempty"`
	CompressionConfig      *LogCompressionConfig   `json:"compression_config,omitempty"`
}

// FileLogConfig configuration for file output
type FileLogConfig struct {
	Filename      string        `json:"filename"`
	MaxSize       int           `json:"max_size_mb"`
	MaxBackups    int           `json:"max_backups"`
	MaxAge        int           `json:"max_age_days"`
	Compress      bool          `json:"compress"`
	LocalTime     bool          `json:"local_time"`
	RotationTime  time.Duration `json:"rotation_time"`
	RotationCount int64         `json:"rotation_count"`
}

// SyslogConfig configuration for syslog output
type SyslogConfig struct {
	Protocol string `json:"protocol"` // "tcp", "udp", "unix"
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Tag      string `json:"tag"`
	Facility string `json:"facility"`
}

// RemoteLogConfig configuration for remote logging
type RemoteLogConfig struct {
	Endpoint     string            `json:"endpoint"`
	Protocol     string            `json:"protocol"` // "http", "https", "tcp", "udp"
	Timeout      time.Duration     `json:"timeout"`
	BatchSize    int               `json:"batch_size"`
	FlushTimeout time.Duration     `json:"flush_timeout"`
	Headers      map[string]string `json:"headers"`
	Compression  string            `json:"compression"`
	Authentication *AuthConfig     `json:"authentication,omitempty"`
}

// AuthConfig authentication configuration
type AuthConfig struct {
	Type     string `json:"type"` // "basic", "bearer", "api_key"
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Token    string `json:"token,omitempty"`
	APIKey   string `json:"api_key,omitempty"`
}

// LogSamplingConfig configuration for log sampling
type LogSamplingConfig struct {
	Enabled       bool          `json:"enabled"`
	Rate          float64       `json:"rate"`         // 0.0 to 1.0
	BurstLimit    int           `json:"burst_limit"`  // Allow burst of logs
	WindowSize    time.Duration `json:"window_size"`  // Sampling window
	KeyFields     []string      `json:"key_fields"`   // Fields to use for sampling key
	ExcludeFields []string      `json:"exclude_fields"` // Fields to exclude from sampling
}

// LogHookConfig configuration for log hooks
type LogHookConfig struct {
	Name      string                 `json:"name"`
	Type      string                 `json:"type"` // "webhook", "database", "metrics", "custom"
	Config    map[string]interface{} `json:"config"`
	Levels    []LogLevel             `json:"levels"`
	Filters   []LogFilter            `json:"filters"`
	Async     bool                   `json:"async"`
	BatchSize int                    `json:"batch_size"`
}

// LogFilter represents a log filter
type LogFilter struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // "eq", "ne", "contains", "regex"
	Value    interface{} `json:"value"`
}

// LogBufferConfig configuration for log buffering
type LogBufferConfig struct {
	Enabled      bool          `json:"enabled"`
	Size         int           `json:"size"`
	FlushTimeout time.Duration `json:"flush_timeout"`
	FlushOnLevel LogLevel      `json:"flush_on_level"`
}

// LogCompressionConfig configuration for log compression
type LogCompressionConfig struct {
	Enabled   bool   `json:"enabled"`
	Algorithm string `json:"algorithm"` // "gzip", "lz4", "snappy"
	Level     int    `json:"level"`     // Compression level
}

// CorrelatedLogger enhanced logger with correlation and tracing
type CorrelatedLogger struct {
	logger        zerolog.Logger
	config        *LoggingConfig
	tracingMgr    *TracingManager
	hooks         []LogHook
	samplers      map[string]*LogSampler
	buffer        *LogBuffer
	writers       []io.Writer
	mu            sync.RWMutex
	correlationID string
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp     time.Time              `json:"timestamp"`
	Level         string                 `json:"level"`
	Message       string                 `json:"message"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	TraceID       string                 `json:"trace_id,omitempty"`
	SpanID        string                 `json:"span_id,omitempty"`
	Caller        string                 `json:"caller,omitempty"`
	Fields        map[string]interface{} `json:"fields,omitempty"`
	StackTrace    string                 `json:"stack_trace,omitempty"`
}

// LogHook interface for log hooks
type LogHook interface {
	Fire(entry *LogEntry) error
	Levels() []LogLevel
}

// LogSampler implements log sampling
type LogSampler struct {
	rate       float64
	burstLimit int
	windowSize time.Duration
	keyFields  []string
	counter    map[string]int
	lastReset  time.Time
	mu         sync.Mutex
}

// LogBuffer implements log buffering
type LogBuffer struct {
	entries      []*LogEntry
	size         int
	flushTimeout time.Duration
	flushOnLevel LogLevel
	lastFlush    time.Time
	mu           sync.Mutex
}

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() *LoggingConfig {
	return &LoggingConfig{
		Enabled:                true,
		Level:                  LogLevelInfo,
		Format:                 LogFormatJSON,
		Output:                 LogOutputStdout,
		EnableCaller:           true,
		EnableStackTrace:       false,
		EnableCorrelationID:    true,
		EnableTraceIntegration: true,
		TimeFormat:             time.RFC3339,
		FieldMappings:          make(map[string]string),
		GlobalFields:           make(map[string]interface{}),
		Hooks:                  make([]LogHookConfig, 0),
		SamplingConfig: &LogSamplingConfig{
			Enabled:    false,
			Rate:       1.0,
			BurstLimit: 100,
			WindowSize: time.Minute,
		},
		BufferConfig: &LogBufferConfig{
			Enabled:      false,
			Size:         1000,
			FlushTimeout: 5 * time.Second,
			FlushOnLevel: LogLevelError,
		},
	}
}

// NewCorrelatedLogger creates a new correlated logger
func NewCorrelatedLogger(config *LoggingConfig, tracingMgr *TracingManager) (*CorrelatedLogger, error) {
	if config == nil {
		config = DefaultLoggingConfig()
	}

	if !config.Enabled {
		log.Info().Msg("Enhanced logging disabled")
		return &CorrelatedLogger{config: config}, nil
	}

	cl := &CorrelatedLogger{
		config:     config,
		tracingMgr: tracingMgr,
		hooks:      make([]LogHook, 0),
		samplers:   make(map[string]*LogSampler),
		writers:    make([]io.Writer, 0),
	}

	if err := cl.initializeLogger(); err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	log.Info().
		Str("level", string(config.Level)).
		Str("format", string(config.Format)).
		Str("output", string(config.Output)).
		Bool("correlation_id", config.EnableCorrelationID).
		Bool("trace_integration", config.EnableTraceIntegration).
		Msg("Enhanced logging initialized successfully")

	return cl, nil
}

// initializeLogger initializes the logger configuration
func (cl *CorrelatedLogger) initializeLogger() error {
	// Set global log level
	level, err := cl.parseLogLevel(cl.config.Level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	zerolog.SetGlobalLevel(level)

	// Configure time format
	if cl.config.TimeFormat != "" {
		zerolog.TimeFieldFormat = cl.config.TimeFormat
	}

	// Create writers based on output configuration
	if err := cl.createWriters(); err != nil {
		return fmt.Errorf("failed to create writers: %w", err)
	}

	// Create multi-writer
	var writer io.Writer
	if len(cl.writers) == 1 {
		writer = cl.writers[0]
	} else {
		writer = io.MultiWriter(cl.writers...)
	}

	// Create logger
	cl.logger = zerolog.New(writer).With().Timestamp().Logger()

	// Configure caller information
	if cl.config.EnableCaller {
		cl.logger = cl.logger.With().Caller().Logger()
	}

	// Add global fields
	if len(cl.config.GlobalFields) > 0 {
		logContext := cl.logger.With()
		for key, value := range cl.config.GlobalFields {
			logContext = logContext.Interface(key, value)
		}
		cl.logger = logContext.Logger()
	}

	// Initialize sampling
	if cl.config.SamplingConfig != nil && cl.config.SamplingConfig.Enabled {
		cl.initializeSampling()
	}

	// Initialize buffering
	if cl.config.BufferConfig != nil && cl.config.BufferConfig.Enabled {
		cl.initializeBuffering()
	}

	// Initialize hooks
	if err := cl.initializeHooks(); err != nil {
		return fmt.Errorf("failed to initialize hooks: %w", err)
	}

	return nil
}

// createWriters creates output writers based on configuration
func (cl *CorrelatedLogger) createWriters() error {
	switch cl.config.Output {
	case LogOutputStdout:
		cl.writers = append(cl.writers, os.Stdout)
	case LogOutputStderr:
		cl.writers = append(cl.writers, os.Stderr)
	case LogOutputFile:
		if cl.config.FileConfig == nil {
			return fmt.Errorf("file config required for file output")
		}
		writer, err := cl.createFileWriter()
		if err != nil {
			return err
		}
		cl.writers = append(cl.writers, writer)
	case LogOutputSyslog:
		if cl.config.SyslogConfig == nil {
			return fmt.Errorf("syslog config required for syslog output")
		}
		writer, err := cl.createSyslogWriter()
		if err != nil {
			return err
		}
		cl.writers = append(cl.writers, writer)
	case LogOutputRemote:
		if cl.config.RemoteConfig == nil {
			return fmt.Errorf("remote config required for remote output")
		}
		writer, err := cl.createRemoteWriter()
		if err != nil {
			return err
		}
		cl.writers = append(cl.writers, writer)
	case LogOutputMultiple:
		return cl.createMultipleWriters()
	default:
		return fmt.Errorf("unsupported output type: %s", cl.config.Output)
	}

	return nil
}

// createFileWriter creates a file writer
func (cl *CorrelatedLogger) createFileWriter() (io.Writer, error) {
	// For simplicity, using os.OpenFile. In production, you might want rotating file writer
	file, err := os.OpenFile(cl.config.FileConfig.Filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	return file, nil
}

// createSyslogWriter creates a syslog writer
func (cl *CorrelatedLogger) createSyslogWriter() (io.Writer, error) {
	// Placeholder for syslog implementation
	return os.Stdout, nil
}

// createRemoteWriter creates a remote writer
func (cl *CorrelatedLogger) createRemoteWriter() (io.Writer, error) {
	// Placeholder for remote logging implementation
	return os.Stdout, nil
}

// createMultipleWriters creates multiple writers
func (cl *CorrelatedLogger) createMultipleWriters() error {
	// Add stdout
	cl.writers = append(cl.writers, os.Stdout)

	// Add file if configured
	if cl.config.FileConfig != nil {
		writer, err := cl.createFileWriter()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to create file writer")
		} else {
			cl.writers = append(cl.writers, writer)
		}
	}

	// Add remote if configured
	if cl.config.RemoteConfig != nil {
		writer, err := cl.createRemoteWriter()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to create remote writer")
		} else {
			cl.writers = append(cl.writers, writer)
		}
	}

	return nil
}

// initializeSampling initializes log sampling
func (cl *CorrelatedLogger) initializeSampling() {
	config := cl.config.SamplingConfig
	sampler := &LogSampler{
		rate:       config.Rate,
		burstLimit: config.BurstLimit,
		windowSize: config.WindowSize,
		keyFields:  config.KeyFields,
		counter:    make(map[string]int),
		lastReset:  time.Now(),
	}
	cl.samplers["default"] = sampler
}

// initializeBuffering initializes log buffering
func (cl *CorrelatedLogger) initializeBuffering() {
	config := cl.config.BufferConfig
	cl.buffer = &LogBuffer{
		entries:      make([]*LogEntry, 0, config.Size),
		size:         config.Size,
		flushTimeout: config.FlushTimeout,
		flushOnLevel: config.FlushOnLevel,
		lastFlush:    time.Now(),
	}

	// Start flush goroutine
	go cl.bufferFlushRoutine()
}

// initializeHooks initializes log hooks
func (cl *CorrelatedLogger) initializeHooks() error {
	for _, hookConfig := range cl.config.Hooks {
		hook, err := cl.createHook(hookConfig)
		if err != nil {
			log.Warn().Err(err).Str("hook", hookConfig.Name).Msg("Failed to create hook")
			continue
		}
		cl.hooks = append(cl.hooks, hook)
	}
	return nil
}

// createHook creates a log hook
func (cl *CorrelatedLogger) createHook(config LogHookConfig) (LogHook, error) {
	switch config.Type {
	case "webhook":
		return cl.createWebhookHook(config)
	case "metrics":
		return cl.createMetricsHook(config)
	default:
		return nil, fmt.Errorf("unsupported hook type: %s", config.Type)
	}
}

// createWebhookHook creates a webhook hook
func (cl *CorrelatedLogger) createWebhookHook(config LogHookConfig) (LogHook, error) {
	// Placeholder for webhook hook implementation
	return &WebhookHook{config: config}, nil
}

// createMetricsHook creates a metrics hook
func (cl *CorrelatedLogger) createMetricsHook(config LogHookConfig) (LogHook, error) {
	// Placeholder for metrics hook implementation
	return &MetricsHook{config: config}, nil
}

// parseLogLevel parses log level string
func (cl *CorrelatedLogger) parseLogLevel(level LogLevel) (zerolog.Level, error) {
	switch level {
	case LogLevelTrace:
		return zerolog.TraceLevel, nil
	case LogLevelDebug:
		return zerolog.DebugLevel, nil
	case LogLevelInfo:
		return zerolog.InfoLevel, nil
	case LogLevelWarn:
		return zerolog.WarnLevel, nil
	case LogLevelError:
		return zerolog.ErrorLevel, nil
	case LogLevelFatal:
		return zerolog.FatalLevel, nil
	case LogLevelPanic:
		return zerolog.PanicLevel, nil
	default:
		return zerolog.InfoLevel, fmt.Errorf("unknown log level: %s", level)
	}
}

// WithCorrelationID adds correlation ID to logger context
func (cl *CorrelatedLogger) WithCorrelationID(correlationID string) *CorrelatedLogger {
	newLogger := *cl
	newLogger.correlationID = correlationID
	newLogger.logger = cl.logger.With().Str("correlation_id", correlationID).Logger()
	return &newLogger
}

// WithContext adds trace context information to logger
func (cl *CorrelatedLogger) WithContext(ctx context.Context) *CorrelatedLogger {
	newLogger := *cl
	
	// Add trace information if available
	if cl.config.EnableTraceIntegration && cl.tracingMgr != nil {
		if spanCtx := cl.tracingMgr.GetSpanContext(ctx); spanCtx != nil {
			newLogger.logger = cl.logger.With().
				Str("trace_id", spanCtx.TraceID).
				Str("span_id", spanCtx.SpanID).
				Logger()
		}
	}

	// Add correlation ID from context if available
	if cl.config.EnableCorrelationID && cl.tracingMgr != nil {
		if correlationID := cl.tracingMgr.CorrelationIDFromContext(ctx); correlationID != "" {
			newLogger.correlationID = correlationID
			newLogger.logger = newLogger.logger.With().Str("correlation_id", correlationID).Logger()
		}
	}

	return &newLogger
}

// WithFields adds fields to logger context
func (cl *CorrelatedLogger) WithFields(fields map[string]interface{}) *CorrelatedLogger {
	newLogger := *cl
	logContext := cl.logger.With()
	for key, value := range fields {
		logContext = logContext.Interface(key, value)
	}
	newLogger.logger = logContext.Logger()
	return &newLogger
}

// Info logs an info message
func (cl *CorrelatedLogger) Info(msg string, fields ...map[string]interface{}) {
	cl.log(LogLevelInfo, msg, fields...)
}

// Debug logs a debug message
func (cl *CorrelatedLogger) Debug(msg string, fields ...map[string]interface{}) {
	cl.log(LogLevelDebug, msg, fields...)
}

// Warn logs a warning message
func (cl *CorrelatedLogger) Warn(msg string, fields ...map[string]interface{}) {
	cl.log(LogLevelWarn, msg, fields...)
}

// Error logs an error message
func (cl *CorrelatedLogger) Error(msg string, err error, fields ...map[string]interface{}) {
	allFields := make(map[string]interface{})
	if err != nil {
		allFields["error"] = err.Error()
	}
	
	for _, fieldMap := range fields {
		for k, v := range fieldMap {
			allFields[k] = v
		}
	}
	
	cl.log(LogLevelError, msg, allFields)
}

// Fatal logs a fatal message and exits
func (cl *CorrelatedLogger) Fatal(msg string, fields ...map[string]interface{}) {
	cl.log(LogLevelFatal, msg, fields...)
	os.Exit(1)
}

// log internal logging method
func (cl *CorrelatedLogger) log(level LogLevel, msg string, fields ...map[string]interface{}) {
	// Create log entry
	entry := &LogEntry{
		Timestamp:     time.Now(),
		Level:         string(level),
		Message:       msg,
		CorrelationID: cl.correlationID,
		Fields:        make(map[string]interface{}),
	}

	// Add fields
	for _, fieldMap := range fields {
		for k, v := range fieldMap {
			entry.Fields[k] = v
		}
	}

	// Add caller information if enabled
	if cl.config.EnableCaller {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			entry.Caller = fmt.Sprintf("%s:%d", file, line)
		}
	}

	// Add stack trace for errors if enabled
	if cl.config.EnableStackTrace && level == LogLevelError {
		entry.StackTrace = cl.getStackTrace()
	}

	// Check sampling
	if cl.shouldSample(entry) {
		// Check buffering
		if cl.config.BufferConfig != nil && cl.config.BufferConfig.Enabled {
			cl.bufferEntry(entry)
		} else {
			cl.writeEntry(entry)
		}

		// Fire hooks
		cl.fireHooks(entry)
	}
}

// shouldSample determines if log entry should be sampled
func (cl *CorrelatedLogger) shouldSample(entry *LogEntry) bool {
	if cl.config.SamplingConfig == nil || !cl.config.SamplingConfig.Enabled {
		return true
	}

	sampler := cl.samplers["default"]
	if sampler == nil {
		return true
	}

	return sampler.ShouldSample(entry)
}

// bufferEntry adds entry to buffer
func (cl *CorrelatedLogger) bufferEntry(entry *LogEntry) {
	if cl.buffer == nil {
		cl.writeEntry(entry)
		return
	}

	cl.buffer.mu.Lock()
	defer cl.buffer.mu.Unlock()

	cl.buffer.entries = append(cl.buffer.entries, entry)

	// Flush if buffer is full or flush level reached
	if len(cl.buffer.entries) >= cl.buffer.size || 
	   (cl.buffer.flushOnLevel != "" && LogLevel(entry.Level) >= cl.buffer.flushOnLevel) {
		cl.flushBuffer()
	}
}

// flushBuffer flushes buffered entries
func (cl *CorrelatedLogger) flushBuffer() {
	if cl.buffer == nil || len(cl.buffer.entries) == 0 {
		return
	}

	for _, entry := range cl.buffer.entries {
		cl.writeEntry(entry)
	}

	cl.buffer.entries = cl.buffer.entries[:0]
	cl.buffer.lastFlush = time.Now()
}

// bufferFlushRoutine periodically flushes buffer
func (cl *CorrelatedLogger) bufferFlushRoutine() {
	if cl.buffer == nil {
		return
	}

	ticker := time.NewTicker(cl.buffer.flushTimeout)
	defer ticker.Stop()

	for range ticker.C {
		cl.buffer.mu.Lock()
		if time.Since(cl.buffer.lastFlush) >= cl.buffer.flushTimeout {
			cl.flushBuffer()
		}
		cl.buffer.mu.Unlock()
	}
}

// writeEntry writes log entry to configured outputs
func (cl *CorrelatedLogger) writeEntry(entry *LogEntry) {
	// Convert to zerolog event
	var event *zerolog.Event
	switch LogLevel(entry.Level) {
	case LogLevelTrace:
		event = cl.logger.Trace()
	case LogLevelDebug:
		event = cl.logger.Debug()
	case LogLevelInfo:
		event = cl.logger.Info()
	case LogLevelWarn:
		event = cl.logger.Warn()
	case LogLevelError:
		event = cl.logger.Error()
	case LogLevelFatal:
		event = cl.logger.Fatal()
	case LogLevelPanic:
		event = cl.logger.Panic()
	default:
		event = cl.logger.Info()
	}

	// Add fields
	for key, value := range entry.Fields {
		event = event.Interface(key, value)
	}

	// Add trace information
	if entry.TraceID != "" {
		event = event.Str("trace_id", entry.TraceID)
	}
	if entry.SpanID != "" {
		event = event.Str("span_id", entry.SpanID)
	}

	// Add stack trace
	if entry.StackTrace != "" {
		event = event.Str("stack_trace", entry.StackTrace)
	}

	event.Msg(entry.Message)
}

// fireHooks fires log hooks
func (cl *CorrelatedLogger) fireHooks(entry *LogEntry) {
	for _, hook := range cl.hooks {
		levels := hook.Levels()
		shouldFire := false
		for _, level := range levels {
			if level == LogLevel(entry.Level) {
				shouldFire = true
				break
			}
		}

		if shouldFire {
			go func(h LogHook, e *LogEntry) {
				if err := h.Fire(e); err != nil {
					log.Error().Err(err).Msg("Failed to fire log hook")
				}
			}(hook, entry)
		}
	}
}

// getStackTrace gets current stack trace
func (cl *CorrelatedLogger) getStackTrace() string {
	buf := make([]byte, 1024*8)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// ShouldSample determines if log entry should be sampled
func (ls *LogSampler) ShouldSample(entry *LogEntry) bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()

	// Reset counter if window has passed
	if time.Since(ls.lastReset) >= ls.windowSize {
		ls.counter = make(map[string]int)
		ls.lastReset = time.Now()
	}

	// Create sampling key
	key := ls.createSamplingKey(entry)

	// Check burst limit
	if ls.counter[key] < ls.burstLimit {
		ls.counter[key]++
		return true
	}

	// Apply sampling rate
	ls.counter[key]++
	return float64(ls.counter[key]) * ls.rate >= 1.0
}

// createSamplingKey creates sampling key from entry
func (ls *LogSampler) createSamplingKey(entry *LogEntry) string {
	if len(ls.keyFields) == 0 {
		return "default"
	}

	var keyParts []string
	for _, field := range ls.keyFields {
		if value, exists := entry.Fields[field]; exists {
			keyParts = append(keyParts, fmt.Sprintf("%v", value))
		}
	}

	if len(keyParts) == 0 {
		return "default"
	}

	return strings.Join(keyParts, ":")
}

// GetLogAnalytics returns log analytics data
func (cl *CorrelatedLogger) GetLogAnalytics(timeRange time.Duration) (*LogAnalytics, error) {
	// This would typically query your log backend for analytics
	return &LogAnalytics{
		TotalLogs:      10000,
		LogsByLevel:    map[string]int64{"info": 7000, "warn": 2000, "error": 1000},
		TopLogSources:  []LogSource{{Source: "container.manager", Count: 3000}, {Source: "health.checker", Count: 2500}},
		ErrorRate:      0.10,
		AverageLatency: 50 * time.Millisecond,
	}, nil
}

// LogAnalytics represents log analytics data
type LogAnalytics struct {
	TotalLogs      int64              `json:"total_logs"`
	LogsByLevel    map[string]int64   `json:"logs_by_level"`
	TopLogSources  []LogSource        `json:"top_log_sources"`
	ErrorRate      float64            `json:"error_rate"`
	AverageLatency time.Duration      `json:"average_latency"`
}

// LogSource represents a log source with count
type LogSource struct {
	Source string `json:"source"`
	Count  int64  `json:"count"`
}

// Shutdown gracefully shuts down the logger
func (cl *CorrelatedLogger) Shutdown(ctx context.Context) error {
	// Flush buffer
	if cl.buffer != nil {
		cl.buffer.mu.Lock()
		cl.flushBuffer()
		cl.buffer.mu.Unlock()
	}

	log.Info().Msg("Enhanced logging shut down successfully")
	return nil
}

// Hook implementations

// WebhookHook sends logs to webhook
type WebhookHook struct {
	config LogHookConfig
}

func (wh *WebhookHook) Fire(entry *LogEntry) error {
	// Placeholder for webhook implementation
	return nil
}

func (wh *WebhookHook) Levels() []LogLevel {
	return wh.config.Levels
}

// MetricsHook updates metrics based on logs
type MetricsHook struct {
	config LogHookConfig
}

func (mh *MetricsHook) Fire(entry *LogEntry) error {
	// Placeholder for metrics implementation
	return nil
}

func (mh *MetricsHook) Levels() []LogLevel {
	return mh.config.Levels
}