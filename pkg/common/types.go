package common

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"
)

// Error codes for the sandbox system
const (
	ErrCodeSandboxNotFound    = "SANDBOX_NOT_FOUND"
	ErrCodeSandboxNotRunning  = "SANDBOX_NOT_RUNNING"
	ErrCodeProcessNotFound    = "PROCESS_NOT_FOUND"
	ErrCodeFileNotFound       = "FILE_NOT_FOUND"
	ErrCodeInvalidArgument    = "INVALID_ARGUMENT"
	ErrCodePermissionDenied   = "PERMISSION_DENIED"
	ErrCodeResourceExhausted  = "RESOURCE_EXHAUSTED"
	ErrCodeInternalError      = "INTERNAL_ERROR"
	ErrCodeTimeout            = "TIMEOUT"
)

// SandboxError represents a structured error from the sandbox system
type SandboxError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *SandboxError) Error() string {
	return e.Message
}

// NewSandboxError creates a new structured error
func NewSandboxError(code, message, details string) *SandboxError {
	return &SandboxError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// OutputMsg represents a message in an output stream
type OutputMsg struct {
	Message   string                 `json:"message"`
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level,omitempty"`
	Source    string                 `json:"source,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// SafeBuffer provides a thread-safe buffer for capturing output
type SafeBuffer struct {
	mu     sync.RWMutex
	buffer bytes.Buffer
	maxSize int
}

// NewSafeBuffer creates a new safe buffer with optional max size
func NewSafeBuffer(maxSize int) *SafeBuffer {
	if maxSize <= 0 {
		maxSize = 1024 * 1024 // Default 1MB
	}
	
	return &SafeBuffer{
		maxSize: maxSize,
	}
}

// Write implements io.Writer
func (sb *SafeBuffer) Write(p []byte) (n int, err error) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Check if adding this data would exceed max size
	if sb.buffer.Len()+len(p) > sb.maxSize {
		// Truncate to make room
		excess := sb.buffer.Len() + len(p) - sb.maxSize
		sb.buffer.Next(excess)
	}

	return sb.buffer.Write(p)
}

// String returns the buffer contents as a string
func (sb *SafeBuffer) String() string {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return sb.buffer.String()
}

// Bytes returns the buffer contents as bytes
func (sb *SafeBuffer) Bytes() []byte {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return sb.buffer.Bytes()
}

// Len returns the buffer length
func (sb *SafeBuffer) Len() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return sb.buffer.Len()
}

// Reset resets the buffer
func (sb *SafeBuffer) Reset() {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	sb.buffer.Reset()
}

// StringAndReset returns buffer contents and resets it
func (sb *SafeBuffer) StringAndReset() string {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	
	str := sb.buffer.String()
	sb.buffer.Reset()
	return str
}

// ProcessIO handles process input/output streams
type ProcessIO struct {
	stdinR  io.ReadCloser
	stdinW  io.WriteCloser
	stdoutR io.ReadCloser
	stdoutW io.WriteCloser
	stderrR io.ReadCloser
	stderrW io.WriteCloser
	done    chan struct{}
}

// NewProcessIO creates new process IO streams
func NewProcessIO() *ProcessIO {
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()

	return &ProcessIO{
		stdinR:  stdinR,
		stdinW:  stdinW,
		stdoutR: stdoutR,
		stdoutW: stdoutW,
		stderrR: stderrR,
		stderrW: stderrW,
		done:    make(chan struct{}),
	}
}

// Stdin returns the stdin writer
func (pio *ProcessIO) Stdin() io.WriteCloser {
	return pio.stdinW
}

// Stdout returns the stdout reader
func (pio *ProcessIO) Stdout() io.ReadCloser {
	return pio.stdoutR
}

// Stderr returns the stderr reader
func (pio *ProcessIO) Stderr() io.ReadCloser {
	return pio.stderrR
}

// Done returns a channel that's closed when the process is done
func (pio *ProcessIO) Done() <-chan struct{} {
	return pio.done
}

// Close closes all streams
func (pio *ProcessIO) Close() error {
	close(pio.done)
	
	pio.stdinR.Close()
	pio.stdinW.Close()
	pio.stdoutR.Close()
	pio.stdoutW.Close()
	pio.stderrR.Close()
	pio.stderrW.Close()
	
	return nil
}

// ContextKey is a type for context keys to avoid collisions
type ContextKey string

const (
	// Context keys
	ContextKeySandboxID ContextKey = "sandbox_id"
	ContextKeyProcessID ContextKey = "process_id"
	ContextKeyRequestID ContextKey = "request_id"
	ContextKeyUserAgent ContextKey = "user_agent"
)

// ContextWithSandboxID adds sandbox ID to context
func ContextWithSandboxID(ctx context.Context, sandboxID string) context.Context {
	return context.WithValue(ctx, ContextKeySandboxID, sandboxID)
}

// SandboxIDFromContext retrieves sandbox ID from context
func SandboxIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ContextKeySandboxID).(string)
	return id, ok
}

// ContextWithProcessID adds process ID to context
func ContextWithProcessID(ctx context.Context, processID string) context.Context {
	return context.WithValue(ctx, ContextKeyProcessID, processID)
}

// ProcessIDFromContext retrieves process ID from context
func ProcessIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(ContextKeyProcessID).(string)
	return id, ok
}

// Pagination represents pagination parameters
type Pagination struct {
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

// DefaultPagination returns default pagination settings
func DefaultPagination() Pagination {
	return Pagination{
		Limit:  50,
		Offset: 0,
	}
}

// Validate validates pagination parameters
func (p *Pagination) Validate() error {
	if p.Limit < 0 {
		return NewSandboxError(ErrCodeInvalidArgument, "limit cannot be negative", "")
	}
	if p.Offset < 0 {
		return NewSandboxError(ErrCodeInvalidArgument, "offset cannot be negative", "")
	}
	if p.Limit > 1000 {
		return NewSandboxError(ErrCodeInvalidArgument, "limit cannot exceed 1000", "")
	}
	if p.Limit == 0 {
		p.Limit = 50
	}
	return nil
}

// HealthStatus represents system health status
type HealthStatus struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Version   string            `json:"version"`
	Uptime    time.Duration     `json:"uptime"`
	Metrics   map[string]interface{} `json:"metrics"`
}

// SystemMetrics represents system resource metrics
type SystemMetrics struct {
	ActiveSandboxes int64     `json:"active_sandboxes"`
	RunningProcesses int64    `json:"running_processes"`
	MemoryUsage     int64     `json:"memory_usage_bytes"`
	CPUUsage        float64   `json:"cpu_usage_percent"`
	DiskUsage       int64     `json:"disk_usage_bytes"`
	Timestamp       time.Time `json:"timestamp"`
}

// RetryConfig represents retry configuration
type RetryConfig struct {
	MaxAttempts int           `json:"max_attempts"`
	InitialDelay time.Duration `json:"initial_delay"`
	MaxDelay     time.Duration `json:"max_delay"`
	Multiplier   float64       `json:"multiplier"`
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
	}
}

// EventType represents different types of system events
type EventType string

const (
	EventTypeSandboxCreated   EventType = "sandbox.created"
	EventTypeSandboxStarted   EventType = "sandbox.started"
	EventTypeSandboxStopped   EventType = "sandbox.stopped"
	EventTypeSandboxDeleted   EventType = "sandbox.deleted"
	EventTypeProcessStarted   EventType = "process.started"
	EventTypeProcessExited    EventType = "process.exited"
	EventTypeProcessKilled    EventType = "process.killed"
	EventTypeFileUploaded     EventType = "file.uploaded"
	EventTypeFileDeleted      EventType = "file.deleted"
	EventTypeDirectoryCreated EventType = "directory.created"
	EventTypeDirectoryDeleted EventType = "directory.deleted"
)

// Event represents a system event
type Event struct {
	ID        string                 `json:"id"`
	Type      EventType              `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	SandboxID string                 `json:"sandbox_id,omitempty"`
	ProcessID string                 `json:"process_id,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// ResourceUsage represents resource usage information
type ResourceUsage struct {
	CPUTime       time.Duration `json:"cpu_time"`
	MemoryPeak    int64         `json:"memory_peak_bytes"`
	MemoryCurrent int64         `json:"memory_current_bytes"`
	NetworkIO     NetworkIO     `json:"network_io"`
	DiskIO        DiskIO        `json:"disk_io"`
}

// NetworkIO represents network I/O statistics
type NetworkIO struct {
	BytesReceived    int64 `json:"bytes_received"`
	BytesTransmitted int64 `json:"bytes_transmitted"`
	PacketsReceived  int64 `json:"packets_received"`
	PacketsTransmitted int64 `json:"packets_transmitted"`
}

// DiskIO represents disk I/O statistics
type DiskIO struct {
	BytesRead    int64 `json:"bytes_read"`
	BytesWritten int64 `json:"bytes_written"`
	ReadOps      int64 `json:"read_ops"`
	WriteOps     int64 `json:"write_ops"`
}

// LogLevel represents logging levels
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     LogLevel               `json:"level"`
	Message   string                 `json:"message"`
	SandboxID string                 `json:"sandbox_id,omitempty"`
	ProcessID string                 `json:"process_id,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}