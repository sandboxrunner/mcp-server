package api

import (
	"time"
)

// Request/Response types for REST API

// QueryParams holds common query parameters
type QueryParams struct {
	PageSize   int               `json:"page_size"`
	PageOffset int               `json:"page_offset"`
	SortBy     string            `json:"sort_by"`
	SortOrder  string            `json:"sort_order"`
	Filters    map[string]string `json:"filters"`
	Fields     []string          `json:"fields"`
}

// ListResponse is a generic list response with pagination
type ListResponse struct {
	Data       interface{}    `json:"data"`
	Pagination PaginationInfo `json:"pagination,omitempty"`
	Total      int            `json:"total"`
	Timestamp  time.Time      `json:"timestamp"`
	Version    string         `json:"version,omitempty"`
}

// PaginationInfo provides pagination metadata
type PaginationInfo struct {
	PageSize   int  `json:"page_size"`
	PageOffset int  `json:"page_offset"`
	HasNext    bool `json:"has_next"`
	HasPrev    bool `json:"has_prev"`
	NextOffset *int `json:"next_offset,omitempty"`
	PrevOffset *int `json:"prev_offset,omitempty"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error Error `json:"error"`
}

// Error represents an API error
type Error struct {
	Code      int       `json:"code"`
	Message   string    `json:"message"`
	Details   string    `json:"details,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id,omitempty"`
}

// Sandbox-related types

// SandboxResponse represents a sandbox in API responses
type SandboxResponse struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Image       string                 `json:"image"`
	Status      string                 `json:"status"`
	Resources   map[string]interface{} `json:"resources,omitempty"`
	Environment map[string]string      `json:"environment,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at,omitempty"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CreateSandboxRequest represents a request to create a sandbox
type CreateSandboxRequest struct {
	Name        string                 `json:"name,omitempty"`
	Image       string                 `json:"image"`
	Resources   map[string]interface{} `json:"resources,omitempty"`
	Environment map[string]string      `json:"environment,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	TTL         *time.Duration         `json:"ttl,omitempty"`
}

// CreateSandboxResponse represents the response after creating a sandbox
type CreateSandboxResponse struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Image     string    `json:"image"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// UpdateSandboxRequest represents a request to update a sandbox
type UpdateSandboxRequest struct {
	Name        *string                `json:"name,omitempty"`
	Resources   map[string]interface{} `json:"resources,omitempty"`
	Environment map[string]string      `json:"environment,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SandboxAction represents actions that can be performed on sandboxes
type SandboxAction struct {
	Action     string                 `json:"action"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Timeout    *time.Duration         `json:"timeout,omitempty"`
}

// BatchSandboxRequest represents a batch operation on sandboxes
type BatchSandboxRequest struct {
	Action     string                   `json:"action"`
	SandboxIDs []string                 `json:"sandbox_ids"`
	Parameters map[string]interface{}   `json:"parameters,omitempty"`
	Options    BatchRequestOptions      `json:"options,omitempty"`
}

// BatchRequestOptions provides options for batch operations
type BatchRequestOptions struct {
	ContinueOnError bool           `json:"continue_on_error"`
	Timeout         *time.Duration `json:"timeout,omitempty"`
	MaxConcurrency  int            `json:"max_concurrency,omitempty"`
}

// BatchSandboxResponse represents the response from a batch operation
type BatchSandboxResponse struct {
	Results   []BatchResult `json:"results"`
	Summary   BatchSummary  `json:"summary"`
	Timestamp time.Time     `json:"timestamp"`
}

// BatchResult represents the result of a single operation in a batch
type BatchResult struct {
	SandboxID string      `json:"sandbox_id"`
	Success   bool        `json:"success"`
	Result    interface{} `json:"result,omitempty"`
	Error     *Error      `json:"error,omitempty"`
}

// BatchSummary provides a summary of batch operation results
type BatchSummary struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

// File-related types

// FileResponse represents a file in API responses
type FileResponse struct {
	Path        string                 `json:"path"`
	Name        string                 `json:"name,omitempty"`
	Size        int64                  `json:"size"`
	ModTime     *time.Time             `json:"mod_time,omitempty"`
	IsDir       bool                   `json:"is_dir"`
	Content     string                 `json:"content,omitempty"`
	ContentType string                 `json:"content_type,omitempty"`
	Encoding    string                 `json:"encoding,omitempty"`
	Checksum    string                 `json:"checksum,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// UploadFileRequest represents a file upload request
type UploadFileRequest struct {
	Path        string `json:"path"`
	Content     string `json:"content"`
	Encoding    string `json:"encoding,omitempty"`
	Permissions string `json:"permissions,omitempty"`
	Overwrite   bool   `json:"overwrite"`
}

// FileListResponse represents a list of files
type FileListResponse struct {
	Path      string         `json:"path"`
	Files     []FileResponse `json:"files"`
	Total     int            `json:"total"`
	Timestamp time.Time      `json:"timestamp"`
}

// Tool-related types

// ToolResponse represents a tool in API responses
type ToolResponse struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Schema      map[string]interface{} `json:"schema"`
	Version     string                 `json:"version,omitempty"`
	Category    string                 `json:"category,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Deprecated  bool                   `json:"deprecated,omitempty"`
}

// ExecuteToolRequest represents a tool execution request
type ExecuteToolRequest struct {
	Arguments map[string]interface{} `json:"arguments,omitempty"`
	Options   ToolExecutionOptions   `json:"options,omitempty"`
}

// ToolExecutionOptions provides options for tool execution
type ToolExecutionOptions struct {
	Timeout     *time.Duration `json:"timeout,omitempty"`
	Async       bool           `json:"async"`
	Stream      bool           `json:"stream"`
	RetryPolicy *RetryPolicy   `json:"retry_policy,omitempty"`
}

// RetryPolicy defines retry behavior for tool execution
type RetryPolicy struct {
	MaxRetries    int           `json:"max_retries"`
	InitialDelay  time.Duration `json:"initial_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	MaxDelay      time.Duration `json:"max_delay"`
}

// ExecuteToolResponse represents a tool execution response
type ExecuteToolResponse struct {
	Result      interface{} `json:"result"`
	IsError     bool        `json:"is_error"`
	ExecutionID string      `json:"execution_id,omitempty"`
	Duration    time.Duration `json:"duration"`
	Timestamp   time.Time   `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Command execution types

// ExecuteCommandRequest represents a command execution request
type ExecuteCommandRequest struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Timeout     *time.Duration    `json:"timeout,omitempty"`
	Stream      bool              `json:"stream"`
	Input       string            `json:"input,omitempty"`
}

// ExecuteCommandResponse represents a command execution response
type ExecuteCommandResponse struct {
	ExitCode  int           `json:"exit_code"`
	Stdout    string        `json:"stdout"`
	Stderr    string        `json:"stderr"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
	StreamID  string        `json:"stream_id,omitempty"`
}

// RunCodeRequest represents a code execution request
type RunCodeRequest struct {
	Code        string            `json:"code"`
	Language    string            `json:"language,omitempty"`
	Filename    string            `json:"filename,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Packages    []string          `json:"packages,omitempty"`
	Timeout     *time.Duration    `json:"timeout,omitempty"`
	Stream      bool              `json:"stream"`
}

// RunCodeResponse represents a code execution response
type RunCodeResponse struct {
	Output      string        `json:"output"`
	Error       string        `json:"error,omitempty"`
	ExitCode    int           `json:"exit_code"`
	Language    string        `json:"language"`
	Duration    time.Duration `json:"duration"`
	Timestamp   time.Time     `json:"timestamp"`
	StreamID    string        `json:"stream_id,omitempty"`
}

// Resource-related types

// ResourceResponse represents a resource in API responses
type ResourceResponse struct {
	URI         string                 `json:"uri"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	MimeType    string                 `json:"mime_type,omitempty"`
	Size        int64                  `json:"size,omitempty"`
	Content     string                 `json:"content,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Prompt-related types

// PromptResponse represents a prompt in API responses
type PromptResponse struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Arguments   []PromptArgument       `json:"arguments,omitempty"`
	Template    string                 `json:"template,omitempty"`
	Version     string                 `json:"version,omitempty"`
	Category    string                 `json:"category,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// PromptArgument represents a prompt argument
type PromptArgument struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Type        string      `json:"type,omitempty"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
}

// GetPromptRequest represents a prompt generation request
type GetPromptRequest struct {
	Arguments map[string]interface{} `json:"arguments,omitempty"`
	Options   PromptOptions          `json:"options,omitempty"`
}

// PromptOptions provides options for prompt generation
type PromptOptions struct {
	Format   string `json:"format,omitempty"`
	Template string `json:"template,omitempty"`
}

// GetPromptResponse represents a prompt generation response
type GetPromptResponse struct {
	Messages  []PromptMessage        `json:"messages"`
	Template  string                 `json:"template,omitempty"`
	Variables map[string]interface{} `json:"variables,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// PromptMessage represents a message in a prompt
type PromptMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// V2-specific types (for future expansion)

// SandboxLogEntry represents a log entry from a sandbox
type SandboxLogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Source    string                 `json:"source"`
	Message   string                 `json:"message"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// SandboxLogsResponse represents sandbox logs
type SandboxLogsResponse struct {
	SandboxID string             `json:"sandbox_id"`
	Logs      []SandboxLogEntry  `json:"logs"`
	Total     int                `json:"total"`
	StartTime time.Time          `json:"start_time"`
	EndTime   time.Time          `json:"end_time"`
	Timestamp time.Time          `json:"timestamp"`
}

// SandboxMetrics represents metrics for a sandbox
type SandboxMetrics struct {
	SandboxID   string                 `json:"sandbox_id"`
	CPU         CPUMetrics             `json:"cpu"`
	Memory      MemoryMetrics          `json:"memory"`
	Disk        DiskMetrics            `json:"disk"`
	Network     NetworkMetrics         `json:"network"`
	Processes   int                    `json:"processes"`
	Uptime      time.Duration          `json:"uptime"`
	LastUpdated time.Time              `json:"last_updated"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CPUMetrics represents CPU usage metrics
type CPUMetrics struct {
	Usage     float64 `json:"usage"`     // Percentage
	UserTime  float64 `json:"user_time"` // Seconds
	SystemTime float64 `json:"system_time"` // Seconds
	Cores     int     `json:"cores"`
}

// MemoryMetrics represents memory usage metrics
type MemoryMetrics struct {
	Used      int64   `json:"used"`       // Bytes
	Available int64   `json:"available"`  // Bytes
	Total     int64   `json:"total"`      // Bytes
	Usage     float64 `json:"usage"`      // Percentage
	Swap      SwapMetrics `json:"swap"`
}

// SwapMetrics represents swap usage metrics
type SwapMetrics struct {
	Used  int64   `json:"used"`  // Bytes
	Total int64   `json:"total"` // Bytes
	Usage float64 `json:"usage"` // Percentage
}

// DiskMetrics represents disk usage metrics
type DiskMetrics struct {
	Used      int64   `json:"used"`      // Bytes
	Available int64   `json:"available"` // Bytes
	Total     int64   `json:"total"`     // Bytes
	Usage     float64 `json:"usage"`     // Percentage
	ReadOps   int64   `json:"read_ops"`
	WriteOps  int64   `json:"write_ops"`
	ReadBytes int64   `json:"read_bytes"`
	WriteBytes int64  `json:"write_bytes"`
}

// NetworkMetrics represents network usage metrics
type NetworkMetrics struct {
	BytesReceived int64 `json:"bytes_received"`
	BytesSent     int64 `json:"bytes_sent"`
	PacketsReceived int64 `json:"packets_received"`
	PacketsSent   int64 `json:"packets_sent"`
	Errors        int64 `json:"errors"`
	Drops         int64 `json:"drops"`
}

// Async operation types

// AsyncOperation represents an asynchronous operation
type AsyncOperation struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Status      string                 `json:"status"`
	Progress    float64                `json:"progress"`
	Result      interface{}            `json:"result,omitempty"`
	Error       *Error                 `json:"error,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// WebSocket message types

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	Type      string      `json:"type"`
	ID        string      `json:"id,omitempty"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// WebSocketEventType represents types of WebSocket events
type WebSocketEventType string

const (
	WSEventSandboxCreated   WebSocketEventType = "sandbox.created"
	WSEventSandboxUpdated   WebSocketEventType = "sandbox.updated"
	WSEventSandboxDeleted   WebSocketEventType = "sandbox.deleted"
	WSEventSandboxStatus    WebSocketEventType = "sandbox.status"
	WSEventCommandStart     WebSocketEventType = "command.start"
	WSEventCommandProgress  WebSocketEventType = "command.progress"
	WSEventCommandComplete  WebSocketEventType = "command.complete"
	WSEventStreamData       WebSocketEventType = "stream.data"
	WSEventStreamEnd        WebSocketEventType = "stream.end"
	WSEventError            WebSocketEventType = "error"
)

// WebSocketEvent represents a WebSocket event
type WebSocketEvent struct {
	Type      WebSocketEventType     `json:"type"`
	SandboxID string                 `json:"sandbox_id,omitempty"`
	Data      interface{}            `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}