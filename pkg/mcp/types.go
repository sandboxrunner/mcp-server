package mcp

import (
	"encoding/json"
	"time"
)

// JSON-RPC 2.0 message types
const (
	JSONRPC20Version = "2.0"
)

// JSON-RPC 2.0 base message
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
}

// JSON-RPC 2.0 request message
type JSONRPCRequest struct {
	JSONRPCMessage
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// JSON-RPC 2.0 response message
type JSONRPCResponse struct {
	JSONRPCMessage
	Result json.RawMessage `json:"result,omitempty"`
	Error  *JSONRPCError   `json:"error,omitempty"`
}

// JSON-RPC 2.0 notification message (no ID)
type JSONRPCNotification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSON-RPC 2.0 error object
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// MCP error codes
const (
	ErrorCodeParseError     = -32700
	ErrorCodeInvalidRequest = -32600
	ErrorCodeMethodNotFound = -32601
	ErrorCodeInvalidParams  = -32602
	ErrorCodeInternalError  = -32603
	
	// MCP-specific error codes
	ErrorCodeToolNotFound     = -32000
	ErrorCodeToolError        = -32001
	ErrorCodeValidationError  = -32002
	ErrorCodePermissionDenied = -32003
	ErrorCodeResourceNotFound = -32004
)

// MCP protocol methods
const (
	MethodInitialize     = "initialize"
	MethodInitialized    = "initialized"
	MethodShutdown       = "shutdown"
	MethodExit           = "exit"
	MethodListTools      = "tools/list"
	MethodCallTool       = "tools/call"
	MethodListResources  = "resources/list"
	MethodReadResource   = "resources/read"
	MethodListPrompts    = "prompts/list"
	MethodGetPrompt      = "prompts/get"
	MethodSamplePrompt   = "prompts/sample"
	MethodSetLevel       = "logging/setLevel"
	MethodLog            = "notifications/message"
)

// Initialize request parameters
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ClientInfo         `json:"clientInfo"`
}

// Client capabilities
type ClientCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
	Sampling     *SamplingCapability    `json:"sampling,omitempty"`
}

// Sampling capability
type SamplingCapability struct{}

// Client info
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Initialize response result
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// Server capabilities
type ServerCapabilities struct {
	Tools       *ToolsCapability    `json:"tools,omitempty"`
	Resources   *ResourcesCapability `json:"resources,omitempty"`
	Prompts     *PromptsCapability  `json:"prompts,omitempty"`
	Logging     *LoggingCapability  `json:"logging,omitempty"`
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

// Tools capability
type ToolsCapability struct {
	ListChanged *bool `json:"listChanged,omitempty"`
}

// Resources capability
type ResourcesCapability struct {
	Subscribe   *bool `json:"subscribe,omitempty"`
	ListChanged *bool `json:"listChanged,omitempty"`
}

// Prompts capability
type PromptsCapability struct {
	ListChanged *bool `json:"listChanged,omitempty"`
}

// Logging capability
type LoggingCapability struct{}

// Server info
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool definition
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema ToolInputSchema        `json:"inputSchema"`
}

// Tool input schema
type ToolInputSchema struct {
	Type       string                          `json:"type"`
	Properties map[string]ToolPropertySchema  `json:"properties,omitempty"`
	Required   []string                        `json:"required,omitempty"`
}

// Tool property schema
type ToolPropertySchema struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Default     interface{} `json:"default,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
}

// List tools result
type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// Call tool request parameters
type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// Call tool result
type CallToolResult struct {
	Content []ToolContent `json:"content"`
	IsError *bool         `json:"isError,omitempty"`
}

// Tool content types
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// Resource definition
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

// List resources result
type ListResourcesResult struct {
	Resources []Resource `json:"resources"`
}

// Read resource request parameters
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// Read resource result
type ReadResourceResult struct {
	Contents []ResourceContent `json:"contents"`
}

// Resource content
type ResourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// Prompt definition
type Prompt struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Arguments   []PromptArgument       `json:"arguments,omitempty"`
}

// Prompt argument
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    *bool  `json:"required,omitempty"`
}

// List prompts result
type ListPromptsResult struct {
	Prompts []Prompt `json:"prompts"`
}

// Get prompt request parameters
type GetPromptParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// Get prompt result
type GetPromptResult struct {
	Description string         `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// Prompt message
type PromptMessage struct {
	Role    string        `json:"role"`
	Content PromptContent `json:"content"`
}

// Prompt content
type PromptContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// Set level request parameters
type SetLevelParams struct {
	Level LogLevel `json:"level"`
}

// Log level enum
type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelNotice LogLevel = "notice" 
	LogLevelWarning LogLevel = "warning"
	LogLevelError LogLevel = "error"
	LogLevelCritical LogLevel = "critical"
	LogLevelAlert LogLevel = "alert"
	LogLevelEmergency LogLevel = "emergency"
)

// Log message notification parameters
type LogMessageParams struct {
	Level  LogLevel `json:"level"`
	Logger string   `json:"logger,omitempty"`
	Data   interface{} `json:"data"`
}

// Progress notification parameters
type ProgressParams struct {
	ProgressToken json.RawMessage `json:"progressToken"`
	Progress      float64         `json:"progress"`
	Total         *float64        `json:"total,omitempty"`
}

// Cancellation notification parameters
type CancellationParams struct {
	RequestID json.RawMessage `json:"requestId"`
}

// Stream types for progress reporting
type StreamResponse struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// Context for MCP operations
type RequestContext struct {
	RequestID   string
	StartTime   time.Time
	ClientInfo  *ClientInfo
	Capabilities *ClientCapabilities
}

// Server state
type ServerState string

const (
	ServerStateUninitialized ServerState = "uninitialized"
	ServerStateInitializing  ServerState = "initializing"
	ServerStateReady         ServerState = "ready"
	ServerStateShuttingDown  ServerState = "shutting_down"
	ServerStateStopped       ServerState = "stopped"
)