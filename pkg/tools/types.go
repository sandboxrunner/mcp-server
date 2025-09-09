package tools

import (
	"context"
	"fmt"
	"time"
)

// Tool represents a tool that can be called via MCP
type Tool interface {
	// Name returns the tool name
	Name() string

	// Description returns the tool description
	Description() string

	// Schema returns the JSON schema for tool parameters
	Schema() map[string]interface{}

	// Execute runs the tool with the given parameters
	Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error)
}

// ToolResult represents the result of tool execution
type ToolResult struct {
	Text     string                 `json:"text"`
	IsError  bool                   `json:"is_error"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ToolError represents an error during tool execution
type ToolError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *ToolError) Error() string {
	return e.Message
}

// NewToolError creates a new tool error
func NewToolError(code, message, details string) *ToolError {
	return &ToolError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// ToolContext provides context for tool execution
type ToolContext struct {
	RequestID     string
	StartTime     time.Time
	UserAgent     string
	ClientVersion string
}

// ExecutionOptions provides options for tool execution
type ExecutionOptions struct {
	Timeout   time.Duration
	MaxOutput int
}

// DefaultExecutionOptions returns default execution options
func DefaultExecutionOptions() ExecutionOptions {
	return ExecutionOptions{
		Timeout:   30 * time.Second,
		MaxOutput: 1024 * 1024, // 1MB
	}
}

// ValidationError represents a parameter validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Progress represents progress information for long-running operations
type Progress struct {
	Current int    `json:"current"`
	Total   int    `json:"total"`
	Message string `json:"message"`
}

// StreamResult represents a streaming result from a tool
type StreamResult struct {
	Type     string      `json:"type"` // "data", "error", "progress", "complete"
	Data     interface{} `json:"data"`
	Progress *Progress   `json:"progress,omitempty"`
	Error    *ToolError  `json:"error,omitempty"`
}

// StreamingTool extends Tool to support streaming results
type StreamingTool interface {
	Tool

	// ExecuteStreaming runs the tool with streaming results
	ExecuteStreaming(ctx context.Context, params map[string]interface{}) (<-chan StreamResult, error)
}

// BaseTool provides common functionality for tools
type BaseTool struct {
	name        string
	description string
	schema      map[string]interface{}
}

// NewBaseTool creates a new base tool
func NewBaseTool(name, description string, schema map[string]interface{}) *BaseTool {
	return &BaseTool{
		name:        name,
		description: description,
		schema:      schema,
	}
}

// Name returns the tool name
func (bt *BaseTool) Name() string {
	return bt.name
}

// Description returns the tool description
func (bt *BaseTool) Description() string {
	return bt.description
}

// Schema returns the tool schema
func (bt *BaseTool) Schema() map[string]interface{} {
	return bt.schema
}

// Common parameter types and schemas

// SandboxIDParam represents a sandbox ID parameter
type SandboxIDParam struct {
	SandboxID string `json:"sandbox_id" validate:"required"`
}

// CommandParam represents a command parameter
type CommandParam struct {
	Command string `json:"command" validate:"required"`
}

// FilePathParam represents a file path parameter
type FilePathParam struct {
	Path string `json:"path" validate:"required"`
}

// FileContentParam represents file content parameter
type FileContentParam struct {
	Path     string `json:"path" validate:"required"`
	Content  string `json:"content" validate:"required"`
	Encoding string `json:"encoding,omitempty"` // base64, utf8
}

// DirectoryParam represents a directory parameter
type DirectoryParam struct {
	Path      string `json:"path" validate:"required"`
	Recursive bool   `json:"recursive,omitempty"`
}

// CodeParam represents code execution parameter
type CodeParam struct {
	Code     string `json:"code" validate:"required"`
	Language string `json:"language,omitempty"`
}

// SandboxConfigParam represents sandbox configuration
type SandboxConfigParam struct {
	Image        string            `json:"image,omitempty"`
	WorkspaceDir string            `json:"workspace_dir,omitempty"`
	Environment  map[string]string `json:"environment,omitempty"`
	CPULimit     string            `json:"cpu_limit,omitempty"`
	MemoryLimit  string            `json:"memory_limit,omitempty"`
	DiskLimit    string            `json:"disk_limit,omitempty"`
	NetworkMode  string            `json:"network_mode,omitempty"`
}

// Common schemas

// SandboxIDSchema returns schema for sandbox ID parameter
func SandboxIDSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
		},
		"required": []string{"sandbox_id"},
	}
}

// CommandSchema returns schema for command parameter
func CommandSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"command": map[string]interface{}{
				"type":        "string",
				"description": "The shell command to execute",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for command execution",
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for the command",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Command timeout in seconds",
				"default":     30,
			},
		},
		"required": []string{"sandbox_id", "command"},
	}
}

// CodeSchema returns schema for code execution parameter
func CodeSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "The code to execute",
			},
			"language": map[string]interface{}{
				"type":        "string",
				"description": "Programming language (python, javascript, bash, etc.)",
				"enum":        []string{"python", "javascript", "typescript", "bash", "sh", "go", "rust", "java", "cpp", "c"},
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for code execution",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds",
				"default":     30,
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// FilePathSchema returns schema for file path parameter
func FilePathSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"path": map[string]interface{}{
				"type":        "string",
				"description": "The file or directory path",
			},
		},
		"required": []string{"sandbox_id", "path"},
	}
}

// FileContentSchema returns schema for file content parameter
func FileContentSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"path": map[string]interface{}{
				"type":        "string",
				"description": "The file path",
			},
			"content": map[string]interface{}{
				"type":        "string",
				"description": "The file content",
			},
			"encoding": map[string]interface{}{
				"type":        "string",
				"description": "Content encoding (base64 or utf8)",
				"enum":        []string{"base64", "utf8"},
				"default":     "utf8",
			},
		},
		"required": []string{"sandbox_id", "path", "content"},
	}
}

// SandboxConfigSchema returns schema for sandbox configuration
func SandboxConfigSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"image": map[string]interface{}{
				"type":        "string",
				"description": "Container image to use for the sandbox",
				"default":     "ubuntu:22.04",
			},
			"workspace_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory inside the sandbox",
				"default":     "/workspace",
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables",
			},
			"cpu_limit": map[string]interface{}{
				"type":        "string",
				"description": "CPU limit (e.g., '1.0' for 1 CPU)",
			},
			"memory_limit": map[string]interface{}{
				"type":        "string",
				"description": "Memory limit (e.g., '1G' for 1GB)",
			},
			"disk_limit": map[string]interface{}{
				"type":        "string",
				"description": "Disk limit (e.g., '10G' for 10GB)",
			},
			"network_mode": map[string]interface{}{
				"type":        "string",
				"description": "Network mode (none, bridge, host)",
				"enum":        []string{"none", "bridge", "host"},
				"default":     "none",
			},
		},
		"required": []string{},
	}
}
