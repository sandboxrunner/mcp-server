package sandbox

import (
	"context"
)

// SandboxManagerInterface defines the contract for sandbox management operations
// This interface allows for easy testing and mocking of sandbox operations
type SandboxManagerInterface interface {
	// Core sandbox operations
	GetSandbox(sandboxID string) (*Sandbox, error)
	CreateSandbox(ctx context.Context, config SandboxConfig) (*Sandbox, error)
	ListSandboxes() ([]*Sandbox, error)
	StopSandbox(ctx context.Context, sandboxID string) error
	DeleteSandbox(ctx context.Context, sandboxID string) error
	
	// Sandbox metadata and logs
	GetSandboxLogs(ctx context.Context, sandboxID string) ([]byte, error)
	UpdateSandboxMetadata(sandboxID string, metadata map[string]interface{}) error
}

// Ensure that Manager implements SandboxManagerInterface
var _ SandboxManagerInterface = (*Manager)(nil)