package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/common"
)

// Client provides a unified interface to the sandbox system
type Client struct {
	manager   *Manager
	executor  *ProcessExecutor
	filesystem *FileSystemManager
}

// Config holds configuration for the sandbox client
type Config struct {
	WorkspaceDir string `json:"workspace_dir"`
	DatabasePath string `json:"database_path"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() Config {
	homeDir, _ := os.UserHomeDir()
	baseDir := filepath.Join(homeDir, ".sandboxrunner")
	
	return Config{
		WorkspaceDir: filepath.Join(baseDir, "workspaces"),
		DatabasePath: filepath.Join(baseDir, "sandboxrunner.db"),
	}
}

// NewClient creates a new sandbox client
func NewClient(config Config) (*Client, error) {
	// Ensure base directories exist
	if err := common.EnsureDirectoryExists(filepath.Dir(config.DatabasePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	if err := common.EnsureDirectoryExists(config.WorkspaceDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace directory: %w", err)
	}

	// Initialize manager
	manager, err := NewManager(config.DatabasePath, config.WorkspaceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox manager: %w", err)
	}

	// Initialize process executor
	executor, err := NewProcessExecutor(manager.db, manager)
	if err != nil {
		manager.Close()
		return nil, fmt.Errorf("failed to create process executor: %w", err)
	}

	// Initialize filesystem manager
	filesystem := NewFileSystemManager(manager)

	client := &Client{
		manager:    manager,
		executor:   executor,
		filesystem: filesystem,
	}

	log.Info().
		Str("workspace_dir", config.WorkspaceDir).
		Str("database_path", config.DatabasePath).
		Msg("Sandbox client initialized")

	return client, nil
}

// Sandbox Operations

// CreateSandbox creates a new sandbox with the given configuration
func (c *Client) CreateSandbox(ctx context.Context, config SandboxConfig) (*Sandbox, error) {
	return c.manager.CreateSandbox(ctx, config)
}

// GetSandbox retrieves a sandbox by ID
func (c *Client) GetSandbox(sandboxID string) (*Sandbox, error) {
	return c.manager.GetSandbox(sandboxID)
}

// ListSandboxes returns all sandboxes
func (c *Client) ListSandboxes() ([]*Sandbox, error) {
	return c.manager.ListSandboxes()
}

// StopSandbox stops a running sandbox
func (c *Client) StopSandbox(ctx context.Context, sandboxID string) error {
	return c.manager.StopSandbox(ctx, sandboxID)
}

// DeleteSandbox removes a sandbox
func (c *Client) DeleteSandbox(ctx context.Context, sandboxID string) error {
	return c.manager.DeleteSandbox(ctx, sandboxID)
}

// GetSandboxLogs retrieves logs from a sandbox
func (c *Client) GetSandboxLogs(ctx context.Context, sandboxID string) ([]byte, error) {
	return c.manager.GetSandboxLogs(ctx, sandboxID)
}

// UpdateSandboxMetadata updates sandbox metadata
func (c *Client) UpdateSandboxMetadata(sandboxID string, metadata map[string]interface{}) error {
	return c.manager.UpdateSandboxMetadata(sandboxID, metadata)
}

// Process Operations

// ExecuteProcess executes a process in the specified sandbox
func (c *Client) ExecuteProcess(ctx context.Context, req ProcessExecRequest) (*ProcessExecResponse, error) {
	return c.executor.ExecuteProcess(ctx, req)
}

// ExecuteCommand is a convenience method to execute a simple command
func (c *Client) ExecuteCommand(ctx context.Context, sandboxID string, command []string, options ...ProcessOption) (*ProcessExecResponse, error) {
	req := ProcessExecRequest{
		SandboxID: sandboxID,
		Command:   command,
	}

	// Apply options
	for _, opt := range options {
		opt(&req)
	}

	return c.executor.ExecuteProcess(ctx, req)
}

// GetProcess retrieves a process by ID
func (c *Client) GetProcess(processID string) (*Process, error) {
	return c.executor.GetProcess(processID)
}

// ListProcesses lists all processes for a sandbox
func (c *Client) ListProcesses(sandboxID string) ([]*Process, error) {
	return c.executor.ListProcesses(sandboxID)
}

// KillProcess terminates a running process
func (c *Client) KillProcess(ctx context.Context, processID string) error {
	return c.executor.KillProcess(ctx, processID)
}

// GetProcessOutput retrieves stdout and stderr for a process
func (c *Client) GetProcessOutput(processID string) (string, string, error) {
	return c.executor.GetProcessOutput(processID)
}

// StreamProcessOutput streams real-time output from a process
func (c *Client) StreamProcessOutput(ctx context.Context, processID string) (<-chan string, error) {
	return c.executor.StreamProcessOutput(ctx, processID)
}

// File System Operations

// UploadFile uploads a file to the sandbox
func (c *Client) UploadFile(ctx context.Context, sandboxID, containerPath string, data []byte, mode os.FileMode) error {
	return c.filesystem.UploadFile(ctx, sandboxID, containerPath, data, mode)
}

// DownloadFile downloads a file from the sandbox
func (c *Client) DownloadFile(ctx context.Context, sandboxID, containerPath string) ([]byte, error) {
	return c.filesystem.DownloadFile(ctx, sandboxID, containerPath)
}

// DeleteFile deletes a file from the sandbox
func (c *Client) DeleteFile(ctx context.Context, sandboxID, containerPath string) error {
	return c.filesystem.DeleteFile(ctx, sandboxID, containerPath)
}

// CreateDirectory creates a directory in the sandbox
func (c *Client) CreateDirectory(ctx context.Context, sandboxID, containerPath string, mode os.FileMode) error {
	return c.filesystem.CreateDirectory(ctx, sandboxID, containerPath, mode)
}

// DeleteDirectory deletes a directory from the sandbox
func (c *Client) DeleteDirectory(ctx context.Context, sandboxID, containerPath string) error {
	return c.filesystem.DeleteDirectory(ctx, sandboxID, containerPath)
}

// StatFile gets file information
func (c *Client) StatFile(ctx context.Context, sandboxID, containerPath string) (*FileInfo, error) {
	return c.filesystem.StatFile(ctx, sandboxID, containerPath)
}

// ListFiles lists files in a directory
func (c *Client) ListFiles(ctx context.Context, sandboxID, containerPath string) ([]*FileInfo, error) {
	return c.filesystem.ListFiles(ctx, sandboxID, containerPath)
}

// FindInFiles searches for a pattern in files
func (c *Client) FindInFiles(ctx context.Context, sandboxID, containerPath, pattern string) ([]*FileSearchResult, error) {
	return c.filesystem.FindInFiles(ctx, sandboxID, containerPath, pattern)
}

// ReplaceInFiles replaces text in files
func (c *Client) ReplaceInFiles(ctx context.Context, sandboxID, containerPath, pattern, newString string) (int, error) {
	return c.filesystem.ReplaceInFiles(ctx, sandboxID, containerPath, pattern, newString)
}

// CopyFile copies a file within the sandbox
func (c *Client) CopyFile(ctx context.Context, sandboxID, srcPath, dstPath string) error {
	return c.filesystem.CopyFile(ctx, sandboxID, srcPath, dstPath)
}

// MoveFile moves a file within the sandbox
func (c *Client) MoveFile(ctx context.Context, sandboxID, srcPath, dstPath string) error {
	return c.filesystem.MoveFile(ctx, sandboxID, srcPath, dstPath)
}

// Convenience Methods

// CreateBasicSandbox creates a sandbox with basic configuration
func (c *Client) CreateBasicSandbox(ctx context.Context, workspaceDir string) (*Sandbox, error) {
	config := SandboxConfig{
		Image:        "basic",
		WorkspaceDir: workspaceDir,
		Environment: map[string]string{
			"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME": "/root",
		},
		Resources: ResourceLimits{
			CPULimit:    "1",
			MemoryLimit: "512M",
			DiskLimit:   "1G",
		},
		NetworkMode:   "none",
		EnableLogging: true,
	}

	return c.manager.CreateSandbox(ctx, config)
}

// RunCommand runs a command in a sandbox and waits for completion
func (c *Client) RunCommand(ctx context.Context, sandboxID string, command []string, timeout time.Duration) (*ProcessExecResponse, error) {
	// Set up timeout
	var execCtx context.Context
	var cancel context.CancelFunc

	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	} else {
		execCtx = ctx
	}

	req := ProcessExecRequest{
		SandboxID: sandboxID,
		Command:   command,
		Timeout:   &timeout,
	}

	return c.executor.ExecuteProcess(execCtx, req)
}

// WriteFile is a convenience method to write text content to a file
func (c *Client) WriteFile(ctx context.Context, sandboxID, path, content string) error {
	return c.filesystem.UploadFile(ctx, sandboxID, path, []byte(content), 0644)
}

// ReadFile is a convenience method to read text content from a file
func (c *Client) ReadFile(ctx context.Context, sandboxID, path string) (string, error) {
	data, err := c.filesystem.DownloadFile(ctx, sandboxID, path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetSystemMetrics returns system metrics
func (c *Client) GetSystemMetrics() (*common.SystemMetrics, error) {
	sandboxes, err := c.manager.ListSandboxes()
	if err != nil {
		return nil, err
	}

	activeSandboxes := int64(0)
	runningProcesses := int64(0)

	for _, sandbox := range sandboxes {
		if sandbox.Status == SandboxStatusRunning {
			activeSandboxes++
		}

		processes, err := c.executor.ListProcesses(sandbox.ID)
		if err == nil {
			for _, process := range processes {
				if process.Status == ProcessStatusRunning {
					runningProcesses++
				}
			}
		}
	}

	metrics := &common.SystemMetrics{
		ActiveSandboxes:  activeSandboxes,
		RunningProcesses: runningProcesses,
		Timestamp:        time.Now(),
		// Note: In a production system, you would collect actual resource metrics
		MemoryUsage: 0,
		CPUUsage:    0,
		DiskUsage:   0,
	}

	return metrics, nil
}

// Health returns system health status
func (c *Client) Health() (*common.HealthStatus, error) {
	status := &common.HealthStatus{
		Status:    "healthy",
		Timestamp: time.Now(),
		Version:   "1.0.0",
		Uptime:    time.Since(time.Now()), // Would be calculated from start time
		Metrics:   make(map[string]interface{}),
	}

	// Add basic metrics
	metrics, err := c.GetSystemMetrics()
	if err != nil {
		status.Status = "degraded"
		status.Metrics["error"] = err.Error()
	} else {
		status.Metrics["active_sandboxes"] = metrics.ActiveSandboxes
		status.Metrics["running_processes"] = metrics.RunningProcesses
	}

	return status, nil
}

// Close cleans up client resources
func (c *Client) Close() error {
	log.Info().Msg("Shutting down sandbox client")
	
	if c.manager != nil {
		return c.manager.Close()
	}
	
	return nil
}

// ProcessOption represents an option for process execution
type ProcessOption func(*ProcessExecRequest)

// WithEnvironment sets environment variables for the process
func WithEnvironment(env map[string]string) ProcessOption {
	return func(req *ProcessExecRequest) {
		req.Environment = env
	}
}

// WithWorkingDirectory sets the working directory for the process
func WithWorkingDirectory(dir string) ProcessOption {
	return func(req *ProcessExecRequest) {
		req.WorkingDir = dir
	}
}

// WithTimeout sets a timeout for the process
func WithTimeout(timeout time.Duration) ProcessOption {
	return func(req *ProcessExecRequest) {
		req.Timeout = &timeout
	}
}

// WithMetadata sets metadata for the process
func WithMetadata(metadata map[string]interface{}) ProcessOption {
	return func(req *ProcessExecRequest) {
		req.Metadata = metadata
	}
}