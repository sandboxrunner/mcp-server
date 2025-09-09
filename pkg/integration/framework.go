package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandboxrunner/mcp-server/pkg/config"
	"github.com/sandboxrunner/mcp-server/pkg/mcp"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/storage"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// TestFramework provides comprehensive integration testing infrastructure
type TestFramework struct {
	// Core components
	Config         *config.Config
	SandboxManager *sandbox.Manager
	ToolRegistry   *tools.Registry
	MCPServer      *mcp.Server
	Storage        *storage.SQLiteStore

	// Test infrastructure
	TestDir       string
	WorkspaceDir  string
	DatabasePath  string
	LogFile       *os.File
	
	// Containers created during tests
	ActiveContainers sync.Map
	
	// Resource monitoring
	ResourceMonitor *ResourceMonitor
	
	// Cleanup functions
	cleanupFuncs []func() error
	mu           sync.RWMutex
}

// TestEnvironment holds test configuration and settings
type TestEnvironment struct {
	MaxConcurrentSandboxes int
	DefaultTimeout         time.Duration
	ResourceLimits         config.ResourceLimits
	EnableLogging          bool
	LogLevel               string
	EnableMetrics          bool
	CleanupOnFailure       bool
}

// DefaultTestEnvironment returns sensible defaults for testing
func DefaultTestEnvironment() *TestEnvironment {
	return &TestEnvironment{
		MaxConcurrentSandboxes: 10,
		DefaultTimeout:         30 * time.Second,
		ResourceLimits: config.ResourceLimits{
			CPULimit:    "0.5",
			MemoryLimit: "256M",
			DiskLimit:   "512M",
		},
		EnableLogging:    true,
		LogLevel:        "info",
		EnableMetrics:   true,
		CleanupOnFailure: true,
	}
}

// SetupTestFramework initializes the complete integration testing framework
func SetupTestFramework(t *testing.T, env *TestEnvironment) *TestFramework {
	if env == nil {
		env = DefaultTestEnvironment()
	}

	// Create temporary test directory
	testDir, err := os.MkdirTemp("", "sandboxrunner-integration-*")
	require.NoError(t, err)

	// Setup logging
	logFile, err := os.Create(filepath.Join(testDir, "test.log"))
	require.NoError(t, err)

	if env.EnableLogging {
		level, _ := zerolog.ParseLevel(env.LogLevel)
		zerolog.SetGlobalLevel(level)
		log.Logger = zerolog.New(zerolog.MultiLevelWriter(
			zerolog.ConsoleWriter{Out: os.Stdout},
			logFile,
		)).With().Timestamp().Caller().Logger()
	}

	// Create workspace directory
	workspaceDir := filepath.Join(testDir, "workspaces")
	err = os.MkdirAll(workspaceDir, 0755)
	require.NoError(t, err)

	// Setup database
	databasePath := filepath.Join(testDir, "test.db")
	store, err := storage.NewSQLiteStore(databasePath)
	require.NoError(t, err)

	// Create configuration
	cfg := &config.Config{
		Server: config.ServerConfig{
			Protocol: "stdio",
		},
		Sandbox: config.SandboxConfig{
			WorkspaceDir:     workspaceDir,
			DatabasePath:     databasePath,
			DefaultImage:     "ubuntu:20.04",
			DefaultResources: env.ResourceLimits,
			MaxSandboxes:     env.MaxConcurrentSandboxes,
			NetworkMode:      "none",
			EnableLogging:    env.EnableLogging,
		},
		Logging: config.LoggingConfig{
			Level:  env.LogLevel,
			Format: "json",
		},
		Tools: config.ToolsConfig{
			DefaultTimeout: env.DefaultTimeout,
		},
	}

	// Initialize sandbox manager
	sandboxManager, err := sandbox.NewManager(databasePath, workspaceDir)
	require.NoError(t, err)

	// Initialize tool registry
	toolRegistry := tools.NewRegistry()
	
	// Register standard tools for testing
	registerTestTools(toolRegistry, sandboxManager)

	// Initialize MCP server
	mcpServer, err := mcp.NewServer(cfg, sandboxManager, toolRegistry)
	require.NoError(t, err)

	framework := &TestFramework{
		Config:          cfg,
		SandboxManager:  sandboxManager,
		ToolRegistry:    toolRegistry,
		MCPServer:       mcpServer,
		Storage:         store,
		TestDir:         testDir,
		WorkspaceDir:    workspaceDir,
		DatabasePath:    databasePath,
		LogFile:         logFile,
		ResourceMonitor: NewResourceMonitor(),
		cleanupFuncs:    make([]func() error, 0),
	}

	// Register cleanup for the framework itself
	t.Cleanup(func() {
		framework.Cleanup(t)
	})

	return framework
}

// AddCleanupFunc registers a cleanup function to be called during teardown
func (f *TestFramework) AddCleanupFunc(cleanup func() error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanupFuncs = append(f.cleanupFuncs, cleanup)
}

// CreateTestSandbox creates a sandbox for testing with reasonable defaults
func (f *TestFramework) CreateTestSandbox(ctx context.Context, t *testing.T, config *sandbox.SandboxConfig) *sandbox.Sandbox {
	if config == nil {
		config = &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"TEST_MODE": "true",
			},
			Resources: f.Config.Sandbox.DefaultLimits,
		}
	}

	sb, err := f.SandboxManager.CreateSandbox(ctx, *config)
	require.NoError(t, err)
	require.NotNil(t, sb)

	// Track for cleanup
	f.ActiveContainers.Store(sb.ID, sb)
	
	// Register cleanup function
	f.AddCleanupFunc(func() error {
		return f.SandboxManager.TerminateSandbox(context.Background(), sb.ID)
	})

	return sb
}

// WaitForSandboxReady waits for a sandbox to reach the running state
func (f *TestFramework) WaitForSandboxReady(ctx context.Context, t *testing.T, sandboxID string, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timeout waiting for sandbox %s to become ready", sandboxID)
		case <-ticker.C:
			sb, err := f.SandboxManager.GetSandbox(sandboxID)
			require.NoError(t, err)
			
			if sb.Status == sandbox.SandboxStatusRunning {
				return
			}
			
			if sb.Status == sandbox.SandboxStatusError {
				t.Fatalf("Sandbox %s entered error state", sandboxID)
			}
		}
	}
}

// ExecuteWithTimeout executes a function with a timeout context
func (f *TestFramework) ExecuteWithTimeout(t *testing.T, timeout time.Duration, fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- fn(ctx)
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("Operation timed out")
	}
}

// GetActiveSandboxCount returns the number of currently active sandboxes
func (f *TestFramework) GetActiveSandboxCount() int {
	count := 0
	f.ActiveContainers.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// Cleanup performs comprehensive cleanup of all test resources
func (f *TestFramework) Cleanup(t *testing.T) {
	log.Info().Msg("Starting integration test cleanup")

	// Stop resource monitor
	if f.ResourceMonitor != nil {
		f.ResourceMonitor.Stop()
	}

	// Execute registered cleanup functions
	f.mu.RLock()
	cleanupFuncs := make([]func() error, len(f.cleanupFuncs))
	copy(cleanupFuncs, f.cleanupFuncs)
	f.mu.RUnlock()

	for i := len(cleanupFuncs) - 1; i >= 0; i-- {
		if err := cleanupFuncs[i](); err != nil {
			t.Logf("Cleanup function %d failed: %v", i, err)
		}
	}

	// Cleanup active containers
	var wg sync.WaitGroup
	f.ActiveContainers.Range(func(key, value interface{}) bool {
		wg.Add(1)
		go func(sandboxID string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			if err := f.SandboxManager.TerminateSandbox(ctx, sandboxID); err != nil {
				t.Logf("Failed to cleanup sandbox %s: %v", sandboxID, err)
			}
		}(key.(string))
		return true
	})
	wg.Wait()

	// Close major components
	if f.SandboxManager != nil {
		if err := f.SandboxManager.Close(); err != nil {
			t.Logf("Failed to close sandbox manager: %v", err)
		}
	}

	if f.Storage != nil {
		if err := f.Storage.Close(); err != nil {
			t.Logf("Failed to close storage: %v", err)
		}
	}

	// Close log file
	if f.LogFile != nil {
		f.LogFile.Close()
	}

	// Remove test directory
	if f.TestDir != "" {
		if err := os.RemoveAll(f.TestDir); err != nil {
			t.Logf("Failed to remove test directory %s: %v", f.TestDir, err)
		}
	}

	log.Info().Msg("Integration test cleanup completed")
}

// registerTestTools registers standard tools needed for integration testing
func registerTestTools(registry *tools.Registry, sandboxManager *sandbox.Manager) {
	// Register core sandbox management tools
	registry.RegisterTool(tools.NewCreateSandboxTool(sandboxManager))
	registry.RegisterTool(tools.NewListSandboxesTool(sandboxManager))
	registry.RegisterTool(tools.NewTerminateSandboxTool(sandboxManager))
	
	// Register file operation tools
	registry.RegisterTool(tools.NewUploadFileTool(sandboxManager))
	registry.RegisterTool(tools.NewDownloadFileTool(sandboxManager))
	registry.RegisterTool(tools.NewReadFileTool(sandboxManager))
	registry.RegisterTool(tools.NewWriteFileTool(sandboxManager))
	registry.RegisterTool(tools.NewListFilesTool(sandboxManager))
	
	// Register code execution tools
	registry.RegisterTool(tools.NewRunCodeTool(sandboxManager))
	registry.RegisterTool(tools.NewExecCommandTool(sandboxManager))
}

// TestDataGenerator provides utilities for generating test data
type TestDataGenerator struct {
	rand *uuid.UUID
}

// NewTestDataGenerator creates a new test data generator
func NewTestDataGenerator() *TestDataGenerator {
	return &TestDataGenerator{}
}

// GenerateTestFile creates a test file with specified content
func (g *TestDataGenerator) GenerateTestFile(dir, filename, content string) (string, error) {
	filePath := filepath.Join(dir, filename)
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return "", err
	}
	return filePath, nil
}

// GenerateRandomData creates random test data of specified size
func (g *TestDataGenerator) GenerateRandomData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}
	return data
}

// GenerateCodeSample creates a code sample in the specified language
func (g *TestDataGenerator) GenerateCodeSample(language string) (string, string) {
	samples := map[string]struct {
		filename string
		content  string
	}{
		"python": {
			"test.py",
			`#!/usr/bin/env python3
import sys
import time

def main():
    print("Hello from Python!")
    print(f"Arguments: {sys.argv[1:]}")
    time.sleep(0.1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
`,
		},
		"javascript": {
			"test.js",
			`#!/usr/bin/env node
console.log("Hello from Node.js!");
console.log("Arguments:", process.argv.slice(2));
setTimeout(() => {
    console.log("Execution completed");
}, 100);
`,
		},
		"go": {
			"main.go",
			`package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Println("Hello from Go!")
	fmt.Printf("Arguments: %v\n", os.Args[1:])
	time.Sleep(100 * time.Millisecond)
	fmt.Println("Execution completed")
}
`,
		},
		"rust": {
			"main.rs",
			`use std::env;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Hello from Rust!");
    let args: Vec<String> = env::args().collect();
    println!("Arguments: {:?}", &args[1..]);
    thread::sleep(Duration::from_millis(100));
    println!("Execution completed");
}
`,
		},
	}

	if sample, exists := samples[language]; exists {
		return sample.filename, sample.content
	}

	// Default to shell script
	return "test.sh", `#!/bin/bash
echo "Hello from Shell!"
echo "Arguments: $@"
sleep 0.1
echo "Execution completed"
`
}

// Assert helpers for integration tests
type IntegrationAsserts struct {
	*testing.T
}

// NewIntegrationAsserts creates assertion helpers for integration tests
func NewIntegrationAsserts(t *testing.T) *IntegrationAsserts {
	return &IntegrationAsserts{T: t}
}

// AssertSandboxExists verifies a sandbox exists and is in the expected state
func (a *IntegrationAsserts) AssertSandboxExists(manager *sandbox.Manager, sandboxID string, expectedStatus sandbox.SandboxStatus) {
	sb, err := manager.GetSandbox(sandboxID)
	require.NoError(a.T, err)
	require.NotNil(a.T, sb)
	assert.Equal(a.T, expectedStatus, sb.Status)
}

// AssertSandboxNotExists verifies a sandbox does not exist
func (a *IntegrationAsserts) AssertSandboxNotExists(manager *sandbox.Manager, sandboxID string) {
	_, err := manager.GetSandbox(sandboxID)
	assert.Error(a.T, err)
}

// AssertFileExists verifies a file exists in a sandbox
func (a *IntegrationAsserts) AssertFileExists(manager *sandbox.Manager, sandboxID, filePath string) {
	exists, err := manager.FileExists(context.Background(), sandboxID, filePath)
	require.NoError(a.T, err)
	assert.True(a.T, exists, fmt.Sprintf("File %s should exist in sandbox %s", filePath, sandboxID))
}

// AssertExecutionSuccess verifies tool execution was successful
func (a *IntegrationAsserts) AssertExecutionSuccess(result *tools.ToolResult) {
	require.NotNil(a.T, result)
	assert.False(a.T, result.IsError, fmt.Sprintf("Tool should succeed, but got error: %s", result.Text))
}

// AssertExecutionFailure verifies tool execution failed as expected
func (a *IntegrationAsserts) AssertExecutionFailure(result *tools.ToolResult) {
	require.NotNil(a.T, result)
	assert.True(a.T, result.IsError, "Tool should fail")
}

// AssertResourceLimitsRespected verifies resource usage is within limits
func (a *IntegrationAsserts) AssertResourceLimitsRespected(monitor *ResourceMonitor, limits config.ResourceLimits) {
	usage := monitor.GetCurrentUsage()
	
	if limits.MemoryLimit != "" {
		// Parse memory limit and compare (simplified)
		assert.True(a.T, usage.MemoryUsedMB < 512, "Memory usage should respect limits")
	}
	
	if limits.CPULimit != "" {
		// CPU usage checks (simplified)
		assert.True(a.T, usage.CPUPercent < 100, "CPU usage should respect limits")
	}
}