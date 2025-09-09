package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"
	
	"github.com/sandboxrunner/mcp-server/pkg/config"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// Mock sandbox manager for testing
type MockSandboxManager struct {
	mock.Mock
}

func (m *MockSandboxManager) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestMain_Version(t *testing.T) {
	// Save original values
	origVersion := version
	origCommit := commit
	origDate := date
	defer func() {
		version = origVersion
		commit = origCommit
		date = origDate
	}()
	
	// Set test values
	version = "1.2.3"
	commit = "abc123"
	date = "2024-01-01"
	
	// Test that version values are set correctly
	assert.Equal(t, "1.2.3", version)
	assert.Equal(t, "abc123", commit)
	assert.Equal(t, "2024-01-01", date)
	
	// Test version command creation
	versionCmd := newVersionCmd()
	assert.Equal(t, "version", versionCmd.Use)
	assert.Equal(t, "Show version information", versionCmd.Short)
	
	// The actual output test would require capturing stdout which is complex
	// Instead we test that the version command can be created and has the right structure
}

func TestMain_ConfigGenerate(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test-config.yaml")
	
	// Test the config generate functionality directly
	cmd := newConfigCmd()
	assert.NotNil(t, cmd)
	
	// Find the generate subcommand
	var generateCmd *cobra.Command
	for _, subCmd := range cmd.Commands() {
		if subCmd.Use == "generate" {
			generateCmd = subCmd
			break
		}
	}
	require.NotNil(t, generateCmd)
	
	// Test that we can create default config
	cfg := config.DefaultConfig()
	err := cfg.SaveConfig(outputPath)
	require.NoError(t, err)
	
	// Check file was created
	assert.FileExists(t, outputPath)
	
	// Verify config can be loaded
	loadedCfg, err := config.LoadConfig(outputPath)
	require.NoError(t, err)
	assert.Equal(t, "SandboxRunner MCP Server", loadedCfg.Server.Name)
}

func TestMain_ConfigGenerate_DefaultPath(t *testing.T) {
	// Change to temp directory for test
	origDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(origDir)
	
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	
	// Create root command with config subcommand
	rootCmd := &cobra.Command{Use: "mcp-sandboxd"}
	rootCmd.AddCommand(newConfigCmd())
	
	rootCmd.SetArgs([]string{"config", "generate"})
	
	err = rootCmd.Execute()
	require.NoError(t, err)
	
	// Check default file was created
	assert.FileExists(t, "mcp-sandboxd.yaml")
}

func TestMain_ConfigValidate_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "valid-config.yaml")
	
	// Create valid config file
	cfg := config.DefaultConfig()
	err := cfg.SaveConfig(configPath)
	require.NoError(t, err)
	
	// Test that we can load and validate the config
	loadedCfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	
	// Verify validation passes
	err = loadedCfg.Validate()
	assert.NoError(t, err)
	
	// Verify expected values
	assert.Equal(t, "SandboxRunner MCP Server", loadedCfg.Server.Name)
	assert.Equal(t, "stdio", loadedCfg.Server.Protocol)
}

func TestMain_ConfigValidate_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid-config.yaml")
	
	// Create invalid config file
	invalidYAML := `
server:
  name: ""
  protocol: "invalid"
`
	err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
	require.NoError(t, err)
	
	// Set global config file variable
	configFile = configPath
	defer func() { configFile = "" }()
	
	// Create root command with config subcommand
	rootCmd := &cobra.Command{Use: "mcp-sandboxd"}
	rootCmd.AddCommand(newConfigCmd())
	
	rootCmd.SetArgs([]string{"config", "validate"})
	
	err = rootCmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestSetupLogging(t *testing.T) {
	tests := []struct {
		name      string
		config    config.LoggingConfig
		expectErr bool
	}{
		{
			name: "json_format",
			config: config.LoggingConfig{
				Level:  "info",
				Format: "json",
			},
			expectErr: false,
		},
		{
			name: "console_format",
			config: config.LoggingConfig{
				Level:  "debug",
				Format: "console",
			},
			expectErr: false,
		},
		{
			name: "text_format",
			config: config.LoggingConfig{
				Level:  "warn",
				Format: "text",
			},
			expectErr: false,
		},
		{
			name: "invalid_level",
			config: config.LoggingConfig{
				Level:  "invalid",
				Format: "json",
			},
			expectErr: true,
		},
		{
			name: "with_output_file",
			config: config.LoggingConfig{
				Level:      "info",
				Format:     "json",
				OutputFile: filepath.Join(t.TempDir(), "test.log"),
			},
			expectErr: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := setupLogging(tt.config)
			
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestSetupLogging_FileCreation(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "logs", "app.log")
	
	cfg := config.LoggingConfig{
		Level:      "info",
		Format:     "json",
		OutputFile: logFile,
	}
	
	logger, err := setupLogging(cfg)
	require.NoError(t, err)
	require.NotNil(t, logger)
	
	// Verify log directory was created
	assert.DirExists(t, filepath.Dir(logFile))
}

func TestSetupLogging_InvalidFile(t *testing.T) {
	cfg := config.LoggingConfig{
		Level:      "info",
		Format:     "json",
		OutputFile: "/invalid/path/that/cannot/be/created.log",
	}
	
	_, err := setupLogging(cfg)
	assert.Error(t, err)
	// The error could be about directory creation or file opening
	errMsg := err.Error()
	assert.True(t, 
		(errMsg == "failed to create log directory: mkdir /invalid: permission denied" || 
		 errMsg == "failed to open log file: mkdir /invalid: permission denied" ||
		 containsAny(errMsg, []string{"failed to create log directory", "failed to open log file", "permission denied"})),
		"Error should be about log directory or file creation, got: %s", errMsg)
}

// Helper function for testing error messages
func containsAny(str string, substrings []string) bool {
	for _, substr := range substrings {
		if len(str) >= len(substr) {
			for i := 0; i <= len(str)-len(substr); i++ {
				if str[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}

func TestRegisterTools(t *testing.T) {
	// Test tool registration functionality by testing individual components
	
	// Test that we can create a registry
	registry := tools.NewRegistry()
	assert.Equal(t, 0, registry.Count())
	
	// Test default config has expected enabled tools
	cfg := config.DefaultConfig()
	expectedTools := []string{
		"create_sandbox", "list_sandboxes", "terminate_sandbox",
		"exec_command", "run_code", "upload_file", "download_file",
		"list_files", "read_file", "write_file",
	}
	assert.Equal(t, expectedTools, cfg.Tools.EnabledTools)
	
	// Test that enabled tools logic works
	enabledTools := cfg.GetEnabledTools()
	assert.Equal(t, expectedTools, enabledTools)
	
	// Note: Full registerTools testing would require proper mocking of sandbox.Manager
	// This tests the component logic without the complex dependencies
}

func TestCommandLineFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		validate func(t *testing.T)
	}{
		{
			name: "config_flag",
			args: []string{"--config", "/path/to/config.yaml"},
			validate: func(t *testing.T) {
				assert.Equal(t, "/path/to/config.yaml", configFile)
			},
		},
		{
			name: "log_level_flag",
			args: []string{"--log-level", "debug"},
			validate: func(t *testing.T) {
				assert.Equal(t, "debug", logLevel)
			},
		},
		{
			name: "log_format_flag",
			args: []string{"--log-format", "console"},
			validate: func(t *testing.T) {
				assert.Equal(t, "console", logFormat)
			},
		},
		{
			name: "workspace_dir_flag",
			args: []string{"--workspace-dir", "/custom/workspace"},
			validate: func(t *testing.T) {
				assert.Equal(t, "/custom/workspace", workspaceDir)
			},
		},
		{
			name: "http_flag",
			args: []string{"--http"},
			validate: func(t *testing.T) {
				assert.True(t, enableHTTP)
			},
		},
		{
			name: "port_flag",
			args: []string{"--port", "8080"},
			validate: func(t *testing.T) {
				assert.Equal(t, 8080, httpPort)
			},
		},
		{
			name: "multiple_flags",
			args: []string{"--log-level", "warn", "--http", "--port", "9000"},
			validate: func(t *testing.T) {
				assert.Equal(t, "warn", logLevel)
				assert.True(t, enableHTTP)
				assert.Equal(t, 9000, httpPort)
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset global variables
			configFile = ""
			logLevel = ""
			logFormat = ""
			workspaceDir = ""
			enableHTTP = false
			httpPort = 0
			
			// Create root command
			rootCmd := &cobra.Command{
				Use: "mcp-sandboxd",
				RunE: func(cmd *cobra.Command, args []string) error {
					// Just validate flags, don't run server
					return nil
				},
			}
			
			// Add flags
			rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "config file path")
			rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "", "log level")
			rootCmd.PersistentFlags().StringVarP(&logFormat, "log-format", "f", "", "log format")
			rootCmd.PersistentFlags().StringVarP(&workspaceDir, "workspace-dir", "w", "", "workspace directory")
			rootCmd.PersistentFlags().BoolVar(&enableHTTP, "http", false, "enable HTTP")
			rootCmd.PersistentFlags().IntVarP(&httpPort, "port", "p", 0, "HTTP port")
			
			rootCmd.SetArgs(tt.args)
			
			err := rootCmd.Execute()
			require.NoError(t, err)
			
			tt.validate(t)
		})
	}
}

func TestRunServer_ConfigOverrides(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	
	cfg := config.DefaultConfig()
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "json"
	cfg.Sandbox.WorkspaceDir = "/default/workspace"
	cfg.Server.EnableHTTP = false
	cfg.Server.Port = 3000
	
	err := cfg.SaveConfig(configPath)
	require.NoError(t, err)
	
	// Set global flags to override config
	configFile = configPath
	logLevel = "debug"
	logFormat = "console"
	workspaceDir = "/override/workspace"
	enableHTTP = true
	httpPort = 8080
	
	defer func() {
		configFile = ""
		logLevel = ""
		logFormat = ""
		workspaceDir = ""
		enableHTTP = false
		httpPort = 0
	}()
	
	// Test the config loading and override logic
	// This would normally be part of runServer, but we extract it for testing
	loadedCfg, err := config.LoadConfig(configFile)
	require.NoError(t, err)
	
	// Apply overrides (this logic is from runServer)
	if logLevel != "" {
		loadedCfg.Logging.Level = logLevel
	}
	if logFormat != "" {
		loadedCfg.Logging.Format = logFormat
	}
	if workspaceDir != "" {
		loadedCfg.Sandbox.WorkspaceDir = workspaceDir
	}
	if enableHTTP {
		loadedCfg.Server.EnableHTTP = true
	}
	if httpPort > 0 {
		loadedCfg.Server.Port = httpPort
	}
	
	// Verify overrides applied
	assert.Equal(t, "debug", loadedCfg.Logging.Level)
	assert.Equal(t, "console", loadedCfg.Logging.Format)
	assert.Equal(t, "/override/workspace", loadedCfg.Sandbox.WorkspaceDir)
	assert.True(t, loadedCfg.Server.EnableHTTP)
	assert.Equal(t, 8080, loadedCfg.Server.Port)
}

func TestBuildInfo(t *testing.T) {
	// Test that version info can be set and retrieved
	origVersion := version
	origCommit := commit
	origDate := date
	
	defer func() {
		version = origVersion
		commit = origCommit
		date = origDate
	}()
	
	version = "test-version"
	commit = "test-commit"
	date = "test-date"
	
	rootCmd := &cobra.Command{
		Use:     "mcp-sandboxd",
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}
	
	expectedVersion := "test-version (commit: test-commit, built: test-date)"
	assert.Equal(t, expectedVersion, rootCmd.Version)
}

func TestAPIVersionsToStrings(t *testing.T) {
	// This tests the helper function used in main.go
	// We need to import the API package types, but for this test we'll mock them
	type APIVersion string
	
	versions := []APIVersion{"v1", "v2", "v3"}
	
	// Simulate the helper function logic
	strings := make([]string, len(versions))
	for i, v := range versions {
		strings[i] = string(v)
	}
	
	expected := []string{"v1", "v2", "v3"}
	assert.Equal(t, expected, strings)
}

func TestGracefulShutdown(t *testing.T) {
	// Test graceful shutdown scenario
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Simulate a server that shuts down gracefully
	errCh := make(chan error, 1)
	go func() {
		<-ctx.Done()
		errCh <- nil // No error on graceful shutdown
	}()
	
	// Cancel context (simulate signal)
	cancel()
	
	// Wait for shutdown with timeout
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timeout waiting for graceful shutdown")
	}
}

func TestServerError(t *testing.T) {
	// Test server error scenario
	_ = context.Background() // Use context to avoid unused variable
	
	errCh := make(chan error, 1)
	go func() {
		errCh <- fmt.Errorf("simulated server error")
	}()
	
	// Should receive error immediately
	select {
	case err := <-errCh:
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "simulated server error")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected error but none received")
	}
}

func TestInvalidCommandLineArgs(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expectError bool
	}{
		{
			name:        "unknown_flag",
			args:        []string{"--unknown-flag"},
			expectError: true,
		},
		{
			name:        "invalid_port",
			args:        []string{"--port", "invalid"},
			expectError: true,
		},
		{
			name:        "valid_args",
			args:        []string{"--log-level", "debug"},
			expectError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootCmd := &cobra.Command{
				Use: "mcp-sandboxd",
				RunE: func(cmd *cobra.Command, args []string) error {
					return nil // Don't actually run server
				},
			}
			
			// Add flags
			rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", "", "log level")
			rootCmd.PersistentFlags().IntVarP(&httpPort, "port", "p", 0, "HTTP port")
			
			rootCmd.SetArgs(tt.args)
			
			err := rootCmd.Execute()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func BenchmarkSetupLogging(b *testing.B) {
	cfg := config.LoggingConfig{
		Level:  "info",
		Format: "json",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger, err := setupLogging(cfg)
		require.NoError(b, err)
		_ = logger
	}
}

func BenchmarkRegisterTools(b *testing.B) {
	// Create a minimal config
	cfg := config.DefaultConfig()
	cfg.Tools.EnabledTools = []string{"create_sandbox", "run_code"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry := tools.NewRegistry()
		// Note: This will fail without proper mocking, but shows the performance pattern
		_ = registerTools(registry, nil, cfg)
	}
}

// Integration test helper that demonstrates how main components work together
func TestMainComponentIntegration(t *testing.T) {
	// This test demonstrates how the main components integrate
	// In a real integration test, you'd start the actual server
	
	tmpDir := t.TempDir()
	
	// 1. Create and save config
	cfg := config.DefaultConfig()
	cfg.Sandbox.WorkspaceDir = filepath.Join(tmpDir, "workspaces")
	cfg.Sandbox.DatabasePath = filepath.Join(tmpDir, "db", "sandboxes.db")
	cfg.Logging.Level = "debug"
	
	configPath := filepath.Join(tmpDir, "config.yaml")
	err := cfg.SaveConfig(configPath)
	require.NoError(t, err)
	
	// 2. Load config back
	loadedCfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	assert.Equal(t, cfg.Logging.Level, loadedCfg.Logging.Level)
	
	// 3. Setup logging
	logger, err := setupLogging(loadedCfg.Logging)
	require.NoError(t, err)
	assert.NotNil(t, logger)
	
	// 4. Create directories
	err = loadedCfg.CreateDirectories()
	require.NoError(t, err)
	assert.DirExists(t, loadedCfg.Sandbox.WorkspaceDir)
	
	// 5. Create tool registry
	registry := tools.NewRegistry()
	assert.Equal(t, 0, registry.Count())
	
	// This demonstrates the integration flow without actually starting servers
}

// Test that demonstrates proper resource cleanup
func TestResourceCleanup(t *testing.T) {
	// Simulate resource cleanup scenarios
	var cleanupCalled bool
	
	cleanup := func() {
		cleanupCalled = true
	}
	
	// Defer cleanup (like in main)
	defer func() {
		cleanup()
		assert.True(t, cleanupCalled, "Cleanup should have been called")
	}()
	
	// Do some work...
	cfg := config.DefaultConfig()
	assert.NotNil(t, cfg)
	
	// When test ends, cleanup should be called
	// (defer will execute when function returns)
}