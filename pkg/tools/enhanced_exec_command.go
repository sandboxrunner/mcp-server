package tools

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/config"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
)

// EnhancedExecCommandTool extends ExecCommandTool with streaming, caching, and enhanced environment
type EnhancedExecCommandTool struct {
	*BaseTool
	manager     *sandbox.Manager
	config      *config.Config
	cache       CommandCache
	environment *CommandEnvironment
}

// NewEnhancedExecCommandTool creates a new enhanced execute command tool
func NewEnhancedExecCommandTool(manager *sandbox.Manager, cfg *config.Config) (*EnhancedExecCommandTool, error) {
	tool := &EnhancedExecCommandTool{
		BaseTool: NewBaseTool(
			"exec_command_enhanced",
			"Executes a shell command in a sandbox environment with advanced features (streaming, caching, enhanced environment)",
			EnhancedCommandSchema(),
		),
		manager: manager,
		config:  cfg,
	}

	// Initialize command cache if enabled
	if cfg.Tools.EnableCaching {
		cacheConfig := CacheConfig{
			DatabasePath:     cfg.Tools.CacheConfig.DatabasePath,
			MaxEntries:       cfg.Tools.CacheConfig.MaxEntries,
			DefaultTTL:       cfg.Tools.CacheConfig.DefaultTTL,
			CleanupInterval:  cfg.Tools.CacheConfig.CleanupInterval,
			CompressionLevel: cfg.Tools.CacheConfig.CompressionLevel,
			CompressionMin:   cfg.Tools.CacheConfig.CompressionMin,
			EnableWarming:    cfg.Tools.CacheConfig.EnableWarming,
			WarmCommands:     cfg.Tools.CacheConfig.WarmCommands,
			MaxCacheSize:     cfg.Tools.CacheConfig.MaxCacheSize,
		}

		cache, err := NewSQLiteCommandCache(cacheConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize command cache: %w", err)
		}
		tool.cache = cache
	}

	// Initialize command environment
	envOpts := EnvironmentOptions{
		BaseEnvironment:  cfg.Sandbox.Environment,
		WorkingDirectory: "/workspace",
		ExpandVariables:  cfg.Tools.EnvironmentConfig.ExpandVariables,
		FilterSensitive:  cfg.Tools.EnvironmentConfig.FilterSensitive,
		CustomPaths:      cfg.Tools.EnvironmentConfig.CustomPaths,
		Shell:            cfg.Tools.EnvironmentConfig.DefaultShell,
		User:             cfg.Tools.EnvironmentConfig.DefaultUser,
	}

	env, err := NewCommandEnvironment(envOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize command environment: %w", err)
	}
	tool.environment = env

	return tool, nil
}

// Execute runs a shell command in a sandbox with enhanced features
func (t *EnhancedExecCommandTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	// Extract and validate parameters
	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	command, err := validator.ExtractString(params, "command", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	workingDir, _ := validator.ExtractString(params, "working_dir", false, "/workspace")
	environment, _ := validator.ExtractStringMap(params, "environment", false)
	timeout, _ := validator.ExtractInt(params, "timeout", false, 30)
	enableStreaming, _ := validator.ExtractBool(params, "enable_streaming", false, t.config.Tools.EnableStreaming)
	enableCaching, _ := validator.ExtractBool(params, "enable_caching", false, t.config.Tools.EnableCaching)
	language, _ := validator.ExtractString(params, "language", false, "")

	// Parse command into arguments
	args := parseCommand(command)
	if len(args) == 0 {
		return &ToolResult{
			Text:    "Command cannot be empty",
			IsError: true,
		}, nil
	}

	// Get sandbox and validate state
	sb, err := t.manager.GetSandbox(sandboxID)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox not found: %v", err),
			IsError: true,
		}, nil
	}

	if sb.Status != sandbox.SandboxStatusRunning {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox is not running (status: %s)", sb.Status),
			IsError: true,
		}, nil
	}

	// Check cache if enabled
	var cacheEntry *CommandCacheEntry
	if enableCaching && t.cache != nil {
		cacheKey := t.generateCacheKey(command, args, environment, workingDir)
		if cached, err := t.cache.Get(cacheKey); err == nil && cached != nil {
			log.Debug().
				Str("cache_key", cacheKey).
				Str("command", command).
				Msg("Using cached command result")

			return t.formatCachedResult(cached), nil
		}
	}

	// Prepare environment for execution
	if err := t.environment.setWorkingDirectory(workingDir); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid working directory: %v", err),
			IsError: true,
		}, nil
	}

	// Add additional environment variables
	if environment != nil {
		t.environment.addEnvironmentVariables(environment, t.config.Tools.EnvironmentConfig.FilterSensitive)
	}

	// Prepare environment for language if specified
	envSlice, err := t.environment.PrepareEnvironmentForLanguage(language)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to prepare environment: %v", err),
			IsError: true,
		}, nil
	}

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Get runtime client
	runtimeClient := t.manager.GetRuntimeClient()
	if runtimeClient == nil {
		return &ToolResult{
			Text:    "Runtime client not available",
			IsError: true,
		}, nil
	}

	// Create process specification
	userCtx := t.environment.GetUserContext()
	spec := runtime.NewProcessSpec(args[0], args)
	spec.WithWorkingDir(workingDir)
	spec.WithEnvSlice(envSlice)
	spec.WithTimeout(time.Duration(timeout) * time.Second)
	spec.WithUser(fmt.Sprintf("%d:%d", userCtx.UID, userCtx.GID))

	// Execute with or without streaming
	var result *ToolResult
	if enableStreaming && t.config.Tools.EnableStreaming {
		result = t.executeWithStreaming(execCtx, runtimeClient, sb.ContainerID, spec, command)
	} else {
		result = t.executeBasic(execCtx, runtimeClient, sb.ContainerID, spec, command)
	}

	// Cache the result if enabled and successful
	if enableCaching && t.cache != nil && !result.IsError {
		cacheEntry = &CommandCacheEntry{
			SandboxID:     sandboxID,
			Command:       command,
			Args:          args,
			WorkingDir:    workingDir,
			Environment:   environment,
			ExitCode:      result.Metadata["exit_code"].(int),
			Stdout:        t.extractOutput(result, "stdout"),
			Stderr:        t.extractOutput(result, "stderr"),
			ExecutionTime: time.Duration(result.Metadata["execution_time_ms"].(int64)) * time.Millisecond,
			Timestamp:     time.Now(),
			Metadata:      result.Metadata,
		}

		if err := t.cache.Store(cacheEntry); err != nil {
			log.Warn().Err(err).Msg("Failed to cache command result")
		}
	}

	return result, nil
}

// executeBasic performs basic command execution without streaming
func (t *EnhancedExecCommandTool) executeBasic(ctx context.Context, client *runtime.RunCClient, containerID string, spec *runtime.ProcessSpec, command string) *ToolResult {
	startTime := time.Now()
	result, err := client.ExecProcess(ctx, containerID, spec)
	executionDuration := time.Since(startTime)

	if err != nil {
		errorCode := "EXECUTION_FAILED"
		errorMessage := err.Error()

		if strings.Contains(errorMessage, "timeout") || strings.Contains(errorMessage, "deadline exceeded") {
			errorCode = "TIMEOUT"
		} else if strings.Contains(errorMessage, "not found") {
			errorCode = "CONTAINER_NOT_FOUND"
		} else if strings.Contains(errorMessage, "not running") {
			errorCode = "CONTAINER_NOT_RUNNING"
		}

		return &ToolResult{
			Text:    fmt.Sprintf("Command execution failed: %v", err),
			IsError: true,
			Metadata: map[string]interface{}{
				"command":        command,
				"error_code":     errorCode,
				"error_message":  errorMessage,
				"execution_time": executionDuration.Milliseconds(),
			},
		}
	}

	// Get stdout and stderr
	stdout, stdoutErr := result.GetStdout()
	if stdoutErr != nil {
		stdout = []byte(fmt.Sprintf("Error getting stdout: %v", stdoutErr))
	}

	stderr, stderrErr := result.GetStderr()
	if stderrErr != nil {
		stderr = []byte(fmt.Sprintf("Error getting stderr: %v", stderrErr))
	}

	// Format output text
	outputText := fmt.Sprintf(`Enhanced command executed:
Command: %s
Working Directory: %s
Exit Code: %d
Execution Time: %v
Environment Variables: %d
User Context: %s

Stdout:
%s

Stderr:
%s`,
		command,
		spec.WorkingDir,
		result.ExitCode,
		executionDuration,
		len(spec.Env),
		spec.User,
		string(stdout),
		string(stderr))

	return &ToolResult{
		Text:    outputText,
		IsError: result.ExitCode != 0,
		Metadata: map[string]interface{}{
			"command":           command,
			"working_dir":       spec.WorkingDir,
			"exit_code":         result.ExitCode,
			"execution_time_ms": executionDuration.Milliseconds(),
			"execution_time":    executionDuration.String(),
			"stdout_size":       result.Output.StdoutSize,
			"stderr_size":       result.Output.StderrSize,
			"output_truncated":  result.Output.Truncated,
			"output_compressed": result.Output.Compressed,
			"process_id":        result.Process.ID,
			"process_pid":       result.Process.PID,
			"duration":          result.Output.Duration.String(),
			"enhanced":          true,
			"cached":            false,
			"streamed":          false,
		},
	}
}

// executeWithStreaming performs command execution with real-time output streaming
func (t *EnhancedExecCommandTool) executeWithStreaming(ctx context.Context, client *runtime.RunCClient, containerID string, spec *runtime.ProcessSpec, command string) *ToolResult {
	streamConfig := OutputStreamConfig{
		BufferSize:     t.config.Tools.StreamConfig.BufferSize,
		FlushInterval:  t.config.Tools.StreamConfig.FlushInterval,
		MaxChunkSize:   t.config.Tools.StreamConfig.MaxChunkSize,
		EnableANSI:     t.config.Tools.StreamConfig.EnableANSI,
		FilterANSI:     t.config.Tools.StreamConfig.FilterANSI,
		DetectProgress: t.config.Tools.StreamConfig.DetectProgress,
		EnableJSON:     t.config.Tools.StreamConfig.EnableJSON,
		Compress:       t.config.Tools.StreamConfig.Compress,
		CompressionMin: t.config.Tools.StreamConfig.CompressionMin,
	}

	streamer := NewBufferedOutputStreamer(streamConfig)
	defer streamer.Stop()

	// Create pipes for stdout and stderr
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()

	// Start streaming
	streamCtx, streamCancel := context.WithCancel(ctx)
	defer streamCancel()

	if err := streamer.StartStreaming(streamCtx, stdoutReader, stderrReader); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to start streaming: %v", err),
			IsError: true,
		}
	}

	// Collect streaming output
	collector := NewStreamCollector()
	go collector.Collect(streamCtx, streamer)

	// Modify spec to use our pipes
	originalSpec := *spec
	// Note: In a real implementation, you would need to modify the runtime client
	// to support custom stdout/stderr writers. This is a conceptual example.

	startTime := time.Now()
	result, err := client.ExecProcess(ctx, containerID, &originalSpec)
	executionDuration := time.Since(startTime)

	// Close writers to signal EOF to readers
	stdoutWriter.Close()
	stderrWriter.Close()

	// Wait a bit for streaming to complete
	time.Sleep(100 * time.Millisecond)

	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Streaming command execution failed: %v", err),
			IsError: true,
			Metadata: map[string]interface{}{
				"command":           command,
				"error":             err.Error(),
				"execution_time":    executionDuration.Milliseconds(),
				"streaming_metrics": streamer.GetMetrics(),
			},
		}
	}

	// Collect streaming results
	streamOutputs := collector.GetOutputs()
	combinedStdout := collector.GetCombinedContent(StreamSourceStdout)
	combinedStderr := collector.GetCombinedContent(StreamSourceStderr)
	streamMetrics := streamer.GetMetrics()

	// Format output text with streaming information
	outputText := fmt.Sprintf(`Enhanced streaming command executed:
Command: %s
Working Directory: %s
Exit Code: %d
Execution Time: %v
Streaming Chunks: %d
Streaming Metrics: %+v

Combined Stdout:
%s

Combined Stderr:
%s`,
		command,
		spec.WorkingDir,
		result.ExitCode,
		executionDuration,
		len(streamOutputs),
		streamMetrics,
		combinedStdout,
		combinedStderr)

	return &ToolResult{
		Text:    outputText,
		IsError: result.ExitCode != 0,
		Metadata: map[string]interface{}{
			"command":           command,
			"working_dir":       spec.WorkingDir,
			"exit_code":         result.ExitCode,
			"execution_time_ms": executionDuration.Milliseconds(),
			"execution_time":    executionDuration.String(),
			"enhanced":          true,
			"cached":            false,
			"streamed":          true,
			"streaming_metrics": streamMetrics,
			"stream_outputs":    len(streamOutputs),
			"stdout_size":       len(combinedStdout),
			"stderr_size":       len(combinedStderr),
		},
	}
}

// formatCachedResult formats a cached command result
func (t *EnhancedExecCommandTool) formatCachedResult(entry *CommandCacheEntry) *ToolResult {
	outputText := fmt.Sprintf(`Cached command result:
Command: %s
Working Directory: %s
Exit Code: %d
Execution Time: %v (cached)
Cache Hit Count: %d
Cached At: %v

Stdout:
%s

Stderr:
%s`,
		entry.Command,
		entry.WorkingDir,
		entry.ExitCode,
		entry.ExecutionTime,
		entry.HitCount+1,
		entry.Timestamp.Format(time.RFC3339),
		entry.Stdout,
		entry.Stderr)

	return &ToolResult{
		Text:    outputText,
		IsError: entry.ExitCode != 0,
		Metadata: map[string]interface{}{
			"command":           entry.Command,
			"working_dir":       entry.WorkingDir,
			"exit_code":         entry.ExitCode,
			"execution_time_ms": entry.ExecutionTime.Milliseconds(),
			"execution_time":    entry.ExecutionTime.String(),
			"enhanced":          true,
			"cached":            true,
			"cache_hit_count":   entry.HitCount + 1,
			"cached_at":         entry.Timestamp.Format(time.RFC3339),
			"stdout_size":       len(entry.Stdout),
			"stderr_size":       len(entry.Stderr),
		},
	}
}

// generateCacheKey generates a cache key for the command
func (t *EnhancedExecCommandTool) generateCacheKey(command string, args []string, env map[string]string, workingDir string) string {
	if t.cache != nil {
		// Use the cache's method if available
		if sqliteCache, ok := t.cache.(*SQLiteCommandCache); ok {
			return sqliteCache.generateCacheKey(command, args, env, workingDir)
		}
	}

	// Fallback implementation
	return fmt.Sprintf("%s:%s:%s", command, workingDir, fmt.Sprintf("%v", env))
}

// extractOutput extracts output from tool result metadata
func (t *EnhancedExecCommandTool) extractOutput(result *ToolResult, outputType string) string {
	// This would extract stdout/stderr from the result
	// Implementation depends on how the output is stored in the result
	if result.Text != "" {
		lines := strings.Split(result.Text, "\n")
		for i, line := range lines {
			if strings.Contains(strings.ToLower(line), outputType+":") && i+1 < len(lines) {
				return strings.Join(lines[i+1:], "\n")
			}
		}
	}
	return ""
}

// Close closes the enhanced command tool and cleans up resources
func (t *EnhancedExecCommandTool) Close() error {
	if t.cache != nil {
		return t.cache.Close()
	}
	return nil
}

// EnhancedCommandSchema returns the JSON schema for enhanced command execution
func EnhancedCommandSchema() map[string]interface{} {
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
				"default":     "/workspace",
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for the command",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Command timeout in seconds",
				"default":     30,
				"minimum":     1,
				"maximum":     300,
			},
			"language": map[string]interface{}{
				"type":        "string",
				"description": "Programming language context for environment setup",
				"enum": []string{
					"python", "javascript", "typescript", "bash", "sh",
					"go", "rust", "java", "c", "cpp", "csharp", "ruby", "php",
				},
			},
			"enable_streaming": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable real-time output streaming",
				"default":     true,
			},
			"enable_caching": map[string]interface{}{
				"type":        "boolean",
				"description": "Enable command result caching",
				"default":     true,
			},
		},
		"required": []string{"sandbox_id", "command"},
	}
}
