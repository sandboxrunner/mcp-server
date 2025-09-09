package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/languages"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
)

// CreateSandboxTool creates new sandbox environments
type CreateSandboxTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewCreateSandboxTool creates a new create sandbox tool
func NewCreateSandboxTool(manager *sandbox.Manager) *CreateSandboxTool {
	return &CreateSandboxTool{
		BaseTool: NewBaseTool(
			"create_sandbox",
			"Creates a new sandbox environment with the specified configuration",
			SandboxConfigSchema(),
		),
		manager: manager,
	}
}

// Execute creates a new sandbox
func (t *CreateSandboxTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	// Extract parameters
	image, _ := validator.ExtractString(params, "image", false, "ubuntu:22.04")
	workspaceDir, _ := validator.ExtractString(params, "workspace_dir", false, "/workspace")
	cpuLimit, _ := validator.ExtractString(params, "cpu_limit", false, "")
	memoryLimit, _ := validator.ExtractString(params, "memory_limit", false, "")
	diskLimit, _ := validator.ExtractString(params, "disk_limit", false, "")
	networkMode, _ := validator.ExtractString(params, "network_mode", false, "none")
	environment, _ := validator.ExtractStringMap(params, "environment", false)

	// Create sandbox configuration
	config := sandbox.SandboxConfig{
		Image:        image,
		WorkspaceDir: workspaceDir,
		Environment:  environment,
		Resources: sandbox.ResourceLimits{
			CPULimit:    cpuLimit,
			MemoryLimit: memoryLimit,
			DiskLimit:   diskLimit,
		},
		NetworkMode:   networkMode,
		EnableLogging: true,
	}

	// Create the sandbox
	sb, err := t.manager.CreateSandbox(ctx, config)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to create sandbox: %v", err),
			IsError: true,
		}, nil
	}

	// Return sandbox info
	info := map[string]interface{}{
		"sandbox_id":   sb.ID,
		"container_id": sb.ContainerID,
		"status":       string(sb.Status),
		"working_dir":  sb.WorkingDir,
		"created_at":   sb.CreatedAt,
		"config":       sb.Config,
	}

	infoJSON, _ := json.MarshalIndent(info, "", "  ")

	return &ToolResult{
		Text:    fmt.Sprintf("Sandbox created successfully:\n%s", string(infoJSON)),
		IsError: false,
		Metadata: map[string]interface{}{
			"sandbox_id":   sb.ID,
			"container_id": sb.ContainerID,
		},
	}, nil
}

// ListSandboxesTool lists active sandbox environments
type ListSandboxesTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewListSandboxesTool creates a new list sandboxes tool
func NewListSandboxesTool(manager *sandbox.Manager) *ListSandboxesTool {
	return &ListSandboxesTool{
		BaseTool: NewBaseTool(
			"list_sandboxes",
			"Lists all active sandbox environments",
			map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
				"required":   []string{},
			},
		),
		manager: manager,
	}
}

// Execute lists all sandboxes
func (t *ListSandboxesTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	sandboxes, err := t.manager.ListSandboxes()
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to list sandboxes: %v", err),
			IsError: true,
		}, nil
	}

	if len(sandboxes) == 0 {
		return &ToolResult{
			Text:    "No active sandboxes found",
			IsError: false,
		}, nil
	}

	// Format sandbox list
	sandboxList := make([]map[string]interface{}, len(sandboxes))
	for i, sb := range sandboxes {
		sandboxList[i] = map[string]interface{}{
			"id":           sb.ID,
			"container_id": sb.ContainerID,
			"status":       string(sb.Status),
			"created_at":   sb.CreatedAt.Format(time.RFC3339),
			"updated_at":   sb.UpdatedAt.Format(time.RFC3339),
		}
	}

	listJSON, _ := json.MarshalIndent(sandboxList, "", "  ")

	return &ToolResult{
		Text:    fmt.Sprintf("Active sandboxes (%d):\n%s", len(sandboxes), string(listJSON)),
		IsError: false,
		Metadata: map[string]interface{}{
			"count":     len(sandboxes),
			"sandboxes": sandboxList,
		},
	}, nil
}

// TerminateSandboxTool stops and cleans up sandbox environments
type TerminateSandboxTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewTerminateSandboxTool creates a new terminate sandbox tool
func NewTerminateSandboxTool(manager *sandbox.Manager) *TerminateSandboxTool {
	return &TerminateSandboxTool{
		BaseTool: NewBaseTool(
			"terminate_sandbox",
			"Stops and removes a sandbox environment",
			SandboxIDSchema(),
		),
		manager: manager,
	}
}

// Execute terminates a sandbox
func (t *TerminateSandboxTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	// Delete the sandbox (which will stop it first if running)
	if err := t.manager.DeleteSandbox(ctx, sandboxID); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to terminate sandbox: %v", err),
			IsError: true,
		}, nil
	}

	return &ToolResult{
		Text:    fmt.Sprintf("Sandbox %s terminated successfully", sandboxID),
		IsError: false,
		Metadata: map[string]interface{}{
			"sandbox_id": sandboxID,
		},
	}, nil
}

// ExecCommandTool executes shell commands in a sandbox
type ExecCommandTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewExecCommandTool creates a new execute command tool
func NewExecCommandTool(manager *sandbox.Manager) *ExecCommandTool {
	return &ExecCommandTool{
		BaseTool: NewBaseTool(
			"exec_command",
			"Executes a shell command in a sandbox environment",
			CommandSchema(),
		),
		manager: manager,
	}
}

// Execute runs a shell command in a sandbox
func (t *ExecCommandTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

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

	// Get sandbox
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

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Get runtime client from manager
	runtimeClient := t.manager.GetRuntimeClient()
	if runtimeClient == nil {
		return &ToolResult{
			Text:    "Runtime client not available",
			IsError: true,
		}, nil
	}

	// Create environment slice from map
	var envSlice []string
	if environment != nil {
		for key, value := range environment {
			envSlice = append(envSlice, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Parse command into command and arguments
	// Split on whitespace, respecting quoted strings
	args := parseCommand(command)
	if len(args) == 0 {
		return &ToolResult{
			Text:    "Command cannot be empty",
			IsError: true,
		}, nil
	}

	// Create ProcessSpec
	spec := runtime.NewProcessSpec(args[0], args)
	spec.WithWorkingDir(workingDir)
	spec.WithEnvSlice(envSlice)
	spec.WithTimeout(time.Duration(timeout) * time.Second)
	spec.WithUser("0:0") // Run as root by default

	// Record start time for execution tracking
	startTime := time.Now()

	// Execute the process
	result, err := runtimeClient.ExecProcess(execCtx, sb.ContainerID, spec)
	executionDuration := time.Since(startTime)

	// Handle execution errors
	if err != nil {
		// Determine error type for specific error codes
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
				"sandbox_id":     sandboxID,
				"command":        command,
				"working_dir":    workingDir,
				"environment":    environment,
				"error_code":     errorCode,
				"error_message":  errorMessage,
				"execution_time": executionDuration.Milliseconds(),
			},
		}, nil
	}

	// Get stdout and stderr, handling decompression if needed
	stdout, stdoutErr := result.GetStdout()
	if stdoutErr != nil {
		stdout = []byte(fmt.Sprintf("Error getting stdout: %v", stdoutErr))
	}

	stderr, stderrErr := result.GetStderr()
	if stderrErr != nil {
		stderr = []byte(fmt.Sprintf("Error getting stderr: %v", stderrErr))
	}

	// Format output text
	outputText := fmt.Sprintf(`Command executed in sandbox %s:
Command: %s
Working Directory: %s
Exit Code: %d
Execution Time: %v

Stdout:
%s

Stderr:
%s`,
		sandboxID,
		command,
		workingDir,
		result.ExitCode,
		executionDuration,
		string(stdout),
		string(stderr))

	// Determine if this is considered an error (non-zero exit code)
	isError := result.ExitCode != 0

	return &ToolResult{
		Text:    outputText,
		IsError: isError,
		Metadata: map[string]interface{}{
			"sandbox_id":        sandboxID,
			"command":           command,
			"working_dir":       workingDir,
			"environment":       environment,
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
		},
	}, nil
}

// RunCodeTool executes code with language detection
type RunCodeTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewRunCodeTool creates a new run code tool
func NewRunCodeTool(manager *sandbox.Manager) *RunCodeTool {
	return &RunCodeTool{
		BaseTool: NewBaseTool(
			"run_code",
			"Executes code in a sandbox environment with language detection",
			CodeSchema(),
		),
		manager: manager,
	}
}

// Execute runs code in a sandbox
func (t *RunCodeTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	code, err := validator.ExtractString(params, "code", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	language, _ := validator.ExtractString(params, "language", false, "")
	workingDir, _ := validator.ExtractString(params, "working_dir", false, "/workspace")
	timeout, _ := validator.ExtractInt(params, "timeout", false, 30)

	// Additional input validation and security checks
	if err := t.validateCodeInput(code, language, workingDir, timeout); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Input validation failed: %v", err),
			IsError: true,
		}, nil
	}

	// Auto-detect language if not provided
	if language == "" {
		language = t.detectLanguage(code)
	}

	// Get sandbox
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

	// Create language detector for better language detection
	detector := languages.NewDetector()
	if language == "" {
		detectionResult := detector.GetBestMatch(code, "")
		language = string(detectionResult.Language)
	}

	// Get the runtime client from the sandbox manager
	runtimeClient := t.manager.GetRuntimeClient()

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	logger := log.With().
		Str("sandbox_id", sandboxID).
		Str("language", language).
		Str("working_dir", workingDir).
		Logger()

	logger.Info().Msg("Starting code execution")

	// Create temporary file with appropriate extension
	tempFile, cleanup, err := t.createTempFile(code, language, workingDir)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create temporary file")
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to create temporary file: %v", err),
			IsError: true,
		}, nil
	}
	defer cleanup()

	// Generate execution commands based on language
	execSpec, err := t.createProcessSpec(language, tempFile, workingDir, time.Duration(timeout)*time.Second)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to create process spec")
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to create process spec: %v", err),
			IsError: true,
		}, nil
	}

	// Execute the code using the runtime client
	startTime := time.Now()
	result, err := runtimeClient.ExecProcess(execCtx, sandboxID, execSpec)
	executionDuration := time.Since(startTime)

	if err != nil {
		logger.Error().Err(err).Msg("Failed to execute process")
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to execute code: %v", err),
			IsError: true,
		}, nil
	}

	// Parse the execution result
	return t.parseExecutionResult(sandboxID, language, workingDir, result, executionDuration, strings.Join(execSpec.Args, " "))
}

// detectLanguage attempts to detect the programming language from code
func (t *RunCodeTool) detectLanguage(code string) string {
	// Simple heuristics for language detection
	if containsAny(code, []string{"print(", "import ", "def ", "if __name__"}) {
		return "python"
	}
	if containsAny(code, []string{"console.log", "function ", "const ", "let ", "var "}) {
		return "javascript"
	}
	if containsAny(code, []string{"package main", "func main", "fmt.Print"}) {
		return "go"
	}
	if containsAny(code, []string{"#include", "int main", "printf"}) {
		return "c"
	}
	if containsAny(code, []string{"#!/bin/bash", "#!/bin/sh", "echo ", "ls ", "cd "}) {
		return "bash"
	}

	// Default to bash for simple commands
	return "bash"
}

// generateCommand creates the appropriate execution command for the language
func (t *RunCodeTool) generateCommand(language, code, workingDir string) string {
	switch language {
	case "python":
		return fmt.Sprintf("cd %s && python3 -c %q", workingDir, code)
	case "javascript":
		return fmt.Sprintf("cd %s && node -e %q", workingDir, code)
	case "bash", "sh":
		return fmt.Sprintf("cd %s && %s", workingDir, code)
	case "go":
		return fmt.Sprintf("cd %s && echo %q > main.go && go run main.go", workingDir, code)
	default:
		return fmt.Sprintf("cd %s && echo %q | %s", workingDir, code, language)
	}
}

// createTempFile creates a temporary file with appropriate extension for the language
func (t *RunCodeTool) createTempFile(code, language, workingDir string) (string, func(), error) {
	// Map languages to file extensions
	extensionMap := map[string]string{
		"python":     ".py",
		"javascript": ".js",
		"typescript": ".ts",
		"go":         ".go",
		"rust":       ".rs",
		"java":       ".java",
		"c":          ".c",
		"cpp":        ".cpp",
		"csharp":     ".cs",
		"ruby":       ".rb",
		"php":        ".php",
		"shell":      ".sh",
		"bash":       ".sh",
		"r":          ".r",
		"lua":        ".lua",
		"perl":       ".pl",
	}

	// Get file extension, default to .txt if unknown language
	extension := extensionMap[language]
	if extension == "" {
		extension = ".txt"
	}

	// Create filename based on language
	var filename string
	switch language {
	case "go":
		filename = "main.go"
	case "java":
		// Try to extract class name from code for Java
		if strings.Contains(code, "public class ") {
			start := strings.Index(code, "public class ") + len("public class ")
			end := strings.IndexAny(code[start:], " \t\n{")
			if end != -1 {
				className := code[start : start+end]
				filename = className + ".java"
			} else {
				filename = "Main.java"
			}
		} else {
			filename = "Main.java"
		}
	case "csharp":
		filename = "Program.cs"
	case "rust":
		filename = "main.rs"
	default:
		filename = "main" + extension
	}

	// Create the full file path
	tempFile := filepath.Join(workingDir, filename)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(tempFile), 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create directory: %w", err)
	}

	// Write code to temporary file
	if err := os.WriteFile(tempFile, []byte(code), 0644); err != nil {
		return "", nil, fmt.Errorf("failed to write temporary file: %w", err)
	}

	// Return cleanup function
	cleanup := func() {
		if err := os.Remove(tempFile); err != nil {
			log.Warn().Err(err).Str("file", tempFile).Msg("Failed to cleanup temporary file")
		}
	}

	return tempFile, cleanup, nil
}

// createProcessSpec creates a ProcessSpec for executing code based on the language
func (t *RunCodeTool) createProcessSpec(language, tempFile, workingDir string, timeout time.Duration) (*runtime.ProcessSpec, error) {
	var args []string

	switch language {
	case "python":
		args = []string{"python3", tempFile}
	case "javascript":
		args = []string{"node", tempFile}
	case "typescript":
		// TypeScript requires compilation first
		compiledFile := strings.TrimSuffix(tempFile, ".ts") + ".js"
		args = []string{"sh", "-c", fmt.Sprintf("tsc %s && node %s", tempFile, compiledFile)}
	case "go":
		args = []string{"sh", "-c", fmt.Sprintf("cd %s && go run %s", workingDir, filepath.Base(tempFile))}
	case "rust":
		executableFile := strings.TrimSuffix(tempFile, ".rs")
		args = []string{"sh", "-c", fmt.Sprintf("rustc %s -o %s && %s", tempFile, executableFile, executableFile)}
	case "java":
		className := strings.TrimSuffix(filepath.Base(tempFile), ".java")
		args = []string{"sh", "-c", fmt.Sprintf("cd %s && javac %s && java %s", workingDir, filepath.Base(tempFile), className)}
	case "c":
		executableFile := strings.TrimSuffix(tempFile, ".c")
		args = []string{"sh", "-c", fmt.Sprintf("gcc %s -o %s && %s", tempFile, executableFile, executableFile)}
	case "cpp":
		executableFile := strings.TrimSuffix(tempFile, ".cpp")
		args = []string{"sh", "-c", fmt.Sprintf("g++ %s -o %s && %s", tempFile, executableFile, executableFile)}
	case "csharp":
		args = []string{"sh", "-c", fmt.Sprintf("cd %s && dotnet run", workingDir)}
	case "ruby":
		args = []string{"ruby", tempFile}
	case "php":
		args = []string{"php", tempFile}
	case "shell", "bash":
		args = []string{"bash", tempFile}
	case "r":
		args = []string{"Rscript", tempFile}
	case "lua":
		args = []string{"lua", tempFile}
	case "perl":
		args = []string{"perl", tempFile}
	default:
		// For unknown languages, try to execute as shell script
		args = []string{"sh", "-c", fmt.Sprintf("cat %s", tempFile)}
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("unsupported language: %s", language)
	}

	// Create ProcessSpec
	spec := &runtime.ProcessSpec{
		Cmd:        args[0],
		Args:       args,
		WorkingDir: workingDir,
		Terminal:   false,
		Timeout:    timeout,
		User:       "root",     // Default user for sandbox execution
		Env:        []string{}, // Will be populated with default environment
	}

	// Add language-specific environment variables
	switch language {
	case "python":
		spec.Env = append(spec.Env, "PYTHONUNBUFFERED=1")
	case "go":
		spec.Env = append(spec.Env, "GOCACHE=/tmp/.cache/go-build")
	case "java":
		spec.Env = append(spec.Env, "JAVA_HOME=/usr/lib/jvm/default-java")
	case "csharp":
		spec.Env = append(spec.Env, "DOTNET_CLI_TELEMETRY_OPTOUT=1")
	}

	return spec, nil
}

// parseExecutionResult converts the runtime ProcessResult to a ToolResult
func (t *RunCodeTool) parseExecutionResult(sandboxID, language, workingDir string, result *runtime.ProcessResult, executionDuration time.Duration, command string) (*ToolResult, error) {
	// Extract stdout and stderr
	stdout := string(result.Stdout)
	stderr := string(result.Stderr)

	// Format the output text
	outputText := fmt.Sprintf(`Code executed in sandbox %s:

Language: %s
Working Directory: %s  
Command: %s
Exit Code: %d
Execution Time: %s

Stdout:
%s

Stderr:
%s`,
		sandboxID,
		language,
		workingDir,
		command,
		result.ExitCode,
		executionDuration,
		stdout,
		stderr)

	// Determine if this is considered an error (non-zero exit code)
	isError := result.ExitCode != 0

	return &ToolResult{
		Text:    outputText,
		IsError: isError,
		Metadata: map[string]interface{}{
			"sandbox_id":        sandboxID,
			"language":          language,
			"working_dir":       workingDir,
			"command":           command,
			"exit_code":         result.ExitCode,
			"execution_time_ms": executionDuration.Milliseconds(),
			"execution_time":    executionDuration.String(),
			"stdout_size":       len(stdout),
			"stderr_size":       len(stderr),
		},
	}, nil
}

// validateCodeInput performs security and sanity checks on the input
func (t *RunCodeTool) validateCodeInput(code, language, workingDir string, timeout int) error {
	// Check code length limits
	const maxCodeLength = 1024 * 1024 // 1MB limit
	if len(code) > maxCodeLength {
		return fmt.Errorf("code too long: %d bytes (maximum %d bytes)", len(code), maxCodeLength)
	}

	// Check for empty code
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("code cannot be empty")
	}

	// Validate timeout limits
	if timeout < 1 {
		return fmt.Errorf("timeout must be at least 1 second")
	}
	if timeout > 300 { // 5 minutes max
		return fmt.Errorf("timeout too high: %d seconds (maximum 300 seconds)", timeout)
	}

	// Validate working directory path
	if !strings.HasPrefix(workingDir, "/workspace") && !strings.HasPrefix(workingDir, "/tmp") {
		return fmt.Errorf("working directory must be within /workspace or /tmp")
	}

	// Check for potentially dangerous commands (basic security filtering)
	dangerousPatterns := []string{
		"rm -rf /",
		"chmod 777",
		"chown",
		"passwd",
		"su ",
		"sudo ",
		"/etc/",
		">/dev/",
		"mkfs",
		"fdisk",
		"dd if=",
		":(){ :|:& };:", // Fork bomb
		"curl ",
		"wget ",
		"nc ",
		"netcat",
	}

	lowerCode := strings.ToLower(code)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerCode, pattern) {
			return fmt.Errorf("potentially dangerous command detected: %s", pattern)
		}
	}

	// Language-specific validations
	switch language {
	case "python":
		// Check for dangerous Python imports/calls
		pythonDangerous := []string{
			"import os",
			"import sys",
			"import subprocess",
			"import socket",
			"import urllib",
			"import requests",
			"__import__",
			"exec(",
			"eval(",
			"compile(",
		}
		for _, pattern := range pythonDangerous {
			if strings.Contains(lowerCode, pattern) {
				log.Warn().Str("pattern", pattern).Msg("Potentially dangerous Python code detected")
				// Log but don't block - some legitimate code might use these
			}
		}
	case "javascript":
		// Check for dangerous JavaScript patterns
		jsDangerous := []string{
			"require('child_process')",
			"require('fs')",
			"require('net')",
			"require('http')",
			"process.exit",
			"process.kill",
		}
		for _, pattern := range jsDangerous {
			if strings.Contains(lowerCode, pattern) {
				log.Warn().Str("pattern", pattern).Msg("Potentially dangerous JavaScript code detected")
			}
		}
	}

	return nil
}

// Helper function to check if string contains any of the given substrings
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// parseCommand parses a command string into command and arguments, respecting quoted strings
func parseCommand(command string) []string {
	var args []string
	var currentArg strings.Builder
	inQuotes := false
	quoteChar := byte(0)
	escaped := false

	for i := 0; i < len(command); i++ {
		char := command[i]

		if escaped {
			// Previous character was escape, add this character literally
			currentArg.WriteByte(char)
			escaped = false
			continue
		}

		if char == '\\' {
			// Escape next character
			escaped = true
			continue
		}

		if !inQuotes {
			if char == ' ' || char == '\t' {
				// Whitespace outside quotes - end current argument
				if currentArg.Len() > 0 {
					args = append(args, currentArg.String())
					currentArg.Reset()
				}
				continue
			} else if char == '"' || char == '\'' {
				// Start quoted string
				inQuotes = true
				quoteChar = char
				continue
			}
		} else {
			if char == quoteChar {
				// End quoted string
				inQuotes = false
				quoteChar = 0
				continue
			}
		}

		// Regular character, add to current argument
		currentArg.WriteByte(char)
	}

	// Add final argument if any
	if currentArg.Len() > 0 {
		args = append(args, currentArg.String())
	}

	return args
}
