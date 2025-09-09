package languages

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ShellHandler handles shell script execution
type ShellHandler struct {
	*BaseHandler
}

// NewShellHandler creates a new shell handler
func NewShellHandler() *ShellHandler {
	return &ShellHandler{
		BaseHandler: NewBaseHandler(
			LanguageShell,
			[]string{".sh", ".bash", ".zsh", ".fish"},
			"alpine:latest",
			[]string{"alpine:latest", "ubuntu:22.04", "debian:bullseye"},
			"", // No package manager for shell
			30*time.Second,
			false, // Interpreted
		),
	}
}

// DetectLanguage checks if the code is shell script
func (h *ShellHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	// Check file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".sh" || ext == ".bash" || ext == ".zsh" || ext == ".fish" {
		confidence += 0.8
	}

	// Check shebang
	if strings.HasPrefix(code, "#!/bin/bash") ||
		strings.HasPrefix(code, "#!/bin/sh") ||
		strings.HasPrefix(code, "#!/usr/bin/env bash") {
		confidence += 0.9
	}

	// Shell command patterns
	shellPatterns := []string{
		`echo\s+`, `ls\s+`, `cd\s+`, `mkdir\s+`, `rm\s+`, `cp\s+`, `mv\s+`,
		`grep\s+`, `sed\s+`, `awk\s+`, `sort\s+`, `uniq\s+`, `wc\s+`,
		`find\s+`, `which\s+`, `whereis\s+`, `chmod\s+`, `chown\s+`,
		`export\s+\w+=`, `\$\w+`, `if\s*\[`, `\[\s*`, `fi\b`, `then\b`,
		`else\b`, `elif\b`, `for\s+\w+\s+in`, `while\s*\[`, `do\b`, `done\b`,
		`case\s+`, `esac\b`, `function\s+\w+`, `\w+\s*\(\s*\)\s*{`,
	}

	for _, pattern := range shellPatterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.1
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares shell script for execution
func (h *ShellHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return NewEnvironmentError(
			fmt.Sprintf("failed to create working directory: %v", err),
			LanguageShell,
			err.Error(),
		)
	}

	// Create additional files
	for filename, content := range req.Files {
		filePath := filepath.Join(req.WorkingDir, filename)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return err
		}
	}

	return nil
}

// Execute runs shell script
func (h *ShellHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguageShell,
		Metadata: make(map[string]string),
	}

	// Determine shell
	shell := h.getShell(req)

	// Create execution context
	execCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	var cmd *exec.Cmd

	// Check if code should be executed directly or as a script file
	if h.isSimpleCommand(req.Code) {
		// Execute directly
		cmd = exec.CommandContext(execCtx, shell, "-c", req.Code)
		result.Command = fmt.Sprintf("%s -c '%s'", shell, req.Code)
	} else {
		// Create temporary script file
		scriptFile := filepath.Join(req.WorkingDir, "temp_script.sh")
		scriptContent := req.Code

		// Add shebang if not present
		if !strings.HasPrefix(scriptContent, "#!") {
			scriptContent = fmt.Sprintf("#!/bin/%s\n%s", shell, scriptContent)
		}

		if err := os.WriteFile(scriptFile, []byte(scriptContent), 0755); err != nil {
			result.Error = err
			return result, err
		}

		cmd = exec.CommandContext(execCtx, shell, scriptFile)
		result.Command = fmt.Sprintf("%s %s", shell, scriptFile)
		defer os.Remove(scriptFile)
	}

	cmd.Dir = req.WorkingDir

	// Set environment
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Handle stdin
	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	// Execute
	output, err := cmd.CombinedOutput()
	result.Duration = time.Since(startTime)
	result.Stdout = string(output)

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}
		result.Error = err
	} else {
		result.ExitCode = 0
	}

	return result, nil
}

// InstallPackages - not applicable for shell
func (h *ShellHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	return &PackageInstallResult{
		Success: true,
		Output:  "Package installation not applicable for shell scripts",
	}, nil
}

// SetupEnvironment sets up shell environment
func (h *ShellHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	result := &EnvironmentSetupResult{
		Environment: make(map[string]string),
		Success:     true,
		Path:        "/bin/bash",
		Version:     "bash",
		Output:      "Shell environment ready",
	}

	return result, nil
}

// GetRequiredFiles returns files needed for shell execution
func (h *ShellHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)

	scriptContent := req.Code
	if !strings.HasPrefix(scriptContent, "#!") {
		scriptContent = "#!/bin/bash\n" + scriptContent
	}

	files["script.sh"] = scriptContent
	return files
}

// GetCompileCommand returns empty for shell
func (h *ShellHandler) GetCompileCommand(req *ExecutionRequest) string {
	return ""
}

// GetRunCommand returns the run command
func (h *ShellHandler) GetRunCommand(req *ExecutionRequest) string {
	return "bash script.sh"
}

// ValidateCode performs basic shell validation
func (h *ShellHandler) ValidateCode(code string) error {
	if err := h.BaseHandler.ValidateCode(code); err != nil {
		return err
	}

	// Check for dangerous commands
	dangerousCommands := []string{"rm -rf /", "dd if=", ":(){ :|:& };:", "mv / /dev/null"}
	for _, dangerous := range dangerousCommands {
		if strings.Contains(code, dangerous) {
			return NewLanguageError(
				fmt.Sprintf("Potentially dangerous command detected: %s", dangerous),
				LanguageShell,
				"security",
			)
		}
	}

	return nil
}

// Helper methods

func (h *ShellHandler) getShell(req *ExecutionRequest) string {
	if shell, exists := req.Options["shell"]; exists {
		return shell
	}

	// Default to bash
	return "bash"
}

func (h *ShellHandler) isSimpleCommand(code string) bool {
	// Simple heuristic: if it's a single line without complex constructs
	lines := strings.Split(strings.TrimSpace(code), "\n")
	if len(lines) > 1 {
		return false
	}

	// Check for complex constructs
	complexPatterns := []string{"if", "for", "while", "function", "case", "{", "}"}
	for _, pattern := range complexPatterns {
		if strings.Contains(code, pattern) {
			return false
		}
	}

	return true
}
