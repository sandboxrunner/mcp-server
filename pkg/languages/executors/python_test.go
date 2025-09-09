package executors

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/types"
)

func TestPythonExecutor(t *testing.T) {
	// Skip test if Python is not available
	if _, err := os.Stat("/usr/bin/python3"); os.IsNotExist(err) {
		t.Skip("Python3 not found, skipping test")
	}

	executor := NewPythonExecutor()
	ctx := context.Background()

	// Create temporary working directory
	tempDir := t.TempDir()

	t.Run("GetVersion", func(t *testing.T) {
		version, err := executor.GetVersion(ctx)
		if err != nil {
			t.Fatalf("Failed to get Python version: %v", err)
		}
		if version == "" {
			t.Error("Expected non-empty version string")
		}
		t.Logf("Python version: %s", version)
	})

	t.Run("SetupEnvironment", func(t *testing.T) {
		options := &ExecutionOptions{
			WorkingDir:    tempDir,
			UseVirtualEnv: false,
		}

		envInfo, err := executor.SetupEnvironment(ctx, options)
		if err != nil {
			t.Fatalf("Failed to setup environment: %v", err)
		}

		if envInfo.Language != types.LanguagePython {
			t.Errorf("Expected language Python, got %s", envInfo.Language)
		}
		if envInfo.WorkingDir != tempDir {
			t.Errorf("Expected working dir %s, got %s", tempDir, envInfo.WorkingDir)
		}
	})

	t.Run("ValidateCode", func(t *testing.T) {
		options := &ExecutionOptions{
			WorkingDir: tempDir,
		}

		// Valid code
		err := executor.ValidateCode(ctx, "print('Hello, World!')", options)
		if err != nil {
			t.Errorf("Valid code should not produce error: %v", err)
		}

		// Invalid code
		err = executor.ValidateCode(ctx, "print('unclosed string", options)
		if err == nil {
			t.Error("Invalid code should produce error")
		}
	})

	t.Run("PrepareFiles", func(t *testing.T) {
		options := &ExecutionOptions{
			WorkingDir: tempDir,
			Files: map[string]string{
				"helper.py": "def helper():\n    return 'helper'",
			},
		}

		files, err := executor.PrepareFiles(ctx, "print('Hello')", options)
		if err != nil {
			t.Fatalf("Failed to prepare files: %v", err)
		}

		if _, exists := files["main.py"]; !exists {
			t.Error("Expected main.py to be created")
		}
		if _, exists := files["helper.py"]; !exists {
			t.Error("Expected helper.py to be created")
		}

		// Check if files were actually written
		mainPath := filepath.Join(tempDir, "main.py")
		if _, err := os.Stat(mainPath); os.IsNotExist(err) {
			t.Error("main.py was not written to disk")
		}
	})

	t.Run("Execute", func(t *testing.T) {
		options := &ExecutionOptions{
			WorkingDir: tempDir,
			Timeout:    5 * time.Second,
		}

		result, err := executor.Execute(ctx, "print('Hello, Python!')", options)
		if err != nil {
			t.Fatalf("Failed to execute Python code: %v", err)
		}

		if result.ExitCode != 0 {
			t.Errorf("Expected exit code 0, got %d", result.ExitCode)
		}
		if !contains(result.Stdout, "Hello, Python!") {
			t.Errorf("Expected output to contain 'Hello, Python!', got: %s", result.Stdout)
		}
		if result.Language != types.LanguagePython {
			t.Errorf("Expected language Python, got %s", result.Language)
		}
	})

	t.Run("ExecuteWithPackages", func(t *testing.T) {
		options := &ExecutionOptions{
			WorkingDir: tempDir,
			Packages:   []string{"json"},
			Timeout:    30 * time.Second,
		}

		code := `
import json
data = {"message": "Hello, JSON!"}
print(json.dumps(data))
`

		result, err := executor.Execute(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to execute Python code with packages: %v", err)
		}

		if result.ExitCode != 0 {
			t.Errorf("Expected exit code 0, got %d", result.ExitCode)
			t.Logf("Stderr: %s", result.Stderr)
		}
	})

	t.Run("ExecuteWithVirtualEnv", func(t *testing.T) {
		venvDir := filepath.Join(tempDir, "venv_test")
		options := &ExecutionOptions{
			WorkingDir:    venvDir,
			UseVirtualEnv: true,
			Timeout:       30 * time.Second,
		}

		// Create directory
		os.MkdirAll(venvDir, 0755)

		result, err := executor.Execute(ctx, "import sys; print(sys.executable)", options)
		if err != nil {
			t.Fatalf("Failed to execute Python code with virtual env: %v", err)
		}

		if result.ExitCode != 0 {
			t.Errorf("Expected exit code 0, got %d", result.ExitCode)
			t.Logf("Stderr: %s", result.Stderr)
		}

		// Check if virtual environment was used
		if result.Metadata["virtual_env_used"] != "true" {
			t.Error("Expected virtual environment to be used")
		}
	})

	t.Run("ExecuteWithError", func(t *testing.T) {
		options := &ExecutionOptions{
			WorkingDir: tempDir,
			Timeout:    5 * time.Second,
		}

		result, err := executor.Execute(ctx, "undefined_variable", options)
		if err != nil {
			t.Fatalf("Execute should not return error for runtime failures: %v", err)
		}

		if result.ExitCode == 0 {
			t.Error("Expected non-zero exit code for invalid code")
		}
		if result.Stderr == "" {
			t.Error("Expected stderr to contain error message")
		}
	})
}

func TestPythonExecutorInstallPackages(t *testing.T) {
	// Skip if Python is not available
	if _, err := os.Stat("/usr/bin/python3"); os.IsNotExist(err) {
		t.Skip("Python3 not found, skipping test")
	}

	executor := NewPythonExecutor()
	ctx := context.Background()
	tempDir := t.TempDir()

	options := &ExecutionOptions{
		WorkingDir: tempDir,
		Timeout:    60 * time.Second,
	}

	// Setup environment first
	_, err := executor.SetupEnvironment(ctx, options)
	if err != nil {
		t.Fatalf("Failed to setup environment: %v", err)
	}

	t.Run("InstallValidPackage", func(t *testing.T) {
		// Test with a lightweight, commonly available package
		packages := []string{"six"} // six is a lightweight Python 2/3 compatibility library

		result, err := executor.InstallPackages(ctx, packages, options)
		if err != nil {
			t.Fatalf("Failed to install packages: %v", err)
		}

		if !result.Success {
			t.Errorf("Package installation failed: %s", result.Output)
		}
		if len(result.InstalledPackages) == 0 {
			t.Error("Expected at least one installed package")
		}
	})

	t.Run("InstallNonExistentPackage", func(t *testing.T) {
		packages := []string{"non_existent_package_12345"}

		result, err := executor.InstallPackages(ctx, packages, options)
		if err != nil {
			t.Fatalf("InstallPackages should not return error: %v", err)
		}

		if result.Success {
			t.Error("Installing non-existent package should fail")
		}
		if len(result.FailedPackages) == 0 {
			t.Error("Expected failed packages list to be non-empty")
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    contains(s[1:], substr) || 
		    (len(s) > 0 && s[:len(substr)] == substr))
}