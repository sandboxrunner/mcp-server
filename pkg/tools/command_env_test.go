package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewCommandEnvironment(t *testing.T) {
	tests := []struct {
		name      string
		opts      EnvironmentOptions
		wantError bool
	}{
		{
			name: "valid environment options",
			opts: EnvironmentOptions{
				BaseEnvironment: map[string]string{
					"TEST_VAR": "test_value",
				},
				WorkingDirectory: "/workspace",
				Language:         "python",
				User:             "root",
				Shell:            "/bin/bash",
				ExpandVariables:  true,
				FilterSensitive:  true,
			},
			wantError: false,
		},
		{
			name:      "empty options with defaults",
			opts:      EnvironmentOptions{},
			wantError: false,
		},
		{
			name: "invalid working directory",
			opts: EnvironmentOptions{
				WorkingDirectory: "/invalid/path/outside/allowed",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := NewCommandEnvironment(tt.opts)

			if tt.wantError {
				if err == nil {
					t.Errorf("NewCommandEnvironment() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("NewCommandEnvironment() unexpected error: %v", err)
				return
			}

			if env == nil {
				t.Error("NewCommandEnvironment() returned nil environment")
			}

			// Validate environment was properly initialized
			if err := env.Validate(); err != nil {
				t.Errorf("Environment validation failed: %v", err)
			}
		})
	}
}

func TestCommandEnvironment_PrepareEnvironmentForLanguage(t *testing.T) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		BaseEnvironment: map[string]string{
			"PATH": "/usr/bin:/bin",
			"HOME": "/root",
		},
	})
	if err != nil {
		t.Fatalf("Failed to create environment: %v", err)
	}

	tests := []struct {
		name     string
		language string
		wantVars []string // Variables that should be present
	}{
		{
			name:     "python environment",
			language: "python",
			wantVars: []string{"PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE", "PATH"},
		},
		{
			name:     "node environment",
			language: "node",
			wantVars: []string{"NODE_ENV", "NPM_CONFIG_CACHE", "PATH"},
		},
		{
			name:     "go environment",
			language: "go",
			wantVars: []string{"GOCACHE", "GOMODCACHE", "CGO_ENABLED", "PATH"},
		},
		{
			name:     "unknown language",
			language: "unknown",
			wantVars: []string{"PATH", "HOME"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envSlice, err := env.PrepareEnvironmentForLanguage(tt.language)
			if err != nil {
				t.Errorf("PrepareEnvironmentForLanguage() error: %v", err)
				return
			}

			envMap := make(map[string]string)
			for _, envVar := range envSlice {
				parts := strings.SplitN(envVar, "=", 2)
				if len(parts) == 2 {
					envMap[parts[0]] = parts[1]
				}
			}

			for _, wantVar := range tt.wantVars {
				if _, exists := envMap[wantVar]; !exists {
					t.Errorf("Expected environment variable %s not found", wantVar)
				}
			}

			// Check that PATH contains language-specific paths for known languages
			if tt.language != "unknown" {
				pathValue := envMap["PATH"]
				if pathValue == "" {
					t.Error("PATH environment variable is empty")
				}
			}
		})
	}
}

func TestCommandEnvironment_UserContext(t *testing.T) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		User: "root",
	})
	if err != nil {
		t.Fatalf("Failed to create environment: %v", err)
	}

	userCtx := env.GetUserContext()
	if userCtx == nil {
		t.Fatal("GetUserContext() returned nil")
	}

	if userCtx.Username != "root" {
		t.Errorf("Expected username 'root', got '%s'", userCtx.Username)
	}

	if userCtx.UID != 0 {
		t.Errorf("Expected UID 0, got %d", userCtx.UID)
	}

	if userCtx.GID != 0 {
		t.Errorf("Expected GID 0, got %d", userCtx.GID)
	}
}

func TestCommandEnvironment_WorkingDirectory(t *testing.T) {
	tests := []struct {
		name      string
		workDir   string
		wantError bool
	}{
		{
			name:      "valid workspace directory",
			workDir:   "/workspace/test",
			wantError: false,
		},
		{
			name:      "valid tmp directory",
			workDir:   "/tmp/test",
			wantError: false,
		},
		{
			name:      "invalid directory outside allowed paths",
			workDir:   "/etc/passwd",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := NewCommandEnvironment(EnvironmentOptions{
				WorkingDirectory: tt.workDir,
			})

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error for working directory %s, got nil", tt.workDir)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for working directory %s: %v", tt.workDir, err)
				return
			}

			actualDir := env.GetWorkingDirectory()
			expectedDir, _ := filepath.Abs(tt.workDir)
			if actualDir != expectedDir {
				t.Errorf("Expected working directory %s, got %s", expectedDir, actualDir)
			}
		})
	}
}

func TestCommandEnvironment_EnvironmentVariableManagement(t *testing.T) {
	env, err := NewCommandEnvironment(EnvironmentOptions{})
	if err != nil {
		t.Fatalf("Failed to create environment: %v", err)
	}

	// Test updating environment variable
	err = env.UpdateEnvironmentVariable("TEST_VAR", "test_value")
	if err != nil {
		t.Errorf("UpdateEnvironmentVariable() error: %v", err)
	}

	envVars := env.GetEnvironmentVariables(false)
	if envVars["TEST_VAR"] != "test_value" {
		t.Errorf("Expected TEST_VAR='test_value', got '%s'", envVars["TEST_VAR"])
	}

	// Test removing environment variable
	err = env.RemoveEnvironmentVariable("TEST_VAR")
	if err != nil {
		t.Errorf("RemoveEnvironmentVariable() error: %v", err)
	}

	envVars = env.GetEnvironmentVariables(false)
	if _, exists := envVars["TEST_VAR"]; exists {
		t.Error("Expected TEST_VAR to be removed, but it still exists")
	}

	// Test that essential variables cannot be removed
	err = env.RemoveEnvironmentVariable("PATH")
	if err == nil {
		t.Error("Expected error when removing essential variable PATH, got nil")
	}
}

func TestCommandEnvironment_SensitiveVariableFiltering(t *testing.T) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		FilterSensitive: true,
	})
	if err != nil {
		t.Fatalf("Failed to create environment: %v", err)
	}

	// Try to set a sensitive variable
	sensitiveVars := map[string]string{
		"PASSWORD":     "secret123",
		"API_KEY":      "key123",
		"PRIVATE_KEY":  "private123",
		"DATABASE_URL": "postgres://user:pass@host/db",
	}

	for key, value := range sensitiveVars {
		err := env.UpdateEnvironmentVariable(key, value)
		if err == nil {
			t.Errorf("Expected error when setting sensitive variable %s, got nil", key)
		}
	}

	// Test that non-sensitive variables can be set
	err = env.UpdateEnvironmentVariable("NORMAL_VAR", "normal_value")
	if err != nil {
		t.Errorf("Unexpected error when setting normal variable: %v", err)
	}
}

func TestCommandEnvironment_VariableExpansion(t *testing.T) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		BaseEnvironment: map[string]string{
			"BASE_PATH": "/usr/local/bin",
			"HOME":      "/root",
		},
		ExpandVariables: true,
	})
	if err != nil {
		t.Fatalf("Failed to create environment: %v", err)
	}

	// Add a variable that references another variable
	env.UpdateEnvironmentVariable("EXPANDED_PATH", "${BASE_PATH}:/bin")

	envSlice, err := env.PrepareEnvironmentForLanguage("")
	if err != nil {
		t.Errorf("PrepareEnvironmentForLanguage() error: %v", err)
	}

	// Convert to map for easier checking
	envMap := make(map[string]string)
	for _, envVar := range envSlice {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	expandedPath := envMap["EXPANDED_PATH"]
	if expandedPath != "/usr/local/bin:/bin" {
		t.Errorf("Expected EXPANDED_PATH='/usr/local/bin:/bin', got '%s'", expandedPath)
	}
}

func TestCommandEnvironment_Clone(t *testing.T) {
	original, err := NewCommandEnvironment(EnvironmentOptions{
		BaseEnvironment: map[string]string{
			"TEST_VAR": "test_value",
		},
		WorkingDirectory: "/workspace",
		User:             "root",
	})
	if err != nil {
		t.Fatalf("Failed to create original environment: %v", err)
	}

	clone, err := original.Clone()
	if err != nil {
		t.Errorf("Clone() error: %v", err)
		return
	}

	// Test that clone has same values
	originalVars := original.GetEnvironmentVariables(false)
	cloneVars := clone.GetEnvironmentVariables(false)

	if len(originalVars) != len(cloneVars) {
		t.Errorf("Clone has different number of environment variables: original=%d, clone=%d", len(originalVars), len(cloneVars))
	}

	for key, value := range originalVars {
		if cloneVars[key] != value {
			t.Errorf("Clone environment variable %s: expected '%s', got '%s'", key, value, cloneVars[key])
		}
	}

	// Test that modifying clone doesn't affect original
	clone.UpdateEnvironmentVariable("CLONE_ONLY", "clone_value")

	originalVarsAfter := original.GetEnvironmentVariables(false)
	if _, exists := originalVarsAfter["CLONE_ONLY"]; exists {
		t.Error("Modifying clone affected original environment")
	}
}

func TestCommandEnvironment_Validation(t *testing.T) {
	tests := []struct {
		name      string
		setup     func() *CommandEnvironment
		wantError bool
	}{
		{
			name: "valid environment",
			setup: func() *CommandEnvironment {
				env, _ := NewCommandEnvironment(EnvironmentOptions{})
				return env
			},
			wantError: false,
		},
		{
			name: "missing essential variables",
			setup: func() *CommandEnvironment {
				env, _ := NewCommandEnvironment(EnvironmentOptions{})
				env.RemoveEnvironmentVariable("USER") // This should be prevented, but test the validation
				return env
			},
			wantError: false, // Should be false because removal of essential vars is prevented
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.setup()
			err := env.Validate()

			if tt.wantError {
				if err == nil {
					t.Error("Expected validation error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected validation error: %v", err)
				}
			}
		})
	}
}

func TestCommandEnvironment_ShellDetection(t *testing.T) {
	// Create a temporary directory with test shells
	tempDir, err := os.MkdirTemp("", "shell_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a mock shell file
	mockShell := filepath.Join(tempDir, "bash")
	file, err := os.Create(mockShell)
	if err != nil {
		t.Fatalf("Failed to create mock shell: %v", err)
	}
	file.Close()

	env, err := NewCommandEnvironment(EnvironmentOptions{
		Shell: mockShell,
	})
	if err != nil {
		t.Fatalf("Failed to create environment: %v", err)
	}

	detectedShell := env.GetDefaultShell()
	if detectedShell != mockShell {
		t.Errorf("Expected shell %s, got %s", mockShell, detectedShell)
	}
}

// Benchmark tests
func BenchmarkCommandEnvironment_PrepareEnvironmentForLanguage(b *testing.B) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		BaseEnvironment: map[string]string{
			"PATH": "/usr/bin:/bin",
			"HOME": "/root",
			"USER": "root",
		},
	})
	if err != nil {
		b.Fatalf("Failed to create environment: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := env.PrepareEnvironmentForLanguage("python")
		if err != nil {
			b.Errorf("PrepareEnvironmentForLanguage() error: %v", err)
		}
	}
}

func BenchmarkCommandEnvironment_Clone(b *testing.B) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		BaseEnvironment: map[string]string{
			"PATH": "/usr/bin:/bin",
			"HOME": "/root",
			"USER": "root",
		},
	})
	if err != nil {
		b.Fatalf("Failed to create environment: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := env.Clone()
		if err != nil {
			b.Errorf("Clone() error: %v", err)
		}
	}
}
