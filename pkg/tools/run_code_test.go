package tools

import (
	"testing"
	"time"
)

func TestRunCodeTool_ValidateCodeInput(t *testing.T) {
	tool := &RunCodeTool{}

	tests := []struct {
		name        string
		code        string
		language    string
		workingDir  string
		timeout     int
		expectError bool
	}{
		{
			name:        "valid python code",
			code:        "print('Hello World')",
			language:    "python",
			workingDir:  "/workspace",
			timeout:     30,
			expectError: false,
		},
		{
			name:        "empty code",
			code:        "",
			language:    "python",
			workingDir:  "/workspace",
			timeout:     30,
			expectError: true,
		},
		{
			name:        "code too long",
			code:        string(make([]byte, 1024*1024+1)), // 1MB + 1 byte
			language:    "python",
			workingDir:  "/workspace",
			timeout:     30,
			expectError: true,
		},
		{
			name:        "timeout too high",
			code:        "print('Hello')",
			language:    "python",
			workingDir:  "/workspace",
			timeout:     400,
			expectError: true,
		},
		{
			name:        "invalid working directory",
			code:        "print('Hello')",
			language:    "python",
			workingDir:  "/etc",
			timeout:     30,
			expectError: true,
		},
		{
			name:        "dangerous command",
			code:        "rm -rf /",
			language:    "bash",
			workingDir:  "/workspace",
			timeout:     30,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tool.validateCodeInput(tt.code, tt.language, tt.workingDir, tt.timeout)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunCodeTool_CreateTempFile(t *testing.T) {
	tool := &RunCodeTool{}

	tests := []struct {
		name       string
		code       string
		language   string
		workingDir string
		wantExt    string
	}{
		{
			name:       "python file",
			code:       "print('hello')",
			language:   "python",
			workingDir: "/tmp/test",
			wantExt:    ".py",
		},
		{
			name:       "javascript file",
			code:       "console.log('hello')",
			language:   "javascript",
			workingDir: "/tmp/test",
			wantExt:    ".js",
		},
		{
			name:       "go file",
			code:       "package main\nfunc main() {}",
			language:   "go",
			workingDir: "/tmp/test",
			wantExt:    ".go",
		},
		{
			name:       "java file with class",
			code:       "public class MyClass { public static void main(String[] args) {} }",
			language:   "java",
			workingDir: "/tmp/test",
			wantExt:    ".java",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempFile, cleanup, err := tool.createTempFile(tt.code, tt.language, tt.workingDir)
			if err != nil {
				t.Fatalf("createTempFile() error = %v", err)
			}
			defer cleanup()

			if tempFile == "" {
				t.Error("expected non-empty temp file path")
			}

			// For now, we just verify the function doesn't crash
			// In a real test environment, we'd check file existence and content
		})
	}
}

func TestRunCodeTool_CreateProcessSpec(t *testing.T) {
	tool := &RunCodeTool{}

	tests := []struct {
		name     string
		language string
		tempFile string
		wantCmd  string
	}{
		{
			name:     "python spec",
			language: "python",
			tempFile: "/workspace/main.py",
			wantCmd:  "python3",
		},
		{
			name:     "javascript spec",
			language: "javascript",
			tempFile: "/workspace/main.js",
			wantCmd:  "node",
		},
		{
			name:     "go spec",
			language: "go",
			tempFile: "/workspace/main.go",
			wantCmd:  "sh",
		},
		{
			name:     "shell spec",
			language: "bash",
			tempFile: "/workspace/script.sh",
			wantCmd:  "bash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := tool.createProcessSpec(tt.language, tt.tempFile, "/workspace", 30*time.Second)
			if err != nil {
				t.Fatalf("createProcessSpec() error = %v", err)
			}

			if spec.Cmd != tt.wantCmd {
				t.Errorf("createProcessSpec() cmd = %v, want %v", spec.Cmd, tt.wantCmd)
			}

			if len(spec.Args) == 0 {
				t.Error("createProcessSpec() args should not be empty")
			}

			if spec.Timeout != 30*time.Second {
				t.Errorf("createProcessSpec() timeout = %v, want %v", spec.Timeout, 30*time.Second)
			}
		})
	}
}

// TestRunCodeTool_LanguageDetection tests the language detection integration
func TestRunCodeTool_LanguageDetection(t *testing.T) {
	tool := &RunCodeTool{}

	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "python import",
			code:     "import sys\nprint('hello')",
			expected: "python",
		},
		{
			name:     "javascript console",
			code:     "console.log('hello world')",
			expected: "javascript",
		},
		{
			name:     "go package",
			code:     "package main\nfunc main() { fmt.Println(\"hello\") }",
			expected: "go",
		},
		{
			name:     "shell echo",
			code:     "echo 'hello world'",
			expected: "bash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected := tool.detectLanguage(tt.code)
			if detected != tt.expected {
				t.Errorf("detectLanguage() = %v, want %v", detected, tt.expected)
			}
		})
	}
}
