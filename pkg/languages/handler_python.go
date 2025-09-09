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

// PythonHandler handles Python code execution
type PythonHandler struct {
	*BaseHandler
}

// NewPythonHandler creates a new Python handler
func NewPythonHandler() *PythonHandler {
	return &PythonHandler{
		BaseHandler: NewBaseHandler(
			LanguagePython,
			[]string{".py", ".pyw"},
			"python:3.12-slim",
			[]string{"python:3.12-slim", "python:3.11-slim", "python:3.10-slim"},
			"pip",
			60*time.Second,
			false, // Interpreted language
		),
	}
}

// DetectLanguage checks if the code is Python
func (h *PythonHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	// Check file extension
	if strings.HasSuffix(strings.ToLower(filename), ".py") ||
		strings.HasSuffix(strings.ToLower(filename), ".pyw") {
		confidence += 0.8
	}

	// Check shebang
	if strings.HasPrefix(code, "#!/usr/bin/python") ||
		strings.HasPrefix(code, "#!/usr/bin/env python") {
		confidence += 0.9
	}

	// Check for Python-specific patterns
	pythonPatterns := []string{
		`import\s+\w+`,
		`from\s+\w+\s+import`,
		`def\s+\w+\s*\(`,
		`class\s+\w+\s*:`,
		`if\s+__name__\s*==\s*['"']__main__['"]`,
		`print\s*\(`,
		`elif\s+`,
		`except\s+`,
		`finally\s*:`,
		`with\s+\w+`,
		`lambda\s+`,
		`yield\s+`,
		`async\s+def`,
		`await\s+`,
	}

	for _, pattern := range pythonPatterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.15
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares Python code for execution
func (h *PythonHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return err
	}

	// Create additional files if specified
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

// Execute runs Python code
func (h *PythonHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguagePython,
		Metadata: make(map[string]string),
	}

	// Write Python file
	pythonFile := filepath.Join(req.WorkingDir, "main.py")
	if err := os.WriteFile(pythonFile, []byte(req.Code), 0644); err != nil {
		result.Error = err
		return result, err
	}

	// Execute Python code
	execCtx, execCancel := context.WithTimeout(ctx, req.Timeout)
	defer execCancel()

	execCmd := exec.CommandContext(execCtx, "python3", pythonFile)
	execCmd.Dir = req.WorkingDir

	// Set environment
	execCmd.Env = os.Environ()
	for key, value := range req.Environment {
		execCmd.Env = append(execCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	if req.Stdin != "" {
		execCmd.Stdin = strings.NewReader(req.Stdin)
	}

	output, err := execCmd.CombinedOutput()
	result.Duration = time.Since(startTime)
	result.Stdout = string(output)
	result.Command = "python3 main.py"

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

// InstallPackages installs Python packages using pip
func (h *PythonHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	if len(req.Packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	result := &PackageInstallResult{
		InstalledPackages: make([]string, 0),
		FailedPackages:    make([]string, 0),
	}

	startTime := time.Now()

	// Build pip install command
	args := []string{"install", "--user"}
	args = append(args, req.Packages...)

	execCmd := exec.CommandContext(ctx, "pip3", args...)
	execCmd.Dir = req.WorkingDir

	output, err := execCmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.FailedPackages = req.Packages
		result.Error = err
		return result, nil
	}

	result.Success = true
	result.InstalledPackages = req.Packages
	return result, nil
}

// SetupEnvironment sets up Python environment
func (h *PythonHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	result := &EnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	// Check Python version
	cmd := exec.CommandContext(ctx, "python3", "--version")
	output, err := cmd.Output()
	if err != nil {
		result.Success = false
		result.Error = err
		return result, result.Error
	}

	result.Version = strings.TrimSpace(string(output))
	result.Path = "python3"
	result.Success = true
	result.Output = fmt.Sprintf("Python environment ready. %s", result.Version)

	return result, nil
}

// GetRequiredFiles returns files needed for Python execution
func (h *PythonHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)
	files["main.py"] = req.Code
	return files
}

// GetCompileCommand returns empty for Python (interpreted)
func (h *PythonHandler) GetCompileCommand(req *ExecutionRequest) string {
	return ""
}

// GetRunCommand returns the Python run command
func (h *PythonHandler) GetRunCommand(req *ExecutionRequest) string {
	return "python3 main.py"
}

// ValidateCode performs basic Python validation
func (h *PythonHandler) ValidateCode(code string) error {
	return h.BaseHandler.ValidateCode(code)
}
