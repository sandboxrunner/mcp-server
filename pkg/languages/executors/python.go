package executors

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/types"
)

// PythonExecutor handles Python code execution with virtualenv support
type PythonExecutor struct {
	*BaseExecutor
	pythonCmd    string
	venvPath     string
	pipCmd       string
	requirements []string
}

// NewPythonExecutor creates a new Python executor
func NewPythonExecutor() *PythonExecutor {
	base := NewBaseExecutor(
		types.LanguagePython,
		60*time.Second,
		[]string{"pip", "conda", "poetry", "pipenv"},
		false,
	)

	return &PythonExecutor{
		BaseExecutor: base,
		pythonCmd:    "python3",
		requirements: []string{},
	}
}

// GetVersion returns the Python version
func (e *PythonExecutor) GetVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.pythonCmd, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Python version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	version = strings.TrimPrefix(version, "Python ")
	return version, nil
}

// SetupEnvironment prepares the Python execution environment
func (e *PythonExecutor) SetupEnvironment(ctx context.Context, options *ExecutionOptions) (*EnvironmentInfo, error) {
	// Set Python command from options if specified
	if pythonCmd, exists := options.CustomConfig["python_cmd"]; exists {
		e.pythonCmd = pythonCmd
	}

	// Create working directory
	if err := os.MkdirAll(options.WorkingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Setup virtual environment if requested
	var venvPath string
	if options.UseVirtualEnv {
		venvPath = filepath.Join(options.WorkingDir, ".venv")
		e.venvPath = venvPath

		// Create virtual environment
		if err := e.createVirtualEnv(ctx, venvPath); err != nil {
			return nil, fmt.Errorf("failed to create virtual environment: %w", err)
		}

		// Update Python and pip commands to use virtual environment
		if isWindows() {
			e.pythonCmd = filepath.Join(venvPath, "Scripts", "python.exe")
			e.pipCmd = filepath.Join(venvPath, "Scripts", "pip.exe")
		} else {
			e.pythonCmd = filepath.Join(venvPath, "bin", "python")
			e.pipCmd = filepath.Join(venvPath, "bin", "pip")
		}
	} else {
		e.pipCmd = "pip3"
	}

	// Get version info
	version, err := e.GetVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Python version: %w", err)
	}

	// Create environment info
	envInfo := &EnvironmentInfo{
		Language:       e.GetLanguage(),
		Version:        version,
		Interpreter:    e.pythonCmd,
		PackageManager: e.pipCmd,
		VirtualEnvPath: venvPath,
		WorkingDir:     options.WorkingDir,
		ConfigFiles:    []string{},
		SystemInfo: map[string]string{
			"python_executable": e.pythonCmd,
			"pip_executable":    e.pipCmd,
			"virtual_env":       fmt.Sprintf("%v", options.UseVirtualEnv),
		},
	}

	// Add requirements.txt if packages are specified
	if len(options.Packages) > 0 {
		reqFile := filepath.Join(options.WorkingDir, "requirements.txt")
		envInfo.ConfigFiles = append(envInfo.ConfigFiles, reqFile)
	}

	e.UpdateMetrics("setup_completed", time.Now())
	e.UpdateMetrics("virtual_env_used", options.UseVirtualEnv)
	e.UpdateMetrics("python_version", version)

	return envInfo, nil
}

// InstallPackages installs Python packages using pip
func (e *PythonExecutor) InstallPackages(ctx context.Context, packages []string, options *ExecutionOptions) (*PackageInstallResult, error) {
	if len(packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	startTime := time.Now()
	result := &PackageInstallResult{
		InstalledPackages: []PackageInfo{},
		FailedPackages:    []string{},
	}

	// Create requirements.txt file
	reqFile := filepath.Join(options.WorkingDir, "requirements.txt")
	reqContent := strings.Join(packages, "\n")
	
	if err := os.WriteFile(reqFile, []byte(reqContent), 0644); err != nil {
		result.Error = fmt.Errorf("failed to create requirements.txt: %w", err)
		return result, nil
	}

	// Prepare install command
	args := []string{"install", "-r", reqFile}
	
	// Add user flag if not using virtual environment
	if !options.UseVirtualEnv {
		args = append([]string{"install", "--user", "-r", reqFile}, args[3:]...)
	}

	// Add additional pip options
	if upgrade, exists := options.CustomConfig["upgrade"]; exists && upgrade == "true" {
		args = append(args, "--upgrade")
	}
	
	if quiet, exists := options.CustomConfig["quiet"]; exists && quiet == "true" {
		args = append(args, "--quiet")
	}

	// Execute pip install
	cmd := exec.CommandContext(ctx, e.pipCmd, args...)
	cmd.Dir = options.WorkingDir
	
	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("pip install failed: %w", err)
		result.FailedPackages = packages
		return result, nil
	}

	// Parse successful installations
	result.Success = true
	for _, pkg := range packages {
		// Extract package name (handle version specifiers)
		pkgName := strings.Split(pkg, "==")[0]
		pkgName = strings.Split(pkgName, ">=")[0]
		pkgName = strings.Split(pkgName, "<=")[0]
		pkgName = strings.Split(pkgName, ">")[0]
		pkgName = strings.Split(pkgName, "<")[0]
		pkgName = strings.Split(pkgName, "~=")[0]
		
		result.InstalledPackages = append(result.InstalledPackages, PackageInfo{
			Name: strings.TrimSpace(pkgName),
		})
	}

	e.UpdateMetrics("packages_installed", len(result.InstalledPackages))
	e.UpdateMetrics("package_install_duration", result.Duration)

	return result, nil
}

// ValidateCode performs Python syntax validation
func (e *PythonExecutor) ValidateCode(ctx context.Context, code string, options *ExecutionOptions) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("empty code provided")
	}

	// Create temporary file for syntax checking
	tmpFile := filepath.Join(options.WorkingDir, "syntax_check.py")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Check syntax using python -m py_compile
	cmd := exec.CommandContext(ctx, e.pythonCmd, "-m", "py_compile", tmpFile)
	cmd.Dir = options.WorkingDir
	
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syntax error: %s", string(output))
	}

	e.UpdateMetrics("syntax_validation_completed", time.Now())
	return nil
}

// PrepareFiles creates necessary files for Python execution
func (e *PythonExecutor) PrepareFiles(ctx context.Context, code string, options *ExecutionOptions) (map[string]string, error) {
	files := make(map[string]string)
	
	// Main Python file
	mainFile := "main.py"
	files[mainFile] = code
	
	// Add user-specified files
	for filename, content := range options.Files {
		files[filename] = content
	}
	
	// Create requirements.txt if packages are specified
	if len(options.Packages) > 0 {
		files["requirements.txt"] = strings.Join(options.Packages, "\n")
	}
	
	// Write all files to working directory
	for filename, content := range files {
		fullPath := filepath.Join(options.WorkingDir, filename)
		
		// Create directories if needed
		if dir := filepath.Dir(fullPath); dir != options.WorkingDir {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
		
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("failed to write file %s: %w", filename, err)
		}
	}
	
	e.UpdateMetrics("files_prepared", len(files))
	return files, nil
}

// Compile is not needed for Python (interpreted language)
func (e *PythonExecutor) Compile(ctx context.Context, code string, options *ExecutionOptions) (*CompilationResult, error) {
	return &CompilationResult{
		Success:  true,
		Duration: 0,
		CacheHit: true,
	}, nil
}

// Execute runs Python code and returns the result
func (e *PythonExecutor) Execute(ctx context.Context, code string, options *ExecutionOptions) (*ExecutionResult, error) {
	startTime := time.Now()
	
	// Prepare files
	files, err := e.PrepareFiles(ctx, code, options)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare files: %w", err)
	}
	
	// Install packages if specified
	if len(options.Packages) > 0 {
		if _, err := e.InstallPackages(ctx, options.Packages, options); err != nil {
			return &ExecutionResult{
				ExitCode: 1,
				Stderr:   fmt.Sprintf("Package installation failed: %v", err),
				Duration: time.Since(startTime),
				Language: e.GetLanguage(),
				Error:    err,
			}, nil
		}
	}
	
	// Execute Python code
	executionStart := time.Now()
	args := []string{"main.py"}
	
	// Add runtime flags if specified
	if len(options.RuntimeFlags) > 0 {
		args = append(options.RuntimeFlags, args...)
	}
	
	cmd := exec.CommandContext(ctx, e.pythonCmd, args...)
	cmd.Dir = options.WorkingDir
	
	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env
	
	// Setup stdin if provided
	if options.Stdin != "" {
		cmd.Stdin = strings.NewReader(options.Stdin)
	}
	
	// Execute command
	stdout, stderr, exitCode := e.executeCommand(ctx, cmd, options.Timeout)
	executionTime := time.Since(executionStart)
	totalDuration := time.Since(startTime)
	
	// Collect created files
	createdFiles := make([]string, 0, len(files))
	for filename := range files {
		createdFiles = append(createdFiles, filename)
	}
	
	result := &ExecutionResult{
		ExitCode:        exitCode,
		Stdout:          stdout,
		Stderr:          stderr,
		Duration:        totalDuration,
		Language:        e.GetLanguage(),
		Commands:        []string{fmt.Sprintf("%s %s", e.pythonCmd, strings.Join(args, " "))},
		CreatedFiles:    createdFiles,
		ExecutionTime:   executionTime,
		Metadata: map[string]string{
			"interpreter":      e.pythonCmd,
			"working_dir":      options.WorkingDir,
			"virtual_env_used": fmt.Sprintf("%v", options.UseVirtualEnv),
			"packages_count":   fmt.Sprintf("%d", len(options.Packages)),
		},
	}
	
	e.UpdateMetrics("execution_completed", time.Now())
	e.UpdateMetrics("execution_duration", totalDuration)
	e.UpdateMetrics("exit_code", exitCode)
	
	return result, nil
}

// createVirtualEnv creates a Python virtual environment
func (e *PythonExecutor) createVirtualEnv(ctx context.Context, venvPath string) error {
	// Remove existing venv if it exists
	if _, err := os.Stat(venvPath); err == nil {
		if err := os.RemoveAll(venvPath); err != nil {
			return fmt.Errorf("failed to remove existing virtual environment: %w", err)
		}
	}
	
	// Create new virtual environment
	cmd := exec.CommandContext(ctx, e.pythonCmd, "-m", "venv", venvPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create virtual environment: %s", string(output))
	}
	
	return nil
}

// executeCommand executes a command with timeout and returns stdout, stderr, and exit code
func (e *PythonExecutor) executeCommand(ctx context.Context, cmd *exec.Cmd, timeout time.Duration) (string, string, int) {
	// Create context with timeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd.Cancel = func() error {
			return cmd.Process.Kill()
		}
	}
	
	// Execute command
	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	
	// Parse stdout and stderr (Python writes to both)
	lines := strings.Split(outputStr, "\n")
	var stdout, stderr []string
	
	for _, line := range lines {
		// Simple heuristic: lines with "Traceback" or "Error:" go to stderr
		if strings.Contains(line, "Traceback") || 
		   strings.Contains(line, "Error:") || 
		   strings.Contains(line, "Exception:") ||
		   regexp.MustCompile(`^\s*File "`).MatchString(line) {
			stderr = append(stderr, line)
		} else if strings.TrimSpace(line) != "" {
			stdout = append(stdout, line)
		}
	}
	
	// Determine exit code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}
	
	return strings.Join(stdout, "\n"), strings.Join(stderr, "\n"), exitCode
}

// extractPythonImports extracts import statements from Python code
func (e *PythonExecutor) extractPythonImports(code string) []string {
	var imports []string
	
	// Regular expressions for different import patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^\s*import\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)`),
		regexp.MustCompile(`^\s*from\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s+import`),
	}
	
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		for _, pattern := range patterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				importName := strings.Split(matches[1], ".")[0] // Get top-level module
				imports = append(imports, importName)
			}
		}
	}
	
	return removeDuplicates(imports)
}

// isWindows checks if the current OS is Windows
func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows")
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}