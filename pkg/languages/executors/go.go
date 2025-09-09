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

// GoModFile represents a Go module file (go.mod)
type GoModFile struct {
	Module  string   `json:"module"`
	Go      string   `json:"go"`
	Require []string `json:"require,omitempty"`
	Replace []string `json:"replace,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// GoExecutor handles Go code execution with module support
type GoExecutor struct {
	*BaseExecutor
	goCmd      string
	moduleName string
	goVersion  string
	buildFlags []string
	modFile    *GoModFile
}

// NewGoExecutor creates a new Go executor
func NewGoExecutor() *GoExecutor {
	base := NewBaseExecutor(
		types.LanguageGo,
		30*time.Second,
		[]string{"go"},
		true,
	)

	return &GoExecutor{
		BaseExecutor: base,
		goCmd:        "go",
		moduleName:   "sandbox-project",
		goVersion:    "1.21",
		buildFlags:   []string{},
	}
}

// GetVersion returns the Go version
func (e *GoExecutor) GetVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.goCmd, "version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Go version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	// Extract version from "go version go1.21.0 linux/amd64"
	re := regexp.MustCompile(`go(\d+\.\d+(?:\.\d+)?)`)
	matches := re.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return version, nil
}

// SetupEnvironment prepares the Go execution environment
func (e *GoExecutor) SetupEnvironment(ctx context.Context, options *ExecutionOptions) (*EnvironmentInfo, error) {
	// Set Go command from options if specified
	if goCmd, exists := options.CustomConfig["go_cmd"]; exists {
		e.goCmd = goCmd
	}

	// Set module name from options
	if moduleName, exists := options.CustomConfig["module_name"]; exists {
		e.moduleName = moduleName
	}

	// Set Go version from options
	if goVersion, exists := options.CustomConfig["go_version"]; exists {
		e.goVersion = goVersion
	}

	// Create working directory
	if err := os.MkdirAll(options.WorkingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Initialize Go module
	if err := e.initializeGoModule(ctx, options); err != nil {
		return nil, fmt.Errorf("failed to initialize Go module: %w", err)
	}

	// Get version info
	version, err := e.GetVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Go version: %w", err)
	}

	// Create environment info
	envInfo := &EnvironmentInfo{
		Language:       e.GetLanguage(),
		Version:        version,
		Interpreter:    e.goCmd,
		PackageManager: e.goCmd,
		WorkingDir:     options.WorkingDir,
		ConfigFiles:    []string{"go.mod"},
		SystemInfo: map[string]string{
			"go_executable": e.goCmd,
			"module_name":   e.moduleName,
			"go_version":    e.goVersion,
		},
	}

	// Check for go.sum
	goSumPath := filepath.Join(options.WorkingDir, "go.sum")
	if _, err := os.Stat(goSumPath); err == nil {
		envInfo.ConfigFiles = append(envInfo.ConfigFiles, "go.sum")
	}

	e.UpdateMetrics("setup_completed", time.Now())
	e.UpdateMetrics("module_name", e.moduleName)
	e.UpdateMetrics("go_version", version)

	return envInfo, nil
}

// InstallPackages installs Go modules/packages
func (e *GoExecutor) InstallPackages(ctx context.Context, packages []string, options *ExecutionOptions) (*PackageInstallResult, error) {
	if len(packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	startTime := time.Now()
	result := &PackageInstallResult{
		InstalledPackages: []PackageInfo{},
		FailedPackages:    []string{},
	}

	// Ensure go.mod exists
	if err := e.initializeGoModule(ctx, options); err != nil {
		result.Error = fmt.Errorf("failed to initialize Go module: %w", err)
		return result, nil
	}

	// Install each package
	for _, pkg := range packages {
		if err := e.installSinglePackage(ctx, pkg, options, result); err != nil {
			result.FailedPackages = append(result.FailedPackages, pkg)
			if result.Output != "" {
				result.Output += "\n"
			}
			result.Output += fmt.Sprintf("Failed to install %s: %v", pkg, err)
		}
	}

	// Run go mod tidy to clean up dependencies
	tidyCmd := exec.CommandContext(ctx, e.goCmd, "mod", "tidy")
	tidyCmd.Dir = options.WorkingDir
	if output, err := tidyCmd.CombinedOutput(); err != nil {
		result.Output += "\nGo mod tidy warning: " + string(output)
	}

	result.Duration = time.Since(startTime)
	result.Success = len(result.FailedPackages) == 0

	e.UpdateMetrics("packages_installed", len(result.InstalledPackages))
	e.UpdateMetrics("package_install_duration", result.Duration)

	return result, nil
}

// ValidateCode performs Go syntax validation
func (e *GoExecutor) ValidateCode(ctx context.Context, code string, options *ExecutionOptions) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("empty code provided")
	}

	// Create temporary file for syntax checking
	tmpFile := filepath.Join(options.WorkingDir, "syntax_check.go")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Check syntax using go fmt (which includes syntax checking)
	cmd := exec.CommandContext(ctx, e.goCmd, "fmt", tmpFile)
	cmd.Dir = options.WorkingDir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syntax error: %s", string(output))
	}

	e.UpdateMetrics("syntax_validation_completed", time.Now())
	return nil
}

// PrepareFiles creates necessary files for Go execution
func (e *GoExecutor) PrepareFiles(ctx context.Context, code string, options *ExecutionOptions) (map[string]string, error) {
	files := make(map[string]string)

	// Main Go file
	mainFile := "main.go"
	
	// Ensure code has package main declaration
	if !strings.Contains(code, "package main") {
		code = "package main\n\n" + code
	}

	files[mainFile] = code

	// Add user-specified files
	for filename, content := range options.Files {
		files[filename] = content
	}

	// Create go.mod file
	goMod := e.createGoMod(options)
	files["go.mod"] = goMod

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

// Compile compiles Go code
func (e *GoExecutor) Compile(ctx context.Context, code string, options *ExecutionOptions) (*CompilationResult, error) {
	startTime := time.Now()
	
	result := &CompilationResult{
		Success:   false,
		CacheKey:  e.generateCacheKey(code, options),
		CacheHit:  false,
	}

	// Prepare compilation arguments
	args := []string{"build"}
	
	// Add build flags
	if len(e.buildFlags) > 0 {
		args = append(args, e.buildFlags...)
	}
	
	if len(options.CompileFlags) > 0 {
		args = append(args, options.CompileFlags...)
	}

	// Set output executable name
	executableName := "main"
	if isWindows() {
		executableName += ".exe"
	}
	
	args = append(args, "-o", executableName, "main.go")

	// Execute compilation
	cmd := exec.CommandContext(ctx, e.goCmd, args...)
	cmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	
	// Set build mode environment variables
	if options.BuildMode == "release" {
		env = append(env, "CGO_ENABLED=0")
	}
	
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Error = fmt.Errorf("compilation failed: %w", err)
		return result, nil
	}

	// Check if executable was created
	executablePath := filepath.Join(options.WorkingDir, executableName)
	if _, err := os.Stat(executablePath); err != nil {
		result.Error = fmt.Errorf("executable not found after compilation: %w", err)
		return result, nil
	}

	result.Success = true
	result.ExecutablePath = executablePath
	result.ArtifactPaths = []string{executablePath}

	e.UpdateMetrics("compilation_completed", time.Now())
	e.UpdateMetrics("compilation_duration", result.Duration)

	return result, nil
}

// Execute runs Go code and returns the result
func (e *GoExecutor) Execute(ctx context.Context, code string, options *ExecutionOptions) (*ExecutionResult, error) {
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

	// Compile the code
	compileResult, err := e.Compile(ctx, code, options)
	if err != nil {
		return &ExecutionResult{
			ExitCode: 1,
			Stderr:   fmt.Sprintf("Compilation failed: %v", err),
			Duration: time.Since(startTime),
			Language: e.GetLanguage(),
			Error:    err,
		}, nil
	}

	if !compileResult.Success {
		return &ExecutionResult{
			ExitCode:        1,
			Stderr:          compileResult.Output,
			Duration:        time.Since(startTime),
			Language:        e.GetLanguage(),
			CompilationTime: compileResult.Duration,
			Error:           compileResult.Error,
		}, nil
	}

	// Execute the compiled binary
	executionStart := time.Now()
	executableName := "main"
	if isWindows() {
		executableName += ".exe"
	}

	args := []string{"./" + executableName}

	// Add runtime flags if specified
	if len(options.RuntimeFlags) > 0 {
		args = append(args, options.RuntimeFlags...)
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
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
	createdFiles := make([]string, 0, len(files)+1)
	for filename := range files {
		createdFiles = append(createdFiles, filename)
	}
	createdFiles = append(createdFiles, executableName)

	result := &ExecutionResult{
		ExitCode:        exitCode,
		Stdout:          stdout,
		Stderr:          stderr,
		Duration:        totalDuration,
		Language:        e.GetLanguage(),
		Commands:        []string{fmt.Sprintf("go build -o %s main.go", executableName), strings.Join(args, " ")},
		CreatedFiles:    createdFiles,
		CompilationTime: compileResult.Duration,
		ExecutionTime:   executionTime,
		Metadata: map[string]string{
			"go_executable":    e.goCmd,
			"working_dir":      options.WorkingDir,
			"module_name":      e.moduleName,
			"packages_count":   fmt.Sprintf("%d", len(options.Packages)),
			"executable_path":  compileResult.ExecutablePath,
		},
	}

	e.UpdateMetrics("execution_completed", time.Now())
	e.UpdateMetrics("execution_duration", totalDuration)
	e.UpdateMetrics("exit_code", exitCode)

	return result, nil
}

// initializeGoModule creates or updates go.mod file
func (e *GoExecutor) initializeGoModule(ctx context.Context, options *ExecutionOptions) error {
	goModPath := filepath.Join(options.WorkingDir, "go.mod")

	// Check if go.mod already exists
	if _, err := os.Stat(goModPath); err == nil {
		return nil // go.mod already exists
	}

	// Initialize Go module
	cmd := exec.CommandContext(ctx, e.goCmd, "mod", "init", e.moduleName)
	cmd.Dir = options.WorkingDir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to initialize Go module: %s", string(output))
	}

	return nil
}

// createGoMod creates go.mod content
func (e *GoExecutor) createGoMod(options *ExecutionOptions) string {
	goMod := fmt.Sprintf("module %s\n\ngo %s\n", e.moduleName, e.goVersion)

	if len(options.Packages) > 0 {
		goMod += "\nrequire (\n"
		for _, pkg := range options.Packages {
			// Handle version specifications
			if strings.Contains(pkg, "@") {
				parts := strings.Split(pkg, "@")
				goMod += fmt.Sprintf("\t%s %s\n", parts[0], parts[1])
			} else {
				// Use latest version if no version specified
				goMod += fmt.Sprintf("\t%s latest\n", pkg)
			}
		}
		goMod += ")\n"
	}

	return goMod
}

// installSinglePackage installs a single Go package
func (e *GoExecutor) installSinglePackage(ctx context.Context, pkg string, options *ExecutionOptions, result *PackageInstallResult) error {
	// Use go get to install the package
	cmd := exec.CommandContext(ctx, e.goCmd, "get", pkg)
	cmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	if result.Output != "" {
		result.Output += "\n"
	}
	result.Output += string(output)

	if err != nil {
		return fmt.Errorf("go get failed: %w", err)
	}

	// Extract package name for result
	pkgName := pkg
	if strings.Contains(pkg, "@") {
		pkgName = strings.Split(pkg, "@")[0]
	}

	result.InstalledPackages = append(result.InstalledPackages, PackageInfo{
		Name: pkgName,
	})

	return nil
}

// executeCommand executes a command with timeout and returns stdout, stderr, and exit code
func (e *GoExecutor) executeCommand(ctx context.Context, cmd *exec.Cmd, timeout time.Duration) (string, string, int) {
	// Create context with timeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd.Cancel = func() error {
			return cmd.Process.Kill()
		}
	}

	// Capture stdout and stderr separately
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Sprintf("Failed to create stdout pipe: %v", err), 1
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Sprintf("Failed to create stderr pipe: %v", err), 1
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return "", fmt.Sprintf("Failed to start command: %v", err), 1
	}

	// Read output
	stdoutBytes, _ := readAll(stdout)
	stderrBytes, _ := readAll(stderr)

	// Wait for command to finish
	err = cmd.Wait()

	// Determine exit code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return string(stdoutBytes), string(stderrBytes), exitCode
}

// generateCacheKey generates a cache key for compilation
func (e *GoExecutor) generateCacheKey(code string, options *ExecutionOptions) string {
	// Simple hash-like key based on code and options
	key := fmt.Sprintf("go-%s-%s-%v", code[:min(len(code), 100)], e.goVersion, options.CompileFlags)
	return fmt.Sprintf("%x", []byte(key))
}

// extractGoImports extracts import statements from Go code
func (e *GoExecutor) extractGoImports(code string) []string {
	var imports []string

	// Regular expression for Go imports
	patterns := []*regexp.Regexp{
		// Single import: import "package"
		regexp.MustCompile(`^\s*import\s+"([^"]+)"`),
		// Import block: import ( "package1" "package2" )
		regexp.MustCompile(`^\s*"([^"]+)"\s*$`),
	}

	lines := strings.Split(code, "\n")
	inImportBlock := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		
		// Check for import block start
		if strings.HasPrefix(trimmedLine, "import (") {
			inImportBlock = true
			continue
		}
		
		// Check for import block end
		if inImportBlock && strings.Contains(trimmedLine, ")") {
			inImportBlock = false
			continue
		}

		// Process import lines
		for i, pattern := range patterns {
			if (i == 0 && !inImportBlock) || (i == 1 && inImportBlock) {
				matches := pattern.FindStringSubmatch(line)
				if len(matches) > 1 && !strings.HasPrefix(matches[1], ".") {
					// Only include non-relative imports (external packages)
					imports = append(imports, matches[1])
				}
			}
		}
	}

	return removeDuplicates(imports)
}

// readAll reads all data from a reader (helper function)
func readAll(reader interface{}) ([]byte, error) {
	if r, ok := reader.(interface{ Read([]byte) (int, error) }); ok {
		var result []byte
		buf := make([]byte, 1024)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				result = append(result, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		return result, nil
	}
	return nil, fmt.Errorf("invalid reader type")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}