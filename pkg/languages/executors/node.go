package executors

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/types"
)

// NodePackageJSON represents a Node.js package.json file
type NodePackageJSON struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	Description     string                 `json:"description,omitempty"`
	Main            string                 `json:"main,omitempty"`
	Scripts         map[string]string      `json:"scripts,omitempty"`
	Dependencies    map[string]string      `json:"dependencies,omitempty"`
	DevDependencies map[string]string      `json:"devDependencies,omitempty"`
	Keywords        []string               `json:"keywords,omitempty"`
	Author          string                 `json:"author,omitempty"`
	License         string                 `json:"license,omitempty"`
	Repository      map[string]string      `json:"repository,omitempty"`
	Engines         map[string]string      `json:"engines,omitempty"`
	Type            string                 `json:"type,omitempty"`
	Exports         map[string]interface{} `json:"exports,omitempty"`
}

// NodeExecutor handles Node.js code execution with package management
type NodeExecutor struct {
	*BaseExecutor
	nodeCmd        string
	npmCmd         string
	packageManager string
	packageJSON    *NodePackageJSON
}

// NewNodeExecutor creates a new Node.js executor
func NewNodeExecutor() *NodeExecutor {
	base := NewBaseExecutor(
		types.LanguageJavaScript,
		30*time.Second,
		[]string{"npm", "yarn", "pnpm"},
		false,
	)

	return &NodeExecutor{
		BaseExecutor:   base,
		nodeCmd:        "node",
		npmCmd:         "npm",
		packageManager: "npm",
	}
}

// GetVersion returns the Node.js version
func (e *NodeExecutor) GetVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.nodeCmd, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Node.js version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	version = strings.TrimPrefix(version, "v")
	return version, nil
}

// SetupEnvironment prepares the Node.js execution environment
func (e *NodeExecutor) SetupEnvironment(ctx context.Context, options *ExecutionOptions) (*EnvironmentInfo, error) {
	// Set Node.js command from options if specified
	if nodeCmd, exists := options.CustomConfig["node_cmd"]; exists {
		e.nodeCmd = nodeCmd
	}

	// Set package manager from options
	if pkgMgr, exists := options.CustomConfig["package_manager"]; exists {
		e.packageManager = pkgMgr
		switch pkgMgr {
		case "yarn":
			e.npmCmd = "yarn"
		case "pnpm":
			e.npmCmd = "pnpm"
		default:
			e.npmCmd = "npm"
		}
	}

	// Create working directory
	if err := os.MkdirAll(options.WorkingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Initialize package.json if packages are specified or requested
	if len(options.Packages) > 0 || options.CustomConfig["init_npm"] == "true" {
		if err := e.initializePackageJSON(ctx, options); err != nil {
			return nil, fmt.Errorf("failed to initialize package.json: %w", err)
		}
	}

	// Get version info
	version, err := e.GetVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Node.js version: %w", err)
	}

	// Get package manager version
	pmVersion, _ := e.getPackageManagerVersion(ctx)

	// Create environment info
	envInfo := &EnvironmentInfo{
		Language:       e.GetLanguage(),
		Version:        version,
		Interpreter:    e.nodeCmd,
		PackageManager: e.npmCmd,
		WorkingDir:     options.WorkingDir,
		ConfigFiles:    []string{},
		SystemInfo: map[string]string{
			"node_executable":     e.nodeCmd,
			"package_manager":     e.packageManager,
			"package_manager_cmd": e.npmCmd,
			"pm_version":          pmVersion,
		},
	}

	// Add configuration files
	packageJSONPath := filepath.Join(options.WorkingDir, "package.json")
	if _, err := os.Stat(packageJSONPath); err == nil {
		envInfo.ConfigFiles = append(envInfo.ConfigFiles, "package.json")
	}

	e.UpdateMetrics("setup_completed", time.Now())
	e.UpdateMetrics("package_manager", e.packageManager)
	e.UpdateMetrics("node_version", version)

	return envInfo, nil
}

// InstallPackages installs Node.js packages using npm/yarn/pnpm
func (e *NodeExecutor) InstallPackages(ctx context.Context, packages []string, options *ExecutionOptions) (*PackageInstallResult, error) {
	if len(packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	startTime := time.Now()
	result := &PackageInstallResult{
		InstalledPackages: []PackageInfo{},
		FailedPackages:    []string{},
	}

	// Ensure package.json exists
	if err := e.initializePackageJSON(ctx, options); err != nil {
		result.Error = fmt.Errorf("failed to initialize package.json: %w", err)
		return result, nil
	}

	// Install packages using the configured package manager

	// Separate regular and dev dependencies
	regularPackages := []string{}
	devPackages := []string{}

	for _, pkg := range packages {
		if strings.HasSuffix(pkg, "@dev") || strings.Contains(pkg, "--save-dev") {
			devPackages = append(devPackages, strings.Replace(pkg, "@dev", "", 1))
		} else {
			regularPackages = append(regularPackages, pkg)
		}
	}

	// Install regular dependencies
	if len(regularPackages) > 0 {
		if err := e.installPackageGroup(ctx, regularPackages, false, options, result); err != nil {
			result.Error = err
			return result, nil
		}
	}

	// Install dev dependencies
	if len(devPackages) > 0 {
		if err := e.installPackageGroup(ctx, devPackages, true, options, result); err != nil {
			result.Error = err
			return result, nil
		}
	}

	result.Duration = time.Since(startTime)
	result.Success = len(result.FailedPackages) == 0

	e.UpdateMetrics("packages_installed", len(result.InstalledPackages))
	e.UpdateMetrics("package_install_duration", result.Duration)

	return result, nil
}

// ValidateCode performs Node.js syntax validation
func (e *NodeExecutor) ValidateCode(ctx context.Context, code string, options *ExecutionOptions) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("empty code provided")
	}

	// Create temporary file for syntax checking
	tmpFile := filepath.Join(options.WorkingDir, "syntax_check.js")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Check syntax using node --check
	cmd := exec.CommandContext(ctx, e.nodeCmd, "--check", tmpFile)
	cmd.Dir = options.WorkingDir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syntax error: %s", string(output))
	}

	e.UpdateMetrics("syntax_validation_completed", time.Now())
	return nil
}

// PrepareFiles creates necessary files for Node.js execution
func (e *NodeExecutor) PrepareFiles(ctx context.Context, code string, options *ExecutionOptions) (map[string]string, error) {
	files := make(map[string]string)

	// Main JavaScript file
	mainFile := "main.js"
	files[mainFile] = code

	// Add user-specified files
	for filename, content := range options.Files {
		files[filename] = content
	}

	// Create package.json if packages are specified
	if len(options.Packages) > 0 {
		packageJSON := e.createPackageJSON(options)
		packageJSONContent, err := json.MarshalIndent(packageJSON, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal package.json: %w", err)
		}
		files["package.json"] = string(packageJSONContent)
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

// Compile is not needed for Node.js (interpreted language)
func (e *NodeExecutor) Compile(ctx context.Context, code string, options *ExecutionOptions) (*CompilationResult, error) {
	return &CompilationResult{
		Success:  true,
		Duration: 0,
		CacheHit: true,
	}, nil
}

// Execute runs Node.js code and returns the result
func (e *NodeExecutor) Execute(ctx context.Context, code string, options *ExecutionOptions) (*ExecutionResult, error) {
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

	// Execute Node.js code
	executionStart := time.Now()
	args := []string{"main.js"}

	// Add runtime flags if specified
	if len(options.RuntimeFlags) > 0 {
		args = append(options.RuntimeFlags, args...)
	}

	cmd := exec.CommandContext(ctx, e.nodeCmd, args...)
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
		ExitCode:      exitCode,
		Stdout:        stdout,
		Stderr:        stderr,
		Duration:      totalDuration,
		Language:      e.GetLanguage(),
		Commands:      []string{fmt.Sprintf("%s %s", e.nodeCmd, strings.Join(args, " "))},
		CreatedFiles:  createdFiles,
		ExecutionTime: executionTime,
		Metadata: map[string]string{
			"interpreter":      e.nodeCmd,
			"working_dir":      options.WorkingDir,
			"package_manager":  e.packageManager,
			"packages_count":   fmt.Sprintf("%d", len(options.Packages)),
		},
	}

	e.UpdateMetrics("execution_completed", time.Now())
	e.UpdateMetrics("execution_duration", totalDuration)
	e.UpdateMetrics("exit_code", exitCode)

	return result, nil
}

// initializePackageJSON creates or updates package.json
func (e *NodeExecutor) initializePackageJSON(ctx context.Context, options *ExecutionOptions) error {
	packageJSONPath := filepath.Join(options.WorkingDir, "package.json")
	
	// Check if package.json already exists
	if _, err := os.Stat(packageJSONPath); err == nil {
		// Load existing package.json
		content, err := os.ReadFile(packageJSONPath)
		if err != nil {
			return fmt.Errorf("failed to read existing package.json: %w", err)
		}
		
		if err := json.Unmarshal(content, &e.packageJSON); err != nil {
			return fmt.Errorf("failed to parse existing package.json: %w", err)
		}
	} else {
		// Create new package.json
		e.packageJSON = e.createPackageJSON(options)
	}

	// Write package.json
	content, err := json.MarshalIndent(e.packageJSON, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal package.json: %w", err)
	}

	if err := os.WriteFile(packageJSONPath, content, 0644); err != nil {
		return fmt.Errorf("failed to write package.json: %w", err)
	}

	return nil
}

// createPackageJSON creates a basic package.json structure
func (e *NodeExecutor) createPackageJSON(options *ExecutionOptions) *NodePackageJSON {
	pkg := &NodePackageJSON{
		Name:         "sandbox-project",
		Version:      "1.0.0",
		Description:  "Generated project for code execution",
		Main:         "main.js",
		Scripts:      map[string]string{
			"start": "node main.js",
			"test":  "echo \"Error: no test specified\" && exit 1",
		},
		Dependencies:    make(map[string]string),
		DevDependencies: make(map[string]string),
		License:         "ISC",
	}

	// Set Node.js engine requirement
	if nodeVersion, exists := options.CustomConfig["node_version"]; exists {
		pkg.Engines = map[string]string{
			"node": nodeVersion,
		}
	}

	// Set module type if specified
	if moduleType, exists := options.CustomConfig["module_type"]; exists {
		pkg.Type = moduleType
	}

	return pkg
}

// installPackageGroup installs a group of packages
func (e *NodeExecutor) installPackageGroup(ctx context.Context, packages []string, isDev bool, options *ExecutionOptions, result *PackageInstallResult) error {
	var args []string

	switch e.packageManager {
	case "yarn":
		args = []string{"add"}
		if isDev {
			args = append(args, "--dev")
		}
	case "pnpm":
		args = []string{"install"}
		if isDev {
			args = append(args, "--save-dev")
		}
	default: // npm
		args = []string{"install"}
		if isDev {
			args = append(args, "--save-dev")
		}
	}

	args = append(args, packages...)

	// Execute package installation
	cmd := exec.CommandContext(ctx, e.npmCmd, args...)
	cmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	result.Output += string(output)

	if err != nil {
		result.FailedPackages = append(result.FailedPackages, packages...)
		return fmt.Errorf("package installation failed: %w", err)
	}

	// Parse successful installations
	for _, pkg := range packages {
		// Extract package name (handle version specifiers and scoped packages)
		pkgName := strings.Split(pkg, "@")[0]
		if strings.HasPrefix(pkg, "@") {
			// Scoped package: @scope/package@version -> @scope/package
			parts := strings.Split(pkg, "@")
			if len(parts) >= 3 {
				pkgName = "@" + parts[1]
			} else {
				pkgName = pkg
			}
		}

		result.InstalledPackages = append(result.InstalledPackages, PackageInfo{
			Name: strings.TrimSpace(pkgName),
		})
	}

	return nil
}

// getPackageManagerVersion returns the version of the package manager
func (e *NodeExecutor) getPackageManagerVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.npmCmd, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// executeCommand executes a command with timeout and returns stdout, stderr, and exit code
func (e *NodeExecutor) executeCommand(ctx context.Context, cmd *exec.Cmd, timeout time.Duration) (string, string, int) {
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

	// For Node.js, stdout and stderr are often mixed, so we need to separate them
	lines := strings.Split(outputStr, "\n")
	var stdout, stderr []string

	for _, line := range lines {
		// Simple heuristic: lines with error indicators go to stderr
		if strings.Contains(strings.ToLower(line), "error") ||
		   strings.Contains(line, "Error:") ||
		   strings.Contains(line, "TypeError:") ||
		   strings.Contains(line, "ReferenceError:") ||
		   strings.Contains(line, "SyntaxError:") ||
		   regexp.MustCompile(`^\s*at\s+`).MatchString(line) {
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

// extractNodeImports extracts require/import statements from Node.js code
func (e *NodeExecutor) extractNodeImports(code string) []string {
	var imports []string

	// Regular expressions for different import patterns
	patterns := []*regexp.Regexp{
		// require statements
		regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		// ES6 imports
		regexp.MustCompile(`^\s*import\s+(?:.*\s+from\s+)?['"]([^'"]+)['"]`),
		// Dynamic imports
		regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`),
	}

	lines := strings.Split(code, "\n")
	for _, line := range lines {
		for _, pattern := range patterns {
			matches := pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 && !strings.HasPrefix(match[1], ".") {
					// Only include non-relative imports (external packages)
					imports = append(imports, match[1])
				}
			}
		}
	}

	return removeDuplicates(imports)
}