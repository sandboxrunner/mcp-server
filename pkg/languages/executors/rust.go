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

// CargoToml represents a Cargo.toml file structure
type CargoToml struct {
	Package      CargoPackage            `toml:"package"`
	Dependencies map[string]interface{}  `toml:"dependencies,omitempty"`
	DevDependencies map[string]interface{} `toml:"dev-dependencies,omitempty"`
	BuildDependencies map[string]interface{} `toml:"build-dependencies,omitempty"`
	Bin          []CargoBin              `toml:"bin,omitempty"`
	Lib          *CargoLib               `toml:"lib,omitempty"`
	Features     map[string][]string     `toml:"features,omitempty"`
}

// CargoPackage represents the [package] section of Cargo.toml
type CargoPackage struct {
	Name        string   `toml:"name"`
	Version     string   `toml:"version"`
	Edition     string   `toml:"edition"`
	Description string   `toml:"description,omitempty"`
	Authors     []string `toml:"authors,omitempty"`
	License     string   `toml:"license,omitempty"`
	Repository  string   `toml:"repository,omitempty"`
	Homepage    string   `toml:"homepage,omitempty"`
	Keywords    []string `toml:"keywords,omitempty"`
	Categories  []string `toml:"categories,omitempty"`
}

// CargoBin represents a binary target
type CargoBin struct {
	Name string `toml:"name"`
	Path string `toml:"path"`
}

// CargoLib represents a library target
type CargoLib struct {
	Name string `toml:"name,omitempty"`
	Path string `toml:"path,omitempty"`
}

// RustExecutor handles Rust code execution with Cargo integration
type RustExecutor struct {
	*BaseExecutor
	rustcCmd     string
	cargoCmd     string
	packageName  string
	edition      string
	buildFlags   []string
	cargoToml    *CargoToml
}

// NewRustExecutor creates a new Rust executor
func NewRustExecutor() *RustExecutor {
	base := NewBaseExecutor(
		types.LanguageRust,
		120*time.Second,
		[]string{"cargo"},
		true,
	)

	return &RustExecutor{
		BaseExecutor: base,
		rustcCmd:     "rustc",
		cargoCmd:     "cargo",
		packageName:  "sandbox_project",
		edition:      "2021",
		buildFlags:   []string{},
	}
}

// GetVersion returns the Rust version
func (e *RustExecutor) GetVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.rustcCmd, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Rust version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	// Extract version from "rustc 1.70.0 (90c541806 2023-05-31)"
	re := regexp.MustCompile(`rustc\s+(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return version, nil
}

// SetupEnvironment prepares the Rust execution environment
func (e *RustExecutor) SetupEnvironment(ctx context.Context, options *ExecutionOptions) (*EnvironmentInfo, error) {
	// Set Rust commands from options if specified
	if rustcCmd, exists := options.CustomConfig["rustc_cmd"]; exists {
		e.rustcCmd = rustcCmd
	}
	if cargoCmd, exists := options.CustomConfig["cargo_cmd"]; exists {
		e.cargoCmd = cargoCmd
	}

	// Set package name from options
	if packageName, exists := options.CustomConfig["package_name"]; exists {
		e.packageName = packageName
	}

	// Set edition from options
	if edition, exists := options.CustomConfig["edition"]; exists {
		e.edition = edition
	}

	// Create working directory
	if err := os.MkdirAll(options.WorkingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Initialize Cargo project
	if err := e.initializeCargoProject(ctx, options); err != nil {
		return nil, fmt.Errorf("failed to initialize Cargo project: %w", err)
	}

	// Get version info
	version, err := e.GetVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Rust version: %w", err)
	}

	// Get Cargo version
	cargoVersion, _ := e.getCargoVersion(ctx)

	// Create environment info
	envInfo := &EnvironmentInfo{
		Language:       e.GetLanguage(),
		Version:        version,
		Interpreter:    e.rustcCmd,
		PackageManager: e.cargoCmd,
		WorkingDir:     options.WorkingDir,
		ConfigFiles:    []string{"Cargo.toml"},
		SystemInfo: map[string]string{
			"rustc_executable": e.rustcCmd,
			"cargo_executable": e.cargoCmd,
			"cargo_version":    cargoVersion,
			"package_name":     e.packageName,
			"edition":          e.edition,
		},
	}

	// Check for Cargo.lock
	cargoLockPath := filepath.Join(options.WorkingDir, "Cargo.lock")
	if _, err := os.Stat(cargoLockPath); err == nil {
		envInfo.ConfigFiles = append(envInfo.ConfigFiles, "Cargo.lock")
	}

	e.UpdateMetrics("setup_completed", time.Now())
	e.UpdateMetrics("package_name", e.packageName)
	e.UpdateMetrics("rust_version", version)
	e.UpdateMetrics("edition", e.edition)

	return envInfo, nil
}

// InstallPackages installs Rust crates as dependencies
func (e *RustExecutor) InstallPackages(ctx context.Context, packages []string, options *ExecutionOptions) (*PackageInstallResult, error) {
	if len(packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	startTime := time.Now()
	result := &PackageInstallResult{
		InstalledPackages: []PackageInfo{},
		FailedPackages:    []string{},
	}

	// Ensure Cargo.toml exists
	if err := e.initializeCargoProject(ctx, options); err != nil {
		result.Error = fmt.Errorf("failed to initialize Cargo project: %w", err)
		return result, nil
	}

	// Update Cargo.toml with dependencies
	if err := e.updateCargoTomlDependencies(packages, options); err != nil {
		result.Error = fmt.Errorf("failed to update Cargo.toml: %w", err)
		return result, nil
	}

	// Run cargo update to fetch dependencies
	updateCmd := exec.CommandContext(ctx, e.cargoCmd, "update")
	updateCmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	updateCmd.Env = env

	output, err := updateCmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		result.Error = fmt.Errorf("cargo update failed: %w", err)
		result.FailedPackages = packages
		return result, nil
	}

	// Parse successful installations
	result.Success = true
	for _, pkg := range packages {
		// Extract crate name (handle version specifiers)
		crateName := strings.Split(pkg, " = ")[0]
		crateName = strings.Trim(crateName, "\"")

		result.InstalledPackages = append(result.InstalledPackages, PackageInfo{
			Name: crateName,
		})
	}

	result.Duration = time.Since(startTime)

	e.UpdateMetrics("packages_installed", len(result.InstalledPackages))
	e.UpdateMetrics("package_install_duration", result.Duration)

	return result, nil
}

// ValidateCode performs Rust syntax validation
func (e *RustExecutor) ValidateCode(ctx context.Context, code string, options *ExecutionOptions) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("empty code provided")
	}

	// Create temporary file for syntax checking
	tmpFile := filepath.Join(options.WorkingDir, "syntax_check.rs")
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Check syntax using rustc --parse
	cmd := exec.CommandContext(ctx, e.rustcCmd, "--parse", tmpFile)
	cmd.Dir = options.WorkingDir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syntax error: %s", string(output))
	}

	e.UpdateMetrics("syntax_validation_completed", time.Now())
	return nil
}

// PrepareFiles creates necessary files for Rust execution
func (e *RustExecutor) PrepareFiles(ctx context.Context, code string, options *ExecutionOptions) (map[string]string, error) {
	files := make(map[string]string)

	// Create src directory structure
	srcDir := "src"
	mainFile := filepath.Join(srcDir, "main.rs")

	// Ensure code has main function for binary execution
	if !strings.Contains(code, "fn main()") {
		code = "fn main() {\n" + code + "\n}"
	}

	files[mainFile] = code

	// Add user-specified files
	for filename, content := range options.Files {
		files[filename] = content
	}

	// Create Cargo.toml
	cargoToml := e.createCargoToml(options)
	files["Cargo.toml"] = cargoToml

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

// Compile compiles Rust code using Cargo
func (e *RustExecutor) Compile(ctx context.Context, code string, options *ExecutionOptions) (*CompilationResult, error) {
	startTime := time.Now()

	result := &CompilationResult{
		Success:  false,
		CacheKey: e.generateCacheKey(code, options),
		CacheHit: false,
	}

	// Prepare compilation arguments
	args := []string{"build"}

	// Add build mode
	if options.BuildMode == "release" {
		args = append(args, "--release")
	}

	// Add build flags
	if len(options.CompileFlags) > 0 {
		args = append(args, options.CompileFlags...)
	}

	// Execute compilation
	cmd := exec.CommandContext(ctx, e.cargoCmd, args...)
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
		result.Error = fmt.Errorf("compilation failed: %w", err)
		return result, nil
	}

	// Determine executable path
	buildDir := "target"
	if options.BuildMode == "release" {
		buildDir = filepath.Join(buildDir, "release")
	} else {
		buildDir = filepath.Join(buildDir, "debug")
	}

	executableName := e.packageName
	if isWindows() {
		executableName += ".exe"
	}

	executablePath := filepath.Join(options.WorkingDir, buildDir, executableName)

	// Check if executable was created
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

// Execute runs Rust code and returns the result
func (e *RustExecutor) Execute(ctx context.Context, code string, options *ExecutionOptions) (*ExecutionResult, error) {
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

	// Use cargo run for direct execution (which includes compilation)
	executionStart := time.Now()
	args := []string{"run"}

	// Add build mode
	if options.BuildMode == "release" {
		args = append(args, "--release")
	}

	// Add runtime flags if specified (after --)
	if len(options.RuntimeFlags) > 0 {
		args = append(args, "--")
		args = append(args, options.RuntimeFlags...)
	}

	cmd := exec.CommandContext(ctx, e.cargoCmd, args...)
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

	// Add target directory files
	targetDir := filepath.Join(options.WorkingDir, "target")
	if _, err := os.Stat(targetDir); err == nil {
		createdFiles = append(createdFiles, "target/")
	}

	result := &ExecutionResult{
		ExitCode:      exitCode,
		Stdout:        stdout,
		Stderr:        stderr,
		Duration:      totalDuration,
		Language:      e.GetLanguage(),
		Commands:      []string{fmt.Sprintf("cargo %s", strings.Join(args, " "))},
		CreatedFiles:  createdFiles,
		ExecutionTime: executionTime,
		Metadata: map[string]string{
			"cargo_executable": e.cargoCmd,
			"working_dir":      options.WorkingDir,
			"package_name":     e.packageName,
			"edition":          e.edition,
			"packages_count":   fmt.Sprintf("%d", len(options.Packages)),
			"build_mode":       options.BuildMode,
		},
	}

	e.UpdateMetrics("execution_completed", time.Now())
	e.UpdateMetrics("execution_duration", totalDuration)
	e.UpdateMetrics("exit_code", exitCode)

	return result, nil
}

// initializeCargoProject initializes a Cargo project
func (e *RustExecutor) initializeCargoProject(ctx context.Context, options *ExecutionOptions) error {
	cargoTomlPath := filepath.Join(options.WorkingDir, "Cargo.toml")

	// Check if Cargo.toml already exists
	if _, err := os.Stat(cargoTomlPath); err == nil {
		return nil // Cargo.toml already exists
	}

	// Create src directory
	srcDir := filepath.Join(options.WorkingDir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		return fmt.Errorf("failed to create src directory: %w", err)
	}

	// Create Cargo.toml
	cargoToml := e.createCargoToml(options)
	if err := os.WriteFile(cargoTomlPath, []byte(cargoToml), 0644); err != nil {
		return fmt.Errorf("failed to create Cargo.toml: %w", err)
	}

	return nil
}

// createCargoToml creates Cargo.toml content
func (e *RustExecutor) createCargoToml(options *ExecutionOptions) string {
	cargoToml := fmt.Sprintf(`[package]
name = "%s"
version = "0.1.0"
edition = "%s"
description = "Generated project for code execution"
authors = ["Sandbox Runner"]
license = "MIT"

[[bin]]
name = "%s"
path = "src/main.rs"
`, e.packageName, e.edition, e.packageName)

	if len(options.Packages) > 0 {
		cargoToml += "\n[dependencies]\n"
		for _, pkg := range options.Packages {
			if strings.Contains(pkg, "=") {
				// Package with version specification: serde = "1.0"
				cargoToml += fmt.Sprintf("%s\n", pkg)
			} else {
				// Package without version: serde -> serde = "*"
				cargoToml += fmt.Sprintf("%s = \"*\"\n", pkg)
			}
		}
	}

	// Add features if specified
	if features, exists := options.CustomConfig["features"]; exists {
		cargoToml += "\n[features]\n"
		cargoToml += fmt.Sprintf("default = %s\n", features)
	}

	return cargoToml
}

// updateCargoTomlDependencies updates Cargo.toml with new dependencies
func (e *RustExecutor) updateCargoTomlDependencies(packages []string, options *ExecutionOptions) error {
	cargoTomlPath := filepath.Join(options.WorkingDir, "Cargo.toml")
	
	// Read existing Cargo.toml
	content, err := os.ReadFile(cargoTomlPath)
	if err != nil {
		return fmt.Errorf("failed to read Cargo.toml: %w", err)
	}

	cargoTomlContent := string(content)

	// Add dependencies section if it doesn't exist
	if !strings.Contains(cargoTomlContent, "[dependencies]") {
		cargoTomlContent += "\n[dependencies]\n"
	}

	// Add each package
	for _, pkg := range packages {
		if strings.Contains(pkg, "=") {
			cargoTomlContent += fmt.Sprintf("%s\n", pkg)
		} else {
			cargoTomlContent += fmt.Sprintf("%s = \"*\"\n", pkg)
		}
	}

	// Write updated Cargo.toml
	if err := os.WriteFile(cargoTomlPath, []byte(cargoTomlContent), 0644); err != nil {
		return fmt.Errorf("failed to write updated Cargo.toml: %w", err)
	}

	return nil
}

// getCargoVersion returns the Cargo version
func (e *RustExecutor) getCargoVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.cargoCmd, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	version := strings.TrimSpace(string(output))
	// Extract version from "cargo 1.70.0 (7fe40dc8c 2023-05-31)"
	re := regexp.MustCompile(`cargo\s+(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return version, nil
}

// executeCommand executes a command with timeout and returns stdout, stderr, and exit code
func (e *RustExecutor) executeCommand(ctx context.Context, cmd *exec.Cmd, timeout time.Duration) (string, string, int) {
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
func (e *RustExecutor) generateCacheKey(code string, options *ExecutionOptions) string {
	// Simple hash-like key based on code and options
	key := fmt.Sprintf("rust-%s-%s-%s-%v", code[:min(len(code), 100)], e.edition, options.BuildMode, options.CompileFlags)
	return fmt.Sprintf("%x", []byte(key))
}

// extractRustImports extracts use statements from Rust code
func (e *RustExecutor) extractRustImports(code string) []string {
	var imports []string

	// Regular expressions for Rust use statements
	patterns := []*regexp.Regexp{
		// External crate: use serde::Serialize;
		regexp.MustCompile(`^\s*use\s+([a-zA-Z_][a-zA-Z0-9_]*)::`),
		// External crate with macro: use serde_json!;
		regexp.MustCompile(`^\s*use\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*!`),
	}

	lines := strings.Split(code, "\n")
	for _, line := range lines {
		for _, pattern := range patterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				crateName := matches[1]
				// Skip standard library crates
				if !isStdCrate(crateName) {
					imports = append(imports, crateName)
				}
			}
		}
	}

	return removeDuplicates(imports)
}

// isStdCrate checks if a crate is part of the standard library
func isStdCrate(crateName string) bool {
	stdCrates := map[string]bool{
		"std":         true,
		"core":        true,
		"alloc":       true,
		"proc_macro":  true,
		"test":        true,
		"collections": true,
		"fmt":         true,
		"io":          true,
		"net":         true,
		"path":        true,
		"sync":        true,
		"thread":      true,
		"time":        true,
		"env":         true,
		"fs":          true,
		"process":     true,
	}
	return stdCrates[crateName]
}