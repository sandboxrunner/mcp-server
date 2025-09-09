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

// CompilerExecutor provides common functionality for compiled languages (C/C++/C#)
type CompilerExecutor struct {
	*BaseExecutor
	compilerCmd     string
	linkerCmd       string
	debuggerCmd     string
	language        types.Language
	sourceExt       string
	executableExt   string
	compilerFlags   []string
	linkerFlags     []string
	includePaths    []string
	libraryPaths    []string
	libraries       []string
	optimizationLevel string
	debugSymbols    bool
}

// NewCompilerExecutor creates a new compiler executor
func NewCompilerExecutor(
	lang types.Language,
	compilerCmd string,
	sourceExt string,
	timeout time.Duration,
) *CompilerExecutor {
	base := NewBaseExecutor(lang, timeout, []string{"apt", "pkg-config"}, true)

	executableExt := ""
	if isWindows() {
		executableExt = ".exe"
	}

	return &CompilerExecutor{
		BaseExecutor:      base,
		compilerCmd:       compilerCmd,
		language:          lang,
		sourceExt:         sourceExt,
		executableExt:     executableExt,
		compilerFlags:     []string{},
		linkerFlags:       []string{},
		includePaths:      []string{},
		libraryPaths:      []string{},
		libraries:         []string{},
		optimizationLevel: "O2",
		debugSymbols:      false,
	}
}

// CppExecutor handles C++ code execution
type CppExecutor struct {
	*CompilerExecutor
}

// NewCppExecutor creates a new C++ executor
func NewCppExecutor() *CppExecutor {
	compiler := NewCompilerExecutor(
		types.LanguageCPP,
		"g++",
		".cpp",
		45*time.Second,
	)
	compiler.linkerCmd = "g++"
	
	return &CppExecutor{
		CompilerExecutor: compiler,
	}
}

// CExecutor handles C code execution
type CExecutor struct {
	*CompilerExecutor
}

// NewCExecutor creates a new C executor
func NewCExecutor() *CExecutor {
	compiler := NewCompilerExecutor(
		types.LanguageC,
		"gcc",
		".c",
		45*time.Second,
	)
	compiler.linkerCmd = "gcc"
	
	return &CExecutor{
		CompilerExecutor: compiler,
	}
}

// CSharpExecutor handles C# code execution with .NET
type CSharpExecutor struct {
	*CompilerExecutor
	dotnetCmd string
	framework string
	projectName string
}

// NewCSharpExecutor creates a new C# executor
func NewCSharpExecutor() *CSharpExecutor {
	compiler := NewCompilerExecutor(
		types.LanguageCSharp,
		"dotnet",
		".cs",
		45*time.Second,
	)

	return &CSharpExecutor{
		CompilerExecutor: compiler,
		dotnetCmd:        "dotnet",
		framework:        "net8.0",
		projectName:      "SandboxProject",
	}
}

// GetVersion returns the compiler version
func (e *CompilerExecutor) GetVersion(ctx context.Context) (string, error) {
	var cmd *exec.Cmd
	
	switch e.language {
	case types.LanguageCSharp:
		cmd = exec.CommandContext(ctx, e.compilerCmd, "--version")
	default:
		cmd = exec.CommandContext(ctx, e.compilerCmd, "--version")
	}

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get compiler version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	
	// Extract version from different compiler outputs
	var re *regexp.Regexp
	switch e.language {
	case types.LanguageCPP, types.LanguageC:
		// GCC/Clang version extraction
		re = regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	case types.LanguageCSharp:
		// .NET version extraction
		re = regexp.MustCompile(`(\d+\.\d+\.\d+)`)
	}
	
	if re != nil {
		matches := re.FindStringSubmatch(version)
		if len(matches) > 1 {
			return matches[1], nil
		}
	}
	
	return version, nil
}

// SetupEnvironment prepares the compiler execution environment
func (e *CompilerExecutor) SetupEnvironment(ctx context.Context, options *ExecutionOptions) (*EnvironmentInfo, error) {
	// Set compiler from options if specified
	if compilerCmd, exists := options.CustomConfig["compiler"]; exists {
		e.compilerCmd = compilerCmd
		if e.language == types.LanguageCPP || e.language == types.LanguageC {
			e.linkerCmd = compilerCmd
		}
	}

	// Set optimization level from options
	if opt, exists := options.CustomConfig["optimization"]; exists {
		e.optimizationLevel = opt
	}

	// Set debug symbols from options
	if debug, exists := options.CustomConfig["debug"]; exists {
		e.debugSymbols = debug == "true"
	}

	// Create working directory
	if err := os.MkdirAll(options.WorkingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Language-specific setup
	var configFiles []string
	switch e.language {
	case types.LanguageCSharp:
		// C# specific setup will be handled by CSharpExecutor's overridden methods
		// This base method doesn't need to handle C#-specific logic
	}

	// Get version info
	version, err := e.GetVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get compiler version: %w", err)
	}

	// Create environment info
	envInfo := &EnvironmentInfo{
		Language:       e.GetLanguage(),
		Version:        version,
		Interpreter:    e.compilerCmd,
		PackageManager: "apt", // Default package manager for system libraries
		WorkingDir:     options.WorkingDir,
		ConfigFiles:    configFiles,
		SystemInfo: map[string]string{
			"compiler":           e.compilerCmd,
			"linker":            e.linkerCmd,
			"source_extension":  e.sourceExt,
			"optimization":      e.optimizationLevel,
			"debug_symbols":     fmt.Sprintf("%v", e.debugSymbols),
		},
	}

	e.UpdateMetrics("setup_completed", time.Now())
	e.UpdateMetrics("compiler", e.compilerCmd)
	e.UpdateMetrics("compiler_version", version)

	return envInfo, nil
}

// InstallPackages installs system packages/libraries
func (e *CompilerExecutor) InstallPackages(ctx context.Context, packages []string, options *ExecutionOptions) (*PackageInstallResult, error) {
	if len(packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	result := &PackageInstallResult{
		InstalledPackages: []PackageInfo{},
		FailedPackages:    []string{},
	}

	switch e.language {
	case types.LanguageCSharp:
		// C# package installation will be handled by CSharpExecutor's overridden method
		return &PackageInstallResult{Success: true}, nil
	default:
		// Handle system packages for C/C++
		return e.installSystemPackages(ctx, packages, options, result)
	}
}

// ValidateCode performs syntax validation
func (e *CompilerExecutor) ValidateCode(ctx context.Context, code string, options *ExecutionOptions) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("empty code provided")
	}

	// Create temporary file for syntax checking
	tmpFile := filepath.Join(options.WorkingDir, fmt.Sprintf("syntax_check%s", e.sourceExt))
	
	// Language-specific code preparation
	switch e.language {
	case types.LanguageC, types.LanguageCPP:
		// Ensure main function exists for C/C++
		if !strings.Contains(code, "int main") {
			code = "#include <stdio.h>\nint main() {\n" + code + "\nreturn 0;\n}"
		}
	case types.LanguageCSharp:
		// Ensure class and Main method exist for C#
		if !strings.Contains(code, "class ") {
			code = "using System;\nclass Program {\nstatic void Main() {\n" + code + "\n}\n}"
		}
	}

	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Syntax check command
	var cmd *exec.Cmd
	switch e.language {
	case types.LanguageC, types.LanguageCPP:
		// Use -fsyntax-only for syntax checking only
		cmd = exec.CommandContext(ctx, e.compilerCmd, "-fsyntax-only", tmpFile)
	case types.LanguageCSharp:
		// Use dotnet build --no-restore for syntax checking
		cmd = exec.CommandContext(ctx, e.compilerCmd, "build", "--no-restore", "--verbosity", "quiet")
	}

	cmd.Dir = options.WorkingDir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syntax error: %s", string(output))
	}

	e.UpdateMetrics("syntax_validation_completed", time.Now())
	return nil
}

// PrepareFiles creates necessary files for compilation
func (e *CompilerExecutor) PrepareFiles(ctx context.Context, code string, options *ExecutionOptions) (map[string]string, error) {
	files := make(map[string]string)

	// Main source file
	mainFile := fmt.Sprintf("main%s", e.sourceExt)

	// Language-specific code preparation
	switch e.language {
	case types.LanguageC:
		if !strings.Contains(code, "#include") && !strings.Contains(code, "int main") {
			code = "#include <stdio.h>\nint main() {\n" + code + "\nreturn 0;\n}"
		}
	case types.LanguageCPP:
		if !strings.Contains(code, "#include") && !strings.Contains(code, "int main") {
			code = "#include <iostream>\nint main() {\n" + code + "\nreturn 0;\n}"
		}
	case types.LanguageCSharp:
		mainFile = "Program.cs"
		if !strings.Contains(code, "class ") {
			code = "using System;\nclass Program {\nstatic void Main() {\n" + code + "\n}\n}"
		}
	}

	files[mainFile] = code

	// Add user-specified files
	for filename, content := range options.Files {
		files[filename] = content
	}

	// Language-specific configuration files will be handled by concrete executors
	// Base CompilerExecutor doesn't handle language-specific configurations

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

// Compile compiles the source code
func (e *CompilerExecutor) Compile(ctx context.Context, code string, options *ExecutionOptions) (*CompilationResult, error) {
	result := &CompilationResult{
		Success:  false,
		CacheKey: e.generateCacheKey(code, options),
		CacheHit: false,
	}

	switch e.language {
	case types.LanguageCSharp:
		// C# compilation will be handled by CSharpExecutor's overridden method
		return &CompilationResult{Success: true}, nil
	default:
		return e.compileCOrCpp(ctx, options, result)
	}
}

// Execute runs the compiled code
func (e *CompilerExecutor) Execute(ctx context.Context, code string, options *ExecutionOptions) (*ExecutionResult, error) {
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
	var cmd *exec.Cmd

	switch e.language {
	case types.LanguageCSharp:
		cmd = exec.CommandContext(ctx, e.compilerCmd, "run")
	default:
		executablePath := compileResult.ExecutablePath
		if executablePath == "" {
			executablePath = filepath.Join(options.WorkingDir, "main"+e.executableExt)
		}
		args := []string{executablePath}
		if len(options.RuntimeFlags) > 0 {
			args = append(args, options.RuntimeFlags...)
		}
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	}

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
	if compileResult.ExecutablePath != "" {
		createdFiles = append(createdFiles, filepath.Base(compileResult.ExecutablePath))
	}

	result := &ExecutionResult{
		ExitCode:        exitCode,
		Stdout:          stdout,
		Stderr:          stderr,
		Duration:        totalDuration,
		Language:        e.GetLanguage(),
		Commands:        []string{compileResult.Output}, // Compilation command
		CreatedFiles:    createdFiles,
		CompilationTime: compileResult.Duration,
		ExecutionTime:   executionTime,
		Metadata: map[string]string{
			"compiler":         e.compilerCmd,
			"working_dir":      options.WorkingDir,
			"optimization":     e.optimizationLevel,
			"debug_symbols":    fmt.Sprintf("%v", e.debugSymbols),
			"packages_count":   fmt.Sprintf("%d", len(options.Packages)),
			"executable_path":  compileResult.ExecutablePath,
		},
	}

	e.UpdateMetrics("execution_completed", time.Now())
	e.UpdateMetrics("execution_duration", totalDuration)
	e.UpdateMetrics("exit_code", exitCode)

	return result, nil
}

// Helper methods for C/C++ compilation
func (e *CompilerExecutor) compileCOrCpp(ctx context.Context, options *ExecutionOptions, result *CompilationResult) (*CompilationResult, error) {
	executableName := "main" + e.executableExt
	sourceFile := fmt.Sprintf("main%s", e.sourceExt)

	// Build compilation arguments
	args := []string{}

	// Add optimization level
	args = append(args, "-"+e.optimizationLevel)

	// Add debug symbols if requested
	if e.debugSymbols {
		args = append(args, "-g")
	}

	// Add include paths
	for _, includePath := range e.includePaths {
		args = append(args, "-I"+includePath)
	}

	// Add library paths
	for _, libPath := range e.libraryPaths {
		args = append(args, "-L"+libPath)
	}

	// Add libraries
	for _, lib := range e.libraries {
		args = append(args, "-l"+lib)
	}

	// Add compiler flags
	args = append(args, e.compilerFlags...)
	args = append(args, options.CompileFlags...)

	// Add source file and output
	args = append(args, sourceFile, "-o", executableName)

	// Execute compilation
	cmd := exec.CommandContext(ctx, e.compilerCmd, args...)
	cmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(time.Now().Add(-result.Duration))

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

	return result, nil
}

// Helper methods for C# compilation
func (e *CSharpExecutor) compileCSharp(ctx context.Context, options *ExecutionOptions, result *CompilationResult) (*CompilationResult, error) {
	// Use dotnet build
	args := []string{"build"}
	
	if options.BuildMode == "release" {
		args = append(args, "--configuration", "Release")
	}

	// Add compile flags
	if len(options.CompileFlags) > 0 {
		args = append(args, options.CompileFlags...)
	}

	cmd := exec.CommandContext(ctx, e.dotnetCmd, args...)
	cmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(time.Now().Add(-result.Duration))

	if err != nil {
		result.Error = fmt.Errorf("compilation failed: %w", err)
		return result, nil
	}

	result.Success = true
	// .NET builds to bin directory
	result.ExecutablePath = filepath.Join(options.WorkingDir, "bin", "Debug", e.framework, e.projectName+e.executableExt)

	return result, nil
}

// Helper methods for package installation
func (e *CompilerExecutor) installSystemPackages(ctx context.Context, packages []string, options *ExecutionOptions, result *PackageInstallResult) (*PackageInstallResult, error) {
	startTime := time.Now()

	// Use apt-get to install system packages
	args := []string{"update", "&&", "apt-get", "install", "-y"}
	args = append(args, packages...)

	cmd := exec.CommandContext(ctx, "sh", "-c", "apt-get "+strings.Join(args, " "))

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
		result.Error = fmt.Errorf("package installation failed: %w", err)
		result.FailedPackages = packages
		return result, nil
	}

	// Mark all packages as successfully installed
	result.Success = true
	for _, pkg := range packages {
		result.InstalledPackages = append(result.InstalledPackages, PackageInfo{
			Name: pkg,
		})
	}

	return result, nil
}

func (e *CSharpExecutor) installNuGetPackages(ctx context.Context, packages []string, options *ExecutionOptions, result *PackageInstallResult) (*PackageInstallResult, error) {
	startTime := time.Now()

	// Install each NuGet package
	for _, pkg := range packages {
		args := []string{"add", "package", pkg}

		cmd := exec.CommandContext(ctx, e.dotnetCmd, args...)
		cmd.Dir = options.WorkingDir

		// Set environment variables
		env := os.Environ()
		for k, v := range options.Environment {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env

		output, err := cmd.CombinedOutput()
		result.Output += string(output) + "\n"

		if err != nil {
			result.FailedPackages = append(result.FailedPackages, pkg)
		} else {
			result.InstalledPackages = append(result.InstalledPackages, PackageInfo{
				Name: pkg,
			})
		}
	}

	result.Duration = time.Since(startTime)
	result.Success = len(result.FailedPackages) == 0

	return result, nil
}

// Helper methods for C# project setup
func (e *CSharpExecutor) setupDotNetProject(ctx context.Context, options *ExecutionOptions) error {
	// Check if project already exists
	csprojPath := filepath.Join(options.WorkingDir, e.projectName+".csproj")
	if _, err := os.Stat(csprojPath); err == nil {
		return nil // Project already exists
	}

	// Create new .NET project
	cmd := exec.CommandContext(ctx, e.dotnetCmd, "new", "console", "-n", e.projectName, "--force")
	cmd.Dir = options.WorkingDir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create .NET project: %s", string(output))
	}

	return nil
}

func (e *CSharpExecutor) createProjectFile(options *ExecutionOptions) string {
	framework := e.framework
	if fw, exists := options.CustomConfig["framework"]; exists {
		framework = fw
	}

	csproj := fmt.Sprintf(`<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>%s</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>true</ImplicitUsings>
  </PropertyGroup>

</Project>`, framework)

	return csproj
}

// Common helper methods
func (e *CompilerExecutor) executeCommand(ctx context.Context, cmd *exec.Cmd, timeout time.Duration) (string, string, int) {
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

func (e *CompilerExecutor) generateCacheKey(code string, options *ExecutionOptions) string {
	// Simple hash-like key based on code and options
	key := fmt.Sprintf("%s-%s-%s-%s-%v", string(e.language), code[:min(len(code), 100)], e.optimizationLevel, e.compilerCmd, options.CompileFlags)
	return fmt.Sprintf("%x", []byte(key))
}