package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
)

// Common parameters for all language tools
type LanguageExecutionParams struct {
	SandboxID   string            `json:"sandbox_id" validate:"required"`
	Code        string            `json:"code" validate:"required"`
	Packages    []string          `json:"packages,omitempty"`
	Files       map[string]string `json:"files,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Timeout     *int              `json:"timeout,omitempty"` // seconds
	Stdin       string            `json:"stdin,omitempty"`
}

// GenericExecutionParams includes language parameter for generic execution
type GenericExecutionParams struct {
	LanguageExecutionParams
	Language string `json:"language,omitempty"` // Optional for auto-detection
}

// LanguageToolManager provides a centralized way to access language handlers and detection
type LanguageToolManager struct {
	detector *languages.Detector
}

// NewLanguageToolManager creates a new language tool manager
func NewLanguageToolManager() *LanguageToolManager {
	return &LanguageToolManager{
		detector: languages.NewDetector(),
	}
}

// DetectLanguage detects the language from code content
func (ltm *LanguageToolManager) DetectLanguage(code string, filename string) *languages.DetectionResult {
	return ltm.detector.GetBestMatch(code, filename)
}

// Global language tool manager instance
var langToolManager = NewLanguageToolManager()

// createLanguageHandler creates a language handler for the given language
// This avoids circular import by not importing the handlers package
func createLanguageHandler(lang languages.Language) languages.LanguageHandler {
	// Since we can't import handlers due to circular import, we'll use basic execution
	// In a real implementation, the handlers would need to be refactored to avoid the cycle
	// For now, we'll create a minimal handler that can work with the sandbox execution
	return &basicLanguageHandler{language: lang}
}

// basicLanguageHandler provides basic language handling without circular imports
type basicLanguageHandler struct {
	language languages.Language
}

func (h *basicLanguageHandler) GetLanguage() languages.Language { return h.language }
func (h *basicLanguageHandler) GetSupportedExtensions() []string {
	return getLanguageExtensions(h.language)
}
func (h *basicLanguageHandler) GetDefaultImage() string                             { return getLanguageImage(h.language) }
func (h *basicLanguageHandler) GetImageVersions() []string                          { return []string{} }
func (h *basicLanguageHandler) DetectLanguage(code string, filename string) float64 { return 0.5 }
func (h *basicLanguageHandler) PrepareExecution(ctx context.Context, req *languages.ExecutionRequest) error {
	return nil
}
func (h *basicLanguageHandler) Execute(ctx context.Context, req *languages.ExecutionRequest) (*languages.ExecutionResult, error) {
	// This is handled by our executeLanguageTool function instead
	return &languages.ExecutionResult{Language: h.language}, nil
}
func (h *basicLanguageHandler) InstallPackages(ctx context.Context, req *languages.PackageInstallRequest) (*languages.PackageInstallResult, error) {
	return &languages.PackageInstallResult{Success: true}, nil
}
func (h *basicLanguageHandler) SetupEnvironment(ctx context.Context, req *languages.EnvironmentSetupRequest) (*languages.EnvironmentSetupResult, error) {
	return &languages.EnvironmentSetupResult{Success: true}, nil
}
func (h *basicLanguageHandler) GetPackageManager() string {
	return getLanguagePackageManager(h.language)
}
func (h *basicLanguageHandler) GetRequiredFiles(req *languages.ExecutionRequest) map[string]string {
	files := make(map[string]string)
	filename := getLanguageMainFile(h.language)
	files[filename] = req.Code
	return files
}
func (h *basicLanguageHandler) Cleanup(ctx context.Context, req *languages.ExecutionRequest) error {
	return nil
}
func (h *basicLanguageHandler) GetDefaultTimeout() time.Duration {
	return getLanguageTimeout(h.language)
}
func (h *basicLanguageHandler) IsCompiled() bool                                         { return isLanguageCompiled(h.language) }
func (h *basicLanguageHandler) GetCompileCommand(req *languages.ExecutionRequest) string { return "" }
func (h *basicLanguageHandler) GetRunCommand(req *languages.ExecutionRequest) string {
	return buildRunCommand(h.language, req)
}
func (h *basicLanguageHandler) ValidateCode(code string) error { return nil }

// Helper functions for language properties
func getLanguageExtensions(lang languages.Language) []string {
	switch lang {
	case languages.LanguagePython:
		return []string{".py"}
	case languages.LanguageJavaScript:
		return []string{".js"}
	case languages.LanguageTypeScript:
		return []string{".ts"}
	case languages.LanguageGo:
		return []string{".go"}
	case languages.LanguageRust:
		return []string{".rs"}
	case languages.LanguageJava:
		return []string{".java"}
	case languages.LanguageCPP:
		return []string{".cpp"}
	case languages.LanguageCSharp:
		return []string{".cs"}
	case languages.LanguageShell:
		return []string{".sh"}
	default:
		return []string{}
	}
}

func getLanguageImage(lang languages.Language) string {
	switch lang {
	case languages.LanguagePython:
		return "python:3.11-slim"
	case languages.LanguageJavaScript:
		return "node:18-alpine"
	case languages.LanguageTypeScript:
		return "node:18-alpine"
	case languages.LanguageGo:
		return "golang:1.21-alpine"
	case languages.LanguageRust:
		return "rust:1.70-slim"
	case languages.LanguageJava:
		return "openjdk:17-slim"
	case languages.LanguageCPP:
		return "gcc:latest"
	case languages.LanguageCSharp:
		return "mcr.microsoft.com/dotnet/sdk:8.0"
	case languages.LanguageShell:
		return "ubuntu:22.04"
	default:
		return "ubuntu:22.04"
	}
}

func getLanguagePackageManager(lang languages.Language) string {
	switch lang {
	case languages.LanguagePython:
		return "pip"
	case languages.LanguageJavaScript, languages.LanguageTypeScript:
		return "npm"
	case languages.LanguageGo:
		return "go"
	case languages.LanguageRust:
		return "cargo"
	case languages.LanguageJava:
		return "maven"
	case languages.LanguageCPP:
		return "apt"
	case languages.LanguageCSharp:
		return "dotnet"
	case languages.LanguageShell:
		return "apt"
	default:
		return ""
	}
}

func getLanguageMainFile(lang languages.Language) string {
	switch lang {
	case languages.LanguagePython:
		return "main.py"
	case languages.LanguageJavaScript:
		return "main.js"
	case languages.LanguageTypeScript:
		return "main.ts"
	case languages.LanguageGo:
		return "main.go"
	case languages.LanguageRust:
		return "src/main.rs"
	case languages.LanguageJava:
		return "Main.java"
	case languages.LanguageCPP:
		return "main.cpp"
	case languages.LanguageCSharp:
		return "Program.cs"
	case languages.LanguageShell:
		return "main.sh"
	default:
		return "main.txt"
	}
}

func getLanguageTimeout(lang languages.Language) time.Duration {
	switch lang {
	case languages.LanguagePython:
		return 60 * time.Second
	case languages.LanguageJavaScript:
		return 30 * time.Second
	case languages.LanguageTypeScript:
		return 45 * time.Second
	case languages.LanguageGo:
		return 30 * time.Second
	case languages.LanguageRust:
		return 120 * time.Second
	case languages.LanguageJava:
		return 60 * time.Second
	case languages.LanguageCPP:
		return 45 * time.Second
	case languages.LanguageCSharp:
		return 45 * time.Second
	case languages.LanguageShell:
		return 30 * time.Second
	default:
		return 30 * time.Second
	}
}

func isLanguageCompiled(lang languages.Language) bool {
	switch lang {
	case languages.LanguageGo, languages.LanguageRust, languages.LanguageJava, languages.LanguageCPP, languages.LanguageCSharp:
		return true
	default:
		return false
	}
}

// Base language tool implementation
func executeLanguageTool(ctx context.Context, lang languages.Language, params map[string]interface{}, manager *sandbox.Manager) (*ToolResult, error) {
	// Parse parameters
	var execParams LanguageExecutionParams
	if err := parseParams(params, &execParams); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	// Get sandbox
	sb, err := manager.GetSandbox(execParams.SandboxID)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox not found: %v", err),
			IsError: true,
		}, nil
	}

	if sb.Status != sandbox.SandboxStatusRunning {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox is not running (status: %s)", sb.Status),
			IsError: true,
		}, nil
	}

	// Get language handler (create directly to avoid circular imports)
	handler := createLanguageHandler(lang)
	if handler == nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Language handler not found for: %s", lang),
			IsError: true,
		}, nil
	}

	// Set default timeout if not specified
	timeout := handler.GetDefaultTimeout()
	if execParams.Timeout != nil {
		timeout = time.Duration(*execParams.Timeout) * time.Second
	}

	// Set working directory if not specified
	workingDir := execParams.WorkingDir
	if workingDir == "" {
		workingDir = "/workspace"
	}

	// Build execution request
	req := &languages.ExecutionRequest{
		Code:        execParams.Code,
		Language:    lang,
		WorkingDir:  workingDir,
		Environment: execParams.Environment,
		Timeout:     timeout,
		Packages:    execParams.Packages,
		Options:     execParams.Options,
		Files:       execParams.Files,
		Stdin:       execParams.Stdin,
	}

	// Create a temporary execution directory in the sandbox
	tempDir := fmt.Sprintf("/tmp/lang_exec_%d", time.Now().UnixNano())
	createDirCmd := fmt.Sprintf("mkdir -p %s && cd %s", tempDir, tempDir)

	// Execute directory creation - placeholder implementation
	// TODO: Implement actual command execution using runtime client
	_ = createDirCmd // Avoid unused variable

	// For now, just set the working directory
	// In a real implementation, this would execute commands in the sandbox

	req.WorkingDir = tempDir

	// Get required files from handler
	requiredFiles := handler.GetRequiredFiles(req)

	// Create additional files if specified
	allFiles := make(map[string]string)
	for name, content := range requiredFiles {
		allFiles[name] = content
	}
	for name, content := range req.Files {
		allFiles[name] = content
	}

	// Write all required files to the sandbox - placeholder implementation
	// TODO: Implement actual file writing using runtime client
	for filename, content := range allFiles {
		_ = filename // Avoid unused variable
		_ = content  // Avoid unused variable
		// In a real implementation, this would write files to the sandbox
	}

	// Install packages if specified and handler supports it
	if len(req.Packages) > 0 {
		installCmd := getPackageInstallCommand(lang, req.Packages, req.Options)
		if installCmd != "" {
			// TODO: Implement actual package installation using runtime client
			_ = installCmd // Avoid unused variable
			// In a real implementation, this would install packages in the sandbox
		}
	}

	// Build and execute the run command
	runCmd := buildRunCommand(lang, req)
	if runCmd == "" {
		return &ToolResult{
			Text:    fmt.Sprintf("Unable to build run command for language: %s", lang),
			IsError: true,
		}, nil
	}

	// Handle stdin if provided
	if req.Stdin != "" {
		runCmd = fmt.Sprintf("echo %s | %s", strconv.Quote(req.Stdin), runCmd)
	}

	// Execute the code - placeholder implementation
	startTime := time.Now()
	// TODO: Implement actual code execution using runtime client
	_ = runCmd // Avoid unused variable
	duration := time.Since(startTime)

	// Placeholder output for now
	output := fmt.Sprintf("Language execution not yet implemented for %s\nCommand would be: %s", lang, runCmd)
	err = nil // No error in placeholder

	// Cleanup temporary directory - placeholder
	cleanupCmd := fmt.Sprintf("rm -rf %s", tempDir)
	_ = cleanupCmd // Avoid unused variable
	// TODO: Implement actual cleanup using runtime client

	// Determine exit code and parse output
	exitCode := 0
	stdout := output
	stderr := ""

	if err != nil {
		exitCode = 1
		stderr = err.Error()
		if output != "" {
			stderr += "\n" + output
		}
	}

	// Format result
	resultText := ""
	if stdout != "" {
		resultText += fmt.Sprintf("STDOUT:\n%s\n", stdout)
	}
	if stderr != "" {
		resultText += fmt.Sprintf("STDERR:\n%s\n", stderr)
	}
	if exitCode != 0 {
		resultText += fmt.Sprintf("Exit Code: %d\n", exitCode)
	}
	resultText += fmt.Sprintf("Duration: %s\n", duration)
	resultText += fmt.Sprintf("Language: %s\n", lang)
	resultText += fmt.Sprintf("Command: %s\n", runCmd)

	metadata := map[string]interface{}{
		"sandbox_id":  execParams.SandboxID,
		"language":    string(lang),
		"exit_code":   exitCode,
		"duration_ms": duration.Milliseconds(),
		"command":     runCmd,
		"working_dir": tempDir,
	}

	return &ToolResult{
		Text:     resultText,
		IsError:  exitCode != 0,
		Metadata: metadata,
	}, nil
}

// Helper function to format execution results
func formatExecutionResult(result *languages.ExecutionResult) string {
	output := ""

	if result.Stdout != "" {
		output += fmt.Sprintf("STDOUT:\n%s\n", result.Stdout)
	}

	if result.Stderr != "" {
		output += fmt.Sprintf("STDERR:\n%s\n", result.Stderr)
	}

	if result.ExitCode != 0 {
		output += fmt.Sprintf("Exit Code: %d\n", result.ExitCode)
	}

	output += fmt.Sprintf("Duration: %s\n", result.Duration)
	output += fmt.Sprintf("Language: %s\n", result.Language)

	if result.Command != "" {
		output += fmt.Sprintf("Command: %s\n", result.Command)
	}

	return output
}

// Helper function to parse parameters into struct
func parseParams(params map[string]interface{}, target interface{}) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, target)
}

// getPackageInstallCommand returns the appropriate package installation command for each language
func getPackageInstallCommand(lang languages.Language, packages []string, options map[string]string) string {
	if len(packages) == 0 {
		return ""
	}

	switch lang {
	case languages.LanguagePython:
		cmd := "pip install"
		if options["user"] == "true" {
			cmd += " --user"
		}
		if options["upgrade"] == "true" {
			cmd += " --upgrade"
		}
		return fmt.Sprintf("%s %s", cmd, strings.Join(packages, " "))

	case languages.LanguageJavaScript, languages.LanguageTypeScript:
		return fmt.Sprintf("npm install %s", strings.Join(packages, " "))

	case languages.LanguageGo:
		cmds := []string{}
		if _, exists := options["module_name"]; !exists {
			cmds = append(cmds, "go mod init main")
		}
		for _, pkg := range packages {
			cmds = append(cmds, fmt.Sprintf("go mod download %s", pkg))
		}
		return strings.Join(cmds, " && ")

	case languages.LanguageRust:
		// For Rust, packages are dependencies in Cargo.toml
		return ""

	case languages.LanguageJava:
		// Java dependencies are complex, would need Maven/Gradle setup
		return ""

	case languages.LanguageCPP:
		// Install system packages
		return fmt.Sprintf("apt-get update && apt-get install -y %s", strings.Join(packages, " "))

	case languages.LanguageCSharp:
		cmds := []string{}
		for _, pkg := range packages {
			cmds = append(cmds, fmt.Sprintf("dotnet add package %s", pkg))
		}
		return strings.Join(cmds, " && ")

	case languages.LanguageShell:
		// Install system packages
		return fmt.Sprintf("apt-get update && apt-get install -y %s", strings.Join(packages, " "))

	default:
		return ""
	}
}

// buildRunCommand builds the appropriate run command for each language
func buildRunCommand(lang languages.Language, req *languages.ExecutionRequest) string {
	switch lang {
	case languages.LanguagePython:
		pythonCmd := "python3"
		if cmd, exists := req.Options["python_cmd"]; exists {
			pythonCmd = cmd
		}
		return fmt.Sprintf("%s main.py", pythonCmd)

	case languages.LanguageJavaScript:
		return "node main.js"

	case languages.LanguageTypeScript:
		// Compile and run TypeScript
		target := "ES2020"
		if t, exists := req.Options["target"]; exists {
			target = t
		}
		return fmt.Sprintf("npx tsc --target %s main.ts && node main.js", target)

	case languages.LanguageGo:
		return "go run main.go"

	case languages.LanguageRust:
		// Create Cargo.toml and run
		edition := "2021"
		if e, exists := req.Options["edition"]; exists {
			edition = e
		}

		cargoCmd := "cargo run"
		if req.Options["release"] == "true" {
			cargoCmd = "cargo run --release"
		}

		// Create a basic Cargo.toml first
		createCargo := fmt.Sprintf(`cat > Cargo.toml << 'EOF'
[package]
name = "main"
version = "0.1.0"
edition = "%s"

[dependencies]
EOF`, edition)

		return fmt.Sprintf("%s && %s", createCargo, cargoCmd)

	case languages.LanguageJava:
		className := "Main"
		if c, exists := req.Options["main_class"]; exists {
			className = c
		}
		return fmt.Sprintf("javac %s.java && java %s", className, className)

	case languages.LanguageCPP:
		compiler := "g++"
		if c, exists := req.Options["compiler"]; exists {
			compiler = c
		}

		std := "c++17"
		if s, exists := req.Options["std"]; exists {
			std = s
		}

		optimization := "O2"
		if o, exists := req.Options["optimization"]; exists {
			optimization = o
		}

		extraFlags := ""
		if f, exists := req.Options["extra_flags"]; exists {
			extraFlags = " " + f
		}

		return fmt.Sprintf("%s -std=%s -%s%s main.cpp -o main && ./main", compiler, std, optimization, extraFlags)

	case languages.LanguageCSharp:
		framework := "net8.0"
		if f, exists := req.Options["framework"]; exists {
			framework = f
		}

		// Create basic project file
		createProj := fmt.Sprintf(`cat > main.csproj << 'EOF'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>%s</TargetFramework>
  </PropertyGroup>
</Project>
EOF`, framework)

		return fmt.Sprintf("%s && dotnet run", createProj)

	case languages.LanguageShell:
		shell := "bash"
		if s, exists := req.Options["shell"]; exists {
			shell = s
		}

		setFlags := ""
		if flags, exists := req.Options["set_flags"]; exists {
			setFlags = fmt.Sprintf("set %s && ", flags)
		}

		return fmt.Sprintf("%s%s main.sh", setFlags, shell)

	default:
		return ""
	}
}

// RunPythonTool executes Python code
type RunPythonTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunPythonTool(manager *sandbox.Manager) *RunPythonTool {
	return &RunPythonTool{
		BaseTool: NewBaseTool(
			"run_python",
			"Execute Python code with pip package support and virtual environment management",
			PythonSchema(),
		),
		manager: manager,
	}
}

func (t *RunPythonTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguagePython, params, t.manager)
}

// RunJavaScriptTool executes JavaScript/Node.js code
type RunJavaScriptTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunJavaScriptTool(manager *sandbox.Manager) *RunJavaScriptTool {
	return &RunJavaScriptTool{
		BaseTool: NewBaseTool(
			"run_javascript",
			"Execute JavaScript/Node.js code with npm package support and project management",
			JavaScriptSchema(),
		),
		manager: manager,
	}
}

func (t *RunJavaScriptTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguageJavaScript, params, t.manager)
}

// RunTypeScriptTool executes TypeScript code
type RunTypeScriptTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunTypeScriptTool(manager *sandbox.Manager) *RunTypeScriptTool {
	return &RunTypeScriptTool{
		BaseTool: NewBaseTool(
			"run_typescript",
			"Execute TypeScript code with compilation support and npm package management",
			TypeScriptSchema(),
		),
		manager: manager,
	}
}

func (t *RunTypeScriptTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguageTypeScript, params, t.manager)
}

// RunGoTool executes Go code
type RunGoTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunGoTool(manager *sandbox.Manager) *RunGoTool {
	return &RunGoTool{
		BaseTool: NewBaseTool(
			"run_go",
			"Execute Go code with module support and dependency management",
			GoSchema(),
		),
		manager: manager,
	}
}

func (t *RunGoTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguageGo, params, t.manager)
}

// RunRustTool executes Rust code
type RunRustTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunRustTool(manager *sandbox.Manager) *RunRustTool {
	return &RunRustTool{
		BaseTool: NewBaseTool(
			"run_rust",
			"Execute Rust code with Cargo support and dependency management",
			RustSchema(),
		),
		manager: manager,
	}
}

func (t *RunRustTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguageRust, params, t.manager)
}

// RunJavaTool executes Java code
type RunJavaTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunJavaTool(manager *sandbox.Manager) *RunJavaTool {
	return &RunJavaTool{
		BaseTool: NewBaseTool(
			"run_java",
			"Execute Java code with compilation and Maven/Gradle dependency support",
			JavaSchema(),
		),
		manager: manager,
	}
}

func (t *RunJavaTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguageJava, params, t.manager)
}

// RunCppTool executes C++ code
type RunCppTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunCppTool(manager *sandbox.Manager) *RunCppTool {
	return &RunCppTool{
		BaseTool: NewBaseTool(
			"run_cpp",
			"Execute C++ code with compilation support and library management",
			CppSchema(),
		),
		manager: manager,
	}
}

func (t *RunCppTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguageCPP, params, t.manager)
}

// RunCSharpTool executes C# code
type RunCSharpTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunCSharpTool(manager *sandbox.Manager) *RunCSharpTool {
	return &RunCSharpTool{
		BaseTool: NewBaseTool(
			"run_csharp",
			"Execute C# code with .NET support and NuGet package management",
			CSharpSchema(),
		),
		manager: manager,
	}
}

func (t *RunCSharpTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguageCSharp, params, t.manager)
}

// RunShellTool executes shell scripts
type RunShellTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunShellTool(manager *sandbox.Manager) *RunShellTool {
	return &RunShellTool{
		BaseTool: NewBaseTool(
			"run_shell",
			"Execute shell scripts with support for multiple shell interpreters",
			ShellSchema(),
		),
		manager: manager,
	}
}

func (t *RunShellTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return executeLanguageTool(ctx, languages.LanguageShell, params, t.manager)
}

// RunGenericTool executes code with automatic language detection
type RunGenericTool struct {
	*BaseTool
	manager *sandbox.Manager
}

func NewRunGenericTool(manager *sandbox.Manager) *RunGenericTool {
	return &RunGenericTool{
		BaseTool: NewBaseTool(
			"run_generic",
			"Execute code in any supported language with automatic detection and package management",
			GenericSchema(),
		),
		manager: manager,
	}
}

func (t *RunGenericTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	// Parse parameters
	var execParams GenericExecutionParams
	if err := parseParams(params, &execParams); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	var detectedLang languages.Language

	// Use provided language or detect it
	if execParams.Language != "" {
		detectedLang = languages.Language(execParams.Language)
	} else {
		// Auto-detect language
		detection := langToolManager.DetectLanguage(execParams.Code, "")
		if detection.Confidence < 0.3 {
			return &ToolResult{
				Text:    fmt.Sprintf("Unable to reliably detect language (confidence: %.2f). Please specify the language explicitly.", detection.Confidence),
				IsError: true,
			}, nil
		}
		detectedLang = detection.Language
	}

	// Verify language is supported
	handler := createLanguageHandler(detectedLang)
	if handler == nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Unsupported language: %s", detectedLang),
			IsError: true,
		}, nil
	}

	// Convert to base parameters and execute
	baseParams := map[string]interface{}{
		"sandbox_id":  execParams.SandboxID,
		"code":        execParams.Code,
		"packages":    execParams.Packages,
		"files":       execParams.Files,
		"options":     execParams.Options,
		"environment": execParams.Environment,
		"working_dir": execParams.WorkingDir,
		"timeout":     execParams.Timeout,
		"stdin":       execParams.Stdin,
	}

	result, err := executeLanguageTool(ctx, detectedLang, baseParams, t.manager)
	if err != nil {
		return result, err
	}

	// Add detection information to metadata
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	result.Metadata["detected_language"] = string(detectedLang)
	result.Metadata["was_auto_detected"] = execParams.Language == ""

	return result, nil
}

// Schema definitions for each language tool

// PythonSchema returns the JSON schema for Python execution
func PythonSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "Python code to execute",
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "Python packages to install via pip (e.g., ['numpy', 'pandas==1.5.0'])",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace (filename -> content)",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "Python-specific options (use_venv, python_cmd, etc.)",
				"properties": map[string]interface{}{
					"use_venv": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"true", "false"},
						"description": "Whether to use a virtual environment",
					},
					"python_cmd": map[string]interface{}{
						"type":        "string",
						"description": "Python command to use (default: python3)",
					},
				},
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 30)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// JavaScriptSchema returns the JSON schema for JavaScript execution
func JavaScriptSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "JavaScript/Node.js code to execute",
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "NPM packages to install (e.g., ['lodash', 'express@^4.18.0'])",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "JavaScript-specific options",
				"properties": map[string]interface{}{
					"node_version": map[string]interface{}{
						"type":        "string",
						"description": "Node.js version to use",
					},
					"use_typescript": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"true", "false"},
						"description": "Enable TypeScript support",
					},
				},
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 30)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// TypeScriptSchema returns the JSON schema for TypeScript execution
func TypeScriptSchema() map[string]interface{} {
	schema := JavaScriptSchema()
	props := schema["properties"].(map[string]interface{})
	props["code"].(map[string]interface{})["description"] = "TypeScript code to execute (will be compiled automatically)"

	options := props["options"].(map[string]interface{})["properties"].(map[string]interface{})
	options["tsconfig"] = map[string]interface{}{
		"type":        "object",
		"description": "TypeScript configuration options",
	}
	options["target"] = map[string]interface{}{
		"type":        "string",
		"description": "TypeScript compilation target (ES2020, ES2021, etc.)",
		"default":     "ES2020",
	}

	return schema
}

// GoSchema returns the JSON schema for Go execution
func GoSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "Go code to execute",
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "Go modules to install (e.g., ['github.com/gin-gonic/gin@v1.9.0'])",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "Go-specific options",
				"properties": map[string]interface{}{
					"go_version": map[string]interface{}{
						"type":        "string",
						"description": "Go version to use",
					},
					"build_flags": map[string]interface{}{
						"type":        "string",
						"description": "Additional build flags",
					},
					"module_name": map[string]interface{}{
						"type":        "string",
						"description": "Go module name (default: main)",
						"default":     "main",
					},
				},
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 30)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// RustSchema returns the JSON schema for Rust execution
func RustSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "Rust code to execute",
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "Rust crates to add as dependencies (e.g., ['serde = \"1.0\"', 'tokio = { version = \"1.0\", features = [\"full\"] }'])",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "Rust-specific options",
				"properties": map[string]interface{}{
					"edition": map[string]interface{}{
						"type":        "string",
						"description": "Rust edition (2018, 2021)",
						"default":     "2021",
					},
					"release": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"true", "false"},
						"description": "Build in release mode",
					},
					"features": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "Cargo features to enable",
					},
				},
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 60)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// JavaSchema returns the JSON schema for Java execution
func JavaSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "Java code to execute",
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "Maven/Gradle dependencies (e.g., ['com.google.gson:gson:2.8.9'])",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "Java-specific options",
				"properties": map[string]interface{}{
					"java_version": map[string]interface{}{
						"type":        "string",
						"description": "Java version to use",
					},
					"main_class": map[string]interface{}{
						"type":        "string",
						"description": "Main class name (default: Main)",
						"default":     "Main",
					},
					"classpath": map[string]interface{}{
						"type":        "string",
						"description": "Additional classpath entries",
					},
					"build_tool": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"maven", "gradle"},
						"description": "Build tool to use for dependencies",
						"default":     "maven",
					},
				},
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 60)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// CppSchema returns the JSON schema for C++ execution
func CppSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "C++ code to execute",
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "System packages/libraries to install (e.g., ['libboost-dev', 'libeigen3-dev'])",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "C++-specific options",
				"properties": map[string]interface{}{
					"std": map[string]interface{}{
						"type":        "string",
						"description": "C++ standard (c++11, c++14, c++17, c++20)",
						"default":     "c++17",
					},
					"compiler": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"g++", "clang++"},
						"description": "C++ compiler to use",
						"default":     "g++",
					},
					"optimization": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"O0", "O1", "O2", "O3"},
						"description": "Optimization level",
						"default":     "O2",
					},
					"extra_flags": map[string]interface{}{
						"type":        "string",
						"description": "Additional compiler flags",
					},
				},
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 45)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// CSharpSchema returns the JSON schema for C# execution
func CSharpSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "C# code to execute",
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "NuGet packages to install (e.g., ['Newtonsoft.Json', 'Microsoft.Extensions.Logging'])",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "C#-specific options",
				"properties": map[string]interface{}{
					"framework": map[string]interface{}{
						"type":        "string",
						"description": ".NET framework version (net6.0, net7.0, net8.0)",
						"default":     "net8.0",
					},
					"nullable": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"enable", "disable"},
						"description": "Nullable reference types",
						"default":     "enable",
					},
					"implicit_usings": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"true", "false"},
						"description": "Enable implicit using directives",
						"default":     "true",
					},
				},
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 45)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// ShellSchema returns the JSON schema for shell execution
func ShellSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "Shell script to execute",
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "System packages to install (e.g., ['curl', 'jq', 'git'])",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "Shell-specific options",
				"properties": map[string]interface{}{
					"shell": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"bash", "sh", "zsh", "fish"},
						"description": "Shell interpreter to use",
						"default":     "bash",
					},
					"set_flags": map[string]interface{}{
						"type":        "string",
						"description": "Shell set flags (e.g., '-euo pipefail')",
					},
				},
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 30)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}

// GenericSchema returns the JSON schema for generic execution with auto-detection
func GenericSchema() map[string]interface{} {
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"sandbox_id": map[string]interface{}{
				"type":        "string",
				"description": "The unique identifier of the sandbox",
			},
			"code": map[string]interface{}{
				"type":        "string",
				"description": "Code to execute in any supported language",
			},
			"language": map[string]interface{}{
				"type":        "string",
				"description": "Programming language (optional - will be auto-detected if not specified)",
				"enum": []string{
					"python", "javascript", "typescript", "go", "rust",
					"java", "cpp", "csharp", "shell",
				},
			},
			"packages": map[string]interface{}{
				"type":        "array",
				"items":       map[string]interface{}{"type": "string"},
				"description": "Language-specific packages to install",
			},
			"files": map[string]interface{}{
				"type":        "object",
				"description": "Additional files to create in the workspace",
			},
			"options": map[string]interface{}{
				"type":        "object",
				"description": "Language-specific execution options",
			},
			"environment": map[string]interface{}{
				"type":        "object",
				"description": "Environment variables for execution",
			},
			"working_dir": map[string]interface{}{
				"type":        "string",
				"description": "Working directory for execution (default: /workspace)",
			},
			"timeout": map[string]interface{}{
				"type":        "integer",
				"description": "Execution timeout in seconds (default: 30)",
				"minimum":     1,
				"maximum":     300,
			},
			"stdin": map[string]interface{}{
				"type":        "string",
				"description": "Standard input to provide to the program",
			},
		},
		"required": []string{"sandbox_id", "code"},
	}
}
