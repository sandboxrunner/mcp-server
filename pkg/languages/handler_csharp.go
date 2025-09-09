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

// CSharpHandler handles C# code execution
type CSharpHandler struct {
	*BaseHandler
	baseDir string
}

// NewCSharpHandler creates a new C# handler
func NewCSharpHandler(baseDir string) *CSharpHandler {
	return &CSharpHandler{
		BaseHandler: NewBaseHandler(
			LanguageCSharp,
			[]string{".cs", ".csx"},
			"mcr.microsoft.com/dotnet/sdk:8.0",
			[]string{"8.0", "7.0", "6.0"},
			"dotnet",
			45*time.Second,
			true, // Compiled language
		),
		baseDir: baseDir,
	}
}

// DetectLanguage checks if the code is C#
func (h *CSharpHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	// Check file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".cs" || ext == ".csx" {
		confidence += 0.9
	}

	// Check for C# patterns
	patterns := []string{
		`using\s+\w+(\.\w+)*;`,              // using statements
		`namespace\s+\w+(\.\w+)*`,           // namespace declaration
		`public\s+class\s+\w+`,              // class declaration
		`static\s+void\s+Main\s*\(`,         // Main method
		`Console\.(WriteLine|Write)\s*\(`,   // Console output
		`\[\w+Attribute\]`,                  // Attributes
		`public\s+(static\s+)?async\s+Task`, // Async methods
		`var\s+\w+\s*=`,                     // var declarations
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.15
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares C# code for execution
func (h *CSharpHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return NewEnvironmentError(
			fmt.Sprintf("failed to create working directory: %v", err),
			LanguageCSharp,
			err.Error(),
		)
	}

	// Create additional files
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

// Execute runs C# code
func (h *CSharpHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguageCSharp,
		Metadata: make(map[string]string),
	}

	// Create project directory
	projectDir := req.WorkingDir

	// Create Program.cs
	programFile := filepath.Join(projectDir, "Program.cs")
	code := req.Code

	// Wrap in Main method if needed
	if !strings.Contains(code, "static void Main") && !strings.Contains(code, "class") {
		code = fmt.Sprintf(`using System;
public class Program {
    public static void Main(string[] args) {
        %s
    }
}`, code)
	}

	if err := os.WriteFile(programFile, []byte(code), 0644); err != nil {
		result.Error = err
		return result, err
	}

	// Create project file
	projectFile := filepath.Join(projectDir, "Project.csproj")
	csprojContent := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>`

	if err := os.WriteFile(projectFile, []byte(csprojContent), 0644); err != nil {
		result.Error = err
		return result, err
	}

	// Build project
	buildCtx, buildCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer buildCancel()

	buildCmd := exec.CommandContext(buildCtx, "dotnet", "build", "--configuration", "Release")
	buildCmd.Dir = projectDir

	buildOutput, buildErr := buildCmd.CombinedOutput()
	if buildErr != nil {
		result.Duration = time.Since(startTime)
		result.Stderr = string(buildOutput)
		result.Error = NewCompilationError(
			"C# compilation failed",
			LanguageCSharp,
			result.Stderr,
		)
		return result, result.Error
	}

	// Run project
	execCtx, execCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer execCancel()

	runCmd := exec.CommandContext(execCtx, "dotnet", "run", "--configuration", "Release")
	runCmd.Dir = projectDir

	// Set environment
	runCmd.Env = os.Environ()
	for key, value := range req.Environment {
		runCmd.Env = append(runCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	if req.Stdin != "" {
		runCmd.Stdin = strings.NewReader(req.Stdin)
	}

	output, err := runCmd.CombinedOutput()
	result.Duration = time.Since(startTime)
	result.Stdout = string(output)
	result.Command = "dotnet build && dotnet run"

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

// InstallPackages installs NuGet packages
func (h *CSharpHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	result := &PackageInstallResult{
		InstalledPackages: make([]string, 0),
		FailedPackages:    make([]string, 0),
	}

	startTime := time.Now()

	for _, pkg := range req.Packages {
		parts := strings.Split(pkg, "@")
		packageName := parts[0]

		cmd := []string{"dotnet", "add", "package", packageName}
		if len(parts) > 1 {
			cmd = append(cmd, "--version", parts[1])
		}

		execCmd := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
		execCmd.Dir = req.WorkingDir

		_, err := execCmd.CombinedOutput()
		if err != nil {
			result.FailedPackages = append(result.FailedPackages, pkg)
		} else {
			result.InstalledPackages = append(result.InstalledPackages, pkg)
		}
	}

	result.Duration = time.Since(startTime)
	result.Success = len(result.FailedPackages) == 0

	return result, nil
}

// SetupEnvironment sets up C# environment
func (h *CSharpHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	result := &EnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	// Check .NET version
	cmd := exec.CommandContext(ctx, "dotnet", "--version")
	output, err := cmd.Output()
	if err != nil {
		result.Success = false
		result.Error = err
		return result, result.Error
	}

	result.Version = strings.TrimSpace(string(output))
	result.Path = "dotnet"
	result.Success = true
	result.Output = fmt.Sprintf("C# environment ready. .NET %s", result.Version)

	return result, nil
}

// GetRequiredFiles returns files needed for C# execution
func (h *CSharpHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)

	code := req.Code
	if !strings.Contains(code, "static void Main") && !strings.Contains(code, "class") {
		code = fmt.Sprintf(`using System;
public class Program {
    public static void Main(string[] args) {
        %s
    }
}`, code)
	}

	files["Program.cs"] = code
	files["Project.csproj"] = `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
</Project>`

	return files
}

// GetCompileCommand returns the compile command
func (h *CSharpHandler) GetCompileCommand(req *ExecutionRequest) string {
	return "dotnet build"
}

// GetRunCommand returns the run command
func (h *CSharpHandler) GetRunCommand(req *ExecutionRequest) string {
	return "dotnet run"
}

// ValidateCode performs basic C# validation
func (h *CSharpHandler) ValidateCode(code string) error {
	return h.BaseHandler.ValidateCode(code)
}
