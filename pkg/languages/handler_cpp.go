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

// CPPHandler handles C++ code execution
type CPPHandler struct {
	*BaseHandler
}

// NewCPPHandler creates a new C++ handler
func NewCPPHandler() *CPPHandler {
	return &CPPHandler{
		BaseHandler: NewBaseHandler(
			LanguageCPP,
			[]string{".cpp", ".cxx", ".cc", ".hpp", ".hxx"},
			"gcc:latest",
			[]string{"gcc:latest", "gcc:11", "gcc:10"},
			"", // No package manager
			30*time.Second,
			true, // Compiled language
		),
	}
}

// DetectLanguage checks if the code is C++
func (h *CPPHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".hpp" || ext == ".hxx" {
		confidence += 0.9
	}

	cppPatterns := []string{
		`#include\s*<iostream>`,
		`std::(cout|cin|endl)`,
		`using\s+namespace\s+std`,
		`class\s+\w+\s*{`,
		`public\s*:`,
		`private\s*:`,
		`protected\s*:`,
		`virtual\s+\w+`,
		`template\s*<`,
		`namespace\s+\w+`,
		`operator\s*\w+`,
		`::`,
	}

	for _, pattern := range cppPatterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.15
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares C++ code for execution
func (h *CPPHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return err
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

// Execute runs C++ code
func (h *CPPHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguageCPP,
		Metadata: make(map[string]string),
	}

	// Write C++ file
	cppFile := filepath.Join(req.WorkingDir, "main.cpp")
	code := req.Code

	// Add basic includes if missing
	if !strings.Contains(code, "#include") && strings.Contains(code, "cout") {
		code = "#include <iostream>\nusing namespace std;\n\n" + code
	}

	// Wrap in main function if needed
	if !strings.Contains(code, "int main") {
		code = fmt.Sprintf("#include <iostream>\nusing namespace std;\n\nint main() {\n%s\nreturn 0;\n}", code)
	}

	if err := os.WriteFile(cppFile, []byte(code), 0644); err != nil {
		result.Error = err
		return result, err
	}

	// Compile C++ code
	compileCtx, compileCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer compileCancel()

	binaryFile := filepath.Join(req.WorkingDir, "main")
	compileCmd := exec.CommandContext(compileCtx, "g++", "-o", binaryFile, cppFile)
	compileCmd.Dir = req.WorkingDir

	compileOutput, compileErr := compileCmd.CombinedOutput()
	if compileErr != nil {
		result.Duration = time.Since(startTime)
		result.Stderr = string(compileOutput)
		result.Error = NewCompilationError(
			"C++ compilation failed",
			LanguageCPP,
			result.Stderr,
		)
		return result, result.Error
	}

	// Run the binary
	execCtx, execCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer execCancel()

	execCmd := exec.CommandContext(execCtx, binaryFile)
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
	result.Command = "g++ -o main main.cpp && ./main"

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

	// Clean up binary
	os.Remove(binaryFile)

	return result, nil
}

// InstallPackages - not applicable for basic C++
func (h *CPPHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	return &PackageInstallResult{
		Success: false,
		Output:  "Basic C++ handler doesn't support package management",
	}, nil
}

// SetupEnvironment sets up C++ environment
func (h *CPPHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	result := &EnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	// Check g++ version
	cmd := exec.CommandContext(ctx, "g++", "--version")
	output, err := cmd.Output()
	if err != nil {
		result.Success = false
		result.Error = err
		return result, result.Error
	}

	result.Version = strings.TrimSpace(string(output))
	result.Path = "g++"
	result.Success = true
	result.Output = fmt.Sprintf("C++ environment ready. %s", result.Version)

	return result, nil
}

// GetRequiredFiles returns files needed for C++ execution
func (h *CPPHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)

	code := req.Code
	if !strings.Contains(code, "#include") && strings.Contains(code, "cout") {
		code = "#include <iostream>\nusing namespace std;\n\n" + code
	}

	if !strings.Contains(code, "int main") {
		code = fmt.Sprintf("#include <iostream>\nusing namespace std;\n\nint main() {\n%s\nreturn 0;\n}", code)
	}

	files["main.cpp"] = code
	return files
}

// GetCompileCommand returns the compile command
func (h *CPPHandler) GetCompileCommand(req *ExecutionRequest) string {
	return "g++ -o main main.cpp"
}

// GetRunCommand returns the run command
func (h *CPPHandler) GetRunCommand(req *ExecutionRequest) string {
	return "./main"
}

// ValidateCode performs basic C++ validation
func (h *CPPHandler) ValidateCode(code string) error {
	return h.BaseHandler.ValidateCode(code)
}
