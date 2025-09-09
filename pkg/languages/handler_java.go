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

// JavaHandler handles Java code execution
type JavaHandler struct {
	*BaseHandler
}

// NewJavaHandler creates a new Java handler
func NewJavaHandler() *JavaHandler {
	return &JavaHandler{
		BaseHandler: NewBaseHandler(
			LanguageJava,
			[]string{".java"},
			"openjdk:21-jdk-slim",
			[]string{"21-jdk-slim", "17-jdk-slim", "11-jdk-slim"},
			"maven",
			45*time.Second,
			true, // Compiled language
		),
	}
}

// DetectLanguage checks if the code is Java
func (h *JavaHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	if strings.HasSuffix(strings.ToLower(filename), ".java") {
		confidence += 0.9
	}

	javaPatterns := []string{
		`public\s+class\s+\w+`,
		`public\s+static\s+void\s+main`,
		`import\s+java\.`,
		`System\.out\.print`,
		`String\[\]\s+args`,
		`public\s+\w+\s+\w+\s*\(`,
		`private\s+\w+\s+\w+`,
		`protected\s+\w+\s+\w+`,
		`@Override\b`,
		`extends\s+\w+`,
		`implements\s+\w+`,
		`new\s+\w+\s*\(`,
	}

	for _, pattern := range javaPatterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.12
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares Java code for execution
func (h *JavaHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
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

// Execute runs Java code
func (h *JavaHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguageJava,
		Metadata: make(map[string]string),
	}

	// Extract or generate class name
	className := h.extractClassName(req.Code)
	if className == "" {
		className = "Main"
		// Wrap code in a class if needed
		if !strings.Contains(req.Code, "class ") {
			req.Code = fmt.Sprintf(`public class Main {
    public static void main(String[] args) {
        %s
    }
}`, req.Code)
		}
	}

	// Write Java file
	javaFile := filepath.Join(req.WorkingDir, className+".java")
	if err := os.WriteFile(javaFile, []byte(req.Code), 0644); err != nil {
		result.Error = err
		return result, err
	}

	// Compile Java code
	compileCtx, compileCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer compileCancel()

	compileCmd := exec.CommandContext(compileCtx, "javac", javaFile)
	compileCmd.Dir = req.WorkingDir

	compileOutput, compileErr := compileCmd.CombinedOutput()
	if compileErr != nil {
		result.Duration = time.Since(startTime)
		result.Stderr = string(compileOutput)
		result.Error = NewCompilationError(
			"Java compilation failed",
			LanguageJava,
			result.Stderr,
		)
		return result, result.Error
	}

	// Run Java program
	execCtx, execCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer execCancel()

	execCmd := exec.CommandContext(execCtx, "java", className)
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
	result.Command = fmt.Sprintf("javac %s.java && java %s", className, className)

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

	// Clean up class file
	os.Remove(filepath.Join(req.WorkingDir, className+".class"))

	return result, nil
}

// InstallPackages - Java packages are typically managed via Maven/Gradle
func (h *JavaHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	return &PackageInstallResult{
		Success: false,
		Output:  "Java package management requires Maven or Gradle setup",
		Error:   fmt.Errorf("basic Java handler doesn't support package management"),
	}, nil
}

// SetupEnvironment sets up Java environment
func (h *JavaHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	result := &EnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	// Check Java version
	cmd := exec.CommandContext(ctx, "java", "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		result.Success = false
		result.Error = err
		return result, result.Error
	}

	result.Version = strings.TrimSpace(string(output))
	result.Path = "java"
	result.Success = true
	result.Output = fmt.Sprintf("Java environment ready. %s", result.Version)

	return result, nil
}

// GetRequiredFiles returns files needed for Java execution
func (h *JavaHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)

	className := h.extractClassName(req.Code)
	if className == "" {
		className = "Main"
		if !strings.Contains(req.Code, "class ") {
			req.Code = fmt.Sprintf(`public class Main {
    public static void main(String[] args) {
        %s
    }
}`, req.Code)
		}
	}

	files[className+".java"] = req.Code
	return files
}

// GetCompileCommand returns the compile command
func (h *JavaHandler) GetCompileCommand(req *ExecutionRequest) string {
	className := h.extractClassName(req.Code)
	if className == "" {
		className = "Main"
	}
	return fmt.Sprintf("javac %s.java", className)
}

// GetRunCommand returns the run command
func (h *JavaHandler) GetRunCommand(req *ExecutionRequest) string {
	className := h.extractClassName(req.Code)
	if className == "" {
		className = "Main"
	}
	return fmt.Sprintf("java %s", className)
}

// ValidateCode performs basic Java validation
func (h *JavaHandler) ValidateCode(code string) error {
	if err := h.BaseHandler.ValidateCode(code); err != nil {
		return err
	}

	// Check for public class
	if !strings.Contains(code, "class ") && !strings.Contains(code, "System.out.print") {
		return NewCompilationError(
			"Java code should contain a class or main method",
			LanguageJava,
			code,
		)
	}

	return nil
}

// Helper methods

func (h *JavaHandler) extractClassName(code string) string {
	// Look for public class declaration
	re := regexp.MustCompile(`public\s+class\s+(\w+)`)
	matches := re.FindStringSubmatch(code)
	if len(matches) > 1 {
		return matches[1]
	}

	// Look for any class declaration
	re = regexp.MustCompile(`class\s+(\w+)`)
	matches = re.FindStringSubmatch(code)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}
