package languages

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/node"
)

// JavaScriptHandler handles JavaScript/Node.js code execution
type JavaScriptHandler struct {
	*BaseHandler
	npmInstaller      *node.NPMInstaller
	environmentManager *node.NodeEnvironmentManager
	analyzer          *node.JavaScriptAnalyzer
}

// NewJavaScriptHandler creates a new JavaScript handler
func NewJavaScriptHandler() *JavaScriptHandler {
	handler := &JavaScriptHandler{
		BaseHandler: NewBaseHandler(
			LanguageJavaScript,
			[]string{".js", ".mjs", ".cjs"},
			"node:18-alpine",
			[]string{"node:18-alpine", "node:16-alpine", "node:20-alpine"},
			"npm",
			30*time.Second,
			false, // Interpreted language
		),
	}
	
	return handler
}

// initializeNodeComponents initializes Node.js components for the handler
func (h *JavaScriptHandler) initializeNodeComponents(workingDir string) {
	if h.npmInstaller == nil {
		h.npmInstaller = node.NewNPMInstaller(workingDir, "node", node.PackageManagerNPM)
	}
	if h.environmentManager == nil {
		h.environmentManager = node.NewNodeEnvironmentManager(workingDir)
	}
	if h.analyzer == nil {
		h.analyzer = node.NewJavaScriptAnalyzer(workingDir)
	}
}

// DetectLanguage checks if the code is JavaScript
func (h *JavaScriptHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	// Check file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".js" || ext == ".mjs" || ext == ".cjs" {
		confidence += 0.8
	}

	// Simple JavaScript pattern detection
	if strings.Contains(code, "function") || strings.Contains(code, "const ") ||
		strings.Contains(code, "let ") || strings.Contains(code, "var ") ||
		strings.Contains(code, "console.log") {
		confidence += 0.3
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares JavaScript code for execution
func (h *JavaScriptHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return err
	}

	// Initialize Node.js components
	h.initializeNodeComponents(req.WorkingDir)

	// Setup Node.js environment if needed
	if h.environmentManager != nil {
		setupReq := &node.NodeEnvironmentSetupRequest{
			Environment: req.Environment,
		}
		
		// Auto-detect package manager
		packageManager := h.environmentManager.DetectPackageManager()
		h.npmInstaller = node.NewNPMInstaller(req.WorkingDir, "node", packageManager)
		
		_, err := h.environmentManager.SetupEnvironment(ctx, setupReq)
		if err != nil {
			// Log warning but don't fail - basic execution might still work
			fmt.Printf("Warning: Node.js environment setup failed: %v\n", err)
		}
	}

	// Install packages if specified
	if len(req.Packages) > 0 && h.npmInstaller != nil {
		installReq := &node.NodeInstallRequest{
			Packages:       req.Packages,
			PackageManager: h.environmentManager.DetectPackageManager(),
			Environment:    req.Environment,
			Timeout:        req.Timeout,
		}
		
		result, err := h.npmInstaller.Install(ctx, installReq)
		if err != nil || !result.Success {
			return fmt.Errorf("package installation failed: %v", err)
		}
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

// Execute runs JavaScript code
func (h *JavaScriptHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguageJavaScript,
		Metadata: make(map[string]string),
	}

	// Write JavaScript file
	jsFile := filepath.Join(req.WorkingDir, "main.js")
	if err := os.WriteFile(jsFile, []byte(req.Code), 0644); err != nil {
		result.Error = err
		return result, err
	}

	// Execute JavaScript code
	execCtx, execCancel := context.WithTimeout(ctx, req.Timeout)
	defer execCancel()

	execCmd := exec.CommandContext(execCtx, "node", jsFile)
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
	result.Command = "node main.js"

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

// InstallPackages installs JavaScript packages using npm
func (h *JavaScriptHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	h.initializeNodeComponents(req.WorkingDir)
	
	if h.npmInstaller == nil {
		return &PackageInstallResult{
			Success: false,
			Output:  "npm installer not available",
		}, fmt.Errorf("npm installer not initialized")
	}

	// Convert to Node.js install request
	nodeReq := &node.NodeInstallRequest{
		Packages:       req.Packages,
		PackageManager: h.environmentManager.DetectPackageManager(),
		Environment:    req.Environment,
		Timeout:        30 * time.Second,
	}

	result, err := h.npmInstaller.Install(ctx, nodeReq)
	if err != nil {
		return &PackageInstallResult{
			Success:        false,
			Output:         result.Output,
			Error:          err,
			Duration:       result.Duration,
		}, err
	}

	// Convert result
	installedPackages := make([]string, len(result.InstalledPackages))
	for i, pkg := range result.InstalledPackages {
		installedPackages[i] = pkg.Name
	}

	failedPackages := make([]string, 0)
	for pkg := range result.FailedPackages {
		failedPackages = append(failedPackages, pkg)
	}

	return &PackageInstallResult{
		Success:           result.Success,
		InstalledPackages: installedPackages,
		FailedPackages:    failedPackages,
		Output:            result.Output,
		Error:             result.Error,
		Duration:          result.Duration,
	}, nil
}

// SetupEnvironment sets up JavaScript environment
func (h *JavaScriptHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	h.initializeNodeComponents(req.WorkingDir)
	
	if h.environmentManager == nil {
		// Fallback to simple setup
		result := &EnvironmentSetupResult{
			Environment: make(map[string]string),
		}

		// Check Node.js version
		cmd := exec.CommandContext(ctx, "node", "--version")
		output, err := cmd.Output()
		if err != nil {
			result.Success = false
			result.Error = err
			return result, result.Error
		}

		result.Version = strings.TrimSpace(string(output))
		result.Path = "node"
		result.Success = true
		result.Output = fmt.Sprintf("JavaScript environment ready. Node.js %s", result.Version)
		return result, nil
	}

	// Use comprehensive Node.js environment setup
	nodeReq := &node.NodeEnvironmentSetupRequest{
		NodeVersion: req.Version,
		Environment: req.Options,
	}

	nodeResult, err := h.environmentManager.SetupEnvironment(ctx, nodeReq)
	if err != nil {
		return &EnvironmentSetupResult{
			Success: false,
			Error:   err,
			Output:  nodeResult.Output,
		}, err
	}

	return &EnvironmentSetupResult{
		Success:     nodeResult.Success,
		Version:     nodeResult.NodeVersion,
		Path:        nodeResult.NodePath,
		Environment: nodeResult.Environment,
		Output:      nodeResult.Output,
		Error:       nodeResult.Error,
	}, nil
}

// GetRequiredFiles returns files needed for JavaScript execution
func (h *JavaScriptHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)
	files["main.js"] = req.Code
	return files
}

// GetCompileCommand returns empty for JavaScript (interpreted)
func (h *JavaScriptHandler) GetCompileCommand(req *ExecutionRequest) string {
	return ""
}

// GetRunCommand returns the JavaScript run command
func (h *JavaScriptHandler) GetRunCommand(req *ExecutionRequest) string {
	return "node main.js"
}

// ValidateCode performs basic JavaScript validation
func (h *JavaScriptHandler) ValidateCode(code string) error {
	return h.BaseHandler.ValidateCode(code)
}
