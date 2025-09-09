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

// RustHandler handles Rust code execution
type RustHandler struct {
	*BaseHandler
}

// NewRustHandler creates a new Rust handler
func NewRustHandler() *RustHandler {
	return &RustHandler{
		BaseHandler: NewBaseHandler(
			LanguageRust,
			[]string{".rs"},
			"rust:1.75-slim",
			[]string{"1.75-slim", "1.74-slim", "latest"},
			"cargo",
			60*time.Second, // Rust compilation can be slow
			true,           // Compiled language
		),
	}
}

// DetectLanguage checks if the code is Rust
func (h *RustHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	if strings.HasSuffix(strings.ToLower(filename), ".rs") {
		confidence += 0.9
	}

	rustPatterns := []string{
		`fn\s+main\s*\(\s*\)`,
		`use\s+std::`,
		`println!\s*\(`,
		`let\s+mut\s+\w+`,
		`impl\s+\w+`,
		`struct\s+\w+`,
		`enum\s+\w+`,
		`match\s+\w+`,
		`&str\b`,
		`Vec<`,
		`Option<`,
		`Result<`,
	}

	for _, pattern := range rustPatterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.15
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares Rust code for execution
func (h *RustHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return err
	}

	// Create Cargo project structure
	if err := h.initCargoProject(ctx, req.WorkingDir); err != nil {
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

// Execute runs Rust code
func (h *RustHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguageRust,
		Metadata: make(map[string]string),
	}

	// Write main.rs
	srcDir := filepath.Join(req.WorkingDir, "src")
	os.MkdirAll(srcDir, 0755)

	code := req.Code
	if !strings.Contains(code, "fn main") {
		code = fmt.Sprintf("fn main() {\n%s\n}", code)
	}

	mainFile := filepath.Join(srcDir, "main.rs")
	if err := os.WriteFile(mainFile, []byte(code), 0644); err != nil {
		result.Error = err
		return result, err
	}

	// Build with cargo
	buildCtx, buildCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer buildCancel()

	buildCmd := exec.CommandContext(buildCtx, "cargo", "build", "--release")
	buildCmd.Dir = req.WorkingDir

	buildOutput, buildErr := buildCmd.CombinedOutput()
	if buildErr != nil {
		result.Duration = time.Since(startTime)
		result.Stderr = string(buildOutput)
		result.Error = NewCompilationError(
			"Rust compilation failed",
			LanguageRust,
			result.Stderr,
		)
		return result, result.Error
	}

	// Run the binary
	execCtx, execCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer execCancel()

	binaryPath := filepath.Join(req.WorkingDir, "target", "release", "rust-sandbox")
	execCmd := exec.CommandContext(execCtx, binaryPath)
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
	result.Command = "cargo build --release && ./target/release/rust-sandbox"

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

// InstallPackages installs Rust crates
func (h *RustHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	result := &PackageInstallResult{
		InstalledPackages: make([]string, 0),
		FailedPackages:    make([]string, 0),
	}

	startTime := time.Now()

	// Add dependencies to Cargo.toml
	cargoTomlPath := filepath.Join(req.WorkingDir, "Cargo.toml")
	if err := h.addDependenciesToCargoToml(cargoTomlPath, req.Packages); err != nil {
		result.Success = false
		result.Error = err
		return result, nil
	}

	// Run cargo build to install dependencies
	cmd := exec.CommandContext(ctx, "cargo", "build")
	cmd.Dir = req.WorkingDir

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.FailedPackages = req.Packages
		result.Error = err
	} else {
		result.Success = true
		result.InstalledPackages = req.Packages
	}

	return result, nil
}

// SetupEnvironment sets up Rust environment
func (h *RustHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	result := &EnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	// Check Rust version
	cmd := exec.CommandContext(ctx, "rustc", "--version")
	output, err := cmd.Output()
	if err != nil {
		result.Success = false
		result.Error = err
		return result, result.Error
	}

	result.Version = strings.TrimSpace(string(output))
	result.Path = "cargo"
	result.Success = true
	result.Output = fmt.Sprintf("Rust environment ready. %s", result.Version)

	return result, nil
}

// GetRequiredFiles returns files needed for Rust execution
func (h *RustHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)

	code := req.Code
	if !strings.Contains(code, "fn main") {
		code = fmt.Sprintf("fn main() {\n%s\n}", code)
	}

	files["src/main.rs"] = code
	files["Cargo.toml"] = h.generateCargoToml(req.Packages)

	return files
}

// GetCompileCommand returns the compile command
func (h *RustHandler) GetCompileCommand(req *ExecutionRequest) string {
	return "cargo build --release"
}

// GetRunCommand returns the run command
func (h *RustHandler) GetRunCommand(req *ExecutionRequest) string {
	return "./target/release/rust-sandbox"
}

// ValidateCode performs basic Rust validation
func (h *RustHandler) ValidateCode(code string) error {
	return h.BaseHandler.ValidateCode(code)
}

// Helper methods

func (h *RustHandler) initCargoProject(ctx context.Context, workingDir string) error {
	// Check if Cargo.toml exists
	cargoTomlPath := filepath.Join(workingDir, "Cargo.toml")
	if _, err := os.Stat(cargoTomlPath); err == nil {
		return nil
	}

	// Create Cargo.toml
	cargoToml := h.generateCargoToml(nil)
	if err := os.WriteFile(cargoTomlPath, []byte(cargoToml), 0644); err != nil {
		return err
	}

	// Create src directory
	srcDir := filepath.Join(workingDir, "src")
	return os.MkdirAll(srcDir, 0755)
}

func (h *RustHandler) generateCargoToml(packages []string) string {
	toml := `[package]
name = "rust-sandbox"
version = "0.1.0"
edition = "2021"

[dependencies]
`

	for _, pkg := range packages {
		if strings.Contains(pkg, "=") {
			toml += fmt.Sprintf("%s\n", pkg)
		} else {
			toml += fmt.Sprintf("%s = \"*\"\n", pkg)
		}
	}

	return toml
}

func (h *RustHandler) addDependenciesToCargoToml(cargoTomlPath string, packages []string) error {
	// Simple implementation - in production, use proper TOML parsing
	existing, err := os.ReadFile(cargoTomlPath)
	if err != nil {
		return err
	}

	content := string(existing)

	for _, pkg := range packages {
		if strings.Contains(pkg, "=") {
			content += fmt.Sprintf("%s\n", pkg)
		} else {
			content += fmt.Sprintf("%s = \"*\"\n", pkg)
		}
	}

	return os.WriteFile(cargoTomlPath, []byte(content), 0644)
}
