package languages

import (
	"context"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/types"
)

// Import the Language type from the common types package
type Language = types.Language

// Re-export language constants for backward compatibility
const (
	LanguagePython     = types.LanguagePython
	LanguageJavaScript = types.LanguageJavaScript
	LanguageTypeScript = types.LanguageTypeScript
	LanguageGo         = types.LanguageGo
	LanguageRust       = types.LanguageRust
	LanguageJava       = types.LanguageJava
	LanguageC          = types.LanguageC
	LanguageCPP        = types.LanguageCPP
	LanguageCSharp     = types.LanguageCSharp
	LanguageRuby       = types.LanguageRuby
	LanguagePHP        = types.LanguagePHP
	LanguageShell      = types.LanguageShell
	LanguageR          = types.LanguageR
	LanguageLua        = types.LanguageLua
	LanguagePerl       = types.LanguagePerl
)

// ExecutionRequest contains the parameters for code execution
type ExecutionRequest struct {
	Code        string            `json:"code"`
	Language    Language          `json:"language"`
	WorkingDir  string            `json:"working_dir"`
	Environment map[string]string `json:"environment"`
	Timeout     time.Duration     `json:"timeout"`
	Packages    []string          `json:"packages,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
	Files       map[string]string `json:"files,omitempty"` // Additional files to create
	Stdin       string            `json:"stdin,omitempty"`
}

// ExecutionResult contains the result of code execution
type ExecutionResult struct {
	ExitCode int               `json:"exit_code"`
	Stdout   string            `json:"stdout"`
	Stderr   string            `json:"stderr"`
	Duration time.Duration     `json:"duration"`
	Language Language          `json:"language"`
	Command  string            `json:"command"`
	Error    error             `json:"error,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Files    map[string]string `json:"files,omitempty"` // Created/modified files
}

// PackageInstallRequest contains package installation parameters
type PackageInstallRequest struct {
	Packages    []string          `json:"packages"`
	Language    Language          `json:"language"`
	WorkingDir  string            `json:"working_dir"`
	Environment map[string]string `json:"environment"`
	Options     map[string]string `json:"options,omitempty"`
}

// PackageInstallResult contains the result of package installation
type PackageInstallResult struct {
	Success           bool          `json:"success"`
	InstalledPackages []string      `json:"installed_packages"`
	FailedPackages    []string      `json:"failed_packages"`
	Output            string        `json:"output"`
	Error             error         `json:"error,omitempty"`
	Duration          time.Duration `json:"duration"`
}

// EnvironmentSetupRequest contains environment setup parameters
type EnvironmentSetupRequest struct {
	Language   Language          `json:"language"`
	WorkingDir string            `json:"working_dir"`
	Version    string            `json:"version,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
}

// EnvironmentSetupResult contains the result of environment setup
type EnvironmentSetupResult struct {
	Success     bool              `json:"success"`
	Version     string            `json:"version"`
	Path        string            `json:"path"`
	Environment map[string]string `json:"environment"`
	Output      string            `json:"output"`
	Error       error             `json:"error,omitempty"`
}

// LanguageHandler defines the interface for language-specific handlers
type LanguageHandler interface {
	// GetLanguage returns the language this handler supports
	GetLanguage() Language

	// GetSupportedExtensions returns file extensions supported by this language
	GetSupportedExtensions() []string

	// GetDefaultImage returns the default container image for this language
	GetDefaultImage() string

	// GetImageVersions returns available image versions
	GetImageVersions() []string

	// DetectLanguage checks if the given code/file matches this language
	DetectLanguage(code string, filename string) float64 // Returns confidence score 0-1

	// PrepareExecution prepares the code for execution (e.g., create temp files)
	PrepareExecution(ctx context.Context, req *ExecutionRequest) error

	// Execute runs the code and returns the result
	Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error)

	// InstallPackages installs the specified packages
	InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error)

	// SetupEnvironment sets up the language environment
	SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error)

	// GetPackageManager returns the package manager for this language
	GetPackageManager() string

	// GetRequiredFiles returns files that need to be created for execution
	GetRequiredFiles(req *ExecutionRequest) map[string]string

	// Cleanup performs any necessary cleanup after execution
	Cleanup(ctx context.Context, req *ExecutionRequest) error

	// GetDefaultTimeout returns the default timeout for this language
	GetDefaultTimeout() time.Duration

	// IsCompiled returns true if this is a compiled language
	IsCompiled() bool

	// GetCompileCommand returns the compile command for compiled languages
	GetCompileCommand(req *ExecutionRequest) string

	// GetRunCommand returns the run command
	GetRunCommand(req *ExecutionRequest) string

	// ValidateCode performs basic syntax validation if possible
	ValidateCode(code string) error
}

// BaseHandler provides common functionality for language handlers
type BaseHandler struct {
	language       Language
	extensions     []string
	defaultImage   string
	imageVersions  []string
	packageManager string
	defaultTimeout time.Duration
	compiled       bool
}

// NewBaseHandler creates a new base handler
func NewBaseHandler(
	language Language,
	extensions []string,
	defaultImage string,
	imageVersions []string,
	packageManager string,
	defaultTimeout time.Duration,
	compiled bool,
) *BaseHandler {
	return &BaseHandler{
		language:       language,
		extensions:     extensions,
		defaultImage:   defaultImage,
		imageVersions:  imageVersions,
		packageManager: packageManager,
		defaultTimeout: defaultTimeout,
		compiled:       compiled,
	}
}

// GetLanguage returns the language
func (h *BaseHandler) GetLanguage() Language {
	return h.language
}

// GetSupportedExtensions returns supported extensions
func (h *BaseHandler) GetSupportedExtensions() []string {
	return h.extensions
}

// GetDefaultImage returns the default image
func (h *BaseHandler) GetDefaultImage() string {
	return h.defaultImage
}

// GetImageVersions returns image versions
func (h *BaseHandler) GetImageVersions() []string {
	return h.imageVersions
}

// GetPackageManager returns the package manager
func (h *BaseHandler) GetPackageManager() string {
	return h.packageManager
}

// GetDefaultTimeout returns the default timeout
func (h *BaseHandler) GetDefaultTimeout() time.Duration {
	return h.defaultTimeout
}

// IsCompiled returns if the language is compiled
func (h *BaseHandler) IsCompiled() bool {
	return h.compiled
}

// ValidateCode provides basic validation (override in specific handlers)
func (h *BaseHandler) ValidateCode(code string) error {
	if code == "" {
		return NewLanguageError("empty code provided", h.language, "validation")
	}
	return nil
}

// Cleanup provides basic cleanup (override in specific handlers)
func (h *BaseHandler) Cleanup(ctx context.Context, req *ExecutionRequest) error {
	// Default implementation does nothing
	return nil
}
