package executors

import (
	"context"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/types"
)

// ExecutionOptions contains options for code execution
type ExecutionOptions struct {
	Timeout          time.Duration     `json:"timeout"`
	WorkingDir       string            `json:"working_dir"`
	Environment      map[string]string `json:"environment"`
	Packages         []string          `json:"packages"`
	Files            map[string]string `json:"files"`
	Stdin            string            `json:"stdin"`
	CompileFlags     []string          `json:"compile_flags,omitempty"`
	RuntimeFlags     []string          `json:"runtime_flags,omitempty"`
	UseVirtualEnv    bool              `json:"use_virtual_env,omitempty"`
	BuildMode        string            `json:"build_mode,omitempty"` // debug, release, etc.
	Framework        string            `json:"framework,omitempty"`   // for .NET, etc.
	PackageManager   string            `json:"package_manager,omitempty"`
	CustomConfig     map[string]string `json:"custom_config,omitempty"`
}

// ExecutionResult contains the result of code execution
type ExecutionResult struct {
	ExitCode         int               `json:"exit_code"`
	Stdout           string            `json:"stdout"`
	Stderr           string            `json:"stderr"`
	Duration         time.Duration     `json:"duration"`
	Language         types.Language `json:"language"`
	Commands         []string          `json:"commands"`
	Error            error             `json:"error,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
	CreatedFiles     []string          `json:"created_files,omitempty"`
	ModifiedFiles    []string          `json:"modified_files,omitempty"`
	CompilationTime  time.Duration     `json:"compilation_time,omitempty"`
	ExecutionTime    time.Duration     `json:"execution_time,omitempty"`
	MemoryUsage      int64             `json:"memory_usage,omitempty"`
	CPUUsage         float64           `json:"cpu_usage,omitempty"`
}

// PackageInfo contains package installation information
type PackageInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Repository  string `json:"repository,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
}

// PackageInstallResult contains the result of package installation
type PackageInstallResult struct {
	Success           bool          `json:"success"`
	InstalledPackages []PackageInfo `json:"installed_packages"`
	FailedPackages    []string      `json:"failed_packages"`
	Output            string        `json:"output"`
	Error             error         `json:"error,omitempty"`
	Duration          time.Duration `json:"duration"`
	CachePath         string        `json:"cache_path,omitempty"`
}

// EnvironmentInfo contains information about the execution environment
type EnvironmentInfo struct {
	Language       types.Language `json:"language"`
	Version        string             `json:"version"`
	Interpreter    string             `json:"interpreter"`
	PackageManager string             `json:"package_manager"`
	VirtualEnvPath string             `json:"virtual_env_path,omitempty"`
	WorkingDir     string             `json:"working_dir"`
	ConfigFiles    []string           `json:"config_files,omitempty"`
	SystemInfo     map[string]string  `json:"system_info,omitempty"`
}

// Executor defines the interface for language-specific code execution
type Executor interface {
	// GetLanguage returns the language this executor supports
	GetLanguage() types.Language

	// GetVersion returns the version of the language runtime
	GetVersion(ctx context.Context) (string, error)

	// SetupEnvironment prepares the execution environment
	SetupEnvironment(ctx context.Context, options *ExecutionOptions) (*EnvironmentInfo, error)

	// InstallPackages installs the specified packages
	InstallPackages(ctx context.Context, packages []string, options *ExecutionOptions) (*PackageInstallResult, error)

	// ValidateCode performs syntax and basic validation
	ValidateCode(ctx context.Context, code string, options *ExecutionOptions) error

	// PrepareFiles creates necessary files for execution
	PrepareFiles(ctx context.Context, code string, options *ExecutionOptions) (map[string]string, error)

	// Compile compiles the code if needed (for compiled languages)
	Compile(ctx context.Context, code string, options *ExecutionOptions) (*CompilationResult, error)

	// Execute runs the code and returns the result
	Execute(ctx context.Context, code string, options *ExecutionOptions) (*ExecutionResult, error)

	// Cleanup performs any necessary cleanup after execution
	Cleanup(ctx context.Context, options *ExecutionOptions) error

	// GetDefaultOptions returns default execution options for this language
	GetDefaultOptions() *ExecutionOptions

	// IsCompiled returns true if this is a compiled language
	IsCompiled() bool

	// GetSupportedPackageManagers returns supported package managers
	GetSupportedPackageManagers() []string

	// GetMetrics returns execution metrics and performance data
	GetMetrics(ctx context.Context) (map[string]interface{}, error)
}

// CompilationResult contains the result of code compilation
type CompilationResult struct {
	Success        bool          `json:"success"`
	Output         string        `json:"output"`
	Error          error         `json:"error,omitempty"`
	Duration       time.Duration `json:"duration"`
	ExecutablePath string        `json:"executable_path,omitempty"`
	ArtifactPaths  []string      `json:"artifact_paths,omitempty"`
	Warnings       []string      `json:"warnings,omitempty"`
	CacheKey       string        `json:"cache_key,omitempty"`
	CacheHit       bool          `json:"cache_hit"`
}

// BaseExecutor provides common functionality for all executors
type BaseExecutor struct {
	language         types.Language
	defaultTimeout   time.Duration
	supportedPackageManagers []string
	isCompiled       bool
	workingDir       string
	metrics          map[string]interface{}
}

// NewBaseExecutor creates a new base executor
func NewBaseExecutor(
	language types.Language,
	defaultTimeout time.Duration,
	packageManagers []string,
	isCompiled bool,
) *BaseExecutor {
	return &BaseExecutor{
		language:         language,
		defaultTimeout:   defaultTimeout,
		supportedPackageManagers: packageManagers,
		isCompiled:       isCompiled,
		metrics:          make(map[string]interface{}),
	}
}

// GetLanguage returns the supported language
func (e *BaseExecutor) GetLanguage() types.Language {
	return e.language
}

// IsCompiled returns if this is a compiled language
func (e *BaseExecutor) IsCompiled() bool {
	return e.isCompiled
}

// GetSupportedPackageManagers returns supported package managers
func (e *BaseExecutor) GetSupportedPackageManagers() []string {
	return e.supportedPackageManagers
}

// GetDefaultOptions returns default execution options
func (e *BaseExecutor) GetDefaultOptions() *ExecutionOptions {
	return &ExecutionOptions{
		Timeout:     e.defaultTimeout,
		WorkingDir:  "/workspace",
		Environment: make(map[string]string),
		Packages:    []string{},
		Files:       make(map[string]string),
		BuildMode:   "debug",
	}
}

// GetMetrics returns execution metrics
func (e *BaseExecutor) GetMetrics(ctx context.Context) (map[string]interface{}, error) {
	return e.metrics, nil
}

// UpdateMetrics updates the metrics with new data
func (e *BaseExecutor) UpdateMetrics(key string, value interface{}) {
	if e.metrics == nil {
		e.metrics = make(map[string]interface{})
	}
	e.metrics[key] = value
}

// Cleanup provides default cleanup (can be overridden)
func (e *BaseExecutor) Cleanup(ctx context.Context, options *ExecutionOptions) error {
	// Default cleanup does nothing
	return nil
}