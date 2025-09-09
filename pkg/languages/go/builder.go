package go_lang

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// BuildTarget represents a build target configuration
type BuildTarget struct {
	GOOS     string            `json:"goos"`
	GOARCH   string            `json:"goarch"`
	CGO      bool              `json:"cgo"`
	Tags     []string          `json:"tags"`
	LDFlags  []string          `json:"ldflags"`
	GCFlags  []string          `json:"gcflags"`
	ASMFlags []string          `json:"asmflags"`
	Output   string            `json:"output"`
	Env      map[string]string `json:"env"`
}

// BuildConfig represents the build configuration
type BuildConfig struct {
	Targets         []BuildTarget `json:"targets"`
	Verbose         bool          `json:"verbose"`
	Race            bool          `json:"race"`
	Work            bool          `json:"work"`
	Trimpath        bool          `json:"trimpath"`
	ModReadonly     bool          `json:"mod_readonly"`
	ModDownload     bool          `json:"mod_download"`
	BuildMode       string        `json:"build_mode"`      // default, archive, c-archive, c-shared, shared, plugin
	Compiler        string        `json:"compiler"`        // gc, gccgo
	Installsuffix   string        `json:"installsuffix"`
	LinkShared      bool          `json:"linkshared"`
	MSan            bool          `json:"msan"`
	ASan            bool          `json:"asan"`
	Cover           bool          `json:"cover"`
	CoverMode       string        `json:"covermode"`       // set, count, atomic
	CoverPkg        []string      `json:"coverpkg"`
	PGO             string        `json:"pgo"`             // Profile-guided optimization file
	OptimizeLevel   string        `json:"optimize_level"`  // -N (disable), -l (disable inlining)
	DebugInfo       bool          `json:"debug_info"`
	Parallel        int           `json:"parallel"`        // Number of parallel builds
	TimeStamps      bool          `json:"timestamps"`
	X               []string      `json:"x"`               // Additional build flags
}

// BuildResult represents the result of a build operation
type BuildResult struct {
	Success     bool              `json:"success"`
	Duration    time.Duration     `json:"duration"`
	OutputPath  string            `json:"output_path"`
	Targets     []BuildTarget     `json:"targets"`
	Errors      []string          `json:"errors"`
	Warnings    []string          `json:"warnings"`
	BuildOutput string            `json:"build_output"`
	BinarySize  int64             `json:"binary_size"`
	BuildInfo   map[string]string `json:"build_info"`
	WorkDir     string            `json:"work_dir,omitempty"`
}

// CrossCompileTarget represents common cross-compilation targets
var CrossCompileTargets = map[string]BuildTarget{
	"linux-amd64": {
		GOOS:   "linux",
		GOARCH: "amd64",
		CGO:    false,
		Output: "app-linux-amd64",
	},
	"linux-arm64": {
		GOOS:   "linux",
		GOARCH: "arm64",
		CGO:    false,
		Output: "app-linux-arm64",
	},
	"windows-amd64": {
		GOOS:   "windows",
		GOARCH: "amd64",
		CGO:    false,
		Output: "app-windows-amd64.exe",
	},
	"darwin-amd64": {
		GOOS:   "darwin",
		GOARCH: "amd64",
		CGO:    false,
		Output: "app-darwin-amd64",
	},
	"darwin-arm64": {
		GOOS:   "darwin",
		GOARCH: "arm64",
		CGO:    false,
		Output: "app-darwin-arm64",
	},
	"freebsd-amd64": {
		GOOS:   "freebsd",
		GOARCH: "amd64",
		CGO:    false,
		Output: "app-freebsd-amd64",
	},
	"netbsd-amd64": {
		GOOS:   "netbsd",
		GOARCH: "amd64",
		CGO:    false,
		Output: "app-netbsd-amd64",
	},
	"openbsd-amd64": {
		GOOS:   "openbsd",
		GOARCH: "amd64",
		CGO:    false,
		Output: "app-openbsd-amd64",
	},
}

// Builder handles Go build operations
type Builder struct {
	workingDir  string
	config      *BuildConfig
	cacheDir    string
	enableCache bool
	verbose     bool
}

// NewBuilder creates a new Go builder
func NewBuilder(workingDir string) *Builder {
	return &Builder{
		workingDir:  workingDir,
		config:      NewDefaultBuildConfig(),
		enableCache: true,
		verbose:     false,
	}
}

// NewDefaultBuildConfig creates a default build configuration
func NewDefaultBuildConfig() *BuildConfig {
	return &BuildConfig{
		Targets: []BuildTarget{
			{
				GOOS:   runtime.GOOS,
				GOARCH: runtime.GOARCH,
				CGO:    true,
				Output: "app",
			},
		},
		Verbose:       false,
		Race:          false,
		Work:          false,
		Trimpath:      true,
		ModReadonly:   false,
		ModDownload:   true,
		BuildMode:     "default",
		Compiler:      "gc",
		DebugInfo:     true,
		Parallel:      runtime.NumCPU(),
		TimeStamps:    false,
		OptimizeLevel: "",
	}
}

// SetConfig sets the build configuration
func (b *Builder) SetConfig(config *BuildConfig) {
	b.config = config
}

// SetCacheDir sets the build cache directory
func (b *Builder) SetCacheDir(dir string) {
	b.cacheDir = dir
}

// EnableCache enables or disables build caching
func (b *Builder) EnableCache(enable bool) {
	b.enableCache = enable
}

// SetVerbose enables verbose output
func (b *Builder) SetVerbose(verbose bool) {
	b.verbose = verbose
}

// Build builds the Go application with the configured settings
func (b *Builder) Build(ctx context.Context) (*BuildResult, error) {
	startTime := time.Now()
	
	result := &BuildResult{
		Targets:   b.config.Targets,
		BuildInfo: make(map[string]string),
	}

	log.Debug().
		Str("working_dir", b.workingDir).
		Int("targets", len(b.config.Targets)).
		Msg("Starting Go build")

	// Build each target
	for i, target := range b.config.Targets {
		log.Debug().
			Str("goos", target.GOOS).
			Str("goarch", target.GOARCH).
			Str("output", target.Output).
			Msg("Building target")

		if err := b.buildTarget(ctx, &target, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Target %d failed: %v", i, err))
			result.Success = false
			result.Duration = time.Since(startTime)
			return result, err
		}
	}

	result.Duration = time.Since(startTime)
	result.Success = len(result.Errors) == 0

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Msg("Build completed")

	return result, nil
}

// BuildSingle builds a single target
func (b *Builder) BuildSingle(ctx context.Context, target BuildTarget) (*BuildResult, error) {
	oldTargets := b.config.Targets
	b.config.Targets = []BuildTarget{target}
	
	result, err := b.Build(ctx)
	
	b.config.Targets = oldTargets
	return result, err
}

// CrossCompile builds for multiple platforms
func (b *Builder) CrossCompile(ctx context.Context, platforms []string) (*BuildResult, error) {
	var targets []BuildTarget
	
	for _, platform := range platforms {
		if target, exists := CrossCompileTargets[platform]; exists {
			targets = append(targets, target)
		} else {
			return nil, fmt.Errorf("unknown cross-compile target: %s", platform)
		}
	}

	oldTargets := b.config.Targets
	b.config.Targets = targets
	
	result, err := b.Build(ctx)
	
	b.config.Targets = oldTargets
	return result, err
}

// BuildWithOptimization builds with specific optimization settings
func (b *Builder) BuildWithOptimization(ctx context.Context, level string, stripDebug bool) (*BuildResult, error) {
	// Save original config
	oldOptimizeLevel := b.config.OptimizeLevel
	oldDebugInfo := b.config.DebugInfo
	oldLDFlags := make([][]string, len(b.config.Targets))
	
	for i, target := range b.config.Targets {
		oldLDFlags[i] = make([]string, len(target.LDFlags))
		copy(oldLDFlags[i], target.LDFlags)
	}

	// Apply optimization settings
	b.config.OptimizeLevel = level
	b.config.DebugInfo = !stripDebug

	for i := range b.config.Targets {
		if stripDebug {
			// Add flags to strip debug info and reduce binary size
			b.config.Targets[i].LDFlags = append(b.config.Targets[i].LDFlags, "-s", "-w")
		}
	}

	result, err := b.Build(ctx)

	// Restore original config
	b.config.OptimizeLevel = oldOptimizeLevel
	b.config.DebugInfo = oldDebugInfo
	for i := range b.config.Targets {
		b.config.Targets[i].LDFlags = oldLDFlags[i]
	}

	return result, err
}

// Clean cleans build artifacts
func (b *Builder) Clean(ctx context.Context) error {
	log.Debug().Str("working_dir", b.workingDir).Msg("Cleaning build artifacts")

	cmd := exec.CommandContext(ctx, "go", "clean", "-cache", "-modcache", "-testcache")
	cmd.Dir = b.workingDir
	cmd.Env = b.buildEnvironment(BuildTarget{})

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to clean: %w\nOutput: %s", err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Clean completed")
	return nil
}

// GetBuildInfo retrieves build information
func (b *Builder) GetBuildInfo(ctx context.Context) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "go", "version", "-m", ".")
	cmd.Dir = b.workingDir

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get build info: %w", err)
	}

	buildInfo := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				buildInfo[key] = value
			}
		}
	}

	return buildInfo, nil
}

// ValidateConfig validates the build configuration
func (b *Builder) ValidateConfig() error {
	if b.config == nil {
		return fmt.Errorf("build configuration is nil")
	}

	if len(b.config.Targets) == 0 {
		return fmt.Errorf("no build targets specified")
	}

	for i, target := range b.config.Targets {
		if target.GOOS == "" {
			return fmt.Errorf("target %d: GOOS not specified", i)
		}
		if target.GOARCH == "" {
			return fmt.Errorf("target %d: GOARCH not specified", i)
		}
		if target.Output == "" {
			return fmt.Errorf("target %d: output path not specified", i)
		}
	}

	// Validate build mode
	validBuildModes := []string{"default", "archive", "c-archive", "c-shared", "shared", "plugin"}
	valid := false
	for _, mode := range validBuildModes {
		if b.config.BuildMode == mode {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid build mode: %s", b.config.BuildMode)
	}

	return nil
}

// AddBuildFlag adds a build flag to all targets
func (b *Builder) AddBuildFlag(flag string) {
	for i := range b.config.Targets {
		b.config.Targets[i].LDFlags = append(b.config.Targets[i].LDFlags, flag)
	}
}

// SetBuildTag sets build tags for all targets
func (b *Builder) SetBuildTag(tags []string) {
	for i := range b.config.Targets {
		b.config.Targets[i].Tags = tags
	}
}

// EnableRaceDetection enables race detection
func (b *Builder) EnableRaceDetection(enable bool) {
	b.config.Race = enable
}

// EnableCGO enables or disables CGO for all targets
func (b *Builder) EnableCGO(enable bool) {
	for i := range b.config.Targets {
		b.config.Targets[i].CGO = enable
	}
}

// buildTarget builds a specific target
func (b *Builder) buildTarget(ctx context.Context, target *BuildTarget, result *BuildResult) error {
	args := []string{"build"}

	// Add build flags
	if b.config.Verbose || b.verbose {
		args = append(args, "-v")
	}
	
	if b.config.Race && target.GOOS == runtime.GOOS && target.GOARCH == runtime.GOARCH {
		args = append(args, "-race")
	}
	
	if b.config.Work {
		args = append(args, "-work")
	}
	
	if b.config.Trimpath {
		args = append(args, "-trimpath")
	}

	if b.config.MSan && target.GOOS == "linux" {
		args = append(args, "-msan")
	}

	if b.config.ASan && (target.GOOS == "linux" || target.GOOS == "darwin") {
		args = append(args, "-asan")
	}

	if b.config.LinkShared {
		args = append(args, "-linkshared")
	}

	// Build mode
	if b.config.BuildMode != "default" {
		args = append(args, "-buildmode", b.config.BuildMode)
	}

	// Compiler
	if b.config.Compiler != "gc" {
		args = append(args, "-compiler", b.config.Compiler)
	}

	// Install suffix
	if b.config.Installsuffix != "" {
		args = append(args, "-installsuffix", b.config.Installsuffix)
	}

	// Parallel builds
	if b.config.Parallel > 0 {
		args = append(args, "-p", fmt.Sprintf("%d", b.config.Parallel))
	}

	// Build tags
	if len(target.Tags) > 0 {
		args = append(args, "-tags", strings.Join(target.Tags, ","))
	}

	// LD flags
	if len(target.LDFlags) > 0 {
		args = append(args, "-ldflags", strings.Join(target.LDFlags, " "))
	}

	// GC flags
	if len(target.GCFlags) > 0 {
		args = append(args, "-gcflags", strings.Join(target.GCFlags, " "))
	}

	// ASM flags
	if len(target.ASMFlags) > 0 {
		args = append(args, "-asmflags", strings.Join(target.ASMFlags, " "))
	}

	// Optimization level
	if b.config.OptimizeLevel != "" {
		args = append(args, "-gcflags", b.config.OptimizeLevel)
	}

	// PGO
	if b.config.PGO != "" {
		args = append(args, "-pgo", b.config.PGO)
	}

	// Additional flags
	args = append(args, b.config.X...)

	// Output
	outputPath := filepath.Join(b.workingDir, target.Output)
	args = append(args, "-o", outputPath)

	// Add current directory as the package to build
	args = append(args, ".")

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = b.workingDir
	cmd.Env = b.buildEnvironment(*target)

	log.Debug().
		Strs("args", args).
		Str("output", outputPath).
		Msg("Executing go build")

	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	
	if b.config.Work && strings.Contains(outputStr, "WORK=") {
		// Extract work directory
		lines := strings.Split(outputStr, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "WORK=") {
				result.WorkDir = strings.TrimPrefix(line, "WORK=")
				break
			}
		}
	}

	result.BuildOutput += outputStr

	if err != nil {
		// Parse build errors and warnings
		b.parseBuildOutput(outputStr, result)
		return fmt.Errorf("build failed: %w", err)
	}

	// Get binary size
	if stat, err := os.Stat(outputPath); err == nil {
		result.BinarySize = stat.Size()
	}

	result.OutputPath = outputPath
	
	log.Debug().
		Str("output_path", outputPath).
		Int64("binary_size", result.BinarySize).
		Msg("Build target completed successfully")

	return nil
}

// buildEnvironment builds environment variables for the build
func (b *Builder) buildEnvironment(target BuildTarget) []string {
	env := os.Environ()

	// Set GOOS and GOARCH
	env = append(env, fmt.Sprintf("GOOS=%s", target.GOOS))
	env = append(env, fmt.Sprintf("GOARCH=%s", target.GOARCH))

	// Set CGO
	if target.CGO {
		env = append(env, "CGO_ENABLED=1")
	} else {
		env = append(env, "CGO_ENABLED=0")
	}

	// Module settings
	env = append(env, "GO111MODULE=on")
	
	if b.config.ModReadonly {
		env = append(env, "GOFLAGS=-mod=readonly")
	}

	// Cache settings
	if b.enableCache && b.cacheDir != "" {
		env = append(env, fmt.Sprintf("GOCACHE=%s", b.cacheDir))
	} else if !b.enableCache {
		env = append(env, "GOCACHE=off")
	}

	// Target-specific environment variables
	for key, value := range target.Env {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}

// parseBuildOutput parses build output for errors and warnings
func (b *Builder) parseBuildOutput(output string, result *BuildResult) {
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Check for errors
		if strings.Contains(line, "error:") || strings.Contains(line, "undefined:") ||
			strings.Contains(line, "cannot find package") || strings.Contains(line, "syntax error") {
			result.Errors = append(result.Errors, line)
		} else if strings.Contains(line, "warning:") || strings.Contains(line, "note:") {
			result.Warnings = append(result.Warnings, line)
		}
	}
}

// GetAvailableTargets returns all available cross-compilation targets
func GetAvailableTargets() map[string]BuildTarget {
	return CrossCompileTargets
}

// CreateBuildConfig creates a build configuration from JSON
func CreateBuildConfig(configJSON string) (*BuildConfig, error) {
	var config BuildConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return nil, fmt.Errorf("failed to parse build configuration: %w", err)
	}
	return &config, nil
}

// ExportBuildConfig exports build configuration to JSON
func (b *Builder) ExportBuildConfig() (string, error) {
	data, err := json.MarshalIndent(b.config, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to export build configuration: %w", err)
	}
	return string(data), nil
}