// Package go_lang provides comprehensive Go language support for the SandboxRunner.
// It includes module management, building, testing, and static analysis capabilities.
package go_lang

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// GoLanguageSupport provides a unified interface for all Go language operations
type GoLanguageSupport struct {
	workingDir      string
	moduleManager   *ModuleManager
	builder         *Builder
	testRunner      *TestRunner
	analyzer        *Analyzer
	initialized     bool
	defaultTimeout  time.Duration
}

// GoOperationResult represents the result of any Go operation
type GoOperationResult struct {
	Success      bool                   `json:"success"`
	Duration     time.Duration          `json:"duration"`
	Operation    string                 `json:"operation"`
	Output       string                 `json:"output"`
	Error        error                  `json:"error,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Files        []string               `json:"files,omitempty"`
	BinaryPath   string                 `json:"binary_path,omitempty"`
	CoverageFile string                 `json:"coverage_file,omitempty"`
}

// GoProjectConfig represents configuration for a Go project
type GoProjectConfig struct {
	ModulePath      string                 `json:"module_path"`
	GoVersion       string                 `json:"go_version"`
	Dependencies    []string               `json:"dependencies"`
	BuildConfig     *BuildConfig           `json:"build_config,omitempty"`
	TestConfig      *TestConfig            `json:"test_config,omitempty"`
	AnalysisConfig  *AnalysisConfig        `json:"analysis_config,omitempty"`
	Environment     map[string]string      `json:"environment"`
	Timeout         time.Duration          `json:"timeout"`
	EnableCoverage  bool                   `json:"enable_coverage"`
	EnableProfiling bool                   `json:"enable_profiling"`
	CacheEnabled    bool                   `json:"cache_enabled"`
}

// NewGoLanguageSupport creates a new Go language support instance
func NewGoLanguageSupport(workingDir string) *GoLanguageSupport {
	return &GoLanguageSupport{
		workingDir:     workingDir,
		moduleManager:  NewModuleManager(workingDir),
		builder:        NewBuilder(workingDir),
		testRunner:     NewTestRunner(workingDir),
		analyzer:       NewAnalyzer(workingDir),
		initialized:    false,
		defaultTimeout: 10 * time.Minute,
	}
}

// Initialize sets up the Go project with the given configuration
func (gls *GoLanguageSupport) Initialize(ctx context.Context, config *GoProjectConfig) (*GoOperationResult, error) {
	startTime := time.Now()
	
	log.Debug().
		Str("working_dir", gls.workingDir).
		Str("module_path", config.ModulePath).
		Msg("Initializing Go project")

	result := &GoOperationResult{
		Operation: "initialize",
		Metadata:  make(map[string]interface{}),
	}

	// Initialize Go module
	if err := gls.moduleManager.InitializeModule(ctx, config.ModulePath); err != nil {
		result.Success = false
		result.Error = fmt.Errorf("failed to initialize module: %w", err)
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	// Install dependencies
	if len(config.Dependencies) > 0 {
		for _, dep := range config.Dependencies {
			if err := gls.moduleManager.AddDependency(ctx, dep, "latest"); err != nil {
				log.Warn().Err(err).Str("dependency", dep).Msg("Failed to add dependency")
			}
		}
	}

	// Configure components
	if config.BuildConfig != nil {
		gls.builder.SetConfig(config.BuildConfig)
	}

	if config.TestConfig != nil {
		gls.testRunner.SetConfig(config.TestConfig)
	}

	if config.AnalysisConfig != nil {
		gls.analyzer.SetConfig(config.AnalysisConfig)
	}

	// Configure coverage if enabled
	if config.EnableCoverage {
		gls.testRunner.EnableCoverage("set", "coverage.out")
	}

	// Configure profiling if enabled
	if config.EnableProfiling {
		gls.testRunner.EnableProfiling("cpu.prof", "mem.prof", "block.prof", "mutex.prof", "trace.out")
	}

	// Enable/disable cache
	gls.builder.EnableCache(config.CacheEnabled)

	gls.initialized = true
	result.Success = true
	result.Duration = time.Since(startTime)
	result.Output = "Go project initialized successfully"
	result.Metadata["module_path"] = config.ModulePath
	result.Metadata["dependencies_count"] = len(config.Dependencies)

	log.Debug().
		Dur("duration", result.Duration).
		Msg("Go project initialization completed")

	return result, nil
}

// Build compiles the Go project
func (gls *GoLanguageSupport) Build(ctx context.Context) (*GoOperationResult, error) {
	startTime := time.Now()
	
	log.Debug().Str("working_dir", gls.workingDir).Msg("Building Go project")

	result := &GoOperationResult{
		Operation: "build",
		Metadata:  make(map[string]interface{}),
	}

	if !gls.initialized {
		result.Success = false
		result.Error = fmt.Errorf("Go project not initialized")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	buildResult, err := gls.builder.Build(ctx)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("build failed: %w", err)
		result.Output = buildResult.BuildOutput
		return result, result.Error
	}

	result.Success = buildResult.Success
	result.Output = buildResult.BuildOutput
	result.BinaryPath = buildResult.OutputPath
	result.Metadata["binary_size"] = buildResult.BinarySize
	result.Metadata["build_duration"] = buildResult.Duration
	result.Metadata["targets_built"] = len(buildResult.Targets)
	
	if len(buildResult.Errors) > 0 {
		result.Metadata["build_errors"] = buildResult.Errors
	}

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Str("binary_path", result.BinaryPath).
		Msg("Go project build completed")

	return result, nil
}

// Test runs tests for the Go project
func (gls *GoLanguageSupport) Test(ctx context.Context) (*GoOperationResult, error) {
	startTime := time.Now()
	
	log.Debug().Str("working_dir", gls.workingDir).Msg("Running Go tests")

	result := &GoOperationResult{
		Operation: "test",
		Metadata:  make(map[string]interface{}),
	}

	if !gls.initialized {
		result.Success = false
		result.Error = fmt.Errorf("Go project not initialized")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	testResult, err := gls.testRunner.RunTests(ctx)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("tests failed: %w", err)
		result.Output = testResult.Output
		return result, result.Error
	}

	result.Success = testResult.Success
	result.Output = testResult.Output
	result.Metadata["test_summary"] = testResult.Summary
	result.Metadata["test_duration"] = testResult.Duration
	
	if testResult.Coverage != nil {
		result.CoverageFile = testResult.Coverage.ProfileFile
		result.Metadata["coverage_percentage"] = testResult.Coverage.Percentage
	}
	
	if len(testResult.ProfileFiles) > 0 {
		result.Metadata["profile_files"] = testResult.ProfileFiles
	}
	
	if len(testResult.FailedTests) > 0 {
		result.Metadata["failed_tests"] = testResult.FailedTests
	}

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Int("total_tests", testResult.Summary.TotalTests).
		Int("passed_tests", testResult.Summary.PassedTests).
		Int("failed_tests", testResult.Summary.FailedTests).
		Msg("Go tests completed")

	return result, nil
}

// Analyze performs static analysis on the Go project
func (gls *GoLanguageSupport) Analyze(ctx context.Context) (*GoOperationResult, error) {
	startTime := time.Now()
	
	log.Debug().Str("working_dir", gls.workingDir).Msg("Analyzing Go project")

	result := &GoOperationResult{
		Operation: "analyze",
		Metadata:  make(map[string]interface{}),
	}

	if !gls.initialized {
		result.Success = false
		result.Error = fmt.Errorf("Go project not initialized")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	analysisResult, err := gls.analyzer.Analyze(ctx)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("analysis failed: %w", err)
		if analysisResult != nil {
			result.Output = fmt.Sprintf("Analysis errors: %v", analysisResult.Errors)
		}
		return result, result.Error
	}

	result.Success = analysisResult.Success
	result.Metadata["analysis_summary"] = analysisResult.Summary
	result.Metadata["analysis_duration"] = analysisResult.Duration
	
	if len(analysisResult.VetResults) > 0 {
		result.Metadata["vet_issues"] = analysisResult.VetResults
	}
	
	if len(analysisResult.StaticResults) > 0 {
		result.Metadata["static_issues"] = analysisResult.StaticResults
	}
	
	if len(analysisResult.LintResults) > 0 {
		result.Metadata["lint_issues"] = analysisResult.LintResults
	}
	
	if len(analysisResult.Errors) > 0 {
		result.Metadata["analysis_errors"] = analysisResult.Errors
	}

	// Generate summary output
	summary := analysisResult.Summary
	result.Output = fmt.Sprintf("Analysis completed: %d total issues (%d critical, %d warning, %d info)",
		summary.TotalIssues, summary.CriticalIssues, summary.WarningIssues, summary.InfoIssues)

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Int("total_issues", summary.TotalIssues).
		Int("vet_issues", summary.VetIssues).
		Int("static_issues", summary.StaticIssues).
		Int("lint_issues", summary.LintIssues).
		Msg("Go analysis completed")

	return result, nil
}

// CrossCompile builds the project for multiple platforms
func (gls *GoLanguageSupport) CrossCompile(ctx context.Context, platforms []string) (*GoOperationResult, error) {
	startTime := time.Now()
	
	log.Debug().
		Str("working_dir", gls.workingDir).
		Strs("platforms", platforms).
		Msg("Cross-compiling Go project")

	result := &GoOperationResult{
		Operation: "cross_compile",
		Metadata:  make(map[string]interface{}),
		Files:     []string{},
	}

	if !gls.initialized {
		result.Success = false
		result.Error = fmt.Errorf("Go project not initialized")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	buildResult, err := gls.builder.CrossCompile(ctx, platforms)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("cross-compilation failed: %w", err)
		result.Output = buildResult.BuildOutput
		return result, result.Error
	}

	result.Success = buildResult.Success
	result.Output = buildResult.BuildOutput
	result.Metadata["build_duration"] = buildResult.Duration
	result.Metadata["platforms"] = platforms
	result.Metadata["targets_built"] = len(buildResult.Targets)
	
	// Collect output files
	for _, target := range buildResult.Targets {
		result.Files = append(result.Files, target.Output)
	}
	
	if len(buildResult.Errors) > 0 {
		result.Metadata["build_errors"] = buildResult.Errors
	}

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Int("platforms_built", len(platforms)).
		Msg("Cross-compilation completed")

	return result, nil
}

// RunBenchmarks executes benchmark tests
func (gls *GoLanguageSupport) RunBenchmarks(ctx context.Context, pattern string) (*GoOperationResult, error) {
	startTime := time.Now()
	
	log.Debug().
		Str("working_dir", gls.workingDir).
		Str("pattern", pattern).
		Msg("Running Go benchmarks")

	result := &GoOperationResult{
		Operation: "benchmark",
		Metadata:  make(map[string]interface{}),
	}

	if !gls.initialized {
		result.Success = false
		result.Error = fmt.Errorf("Go project not initialized")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	benchResult, err := gls.testRunner.RunBenchmarks(ctx, pattern)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("benchmarks failed: %w", err)
		result.Output = benchResult.Output
		return result, result.Error
	}

	result.Success = benchResult.Success
	result.Output = benchResult.Output
	result.Metadata["benchmark_duration"] = benchResult.Duration
	result.Metadata["benchmarks"] = benchResult.Benchmarks
	result.Metadata["total_benchmarks"] = len(benchResult.Benchmarks)

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Int("benchmarks_run", len(benchResult.Benchmarks)).
		Msg("Benchmarks completed")

	return result, nil
}

// Clean removes build artifacts and caches
func (gls *GoLanguageSupport) Clean(ctx context.Context) (*GoOperationResult, error) {
	startTime := time.Now()
	
	log.Debug().Str("working_dir", gls.workingDir).Msg("Cleaning Go project")

	result := &GoOperationResult{
		Operation: "clean",
		Metadata:  make(map[string]interface{}),
	}

	if !gls.initialized {
		result.Success = false
		result.Error = fmt.Errorf("Go project not initialized")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	err := gls.builder.Clean(ctx)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("clean failed: %w", err)
		return result, result.Error
	}

	result.Success = true
	result.Output = "Project cleaned successfully"

	log.Debug().
		Dur("duration", result.Duration).
		Msg("Go project clean completed")

	return result, nil
}

// GetProjectInfo returns information about the Go project
func (gls *GoLanguageSupport) GetProjectInfo(ctx context.Context) (*GoOperationResult, error) {
	startTime := time.Now()
	
	result := &GoOperationResult{
		Operation: "project_info",
		Metadata:  make(map[string]interface{}),
	}

	if !gls.initialized {
		result.Success = false
		result.Error = fmt.Errorf("Go project not initialized")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	// Get module info
	moduleInfo, err := gls.moduleManager.GetModuleInfo(ctx)
	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("failed to get module info: %w", err)
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	// Get dependencies
	deps, err := gls.moduleManager.ListDependencies(ctx, false)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to list dependencies")
		deps = []*ModuleInfo{}
	}

	// Get module configuration
	config, err := gls.moduleManager.GetModuleConfig(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get module config")
	}

	result.Success = true
	result.Duration = time.Since(startTime)
	result.Metadata["module_info"] = moduleInfo
	result.Metadata["dependencies"] = deps
	result.Metadata["dependency_count"] = len(deps)
	
	if config != nil {
		result.Metadata["module_config"] = config
	}

	result.Output = fmt.Sprintf("Module: %s, Dependencies: %d", moduleInfo.Path, len(deps))

	return result, nil
}

// FullWorkflow runs a complete development workflow (analyze, test, build)
func (gls *GoLanguageSupport) FullWorkflow(ctx context.Context) (*GoOperationResult, error) {
	startTime := time.Now()
	
	log.Debug().Str("working_dir", gls.workingDir).Msg("Running full Go workflow")

	result := &GoOperationResult{
		Operation: "full_workflow",
		Metadata:  make(map[string]interface{}),
	}

	if !gls.initialized {
		result.Success = false
		result.Error = fmt.Errorf("Go project not initialized")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}

	workflow := make(map[string]interface{})
	var overallSuccess = true
	var outputs []string

	// Step 1: Analysis
	log.Debug().Msg("Running analysis step")
	analysisResult, err := gls.Analyze(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Analysis step failed")
		overallSuccess = false
	}
	workflow["analysis"] = map[string]interface{}{
		"success":  analysisResult.Success,
		"duration": analysisResult.Duration,
		"summary":  analysisResult.Metadata["analysis_summary"],
	}
	outputs = append(outputs, fmt.Sprintf("Analysis: %s", analysisResult.Output))

	// Step 2: Testing
	log.Debug().Msg("Running testing step")
	testResult, err := gls.Test(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Testing step failed")
		overallSuccess = false
	}
	workflow["testing"] = map[string]interface{}{
		"success":  testResult.Success,
		"duration": testResult.Duration,
		"summary":  testResult.Metadata["test_summary"],
	}
	outputs = append(outputs, fmt.Sprintf("Testing: %s", testResult.Output))

	// Step 3: Building (only if tests pass)
	if testResult.Success {
		log.Debug().Msg("Running build step")
		buildResult, err := gls.Build(ctx)
		if err != nil {
			log.Warn().Err(err).Msg("Build step failed")
			overallSuccess = false
		}
		workflow["building"] = map[string]interface{}{
			"success":     buildResult.Success,
			"duration":    buildResult.Duration,
			"binary_path": buildResult.BinaryPath,
			"binary_size": buildResult.Metadata["binary_size"],
		}
		outputs = append(outputs, fmt.Sprintf("Building: %s", buildResult.Output))
		
		if buildResult.BinaryPath != "" {
			result.BinaryPath = buildResult.BinaryPath
		}
	} else {
		log.Debug().Msg("Skipping build step due to test failures")
		workflow["building"] = map[string]interface{}{
			"success": false,
			"skipped": true,
			"reason":  "tests failed",
		}
		outputs = append(outputs, "Building: Skipped due to test failures")
		overallSuccess = false
	}

	result.Success = overallSuccess
	result.Duration = time.Since(startTime)
	result.Metadata["workflow"] = workflow
	result.Output = fmt.Sprintf("Workflow completed. Steps: %s", outputs)

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Msg("Full workflow completed")

	return result, nil
}

// ValidateProject validates the Go project structure and configuration
func (gls *GoLanguageSupport) ValidateProject(ctx context.Context) (*GoOperationResult, error) {
	startTime := time.Now()
	
	result := &GoOperationResult{
		Operation: "validate",
		Metadata:  make(map[string]interface{}),
	}

	validationIssues := []string{}
	validationSuccess := true

	// Validate module
	if err := gls.moduleManager.ValidateModule(ctx); err != nil {
		validationIssues = append(validationIssues, fmt.Sprintf("Module validation failed: %v", err))
		validationSuccess = false
	}

	// Validate build configuration
	if err := gls.builder.ValidateConfig(); err != nil {
		validationIssues = append(validationIssues, fmt.Sprintf("Build config validation failed: %v", err))
		validationSuccess = false
	}

	// Validate test configuration
	if err := gls.testRunner.ValidateConfig(); err != nil {
		validationIssues = append(validationIssues, fmt.Sprintf("Test config validation failed: %v", err))
		validationSuccess = false
	}

	// Validate analysis configuration
	if err := gls.analyzer.ValidateConfig(); err != nil {
		validationIssues = append(validationIssues, fmt.Sprintf("Analysis config validation failed: %v", err))
		validationSuccess = false
	}

	result.Success = validationSuccess
	result.Duration = time.Since(startTime)
	result.Metadata["validation_issues"] = validationIssues
	result.Metadata["issues_count"] = len(validationIssues)

	if validationSuccess {
		result.Output = "Project validation passed"
	} else {
		result.Output = fmt.Sprintf("Project validation failed with %d issues", len(validationIssues))
		result.Error = fmt.Errorf("validation failed")
	}

	return result, nil
}

// GetDefaultProjectConfig returns a default project configuration
func GetDefaultProjectConfig(modulePath string) *GoProjectConfig {
	return &GoProjectConfig{
		ModulePath:      modulePath,
		GoVersion:       "1.21",
		Dependencies:    []string{},
		BuildConfig:     NewDefaultBuildConfig(),
		TestConfig:      NewDefaultTestConfig(),
		AnalysisConfig:  NewDefaultAnalysisConfig(),
		Environment:     make(map[string]string),
		Timeout:         10 * time.Minute,
		EnableCoverage:  true,
		EnableProfiling: false,
		CacheEnabled:    true,
	}
}

// CreateProjectWithDefaults creates a new Go project with default configuration
func CreateProjectWithDefaults(workingDir, modulePath string) (*GoLanguageSupport, error) {
	gls := NewGoLanguageSupport(workingDir)
	config := GetDefaultProjectConfig(modulePath)
	
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()
	
	result, err := gls.Initialize(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize project: %w", err)
	}
	
	if !result.Success {
		return nil, fmt.Errorf("project initialization failed: %v", result.Error)
	}
	
	return gls, nil
}