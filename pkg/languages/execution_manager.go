package languages

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/executors"
)

// ExecutionManager manages language execution with enhanced capabilities
type ExecutionManager struct {
	executors    map[Language]executors.Executor
	preprocessor *CodePreprocessor
	manager      *Manager // Existing language manager
	metrics      *ExecutionMetrics
	mu           sync.RWMutex
}

// ExecutionMetrics tracks execution statistics
type ExecutionMetrics struct {
	TotalExecutions      int64                     `json:"total_executions"`
	SuccessfulExecutions int64                     `json:"successful_executions"`
	FailedExecutions     int64                     `json:"failed_executions"`
	AverageExecutionTime time.Duration             `json:"average_execution_time"`
	LanguageStats        map[Language]*LanguageStat `json:"language_stats"`
	mu                   sync.RWMutex              `json:"-"`
}

// LanguageStat tracks statistics for a specific language
type LanguageStat struct {
	Executions       int64         `json:"executions"`
	SuccessCount     int64         `json:"success_count"`
	FailureCount     int64         `json:"failure_count"`
	AverageTime      time.Duration `json:"average_time"`
	TotalTime        time.Duration `json:"total_time"`
	PackageInstalls  int64         `json:"package_installs"`
	CompilationCount int64         `json:"compilation_count"`
	CacheHits        int64         `json:"cache_hits"`
}

// EnhancedExecutionRequest extends the basic execution request
type EnhancedExecutionRequest struct {
	*ExecutionRequest
	PreprocessorOptions *PreprocessorOptions           `json:"preprocessor_options,omitempty"`
	ExecutorOptions     *executors.ExecutionOptions    `json:"executor_options,omitempty"`
	UsePreprocessor     bool                           `json:"use_preprocessor,omitempty"`
	UseNewExecutors     bool                           `json:"use_new_executors,omitempty"`
	SecurityLevel       string                         `json:"security_level,omitempty"` // strict, normal, permissive
	CustomConfig        map[string]string              `json:"custom_config,omitempty"`
}

// EnhancedExecutionResult extends the basic execution result
type EnhancedExecutionResult struct {
	*ExecutionResult
	PreprocessorResult  *PreprocessorResult            `json:"preprocessor_result,omitempty"`
	ExecutorResult      *executors.ExecutionResult     `json:"executor_result,omitempty"`
	SecurityWarnings    []SecurityWarning              `json:"security_warnings,omitempty"`
	PerformanceMetrics  *PerformanceMetrics            `json:"performance_metrics,omitempty"`
	ExecutionPath       string                         `json:"execution_path,omitempty"` // legacy, new_executor
	Recommendations     []string                       `json:"recommendations,omitempty"`
}

// PerformanceMetrics contains detailed performance information
type PerformanceMetrics struct {
	PreprocessingTime   time.Duration `json:"preprocessing_time"`
	CompilationTime     time.Duration `json:"compilation_time"`
	ExecutionTime       time.Duration `json:"execution_time"`
	PackageInstallTime  time.Duration `json:"package_install_time"`
	TotalTime           time.Duration `json:"total_time"`
	MemoryUsage         int64         `json:"memory_usage,omitempty"`
	CPUUsage            float64       `json:"cpu_usage,omitempty"`
	DiskIO              int64         `json:"disk_io,omitempty"`
	NetworkIO           int64         `json:"network_io,omitempty"`
	CacheHit            bool          `json:"cache_hit"`
}

// NewExecutionManager creates a new execution manager
func NewExecutionManager(existingManager *Manager) *ExecutionManager {
	em := &ExecutionManager{
		executors:    make(map[Language]executors.Executor),
		preprocessor: NewCodePreprocessor(),
		manager:      existingManager,
		metrics:      NewExecutionMetrics(),
	}

	// Register new executors
	em.registerExecutors()

	return em
}

// NewExecutionMetrics creates a new execution metrics instance
func NewExecutionMetrics() *ExecutionMetrics {
	return &ExecutionMetrics{
		LanguageStats: make(map[Language]*LanguageStat),
	}
}

// Execute performs enhanced code execution
func (em *ExecutionManager) Execute(ctx context.Context, request *EnhancedExecutionRequest) (*EnhancedExecutionResult, error) {
	startTime := time.Now()
	
	result := &EnhancedExecutionResult{
		ExecutionResult: &ExecutionResult{
			Language: request.Language,
		},
		PerformanceMetrics: &PerformanceMetrics{},
		Recommendations:    []string{},
	}

	// Update metrics
	defer func() {
		result.PerformanceMetrics.TotalTime = time.Since(startTime)
		em.updateMetrics(request.Language, result)
	}()

	// Step 1: Preprocessing (if enabled)
	if request.UsePreprocessor && request.PreprocessorOptions != nil {
		preprocessStart := time.Now()
		
		preprocessResult, err := em.preprocessor.Process(ctx, request.Code, request.PreprocessorOptions)
		if err != nil {
			return result, fmt.Errorf("preprocessing failed: %w", err)
		}
		
		result.PreprocessorResult = preprocessResult
		result.PerformanceMetrics.PreprocessingTime = time.Since(preprocessStart)
		
		// Use preprocessed code
		request.Code = preprocessResult.ProcessedCode
		
		// Add security warnings if any
		result.SecurityWarnings = preprocessResult.SecurityWarnings
		
		// Add recommendations based on preprocessing
		em.addPreprocessingRecommendations(result, preprocessResult)
		
		// Update detected language if different
		if preprocessResult.DetectedLanguage != "" && preprocessResult.LanguageConfidence > 0.8 {
			request.Language = preprocessResult.DetectedLanguage
			result.ExecutionResult.Language = preprocessResult.DetectedLanguage
		}
	}

	// Step 2: Security checks
	if err := em.performSecurityChecks(request, result); err != nil {
		return result, fmt.Errorf("security check failed: %w", err)
	}

	// Step 3: Choose execution path
	if request.UseNewExecutors {
		result.ExecutionPath = "new_executor"
		return em.executeWithNewExecutor(ctx, request, result)
	} else {
		result.ExecutionPath = "legacy"
		return em.executeWithLegacyHandler(ctx, request, result)
	}
}

// executeWithNewExecutor uses the new executor system
func (em *ExecutionManager) executeWithNewExecutor(ctx context.Context, request *EnhancedExecutionRequest, result *EnhancedExecutionResult) (*EnhancedExecutionResult, error) {
	executor, exists := em.executors[request.Language]
	if !exists {
		return result, fmt.Errorf("no enhanced executor available for language: %s", request.Language)
	}

	// Convert request to executor format
	execOptions := em.convertToExecutorOptions(request)

	// Setup environment
	envInfo, err := executor.SetupEnvironment(ctx, execOptions)
	if err != nil {
		return result, fmt.Errorf("environment setup failed: %w", err)
	}

	// Install packages if needed
	packageStart := time.Now()
	if len(request.Packages) > 0 {
		packageResult, err := executor.InstallPackages(ctx, request.Packages, execOptions)
		if err != nil {
			return result, fmt.Errorf("package installation failed: %w", err)
		}
		
		if !packageResult.Success {
			result.Recommendations = append(result.Recommendations, 
				fmt.Sprintf("Package installation partially failed: %v", packageResult.FailedPackages))
		}
	}
	result.PerformanceMetrics.PackageInstallTime = time.Since(packageStart)

	// Validate code syntax
	if err := executor.ValidateCode(ctx, request.Code, execOptions); err != nil {
		result.Recommendations = append(result.Recommendations, 
			fmt.Sprintf("Syntax validation warning: %v", err))
	}

	// Compile if needed
	compileStart := time.Now()
	if executor.IsCompiled() {
		compileResult, err := executor.Compile(ctx, request.Code, execOptions)
		if err != nil {
			return result, fmt.Errorf("compilation failed: %w", err)
		}
		
		if !compileResult.Success {
			result.ExecutionResult.Error = compileResult.Error
			result.ExecutionResult.ExitCode = 1
			return result, nil
		}
		
		result.PerformanceMetrics.CacheHit = compileResult.CacheHit
	}
	result.PerformanceMetrics.CompilationTime = time.Since(compileStart)

	// Execute code
	execStart := time.Now()
	executorResult, err := executor.Execute(ctx, request.Code, execOptions)
	if err != nil {
		return result, fmt.Errorf("execution failed: %w", err)
	}
	result.PerformanceMetrics.ExecutionTime = time.Since(execStart)

	// Convert executor result to enhanced result
	result.ExecutorResult = executorResult
	result.ExecutionResult.ExitCode = executorResult.ExitCode
	result.ExecutionResult.Stdout = executorResult.Stdout
	result.ExecutionResult.Stderr = executorResult.Stderr
	result.ExecutionResult.Duration = executorResult.Duration
	result.ExecutionResult.Command = strings.Join(executorResult.Commands, "; ")
	result.ExecutionResult.Files = make(map[string]string)

	// Add environment info to metadata
	result.ExecutionResult.Metadata = map[string]string{
		"executor_type":     "enhanced",
		"interpreter":       envInfo.Interpreter,
		"package_manager":   envInfo.PackageManager,
		"working_dir":       envInfo.WorkingDir,
		"version":           envInfo.Version,
	}

	return result, nil
}

// executeWithLegacyHandler uses the existing language handler system
func (em *ExecutionManager) executeWithLegacyHandler(ctx context.Context, request *EnhancedExecutionRequest, result *EnhancedExecutionResult) (*EnhancedExecutionResult, error) {
	// Convert to legacy request format
	legacyRequest := &ExecutionRequest{
		Code:        request.Code,
		Language:    request.Language,
		WorkingDir:  request.WorkingDir,
		Environment: request.Environment,
		Timeout:     request.Timeout,
		Packages:    request.Packages,
		Options:     request.Options,
		Files:       request.Files,
		Stdin:       request.Stdin,
	}

	// Execute using legacy system
	execStart := time.Now()
	legacyResult, err := em.manager.ExecuteCode(ctx, legacyRequest)
	if err != nil {
		return result, fmt.Errorf("legacy execution failed: %w", err)
	}
	result.PerformanceMetrics.ExecutionTime = time.Since(execStart)

	// Copy results
	result.ExecutionResult = legacyResult

	// Add legacy-specific metadata
	if result.ExecutionResult.Metadata == nil {
		result.ExecutionResult.Metadata = make(map[string]string)
	}
	result.ExecutionResult.Metadata["executor_type"] = "legacy"

	return result, nil
}

// GetSupportedLanguages returns all supported languages
func (em *ExecutionManager) GetSupportedLanguages() []Language {
	em.mu.RLock()
	defer em.mu.RUnlock()

	languageSet := make(map[Language]bool)

	// Add languages from new executors
	for lang := range em.executors {
		languageSet[lang] = true
	}

	// Add languages from legacy handlers
	if em.manager != nil {
		for _, lang := range em.manager.GetSupportedLanguages() {
			languageSet[lang] = true
		}
	}

	// Convert to slice
	languages := make([]Language, 0, len(languageSet))
	for lang := range languageSet {
		languages = append(languages, lang)
	}

	return languages
}

// GetExecutionMetrics returns current execution metrics
func (em *ExecutionManager) GetExecutionMetrics() *ExecutionMetrics {
	em.metrics.mu.RLock()
	defer em.metrics.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := &ExecutionMetrics{
		TotalExecutions:      em.metrics.TotalExecutions,
		SuccessfulExecutions: em.metrics.SuccessfulExecutions,
		FailedExecutions:     em.metrics.FailedExecutions,
		AverageExecutionTime: em.metrics.AverageExecutionTime,
		LanguageStats:        make(map[Language]*LanguageStat),
	}

	// Copy language stats
	for lang, stat := range em.metrics.LanguageStats {
		metrics.LanguageStats[lang] = &LanguageStat{
			Executions:       stat.Executions,
			SuccessCount:     stat.SuccessCount,
			FailureCount:     stat.FailureCount,
			AverageTime:      stat.AverageTime,
			TotalTime:        stat.TotalTime,
			PackageInstalls:  stat.PackageInstalls,
			CompilationCount: stat.CompilationCount,
			CacheHits:        stat.CacheHits,
		}
	}

	return metrics
}

// Private helper methods

func (em *ExecutionManager) registerExecutors() {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Register language-specific executors
	em.executors[LanguagePython] = executors.NewPythonExecutor()
	em.executors[LanguageJavaScript] = executors.NewNodeExecutor()
	em.executors[LanguageGo] = executors.NewGoExecutor()
	em.executors[LanguageRust] = executors.NewRustExecutor()
	em.executors[LanguageJava] = executors.NewJavaExecutor()
	em.executors[LanguageCPP] = executors.NewCppExecutor()
	em.executors[LanguageC] = executors.NewCExecutor()
	em.executors[LanguageCSharp] = executors.NewCSharpExecutor()
}

func (em *ExecutionManager) convertToExecutorOptions(request *EnhancedExecutionRequest) *executors.ExecutionOptions {
	options := &executors.ExecutionOptions{
		Timeout:        request.Timeout,
		WorkingDir:     request.WorkingDir,
		Environment:    request.Environment,
		Packages:       request.Packages,
		Files:          request.Files,
		Stdin:          request.Stdin,
		CustomConfig:   request.CustomConfig,
	}

	// Copy executor-specific options if provided
	if request.ExecutorOptions != nil {
		options.CompileFlags = request.ExecutorOptions.CompileFlags
		options.RuntimeFlags = request.ExecutorOptions.RuntimeFlags
		options.UseVirtualEnv = request.ExecutorOptions.UseVirtualEnv
		options.BuildMode = request.ExecutorOptions.BuildMode
		options.Framework = request.ExecutorOptions.Framework
		options.PackageManager = request.ExecutorOptions.PackageManager
	}

	return options
}

func (em *ExecutionManager) performSecurityChecks(request *EnhancedExecutionRequest, result *EnhancedExecutionResult) error {
	if request.SecurityLevel == "strict" {
		// Strict security checks
		if len(result.SecurityWarnings) > 0 {
			for _, warning := range result.SecurityWarnings {
				if warning.Severity == "critical" || warning.Severity == "high" {
					return fmt.Errorf("security violation: %s", warning.Message)
				}
			}
		}
	}

	return nil
}

func (em *ExecutionManager) addPreprocessingRecommendations(result *EnhancedExecutionResult, preprocessResult *PreprocessorResult) {
	// Language detection recommendations
	if preprocessResult.LanguageConfidence < 0.7 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Language detection confidence is low (%.2f). Consider specifying the language explicitly.", preprocessResult.LanguageConfidence))
	}

	// Dependency recommendations
	if len(preprocessResult.MissingDependencies) > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Missing dependencies detected: %v", preprocessResult.MissingDependencies))
	}

	// Security recommendations
	highSeverityWarnings := 0
	for _, warning := range preprocessResult.SecurityWarnings {
		if warning.Severity == "critical" || warning.Severity == "high" {
			highSeverityWarnings++
		}
	}
	
	if highSeverityWarnings > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Code contains %d high-severity security issues. Review and fix before production use.", highSeverityWarnings))
	}

	// Performance recommendations
	if len(preprocessResult.InstrumentationPoints) > 1000 {
		result.Recommendations = append(result.Recommendations,
			"Code is complex with many instrumentation points. Consider breaking it into smaller functions.")
	}
}

func (em *ExecutionManager) updateMetrics(language Language, result *EnhancedExecutionResult) {
	em.metrics.mu.Lock()
	defer em.metrics.mu.Unlock()

	// Update total metrics
	em.metrics.TotalExecutions++
	if result.ExecutionResult.ExitCode == 0 {
		em.metrics.SuccessfulExecutions++
	} else {
		em.metrics.FailedExecutions++
	}

	// Update average execution time
	totalTime := em.metrics.AverageExecutionTime * time.Duration(em.metrics.TotalExecutions-1) + result.PerformanceMetrics.TotalTime
	em.metrics.AverageExecutionTime = totalTime / time.Duration(em.metrics.TotalExecutions)

	// Update language-specific metrics
	if _, exists := em.metrics.LanguageStats[language]; !exists {
		em.metrics.LanguageStats[language] = &LanguageStat{}
	}

	stat := em.metrics.LanguageStats[language]
	stat.Executions++
	stat.TotalTime += result.PerformanceMetrics.TotalTime
	stat.AverageTime = stat.TotalTime / time.Duration(stat.Executions)

	if result.ExecutionResult.ExitCode == 0 {
		stat.SuccessCount++
	} else {
		stat.FailureCount++
	}

	if result.PerformanceMetrics.CacheHit {
		stat.CacheHits++
	}

	if result.PerformanceMetrics.CompilationTime > 0 {
		stat.CompilationCount++
	}
}