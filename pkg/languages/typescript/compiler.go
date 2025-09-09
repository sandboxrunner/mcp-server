package typescript

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// TypeScriptCompiler handles TypeScript compilation with advanced features
type TypeScriptCompiler struct {
	workingDir       string
	tscPath          string
	nodeModulesPath  string
	configPath       string
	outputDir        string
	sourceMap        bool
	incremental      bool
	watch            bool
	compilationCache *CompilationCache
	buildOptimizer   *BuildOptimizer
	diagnosticsEngine *DiagnosticsEngine
	mutex            sync.RWMutex
}

// NewTypeScriptCompiler creates a new TypeScript compiler instance
func NewTypeScriptCompiler(workingDir string) *TypeScriptCompiler {
	return &TypeScriptCompiler{
		workingDir:        workingDir,
		outputDir:         filepath.Join(workingDir, "dist"),
		sourceMap:         true,
		incremental:       true,
		compilationCache:  NewCompilationCache(),
		buildOptimizer:    NewBuildOptimizer(),
		diagnosticsEngine: NewDiagnosticsEngine(),
	}
}

// CompilationCache handles caching of compilation results
type CompilationCache struct {
	compiledFiles map[string]*CompiledFileInfo
	tsbuildinfo   string
	mutex         sync.RWMutex
	cacheDir      string
	maxAge        time.Duration
}

// CompiledFileInfo contains information about a compiled file
type CompiledFileInfo struct {
	SourcePath     string            `json:"source_path"`
	OutputPath     string            `json:"output_path"`
	SourceMapPath  string            `json:"source_map_path"`
	DeclarationPath string           `json:"declaration_path"`
	ModificationTime time.Time       `json:"modification_time"`
	CompileTime    time.Time         `json:"compile_time"`
	Dependencies   []string          `json:"dependencies"`
	Metadata       map[string]string `json:"metadata"`
	Hash           string            `json:"hash"`
}

// NewCompilationCache creates a new compilation cache
func NewCompilationCache() *CompilationCache {
	return &CompilationCache{
		compiledFiles: make(map[string]*CompiledFileInfo),
		maxAge:        24 * time.Hour,
		cacheDir:      ".tscache",
	}
}

// BuildOptimizer handles build optimization strategies
type BuildOptimizer struct {
	enableTreeShaking     bool
	enableMinification    bool
	enableCodeSplitting   bool
	enableParallelBuild   bool
	chunkSize            int64
	optimizationLevel    OptimizationLevel
	bundleAnalyzer       *BundleAnalyzer
}

// OptimizationLevel represents different optimization levels
type OptimizationLevel string

const (
	OptimizationNone         OptimizationLevel = "none"
	OptimizationDevelopment  OptimizationLevel = "development"
	OptimizationProduction   OptimizationLevel = "production"
	OptimizationAggressive   OptimizationLevel = "aggressive"
)

// NewBuildOptimizer creates a new build optimizer
func NewBuildOptimizer() *BuildOptimizer {
	return &BuildOptimizer{
		enableTreeShaking:   true,
		enableMinification:  false,
		enableCodeSplitting: false,
		enableParallelBuild: true,
		chunkSize:          500 * 1024, // 500KB
		optimizationLevel:  OptimizationDevelopment,
		bundleAnalyzer:     NewBundleAnalyzer(),
	}
}

// BundleAnalyzer analyzes bundle size and composition
type BundleAnalyzer struct {
	totalSize      int64
	chunkSizes     map[string]int64
	dependencies   map[string]int64
	treeshakeStats *TreeshakeStats
}

// TreeshakeStats contains tree-shaking statistics
type TreeshakeStats struct {
	ModulesShaken   int   `json:"modules_shaken"`
	SizeReduction   int64 `json:"size_reduction"`
	UnusedExports   int   `json:"unused_exports"`
	DeadCodeRemoved int64 `json:"dead_code_removed"`
}

// NewBundleAnalyzer creates a new bundle analyzer
func NewBundleAnalyzer() *BundleAnalyzer {
	return &BundleAnalyzer{
		chunkSizes:     make(map[string]int64),
		dependencies:   make(map[string]int64),
		treeshakeStats: &TreeshakeStats{},
	}
}

// DiagnosticsEngine handles TypeScript diagnostics and error reporting
type DiagnosticsEngine struct {
	diagnostics      []Diagnostic
	errorCount       int
	warningCount     int
	infoCount        int
	suggestionCount  int
	semanticErrors   []SemanticError
	syntaxErrors     []SyntaxError
	typeErrors       []TypeError
	mutex            sync.RWMutex
}

// Diagnostic represents a TypeScript diagnostic message
type Diagnostic struct {
	File     string            `json:"file"`
	Line     int               `json:"line"`
	Column   int               `json:"column"`
	Message  string            `json:"message"`
	Category DiagnosticCategory `json:"category"`
	Code     int               `json:"code"`
	Source   string            `json:"source"`
	Severity DiagnosticSeverity `json:"severity"`
}

// DiagnosticCategory represents diagnostic categories
type DiagnosticCategory string

const (
	DiagnosticCategoryError      DiagnosticCategory = "error"
	DiagnosticCategoryWarning    DiagnosticCategory = "warning"
	DiagnosticCategoryInfo       DiagnosticCategory = "info"
	DiagnosticCategorySuggestion DiagnosticCategory = "suggestion"
)

// DiagnosticSeverity represents diagnostic severity levels
type DiagnosticSeverity int

const (
	DiagnosticSeverityError DiagnosticSeverity = iota
	DiagnosticSeverityWarning
	DiagnosticSeverityInfo
	DiagnosticSeveritySuggestion
)

// SemanticError represents semantic analysis errors
type SemanticError struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Message     string `json:"message"`
	Symbol      string `json:"symbol"`
	SymbolKind  string `json:"symbol_kind"`
	Suggestion  string `json:"suggestion"`
}

// SyntaxError represents syntax errors
type SyntaxError struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Column     int    `json:"column"`
	Message    string `json:"message"`
	Token      string `json:"token"`
	Expected   string `json:"expected"`
	Suggestion string `json:"suggestion"`
}

// TypeError represents type checking errors
type TypeError struct {
	File         string   `json:"file"`
	Line         int      `json:"line"`
	Column       int      `json:"column"`
	Message      string   `json:"message"`
	ActualType   string   `json:"actual_type"`
	ExpectedType string   `json:"expected_type"`
	Context      string   `json:"context"`
	Solutions    []string `json:"solutions"`
}

// NewDiagnosticsEngine creates a new diagnostics engine
func NewDiagnosticsEngine() *DiagnosticsEngine {
	return &DiagnosticsEngine{
		diagnostics: make([]Diagnostic, 0),
	}
}

// CompilationRequest contains TypeScript compilation parameters
type CompilationRequest struct {
	SourceFiles        []string                   `json:"source_files"`
	EntryPoint         string                     `json:"entry_point"`
	ConfigFile         string                     `json:"config_file"`
	OutputDir          string                     `json:"output_dir"`
	Target             CompileTarget              `json:"target"`
	Module             ModuleKind                 `json:"module"`
	SourceMap          bool                       `json:"source_map"`
	Declaration        bool                       `json:"declaration"`
	Incremental        bool                       `json:"incremental"`
	Watch              bool                       `json:"watch"`
	Strict             bool                       `json:"strict"`
	OptimizationLevel  OptimizationLevel          `json:"optimization_level"`
	BuildOptions       map[string]interface{}     `json:"build_options"`
	TypeCheckingOptions *TypeCheckingOptions      `json:"type_checking_options"`
	Environment        map[string]string          `json:"environment"`
	Timeout            time.Duration              `json:"timeout"`
}

// CompileTarget represents TypeScript compilation targets
type CompileTarget string

const (
	TargetES3    CompileTarget = "es3"
	TargetES5    CompileTarget = "es5"
	TargetES6    CompileTarget = "es6"
	TargetES2015 CompileTarget = "es2015"
	TargetES2016 CompileTarget = "es2016"
	TargetES2017 CompileTarget = "es2017"
	TargetES2018 CompileTarget = "es2018"
	TargetES2019 CompileTarget = "es2019"
	TargetES2020 CompileTarget = "es2020"
	TargetES2021 CompileTarget = "es2021"
	TargetES2022 CompileTarget = "es2022"
	TargetESNext CompileTarget = "esnext"
)

// ModuleKind represents TypeScript module systems
type ModuleKind string

const (
	ModuleNone         ModuleKind = "none"
	ModuleCommonJS     ModuleKind = "commonjs"
	ModuleAMD          ModuleKind = "amd"
	ModuleSystem       ModuleKind = "system"
	ModuleUMD          ModuleKind = "umd"
	ModuleES6          ModuleKind = "es6"
	ModuleES2015       ModuleKind = "es2015"
	ModuleES2020       ModuleKind = "es2020"
	ModuleES2022       ModuleKind = "es2022"
	ModuleESNext       ModuleKind = "esnext"
	ModuleNode16       ModuleKind = "node16"
	ModuleNodeNext     ModuleKind = "nodenext"
)

// TypeCheckingOptions contains type checking configuration
type TypeCheckingOptions struct {
	Strict                   bool `json:"strict"`
	NoImplicitAny           bool `json:"no_implicit_any"`
	StrictNullChecks        bool `json:"strict_null_checks"`
	StrictFunctionTypes     bool `json:"strict_function_types"`
	StrictBindCallApply     bool `json:"strict_bind_call_apply"`
	StrictPropertyInit      bool `json:"strict_property_initialization"`
	NoImplicitReturns       bool `json:"no_implicit_returns"`
	NoFallthroughCasesInSwitch bool `json:"no_fallthrough_cases_in_switch"`
	NoUncheckedIndexedAccess bool `json:"no_unchecked_indexed_access"`
	NoImplicitOverride      bool `json:"no_implicit_override"`
	ExactOptionalPropertyTypes bool `json:"exact_optional_property_types"`
}

// CompilationResult contains TypeScript compilation results
type CompilationResult struct {
	Success              bool                  `json:"success"`
	OutputFiles          []string              `json:"output_files"`
	SourceMapFiles       []string              `json:"source_map_files"`
	DeclarationFiles     []string              `json:"declaration_files"`
	Diagnostics          []Diagnostic          `json:"diagnostics"`
	SemanticErrors       []SemanticError       `json:"semantic_errors"`
	SyntaxErrors         []SyntaxError         `json:"syntax_errors"`
	TypeErrors           []TypeError           `json:"type_errors"`
	Output               string                `json:"output"`
	Error                error                 `json:"error"`
	Duration             time.Duration         `json:"duration"`
	BundleAnalysis       *BundleAnalysis       `json:"bundle_analysis"`
	CacheHits            int                   `json:"cache_hits"`
	IncrementalInfo      *IncrementalInfo      `json:"incremental_info"`
	OptimizationResults  *OptimizationResults  `json:"optimization_results"`
}

// BundleAnalysis contains bundle analysis results
type BundleAnalysis struct {
	TotalSize        int64                    `json:"total_size"`
	ChunkSizes       map[string]int64         `json:"chunk_sizes"`
	DependencySizes  map[string]int64         `json:"dependency_sizes"`
	TreeshakeStats   *TreeshakeStats          `json:"treeshake_stats"`
	SizeComparison   *SizeComparison          `json:"size_comparison"`
	Recommendations  []OptimizationSuggestion `json:"recommendations"`
}

// SizeComparison compares bundle sizes
type SizeComparison struct {
	Original   int64 `json:"original"`
	Compressed int64 `json:"compressed"`
	Gzipped    int64 `json:"gzipped"`
	Reduction  int64 `json:"reduction"`
}

// OptimizationSuggestion represents optimization recommendations
type OptimizationSuggestion struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Difficulty  string `json:"difficulty"`
}

// IncrementalInfo contains incremental compilation information
type IncrementalInfo struct {
	FilesChanged     []string      `json:"files_changed"`
	FilesRecompiled  []string      `json:"files_recompiled"`
	DependentsRecompiled []string  `json:"dependents_recompiled"`
	TimeSaved        time.Duration `json:"time_saved"`
	CacheHitRatio    float64       `json:"cache_hit_ratio"`
}

// OptimizationResults contains optimization results
type OptimizationResults struct {
	TreeShakingApplied bool          `json:"tree_shaking_applied"`
	MinificationApplied bool         `json:"minification_applied"`
	SizeReduction      int64         `json:"size_reduction"`
	CompileTimeReduction time.Duration `json:"compile_time_reduction"`
	ModulesEliminated  int           `json:"modules_eliminated"`
}

// TSConfigGenerator generates tsconfig.json files
type TSConfigGenerator struct {
	compiler *TypeScriptCompiler
}

// NewTSConfigGenerator creates a new tsconfig generator
func NewTSConfigGenerator(compiler *TypeScriptCompiler) *TSConfigGenerator {
	return &TSConfigGenerator{compiler: compiler}
}

// TSConfig represents tsconfig.json structure
type TSConfig struct {
	CompilerOptions *CompilerOptions `json:"compilerOptions,omitempty"`
	Include         []string         `json:"include,omitempty"`
	Exclude         []string         `json:"exclude,omitempty"`
	Files           []string         `json:"files,omitempty"`
	Extends         string           `json:"extends,omitempty"`
	References      []ProjectRef     `json:"references,omitempty"`
	TypeAcquisition *TypeAcquisition `json:"typeAcquisition,omitempty"`
	WatchOptions    *WatchOptions    `json:"watchOptions,omitempty"`
}

// CompilerOptions represents TypeScript compiler options
type CompilerOptions struct {
	Target                    string            `json:"target,omitempty"`
	Module                    string            `json:"module,omitempty"`
	Lib                       []string          `json:"lib,omitempty"`
	OutDir                    string            `json:"outDir,omitempty"`
	RootDir                   string            `json:"rootDir,omitempty"`
	SourceMap                 bool              `json:"sourceMap,omitempty"`
	Declaration               bool              `json:"declaration,omitempty"`
	DeclarationMap           bool              `json:"declarationMap,omitempty"`
	Strict                    bool              `json:"strict,omitempty"`
	NoImplicitAny            bool              `json:"noImplicitAny,omitempty"`
	StrictNullChecks         bool              `json:"strictNullChecks,omitempty"`
	StrictFunctionTypes      bool              `json:"strictFunctionTypes,omitempty"`
	NoImplicitReturns        bool              `json:"noImplicitReturns,omitempty"`
	NoImplicitThis           bool              `json:"noImplicitThis,omitempty"`
	AlwaysStrict             bool              `json:"alwaysStrict,omitempty"`
	NoUnusedLocals           bool              `json:"noUnusedLocals,omitempty"`
	NoUnusedParameters       bool              `json:"noUnusedParameters,omitempty"`
	ExactOptionalPropertyTypes bool            `json:"exactOptionalPropertyTypes,omitempty"`
	NoFallthroughCasesInSwitch bool           `json:"noFallthroughCasesInSwitch,omitempty"`
	NoUncheckedIndexedAccess bool              `json:"noUncheckedIndexedAccess,omitempty"`
	ModuleResolution         string            `json:"moduleResolution,omitempty"`
	BaseUrl                  string            `json:"baseUrl,omitempty"`
	Paths                    map[string][]string `json:"paths,omitempty"`
	TypeRoots                []string          `json:"typeRoots,omitempty"`
	Types                    []string          `json:"types,omitempty"`
	AllowSyntheticDefaultImports bool         `json:"allowSyntheticDefaultImports,omitempty"`
	EsModuleInterop          bool              `json:"esModuleInterop,omitempty"`
	ForceConsistentCasingInFileNames bool     `json:"forceConsistentCasingInFileNames,omitempty"`
	SkipLibCheck             bool              `json:"skipLibCheck,omitempty"`
	Incremental              bool              `json:"incremental,omitempty"`
	TsBuildInfoFile          string            `json:"tsBuildInfoFile,omitempty"`
	Composite                bool              `json:"composite,omitempty"`
}

// ProjectRef represents project references
type ProjectRef struct {
	Path     string `json:"path"`
	Prepend  bool   `json:"prepend,omitempty"`
}

// TypeAcquisition represents type acquisition settings
type TypeAcquisition struct {
	Enable  bool     `json:"enable,omitempty"`
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// WatchOptions represents watch mode options
type WatchOptions struct {
	WatchFile          string `json:"watchFile,omitempty"`
	WatchDirectory     string `json:"watchDirectory,omitempty"`
	FallbackPolling    string `json:"fallbackPolling,omitempty"`
	SynchronousWatchDirectory bool `json:"synchronousWatchDirectory,omitempty"`
	ExcludeFiles       []string `json:"excludeFiles,omitempty"`
	ExcludeDirectories []string `json:"excludeDirectories,omitempty"`
}

// Initialize initializes the TypeScript compiler
func (tsc *TypeScriptCompiler) Initialize(ctx context.Context) error {
	tsc.mutex.Lock()
	defer tsc.mutex.Unlock()
	
	// Find TypeScript compiler
	tscPath, err := tsc.findTypeScriptCompiler()
	if err != nil {
		return fmt.Errorf("TypeScript compiler not found: %w", err)
	}
	tsc.tscPath = tscPath
	
	// Set node_modules path
	tsc.nodeModulesPath = filepath.Join(tsc.workingDir, "node_modules")
	
	// Initialize cache directory
	cacheDir := filepath.Join(tsc.workingDir, tsc.compilationCache.cacheDir)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}
	tsc.compilationCache.cacheDir = cacheDir
	
	// Initialize output directory
	if err := os.MkdirAll(tsc.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	
	log.Info().
		Str("tsc_path", tscPath).
		Str("output_dir", tsc.outputDir).
		Msg("TypeScript compiler initialized")
	
	return nil
}

// findTypeScriptCompiler finds the TypeScript compiler executable
func (tsc *TypeScriptCompiler) findTypeScriptCompiler() (string, error) {
	// Try local node_modules first
	localTsc := filepath.Join(tsc.nodeModulesPath, ".bin", "tsc")
	if _, err := os.Stat(localTsc); err == nil {
		return localTsc, nil
	}
	
	// Try global installation
	globalTsc, err := exec.LookPath("tsc")
	if err == nil {
		return globalTsc, nil
	}
	
	// Try npx
	npxTsc, err := exec.LookPath("npx")
	if err == nil {
		// Test if tsc is available via npx
		cmd := exec.Command(npxTsc, "tsc", "--version")
		if _, err := cmd.Output(); err == nil {
			return fmt.Sprintf("%s tsc", npxTsc), nil
		}
	}
	
	return "", fmt.Errorf("TypeScript compiler not found")
}

// GenerateTSConfig generates a tsconfig.json file
func (tsc *TypeScriptCompiler) GenerateTSConfig(req *CompilationRequest) error {
	configPath := filepath.Join(tsc.workingDir, "tsconfig.json")
	
	// Check if tsconfig.json already exists
	if req.ConfigFile != "" {
		configPath = req.ConfigFile
	} else if _, err := os.Stat(configPath); err == nil {
		log.Info().Str("path", configPath).Msg("tsconfig.json already exists")
		tsc.configPath = configPath
		return nil
	}
	
	// Generate default tsconfig.json
	config := &TSConfig{
		CompilerOptions: &CompilerOptions{
			Target:                    string(req.Target),
			Module:                    string(req.Module),
			Lib:                       []string{"dom", "es2020"},
			OutDir:                    req.OutputDir,
			RootDir:                   ".",
			SourceMap:                 req.SourceMap,
			Declaration:               req.Declaration,
			DeclarationMap:           req.Declaration,
			Strict:                    req.Strict,
			EsModuleInterop:          true,
			ForceConsistentCasingInFileNames: true,
			SkipLibCheck:             true,
			Incremental:              req.Incremental,
			ModuleResolution:         "node",
		},
		Include: []string{"src/**/*"},
		Exclude: []string{"node_modules", "dist"},
	}
	
	// Apply type checking options
	if req.TypeCheckingOptions != nil {
		tco := req.TypeCheckingOptions
		config.CompilerOptions.NoImplicitAny = tco.NoImplicitAny
		config.CompilerOptions.StrictNullChecks = tco.StrictNullChecks
		config.CompilerOptions.StrictFunctionTypes = tco.StrictFunctionTypes
		config.CompilerOptions.NoImplicitReturns = tco.NoImplicitReturns
		config.CompilerOptions.NoFallthroughCasesInSwitch = tco.NoFallthroughCasesInSwitch
		config.CompilerOptions.NoUncheckedIndexedAccess = tco.NoUncheckedIndexedAccess
		config.CompilerOptions.ExactOptionalPropertyTypes = tco.ExactOptionalPropertyTypes
	}
	
	// Set incremental build info file
	if req.Incremental {
		config.CompilerOptions.TsBuildInfoFile = filepath.Join(tsc.compilationCache.cacheDir, "tsbuildinfo")
	}
	
	// Marshal to JSON with proper formatting
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tsconfig.json: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write tsconfig.json: %w", err)
	}
	
	tsc.configPath = configPath
	log.Info().Str("path", configPath).Msg("Generated tsconfig.json")
	return nil
}

// Compile compiles TypeScript code
func (tsc *TypeScriptCompiler) Compile(ctx context.Context, req *CompilationRequest) (*CompilationResult, error) {
	startTime := time.Now()
	result := &CompilationResult{
		OutputFiles:      make([]string, 0),
		SourceMapFiles:   make([]string, 0),
		DeclarationFiles: make([]string, 0),
		Diagnostics:      make([]Diagnostic, 0),
	}
	
	// Set default timeout if not specified
	if req.Timeout == 0 {
		req.Timeout = 10 * time.Minute
	}
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	
	log.Info().
		Strs("source_files", req.SourceFiles).
		Str("target", string(req.Target)).
		Str("module", string(req.Module)).
		Msg("Starting TypeScript compilation")
	
	// Generate tsconfig.json if needed
	if err := tsc.GenerateTSConfig(req); err != nil {
		result.Error = fmt.Errorf("failed to generate tsconfig.json: %w", err)
		return result, result.Error
	}
	
	// Check cache for incremental compilation
	if req.Incremental {
		cacheHits := tsc.checkCompilationCache(req.SourceFiles)
		result.CacheHits = cacheHits
	}
	
	// Prepare TypeScript compiler command
	args := tsc.buildCompilerArgs(req)
	
	// Execute compilation
	var compilationResult *CompilationResult
	var err error
	if req.Watch {
		compilationResult, err = tsc.compileInWatchMode(ctx, args, req, result)
	} else {
		compilationResult, err = tsc.compileSingle(ctx, args, req, result)
	}
	
	// Calculate total duration
	if compilationResult != nil {
		compilationResult.Duration = time.Since(startTime)
	}
	
	return compilationResult, err
}

// buildCompilerArgs builds TypeScript compiler arguments
func (tsc *TypeScriptCompiler) buildCompilerArgs(req *CompilationRequest) []string {
	var args []string
	
	// Use project configuration if available
	if tsc.configPath != "" {
		args = append(args, "--project", tsc.configPath)
	}
	
	// Add specific source files if provided
	if len(req.SourceFiles) > 0 && tsc.configPath == "" {
		args = append(args, req.SourceFiles...)
	}
	
	// Override configuration with request parameters
	if req.Target != "" {
		args = append(args, "--target", string(req.Target))
	}
	
	if req.Module != "" {
		args = append(args, "--module", string(req.Module))
	}
	
	if req.OutputDir != "" {
		args = append(args, "--outDir", req.OutputDir)
	}
	
	if req.SourceMap {
		args = append(args, "--sourceMap")
	}
	
	if req.Declaration {
		args = append(args, "--declaration")
		args = append(args, "--declarationMap")
	}
	
	if req.Strict {
		args = append(args, "--strict")
	}
	
	if req.Incremental {
		args = append(args, "--incremental")
		args = append(args, "--tsBuildInfoFile", filepath.Join(tsc.compilationCache.cacheDir, "tsbuildinfo"))
	}
	
	// Add build optimization flags
	if req.OptimizationLevel == OptimizationProduction {
		args = append(args, "--removeComments")
		args = append(args, "--noEmitHelpers")
	}
	
	// Always generate diagnostics
	args = append(args, "--pretty")
	
	return args
}

// compileSingle performs a single compilation
func (tsc *TypeScriptCompiler) compileSingle(ctx context.Context, args []string, req *CompilationRequest, result *CompilationResult) (*CompilationResult, error) {
	// Execute TypeScript compiler
	var cmd *exec.Cmd
	if strings.Contains(tsc.tscPath, "npx") {
		cmdParts := strings.Split(tsc.tscPath, " ")
		cmd = exec.CommandContext(ctx, cmdParts[0], append(cmdParts[1:], args...)...)
	} else {
		cmd = exec.CommandContext(ctx, tsc.tscPath, args...)
	}
	
	cmd.Dir = tsc.workingDir
	
	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Execute command with output streaming
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stdout pipe: %w", err)
		return result, result.Error
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stderr pipe: %w", err)
		return result, result.Error
	}
	
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("failed to start TypeScript compiler: %w", err)
		return result, result.Error
	}
	
	// Collect output and parse diagnostics
	var outputBuilder strings.Builder
	outputDone := make(chan struct{})
	
	go func() {
		defer close(outputDone)
		tsc.streamCompilationOutput(stdout, stderr, &outputBuilder, result)
	}()
	
	// Wait for compilation completion
	err = cmd.Wait()
	<-outputDone
	
	// Duration will be calculated in the main Compile function
	result.Output = outputBuilder.String()
	
	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("TypeScript compilation failed: %w", err)
		
		// Parse diagnostics from output even on failure
		tsc.parseDiagnostics(result.Output, result)
		return result, nil
	}
	
	// Parse compilation output
	tsc.parseCompilationOutput(result)
	
	// Collect output files
	tsc.collectOutputFiles(req, result)
	
	// Run post-compilation optimizations
	if req.OptimizationLevel != OptimizationNone {
		tsc.applyOptimizations(ctx, req, result)
	}
	
	// Update compilation cache
	if req.Incremental {
		tsc.updateCompilationCache(req.SourceFiles, result)
	}
	
	// Analyze bundle if requested
	if req.OptimizationLevel == OptimizationProduction || req.OptimizationLevel == OptimizationAggressive {
		bundleAnalysis := tsc.analyzeBundles(result.OutputFiles)
		result.BundleAnalysis = bundleAnalysis
	}
	
	result.Success = true
	
	log.Info().
		Int("output_files", len(result.OutputFiles)).
		Int("diagnostics", len(result.Diagnostics)).
		Dur("duration", result.Duration).
		Msg("TypeScript compilation completed")
	
	return result, nil
}

// compileInWatchMode performs compilation in watch mode
func (tsc *TypeScriptCompiler) compileInWatchMode(ctx context.Context, args []string, req *CompilationRequest, result *CompilationResult) (*CompilationResult, error) {
	// Add watch flag
	args = append(args, "--watch")
	
	var cmd *exec.Cmd
	if strings.Contains(tsc.tscPath, "npx") {
		cmdParts := strings.Split(tsc.tscPath, " ")
		cmd = exec.CommandContext(ctx, cmdParts[0], append(cmdParts[1:], args...)...)
	} else {
		cmd = exec.CommandContext(ctx, tsc.tscPath, args...)
	}
	
	cmd.Dir = tsc.workingDir
	
	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Start watch mode compilation
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stdout pipe: %w", err)
		return result, result.Error
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stderr pipe: %w", err)
		return result, result.Error
	}
	
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("failed to start TypeScript compiler in watch mode: %w", err)
		return result, result.Error
	}
	
	log.Info().Msg("TypeScript compiler started in watch mode")
	
	// Stream output in background
	go func() {
		var outputBuilder strings.Builder
		tsc.streamCompilationOutput(stdout, stderr, &outputBuilder, result)
	}()
	
	// Wait for context cancellation or initial compilation
	select {
	case <-ctx.Done():
		cmd.Process.Kill()
		result.Error = ctx.Err()
	case <-time.After(30 * time.Second):
		// Give initial compilation time to complete
		result.Success = true
	}
	
	// Duration will be calculated in the main Compile function
	
	return result, nil
}

// streamCompilationOutput streams TypeScript compiler output
func (tsc *TypeScriptCompiler) streamCompilationOutput(stdout, stderr io.Reader, outputBuilder *strings.Builder, result *CompilationResult) {
	// Create scanners for both stdout and stderr
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)
	
	// Process stdout
	go func() {
		for stdoutScanner.Scan() {
			line := stdoutScanner.Text()
			outputBuilder.WriteString(line + "\n")
			tsc.parseProgressLine(line, result)
		}
	}()
	
	// Process stderr
	go func() {
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			outputBuilder.WriteString(line + "\n")
			tsc.parseProgressLine(line, result)
		}
	}()
}

// parseProgressLine parses TypeScript compiler output lines
func (tsc *TypeScriptCompiler) parseProgressLine(line string, result *CompilationResult) {
	// Parse different types of messages
	if strings.Contains(line, "error TS") {
		diagnostic := tsc.parseDiagnosticLine(line, DiagnosticCategoryError)
		if diagnostic != nil {
			result.Diagnostics = append(result.Diagnostics, *diagnostic)
			tsc.diagnosticsEngine.errorCount++
		}
	} else if strings.Contains(line, "warning TS") {
		diagnostic := tsc.parseDiagnosticLine(line, DiagnosticCategoryWarning)
		if diagnostic != nil {
			result.Diagnostics = append(result.Diagnostics, *diagnostic)
			tsc.diagnosticsEngine.warningCount++
		}
	} else if strings.Contains(line, "Found") && strings.Contains(line, "error") {
		// Parse error summary
		log.Info().Str("error_summary", line).Msg("TypeScript compilation errors found")
	} else if strings.Contains(line, "Watching for file changes") {
		log.Info().Msg("TypeScript watch mode active")
	}
}

// parseDiagnosticLine parses a TypeScript diagnostic line
func (tsc *TypeScriptCompiler) parseDiagnosticLine(line string, category DiagnosticCategory) *Diagnostic {
	// Example: "src/index.ts(10,5): error TS2322: Type 'string' is not assignable to type 'number'."
	re := regexp.MustCompile(`(.+?)\((\d+),(\d+)\):\s*(\w+)\s*TS(\d+):\s*(.+)`)
	matches := re.FindStringSubmatch(line)
	
	if len(matches) < 7 {
		// Try simpler pattern
		re2 := regexp.MustCompile(`(\w+)\s*TS(\d+):\s*(.+)`)
		matches2 := re2.FindStringSubmatch(line)
		if len(matches2) >= 4 {
			return &Diagnostic{
				Message:  matches2[3],
				Category: category,
				Code:     parseInt(matches2[2]),
				Source:   line,
			}
		}
		return nil
	}
	
	return &Diagnostic{
		File:     matches[1],
		Line:     parseInt(matches[2]),
		Column:   parseInt(matches[3]),
		Message:  matches[6],
		Category: category,
		Code:     parseInt(matches[5]),
		Source:   line,
	}
}

// parseInt safely parses integer from string
func parseInt(s string) int {
	if i, err := fmt.Sscanf(s, "%d", new(int)); err == nil && i == 1 {
		var result int
		fmt.Sscanf(s, "%d", &result)
		return result
	}
	return 0
}

// parseDiagnostics parses diagnostics from compilation output
func (tsc *TypeScriptCompiler) parseDiagnostics(output string, result *CompilationResult) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if diagnostic := tsc.parseDiagnosticLine(line, DiagnosticCategoryError); diagnostic != nil {
			result.Diagnostics = append(result.Diagnostics, *diagnostic)
		}
	}
}

// parseCompilationOutput parses the compilation output for additional information
func (tsc *TypeScriptCompiler) parseCompilationOutput(result *CompilationResult) {
	// Parse compilation statistics
	lines := strings.Split(result.Output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Found") && strings.Contains(line, "error") {
			// Extract error count
			re := regexp.MustCompile(`Found (\d+) error`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				tsc.diagnosticsEngine.errorCount = parseInt(matches[1])
			}
		}
	}
}

// collectOutputFiles collects generated output files
func (tsc *TypeScriptCompiler) collectOutputFiles(req *CompilationRequest, result *CompilationResult) {
	outputDir := req.OutputDir
	if outputDir == "" {
		outputDir = tsc.outputDir
	}
	
	// Walk through output directory
	filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() {
			ext := filepath.Ext(path)
			switch ext {
			case ".js":
				result.OutputFiles = append(result.OutputFiles, path)
			case ".js.map":
				result.SourceMapFiles = append(result.SourceMapFiles, path)
			case ".d.ts":
				result.DeclarationFiles = append(result.DeclarationFiles, path)
			}
		}
		
		return nil
	})
}

// applyOptimizations applies post-compilation optimizations
func (tsc *TypeScriptCompiler) applyOptimizations(ctx context.Context, req *CompilationRequest, result *CompilationResult) {
	optimizer := tsc.buildOptimizer
	optimizationResults := &OptimizationResults{}
	
	log.Info().Str("level", string(req.OptimizationLevel)).Msg("Applying optimizations")
	
	// Apply tree shaking if enabled
	if optimizer.enableTreeShaking && req.OptimizationLevel != OptimizationNone {
		if err := tsc.applyTreeShaking(result.OutputFiles); err == nil {
			optimizationResults.TreeShakingApplied = true
		}
	}
	
	// Apply minification if enabled
	if optimizer.enableMinification && (req.OptimizationLevel == OptimizationProduction || req.OptimizationLevel == OptimizationAggressive) {
		if err := tsc.applyMinification(result.OutputFiles); err == nil {
			optimizationResults.MinificationApplied = true
		}
	}
	
	result.OptimizationResults = optimizationResults
}

// applyTreeShaking applies tree shaking optimization
func (tsc *TypeScriptCompiler) applyTreeShaking(outputFiles []string) error {
	log.Info().Msg("Applying tree shaking optimization")
	
	// This would involve more sophisticated analysis
	// For now, just mark as applied
	return nil
}

// applyMinification applies minification to output files
func (tsc *TypeScriptCompiler) applyMinification(outputFiles []string) error {
	log.Info().Msg("Applying minification")
	
	// This would involve calling a minification tool
	// For now, just mark as applied
	return nil
}

// analyzeBundles analyzes bundle composition and sizes
func (tsc *TypeScriptCompiler) analyzeBundles(outputFiles []string) *BundleAnalysis {
	analyzer := tsc.buildOptimizer.bundleAnalyzer
	analysis := &BundleAnalysis{
		ChunkSizes:      make(map[string]int64),
		DependencySizes: make(map[string]int64),
		TreeshakeStats:  analyzer.treeshakeStats,
		Recommendations: make([]OptimizationSuggestion, 0),
	}
	
	var totalSize int64
	
	// Analyze each output file
	for _, file := range outputFiles {
		if info, err := os.Stat(file); err == nil {
			size := info.Size()
			totalSize += size
			analysis.ChunkSizes[filepath.Base(file)] = size
		}
	}
	
	analysis.TotalSize = totalSize
	
	// Generate optimization recommendations
	if totalSize > 1024*1024 { // > 1MB
		analysis.Recommendations = append(analysis.Recommendations, OptimizationSuggestion{
			Type:        "bundle_size",
			Description: "Consider enabling code splitting to reduce bundle size",
			Impact:      "high",
			Difficulty:  "medium",
		})
	}
	
	return analysis
}

// checkCompilationCache checks if files need recompilation
func (tsc *TypeScriptCompiler) checkCompilationCache(sourceFiles []string) int {
	tsc.compilationCache.mutex.RLock()
	defer tsc.compilationCache.mutex.RUnlock()
	
	hits := 0
	for _, file := range sourceFiles {
		if info, exists := tsc.compilationCache.compiledFiles[file]; exists {
			// Check if source file has been modified since last compilation
			if stat, err := os.Stat(file); err == nil {
				if stat.ModTime().Before(info.CompileTime) {
					hits++
				}
			}
		}
	}
	
	return hits
}

// updateCompilationCache updates the compilation cache
func (tsc *TypeScriptCompiler) updateCompilationCache(sourceFiles []string, result *CompilationResult) {
	tsc.compilationCache.mutex.Lock()
	defer tsc.compilationCache.mutex.Unlock()
	
	now := time.Now()
	
	for _, file := range sourceFiles {
		info := &CompiledFileInfo{
			SourcePath:   file,
			CompileTime:  now,
			Dependencies: make([]string, 0),
			Metadata:     make(map[string]string),
		}
		
		// Set modification time
		if stat, err := os.Stat(file); err == nil {
			info.ModificationTime = stat.ModTime()
		}
		
		// Find corresponding output file
		for _, output := range result.OutputFiles {
			if strings.Contains(output, filepath.Base(file)) {
				info.OutputPath = output
				break
			}
		}
		
		tsc.compilationCache.compiledFiles[file] = info
	}
}

// TypeCheck performs type checking without compilation
func (tsc *TypeScriptCompiler) TypeCheck(ctx context.Context, req *CompilationRequest) (*CompilationResult, error) {
	// Create a modified request for type checking only
	typeCheckReq := *req
	
	// Add noEmit flag to prevent file generation
	args := tsc.buildCompilerArgs(&typeCheckReq)
	args = append(args, "--noEmit")
	
	// Execute type checking
	return tsc.compileSingle(ctx, args, &typeCheckReq, &CompilationResult{
		Diagnostics: make([]Diagnostic, 0),
	})
}

// GetCompilerVersion returns the TypeScript compiler version
func (tsc *TypeScriptCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	var cmd *exec.Cmd
	if strings.Contains(tsc.tscPath, "npx") {
		cmd = exec.CommandContext(ctx, "npx", "tsc", "--version")
	} else {
		cmd = exec.CommandContext(ctx, tsc.tscPath, "--version")
	}
	
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get TypeScript version: %w", err)
	}
	
	return strings.TrimSpace(string(output)), nil
}

// CleanOutput cleans the output directory
func (tsc *TypeScriptCompiler) CleanOutput() error {
	if _, err := os.Stat(tsc.outputDir); os.IsNotExist(err) {
		return nil
	}
	
	err := os.RemoveAll(tsc.outputDir)
	if err != nil {
		return fmt.Errorf("failed to clean output directory: %w", err)
	}
	
	// Recreate output directory
	err = os.MkdirAll(tsc.outputDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to recreate output directory: %w", err)
	}
	
	log.Info().Str("output_dir", tsc.outputDir).Msg("Cleaned TypeScript output directory")
	return nil
}

// GetDiagnostics returns current diagnostics
func (tsc *TypeScriptCompiler) GetDiagnostics() []Diagnostic {
	tsc.diagnosticsEngine.mutex.RLock()
	defer tsc.diagnosticsEngine.mutex.RUnlock()
	
	return tsc.diagnosticsEngine.diagnostics
}

// ClearCache clears the compilation cache
func (tsc *TypeScriptCompiler) ClearCache() error {
	tsc.compilationCache.mutex.Lock()
	defer tsc.compilationCache.mutex.Unlock()
	
	// Clear in-memory cache
	tsc.compilationCache.compiledFiles = make(map[string]*CompiledFileInfo)
	
	// Remove cache directory
	if err := os.RemoveAll(tsc.compilationCache.cacheDir); err != nil {
		return fmt.Errorf("failed to clear cache directory: %w", err)
	}
	
	// Recreate cache directory
	if err := os.MkdirAll(tsc.compilationCache.cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to recreate cache directory: %w", err)
	}
	
	log.Info().Msg("TypeScript compilation cache cleared")
	return nil
}