package cpp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages"
)

// CompilerType represents the C/C++ compiler type
type CompilerType string

const (
	CompilerGCC   CompilerType = "gcc"
	CompilerClang CompilerType = "clang"
	CompilerMSVC  CompilerType = "msvc"
)

// BuildSystem represents the build system type
type BuildSystem string

const (
	BuildSystemDirect BuildSystem = "direct"
	BuildSystemMake   BuildSystem = "make"
	BuildSystemCMake  BuildSystem = "cmake"
	BuildSystemNinja  BuildSystem = "ninja"
)

// OptimizationLevel represents compiler optimization levels
type OptimizationLevel string

const (
	OptO0    OptimizationLevel = "O0"    // No optimization
	OptO1    OptimizationLevel = "O1"    // Basic optimization
	OptO2    OptimizationLevel = "O2"    // Standard optimization
	OptO3    OptimizationLevel = "O3"    // Aggressive optimization
	OptOs    OptimizationLevel = "Os"    // Size optimization
	OptOz    OptimizationLevel = "Oz"    // Aggressive size optimization (Clang)
	OptOg    OptimizationLevel = "Og"    // Debug-friendly optimization
	OptOfast OptimizationLevel = "Ofast" // Fast math optimization
)

// CPPCompiler provides comprehensive C/C++ compilation support
type CPPCompiler struct {
	compilerType     CompilerType
	language         languages.Language
	compilerCommand  string
	linkerCommand    string
	archiverCommand  string
	version          string
	features         *CompilerFeatures
	buildSystems     map[BuildSystem]BuildSystemHandler
	includePaths     []string
	libraryPaths     []string
	libraries        []string
	defines          map[string]string
	standards        []string
	sanitizers       []string
	crossTarget      *CrossCompileTarget
	debugger         *DebuggerConfig
	staticAnalyzer   *StaticAnalyzerConfig
	cache            *CompilationCache
	metrics          *CompilationMetrics
	mu               sync.RWMutex
}

// CompilerFeatures describes available compiler features
type CompilerFeatures struct {
	Standards          []string
	Architectures      []string
	OptimizationLevels []OptimizationLevel
	Sanitizers         []string
	StaticAnalyzers    []string
	Debuggers          []string
	CrossCompile       bool
	LTO               bool // Link Time Optimization
	PGO               bool // Profile Guided Optimization
	OpenMP            bool
	CUDA              bool
	SIMD              []string // SSE, AVX, NEON, etc.
	Version           string
}

// CrossCompileTarget represents cross-compilation configuration
type CrossCompileTarget struct {
	TargetTriple    string
	TargetArch      string
	TargetOS        string
	Sysroot         string
	ToolchainPrefix string
	AdditionalFlags []string
}

// DebuggerConfig configures debugging support
type DebuggerConfig struct {
	Enabled      bool
	DebugLevel   string // none, minimal, default, full
	DebugFormat  string // dwarf, codeview, stabs
	SplitDebug   bool
	DebuggerType string // gdb, lldb, msvc
}

// StaticAnalyzerConfig configures static analysis
type StaticAnalyzerConfig struct {
	Enabled    bool
	Analyzers  []string // clang-tidy, cppcheck, scan-build, pvs-studio
	ConfigFile string
	FailOnWarning bool
}

// BuildSystemHandler interface for different build systems
type BuildSystemHandler interface {
	DetectBuildSystem(workingDir string) bool
	PrepareBuildFiles(ctx context.Context, request *CompilationRequest) error
	Execute(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error)
	GetBuildCommand(request *CompilationRequest) []string
	CleanBuild(workingDir string) error
}

// CompilationRequest represents a C/C++ compilation request
type CompilationRequest struct {
	*languages.CompilationRequest
	
	// C/C++ specific options
	Standard          string
	CompilerType      CompilerType
	BuildSystem       BuildSystem
	ProjectFiles      map[string]string // CMakeLists.txt, Makefile, etc.
	HeaderFiles       map[string]string
	Libraries         []string
	StaticLibraries   []string
	DynamicLibraries  []string
	PackageConfig     []string // pkg-config packages
	PkgConfigPaths    []string
	Defines           map[string]string
	UndefineSymbols   []string
	IncludeDirectories []string
	LibraryDirectories []string
	SystemIncludes    []string
	PrecompiledHeaders map[string]string
	LinkTimeOptimization bool
	ProfileGuidedOptimization string // path to profile data
	Position          string // pic, pie, static
	ThreadingModel    string // pthread, openmp, tbb
	ExceptionHandling bool
	RTTI              bool // Run-Time Type Information
	StandardLibrary   string // libstdc++, libc++, msvc
	RuntimeLibrary    string // static, dynamic
	LanguageExtensions bool
	WarningLevel      string // none, default, extra, all, error
	WarningsAsErrors  bool
	SuppressedWarnings []string
	Sanitizers        []string // address, thread, memory, undefined, leak
	CodeCoverage      bool
	Profiling         bool
	Debug             *DebuggerConfig
	StaticAnalysis    *StaticAnalyzerConfig
	CrossCompile      *CrossCompileTarget
}

// CompilationResponse represents the compilation result
type CompilationResponse struct {
	*languages.CompilationResponse
	
	// C/C++ specific results
	ObjectFiles       []string
	StaticLibraries   []string
	DynamicLibraries  []string
	DebugFiles        []string
	AssemblyFiles     []string
	PreprocessedFiles []string
	Dependencies      []string
	CompilerDiagnostics []CompilerDiagnostic
	StaticAnalysisResults []StaticAnalysisResult
	CodeCoverageResults *CodeCoverageResults
	ProfileResults    *ProfileResults
	BuildSystem       BuildSystem
	CompilerVersion   string
	LinkerVersion     string
}

// CompilerDiagnostic represents compiler warnings/errors with enhanced information
type CompilerDiagnostic struct {
	Type        string // error, warning, note, remark
	Message     string
	File        string
	Line        int
	Column      int
	Code        string // Diagnostic code (e.g., -Wunused-variable)
	Category    string // semantic, syntax, linker, etc.
	Severity    int    // 0=note, 1=warning, 2=error, 3=fatal
	FixItHints  []FixItHint
	Context     string // Source code context
	StackTrace  []string
}

// FixItHint provides automatic fix suggestions
type FixItHint struct {
	Range       SourceRange
	Replacement string
	Description string
}

// SourceRange represents a range in source code
type SourceRange struct {
	StartLine   int
	StartColumn int
	EndLine     int
	EndColumn   int
}

// StaticAnalysisResult represents static analysis findings
type StaticAnalysisResult struct {
	Tool       string
	Rule       string
	Severity   string
	Message    string
	File       string
	Line       int
	Column     int
	Suggestion string
}

// CodeCoverageResults represents code coverage metrics
type CodeCoverageResults struct {
	LinesCovered    int
	LinesTotal      int
	BranchesCovered int
	BranchesTotal   int
	FunctionsCovered int
	FunctionsTotal  int
	CoveragePercent float64
	CoverageFiles   map[string]FileCoverage
}

// FileCoverage represents coverage for a single file
type FileCoverage struct {
	LinesExecuted   []int
	LinesNotExecuted []int
	BranchesTaken   []BranchCoverage
	Functions       []FunctionCoverage
}

// BranchCoverage represents branch coverage information
type BranchCoverage struct {
	Line      int
	Branch    int
	Taken     bool
	Count     int64
}

// FunctionCoverage represents function coverage information  
type FunctionCoverage struct {
	Name        string
	Line        int
	Executed    bool
	Count       int64
}

// ProfileResults represents profiling results
type ProfileResults struct {
	ExecutionTime   time.Duration
	CPUUsage        float64
	MemoryUsage     int64
	HotSpots        []HotSpot
	CallGraph       *CallGraph
	ProfileDataPath string
}

// HotSpot represents performance hot spots
type HotSpot struct {
	Function    string
	File        string
	Line        int
	CPUPercent  float64
	CallCount   int64
	AvgTime     time.Duration
}

// CallGraph represents function call relationships
type CallGraph struct {
	Nodes []CallGraphNode
	Edges []CallGraphEdge
}

// CallGraphNode represents a function in call graph
type CallGraphNode struct {
	ID       string
	Function string
	File     string
	Line     int
}

// CallGraphEdge represents a call relationship
type CallGraphEdge struct {
	From      string
	To        string
	CallCount int64
	Time      time.Duration
}

// CompilationCache provides intelligent caching
type CompilationCache struct {
	cacheDir     string
	entries      map[string]*CacheEntry
	dependencyGraph map[string][]string
	maxSize      int64
	currentSize  int64
	enabled      bool
	mu           sync.RWMutex
}

// CacheEntry represents a cached compilation result
type CacheEntry struct {
	Hash         string
	Language     languages.Language
	CompilerHash string
	SourceFiles  map[string]string
	ObjectFiles  []string
	Dependencies []string
	Timestamp    time.Time
	AccessTime   time.Time
	Size         int64
}

// CompilationMetrics tracks compilation performance
type CompilationMetrics struct {
	CompilationCount      int64
	CacheHitCount        int64
	CacheMissCount       int64
	TotalCompileTime     time.Duration
	AverageCompileTime   time.Duration
	LargestBinary        int64
	SmallestBinary       int64
	SuccessfulBuilds     int64
	FailedBuilds         int64
	WarningCount         int64
	ErrorCount           int64
	mu                   sync.RWMutex
}

// NewCPPCompiler creates a new C/C++ compiler instance
func NewCPPCompiler(compilerType CompilerType, language languages.Language) (*CPPCompiler, error) {
	compiler := &CPPCompiler{
		compilerType:   compilerType,
		language:       language,
		includePaths:   []string{},
		libraryPaths:   []string{},
		libraries:      []string{},
		defines:        make(map[string]string),
		buildSystems:   make(map[BuildSystem]BuildSystemHandler),
		cache:          NewCompilationCache("", false),
		metrics:        NewCompilationMetrics(),
	}

	if err := compiler.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize compiler: %w", err)
	}

	return compiler, nil
}

// Initialize sets up the compiler with system-specific configuration
func (c *CPPCompiler) initialize() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Set compiler commands based on type
	if err := c.setCompilerCommands(); err != nil {
		return err
	}

	// Detect compiler features and version
	if err := c.detectCompilerFeatures(); err != nil {
		return err
	}

	// Initialize build systems
	c.initializeBuildSystems()

	// Set up standard library and system paths
	if err := c.setupSystemPaths(); err != nil {
		return err
	}

	return nil
}

func (c *CPPCompiler) setCompilerCommands() error {
	switch c.compilerType {
	case CompilerGCC:
		if c.language == languages.LanguageC {
			c.compilerCommand = "gcc"
			c.linkerCommand = "gcc"
		} else {
			c.compilerCommand = "g++"
			c.linkerCommand = "g++"
		}
		c.archiverCommand = "ar"

	case CompilerClang:
		if c.language == languages.LanguageC {
			c.compilerCommand = "clang"
			c.linkerCommand = "clang"
		} else {
			c.compilerCommand = "clang++"
			c.linkerCommand = "clang++"
		}
		c.archiverCommand = "llvm-ar"

	case CompilerMSVC:
		c.compilerCommand = "cl"
		c.linkerCommand = "link"
		c.archiverCommand = "lib"

	default:
		return fmt.Errorf("unsupported compiler type: %s", c.compilerType)
	}

	// Verify compiler is available
	if _, err := exec.LookPath(c.compilerCommand); err != nil {
		return fmt.Errorf("compiler not found: %s", c.compilerCommand)
	}

	return nil
}

func (c *CPPCompiler) detectCompilerFeatures() error {
	ctx := context.Background()

	// Get compiler version
	version, err := c.getCompilerVersion(ctx)
	if err != nil {
		return err
	}
	c.version = version

	// Initialize features
	c.features = &CompilerFeatures{
		Version:            version,
		OptimizationLevels: []OptimizationLevel{OptO0, OptO1, OptO2, OptO3, OptOs, OptOg},
		Sanitizers:         []string{"address", "thread", "memory", "undefined", "leak"},
		StaticAnalyzers:    []string{},
		Debuggers:          []string{"gdb"},
		CrossCompile:       true,
		LTO:               true,
		PGO:               false,
	}

	// Language-specific standards
	if c.language == languages.LanguageC {
		c.features.Standards = []string{"c90", "c99", "c11", "c17", "c2x"}
		c.standards = c.features.Standards
	} else {
		c.features.Standards = []string{"c++98", "c++03", "c++11", "c++14", "c++17", "c++20", "c++2b"}
		c.standards = c.features.Standards
	}

	// Compiler-specific features
	switch c.compilerType {
	case CompilerClang:
		c.features.OptimizationLevels = append(c.features.OptimizationLevels, OptOz, OptOfast)
		c.features.StaticAnalyzers = append(c.features.StaticAnalyzers, "clang-tidy", "scan-build")
		c.features.Debuggers = append(c.features.Debuggers, "lldb")
		c.features.PGO = true
		c.features.SIMD = []string{"sse", "sse2", "sse3", "ssse3", "sse4.1", "sse4.2", "avx", "avx2", "avx512"}
		
	case CompilerGCC:
		c.features.OptimizationLevels = append(c.features.OptimizationLevels, OptOfast)
		c.features.StaticAnalyzers = append(c.features.StaticAnalyzers, "cppcheck")
		c.features.OpenMP = true
		c.features.SIMD = []string{"sse", "sse2", "sse3", "ssse3", "sse4.1", "sse4.2", "avx", "avx2"}
		
	case CompilerMSVC:
		c.features.Debuggers = []string{"msvc"}
		c.features.StaticAnalyzers = append(c.features.StaticAnalyzers, "msvc-analyze")
		c.features.SIMD = []string{"sse", "sse2", "avx", "avx2"}
	}

	// Detect supported architectures
	c.features.Architectures = c.detectSupportedArchitectures(ctx)

	return nil
}

func (c *CPPCompiler) detectSupportedArchitectures(ctx context.Context) []string {
	// Common architectures - this could be enhanced to query the compiler
	archs := []string{"x86_64", "i386"}
	
	// Additional architectures based on platform
	switch runtime.GOOS {
	case "linux":
		archs = append(archs, "aarch64", "arm", "armv7", "mips", "mips64", "powerpc", "powerpc64", "riscv64", "s390x")
	case "darwin":
		archs = append(archs, "arm64")
	case "windows":
		archs = append(archs, "arm64")
	}
	
	return archs
}

func (c *CPPCompiler) initializeBuildSystems() {
	c.buildSystems[BuildSystemDirect] = &DirectBuildSystem{compiler: c}
	c.buildSystems[BuildSystemMake] = &MakeBuildSystem{compiler: c}
	c.buildSystems[BuildSystemCMake] = &CMakeBuildSystem{compiler: c}
	c.buildSystems[BuildSystemNinja] = &NinjaBuildSystem{compiler: c}
}

func (c *CPPCompiler) setupSystemPaths() error {
	// Add standard system include paths
	systemIncludes := []string{
		"/usr/include",
		"/usr/local/include",
	}
	
	// Compiler-specific includes
	switch c.compilerType {
	case CompilerGCC:
		systemIncludes = append(systemIncludes, 
			"/usr/include/c++/11",
			"/usr/include/c++/10",
			"/usr/include/c++/9",
		)
	case CompilerClang:
		systemIncludes = append(systemIncludes,
			"/usr/include/c++/v1",
		)
	}
	
	// Filter existing paths
	for _, path := range systemIncludes {
		if _, err := os.Stat(path); err == nil {
			c.includePaths = append(c.includePaths, path)
		}
	}
	
	// Standard library paths
	systemLibPaths := []string{
		"/usr/lib",
		"/usr/local/lib",
		"/usr/lib/x86_64-linux-gnu",
		"/usr/lib64",
	}
	
	for _, path := range systemLibPaths {
		if _, err := os.Stat(path); err == nil {
			c.libraryPaths = append(c.libraryPaths, path)
		}
	}
	
	return nil
}

// Compile implements the CompilerInterface
func (c *CPPCompiler) Compile(ctx context.Context, request *languages.CompilationRequest) (*languages.CompilationResponse, error) {
	startTime := time.Now()
	
	// Convert to C/C++ specific request
	cppRequest := &CompilationRequest{
		CompilationRequest: request,
		CompilerType:       c.compilerType,
		Standard:          c.getDefaultStandard(request),
		BuildSystem:       c.detectBuildSystem(request.WorkingDir),
	}
	
	// Apply request-specific configuration
	c.applyRequestConfig(cppRequest)
	
	response := &CompilationResponse{
		CompilationResponse: &languages.CompilationResponse{
			Success:  false,
			Metadata: make(map[string]interface{}),
		},
		BuildSystem:         cppRequest.BuildSystem,
		CompilerVersion:     c.version,
		CompilerDiagnostics: []CompilerDiagnostic{},
	}
	
	// Check cache first
	if request.CacheEnabled {
		if cached := c.checkCache(cppRequest); cached != nil {
			c.metrics.RecordCacheHit()
			response.CompilationResponse = cached
			response.CompilationResponse.CacheHit = true
			return response.CompilationResponse, nil
		}
		c.metrics.RecordCacheMiss()
	}
	
	// Get appropriate build system handler
	handler, exists := c.buildSystems[cppRequest.BuildSystem]
	if !exists {
		response.Error = fmt.Errorf("unsupported build system: %s", cppRequest.BuildSystem)
		c.metrics.RecordFailure()
		return response.CompilationResponse, nil
	}
	
	// Prepare build files
	if err := handler.PrepareBuildFiles(ctx, cppRequest); err != nil {
		response.Error = fmt.Errorf("failed to prepare build files: %w", err)
		c.metrics.RecordFailure()
		return response.CompilationResponse, nil
	}
	
	// Execute compilation
	buildResponse, err := handler.Execute(ctx, cppRequest)
	if err != nil {
		response.Error = err
		c.metrics.RecordFailure()
		return response.CompilationResponse, nil
	}
	
	// Merge responses
	response.CompilationResponse = buildResponse.CompilationResponse
	response.ObjectFiles = buildResponse.ObjectFiles
	response.StaticLibraries = buildResponse.StaticLibraries
	response.DynamicLibraries = buildResponse.DynamicLibraries
	response.DebugFiles = buildResponse.DebugFiles
	response.CompilerDiagnostics = buildResponse.CompilerDiagnostics
	response.StaticAnalysisResults = buildResponse.StaticAnalysisResults
	
	response.Duration = time.Since(startTime)
	
	// Cache successful compilation
	if response.Success && request.CacheEnabled {
		c.cacheResult(cppRequest, response)
	}
	
	// Update metrics
	c.metrics.RecordCompilation(response.Duration, response.Success)
	
	return response.CompilationResponse, nil
}

// GetSupportedLanguages returns supported languages
func (c *CPPCompiler) GetSupportedLanguages() []languages.Language {
	return []languages.Language{c.language}
}

// GetCompilerVersion returns compiler version
func (c *CPPCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	return c.getCompilerVersion(ctx)
}

func (c *CPPCompiler) getCompilerVersion(ctx context.Context) (string, error) {
	var args []string
	
	switch c.compilerType {
	case CompilerMSVC:
		args = []string{} // cl without args shows version
	default:
		args = []string{"--version"}
	}
	
	cmd := exec.CommandContext(ctx, c.compilerCommand, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get compiler version: %w", err)
	}
	
	// Parse version from output
	versionRegex := regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)
	version := versionRegex.FindString(string(output))
	if version == "" {
		version = strings.Split(string(output), "\n")[0]
	}
	
	return strings.TrimSpace(version), nil
}

// ValidateCompilerAvailability checks if compiler is available
func (c *CPPCompiler) ValidateCompilerAvailability(ctx context.Context) error {
	if _, err := exec.LookPath(c.compilerCommand); err != nil {
		return fmt.Errorf("compiler not available: %s", c.compilerCommand)
	}
	
	if _, err := exec.LookPath(c.linkerCommand); err != nil {
		return fmt.Errorf("linker not available: %s", c.linkerCommand)
	}
	
	if _, err := exec.LookPath(c.archiverCommand); err != nil {
		return fmt.Errorf("archiver not available: %s", c.archiverCommand)
	}
	
	return nil
}

// Helper methods

func (c *CPPCompiler) getDefaultStandard(request *languages.CompilationRequest) string {
	if std := request.CustomConfig["standard"]; std != "" {
		return std
	}
	
	if c.language == languages.LanguageC {
		return "c11"
	}
	return "c++17"
}

func (c *CPPCompiler) detectBuildSystem(workingDir string) BuildSystem {
	// Check for build system files in order of preference
	buildSystemFiles := map[BuildSystem][]string{
		BuildSystemCMake: {"CMakeLists.txt", "cmake/CMakeLists.txt"},
		BuildSystemMake:  {"Makefile", "makefile", "GNUmakefile"},
		BuildSystemNinja: {"build.ninja", "rules.ninja"},
	}
	
	for system, files := range buildSystemFiles {
		for _, file := range files {
			if _, err := os.Stat(filepath.Join(workingDir, file)); err == nil {
				return system
			}
		}
	}
	
	return BuildSystemDirect
}

func (c *CPPCompiler) applyRequestConfig(request *CompilationRequest) {
	// Apply compiler-specific configuration from request
	if request.CompilerFlags != nil {
		// Parse and categorize compiler flags
	}
	
	if request.CustomConfig != nil {
		for key, value := range request.CustomConfig {
			switch key {
			case "compiler_type":
				if compType := CompilerType(value); compType != "" {
					request.CompilerType = compType
				}
			case "build_system":
				if buildSys := BuildSystem(value); buildSys != "" {
					request.BuildSystem = buildSys
				}
			case "threading":
				request.ThreadingModel = value
			case "exceptions":
				request.ExceptionHandling = value == "true"
			case "rtti":
				request.RTTI = value == "true"
			}
		}
	}
}

func (c *CPPCompiler) checkCache(request *CompilationRequest) *languages.CompilationResponse {
	// Implementation of cache checking
	return nil
}

func (c *CPPCompiler) cacheResult(request *CompilationRequest, response *CompilationResponse) {
	// Implementation of result caching
}

// NewCompilationCache creates a new compilation cache
func NewCompilationCache(cacheDir string, enabled bool) *CompilationCache {
	cache := &CompilationCache{
		cacheDir:        cacheDir,
		entries:         make(map[string]*CacheEntry),
		dependencyGraph: make(map[string][]string),
		maxSize:         1024 * 1024 * 1024, // 1GB
		enabled:         enabled,
	}
	
	if enabled && cacheDir != "" {
		os.MkdirAll(cacheDir, 0755)
		cache.loadCache()
	}
	
	return cache
}

func (cache *CompilationCache) loadCache() {
	// Load existing cache entries from disk
}

// NewCompilationMetrics creates new compilation metrics tracker
func NewCompilationMetrics() *CompilationMetrics {
	return &CompilationMetrics{}
}

func (m *CompilationMetrics) RecordCompilation(duration time.Duration, success bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.CompilationCount++
	m.TotalCompileTime += duration
	m.AverageCompileTime = m.TotalCompileTime / time.Duration(m.CompilationCount)
	
	if success {
		m.SuccessfulBuilds++
	} else {
		m.FailedBuilds++
	}
}

func (m *CompilationMetrics) RecordCacheHit() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheHitCount++
}

func (m *CompilationMetrics) RecordCacheMiss() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CacheMissCount++
}

func (m *CompilationMetrics) RecordFailure() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FailedBuilds++
}