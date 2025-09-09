package compilers

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages"
)

// GCCClangCompiler wraps GCC and Clang compilers for C and C++
type GCCClangCompiler struct {
	compilerType   string // "gcc" or "clang"
	language       languages.Language
	compilerCmd    string
	linkerCmd      string
	archiverCmd    string
	standardFlags  []string
	optimizationFlags map[string][]string
	debugFlags     []string
	warningFlags   []string
	libraryPaths   []string
	includePaths   []string
	systemLibraries []string
	crossCompile   *CrossCompileConfig
}

// CrossCompileConfig contains cross-compilation settings
type CrossCompileConfig struct {
	TargetTriple string
	Sysroot      string
	ToolchainPrefix string
	AdditionalFlags []string
}

// CompilerFeatures describes supported compiler features
type CompilerFeatures struct {
	Standards      []string // C90, C99, C11, C17, C++98, C++11, C++14, C++17, C++20
	Architectures  []string
	OptLevels     []string
	Sanitizers    []string
	LTO           bool // Link Time Optimization
	PGO           bool // Profile Guided Optimization
	Parallel      bool // Parallel compilation
}

// NewGCCCompiler creates a new GCC compiler wrapper
func NewGCCCompiler(language languages.Language) *GCCClangCompiler {
	var compilerCmd, linkerCmd string
	
	switch language {
	case languages.LanguageC:
		compilerCmd = "gcc"
		linkerCmd = "gcc"
	case languages.LanguageCPP:
		compilerCmd = "g++"
		linkerCmd = "g++"
	default:
		compilerCmd = "gcc"
		linkerCmd = "gcc"
	}

	return &GCCClangCompiler{
		compilerType:  "gcc",
		language:      language,
		compilerCmd:   compilerCmd,
		linkerCmd:     linkerCmd,
		archiverCmd:   "ar",
		standardFlags: []string{},
		optimizationFlags: map[string][]string{
			"O0": {"-O0"},
			"O1": {"-O1"},
			"O2": {"-O2"},
			"O3": {"-O3"},
			"Os": {"-Os"}, // Size optimization
			"Oz": {"-Oz"}, // Aggressive size optimization (Clang)
			"Og": {"-Og"}, // Debug optimization
			"Ofast": {"-Ofast"}, // Fast optimization
		},
		debugFlags:    []string{"-g", "-ggdb"},
		warningFlags:  []string{"-Wall", "-Wextra", "-Wpedantic"},
		libraryPaths:  []string{},
		includePaths:  []string{},
		systemLibraries: []string{"c", "m", "pthread", "dl"},
	}
}

// NewClangCompiler creates a new Clang compiler wrapper
func NewClangCompiler(language languages.Language) *GCCClangCompiler {
	var compilerCmd, linkerCmd string
	
	switch language {
	case languages.LanguageC:
		compilerCmd = "clang"
		linkerCmd = "clang"
	case languages.LanguageCPP:
		compilerCmd = "clang++"
		linkerCmd = "clang++"
	default:
		compilerCmd = "clang"
		linkerCmd = "clang"
	}

	compiler := NewGCCCompiler(language)
	compiler.compilerType = "clang"
	compiler.compilerCmd = compilerCmd
	compiler.linkerCmd = linkerCmd
	compiler.archiverCmd = "llvm-ar"
	
	// Clang-specific optimizations
	compiler.optimizationFlags["Oz"] = []string{"-Oz"}
	
	return compiler
}

// Compile implements the CompilerInterface
func (gcc *GCCClangCompiler) Compile(ctx context.Context, request *languages.CompilationRequest) (*languages.CompilationResponse, error) {
	startTime := time.Now()
	
	response := &languages.CompilationResponse{
		Success:  false,
		Metadata: make(map[string]interface{}),
	}
	
	// Validate request
	if err := gcc.validateRequest(request); err != nil {
		response.Error = err
		return response, nil
	}
	
	// Prepare source files
	sourceFiles, err := gcc.prepareSourceFiles(request)
	if err != nil {
		response.Error = fmt.Errorf("failed to prepare source files: %w", err)
		return response, nil
	}
	
	// Build compilation command
	compileArgs, err := gcc.buildCompileCommand(request, sourceFiles)
	if err != nil {
		response.Error = fmt.Errorf("failed to build compile command: %w", err)
		return response, nil
	}
	
	// Execute compilation
	cmd := exec.CommandContext(ctx, gcc.compilerCmd, compileArgs...)
	cmd.Dir = request.WorkingDir
	
	// Set environment
	env := os.Environ()
	for k, v := range request.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env
	
	// Capture output
	output, err := cmd.CombinedOutput()
	response.Output = string(output)
	response.Duration = time.Since(startTime)
	
	if err != nil {
		response.ErrorOutput = string(output)
		response.Error = fmt.Errorf("compilation failed: %w", err)
		
		// Parse compiler warnings/errors
		warnings := gcc.parseCompilerOutput(string(output))
		response.Warnings = warnings
		
		return response, nil
	}
	
	// Determine output paths
	executablePath := gcc.getExecutablePath(request)
	artifactPaths := gcc.getArtifactPaths(request, sourceFiles)
	
	// Verify executable was created
	if _, err := os.Stat(executablePath); err != nil {
		response.Error = fmt.Errorf("executable not found: %s", executablePath)
		return response, nil
	}
	
	response.Success = true
	response.ExecutablePath = executablePath
	response.ArtifactPaths = artifactPaths
	response.CompilerVersion = gcc.getVersion(ctx)
	
	// Add metadata
	response.Metadata["compiler_type"] = gcc.compilerType
	response.Metadata["language"] = string(gcc.language)
	response.Metadata["source_files"] = len(sourceFiles)
	response.Metadata["compile_command"] = strings.Join(append([]string{gcc.compilerCmd}, compileArgs...), " ")
	
	return response, nil
}

// GetSupportedLanguages returns supported languages
func (gcc *GCCClangCompiler) GetSupportedLanguages() []languages.Language {
	return []languages.Language{gcc.language}
}

// GetCompilerVersion returns compiler version
func (gcc *GCCClangCompiler) GetCompilerVersion(ctx context.Context) (string, error) {
	return gcc.getVersion(ctx), nil
}

// ValidateCompilerAvailability checks if compiler is available
func (gcc *GCCClangCompiler) ValidateCompilerAvailability(ctx context.Context) error {
	if _, err := exec.LookPath(gcc.compilerCmd); err != nil {
		return fmt.Errorf("compiler not found: %s", gcc.compilerCmd)
	}
	
	if _, err := exec.LookPath(gcc.linkerCmd); err != nil {
		return fmt.Errorf("linker not found: %s", gcc.linkerCmd)
	}
	
	if _, err := exec.LookPath(gcc.archiverCmd); err != nil {
		return fmt.Errorf("archiver not found: %s", gcc.archiverCmd)
	}
	
	return nil
}

// GetFeatures returns compiler features and capabilities
func (gcc *GCCClangCompiler) GetFeatures(ctx context.Context) (*CompilerFeatures, error) {
	features := &CompilerFeatures{
		OptLevels:  []string{"O0", "O1", "O2", "O3", "Os", "Og", "Ofast"},
		Sanitizers: []string{"address", "thread", "memory", "undefined", "leak"},
		LTO:        true,
		PGO:        gcc.compilerType == "clang", // PGO more commonly used with Clang
		Parallel:   true,
	}
	
	switch gcc.language {
	case languages.LanguageC:
		features.Standards = []string{"c90", "c99", "c11", "c17", "c2x"}
	case languages.LanguageCPP:
		features.Standards = []string{"c++98", "c++03", "c++11", "c++14", "c++17", "c++20", "c++23"}
	}
	
	// Get supported architectures
	features.Architectures = gcc.getSupportedArchitectures(ctx)
	
	// Clang-specific features
	if gcc.compilerType == "clang" {
		features.OptLevels = append(features.OptLevels, "Oz")
		features.Sanitizers = append(features.Sanitizers, "dataflow", "cfi")
	}
	
	return features, nil
}

// SetCrossCompile configures cross-compilation
func (gcc *GCCClangCompiler) SetCrossCompile(config *CrossCompileConfig) {
	gcc.crossCompile = config
}

// AddLibraryPath adds a library search path
func (gcc *GCCClangCompiler) AddLibraryPath(path string) {
	gcc.libraryPaths = append(gcc.libraryPaths, path)
}

// AddIncludePath adds an include search path
func (gcc *GCCClangCompiler) AddIncludePath(path string) {
	gcc.includePaths = append(gcc.includePaths, path)
}

// Private helper methods

func (gcc *GCCClangCompiler) validateRequest(request *languages.CompilationRequest) error {
	if request.SourceCode == "" && len(request.SourceFiles) == 0 {
		return fmt.Errorf("no source code provided")
	}
	
	if request.WorkingDir == "" {
		return fmt.Errorf("working directory not specified")
	}
	
	return nil
}

func (gcc *GCCClangCompiler) prepareSourceFiles(request *languages.CompilationRequest) ([]string, error) {
	var sourceFiles []string
	
	// Create main source file if needed
	if request.SourceCode != "" {
		var filename string
		switch gcc.language {
		case languages.LanguageC:
			filename = "main.c"
		case languages.LanguageCPP:
			filename = "main.cpp"
		}
		
		mainPath := filepath.Join(request.WorkingDir, filename)
		if err := os.WriteFile(mainPath, []byte(request.SourceCode), 0644); err != nil {
			return nil, fmt.Errorf("failed to write main source file: %w", err)
		}
		sourceFiles = append(sourceFiles, mainPath)
	}
	
	// Write additional source files
	for filename, content := range request.SourceFiles {
		fullPath := filepath.Join(request.WorkingDir, filename)
		
		// Create directory if needed
		if dir := filepath.Dir(fullPath); dir != request.WorkingDir {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
		
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("failed to write source file %s: %w", filename, err)
		}
		
		// Add to compilation if it's a source file
		if gcc.isSourceFile(filename) {
			sourceFiles = append(sourceFiles, fullPath)
		}
	}
	
	return sourceFiles, nil
}

func (gcc *GCCClangCompiler) buildCompileCommand(request *languages.CompilationRequest, sourceFiles []string) ([]string, error) {
	var args []string
	
	// Language standard
	if standard := request.CustomConfig["standard"]; standard != "" {
		args = append(args, fmt.Sprintf("-std=%s", standard))
	} else {
		// Default standards
		switch gcc.language {
		case languages.LanguageC:
			args = append(args, "-std=c11")
		case languages.LanguageCPP:
			args = append(args, "-std=c++17")
		}
	}
	
	// Optimization level
	optLevel := request.OptimizationLevel
	if optLevel == "" {
		optLevel = "O2"
	}
	if flags, exists := gcc.optimizationFlags[optLevel]; exists {
		args = append(args, flags...)
	}
	
	// Debug symbols
	if request.DebugSymbols {
		args = append(args, gcc.debugFlags...)
	}
	
	// Warning flags
	if request.CustomConfig["warnings"] != "off" {
		args = append(args, gcc.warningFlags...)
		
		// Additional warning flags
		if request.CustomConfig["extra_warnings"] == "true" {
			args = append(args, "-Weverything") // Clang
			if gcc.compilerType == "gcc" {
				args = append(args, "-Wcast-align", "-Wcast-qual", "-Wconversion")
			}
		}
	}
	
	// Sanitizers
	if sanitizer := request.CustomConfig["sanitizer"]; sanitizer != "" {
		sanitizers := strings.Split(sanitizer, ",")
		for _, s := range sanitizers {
			args = append(args, fmt.Sprintf("-fsanitize=%s", strings.TrimSpace(s)))
		}
	}
	
	// Position Independent Code
	if request.CustomConfig["pic"] == "true" {
		args = append(args, "-fPIC")
	}
	
	// Link Time Optimization
	if request.CustomConfig["lto"] == "true" {
		args = append(args, "-flto")
	}
	
	// Cross-compilation
	if gcc.crossCompile != nil {
		args = append(args, fmt.Sprintf("--target=%s", gcc.crossCompile.TargetTriple))
		if gcc.crossCompile.Sysroot != "" {
			args = append(args, fmt.Sprintf("--sysroot=%s", gcc.crossCompile.Sysroot))
		}
		args = append(args, gcc.crossCompile.AdditionalFlags...)
	}
	
	// Include paths
	for _, includePath := range gcc.includePaths {
		args = append(args, fmt.Sprintf("-I%s", includePath))
	}
	
	// Library paths
	for _, libPath := range gcc.libraryPaths {
		args = append(args, fmt.Sprintf("-L%s", libPath))
	}
	
	// System libraries
	for _, lib := range gcc.systemLibraries {
		if request.CustomConfig[fmt.Sprintf("link_%s", lib)] != "false" {
			args = append(args, fmt.Sprintf("-l%s", lib))
		}
	}
	
	// Custom compiler flags
	args = append(args, request.CompilerFlags...)
	
	// Custom linker flags
	args = append(args, request.LinkerFlags...)
	
	// Output file
	outputPath := gcc.getExecutablePath(request)
	args = append(args, "-o", outputPath)
	
	// Source files
	args = append(args, sourceFiles...)
	
	return args, nil
}

func (gcc *GCCClangCompiler) getExecutablePath(request *languages.CompilationRequest) string {
	if request.OutputPath != "" {
		return filepath.Join(request.WorkingDir, request.OutputPath)
	}
	
	executableName := "main"
	if isWindows() {
		executableName += ".exe"
	}
	
	return filepath.Join(request.WorkingDir, executableName)
}

func (gcc *GCCClangCompiler) getArtifactPaths(request *languages.CompilationRequest, sourceFiles []string) []string {
	artifacts := []string{}
	
	// Executable
	executablePath := gcc.getExecutablePath(request)
	artifacts = append(artifacts, executablePath)
	
	// Object files (if separate compilation)
	if request.CustomConfig["keep_objects"] == "true" {
		for _, sourceFile := range sourceFiles {
			objFile := strings.TrimSuffix(sourceFile, filepath.Ext(sourceFile)) + ".o"
			if _, err := os.Stat(objFile); err == nil {
				artifacts = append(artifacts, objFile)
			}
		}
	}
	
	// Debug files
	if request.DebugSymbols && request.CustomConfig["separate_debug"] == "true" {
		debugFile := executablePath + ".debug"
		if _, err := os.Stat(debugFile); err == nil {
			artifacts = append(artifacts, debugFile)
		}
	}
	
	return artifacts
}

func (gcc *GCCClangCompiler) parseCompilerOutput(output string) []languages.CompilerWarning {
	var warnings []languages.CompilerWarning
	
	// Common patterns for GCC/Clang warnings and errors
	patterns := []*regexp.Regexp{
		// file.c:line:column: severity: message
		regexp.MustCompile(`([^:]+):(\d+):(\d+):\s+(warning|error|note):\s+(.+)`),
		// file.c:line: severity: message
		regexp.MustCompile(`([^:]+):(\d+):\s+(warning|error|note):\s+(.+)`),
	}
	
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		for _, pattern := range patterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) >= 5 {
				warning := languages.CompilerWarning{
					File:     matches[1],
					Severity: matches[len(matches)-2],
					Message:  matches[len(matches)-1],
				}
				
				// Parse line and column if available
				if len(matches) >= 6 {
					if lineNum, err := parseInt(matches[2]); err == nil {
						warning.Line = lineNum
					}
					if colNum, err := parseInt(matches[3]); err == nil {
						warning.Column = colNum
					}
				} else if len(matches) >= 4 {
					if lineNum, err := parseInt(matches[2]); err == nil {
						warning.Line = lineNum
					}
				}
				
				warnings = append(warnings, warning)
			}
		}
	}
	
	return warnings
}

func (gcc *GCCClangCompiler) getVersion(ctx context.Context) string {
	cmd := exec.CommandContext(ctx, gcc.compilerCmd, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	
	// Parse version from first line
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		// Extract version number
		versionPattern := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
		matches := versionPattern.FindStringSubmatch(lines[0])
		if len(matches) > 1 {
			return matches[1]
		}
	}
	
	return strings.TrimSpace(string(output))
}

func (gcc *GCCClangCompiler) getSupportedArchitectures(ctx context.Context) []string {
	// Common architectures supported by GCC/Clang
	architectures := []string{
		"x86_64", "i386", "aarch64", "arm", "armv7",
		"mips", "mips64", "powerpc", "powerpc64",
		"riscv32", "riscv64", "s390x", "sparc", "sparc64",
	}
	
	// TODO: Query compiler for actual supported targets
	return architectures
}

func (gcc *GCCClangCompiler) isSourceFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	
	switch gcc.language {
	case languages.LanguageC:
		return ext == ".c"
	case languages.LanguageCPP:
		return ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".C"
	}
	
	return false
}

// Utility functions

func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows")
}

func parseInt(s string) (int, error) {
	var result int
	var err error
	
	// Simple integer parsing
	for _, r := range s {
		if r >= '0' && r <= '9' {
			result = result*10 + int(r-'0')
		} else {
			err = fmt.Errorf("invalid integer: %s", s)
			break
		}
	}
	
	return result, err
}