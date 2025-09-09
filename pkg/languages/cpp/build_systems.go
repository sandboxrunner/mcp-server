package cpp

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/sandboxrunner/mcp-server/pkg/languages"
)

// DirectBuildSystem handles direct compiler invocation
type DirectBuildSystem struct {
	compiler *CPPCompiler
}

func (d *DirectBuildSystem) DetectBuildSystem(workingDir string) bool {
	// Direct build is always available as fallback
	return true
}

func (d *DirectBuildSystem) PrepareBuildFiles(ctx context.Context, request *CompilationRequest) error {
	// Create source files
	if request.SourceCode != "" {
		var filename string
		if d.compiler.language == languages.LanguageC {
			filename = "main.c"
		} else {
			filename = "main.cpp"
		}
		
		filePath := filepath.Join(request.WorkingDir, filename)
		if err := os.WriteFile(filePath, []byte(request.SourceCode), 0644); err != nil {
			return fmt.Errorf("failed to write source file: %w", err)
		}
	}
	
	// Write additional source files
	for filename, content := range request.SourceFiles {
		filePath := filepath.Join(request.WorkingDir, filename)
		
		// Create directory if needed
		if dir := filepath.Dir(filePath); dir != request.WorkingDir {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
		
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write source file %s: %w", filename, err)
		}
	}
	
	// Write header files
	for filename, content := range request.HeaderFiles {
		filePath := filepath.Join(request.WorkingDir, filename)
		
		if dir := filepath.Dir(filePath); dir != request.WorkingDir {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
		
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write header file %s: %w", filename, err)
		}
	}
	
	return nil
}

func (d *DirectBuildSystem) Execute(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	response := &CompilationResponse{
		CompilationResponse: &languages.CompilationResponse{
			Success:  false,
			Metadata: make(map[string]interface{}),
		},
		CompilerDiagnostics: []CompilerDiagnostic{},
	}
	
	// Find source files to compile
	sourceFiles, err := d.findSourceFiles(request.WorkingDir)
	if err != nil {
		response.Error = err
		return response, nil
	}
	
	if len(sourceFiles) == 0 {
		response.Error = fmt.Errorf("no source files found")
		return response, nil
	}
	
	// Build compilation command
	compileArgs := d.buildCompileArgs(request, sourceFiles)
	
	// Execute compilation
	cmd := exec.CommandContext(ctx, d.compiler.compilerCommand, compileArgs...)
	cmd.Dir = request.WorkingDir
	
	// Set environment
	env := os.Environ()
	for key, value := range request.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = env
	
	// Capture output
	output, err := cmd.CombinedOutput()
	response.Output = string(output)
	
	if err != nil {
		response.ErrorOutput = string(output)
		response.Error = fmt.Errorf("compilation failed: %w", err)
		
		// Parse compiler diagnostics
		response.CompilerDiagnostics = d.parseCompilerOutput(string(output))
		return response, nil
	}
	
	// Determine executable path
	executablePath := d.getExecutablePath(request)
	
	// Verify executable was created
	if _, err := os.Stat(executablePath); err != nil {
		response.Error = fmt.Errorf("executable not found: %s", executablePath)
		return response, nil
	}
	
	response.Success = true
	response.ExecutablePath = executablePath
	response.ArtifactPaths = []string{executablePath}
	
	// Add metadata
	response.Metadata["compile_command"] = strings.Join(append([]string{d.compiler.compilerCommand}, compileArgs...), " ")
	response.Metadata["source_files"] = sourceFiles
	response.Metadata["compiler_type"] = string(d.compiler.compilerType)
	
	return response, nil
}

func (d *DirectBuildSystem) GetBuildCommand(request *CompilationRequest) []string {
	sourceFiles, _ := d.findSourceFiles(request.WorkingDir)
	return d.buildCompileArgs(request, sourceFiles)
}

func (d *DirectBuildSystem) CleanBuild(workingDir string) error {
	// Remove common build artifacts
	patterns := []string{"*.o", "*.obj", "*.exe", "main", "a.out"}
	
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(workingDir, pattern))
		if err != nil {
			continue
		}
		for _, match := range matches {
			os.Remove(match)
		}
	}
	
	return nil
}

func (d *DirectBuildSystem) findSourceFiles(workingDir string) ([]string, error) {
	var sourceFiles []string
	var extensions []string
	
	if d.compiler.language == languages.LanguageC {
		extensions = []string{".c"}
	} else {
		extensions = []string{".cpp", ".cxx", ".cc", ".c++", ".C"}
	}
	
	for _, ext := range extensions {
		matches, err := filepath.Glob(filepath.Join(workingDir, "*"+ext))
		if err != nil {
			continue
		}
		sourceFiles = append(sourceFiles, matches...)
	}
	
	// Also check subdirectories (non-recursively for now)
	entries, err := os.ReadDir(workingDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				dirPath := filepath.Join(workingDir, entry.Name())
				for _, ext := range extensions {
					matches, err := filepath.Glob(filepath.Join(dirPath, "*"+ext))
					if err != nil {
						continue
					}
					sourceFiles = append(sourceFiles, matches...)
				}
			}
		}
	}
	
	return sourceFiles, nil
}

func (d *DirectBuildSystem) buildCompileArgs(request *CompilationRequest, sourceFiles []string) []string {
	var args []string
	
	// Language standard
	if request.Standard != "" {
		args = append(args, fmt.Sprintf("-std=%s", request.Standard))
	}
	
	// Optimization level
	optLevel := OptimizationLevel(request.OptimizationLevel)
	if optLevel == "" {
		optLevel = OptO2
	}
	args = append(args, fmt.Sprintf("-%s", optLevel))
	
	// Debug symbols
	if request.DebugSymbols {
		args = append(args, "-g")
		if d.compiler.compilerType == CompilerGCC {
			args = append(args, "-ggdb")
		}
	}
	
	// Warning level
	switch request.WarningLevel {
	case "none":
		args = append(args, "-w")
	case "extra":
		args = append(args, "-Wall", "-Wextra")
	case "all":
		args = append(args, "-Wall", "-Wextra", "-Wpedantic")
		if d.compiler.compilerType == CompilerClang {
			args = append(args, "-Weverything")
		}
	default:
		args = append(args, "-Wall")
	}
	
	// Warnings as errors
	if request.WarningsAsErrors {
		args = append(args, "-Werror")
	}
	
	// Suppressed warnings
	for _, warning := range request.SuppressedWarnings {
		args = append(args, fmt.Sprintf("-Wno-%s", warning))
	}
	
	// Defines
	for symbol, value := range request.Defines {
		if value == "" {
			args = append(args, fmt.Sprintf("-D%s", symbol))
		} else {
			args = append(args, fmt.Sprintf("-D%s=%s", symbol, value))
		}
	}
	
	// Undefined symbols
	for _, symbol := range request.UndefineSymbols {
		args = append(args, fmt.Sprintf("-U%s", symbol))
	}
	
	// Include directories
	for _, includeDir := range request.IncludeDirectories {
		args = append(args, fmt.Sprintf("-I%s", includeDir))
	}
	
	// System includes
	for _, sysInclude := range request.SystemIncludes {
		args = append(args, "-isystem", sysInclude)
	}
	
	// Library directories
	for _, libDir := range request.LibraryDirectories {
		args = append(args, fmt.Sprintf("-L%s", libDir))
	}
	
	// Libraries
	for _, lib := range request.Libraries {
		args = append(args, fmt.Sprintf("-l%s", lib))
	}
	
	// Static libraries (full path)
	for _, staticLib := range request.StaticLibraries {
		args = append(args, staticLib)
	}
	
	// Position independent code
	switch request.Position {
	case "pic":
		args = append(args, "-fPIC")
	case "pie":
		args = append(args, "-fPIE")
	case "static":
		args = append(args, "-static")
	}
	
	// Threading model
	switch request.ThreadingModel {
	case "pthread":
		args = append(args, "-pthread")
	case "openmp":
		args = append(args, "-fopenmp")
	}
	
	// Exception handling
	if !request.ExceptionHandling && d.compiler.language == languages.LanguageCPP {
		args = append(args, "-fno-exceptions")
	}
	
	// RTTI
	if !request.RTTI && d.compiler.language == languages.LanguageCPP {
		args = append(args, "-fno-rtti")
	}
	
	// Standard library
	if request.StandardLibrary != "" && d.compiler.language == languages.LanguageCPP {
		args = append(args, fmt.Sprintf("-stdlib=%s", request.StandardLibrary))
	}
	
	// Runtime library
	if request.RuntimeLibrary == "static" {
		args = append(args, "-static-libgcc")
		if d.compiler.language == languages.LanguageCPP {
			args = append(args, "-static-libstdc++")
		}
	}
	
	// Sanitizers
	for _, sanitizer := range request.Sanitizers {
		args = append(args, fmt.Sprintf("-fsanitize=%s", sanitizer))
	}
	
	// Link Time Optimization
	if request.LinkTimeOptimization {
		args = append(args, "-flto")
	}
	
	// Profile Guided Optimization
	if request.ProfileGuidedOptimization != "" {
		args = append(args, fmt.Sprintf("-fprofile-use=%s", request.ProfileGuidedOptimization))
	}
	
	// Code coverage
	if request.CodeCoverage {
		args = append(args, "-fprofile-arcs", "-ftest-coverage")
	}
	
	// Profiling
	if request.Profiling {
		args = append(args, "-pg")
	}
	
	// Cross compilation
	if request.CrossCompile != nil {
		args = append(args, fmt.Sprintf("--target=%s", request.CrossCompile.TargetTriple))
		if request.CrossCompile.Sysroot != "" {
			args = append(args, fmt.Sprintf("--sysroot=%s", request.CrossCompile.Sysroot))
		}
		args = append(args, request.CrossCompile.AdditionalFlags...)
	}
	
	// Custom compiler flags
	args = append(args, request.CompilerFlags...)
	
	// Custom linker flags
	args = append(args, request.LinkerFlags...)
	
	// Output file
	outputPath := d.getExecutablePath(request)
	args = append(args, "-o", outputPath)
	
	// Source files
	args = append(args, sourceFiles...)
	
	return args
}

func (d *DirectBuildSystem) getExecutablePath(request *CompilationRequest) string {
	if request.OutputPath != "" {
		return filepath.Join(request.WorkingDir, request.OutputPath)
	}
	
	executableName := "main"
	if request.TargetOS == "windows" || strings.Contains(strings.ToLower(os.Getenv("OS")), "windows") {
		executableName += ".exe"
	}
	
	return filepath.Join(request.WorkingDir, executableName)
}

func (d *DirectBuildSystem) parseCompilerOutput(output string) []CompilerDiagnostic {
	var diagnostics []CompilerDiagnostic
	
	// Common patterns for GCC/Clang diagnostics
	patterns := []*regexp.Regexp{
		// file.c:line:column: severity: message
		regexp.MustCompile(`([^:]+):(\d+):(\d+):\s+(warning|error|note|remark):\s+(.+?)(?:\s+\[([^\]]+)\])?$`),
		// file.c:line: severity: message
		regexp.MustCompile(`([^:]+):(\d+):\s+(warning|error|note|remark):\s+(.+?)(?:\s+\[([^\]]+)\])?$`),
		// file.c: severity: message
		regexp.MustCompile(`([^:]+):\s+(warning|error|note|remark):\s+(.+?)(?:\s+\[([^\]]+)\])?$`),
	}
	
	lines := strings.Split(output, "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		for _, pattern := range patterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) >= 4 {
				diagnostic := CompilerDiagnostic{
					Type:    matches[len(matches)-3],
					Message: matches[len(matches)-2],
					File:    matches[1],
				}
				
				// Parse line number
				if len(matches) >= 6 && matches[2] != "" {
					if lineNum, err := strconv.Atoi(matches[2]); err == nil {
						diagnostic.Line = lineNum
					}
				}
				
				// Parse column number
				if len(matches) >= 7 && matches[3] != "" {
					if colNum, err := strconv.Atoi(matches[3]); err == nil {
						diagnostic.Column = colNum
					}
				}
				
				// Parse diagnostic code
				if len(matches) >= 8 && matches[len(matches)-1] != "" {
					diagnostic.Code = matches[len(matches)-1]
				}
				
				// Set severity
				switch diagnostic.Type {
				case "note", "remark":
					diagnostic.Severity = 0
				case "warning":
					diagnostic.Severity = 1
				case "error":
					diagnostic.Severity = 2
				case "fatal":
					diagnostic.Severity = 3
				}
				
				// Try to get context from surrounding lines
				if diagnostic.Line > 0 {
					diagnostic.Context = d.extractSourceContext(lines, i)
				}
				
				diagnostics = append(diagnostics, diagnostic)
				break
			}
		}
	}
	
	return diagnostics
}

func (d *DirectBuildSystem) extractSourceContext(lines []string, currentIndex int) string {
	// Look for source context in surrounding lines
	contextLines := []string{}
	
	for i := currentIndex + 1; i < len(lines) && i < currentIndex+3; i++ {
		line := strings.TrimSpace(lines[i])
		if line != "" && !strings.Contains(line, ":") {
			contextLines = append(contextLines, line)
		} else {
			break
		}
	}
	
	return strings.Join(contextLines, "\n")
}

// MakeBuildSystem handles Makefile-based builds
type MakeBuildSystem struct {
	compiler *CPPCompiler
}

func (m *MakeBuildSystem) DetectBuildSystem(workingDir string) bool {
	makefiles := []string{"Makefile", "makefile", "GNUmakefile"}
	for _, makefile := range makefiles {
		if _, err := os.Stat(filepath.Join(workingDir, makefile)); err == nil {
			return true
		}
	}
	return false
}

func (m *MakeBuildSystem) PrepareBuildFiles(ctx context.Context, request *CompilationRequest) error {
	// If no Makefile exists, create a basic one
	if !m.DetectBuildSystem(request.WorkingDir) {
		return m.generateMakefile(request)
	}
	return nil
}

func (m *MakeBuildSystem) Execute(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	response := &CompilationResponse{
		CompilationResponse: &languages.CompilationResponse{
			Success:  false,
			Metadata: make(map[string]interface{}),
		},
	}
	
	// Execute make
	makeCmd := "make"
	args := []string{}
	
	// Add parallel build flag if available
	if j := request.CustomConfig["parallel_jobs"]; j != "" {
		args = append(args, fmt.Sprintf("-j%s", j))
	} else {
		args = append(args, "-j4") // Default to 4 parallel jobs
	}
	
	// Add target if specified
	if target := request.CustomConfig["make_target"]; target != "" {
		args = append(args, target)
	}
	
	cmd := exec.CommandContext(ctx, makeCmd, args...)
	cmd.Dir = request.WorkingDir
	
	// Set environment
	env := os.Environ()
	for key, value := range request.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Pass compiler settings via environment
	env = append(env, fmt.Sprintf("CC=%s", m.compiler.compilerCommand))
	if m.compiler.language == languages.LanguageCPP {
		env = append(env, fmt.Sprintf("CXX=%s", m.compiler.compilerCommand))
	}
	
	cmd.Env = env
	
	// Execute make
	output, err := cmd.CombinedOutput()
	response.Output = string(output)
	
	if err != nil {
		response.ErrorOutput = string(output)
		response.Error = fmt.Errorf("make failed: %w", err)
		response.CompilerDiagnostics = m.parseCompilerOutput(string(output))
		return response, nil
	}
	
	// Find generated executable
	executablePath := m.findExecutable(request.WorkingDir)
	if executablePath == "" {
		response.Error = fmt.Errorf("no executable found after make")
		return response, nil
	}
	
	response.Success = true
	response.ExecutablePath = executablePath
	response.ArtifactPaths = []string{executablePath}
	
	// Find object files
	response.ObjectFiles = m.findObjectFiles(request.WorkingDir)
	
	response.Metadata["build_system"] = "make"
	response.Metadata["make_command"] = strings.Join(append([]string{makeCmd}, args...), " ")
	
	return response, nil
}

func (m *MakeBuildSystem) GetBuildCommand(request *CompilationRequest) []string {
	args := []string{"make"}
	
	if j := request.CustomConfig["parallel_jobs"]; j != "" {
		args = append(args, fmt.Sprintf("-j%s", j))
	}
	
	if target := request.CustomConfig["make_target"]; target != "" {
		args = append(args, target)
	}
	
	return args
}

func (m *MakeBuildSystem) CleanBuild(workingDir string) error {
	cmd := exec.Command("make", "clean")
	cmd.Dir = workingDir
	return cmd.Run()
}

func (m *MakeBuildSystem) generateMakefile(request *CompilationRequest) error {
	// Generate a basic Makefile
	var makefile strings.Builder
	
	// Determine compiler variable
	compilerVar := "CC"
	if m.compiler.language == languages.LanguageCPP {
		compilerVar = "CXX"
	}
	
	makefile.WriteString(fmt.Sprintf("# Generated Makefile\n"))
	makefile.WriteString(fmt.Sprintf("%s = %s\n", compilerVar, m.compiler.compilerCommand))
	makefile.WriteString(fmt.Sprintf("CFLAGS = -std=%s -Wall -O2\n", request.Standard))
	
	if request.DebugSymbols {
		makefile.WriteString("CFLAGS += -g\n")
	}
	
	// Add include directories
	for _, includeDir := range request.IncludeDirectories {
		makefile.WriteString(fmt.Sprintf("CFLAGS += -I%s\n", includeDir))
	}
	
	// Add library directories and libraries
	for _, libDir := range request.LibraryDirectories {
		makefile.WriteString(fmt.Sprintf("LDFLAGS += -L%s\n", libDir))
	}
	for _, lib := range request.Libraries {
		makefile.WriteString(fmt.Sprintf("LDFLAGS += -l%s\n", lib))
	}
	
	makefile.WriteString("\n")
	
	// Find source files
	var sourcePattern string
	if m.compiler.language == languages.LanguageC {
		sourcePattern = "*.c"
	} else {
		sourcePattern = "*.cpp *.cxx *.cc"
	}
	
	makefile.WriteString(fmt.Sprintf("SOURCES = $(wildcard %s)\n", sourcePattern))
	makefile.WriteString("OBJECTS = $(SOURCES:.c=.o)\n")
	if m.compiler.language == languages.LanguageCPP {
		makefile.WriteString("OBJECTS := $(OBJECTS:.cpp=.o)\n")
		makefile.WriteString("OBJECTS := $(OBJECTS:.cxx=.o)\n")
		makefile.WriteString("OBJECTS := $(OBJECTS:.cc=.o)\n")
	}
	
	makefile.WriteString("TARGET = main\n\n")
	
	// Rules
	makefile.WriteString("all: $(TARGET)\n\n")
	makefile.WriteString("$(TARGET): $(OBJECTS)\n")
	makefile.WriteString(fmt.Sprintf("\t$(%s) $(OBJECTS) -o $@ $(LDFLAGS)\n\n", compilerVar))
	
	makefile.WriteString("%.o: %.c\n")
	makefile.WriteString(fmt.Sprintf("\t$(%s) $(CFLAGS) -c $< -o $@\n\n", compilerVar))
	
	if m.compiler.language == languages.LanguageCPP {
		makefile.WriteString("%.o: %.cpp\n")
		makefile.WriteString(fmt.Sprintf("\t$(%s) $(CFLAGS) -c $< -o $@\n\n", compilerVar))
		makefile.WriteString("%.o: %.cxx\n")
		makefile.WriteString(fmt.Sprintf("\t$(%s) $(CFLAGS) -c $< -o $@\n\n", compilerVar))
		makefile.WriteString("%.o: %.cc\n")
		makefile.WriteString(fmt.Sprintf("\t$(%s) $(CFLAGS) -c $< -o $@\n\n", compilerVar))
	}
	
	makefile.WriteString("clean:\n")
	makefile.WriteString("\trm -f $(OBJECTS) $(TARGET)\n\n")
	makefile.WriteString(".PHONY: all clean\n")
	
	// Write Makefile
	makefilePath := filepath.Join(request.WorkingDir, "Makefile")
	return os.WriteFile(makefilePath, []byte(makefile.String()), 0644)
}

func (m *MakeBuildSystem) findExecutable(workingDir string) string {
	// Common executable names
	candidates := []string{"main", "a.out"}
	
	for _, candidate := range candidates {
		path := filepath.Join(workingDir, candidate)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			// Check if file is executable
			return path
		}
	}
	
	return ""
}

func (m *MakeBuildSystem) findObjectFiles(workingDir string) []string {
	var objectFiles []string
	
	matches, err := filepath.Glob(filepath.Join(workingDir, "*.o"))
	if err == nil {
		objectFiles = append(objectFiles, matches...)
	}
	
	return objectFiles
}

func (m *MakeBuildSystem) parseCompilerOutput(output string) []CompilerDiagnostic {
	// Reuse the direct build system's parser
	direct := &DirectBuildSystem{compiler: m.compiler}
	return direct.parseCompilerOutput(output)
}

// CMakeBuildSystem handles CMake-based builds
type CMakeBuildSystem struct {
	compiler *CPPCompiler
}

func (c *CMakeBuildSystem) DetectBuildSystem(workingDir string) bool {
	cmakeFiles := []string{"CMakeLists.txt", "cmake/CMakeLists.txt"}
	for _, cmakeFile := range cmakeFiles {
		if _, err := os.Stat(filepath.Join(workingDir, cmakeFile)); err == nil {
			return true
		}
	}
	return false
}

func (c *CMakeBuildSystem) PrepareBuildFiles(ctx context.Context, request *CompilationRequest) error {
	// Create build directory
	buildDir := filepath.Join(request.WorkingDir, "build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		return fmt.Errorf("failed to create build directory: %w", err)
	}
	
	// If no CMakeLists.txt exists, create a basic one
	if !c.DetectBuildSystem(request.WorkingDir) {
		if err := c.generateCMakeLists(request); err != nil {
			return err
		}
	}
	
	// Run cmake configure
	return c.runCMakeConfigure(ctx, request, buildDir)
}

func (c *CMakeBuildSystem) Execute(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	response := &CompilationResponse{
		CompilationResponse: &languages.CompilationResponse{
			Success:  false,
			Metadata: make(map[string]interface{}),
		},
	}
	
	buildDir := filepath.Join(request.WorkingDir, "build")
	
	// Run cmake build
	args := []string{"--build", buildDir}
	
	// Add parallel build flag
	if j := request.CustomConfig["parallel_jobs"]; j != "" {
		args = append(args, "--parallel", j)
	} else {
		args = append(args, "--parallel", "4")
	}
	
	// Add target if specified
	if target := request.CustomConfig["cmake_target"]; target != "" {
		args = append(args, "--target", target)
	}
	
	// Add configuration (Debug/Release)
	buildMode := request.BuildMode
	if buildMode == "" {
		if request.DebugSymbols {
			buildMode = "Debug"
		} else {
			buildMode = "Release"
		}
	}
	args = append(args, "--config", buildMode)
	
	cmd := exec.CommandContext(ctx, "cmake", args...)
	
	// Set environment
	env := os.Environ()
	for key, value := range request.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = env
	
	output, err := cmd.CombinedOutput()
	response.Output = string(output)
	
	if err != nil {
		response.ErrorOutput = string(output)
		response.Error = fmt.Errorf("cmake build failed: %w", err)
		response.CompilerDiagnostics = c.parseCompilerOutput(string(output))
		return response, nil
	}
	
	// Find generated executable
	executablePath := c.findExecutable(buildDir)
	if executablePath == "" {
		response.Error = fmt.Errorf("no executable found after cmake build")
		return response, nil
	}
	
	response.Success = true
	response.ExecutablePath = executablePath
	response.ArtifactPaths = []string{executablePath}
	
	// Find other artifacts
	response.ObjectFiles = c.findObjectFiles(buildDir)
	response.StaticLibraries = c.findLibraries(buildDir, ".a")
	response.DynamicLibraries = c.findLibraries(buildDir, ".so")
	
	response.Metadata["build_system"] = "cmake"
	response.Metadata["build_directory"] = buildDir
	response.Metadata["cmake_command"] = strings.Join(append([]string{"cmake"}, args...), " ")
	
	return response, nil
}

func (c *CMakeBuildSystem) GetBuildCommand(request *CompilationRequest) []string {
	buildDir := filepath.Join(request.WorkingDir, "build")
	args := []string{"cmake", "--build", buildDir}
	
	if j := request.CustomConfig["parallel_jobs"]; j != "" {
		args = append(args, "--parallel", j)
	}
	
	return args
}

func (c *CMakeBuildSystem) CleanBuild(workingDir string) error {
	buildDir := filepath.Join(workingDir, "build")
	return os.RemoveAll(buildDir)
}

func (c *CMakeBuildSystem) runCMakeConfigure(ctx context.Context, request *CompilationRequest, buildDir string) error {
	args := []string{"-B", buildDir, "-S", request.WorkingDir}
	
	// Set compiler
	args = append(args, fmt.Sprintf("-DCMAKE_C_COMPILER=%s", c.compiler.compilerCommand))
	if c.compiler.language == languages.LanguageCPP {
		args = append(args, fmt.Sprintf("-DCMAKE_CXX_COMPILER=%s", c.compiler.compilerCommand))
	}
	
	// Set build type
	buildType := request.BuildMode
	if buildType == "" {
		if request.DebugSymbols {
			buildType = "Debug"
		} else {
			buildType = "Release"
		}
	}
	args = append(args, fmt.Sprintf("-DCMAKE_BUILD_TYPE=%s", buildType))
	
	// Set C/C++ standard
	if request.Standard != "" {
		if c.compiler.language == languages.LanguageC {
			args = append(args, fmt.Sprintf("-DCMAKE_C_STANDARD=%s", strings.TrimPrefix(request.Standard, "c")))
		} else {
			standard := strings.TrimPrefix(request.Standard, "c++")
			args = append(args, fmt.Sprintf("-DCMAKE_CXX_STANDARD=%s", standard))
		}
	}
	
	// Additional cmake variables from config
	for key, value := range request.CustomConfig {
		if strings.HasPrefix(key, "CMAKE_") {
			args = append(args, fmt.Sprintf("-D%s=%s", key, value))
		}
	}
	
	cmd := exec.CommandContext(ctx, "cmake", args...)
	
	env := os.Environ()
	for key, value := range request.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = env
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cmake configure failed: %w\nOutput: %s", err, string(output))
	}
	
	return nil
}

func (c *CMakeBuildSystem) generateCMakeLists(request *CompilationRequest) error {
	var cmake strings.Builder
	
	cmake.WriteString("# Generated CMakeLists.txt\n")
	cmake.WriteString("cmake_minimum_required(VERSION 3.10)\n\n")
	cmake.WriteString("project(main)\n\n")
	
	// Set language standard
	if c.compiler.language == languages.LanguageC {
		standard := strings.TrimPrefix(request.Standard, "c")
		cmake.WriteString(fmt.Sprintf("set(CMAKE_C_STANDARD %s)\n", standard))
		cmake.WriteString("set(CMAKE_C_STANDARD_REQUIRED ON)\n\n")
	} else {
		standard := strings.TrimPrefix(request.Standard, "c++")
		cmake.WriteString(fmt.Sprintf("set(CMAKE_CXX_STANDARD %s)\n", standard))
		cmake.WriteString("set(CMAKE_CXX_STANDARD_REQUIRED ON)\n\n")
	}
	
	// Find source files
	var sourcePattern string
	if c.compiler.language == languages.LanguageC {
		sourcePattern = "*.c"
	} else {
		sourcePattern = "*.cpp *.cxx *.cc"
	}
	
	cmake.WriteString(fmt.Sprintf("file(GLOB SOURCES %s)\n\n", sourcePattern))
	cmake.WriteString("add_executable(main ${SOURCES})\n\n")
	
	// Add include directories
	if len(request.IncludeDirectories) > 0 {
		cmake.WriteString("target_include_directories(main PRIVATE\n")
		for _, includeDir := range request.IncludeDirectories {
			cmake.WriteString(fmt.Sprintf("    %s\n", includeDir))
		}
		cmake.WriteString(")\n\n")
	}
	
	// Add libraries
	if len(request.Libraries) > 0 {
		cmake.WriteString("target_link_libraries(main\n")
		for _, lib := range request.Libraries {
			cmake.WriteString(fmt.Sprintf("    %s\n", lib))
		}
		cmake.WriteString(")\n\n")
	}
	
	// Add compiler definitions
	if len(request.Defines) > 0 {
		cmake.WriteString("target_compile_definitions(main PRIVATE\n")
		for symbol, value := range request.Defines {
			if value == "" {
				cmake.WriteString(fmt.Sprintf("    %s\n", symbol))
			} else {
				cmake.WriteString(fmt.Sprintf("    %s=%s\n", symbol, value))
			}
		}
		cmake.WriteString(")\n\n")
	}
	
	// Write CMakeLists.txt
	cmakeListsPath := filepath.Join(request.WorkingDir, "CMakeLists.txt")
	return os.WriteFile(cmakeListsPath, []byte(cmake.String()), 0644)
}

func (c *CMakeBuildSystem) findExecutable(buildDir string) string {
	// Common locations for executables in cmake build
	candidates := []string{
		filepath.Join(buildDir, "main"),
		filepath.Join(buildDir, "Debug", "main"),
		filepath.Join(buildDir, "Release", "main"),
		filepath.Join(buildDir, "main.exe"),
		filepath.Join(buildDir, "Debug", "main.exe"),
		filepath.Join(buildDir, "Release", "main.exe"),
	}
	
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	
	return ""
}

func (c *CMakeBuildSystem) findObjectFiles(buildDir string) []string {
	var objectFiles []string
	
	// Recursively find object files
	filepath.Walk(buildDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if strings.HasSuffix(path, ".o") || strings.HasSuffix(path, ".obj") {
			objectFiles = append(objectFiles, path)
		}
		
		return nil
	})
	
	return objectFiles
}

func (c *CMakeBuildSystem) findLibraries(buildDir string, extension string) []string {
	var libraries []string
	
	filepath.Walk(buildDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if strings.HasSuffix(path, extension) || 
		   (extension == ".so" && (strings.HasSuffix(path, ".so") || 
		    regexp.MustCompile(`\.so\.\d+`).MatchString(path))) {
			libraries = append(libraries, path)
		}
		
		return nil
	})
	
	return libraries
}

func (c *CMakeBuildSystem) parseCompilerOutput(output string) []CompilerDiagnostic {
	// Reuse the direct build system's parser
	direct := &DirectBuildSystem{compiler: c.compiler}
	return direct.parseCompilerOutput(output)
}

// NinjaBuildSystem handles Ninja-based builds
type NinjaBuildSystem struct {
	compiler *CPPCompiler
}

func (n *NinjaBuildSystem) DetectBuildSystem(workingDir string) bool {
	ninjaFiles := []string{"build.ninja", "rules.ninja"}
	for _, ninjaFile := range ninjaFiles {
		if _, err := os.Stat(filepath.Join(workingDir, ninjaFile)); err == nil {
			return true
		}
	}
	return false
}

func (n *NinjaBuildSystem) PrepareBuildFiles(ctx context.Context, request *CompilationRequest) error {
	// If no build.ninja exists, create a basic one
	if !n.DetectBuildSystem(request.WorkingDir) {
		return n.generateNinjaFile(request)
	}
	return nil
}

func (n *NinjaBuildSystem) Execute(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	response := &CompilationResponse{
		CompilationResponse: &languages.CompilationResponse{
			Success:  false,
			Metadata: make(map[string]interface{}),
		},
	}
	
	// Run ninja
	args := []string{}
	
	// Add parallel build flag
	if j := request.CustomConfig["parallel_jobs"]; j != "" {
		args = append(args, "-j", j)
	}
	
	// Add target if specified
	if target := request.CustomConfig["ninja_target"]; target != "" {
		args = append(args, target)
	}
	
	cmd := exec.CommandContext(ctx, "ninja", args...)
	cmd.Dir = request.WorkingDir
	
	// Set environment
	env := os.Environ()
	for key, value := range request.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}
	cmd.Env = env
	
	output, err := cmd.CombinedOutput()
	response.Output = string(output)
	
	if err != nil {
		response.ErrorOutput = string(output)
		response.Error = fmt.Errorf("ninja build failed: %w", err)
		response.CompilerDiagnostics = n.parseCompilerOutput(string(output))
		return response, nil
	}
	
	// Find generated executable
	executablePath := n.findExecutable(request.WorkingDir)
	if executablePath == "" {
		response.Error = fmt.Errorf("no executable found after ninja build")
		return response, nil
	}
	
	response.Success = true
	response.ExecutablePath = executablePath
	response.ArtifactPaths = []string{executablePath}
	
	response.Metadata["build_system"] = "ninja"
	response.Metadata["ninja_command"] = strings.Join(append([]string{"ninja"}, args...), " ")
	
	return response, nil
}

func (n *NinjaBuildSystem) GetBuildCommand(request *CompilationRequest) []string {
	args := []string{"ninja"}
	
	if j := request.CustomConfig["parallel_jobs"]; j != "" {
		args = append(args, "-j", j)
	}
	
	return args
}

func (n *NinjaBuildSystem) CleanBuild(workingDir string) error {
	cmd := exec.Command("ninja", "-t", "clean")
	cmd.Dir = workingDir
	return cmd.Run()
}

func (n *NinjaBuildSystem) generateNinjaFile(request *CompilationRequest) error {
	var ninja strings.Builder
	
	// Rules
	ninja.WriteString("# Generated build.ninja\n")
	ninja.WriteString(fmt.Sprintf("rule compile\n"))
	ninja.WriteString(fmt.Sprintf("  command = %s -std=%s -Wall -O2", n.compiler.compilerCommand, request.Standard))
	
	if request.DebugSymbols {
		ninja.WriteString(" -g")
	}
	
	// Add include directories
	for _, includeDir := range request.IncludeDirectories {
		ninja.WriteString(fmt.Sprintf(" -I%s", includeDir))
	}
	
	ninja.WriteString(" -c $in -o $out\n")
	ninja.WriteString("  description = Compiling $in\n\n")
	
	ninja.WriteString("rule link\n")
	ninja.WriteString(fmt.Sprintf("  command = %s $in -o $out", n.compiler.linkerCommand))
	
	// Add library directories and libraries
	for _, libDir := range request.LibraryDirectories {
		ninja.WriteString(fmt.Sprintf(" -L%s", libDir))
	}
	for _, lib := range request.Libraries {
		ninja.WriteString(fmt.Sprintf(" -l%s", lib))
	}
	
	ninja.WriteString("\n  description = Linking $out\n\n")
	
	// Find source files and generate build statements
	sourceFiles, err := filepath.Glob(filepath.Join(request.WorkingDir, "*.c"))
	if err == nil && len(sourceFiles) == 0 && n.compiler.language == languages.LanguageCPP {
		sourceFiles, _ = filepath.Glob(filepath.Join(request.WorkingDir, "*.cpp"))
	}
	
	var objectFiles []string
	for _, sourceFile := range sourceFiles {
		baseName := filepath.Base(sourceFile)
		objectFile := strings.TrimSuffix(baseName, filepath.Ext(baseName)) + ".o"
		objectFiles = append(objectFiles, objectFile)
		
		ninja.WriteString(fmt.Sprintf("build %s: compile %s\n", objectFile, baseName))
	}
	
	ninja.WriteString("\n")
	ninja.WriteString(fmt.Sprintf("build main: link %s\n", strings.Join(objectFiles, " ")))
	ninja.WriteString("\ndefault main\n")
	
	// Write build.ninja
	ninjaFilePath := filepath.Join(request.WorkingDir, "build.ninja")
	return os.WriteFile(ninjaFilePath, []byte(ninja.String()), 0644)
}

func (n *NinjaBuildSystem) findExecutable(workingDir string) string {
	candidates := []string{"main", "a.out"}
	
	for _, candidate := range candidates {
		path := filepath.Join(workingDir, candidate)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	
	return ""
}

func (n *NinjaBuildSystem) parseCompilerOutput(output string) []CompilerDiagnostic {
	// Reuse the direct build system's parser
	direct := &DirectBuildSystem{compiler: n.compiler}
	return direct.parseCompilerOutput(output)
}