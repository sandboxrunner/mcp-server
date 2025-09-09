package cpp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages"
)

func TestNewCPPCompiler(t *testing.T) {
	tests := []struct {
		name         string
		compilerType CompilerType
		language     languages.Language
		expectError  bool
	}{
		{
			name:         "GCC C compiler",
			compilerType: CompilerGCC,
			language:     languages.LanguageC,
			expectError:  false,
		},
		{
			name:         "GCC C++ compiler",
			compilerType: CompilerGCC,
			language:     languages.LanguageCPP,
			expectError:  false,
		},
		{
			name:         "Clang C compiler",
			compilerType: CompilerClang,
			language:     languages.LanguageC,
			expectError:  false,
		},
		{
			name:         "Clang C++ compiler",
			compilerType: CompilerClang,
			language:     languages.LanguageCPP,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler, err := NewCPPCompiler(tt.compilerType, tt.language)
			
			if tt.expectError {
				if err == nil {
					t.Error("Expected error, but got nil")
				}
				return
			}
			
			if err != nil {
				t.Skipf("Compiler not available: %v", err)
				return
			}

			if compiler == nil {
				t.Fatal("Expected compiler, but got nil")
			}

			if compiler.compilerType != tt.compilerType {
				t.Errorf("Expected compiler type %s, got %s", tt.compilerType, compiler.compilerType)
			}

			if compiler.language != tt.language {
				t.Errorf("Expected language %s, got %s", tt.language, compiler.language)
			}

			// Test that compiler commands are set
			if compiler.compilerCommand == "" {
				t.Error("Compiler command not set")
			}

			if compiler.linkerCommand == "" {
				t.Error("Linker command not set")
			}

			if compiler.archiverCommand == "" {
				t.Error("Archiver command not set")
			}
		})
	}
}

func TestCPPCompilerFeatures(t *testing.T) {
	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	features := compiler.features
	if features == nil {
		t.Fatal("Features not initialized")
	}

	// Test that features are populated
	if len(features.Standards) == 0 {
		t.Error("No standards available")
	}

	if len(features.OptimizationLevels) == 0 {
		t.Error("No optimization levels available")
	}

	if len(features.Sanitizers) == 0 {
		t.Error("No sanitizers available")
	}

	// Test C++ specific standards
	expectedStandards := []string{"c++98", "c++03", "c++11", "c++14", "c++17", "c++20", "c++2b"}
	for _, expected := range expectedStandards {
		found := false
		for _, standard := range features.Standards {
			if standard == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected standard %s not found", expected)
		}
	}
}

func TestDirectBuildSystem(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "cpp-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create C++ compiler
	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	// Create build system
	buildSystem := &DirectBuildSystem{compiler: compiler}

	// Test detection (should always return true for direct build)
	if !buildSystem.DetectBuildSystem(tempDir) {
		t.Error("Direct build system should always be available")
	}

	// Test simple C++ program compilation
	sourceCode := `
#include <iostream>
int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
`

	request := &CompilationRequest{
		CompilationRequest: &languages.CompilationRequest{
			Language:    languages.LanguageCPP,
			SourceCode:  sourceCode,
			WorkingDir:  tempDir,
			Environment: make(map[string]string),
		},
		Standard:     "c++17",
		CompilerType: CompilerGCC,
		BuildSystem:  BuildSystemDirect,
	}

	// Prepare build files
	ctx := context.Background()
	err = buildSystem.PrepareBuildFiles(ctx, request)
	if err != nil {
		t.Fatalf("Failed to prepare build files: %v", err)
	}

	// Verify source file was created
	sourceFile := filepath.Join(tempDir, "main.cpp")
	if _, err := os.Stat(sourceFile); os.IsNotExist(err) {
		t.Error("Source file was not created")
	}

	// Execute compilation
	response, err := buildSystem.Execute(ctx, request)
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Compilation was not successful: %s", response.ErrorOutput)
	}

	if response.ExecutablePath == "" {
		t.Error("Executable path not set")
	}

	// Verify executable was created
	if _, err := os.Stat(response.ExecutablePath); os.IsNotExist(err) {
		t.Error("Executable was not created")
	}

	// Test metadata
	if response.Metadata["compiler_type"] != string(CompilerGCC) {
		t.Error("Compiler type metadata not set correctly")
	}
}

func TestDirectBuildSystemWithErrors(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cpp-test-error-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	buildSystem := &DirectBuildSystem{compiler: compiler}

	// Test with syntax error
	sourceCode := `
#include <iostream>
int main() {
    std::cout << "Hello, World!" // Missing semicolon and endl
    return 0;
}
`

	request := &CompilationRequest{
		CompilationRequest: &languages.CompilationRequest{
			Language:    languages.LanguageCPP,
			SourceCode:  sourceCode,
			WorkingDir:  tempDir,
			Environment: make(map[string]string),
		},
		Standard:     "c++17",
		CompilerType: CompilerGCC,
		BuildSystem:  BuildSystemDirect,
	}

	ctx := context.Background()
	err = buildSystem.PrepareBuildFiles(ctx, request)
	if err != nil {
		t.Fatalf("Failed to prepare build files: %v", err)
	}

	response, err := buildSystem.Execute(ctx, request)
	if err != nil {
		t.Fatalf("Build system execute failed: %v", err)
	}

	// Should fail due to syntax error
	if response.Success {
		t.Error("Compilation should have failed due to syntax error")
	}

	// Should have error output
	if response.ErrorOutput == "" {
		t.Error("Expected error output for failed compilation")
	}

	// Should have diagnostics
	if len(response.CompilerDiagnostics) == 0 {
		t.Error("Expected compiler diagnostics for failed compilation")
	}
}

func TestDirectBuildSystemWithWarnings(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cpp-test-warning-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	buildSystem := &DirectBuildSystem{compiler: compiler}

	// Test with unused variable warning
	sourceCode := `
#include <iostream>
int main() {
    int unused_variable = 42;
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
`

	request := &CompilationRequest{
		CompilationRequest: &languages.CompilationRequest{
			Language:    languages.LanguageCPP,
			SourceCode:  sourceCode,
			WorkingDir:  tempDir,
			Environment: make(map[string]string),
		},
		Standard:     "c++17",
		CompilerType: CompilerGCC,
		BuildSystem:  BuildSystemDirect,
		WarningLevel: "extra",
	}

	ctx := context.Background()
	err = buildSystem.PrepareBuildFiles(ctx, request)
	if err != nil {
		t.Fatalf("Failed to prepare build files: %v", err)
	}

	response, err := buildSystem.Execute(ctx, request)
	if err != nil {
		t.Fatalf("Build system execute failed: %v", err)
	}

	// Should succeed despite warnings
	if !response.Success {
		t.Errorf("Compilation should have succeeded: %s", response.ErrorOutput)
	}

	// Should have warnings in output
	if response.Output == "" {
		t.Error("Expected warning output")
	}
}

func TestDirectBuildSystemMultipleFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cpp-test-multi-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	buildSystem := &DirectBuildSystem{compiler: compiler}

	// Test with multiple source files
	mainCode := `
#include <iostream>
#include "helper.h"
int main() {
    helper_function();
    return 0;
}
`

	helperCode := `
#include <iostream>
#include "helper.h"
void helper_function() {
    std::cout << "Hello from helper!" << std::endl;
}
`

	headerCode := `
#ifndef HELPER_H
#define HELPER_H
void helper_function();
#endif
`

	request := &CompilationRequest{
		CompilationRequest: &languages.CompilationRequest{
			Language:   languages.LanguageCPP,
			SourceCode: mainCode,
			WorkingDir: tempDir,
			SourceFiles: map[string]string{
				"helper.cpp": helperCode,
			},
			Environment: make(map[string]string),
		},
		Standard:     "c++17",
		CompilerType: CompilerGCC,
		BuildSystem:  BuildSystemDirect,
		HeaderFiles: map[string]string{
			"helper.h": headerCode,
		},
	}

	ctx := context.Background()
	err = buildSystem.PrepareBuildFiles(ctx, request)
	if err != nil {
		t.Fatalf("Failed to prepare build files: %v", err)
	}

	// Verify files were created
	files := []string{"main.cpp", "helper.cpp", "helper.h"}
	for _, file := range files {
		if _, err := os.Stat(filepath.Join(tempDir, file)); os.IsNotExist(err) {
			t.Errorf("File %s was not created", file)
		}
	}

	response, err := buildSystem.Execute(ctx, request)
	if err != nil {
		t.Fatalf("Build system execute failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Multi-file compilation failed: %s", response.ErrorOutput)
	}
}

func TestDirectBuildSystemCompilerFlags(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cpp-test-flags-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	buildSystem := &DirectBuildSystem{compiler: compiler}

	sourceCode := `
#include <iostream>
int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
`

	request := &CompilationRequest{
		CompilationRequest: &languages.CompilationRequest{
			Language:         languages.LanguageCPP,
			SourceCode:       sourceCode,
			WorkingDir:       tempDir,
			Environment:      make(map[string]string),
			OptimizationLevel: "O3",
			DebugSymbols:     true,
		},
		Standard:          "c++20",
		CompilerType:      CompilerGCC,
		BuildSystem:       BuildSystemDirect,
		WarningLevel:      "all",
		WarningsAsErrors:  false,
		ExceptionHandling: true,
		RTTI:              true,
		ThreadingModel:    "pthread",
		Position:          "pic",
		Defines: map[string]string{
			"VERSION": "1.0",
			"DEBUG":   "",
		},
		IncludeDirectories: []string{"/usr/local/include"},
		LibraryDirectories: []string{"/usr/local/lib"},
		Libraries:          []string{"m", "pthread"},
	}

	ctx := context.Background()
	err = buildSystem.PrepareBuildFiles(ctx, request)
	if err != nil {
		t.Fatalf("Failed to prepare build files: %v", err)
	}

	// Test build command generation
	sourceFiles := []string{filepath.Join(tempDir, "main.cpp")}
	args := buildSystem.buildCompileArgs(request, sourceFiles)

	// Verify important flags are present
	argsStr := strings.Join(args, " ")
	
	expectedFlags := []string{
		"-std=c++20",
		"-O3",
		"-g",
		"-Wall",
		"-Wextra",
		"-Wpedantic",
		"-DVERSION=1.0",
		"-DDEBUG",
		"-I/usr/local/include",
		"-L/usr/local/lib",
		"-lm",
		"-lpthread",
		"-pthread",
		"-fPIC",
	}

	for _, flag := range expectedFlags {
		if !strings.Contains(argsStr, flag) {
			t.Errorf("Expected flag %s not found in args: %s", flag, argsStr)
		}
	}
}

func TestMakeBuildSystem(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cpp-test-make-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	buildSystem := &MakeBuildSystem{compiler: compiler}

	// Test detection without Makefile
	if buildSystem.DetectBuildSystem(tempDir) {
		t.Error("Should not detect make build system without Makefile")
	}

	// Create a simple Makefile
	makefile := `
CC = g++
CFLAGS = -Wall -std=c++17
TARGET = test
SOURCES = main.cpp

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

clean:
	rm -f $(TARGET)
`

	makefilePath := filepath.Join(tempDir, "Makefile")
	err = os.WriteFile(makefilePath, []byte(makefile), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Now should detect make build system
	if !buildSystem.DetectBuildSystem(tempDir) {
		t.Error("Should detect make build system with Makefile")
	}

	// Create source file
	sourceCode := `
#include <iostream>
int main() {
    std::cout << "Hello from Make!" << std::endl;
    return 0;
}
`

	sourceFile := filepath.Join(tempDir, "main.cpp")
	err = os.WriteFile(sourceFile, []byte(sourceCode), 0644)
	if err != nil {
		t.Fatal(err)
	}

	request := &CompilationRequest{
		CompilationRequest: &languages.CompilationRequest{
			Language:    languages.LanguageCPP,
			WorkingDir:  tempDir,
			Environment: make(map[string]string),
		},
		CompilerType: CompilerGCC,
		BuildSystem:  BuildSystemMake,
	}

	ctx := context.Background()

	// Test if make is available
	if _, err := os.Stat("/usr/bin/make"); os.IsNotExist(err) {
		t.Skip("Make not available")
	}

	response, err := buildSystem.Execute(ctx, request)
	if err != nil {
		t.Fatalf("Make build failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Make build was not successful: %s", response.ErrorOutput)
	}

	// Verify executable was created
	expectedExe := filepath.Join(tempDir, "test")
	if _, err := os.Stat(expectedExe); os.IsNotExist(err) {
		t.Error("Make did not create expected executable")
	}
}

func TestCMakeBuildSystem(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cpp-test-cmake-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	buildSystem := &CMakeBuildSystem{compiler: compiler}

	// Test detection without CMakeLists.txt
	if buildSystem.DetectBuildSystem(tempDir) {
		t.Error("Should not detect cmake build system without CMakeLists.txt")
	}

	// Create source file
	sourceCode := `
#include <iostream>
int main() {
    std::cout << "Hello from CMake!" << std::endl;
    return 0;
}
`

	sourceFile := filepath.Join(tempDir, "main.cpp")
	err = os.WriteFile(sourceFile, []byte(sourceCode), 0644)
	if err != nil {
		t.Fatal(err)
	}

	request := &CompilationRequest{
		CompilationRequest: &languages.CompilationRequest{
			Language:      languages.LanguageCPP,
			WorkingDir:    tempDir,
			Environment:   make(map[string]string),
			DebugSymbols:  true,
		},
		Standard:     "c++17",
		CompilerType: CompilerGCC,
		BuildSystem:  BuildSystemCMake,
	}

	ctx := context.Background()

	// Test if cmake is available
	if _, err := os.Stat("/usr/bin/cmake"); os.IsNotExist(err) {
		t.Skip("CMake not available")
	}

	// Prepare build files (should generate CMakeLists.txt)
	err = buildSystem.PrepareBuildFiles(ctx, request)
	if err != nil {
		t.Fatalf("Failed to prepare CMake build files: %v", err)
	}

	// Verify CMakeLists.txt was created
	cmakeFile := filepath.Join(tempDir, "CMakeLists.txt")
	if _, err := os.Stat(cmakeFile); os.IsNotExist(err) {
		t.Error("CMakeLists.txt was not generated")
	}

	// Now should detect cmake build system
	if !buildSystem.DetectBuildSystem(tempDir) {
		t.Error("Should detect cmake build system with CMakeLists.txt")
	}

	// Execute build
	response, err := buildSystem.Execute(ctx, request)
	if err != nil {
		t.Fatalf("CMake build failed: %v", err)
	}

	if !response.Success {
		t.Errorf("CMake build was not successful: %s", response.ErrorOutput)
	}

	// Verify build directory was created
	buildDir := filepath.Join(tempDir, "build")
	if _, err := os.Stat(buildDir); os.IsNotExist(err) {
		t.Error("Build directory was not created")
	}

	// Verify executable exists somewhere in build directory
	if response.ExecutablePath == "" {
		t.Error("Executable path not set in response")
	}
}

func TestCompilerDiagnosticParsing(t *testing.T) {
	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	buildSystem := &DirectBuildSystem{compiler: compiler}

	tests := []struct {
		name           string
		output         string
		expectedCount  int
		expectedType   string
		expectedFile   string
		expectedLine   int
		expectedColumn int
	}{
		{
			name:           "GCC error with line and column",
			output:         "main.cpp:5:10: error: expected ';' before 'return'",
			expectedCount:  1,
			expectedType:   "error",
			expectedFile:   "main.cpp",
			expectedLine:   5,
			expectedColumn: 10,
		},
		{
			name:           "GCC warning",
			output:         "main.cpp:3:9: warning: unused variable 'x' [-Wunused-variable]",
			expectedCount:  1,
			expectedType:   "warning",
			expectedFile:   "main.cpp",
			expectedLine:   3,
			expectedColumn: 9,
		},
		{
			name:           "Clang note",
			output:         "main.cpp:8:5: note: candidate function not viable",
			expectedCount:  1,
			expectedType:   "note",
			expectedFile:   "main.cpp",
			expectedLine:   8,
			expectedColumn: 5,
		},
		{
			name: "Multiple diagnostics",
			output: `main.cpp:3:9: warning: unused variable 'x' [-Wunused-variable]
main.cpp:5:10: error: expected ';' before 'return'`,
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diagnostics := buildSystem.parseCompilerOutput(tt.output)

			if len(diagnostics) != tt.expectedCount {
				t.Errorf("Expected %d diagnostics, got %d", tt.expectedCount, len(diagnostics))
			}

			if len(diagnostics) > 0 {
				diag := diagnostics[0]

				if tt.expectedType != "" && diag.Type != tt.expectedType {
					t.Errorf("Expected type %s, got %s", tt.expectedType, diag.Type)
				}

				if tt.expectedFile != "" && diag.File != tt.expectedFile {
					t.Errorf("Expected file %s, got %s", tt.expectedFile, diag.File)
				}

				if tt.expectedLine != 0 && diag.Line != tt.expectedLine {
					t.Errorf("Expected line %d, got %d", tt.expectedLine, diag.Line)
				}

				if tt.expectedColumn != 0 && diag.Column != tt.expectedColumn {
					t.Errorf("Expected column %d, got %d", tt.expectedColumn, diag.Column)
				}
			}
		})
	}
}

func TestCompilationMetrics(t *testing.T) {
	metrics := NewCompilationMetrics()

	// Test initial state
	if metrics.CompilationCount != 0 {
		t.Error("Initial compilation count should be 0")
	}

	if metrics.SuccessfulBuilds != 0 {
		t.Error("Initial successful builds should be 0")
	}

	if metrics.FailedBuilds != 0 {
		t.Error("Initial failed builds should be 0")
	}

	// Record successful compilation
	metrics.RecordCompilation(100*time.Millisecond, true)

	if metrics.CompilationCount != 1 {
		t.Error("Compilation count should be 1")
	}

	if metrics.SuccessfulBuilds != 1 {
		t.Error("Successful builds should be 1")
	}

	if metrics.TotalCompileTime != 100*time.Millisecond {
		t.Error("Total compile time should be 100ms")
	}

	if metrics.AverageCompileTime != 100*time.Millisecond {
		t.Error("Average compile time should be 100ms")
	}

	// Record failed compilation
	metrics.RecordCompilation(200*time.Millisecond, false)

	if metrics.CompilationCount != 2 {
		t.Error("Compilation count should be 2")
	}

	if metrics.SuccessfulBuilds != 1 {
		t.Error("Successful builds should still be 1")
	}

	if metrics.FailedBuilds != 1 {
		t.Error("Failed builds should be 1")
	}

	expectedTotal := 300 * time.Millisecond
	if metrics.TotalCompileTime != expectedTotal {
		t.Errorf("Total compile time should be %v, got %v", expectedTotal, metrics.TotalCompileTime)
	}

	expectedAverage := 150 * time.Millisecond
	if metrics.AverageCompileTime != expectedAverage {
		t.Errorf("Average compile time should be %v, got %v", expectedAverage, metrics.AverageCompileTime)
	}

	// Test cache metrics
	metrics.RecordCacheHit()
	metrics.RecordCacheMiss()

	if metrics.CacheHitCount != 1 {
		t.Error("Cache hit count should be 1")
	}

	if metrics.CacheMissCount != 1 {
		t.Error("Cache miss count should be 1")
	}
}

func TestCPPCompilerInterface(t *testing.T) {
	compiler, err := NewCPPCompiler(CompilerGCC, languages.LanguageCPP)
	if err != nil {
		t.Skipf("GCC not available: %v", err)
	}

	// Test GetSupportedLanguages
	supportedLangs := compiler.GetSupportedLanguages()
	if len(supportedLangs) != 1 {
		t.Error("Should support exactly one language")
	}

	if supportedLangs[0] != languages.LanguageCPP {
		t.Error("Should support C++ language")
	}

	// Test ValidateCompilerAvailability
	ctx := context.Background()
	if err := compiler.ValidateCompilerAvailability(ctx); err != nil {
		t.Errorf("Compiler should be available: %v", err)
	}

	// Test GetCompilerVersion
	version, err := compiler.GetCompilerVersion(ctx)
	if err != nil {
		t.Errorf("Should get compiler version: %v", err)
	}

	if version == "" {
		t.Error("Version should not be empty")
	}
}

func TestCrossCompilationConfig(t *testing.T) {
	crossTarget := &CrossCompileTarget{
		TargetTriple:    "x86_64-linux-gnu",
		TargetArch:      "x86_64",
		TargetOS:        "linux",
		Sysroot:         "/usr/x86_64-linux-gnu",
		ToolchainPrefix: "x86_64-linux-gnu-",
		AdditionalFlags: []string{"-march=native"},
	}

	if crossTarget.TargetTriple != "x86_64-linux-gnu" {
		t.Error("Target triple not set correctly")
	}

	if len(crossTarget.AdditionalFlags) != 1 {
		t.Error("Additional flags not set correctly")
	}
}

func TestDebuggerConfig(t *testing.T) {
	debugConfig := &DebuggerConfig{
		Enabled:      true,
		DebugLevel:   "full",
		DebugFormat:  "dwarf",
		SplitDebug:   true,
		DebuggerType: "gdb",
	}

	if !debugConfig.Enabled {
		t.Error("Debugger should be enabled")
	}

	if debugConfig.DebugLevel != "full" {
		t.Error("Debug level should be 'full'")
	}

	if debugConfig.DebugFormat != "dwarf" {
		t.Error("Debug format should be 'dwarf'")
	}
}

func TestStaticAnalyzerConfig(t *testing.T) {
	analyzerConfig := &StaticAnalyzerConfig{
		Enabled:       true,
		Analyzers:     []string{"clang-tidy", "cppcheck"},
		ConfigFile:    ".clang-tidy",
		FailOnWarning: true,
	}

	if !analyzerConfig.Enabled {
		t.Error("Static analyzer should be enabled")
	}

	if len(analyzerConfig.Analyzers) != 2 {
		t.Error("Should have 2 analyzers configured")
	}

	if !analyzerConfig.FailOnWarning {
		t.Error("Should fail on warning")
	}
}