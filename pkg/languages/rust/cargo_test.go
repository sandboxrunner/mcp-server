package rust

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages"
)

func TestNewCargoCompiler(t *testing.T) {
	tests := []struct {
		name        string
		language    languages.Language
		expectError bool
	}{
		{
			name:        "Rust language",
			language:    languages.LanguageRust,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiler, err := NewCargoCompiler(tt.language)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, but got nil")
				}
				return
			}

			if err != nil {
				t.Skipf("Rust/Cargo not available: %v", err)
				return
			}

			if compiler == nil {
				t.Fatal("Expected compiler, but got nil")
			}

			if compiler.language != tt.language {
				t.Errorf("Expected language %s, got %s", tt.language, compiler.language)
			}

			// Test that commands are set
			if compiler.cargoCommand == "" {
				t.Error("Cargo command not set")
			}

			if compiler.rustcCommand == "" {
				t.Error("Rustc command not set")
			}

			if compiler.targetTriple == "" {
				t.Error("Target triple not set")
			}
		})
	}
}

func TestCargoCompilerFeatures(t *testing.T) {
	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	features := compiler.features
	if features == nil {
		t.Fatal("Features not initialized")
	}

	// Test that features are populated
	if features.RustcVersion == "" {
		t.Error("Rustc version not detected")
	}

	if features.CargoVersion == "" {
		t.Error("Cargo version not detected")
	}

	if features.Edition == "" {
		t.Error("Edition not set")
	}

	if features.HostTriple == "" {
		t.Error("Host triple not set")
	}

	if len(features.OptLevels) == 0 {
		t.Error("No optimization levels available")
	}

	// Test expected optimization levels
	expectedOptLevels := []string{"0", "1", "2", "3", "s", "z"}
	for _, expected := range expectedOptLevels {
		found := false
		for _, level := range features.OptLevels {
			if level == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected optimization level %s not found", expected)
		}
	}

	// Test panic strategies
	if len(features.PanicStrategies) == 0 {
		t.Error("No panic strategies available")
	}

	expectedPanicStrategies := []string{"unwind", "abort"}
	for _, expected := range expectedPanicStrategies {
		found := false
		for _, strategy := range features.PanicStrategies {
			if strategy == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected panic strategy %s not found", expected)
		}
	}
}

func TestCargoCompilerInterface(t *testing.T) {
	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	// Test GetSupportedLanguages
	supportedLangs := compiler.GetSupportedLanguages()
	if len(supportedLangs) != 1 {
		t.Error("Should support exactly one language")
	}

	if supportedLangs[0] != languages.LanguageRust {
		t.Error("Should support Rust language")
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

func TestCargoCompilerSimpleCompilation(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "rust-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	// Create Rust compiler
	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	// Test simple Rust program compilation
	sourceCode := `
fn main() {
    println!("Hello, World!");
}
`

	request := &languages.CompilationRequest{
		Language:    languages.LanguageRust,
		SourceCode:  sourceCode,
		WorkingDir:  tempDir,
		Environment: make(map[string]string),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
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
	if response.Metadata["cargo_command"] == nil {
		t.Error("Cargo command metadata not set")
	}
}

func TestCargoTomlGeneration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rust-cargo-toml-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	request := &RustCompilationRequest{
		CompilationRequest: &languages.CompilationRequest{
			Language:    languages.LanguageRust,
			WorkingDir:  tempDir,
			Environment: make(map[string]string),
		},
		Edition: "2021",
	}

	err = compiler.generateCargoToml(request)
	if err != nil {
		t.Fatalf("Failed to generate Cargo.toml: %v", err)
	}

	// Verify Cargo.toml was created
	cargoTomlPath := filepath.Join(tempDir, "Cargo.toml")
	if _, err := os.Stat(cargoTomlPath); os.IsNotExist(err) {
		t.Error("Cargo.toml was not created")
	}

	// Read and verify contents
	content, err := os.ReadFile(cargoTomlPath)
	if err != nil {
		t.Fatalf("Failed to read Cargo.toml: %v", err)
	}

	contentStr := string(content)
	
	// Check for essential sections
	if !strings.Contains(contentStr, "[package]") {
		t.Error("Cargo.toml should contain [package] section")
	}

	if !strings.Contains(contentStr, "name = \"sandbox-project\"") {
		t.Error("Cargo.toml should contain project name")
	}

	if !strings.Contains(contentStr, "version = \"0.1.0\"") {
		t.Error("Cargo.toml should contain version")
	}

	if !strings.Contains(contentStr, "edition = \"2021\"") {
		t.Error("Cargo.toml should contain edition")
	}

	if !strings.Contains(contentStr, "[[bin]]") {
		t.Error("Cargo.toml should contain binary configuration")
	}

	if !strings.Contains(contentStr, "[dependencies]") {
		t.Error("Cargo.toml should contain dependencies section")
	}
}

func TestCargoCompilerWithFeatures(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rust-features-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	sourceCode := `
#[cfg(feature = "test_feature")]
fn test_function() {
    println!("Test feature is enabled");
}

fn main() {
    #[cfg(feature = "test_feature")]
    test_function();
    
    println!("Hello, World!");
}
`

	// Create custom Cargo.toml with features
	cargoToml := `[package]
name = "feature-test"
version = "0.1.0"
edition = "2021"

[features]
default = []
test_feature = []

[[bin]]
name = "main"
path = "src/main.rs"

[dependencies]
`

	cargoTomlPath := filepath.Join(tempDir, "Cargo.toml")
	if err := os.WriteFile(cargoTomlPath, []byte(cargoToml), 0644); err != nil {
		t.Fatal(err)
	}

	request := &languages.CompilationRequest{
		Language:    languages.LanguageRust,
		SourceCode:  sourceCode,
		WorkingDir:  tempDir,
		Environment: make(map[string]string),
		CustomConfig: map[string]string{
			"features": "test_feature",
		},
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	if err != nil {
		t.Fatalf("Compilation with features failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Compilation with features was not successful: %s", response.ErrorOutput)
	}
}

func TestCargoCompilerWithDependencies(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rust-deps-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	sourceCode := `
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Person {
    name: String,
    age: u32,
}

fn main() {
    let person = Person {
        name: "Alice".to_string(),
        age: 30,
    };
    
    let json = serde_json::to_string(&person).unwrap();
    println!("JSON: {}", json);
}
`

	// Create Cargo.toml with dependencies
	cargoToml := `[package]
name = "deps-test"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "main"
path = "src/main.rs"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
`

	cargoTomlPath := filepath.Join(tempDir, "Cargo.toml")
	if err := os.WriteFile(cargoTomlPath, []byte(cargoToml), 0644); err != nil {
		t.Fatal(err)
	}

	request := &languages.CompilationRequest{
		Language:    languages.LanguageRust,
		SourceCode:  sourceCode,
		WorkingDir:  tempDir,
		Environment: make(map[string]string),
		Timeout:     5 * time.Minute, // Dependencies need more time
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	if err != nil {
		t.Fatalf("Compilation with dependencies failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Compilation with dependencies was not successful: %s", response.ErrorOutput)
	}
}

func TestCargoCompilerReleaseMode(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rust-release-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	sourceCode := `
fn main() {
    println!("Release mode test");
}
`

	request := &languages.CompilationRequest{
		Language:         languages.LanguageRust,
		SourceCode:       sourceCode,
		WorkingDir:       tempDir,
		Environment:      make(map[string]string),
		OptimizationLevel: "3",
		BuildMode:        "release",
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	if err != nil {
		t.Fatalf("Release mode compilation failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Release mode compilation was not successful: %s", response.ErrorOutput)
	}

	// Verify release binary was created
	if response.ExecutablePath == "" {
		t.Error("Release executable path not set")
	}

	// Check that executable is in release directory
	if !strings.Contains(response.ExecutablePath, "release") {
		t.Error("Executable should be in release directory")
	}
}

func TestCargoCompilerWithErrors(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rust-error-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	// Test with syntax error
	sourceCode := `
fn main() {
    println!("Hello, World!"  // Missing closing parenthesis and semicolon
}
`

	request := &languages.CompilationRequest{
		Language:    languages.LanguageRust,
		SourceCode:  sourceCode,
		WorkingDir:  tempDir,
		Environment: make(map[string]string),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	if err != nil {
		t.Fatalf("Compiler error handling failed: %v", err)
	}

	// Should fail due to syntax error
	if response.Success {
		t.Error("Compilation should have failed due to syntax error")
	}

	// Should have error output
	if response.ErrorOutput == "" {
		t.Error("Expected error output for failed compilation")
	}

	// Should have compiler warnings/errors
	if len(response.Warnings) == 0 {
		t.Error("Expected compiler diagnostics for failed compilation")
	}
}

func TestCargoCompilerMultipleFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rust-multi-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	// Test with multiple source files
	mainCode := `
mod helper;

use helper::helper_function;

fn main() {
    helper_function();
}
`

	helperCode := `
pub fn helper_function() {
    println!("Hello from helper!");
}
`

	request := &languages.CompilationRequest{
		Language:   languages.LanguageRust,
		SourceCode: mainCode,
		WorkingDir: tempDir,
		SourceFiles: map[string]string{
			"src/helper.rs": helperCode,
		},
		Environment: make(map[string]string),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	if err != nil {
		t.Fatalf("Multi-file compilation failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Multi-file compilation was not successful: %s", response.ErrorOutput)
	}

	// Verify files were created
	files := []string{"src/main.rs", "src/helper.rs", "Cargo.toml"}
	for _, file := range files {
		if _, err := os.Stat(filepath.Join(tempDir, file)); os.IsNotExist(err) {
			t.Errorf("File %s was not created", file)
		}
	}
}

func TestRustToolchain(t *testing.T) {
	toolchain := NewRustToolchain()

	if toolchain == nil {
		t.Fatal("Expected toolchain, but got nil")
	}

	if toolchain.toolchains == nil {
		t.Error("Toolchains map not initialized")
	}

	if toolchain.components == nil {
		t.Error("Components map not initialized")
	}

	if toolchain.targets == nil {
		t.Error("Targets map not initialized")
	}
}

func TestDependencyManager(t *testing.T) {
	depManager := NewDependencyManager()

	if depManager == nil {
		t.Fatal("Expected dependency manager, but got nil")
	}

	if depManager.resolver == nil {
		t.Error("Dependency resolver not initialized")
	}

	if depManager.resolver.resolutionCache == nil {
		t.Error("Resolution cache not initialized")
	}

	if depManager.resolver.conflictCache == nil {
		t.Error("Conflict cache not initialized")
	}

	if depManager.resolver.updateCache == nil {
		t.Error("Update cache not initialized")
	}
}

func TestCargoBuildCache(t *testing.T) {
	cache := NewCargoBuildCache("", true)

	if cache == nil {
		t.Fatal("Expected cache, but got nil")
	}

	if !cache.enabled {
		t.Error("Cache should be enabled")
	}

	if cache.fingerprints == nil {
		t.Error("Fingerprints map not initialized")
	}

	if cache.artifacts == nil {
		t.Error("Artifacts map not initialized")
	}

	if cache.maxSize == 0 {
		t.Error("Max size should be set")
	}
}

func TestCrossCompiler(t *testing.T) {
	crossCompiler := NewCrossCompiler()

	if crossCompiler == nil {
		t.Fatal("Expected cross compiler, but got nil")
	}

	if crossCompiler.targets == nil {
		t.Error("Targets map not initialized")
	}

	if crossCompiler.linkers == nil {
		t.Error("Linkers map not initialized")
	}

	if crossCompiler.sysroots == nil {
		t.Error("Sysroots map not initialized")
	}

	if crossCompiler.toolchains == nil {
		t.Error("Toolchains map not initialized")
	}
}

func TestRustLinter(t *testing.T) {
	linter := NewRustLinter()

	if linter == nil {
		t.Fatal("Expected linter, but got nil")
	}

	if linter.lintCache == nil {
		t.Error("Lint cache not initialized")
	}

	if linter.customLints == nil {
		t.Error("Custom lints not initialized")
	}

	if linter.allowedLints == nil {
		t.Error("Allowed lints not initialized")
	}

	if linter.deniedLints == nil {
		t.Error("Denied lints not initialized")
	}

	if linter.warnLints == nil {
		t.Error("Warn lints not initialized")
	}
}

func TestRustFormatter(t *testing.T) {
	formatter := NewRustFormatter()

	if formatter == nil {
		t.Fatal("Expected formatter, but got nil")
	}

	if formatter.config == nil {
		t.Error("Formatter config not initialized")
	}

	// Test default configuration
	if formatter.config.MaxWidth != 100 {
		t.Error("Default max width should be 100")
	}

	if formatter.config.TabSpaces != 4 {
		t.Error("Default tab spaces should be 4")
	}

	if formatter.config.HardTabs {
		t.Error("Hard tabs should be false by default")
	}
}

func TestRustProfiler(t *testing.T) {
	profiler := NewRustProfiler()

	if profiler == nil {
		t.Fatal("Expected profiler, but got nil")
	}

	if profiler.profiles == nil {
		t.Error("Profiles map not initialized")
	}

	if profiler.profilerType == "" {
		t.Error("Profiler type not set")
	}

	if profiler.samplingRate == 0 {
		t.Error("Sampling rate not set")
	}
}

func TestRustBenchmarker(t *testing.T) {
	benchmarker := NewRustBenchmarker()

	if benchmarker == nil {
		t.Fatal("Expected benchmarker, but got nil")
	}

	if benchmarker.criteria == nil {
		t.Error("Benchmark criteria not initialized")
	}

	if benchmarker.baselines == nil {
		t.Error("Baselines map not initialized")
	}

	if benchmarker.comparisons == nil {
		t.Error("Comparisons map not initialized")
	}

	// Test default criteria
	if benchmarker.criteria.Iterations == 0 {
		t.Error("Default iterations should be set")
	}

	if benchmarker.criteria.SampleSize == 0 {
		t.Error("Default sample size should be set")
	}
}

func TestRustTestRunner(t *testing.T) {
	testRunner := NewRustTestRunner()

	if testRunner == nil {
		t.Fatal("Expected test runner, but got nil")
	}

	if testRunner.coverage == nil {
		t.Error("Coverage not initialized")
	}

	if testRunner.testResults == nil {
		t.Error("Test results map not initialized")
	}

	if testRunner.coverage.File_coverage == nil {
		t.Error("File coverage map not initialized")
	}
}

func TestRustDocGenerator(t *testing.T) {
	docGen := NewRustDocGenerator()

	if docGen == nil {
		t.Fatal("Expected doc generator, but got nil")
	}

	if docGen.outputDir == "" {
		t.Error("Output directory not set")
	}

	if docGen.theme == "" {
		t.Error("Theme not set")
	}

	if docGen.features == nil {
		t.Error("Features slice not initialized")
	}
}

func TestRustPackager(t *testing.T) {
	packager := NewRustPackager()

	if packager == nil {
		t.Fatal("Expected packager, but got nil")
	}

	if packager.registry == "" {
		t.Error("Registry not set")
	}

	// Default registry should be crates.io
	if packager.registry != "https://crates.io/" {
		t.Error("Default registry should be crates.io")
	}
}

func TestRustSecurityScanner(t *testing.T) {
	scanner := NewRustSecurityScanner()

	if scanner == nil {
		t.Fatal("Expected security scanner, but got nil")
	}

	if scanner.vulnerabilities == nil {
		t.Error("Vulnerabilities slice not initialized")
	}

	if scanner.ignoreList == nil {
		t.Error("Ignore list not initialized")
	}
}

func TestCargoMetrics(t *testing.T) {
	metrics := NewCargoMetrics()

	if metrics == nil {
		t.Fatal("Expected metrics, but got nil")
	}

	// Test initial state
	if metrics.BuildCount != 0 {
		t.Error("Initial build count should be 0")
	}

	if metrics.SuccessfulBuilds != 0 {
		t.Error("Initial successful builds should be 0")
	}

	if metrics.FailedBuilds != 0 {
		t.Error("Initial failed builds should be 0")
	}

	// Record successful compilation
	metrics.RecordCompilation(100*time.Millisecond, true)

	if metrics.BuildCount != 1 {
		t.Error("Build count should be 1")
	}

	if metrics.SuccessfulBuilds != 1 {
		t.Error("Successful builds should be 1")
	}

	if metrics.TotalBuildTime != 100*time.Millisecond {
		t.Error("Total build time should be 100ms")
	}

	if metrics.AverageBuildTime != 100*time.Millisecond {
		t.Error("Average build time should be 100ms")
	}

	// Record failed compilation
	metrics.RecordCompilation(200*time.Millisecond, false)

	if metrics.BuildCount != 2 {
		t.Error("Build count should be 2")
	}

	if metrics.SuccessfulBuilds != 1 {
		t.Error("Successful builds should still be 1")
	}

	if metrics.FailedBuilds != 1 {
		t.Error("Failed builds should be 1")
	}

	expectedTotal := 300 * time.Millisecond
	if metrics.TotalBuildTime != expectedTotal {
		t.Errorf("Total build time should be %v, got %v", expectedTotal, metrics.TotalBuildTime)
	}

	expectedAverage := 150 * time.Millisecond
	if metrics.AverageBuildTime != expectedAverage {
		t.Errorf("Average build time should be %v, got %v", expectedAverage, metrics.AverageBuildTime)
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

// Benchmark tests
func BenchmarkNewCargoCompiler(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewCargoCompiler(languages.LanguageRust)
	}
}

func BenchmarkCargoMetricsRecording(b *testing.B) {
	metrics := NewCargoMetrics()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics.RecordCompilation(time.Millisecond*100, i%2 == 0)
	}
}

// Integration tests (would require actual Rust/Cargo installation)
func TestIntegrationCargoCompilation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This would test actual Cargo compilation
	// Skip if Rust/Cargo is not available
	t.Skip("Integration test requires actual Rust/Cargo installation")
}

func TestIntegrationCargoWithDependencies(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Skip("Integration test requires actual Rust/Cargo installation and network access")
}

// Error handling tests
func TestCargoCompilerInvalidWorkingDir(t *testing.T) {
	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	request := &languages.CompilationRequest{
		Language:    languages.LanguageRust,
		SourceCode:  "fn main() {}",
		WorkingDir:  "/nonexistent/directory",
		Environment: make(map[string]string),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)

	// Should handle invalid directory gracefully
	if err == nil && response.Success {
		t.Error("Expected compilation to fail with invalid working directory")
	}
}

func TestCargoCompilerTimeout(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "rust-timeout-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	compiler, err := NewCargoCompiler(languages.LanguageRust)
	if err != nil {
		t.Skipf("Rust/Cargo not available: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Microsecond)
	defer cancel()

	request := &languages.CompilationRequest{
		Language:    languages.LanguageRust,
		SourceCode:  "fn main() { println!(\"Hello\"); }",
		WorkingDir:  tempDir,
		Environment: make(map[string]string),
		Timeout:     1 * time.Microsecond,
	}

	response, err := compiler.Compile(ctx, request)

	// Should either timeout or fail quickly
	if err == nil && response.Success {
		t.Error("Expected compilation to fail or timeout")
	}
}