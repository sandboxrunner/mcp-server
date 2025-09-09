package go_lang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGoLanguageSupport_Initialize(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Go language support instance
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	// Test initialization
	config := GetDefaultProjectConfig("test-support")
	result, err := gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful initialization, got failure: %v", result.Error)
	}

	if result.Operation != "initialize" {
		t.Errorf("Expected operation 'initialize', got '%s'", result.Operation)
	}

	if result.Duration == 0 {
		t.Errorf("Expected non-zero duration")
	}

	if !gls.initialized {
		t.Errorf("Expected initialized flag to be true")
	}

	// Check if go.mod was created
	goModPath := filepath.Join(tempDir, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		t.Errorf("go.mod file was not created")
	}
}

func TestGoLanguageSupport_FullWorkflow(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-workflow-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a complete Go project
	projectFiles := map[string]string{
		"main.go": `package main

import "fmt"

func Add(a, b int) int {
	return a + b
}

func main() {
	result := Add(2, 3)
	fmt.Printf("Result: %d\n", result)
}
`,
		"main_test.go": `package main

import "testing"

func TestAdd(t *testing.T) {
	result := Add(2, 3)
	expected := 5
	if result != expected {
		t.Errorf("Add(2, 3) = %d; want %d", result, expected)
	}
}

func BenchmarkAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Add(2, 3)
	}
}
`,
	}

	// Create project files
	for filename, content := range projectFiles {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", filename, err)
		}
	}

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-workflow")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test full workflow
	result, err := gls.FullWorkflow(ctx)
	if err != nil {
		t.Fatalf("Full workflow failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful workflow, got failure: %v", result.Error)
	}

	if result.Operation != "full_workflow" {
		t.Errorf("Expected operation 'full_workflow', got '%s'", result.Operation)
	}

	// Check workflow metadata
	workflow, exists := result.Metadata["workflow"]
	if !exists {
		t.Errorf("Expected workflow metadata to be present")
	}

	workflowMap, ok := workflow.(map[string]interface{})
	if !ok {
		t.Errorf("Expected workflow metadata to be a map")
	}

	// Check that all workflow steps are present
	expectedSteps := []string{"analysis", "testing", "building"}
	for _, step := range expectedSteps {
		if _, exists := workflowMap[step]; !exists {
			t.Errorf("Expected workflow step '%s' to be present", step)
		}
	}

	// Check if binary was created
	if result.BinaryPath == "" {
		t.Errorf("Expected binary path to be set")
	}
}

func TestGoLanguageSupport_Build(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-build-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Build Support!")
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-build-support")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test build
	result, err := gls.Build(ctx)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful build, got failure: %v", result.Error)
	}

	if result.Operation != "build" {
		t.Errorf("Expected operation 'build', got '%s'", result.Operation)
	}

	if result.BinaryPath == "" {
		t.Errorf("Expected binary path to be set")
	}

	// Check metadata
	if binarySize, exists := result.Metadata["binary_size"]; !exists || binarySize == 0 {
		t.Errorf("Expected binary size to be set and non-zero")
	}

	// Check if binary file exists
	if _, err := os.Stat(result.BinaryPath); os.IsNotExist(err) {
		t.Errorf("Binary file does not exist at %s", result.BinaryPath)
	}
}

func TestGoLanguageSupport_Test(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-test-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Go program with tests
	mainCode := `package main

func Add(a, b int) int {
	return a + b
}

func main() {
	// Main function
}
`
	testCode := `package main

import "testing"

func TestAdd(t *testing.T) {
	result := Add(2, 3)
	expected := 5
	if result != expected {
		t.Errorf("Add(2, 3) = %d; want %d", result, expected)
	}
}

func TestAddNegative(t *testing.T) {
	result := Add(-1, 1)
	expected := 0
	if result != expected {
		t.Errorf("Add(-1, 1) = %d; want %d", result, expected)
	}
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "main_test.go"), []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-test-support")
	config.EnableCoverage = true
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test testing
	result, err := gls.Test(ctx)
	if err != nil {
		t.Fatalf("Test execution failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful tests, got failure: %v", result.Error)
	}

	if result.Operation != "test" {
		t.Errorf("Expected operation 'test', got '%s'", result.Operation)
	}

	// Check test summary
	testSummary, exists := result.Metadata["test_summary"]
	if !exists {
		t.Errorf("Expected test summary to be present")
	}

	summary, ok := testSummary.(TestSummary)
	if !ok {
		t.Errorf("Expected test summary to be of correct type")
	}

	if summary.TotalTests < 2 {
		t.Errorf("Expected at least 2 tests, got %d", summary.TotalTests)
	}

	// Check coverage
	if result.CoverageFile == "" {
		t.Errorf("Expected coverage file to be set")
	}

	if coveragePercentage, exists := result.Metadata["coverage_percentage"]; !exists {
		t.Errorf("Expected coverage percentage to be present")
	} else {
		if percentage, ok := coveragePercentage.(float64); !ok || percentage < 0 {
			t.Errorf("Expected valid coverage percentage")
		}
	}
}

func TestGoLanguageSupport_Analyze(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-analyze-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Go program
	mainCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Analysis!")
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-analyze-support")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test analysis
	result, err := gls.Analyze(ctx)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if result.Operation != "analyze" {
		t.Errorf("Expected operation 'analyze', got '%s'", result.Operation)
	}

	// Check analysis summary
	analysisSummary, exists := result.Metadata["analysis_summary"]
	if !exists {
		t.Errorf("Expected analysis summary to be present")
	}

	summary, ok := analysisSummary.(AnalysisSummary)
	if !ok {
		t.Errorf("Expected analysis summary to be of correct type")
	}

	if summary.TotalIssues < 0 {
		t.Errorf("Total issues should be non-negative")
	}
}

func TestGoLanguageSupport_CrossCompile(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-cross-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Cross-Compile!")
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-cross-support")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test cross-compilation
	platforms := []string{"linux-amd64", "windows-amd64"}
	result, err := gls.CrossCompile(ctx, platforms)
	if err != nil {
		t.Fatalf("Cross-compilation failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful cross-compilation, got failure: %v", result.Error)
	}

	if result.Operation != "cross_compile" {
		t.Errorf("Expected operation 'cross_compile', got '%s'", result.Operation)
	}

	// Check that files were created
	if len(result.Files) != len(platforms) {
		t.Errorf("Expected %d output files, got %d", len(platforms), len(result.Files))
	}

	// Check metadata
	if platformsBuilt, exists := result.Metadata["platforms"]; !exists {
		t.Errorf("Expected platforms metadata to be present")
	} else {
		if platforms, ok := platformsBuilt.([]string); !ok || len(platforms) != len(platforms) {
			t.Errorf("Expected platforms metadata to match input")
		}
	}
}

func TestGoLanguageSupport_RunBenchmarks(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-bench-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Go program with benchmarks
	mainCode := `package main

func Add(a, b int) int {
	return a + b
}

func main() {
	// Main function
}
`
	benchCode := `package main

import "testing"

func BenchmarkAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Add(2, 3)
	}
}

func BenchmarkAddLarge(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Add(1000, 2000)
	}
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "main_test.go"), []byte(benchCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write benchmark file: %v", err)
	}

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-bench-support")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test benchmarks
	result, err := gls.RunBenchmarks(ctx, "BenchmarkAdd")
	if err != nil {
		t.Fatalf("Benchmark execution failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful benchmarks, got failure: %v", result.Error)
	}

	if result.Operation != "benchmark" {
		t.Errorf("Expected operation 'benchmark', got '%s'", result.Operation)
	}

	// Check benchmarks metadata
	if totalBenchmarks, exists := result.Metadata["total_benchmarks"]; !exists {
		t.Errorf("Expected total benchmarks metadata to be present")
	} else {
		if count, ok := totalBenchmarks.(int); !ok || count == 0 {
			t.Errorf("Expected non-zero benchmark count")
		}
	}
}

func TestGoLanguageSupport_GetProjectInfo(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-info-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-info-support")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test get project info
	result, err := gls.GetProjectInfo(ctx)
	if err != nil {
		t.Fatalf("Get project info failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful project info retrieval, got failure: %v", result.Error)
	}

	if result.Operation != "project_info" {
		t.Errorf("Expected operation 'project_info', got '%s'", result.Operation)
	}

	// Check module info
	moduleInfo, exists := result.Metadata["module_info"]
	if !exists {
		t.Errorf("Expected module info to be present")
	}

	if moduleInfo, ok := moduleInfo.(*ModuleInfo); !ok || moduleInfo.Path != "test-info-support" {
		t.Errorf("Expected correct module info")
	}

	// Check dependencies
	if dependencyCount, exists := result.Metadata["dependency_count"]; !exists {
		t.Errorf("Expected dependency count to be present")
	} else {
		if count, ok := dependencyCount.(int); !ok || count < 0 {
			t.Errorf("Expected valid dependency count")
		}
	}
}

func TestGoLanguageSupport_ValidateProject(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-validate-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-validate-support")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test project validation
	result, err := gls.ValidateProject(ctx)
	if err != nil {
		t.Fatalf("Project validation failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful project validation, got failure: %v", result.Error)
	}

	if result.Operation != "validate" {
		t.Errorf("Expected operation 'validate', got '%s'", result.Operation)
	}

	// Check validation issues
	if issuesCount, exists := result.Metadata["issues_count"]; !exists {
		t.Errorf("Expected issues count to be present")
	} else {
		if count, ok := issuesCount.(int); !ok || count < 0 {
			t.Errorf("Expected valid issues count")
		}
	}
}

func TestGoLanguageSupport_Clean(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-clean-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-clean-support")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Test clean
	result, err := gls.Clean(ctx)
	if err != nil {
		t.Fatalf("Clean failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful clean, got failure: %v", result.Error)
	}

	if result.Operation != "clean" {
		t.Errorf("Expected operation 'clean', got '%s'", result.Operation)
	}
}

func TestGoLanguageSupport_ErrorHandling(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-error-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Go language support instance without initialization
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	// Test operations without initialization - should fail
	operations := []func() (*GoOperationResult, error){
		func() (*GoOperationResult, error) { return gls.Build(ctx) },
		func() (*GoOperationResult, error) { return gls.Test(ctx) },
		func() (*GoOperationResult, error) { return gls.Analyze(ctx) },
		func() (*GoOperationResult, error) { return gls.CrossCompile(ctx, []string{"linux-amd64"}) },
		func() (*GoOperationResult, error) { return gls.RunBenchmarks(ctx, "") },
		func() (*GoOperationResult, error) { return gls.Clean(ctx) },
		func() (*GoOperationResult, error) { return gls.GetProjectInfo(ctx) },
		func() (*GoOperationResult, error) { return gls.FullWorkflow(ctx) },
		func() (*GoOperationResult, error) { return gls.ValidateProject(ctx) },
	}

	for i, operation := range operations {
		result, err := operation()
		if err == nil {
			t.Errorf("Operation %d should fail without initialization", i)
		}

		if result.Success {
			t.Errorf("Operation %d should not succeed without initialization", i)
		}
	}
}

func TestGetDefaultProjectConfig(t *testing.T) {
	modulePath := "test-default-config"
	config := GetDefaultProjectConfig(modulePath)

	if config.ModulePath != modulePath {
		t.Errorf("Expected module path '%s', got '%s'", modulePath, config.ModulePath)
	}

	if config.GoVersion == "" {
		t.Errorf("Expected Go version to be set")
	}

	if config.BuildConfig == nil {
		t.Errorf("Expected build config to be set")
	}

	if config.TestConfig == nil {
		t.Errorf("Expected test config to be set")
	}

	if config.AnalysisConfig == nil {
		t.Errorf("Expected analysis config to be set")
	}

	if config.Timeout == 0 {
		t.Errorf("Expected timeout to be set")
	}

	if !config.EnableCoverage {
		t.Errorf("Expected coverage to be enabled by default")
	}

	if !config.CacheEnabled {
		t.Errorf("Expected cache to be enabled by default")
	}
}

func TestCreateProjectWithDefaults(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-defaults-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Test project creation with defaults
	gls, err := CreateProjectWithDefaults(tempDir, "test-defaults")
	if err != nil {
		t.Fatalf("Failed to create project with defaults: %v", err)
	}

	if !gls.initialized {
		t.Errorf("Expected project to be initialized")
	}

	// Check if go.mod was created
	goModPath := filepath.Join(tempDir, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		t.Errorf("go.mod file was not created")
	}
}

// Benchmark tests
func BenchmarkGoLanguageSupport_Initialize(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tempDir, err := os.MkdirTemp("", "bench-go-init-*")
		if err != nil {
			b.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		gls := NewGoLanguageSupport(tempDir)
		ctx := context.Background()
		config := GetDefaultProjectConfig("bench-init")

		b.StartTimer()
		result, err := gls.Initialize(ctx, config)
		b.StopTimer()

		if err != nil {
			b.Fatalf("Initialize failed: %v", err)
		}

		if !result.Success {
			b.Fatalf("Initialize was not successful")
		}
	}
}

func BenchmarkGoLanguageSupport_FullWorkflow(b *testing.B) {
	// Setup
	tempDir, err := os.MkdirTemp("", "bench-go-workflow-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create simple Go files
	mainCode := `package main
import "fmt"
func Add(a, b int) int { return a + b }
func main() { fmt.Println(Add(2, 3)) }
`
	testCode := `package main
import "testing"
func TestAdd(t *testing.T) {
	if Add(2, 3) != 5 {
		t.Errorf("Add failed")
	}
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		b.Fatalf("Failed to write main.go: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "main_test.go"), []byte(testCode), 0644)
	if err != nil {
		b.Fatalf("Failed to write test file: %v", err)
	}

	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()
	config := GetDefaultProjectConfig("bench-workflow")

	_, err = gls.Initialize(ctx, config)
	if err != nil {
		b.Fatalf("Failed to initialize: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		result, err := gls.FullWorkflow(ctx)
		b.StopTimer()

		if err != nil {
			b.Fatalf("Full workflow failed: %v", err)
		}

		if !result.Success {
			b.Fatalf("Full workflow was not successful")
		}

		// Clean up binary for next iteration
		if result.BinaryPath != "" {
			os.Remove(result.BinaryPath)
		}
	}
}

// Test concurrent operations
func TestGoLanguageSupport_ConcurrentOperations(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-concurrent-support-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create simple Go files
	mainCode := `package main
import "fmt"
func main() { fmt.Println("Hello, Concurrent!") }
`
	testCode := `package main
import "testing"
func TestSimple(t *testing.T) {
	if 1+1 != 2 {
		t.Errorf("Math is broken")
	}
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "main_test.go"), []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Go language support
	gls := NewGoLanguageSupport(tempDir)
	ctx := context.Background()

	config := GetDefaultProjectConfig("test-concurrent-support")
	_, err = gls.Initialize(ctx, config)
	if err != nil {
		t.Fatalf("Failed to initialize Go support: %v", err)
	}

	// Run concurrent operations
	numOperations := 3
	done := make(chan string, numOperations)
	errors := make(chan error, numOperations)

	// Concurrent builds with different output names
	go func() {
		// Create a copy with different config to avoid conflicts
		gls2 := NewGoLanguageSupport(tempDir)
		config2 := GetDefaultProjectConfig("test-concurrent-support")
		config2.BuildConfig.Targets[0].Output = "app-1"
		_, err := gls2.Initialize(ctx, config2)
		if err != nil {
			errors <- fmt.Errorf("initialization failed: %v", err)
			return
		}
		
		result, err := gls2.Build(ctx)
		if err != nil || !result.Success {
			errors <- fmt.Errorf("build failed: %v", err)
			return
		}
		done <- "build"
	}()

	// Concurrent tests
	go func() {
		result, err := gls.Test(ctx)
		if err != nil || !result.Success {
			errors <- fmt.Errorf("test failed: %v", err)
			return
		}
		done <- "test"
	}()

	// Concurrent analysis
	go func() {
		_, err := gls.Analyze(ctx)
		if err != nil {
			errors <- fmt.Errorf("analyze failed: %v", err)
			return
		}
		done <- "analyze"
	}()

	// Wait for all operations to complete
	timeout := time.After(120 * time.Second)
	completed := 0
	operations := make([]string, 0, numOperations)

	for completed < numOperations {
		select {
		case operation := <-done:
			operations = append(operations, operation)
			completed++
		case err := <-errors:
			t.Errorf("Concurrent operation failed: %v", err)
			completed++
		case <-timeout:
			t.Fatalf("Concurrent operations timed out")
		}
	}

	if len(operations) < numOperations {
		t.Errorf("Expected %d successful operations, got %d", numOperations, len(operations))
	}

	t.Logf("Completed concurrent operations: %v", operations)
}