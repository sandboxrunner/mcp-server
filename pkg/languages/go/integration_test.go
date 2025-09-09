package go_lang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGoLanguageIntegration tests the full Go language support pipeline
func TestGoLanguageIntegration(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-integration-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	// 1. Initialize Go module
	t.Run("ModuleInitialization", func(t *testing.T) {
		moduleManager := NewModuleManager(tempDir)
		err := moduleManager.InitializeModule(ctx, "integration-test")
		if err != nil {
			t.Fatalf("Failed to initialize module: %v", err)
		}

		// Verify go.mod exists
		goModPath := filepath.Join(tempDir, "go.mod")
		if _, err := os.Stat(goModPath); os.IsNotExist(err) {
			t.Fatalf("go.mod file was not created")
		}
	})

	// 2. Create a complete Go project
	projectFiles := map[string]string{
		"main.go": `package main

import (
	"fmt"
	"math"
)

// Calculator provides mathematical operations
type Calculator struct{}

// Add performs addition
func (c Calculator) Add(a, b float64) float64 {
	return a + b
}

// Multiply performs multiplication
func (c Calculator) Multiply(a, b float64) float64 {
	return a * b
}

// Sqrt calculates square root
func (c Calculator) Sqrt(x float64) float64 {
	if x < 0 {
		return math.NaN()
	}
	return math.Sqrt(x)
}

func main() {
	calc := Calculator{}
	result := calc.Add(2.5, 3.7)
	fmt.Printf("Result: %.2f\n", result)
}
`,
		"main_test.go": `package main

import (
	"math"
	"testing"
)

func TestCalculator_Add(t *testing.T) {
	calc := Calculator{}
	result := calc.Add(2.5, 3.7)
	expected := 6.2
	if math.Abs(result-expected) > 0.001 {
		t.Errorf("Add(2.5, 3.7) = %.3f; want %.3f", result, expected)
	}
}

func TestCalculator_Multiply(t *testing.T) {
	calc := Calculator{}
	result := calc.Multiply(4.0, 2.5)
	expected := 10.0
	if math.Abs(result-expected) > 0.001 {
		t.Errorf("Multiply(4.0, 2.5) = %.3f; want %.3f", result, expected)
	}
}

func TestCalculator_Sqrt(t *testing.T) {
	calc := Calculator{}
	
	// Test positive number
	result := calc.Sqrt(16.0)
	expected := 4.0
	if math.Abs(result-expected) > 0.001 {
		t.Errorf("Sqrt(16.0) = %.3f; want %.3f", result, expected)
	}
	
	// Test negative number
	result = calc.Sqrt(-1.0)
	if !math.IsNaN(result) {
		t.Errorf("Sqrt(-1.0) should return NaN")
	}
}

func BenchmarkCalculator_Add(b *testing.B) {
	calc := Calculator{}
	for i := 0; i < b.N; i++ {
		calc.Add(2.5, 3.7)
	}
}

func BenchmarkCalculator_Multiply(b *testing.B) {
	calc := Calculator{}
	for i := 0; i < b.N; i++ {
		calc.Multiply(4.0, 2.5)
	}
}
`,
		"utils/helper.go": `package utils

import "fmt"

// FormatResult formats a floating point result
func FormatResult(value float64) string {
	return fmt.Sprintf("%.2f", value)
}
`,
		"utils/helper_test.go": `package utils

import "testing"

func TestFormatResult(t *testing.T) {
	result := FormatResult(3.14159)
	expected := "3.14"
	if result != expected {
		t.Errorf("FormatResult(3.14159) = %s; want %s", result, expected)
	}
}
`,
	}

	// Create project files
	for filename, content := range projectFiles {
		filePath := filepath.Join(tempDir, filename)
		
		// Create directory if needed
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create directory for %s: %v", filename, err)
		}
		
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", filename, err)
		}
	}

	// 3. Test module management
	t.Run("ModuleManagement", func(t *testing.T) {
		moduleManager := NewModuleManager(tempDir)
		
		// Add a dependency
		err := moduleManager.AddDependency(ctx, "github.com/stretchr/testify", "latest")
		if err != nil {
			t.Fatalf("Failed to add dependency: %v", err)
		}
		
		// Tidy the module
		err = moduleManager.TidyModule(ctx)
		if err != nil {
			t.Fatalf("Failed to tidy module: %v", err)
		}
		
		// Validate the module
		err = moduleManager.ValidateModule(ctx)
		if err != nil {
			t.Fatalf("Failed to validate module: %v", err)
		}
		
		// Get module info
		info, err := moduleManager.GetModuleInfo(ctx)
		if err != nil {
			t.Fatalf("Failed to get module info: %v", err)
		}
		
		if info.Path != "integration-test" {
			t.Errorf("Expected module path 'integration-test', got '%s'", info.Path)
		}
	})

	// 4. Test building
	t.Run("Building", func(t *testing.T) {
		builder := NewBuilder(tempDir)
		
		// Test standard build
		result, err := builder.Build(ctx)
		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}
		
		if !result.Success {
			t.Errorf("Expected successful build, got failure. Errors: %v", result.Errors)
		}
		
		// Check if binary was created
		binaryPath := filepath.Join(tempDir, "app")
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			t.Errorf("Binary was not created")
		}
		
		// Test cross-compilation
		platforms := []string{"linux-amd64", "windows-amd64"}
		crossResult, err := builder.CrossCompile(ctx, platforms)
		if err != nil {
			t.Fatalf("Cross-compilation failed: %v", err)
		}
		
		if !crossResult.Success {
			t.Errorf("Expected successful cross-compilation")
		}
		
		// Test optimized build
		optResult, err := builder.BuildWithOptimization(ctx, "-N -l", true)
		if err != nil {
			t.Fatalf("Optimized build failed: %v", err)
		}
		
		if !optResult.Success {
			t.Errorf("Expected successful optimized build")
		}
	})

	// 5. Test testing
	t.Run("Testing", func(t *testing.T) {
		runner := NewTestRunner(tempDir)
		
		// Run tests
		result, err := runner.RunTests(ctx)
		if err != nil {
			t.Fatalf("Test execution failed: %v", err)
		}
		
		if !result.Success {
			t.Errorf("Expected successful test run, got failure. Errors: %v", result.FailedTests)
		}
		
		// Check test summary
		if result.Summary.TotalTests < 3 {
			t.Errorf("Expected at least 3 tests, got %d", result.Summary.TotalTests)
		}
		
		// Run tests with coverage
		runner.EnableCoverage("set", "coverage.out")
		coverageResult, err := runner.RunTests(ctx)
		if err != nil {
			t.Fatalf("Test execution with coverage failed: %v", err)
		}
		
		if !coverageResult.Success {
			t.Errorf("Expected successful test run with coverage")
		}
		
		// Check coverage report
		if coverageResult.Coverage == nil {
			t.Errorf("Expected coverage report to be generated")
		}
		
		// Run benchmarks
		benchResult, err := runner.RunBenchmarks(ctx, "BenchmarkCalculator")
		if err != nil {
			t.Fatalf("Benchmark execution failed: %v", err)
		}
		
		if !benchResult.Success {
			t.Errorf("Expected successful benchmark run")
		}
		
		if len(benchResult.Benchmarks) == 0 {
			t.Errorf("Expected benchmark results to be captured")
		}
	})

	// 6. Test analysis
	t.Run("Analysis", func(t *testing.T) {
		analyzer := NewAnalyzer(tempDir)
		
		// Run basic analysis
		result, err := analyzer.Analyze(ctx)
		if err != nil {
			t.Fatalf("Analysis failed: %v", err)
		}
		
		if result.Duration == 0 {
			t.Errorf("Expected non-zero analysis duration")
		}
		
		// Run vet analysis only
		vetResult, err := analyzer.RunVetOnly(ctx)
		if err != nil {
			t.Fatalf("Vet analysis failed: %v", err)
		}
		
		if vetResult.Duration == 0 {
			t.Errorf("Expected non-zero vet analysis duration")
		}
	})

	// 7. Test end-to-end workflow
	t.Run("EndToEndWorkflow", func(t *testing.T) {
		// Simulate a complete development workflow
		
		// 1. Module management
		moduleManager := NewModuleManager(tempDir)
		err := moduleManager.TidyModule(ctx)
		if err != nil {
			t.Fatalf("Failed to tidy module in workflow: %v", err)
		}
		
		// 2. Code analysis
		analyzer := NewAnalyzer(tempDir)
		analysisResult, err := analyzer.Analyze(ctx)
		if err != nil {
			t.Fatalf("Analysis failed in workflow: %v", err)
		}
		
		// 3. Testing
		runner := NewTestRunner(tempDir)
		runner.EnableCoverage("set", "coverage.out")
		testResult, err := runner.RunTests(ctx)
		if err != nil {
			t.Fatalf("Testing failed in workflow: %v", err)
		}
		
		if !testResult.Success {
			t.Errorf("Tests failed in workflow")
		}
		
		// 4. Building
		builder := NewBuilder(tempDir)
		buildResult, err := builder.Build(ctx)
		if err != nil {
			t.Fatalf("Build failed in workflow: %v", err)
		}
		
		if !buildResult.Success {
			t.Errorf("Build failed in workflow")
		}
		
		// 5. Verify all components worked together
		if analysisResult.Duration == 0 {
			t.Errorf("Analysis duration should be non-zero")
		}
		
		if testResult.Coverage == nil {
			t.Errorf("Coverage should be available")
		}
		
		if buildResult.BinarySize == 0 {
			t.Errorf("Binary size should be non-zero")
		}
	})
}

// TestGoLanguagePerformance tests performance characteristics
func TestGoLanguagePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-performance-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	// Initialize module
	moduleManager := NewModuleManager(tempDir)
	err = moduleManager.InitializeModule(ctx, "performance-test")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Create a larger Go project for performance testing
	mainCode := `package main

import "fmt"

func fibonacci(n int) int {
	if n <= 1 {
		return n
	}
	return fibonacci(n-1) + fibonacci(n-2)
}

func main() {
	result := fibonacci(10)
	fmt.Printf("Fibonacci(10) = %d\n", result)
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	testCode := `package main

import "testing"

func TestFibonacci(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{0, 0},
		{1, 1},
		{2, 1},
		{3, 2},
		{4, 3},
		{5, 5},
		{10, 55},
	}

	for _, test := range tests {
		result := fibonacci(test.input)
		if result != test.expected {
			t.Errorf("fibonacci(%d) = %d; want %d", test.input, result, test.expected)
		}
	}
}

func BenchmarkFibonacci10(b *testing.B) {
	for i := 0; i < b.N; i++ {
		fibonacci(10)
	}
}

func BenchmarkFibonacci20(b *testing.B) {
	for i := 0; i < b.N; i++ {
		fibonacci(20)
	}
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main_test.go"), []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test build performance
	t.Run("BuildPerformance", func(t *testing.T) {
		builder := NewBuilder(tempDir)
		
		start := time.Now()
		result, err := builder.Build(ctx)
		duration := time.Since(start)
		
		if err != nil {
			t.Fatalf("Build failed: %v", err)
		}
		
		if !result.Success {
			t.Errorf("Build was not successful")
		}
		
		// Build should complete in reasonable time (adjust threshold as needed)
		if duration > 30*time.Second {
			t.Errorf("Build took too long: %v", duration)
		}
		
		t.Logf("Build completed in %v", duration)
	})

	// Test testing performance
	t.Run("TestingPerformance", func(t *testing.T) {
		runner := NewTestRunner(tempDir)
		
		start := time.Now()
		result, err := runner.RunTests(ctx)
		duration := time.Since(start)
		
		if err != nil {
			t.Fatalf("Test execution failed: %v", err)
		}
		
		if !result.Success {
			t.Errorf("Tests were not successful")
		}
		
		// Tests should complete in reasonable time
		if duration > 30*time.Second {
			t.Errorf("Tests took too long: %v", duration)
		}
		
		t.Logf("Tests completed in %v", duration)
	})

	// Test analysis performance
	t.Run("AnalysisPerformance", func(t *testing.T) {
		analyzer := NewAnalyzer(tempDir)
		
		start := time.Now()
		result, err := analyzer.Analyze(ctx)
		duration := time.Since(start)
		
		if err != nil {
			t.Fatalf("Analysis failed: %v", err)
		}
		
		// Analysis should complete in reasonable time
		if duration > 60*time.Second {
			t.Errorf("Analysis took too long: %v", duration)
		}
		
		t.Logf("Analysis completed in %v", duration)
		t.Logf("Analysis summary: %+v", result.Summary)
	})
}

// TestGoLanguageErrorHandling tests error handling across components
func TestGoLanguageErrorHandling(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-errors-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	// Test module management errors
	t.Run("ModuleErrors", func(t *testing.T) {
		// Test with non-existent directory
		badManager := NewModuleManager("/non/existent/directory")
		err := badManager.InitializeModule(ctx, "test")
		if err == nil {
			t.Errorf("Expected error with non-existent directory")
		}
	})

	// Test build errors
	t.Run("BuildErrors", func(t *testing.T) {
		// Create invalid Go code
		invalidCode := `package main

func main() {
	undefinedFunction() // This will cause a build error
}
`
		err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(invalidCode), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid code: %v", err)
		}

		// Initialize module
		moduleManager := NewModuleManager(tempDir)
		err = moduleManager.InitializeModule(ctx, "error-test")
		if err != nil {
			t.Fatalf("Failed to initialize module: %v", err)
		}

		// Try to build invalid code
		builder := NewBuilder(tempDir)
		result, err := builder.Build(ctx)
		if err == nil {
			t.Errorf("Expected build error with invalid code")
		}
		
		if result.Success {
			t.Errorf("Build should not succeed with invalid code")
		}
		
		if len(result.Errors) == 0 {
			t.Errorf("Expected build errors to be captured")
		}
	})

	// Test testing errors
	t.Run("TestingErrors", func(t *testing.T) {
		// Create test with failure
		testCode := `package main

import "testing"

func TestFailure(t *testing.T) {
	t.Errorf("This test is designed to fail")
}
`
		err := os.WriteFile(filepath.Join(tempDir, "main_test.go"), []byte(testCode), 0644)
		if err != nil {
			t.Fatalf("Failed to write test code: %v", err)
		}

		runner := NewTestRunner(tempDir)
		result, err := runner.RunTests(ctx)
		if err != nil {
			t.Fatalf("Test execution failed: %v", err)
		}
		
		if result.Success {
			t.Errorf("Tests should fail with failing test")
		}
		
		if len(result.FailedTests) == 0 {
			t.Errorf("Expected failed tests to be reported")
		}
	})
}

// TestGoLanguageConcurrency tests concurrent operations
func TestGoLanguageConcurrency(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-concurrency-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	ctx := context.Background()

	// Initialize module
	moduleManager := NewModuleManager(tempDir)
	err = moduleManager.InitializeModule(ctx, "concurrency-test")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Create a simple Go program
	mainCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Concurrency!")
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	testCode := `package main

import "testing"

func TestConcurrency(t *testing.T) {
	// Simple test
	if 1+1 != 2 {
		t.Errorf("Math is broken")
	}
}
`
	err = os.WriteFile(filepath.Join(tempDir, "main_test.go"), []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Run concurrent operations
	numOperations := 5
	done := make(chan string, numOperations)
	errors := make(chan error, numOperations)

	// Concurrent builds
	go func() {
		builder := NewBuilder(tempDir)
		result, err := builder.Build(ctx)
		if err != nil {
			errors <- err
			return
		}
		if !result.Success {
			errors <- fmt.Errorf("build failed")
			return
		}
		done <- "build"
	}()

	// Concurrent tests
	go func() {
		runner := NewTestRunner(tempDir)
		result, err := runner.RunTests(ctx)
		if err != nil {
			errors <- err
			return
		}
		if !result.Success {
			errors <- fmt.Errorf("tests failed")
			return
		}
		done <- "test"
	}()

	// Concurrent analysis
	go func() {
		analyzer := NewAnalyzer(tempDir)
		_, err := analyzer.Analyze(ctx)
		if err != nil {
			errors <- err
			return
		}
		done <- "analyze"
	}()

	// Concurrent module operations
	go func() {
		manager := NewModuleManager(tempDir)
		err := manager.TidyModule(ctx)
		if err != nil {
			errors <- err
			return
		}
		done <- "tidy"
	}()

	go func() {
		manager := NewModuleManager(tempDir)
		err := manager.ValidateModule(ctx)
		if err != nil {
			errors <- err
			return
		}
		done <- "validate"
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

	t.Logf("Completed operations: %v", operations)
	
	if len(operations) < numOperations {
		t.Errorf("Expected %d successful operations, got %d", numOperations, len(operations))
	}
}