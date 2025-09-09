package go_lang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTestRunner_RunTests(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-testing-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program with tests
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import "fmt"

func Add(a, b int) int {
	return a + b
}

func main() {
	fmt.Println("Hello, Testing!")
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	testFile := filepath.Join(tempDir, "main_test.go")
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
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main_test.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-testing")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run tests
	runner := NewTestRunner(tempDir)
	result, err := runner.RunTests(ctx)
	if err != nil {
		t.Fatalf("Test execution failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful test run, got failure. Errors: %v", result.FailedTests)
	}

	if result.Duration == 0 {
		t.Errorf("Expected non-zero test duration")
	}

	// Check test summary
	if result.Summary.TotalTests < 2 {
		t.Errorf("Expected at least 2 tests, got %d", result.Summary.TotalTests)
	}

	if result.Summary.PassedTests < 2 {
		t.Errorf("Expected at least 2 passed tests, got %d", result.Summary.PassedTests)
	}
}

func TestTestRunner_RunTestsWithCoverage(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-coverage-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program with tests
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import "fmt"

func Add(a, b int) int {
	return a + b
}

func Multiply(a, b int) int {
	return a * b
}

func main() {
	fmt.Println("Hello, Coverage!")
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	testFile := filepath.Join(tempDir, "main_test.go")
	testCode := `package main

import "testing"

func TestAdd(t *testing.T) {
	result := Add(2, 3)
	expected := 5
	if result != expected {
		t.Errorf("Add(2, 3) = %d; want %d", result, expected)
	}
}

// Note: Multiply function is not tested, so coverage won't be 100%
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main_test.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-coverage")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run tests with coverage
	runner := NewTestRunner(tempDir)
	runner.EnableCoverage("set", "coverage.out")
	
	result, err := runner.RunTests(ctx)
	if err != nil {
		t.Fatalf("Test execution with coverage failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful test run with coverage, got failure")
	}

	// Check if coverage profile was generated
	coverageFile := filepath.Join(tempDir, "coverage.out")
	if _, err := os.Stat(coverageFile); os.IsNotExist(err) {
		t.Errorf("Coverage profile was not generated")
	}

	// Check if coverage report was parsed
	if result.Coverage == nil {
		t.Errorf("Expected coverage report to be generated")
	} else {
		if result.Coverage.Mode != "set" {
			t.Errorf("Expected coverage mode 'set', got '%s'", result.Coverage.Mode)
		}
		
		if result.Coverage.Percentage == 0 {
			t.Errorf("Expected non-zero coverage percentage")
		}
	}
}

func TestTestRunner_RunBenchmarks(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-bench-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program with benchmarks
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import "fmt"

func Add(a, b int) int {
	return a + b
}

func main() {
	fmt.Println("Hello, Benchmarks!")
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	benchFile := filepath.Join(tempDir, "main_test.go")
	benchCode := `package main

import "testing"

func BenchmarkAdd(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Add(2, 3)
	}
}

func BenchmarkAddLarge(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Add(1000000, 2000000)
	}
}
`
	err = os.WriteFile(benchFile, []byte(benchCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write bench_test.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-benchmarks")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run benchmarks
	runner := NewTestRunner(tempDir)
	result, err := runner.RunBenchmarks(ctx, "BenchmarkAdd")
	if err != nil {
		t.Fatalf("Benchmark execution failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful benchmark run, got failure")
	}

	// Check benchmark results
	if len(result.Benchmarks) == 0 {
		t.Errorf("Expected benchmark results to be captured")
	}

	for _, bench := range result.Benchmarks {
		if bench.Iterations == 0 {
			t.Errorf("Expected non-zero iterations for benchmark %s", bench.Name)
		}
		if bench.NsPerOp == 0 {
			t.Errorf("Expected non-zero ns/op for benchmark %s", bench.Name)
		}
	}
}

func TestTestRunner_DiscoverTests(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-discover-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program with tests
	testFile := filepath.Join(tempDir, "main_test.go")
	testCode := `package main

import "testing"

func TestFunction1(t *testing.T) {
	// Test implementation
}

func TestFunction2(t *testing.T) {
	// Test implementation
}

func BenchmarkFunction1(b *testing.B) {
	// Benchmark implementation
}

func ExampleFunction1() {
	// Example implementation
}
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-discover")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Discover tests
	runner := NewTestRunner(tempDir)
	tests, err := runner.DiscoverTests(ctx)
	if err != nil {
		t.Fatalf("Test discovery failed: %v", err)
	}

	if len(tests) == 0 {
		t.Errorf("Expected to discover tests")
	}

	// Check for expected test names
	expectedTests := []string{"TestFunction1", "TestFunction2", "BenchmarkFunction1", "ExampleFunction1"}
	for _, expected := range expectedTests {
		found := false
		for _, test := range tests {
			if test == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected test %s not discovered", expected)
		}
	}
}

func TestTestRunner_RunSingleTest(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-single-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program with tests
	testFile := filepath.Join(tempDir, "main_test.go")
	testCode := `package main

import "testing"

func TestSuccess(t *testing.T) {
	// This test should pass
}

func TestFailure(t *testing.T) {
	t.Errorf("This test is designed to fail")
}
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-single")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run single successful test
	runner := NewTestRunner(tempDir)
	result, err := runner.RunSingleTest(ctx, "", "TestSuccess")
	if err != nil {
		t.Fatalf("Single test execution failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected TestSuccess to pass")
	}

	// Run single failing test
	result, err = runner.RunSingleTest(ctx, "", "TestFailure")
	if err != nil {
		t.Fatalf("Single test execution failed: %v", err)
	}

	if result.Success {
		t.Errorf("Expected TestFailure to fail")
	}

	if len(result.FailedTests) == 0 {
		t.Errorf("Expected failed test to be reported")
	}
}

func TestTestRunner_ValidateConfig(t *testing.T) {
	runner := NewTestRunner("/tmp")

	// Test valid config
	err := runner.ValidateConfig()
	if err != nil {
		t.Errorf("Valid config should not produce error: %v", err)
	}

	// Test with nil config
	runner.config = nil
	err = runner.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with nil config")
	}

	// Test with empty packages
	runner.config = &TestConfig{
		Packages: []string{},
	}
	err = runner.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with empty packages")
	}

	// Test with invalid coverage mode
	runner.config = &TestConfig{
		Packages:  []string{"./..."},
		Cover:     true,
		CoverMode: "invalid-mode",
	}
	err = runner.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with invalid coverage mode")
	}
}

func TestTestRunner_Configuration(t *testing.T) {
	runner := NewTestRunner("/tmp")

	// Test default configuration
	defaultConfig := NewDefaultTestConfig()
	if len(defaultConfig.Packages) != 1 || defaultConfig.Packages[0] != "./..." {
		t.Errorf("Expected default packages to be ['./...']")
	}

	if defaultConfig.CoverMode != "set" {
		t.Errorf("Expected default coverage mode to be 'set'")
	}

	if defaultConfig.Timeout != 10*time.Minute {
		t.Errorf("Expected default timeout to be 10 minutes")
	}

	// Test setting configuration
	customConfig := &TestConfig{
		Packages:  []string{"./pkg/..."},
		Verbose:   true,
		Race:      true,
		Cover:     true,
		CoverMode: "atomic",
		Timeout:   5 * time.Minute,
	}

	runner.SetConfig(customConfig)
	if runner.config.Verbose != true {
		t.Errorf("Expected verbose to be true after setting config")
	}

	if runner.config.Race != true {
		t.Errorf("Expected race to be true after setting config")
	}

	if runner.config.CoverMode != "atomic" {
		t.Errorf("Expected coverage mode to be 'atomic' after setting config")
	}
}

func TestTestRunner_ProfilingSettings(t *testing.T) {
	runner := NewTestRunner("/tmp")

	// Test enabling profiling
	runner.EnableProfiling("cpu.prof", "mem.prof", "block.prof", "mutex.prof", "trace.out")

	if runner.config.CPUProfile != "cpu.prof" {
		t.Errorf("CPU profile not set correctly")
	}

	if runner.config.MemProfile != "mem.prof" {
		t.Errorf("Memory profile not set correctly")
	}

	if runner.config.BlockProfile != "block.prof" {
		t.Errorf("Block profile not set correctly")
	}

	if runner.config.MutexProfile != "mutex.prof" {
		t.Errorf("Mutex profile not set correctly")
	}

	if runner.config.TraceProfile != "trace.out" {
		t.Errorf("Trace profile not set correctly")
	}
}

func TestTestRunner_CoverageSettings(t *testing.T) {
	runner := NewTestRunner("/tmp")

	// Test enabling coverage
	runner.EnableCoverage("count", "coverage.out")

	if !runner.config.Cover {
		t.Errorf("Coverage should be enabled")
	}

	if runner.config.CoverMode != "count" {
		t.Errorf("Coverage mode should be 'count'")
	}

	if runner.config.CoverProfile != "coverage.out" {
		t.Errorf("Coverage profile should be 'coverage.out'")
	}
}

func TestTestRunner_VerboseMode(t *testing.T) {
	runner := NewTestRunner("/tmp")

	// Test verbose mode
	runner.SetVerbose(true)
	if !runner.verbose {
		t.Errorf("Verbose mode should be enabled")
	}

	runner.SetVerbose(false)
	if runner.verbose {
		t.Errorf("Verbose mode should be disabled")
	}
}

// Test parsing functionality
func TestTestRunner_ParseTestOutput(t *testing.T) {
	runner := NewTestRunner("/tmp")
	result := &TestResult{
		PackageResults: []PackageTestResult{},
		FailedTests:    []TestFailure{},
		SkippedTests:   []string{},
		Benchmarks:     []BenchmarkResult{},
		Summary:        TestSummary{},
	}

	// Sample test output
	output := `=== RUN   TestAdd
--- PASS: TestAdd (0.00s)
=== RUN   TestMultiply
--- FAIL: TestMultiply (0.00s)
    main_test.go:15: Multiply(2, 3) = 7; want 6
=== RUN   TestSkipped
--- SKIP: TestSkipped (0.00s)
    main_test.go:20: Skipping this test
BenchmarkAdd-8    	1000000000	         0.25 ns/op
ok  	test-package	0.123s	coverage: 75.0% of statements`

	err := runner.parseTestOutput(output, result)
	if err != nil {
		t.Fatalf("Failed to parse test output: %v", err)
	}

	// Check parsed results
	if result.Summary.PassedTests != 1 {
		t.Errorf("Expected 1 passed test, got %d", result.Summary.PassedTests)
	}

	if result.Summary.FailedTests != 1 {
		t.Errorf("Expected 1 failed test, got %d", result.Summary.FailedTests)
	}

	if result.Summary.SkippedTests != 1 {
		t.Errorf("Expected 1 skipped test, got %d", result.Summary.SkippedTests)
	}

	if len(result.Benchmarks) != 1 {
		t.Errorf("Expected 1 benchmark, got %d", len(result.Benchmarks))
	}

	if len(result.PackageResults) != 1 {
		t.Errorf("Expected 1 package result, got %d", len(result.PackageResults))
	}

	packageResult := result.PackageResults[0]
	if packageResult.Package != "test-package" {
		t.Errorf("Expected package 'test-package', got '%s'", packageResult.Package)
	}

	if packageResult.Coverage != 75.0 {
		t.Errorf("Expected coverage 75.0%%, got %.1f%%", packageResult.Coverage)
	}
}

// Benchmark tests
func BenchmarkTestRunner_RunTests(b *testing.B) {
	// Setup
	tempDir, err := os.MkdirTemp("", "bench-go-test-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "main_test.go")
	testCode := `package main

import "testing"

func TestSimple(t *testing.T) {
	if 1+1 != 2 {
		t.Errorf("Math is broken")
	}
}
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		b.Fatalf("Failed to write test file: %v", err)
	}

	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "bench-test")
	if err != nil {
		b.Fatalf("Failed to initialize module: %v", err)
	}

	runner := NewTestRunner(tempDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		result, err := runner.RunTests(ctx)
		b.StopTimer()

		if err != nil {
			b.Fatalf("Test run failed: %v", err)
		}

		if !result.Success {
			b.Fatalf("Test run was not successful")
		}
	}
}

// Test error cases
func TestTestRunner_ErrorCases(t *testing.T) {
	// Test with non-existent directory
	runner := NewTestRunner("/non/existent/directory")
	ctx := context.Background()

	_, err := runner.RunTests(ctx)
	if err == nil {
		t.Errorf("Expected error with non-existent directory")
	}

	// Test with invalid test code
	tempDir, err := os.MkdirTemp("", "test-go-error-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "main_test.go")
	invalidCode := `package main

import "testing"

func TestInvalid(t *testing.T) {
	undefinedFunction() // This will cause a compilation error
}
`
	err = os.WriteFile(testFile, []byte(invalidCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	err = moduleManager.InitializeModule(ctx, "test-error")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	runner = NewTestRunner(tempDir)
	result, err := runner.RunTests(ctx)
	if err == nil {
		t.Errorf("Expected error with invalid test code")
	}

	if result.Success {
		t.Errorf("Expected test run to fail with invalid code")
	}
}

// Test concurrent test runs
func TestTestRunner_ConcurrentRuns(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-concurrent-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple test
	testFile := filepath.Join(tempDir, "main_test.go")
	testCode := `package main

import (
	"testing"
	"time"
)

func TestConcurrent(t *testing.T) {
	time.Sleep(10 * time.Millisecond) // Small delay to simulate work
	if 1+1 != 2 {
		t.Errorf("Math is broken")
	}
}
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-concurrent")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run concurrent tests
	numRuns := 3
	done := make(chan bool, numRuns)
	errors := make(chan error, numRuns)

	for i := 0; i < numRuns; i++ {
		go func(runID int) {
			runner := NewTestRunner(tempDir)
			result, err := runner.RunTests(ctx)
			if err != nil {
				errors <- err
				return
			}
			
			if !result.Success {
				errors <- fmt.Errorf("test run %d failed", runID)
				return
			}
			
			done <- true
		}(i)
	}

	// Wait for all test runs to complete
	timeout := time.After(60 * time.Second)
	completed := 0
	
	for completed < numRuns {
		select {
		case <-done:
			completed++
		case err := <-errors:
			t.Errorf("Concurrent test run failed: %v", err)
			completed++
		case <-timeout:
			t.Fatalf("Concurrent test runs timed out")
		}
	}
}

// Test coverage report generation
func TestTestRunner_CoverageReportGeneration(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-cov-report-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program with tests
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

func Covered() int {
	return 42
}

func NotCovered() int {
	return 0
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	testFile := filepath.Join(tempDir, "main_test.go")
	testCode := `package main

import "testing"

func TestCovered(t *testing.T) {
	result := Covered()
	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}
}

// NotCovered() is not tested
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-cov-report")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Create coverage profile manually (simulating go test -cover output)
	coverageProfile := filepath.Join(tempDir, "coverage.out")
	coverageData := `mode: set
test-cov-report/main.go:3.17,5.2 1 1
test-cov-report/main.go:7.20,9.2 1 0
`
	err = os.WriteFile(coverageProfile, []byte(coverageData), 0644)
	if err != nil {
		t.Fatalf("Failed to write coverage profile: %v", err)
	}

	// Test coverage report generation
	runner := NewTestRunner(tempDir)
	runner.config.CoverProfile = "coverage.out"
	
	coverage, err := runner.generateCoverageReport(ctx)
	if err != nil {
		t.Fatalf("Failed to generate coverage report: %v", err)
	}

	if coverage.Mode != "set" {
		t.Errorf("Expected coverage mode 'set', got '%s'", coverage.Mode)
	}

	if coverage.TotalLines == 0 {
		t.Errorf("Expected non-zero total lines")
	}

	if coverage.Percentage == 0 {
		t.Errorf("Expected non-zero coverage percentage")
	}

	if len(coverage.Packages) == 0 {
		t.Errorf("Expected at least one package in coverage report")
	}
}

// Test profile file collection
func TestTestRunner_ProfileFileCollection(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-profiles-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	runner := NewTestRunner(tempDir)
	
	// Configure profiling
	runner.config.CPUProfile = "cpu.prof"
	runner.config.MemProfile = "mem.prof"
	runner.config.BlockProfile = "block.prof"
	runner.config.MutexProfile = "mutex.prof"
	runner.config.TraceProfile = "trace.out"

	// Create dummy profile files
	profileFiles := []string{"cpu.prof", "mem.prof", "block.prof", "mutex.prof", "trace.out"}
	for _, file := range profileFiles {
		profilePath := filepath.Join(tempDir, file)
		err := os.WriteFile(profilePath, []byte("dummy profile data"), 0644)
		if err != nil {
			t.Fatalf("Failed to create profile file %s: %v", file, err)
		}
	}

	result := &TestResult{
		ProfileFiles: make(map[string]string),
	}

	// Test profile file collection
	runner.collectProfileFiles(result)

	expectedProfiles := map[string]string{
		"cpu":   "cpu.prof",
		"mem":   "mem.prof",
		"block": "block.prof",
		"mutex": "mutex.prof",
		"trace": "trace.out",
	}

	for profileType, expectedFile := range expectedProfiles {
		if actualPath, exists := result.ProfileFiles[profileType]; !exists {
			t.Errorf("Profile type %s not found in results", profileType)
		} else {
			expectedPath := filepath.Join(tempDir, expectedFile)
			if actualPath != expectedPath {
				t.Errorf("Profile path mismatch for %s: expected %s, got %s", profileType, expectedPath, actualPath)
			}
		}
	}
}