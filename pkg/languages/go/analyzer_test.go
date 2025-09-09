package go_lang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzer_Analyze(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-analyze-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program with some issues
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import (
	"fmt"
	"os"     // unused import
	"strings" // unused import
)

func main() {
	fmt.Println("Hello, Analysis!")
}

func unusedFunction() {
	// This function is not used
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-analyze")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run analysis
	analyzer := NewAnalyzer(tempDir)
	result, err := analyzer.Analyze(ctx)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if result.Duration == 0 {
		t.Errorf("Expected non-zero analysis duration")
	}

	// Check that vet analysis was run
	if len(result.VetResults) == 0 && result.Summary.VetIssues == 0 {
		// This might be expected if no vet issues are found
		t.Logf("No vet issues found (this may be expected)")
	}

	// Check summary
	if result.Summary.TotalIssues < 0 {
		t.Errorf("Total issues should be non-negative")
	}
}

func TestAnalyzer_RunVetOnly(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-vet-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Go program with vet issues
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import "fmt"

func main() {
	var x int
	if x = 1; x == 1 {
		fmt.Printf("Value: %d\n", x)
	}
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-vet")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run vet analysis only
	analyzer := NewAnalyzer(tempDir)
	result, err := analyzer.RunVetOnly(ctx)
	if err != nil {
		t.Fatalf("Vet analysis failed: %v", err)
	}

	if !result.Success && len(result.Errors) > 0 {
		// Vet found issues, which is expected
		t.Logf("Vet analysis completed with issues: %v", result.Errors)
	}

	// Check that other analyses were not run
	if len(result.StaticResults) > 0 {
		t.Errorf("Expected no staticcheck results in vet-only analysis")
	}

	if len(result.LintResults) > 0 {
		t.Errorf("Expected no lint results in vet-only analysis")
	}
}

func TestAnalyzer_RunRaceDetection(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-race-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create Go program with potential race condition
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import (
	"sync"
	"time"
)

var counter int

func increment() {
	counter++
}

func main() {
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			increment()
		}()
	}
	wg.Wait()
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	testFile := filepath.Join(tempDir, "main_test.go")
	testCode := `package main

import "testing"

func TestRace(t *testing.T) {
	main()
}
`
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-race")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run race detection
	analyzer := NewAnalyzer(tempDir)
	result, err := analyzer.RunRaceDetection(ctx)
	if err != nil {
		t.Fatalf("Race detection failed: %v", err)
	}

	// Check if race detection output is captured
	if raceOutput, exists := result.RawOutput["race"]; exists {
		if strings.Contains(raceOutput, "WARNING: DATA RACE") {
			t.Logf("Race condition detected as expected")
		}
	}
}

func TestAnalyzer_ValidateConfig(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")

	// Test valid config
	err := analyzer.ValidateConfig()
	if err != nil {
		t.Errorf("Valid config should not produce error: %v", err)
	}

	// Test with nil config
	analyzer.config = nil
	err = analyzer.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with nil config")
	}

	// Test with empty packages
	analyzer.config = &AnalysisConfig{
		Packages: []string{},
	}
	err = analyzer.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with empty packages")
	}
}

func TestAnalyzer_Configuration(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")

	// Test default configuration
	defaultConfig := NewDefaultAnalysisConfig()
	if len(defaultConfig.Packages) != 1 || defaultConfig.Packages[0] != "./..." {
		t.Errorf("Expected default packages to be ['./...']")
	}

	if !defaultConfig.EnableVet {
		t.Errorf("Expected vet to be enabled by default")
	}

	if defaultConfig.StaticCheck.Enabled {
		t.Errorf("Expected staticcheck to be disabled by default")
	}

	if defaultConfig.Timeout != 10*time.Minute {
		t.Errorf("Expected default timeout to be 10 minutes")
	}

	// Test setting configuration
	customConfig := &AnalysisConfig{
		Packages:    []string{"./pkg/..."},
		EnableVet:   true,
		EnableRace:  true,
		Timeout:     5 * time.Minute,
		Parallel:    2,
		Environment: map[string]string{"GO_ENV": "test"},
		StaticCheck: StaticCheckConfig{
			Enabled: true,
			Checks:  []string{"SA1019", "SA4006"},
		},
		GolangCILint: GolangCIConfig{
			Enabled:        true,
			EnabledLinters: []string{"golint", "vet"},
		},
	}

	analyzer.SetConfig(customConfig)
	if len(analyzer.config.Packages) != 1 || analyzer.config.Packages[0] != "./pkg/..." {
		t.Errorf("Custom packages not set correctly")
	}

	if !analyzer.config.EnableRace {
		t.Errorf("Race detection not enabled in custom config")
	}

	if !analyzer.config.StaticCheck.Enabled {
		t.Errorf("Staticcheck not enabled in custom config")
	}
}

func TestAnalyzer_VerboseMode(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")

	// Test verbose mode
	analyzer.SetVerbose(true)
	if !analyzer.verbose {
		t.Errorf("Verbose mode should be enabled")
	}

	analyzer.SetVerbose(false)
	if analyzer.verbose {
		t.Errorf("Verbose mode should be disabled")
	}
}

func TestAnalyzer_ParseVetOutput(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")
	result := &AnalysisResult{
		VetResults: []VetIssue{},
	}

	// Sample vet output
	output := `main.go:10:5: printf: fmt.Printf format %s has arg x of wrong type int
main.go:15:2: unreachable code
./test.go:5:1: exported function TestFunc should have comment or be unexported`

	analyzer.parseVetOutput(output, result)

	if len(result.VetResults) != 3 {
		t.Errorf("Expected 3 vet issues, got %d", len(result.VetResults))
	}

	// Check first issue
	issue := result.VetResults[0]
	if issue.File != "main.go" {
		t.Errorf("Expected file 'main.go', got '%s'", issue.File)
	}

	if issue.Line != 10 {
		t.Errorf("Expected line 10, got %d", issue.Line)
	}

	if issue.Column != 5 {
		t.Errorf("Expected column 5, got %d", issue.Column)
	}

	if !strings.Contains(issue.Message, "printf") {
		t.Errorf("Expected message to contain 'printf', got '%s'", issue.Message)
	}
}

func TestAnalyzer_ParseStaticCheckOutput(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")
	result := &AnalysisResult{
		StaticResults: []StaticCheckIssue{},
	}

	// Sample staticcheck output
	output := `main.go:5:2: SA1019: package io/ioutil is deprecated
test.go:10:1: SA4006: this value of x is never used
helper.go:20:5: SA1020: this receiver name should be a reflection of its identity`

	analyzer.parseStaticCheckOutput(output, result)

	if len(result.StaticResults) != 3 {
		t.Errorf("Expected 3 staticcheck issues, got %d", len(result.StaticResults))
	}

	// Check first issue
	issue := result.StaticResults[0]
	if issue.File != "main.go" {
		t.Errorf("Expected file 'main.go', got '%s'", issue.File)
	}

	if issue.Line != 5 {
		t.Errorf("Expected line 5, got %d", issue.Line)
	}

	if issue.Check != "SA1019" {
		t.Errorf("Expected check 'SA1019', got '%s'", issue.Check)
	}

	if !strings.Contains(issue.Message, "deprecated") {
		t.Errorf("Expected message to contain 'deprecated', got '%s'", issue.Message)
	}
}

func TestAnalyzer_ParseGolangCILintOutput(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")
	result := &AnalysisResult{
		LintResults: []LintIssue{},
	}

	// Sample golangci-lint JSON output
	jsonOutput := `{
		"Issues": [
			{
				"FromLinter": "golint",
				"Text": "exported function Add should have comment or be unexported",
				"Severity": "warning",
				"Pos": {
					"Filename": "main.go",
					"Line": 5,
					"Column": 1
				}
			},
			{
				"FromLinter": "ineffassign",
				"Text": "ineffectual assignment to x",
				"Severity": "warning",
				"Pos": {
					"Filename": "test.go",
					"Line": 10,
					"Column": 2
				}
			}
		]
	}`

	analyzer.parseGolangCILintOutput(jsonOutput, result)

	if len(result.LintResults) != 2 {
		t.Errorf("Expected 2 lint issues, got %d", len(result.LintResults))
	}

	// Check first issue
	issue := result.LintResults[0]
	if issue.File != "main.go" {
		t.Errorf("Expected file 'main.go', got '%s'", issue.File)
	}

	if issue.Line != 5 {
		t.Errorf("Expected line 5, got %d", issue.Line)
	}

	if issue.Linter != "golint" {
		t.Errorf("Expected linter 'golint', got '%s'", issue.Linter)
	}

	if issue.Severity != "warning" {
		t.Errorf("Expected severity 'warning', got '%s'", issue.Severity)
	}
}

func TestAnalyzer_ParseRaceDetectionOutput(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")
	result := &AnalysisResult{
		Warnings: []string{},
	}

	// Sample race detection output
	output := `WARNING: DATA RACE
Write at 0x00c000012345 by goroutine 7:
  main.increment()
      /path/to/main.go:10 +0x44

Previous read at 0x00c000012345 by main goroutine:
  main.main()
      /path/to/main.go:20 +0x88

Goroutine 7 (running) created at:
  main.main()
      /path/to/main.go:18 +0x7c
==================
Found 1 data race(s)`

	analyzer.parseRaceDetectionOutput(output, result)

	if len(result.Warnings) == 0 {
		t.Errorf("Expected race detection warnings to be captured")
	}

	// Check that race warning was captured
	found := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "WARNING: DATA RACE") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected race detection warning to be captured")
	}
}

func TestAnalyzer_CalculateSummary(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")
	result := &AnalysisResult{
		VetResults: []VetIssue{
			{Severity: "warning"},
			{Severity: "error"},
		},
		StaticResults: []StaticCheckIssue{
			{Severity: "warning"},
			{Severity: "info"},
		},
		LintResults: []LintIssue{
			{Severity: "error"},
			{Severity: "warning"},
			{Severity: "info"},
		},
		Summary: AnalysisSummary{},
	}

	analyzer.calculateSummary(result)

	if result.Summary.VetIssues != 2 {
		t.Errorf("Expected 2 vet issues, got %d", result.Summary.VetIssues)
	}

	if result.Summary.StaticIssues != 2 {
		t.Errorf("Expected 2 static issues, got %d", result.Summary.StaticIssues)
	}

	if result.Summary.LintIssues != 3 {
		t.Errorf("Expected 3 lint issues, got %d", result.Summary.LintIssues)
	}

	if result.Summary.TotalIssues != 7 {
		t.Errorf("Expected 7 total issues, got %d", result.Summary.TotalIssues)
	}

	if result.Summary.CriticalIssues != 2 {
		t.Errorf("Expected 2 critical issues, got %d", result.Summary.CriticalIssues)
	}

	if result.Summary.WarningIssues != 3 {
		t.Errorf("Expected 3 warning issues, got %d", result.Summary.WarningIssues)
	}

	if result.Summary.InfoIssues != 2 {
		t.Errorf("Expected 2 info issues, got %d", result.Summary.InfoIssues)
	}
}

func TestAnalyzer_BuildEnvironment(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")
	analyzer.config.Environment = map[string]string{
		"CUSTOM_VAR": "test_value",
		"GO_ENV":     "testing",
	}

	env := analyzer.buildEnvironment()

	// Check that GO111MODULE is set
	found := false
	for _, envVar := range env {
		if envVar == "GO111MODULE=on" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected GO111MODULE=on to be set in environment")
	}

	// Check custom environment variables
	customFound := false
	for _, envVar := range env {
		if envVar == "CUSTOM_VAR=test_value" {
			customFound = true
			break
		}
	}

	if !customFound {
		t.Errorf("Expected custom environment variable to be set")
	}
}

// Benchmark tests
func BenchmarkAnalyzer_Analyze(b *testing.B) {
	// Setup
	tempDir, err := os.MkdirTemp("", "bench-go-analyze-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Benchmark!")
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		b.Fatalf("Failed to write main.go: %v", err)
	}

	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "bench-analyze")
	if err != nil {
		b.Fatalf("Failed to initialize module: %v", err)
	}

	analyzer := NewAnalyzer(tempDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		result, err := analyzer.Analyze(ctx)
		b.StopTimer()

		if err != nil {
			b.Fatalf("Analysis failed: %v", err)
		}

		if result.Duration == 0 {
			b.Fatalf("Expected non-zero analysis duration")
		}
	}
}

// Test error cases
func TestAnalyzer_ErrorCases(t *testing.T) {
	// Test with non-existent directory
	analyzer := NewAnalyzer("/non/existent/directory")
	ctx := context.Background()

	result, err := analyzer.Analyze(ctx)
	if err == nil && result.Success {
		t.Errorf("Expected error with non-existent directory")
	}

	// Test with invalid Go code
	tempDir, err := os.MkdirTemp("", "test-go-analyze-error-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mainFile := filepath.Join(tempDir, "main.go")
	invalidCode := `package main

func main() {
	undefinedFunction() // This will cause analysis issues
}
`
	err = os.WriteFile(mainFile, []byte(invalidCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	err = moduleManager.InitializeModule(ctx, "test-analyze-error")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	analyzer = NewAnalyzer(tempDir)
	result, err = analyzer.Analyze(ctx)
	if err != nil {
		// This is expected - analysis should report the error
		t.Logf("Analysis failed as expected: %v", err)
	}

	if result.Success && len(result.Errors) == 0 {
		t.Errorf("Expected analysis to report errors for invalid code")
	}
}

// Test concurrent analyses
func TestAnalyzer_ConcurrentAnalyses(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-concurrent-analyze-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Concurrent Analysis!")
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-concurrent-analyze")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run concurrent analyses
	numAnalyses := 3
	done := make(chan bool, numAnalyses)
	errors := make(chan error, numAnalyses)

	for i := 0; i < numAnalyses; i++ {
		go func(analysisID int) {
			analyzer := NewAnalyzer(tempDir)
			result, err := analyzer.Analyze(ctx)
			if err != nil {
				errors <- err
				return
			}
			
			if result.Duration == 0 {
				errors <- fmt.Errorf("analysis %d had zero duration", analysisID)
				return
			}
			
			done <- true
		}(i)
	}

	// Wait for all analyses to complete
	timeout := time.After(120 * time.Second)
	completed := 0
	
	for completed < numAnalyses {
		select {
		case <-done:
			completed++
		case err := <-errors:
			t.Errorf("Concurrent analysis failed: %v", err)
			completed++
		case <-timeout:
			t.Fatalf("Concurrent analyses timed out")
		}
	}
}

// Test analysis with various configurations
func TestAnalyzer_VariousConfigurations(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-config-analyze-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainFile := filepath.Join(tempDir, "main.go")
	mainCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Configuration!")
}
`
	err = os.WriteFile(mainFile, []byte(mainCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-config-analyze")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	testConfigs := []struct {
		name   string
		config *AnalysisConfig
	}{
		{
			name: "VetOnly",
			config: &AnalysisConfig{
				Packages:  []string{"./..."},
				EnableVet: true,
				Timeout:   30 * time.Second,
			},
		},
		{
			name: "WithProfiling",
			config: &AnalysisConfig{
				Packages:        []string{"./..."},
				EnableVet:       true,
				EnableCPUProf:   true,
				EnableMemProf:   true,
				EnableBlockProf: true,
				Timeout:         30 * time.Second,
			},
		},
		{
			name: "WithCodeGen",
			config: &AnalysisConfig{
				Packages:  []string{"./..."},
				EnableVet: true,
				CodeGen: CodeGenConfig{
					Enabled:    true,
					GoGenerate: true,
				},
				Timeout: 30 * time.Second,
			},
		},
	}

	for _, tc := range testConfigs {
		t.Run(tc.name, func(t *testing.T) {
			analyzer := NewAnalyzer(tempDir)
			analyzer.SetConfig(tc.config)

			result, err := analyzer.Analyze(ctx)
			if err != nil {
				t.Errorf("Analysis failed for config %s: %v", tc.name, err)
				return
			}

			if result.Duration == 0 {
				t.Errorf("Expected non-zero duration for config %s", tc.name)
			}

			// Check that the analysis ran
			if len(result.RawOutput) == 0 {
				t.Errorf("Expected some raw output for config %s", tc.name)
			}
		})
	}
}

// Test count severity function
func TestAnalyzer_CountSeverity(t *testing.T) {
	analyzer := NewAnalyzer("/tmp")
	summary := &AnalysisSummary{}

	// Test counting different severities
	analyzer.countSeverity("error", summary)
	analyzer.countSeverity("critical", summary)
	analyzer.countSeverity("warning", summary)
	analyzer.countSeverity("warn", summary)
	analyzer.countSeverity("info", summary)
	analyzer.countSeverity("note", summary)
	analyzer.countSeverity("unknown", summary)

	if summary.CriticalIssues != 2 {
		t.Errorf("Expected 2 critical issues, got %d", summary.CriticalIssues)
	}

	if summary.WarningIssues != 2 {
		t.Errorf("Expected 2 warning issues, got %d", summary.WarningIssues)
	}

	if summary.InfoIssues != 2 {
		t.Errorf("Expected 2 info issues, got %d", summary.InfoIssues)
	}
}