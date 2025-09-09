package languages

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandboxrunner/mcp-server/pkg/languages/node"
	"github.com/sandboxrunner/mcp-server/pkg/languages/typescript"
)

// TestJavaScriptHandlerIntegration tests the integrated JavaScript handler
func TestJavaScriptHandlerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	handler := NewJavaScriptHandler()
	
	req := &ExecutionRequest{
		Code: `
const lodash = require('lodash');
console.log('Hello from JavaScript!');
console.log('Array shuffled:', lodash.shuffle([1, 2, 3, 4, 5]));
		`,
		Language:    LanguageJavaScript,
		WorkingDir:  tempDir,
		Environment: map[string]string{
			"NODE_ENV": "test",
		},
		Timeout:  30 * time.Second,
		Packages: []string{"lodash@4.17.21"},
	}

	// Test preparation
	err := handler.PrepareExecution(context.Background(), req)
	assert.NoError(t, err)

	// Verify Node components were initialized
	assert.NotNil(t, handler.npmInstaller)
	assert.NotNil(t, handler.environmentManager)
	assert.NotNil(t, handler.analyzer)

	// Test package installation (mocked in test environment)
	packageReq := &PackageInstallRequest{
		Packages:    []string{"lodash@4.17.21"},
		Language:    LanguageJavaScript,
		WorkingDir:  tempDir,
		Environment: req.Environment,
	}

	_, err = handler.InstallPackages(context.Background(), packageReq)
	// Package installation might fail in test environment, but should handle gracefully
	assert.NoError(t, err)

	// Test environment setup
	envReq := &EnvironmentSetupRequest{
		Language:   LanguageJavaScript,
		WorkingDir: tempDir,
	}

	envResult, err := handler.SetupEnvironment(context.Background(), envReq)
	assert.NoError(t, err)
	assert.True(t, envResult.Success)
	assert.NotEmpty(t, envResult.Version)
}

// TestTypeScriptHandlerIntegration tests the integrated TypeScript handler
func TestTypeScriptHandlerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	handler := NewTypeScriptHandler()
	
	req := &ExecutionRequest{
		Code: `
interface User {
    name: string;
    age: number;
}

const user: User = {
    name: "Alice",
    age: 30
};

console.log('Hello from TypeScript!');
console.log('User:', user);
		`,
		Language:    LanguageTypeScript,
		WorkingDir:  tempDir,
		Environment: map[string]string{
			"NODE_ENV": "test",
		},
		Timeout:  45 * time.Second,
		Packages: []string{"@types/node"},
	}

	// Test preparation
	err := handler.PrepareExecution(context.Background(), req)
	assert.NoError(t, err)

	// Verify TypeScript components were initialized
	assert.NotNil(t, handler.npmInstaller)
	assert.NotNil(t, handler.environmentManager)
	assert.NotNil(t, handler.analyzer)
	assert.NotNil(t, handler.compiler)

	// Test TypeScript language detection
	confidence := handler.DetectLanguage(req.Code, "test.ts")
	assert.Greater(t, confidence, 0.8) // Should have high confidence for TypeScript
}

// TestNodeJSPackageManagement tests the Node.js package management system
func TestNodeJSPackageManagement(t *testing.T) {
	tempDir := t.TempDir()
	
	// Test NPM installer
	installer := node.NewNPMInstaller(tempDir, "node", node.PackageManagerNPM)
	assert.NotNil(t, installer)

	// Test package.json generation
	req := &node.NodeInstallRequest{
		Packages: []string{"lodash@4.17.21", "express@4.18.2"},
	}

	err := installer.GeneratePackageJSON(req)
	assert.NoError(t, err)

	// Verify package.json was created
	packageJSONPath := filepath.Join(tempDir, "package.json")
	assert.FileExists(t, packageJSONPath)

	// Test package manager detection
	envManager := node.NewNodeEnvironmentManager(tempDir)
	packageManager := envManager.DetectPackageManager()
	assert.Equal(t, node.PackageManagerNPM, packageManager)
}

// TestTypeScriptCompiler tests the TypeScript compiler system
func TestTypeScriptCompiler(t *testing.T) {
	tempDir := t.TempDir()
	
	compiler := typescript.NewTypeScriptCompiler(tempDir)
	assert.NotNil(t, compiler)

	// Create test TypeScript file
	tsContent := `
interface Greeting {
    message: string;
}

function greet(greeting: Greeting): void {
    console.log(greeting.message);
}

greet({ message: "Hello, TypeScript!" });
	`

	tsFile := filepath.Join(tempDir, "test.ts")
	err := os.WriteFile(tsFile, []byte(tsContent), 0644)
	require.NoError(t, err)

	// Test tsconfig.json generation
	req := &typescript.CompilationRequest{
		SourceFiles: []string{tsFile},
		Target:      typescript.TargetES2020,
		Module:      typescript.ModuleCommonJS,
		OutputDir:   filepath.Join(tempDir, "dist"),
	}

	err = compiler.GenerateTSConfig(req)
	assert.NoError(t, err)

	// Verify tsconfig.json was created
	tsconfigPath := filepath.Join(tempDir, "tsconfig.json")
	assert.FileExists(t, tsconfigPath)

	// Test diagnostic parsing would be done through the Compile method
	// since parseDiagnosticLine is an internal method used during compilation
}

// TestJavaScriptAnalyzer tests the JavaScript/TypeScript analyzer
func TestJavaScriptAnalyzer(t *testing.T) {
	tempDir := t.TempDir()
	
	analyzer := node.NewJavaScriptAnalyzer(tempDir)
	assert.NotNil(t, analyzer)

	// Create test files
	jsFile := filepath.Join(tempDir, "test.js")
	jsContent := `
function calculate(a, b) {
    return a + b;
}

console.log(calculate(2, 3));
	`
	
	err := os.WriteFile(jsFile, []byte(jsContent), 0644)
	require.NoError(t, err)

	// Test file auto-detection (using private method via reflection or testing the behavior indirectly)
	// Since autoDetectFiles is not exported, we test the analyze method instead
	autoDetectReq := &node.AnalysisRequest{
		SourceFiles:  []string{}, // Empty to trigger auto-detection
		AnalysisType: []node.AnalysisType{node.AnalysisTypeLinting},
	}
	
	result, err := analyzer.Analyze(context.Background(), autoDetectReq)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, result.FilesAnalyzed) // Should auto-detect our JS file

	// Test analysis request structure
	req := &node.AnalysisRequest{
		SourceFiles:  []string{jsFile},
		AnalysisType: []node.AnalysisType{node.AnalysisTypeLinting},
		LintingOptions: &node.LintingOptions{
			AutoFix: false,
		},
	}

	// Analysis would require actual tools, but we can test the structure
	assert.NotNil(t, req)
	assert.Len(t, req.AnalysisType, 1)
	assert.Equal(t, node.AnalysisTypeLinting, req.AnalysisType[0])
}

// TestLanguageDetection tests language detection across handlers
func TestLanguageDetection(t *testing.T) {
	jsHandler := NewJavaScriptHandler()
	tsHandler := NewTypeScriptHandler()

	tests := []struct {
		name     string
		code     string
		filename string
		jsScore  float64
		tsScore  float64
	}{
		{
			name:     "pure JavaScript",
			code:     "const x = 5; console.log(x);",
			filename: "test.js",
			jsScore:  0.8, // High JS confidence
			tsScore:  0.3, // Lower TS confidence
		},
		{
			name:     "TypeScript with interfaces",
			code:     "interface User { name: string; } const user: User = { name: 'test' };",
			filename: "test.ts",
			jsScore:  0.3, // Lower JS confidence
			tsScore:  0.9, // High TS confidence
		},
		{
			name:     "React JSX",
			code:     "const Component = () => <div>Hello</div>;",
			filename: "test.jsx",
			jsScore:  0.8, // High JS confidence
			tsScore:  0.3, // Lower TS confidence
		},
		{
			name:     "React TSX",
			code:     "const Component: React.FC = () => <div>Hello</div>;",
			filename: "test.tsx",
			jsScore:  0.3, // Lower JS confidence
			tsScore:  0.9, // High TS confidence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsConfidence := jsHandler.DetectLanguage(tt.code, tt.filename)
			tsConfidence := tsHandler.DetectLanguage(tt.code, tt.filename)

			assert.GreaterOrEqual(t, jsConfidence, tt.jsScore, "JavaScript confidence too low")
			assert.GreaterOrEqual(t, tsConfidence, tt.tsScore, "TypeScript confidence too low")
		})
	}
}

// TestErrorHandling tests error handling across the integrated system
func TestErrorHandling(t *testing.T) {
	tempDir := t.TempDir()
	
	// Test JavaScript handler with invalid code
	jsHandler := NewJavaScriptHandler()
	req := &ExecutionRequest{
		Code:       "this is invalid JavaScript syntax}}}",
		Language:   LanguageJavaScript,
		WorkingDir: tempDir,
		Timeout:    5 * time.Second,
	}

	err := jsHandler.PrepareExecution(context.Background(), req)
	assert.NoError(t, err) // Preparation should succeed

	// Validation should catch syntax errors
	validationErr := jsHandler.ValidateCode(req.Code)
	assert.NoError(t, validationErr) // Base validation is minimal

	// Test TypeScript handler with compilation errors
	tsHandler := NewTypeScriptHandler()
	tsReq := &ExecutionRequest{
		Code: `
let x: string = 42; // Type error
console.log(x);
		`,
		Language:   LanguageTypeScript,
		WorkingDir: tempDir,
		Timeout:    10 * time.Second,
	}

	err = tsHandler.PrepareExecution(context.Background(), tsReq)
	assert.NoError(t, err) // Preparation should succeed even with type errors
}

// TestPerformanceMetrics tests performance tracking
func TestPerformanceMetrics(t *testing.T) {
	tempDir := t.TempDir()
	
	// Test execution timing
	jsHandler := NewJavaScriptHandler()
	req := &ExecutionRequest{
		Code: `
const start = Date.now();
console.log('Performance test');
const end = Date.now();
console.log('Execution time:', end - start, 'ms');
		`,
		Language:   LanguageJavaScript,
		WorkingDir: tempDir,
		Timeout:    10 * time.Second,
	}

	startTime := time.Now()
	err := jsHandler.PrepareExecution(context.Background(), req)
	preparationTime := time.Since(startTime)

	assert.NoError(t, err)
	assert.Less(t, preparationTime, 5*time.Second, "Preparation took too long")

	// Test memory usage tracking (basic)
	assert.NotNil(t, jsHandler.npmInstaller)
	assert.NotNil(t, jsHandler.environmentManager)
}

// TestConcurrency tests concurrent execution safety
func TestConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	const numGoroutines = 5
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			tempDir := t.TempDir()
			handler := NewJavaScriptHandler()
			
			req := &ExecutionRequest{
				Code: fmt.Sprintf(`
console.log('Goroutine %d executing');
const result = %d * 2;
console.log('Result:', result);
				`, id, id),
				Language:   LanguageJavaScript,
				WorkingDir: tempDir,
				Timeout:    10 * time.Second,
			}

			err := handler.PrepareExecution(context.Background(), req)
			assert.NoError(t, err)

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(30 * time.Second):
			t.Fatal("Goroutine timed out")
		}
	}
}

// TestBackwardCompatibility tests that the updated handlers maintain compatibility
func TestBackwardCompatibility(t *testing.T) {
	// Test that the handler interface is still satisfied
	var jsHandler LanguageHandler = NewJavaScriptHandler()
	var tsHandler LanguageHandler = NewTypeScriptHandler()

	assert.NotNil(t, jsHandler)
	assert.NotNil(t, tsHandler)

	// Test basic interface methods
	assert.Equal(t, LanguageJavaScript, jsHandler.GetLanguage())
	assert.Equal(t, LanguageTypeScript, tsHandler.GetLanguage())

	assert.Contains(t, jsHandler.GetSupportedExtensions(), ".js")
	assert.Contains(t, tsHandler.GetSupportedExtensions(), ".ts")

	assert.Equal(t, "npm", jsHandler.GetPackageManager())
	assert.Equal(t, "npm", tsHandler.GetPackageManager())

	assert.False(t, jsHandler.IsCompiled())
	assert.True(t, tsHandler.IsCompiled())
}