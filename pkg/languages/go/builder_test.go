package go_lang

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBuilder_Build(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-build-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainFile := filepath.Join(tempDir, "main.go")
	goCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
`
	err = os.WriteFile(mainFile, []byte(goCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-build")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Test build
	builder := NewBuilder(tempDir)
	result, err := builder.Build(ctx)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful build, got failure. Errors: %v", result.Errors)
	}

	if result.Duration == 0 {
		t.Errorf("Expected non-zero build duration")
	}

	// Check if binary was created
	binaryPath := filepath.Join(tempDir, "app")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}

	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Errorf("Binary was not created at %s", binaryPath)
	}
}

func TestBuilder_CrossCompile(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-cross-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainFile := filepath.Join(tempDir, "main.go")
	goCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Cross-Compile!")
}
`
	err = os.WriteFile(mainFile, []byte(goCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-cross")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Test cross-compilation
	builder := NewBuilder(tempDir)
	platforms := []string{"linux-amd64", "windows-amd64", "darwin-amd64"}
	
	result, err := builder.CrossCompile(ctx, platforms)
	if err != nil {
		t.Fatalf("Cross-compilation failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful cross-compilation, got failure. Errors: %v", result.Errors)
	}

	if len(result.Targets) != len(platforms) {
		t.Errorf("Expected %d targets, got %d", len(platforms), len(result.Targets))
	}

	// Check if binaries were created
	expectedBinaries := []string{
		"app-linux-amd64",
		"app-windows-amd64.exe",
		"app-darwin-amd64",
	}

	for _, binary := range expectedBinaries {
		binaryPath := filepath.Join(tempDir, binary)
		if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
			t.Errorf("Cross-compiled binary was not created at %s", binaryPath)
		}
	}
}

func TestBuilder_BuildWithOptimization(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-optimize-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainFile := filepath.Join(tempDir, "main.go")
	goCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Optimization!")
}
`
	err = os.WriteFile(mainFile, []byte(goCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-optimize")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Test build with optimization
	builder := NewBuilder(tempDir)
	result, err := builder.BuildWithOptimization(ctx, "-N -l", true)
	if err != nil {
		t.Fatalf("Optimized build failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful optimized build, got failure. Errors: %v", result.Errors)
	}

	// Check if binary was created
	binaryPath := filepath.Join(tempDir, "app")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}

	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Errorf("Optimized binary was not created at %s", binaryPath)
	}
}

func TestBuilder_Clean(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-clean-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-clean")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Test clean
	builder := NewBuilder(tempDir)
	err = builder.Clean(ctx)
	if err != nil {
		t.Fatalf("Clean failed: %v", err)
	}
}

func TestBuilder_ValidateConfig(t *testing.T) {
	builder := NewBuilder("/tmp")

	// Test valid config
	err := builder.ValidateConfig()
	if err != nil {
		t.Errorf("Valid config should not produce error: %v", err)
	}

	// Test with nil config
	builder.config = nil
	err = builder.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with nil config")
	}

	// Test with empty targets
	builder.config = &BuildConfig{
		Targets: []BuildTarget{},
	}
	err = builder.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with empty targets")
	}

	// Test with invalid target
	builder.config = &BuildConfig{
		Targets: []BuildTarget{
			{
				GOOS:   "", // Invalid: empty GOOS
				GOARCH: "amd64",
				Output: "app",
			},
		},
	}
	err = builder.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with invalid target")
	}

	// Test with invalid build mode
	builder.config = &BuildConfig{
		Targets: []BuildTarget{
			{
				GOOS:   "linux",
				GOARCH: "amd64",
				Output: "app",
			},
		},
		BuildMode: "invalid-mode",
	}
	err = builder.ValidateConfig()
	if err == nil {
		t.Errorf("Expected error with invalid build mode")
	}
}

func TestBuilder_Configuration(t *testing.T) {
	builder := NewBuilder("/tmp")

	// Test default configuration
	defaultConfig := NewDefaultBuildConfig()
	if defaultConfig.Trimpath != true {
		t.Errorf("Expected default trimpath to be true")
	}

	if defaultConfig.BuildMode != "default" {
		t.Errorf("Expected default build mode to be 'default'")
	}

	if len(defaultConfig.Targets) != 1 {
		t.Errorf("Expected one default target")
	}

	// Test setting configuration
	customConfig := &BuildConfig{
		Targets: []BuildTarget{
			{
				GOOS:   "linux",
				GOARCH: "amd64",
				Output: "custom-app",
			},
		},
		Verbose:   true,
		Race:      true,
		BuildMode: "default",
	}

	builder.SetConfig(customConfig)
	if builder.config.Verbose != true {
		t.Errorf("Expected verbose to be true after setting config")
	}

	if builder.config.Race != true {
		t.Errorf("Expected race to be true after setting config")
	}
}

func TestBuilder_BuildFlags(t *testing.T) {
	builder := NewBuilder("/tmp")

	// Test adding build flags
	builder.AddBuildFlag("-X main.version=1.0.0")
	
	if len(builder.config.Targets) == 0 {
		t.Fatalf("Expected at least one target")
	}

	target := builder.config.Targets[0]
	found := false
	for _, flag := range target.LDFlags {
		if flag == "-X main.version=1.0.0" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Build flag was not added to target")
	}

	// Test setting build tags
	tags := []string{"integration", "slow"}
	builder.SetBuildTag(tags)

	for _, target := range builder.config.Targets {
		if len(target.Tags) != len(tags) {
			t.Errorf("Build tags were not set correctly")
		}
		for i, tag := range target.Tags {
			if tag != tags[i] {
				t.Errorf("Build tag mismatch: expected %s, got %s", tags[i], tag)
			}
		}
	}

	// Test enabling race detection
	builder.EnableRaceDetection(true)
	if !builder.config.Race {
		t.Errorf("Race detection was not enabled")
	}

	// Test enabling CGO
	builder.EnableCGO(false)
	for _, target := range builder.config.Targets {
		if target.CGO {
			t.Errorf("CGO should be disabled")
		}
	}
}

func TestBuilder_GetBuildInfo(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-buildinfo-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainFile := filepath.Join(tempDir, "main.go")
	goCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Build Info!")
}
`
	err = os.WriteFile(mainFile, []byte(goCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-buildinfo")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Build first
	builder := NewBuilder(tempDir)
	_, err = builder.Build(ctx)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Get build info
	buildInfo, err := builder.GetBuildInfo(ctx)
	if err != nil {
		t.Fatalf("Failed to get build info: %v", err)
	}

	if len(buildInfo) == 0 {
		t.Errorf("Expected build info to contain data")
	}
}

func TestBuilder_CacheConfiguration(t *testing.T) {
	builder := NewBuilder("/tmp")

	// Test cache directory setting
	cacheDir := "/tmp/go-cache"
	builder.SetCacheDir(cacheDir)
	if builder.cacheDir != cacheDir {
		t.Errorf("Cache directory was not set correctly")
	}

	// Test cache enable/disable
	builder.EnableCache(false)
	if builder.enableCache {
		t.Errorf("Cache should be disabled")
	}

	builder.EnableCache(true)
	if !builder.enableCache {
		t.Errorf("Cache should be enabled")
	}
}

func TestBuilder_VerboseMode(t *testing.T) {
	builder := NewBuilder("/tmp")

	// Test verbose mode
	builder.SetVerbose(true)
	if !builder.verbose {
		t.Errorf("Verbose mode should be enabled")
	}

	builder.SetVerbose(false)
	if builder.verbose {
		t.Errorf("Verbose mode should be disabled")
	}
}

func TestBuilder_ExportImportConfig(t *testing.T) {
	builder := NewBuilder("/tmp")

	// Test export configuration
	configJSON, err := builder.ExportBuildConfig()
	if err != nil {
		t.Fatalf("Failed to export build config: %v", err)
	}

	if configJSON == "" {
		t.Errorf("Expected non-empty configuration JSON")
	}

	// Test import configuration
	importedConfig, err := CreateBuildConfig(configJSON)
	if err != nil {
		t.Fatalf("Failed to import build config: %v", err)
	}

	if len(importedConfig.Targets) != len(builder.config.Targets) {
		t.Errorf("Imported config has different number of targets")
	}
}

func TestBuilder_AvailableTargets(t *testing.T) {
	targets := GetAvailableTargets()

	if len(targets) == 0 {
		t.Errorf("Expected available targets to be populated")
	}

	// Check for common targets
	expectedTargets := []string{"linux-amd64", "windows-amd64", "darwin-amd64"}
	for _, expected := range expectedTargets {
		if _, exists := targets[expected]; !exists {
			t.Errorf("Expected target %s not found in available targets", expected)
		}
	}
}

func TestBuilder_BuildSingle(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-single-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainFile := filepath.Join(tempDir, "main.go")
	goCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Single Build!")
}
`
	err = os.WriteFile(mainFile, []byte(goCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-single")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Test single target build
	builder := NewBuilder(tempDir)
	target := BuildTarget{
		GOOS:   "linux",
		GOARCH: "amd64",
		Output: "single-app",
	}

	result, err := builder.BuildSingle(ctx, target)
	if err != nil {
		t.Fatalf("Single build failed: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful single build, got failure. Errors: %v", result.Errors)
	}

	if len(result.Targets) != 1 {
		t.Errorf("Expected exactly one target in result")
	}

	// Check if binary was created
	binaryPath := filepath.Join(tempDir, "single-app")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		t.Errorf("Single build binary was not created at %s", binaryPath)
	}
}

// Benchmark tests
func BenchmarkBuilder_Build(b *testing.B) {
	// Setup
	tempDir, err := os.MkdirTemp("", "bench-go-build-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mainFile := filepath.Join(tempDir, "main.go")
	goCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Benchmark!")
}
`
	err = os.WriteFile(mainFile, []byte(goCode), 0644)
	if err != nil {
		b.Fatalf("Failed to write main.go: %v", err)
	}

	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "bench-build")
	if err != nil {
		b.Fatalf("Failed to initialize module: %v", err)
	}

	builder := NewBuilder(tempDir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		result, err := builder.Build(ctx)
		b.StopTimer()

		if err != nil {
			b.Fatalf("Build failed: %v", err)
		}

		if !result.Success {
			b.Fatalf("Build was not successful")
		}

		// Clean up binary for next iteration
		binaryPath := filepath.Join(tempDir, "app")
		if runtime.GOOS == "windows" {
			binaryPath += ".exe"
		}
		os.Remove(binaryPath)
	}
}

func BenchmarkBuilder_CrossCompile(b *testing.B) {
	// Setup
	tempDir, err := os.MkdirTemp("", "bench-go-cross-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mainFile := filepath.Join(tempDir, "main.go")
	goCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Cross Benchmark!")
}
`
	err = os.WriteFile(mainFile, []byte(goCode), 0644)
	if err != nil {
		b.Fatalf("Failed to write main.go: %v", err)
	}

	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "bench-cross")
	if err != nil {
		b.Fatalf("Failed to initialize module: %v", err)
	}

	builder := NewBuilder(tempDir)
	platforms := []string{"linux-amd64", "windows-amd64"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		result, err := builder.CrossCompile(ctx, platforms)
		b.StopTimer()

		if err != nil {
			b.Fatalf("Cross-compile failed: %v", err)
		}

		if !result.Success {
			b.Fatalf("Cross-compile was not successful")
		}

		// Clean up binaries for next iteration
		os.Remove(filepath.Join(tempDir, "app-linux-amd64"))
		os.Remove(filepath.Join(tempDir, "app-windows-amd64.exe"))
	}
}

// Test error cases
func TestBuilder_ErrorCases(t *testing.T) {
	// Test with non-existent directory
	builder := NewBuilder("/non/existent/directory")
	ctx := context.Background()

	_, err := builder.Build(ctx)
	if err == nil {
		t.Errorf("Expected error with non-existent directory")
	}

	// Test with invalid Go code
	tempDir, err := os.MkdirTemp("", "test-go-error-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create invalid Go code
	mainFile := filepath.Join(tempDir, "main.go")
	invalidCode := `package main

func main() {
	fmt.Println("Hello, World!" // Missing closing parenthesis
}
`
	err = os.WriteFile(mainFile, []byte(invalidCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	err = moduleManager.InitializeModule(ctx, "test-error")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	builder = NewBuilder(tempDir)
	result, err := builder.Build(ctx)
	if err == nil {
		t.Errorf("Expected error with invalid Go code")
	}

	if result.Success {
		t.Errorf("Expected build to fail with invalid code")
	}

	if len(result.Errors) == 0 {
		t.Errorf("Expected build errors to be reported")
	}
}

// Test concurrent builds
func TestBuilder_ConcurrentBuilds(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-concurrent-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a simple Go program
	mainFile := filepath.Join(tempDir, "main.go")
	goCode := `package main

import "fmt"

func main() {
	fmt.Println("Hello, Concurrent!")
}
`
	err = os.WriteFile(mainFile, []byte(goCode), 0644)
	if err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	// Initialize Go module
	moduleManager := NewModuleManager(tempDir)
	ctx := context.Background()
	err = moduleManager.InitializeModule(ctx, "test-concurrent")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run concurrent builds
	numBuilds := 3
	done := make(chan bool, numBuilds)
	errors := make(chan error, numBuilds)

	for i := 0; i < numBuilds; i++ {
		go func(buildID int) {
			// Use different output names for concurrent builds
			config := NewDefaultBuildConfig()
			config.Targets[0].Output = fmt.Sprintf("concurrent-app-%d", buildID)
			
			builderCopy := NewBuilder(tempDir)
			builderCopy.SetConfig(config)
			
			result, err := builderCopy.Build(ctx)
			if err != nil {
				errors <- err
				return
			}
			
			if !result.Success {
				errors <- fmt.Errorf("build %d failed with errors: %v", buildID, result.Errors)
				return
			}
			
			done <- true
		}(i)
	}

	// Wait for all builds to complete
	timeout := time.After(60 * time.Second)
	completed := 0
	
	for completed < numBuilds {
		select {
		case <-done:
			completed++
		case err := <-errors:
			t.Errorf("Concurrent build failed: %v", err)
			completed++
		case <-timeout:
			t.Fatalf("Concurrent builds timed out")
		}
	}
}