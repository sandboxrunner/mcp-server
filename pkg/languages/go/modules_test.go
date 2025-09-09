package go_lang

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestModuleManager_InitializeModule(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-module-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Test module initialization
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Check if go.mod file was created
	goModPath := filepath.Join(tempDir, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		t.Fatalf("go.mod file was not created")
	}

	// Read go.mod content
	content, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("Failed to read go.mod: %v", err)
	}

	if !contains(string(content), "module test-module") {
		t.Errorf("go.mod does not contain expected module declaration")
	}
}

func TestModuleManager_AddDependency(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-dependency-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Add a dependency
	err = manager.AddDependency(ctx, "github.com/stretchr/testify", "latest")
	if err != nil {
		t.Fatalf("Failed to add dependency: %v", err)
	}

	// Check if go.mod was updated
	goModPath := filepath.Join(tempDir, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("Failed to read go.mod: %v", err)
	}

	if !contains(string(content), "github.com/stretchr/testify") {
		t.Errorf("go.mod does not contain added dependency")
	}
}

func TestModuleManager_GetModuleInfo(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-info-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Get module info
	info, err := manager.GetModuleInfo(ctx)
	if err != nil {
		t.Fatalf("Failed to get module info: %v", err)
	}

	if info.Path != "test-module" {
		t.Errorf("Expected module path 'test-module', got '%s'", info.Path)
	}
}

func TestModuleManager_TidyModule(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-tidy-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Test tidy operation
	err = manager.TidyModule(ctx)
	if err != nil {
		t.Fatalf("Failed to tidy module: %v", err)
	}
}

func TestModuleManager_ValidateModule(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-validate-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Test validation without go.mod (should fail)
	err = manager.ValidateModule(ctx)
	if err == nil {
		t.Errorf("Expected validation to fail without go.mod")
	}

	// Initialize module and test validation
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	err = manager.ValidateModule(ctx)
	if err != nil {
		t.Fatalf("Module validation failed: %v", err)
	}
}

func TestModuleManager_ReplaceDirective(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-replace-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Add replace directive
	err = manager.AddReplaceDirective(ctx, "old-module", "new-module")
	if err != nil {
		t.Fatalf("Failed to add replace directive: %v", err)
	}

	// Get replace directives
	replaces, err := manager.GetReplaceDirectives(ctx)
	if err != nil {
		t.Fatalf("Failed to get replace directives: %v", err)
	}

	found := false
	for _, replace := range replaces {
		if replace.Old == "old-module" && replace.New == "new-module" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Replace directive not found in go.mod")
	}

	// Remove replace directive
	err = manager.RemoveReplaceDirective(ctx, "old-module")
	if err != nil {
		t.Fatalf("Failed to remove replace directive: %v", err)
	}

	// Verify removal
	replaces, err = manager.GetReplaceDirectives(ctx)
	if err != nil {
		t.Fatalf("Failed to get replace directives: %v", err)
	}

	for _, replace := range replaces {
		if replace.Old == "old-module" {
			t.Errorf("Replace directive should have been removed")
		}
	}
}

func TestModuleManager_GetModuleConfig(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-config-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Get module config
	config, err := manager.GetModuleConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to get module config: %v", err)
	}

	if config.ModulePath != "test-module" {
		t.Errorf("Expected module path 'test-module', got '%s'", config.ModulePath)
	}

	if config.ProxyURL == "" {
		t.Errorf("Expected proxy URL to be set")
	}
}

func TestModuleManager_ProxySettings(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-go-proxy-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)

	// Test proxy URL setting
	customProxy := "https://custom-proxy.example.com"
	manager.SetProxyURL(customProxy)

	if manager.proxyURL != customProxy {
		t.Errorf("Expected proxy URL '%s', got '%s'", customProxy, manager.proxyURL)
	}

	// Test offline mode
	manager.SetOffline(true)
	if !manager.offline {
		t.Errorf("Expected offline mode to be enabled")
	}

	manager.SetOffline(false)
	if manager.offline {
		t.Errorf("Expected offline mode to be disabled")
	}
}

func TestModuleManager_DownloadDependencies(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-download-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Test download (should work even with no dependencies)
	err = manager.DownloadDependencies(ctx)
	if err != nil {
		t.Fatalf("Failed to download dependencies: %v", err)
	}
}

func TestModuleManager_CreateVendorDirectory(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-vendor-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Test vendor directory creation
	err = manager.CreateVendorDirectory(ctx)
	if err != nil {
		t.Fatalf("Failed to create vendor directory: %v", err)
	}

	// Check if vendor directory was created
	vendorPath := filepath.Join(tempDir, "vendor")
	if _, err := os.Stat(vendorPath); os.IsNotExist(err) {
		t.Errorf("Vendor directory was not created")
	}
}

func TestModuleManager_RemoveDependency(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-remove-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Add a dependency first
	err = manager.AddDependency(ctx, "github.com/stretchr/testify", "latest")
	if err != nil {
		t.Fatalf("Failed to add dependency: %v", err)
	}

	// Remove the dependency
	err = manager.RemoveDependency(ctx, "github.com/stretchr/testify")
	if err != nil {
		t.Fatalf("Failed to remove dependency: %v", err)
	}

	// Check if dependency was removed from go.mod
	goModPath := filepath.Join(tempDir, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("Failed to read go.mod: %v", err)
	}

	if contains(string(content), "github.com/stretchr/testify") {
		t.Errorf("Dependency should have been removed from go.mod")
	}
}

func TestModuleManager_ListDependencies(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-list-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// List dependencies (should at least include current module)
	deps, err := manager.ListDependencies(ctx, false)
	if err != nil {
		t.Fatalf("Failed to list dependencies: %v", err)
	}

	if len(deps) == 0 {
		t.Errorf("Expected at least one dependency (current module)")
	}

	// Check if current module is in the list
	found := false
	for _, dep := range deps {
		if dep.Path == "test-module" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Current module not found in dependency list")
	}
}

func TestModuleManager_GetModuleGraph(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "test-go-graph-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Get module graph
	graph, err := manager.GetModuleGraph(ctx)
	if err != nil {
		t.Fatalf("Failed to get module graph: %v", err)
	}

	if graph.Modules == nil {
		t.Errorf("Expected modules map to be initialized")
	}

	if graph.Dependencies == nil {
		t.Errorf("Expected dependencies map to be initialized")
	}

	if graph.Conflicts == nil {
		t.Errorf("Expected conflicts slice to be initialized")
	}
}

// Benchmark tests
func BenchmarkModuleManager_InitializeModule(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tempDir, err := os.MkdirTemp("", "bench-go-module-*")
		if err != nil {
			b.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(tempDir)

		manager := NewModuleManager(tempDir)
		ctx := context.Background()

		b.StartTimer()
		err = manager.InitializeModule(ctx, "bench-module")
		b.StopTimer()

		if err != nil {
			b.Fatalf("Failed to initialize module: %v", err)
		}
	}
}

func BenchmarkModuleManager_TidyModule(b *testing.B) {
	// Setup
	tempDir, err := os.MkdirTemp("", "bench-go-tidy-*")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	err = manager.InitializeModule(ctx, "bench-module")
	if err != nil {
		b.Fatalf("Failed to initialize module: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		err = manager.TidyModule(ctx)
		b.StopTimer()

		if err != nil {
			b.Fatalf("Failed to tidy module: %v", err)
		}
	}
}

// Test error cases
func TestModuleManager_ErrorCases(t *testing.T) {
	// Test with non-existent directory
	manager := NewModuleManager("/non/existent/directory")
	ctx := context.Background()

	err := manager.InitializeModule(ctx, "test-module")
	if err == nil {
		t.Errorf("Expected error with non-existent directory")
	}

	// Test invalid module name
	tempDir, err := os.MkdirTemp("", "test-go-error-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager = NewModuleManager(tempDir)

	// Test operations without initialized module
	err = manager.ValidateModule(ctx)
	if err == nil {
		t.Errorf("Expected error when validating without go.mod")
	}

	err = manager.AddDependency(ctx, "invalid-dependency", "")
	if err == nil {
		t.Errorf("Expected error when adding dependency without initialized module")
	}
}

// Test concurrent operations
func TestModuleManager_ConcurrentOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test-go-concurrent-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	manager := NewModuleManager(tempDir)
	ctx := context.Background()

	// Initialize module first
	err = manager.InitializeModule(ctx, "test-module")
	if err != nil {
		t.Fatalf("Failed to initialize module: %v", err)
	}

	// Run concurrent operations
	done := make(chan bool, 3)

	go func() {
		err := manager.TidyModule(ctx)
		if err != nil {
			t.Errorf("Concurrent tidy failed: %v", err)
		}
		done <- true
	}()

	go func() {
		err := manager.ValidateModule(ctx)
		if err != nil {
			t.Errorf("Concurrent validate failed: %v", err)
		}
		done <- true
	}()

	go func() {
		_, err := manager.GetModuleInfo(ctx)
		if err != nil {
			t.Errorf("Concurrent get info failed: %v", err)
		}
		done <- true
	}()

	// Wait for all operations to complete
	timeout := time.After(30 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case <-done:
			// Operation completed
		case <-timeout:
			t.Fatalf("Concurrent operations timed out")
		}
	}
}

// Helper function
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}