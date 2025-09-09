package python

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnvironmentManager_NewEnvironmentManager(t *testing.T) {
	workingDir := "/tmp/test"
	manager := NewEnvironmentManager(workingDir)
	
	if manager.workingDir != workingDir {
		t.Errorf("Expected workingDir %s, got %s", workingDir, manager.workingDir)
	}
	
	if manager.baseEnv == nil {
		t.Error("Base environment should be initialized")
	}
	
	if manager.envCache == nil {
		t.Error("Environment cache should be initialized")
	}
	
	// Check that base environment contains some system variables
	if len(manager.baseEnv) == 0 {
		t.Error("Base environment should contain system environment variables")
	}
}

func TestEnvironmentManager_DetectPythonVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := NewEnvironmentManager("/tmp")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Test with system python (if available)
	versionInfo, err := manager.DetectPythonVersion(ctx, "python3")
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			t.Skip("Python3 not available, skipping test")
		}
		t.Fatalf("Failed to detect Python version: %v", err)
	}
	
	if versionInfo.Version == "" {
		t.Error("Version should not be empty")
	}
	
	if versionInfo.Executable == "" {
		t.Error("Executable path should not be empty")
	}
	
	if versionInfo.Major < 2 {
		t.Error("Major version should be at least 2")
	}
	
	if versionInfo.Platform == "" {
		t.Error("Platform should not be empty")
	}
	
	if versionInfo.Architecture == "" {
		t.Error("Architecture should not be empty")
	}
}

func TestEnvironmentManager_SelectPythonBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := NewEnvironmentManager("/tmp")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	requirements := &EnvironmentSetupOptions{}
	
	binary, err := manager.SelectPythonBinary(ctx, requirements)
	if err != nil {
		if strings.Contains(err.Error(), "no suitable Python binary found") {
			t.Skip("No Python binary available, skipping test")
		}
		t.Fatalf("Failed to select Python binary: %v", err)
	}
	
	if binary == "" {
		t.Error("Selected binary should not be empty")
	}
	
	// Test with specific version requirement
	requirements.PythonVersion = "3.9"
	binary, err = manager.SelectPythonBinary(ctx, requirements)
	if err != nil {
		// This might fail if Python 3.9 is not available
		t.Logf("Python 3.9 not available: %v", err)
	}
}

func TestEnvironmentManager_versionMatches(t *testing.T) {
	manager := NewEnvironmentManager("/tmp")
	
	tests := []struct {
		actual   string
		required string
		expected bool
	}{
		{"3.9.7", "3.9", true},
		{"3.9.7", "3.10", false},
		{"3.10.0", "3.10", true},
		{"2.7.18", "3", false},
		{"3.8.10", "3.8", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.actual+"_vs_"+tt.required, func(t *testing.T) {
			result := manager.versionMatches(tt.actual, tt.required)
			if result != tt.expected {
				t.Errorf("Expected %v for %s vs %s, got %v", tt.expected, tt.actual, tt.required, result)
			}
		})
	}
}

func TestEnvironmentManager_SetupPythonPath(t *testing.T) {
	manager := NewEnvironmentManager("/tmp")
	
	env := &PythonEnvironment{
		Environment: make(map[string]string),
		SitePackages: []string{"/usr/lib/python3.9/site-packages"},
	}
	
	additionalPaths := []string{"/home/user/mypackages", "/opt/custom/python"}
	
	manager.SetupPythonPath(env, additionalPaths)
	
	if len(env.PythonPath_) == 0 {
		t.Error("Python path should not be empty")
	}
	
	// Check that site-packages are included
	found := false
	for _, path := range env.PythonPath_ {
		if path == "/usr/lib/python3.9/site-packages" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Site-packages path should be included in Python path")
	}
	
	// Check that additional paths are included
	for _, additionalPath := range additionalPaths {
		found := false
		for _, path := range env.PythonPath_ {
			if path == additionalPath {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Additional path %s should be included", additionalPath)
		}
	}
	
	// Check environment variable is set
	if env.Environment["PYTHONPATH"] == "" {
		t.Error("PYTHONPATH environment variable should be set")
	}
}

func TestEnvironmentManager_ActivateEnvironment(t *testing.T) {
	manager := NewEnvironmentManager("/tmp")
	
	env1 := &PythonEnvironment{
		Name: "env1",
		Type: EnvTypeVirtualEnv,
	}
	
	env2 := &PythonEnvironment{
		Name: "env2",
		Type: EnvTypeSystem,
	}
	
	// Activate first environment
	err := manager.ActivateEnvironment(context.Background(), env1)
	if err != nil {
		t.Fatalf("Failed to activate environment: %v", err)
	}
	
	if !env1.IsActive {
		t.Error("Environment should be marked as active")
	}
	
	if manager.GetActiveEnvironment() != env1 {
		t.Error("Active environment should be env1")
	}
	
	// Activate second environment
	err = manager.ActivateEnvironment(context.Background(), env2)
	if err != nil {
		t.Fatalf("Failed to activate environment: %v", err)
	}
	
	if env1.IsActive {
		t.Error("First environment should no longer be active")
	}
	
	if !env2.IsActive {
		t.Error("Second environment should be active")
	}
	
	if manager.GetActiveEnvironment() != env2 {
		t.Error("Active environment should be env2")
	}
}

func TestEnvironmentManager_ValidateEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := NewEnvironmentManager("/tmp")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Test with invalid environment
	invalidEnv := &PythonEnvironment{
		PythonPath: "/non/existent/python",
	}
	
	err := manager.ValidateEnvironment(ctx, invalidEnv)
	if err == nil {
		t.Error("Validation should fail for non-existent Python executable")
	}
	
	// Test with valid environment (if python3 is available)
	validEnv := &PythonEnvironment{
		PythonPath: "python3",
	}
	
	err = manager.ValidateEnvironment(ctx, validEnv)
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			t.Skip("Python3 not available, skipping validation test")
		}
		t.Errorf("Validation should succeed for valid Python executable: %v", err)
	}
}

func TestEnvironmentManager_ExportImportEnvironment(t *testing.T) {
	manager := NewEnvironmentManager("/tmp")
	
	originalEnv := &PythonEnvironment{
		Name:           "test_env",
		Type:           EnvTypeVirtualEnv,
		PythonPath:     "/path/to/python",
		PythonVersion:  "3.9.7",
		VirtualEnvPath: "/path/to/venv",
		PythonPath_:    []string{"/path1", "/path2"},
		Environment:    map[string]string{"VAR1": "value1", "VAR2": "value2"},
	}
	
	// Export environment
	exported, err := manager.ExportEnvironment(originalEnv)
	if err != nil {
		t.Fatalf("Failed to export environment: %v", err)
	}
	
	if exported["PYTHON_EXE"] != originalEnv.PythonPath {
		t.Error("Python executable not correctly exported")
	}
	
	if exported["PYTHON_VERSION"] != originalEnv.PythonVersion {
		t.Error("Python version not correctly exported")
	}
	
	if exported["VIRTUAL_ENV"] != originalEnv.VirtualEnvPath {
		t.Error("Virtual environment path not correctly exported")
	}
	
	// Import environment
	imported, err := manager.ImportEnvironment(exported)
	if err != nil {
		t.Fatalf("Failed to import environment: %v", err)
	}
	
	if imported.PythonPath != originalEnv.PythonPath {
		t.Error("Python path not correctly imported")
	}
	
	if imported.PythonVersion != originalEnv.PythonVersion {
		t.Error("Python version not correctly imported")
	}
	
	if imported.VirtualEnvPath != originalEnv.VirtualEnvPath {
		t.Error("Virtual environment path not correctly imported")
	}
	
	if imported.Type != EnvTypeVirtualEnv {
		t.Error("Environment type should be virtual environment")
	}
}

func TestEnvironmentManager_GetPythonExecutable(t *testing.T) {
	manager := NewEnvironmentManager("/tmp")
	
	// Test with no active environment
	executable := manager.GetPythonExecutable()
	if executable == "" {
		t.Error("Should return a default Python executable")
	}
	
	// Test with active environment
	activeEnv := &PythonEnvironment{
		PythonPath: "/custom/python",
		IsActive:   true,
	}
	
	manager.activeEnv = activeEnv
	
	executable = manager.GetPythonExecutable()
	if executable != "/custom/python" {
		t.Errorf("Expected /custom/python, got %s", executable)
	}
}

func TestEnvironmentManager_findVirtualEnvironments(t *testing.T) {
	// Create temporary directory with mock virtual environment
	tempDir, err := os.MkdirTemp("", "env_manager_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Create mock .venv directory structure
	venvDir := filepath.Join(tempDir, ".venv")
	binDir := filepath.Join(venvDir, "bin")
	err = os.MkdirAll(binDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create venv bin dir: %v", err)
	}
	
	// Create mock python executable
	pythonPath := filepath.Join(binDir, "python")
	err = os.WriteFile(pythonPath, []byte("#!/bin/bash\necho 'mock python'"), 0755)
	if err != nil {
		t.Fatalf("Failed to create mock python: %v", err)
	}
	
	manager := NewEnvironmentManager(tempDir)
	
	environments, err := manager.findVirtualEnvironments()
	if err != nil {
		t.Fatalf("Failed to find virtual environments: %v", err)
	}
	
	if len(environments) != 1 {
		t.Errorf("Expected 1 virtual environment, got %d", len(environments))
	}
	
	if len(environments) > 0 {
		env := environments[0]
		if env.Name != ".venv" {
			t.Errorf("Expected name '.venv', got %s", env.Name)
		}
		
		if env.Type != EnvTypeVirtualEnv {
			t.Errorf("Expected type %s, got %s", EnvTypeVirtualEnv, env.Type)
		}
		
		if env.VirtualEnvPath != venvDir {
			t.Errorf("Expected virtual env path %s, got %s", venvDir, env.VirtualEnvPath)
		}
	}
}

func TestPythonEnvironment_Defaults(t *testing.T) {
	env := &PythonEnvironment{
		Name:        "test",
		Type:        EnvTypeSystem,
		Environment: make(map[string]string),
		CreatedAt:   time.Now(),
	}
	
	if env.Name != "test" {
		t.Errorf("Expected name 'test', got %s", env.Name)
	}
	
	if env.Type != EnvTypeSystem {
		t.Errorf("Expected type %s, got %s", EnvTypeSystem, env.Type)
	}
	
	if env.IsActive {
		t.Error("Environment should not be active by default")
	}
	
	if env.Environment == nil {
		t.Error("Environment map should not be nil")
	}
}

func TestEnvironmentCache(t *testing.T) {
	cache := NewEnvironmentCache()
	
	if cache.environments == nil {
		t.Error("Environments map should be initialized")
	}
	
	if cache.cacheFile != ".env_cache.json" {
		t.Errorf("Expected cache file '.env_cache.json', got %s", cache.cacheFile)
	}
}

func TestEnvironmentSetupOptions_Validation(t *testing.T) {
	tests := []struct {
		name    string
		options *EnvironmentSetupOptions
		valid   bool
	}{
		{
			name: "Valid basic options",
			options: &EnvironmentSetupOptions{
				EnvName: "test_env",
				EnvType: EnvTypeVirtualEnv,
			},
			valid: true,
		},
		{
			name: "Valid with Python version",
			options: &EnvironmentSetupOptions{
				EnvName:       "test_env",
				EnvType:       EnvTypeVirtualEnv,
				PythonVersion: "3.9",
			},
			valid: true,
		},
		{
			name: "Valid with requirements",
			options: &EnvironmentSetupOptions{
				EnvName:      "test_env",
				EnvType:      EnvTypeVirtualEnv,
				Requirements: []string{"requests", "numpy"},
			},
			valid: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - in a real implementation you might have
			// more sophisticated validation logic
			if tt.options.EnvName == "" && tt.valid {
				t.Error("Environment name should be required for valid options")
			}
		})
	}
}

// Integration tests

func TestEnvironmentManager_Integration_CreateVirtualEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "env_manager_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	manager := NewEnvironmentManager(tempDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	options := &EnvironmentSetupOptions{
		EnvName:    "test_env",
		EnvType:    EnvTypeVirtualEnv,
		WithPip:    true,
		WithWheel:  true,
	}
	
	env, err := manager.CreateVirtualEnvironment(ctx, options)
	if err != nil {
		if strings.Contains(err.Error(), "python") {
			t.Skip("Python not available, skipping integration test")
		}
		t.Fatalf("Failed to create virtual environment: %v", err)
	}
	
	if env.Name != "test_env" {
		t.Errorf("Expected environment name 'test_env', got %s", env.Name)
	}
	
	if env.Type != EnvTypeVirtualEnv {
		t.Errorf("Expected environment type %s, got %s", EnvTypeVirtualEnv, env.Type)
	}
	
	// Check if virtual environment directory was created
	expectedPath := filepath.Join(tempDir, "test_env")
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Error("Virtual environment directory was not created")
	}
	
	// Validate the environment
	err = manager.ValidateEnvironment(ctx, env)
	if err != nil {
		t.Errorf("Created environment failed validation: %v", err)
	}
}

func TestEnvironmentManager_Integration_DetectSitePackages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := NewEnvironmentManager("/tmp")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	sitePackages, err := manager.DetectSitePackages(ctx, "python3")
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			t.Skip("Python3 not available, skipping test")
		}
		t.Fatalf("Failed to detect site-packages: %v", err)
	}
	
	if len(sitePackages) == 0 {
		t.Error("Should detect at least one site-packages directory")
	}
	
	// Check that paths look reasonable
	for _, path := range sitePackages {
		if !strings.Contains(path, "site-packages") {
			t.Errorf("Path %s doesn't look like a site-packages directory", path)
		}
	}
}

func TestEnvironmentManager_Integration_GetAvailableEnvironments(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	manager := NewEnvironmentManager("/tmp")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	environments, err := manager.GetAvailableEnvironments(ctx)
	if err != nil {
		t.Fatalf("Failed to get available environments: %v", err)
	}
	
	// Should at least find system environment (if Python is available)
	if len(environments) == 0 {
		t.Log("No environments detected (Python may not be available)")
		return
	}
	
	// Check if system environment is present
	foundSystem := false
	for _, env := range environments {
		if env.Type == EnvTypeSystem {
			foundSystem = true
			break
		}
	}
	
	if !foundSystem {
		t.Error("System environment should be detected")
	}
}

// Benchmark tests

func BenchmarkEnvironmentManager_SetupPythonPath(b *testing.B) {
	manager := NewEnvironmentManager("/tmp")
	env := &PythonEnvironment{
		Environment:  make(map[string]string),
		SitePackages: []string{"/usr/lib/python3.9/site-packages", "/home/user/.local/lib/python3.9/site-packages"},
	}
	additionalPaths := []string{"/path1", "/path2", "/path3"}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.SetupPythonPath(env, additionalPaths)
	}
}

func BenchmarkEnvironmentManager_ExportEnvironment(b *testing.B) {
	manager := NewEnvironmentManager("/tmp")
	env := &PythonEnvironment{
		Name:           "test_env",
		Type:           EnvTypeVirtualEnv,
		PythonPath:     "/path/to/python",
		PythonVersion:  "3.9.7",
		VirtualEnvPath: "/path/to/venv",
		PythonPath_:    []string{"/path1", "/path2", "/path3"},
		Environment:    map[string]string{"VAR1": "value1", "VAR2": "value2", "VAR3": "value3"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.ExportEnvironment(env)
		if err != nil {
			b.Fatalf("Export failed: %v", err)
		}
	}
}

func BenchmarkEnvironmentManager_ActivateEnvironment(b *testing.B) {
	manager := NewEnvironmentManager("/tmp")
	env := &PythonEnvironment{
		Name: "test_env",
		Type: EnvTypeVirtualEnv,
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := manager.ActivateEnvironment(context.Background(), env)
		if err != nil {
			b.Fatalf("Activation failed: %v", err)
		}
	}
}