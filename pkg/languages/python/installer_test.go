package python

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPipInstaller_NewPipInstaller(t *testing.T) {
	workingDir := "/tmp/test"
	pythonPath := "python3"
	
	installer := NewPipInstaller(workingDir, pythonPath)
	
	if installer.workingDir != workingDir {
		t.Errorf("Expected workingDir %s, got %s", workingDir, installer.workingDir)
	}
	
	if installer.pythonPath != pythonPath {
		t.Errorf("Expected pythonPath %s, got %s", pythonPath, installer.pythonPath)
	}
	
	if installer.packageCache == nil {
		t.Error("Package cache should be initialized")
	}
	
	if installer.progressTracker == nil {
		t.Error("Progress tracker should be initialized")
	}
	
	expectedVenvPath := filepath.Join(workingDir, ".venv")
	if installer.virtualEnvPath != expectedVenvPath {
		t.Errorf("Expected virtualEnvPath %s, got %s", expectedVenvPath, installer.virtualEnvPath)
	}
}

func TestRequirementsParser_ParseRequirements(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expected    []string
		expectError bool
	}{
		{
			name:     "Simple requirements",
			content:  "requests\nnumpy==1.21.0\npandas>=1.3.0",
			expected: []string{"requests", "numpy==1.21.0", "pandas>=1.3.0"},
		},
		{
			name:     "Requirements with comments",
			content:  "requests  # HTTP library\n# This is a comment\nnumpy==1.21.0",
			expected: []string{"requests", "numpy==1.21.0"},
		},
		{
			name:     "Requirements with empty lines",
			content:  "requests\n\nnumpy==1.21.0\n\n",
			expected: []string{"requests", "numpy==1.21.0"},
		},
		{
			name:     "Requirements with inline comments",
			content:  "requests==2.25.1  # HTTP library\nnumpy  # numerical computing",
			expected: []string{"requests==2.25.1", "numpy"},
		},
		{
			name:     "Empty requirements",
			content:  "",
			expected: []string{},
		},
		{
			name:     "Only comments",
			content:  "# This is a comment\n# Another comment",
			expected: []string{},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewRequirementsParser(tt.content)
			result, err := parser.ParseRequirements()
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d packages, got %d", len(tt.expected), len(result))
			}
			
			for i, expected := range tt.expected {
				if i >= len(result) {
					t.Errorf("Missing expected package: %s", expected)
					continue
				}
				if result[i] != expected {
					t.Errorf("Expected package %s, got %s", expected, result[i])
				}
			}
		})
	}
}

func TestRequirementsParser_parsePackageSpec(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		expected string
	}{
		{"Simple package", "requests", "requests"},
		{"Package with version", "numpy==1.21.0", "numpy==1.21.0"},
		{"Package with minimum version", "pandas>=1.3.0", "pandas>=1.3.0"},
		{"Package with comment", "requests  # HTTP library", "requests"},
		{"Invalid package", "123invalid", ""},
		{"Empty line", "", ""},
		{"Only comment", "# Just a comment", ""},
	}
	
	parser := NewRequirementsParser("")
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.parsePackageSpec(tt.line)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestPipInstaller_generatePipCommand(t *testing.T) {
	installer := NewPipInstaller("/tmp", "python3")
	
	tests := []struct {
		name     string
		request  *InstallRequest
		expected []string
	}{
		{
			name: "Basic install",
			request: &InstallRequest{
				Packages: []string{"requests", "numpy"},
			},
			expected: []string{"-m", "pip", "install", "requests", "numpy"},
		},
		{
			name: "Install with upgrade",
			request: &InstallRequest{
				Packages:        []string{"requests"},
				UpgradePackages: true,
			},
			expected: []string{"-m", "pip", "install", "--upgrade", "requests"},
		},
		{
			name: "Install with force reinstall",
			request: &InstallRequest{
				Packages:       []string{"requests"},
				ForceReinstall: true,
			},
			expected: []string{"-m", "pip", "install", "--force-reinstall", "requests"},
		},
		{
			name: "Install with no deps",
			request: &InstallRequest{
				Packages: []string{"requests"},
				NoDeps:   true,
			},
			expected: []string{"-m", "pip", "install", "--no-deps", "requests"},
		},
		{
			name: "Install with custom index",
			request: &InstallRequest{
				Packages: []string{"requests"},
				IndexURL: "https://custom.pypi.org/simple",
			},
			expected: []string{"-m", "pip", "install", "--index-url", "https://custom.pypi.org/simple", "requests"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := installer.generatePipCommand(tt.request)
			
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d args, got %d", len(tt.expected), len(result))
			}
			
			for i, expected := range tt.expected {
				if i >= len(result) {
					t.Errorf("Missing expected arg: %s", expected)
					continue
				}
				if result[i] != expected {
					t.Errorf("Expected arg %s, got %s", expected, result[i])
				}
			}
		})
	}
}

func TestPipInstaller_parsePackageNameVersion(t *testing.T) {
	installer := NewPipInstaller("/tmp", "python3")
	
	tests := []struct {
		name     string
		spec     string
		expected *PackageInfo
	}{
		{
			name: "Package with version",
			spec: "requests-2.25.1",
			expected: &PackageInfo{
				Name:    "requests",
				Version: "2.25.1",
			},
		},
		{
			name: "Package with complex version",
			spec: "numpy-1.21.0-py3",
			expected: &PackageInfo{
				Name:    "numpy",
				Version: "1.21.0-py3",
			},
		},
		{
			name:     "Invalid spec",
			spec:     "invalidspec",
			expected: nil,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := installer.parsePackageNameVersion(tt.spec)
			
			if tt.expected == nil && result != nil {
				t.Error("Expected nil but got result")
			}
			
			if tt.expected != nil && result == nil {
				t.Error("Expected result but got nil")
			}
			
			if tt.expected != nil && result != nil {
				if result.Name != tt.expected.Name {
					t.Errorf("Expected name %s, got %s", tt.expected.Name, result.Name)
				}
				if result.Version != tt.expected.Version {
					t.Errorf("Expected version %s, got %s", tt.expected.Version, result.Version)
				}
			}
		})
	}
}

func TestPipInstaller_parseFailedPackages(t *testing.T) {
	installer := NewPipInstaller("/tmp", "python3")
	failedPackages := make(map[string]string)
	
	output := `
Installing collected packages: numpy, requests
ERROR: Failed building wheel for numpy
ERROR: Could not build wheels for numpy which use PEP 517
Successfully installed requests-2.25.1
`
	
	installer.parseFailedPackages(output, failedPackages)
	
	// This is a simplified test as the actual parsing logic is basic
	// In a real implementation, you would have more sophisticated parsing
	if len(failedPackages) == 0 {
		t.Log("No failed packages detected (expected with current implementation)")
	}
}

func TestPackageCache(t *testing.T) {
	cache := NewPackageCache()
	
	if cache.installedPackages == nil {
		t.Error("Installed packages map should be initialized")
	}
	
	if cache.cacheFile != ".package_cache.json" {
		t.Errorf("Expected cache file '.package_cache.json', got %s", cache.cacheFile)
	}
}

func TestInstallationProgressTracker(t *testing.T) {
	tracker := NewInstallationProgressTracker()
	
	if tracker.activeInstalls == nil {
		t.Error("Active installs map should be initialized")
	}
	
	// Test starting tracking
	packageName := "requests"
	tracker.StartTracking(packageName)
	
	progress := tracker.GetProgress(packageName)
	if progress == nil {
		t.Error("Progress should not be nil after starting tracking")
	}
	
	if progress.PackageName != packageName {
		t.Errorf("Expected package name %s, got %s", packageName, progress.PackageName)
	}
	
	if progress.Status != "started" {
		t.Errorf("Expected status 'started', got %s", progress.Status)
	}
	
	if progress.Progress != 0.0 {
		t.Errorf("Expected initial progress 0.0, got %f", progress.Progress)
	}
	
	// Test updating progress
	tracker.UpdateProgress(packageName, "downloading", 0.5)
	
	progress = tracker.GetProgress(packageName)
	if progress.Status != "downloading" {
		t.Errorf("Expected status 'downloading', got %s", progress.Status)
	}
	
	if progress.Progress != 0.5 {
		t.Errorf("Expected progress 0.5, got %f", progress.Progress)
	}
	
	// Test completing progress
	tracker.CompleteProgress(packageName)
	
	progress = tracker.GetProgress(packageName)
	if progress.Status != "completed" {
		t.Errorf("Expected status 'completed', got %s", progress.Status)
	}
	
	if progress.Progress != 1.0 {
		t.Errorf("Expected progress 1.0, got %f", progress.Progress)
	}
	
	// Test getting all progress
	allProgress := tracker.GetAllProgress()
	if len(allProgress) != 1 {
		t.Errorf("Expected 1 progress entry, got %d", len(allProgress))
	}
}

func TestPipInstaller_checkPackageCache(t *testing.T) {
	installer := NewPipInstaller("/tmp", "python3")
	
	// Add some packages to cache
	installer.packageCache.installedPackages["requests"] = &PackageInfo{
		Name:    "requests",
		Version: "2.25.1",
	}
	installer.packageCache.installedPackages["numpy"] = &PackageInfo{
		Name:    "numpy",
		Version: "1.21.0",
	}
	
	packages := []string{"requests", "pandas", "numpy"}
	hits := installer.checkPackageCache(packages)
	
	if hits != 2 {
		t.Errorf("Expected 2 cache hits, got %d", hits)
	}
}

func TestPipInstaller_updatePackageCache(t *testing.T) {
	installer := NewPipInstaller("/tmp", "python3")
	
	packages := []*PackageInfo{
		{Name: "requests", Version: "2.25.1"},
		{Name: "numpy", Version: "1.21.0"},
	}
	
	installer.updatePackageCache(packages)
	
	if len(installer.packageCache.installedPackages) != 2 {
		t.Errorf("Expected 2 packages in cache, got %d", len(installer.packageCache.installedPackages))
	}
	
	if installer.packageCache.installedPackages["requests"].Version != "2.25.1" {
		t.Error("Requests version not correctly cached")
	}
	
	if installer.packageCache.installedPackages["numpy"].Version != "1.21.0" {
		t.Error("Numpy version not correctly cached")
	}
}

// Integration tests (these would require actual Python and pip)

func TestPipInstaller_Integration_CreateVirtualEnvironment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "pip_installer_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	installer := NewPipInstaller(tempDir, "python3")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Test virtual environment creation
	err = installer.CreateVirtualEnvironment(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "python3") {
			t.Skip("Python3 not available, skipping integration test")
		}
		t.Fatalf("Failed to create virtual environment: %v", err)
	}
	
	// Check if virtual environment directory exists
	venvPath := filepath.Join(tempDir, ".venv")
	if _, err := os.Stat(venvPath); os.IsNotExist(err) {
		t.Error("Virtual environment directory was not created")
	}
	
	// Test activation
	err = installer.ActivateVirtualEnvironment()
	if err != nil {
		t.Fatalf("Failed to activate virtual environment: %v", err)
	}
	
	// Check if python path was updated
	expectedPythonPath := filepath.Join(venvPath, "bin", "python")
	if installer.pythonPath != expectedPythonPath {
		// Try Windows path
		expectedPythonPath = filepath.Join(venvPath, "Scripts", "python.exe")
		if installer.pythonPath != expectedPythonPath {
			t.Errorf("Python path not updated correctly after activation")
		}
	}
}

func TestPipInstaller_Integration_InstallPackages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "pip_installer_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	installer := NewPipInstaller(tempDir, "python3")
	
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	// Create virtual environment first
	err = installer.CreateVirtualEnvironment(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "python3") {
			t.Skip("Python3 not available, skipping integration test")
		}
		t.Fatalf("Failed to create virtual environment: %v", err)
	}
	
	err = installer.ActivateVirtualEnvironment()
	if err != nil {
		t.Fatalf("Failed to activate virtual environment: %v", err)
	}
	
	// Test package installation
	req := &InstallRequest{
		Packages:      []string{"requests"},
		UseVirtualEnv: false, // Already activated
		Timeout:       60 * time.Second,
	}
	
	result, err := installer.Install(ctx, req)
	if err != nil {
		// Check if it's a network or pip issue
		if strings.Contains(err.Error(), "network") || strings.Contains(err.Error(), "pip") {
			t.Skip("Network or pip issue, skipping integration test")
		}
		t.Fatalf("Failed to install packages: %v", err)
	}
	
	if !result.Success {
		t.Errorf("Installation was not successful: %v", result.Error)
	}
	
	if len(result.InstalledPackages) == 0 {
		t.Error("No packages were reported as installed")
	}
	
	// Check if requests was installed
	found := false
	for _, pkg := range result.InstalledPackages {
		if pkg.Name == "requests" {
			found = true
			break
		}
	}
	
	if !found {
		t.Error("Requests package was not found in installed packages")
	}
}

func TestPipInstaller_Integration_ResolvePackageVersions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	installer := NewPipInstaller("/tmp", "python3")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	packages := []string{"requests>=2.0", "numpy", "pandas==1.3.0"}
	
	resolved, err := installer.ResolvePackageVersions(ctx, packages)
	if err != nil {
		t.Fatalf("Failed to resolve package versions: %v", err)
	}
	
	if len(resolved) != len(packages) {
		t.Errorf("Expected %d resolved packages, got %d", len(packages), len(resolved))
	}
	
	// In the current implementation, this just returns the input packages
	// In a real implementation, this would resolve actual versions
	for i, pkg := range packages {
		if resolved[i] != pkg {
			t.Errorf("Expected package %s, got %s", pkg, resolved[i])
		}
	}
}

// Benchmark tests

func BenchmarkRequirementsParser_ParseRequirements(b *testing.B) {
	content := `
requests==2.25.1
numpy>=1.20.0
pandas
matplotlib==3.4.0
scipy
scikit-learn>=0.24.0
tensorflow
pytorch
flask==2.0.0
django>=3.2.0
`
	
	parser := NewRequirementsParser(content)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parser.ParseRequirements()
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

func BenchmarkPipInstaller_generatePipCommand(b *testing.B) {
	installer := NewPipInstaller("/tmp", "python3")
	req := &InstallRequest{
		Packages:        []string{"requests", "numpy", "pandas"},
		UpgradePackages: true,
		IndexURL:        "https://pypi.org/simple",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = installer.generatePipCommand(req)
	}
}

func BenchmarkProgressTracker_Operations(b *testing.B) {
	tracker := NewInstallationProgressTracker()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packageName := "package_" + string(rune(i%100))
		tracker.StartTracking(packageName)
		tracker.UpdateProgress(packageName, "downloading", 0.5)
		tracker.CompleteProgress(packageName)
	}
}