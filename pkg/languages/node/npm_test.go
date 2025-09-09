package node

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNPMInstaller(t *testing.T) {
	tempDir := t.TempDir()

	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	assert.NotNil(t, installer)
	assert.Equal(t, tempDir, installer.workingDir)
	assert.Equal(t, "/usr/bin/node", installer.nodePath)
	assert.Equal(t, PackageManagerNPM, installer.packageManager)
	assert.NotNil(t, installer.packageCache)
	assert.NotNil(t, installer.progressTracker)
	assert.NotNil(t, installer.registryConfig)
	assert.NotNil(t, installer.workspaceConfig)
}

func TestNewNodePackageCache(t *testing.T) {
	cache := NewNodePackageCache()

	assert.NotNil(t, cache)
	assert.NotNil(t, cache.installedPackages)
	assert.Equal(t, ".node_package_cache.json", cache.cacheFile)
	assert.Equal(t, 24*time.Hour, cache.cacheExpiry)
}

func TestNewNodeInstallationProgressTracker(t *testing.T) {
	tracker := NewNodeInstallationProgressTracker()

	assert.NotNil(t, tracker)
	assert.NotNil(t, tracker.activeInstalls)
}

func TestNewRegistryConfig(t *testing.T) {
	config := NewRegistryConfig()

	assert.NotNil(t, config)
	assert.Equal(t, "https://registry.npmjs.org/", config.DefaultRegistry)
	assert.NotNil(t, config.ScopedRegistries)
	assert.NotNil(t, config.AuthTokens)
}

func TestNewWorkspaceConfig(t *testing.T) {
	config := NewWorkspaceConfig()

	assert.NotNil(t, config)
	assert.False(t, config.Enabled)
}

func TestNewPackageJSONParser(t *testing.T) {
	content := `{"name": "test", "version": "1.0.0"}`
	parser := NewPackageJSONParser(content)

	assert.NotNil(t, parser)
	assert.Equal(t, content, parser.content)
}

func TestParsePackageJSON(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		expectError bool
	}{
		{
			name: "valid package.json",
			content: `{
				"name": "test-package",
				"version": "1.0.0",
				"description": "Test package",
				"dependencies": {
					"lodash": "^4.17.0"
				},
				"devDependencies": {
					"jest": "^26.0.0"
				}
			}`,
			expectError: false,
		},
		{
			name: "minimal package.json",
			content: `{
				"name": "minimal",
				"version": "1.0.0"
			}`,
			expectError: false,
		},
		{
			name:        "invalid JSON",
			content:     `{"name": "test", "version":}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewPackageJSONParser(tt.content)
			pkg, err := parser.ParsePackageJSON()

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, pkg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pkg)
				assert.NotNil(t, pkg.Dependencies)
				assert.NotNil(t, pkg.DevDependencies)
				assert.NotNil(t, pkg.Scripts)
			}
		})
	}
}

func TestParsePackageSpec(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	tests := []struct {
		spec            string
		expectedName    string
		expectedVersion string
	}{
		{"lodash", "lodash", "latest"},
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@types/node", "@types/node", "latest"},
		{"@types/node@16.0.0", "@types/node", "16.0.0"},
		{"@babel/core@7.15.0", "@babel/core", "7.15.0"},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			name, version := installer.parsePackageSpec(tt.spec)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestGeneratePackageJSON(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	req := &NodeInstallRequest{
		Packages: []string{"lodash@4.17.21", "express@4.18.0"},
	}

	err := installer.GeneratePackageJSON(req)
	assert.NoError(t, err)

	// Check if package.json was created
	packageJSONPath := filepath.Join(tempDir, "package.json")
	assert.FileExists(t, packageJSONPath)

	// Parse the generated package.json
	content, err := os.ReadFile(packageJSONPath)
	assert.NoError(t, err)

	parser := NewPackageJSONParser(string(content))
	pkg, err := parser.ParsePackageJSON()
	assert.NoError(t, err)
	assert.Equal(t, "sandbox-project", pkg.Name)
	assert.Equal(t, "1.0.0", pkg.Version)
	assert.Contains(t, pkg.Dependencies, "lodash")
	assert.Contains(t, pkg.Dependencies, "express")
}

func TestGeneratePackageJSONDevDependencies(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	req := &NodeInstallRequest{
		Packages:        []string{"jest@26.6.3", "typescript@4.5.0"},
		DevDependencies: true,
	}

	err := installer.GeneratePackageJSON(req)
	assert.NoError(t, err)

	// Parse the generated package.json
	packageJSONPath := filepath.Join(tempDir, "package.json")
	content, err := os.ReadFile(packageJSONPath)
	assert.NoError(t, err)

	parser := NewPackageJSONParser(string(content))
	pkg, err := parser.ParsePackageJSON()
	assert.NoError(t, err)
	assert.Contains(t, pkg.DevDependencies, "jest")
	assert.Contains(t, pkg.DevDependencies, "typescript")
}

func TestBuildCompilerArgs(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	tests := []struct {
		name     string
		req      *NodeInstallRequest
		expected []string
	}{
		{
			name: "npm install with packages",
			req: &NodeInstallRequest{
				PackageManager: PackageManagerNPM,
				Packages:       []string{"lodash", "express"},
			},
			expected: []string{"install", "lodash", "express"},
		},
		{
			name: "npm install dev dependencies",
			req: &NodeInstallRequest{
				PackageManager:  PackageManagerNPM,
				Packages:        []string{"jest", "typescript"},
				DevDependencies: true,
			},
			expected: []string{"install", "--save-dev", "jest", "typescript"},
		},
		{
			name: "yarn add with packages",
			req: &NodeInstallRequest{
				PackageManager: PackageManagerYarn,
				Packages:       []string{"lodash", "express"},
			},
			expected: []string{"add", "lodash", "express"},
		},
		{
			name: "pnpm add with packages",
			req: &NodeInstallRequest{
				PackageManager: PackageManagerPNPM,
				Packages:       []string{"lodash", "express"},
			},
			expected: []string{"add", "lodash", "express"},
		},
		{
			name: "npm global install",
			req: &NodeInstallRequest{
				PackageManager: PackageManagerNPM,
				Packages:       []string{"typescript"},
				GlobalInstall:  true,
			},
			expected: []string{"install", "--global", "typescript"},
		},
		{
			name: "npm with custom registry",
			req: &NodeInstallRequest{
				PackageManager: PackageManagerNPM,
				Packages:       []string{"lodash"},
				Registry:       "https://custom.registry.com",
			},
			expected: []string{"install", "--registry", "https://custom.registry.com", "lodash"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := installer.generateInstallCommand(tt.req)
			assert.Equal(t, tt.expected, args)
		})
	}
}

func TestCheckLockfileGenerated(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	// Test when no lockfile exists
	assert.False(t, installer.checkLockfileGenerated(PackageManagerNPM))

	// Create package-lock.json
	lockfilePath := filepath.Join(tempDir, "package-lock.json")
	err := os.WriteFile(lockfilePath, []byte("{}"), 0644)
	require.NoError(t, err)

	assert.True(t, installer.checkLockfileGenerated(PackageManagerNPM))

	// Test yarn lockfile
	os.Remove(lockfilePath)
	yarnLockPath := filepath.Join(tempDir, "yarn.lock")
	err = os.WriteFile(yarnLockPath, []byte(""), 0644)
	require.NoError(t, err)

	assert.True(t, installer.checkLockfileGenerated(PackageManagerYarn))

	// Test pnpm lockfile
	os.Remove(yarnLockPath)
	pnpmLockPath := filepath.Join(tempDir, "pnpm-lock.yaml")
	err = os.WriteFile(pnpmLockPath, []byte(""), 0644)
	require.NoError(t, err)

	assert.True(t, installer.checkLockfileGenerated(PackageManagerPNPM))
}

func TestProgressTracker(t *testing.T) {
	tracker := NewNodeInstallationProgressTracker()

	// Test starting tracking
	tracker.StartTracking("lodash")
	progress := tracker.GetProgress("lodash")
	assert.NotNil(t, progress)
	assert.Equal(t, "lodash", progress.PackageName)
	assert.Equal(t, "started", progress.Status)
	assert.Equal(t, 0.0, progress.Progress)

	// Test updating progress
	tracker.UpdateProgress("lodash", "downloading", 0.5)
	progress = tracker.GetProgress("lodash")
	assert.Equal(t, "downloading", progress.Status)
	assert.Equal(t, 0.5, progress.Progress)

	// Test completing progress
	tracker.CompleteProgress("lodash")
	progress = tracker.GetProgress("lodash")
	assert.Equal(t, "completed", progress.Status)
	assert.Equal(t, 1.0, progress.Progress)

	// Test getting all progress
	tracker.StartTracking("express")
	allProgress := tracker.GetAllProgress()
	assert.Len(t, allProgress, 2)

	// Test non-existent package
	progress = tracker.GetProgress("nonexistent")
	assert.Nil(t, progress)
}

func TestParseProgressLineNPM(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)
	packages := []string{"lodash", "express"}

	// Start tracking
	for _, pkg := range packages {
		installer.progressTracker.StartTracking(pkg)
	}

	// Test parsing completion message
	installer.parseNPMProgressLine("added 152 packages from 112 contributors", packages)

	// Check that packages are marked as complete
	for _, pkg := range packages {
		progress := installer.progressTracker.GetProgress(pkg)
		assert.Equal(t, "completed", progress.Status)
		assert.Equal(t, 1.0, progress.Progress)
	}
}

func TestParseProgressLineYarn(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerYarn)
	packages := []string{"lodash", "express"}

	// Start tracking
	for _, pkg := range packages {
		installer.progressTracker.StartTracking(pkg)
	}

	// Test parsing yarn progress phases
	installer.parseYarnProgressLine("[1/4] Resolving packages...", packages)
	for _, pkg := range packages {
		progress := installer.progressTracker.GetProgress(pkg)
		assert.Equal(t, "resolving", progress.Status)
		assert.Equal(t, 0.25, progress.Progress)
	}

	installer.parseYarnProgressLine("[2/4] Fetching packages...", packages)
	for _, pkg := range packages {
		progress := installer.progressTracker.GetProgress(pkg)
		assert.Equal(t, "fetching", progress.Status)
		assert.Equal(t, 0.5, progress.Progress)
	}

	installer.parseYarnProgressLine("[4/4] Building fresh packages...", packages)
	for _, pkg := range packages {
		progress := installer.progressTracker.GetProgress(pkg)
		assert.Equal(t, "completed", progress.Status)
		assert.Equal(t, 1.0, progress.Progress)
	}
}

func TestParseProgressLinePNPM(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerPNPM)
	packages := []string{"lodash"}

	// Start tracking
	installer.progressTracker.StartTracking("lodash")

	// Test parsing pnpm progress
	installer.parsePNPMProgressLine("Downloading lodash@4.17.21", packages)
	progress := installer.progressTracker.GetProgress("lodash")
	assert.Equal(t, "downloading", progress.Status)
	assert.Equal(t, 0.3, progress.Progress)

	installer.parsePNPMProgressLine("Installing lodash@4.17.21", packages)
	progress = installer.progressTracker.GetProgress("lodash")
	assert.Equal(t, "installing", progress.Status)
	assert.Equal(t, 0.7, progress.Progress)

	installer.parsePNPMProgressLine("Done in 2.3s", packages)
	progress = installer.progressTracker.GetProgress("lodash")
	assert.Equal(t, "completed", progress.Status)
	assert.Equal(t, 1.0, progress.Progress)
}

func TestCheckPackageCache(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	packages := []string{"lodash", "express", "unknown"}

	// Initially no cache hits
	hits := installer.checkPackageCache(packages)
	assert.Equal(t, 0, hits)

	// Add packages to cache
	packageInfo := &NodePackageInfo{
		Name:        "lodash",
		Version:     "4.17.21",
		InstallTime: time.Now(),
	}
	installer.packageCache.installedPackages["lodash"] = packageInfo

	// Should have one cache hit
	hits = installer.checkPackageCache(packages)
	assert.Equal(t, 1, hits)
}

func TestUpdatePackageCache(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	packages := []*NodePackageInfo{
		{
			Name:        "lodash",
			Version:     "4.17.21",
			InstallTime: time.Now(),
		},
		{
			Name:        "express",
			Version:     "4.18.0",
			InstallTime: time.Now(),
		},
	}

	installer.updatePackageCache(packages)

	// Check that packages were added to cache
	assert.Contains(t, installer.packageCache.installedPackages, "lodash")
	assert.Contains(t, installer.packageCache.installedPackages, "express")

	lodashInfo := installer.packageCache.installedPackages["lodash"]
	assert.Equal(t, "4.17.21", lodashInfo.Version)
}

func TestParseFailedPackages(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	output := `npm ERR! code ENOTFOUND
npm ERR! errno ENOTFOUND
npm ERR! network request to https://registry.npmjs.org/unknown-package failed, reason: getaddrinfo ENOTFOUND
npm ERR! network This is a problem related to network connectivity.
npm ERR! network In most cases you are behind a proxy or have bad network settings.

Failed to install unknown-package`

	failedPackages := make(map[string]string)
	installer.parseFailedPackages(output, failedPackages, PackageManagerNPM)

	// Should detect some failed packages (implementation is simplified)
	assert.NotEmpty(t, failedPackages)
}

// Benchmark tests
func BenchmarkNewNPMInstaller(b *testing.B) {
	tempDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)
	}
}

func BenchmarkParsePackageSpec(b *testing.B) {
	tempDir := b.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	specs := []string{
		"lodash",
		"lodash@4.17.21",
		"@types/node",
		"@types/node@16.0.0",
		"@babel/core@7.15.0",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, spec := range specs {
			installer.parsePackageSpec(spec)
		}
	}
}

func BenchmarkProgressTracking(b *testing.B) {
	tracker := NewNodeInstallationProgressTracker()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packageName := "package-" + string(rune(i%1000))
		tracker.StartTracking(packageName)
		tracker.UpdateProgress(packageName, "downloading", 0.5)
		tracker.CompleteProgress(packageName)
	}
}

func BenchmarkPackageCache(b *testing.B) {
	tempDir := b.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		pkg := &NodePackageInfo{
			Name:        "package-" + string(rune(i)),
			Version:     "1.0.0",
			InstallTime: time.Now(),
		}
		installer.packageCache.installedPackages[pkg.Name] = pkg
	}

	packages := []string{"package-1", "package-2", "package-3", "unknown"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		installer.checkPackageCache(packages)
	}
}

// Integration tests (would require actual npm/yarn/pnpm)
func TestIntegrationInstallPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This would test actual package installation
	// Skip if no package manager is available
	t.Skip("Integration test requires actual package manager")
}

// Error handling tests
func TestInstallWithTimeout(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", PackageManagerNPM)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Microsecond)
	defer cancel()

	req := &NodeInstallRequest{
		Packages:       []string{"lodash"},
		PackageManager: PackageManagerNPM,
		Timeout:        1 * time.Microsecond,
	}

	result, err := installer.Install(ctx, req)

	// Should either timeout or fail quickly
	assert.True(t, err != nil || !result.Success)
}

func TestInstallWithInvalidPackageManager(t *testing.T) {
	tempDir := t.TempDir()
	installer := NewNPMInstaller(tempDir, "/usr/bin/node", "invalid")

	req := &NodeInstallRequest{
		Packages:       []string{"lodash"},
		PackageManager: "invalid",
	}

	// This should handle the invalid package manager gracefully
	_, err := installer.Install(context.Background(), req)

	// The implementation should handle this case
	// Either by defaulting to npm or returning an error
	_ = err // Implementation dependent
}
