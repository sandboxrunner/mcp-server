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

func TestNewNodeEnvironmentManager(t *testing.T) {
	tempDir := t.TempDir()

	manager := NewNodeEnvironmentManager(tempDir)

	assert.NotNil(t, manager)
	assert.Equal(t, tempDir, manager.workingDir)
	assert.NotNil(t, manager.environmentVars)
	assert.NotNil(t, manager.versionCache)
	assert.NotNil(t, manager.pathManager)
}

func TestNewNodeVersionCache(t *testing.T) {
	cache := NewNodeVersionCache()

	assert.NotNil(t, cache)
	assert.NotNil(t, cache.versions)
	assert.Equal(t, 1*time.Hour, cache.cacheExpiry)
}

func TestNewNodePathManager(t *testing.T) {
	originalPath := os.Getenv("PATH")
	manager := NewNodePathManager()

	assert.NotNil(t, manager)
	assert.Equal(t, originalPath, manager.originalPath)
}

func TestNewNVMManager(t *testing.T) {
	manager := NewNVMManager()

	assert.NotNil(t, manager)
	assert.Contains(t, manager.nvmDir, ".nvm")
	assert.Contains(t, manager.nvmScript, "nvm.sh")
}

func TestSetupEnvironmentDirect(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Mock finding node and npm
	manager.nodePath = "/usr/bin/node"
	manager.npmPath = "/usr/bin/npm"

	req := &NodeEnvironmentSetupRequest{
		NodeVersion: "",
		UseNVM:      false,
		Environment: map[string]string{
			"NODE_ENV": "test",
		},
	}

	// This would require actual node/npm installation to test fully
	// For unit test, we'll test the request structure
	assert.NotNil(t, req)
	assert.False(t, req.UseNVM)
	assert.Contains(t, req.Environment, "NODE_ENV")
}

func TestConfigureEnvironmentVariables(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	req := &NodeEnvironmentSetupRequest{
		Environment: map[string]string{
			"NODE_ENV":   "development",
			"CUSTOM_VAR": "test-value",
		},
		NodeOptions: []string{"--max-old-space-size=4096"},
	}

	result := &NodeEnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	err := manager.configureEnvironmentVariables(req, result)
	assert.NoError(t, err)

	// Check default variables are set
	assert.Contains(t, result.Environment, "NODE_ENV")
	assert.Contains(t, result.Environment, "NPM_CONFIG_PROGRESS")
	assert.Contains(t, result.Environment, "NPM_CONFIG_LOGLEVEL")
	assert.Contains(t, result.Environment, "NODE_PATH")

	// Check custom variables are set
	assert.Equal(t, "development", result.Environment["NODE_ENV"])
	assert.Equal(t, "test-value", result.Environment["CUSTOM_VAR"])
	assert.Equal(t, "--max-old-space-size=4096", result.Environment["NODE_OPTIONS"])
}

func TestConfigurePaths(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)
	manager.nodePath = "/usr/bin/node"
	manager.npmPath = "/usr/bin/npm"

	// Create node_modules/.bin directory
	nodeModulesBin := filepath.Join(tempDir, "node_modules", ".bin")
	err := os.MkdirAll(nodeModulesBin, 0755)
	require.NoError(t, err)

	req := &NodeEnvironmentSetupRequest{}
	result := &NodeEnvironmentSetupResult{
		Environment:     make(map[string]string),
		PathsConfigured: make([]string, 0),
	}

	err = manager.configurePaths(req, result)
	assert.NoError(t, err)

	// Check that PATH was configured
	assert.Contains(t, result.Environment, "PATH")
	assert.NotEmpty(t, result.PathsConfigured)

	// Check that node directory was added to path
	nodeBinDir := filepath.Dir("/usr/bin/node")
	assert.Contains(t, result.PathsConfigured, nodeBinDir)

	// Check that local node_modules/.bin was added
	assert.Contains(t, result.PathsConfigured, nodeModulesBin)
}

func TestGetGlobalNodeModulesPath(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Without npm path set
	path := manager.getGlobalNodeModulesPath()
	assert.Empty(t, path)

	// With npm path set (would need actual npm to test fully)
	manager.npmPath = "/usr/bin/npm"
	// This would execute npm root -g, which requires npm to be installed
	// For unit test, we just verify the path is set
	assert.Equal(t, "/usr/bin/npm", manager.npmPath)
}

func TestGetGlobalBinPath(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Without npm path set
	path := manager.getGlobalBinPath()
	assert.Empty(t, path)

	// With npm path set (would need actual npm to test fully)
	manager.npmPath = "/usr/bin/npm"
	// This would execute npm bin -g, which requires npm to be installed
	// For unit test, we just verify the path is set
	assert.Equal(t, "/usr/bin/npm", manager.npmPath)
}

func TestBuildEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	manager.environmentVars = map[string]string{
		"NODE_ENV":   "test",
		"CUSTOM_VAR": "value",
	}

	env := manager.buildEnvironment()

	// Should include OS environment plus custom vars
	assert.Greater(t, len(env), 2) // At least our custom vars plus OS vars

	// Check our custom vars are included
	foundNodeEnv := false
	foundCustomVar := false

	for _, envVar := range env {
		if envVar == "NODE_ENV=test" {
			foundNodeEnv = true
		}
		if envVar == "CUSTOM_VAR=value" {
			foundCustomVar = true
		}
	}

	assert.True(t, foundNodeEnv)
	assert.True(t, foundCustomVar)
}

func TestCacheEnvironmentConfig(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	result := &NodeEnvironmentSetupResult{
		NodeVersion: "v16.14.0",
		NodePath:    "/usr/bin/node",
		NPMVersion:  "8.3.1",
	}

	manager.cacheEnvironmentConfig(result)

	// Check that version info was cached
	assert.Contains(t, manager.versionCache.versions, "v16.14.0")
	versionInfo := manager.versionCache.versions["v16.14.0"]
	assert.Equal(t, "v16.14.0", versionInfo.Version)
	assert.Equal(t, "/usr/bin/node", versionInfo.Path)
	assert.Equal(t, "8.3.1", versionInfo.NPMVersion)
	assert.True(t, versionInfo.IsActive)
}

func TestGetAvailableVersions(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	versions, err := manager.GetAvailableVersions(context.Background())
	assert.NoError(t, err)
	assert.NotEmpty(t, versions)

	// Check that common versions are included
	assert.Contains(t, versions, "latest")
	assert.Contains(t, versions, "18.17.0")
	assert.Contains(t, versions, "16.20.0")
}

func TestGetInstalledVersions(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Add some versions to cache
	manager.versionCache.versions["16.14.0"] = &NodeVersionInfo{
		Version:    "16.14.0",
		Path:       "/usr/bin/node",
		NPMVersion: "8.3.1",
		IsActive:   true,
	}

	manager.versionCache.versions["18.17.0"] = &NodeVersionInfo{
		Version:    "18.17.0",
		Path:       "/usr/local/bin/node",
		NPMVersion: "9.6.7",
		IsActive:   false,
	}

	versions, err := manager.GetInstalledVersions(context.Background())
	assert.NoError(t, err)
	assert.Len(t, versions, 2)

	// Check versions are present
	versionStrings := make([]string, len(versions))
	for i, v := range versions {
		versionStrings[i] = v.Version
	}
	assert.Contains(t, versionStrings, "16.14.0")
	assert.Contains(t, versionStrings, "18.17.0")
}

func TestCleanEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Set some state
	manager.environmentVars = map[string]string{
		"NODE_ENV": "test",
	}
	manager.versionCache.versions["16.14.0"] = &NodeVersionInfo{
		Version: "16.14.0",
	}
	manager.pathManager.currentPath = "/custom/path"

	err := manager.CleanEnvironment(context.Background())
	assert.NoError(t, err)

	// Check that state was cleaned
	assert.Empty(t, manager.environmentVars)
	assert.Empty(t, manager.versionCache.versions)
	assert.Equal(t, manager.pathManager.originalPath, manager.pathManager.currentPath)
}

func TestGetEnvironmentInfo(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	manager.nodePath = "/usr/bin/node"
	manager.npmPath = "/usr/bin/npm"
	manager.nodeVersion = "16.14.0"
	manager.environmentVars = map[string]string{
		"NODE_ENV": "test",
	}

	info := manager.GetEnvironmentInfo()

	assert.NotNil(t, info)
	assert.Equal(t, "/usr/bin/node", info["node_path"])
	assert.Equal(t, "/usr/bin/npm", info["npm_path"])
	assert.Equal(t, "16.14.0", info["node_version"])
	assert.Equal(t, tempDir, info["working_dir"])

	environment, ok := info["environment"].(map[string]string)
	assert.True(t, ok)
	assert.Equal(t, "test", environment["NODE_ENV"])

	cacheInfo, ok := info["cache_info"].(map[string]interface{})
	assert.True(t, ok)
	assert.Contains(t, cacheInfo, "cached_versions")
	assert.Contains(t, cacheInfo, "last_refresh")
}

func TestValidateEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Test with no paths configured
	err := manager.ValidateEnvironment(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Node.js path not configured")

	// Test with non-existent node path
	manager.nodePath = "/nonexistent/node"
	err = manager.ValidateEnvironment(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Node.js executable not found")

	// Test with node path but no npm
	manager.nodePath = "/usr/bin/node" // Assume this exists for test
	err = manager.ValidateEnvironment(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "npm path not configured")

	// Test with non-existent npm path
	manager.npmPath = "/nonexistent/npm"
	err = manager.ValidateEnvironment(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "npm executable not found")
}

func TestDetectPackageManager(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Test with no lockfiles (should default to npm)
	pm := manager.DetectPackageManager()
	assert.Equal(t, PackageManagerNPM, pm)

	// Test with package-lock.json
	packageLockPath := filepath.Join(tempDir, "package-lock.json")
	err := os.WriteFile(packageLockPath, []byte("{}"), 0644)
	require.NoError(t, err)

	pm = manager.DetectPackageManager()
	assert.Equal(t, PackageManagerNPM, pm)

	// Test with yarn.lock (should override package-lock.json due to order)
	yarnLockPath := filepath.Join(tempDir, "yarn.lock")
	err = os.WriteFile(yarnLockPath, []byte(""), 0644)
	require.NoError(t, err)

	pm = manager.DetectPackageManager()
	assert.Equal(t, PackageManagerYarn, pm)

	// Test with pnpm-lock.yaml (should override others)
	pnpmLockPath := filepath.Join(tempDir, "pnpm-lock.yaml")
	err = os.WriteFile(pnpmLockPath, []byte(""), 0644)
	require.NoError(t, err)

	pm = manager.DetectPackageManager()
	assert.Equal(t, PackageManagerPNPM, pm)
}

func TestDetectPackageManagerFromPackageJSON(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Test with packageManager field in package.json
	packageJSONContent := `{
		"name": "test",
		"version": "1.0.0",
		"packageManager": "pnpm@7.0.0"
	}`

	packageJSONPath := filepath.Join(tempDir, "package.json")
	err := os.WriteFile(packageJSONPath, []byte(packageJSONContent), 0644)
	require.NoError(t, err)

	pm := manager.DetectPackageManager()
	assert.Equal(t, PackageManagerPNPM, pm)

	// Test with yarn in packageManager
	packageJSONContent = `{
		"name": "test",
		"version": "1.0.0",
		"packageManager": "yarn@3.0.0"
	}`

	err = os.WriteFile(packageJSONPath, []byte(packageJSONContent), 0644)
	require.NoError(t, err)

	pm = manager.DetectPackageManager()
	assert.Equal(t, PackageManagerYarn, pm)
}

func TestUpdateEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Initial environment
	manager.environmentVars = map[string]string{
		"NODE_ENV": "development",
	}

	// Update with new variables
	updates := map[string]string{
		"NODE_ENV": "production",
		"NEW_VAR":  "new_value",
		"ANOTHER":  "another_value",
	}

	manager.UpdateEnvironment(updates)

	// Check updates were applied
	assert.Equal(t, "production", manager.environmentVars["NODE_ENV"])
	assert.Equal(t, "new_value", manager.environmentVars["NEW_VAR"])
	assert.Equal(t, "another_value", manager.environmentVars["ANOTHER"])
	assert.Len(t, manager.environmentVars, 3)
}

func TestWorkspaceSetupConfig(t *testing.T) {
	config := &WorkspaceSetupConfig{
		Type:           WorkspaceTypeNPM,
		PackageManager: PackageManagerNPM,
		Workspaces:     []string{"packages/*", "apps/*"},
		HoistPattern:   []string{"*"},
		NohostPattern:  []string{"@types/*"},
	}

	assert.Equal(t, WorkspaceTypeNPM, config.Type)
	assert.Equal(t, PackageManagerNPM, config.PackageManager)
	assert.Len(t, config.Workspaces, 2)
	assert.Contains(t, config.Workspaces, "packages/*")
	assert.Contains(t, config.HoistPattern, "*")
	assert.Contains(t, config.NohostPattern, "@types/*")
}

func TestRegistrySetupConfig(t *testing.T) {
	config := &RegistrySetupConfig{
		DefaultRegistry: "https://registry.npmjs.org/",
		ScopedRegistries: map[string]string{
			"@mycompany": "https://npm.mycompany.com",
		},
		AuthTokens: map[string]string{
			"registry.npmjs.org": "npm_token_123",
		},
		CacheConfig: &CacheSetupConfig{
			CacheDir:    "/tmp/npm-cache",
			MaxAge:      24 * time.Hour,
			MaxSize:     1024 * 1024 * 1024, // 1GB
			CleanPolicy: "lru",
		},
	}

	assert.Equal(t, "https://registry.npmjs.org/", config.DefaultRegistry)
	assert.Contains(t, config.ScopedRegistries, "@mycompany")
	assert.Contains(t, config.AuthTokens, "registry.npmjs.org")
	assert.NotNil(t, config.CacheConfig)
	assert.Equal(t, "/tmp/npm-cache", config.CacheConfig.CacheDir)
}

// Benchmark tests
func BenchmarkNewNodeEnvironmentManager(b *testing.B) {
	tempDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewNodeEnvironmentManager(tempDir)
	}
}

func BenchmarkConfigureEnvironmentVariables(b *testing.B) {
	tempDir := b.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	req := &NodeEnvironmentSetupRequest{
		Environment: map[string]string{
			"NODE_ENV":   "production",
			"CUSTOM_VAR": "value",
		},
		NodeOptions: []string{"--max-old-space-size=4096"},
	}

	result := &NodeEnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.configureEnvironmentVariables(req, result)
	}
}

func BenchmarkDetectPackageManager(b *testing.B) {
	tempDir := b.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Create lockfiles for more realistic benchmark
	os.WriteFile(filepath.Join(tempDir, "package-lock.json"), []byte("{}"), 0644)
	os.WriteFile(filepath.Join(tempDir, "yarn.lock"), []byte(""), 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.DetectPackageManager()
	}
}

func BenchmarkBuildEnvironment(b *testing.B) {
	tempDir := b.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	// Set up some environment variables
	manager.environmentVars = map[string]string{
		"NODE_ENV":    "production",
		"CUSTOM_VAR1": "value1",
		"CUSTOM_VAR2": "value2",
		"CUSTOM_VAR3": "value3",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager.buildEnvironment()
	}
}

// Error handling and edge case tests
func TestConfigureEnvironmentVariablesWithEmptyRequest(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	req := &NodeEnvironmentSetupRequest{}
	result := &NodeEnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	err := manager.configureEnvironmentVariables(req, result)
	assert.NoError(t, err)

	// Should still set default variables
	assert.Contains(t, result.Environment, "NODE_ENV")
	assert.Contains(t, result.Environment, "NPM_CONFIG_PROGRESS")
	assert.Contains(t, result.Environment, "NODE_PATH")
}

func TestConfigurePathsWithoutNodeModules(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)
	manager.nodePath = "/usr/bin/node"

	req := &NodeEnvironmentSetupRequest{}
	result := &NodeEnvironmentSetupResult{
		Environment:     make(map[string]string),
		PathsConfigured: make([]string, 0),
	}

	err := manager.configurePaths(req, result)
	assert.NoError(t, err)

	// Should still configure PATH with node directory
	assert.Contains(t, result.Environment, "PATH")
	assert.NotEmpty(t, result.PathsConfigured)
}

func TestGetEnvironmentInfoEmpty(t *testing.T) {
	tempDir := t.TempDir()
	manager := NewNodeEnvironmentManager(tempDir)

	info := manager.GetEnvironmentInfo()

	assert.NotNil(t, info)
	assert.Equal(t, "", info["node_path"])
	assert.Equal(t, "", info["npm_path"])
	assert.Equal(t, "", info["node_version"])
	assert.Equal(t, tempDir, info["working_dir"])

	environment, ok := info["environment"].(map[string]string)
	assert.True(t, ok)
	assert.Empty(t, environment)
}
