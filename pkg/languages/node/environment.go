package node

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// NodeEnvironmentManager handles Node.js environment setup and management
type NodeEnvironmentManager struct {
	workingDir      string
	nodeVersion     string
	nodePath        string
	npmPath         string
	nvmPath         string
	environmentVars map[string]string
	mutex           sync.RWMutex
	versionCache    *NodeVersionCache
	pathManager     *NodePathManager
}

// NewNodeEnvironmentManager creates a new Node environment manager
func NewNodeEnvironmentManager(workingDir string) *NodeEnvironmentManager {
	return &NodeEnvironmentManager{
		workingDir:      workingDir,
		environmentVars: make(map[string]string),
		versionCache:    NewNodeVersionCache(),
		pathManager:     NewNodePathManager(),
	}
}

// NodeVersionCache caches Node version information
type NodeVersionCache struct {
	versions    map[string]*NodeVersionInfo
	mutex       sync.RWMutex
	cacheExpiry time.Duration
	lastRefresh time.Time
}

// NodeVersionInfo contains information about a Node.js version
type NodeVersionInfo struct {
	Version      string    `json:"version"`
	Path         string    `json:"path"`
	NPMVersion   string    `json:"npm_version"`
	Architecture string    `json:"architecture"`
	Platform     string    `json:"platform"`
	InstallTime  time.Time `json:"install_time"`
	IsActive     bool      `json:"is_active"`
	IsLTS        bool      `json:"is_lts"`
}

// NewNodeVersionCache creates a new Node version cache
func NewNodeVersionCache() *NodeVersionCache {
	return &NodeVersionCache{
		versions:    make(map[string]*NodeVersionInfo),
		cacheExpiry: 1 * time.Hour,
	}
}

// NodePathManager manages Node.js PATH and environment variables
type NodePathManager struct {
	originalPath    string
	currentPath     string
	nodeModulesPath string
	globalPath      string
	localPath       string
	mutex           sync.RWMutex
}

// NewNodePathManager creates a new Node path manager
func NewNodePathManager() *NodePathManager {
	return &NodePathManager{
		originalPath: os.Getenv("PATH"),
	}
}

// NodeEnvironmentSetupRequest contains Node environment setup parameters
type NodeEnvironmentSetupRequest struct {
	NodeVersion     string                `json:"node_version"`
	NPMVersion      string                `json:"npm_version"`
	UseNVM          bool                  `json:"use_nvm"`
	GlobalPackages  []string              `json:"global_packages"`
	Environment     map[string]string     `json:"environment"`
	NodeOptions     []string              `json:"node_options"`
	NPMOptions      map[string]string     `json:"npm_options"`
	WorkspaceConfig *WorkspaceSetupConfig `json:"workspace_config"`
	RegistryConfig  *RegistrySetupConfig  `json:"registry_config"`
	Timeout         time.Duration         `json:"timeout"`
}

// WorkspaceSetupConfig contains workspace configuration
type WorkspaceSetupConfig struct {
	Type           WorkspaceType  `json:"type"`
	PackageManager PackageManager `json:"package_manager"`
	Workspaces     []string       `json:"workspaces"`
	HoistPattern   []string       `json:"hoist_pattern"`
	NohostPattern  []string       `json:"nohoist_pattern"`
}

// WorkspaceType represents different workspace types
type WorkspaceType string

const (
	WorkspaceTypeNone  WorkspaceType = "none"
	WorkspaceTypeNPM   WorkspaceType = "npm"
	WorkspaceTypeYarn  WorkspaceType = "yarn"
	WorkspaceTypeLerna WorkspaceType = "lerna"
	WorkspaceTypeRush  WorkspaceType = "rush"
)

// RegistrySetupConfig contains registry configuration
type RegistrySetupConfig struct {
	DefaultRegistry  string            `json:"default_registry"`
	ScopedRegistries map[string]string `json:"scoped_registries"`
	AuthTokens       map[string]string `json:"auth_tokens"`
	CacheConfig      *CacheSetupConfig `json:"cache_config"`
}

// CacheSetupConfig contains cache configuration
type CacheSetupConfig struct {
	CacheDir    string        `json:"cache_dir"`
	MaxAge      time.Duration `json:"max_age"`
	MaxSize     int64         `json:"max_size"`
	CleanPolicy string        `json:"clean_policy"`
}

// NodeEnvironmentSetupResult contains Node environment setup result
type NodeEnvironmentSetupResult struct {
	Success         bool               `json:"success"`
	NodeVersion     string             `json:"node_version"`
	NPMVersion      string             `json:"npm_version"`
	NodePath        string             `json:"node_path"`
	NPMPath         string             `json:"npm_path"`
	Environment     map[string]string  `json:"environment"`
	GlobalPackages  []*NodePackageInfo `json:"global_packages"`
	WorkspaceInfo   *WorkspaceInfo     `json:"workspace_info"`
	Output          string             `json:"output"`
	Error           error              `json:"error"`
	Duration        time.Duration      `json:"duration"`
	PathsConfigured []string           `json:"paths_configured"`
}

// WorkspaceInfo contains information about the workspace
type WorkspaceInfo struct {
	Type           WorkspaceType     `json:"type"`
	RootDir        string            `json:"root_dir"`
	PackageManager PackageManager    `json:"package_manager"`
	Workspaces     []string          `json:"workspaces"`
	PackageCount   int               `json:"package_count"`
	Dependencies   map[string]string `json:"dependencies"`
}

// NVMManager handles Node Version Manager integration
type NVMManager struct {
	nvmDir            string
	nvmScript         string
	availableVersions []string
	installedVersions []string
	currentVersion    string
	mutex             sync.RWMutex
}

// NewNVMManager creates a new NVM manager
func NewNVMManager() *NVMManager {
	nvmDir := os.Getenv("NVM_DIR")
	if nvmDir == "" {
		nvmDir = filepath.Join(os.Getenv("HOME"), ".nvm")
	}

	return &NVMManager{
		nvmDir:    nvmDir,
		nvmScript: filepath.Join(nvmDir, "nvm.sh"),
	}
}

// SetupEnvironment sets up the Node.js environment
func (nem *NodeEnvironmentManager) SetupEnvironment(ctx context.Context, req *NodeEnvironmentSetupRequest) (*NodeEnvironmentSetupResult, error) {
	startTime := time.Now()
	result := &NodeEnvironmentSetupResult{
		Environment:     make(map[string]string),
		PathsConfigured: make([]string, 0),
	}

	// Set default timeout if not specified
	if req.Timeout == 0 {
		req.Timeout = 10 * time.Minute
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	log.Info().
		Str("node_version", req.NodeVersion).
		Bool("use_nvm", req.UseNVM).
		Msg("Setting up Node.js environment")

	// Setup Node.js version
	if req.UseNVM {
		if err := nem.setupWithNVM(ctx, req, result); err != nil {
			result.Error = fmt.Errorf("failed to setup Node with NVM: %w", err)
			return result, result.Error
		}
	} else {
		if err := nem.setupDirectNodeInstall(ctx, req, result); err != nil {
			result.Error = fmt.Errorf("failed to setup Node directly: %w", err)
			return result, result.Error
		}
	}

	// Configure environment variables
	if err := nem.configureEnvironmentVariables(req, result); err != nil {
		result.Error = fmt.Errorf("failed to configure environment: %w", err)
		return result, result.Error
	}

	// Setup PATH configuration
	if err := nem.configurePaths(req, result); err != nil {
		result.Error = fmt.Errorf("failed to configure paths: %w", err)
		return result, result.Error
	}

	// Install global packages if specified
	if len(req.GlobalPackages) > 0 {
		if err := nem.installGlobalPackages(ctx, req, result); err != nil {
			log.Warn().Err(err).Msg("Failed to install some global packages")
		}
	}

	// Setup workspace if configured
	if req.WorkspaceConfig != nil {
		if err := nem.setupWorkspace(ctx, req, result); err != nil {
			log.Warn().Err(err).Msg("Failed to setup workspace")
		}
	}

	// Setup registry configuration
	if req.RegistryConfig != nil {
		if err := nem.setupRegistry(ctx, req, result); err != nil {
			log.Warn().Err(err).Msg("Failed to setup registry")
		}
	}

	// Verify installation
	if err := nem.verifyInstallation(ctx, result); err != nil {
		result.Error = fmt.Errorf("installation verification failed: %w", err)
		return result, result.Error
	}

	result.Success = true
	result.Duration = time.Since(startTime)

	// Cache the environment configuration
	nem.cacheEnvironmentConfig(result)

	log.Info().
		Str("node_version", result.NodeVersion).
		Str("npm_version", result.NPMVersion).
		Dur("duration", result.Duration).
		Msg("Node.js environment setup completed successfully")

	return result, nil
}

// setupWithNVM sets up Node.js using NVM
func (nem *NodeEnvironmentManager) setupWithNVM(ctx context.Context, req *NodeEnvironmentSetupRequest, result *NodeEnvironmentSetupResult) error {
	nvmManager := NewNVMManager()

	// Check if NVM is available
	if _, err := os.Stat(nvmManager.nvmScript); os.IsNotExist(err) {
		return fmt.Errorf("NVM not found at %s", nvmManager.nvmScript)
	}

	// Install requested Node version if not available
	nodeVersion := req.NodeVersion
	if nodeVersion == "" {
		nodeVersion = "node" // Use latest stable
	}

	// Use NVM to install/use the specified version
	cmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf(
		"source %s && nvm install %s && nvm use %s",
		nvmManager.nvmScript, nodeVersion, nodeVersion,
	))
	cmd.Dir = nem.workingDir

	output, err := cmd.CombinedOutput()
	result.Output += string(output)

	if err != nil {
		return fmt.Errorf("NVM setup failed: %w", err)
	}

	// Get the actual Node path after NVM setup
	nodePath, err := nem.getNodePathFromNVM(ctx, nodeVersion, nvmManager)
	if err != nil {
		return fmt.Errorf("failed to get Node path from NVM: %w", err)
	}

	nem.nodePath = nodePath
	result.NodePath = nodePath

	// Get npm path
	npmPath := filepath.Join(filepath.Dir(nodePath), "npm")
	nem.npmPath = npmPath
	result.NPMPath = npmPath

	// Get versions
	nodeVersionOutput, _ := nem.getVersionOutput(ctx, nodePath, "--version")
	npmVersionOutput, _ := nem.getVersionOutput(ctx, npmPath, "--version")

	result.NodeVersion = strings.TrimSpace(nodeVersionOutput)
	result.NPMVersion = strings.TrimSpace(npmVersionOutput)

	return nil
}

// setupDirectNodeInstall sets up Node.js without NVM
func (nem *NodeEnvironmentManager) setupDirectNodeInstall(ctx context.Context, req *NodeEnvironmentSetupRequest, result *NodeEnvironmentSetupResult) error {
	// Try to find existing Node installation
	nodePath, err := exec.LookPath("node")
	if err != nil {
		return fmt.Errorf("Node.js not found in PATH: %w", err)
	}

	// Try to find npm
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		return fmt.Errorf("npm not found in PATH: %w", err)
	}

	nem.nodePath = nodePath
	nem.npmPath = npmPath
	result.NodePath = nodePath
	result.NPMPath = npmPath

	// Get versions
	nodeVersionOutput, err := nem.getVersionOutput(ctx, nodePath, "--version")
	if err != nil {
		return fmt.Errorf("failed to get Node version: %w", err)
	}

	npmVersionOutput, err := nem.getVersionOutput(ctx, npmPath, "--version")
	if err != nil {
		return fmt.Errorf("failed to get npm version: %w", err)
	}

	result.NodeVersion = strings.TrimSpace(nodeVersionOutput)
	result.NPMVersion = strings.TrimSpace(npmVersionOutput)

	// Check if requested version matches
	if req.NodeVersion != "" && !strings.Contains(result.NodeVersion, req.NodeVersion) {
		log.Warn().
			Str("requested", req.NodeVersion).
			Str("found", result.NodeVersion).
			Msg("Node version mismatch")
	}

	return nil
}

// getNodePathFromNVM gets the Node path from NVM for a specific version
func (nem *NodeEnvironmentManager) getNodePathFromNVM(ctx context.Context, version string, nvmManager *NVMManager) (string, error) {
	cmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf(
		"source %s && nvm use %s > /dev/null && which node",
		nvmManager.nvmScript, version,
	))

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Node path from NVM: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// getVersionOutput gets version output from a command
func (nem *NodeEnvironmentManager) getVersionOutput(ctx context.Context, command, flag string) (string, error) {
	cmd := exec.CommandContext(ctx, command, flag)
	cmd.Dir = nem.workingDir

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// configureEnvironmentVariables configures Node.js environment variables
func (nem *NodeEnvironmentManager) configureEnvironmentVariables(req *NodeEnvironmentSetupRequest, result *NodeEnvironmentSetupResult) error {
	nem.mutex.Lock()
	defer nem.mutex.Unlock()

	// Set default Node.js environment variables
	nem.environmentVars["NODE_ENV"] = "development"
	nem.environmentVars["NPM_CONFIG_PROGRESS"] = "false"
	nem.environmentVars["NPM_CONFIG_LOGLEVEL"] = "warn"

	// Configure NODE_PATH for module resolution
	nodeModulesPath := filepath.Join(nem.workingDir, "node_modules")
	globalNodeModulesPath := nem.getGlobalNodeModulesPath()

	nodePath := nodeModulesPath
	if globalNodeModulesPath != "" {
		nodePath = fmt.Sprintf("%s%c%s", nodeModulesPath, os.PathListSeparator, globalNodeModulesPath)
	}
	nem.environmentVars["NODE_PATH"] = nodePath

	// Set Node options if specified
	if len(req.NodeOptions) > 0 {
		nem.environmentVars["NODE_OPTIONS"] = strings.Join(req.NodeOptions, " ")
	}

	// Set custom environment variables
	for key, value := range req.Environment {
		nem.environmentVars[key] = value
	}

	// Copy to result
	for key, value := range nem.environmentVars {
		result.Environment[key] = value
	}

	return nil
}

// getGlobalNodeModulesPath gets the global node_modules path
func (nem *NodeEnvironmentManager) getGlobalNodeModulesPath() string {
	if nem.npmPath == "" {
		return ""
	}

	cmd := exec.Command(nem.npmPath, "root", "-g")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

// configurePaths configures PATH and other path-related settings
func (nem *NodeEnvironmentManager) configurePaths(req *NodeEnvironmentSetupRequest, result *NodeEnvironmentSetupResult) error {
	pathManager := nem.pathManager
	pathManager.mutex.Lock()
	defer pathManager.mutex.Unlock()

	// Configure current path
	pathManager.currentPath = pathManager.originalPath

	// Add Node.js bin directory to PATH
	if nem.nodePath != "" {
		nodeDir := filepath.Dir(nem.nodePath)
		if !strings.Contains(pathManager.currentPath, nodeDir) {
			pathManager.currentPath = fmt.Sprintf("%s%c%s", nodeDir, os.PathListSeparator, pathManager.currentPath)
			result.PathsConfigured = append(result.PathsConfigured, nodeDir)
		}
	}

	// Add local node_modules/.bin to PATH
	localBinPath := filepath.Join(nem.workingDir, "node_modules", ".bin")
	if _, err := os.Stat(localBinPath); err == nil {
		pathManager.currentPath = fmt.Sprintf("%s%c%s", localBinPath, os.PathListSeparator, pathManager.currentPath)
		result.PathsConfigured = append(result.PathsConfigured, localBinPath)
	}
	pathManager.localPath = localBinPath

	// Add global node_modules/.bin to PATH
	globalBinPath := nem.getGlobalBinPath()
	if globalBinPath != "" && !strings.Contains(pathManager.currentPath, globalBinPath) {
		pathManager.currentPath = fmt.Sprintf("%s%c%s", globalBinPath, os.PathListSeparator, pathManager.currentPath)
		result.PathsConfigured = append(result.PathsConfigured, globalBinPath)
	}
	pathManager.globalPath = globalBinPath

	// Update environment with new PATH
	nem.environmentVars["PATH"] = pathManager.currentPath
	result.Environment["PATH"] = pathManager.currentPath

	return nil
}

// getGlobalBinPath gets the global npm bin path
func (nem *NodeEnvironmentManager) getGlobalBinPath() string {
	if nem.npmPath == "" {
		return ""
	}

	cmd := exec.Command(nem.npmPath, "bin", "-g")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

// installGlobalPackages installs requested global packages
func (nem *NodeEnvironmentManager) installGlobalPackages(ctx context.Context, req *NodeEnvironmentSetupRequest, result *NodeEnvironmentSetupResult) error {
	if len(req.GlobalPackages) == 0 {
		return nil
	}

	log.Info().Strs("packages", req.GlobalPackages).Msg("Installing global packages")

	// Prepare install command
	args := []string{"install", "-g"}
	args = append(args, req.GlobalPackages...)

	cmd := exec.CommandContext(ctx, nem.npmPath, args...)
	cmd.Dir = nem.workingDir

	// Set environment
	cmd.Env = nem.buildEnvironment()

	output, err := cmd.CombinedOutput()
	result.Output += string(output)

	if err != nil {
		return fmt.Errorf("failed to install global packages: %w", err)
	}

	// Get information about installed global packages
	globalPackages, err := nem.getGlobalPackages(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get global package information")
	} else {
		result.GlobalPackages = globalPackages
	}

	return nil
}

// getGlobalPackages gets information about globally installed packages
func (nem *NodeEnvironmentManager) getGlobalPackages(ctx context.Context) ([]*NodePackageInfo, error) {
	cmd := exec.CommandContext(ctx, nem.npmPath, "list", "-g", "--depth=0", "--json")
	cmd.Dir = nem.workingDir
	cmd.Env = nem.buildEnvironment()

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse npm list JSON output
	var listResult struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(output, &listResult); err != nil {
		return nil, fmt.Errorf("failed to parse npm list output: %w", err)
	}

	var packages []*NodePackageInfo
	for name, info := range listResult.Dependencies {
		pkg := &NodePackageInfo{
			Name:        name,
			Version:     info.Version,
			InstallTime: time.Now(),
			Metadata:    make(map[string]interface{}),
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

// setupWorkspace sets up workspace configuration
func (nem *NodeEnvironmentManager) setupWorkspace(ctx context.Context, req *NodeEnvironmentSetupRequest, result *NodeEnvironmentSetupResult) error {
	workspaceConfig := req.WorkspaceConfig

	log.Info().
		Str("type", string(workspaceConfig.Type)).
		Str("package_manager", string(workspaceConfig.PackageManager)).
		Msg("Setting up workspace")

	workspaceInfo := &WorkspaceInfo{
		Type:           workspaceConfig.Type,
		RootDir:        nem.workingDir,
		PackageManager: workspaceConfig.PackageManager,
		Workspaces:     workspaceConfig.Workspaces,
		Dependencies:   make(map[string]string),
	}

	switch workspaceConfig.Type {
	case WorkspaceTypeNPM:
		if err := nem.setupNPMWorkspace(ctx, workspaceConfig, workspaceInfo); err != nil {
			return fmt.Errorf("failed to setup npm workspace: %w", err)
		}
	case WorkspaceTypeYarn:
		if err := nem.setupYarnWorkspace(ctx, workspaceConfig, workspaceInfo); err != nil {
			return fmt.Errorf("failed to setup yarn workspace: %w", err)
		}
	case WorkspaceTypeLerna:
		if err := nem.setupLernaWorkspace(ctx, workspaceConfig, workspaceInfo); err != nil {
			return fmt.Errorf("failed to setup lerna workspace: %w", err)
		}
	}

	result.WorkspaceInfo = workspaceInfo
	return nil
}

// setupNPMWorkspace sets up npm workspace
func (nem *NodeEnvironmentManager) setupNPMWorkspace(ctx context.Context, config *WorkspaceSetupConfig, info *WorkspaceInfo) error {
	// Update package.json with workspace configuration
	packageJSONPath := filepath.Join(nem.workingDir, "package.json")

	// Read existing package.json or create new one
	var packageJSON map[string]interface{}
	if data, err := os.ReadFile(packageJSONPath); err == nil {
		json.Unmarshal(data, &packageJSON)
	}

	if packageJSON == nil {
		packageJSON = make(map[string]interface{})
	}

	// Add workspace configuration
	packageJSON["workspaces"] = config.Workspaces

	// Write back to file
	data, err := json.MarshalIndent(packageJSON, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(packageJSONPath, data, 0644)
}

// setupYarnWorkspace sets up yarn workspace
func (nem *NodeEnvironmentManager) setupYarnWorkspace(ctx context.Context, config *WorkspaceSetupConfig, info *WorkspaceInfo) error {
	// Similar to npm workspace setup but with yarn-specific configuration
	return nem.setupNPMWorkspace(ctx, config, info)
}

// setupLernaWorkspace sets up lerna workspace
func (nem *NodeEnvironmentManager) setupLernaWorkspace(ctx context.Context, config *WorkspaceSetupConfig, info *WorkspaceInfo) error {
	// Create lerna.json configuration
	lernaConfig := map[string]interface{}{
		"version":       "0.0.0",
		"npmClient":     string(config.PackageManager),
		"packages":      config.Workspaces,
		"useWorkspaces": true,
	}

	lernaConfigPath := filepath.Join(nem.workingDir, "lerna.json")
	data, err := json.MarshalIndent(lernaConfig, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(lernaConfigPath, data, 0644)
}

// setupRegistry sets up npm registry configuration
func (nem *NodeEnvironmentManager) setupRegistry(ctx context.Context, req *NodeEnvironmentSetupRequest, result *NodeEnvironmentSetupResult) error {
	registryConfig := req.RegistryConfig

	log.Info().
		Str("default_registry", registryConfig.DefaultRegistry).
		Msg("Setting up registry configuration")

	var commands [][]string

	// Set default registry
	if registryConfig.DefaultRegistry != "" {
		commands = append(commands, []string{"config", "set", "registry", registryConfig.DefaultRegistry})
	}

	// Set scoped registries
	for scope, registry := range registryConfig.ScopedRegistries {
		commands = append(commands, []string{"config", "set", fmt.Sprintf("%s:registry", scope), registry})
	}

	// Set auth tokens
	for registry, token := range registryConfig.AuthTokens {
		tokenKey := fmt.Sprintf("//%s/:_authToken", strings.TrimPrefix(registry, "https://"))
		commands = append(commands, []string{"config", "set", tokenKey, token})
	}

	// Execute all npm config commands
	for _, cmdArgs := range commands {
		cmd := exec.CommandContext(ctx, nem.npmPath, cmdArgs...)
		cmd.Dir = nem.workingDir
		cmd.Env = nem.buildEnvironment()

		if output, err := cmd.CombinedOutput(); err != nil {
			log.Warn().
				Err(err).
				Str("command", strings.Join(cmdArgs, " ")).
				Str("output", string(output)).
				Msg("Failed to set npm config")
		}
	}

	return nil
}

// verifyInstallation verifies that Node.js and npm are properly installed and configured
func (nem *NodeEnvironmentManager) verifyInstallation(ctx context.Context, result *NodeEnvironmentSetupResult) error {
	// Verify Node.js
	nodeCmd := exec.CommandContext(ctx, nem.nodePath, "--version")
	nodeCmd.Dir = nem.workingDir
	nodeCmd.Env = nem.buildEnvironment()

	if output, err := nodeCmd.Output(); err != nil {
		return fmt.Errorf("Node.js verification failed: %w", err)
	} else {
		version := strings.TrimSpace(string(output))
		if result.NodeVersion == "" {
			result.NodeVersion = version
		}
	}

	// Verify npm
	npmCmd := exec.CommandContext(ctx, nem.npmPath, "--version")
	npmCmd.Dir = nem.workingDir
	npmCmd.Env = nem.buildEnvironment()

	if output, err := npmCmd.Output(); err != nil {
		return fmt.Errorf("npm verification failed: %w", err)
	} else {
		version := strings.TrimSpace(string(output))
		if result.NPMVersion == "" {
			result.NPMVersion = version
		}
	}

	// Verify basic module resolution
	testScript := `console.log("Node.js environment verification successful");`
	testCmd := exec.CommandContext(ctx, nem.nodePath, "-e", testScript)
	testCmd.Dir = nem.workingDir
	testCmd.Env = nem.buildEnvironment()

	if _, err := testCmd.Output(); err != nil {
		return fmt.Errorf("Node.js module resolution test failed: %w", err)
	}

	log.Info().Msg("Node.js environment verification completed successfully")
	return nil
}

// buildEnvironment builds environment variables slice for command execution
func (nem *NodeEnvironmentManager) buildEnvironment() []string {
	env := os.Environ()

	// Add custom environment variables
	for key, value := range nem.environmentVars {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}

// cacheEnvironmentConfig caches the environment configuration for reuse
func (nem *NodeEnvironmentManager) cacheEnvironmentConfig(result *NodeEnvironmentSetupResult) {
	nem.mutex.Lock()
	defer nem.mutex.Unlock()

	// Cache version information
	versionInfo := &NodeVersionInfo{
		Version:     result.NodeVersion,
		Path:        result.NodePath,
		NPMVersion:  result.NPMVersion,
		InstallTime: time.Now(),
		IsActive:    true,
	}

	nem.versionCache.versions[result.NodeVersion] = versionInfo
	nem.versionCache.lastRefresh = time.Now()
}

// GetAvailableVersions returns available Node.js versions
func (nem *NodeEnvironmentManager) GetAvailableVersions(ctx context.Context) ([]string, error) {
	// This would typically query Node.js release API or local NVM cache
	// For now, return common versions
	return []string{
		"18.17.0",
		"16.20.0",
		"14.21.0",
		"20.5.0",
		"latest",
		"lts/hydrogen",
		"lts/gallium",
	}, nil
}

// GetInstalledVersions returns locally installed Node.js versions
func (nem *NodeEnvironmentManager) GetInstalledVersions(ctx context.Context) ([]*NodeVersionInfo, error) {
	nem.versionCache.mutex.RLock()
	defer nem.versionCache.mutex.RUnlock()

	var versions []*NodeVersionInfo
	for _, version := range nem.versionCache.versions {
		versions = append(versions, version)
	}

	return versions, nil
}

// SwitchVersion switches to a different Node.js version
func (nem *NodeEnvironmentManager) SwitchVersion(ctx context.Context, version string) error {
	nvmManager := NewNVMManager()

	// Use NVM to switch version if available
	if _, err := os.Stat(nvmManager.nvmScript); err == nil {
		cmd := exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf(
			"source %s && nvm use %s",
			nvmManager.nvmScript, version,
		))

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to switch Node version: %w, output: %s", err, string(output))
		}

		// Update paths after version switch
		nodePath, err := nem.getNodePathFromNVM(ctx, version, nvmManager)
		if err != nil {
			return fmt.Errorf("failed to get new Node path: %w", err)
		}

		nem.nodePath = nodePath
		nem.npmPath = filepath.Join(filepath.Dir(nodePath), "npm")
		nem.nodeVersion = version

		log.Info().Str("version", version).Msg("Successfully switched Node.js version")
		return nil
	}

	return fmt.Errorf("NVM not available, cannot switch versions")
}

// CleanEnvironment cleans up the Node.js environment
func (nem *NodeEnvironmentManager) CleanEnvironment(ctx context.Context) error {
	nem.mutex.Lock()
	defer nem.mutex.Unlock()

	// Reset PATH
	nem.pathManager.mutex.Lock()
	nem.pathManager.currentPath = nem.pathManager.originalPath
	nem.pathManager.mutex.Unlock()

	// Clear environment variables
	nem.environmentVars = make(map[string]string)

	// Clear version cache
	nem.versionCache.versions = make(map[string]*NodeVersionInfo)

	log.Info().Msg("Node.js environment cleaned successfully")
	return nil
}

// GetEnvironmentInfo returns current environment information
func (nem *NodeEnvironmentManager) GetEnvironmentInfo() map[string]interface{} {
	nem.mutex.RLock()
	defer nem.mutex.RUnlock()

	return map[string]interface{}{
		"node_path":    nem.nodePath,
		"npm_path":     nem.npmPath,
		"node_version": nem.nodeVersion,
		"working_dir":  nem.workingDir,
		"environment":  nem.environmentVars,
		"cache_info": map[string]interface{}{
			"cached_versions": len(nem.versionCache.versions),
			"last_refresh":    nem.versionCache.lastRefresh,
		},
	}
}

// ValidateEnvironment validates the current Node.js environment setup
func (nem *NodeEnvironmentManager) ValidateEnvironment(ctx context.Context) error {
	// Check Node.js accessibility
	if nem.nodePath == "" {
		return fmt.Errorf("Node.js path not configured")
	}

	if _, err := os.Stat(nem.nodePath); err != nil {
		return fmt.Errorf("Node.js executable not found: %w", err)
	}

	// Check npm accessibility
	if nem.npmPath == "" {
		return fmt.Errorf("npm path not configured")
	}

	if _, err := os.Stat(nem.npmPath); err != nil {
		return fmt.Errorf("npm executable not found: %w", err)
	}

	// Test basic functionality
	cmd := exec.CommandContext(ctx, nem.nodePath, "--version")
	if _, err := cmd.Output(); err != nil {
		return fmt.Errorf("Node.js version check failed: %w", err)
	}

	cmd = exec.CommandContext(ctx, nem.npmPath, "--version")
	if _, err := cmd.Output(); err != nil {
		return fmt.Errorf("npm version check failed: %w", err)
	}

	return nil
}

// DetectPackageManager detects the package manager used in the project
func (nem *NodeEnvironmentManager) DetectPackageManager() PackageManager {
	// Check for lockfiles in order of preference
	lockfiles := map[string]PackageManager{
		"pnpm-lock.yaml":    PackageManagerPNPM,
		"yarn.lock":         PackageManagerYarn,
		"package-lock.json": PackageManagerNPM,
	}

	for lockfile, pm := range lockfiles {
		if _, err := os.Stat(filepath.Join(nem.workingDir, lockfile)); err == nil {
			return pm
		}
	}

	// Check package.json for packageManager field
	packageJSONPath := filepath.Join(nem.workingDir, "package.json")
	if data, err := os.ReadFile(packageJSONPath); err == nil {
		var pkg map[string]interface{}
		if json.Unmarshal(data, &pkg) == nil {
			if pmField, ok := pkg["packageManager"].(string); ok {
				if strings.Contains(pmField, "pnpm") {
					return PackageManagerPNPM
				} else if strings.Contains(pmField, "yarn") {
					return PackageManagerYarn
				}
			}
		}
	}

	// Default to npm
	return PackageManagerNPM
}

// UpdateEnvironment updates environment variables
func (nem *NodeEnvironmentManager) UpdateEnvironment(updates map[string]string) {
	nem.mutex.Lock()
	defer nem.mutex.Unlock()

	for key, value := range updates {
		nem.environmentVars[key] = value
	}
}

// GetCurrentVersion returns the currently active Node.js version
func (nem *NodeEnvironmentManager) GetCurrentVersion(ctx context.Context) (string, error) {
	if nem.nodePath == "" {
		return "", fmt.Errorf("Node.js path not configured")
	}

	cmd := exec.CommandContext(ctx, nem.nodePath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Node.js version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")

	return version, nil
}
