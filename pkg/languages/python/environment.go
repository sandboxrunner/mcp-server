package python

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// EnvironmentManager handles Python environment management
type EnvironmentManager struct {
	workingDir     string
	baseEnv        map[string]string
	activeEnv      *PythonEnvironment
	envCache       *EnvironmentCache
	mutex          sync.RWMutex
	pyenvPath      string
	condaPath      string
}

// PythonEnvironment represents a Python environment configuration
type PythonEnvironment struct {
	Name           string            `json:"name"`
	Type           EnvironmentType   `json:"type"`
	PythonPath     string            `json:"python_path"`
	PythonVersion  string            `json:"python_version"`
	VirtualEnvPath string            `json:"virtual_env_path"`
	SitePackages   []string          `json:"site_packages"`
	PythonPath_    []string          `json:"pythonpath"`
	Environment    map[string]string `json:"environment"`
	IsActive       bool              `json:"is_active"`
	CreatedAt      time.Time         `json:"created_at"`
	LastUsed       time.Time         `json:"last_used"`
}

// EnvironmentType represents the type of Python environment
type EnvironmentType string

const (
	EnvTypeSystem     EnvironmentType = "system"
	EnvTypeVirtualEnv EnvironmentType = "virtualenv"
	EnvTypeConda      EnvironmentType = "conda"
	EnvTypePyenv      EnvironmentType = "pyenv"
	EnvTypeDocker     EnvironmentType = "docker"
)

// EnvironmentCache caches environment information
type EnvironmentCache struct {
	environments map[string]*PythonEnvironment
	mutex        sync.RWMutex
	cacheFile    string
}

// NewEnvironmentManager creates a new environment manager
func NewEnvironmentManager(workingDir string) *EnvironmentManager {
	manager := &EnvironmentManager{
		workingDir: workingDir,
		baseEnv:    make(map[string]string),
		envCache:   NewEnvironmentCache(),
	}
	
	// Initialize base environment
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			manager.baseEnv[parts[0]] = parts[1]
		}
	}
	
	// Detect pyenv and conda paths
	manager.detectToolPaths()
	
	return manager
}

// NewEnvironmentCache creates a new environment cache
func NewEnvironmentCache() *EnvironmentCache {
	return &EnvironmentCache{
		environments: make(map[string]*PythonEnvironment),
		cacheFile:    ".env_cache.json",
	}
}

// PythonVersionInfo contains detailed Python version information
type PythonVersionInfo struct {
	Version      string `json:"version"`
	Major        int    `json:"major"`
	Minor        int    `json:"minor"`
	Micro        int    `json:"micro"`
	ReleaseLevel string `json:"release_level"`
	Serial       int    `json:"serial"`
	Executable   string `json:"executable"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
}

// EnvironmentSetupOptions contains options for environment setup
type EnvironmentSetupOptions struct {
	PythonVersion    string            `json:"python_version"`
	EnvType          EnvironmentType   `json:"env_type"`
	EnvName          string            `json:"env_name"`
	Requirements     []string          `json:"requirements"`
	SitePackagesDirs []string          `json:"site_packages_dirs"`
	PythonPathDirs   []string          `json:"pythonpath_dirs"`
	Environment      map[string]string `json:"environment"`
	UseSystemSite    bool              `json:"use_system_site"`
	WithPip          bool              `json:"with_pip"`
	WithSetuptools   bool              `json:"with_setuptools"`
	WithWheel        bool              `json:"with_wheel"`
}

// EnvironmentSetupResult contains the result of environment setup
type EnvironmentSetupResult struct {
	Success     bool              `json:"success"`
	Environment *PythonEnvironment `json:"environment"`
	Output      string            `json:"output"`
	Error       error             `json:"error"`
	Duration    time.Duration     `json:"duration"`
}

// DetectPythonVersion detects the Python version of a given executable
func (em *EnvironmentManager) DetectPythonVersion(ctx context.Context, pythonPath string) (*PythonVersionInfo, error) {
	if pythonPath == "" {
		pythonPath = "python3"
	}
	
	// Get basic version info
	cmd := exec.CommandContext(ctx, pythonPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get Python version: %w", err)
	}
	
	versionStr := strings.TrimSpace(string(output))
	versionStr = strings.TrimPrefix(versionStr, "Python ")
	
	// Parse version components
	versionInfo := &PythonVersionInfo{
		Version:    versionStr,
		Executable: pythonPath,
		Platform:   runtime.GOOS,
		Architecture: runtime.GOARCH,
	}
	
	// Parse version numbers
	versionParts := strings.Split(versionStr, ".")
	if len(versionParts) >= 2 {
		if major, err := strconv.Atoi(versionParts[0]); err == nil {
			versionInfo.Major = major
		}
		if minor, err := strconv.Atoi(versionParts[1]); err == nil {
			versionInfo.Minor = minor
		}
		if len(versionParts) >= 3 {
			microStr := versionParts[2]
			// Handle versions like "3.9.0+" or "3.9.0rc1"
			re := regexp.MustCompile(`(\d+)`)
			if matches := re.FindStringSubmatch(microStr); len(matches) > 1 {
				if micro, err := strconv.Atoi(matches[1]); err == nil {
					versionInfo.Micro = micro
				}
			}
		}
	}
	
	// Get more detailed info with sys module
	detailCmd := exec.CommandContext(ctx, pythonPath, "-c", 
		"import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}'); print(sys.version_info.releaselevel); print(sys.version_info.serial); print(sys.executable); print(sys.platform)")
	
	detailOutput, err := detailCmd.Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(detailOutput)), "\n")
		if len(lines) >= 5 {
			versionInfo.Version = lines[0]
			versionInfo.ReleaseLevel = lines[1]
			if serial, err := strconv.Atoi(lines[2]); err == nil {
				versionInfo.Serial = serial
			}
			versionInfo.Executable = lines[3]
			versionInfo.Platform = lines[4]
		}
	}
	
	return versionInfo, nil
}

// detectToolPaths detects paths for pyenv and conda
func (em *EnvironmentManager) detectToolPaths() {
	// Detect pyenv
	if pyenvPath, err := exec.LookPath("pyenv"); err == nil {
		em.pyenvPath = pyenvPath
		log.Debug().Str("pyenv_path", pyenvPath).Msg("Detected pyenv")
	}
	
	// Detect conda
	if condaPath, err := exec.LookPath("conda"); err == nil {
		em.condaPath = condaPath
		log.Debug().Str("conda_path", condaPath).Msg("Detected conda")
	}
}

// ListPyenvVersions lists available Python versions through pyenv
func (em *EnvironmentManager) ListPyenvVersions(ctx context.Context) ([]string, error) {
	if em.pyenvPath == "" {
		return nil, fmt.Errorf("pyenv not available")
	}
	
	cmd := exec.CommandContext(ctx, em.pyenvPath, "versions", "--bare")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list pyenv versions: %w", err)
	}
	
	var versions []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		version := strings.TrimSpace(scanner.Text())
		if version != "" && !strings.Contains(version, "/") {
			versions = append(versions, version)
		}
	}
	
	return versions, nil
}

// InstallPyenvVersion installs a Python version using pyenv
func (em *EnvironmentManager) InstallPyenvVersion(ctx context.Context, version string) error {
	if em.pyenvPath == "" {
		return fmt.Errorf("pyenv not available")
	}
	
	log.Info().Str("version", version).Msg("Installing Python version with pyenv")
	
	cmd := exec.CommandContext(ctx, em.pyenvPath, "install", version)
	cmd.Dir = em.workingDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install Python %s: %w, output: %s", version, err, string(output))
	}
	
	return nil
}

// SetPyenvVersion sets the local Python version using pyenv
func (em *EnvironmentManager) SetPyenvVersion(ctx context.Context, version string) error {
	if em.pyenvPath == "" {
		return fmt.Errorf("pyenv not available")
	}
	
	cmd := exec.CommandContext(ctx, em.pyenvPath, "local", version)
	cmd.Dir = em.workingDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set Python version %s: %w, output: %s", version, err, string(output))
	}
	
	return nil
}

// ListCondaEnvironments lists available conda environments
func (em *EnvironmentManager) ListCondaEnvironments(ctx context.Context) ([]*PythonEnvironment, error) {
	if em.condaPath == "" {
		return nil, fmt.Errorf("conda not available")
	}
	
	cmd := exec.CommandContext(ctx, em.condaPath, "env", "list", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list conda environments: %w", err)
	}
	
	// Parse JSON output (simplified)
	log.Debug().Str("output", string(output)).Msg("Conda environments")
	
	// This would need proper JSON parsing in a real implementation
	var environments []*PythonEnvironment
	return environments, nil
}

// CreateCondaEnvironment creates a new conda environment
func (em *EnvironmentManager) CreateCondaEnvironment(ctx context.Context, name, pythonVersion string) (*PythonEnvironment, error) {
	if em.condaPath == "" {
		return nil, fmt.Errorf("conda not available")
	}
	
	args := []string{"create", "-n", name, "-y"}
	if pythonVersion != "" {
		args = append(args, fmt.Sprintf("python=%s", pythonVersion))
	}
	
	cmd := exec.CommandContext(ctx, em.condaPath, args...)
	cmd.Dir = em.workingDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create conda environment: %w, output: %s", err, string(output))
	}
	
	// Create environment object
	env := &PythonEnvironment{
		Name:          name,
		Type:          EnvTypeConda,
		PythonVersion: pythonVersion,
		CreatedAt:     time.Now(),
		Environment:   make(map[string]string),
	}
	
	return env, nil
}

// CreateVirtualEnvironment creates a new virtual environment
func (em *EnvironmentManager) CreateVirtualEnvironment(ctx context.Context, options *EnvironmentSetupOptions) (*PythonEnvironment, error) {
	pythonPath := "python3"
	if options.PythonVersion != "" {
		pythonPath = fmt.Sprintf("python%s", options.PythonVersion)
	}
	
	envPath := filepath.Join(em.workingDir, options.EnvName)
	if options.EnvName == "" {
		envPath = filepath.Join(em.workingDir, ".venv")
	}
	
	args := []string{"-m", "venv"}
	
	if options.UseSystemSite {
		args = append(args, "--system-site-packages")
	}
	
	if !options.WithPip {
		args = append(args, "--without-pip")
	}
	
	args = append(args, envPath)
	
	cmd := exec.CommandContext(ctx, pythonPath, args...)
	cmd.Dir = em.workingDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual environment: %w, output: %s", err, string(output))
	}
	
	// Detect Python executable in the new environment
	venvPython := filepath.Join(envPath, "bin", "python")
	if runtime.GOOS == "windows" {
		venvPython = filepath.Join(envPath, "Scripts", "python.exe")
	}
	
	// Get version info
	versionInfo, err := em.DetectPythonVersion(ctx, venvPython)
	if err != nil {
		return nil, fmt.Errorf("failed to detect Python version in virtual environment: %w", err)
	}
	
	// Create environment object
	env := &PythonEnvironment{
		Name:           options.EnvName,
		Type:           EnvTypeVirtualEnv,
		PythonPath:     venvPython,
		PythonVersion:  versionInfo.Version,
		VirtualEnvPath: envPath,
		Environment:    make(map[string]string),
		CreatedAt:      time.Now(),
	}
	
	// Setup environment variables
	env.Environment["VIRTUAL_ENV"] = envPath
	env.Environment["PYTHONHOME"] = ""
	
	// Setup Python path
	sitePackagesPath := filepath.Join(envPath, "lib", fmt.Sprintf("python%d.%d", versionInfo.Major, versionInfo.Minor), "site-packages")
	if runtime.GOOS == "windows" {
		sitePackagesPath = filepath.Join(envPath, "Lib", "site-packages")
	}
	env.SitePackages = []string{sitePackagesPath}
	
	return env, nil
}

// ActivateEnvironment activates a Python environment
func (em *EnvironmentManager) ActivateEnvironment(ctx context.Context, env *PythonEnvironment) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()
	
	// Deactivate current environment
	if em.activeEnv != nil {
		em.activeEnv.IsActive = false
		em.activeEnv.LastUsed = time.Now()
	}
	
	// Activate new environment
	env.IsActive = true
	env.LastUsed = time.Now()
	em.activeEnv = env
	
	log.Info().Str("env_name", env.Name).Str("env_type", string(env.Type)).Msg("Activated Python environment")
	
	return nil
}

// GetActiveEnvironment returns the currently active environment
func (em *EnvironmentManager) GetActiveEnvironment() *PythonEnvironment {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	
	return em.activeEnv
}

// SetupPythonPath configures PYTHONPATH for the environment
func (em *EnvironmentManager) SetupPythonPath(env *PythonEnvironment, additionalPaths []string) {
	// Start with existing PYTHONPATH
	existingPath := env.Environment["PYTHONPATH"]
	var paths []string
	
	if existingPath != "" {
		paths = strings.Split(existingPath, string(os.PathListSeparator))
	}
	
	// Add site-packages directories
	paths = append(paths, env.SitePackages...)
	
	// Add additional paths
	paths = append(paths, additionalPaths...)
	
	// Remove duplicates and empty paths
	uniquePaths := make([]string, 0, len(paths))
	seen := make(map[string]bool)
	
	for _, path := range paths {
		if path != "" && !seen[path] {
			uniquePaths = append(uniquePaths, path)
			seen[path] = true
		}
	}
	
	// Update environment
	env.PythonPath_ = uniquePaths
	env.Environment["PYTHONPATH"] = strings.Join(uniquePaths, string(os.PathListSeparator))
}

// DetectSitePackages detects site-packages directories for an environment
func (em *EnvironmentManager) DetectSitePackages(ctx context.Context, pythonPath string) ([]string, error) {
	cmd := exec.CommandContext(ctx, pythonPath, "-c", 
		"import site; import sys; print('\\n'.join(site.getsitepackages() + [site.getusersitepackages()]))")
	
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to detect site-packages: %w", err)
	}
	
	var sitePackages []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		path := strings.TrimSpace(scanner.Text())
		if path != "" {
			sitePackages = append(sitePackages, path)
		}
	}
	
	return sitePackages, nil
}

// SelectPythonBinary selects the best Python binary based on requirements
func (em *EnvironmentManager) SelectPythonBinary(ctx context.Context, requirements *EnvironmentSetupOptions) (string, error) {
	candidates := []string{
		"python3",
		"python",
		"python3.12",
		"python3.11",
		"python3.10",
		"python3.9",
		"python3.8",
	}
	
	// If specific version requested, prioritize it
	if requirements.PythonVersion != "" {
		versionBinary := fmt.Sprintf("python%s", requirements.PythonVersion)
		candidates = append([]string{versionBinary}, candidates...)
	}
	
	// Test candidates
	for _, candidate := range candidates {
		if _, err := exec.LookPath(candidate); err == nil {
			// Verify version if specified
			if requirements.PythonVersion != "" {
				versionInfo, err := em.DetectPythonVersion(ctx, candidate)
				if err != nil {
					continue
				}
				
				if !em.versionMatches(versionInfo.Version, requirements.PythonVersion) {
					continue
				}
			}
			
			return candidate, nil
		}
	}
	
	return "", fmt.Errorf("no suitable Python binary found")
}

// versionMatches checks if a Python version matches requirements
func (em *EnvironmentManager) versionMatches(actual, required string) bool {
	// Simplified version matching
	return strings.HasPrefix(actual, required)
}

// GetEnvironmentInfo returns detailed information about an environment
func (em *EnvironmentManager) GetEnvironmentInfo(ctx context.Context, env *PythonEnvironment) (*EnvironmentInfo, error) {
	info := &EnvironmentInfo{
		Environment: env,
		Variables:   make(map[string]string),
		Packages:    make([]PackageInfo, 0),
	}
	
	// Get Python version info
	versionInfo, err := em.DetectPythonVersion(ctx, env.PythonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get Python version: %w", err)
	}
	info.PythonVersion = versionInfo
	
	// Get environment variables
	for key, value := range env.Environment {
		info.Variables[key] = value
	}
	
	// Get installed packages (simplified)
	if packages, err := em.getInstalledPackages(ctx, env.PythonPath); err == nil {
		info.Packages = packages
	}
	
	return info, nil
}

// EnvironmentInfo contains detailed environment information
type EnvironmentInfo struct {
	Environment   *PythonEnvironment     `json:"environment"`
	PythonVersion *PythonVersionInfo     `json:"python_version"`
	Variables     map[string]string      `json:"variables"`
	Packages      []PackageInfo          `json:"packages"`
	SitePackages  []string               `json:"site_packages"`
	PythonPath    []string               `json:"python_path"`
}

// getInstalledPackages gets list of installed packages
func (em *EnvironmentManager) getInstalledPackages(ctx context.Context, pythonPath string) ([]PackageInfo, error) {
	cmd := exec.CommandContext(ctx, pythonPath, "-m", "pip", "list", "--format=freeze")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed packages: %w", err)
	}
	
	var packages []PackageInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && strings.Contains(line, "==") {
			parts := strings.Split(line, "==")
			if len(parts) == 2 {
				packages = append(packages, PackageInfo{
					Name:    parts[0],
					Version: parts[1],
				})
			}
		}
	}
	
	return packages, nil
}

// GetAvailableEnvironments returns all available environments
func (em *EnvironmentManager) GetAvailableEnvironments(ctx context.Context) ([]*PythonEnvironment, error) {
	var environments []*PythonEnvironment
	
	// System environment
	systemPython, err := em.SelectPythonBinary(ctx, &EnvironmentSetupOptions{})
	if err == nil {
		versionInfo, _ := em.DetectPythonVersion(ctx, systemPython)
		systemEnv := &PythonEnvironment{
			Name:          "system",
			Type:          EnvTypeSystem,
			PythonPath:    systemPython,
			PythonVersion: versionInfo.Version,
			Environment:   make(map[string]string),
		}
		environments = append(environments, systemEnv)
	}
	
	// Virtual environments (look for common patterns)
	if venvs, err := em.findVirtualEnvironments(); err == nil {
		environments = append(environments, venvs...)
	}
	
	// Conda environments
	if condaEnvs, err := em.ListCondaEnvironments(ctx); err == nil {
		environments = append(environments, condaEnvs...)
	}
	
	return environments, nil
}

// findVirtualEnvironments finds virtual environments in common locations
func (em *EnvironmentManager) findVirtualEnvironments() ([]*PythonEnvironment, error) {
	var environments []*PythonEnvironment
	
	// Check for .venv directory
	venvPath := filepath.Join(em.workingDir, ".venv")
	if info, err := os.Stat(venvPath); err == nil && info.IsDir() {
		pythonPath := filepath.Join(venvPath, "bin", "python")
		if runtime.GOOS == "windows" {
			pythonPath = filepath.Join(venvPath, "Scripts", "python.exe")
		}
		
		if _, err := os.Stat(pythonPath); err == nil {
			env := &PythonEnvironment{
				Name:           ".venv",
				Type:           EnvTypeVirtualEnv,
				PythonPath:     pythonPath,
				VirtualEnvPath: venvPath,
				Environment:    make(map[string]string),
			}
			environments = append(environments, env)
		}
	}
	
	return environments, nil
}

// ValidateEnvironment validates that an environment is properly configured
func (em *EnvironmentManager) ValidateEnvironment(ctx context.Context, env *PythonEnvironment) error {
	// Check if Python executable exists
	if _, err := os.Stat(env.PythonPath); os.IsNotExist(err) {
		return fmt.Errorf("Python executable not found: %s", env.PythonPath)
	}
	
	// Test Python execution
	cmd := exec.CommandContext(ctx, env.PythonPath, "-c", "print('Python validation successful')")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Python execution failed: %w", err)
	}
	
	// Validate site-packages if specified
	for _, sitePackage := range env.SitePackages {
		if _, err := os.Stat(sitePackage); os.IsNotExist(err) {
			log.Warn().Str("site_packages", sitePackage).Msg("Site-packages directory does not exist")
		}
	}
	
	return nil
}

// CleanupEnvironment performs cleanup of an environment
func (em *EnvironmentManager) CleanupEnvironment(ctx context.Context, env *PythonEnvironment) error {
	if env.Type == EnvTypeVirtualEnv && env.VirtualEnvPath != "" {
		// For virtual environments, we can optionally remove the directory
		log.Info().Str("venv_path", env.VirtualEnvPath).Msg("Virtual environment available for cleanup")
	}
	
	// Mark environment as inactive
	env.IsActive = false
	env.LastUsed = time.Now()
	
	return nil
}

// ExportEnvironment exports environment configuration
func (em *EnvironmentManager) ExportEnvironment(env *PythonEnvironment) (map[string]string, error) {
	exported := make(map[string]string)
	
	// Copy environment variables
	for key, value := range env.Environment {
		exported[key] = value
	}
	
	// Add Python-specific variables
	exported["PYTHON_EXE"] = env.PythonPath
	exported["PYTHON_VERSION"] = env.PythonVersion
	
	if env.VirtualEnvPath != "" {
		exported["VIRTUAL_ENV"] = env.VirtualEnvPath
	}
	
	if len(env.PythonPath_) > 0 {
		exported["PYTHONPATH"] = strings.Join(env.PythonPath_, string(os.PathListSeparator))
	}
	
	return exported, nil
}

// ImportEnvironment imports environment configuration
func (em *EnvironmentManager) ImportEnvironment(config map[string]string) (*PythonEnvironment, error) {
	env := &PythonEnvironment{
		Environment: make(map[string]string),
		CreatedAt:   time.Now(),
	}
	
	// Import basic fields
	if pythonPath, exists := config["PYTHON_EXE"]; exists {
		env.PythonPath = pythonPath
	}
	
	if version, exists := config["PYTHON_VERSION"]; exists {
		env.PythonVersion = version
	}
	
	if venvPath, exists := config["VIRTUAL_ENV"]; exists {
		env.VirtualEnvPath = venvPath
		env.Type = EnvTypeVirtualEnv
	} else {
		env.Type = EnvTypeSystem
	}
	
	if pythonPath, exists := config["PYTHONPATH"]; exists {
		env.PythonPath_ = strings.Split(pythonPath, string(os.PathListSeparator))
	}
	
	// Copy all environment variables
	for key, value := range config {
		env.Environment[key] = value
	}
	
	return env, nil
}

// GetPythonExecutable returns the Python executable path for the active environment
func (em *EnvironmentManager) GetPythonExecutable() string {
	if em.activeEnv != nil {
		return em.activeEnv.PythonPath
	}
	
	// Fallback to system Python
	if pythonPath, err := exec.LookPath("python3"); err == nil {
		return pythonPath
	}
	
	if pythonPath, err := exec.LookPath("python"); err == nil {
		return pythonPath
	}
	
	return "python3"
}