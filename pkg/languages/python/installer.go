package python

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// PipInstaller handles Python package installation with pip
type PipInstaller struct {
	workingDir      string
	pythonPath      string
	virtualEnvPath  string
	packageCache    *PackageCache
	cacheMutex      sync.RWMutex
	progressTracker *InstallationProgressTracker
}

// NewPipInstaller creates a new pip installer instance
func NewPipInstaller(workingDir, pythonPath string) *PipInstaller {
	installer := &PipInstaller{
		workingDir:      workingDir,
		pythonPath:      pythonPath,
		packageCache:    NewPackageCache(),
		progressTracker: NewInstallationProgressTracker(),
	}
	
	// Set virtual environment path if not specified
	if installer.virtualEnvPath == "" {
		installer.virtualEnvPath = filepath.Join(workingDir, ".venv")
	}
	
	return installer
}

// PackageCache handles caching of installed packages
type PackageCache struct {
	installedPackages map[string]*PackageInfo
	mutex             sync.RWMutex
	cacheFile         string
}

// PackageInfo contains information about an installed package
type PackageInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies []string          `json:"dependencies"`
	InstallTime  time.Time         `json:"install_time"`
	Metadata     map[string]string `json:"metadata"`
}

// NewPackageCache creates a new package cache
func NewPackageCache() *PackageCache {
	return &PackageCache{
		installedPackages: make(map[string]*PackageInfo),
		cacheFile:         ".package_cache.json",
	}
}

// InstallationProgressTracker tracks package installation progress
type InstallationProgressTracker struct {
	activeInstalls map[string]*InstallProgress
	mutex          sync.RWMutex
}

// InstallProgress tracks progress of a single package installation
type InstallProgress struct {
	PackageName    string        `json:"package_name"`
	Status         string        `json:"status"`
	Progress       float64       `json:"progress"`
	StartTime      time.Time     `json:"start_time"`
	EstimatedTime  time.Duration `json:"estimated_time"`
	CurrentStep    string        `json:"current_step"`
	Dependencies   []string      `json:"dependencies"`
	BytesDownloaded int64        `json:"bytes_downloaded"`
	TotalBytes     int64         `json:"total_bytes"`
}

// NewInstallationProgressTracker creates a new progress tracker
func NewInstallationProgressTracker() *InstallationProgressTracker {
	return &InstallationProgressTracker{
		activeInstalls: make(map[string]*InstallProgress),
	}
}

// InstallRequest contains parameters for package installation
type InstallRequest struct {
	Packages        []string          `json:"packages"`
	Requirements    string            `json:"requirements"`
	UseVirtualEnv   bool              `json:"use_virtual_env"`
	UpgradePackages bool              `json:"upgrade_packages"`
	IndexURL        string            `json:"index_url"`
	ExtraIndexURLs  []string          `json:"extra_index_urls"`
	NoDeps          bool              `json:"no_deps"`
	ForceReinstall  bool              `json:"force_reinstall"`
	Environment     map[string]string `json:"environment"`
	Timeout         time.Duration     `json:"timeout"`
}

// InstallResult contains the result of package installation
type InstallResult struct {
	Success           bool                    `json:"success"`
	InstalledPackages []*PackageInfo          `json:"installed_packages"`
	FailedPackages    map[string]string       `json:"failed_packages"`
	Conflicts         []DependencyConflict    `json:"conflicts"`
	Output            string                  `json:"output"`
	Error             error                   `json:"error"`
	Duration          time.Duration           `json:"duration"`
	CacheHits         int                     `json:"cache_hits"`
	DownloadSize      int64                   `json:"download_size"`
	ProgressTracking  []*InstallProgress      `json:"progress_tracking"`
}

// DependencyConflict represents a dependency version conflict
type DependencyConflict struct {
	Package          string   `json:"package"`
	RequiredVersions []string `json:"required_versions"`
	ResolvedVersion  string   `json:"resolved_version"`
	ConflictingDeps  []string `json:"conflicting_deps"`
}

// RequirementsParser handles parsing of requirements.txt files
type RequirementsParser struct {
	content string
}

// NewRequirementsParser creates a new requirements parser
func NewRequirementsParser(content string) *RequirementsParser {
	return &RequirementsParser{content: content}
}

// ParseRequirements parses requirements.txt content and extracts packages
func (p *RequirementsParser) ParseRequirements() ([]string, error) {
	var packages []string
	scanner := bufio.NewScanner(strings.NewReader(p.content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		// Handle -r and -c flags (recursive requirements)
		if strings.HasPrefix(line, "-r ") || strings.HasPrefix(line, "-c ") {
			log.Warn().Str("line", line).Msg("Recursive requirements not supported in sandbox")
			continue
		}
		
		// Handle -e flag (editable installs)
		if strings.HasPrefix(line, "-e ") {
			log.Warn().Str("line", line).Msg("Editable installs not supported in sandbox")
			continue
		}
		
		// Extract package name and version specifier
		packageSpec := p.parsePackageSpec(line)
		if packageSpec != "" {
			packages = append(packages, packageSpec)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading requirements: %w", err)
	}
	
	return packages, nil
}

// parsePackageSpec parses a single package specification line
func (p *RequirementsParser) parsePackageSpec(line string) string {
	// Remove inline comments
	if idx := strings.Index(line, "#"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}
	
	// Basic validation for package format
	// Supports: package, package==1.0.0, package>=1.0.0, etc.
	re := regexp.MustCompile(`^([a-zA-Z0-9\-_.]+)([<>=!~]+[a-zA-Z0-9\-_.]+)?`)
	if re.MatchString(line) {
		return line
	}
	
	return ""
}

// CreateVirtualEnvironment creates a Python virtual environment
func (pi *PipInstaller) CreateVirtualEnvironment(ctx context.Context) error {
	if _, err := os.Stat(pi.virtualEnvPath); err == nil {
		log.Info().Str("venv_path", pi.virtualEnvPath).Msg("Virtual environment already exists")
		return nil
	}
	
	log.Info().Str("venv_path", pi.virtualEnvPath).Msg("Creating virtual environment")
	
	cmd := exec.CommandContext(ctx, pi.pythonPath, "-m", "venv", pi.virtualEnvPath)
	cmd.Dir = pi.workingDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create virtual environment: %w, output: %s", err, string(output))
	}
	
	return nil
}

// ActivateVirtualEnvironment activates the virtual environment by updating paths
func (pi *PipInstaller) ActivateVirtualEnvironment() error {
	if _, err := os.Stat(pi.virtualEnvPath); os.IsNotExist(err) {
		return fmt.Errorf("virtual environment does not exist: %s", pi.virtualEnvPath)
	}
	
	// Update python path to use virtual environment
	pi.pythonPath = filepath.Join(pi.virtualEnvPath, "bin", "python")
	
	// Verify the virtual environment python exists
	if _, err := os.Stat(pi.pythonPath); os.IsNotExist(err) {
		// Try windows path
		pi.pythonPath = filepath.Join(pi.virtualEnvPath, "Scripts", "python.exe")
		if _, err := os.Stat(pi.pythonPath); os.IsNotExist(err) {
			return fmt.Errorf("virtual environment python not found")
		}
	}
	
	return nil
}

// generatePipCommand generates the pip install command with all options
func (pi *PipInstaller) generatePipCommand(req *InstallRequest) []string {
	args := []string{"-m", "pip", "install"}
	
	// Add upgrade flag if requested
	if req.UpgradePackages {
		args = append(args, "--upgrade")
	}
	
	// Add force reinstall flag if requested
	if req.ForceReinstall {
		args = append(args, "--force-reinstall")
	}
	
	// Add no dependencies flag if requested
	if req.NoDeps {
		args = append(args, "--no-deps")
	}
	
	// Add custom index URL
	if req.IndexURL != "" {
		args = append(args, "--index-url", req.IndexURL)
	}
	
	// Add extra index URLs
	for _, url := range req.ExtraIndexURLs {
		args = append(args, "--extra-index-url", url)
	}
	
	// Add packages or requirements file
	if req.Requirements != "" {
		// Create temporary requirements file
		reqFile := filepath.Join(pi.workingDir, "requirements.txt")
		if err := os.WriteFile(reqFile, []byte(req.Requirements), 0644); err == nil {
			args = append(args, "-r", reqFile)
		}
	} else {
		args = append(args, req.Packages...)
	}
	
	return args
}

// Install installs packages using pip
func (pi *PipInstaller) Install(ctx context.Context, req *InstallRequest) (*InstallResult, error) {
	startTime := time.Now()
	result := &InstallResult{
		FailedPackages: make(map[string]string),
	}
	
	// Set default timeout if not specified
	if req.Timeout == 0 {
		req.Timeout = 5 * time.Minute
	}
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	
	// Parse requirements.txt if provided
	packages := req.Packages
	if req.Requirements != "" {
		parser := NewRequirementsParser(req.Requirements)
		parsed, err := parser.ParseRequirements()
		if err != nil {
			result.Error = fmt.Errorf("failed to parse requirements: %w", err)
			return result, result.Error
		}
		packages = append(packages, parsed...)
	}
	
	if len(packages) == 0 {
		result.Success = true
		return result, nil
	}
	
	// Create virtual environment if requested
	if req.UseVirtualEnv {
		if err := pi.CreateVirtualEnvironment(ctx); err != nil {
			result.Error = fmt.Errorf("failed to create virtual environment: %w", err)
			return result, result.Error
		}
		
		if err := pi.ActivateVirtualEnvironment(); err != nil {
			result.Error = fmt.Errorf("failed to activate virtual environment: %w", err)
			return result, result.Error
		}
	}
	
	// Check cache for already installed packages
	result.CacheHits = pi.checkPackageCache(packages)
	
	// Generate pip command
	args := pi.generatePipCommand(req)
	
	// Execute pip install
	cmd := exec.CommandContext(ctx, pi.pythonPath, args...)
	cmd.Dir = pi.workingDir
	
	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Start progress tracking
	for _, pkg := range packages {
		pi.progressTracker.StartTracking(pkg)
	}
	
	// Execute command with output streaming
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stdout pipe: %w", err)
		return result, result.Error
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		result.Error = fmt.Errorf("failed to create stderr pipe: %w", err)
		return result, result.Error
	}
	
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Errorf("failed to start pip command: %w", err)
		return result, result.Error
	}
	
	// Collect output and track progress
	var outputBuilder strings.Builder
	outputDone := make(chan struct{})
	
	go func() {
		defer close(outputDone)
		pi.streamOutput(stdout, stderr, &outputBuilder, packages)
	}()
	
	// Wait for command completion
	err = cmd.Wait()
	<-outputDone
	
	result.Duration = time.Since(startTime)
	result.Output = outputBuilder.String()
	
	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("pip installation failed: %w", err)
		pi.parseFailedPackages(result.Output, result.FailedPackages)
		return result, nil
	}
	
	// Parse installation results
	result.Success = true
	result.InstalledPackages = pi.parseInstalledPackages(result.Output)
	result.Conflicts = pi.detectDependencyConflicts(ctx)
	
	// Update package cache
	pi.updatePackageCache(result.InstalledPackages)
	
	// Get progress tracking results
	result.ProgressTracking = pi.progressTracker.GetAllProgress()
	
	return result, nil
}

// streamOutput streams command output and tracks installation progress
func (pi *PipInstaller) streamOutput(stdout, stderr io.Reader, outputBuilder *strings.Builder, packages []string) {
	// Create scanners for both stdout and stderr
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)
	
	// Process stdout
	go func() {
		for stdoutScanner.Scan() {
			line := stdoutScanner.Text()
			outputBuilder.WriteString(line + "\n")
			pi.parseProgressLine(line, packages)
		}
	}()
	
	// Process stderr
	go func() {
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			outputBuilder.WriteString(line + "\n")
			pi.parseProgressLine(line, packages)
		}
	}()
}

// parseProgressLine parses pip output to track installation progress
func (pi *PipInstaller) parseProgressLine(line string, packages []string) {
	// Parse downloading progress
	if strings.Contains(line, "Downloading") {
		for _, pkg := range packages {
			if strings.Contains(line, pkg) {
				pi.progressTracker.UpdateProgress(pkg, "downloading", 0.3)
				break
			}
		}
	}
	
	// Parse installing progress
	if strings.Contains(line, "Installing") {
		for _, pkg := range packages {
			if strings.Contains(line, pkg) {
				pi.progressTracker.UpdateProgress(pkg, "installing", 0.8)
				break
			}
		}
	}
	
	// Parse completion
	if strings.Contains(line, "Successfully installed") {
		for _, pkg := range packages {
			if strings.Contains(line, pkg) {
				pi.progressTracker.CompleteProgress(pkg)
			}
		}
	}
}

// parseFailedPackages extracts failed packages from pip output
func (pi *PipInstaller) parseFailedPackages(output string, failedPackages map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ERROR:") || strings.Contains(line, "Failed") {
			// Extract package name and error from the line
			// This is a simplified implementation - could be more sophisticated
			words := strings.Fields(line)
			for i, word := range words {
				if (word == "ERROR:" || word == "Failed") && i+1 < len(words) {
					failedPackages[words[i+1]] = line
					break
				}
			}
		}
	}
}

// parseInstalledPackages extracts successfully installed packages from pip output
func (pi *PipInstaller) parseInstalledPackages(output string) []*PackageInfo {
	var packages []*PackageInfo
	
	// Look for "Successfully installed" line
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Successfully installed") {
			// Extract package names and versions
			parts := strings.Split(line, "Successfully installed")
			if len(parts) > 1 {
				packageStr := strings.TrimSpace(parts[1])
				pkgSpecs := strings.Fields(packageStr)
				
				for _, spec := range pkgSpecs {
					if pkg := pi.parsePackageNameVersion(spec); pkg != nil {
						packages = append(packages, pkg)
					}
				}
			}
		}
	}
	
	return packages
}

// parsePackageNameVersion parses package name and version from pip output
func (pi *PipInstaller) parsePackageNameVersion(spec string) *PackageInfo {
	// Handle package-version format
	parts := strings.Split(spec, "-")
	if len(parts) >= 2 {
		name := parts[0]
		version := strings.Join(parts[1:], "-")
		
		return &PackageInfo{
			Name:        name,
			Version:     version,
			InstallTime: time.Now(),
			Metadata:    make(map[string]string),
		}
	}
	
	return nil
}

// checkPackageCache checks if packages are already installed in cache
func (pi *PipInstaller) checkPackageCache(packages []string) int {
	pi.cacheMutex.RLock()
	defer pi.cacheMutex.RUnlock()
	
	hits := 0
	for _, pkg := range packages {
		if _, exists := pi.packageCache.installedPackages[pkg]; exists {
			hits++
		}
	}
	
	return hits
}

// updatePackageCache updates the package cache with newly installed packages
func (pi *PipInstaller) updatePackageCache(packages []*PackageInfo) {
	pi.cacheMutex.Lock()
	defer pi.cacheMutex.Unlock()
	
	for _, pkg := range packages {
		pi.packageCache.installedPackages[pkg.Name] = pkg
	}
}

// detectDependencyConflicts checks for potential dependency conflicts
func (pi *PipInstaller) detectDependencyConflicts(ctx context.Context) []DependencyConflict {
	var conflicts []DependencyConflict
	
	// Run pip check to detect conflicts
	cmd := exec.CommandContext(ctx, pi.pythonPath, "-m", "pip", "check")
	cmd.Dir = pi.workingDir
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		// pip check returns non-zero exit code when conflicts are found
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if conflict := pi.parseConflictLine(line); conflict != nil {
				conflicts = append(conflicts, *conflict)
			}
		}
	}
	
	return conflicts
}

// parseConflictLine parses a conflict line from pip check output
func (pi *PipInstaller) parseConflictLine(line string) *DependencyConflict {
	// Example: "package1 1.0.0 has requirement package2>=2.0.0, but you have package2 1.5.0 which is incompatible."
	if strings.Contains(line, "has requirement") && strings.Contains(line, "incompatible") {
		// This is a simplified parser - could be more robust
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			return &DependencyConflict{
				Package:          parts[0],
				RequiredVersions: []string{parts[4]}, // Simplified
				ResolvedVersion:  parts[8],           // Simplified
				ConflictingDeps:  []string{parts[8]}, // Simplified
			}
		}
	}
	
	return nil
}

// GetInstalledPackages returns list of currently installed packages
func (pi *PipInstaller) GetInstalledPackages(ctx context.Context) ([]*PackageInfo, error) {
	cmd := exec.CommandContext(ctx, pi.pythonPath, "-m", "pip", "list", "--format=json")
	cmd.Dir = pi.workingDir
	
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed packages: %w", err)
	}
	
	// Parse JSON output from pip list
	// This would need proper JSON parsing in a real implementation
	log.Info().Str("output", string(output)).Msg("Installed packages")
	
	return nil, nil
}

// StartTracking starts tracking installation progress for a package
func (ipt *InstallationProgressTracker) StartTracking(packageName string) {
	ipt.mutex.Lock()
	defer ipt.mutex.Unlock()
	
	ipt.activeInstalls[packageName] = &InstallProgress{
		PackageName: packageName,
		Status:      "started",
		Progress:    0.0,
		StartTime:   time.Now(),
		CurrentStep: "initializing",
	}
}

// UpdateProgress updates the installation progress for a package
func (ipt *InstallationProgressTracker) UpdateProgress(packageName, status string, progress float64) {
	ipt.mutex.Lock()
	defer ipt.mutex.Unlock()
	
	if install, exists := ipt.activeInstalls[packageName]; exists {
		install.Status = status
		install.Progress = progress
		install.CurrentStep = status
	}
}

// CompleteProgress marks a package installation as complete
func (ipt *InstallationProgressTracker) CompleteProgress(packageName string) {
	ipt.mutex.Lock()
	defer ipt.mutex.Unlock()
	
	if install, exists := ipt.activeInstalls[packageName]; exists {
		install.Status = "completed"
		install.Progress = 1.0
		install.CurrentStep = "completed"
	}
}

// GetProgress returns the current progress for a package
func (ipt *InstallationProgressTracker) GetProgress(packageName string) *InstallProgress {
	ipt.mutex.RLock()
	defer ipt.mutex.RUnlock()
	
	if install, exists := ipt.activeInstalls[packageName]; exists {
		return install
	}
	
	return nil
}

// GetAllProgress returns progress for all tracked installations
func (ipt *InstallationProgressTracker) GetAllProgress() []*InstallProgress {
	ipt.mutex.RLock()
	defer ipt.mutex.RUnlock()
	
	var progress []*InstallProgress
	for _, install := range ipt.activeInstalls {
		progress = append(progress, install)
	}
	
	return progress
}

// ResolvePackageVersions resolves package versions and handles conflicts
func (pi *PipInstaller) ResolvePackageVersions(ctx context.Context, packages []string) ([]string, error) {
	// Use pip-tools or similar approach for version resolution
	// This is a simplified implementation
	
	resolved := make([]string, 0, len(packages))
	for _, pkg := range packages {
		// For now, just return the package as-is
		// In a real implementation, this would resolve versions
		resolved = append(resolved, pkg)
	}
	
	return resolved, nil
}