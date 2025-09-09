package node

import (
	"bufio"
	"context"
	"encoding/json"
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

// PackageManager represents different Node.js package managers
type PackageManager string

const (
	PackageManagerNPM  PackageManager = "npm"
	PackageManagerYarn PackageManager = "yarn"
	PackageManagerPNPM PackageManager = "pnpm"
)

// NPMInstaller handles Node.js package installation with multiple package managers
type NPMInstaller struct {
	workingDir      string
	nodePath        string
	packageManager  PackageManager
	packageCache    *NodePackageCache
	cacheMutex      sync.RWMutex
	progressTracker *NodeInstallationProgressTracker
	registryConfig  *RegistryConfig
	workspaceConfig *WorkspaceConfig
}

// NewNPMInstaller creates a new npm installer instance
func NewNPMInstaller(workingDir, nodePath string, packageManager PackageManager) *NPMInstaller {
	installer := &NPMInstaller{
		workingDir:      workingDir,
		nodePath:        nodePath,
		packageManager:  packageManager,
		packageCache:    NewNodePackageCache(),
		progressTracker: NewNodeInstallationProgressTracker(),
		registryConfig:  NewRegistryConfig(),
		workspaceConfig: NewWorkspaceConfig(),
	}

	return installer
}

// NodePackageCache handles caching of installed Node packages
type NodePackageCache struct {
	installedPackages map[string]*NodePackageInfo
	mutex             sync.RWMutex
	cacheFile         string
	cacheExpiry       time.Duration
}

// NodePackageInfo contains information about an installed Node package
type NodePackageInfo struct {
	Name         string                 `json:"name"`
	Version      string                 `json:"version"`
	Dependencies map[string]string      `json:"dependencies"`
	DevDeps      map[string]string      `json:"devDependencies"`
	PeerDeps     map[string]string      `json:"peerDependencies"`
	InstallTime  time.Time              `json:"install_time"`
	Metadata     map[string]interface{} `json:"metadata"`
	BundleSize   int64                  `json:"bundle_size"`
	Security     *SecurityInfo          `json:"security"`
	Performance  *PerformanceMetrics    `json:"performance"`
}

// SecurityInfo contains security vulnerability information
type SecurityInfo struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	LastAuditTime   time.Time       `json:"last_audit_time"`
	RiskLevel       string          `json:"risk_level"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	PackageName string `json:"package_name"`
	Version     string `json:"version"`
	FixedIn     string `json:"fixed_in"`
	Description string `json:"description"`
}

// NewNodePackageCache creates a new Node package cache
func NewNodePackageCache() *NodePackageCache {
	return &NodePackageCache{
		installedPackages: make(map[string]*NodePackageInfo),
		cacheFile:         ".node_package_cache.json",
		cacheExpiry:       24 * time.Hour,
	}
}

// NodeInstallationProgressTracker tracks Node package installation progress
type NodeInstallationProgressTracker struct {
	activeInstalls map[string]*NodeInstallProgress
	mutex          sync.RWMutex
}

// NodeInstallProgress tracks progress of a single Node package installation
type NodeInstallProgress struct {
	PackageName     string        `json:"package_name"`
	Status          string        `json:"status"`
	Progress        float64       `json:"progress"`
	StartTime       time.Time     `json:"start_time"`
	EstimatedTime   time.Duration `json:"estimated_time"`
	CurrentStep     string        `json:"current_step"`
	Dependencies    []string      `json:"dependencies"`
	BytesDownloaded int64         `json:"bytes_downloaded"`
	TotalBytes      int64         `json:"total_bytes"`
	NetworkSpeed    float64       `json:"network_speed"`
}

// NewNodeInstallationProgressTracker creates a new progress tracker
func NewNodeInstallationProgressTracker() *NodeInstallationProgressTracker {
	return &NodeInstallationProgressTracker{
		activeInstalls: make(map[string]*NodeInstallProgress),
	}
}

// RegistryConfig handles npm registry configuration
type RegistryConfig struct {
	DefaultRegistry  string            `json:"default_registry"`
	ScopedRegistries map[string]string `json:"scoped_registries"`
	AuthTokens       map[string]string `json:"auth_tokens"`
	ProxySettings    *ProxySettings    `json:"proxy_settings"`
}

// ProxySettings contains proxy configuration
type ProxySettings struct {
	HTTP    string `json:"http"`
	HTTPS   string `json:"https"`
	NoProxy string `json:"no_proxy"`
}

// NewRegistryConfig creates a new registry configuration
func NewRegistryConfig() *RegistryConfig {
	return &RegistryConfig{
		DefaultRegistry:  "https://registry.npmjs.org/",
		ScopedRegistries: make(map[string]string),
		AuthTokens:       make(map[string]string),
	}
}

// WorkspaceConfig handles npm workspace configuration
type WorkspaceConfig struct {
	Enabled     bool     `json:"enabled"`
	Workspaces  []string `json:"workspaces"`
	RootDir     string   `json:"root_dir"`
	PackageRoot string   `json:"package_root"`
}

// NewWorkspaceConfig creates a new workspace configuration
func NewWorkspaceConfig() *WorkspaceConfig {
	return &WorkspaceConfig{
		Enabled: false,
	}
}

// NodeInstallRequest contains parameters for Node package installation
type NodeInstallRequest struct {
	Packages        []string               `json:"packages"`
	PackageJSON     string                 `json:"package_json"`
	DevDependencies bool                   `json:"dev_dependencies"`
	GlobalInstall   bool                   `json:"global_install"`
	SaveExact       bool                   `json:"save_exact"`
	PackageManager  PackageManager         `json:"package_manager"`
	Registry        string                 `json:"registry"`
	Environment     map[string]string      `json:"environment"`
	Options         map[string]interface{} `json:"options"`
	Timeout         time.Duration          `json:"timeout"`
	Workspace       string                 `json:"workspace"`
	LockfileType    LockfileType           `json:"lockfile_type"`
	CachePolicy     CachePolicy            `json:"cache_policy"`
}

// LockfileType represents different lockfile types
type LockfileType string

const (
	LockfileNPM  LockfileType = "package-lock.json"
	LockfileYarn LockfileType = "yarn.lock"
	LockfilePNPM LockfileType = "pnpm-lock.yaml"
)

// CachePolicy represents different cache policies
type CachePolicy string

const (
	CachePolicyDefault CachePolicy = "default"
	CachePolicyForce   CachePolicy = "force"
	CachePolicyClean   CachePolicy = "clean"
	CachePolicyOffline CachePolicy = "offline"
)

// NodeInstallResult contains the result of Node package installation
type NodeInstallResult struct {
	Success           bool                     `json:"success"`
	InstalledPackages []*NodePackageInfo       `json:"installed_packages"`
	FailedPackages    map[string]string        `json:"failed_packages"`
	Vulnerabilities   []Vulnerability          `json:"vulnerabilities"`
	Conflicts         []NodeDependencyConflict `json:"conflicts"`
	Output            string                   `json:"output"`
	Error             error                    `json:"error"`
	Duration          time.Duration            `json:"duration"`
	CacheHits         int                      `json:"cache_hits"`
	DownloadSize      int64                    `json:"download_size"`
	ProgressTracking  []*NodeInstallProgress   `json:"progress_tracking"`
	LockfileGenerated bool                     `json:"lockfile_generated"`
	AuditResults      *AuditResults            `json:"audit_results"`
}

// NodeDependencyConflict represents a Node dependency version conflict
type NodeDependencyConflict struct {
	Package          string   `json:"package"`
	RequiredVersions []string `json:"required_versions"`
	ResolvedVersion  string   `json:"resolved_version"`
	ConflictingDeps  []string `json:"conflicting_deps"`
	Severity         string   `json:"severity"`
}

// AuditResults contains npm audit results
type AuditResults struct {
	TotalVulnerabilities  int            `json:"total_vulnerabilities"`
	VulnerabilitiesByType map[string]int `json:"vulnerabilities_by_type"`
	Advisories            []Advisory     `json:"advisories"`
	Summary               *AuditSummary  `json:"summary"`
}

// Advisory represents an npm audit advisory
type Advisory struct {
	ID             int      `json:"id"`
	Title          string   `json:"title"`
	ModuleName     string   `json:"module_name"`
	Severity       string   `json:"severity"`
	Range          string   `json:"range"`
	Recommendation string   `json:"recommendation"`
	References     []string `json:"references"`
}

// AuditSummary contains audit summary information
type AuditSummary struct {
	Info     int `json:"info"`
	Low      int `json:"low"`
	Moderate int `json:"moderate"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

// PackageJSONParser handles parsing of package.json files
type PackageJSONParser struct {
	content string
}

// NewPackageJSONParser creates a new package.json parser
func NewPackageJSONParser(content string) *PackageJSONParser {
	return &PackageJSONParser{content: content}
}

// PackageJSON represents a package.json file structure
type PackageJSON struct {
	Name            string                 `json:"name"`
	Version         string                 `json:"version"`
	Description     string                 `json:"description"`
	Dependencies    map[string]string      `json:"dependencies"`
	DevDependencies map[string]string      `json:"devDependencies"`
	PeerDeps        map[string]string      `json:"peerDependencies"`
	Scripts         map[string]string      `json:"scripts"`
	Workspaces      []string               `json:"workspaces"`
	Engines         map[string]string      `json:"engines"`
	Repository      interface{}            `json:"repository"`
	Keywords        []string               `json:"keywords"`
	Author          interface{}            `json:"author"`
	License         string                 `json:"license"`
	Private         bool                   `json:"private"`
	Main            string                 `json:"main"`
	Module          string                 `json:"module"`
	Types           string                 `json:"types"`
	Files           []string               `json:"files"`
	Config          map[string]interface{} `json:"config"`
}

// ParsePackageJSON parses package.json content
func (p *PackageJSONParser) ParsePackageJSON() (*PackageJSON, error) {
	var pkg PackageJSON
	if err := json.Unmarshal([]byte(p.content), &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Initialize maps if nil
	if pkg.Dependencies == nil {
		pkg.Dependencies = make(map[string]string)
	}
	if pkg.DevDependencies == nil {
		pkg.DevDependencies = make(map[string]string)
	}
	if pkg.PeerDeps == nil {
		pkg.PeerDeps = make(map[string]string)
	}
	if pkg.Scripts == nil {
		pkg.Scripts = make(map[string]string)
	}

	return &pkg, nil
}

// GeneratePackageJSON generates a package.json file
func (ni *NPMInstaller) GeneratePackageJSON(req *NodeInstallRequest) error {
	packageJSONPath := filepath.Join(ni.workingDir, "package.json")

	// Check if package.json already exists
	if _, err := os.Stat(packageJSONPath); err == nil {
		log.Info().Str("path", packageJSONPath).Msg("package.json already exists")
		return nil
	}

	// Create basic package.json structure
	pkg := &PackageJSON{
		Name:            "sandbox-project",
		Version:         "1.0.0",
		Description:     "Sandbox project for code execution",
		Dependencies:    make(map[string]string),
		DevDependencies: make(map[string]string),
		Scripts: map[string]string{
			"start": "node index.js",
			"test":  "echo \"Error: no test specified\" && exit 1",
		},
		Engines: map[string]string{
			"node": ">=14.0.0",
		},
		License: "ISC",
		Private: true,
	}

	// Add requested packages
	for _, packageSpec := range req.Packages {
		name, version := ni.parsePackageSpec(packageSpec)
		if req.DevDependencies {
			pkg.DevDependencies[name] = version
		} else {
			pkg.Dependencies[name] = version
		}
	}

	// Marshal to JSON with proper formatting
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal package.json: %w", err)
	}

	// Write to file
	if err := os.WriteFile(packageJSONPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write package.json: %w", err)
	}

	log.Info().Str("path", packageJSONPath).Msg("Generated package.json")
	return nil
}

// parsePackageSpec parses a package specification (name@version)
func (ni *NPMInstaller) parsePackageSpec(spec string) (name, version string) {
	// Handle scoped packages first (@scope/package or @scope/package@version)
	if strings.HasPrefix(spec, "@") {
		parts := strings.Split(spec, "@")
		if len(parts) == 2 {
			// @scope/package (no version specified)
			return "@" + parts[1], "latest"
		} else if len(parts) >= 3 {
			// @scope/package@version
			name = "@" + parts[1]
			version = strings.Join(parts[2:], "@")
			return name, version
		}
	}

	// Handle regular packages (package or package@version)
	parts := strings.Split(spec, "@")
	if len(parts) == 1 {
		return parts[0], "latest"
	}
	if len(parts) == 2 {
		return parts[0], parts[1]
	}

	return spec, "latest"
}

// generateInstallCommand generates the package manager install command
func (ni *NPMInstaller) generateInstallCommand(req *NodeInstallRequest) []string {
	var args []string

	switch req.PackageManager {
	case PackageManagerYarn:
		args = []string{"add"}
		if req.DevDependencies {
			args = append(args, "--dev")
		}
		if req.SaveExact {
			args = append(args, "--exact")
		}
		if req.GlobalInstall {
			args = append(args, "--global")
		}
		if req.Registry != "" {
			args = append(args, "--registry", req.Registry)
		}

	case PackageManagerPNPM:
		args = []string{"add"}
		if req.DevDependencies {
			args = append(args, "--save-dev")
		}
		if req.SaveExact {
			args = append(args, "--save-exact")
		}
		if req.GlobalInstall {
			args = append(args, "--global")
		}
		if req.Registry != "" {
			args = append(args, "--registry", req.Registry)
		}

	default: // npm
		args = []string{"install"}
		if req.DevDependencies {
			args = append(args, "--save-dev")
		}
		if req.SaveExact {
			args = append(args, "--save-exact")
		}
		if req.GlobalInstall {
			args = append(args, "--global")
		}
		if req.Registry != "" {
			args = append(args, "--registry", req.Registry)
		}
	}

	// Add packages
	args = append(args, req.Packages...)

	return args
}

// Install installs Node packages using the specified package manager
func (ni *NPMInstaller) Install(ctx context.Context, req *NodeInstallRequest) (*NodeInstallResult, error) {
	startTime := time.Now()
	result := &NodeInstallResult{
		FailedPackages: make(map[string]string),
	}

	// Set default timeout if not specified
	if req.Timeout == 0 {
		req.Timeout = 10 * time.Minute
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	// Generate package.json if provided via PackageJSON field
	if req.PackageJSON != "" {
		packageJSONPath := filepath.Join(ni.workingDir, "package.json")
		if err := os.WriteFile(packageJSONPath, []byte(req.PackageJSON), 0644); err != nil {
			result.Error = fmt.Errorf("failed to write package.json: %w", err)
			return result, result.Error
		}
	} else if len(req.Packages) > 0 {
		// Generate package.json from packages
		if err := ni.GeneratePackageJSON(req); err != nil {
			result.Error = fmt.Errorf("failed to generate package.json: %w", err)
			return result, result.Error
		}
	}

	// Check cache for already installed packages
	result.CacheHits = ni.checkPackageCache(req.Packages)

	// Clean cache if requested
	if req.CachePolicy == CachePolicyClean {
		if err := ni.CleanCache(ctx, req.PackageManager); err != nil {
			log.Warn().Err(err).Msg("Failed to clean cache")
		}
	}

	// Generate install command
	args := ni.generateInstallCommand(req)

	// Get package manager executable
	packageManagerExec := string(req.PackageManager)

	// Execute package manager install
	cmd := exec.CommandContext(ctx, packageManagerExec, args...)
	cmd.Dir = ni.workingDir

	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Start progress tracking
	for _, pkg := range req.Packages {
		ni.progressTracker.StartTracking(pkg)
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
		result.Error = fmt.Errorf("failed to start %s command: %w", packageManagerExec, err)
		return result, result.Error
	}

	// Collect output and track progress
	var outputBuilder strings.Builder
	outputDone := make(chan struct{})

	go func() {
		defer close(outputDone)
		ni.streamOutput(stdout, stderr, &outputBuilder, req.Packages, req.PackageManager)
	}()

	// Wait for command completion
	err = cmd.Wait()
	<-outputDone

	result.Duration = time.Since(startTime)
	result.Output = outputBuilder.String()

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("%s installation failed: %w", packageManagerExec, err)
		ni.parseFailedPackages(result.Output, result.FailedPackages, req.PackageManager)
		return result, nil
	}

	// Parse installation results
	result.Success = true
	result.InstalledPackages = ni.parseInstalledPackages(result.Output, req.PackageManager)
	result.LockfileGenerated = ni.checkLockfileGenerated(req.PackageManager)

	// Run security audit
	auditResults, err := ni.RunSecurityAudit(ctx, req.PackageManager)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to run security audit")
	} else {
		result.AuditResults = auditResults
		result.Vulnerabilities = ni.extractVulnerabilities(auditResults)
	}

	// Detect dependency conflicts
	result.Conflicts = ni.detectDependencyConflicts(ctx, req.PackageManager)

	// Update package cache
	ni.updatePackageCache(result.InstalledPackages)

	// Get progress tracking results
	result.ProgressTracking = ni.progressTracker.GetAllProgress()

	return result, nil
}

// streamOutput streams command output and tracks installation progress
func (ni *NPMInstaller) streamOutput(stdout, stderr io.Reader, outputBuilder *strings.Builder, packages []string, packageManager PackageManager) {
	// Create scanners for both stdout and stderr
	stdoutScanner := bufio.NewScanner(stdout)
	stderrScanner := bufio.NewScanner(stderr)

	// Process stdout
	go func() {
		for stdoutScanner.Scan() {
			line := stdoutScanner.Text()
			outputBuilder.WriteString(line + "\n")
			ni.parseProgressLine(line, packages, packageManager)
		}
	}()

	// Process stderr
	go func() {
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			outputBuilder.WriteString(line + "\n")
			ni.parseProgressLine(line, packages, packageManager)
		}
	}()
}

// parseProgressLine parses package manager output to track installation progress
func (ni *NPMInstaller) parseProgressLine(line string, packages []string, packageManager PackageManager) {
	switch packageManager {
	case PackageManagerNPM:
		ni.parseNPMProgressLine(line, packages)
	case PackageManagerYarn:
		ni.parseYarnProgressLine(line, packages)
	case PackageManagerPNPM:
		ni.parsePNPMProgressLine(line, packages)
	}
}

// parseNPMProgressLine parses npm-specific progress lines
func (ni *NPMInstaller) parseNPMProgressLine(line string, packages []string) {
	// Parse npm downloading progress
	if strings.Contains(line, "npm WARN") || strings.Contains(line, "npm ERR!") {
		return // Skip warnings and errors for progress tracking
	}

	if strings.Contains(line, "added") && strings.Contains(line, "packages") {
		// npm installation completed
		for _, pkg := range packages {
			ni.progressTracker.CompleteProgress(pkg)
		}
	}

	// Parse specific package operations
	for _, pkg := range packages {
		if strings.Contains(line, pkg) {
			if strings.Contains(line, "installing") {
				ni.progressTracker.UpdateProgress(pkg, "installing", 0.5)
			} else if strings.Contains(line, "installed") {
				ni.progressTracker.CompleteProgress(pkg)
			}
		}
	}
}

// parseYarnProgressLine parses yarn-specific progress lines
func (ni *NPMInstaller) parseYarnProgressLine(line string, packages []string) {
	// Parse yarn progress patterns
	if strings.Contains(line, "[1/4]") {
		for _, pkg := range packages {
			ni.progressTracker.UpdateProgress(pkg, "resolving", 0.25)
		}
	} else if strings.Contains(line, "[2/4]") {
		for _, pkg := range packages {
			ni.progressTracker.UpdateProgress(pkg, "fetching", 0.5)
		}
	} else if strings.Contains(line, "[3/4]") {
		for _, pkg := range packages {
			ni.progressTracker.UpdateProgress(pkg, "linking", 0.75)
		}
	} else if strings.Contains(line, "[4/4]") {
		for _, pkg := range packages {
			ni.progressTracker.CompleteProgress(pkg)
		}
	}
}

// parsePNPMProgressLine parses pnpm-specific progress lines
func (ni *NPMInstaller) parsePNPMProgressLine(line string, packages []string) {
	// Parse pnpm progress patterns
	if strings.Contains(line, "Downloading") {
		for _, pkg := range packages {
			if strings.Contains(line, pkg) {
				ni.progressTracker.UpdateProgress(pkg, "downloading", 0.3)
			}
		}
	} else if strings.Contains(line, "Installing") {
		for _, pkg := range packages {
			if strings.Contains(line, pkg) {
				ni.progressTracker.UpdateProgress(pkg, "installing", 0.7)
			}
		}
	} else if strings.Contains(line, "Done") {
		for _, pkg := range packages {
			ni.progressTracker.CompleteProgress(pkg)
		}
	}
}

// parseFailedPackages extracts failed packages from package manager output
func (ni *NPMInstaller) parseFailedPackages(output string, failedPackages map[string]string, packageManager PackageManager) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "ERR!") || strings.Contains(line, "error") || strings.Contains(line, "failed") {
			// Extract package name and error from the line
			words := strings.Fields(line)
			for i, word := range words {
				if (strings.Contains(word, "ERR!") || word == "error" || word == "failed") && i+1 < len(words) {
					failedPackages[words[i+1]] = line
					break
				}
			}
		}
	}
}

// parseInstalledPackages extracts successfully installed packages from output
func (ni *NPMInstaller) parseInstalledPackages(output string, packageManager PackageManager) []*NodePackageInfo {
	var packages []*NodePackageInfo

	switch packageManager {
	case PackageManagerNPM:
		packages = ni.parseNPMInstalledPackages(output)
	case PackageManagerYarn:
		packages = ni.parseYarnInstalledPackages(output)
	case PackageManagerPNPM:
		packages = ni.parsePNPMInstalledPackages(output)
	}

	return packages
}

// parseNPMInstalledPackages parses npm-specific installed packages
func (ni *NPMInstaller) parseNPMInstalledPackages(output string) []*NodePackageInfo {
	var packages []*NodePackageInfo

	// Look for "added" line in npm output
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "added") && strings.Contains(line, "packages") {
			// This would need more sophisticated parsing in a real implementation
			// For now, create placeholder entries
			re := regexp.MustCompile(`added (\d+) packages`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				log.Info().Str("packages_added", matches[1]).Msg("Packages added via npm")
			}
		}
	}

	return packages
}

// parseYarnInstalledPackages parses yarn-specific installed packages
func (ni *NPMInstaller) parseYarnInstalledPackages(output string) []*NodePackageInfo {
	var packages []*NodePackageInfo

	// Parse yarn output patterns
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Done in") {
			log.Info().Str("yarn_status", line).Msg("Yarn installation completed")
		}
	}

	return packages
}

// parsePNPMInstalledPackages parses pnpm-specific installed packages
func (ni *NPMInstaller) parsePNPMInstalledPackages(output string) []*NodePackageInfo {
	var packages []*NodePackageInfo

	// Parse pnpm output patterns
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Done in") {
			log.Info().Str("pnpm_status", line).Msg("PNPM installation completed")
		}
	}

	return packages
}

// checkLockfileGenerated checks if lockfile was generated
func (ni *NPMInstaller) checkLockfileGenerated(packageManager PackageManager) bool {
	var lockfilePath string

	switch packageManager {
	case PackageManagerYarn:
		lockfilePath = filepath.Join(ni.workingDir, "yarn.lock")
	case PackageManagerPNPM:
		lockfilePath = filepath.Join(ni.workingDir, "pnpm-lock.yaml")
	default:
		lockfilePath = filepath.Join(ni.workingDir, "package-lock.json")
	}

	_, err := os.Stat(lockfilePath)
	return err == nil
}

// RunSecurityAudit runs security audit on installed packages
func (ni *NPMInstaller) RunSecurityAudit(ctx context.Context, packageManager PackageManager) (*AuditResults, error) {
	var cmd *exec.Cmd

	switch packageManager {
	case PackageManagerYarn:
		cmd = exec.CommandContext(ctx, "yarn", "audit", "--json")
	case PackageManagerPNPM:
		cmd = exec.CommandContext(ctx, "pnpm", "audit", "--json")
	default:
		cmd = exec.CommandContext(ctx, "npm", "audit", "--json")
	}

	cmd.Dir = ni.workingDir
	output, err := cmd.Output()
	if err != nil {
		// Audit may return non-zero exit code when vulnerabilities are found
		log.Debug().Err(err).Msg("Audit command returned non-zero exit code")
	}

	// Parse audit results
	results := &AuditResults{
		VulnerabilitiesByType: make(map[string]int),
		Summary:               &AuditSummary{},
	}

	// This would need proper JSON parsing for each package manager format
	log.Info().Str("audit_output", string(output)).Msg("Security audit completed")

	return results, nil
}

// extractVulnerabilities extracts vulnerabilities from audit results
func (ni *NPMInstaller) extractVulnerabilities(auditResults *AuditResults) []Vulnerability {
	var vulnerabilities []Vulnerability

	for _, advisory := range auditResults.Advisories {
		vuln := Vulnerability{
			ID:          fmt.Sprintf("%d", advisory.ID),
			Title:       advisory.Title,
			Severity:    advisory.Severity,
			PackageName: advisory.ModuleName,
			Description: advisory.Recommendation,
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}

	return vulnerabilities
}

// detectDependencyConflicts checks for potential dependency conflicts
func (ni *NPMInstaller) detectDependencyConflicts(ctx context.Context, packageManager PackageManager) []NodeDependencyConflict {
	var conflicts []NodeDependencyConflict

	// This would need sophisticated dependency tree analysis
	// For now, return empty slice

	return conflicts
}

// checkPackageCache checks if packages are already installed in cache
func (ni *NPMInstaller) checkPackageCache(packages []string) int {
	ni.cacheMutex.RLock()
	defer ni.cacheMutex.RUnlock()

	hits := 0
	for _, pkg := range packages {
		name, _ := ni.parsePackageSpec(pkg)
		if _, exists := ni.packageCache.installedPackages[name]; exists {
			hits++
		}
	}

	return hits
}

// updatePackageCache updates the package cache with newly installed packages
func (ni *NPMInstaller) updatePackageCache(packages []*NodePackageInfo) {
	ni.cacheMutex.Lock()
	defer ni.cacheMutex.Unlock()

	for _, pkg := range packages {
		ni.packageCache.installedPackages[pkg.Name] = pkg
	}
}

// CleanCache cleans package manager cache
func (ni *NPMInstaller) CleanCache(ctx context.Context, packageManager PackageManager) error {
	var cmd *exec.Cmd

	switch packageManager {
	case PackageManagerYarn:
		cmd = exec.CommandContext(ctx, "yarn", "cache", "clean")
	case PackageManagerPNPM:
		cmd = exec.CommandContext(ctx, "pnpm", "store", "prune")
	default:
		cmd = exec.CommandContext(ctx, "npm", "cache", "clean", "--force")
	}

	cmd.Dir = ni.workingDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to clean cache: %w, output: %s", err, string(output))
	}

	log.Info().Str("package_manager", string(packageManager)).Msg("Cache cleaned successfully")
	return nil
}

// RunScript executes npm scripts from package.json
func (ni *NPMInstaller) RunScript(ctx context.Context, scriptName string, packageManager PackageManager) (*NodeInstallResult, error) {
	var cmd *exec.Cmd

	switch packageManager {
	case PackageManagerYarn:
		cmd = exec.CommandContext(ctx, "yarn", "run", scriptName)
	case PackageManagerPNPM:
		cmd = exec.CommandContext(ctx, "pnpm", "run", scriptName)
	default:
		cmd = exec.CommandContext(ctx, "npm", "run", scriptName)
	}

	cmd.Dir = ni.workingDir

	startTime := time.Now()
	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	result := &NodeInstallResult{
		Success:        err == nil,
		Output:         string(output),
		Error:          err,
		Duration:       duration,
		FailedPackages: make(map[string]string),
	}

	return result, nil
}

// GetInstalledPackages returns list of currently installed packages
func (ni *NPMInstaller) GetInstalledPackages(ctx context.Context, packageManager PackageManager) ([]*NodePackageInfo, error) {
	var cmd *exec.Cmd

	switch packageManager {
	case PackageManagerYarn:
		cmd = exec.CommandContext(ctx, "yarn", "list", "--json")
	case PackageManagerPNPM:
		cmd = exec.CommandContext(ctx, "pnpm", "list", "--json")
	default:
		cmd = exec.CommandContext(ctx, "npm", "list", "--json")
	}

	cmd.Dir = ni.workingDir
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get installed packages: %w", err)
	}

	// Parse JSON output from package manager
	log.Info().Str("packages_output", string(output)).Msg("Retrieved installed packages")

	// This would need proper JSON parsing for each package manager format
	return nil, nil
}

// StartTracking starts tracking installation progress for a package
func (nipt *NodeInstallationProgressTracker) StartTracking(packageName string) {
	nipt.mutex.Lock()
	defer nipt.mutex.Unlock()

	nipt.activeInstalls[packageName] = &NodeInstallProgress{
		PackageName: packageName,
		Status:      "started",
		Progress:    0.0,
		StartTime:   time.Now(),
		CurrentStep: "initializing",
	}
}

// UpdateProgress updates the installation progress for a package
func (nipt *NodeInstallationProgressTracker) UpdateProgress(packageName, status string, progress float64) {
	nipt.mutex.Lock()
	defer nipt.mutex.Unlock()

	if install, exists := nipt.activeInstalls[packageName]; exists {
		install.Status = status
		install.Progress = progress
		install.CurrentStep = status
	}
}

// CompleteProgress marks a package installation as complete
func (nipt *NodeInstallationProgressTracker) CompleteProgress(packageName string) {
	nipt.mutex.Lock()
	defer nipt.mutex.Unlock()

	if install, exists := nipt.activeInstalls[packageName]; exists {
		install.Status = "completed"
		install.Progress = 1.0
		install.CurrentStep = "completed"
	}
}

// GetProgress returns the current progress for a package
func (nipt *NodeInstallationProgressTracker) GetProgress(packageName string) *NodeInstallProgress {
	nipt.mutex.RLock()
	defer nipt.mutex.RUnlock()

	if install, exists := nipt.activeInstalls[packageName]; exists {
		return install
	}

	return nil
}

// GetAllProgress returns progress for all tracked installations
func (nipt *NodeInstallationProgressTracker) GetAllProgress() []*NodeInstallProgress {
	nipt.mutex.RLock()
	defer nipt.mutex.RUnlock()

	var progress []*NodeInstallProgress
	for _, install := range nipt.activeInstalls {
		progress = append(progress, install)
	}

	return progress
}
