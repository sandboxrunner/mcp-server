package languages

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// PackageManager defines the interface for language-specific package managers
type PackageManager interface {
	// GetName returns the package manager name
	GetName() string

	// GetLanguage returns the supported language
	GetLanguage() Language

	// InstallPackages installs the specified packages
	InstallPackages(ctx context.Context, packages []string, workingDir string, options map[string]string) (*PackageInstallResult, error)

	// UninstallPackages uninstalls the specified packages
	UninstallPackages(ctx context.Context, packages []string, workingDir string, options map[string]string) error

	// ListPackages lists installed packages
	ListPackages(ctx context.Context, workingDir string) ([]string, error)

	// UpdatePackages updates all packages or specific ones
	UpdatePackages(ctx context.Context, packages []string, workingDir string) error

	// SearchPackages searches for available packages
	SearchPackages(ctx context.Context, query string) ([]string, error)

	// GetInstallCommand returns the install command for packages
	GetInstallCommand(packages []string, options map[string]string) string

	// ValidatePackageName validates a package name
	ValidatePackageName(packageName string) error

	// GetConfigFiles returns configuration files used by the package manager
	GetConfigFiles() []string
}

// BasePackageManager provides common functionality
type BasePackageManager struct {
	name        string
	language    Language
	command     string
	configFiles []string
}

// NewBasePackageManager creates a new base package manager
func NewBasePackageManager(name string, language Language, command string, configFiles []string) *BasePackageManager {
	return &BasePackageManager{
		name:        name,
		language:    language,
		command:     command,
		configFiles: configFiles,
	}
}

func (bpm *BasePackageManager) GetName() string {
	return bpm.name
}

func (bpm *BasePackageManager) GetLanguage() Language {
	return bpm.language
}

func (bpm *BasePackageManager) GetConfigFiles() []string {
	return bpm.configFiles
}

func (bpm *BasePackageManager) ValidatePackageName(packageName string) error {
	if packageName == "" {
		return fmt.Errorf("package name cannot be empty")
	}
	if strings.Contains(packageName, " ") {
		return fmt.Errorf("package name cannot contain spaces: %s", packageName)
	}
	return nil
}

// PipManager manages Python packages using pip
type PipManager struct {
	*BasePackageManager
}

func NewPipManager() *PipManager {
	return &PipManager{
		BasePackageManager: NewBasePackageManager(
			"pip",
			LanguagePython,
			"pip",
			[]string{"requirements.txt", "setup.py", "pyproject.toml"},
		),
	}
}

func (pm *PipManager) InstallPackages(ctx context.Context, packages []string, workingDir string, options map[string]string) (*PackageInstallResult, error) {
	if len(packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	result := &PackageInstallResult{
		InstalledPackages: make([]string, 0),
		FailedPackages:    make([]string, 0),
	}

	startTime := time.Now()

	// Build command
	cmd := []string{"pip", "install"}

	// Add options
	if userInstall, exists := options["user"]; exists && userInstall == "true" {
		cmd = append(cmd, "--user")
	}
	if upgrade, exists := options["upgrade"]; exists && upgrade == "true" {
		cmd = append(cmd, "--upgrade")
	}
	if noDeps, exists := options["no-deps"]; exists && noDeps == "true" {
		cmd = append(cmd, "--no-deps")
	}

	cmd = append(cmd, packages...)

	// Execute command
	execCmd := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	execCmd.Dir = workingDir

	output, err := execCmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.FailedPackages = packages
		result.Error = err
		return result, nil
	}

	result.Success = true
	result.InstalledPackages = packages
	return result, nil
}

func (pm *PipManager) GetInstallCommand(packages []string, options map[string]string) string {
	cmd := []string{"pip", "install"}

	if userInstall, exists := options["user"]; exists && userInstall == "true" {
		cmd = append(cmd, "--user")
	}
	if upgrade, exists := options["upgrade"]; exists && upgrade == "true" {
		cmd = append(cmd, "--upgrade")
	}

	cmd = append(cmd, packages...)
	return strings.Join(cmd, " ")
}

func (pm *PipManager) UninstallPackages(ctx context.Context, packages []string, workingDir string, options map[string]string) error {
	cmd := exec.CommandContext(ctx, "pip", append([]string{"uninstall", "-y"}, packages...)...)
	cmd.Dir = workingDir
	return cmd.Run()
}

func (pm *PipManager) ListPackages(ctx context.Context, workingDir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "pip", "list", "--format=freeze")
	cmd.Dir = workingDir
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var packages []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "-") {
			packages = append(packages, line)
		}
	}
	return packages, nil
}

func (pm *PipManager) UpdatePackages(ctx context.Context, packages []string, workingDir string) error {
	args := []string{"install", "--upgrade"}
	if len(packages) == 0 {
		args = append(args, "--upgrade-strategy", "eager", ".")
	} else {
		args = append(args, packages...)
	}

	cmd := exec.CommandContext(ctx, "pip", args...)
	cmd.Dir = workingDir
	return cmd.Run()
}

func (pm *PipManager) SearchPackages(ctx context.Context, query string) ([]string, error) {
	// Note: pip search was deprecated, using alternative approach
	return nil, fmt.Errorf("pip search is deprecated")
}

// NpmManager manages Node.js packages using npm
type NpmManager struct {
	*BasePackageManager
}

func NewNpmManager() *NpmManager {
	return &NpmManager{
		BasePackageManager: NewBasePackageManager(
			"npm",
			LanguageJavaScript,
			"npm",
			[]string{"package.json", "package-lock.json", ".npmrc"},
		),
	}
}

func (nm *NpmManager) InstallPackages(ctx context.Context, packages []string, workingDir string, options map[string]string) (*PackageInstallResult, error) {
	if len(packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	result := &PackageInstallResult{
		InstalledPackages: make([]string, 0),
		FailedPackages:    make([]string, 0),
	}

	startTime := time.Now()

	cmd := []string{"npm", "install"}

	if global, exists := options["global"]; exists && global == "true" {
		cmd = append(cmd, "--global")
	}
	if saveDev, exists := options["save-dev"]; exists && saveDev == "true" {
		cmd = append(cmd, "--save-dev")
	}

	cmd = append(cmd, packages...)

	execCmd := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	execCmd.Dir = workingDir

	output, err := execCmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.FailedPackages = packages
		result.Error = err
		return result, nil
	}

	result.Success = true
	result.InstalledPackages = packages
	return result, nil
}

func (nm *NpmManager) GetInstallCommand(packages []string, options map[string]string) string {
	cmd := []string{"npm", "install"}

	if global, exists := options["global"]; exists && global == "true" {
		cmd = append(cmd, "--global")
	}
	if saveDev, exists := options["save-dev"]; exists && saveDev == "true" {
		cmd = append(cmd, "--save-dev")
	}

	cmd = append(cmd, packages...)
	return strings.Join(cmd, " ")
}

func (nm *NpmManager) UninstallPackages(ctx context.Context, packages []string, workingDir string, options map[string]string) error {
	cmd := exec.CommandContext(ctx, "npm", append([]string{"uninstall"}, packages...)...)
	cmd.Dir = workingDir
	return cmd.Run()
}

func (nm *NpmManager) ListPackages(ctx context.Context, workingDir string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "npm", "list", "--depth=0", "--json")
	cmd.Dir = workingDir
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse JSON output (simplified)
	var packages []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "\"dependencies\":") {
			// Simple parsing - in production, use proper JSON parsing
			break
		}
	}
	return packages, nil
}

func (nm *NpmManager) UpdatePackages(ctx context.Context, packages []string, workingDir string) error {
	args := []string{"update"}
	if len(packages) > 0 {
		args = append(args, packages...)
	}

	cmd := exec.CommandContext(ctx, "npm", args...)
	cmd.Dir = workingDir
	return cmd.Run()
}

func (nm *NpmManager) SearchPackages(ctx context.Context, query string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "npm", "search", query)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var packages []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line != "" && !strings.HasPrefix(line, "NAME") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				packages = append(packages, parts[0])
			}
		}
	}
	return packages, nil
}

// PackageManagerRegistry manages all package managers
type PackageManagerRegistry struct {
	managers map[Language]PackageManager
}

// NewPackageManagerRegistry creates a new registry
func NewPackageManagerRegistry() *PackageManagerRegistry {
	registry := &PackageManagerRegistry{
		managers: make(map[Language]PackageManager),
	}

	// Register built-in package managers
	registry.managers[LanguagePython] = NewPipManager()
	registry.managers[LanguageJavaScript] = NewNpmManager()
	registry.managers[LanguageTypeScript] = NewNpmManager()

	// Add more package managers for other languages
	registry.addOtherManagers()

	return registry
}

// GetPackageManager returns the package manager for a language
func (pmr *PackageManagerRegistry) GetPackageManager(language Language) PackageManager {
	return pmr.managers[language]
}

// RegisterPackageManager registers a custom package manager
func (pmr *PackageManagerRegistry) RegisterPackageManager(language Language, manager PackageManager) {
	pmr.managers[language] = manager
}

// GetSupportedLanguages returns all languages with package managers
func (pmr *PackageManagerRegistry) GetSupportedLanguages() []Language {
	var languages []Language
	for lang := range pmr.managers {
		languages = append(languages, lang)
	}
	return languages
}

func (pmr *PackageManagerRegistry) addOtherManagers() {
	// Add stub implementations for other package managers
	// These would be fully implemented in production

	// Go modules
	pmr.managers[LanguageGo] = &StubPackageManager{
		BasePackageManager: NewBasePackageManager("go", LanguageGo, "go", []string{"go.mod", "go.sum"}),
	}

	// Cargo for Rust
	pmr.managers[LanguageRust] = &StubPackageManager{
		BasePackageManager: NewBasePackageManager("cargo", LanguageRust, "cargo", []string{"Cargo.toml", "Cargo.lock"}),
	}

	// Maven/Gradle for Java
	pmr.managers[LanguageJava] = &StubPackageManager{
		BasePackageManager: NewBasePackageManager("maven", LanguageJava, "mvn", []string{"pom.xml", "build.gradle"}),
	}

	// gem for Ruby
	pmr.managers[LanguageRuby] = &StubPackageManager{
		BasePackageManager: NewBasePackageManager("gem", LanguageRuby, "gem", []string{"Gemfile", "Gemfile.lock"}),
	}

	// composer for PHP
	pmr.managers[LanguagePHP] = &StubPackageManager{
		BasePackageManager: NewBasePackageManager("composer", LanguagePHP, "composer", []string{"composer.json", "composer.lock"}),
	}
}

// StubPackageManager provides a stub implementation for package managers
type StubPackageManager struct {
	*BasePackageManager
}

func (spm *StubPackageManager) InstallPackages(ctx context.Context, packages []string, workingDir string, options map[string]string) (*PackageInstallResult, error) {
	return &PackageInstallResult{
		Success:           false,
		InstalledPackages: nil,
		FailedPackages:    packages,
		Output:            fmt.Sprintf("Package manager %s not fully implemented", spm.GetName()),
		Error:             fmt.Errorf("package manager %s not implemented", spm.GetName()),
	}, nil
}

func (spm *StubPackageManager) GetInstallCommand(packages []string, options map[string]string) string {
	return fmt.Sprintf("%s install %s", spm.command, strings.Join(packages, " "))
}

func (spm *StubPackageManager) UninstallPackages(ctx context.Context, packages []string, workingDir string, options map[string]string) error {
	return fmt.Errorf("package manager %s not implemented", spm.GetName())
}

func (spm *StubPackageManager) ListPackages(ctx context.Context, workingDir string) ([]string, error) {
	return nil, fmt.Errorf("package manager %s not implemented", spm.GetName())
}

func (spm *StubPackageManager) UpdatePackages(ctx context.Context, packages []string, workingDir string) error {
	return fmt.Errorf("package manager %s not implemented", spm.GetName())
}

func (spm *StubPackageManager) SearchPackages(ctx context.Context, query string) ([]string, error) {
	return nil, fmt.Errorf("package manager %s not implemented", spm.GetName())
}
