package go_lang

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ModuleManager handles Go module operations
type ModuleManager struct {
	workingDir string
	proxyURL   string
	offline    bool
	verbose    bool
}

// ModuleInfo represents information about a Go module
type ModuleInfo struct {
	Path      string                 `json:"Path"`
	Version   string                 `json:"Version"`
	Time      *time.Time             `json:"Time,omitempty"`
	Update    *ModuleInfo            `json:"Update,omitempty"`
	Main      bool                   `json:"Main,omitempty"`
	Dir       string                 `json:"Dir,omitempty"`
	GoMod     string                 `json:"GoMod,omitempty"`
	GoVersion string                 `json:"GoVersion,omitempty"`
	Replace   *ModuleInfo            `json:"Replace,omitempty"`
	Retracted []string               `json:"Retracted,omitempty"`
	Require   []*ModuleRequirement   `json:"Require,omitempty"`
	Graph     map[string]*ModuleInfo `json:"Graph,omitempty"`
}

// ModuleRequirement represents a module requirement
type ModuleRequirement struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Indirect bool   `json:"Indirect,omitempty"`
}

// ModuleGraph represents the dependency graph
type ModuleGraph struct {
	Modules      map[string]*ModuleInfo `json:"modules"`
	Dependencies map[string][]string    `json:"dependencies"`
	Conflicts    []ModuleConflict       `json:"conflicts"`
}

// ModuleConflict represents version conflicts
type ModuleConflict struct {
	Module    string   `json:"module"`
	Versions  []string `json:"versions"`
	Resolvers []string `json:"resolvers"`
}

// ReplaceDirective represents a replace directive in go.mod
type ReplaceDirective struct {
	Old string `json:"old"`
	New string `json:"new"`
}

// ModuleConfig represents module configuration
type ModuleConfig struct {
	ModulePath   string             `json:"module_path"`
	GoVersion    string             `json:"go_version"`
	Requires     []ModuleRequirement `json:"requires"`
	Replaces     []ReplaceDirective `json:"replaces"`
	Excludes     []string           `json:"excludes"`
	Retracts     []string           `json:"retracts"`
	ProxyURL     string             `json:"proxy_url"`
	SumDB        string             `json:"sum_db"`
	UseVendor    bool               `json:"use_vendor"`
	PrivateRepos []string           `json:"private_repos"`
}

// NewModuleManager creates a new module manager
func NewModuleManager(workingDir string) *ModuleManager {
	return &ModuleManager{
		workingDir: workingDir,
		proxyURL:   "https://proxy.golang.org",
		offline:    false,
		verbose:    false,
	}
}

// SetProxyURL sets the module proxy URL
func (m *ModuleManager) SetProxyURL(url string) {
	m.proxyURL = url
}

// SetOffline enables offline mode
func (m *ModuleManager) SetOffline(offline bool) {
	m.offline = offline
}

// SetVerbose enables verbose output
func (m *ModuleManager) SetVerbose(verbose bool) {
	m.verbose = verbose
}

// InitializeModule initializes a new Go module
func (m *ModuleManager) InitializeModule(ctx context.Context, modulePath string) error {
	log.Debug().Str("module_path", modulePath).Str("working_dir", m.workingDir).Msg("Initializing Go module")

	// Check if go.mod already exists
	goModPath := filepath.Join(m.workingDir, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		log.Debug().Msg("go.mod already exists, skipping initialization")
		return nil
	}

	// Create working directory if it doesn't exist
	if err := os.MkdirAll(m.workingDir, 0755); err != nil {
		return fmt.Errorf("failed to create working directory: %w", err)
	}

	// Initialize module
	cmd := exec.CommandContext(ctx, "go", "mod", "init", modulePath)
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to initialize module: %w\nOutput: %s", err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Module initialized successfully")
	return nil
}

// DownloadDependencies downloads all module dependencies
func (m *ModuleManager) DownloadDependencies(ctx context.Context) error {
	log.Debug().Str("working_dir", m.workingDir).Msg("Downloading dependencies")

	args := []string{"mod", "download"}
	if m.verbose {
		args = append(args, "-x")
	}

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to download dependencies: %w\nOutput: %s", err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Dependencies downloaded successfully")
	return nil
}

// AddDependency adds a new dependency to the module
func (m *ModuleManager) AddDependency(ctx context.Context, module, version string) error {
	log.Debug().Str("module", module).Str("version", version).Msg("Adding dependency")

	packageSpec := module
	if version != "" && version != "latest" {
		packageSpec = fmt.Sprintf("%s@%s", module, version)
	}

	cmd := exec.CommandContext(ctx, "go", "get", packageSpec)
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add dependency %s: %w\nOutput: %s", packageSpec, err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Dependency added successfully")
	return nil
}

// RemoveDependency removes a dependency from the module
func (m *ModuleManager) RemoveDependency(ctx context.Context, module string) error {
	log.Debug().Str("module", module).Msg("Removing dependency")

	// Remove from go.mod
	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-droprequire", module)
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove dependency %s: %w\nOutput: %s", module, err, output)
	}

	// Clean up unused dependencies
	if err := m.TidyModule(ctx); err != nil {
		return fmt.Errorf("failed to tidy module after removing dependency: %w", err)
	}

	log.Debug().Str("output", string(output)).Msg("Dependency removed successfully")
	return nil
}

// TidyModule runs go mod tidy to clean up dependencies
func (m *ModuleManager) TidyModule(ctx context.Context) error {
	log.Debug().Msg("Tidying module")

	args := []string{"mod", "tidy"}
	if m.verbose {
		args = append(args, "-v")
	}

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to tidy module: %w\nOutput: %s", err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Module tidied successfully")
	return nil
}

// CreateVendorDirectory creates vendor directory with dependencies
func (m *ModuleManager) CreateVendorDirectory(ctx context.Context) error {
	log.Debug().Msg("Creating vendor directory")

	cmd := exec.CommandContext(ctx, "go", "mod", "vendor")
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create vendor directory: %w\nOutput: %s", err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Vendor directory created successfully")
	return nil
}

// GetModuleInfo retrieves information about the current module
func (m *ModuleManager) GetModuleInfo(ctx context.Context) (*ModuleInfo, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json")
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get module info: %w", err)
	}

	var moduleInfo ModuleInfo
	if err := json.Unmarshal(output, &moduleInfo); err != nil {
		return nil, fmt.Errorf("failed to parse module info: %w", err)
	}

	return &moduleInfo, nil
}

// ListDependencies lists all module dependencies
func (m *ModuleManager) ListDependencies(ctx context.Context, includeIndirect bool) ([]*ModuleInfo, error) {
	args := []string{"list", "-m", "-json"}
	if includeIndirect {
		args = append(args, "all")
	} else {
		args = append(args, "...")
	}

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list dependencies: %w", err)
	}

	var modules []*ModuleInfo
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for decoder.More() {
		var module ModuleInfo
		if err := decoder.Decode(&module); err != nil {
			return nil, fmt.Errorf("failed to parse module info: %w", err)
		}
		modules = append(modules, &module)
	}

	return modules, nil
}

// GetModuleGraph analyzes the module dependency graph
func (m *ModuleManager) GetModuleGraph(ctx context.Context) (*ModuleGraph, error) {
	// Get all modules
	modules, err := m.ListDependencies(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("failed to list dependencies: %w", err)
	}

	graph := &ModuleGraph{
		Modules:      make(map[string]*ModuleInfo),
		Dependencies: make(map[string][]string),
		Conflicts:    []ModuleConflict{},
	}

	// Build module map
	for _, module := range modules {
		graph.Modules[module.Path] = module
	}

	// Build dependency relationships
	for _, module := range modules {
		var deps []string
		for _, req := range module.Require {
			deps = append(deps, req.Path)
		}
		if len(deps) > 0 {
			graph.Dependencies[module.Path] = deps
		}
	}

	// Analyze conflicts
	conflicts := m.analyzeVersionConflicts(modules)
	graph.Conflicts = conflicts

	return graph, nil
}

// AddReplaceDirective adds a replace directive to go.mod
func (m *ModuleManager) AddReplaceDirective(ctx context.Context, oldPath, newPath string) error {
	log.Debug().Str("old_path", oldPath).Str("new_path", newPath).Msg("Adding replace directive")

	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-replace", fmt.Sprintf("%s=%s", oldPath, newPath))
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add replace directive: %w\nOutput: %s", err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Replace directive added successfully")
	return nil
}

// RemoveReplaceDirective removes a replace directive from go.mod
func (m *ModuleManager) RemoveReplaceDirective(ctx context.Context, oldPath string) error {
	log.Debug().Str("old_path", oldPath).Msg("Removing replace directive")

	cmd := exec.CommandContext(ctx, "go", "mod", "edit", "-dropreplace", oldPath)
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove replace directive: %w\nOutput: %s", err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Replace directive removed successfully")
	return nil
}

// GetReplaceDirectives gets all replace directives from go.mod
func (m *ModuleManager) GetReplaceDirectives(ctx context.Context) ([]ReplaceDirective, error) {
	goModPath := filepath.Join(m.workingDir, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}

	var replaces []ReplaceDirective
	replaceRegex := regexp.MustCompile(`replace\s+([^\s]+)\s+=>\s+([^\s]+)`)
	
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if matches := replaceRegex.FindStringSubmatch(line); len(matches) == 3 {
			replaces = append(replaces, ReplaceDirective{
				Old: matches[1],
				New: matches[2],
			})
		}
	}

	return replaces, nil
}

// CheckUpdates checks for available updates to dependencies
func (m *ModuleManager) CheckUpdates(ctx context.Context) ([]*ModuleInfo, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-u", "-json", "all")
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to check updates: %w", err)
	}

	var modules []*ModuleInfo
	decoder := json.NewDecoder(strings.NewReader(string(output)))
	for decoder.More() {
		var module ModuleInfo
		if err := decoder.Decode(&module); err != nil {
			return nil, fmt.Errorf("failed to parse module info: %w", err)
		}
		// Only include modules with updates available
		if module.Update != nil {
			modules = append(modules, &module)
		}
	}

	return modules, nil
}

// UpdateDependency updates a specific dependency to the latest version
func (m *ModuleManager) UpdateDependency(ctx context.Context, module, version string) error {
	packageSpec := module
	if version != "" {
		packageSpec = fmt.Sprintf("%s@%s", module, version)
	} else {
		packageSpec = fmt.Sprintf("%s@latest", module)
	}

	return m.AddDependency(ctx, packageSpec, "")
}

// ValidateModule validates the module structure and dependencies
func (m *ModuleManager) ValidateModule(ctx context.Context) error {
	log.Debug().Msg("Validating module")

	// Check if go.mod exists
	goModPath := filepath.Join(m.workingDir, "go.mod")
	if _, err := os.Stat(goModPath); os.IsNotExist(err) {
		return fmt.Errorf("go.mod file not found")
	}

	// Verify module
	cmd := exec.CommandContext(ctx, "go", "mod", "verify")
	cmd.Dir = m.workingDir
	cmd.Env = m.buildEnvironment()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("module verification failed: %w\nOutput: %s", err, output)
	}

	log.Debug().Str("output", string(output)).Msg("Module validated successfully")
	return nil
}

// GetModuleConfig returns the current module configuration
func (m *ModuleManager) GetModuleConfig(ctx context.Context) (*ModuleConfig, error) {
	goModPath := filepath.Join(m.workingDir, "go.mod")
	content, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read go.mod: %w", err)
	}

	config := &ModuleConfig{
		ProxyURL:  m.proxyURL,
		SumDB:     "sum.golang.org",
		UseVendor: false,
	}

	// Parse go.mod content
	lines := strings.Split(string(content), "\n")
	inRequireBlock := false
	inReplaceBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "module ") {
			config.ModulePath = strings.TrimSpace(strings.TrimPrefix(line, "module"))
		} else if strings.HasPrefix(line, "go ") {
			config.GoVersion = strings.TrimSpace(strings.TrimPrefix(line, "go"))
		} else if line == "require (" {
			inRequireBlock = true
		} else if line == "replace (" {
			inReplaceBlock = true
		} else if line == ")" {
			inRequireBlock = false
			inReplaceBlock = false
		} else if inRequireBlock && line != "" {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				req := ModuleRequirement{
					Path:     parts[0],
					Version:  parts[1],
					Indirect: strings.Contains(line, "// indirect"),
				}
				config.Requires = append(config.Requires, req)
			}
		} else if inReplaceBlock && line != "" {
			replaceRegex := regexp.MustCompile(`([^\s]+)\s+=>\s+([^\s]+)`)
			if matches := replaceRegex.FindStringSubmatch(line); len(matches) == 3 {
				config.Replaces = append(config.Replaces, ReplaceDirective{
					Old: matches[1],
					New: matches[2],
				})
			}
		}
	}

	// Check if vendor directory exists
	vendorPath := filepath.Join(m.workingDir, "vendor")
	if _, err := os.Stat(vendorPath); err == nil {
		config.UseVendor = true
	}

	return config, nil
}

// analyzeVersionConflicts analyzes version conflicts in dependencies
func (m *ModuleManager) analyzeVersionConflicts(modules []*ModuleInfo) []ModuleConflict {
	moduleVersions := make(map[string]map[string][]string)

	// Collect all versions for each module
	for _, module := range modules {
		for _, req := range module.Require {
			if moduleVersions[req.Path] == nil {
				moduleVersions[req.Path] = make(map[string][]string)
			}
			moduleVersions[req.Path][req.Version] = append(moduleVersions[req.Path][req.Version], module.Path)
		}
	}

	var conflicts []ModuleConflict
	for modulePath, versions := range moduleVersions {
		if len(versions) > 1 {
			var versionList []string
			var resolverList []string
			
			for version, resolvers := range versions {
				versionList = append(versionList, version)
				resolverList = append(resolverList, strings.Join(resolvers, ", "))
			}

			conflicts = append(conflicts, ModuleConflict{
				Module:    modulePath,
				Versions:  versionList,
				Resolvers: resolverList,
			})
		}
	}

	return conflicts
}

// buildEnvironment builds the environment variables for Go commands
func (m *ModuleManager) buildEnvironment() []string {
	env := os.Environ()
	
	if m.proxyURL != "" {
		env = append(env, fmt.Sprintf("GOPROXY=%s", m.proxyURL))
	}

	if m.offline {
		env = append(env, "GOPROXY=off")
	}

	env = append(env, "GO111MODULE=on")
	
	return env
}