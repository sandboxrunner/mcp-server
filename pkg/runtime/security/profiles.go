package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/rs/zerolog/log"
)

// SecurityProfileType represents different types of security profiles
type SecurityProfileType string

const (
	ProfileTypeSandbox     SecurityProfileType = "sandbox"
	ProfileTypeContainer   SecurityProfileType = "container"
	ProfileTypeApplication SecurityProfileType = "application"
	ProfileTypeSystem      SecurityProfileType = "system"
)

// SecurityProfileLevel represents security levels
type SecurityProfileLevel string

const (
	ProfileLevelMinimal     SecurityProfileLevel = "minimal"
	ProfileLevelRestricted  SecurityProfileLevel = "restricted"
	ProfileLevelStandard    SecurityProfileLevel = "standard"
	ProfileLevelPermissive  SecurityProfileLevel = "permissive"
	ProfileLevelPrivileged  SecurityProfileLevel = "privileged"
)

// SecurityProfile represents a comprehensive security profile
type SecurityProfileSpec struct {
	// Metadata
	Name        string                 `json:"name" yaml:"name"`
	Version     string                 `json:"version" yaml:"version"`
	Description string                 `json:"description" yaml:"description"`
	Author      string                 `json:"author,omitempty" yaml:"author,omitempty"`
	Created     time.Time              `json:"created" yaml:"created"`
	Updated     time.Time              `json:"updated" yaml:"updated"`
	Tags        []string               `json:"tags,omitempty" yaml:"tags,omitempty"`

	// Profile configuration
	Type        SecurityProfileType    `json:"type" yaml:"type"`
	Level       SecurityProfileLevel   `json:"level" yaml:"level"`
	Enabled     bool                   `json:"enabled" yaml:"enabled"`
	
	// Security components
	Namespaces  *NamespaceConfig       `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	Capabilities *CapabilityConfig     `json:"capabilities,omitempty" yaml:"capabilities,omitempty"`
	Seccomp     *SeccompConfig         `json:"seccomp,omitempty" yaml:"seccomp,omitempty"`
	MAC         *MACConfig             `json:"mac,omitempty" yaml:"mac,omitempty"`

	// Advanced options
	Environment  map[string]string      `json:"environment,omitempty" yaml:"environment,omitempty"`
	ResourceLimits map[string]interface{} `json:"resourceLimits,omitempty" yaml:"resourceLimits,omitempty"`
	NetworkPolicy *NetworkPolicy       `json:"networkPolicy,omitempty" yaml:"networkPolicy,omitempty"`
	FileSystemPolicy *FileSystemPolicy `json:"fileSystemPolicy,omitempty" yaml:"fileSystemPolicy,omitempty"`
	
	// Template support
	IsTemplate   bool                   `json:"isTemplate,omitempty" yaml:"isTemplate,omitempty"`
	TemplateVars map[string]interface{} `json:"templateVars,omitempty" yaml:"templateVars,omitempty"`
	BaseProfile  string                 `json:"baseProfile,omitempty" yaml:"baseProfile,omitempty"`
	
	// Validation and compliance
	ValidationRules []ValidationRule     `json:"validationRules,omitempty" yaml:"validationRules,omitempty"`
	ComplianceStandards []string         `json:"complianceStandards,omitempty" yaml:"complianceStandards,omitempty"`
	
	// Usage tracking
	UsageCount   int                   `json:"usageCount" yaml:"usageCount"`
	LastUsed     time.Time             `json:"lastUsed,omitempty" yaml:"lastUsed,omitempty"`
}

// NetworkPolicy defines network access policies
type NetworkPolicy struct {
	AllowAll     bool                  `json:"allowAll" yaml:"allowAll"`
	DenyAll      bool                  `json:"denyAll" yaml:"denyAll"`
	AllowedPorts []PortRule            `json:"allowedPorts,omitempty" yaml:"allowedPorts,omitempty"`
	BlockedPorts []PortRule            `json:"blockedPorts,omitempty" yaml:"blockedPorts,omitempty"`
	AllowedHosts []string              `json:"allowedHosts,omitempty" yaml:"allowedHosts,omitempty"`
	BlockedHosts []string              `json:"blockedHosts,omitempty" yaml:"blockedHosts,omitempty"`
	DNSPolicy    *DNSPolicy            `json:"dnsPolicy,omitempty" yaml:"dnsPolicy,omitempty"`
}

// PortRule defines port access rules
type PortRule struct {
	Port     int    `json:"port" yaml:"port"`
	Protocol string `json:"protocol" yaml:"protocol"` // "tcp", "udp", "both"
	Type     string `json:"type" yaml:"type"`         // "inbound", "outbound", "both"
	Comment  string `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// DNSPolicy defines DNS access policies
type DNSPolicy struct {
	AllowedServers []string `json:"allowedServers,omitempty" yaml:"allowedServers,omitempty"`
	BlockedDomains []string `json:"blockedDomains,omitempty" yaml:"blockedDomains,omitempty"`
	AllowedDomains []string `json:"allowedDomains,omitempty" yaml:"allowedDomains,omitempty"`
	DefaultAction  string   `json:"defaultAction" yaml:"defaultAction"` // "allow", "deny"
}

// FileSystemPolicy defines filesystem access policies
type FileSystemPolicy struct {
	ReadOnlyPaths    []string          `json:"readOnlyPaths,omitempty" yaml:"readOnlyPaths,omitempty"`
	ReadWritePaths   []string          `json:"readWritePaths,omitempty" yaml:"readWritePaths,omitempty"`
	ForbiddenPaths   []string          `json:"forbiddenPaths,omitempty" yaml:"forbiddenPaths,omitempty"`
	TempDirectories  []string          `json:"tempDirectories,omitempty" yaml:"tempDirectories,omitempty"`
	MaxFileSize      int64             `json:"maxFileSize,omitempty" yaml:"maxFileSize,omitempty"`
	MaxTotalSize     int64             `json:"maxTotalSize,omitempty" yaml:"maxTotalSize,omitempty"`
	AllowedExtensions []string         `json:"allowedExtensions,omitempty" yaml:"allowedExtensions,omitempty"`
	ForbiddenExtensions []string       `json:"forbiddenExtensions,omitempty" yaml:"forbiddenExtensions,omitempty"`
}

// ValidationRule defines profile validation rules
type ValidationRule struct {
	Name        string                 `json:"name" yaml:"name"`
	Type        string                 `json:"type" yaml:"type"` // "required", "forbidden", "conditional"
	Target      string                 `json:"target" yaml:"target"`
	Condition   string                 `json:"condition,omitempty" yaml:"condition,omitempty"`
	Message     string                 `json:"message" yaml:"message"`
	Severity    string                 `json:"severity" yaml:"severity"` // "error", "warning", "info"
	Parameters  map[string]interface{} `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// ProfileTemplate represents a security profile template
type ProfileTemplate struct {
	Name         string                 `json:"name" yaml:"name"`
	Description  string                 `json:"description" yaml:"description"`
	Category     string                 `json:"category" yaml:"category"`
	Template     *template.Template     `json:"-"`
	Variables    []TemplateVariable     `json:"variables" yaml:"variables"`
	Examples     []TemplateExample      `json:"examples,omitempty" yaml:"examples,omitempty"`
	Requirements []string               `json:"requirements,omitempty" yaml:"requirements,omitempty"`
}

// TemplateVariable defines template variables
type TemplateVariable struct {
	Name         string      `json:"name" yaml:"name"`
	Type         string      `json:"type" yaml:"type"` // "string", "int", "bool", "array"
	Description  string      `json:"description" yaml:"description"`
	Default      interface{} `json:"default,omitempty" yaml:"default,omitempty"`
	Required     bool        `json:"required" yaml:"required"`
	Validation   string      `json:"validation,omitempty" yaml:"validation,omitempty"`
}

// TemplateExample provides usage examples for templates
type TemplateExample struct {
	Name        string                 `json:"name" yaml:"name"`
	Description string                 `json:"description" yaml:"description"`
	Variables   map[string]interface{} `json:"variables" yaml:"variables"`
}

// ProfileManager manages security profiles and templates
type ProfileManager struct {
	mu                sync.RWMutex
	profiles          map[string]*SecurityProfileSpec
	templates         map[string]*ProfileTemplate
	profilesPath      string
	templatesPath     string
	
	// Built-in profiles
	builtinProfiles   map[string]*SecurityProfileSpec
	
	// Profile validation
	validators        []ProfileValidator
	
	// Usage tracking
	usageStats        map[string]*ProfileUsageStats
	
	// Profile inheritance
	profileHierarchy  map[string][]string // profile -> base profiles
}

// ProfileUsageStats tracks profile usage statistics
type ProfileUsageStats struct {
	ProfileName     string    `json:"profileName"`
	TotalUsage      int       `json:"totalUsage"`
	LastUsed        time.Time `json:"lastUsed"`
	ActiveContainers int      `json:"activeContainers"`
	SuccessRate     float64   `json:"successRate"`
	FailureCount    int       `json:"failureCount"`
}

// ProfileValidator defines profile validation interface
type ProfileValidator interface {
	ValidateProfile(profile *SecurityProfileSpec) error
}

// ProfileQuery defines profile search/filter criteria
type ProfileQuery struct {
	Name     string                 `json:"name,omitempty"`
	Type     SecurityProfileType    `json:"type,omitempty"`
	Level    SecurityProfileLevel   `json:"level,omitempty"`
	Tags     []string               `json:"tags,omitempty"`
	Enabled  *bool                  `json:"enabled,omitempty"`
	Author   string                 `json:"author,omitempty"`
	Limit    int                    `json:"limit,omitempty"`
	Offset   int                    `json:"offset,omitempty"`
}

// NewProfileManager creates a new profile manager
func NewProfileManager(profilesPath, templatesPath string) *ProfileManager {
	pm := &ProfileManager{
		profiles:         make(map[string]*SecurityProfileSpec),
		templates:        make(map[string]*ProfileTemplate),
		builtinProfiles:  make(map[string]*SecurityProfileSpec),
		usageStats:       make(map[string]*ProfileUsageStats),
		profileHierarchy: make(map[string][]string),
		profilesPath:     profilesPath,
		templatesPath:    templatesPath,
	}

	// Ensure directories exist
	os.MkdirAll(profilesPath, 0755)
	os.MkdirAll(templatesPath, 0755)

	// Initialize built-in profiles and templates
	pm.initializeBuiltinProfiles()
	pm.initializeBuiltinTemplates()
	
	// Load existing profiles and templates
	pm.loadProfiles()
	pm.loadTemplates()
	
	return pm
}

// CreateProfile creates a new security profile
func (pm *ProfileManager) CreateProfile(profile *SecurityProfileSpec) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Validate profile
	if err := pm.validateProfile(profile); err != nil {
		return fmt.Errorf("profile validation failed: %w", err)
	}

	// Set metadata
	now := time.Now()
	if profile.Created.IsZero() {
		profile.Created = now
	}
	profile.Updated = now
	profile.UsageCount = 0

	// Handle profile inheritance
	if profile.BaseProfile != "" {
		if err := pm.processProfileInheritance(profile); err != nil {
			return fmt.Errorf("profile inheritance failed: %w", err)
		}
	}

	// Store profile
	pm.profiles[profile.Name] = profile

	// Save to file
	if err := pm.saveProfile(profile); err != nil {
		delete(pm.profiles, profile.Name)
		return fmt.Errorf("failed to save profile: %w", err)
	}

	// Initialize usage stats
	pm.usageStats[profile.Name] = &ProfileUsageStats{
		ProfileName: profile.Name,
		LastUsed:    time.Now(),
	}

	log.Info().
		Str("profile_name", profile.Name).
		Str("type", string(profile.Type)).
		Str("level", string(profile.Level)).
		Msg("Security profile created")

	return nil
}

// GetProfile retrieves a security profile by name
func (pm *ProfileManager) GetProfile(name string) (*SecurityProfileSpec, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Check user profiles first
	if profile, exists := pm.profiles[name]; exists {
		// Update usage stats
		pm.trackProfileUsage(name)
		return pm.deepCopyProfile(profile), nil
	}

	// Check built-in profiles
	if profile, exists := pm.builtinProfiles[name]; exists {
		pm.trackProfileUsage(name)
		return pm.deepCopyProfile(profile), nil
	}

	return nil, fmt.Errorf("profile '%s' not found", name)
}

// ListProfiles lists security profiles based on query criteria
func (pm *ProfileManager) ListProfiles(query *ProfileQuery) ([]*SecurityProfileSpec, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var profiles []*SecurityProfileSpec

	// Collect all profiles
	allProfiles := make(map[string]*SecurityProfileSpec)
	for name, profile := range pm.profiles {
		allProfiles[name] = profile
	}
	for name, profile := range pm.builtinProfiles {
		if _, exists := allProfiles[name]; !exists {
			allProfiles[name] = profile
		}
	}

	// Filter profiles
	for _, profile := range allProfiles {
		if pm.matchesQuery(profile, query) {
			profiles = append(profiles, pm.deepCopyProfile(profile))
		}
	}

	// Sort profiles
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})

	// Apply pagination
	if query != nil {
		if query.Offset > 0 && query.Offset < len(profiles) {
			profiles = profiles[query.Offset:]
		}
		if query.Limit > 0 && query.Limit < len(profiles) {
			profiles = profiles[:query.Limit]
		}
	}

	return profiles, nil
}

// UpdateProfile updates an existing security profile
func (pm *ProfileManager) UpdateProfile(profile *SecurityProfileSpec) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if profile exists
	existing, exists := pm.profiles[profile.Name]
	if !exists {
		return fmt.Errorf("profile '%s' not found", profile.Name)
	}

	// Validate updated profile
	if err := pm.validateProfile(profile); err != nil {
		return fmt.Errorf("profile validation failed: %w", err)
	}

	// Preserve metadata
	profile.Created = existing.Created
	profile.Updated = time.Now()
	profile.UsageCount = existing.UsageCount

	// Handle profile inheritance
	if profile.BaseProfile != "" {
		if err := pm.processProfileInheritance(profile); err != nil {
			return fmt.Errorf("profile inheritance failed: %w", err)
		}
	}

	// Update profile
	pm.profiles[profile.Name] = profile

	// Save to file
	if err := pm.saveProfile(profile); err != nil {
		pm.profiles[profile.Name] = existing
		return fmt.Errorf("failed to save profile: %w", err)
	}

	log.Info().
		Str("profile_name", profile.Name).
		Msg("Security profile updated")

	return nil
}

// DeleteProfile deletes a security profile
func (pm *ProfileManager) DeleteProfile(name string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if profile exists
	if _, exists := pm.profiles[name]; !exists {
		return fmt.Errorf("profile '%s' not found", name)
	}

	// Check for dependencies
	if pm.hasProfileDependencies(name) {
		return fmt.Errorf("profile '%s' is used by other profiles and cannot be deleted", name)
	}

	// Remove profile
	delete(pm.profiles, name)
	delete(pm.usageStats, name)

	// Remove file
	profilePath := filepath.Join(pm.profilesPath, fmt.Sprintf("%s.json", name))
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		log.Warn().Err(err).Str("profile_path", profilePath).Msg("Failed to remove profile file")
	}

	log.Info().
		Str("profile_name", name).
		Msg("Security profile deleted")

	return nil
}

// CreateFromTemplate creates a security profile from a template
func (pm *ProfileManager) CreateFromTemplate(templateName string, profileName string, variables map[string]interface{}) (*SecurityProfileSpec, error) {
	pm.mu.RLock()
	template, exists := pm.templates[templateName]
	pm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("template '%s' not found", templateName)
	}

	// Validate template variables
	if err := pm.validateTemplateVariables(template, variables); err != nil {
		return nil, fmt.Errorf("template variable validation failed: %w", err)
	}

	// Generate profile from template
	profile, err := pm.generateProfileFromTemplate(template, profileName, variables)
	if err != nil {
		return nil, fmt.Errorf("failed to generate profile from template: %w", err)
	}

	// Create the profile
	if err := pm.CreateProfile(profile); err != nil {
		return nil, fmt.Errorf("failed to create profile from template: %w", err)
	}

	return profile, nil
}

// GetProfileUsageStats returns usage statistics for a profile
func (pm *ProfileManager) GetProfileUsageStats(name string) (*ProfileUsageStats, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats, exists := pm.usageStats[name]
	if !exists {
		return nil, fmt.Errorf("no usage stats found for profile '%s'", name)
	}

	// Return a copy
	statsCopy := *stats
	return &statsCopy, nil
}

// ExportProfile exports a profile to JSON format
func (pm *ProfileManager) ExportProfile(name string) ([]byte, error) {
	profile, err := pm.GetProfile(name)
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(profile, "", "  ")
}

// ImportProfile imports a profile from JSON data
func (pm *ProfileManager) ImportProfile(data []byte) (*SecurityProfileSpec, error) {
	var profile SecurityProfileSpec
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile JSON: %w", err)
	}

	if err := pm.CreateProfile(&profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

// Private helper methods

func (pm *ProfileManager) initializeBuiltinProfiles() {
	// Minimal sandbox profile
	pm.builtinProfiles["minimal-sandbox"] = &SecurityProfileSpec{
		Name:        "minimal-sandbox",
		Version:     "1.0",
		Description: "Minimal security profile for basic sandboxing",
		Type:        ProfileTypeSandbox,
		Level:       ProfileLevelMinimal,
		Enabled:     true,
		Created:     time.Now(),
		Updated:     time.Now(),
		Tags:        []string{"sandbox", "minimal", "basic"},
		Namespaces: &NamespaceConfig{
			PID:     true,
			Mount:   true,
			Network: true,
			IPC:     true,
			UTS:     true,
			User:    false,
			Cgroup:  true,
		},
		Capabilities: &CapabilityConfig{
			Profile: ProfileRestricted,
			Drop: []Capability{
				CapSysAdmin, CapNetAdmin, CapSysModule, CapSysRawio, CapSysBoot,
			},
			NoNewPrivs:              true,
			AllowPrivilegeEscalation: false,
		},
		Seccomp: &SeccompConfig{
			ProfileType:     ProfileTypeRestricted,
			NoNewPrivs:      true,
			ViolationAction: SeccompActionKill,
		},
		NetworkPolicy: &NetworkPolicy{
			DenyAll: true,
			DNSPolicy: &DNSPolicy{
				DefaultAction: "deny",
			},
		},
		FileSystemPolicy: &FileSystemPolicy{
			ReadOnlyPaths: []string{
				"/etc", "/usr", "/lib", "/lib64", "/bin", "/sbin",
			},
			ForbiddenPaths: []string{
				"/proc/sys", "/sys/kernel/security", "/dev/mem", "/dev/kmem",
			},
		},
	}

	// Standard container profile
	pm.builtinProfiles["standard-container"] = &SecurityProfileSpec{
		Name:        "standard-container",
		Version:     "1.0",
		Description: "Standard security profile for container applications",
		Type:        ProfileTypeContainer,
		Level:       ProfileLevelStandard,
		Enabled:     true,
		Created:     time.Now(),
		Updated:     time.Now(),
		Tags:        []string{"container", "standard", "balanced"},
		Namespaces: &NamespaceConfig{
			PID:     true,
			Mount:   true,
			Network: true,
			IPC:     true,
			UTS:     true,
			User:    false,
			Cgroup:  true,
		},
		Capabilities: &CapabilityConfig{
			Profile: ProfileDefault,
			NoNewPrivs:              true,
			AllowPrivilegeEscalation: false,
		},
		Seccomp: &SeccompConfig{
			ProfileType:     ProfileTypeDefault,
			NoNewPrivs:      true,
			ViolationAction: SeccompActionErrno,
		},
		NetworkPolicy: &NetworkPolicy{
			AllowedPorts: []PortRule{
				{Port: 80, Protocol: "tcp", Type: "outbound"},
				{Port: 443, Protocol: "tcp", Type: "outbound"},
			},
			DNSPolicy: &DNSPolicy{
				DefaultAction: "allow",
				AllowedServers: []string{"8.8.8.8", "8.8.4.4"},
			},
		},
		FileSystemPolicy: &FileSystemPolicy{
			ReadOnlyPaths: []string{
				"/etc", "/usr", "/lib", "/lib64", "/bin", "/sbin",
			},
			ReadWritePaths: []string{
				"/tmp", "/var/tmp",
			},
			TempDirectories: []string{
				"/tmp", "/var/tmp",
			},
		},
	}

	// Privileged system profile
	pm.builtinProfiles["privileged-system"] = &SecurityProfileSpec{
		Name:        "privileged-system",
		Version:     "1.0",
		Description: "Privileged profile for system-level operations",
		Type:        ProfileTypeSystem,
		Level:       ProfileLevelPrivileged,
		Enabled:     true,
		Created:     time.Now(),
		Updated:     time.Now(),
		Tags:        []string{"system", "privileged", "admin"},
		Namespaces: &NamespaceConfig{
			PID:     false,
			Mount:   false,
			Network: false,
			IPC:     false,
			UTS:     false,
			User:    false,
			Cgroup:  false,
		},
		Capabilities: &CapabilityConfig{
			Profile: ProfilePrivileged,
			NoNewPrivs:              false,
			AllowPrivilegeEscalation: true,
		},
		Seccomp: &SeccompConfig{
			ProfileType:     ProfileTypePrivileged,
			NoNewPrivs:      false,
			ViolationAction: SeccompActionAllow,
		},
		NetworkPolicy: &NetworkPolicy{
			AllowAll: true,
		},
	}

	log.Info().Int("builtin_profiles", len(pm.builtinProfiles)).Msg("Built-in security profiles initialized")
}

func (pm *ProfileManager) initializeBuiltinTemplates() {
	// Web application template
	webAppTemplate := `{
  "name": "{{.Name}}",
  "version": "1.0",
  "description": "Security profile for web application: {{.Description}}",
  "type": "application",
  "level": "{{.SecurityLevel}}",
  "enabled": true,
  "namespaces": {
    "pid": true,
    "mount": true,
    "network": {{.AllowNetwork}},
    "ipc": true,
    "uts": true,
    "user": false,
    "cgroup": true
  },
  "capabilities": {
    "profile": "{{.CapabilityProfile}}",
    "noNewPrivs": true,
    "allowPrivilegeEscalation": false
  },
  "seccomp": {
    "profileType": "{{.SeccompProfile}}",
    "noNewPrivs": true,
    "violationAction": "SCMP_ACT_ERRNO"
  },
  "networkPolicy": {
    "allowedPorts": [
      {{range $index, $port := .AllowedPorts}}
      {{if $index}},{{end}}
      {"port": {{$port.Port}}, "protocol": "{{$port.Protocol}}", "type": "{{$port.Type}}"}
      {{end}}
    ],
    "dnsPolicy": {
      "defaultAction": "allow"
    }
  },
  "fileSystemPolicy": {
    "readOnlyPaths": ["/etc", "/usr", "/lib", "/lib64", "/bin", "/sbin"],
    "readWritePaths": ["/tmp", "/var/tmp", "{{.WorkDir}}"],
    "tempDirectories": ["/tmp", "/var/tmp"]
  }
}`

	tmpl, err := template.New("webapp").Parse(webAppTemplate)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse web app template")
	} else {
		pm.templates["webapp"] = &ProfileTemplate{
			Name:        "webapp",
			Description: "Template for web application security profiles",
			Category:    "application",
			Template:    tmpl,
			Variables: []TemplateVariable{
				{Name: "Name", Type: "string", Description: "Profile name", Required: true},
				{Name: "Description", Type: "string", Description: "Application description", Required: true},
				{Name: "SecurityLevel", Type: "string", Description: "Security level", Default: "standard", Required: false},
				{Name: "AllowNetwork", Type: "bool", Description: "Allow network access", Default: true, Required: false},
				{Name: "CapabilityProfile", Type: "string", Description: "Capability profile", Default: "default", Required: false},
				{Name: "SeccompProfile", Type: "string", Description: "Seccomp profile", Default: "default", Required: false},
				{Name: "AllowedPorts", Type: "array", Description: "Allowed network ports", Default: []map[string]interface{}{{"Port": 80, "Protocol": "tcp", "Type": "outbound"}}, Required: false},
				{Name: "WorkDir", Type: "string", Description: "Working directory", Default: "/app", Required: false},
			},
			Examples: []TemplateExample{
				{
					Name:        "Basic Web Server",
					Description: "Basic web server with HTTP access",
					Variables: map[string]interface{}{
						"Name":        "webserver-basic",
						"Description": "Basic web server application",
						"AllowedPorts": []map[string]interface{}{
							{"Port": 80, "Protocol": "tcp", "Type": "inbound"},
							{"Port": 443, "Protocol": "tcp", "Type": "inbound"},
						},
					},
				},
			},
		}
	}

	log.Info().Int("builtin_templates", len(pm.templates)).Msg("Built-in security templates initialized")
}

func (pm *ProfileManager) loadProfiles() {
	files, err := os.ReadDir(pm.profilesPath)
	if err != nil {
		log.Warn().Err(err).Str("path", pm.profilesPath).Msg("Failed to read profiles directory")
		return
	}

	loaded := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			profilePath := filepath.Join(pm.profilesPath, file.Name())
			if profile, err := pm.loadProfile(profilePath); err == nil {
				pm.profiles[profile.Name] = profile
				loaded++
			} else {
				log.Warn().Err(err).Str("file", file.Name()).Msg("Failed to load profile")
			}
		}
	}

	log.Info().Int("loaded_profiles", loaded).Msg("Security profiles loaded")
}

func (pm *ProfileManager) loadTemplates() {
	files, err := os.ReadDir(pm.templatesPath)
	if err != nil {
		log.Warn().Err(err).Str("path", pm.templatesPath).Msg("Failed to read templates directory")
		return
	}

	loaded := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			templatePath := filepath.Join(pm.templatesPath, file.Name())
			if template, err := pm.loadTemplate(templatePath); err == nil {
				pm.templates[template.Name] = template
				loaded++
			} else {
				log.Warn().Err(err).Str("file", file.Name()).Msg("Failed to load template")
			}
		}
	}

	log.Info().Int("loaded_templates", loaded).Msg("Security templates loaded")
}

func (pm *ProfileManager) loadProfile(profilePath string) (*SecurityProfileSpec, error) {
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, err
	}

	var profile SecurityProfileSpec
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, err
	}

	return &profile, nil
}

func (pm *ProfileManager) loadTemplate(templatePath string) (*ProfileTemplate, error) {
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}

	var template ProfileTemplate
	if err := json.Unmarshal(data, &template); err != nil {
		return nil, err
	}

	return &template, nil
}

func (pm *ProfileManager) saveProfile(profile *SecurityProfileSpec) error {
	profilePath := filepath.Join(pm.profilesPath, fmt.Sprintf("%s.json", profile.Name))
	
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(profilePath, data, 0644)
}

func (pm *ProfileManager) validateProfile(profile *SecurityProfileSpec) error {
	if profile.Name == "" {
		return fmt.Errorf("profile name is required")
	}

	if profile.Type == "" {
		return fmt.Errorf("profile type is required")
	}

	if profile.Level == "" {
		return fmt.Errorf("profile level is required")
	}

	// Run custom validators
	for _, validator := range pm.validators {
		if err := validator.ValidateProfile(profile); err != nil {
			return err
		}
	}

	return nil
}

func (pm *ProfileManager) processProfileInheritance(profile *SecurityProfileSpec) error {
	baseProfile, exists := pm.profiles[profile.BaseProfile]
	if !exists {
		baseProfile, exists = pm.builtinProfiles[profile.BaseProfile]
	}
	
	if !exists {
		return fmt.Errorf("base profile '%s' not found", profile.BaseProfile)
	}

	// Merge base profile settings
	if profile.Namespaces == nil {
		profile.Namespaces = baseProfile.Namespaces
	}
	
	if profile.Capabilities == nil {
		profile.Capabilities = baseProfile.Capabilities
	}
	
	if profile.Seccomp == nil {
		profile.Seccomp = baseProfile.Seccomp
	}
	
	if profile.MAC == nil {
		profile.MAC = baseProfile.MAC
	}

	// Track inheritance
	pm.profileHierarchy[profile.Name] = append(pm.profileHierarchy[profile.Name], profile.BaseProfile)

	return nil
}

func (pm *ProfileManager) matchesQuery(profile *SecurityProfileSpec, query *ProfileQuery) bool {
	if query == nil {
		return true
	}

	if query.Name != "" && !strings.Contains(strings.ToLower(profile.Name), strings.ToLower(query.Name)) {
		return false
	}

	if query.Type != "" && profile.Type != query.Type {
		return false
	}

	if query.Level != "" && profile.Level != query.Level {
		return false
	}

	if query.Enabled != nil && profile.Enabled != *query.Enabled {
		return false
	}

	if query.Author != "" && profile.Author != query.Author {
		return false
	}

	if len(query.Tags) > 0 {
		hasMatchingTag := false
		for _, queryTag := range query.Tags {
			for _, profileTag := range profile.Tags {
				if strings.EqualFold(queryTag, profileTag) {
					hasMatchingTag = true
					break
				}
			}
			if hasMatchingTag {
				break
			}
		}
		if !hasMatchingTag {
			return false
		}
	}

	return true
}

func (pm *ProfileManager) hasProfileDependencies(name string) bool {
	for _, profile := range pm.profiles {
		if profile.BaseProfile == name {
			return true
		}
	}
	return false
}

func (pm *ProfileManager) trackProfileUsage(name string) {
	stats, exists := pm.usageStats[name]
	if !exists {
		stats = &ProfileUsageStats{
			ProfileName: name,
		}
		pm.usageStats[name] = stats
	}

	stats.TotalUsage++
	stats.LastUsed = time.Now()

	// Update profile usage count
	if profile, exists := pm.profiles[name]; exists {
		profile.UsageCount++
		profile.LastUsed = time.Now()
	}
}

func (pm *ProfileManager) validateTemplateVariables(template *ProfileTemplate, variables map[string]interface{}) error {
	for _, variable := range template.Variables {
		value, provided := variables[variable.Name]
		
		if variable.Required && !provided {
			return fmt.Errorf("required template variable '%s' not provided", variable.Name)
		}
		
		if provided {
			// Type validation (simplified)
			switch variable.Type {
			case "string":
				if _, ok := value.(string); !ok {
					return fmt.Errorf("template variable '%s' must be a string", variable.Name)
				}
			case "int":
				if _, ok := value.(int); !ok {
					return fmt.Errorf("template variable '%s' must be an integer", variable.Name)
				}
			case "bool":
				if _, ok := value.(bool); !ok {
					return fmt.Errorf("template variable '%s' must be a boolean", variable.Name)
				}
			}
		}
	}
	
	return nil
}

func (pm *ProfileManager) generateProfileFromTemplate(template *ProfileTemplate, profileName string, variables map[string]interface{}) (*SecurityProfileSpec, error) {
	// Apply default values
	templateVars := make(map[string]interface{})
	for _, variable := range template.Variables {
		if value, provided := variables[variable.Name]; provided {
			templateVars[variable.Name] = value
		} else if variable.Default != nil {
			templateVars[variable.Name] = variable.Default
		}
	}

	// Execute template
	var result strings.Builder
	if err := template.Template.Execute(&result, templateVars); err != nil {
		return nil, err
	}

	// Parse the generated JSON
	var profile SecurityProfileSpec
	if err := json.Unmarshal([]byte(result.String()), &profile); err != nil {
		return nil, err
	}

	// Ensure the profile name matches
	profile.Name = profileName

	return &profile, nil
}

func (pm *ProfileManager) deepCopyProfile(profile *SecurityProfileSpec) *SecurityProfileSpec {
	// Deep copy profile using JSON marshaling/unmarshaling
	data, err := json.Marshal(profile)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to marshal profile for copying")
		return profile
	}

	var copy SecurityProfileSpec
	if err := json.Unmarshal(data, &copy); err != nil {
		log.Warn().Err(err).Msg("Failed to unmarshal profile copy")
		return profile
	}

	return &copy
}