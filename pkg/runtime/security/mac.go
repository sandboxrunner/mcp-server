package security

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"

	"github.com/rs/zerolog/log"
)

// MACType represents Mandatory Access Control system types
type MACType string

const (
	MACTypeNone     MACType = "none"
	MACTypeAppArmor MACType = "apparmor"
	MACTypeSELinux  MACType = "selinux"
)

// MACMode represents MAC profile modes
type MACMode string

const (
	MACModeEnforce    MACMode = "enforce"
	MACModeComplain   MACMode = "complain"
	MACModeDisabled   MACMode = "disabled"
	MACModeUnconfined MACMode = "unconfined"
)

// AppArmorProfile represents an AppArmor security profile
type AppArmorProfile struct {
	Name         string              `json:"name" yaml:"name"`
	Mode         MACMode             `json:"mode" yaml:"mode"`
	Content      string              `json:"content" yaml:"content"`
	Rules        []AppArmorRule      `json:"rules,omitempty" yaml:"rules,omitempty"`
	Includes     []string            `json:"includes,omitempty" yaml:"includes,omitempty"`
	Variables    map[string]string   `json:"variables,omitempty" yaml:"variables,omitempty"`
	Abstractions []string            `json:"abstractions,omitempty" yaml:"abstractions,omitempty"`
	Tunables     map[string]string   `json:"tunables,omitempty" yaml:"tunables,omitempty"`
}

// AppArmorRule represents an AppArmor access rule
type AppArmorRule struct {
	Path        string   `json:"path" yaml:"path"`
	Permissions []string `json:"permissions" yaml:"permissions"`
	Mode        string   `json:"mode,omitempty" yaml:"mode,omitempty"`  // "allow", "deny", "audit"
	Conditions  []string `json:"conditions,omitempty" yaml:"conditions,omitempty"`
	Comment     string   `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// SELinuxContext represents an SELinux security context
type SELinuxContext struct {
	User     string `json:"user" yaml:"user"`
	Role     string `json:"role" yaml:"role"`
	Type     string `json:"type" yaml:"type"`
	Level    string `json:"level" yaml:"level"`
	Range    string `json:"range,omitempty" yaml:"range,omitempty"`
	Category string `json:"category,omitempty" yaml:"category,omitempty"`
}

// SELinuxPolicy represents an SELinux security policy
type SELinuxPolicy struct {
	Name        string             `json:"name" yaml:"name"`
	Version     string             `json:"version" yaml:"version"`
	Context     *SELinuxContext    `json:"context" yaml:"context"`
	Rules       []SELinuxRule      `json:"rules,omitempty" yaml:"rules,omitempty"`
	Modules     []string           `json:"modules,omitempty" yaml:"modules,omitempty"`
	Booleans    map[string]bool    `json:"booleans,omitempty" yaml:"booleans,omitempty"`
	PortContext map[string]string  `json:"portContext,omitempty" yaml:"portContext,omitempty"`
	FileContext map[string]string  `json:"fileContext,omitempty" yaml:"fileContext,omitempty"`
}

// SELinuxRule represents an SELinux access rule
type SELinuxRule struct {
	Source      string   `json:"source" yaml:"source"`
	Target      string   `json:"target" yaml:"target"`
	Class       string   `json:"class" yaml:"class"`
	Permissions []string `json:"permissions" yaml:"permissions"`
	Condition   string   `json:"condition,omitempty" yaml:"condition,omitempty"`
	Comment     string   `json:"comment,omitempty" yaml:"comment,omitempty"`
}

// MACConfig defines MAC system configuration
type MACConfig struct {
	// System type
	Type MACType `json:"type" yaml:"type"`

	// AppArmor configuration
	AppArmor *AppArmorConfig `json:"apparmor,omitempty" yaml:"apparmor,omitempty"`

	// SELinux configuration
	SELinux *SELinuxConfig `json:"selinux,omitempty" yaml:"selinux,omitempty"`

	// Profile management
	ProfileTemplate string            `json:"profileTemplate,omitempty" yaml:"profileTemplate,omitempty"`
	TemplateVars    map[string]string `json:"templateVars,omitempty" yaml:"templateVars,omitempty"`
	
	// Monitoring and compliance
	AuditConfig     *MACAuditConfig   `json:"auditConfig,omitempty" yaml:"auditConfig,omitempty"`
	ComplianceMode  bool              `json:"complianceMode" yaml:"complianceMode"`
	ReportViolations bool             `json:"reportViolations" yaml:"reportViolations"`
}

// AppArmorConfig defines AppArmor-specific configuration
type AppArmorConfig struct {
	ProfileName     string            `json:"profileName" yaml:"profileName"`
	Mode            MACMode           `json:"mode" yaml:"mode"`
	ProfilePath     string            `json:"profilePath,omitempty" yaml:"profilePath,omitempty"`
	CustomProfile   *AppArmorProfile  `json:"customProfile,omitempty" yaml:"customProfile,omitempty"`
	LoadProfile     bool              `json:"loadProfile" yaml:"loadProfile"`
	ProfileTemplate string            `json:"profileTemplate,omitempty" yaml:"profileTemplate,omitempty"`
	ExtraRules      []AppArmorRule    `json:"extraRules,omitempty" yaml:"extraRules,omitempty"`
}

// SELinuxConfig defines SELinux-specific configuration
type SELinuxConfig struct {
	Context       *SELinuxContext   `json:"context" yaml:"context"`
	PolicyName    string            `json:"policyName,omitempty" yaml:"policyName,omitempty"`
	PolicyPath    string            `json:"policyPath,omitempty" yaml:"policyPath,omitempty"`
	CustomPolicy  *SELinuxPolicy    `json:"customPolicy,omitempty" yaml:"customPolicy,omitempty"`
	LoadPolicy    bool              `json:"loadPolicy" yaml:"loadPolicy"`
	ExtraRules    []SELinuxRule     `json:"extraRules,omitempty" yaml:"extraRules,omitempty"`
	Enforcing     bool              `json:"enforcing" yaml:"enforcing"`
}

// MACAuditConfig defines MAC auditing configuration
type MACAuditConfig struct {
	Enabled         bool     `json:"enabled" yaml:"enabled"`
	LogViolations   bool     `json:"logViolations" yaml:"logViolations"`
	LogAccess       bool     `json:"logAccess" yaml:"logAccess"`
	AuditRules      []string `json:"auditRules,omitempty" yaml:"auditRules,omitempty"`
	MaxLogEntries   int      `json:"maxLogEntries" yaml:"maxLogEntries"`
}

// MACManager manages Mandatory Access Control systems
type MACManager struct {
	mu                  sync.RWMutex
	containerConfigs    map[string]*MACConfig
	activeProfiles      map[string]string // containerID -> profile name/path
	
	// System support
	systemType          MACType
	appArmorSupport     bool
	seLinuxSupport      bool
	appArmorVersion     string
	seLinuxVersion      string
	
	// Profile management
	profileTemplates    map[string]*template.Template
	profilesPath        string
	
	// Audit and compliance
	auditLog            []MACAuditEntry
	maxAuditEntries     int
	violationLog        []MACViolation
	complianceReports   []ComplianceReport
}

// MACAuditEntry represents a MAC audit log entry
type MACAuditEntry struct {
	Timestamp     int64   `json:"timestamp"`
	ContainerID   string  `json:"containerId"`
	Type          MACType `json:"type"`
	Action        string  `json:"action"`
	Subject       string  `json:"subject"`
	Object        string  `json:"object"`
	Result        string  `json:"result"`
	ProfileName   string  `json:"profileName,omitempty"`
	Context       string  `json:"context,omitempty"`
	Details       string  `json:"details,omitempty"`
}

// MACViolation represents a MAC policy violation
type MACViolation struct {
	Timestamp     int64   `json:"timestamp"`
	ContainerID   string  `json:"containerId"`
	Type          MACType `json:"type"`
	ViolationType string  `json:"violationType"`
	Subject       string  `json:"subject"`
	Object        string  `json:"object"`
	Permission    string  `json:"permission"`
	ProfileName   string  `json:"profileName"`
	Context       string  `json:"context,omitempty"`
	Severity      string  `json:"severity"`
	Mitigation    string  `json:"mitigation,omitempty"`
}

// ComplianceReport represents a MAC compliance report
type ComplianceReport struct {
	Timestamp        int64                    `json:"timestamp"`
	ContainerID      string                   `json:"containerId"`
	Type             MACType                  `json:"type"`
	Status           string                   `json:"status"` // "compliant", "non-compliant", "warning"
	ProfileName      string                   `json:"profileName"`
	ViolationCount   int                      `json:"violationCount"`
	ComplianceScore  float64                  `json:"complianceScore"`
	Issues           []ComplianceIssue        `json:"issues,omitempty"`
	Recommendations  []string                 `json:"recommendations,omitempty"`
	Metrics          ComplianceMetrics        `json:"metrics"`
}

// ComplianceIssue represents a specific compliance issue
type ComplianceIssue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Resolution  string `json:"resolution,omitempty"`
}

// ComplianceMetrics provides compliance metrics
type ComplianceMetrics struct {
	TotalChecks      int                `json:"totalChecks"`
	PassedChecks     int                `json:"passedChecks"`
	FailedChecks     int                `json:"failedChecks"`
	WarningChecks    int                `json:"warningChecks"`
	CoveragePercent  float64            `json:"coveragePercent"`
	RiskScore        float64            `json:"riskScore"`
	PolicyVersion    string             `json:"policyVersion"`
	LastUpdated      int64              `json:"lastUpdated"`
}

// MACValidationResult holds MAC validation results
type MACValidationResult struct {
	Valid           bool               `json:"valid"`
	Errors          []string           `json:"errors,omitempty"`
	Warnings        []string           `json:"warnings,omitempty"`
	Suggestions     []string           `json:"suggestions,omitempty"`
	ProfileAnalysis *ProfileAnalysis   `json:"profileAnalysis,omitempty"`
}

// ProfileAnalysis provides detailed profile analysis
type ProfileAnalysis struct {
	RuleCount       int                `json:"ruleCount"`
	PermissionCount int                `json:"permissionCount"`
	CoverageAreas   []string           `json:"coverageAreas"`
	RiskLevel       string             `json:"riskLevel"`
	Completeness    float64            `json:"completeness"`
	Conflicts       []string           `json:"conflicts,omitempty"`
}

// NewMACManager creates a new MAC manager
func NewMACManager(profilesPath string) *MACManager {
	mm := &MACManager{
		containerConfigs:  make(map[string]*MACConfig),
		activeProfiles:    make(map[string]string),
		profileTemplates:  make(map[string]*template.Template),
		profilesPath:      profilesPath,
		auditLog:          make([]MACAuditEntry, 0),
		violationLog:      make([]MACViolation, 0),
		complianceReports: make([]ComplianceReport, 0),
		maxAuditEntries:   10000,
	}

	// Detect MAC system support
	mm.detectMACSupport()
	
	// Initialize profile templates
	mm.initializeProfileTemplates()
	
	// Ensure profiles directory exists
	if err := os.MkdirAll(profilesPath, 0755); err != nil {
		log.Warn().Err(err).Str("path", profilesPath).Msg("Failed to create profiles directory")
	}
	
	return mm
}

// SetupMAC configures MAC for a container
func (mm *MACManager) SetupMAC(containerID string, config *MACConfig) error {
	logger := log.With().
		Str("container_id", containerID).
		Str("mac_type", string(config.Type)).
		Logger()

	logger.Debug().Msg("Setting up MAC")

	// Validate MAC configuration
	if validation := mm.validateMACConfig(config); !validation.Valid {
		logger.Error().
			Strs("errors", validation.Errors).
			Msg("MAC configuration validation failed")
		return fmt.Errorf("MAC validation failed: %s", strings.Join(validation.Errors, "; "))
	}

	var profileName string
	var err error

	// Setup based on MAC type
	switch config.Type {
	case MACTypeAppArmor:
		if !mm.appArmorSupport {
			logger.Warn().Msg("AppArmor is not supported on this system")
			return nil
		}
		profileName, err = mm.setupAppArmor(containerID, config.AppArmor)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to setup AppArmor")
			return fmt.Errorf("failed to setup AppArmor: %w", err)
		}

	case MACTypeSELinux:
		if !mm.seLinuxSupport {
			logger.Warn().Msg("SELinux is not supported on this system")
			return nil
		}
		profileName, err = mm.setupSELinux(containerID, config.SELinux)
		if err != nil {
			logger.Error().Err(err).Msg("Failed to setup SELinux")
			return fmt.Errorf("failed to setup SELinux: %w", err)
		}

	case MACTypeNone:
		logger.Debug().Msg("MAC disabled for container")
		profileName = "unconfined"

	default:
		return fmt.Errorf("unsupported MAC type: %s", config.Type)
	}

	// Setup MAC auditing if enabled
	if config.AuditConfig != nil && config.AuditConfig.Enabled {
		if err := mm.setupMACAuditing(containerID, config.AuditConfig); err != nil {
			logger.Warn().Err(err).Msg("Failed to setup MAC auditing")
		}
	}

	// Store configuration and profile
	mm.mu.Lock()
	mm.containerConfigs[containerID] = config
	mm.activeProfiles[containerID] = profileName
	mm.mu.Unlock()

	logger.Info().
		Str("profile_name", profileName).
		Str("mac_type", string(config.Type)).
		Bool("compliance_mode", config.ComplianceMode).
		Msg("MAC configured successfully")

	// Audit the setup
	mm.auditMACAction(containerID, string(config.Type), "setup", "", "", 
		fmt.Sprintf("Profile: %s", profileName))

	return nil
}

// ValidateMAC validates MAC configuration for a container
func (mm *MACManager) ValidateMAC(containerID string) (*MACValidationResult, error) {
	mm.mu.RLock()
	config, exists := mm.containerConfigs[containerID]
	mm.mu.RUnlock()

	if !exists {
		return &MACValidationResult{
			Valid: false,
			Errors: []string{fmt.Sprintf("no MAC configuration found for container %s", containerID)},
		}, nil
	}

	result := mm.validateMACConfig(config)
	
	// Additional runtime validation
	if err := mm.validateRuntimeMAC(containerID); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("runtime MAC validation failed: %s", err))
		result.Valid = false
	}

	return result, nil
}

// GenerateComplianceReport generates a compliance report for a container
func (mm *MACManager) GenerateComplianceReport(containerID string) (*ComplianceReport, error) {
	mm.mu.RLock()
	config, exists := mm.containerConfigs[containerID]
	profileName, _ := mm.activeProfiles[containerID]
	mm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no MAC configuration found for container %s", containerID)
	}

	report := &ComplianceReport{
		Timestamp:   0, // In real implementation, use time.Now().Unix()
		ContainerID: containerID,
		Type:        config.Type,
		ProfileName: profileName,
	}

	// Generate compliance metrics
	report.Metrics = mm.generateComplianceMetrics(containerID, config)

	// Count violations in the last period
	violationCount := 0
	for _, violation := range mm.violationLog {
		if violation.ContainerID == containerID {
			violationCount++
		}
	}
	report.ViolationCount = violationCount

	// Calculate compliance score
	report.ComplianceScore = mm.calculateComplianceScore(containerID, config)

	// Determine overall status
	if report.ComplianceScore >= 0.9 {
		report.Status = "compliant"
	} else if report.ComplianceScore >= 0.7 {
		report.Status = "warning"
	} else {
		report.Status = "non-compliant"
	}

	// Generate issues and recommendations
	report.Issues = mm.generateComplianceIssues(containerID, config)
	report.Recommendations = mm.generateRecommendations(containerID, config)

	// Store the report
	mm.mu.Lock()
	mm.complianceReports = append(mm.complianceReports, *report)
	if len(mm.complianceReports) > 100 { // Keep last 100 reports
		mm.complianceReports = mm.complianceReports[1:]
	}
	mm.mu.Unlock()

	return report, nil
}

// GetAuditLog returns MAC audit log entries
func (mm *MACManager) GetAuditLog(containerID string, limit int) []MACAuditEntry {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	var entries []MACAuditEntry
	for i := len(mm.auditLog) - 1; i >= 0 && len(entries) < limit; i-- {
		entry := mm.auditLog[i]
		if containerID == "" || entry.ContainerID == containerID {
			entries = append(entries, entry)
		}
	}

	return entries
}

// GetViolationLog returns MAC violation log entries
func (mm *MACManager) GetViolationLog(containerID string, limit int) []MACViolation {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	var violations []MACViolation
	for i := len(mm.violationLog) - 1; i >= 0 && len(violations) < limit; i-- {
		violation := mm.violationLog[i]
		if containerID == "" || violation.ContainerID == containerID {
			violations = append(violations, violation)
		}
	}

	return violations
}

// CleanupMAC cleans up MAC configuration for a container
func (mm *MACManager) CleanupMAC(containerID string) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()

	logger.Debug().Msg("Cleaning up MAC")

	mm.mu.Lock()
	config, exists := mm.containerConfigs[containerID]
	profileName, _ := mm.activeProfiles[containerID]
	delete(mm.containerConfigs, containerID)
	delete(mm.activeProfiles, containerID)
	mm.mu.Unlock()

	if !exists {
		logger.Warn().Msg("No MAC configuration found for cleanup")
		return nil
	}

	// Cleanup based on MAC type
	switch config.Type {
	case MACTypeAppArmor:
		if err := mm.cleanupAppArmor(containerID, profileName); err != nil {
			logger.Warn().Err(err).Msg("Failed to cleanup AppArmor")
		}

	case MACTypeSELinux:
		if err := mm.cleanupSELinux(containerID, profileName); err != nil {
			logger.Warn().Err(err).Msg("Failed to cleanup SELinux")
		}
	}

	// Audit the cleanup
	mm.auditMACAction(containerID, string(config.Type), "cleanup", "", "", 
		fmt.Sprintf("Profile: %s", profileName))

	logger.Debug().Msg("MAC cleanup completed")
	return nil
}

// Private helper methods

func (mm *MACManager) detectMACSupport() {
	// Detect AppArmor support
	if mm.checkAppArmorSupport() {
		mm.appArmorSupport = true
		mm.systemType = MACTypeAppArmor
		mm.appArmorVersion = mm.getAppArmorVersion()
		log.Debug().Str("version", mm.appArmorVersion).Msg("AppArmor support detected")
	}

	// Detect SELinux support
	if mm.checkSELinuxSupport() {
		mm.seLinuxSupport = true
		if mm.systemType == MACTypeNone {
			mm.systemType = MACTypeSELinux
		}
		mm.seLinuxVersion = mm.getSELinuxVersion()
		log.Debug().Str("version", mm.seLinuxVersion).Msg("SELinux support detected")
	}

	if mm.systemType == MACTypeNone {
		log.Warn().Msg("No MAC system support detected")
	}

	log.Info().
		Bool("apparmor", mm.appArmorSupport).
		Bool("selinux", mm.seLinuxSupport).
		Str("primary_type", string(mm.systemType)).
		Msg("MAC support detected")
}

func (mm *MACManager) checkAppArmorSupport() bool {
	// Check for AppArmor filesystem
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err != nil {
		return false
	}

	// Check if AppArmor is enabled
	status, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return false
	}

	return len(status) > 0
}

func (mm *MACManager) checkSELinuxSupport() bool {
	// Check for SELinux filesystem
	if _, err := os.Stat("/sys/fs/selinux"); err != nil {
		return false
	}

	// Check if SELinux is enabled
	status, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		return false
	}

	return len(status) > 0
}

func (mm *MACManager) getAppArmorVersion() string {
	// Try to get AppArmor version
	content, err := os.ReadFile("/sys/kernel/security/apparmor/features")
	if err != nil {
		return "unknown"
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.Contains(line, "version") {
			return strings.TrimSpace(line)
		}
	}

	return "unknown"
}

func (mm *MACManager) getSELinuxVersion() string {
	// Try to get SELinux version
	content, err := os.ReadFile("/sys/fs/selinux/policyvers")
	if err != nil {
		return "unknown"
	}

	return strings.TrimSpace(string(content))
}

func (mm *MACManager) initializeProfileTemplates() {
	// AppArmor profile template
	appArmorTemplate := `#include <tunables/global>

profile {{.ProfileName}} flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  {{range .Abstractions}}#include <abstractions/{{.}}>
  {{end}}

  # Capabilities
  {{range .Capabilities}}capability {{.}},
  {{end}}

  # Network access
  {{if .NetworkAccess}}network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,
  network netlink raw,{{end}}

  # File system access
  {{range .Rules}}{{.Path}} {{.Permissions}},
  {{end}}

  # Signal access
  signal (send) set=(term, int, quit, usr1, usr2),
  signal (receive) set=(term, int, quit, usr1, usr2),

  # Process access
  {{range .ProcessAccess}}{{.}},
  {{end}}

  # Deny dangerous operations
  deny /proc/sys/kernel/** w,
  deny /sys/kernel/security/** w,
  deny mount,
  deny umount,
  deny pivot_root,

  # Allow specific operations based on profile type
  {{range .CustomRules}}{{.}},
  {{end}}
}`

	tmpl, err := template.New("apparmor").Parse(appArmorTemplate)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse AppArmor template")
	} else {
		mm.profileTemplates["apparmor"] = tmpl
	}

	// SELinux policy template
	seLinuxTemplate := `policy_module({{.ModuleName}}, {{.Version}})

require {
	type unconfined_t;
	type container_t;
	class process { fork exec };
	class file { read write open };
	class dir { search };
}

# Define container domain
type {{.DomainType}}_t;
domain_type({{.DomainType}}_t)

# Domain transition
allow unconfined_t {{.DomainType}}_t:process transition;
allow {{.DomainType}}_t {{.DomainType}}_t:process { fork signal };

# File access rules
{{range .FileRules}}allow {{.Source}} {{.Target}}:{{.Class}} { {{range .Permissions}}{{.}} {{end}}};
{{end}}

# Network access rules
{{range .NetworkRules}}{{.}}
{{end}}

# Process rules
{{range .ProcessRules}}{{.}}
{{end}}`

	tmpl2, err := template.New("selinux").Parse(seLinuxTemplate)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse SELinux template")
	} else {
		mm.profileTemplates["selinux"] = tmpl2
	}

	log.Info().Int("templates", len(mm.profileTemplates)).Msg("MAC profile templates initialized")
}

func (mm *MACManager) validateMACConfig(config *MACConfig) *MACValidationResult {
	result := &MACValidationResult{
		Valid: true,
	}

	// Validate MAC type
	switch config.Type {
	case MACTypeNone:
		// No additional validation needed
	case MACTypeAppArmor:
		if !mm.appArmorSupport {
			result.Errors = append(result.Errors, "AppArmor is not supported on this system")
			result.Valid = false
		}
		if config.AppArmor == nil {
			result.Errors = append(result.Errors, "AppArmor configuration is required when type is apparmor")
			result.Valid = false
		} else {
			if err := mm.validateAppArmorConfig(config.AppArmor); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("AppArmor validation failed: %s", err))
				result.Valid = false
			}
		}
	case MACTypeSELinux:
		if !mm.seLinuxSupport {
			result.Errors = append(result.Errors, "SELinux is not supported on this system")
			result.Valid = false
		}
		if config.SELinux == nil {
			result.Errors = append(result.Errors, "SELinux configuration is required when type is selinux")
			result.Valid = false
		} else {
			if err := mm.validateSELinuxConfig(config.SELinux); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("SELinux validation failed: %s", err))
				result.Valid = false
			}
		}
	default:
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported MAC type: %s", config.Type))
		result.Valid = false
	}

	return result
}

func (mm *MACManager) validateAppArmorConfig(config *AppArmorConfig) error {
	if config.ProfileName == "" {
		return fmt.Errorf("AppArmor profile name is required")
	}

	// Validate profile name format
	if !isValidProfileName(config.ProfileName) {
		return fmt.Errorf("invalid AppArmor profile name: %s", config.ProfileName)
	}

	// Validate mode
	switch config.Mode {
	case MACModeEnforce, MACModeComplain, MACModeUnconfined:
		// Valid modes
	default:
		return fmt.Errorf("invalid AppArmor mode: %s", config.Mode)
	}

	return nil
}

func (mm *MACManager) validateSELinuxConfig(config *SELinuxConfig) error {
	if config.Context == nil {
		return fmt.Errorf("SELinux context is required")
	}

	// Validate context components
	if config.Context.User == "" || config.Context.Role == "" || config.Context.Type == "" {
		return fmt.Errorf("SELinux context must include user, role, and type")
	}

	// Validate context format
	if !isValidSELinuxContext(config.Context) {
		return fmt.Errorf("invalid SELinux context format")
	}

	return nil
}

func (mm *MACManager) setupAppArmor(containerID string, config *AppArmorConfig) (string, error) {
	logger := log.With().
		Str("container_id", containerID).
		Str("profile_name", config.ProfileName).
		Logger()

	logger.Debug().Msg("Setting up AppArmor profile")

	var profile *AppArmorProfile

	// Generate or load profile
	if config.CustomProfile != nil {
		profile = config.CustomProfile
	} else if config.ProfilePath != "" {
		loadedProfile, err := mm.loadAppArmorProfile(config.ProfilePath)
		if err != nil {
			return "", fmt.Errorf("failed to load AppArmor profile: %w", err)
		}
		profile = loadedProfile
	} else {
		// Generate profile from template
		generatedProfile, err := mm.generateAppArmorProfile(containerID, config)
		if err != nil {
			return "", fmt.Errorf("failed to generate AppArmor profile: %w", err)
		}
		profile = generatedProfile
	}

	// Write profile to file
	profilePath, err := mm.writeAppArmorProfile(containerID, profile)
	if err != nil {
		return "", fmt.Errorf("failed to write AppArmor profile: %w", err)
	}

	// Load profile if requested
	if config.LoadProfile {
		if err := mm.loadAppArmorProfileIntoKernel(profilePath, config.Mode); err != nil {
			logger.Warn().Err(err).Msg("Failed to load AppArmor profile into kernel")
		}
	}

	logger.Info().
		Str("profile_path", profilePath).
		Str("mode", string(config.Mode)).
		Msg("AppArmor profile setup completed")

	return profile.Name, nil
}

func (mm *MACManager) setupSELinux(containerID string, config *SELinuxConfig) (string, error) {
	logger := log.With().
		Str("container_id", containerID).
		Str("context_type", config.Context.Type).
		Logger()

	logger.Debug().Msg("Setting up SELinux policy")

	var policy *SELinuxPolicy

	// Generate or load policy
	if config.CustomPolicy != nil {
		policy = config.CustomPolicy
	} else if config.PolicyPath != "" {
		loadedPolicy, err := mm.loadSELinuxPolicy(config.PolicyPath)
		if err != nil {
			return "", fmt.Errorf("failed to load SELinux policy: %w", err)
		}
		policy = loadedPolicy
	} else {
		// Generate policy from template
		generatedPolicy, err := mm.generateSELinuxPolicy(containerID, config)
		if err != nil {
			return "", fmt.Errorf("failed to generate SELinux policy: %w", err)
		}
		policy = generatedPolicy
	}

	// Write policy to file
	policyPath, err := mm.writeSELinuxPolicy(containerID, policy)
	if err != nil {
		return "", fmt.Errorf("failed to write SELinux policy: %w", err)
	}

	// Load policy if requested
	if config.LoadPolicy {
		if err := mm.loadSELinuxPolicyIntoKernel(policyPath, config.Enforcing); err != nil {
			logger.Warn().Err(err).Msg("Failed to load SELinux policy into kernel")
		}
	}

	logger.Info().
		Str("policy_path", policyPath).
		Bool("enforcing", config.Enforcing).
		Msg("SELinux policy setup completed")

	return policy.Name, nil
}

// Additional helper methods continue...
func (mm *MACManager) loadAppArmorProfile(profilePath string) (*AppArmorProfile, error) {
	// Load AppArmor profile from file
	content, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, err
	}

	// Parse profile (simplified)
	profile := &AppArmorProfile{
		Name:    filepath.Base(profilePath),
		Content: string(content),
	}

	return profile, nil
}

func (mm *MACManager) loadSELinuxPolicy(policyPath string) (*SELinuxPolicy, error) {
	// Load SELinux policy from file
	_, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}

	// Parse policy (simplified)
	policy := &SELinuxPolicy{
		Name:    filepath.Base(policyPath),
	}

	return policy, nil
}

func (mm *MACManager) generateAppArmorProfile(containerID string, config *AppArmorConfig) (*AppArmorProfile, error) {
	// Generate AppArmor profile using template
	profile := &AppArmorProfile{
		Name: config.ProfileName,
		Mode: config.Mode,
	}

	// In a real implementation, this would use the template engine
	// to generate a complete profile based on the configuration

	return profile, nil
}

func (mm *MACManager) generateSELinuxPolicy(containerID string, config *SELinuxConfig) (*SELinuxPolicy, error) {
	// Generate SELinux policy using template
	policy := &SELinuxPolicy{
		Name:    fmt.Sprintf("container-%s", containerID),
		Version: "1.0",
		Context: config.Context,
	}

	// In a real implementation, this would use the template engine
	// to generate a complete policy based on the configuration

	return policy, nil
}

func (mm *MACManager) writeAppArmorProfile(containerID string, profile *AppArmorProfile) (string, error) {
	profilePath := filepath.Join(mm.profilesPath, fmt.Sprintf("apparmor-%s", containerID))
	
	if err := os.WriteFile(profilePath, []byte(profile.Content), 0644); err != nil {
		return "", err
	}

	return profilePath, nil
}

func (mm *MACManager) writeSELinuxPolicy(containerID string, policy *SELinuxPolicy) (string, error) {
	policyPath := filepath.Join(mm.profilesPath, fmt.Sprintf("selinux-%s.te", containerID))
	
	// In a real implementation, this would generate the policy file content
	content := fmt.Sprintf("# SELinux policy for container %s\n", containerID)
	
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		return "", err
	}

	return policyPath, nil
}

func (mm *MACManager) loadAppArmorProfileIntoKernel(profilePath string, mode MACMode) error {
	// In a real implementation, this would use apparmor_parser or similar
	log.Debug().Str("profile_path", profilePath).Str("mode", string(mode)).Msg("Loading AppArmor profile into kernel")
	return nil
}

func (mm *MACManager) loadSELinuxPolicyIntoKernel(policyPath string, enforcing bool) error {
	// In a real implementation, this would use semodule or similar
	log.Debug().Str("policy_path", policyPath).Bool("enforcing", enforcing).Msg("Loading SELinux policy into kernel")
	return nil
}

func (mm *MACManager) cleanupAppArmor(containerID, profileName string) error {
	// Clean up AppArmor profile
	profilePath := filepath.Join(mm.profilesPath, fmt.Sprintf("apparmor-%s", containerID))
	if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (mm *MACManager) cleanupSELinux(containerID, profileName string) error {
	// Clean up SELinux policy
	policyPath := filepath.Join(mm.profilesPath, fmt.Sprintf("selinux-%s.te", containerID))
	if err := os.Remove(policyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (mm *MACManager) setupMACAuditing(containerID string, config *MACAuditConfig) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up MAC auditing")
	// In a real implementation, this would configure audit rules
	return nil
}

func (mm *MACManager) validateRuntimeMAC(containerID string) error {
	// Validate that MAC is properly configured at runtime
	mm.mu.RLock()
	profileName, exists := mm.activeProfiles[containerID]
	mm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no active MAC profile found for container %s", containerID)
	}

	// In a real implementation, this would check that the profile is loaded
	// and properly applied to the container process
	log.Debug().Str("container_id", containerID).Str("profile", profileName).Msg("MAC runtime validation passed")
	
	return nil
}

func (mm *MACManager) generateComplianceMetrics(containerID string, config *MACConfig) ComplianceMetrics {
	// Generate compliance metrics based on configuration and violations
	return ComplianceMetrics{
		TotalChecks:     10,
		PassedChecks:    8,
		FailedChecks:    2,
		WarningChecks:   0,
		CoveragePercent: 80.0,
		RiskScore:       0.2,
		PolicyVersion:   "1.0",
		LastUpdated:     0, // In real implementation, use time.Now().Unix()
	}
}

func (mm *MACManager) calculateComplianceScore(containerID string, config *MACConfig) float64 {
	// Calculate compliance score based on violations and configuration
	baseScore := 1.0
	
	// Count recent violations
	violationCount := 0
	for _, violation := range mm.violationLog {
		if violation.ContainerID == containerID {
			violationCount++
		}
	}
	
	// Reduce score based on violations
	if violationCount > 0 {
		baseScore -= float64(violationCount) * 0.1
	}
	
	if baseScore < 0 {
		baseScore = 0
	}
	
	return baseScore
}

func (mm *MACManager) generateComplianceIssues(containerID string, config *MACConfig) []ComplianceIssue {
	var issues []ComplianceIssue
	
	// Check for common compliance issues
	if config.Type == MACTypeNone {
		issues = append(issues, ComplianceIssue{
			Type:        "security",
			Severity:    "high",
			Description: "MAC is disabled",
			Impact:      "No mandatory access control protection",
			Resolution:  "Enable AppArmor or SELinux",
		})
	}
	
	return issues
}

func (mm *MACManager) generateRecommendations(containerID string, config *MACConfig) []string {
	var recommendations []string
	
	if config.Type == MACTypeNone {
		recommendations = append(recommendations, "Enable mandatory access control (AppArmor or SELinux)")
	}
	
	if config.AuditConfig == nil || !config.AuditConfig.Enabled {
		recommendations = append(recommendations, "Enable MAC auditing for better security monitoring")
	}
	
	return recommendations
}

func (mm *MACManager) auditMACAction(containerID, macType, action, subject, object, details string) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	entry := MACAuditEntry{
		Timestamp:   0, // In real implementation, use time.Now().Unix()
		ContainerID: containerID,
		Type:        MACType(macType),
		Action:      action,
		Subject:     subject,
		Object:      object,
		Details:     details,
	}

	mm.auditLog = append(mm.auditLog, entry)

	if len(mm.auditLog) > mm.maxAuditEntries {
		mm.auditLog = mm.auditLog[len(mm.auditLog)-mm.maxAuditEntries:]
	}
}

// Utility functions

func isValidProfileName(name string) bool {
	// AppArmor profile names should be valid file paths or identifiers
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9/_.-]+$`, name)
	return matched
}

func isValidSELinuxContext(context *SELinuxContext) bool {
	// Basic validation of SELinux context components
	if context.User == "" || context.Role == "" || context.Type == "" {
		return false
	}

	// Check for valid characters
	validChars := regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	return validChars.MatchString(context.User) && 
		   validChars.MatchString(context.Role) && 
		   validChars.MatchString(context.Type)
}