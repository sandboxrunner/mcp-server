package security

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// Capability represents a Linux capability
type Capability string

// Standard Linux capabilities
const (
	// File system capabilities
	CapChown          Capability = "CAP_CHOWN"
	CapDACOverride    Capability = "CAP_DAC_OVERRIDE"
	CapDACReadSearch  Capability = "CAP_DAC_READ_SEARCH"
	CapFowner         Capability = "CAP_FOWNER"
	CapFsetid         Capability = "CAP_FSETID"

	// Process capabilities
	CapKill           Capability = "CAP_KILL"
	CapSetgid         Capability = "CAP_SETGID"
	CapSetuid         Capability = "CAP_SETUID"
	CapSetpcap        Capability = "CAP_SETPCAP"

	// Network capabilities
	CapNetBindService Capability = "CAP_NET_BIND_SERVICE"
	CapNetBroadcast   Capability = "CAP_NET_BROADCAST"
	CapNetAdmin       Capability = "CAP_NET_ADMIN"
	CapNetRaw         Capability = "CAP_NET_RAW"

	// IPC capabilities
	CapIPCLock        Capability = "CAP_IPC_LOCK"
	CapIPCOwner       Capability = "CAP_IPC_OWNER"

	// System capabilities
	CapSysModule      Capability = "CAP_SYS_MODULE"
	CapSysRawio       Capability = "CAP_SYS_RAWIO"
	CapSysChroot      Capability = "CAP_SYS_CHROOT"
	CapSysPtrace      Capability = "CAP_SYS_PTRACE"
	CapSysPacct       Capability = "CAP_SYS_PACCT"
	CapSysAdmin       Capability = "CAP_SYS_ADMIN"
	CapSysBoot        Capability = "CAP_SYS_BOOT"
	CapSysNice        Capability = "CAP_SYS_NICE"
	CapSysResource    Capability = "CAP_SYS_RESOURCE"
	CapSysTime        Capability = "CAP_SYS_TIME"
	CapSysTTYConfig   Capability = "CAP_SYS_TTY_CONFIG"

	// Additional capabilities
	CapMknod          Capability = "CAP_MKNOD"
	CapLease          Capability = "CAP_LEASE"
	CapAuditWrite     Capability = "CAP_AUDIT_WRITE"
	CapAuditControl   Capability = "CAP_AUDIT_CONTROL"
	CapSetfcap        Capability = "CAP_SETFCAP"
	CapMACOverride    Capability = "CAP_MAC_OVERRIDE"
	CapMACAdmin       Capability = "CAP_MAC_ADMIN"
	CapSyslog         Capability = "CAP_SYSLOG"
	CapWakeAlarm      Capability = "CAP_WAKE_ALARM"
	CapBlockSuspend   Capability = "CAP_BLOCK_SUSPEND"
	CapLinuxImmutable Capability = "CAP_LINUX_IMMUTABLE"
)

// CapabilitySet represents different capability sets
type CapabilitySet string

const (
	CapabilitySetEffective   CapabilitySet = "effective"
	CapabilitySetPermitted   CapabilitySet = "permitted"
	CapabilitySetInheritable CapabilitySet = "inheritable"
	CapabilitySetBounding    CapabilitySet = "bounding"
	CapabilitySetAmbient     CapabilitySet = "ambient"
)

// SecurityProfile defines different security profiles with predefined capability sets
type SecurityProfile string

const (
	ProfileRestricted SecurityProfile = "restricted"    // Minimal capabilities
	ProfileDefault    SecurityProfile = "default"       // Standard safe capabilities
	ProfileNetworking SecurityProfile = "networking"    // Network-related capabilities
	ProfileFilesystem SecurityProfile = "filesystem"    // File system capabilities
	ProfilePrivileged SecurityProfile = "privileged"    // Full capabilities (dangerous)
)

// CapabilityConfig defines capability management configuration
type CapabilityConfig struct {
	// Capability operations
	Add    []Capability `json:"add,omitempty" yaml:"add,omitempty"`       // Capabilities to add
	Drop   []Capability `json:"drop,omitempty" yaml:"drop,omitempty"`     // Capabilities to drop
	Keep   []Capability `json:"keep,omitempty" yaml:"keep,omitempty"`     // Capabilities to keep (whitelist)

	// Ambient capabilities
	Ambient []Capability `json:"ambient,omitempty" yaml:"ambient,omitempty"`

	// Security profile
	Profile SecurityProfile `json:"profile,omitempty" yaml:"profile,omitempty"`

	// Advanced options
	NoNewPrivs              bool                            `json:"noNewPrivs,omitempty" yaml:"noNewPrivs,omitempty"`
	AllowPrivilegeEscalation bool                           `json:"allowPrivilegeEscalation,omitempty" yaml:"allowPrivilegeEscalation,omitempty"`
	CapabilityInheritance   *CapabilityInheritanceConfig   `json:"capabilityInheritance,omitempty" yaml:"capabilityInheritance,omitempty"`
	AuditConfig             *CapabilityAuditConfig         `json:"auditConfig,omitempty" yaml:"auditConfig,omitempty"`
}

// CapabilityInheritanceConfig defines how capabilities are inherited
type CapabilityInheritanceConfig struct {
	Enabled            bool         `json:"enabled" yaml:"enabled"`
	InheritableSet     []Capability `json:"inheritableSet,omitempty" yaml:"inheritableSet,omitempty"`
	AmbientSet         []Capability `json:"ambientSet,omitempty" yaml:"ambientSet,omitempty"`
	BoundingSet        []Capability `json:"boundingSet,omitempty" yaml:"boundingSet,omitempty"`
	PreserveAmbient    bool         `json:"preserveAmbient,omitempty" yaml:"preserveAmbient,omitempty"`
}

// CapabilityAuditConfig defines capability auditing configuration
type CapabilityAuditConfig struct {
	Enabled          bool         `json:"enabled" yaml:"enabled"`
	AuditActions     []string     `json:"auditActions,omitempty" yaml:"auditActions,omitempty"`   // "use", "drop", "escalate"
	AuditCapabilities []Capability `json:"auditCapabilities,omitempty" yaml:"auditCapabilities,omitempty"`
	LogLevel         string       `json:"logLevel,omitempty" yaml:"logLevel,omitempty"`
}

// CapabilityInfo provides information about a capability
type CapabilityInfo struct {
	Name        Capability `json:"name"`
	Description string     `json:"description"`
	Risk        string     `json:"risk"`        // "low", "medium", "high", "critical"
	Category    string     `json:"category"`    // "filesystem", "network", "process", "system"
	Required    []string   `json:"required,omitempty"`    // Dependencies
	Conflicts   []string   `json:"conflicts,omitempty"`   // Conflicting capabilities
}

// CapabilityState represents the current capability state
type CapabilityState struct {
	Effective   []Capability `json:"effective"`
	Permitted   []Capability `json:"permitted"`
	Inheritable []Capability `json:"inheritable"`
	Bounding    []Capability `json:"bounding"`
	Ambient     []Capability `json:"ambient"`
}

// CapabilityManager manages Linux capabilities for containers
type CapabilityManager struct {
	mu                    sync.RWMutex
	containerCapabilities map[string]*CapabilityConfig
	activeStates          map[string]*CapabilityState
	
	// System support
	systemCapabilities    map[Capability]bool
	supportInfo          map[Capability]*CapabilityInfo
	
	// Security profiles
	securityProfiles     map[SecurityProfile]*CapabilityConfig
	
	// Auditing
	auditLog             []CapabilityAuditEntry
	maxAuditEntries      int
}

// CapabilityValidationResult holds capability validation results
type CapabilityValidationResult struct {
	Valid          bool                   `json:"valid"`
	Errors         []string               `json:"errors,omitempty"`
	Warnings       []string               `json:"warnings,omitempty"`
	Suggestions    []string               `json:"suggestions,omitempty"`
	RiskAssessment *CapabilityRiskAssessment `json:"riskAssessment,omitempty"`
	CapabilityRisks map[Capability]string `json:"capabilityRisks,omitempty"`
}

// CapabilityRiskAssessment provides risk analysis for capability configuration
type CapabilityRiskAssessment struct {
	OverallRisk     string                      `json:"overallRisk"`  // "low", "medium", "high", "critical"
	RiskFactors     []string                    `json:"riskFactors,omitempty"`
	Mitigations     []string                    `json:"mitigations,omitempty"`
	CapabilityRisks map[Capability]string      `json:"capabilityRisks"`
}

// CapabilityAuditEntry represents a capability audit log entry
type CapabilityAuditEntry struct {
	Timestamp     int64       `json:"timestamp"`
	ContainerID   string      `json:"containerId"`
	Action        string      `json:"action"`     // "use", "drop", "escalate", "deny"
	Capability    Capability  `json:"capability"`
	Process       string      `json:"process,omitempty"`
	Details       string      `json:"details,omitempty"`
	RiskLevel     string      `json:"riskLevel"`
}

// NewCapabilityManager creates a new capability manager
func NewCapabilityManager() *CapabilityManager {
	cm := &CapabilityManager{
		containerCapabilities: make(map[string]*CapabilityConfig),
		activeStates:         make(map[string]*CapabilityState),
		systemCapabilities:   make(map[Capability]bool),
		supportInfo:         make(map[Capability]*CapabilityInfo),
		securityProfiles:    make(map[SecurityProfile]*CapabilityConfig),
		auditLog:            make([]CapabilityAuditEntry, 0),
		maxAuditEntries:     10000,
	}

	// Initialize capability support information
	cm.initializeCapabilityInfo()
	
	// Detect system capability support
	cm.detectCapabilitySupport()
	
	// Initialize security profiles
	cm.initializeSecurityProfiles()
	
	return cm
}

// SetupCapabilities configures capability management for a container
func (cm *CapabilityManager) SetupCapabilities(containerID string, config *CapabilityConfig) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()

	logger.Debug().Msg("Setting up capability management")

	// Validate capability configuration
	if validation := cm.validateCapabilityConfig(config); !validation.Valid {
		logger.Error().
			Strs("errors", validation.Errors).
			Msg("Capability configuration validation failed")
		return fmt.Errorf("capability validation failed: %s", strings.Join(validation.Errors, "; "))
	}

	// Merge with profile if specified
	mergedConfig := cm.mergeWithProfile(config)

	// Apply capability restrictions
	state, err := cm.applyCapabilityConfig(containerID, mergedConfig)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to apply capability configuration")
		return fmt.Errorf("failed to apply capabilities: %w", err)
	}

	// Set up capability auditing if enabled
	if mergedConfig.AuditConfig != nil && mergedConfig.AuditConfig.Enabled {
		if err := cm.setupCapabilityAuditing(containerID, mergedConfig.AuditConfig); err != nil {
			logger.Warn().Err(err).Msg("Failed to setup capability auditing")
		}
	}

	// Store configuration and state
	cm.mu.Lock()
	cm.containerCapabilities[containerID] = mergedConfig
	cm.activeStates[containerID] = state
	cm.mu.Unlock()

	logger.Info().
		Int("effective_capabilities", len(state.Effective)).
		Int("dropped_capabilities", len(mergedConfig.Drop)).
		Int("added_capabilities", len(mergedConfig.Add)).
		Bool("no_new_privs", mergedConfig.NoNewPrivs).
		Str("profile", string(mergedConfig.Profile)).
		Msg("Capability management configured successfully")

	// Audit the setup
	cm.auditCapabilityAction(containerID, "setup", "", fmt.Sprintf("Profile: %s, Effective: %d", mergedConfig.Profile, len(state.Effective)))

	return nil
}

// ValidateCapabilities validates capability configuration for a container
func (cm *CapabilityManager) ValidateCapabilities(containerID string) (*CapabilityValidationResult, error) {
	cm.mu.RLock()
	config, exists := cm.containerCapabilities[containerID]
	state, hasState := cm.activeStates[containerID]
	cm.mu.RUnlock()

	if !exists || !hasState {
		return &CapabilityValidationResult{
			Valid: false,
			Errors: []string{fmt.Sprintf("no capability configuration found for container %s", containerID)},
		}, nil
	}

	result := cm.validateCapabilityConfig(config)
	
	// Additional runtime validations
	if err := cm.validateCapabilityState(state); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("capability state validation failed: %s", err))
		result.Valid = false
	}

	return result, nil
}

// GetCapabilityState returns current capability state for a container
func (cm *CapabilityManager) GetCapabilityState(containerID string) (*CapabilityState, error) {
	cm.mu.RLock()
	state, exists := cm.activeStates[containerID]
	cm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no capability state found for container %s", containerID)
	}

	// Return a copy to prevent modification
	return &CapabilityState{
		Effective:   append([]Capability{}, state.Effective...),
		Permitted:   append([]Capability{}, state.Permitted...),
		Inheritable: append([]Capability{}, state.Inheritable...),
		Bounding:    append([]Capability{}, state.Bounding...),
		Ambient:     append([]Capability{}, state.Ambient...),
	}, nil
}

// AuditCapabilityUsage audits capability usage for a container
func (cm *CapabilityManager) AuditCapabilityUsage(containerID string, capability Capability, action string, process string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Get risk level for capability
	riskLevel := "low"
	if info, exists := cm.supportInfo[capability]; exists {
		riskLevel = info.Risk
	}

	entry := CapabilityAuditEntry{
		Timestamp:   0, // In real implementation, use time.Now().Unix()
		ContainerID: containerID,
		Action:      action,
		Capability:  capability,
		Process:     process,
		RiskLevel:   riskLevel,
	}

	cm.auditLog = append(cm.auditLog, entry)

	// Trim audit log if it exceeds maximum entries
	if len(cm.auditLog) > cm.maxAuditEntries {
		cm.auditLog = cm.auditLog[len(cm.auditLog)-cm.maxAuditEntries:]
	}

	// Log high-risk capability usage
	if riskLevel == "high" || riskLevel == "critical" {
		log.Warn().
			Str("container_id", containerID).
			Str("capability", string(capability)).
			Str("action", action).
			Str("process", process).
			Str("risk_level", riskLevel).
			Msg("High-risk capability usage detected")
	}
}

// GetAuditLog returns capability audit log entries for a container
func (cm *CapabilityManager) GetAuditLog(containerID string, limit int) []CapabilityAuditEntry {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var entries []CapabilityAuditEntry
	for i := len(cm.auditLog) - 1; i >= 0 && len(entries) < limit; i-- {
		entry := cm.auditLog[i]
		if containerID == "" || entry.ContainerID == containerID {
			entries = append(entries, entry)
		}
	}

	return entries
}

// CleanupCapabilities cleans up capability management for a container
func (cm *CapabilityManager) CleanupCapabilities(containerID string) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()

	logger.Debug().Msg("Cleaning up capability management")

	cm.mu.Lock()
	delete(cm.containerCapabilities, containerID)
	delete(cm.activeStates, containerID)
	cm.mu.Unlock()

	// Audit the cleanup
	cm.auditCapabilityAction(containerID, "cleanup", "", "Capability management cleaned up")

	logger.Debug().Msg("Capability management cleanup completed")
	return nil
}

// Private helper methods

func (cm *CapabilityManager) initializeCapabilityInfo() {
	cm.supportInfo = map[Capability]*CapabilityInfo{
		CapChown: {
			Name: CapChown, Description: "Change file ownership", Risk: "medium", Category: "filesystem",
		},
		CapDACOverride: {
			Name: CapDACOverride, Description: "Bypass file read/write/execute permission checks", Risk: "high", Category: "filesystem",
		},
		CapDACReadSearch: {
			Name: CapDACReadSearch, Description: "Bypass file read and directory search permission checks", Risk: "medium", Category: "filesystem",
		},
		CapFowner: {
			Name: CapFowner, Description: "Bypass permission checks on operations that normally require file owner", Risk: "medium", Category: "filesystem",
		},
		CapFsetid: {
			Name: CapFsetid, Description: "Don't clear set-user-ID and set-group-ID bits", Risk: "medium", Category: "filesystem",
		},
		CapKill: {
			Name: CapKill, Description: "Send signals to processes", Risk: "medium", Category: "process",
		},
		CapSetgid: {
			Name: CapSetgid, Description: "Change group ID", Risk: "high", Category: "process",
		},
		CapSetuid: {
			Name: CapSetuid, Description: "Change user ID", Risk: "high", Category: "process",
		},
		CapSetpcap: {
			Name: CapSetpcap, Description: "Transfer capabilities to other processes", Risk: "critical", Category: "process",
		},
		CapNetBindService: {
			Name: CapNetBindService, Description: "Bind to privileged ports (< 1024)", Risk: "low", Category: "network",
		},
		CapNetBroadcast: {
			Name: CapNetBroadcast, Description: "Make socket broadcasts", Risk: "low", Category: "network",
		},
		CapNetAdmin: {
			Name: CapNetAdmin, Description: "Perform network administration tasks", Risk: "critical", Category: "network",
		},
		CapNetRaw: {
			Name: CapNetRaw, Description: "Use raw sockets", Risk: "high", Category: "network",
		},
		CapIPCLock: {
			Name: CapIPCLock, Description: "Lock memory", Risk: "medium", Category: "system",
		},
		CapIPCOwner: {
			Name: CapIPCOwner, Description: "Bypass permission checks for IPC operations", Risk: "medium", Category: "system",
		},
		CapSysModule: {
			Name: CapSysModule, Description: "Load and unload kernel modules", Risk: "critical", Category: "system",
		},
		CapSysRawio: {
			Name: CapSysRawio, Description: "Perform raw I/O operations", Risk: "critical", Category: "system",
		},
		CapSysChroot: {
			Name: CapSysChroot, Description: "Use chroot system call", Risk: "medium", Category: "filesystem",
		},
		CapSysPtrace: {
			Name: CapSysPtrace, Description: "Trace arbitrary processes using ptrace", Risk: "high", Category: "process",
		},
		CapSysAdmin: {
			Name: CapSysAdmin, Description: "Perform system administration operations", Risk: "critical", Category: "system",
		},
		CapSysBoot: {
			Name: CapSysBoot, Description: "Use reboot system call", Risk: "critical", Category: "system",
		},
		CapSysNice: {
			Name: CapSysNice, Description: "Change process priority", Risk: "low", Category: "process",
		},
		CapSysResource: {
			Name: CapSysResource, Description: "Override resource limits", Risk: "high", Category: "system",
		},
		CapSysTime: {
			Name: CapSysTime, Description: "Set system clock", Risk: "high", Category: "system",
		},
		CapMknod: {
			Name: CapMknod, Description: "Create special files", Risk: "medium", Category: "filesystem",
		},
		CapAuditWrite: {
			Name: CapAuditWrite, Description: "Write to audit log", Risk: "low", Category: "system",
		},
		CapSetfcap: {
			Name: CapSetfcap, Description: "Set file capabilities", Risk: "critical", Category: "filesystem",
		},
	}
}

func (cm *CapabilityManager) detectCapabilitySupport() {
	// Check which capabilities are available on the system
	// In a real implementation, this would check /proc/sys/kernel/cap_last_cap
	// and validate each capability
	
	for cap := range cm.supportInfo {
		cm.systemCapabilities[cap] = true
	}

	log.Debug().Int("supported_capabilities", len(cm.systemCapabilities)).Msg("Capability support detected")
}

func (cm *CapabilityManager) initializeSecurityProfiles() {
	// Restricted profile - minimal capabilities
	cm.securityProfiles[ProfileRestricted] = &CapabilityConfig{
		Drop: []Capability{
			CapSysAdmin, CapNetAdmin, CapSysModule, CapSysRawio, CapSysBoot,
			CapSetuid, CapSetgid, CapSetpcap, CapNetRaw, CapDACOverride,
			CapFowner, CapFsetid, CapSetfcap, CapSysPtrace,
		},
		NoNewPrivs:              true,
		AllowPrivilegeEscalation: false,
	}

	// Default profile - standard safe capabilities
	cm.securityProfiles[ProfileDefault] = &CapabilityConfig{
		Keep: []Capability{
			CapChown, CapDACReadSearch, CapKill, CapNetBindService,
			CapAuditWrite, CapSysNice,
		},
		Drop: []Capability{
			CapSysAdmin, CapNetAdmin, CapSysModule, CapSysRawio, CapSysBoot,
			CapSetuid, CapSetgid, CapSetpcap, CapNetRaw, CapSetfcap,
		},
		NoNewPrivs:              true,
		AllowPrivilegeEscalation: false,
	}

	// Networking profile - network-related capabilities
	cm.securityProfiles[ProfileNetworking] = &CapabilityConfig{
		Add: []Capability{
			CapNetBindService, CapNetBroadcast,
		},
		Keep: []Capability{
			CapChown, CapDACReadSearch, CapKill, CapNetBindService,
			CapNetBroadcast, CapAuditWrite, CapSysNice,
		},
		Drop: []Capability{
			CapSysAdmin, CapSysModule, CapSysRawio, CapSysBoot,
			CapSetuid, CapSetgid, CapSetpcap, CapSetfcap,
		},
		NoNewPrivs:              true,
		AllowPrivilegeEscalation: false,
	}

	// Filesystem profile - file system capabilities
	cm.securityProfiles[ProfileFilesystem] = &CapabilityConfig{
		Add: []Capability{
			CapChown, CapFowner, CapMknod, CapSysChroot,
		},
		Keep: []Capability{
			CapChown, CapFowner, CapMknod, CapSysChroot,
			CapDACReadSearch, CapKill, CapAuditWrite, CapSysNice,
		},
		Drop: []Capability{
			CapSysAdmin, CapNetAdmin, CapSysModule, CapSysRawio, CapSysBoot,
			CapSetuid, CapSetgid, CapSetpcap, CapNetRaw, CapSetfcap,
		},
		NoNewPrivs:              true,
		AllowPrivilegeEscalation: false,
	}

	// Privileged profile - full capabilities (dangerous)
	cm.securityProfiles[ProfilePrivileged] = &CapabilityConfig{
		NoNewPrivs:              false,
		AllowPrivilegeEscalation: true,
	}
}

func (cm *CapabilityManager) validateCapabilityConfig(config *CapabilityConfig) *CapabilityValidationResult {
	result := &CapabilityValidationResult{
		Valid: true,
		CapabilityRisks: make(map[Capability]string),
	}

	var highRiskCaps []Capability
	var criticalRiskCaps []Capability

	// Validate each capability in Add list
	for _, cap := range config.Add {
		if !cm.systemCapabilities[cap] {
			result.Errors = append(result.Errors, fmt.Sprintf("capability %s is not supported on this system", cap))
			result.Valid = false
			continue
		}

		if info, exists := cm.supportInfo[cap]; exists {
			result.CapabilityRisks[cap] = info.Risk
			switch info.Risk {
			case "high":
				highRiskCaps = append(highRiskCaps, cap)
			case "critical":
				criticalRiskCaps = append(criticalRiskCaps, cap)
			}
		}
	}

	// Validate each capability in Keep list
	for _, cap := range config.Keep {
		if !cm.systemCapabilities[cap] {
			result.Errors = append(result.Errors, fmt.Sprintf("capability %s is not supported on this system", cap))
			result.Valid = false
			continue
		}

		if info, exists := cm.supportInfo[cap]; exists {
			result.CapabilityRisks[cap] = info.Risk
		}
	}

	// Validate each capability in Drop list
	for _, cap := range config.Drop {
		if !cm.systemCapabilities[cap] {
			result.Warnings = append(result.Warnings, fmt.Sprintf("attempting to drop unsupported capability %s", cap))
		}
	}

	// Risk assessment
	riskAssessment := &CapabilityRiskAssessment{
		CapabilityRisks: result.CapabilityRisks,
	}

	if len(criticalRiskCaps) > 0 {
		riskAssessment.OverallRisk = "critical"
		riskAssessment.RiskFactors = append(riskAssessment.RiskFactors, fmt.Sprintf("Critical capabilities: %v", criticalRiskCaps))
		riskAssessment.Mitigations = append(riskAssessment.Mitigations, "Consider using a more restrictive security profile")
	} else if len(highRiskCaps) > 0 {
		riskAssessment.OverallRisk = "high"
		riskAssessment.RiskFactors = append(riskAssessment.RiskFactors, fmt.Sprintf("High-risk capabilities: %v", highRiskCaps))
		riskAssessment.Mitigations = append(riskAssessment.Mitigations, "Enable capability auditing and monitoring")
	} else {
		riskAssessment.OverallRisk = "low"
	}

	if !config.NoNewPrivs {
		riskAssessment.RiskFactors = append(riskAssessment.RiskFactors, "NoNewPrivs is disabled")
		if riskAssessment.OverallRisk == "low" {
			riskAssessment.OverallRisk = "medium"
		}
	}

	if config.AllowPrivilegeEscalation {
		riskAssessment.RiskFactors = append(riskAssessment.RiskFactors, "Privilege escalation is allowed")
		riskAssessment.OverallRisk = "critical"
	}

	result.RiskAssessment = riskAssessment

	// Add suggestions
	if len(config.Add) > 5 {
		result.Suggestions = append(result.Suggestions, "Consider using a predefined security profile instead of adding many capabilities")
	}
	
	if config.Profile == "" && len(config.Add) > 0 {
		result.Suggestions = append(result.Suggestions, "Consider specifying a security profile for better capability management")
	}

	return result
}

func (cm *CapabilityManager) validateCapabilityState(state *CapabilityState) error {
	// Validate that effective capabilities are subset of permitted
	for _, cap := range state.Effective {
		found := false
		for _, permCap := range state.Permitted {
			if cap == permCap {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("effective capability %s is not in permitted set", cap)
		}
	}

	// Validate that ambient capabilities are subset of inheritable and permitted
	for _, cap := range state.Ambient {
		foundInheritable := false
		foundPermitted := false
		
		for _, inhCap := range state.Inheritable {
			if cap == inhCap {
				foundInheritable = true
				break
			}
		}
		
		for _, permCap := range state.Permitted {
			if cap == permCap {
				foundPermitted = true
				break
			}
		}
		
		if !foundInheritable || !foundPermitted {
			return fmt.Errorf("ambient capability %s must be in both inheritable and permitted sets", cap)
		}
	}

	return nil
}

func (cm *CapabilityManager) mergeWithProfile(config *CapabilityConfig) *CapabilityConfig {
	if config.Profile == "" {
		return config
	}

	profileConfig, exists := cm.securityProfiles[config.Profile]
	if !exists {
		log.Warn().Str("profile", string(config.Profile)).Msg("Unknown security profile, using config as-is")
		return config
	}

	merged := &CapabilityConfig{
		Profile: config.Profile,
	}

	// Merge capability lists
	merged.Add = append(profileConfig.Add, config.Add...)
	merged.Drop = append(profileConfig.Drop, config.Drop...)
	merged.Keep = append(profileConfig.Keep, config.Keep...)
	merged.Ambient = append(profileConfig.Ambient, config.Ambient...)

	// Use config values if set, otherwise use profile values
	merged.NoNewPrivs = config.NoNewPrivs || profileConfig.NoNewPrivs
	merged.AllowPrivilegeEscalation = config.AllowPrivilegeEscalation || profileConfig.AllowPrivilegeEscalation

	// Copy other configurations
	merged.CapabilityInheritance = config.CapabilityInheritance
	merged.AuditConfig = config.AuditConfig

	return merged
}

func (cm *CapabilityManager) applyCapabilityConfig(containerID string, config *CapabilityConfig) (*CapabilityState, error) {
	log.Debug().Str("container_id", containerID).Msg("Applying capability configuration")

	// Start with a default capability state
	state := &CapabilityState{
		Effective:   []Capability{},
		Permitted:   []Capability{},
		Inheritable: []Capability{},
		Bounding:    []Capability{},
		Ambient:     []Capability{},
	}

	// In a real implementation, this would:
	// 1. Get current capability state
	// 2. Apply drops, adds, and keeps
	// 3. Configure capability sets
	// 4. Set NoNewPrivs and other flags

	// For now, simulate based on configuration
	if len(config.Keep) > 0 {
		state.Effective = append(state.Effective, config.Keep...)
		state.Permitted = append(state.Permitted, config.Keep...)
	}

	if len(config.Add) > 0 {
		state.Effective = append(state.Effective, config.Add...)
		state.Permitted = append(state.Permitted, config.Add...)
	}

	if len(config.Ambient) > 0 {
		state.Ambient = append(state.Ambient, config.Ambient...)
		state.Inheritable = append(state.Inheritable, config.Ambient...)
	}

	// Remove duplicates and sort
	state.Effective = cm.uniqueCapabilities(state.Effective)
	state.Permitted = cm.uniqueCapabilities(state.Permitted)
	state.Inheritable = cm.uniqueCapabilities(state.Inheritable)
	state.Ambient = cm.uniqueCapabilities(state.Ambient)

	return state, nil
}

func (cm *CapabilityManager) setupCapabilityAuditing(containerID string, auditConfig *CapabilityAuditConfig) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up capability auditing")
	
	// In a real implementation, this would:
	// 1. Configure audit subsystem
	// 2. Set up capability monitoring
	// 3. Configure audit rules
	
	return nil
}

func (cm *CapabilityManager) auditCapabilityAction(containerID, action, capability, details string) {
	timestamp := int64(0) // In real implementation, use time.Now().Unix()
	
	entry := CapabilityAuditEntry{
		Timestamp:   timestamp,
		ContainerID: containerID,
		Action:      action,
		Details:     details,
		RiskLevel:   "low",
	}
	
	if capability != "" {
		entry.Capability = Capability(capability)
		if info, exists := cm.supportInfo[Capability(capability)]; exists {
			entry.RiskLevel = info.Risk
		}
	}

	cm.mu.Lock()
	cm.auditLog = append(cm.auditLog, entry)
	if len(cm.auditLog) > cm.maxAuditEntries {
		cm.auditLog = cm.auditLog[len(cm.auditLog)-cm.maxAuditEntries:]
	}
	cm.mu.Unlock()
}

func (cm *CapabilityManager) uniqueCapabilities(caps []Capability) []Capability {
	seen := make(map[Capability]bool)
	var result []Capability
	
	for _, cap := range caps {
		if !seen[cap] {
			seen[cap] = true
			result = append(result, cap)
		}
	}
	
	sort.Slice(result, func(i, j int) bool {
		return string(result[i]) < string(result[j])
	})
	
	return result
}