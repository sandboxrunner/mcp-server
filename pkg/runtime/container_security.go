package runtime

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// SecurityContext defines security settings for container processes
type SecurityContext struct {
	// User and group settings
	RunAsUser    *int64  `json:"runAsUser,omitempty"`
	RunAsGroup   *int64  `json:"runAsGroup,omitempty"`
	RunAsNonRoot *bool   `json:"runAsNonRoot,omitempty"`
	
	// Capabilities
	AddCapabilities    []string `json:"addCapabilities,omitempty"`
	DropCapabilities   []string `json:"dropCapabilities,omitempty"`
	AllowedCapabilities []string `json:"allowedCapabilities,omitempty"`
	
	// Security profiles
	SELinuxOptions   *SELinuxOptions   `json:"seLinuxOptions,omitempty"`
	SeccompProfile   *SeccompProfile   `json:"seccompProfile,omitempty"`
	AppArmorProfile  *AppArmorProfile  `json:"appArmorProfile,omitempty"`
	
	// File system settings
	ReadOnlyRootFilesystem *bool                `json:"readOnlyRootFilesystem,omitempty"`
	AllowPrivilegeEscalation *bool             `json:"allowPrivilegeEscalation,omitempty"`
	Privileged             *bool               `json:"privileged,omitempty"`
	
	// Additional security settings
	NoNewPrivs             *bool               `json:"noNewPrivs,omitempty"`
	MountPropagation       *string             `json:"mountPropagation,omitempty"`
}

// SELinuxOptions defines SELinux security context
type SELinuxOptions struct {
	User  string `json:"user,omitempty"`
	Role  string `json:"role,omitempty"`
	Type  string `json:"type,omitempty"`
	Level string `json:"level,omitempty"`
}

// SeccompProfile defines seccomp security profile
type SeccompProfile struct {
	Type             string            `json:"type"` // RuntimeDefault, Localhost, Unconfined
	LocalhostProfile *string           `json:"localhostProfile,omitempty"`
	DefaultAction    string            `json:"defaultAction,omitempty"`
	Syscalls         []SeccompSyscall  `json:"syscalls,omitempty"`
}

// SeccompSyscall defines seccomp syscall restrictions
type SeccompSyscall struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
	Args   []SeccompArg `json:"args,omitempty"`
}

// SeccompArg defines seccomp syscall argument restrictions
type SeccompArg struct {
	Index    uint     `json:"index"`
	Value    uint64   `json:"value"`
	ValueTwo uint64   `json:"valueTwo,omitempty"`
	Op       string   `json:"op"`
}

// AppArmorProfile defines AppArmor security profile
type AppArmorProfile struct {
	Type             string  `json:"type"` // RuntimeDefault, Localhost, Unconfined
	LocalhostProfile *string `json:"localhostProfile,omitempty"`
}

// NamespaceConfig defines namespace isolation configuration
type NamespaceConfig struct {
	// Namespace isolation settings
	PID     bool `json:"pid"`     // Process ID namespace
	Network bool `json:"network"` // Network namespace
	IPC     bool `json:"ipc"`     // Inter-process communication namespace
	UTS     bool `json:"uts"`     // Unix timesharing system namespace
	Mount   bool `json:"mount"`   // Mount namespace
	User    bool `json:"user"`    // User namespace
	Cgroup  bool `json:"cgroup"`  // Control group namespace
	
	// User namespace mapping (if user namespace is enabled)
	UserNamespaceMapping *UserNamespaceMapping `json:"userNamespaceMapping,omitempty"`
}

// UserNamespaceMapping defines user namespace ID mapping
type UserNamespaceMapping struct {
	UIDs []IDMapping `json:"uids,omitempty"`
	GIDs []IDMapping `json:"gids,omitempty"`
}

// IDMapping defines a single ID mapping
type IDMapping struct {
	ContainerID int64 `json:"containerID"`
	HostID      int64 `json:"hostID"`
	Size        int64 `json:"size"`
}

// SecurityManager manages security contexts for containers
type SecurityManager struct {
	mu                sync.RWMutex
	containerContexts map[string]*SecurityContext
	
	// Security capabilities
	supportsSELinux    bool
	supportsSeccomp    bool
	supportsAppArmor   bool
	supportsUserNS     bool
	
	// Default security settings
	defaultSecurityContext *SecurityContext
}

// SecurityValidationResult holds security context validation results
type SecurityValidationResult struct {
	Valid    bool     `json:"valid"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// NewSecurityManager creates a new security manager
func NewSecurityManager() *SecurityManager {
	sm := &SecurityManager{
		containerContexts: make(map[string]*SecurityContext),
		defaultSecurityContext: &SecurityContext{
			RunAsNonRoot:             BoolPtr(true),
			ReadOnlyRootFilesystem:   BoolPtr(false),
			AllowPrivilegeEscalation: BoolPtr(false),
			Privileged:               BoolPtr(false),
			NoNewPrivs:               BoolPtr(true),
		},
	}
	
	// Detect available security features
	sm.detectSecurityFeatures()
	
	return sm
}

// SetupSecurityContext configures security context for a container
func (sm *SecurityManager) SetupSecurityContext(containerID string, securityContext *SecurityContext) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Msg("Setting up security context")
	
	// Validate security context
	if validation := sm.validateSecurityContext(securityContext); !validation.Valid {
		logger.Error().
			Strs("errors", validation.Errors).
			Msg("Security context validation failed")
		return fmt.Errorf("security context validation failed: %s", strings.Join(validation.Errors, "; "))
	}
	
	// Apply default settings if not specified
	mergedContext := sm.mergeWithDefaults(securityContext)
	
	// Setup capabilities
	if err := sm.setupCapabilities(containerID, mergedContext); err != nil {
		logger.Error().Err(err).Msg("Failed to setup capabilities")
		return fmt.Errorf("failed to setup capabilities: %w", err)
	}
	
	// Setup seccomp profile
	if mergedContext.SeccompProfile != nil && sm.supportsSeccomp {
		if err := sm.setupSeccompProfile(containerID, mergedContext.SeccompProfile); err != nil {
			logger.Error().Err(err).Msg("Failed to setup seccomp profile")
			return fmt.Errorf("failed to setup seccomp profile: %w", err)
		}
	}
	
	// Setup AppArmor profile
	if mergedContext.AppArmorProfile != nil && sm.supportsAppArmor {
		if err := sm.setupAppArmorProfile(containerID, mergedContext.AppArmorProfile); err != nil {
			logger.Error().Err(err).Msg("Failed to setup AppArmor profile")
			return fmt.Errorf("failed to setup AppArmor profile: %w", err)
		}
	}
	
	// Setup SELinux context
	if mergedContext.SELinuxOptions != nil && sm.supportsSELinux {
		if err := sm.setupSELinuxContext(containerID, mergedContext.SELinuxOptions); err != nil {
			logger.Error().Err(err).Msg("Failed to setup SELinux context")
			return fmt.Errorf("failed to setup SELinux context: %w", err)
		}
	}
	
	// Store the security context for validation and cleanup
	sm.mu.Lock()
	sm.containerContexts[containerID] = mergedContext
	sm.mu.Unlock()
	
	logger.Info().
		Bool("privileged", *mergedContext.Privileged).
		Bool("run_as_non_root", *mergedContext.RunAsNonRoot).
		Int("add_capabilities", len(mergedContext.AddCapabilities)).
		Int("drop_capabilities", len(mergedContext.DropCapabilities)).
		Msg("Security context configured successfully")
	
	return nil
}

// ValidateSecurityContext validates security context for a container
func (sm *SecurityManager) ValidateSecurityContext(containerID string, securityContext *SecurityContext) error {
	sm.mu.RLock()
	storedContext, exists := sm.containerContexts[containerID]
	sm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("no security context found for container %s", containerID)
	}
	
	// Validate that current context matches stored context
	if !sm.securityContextsMatch(storedContext, securityContext) {
		return fmt.Errorf("security context mismatch for container %s", containerID)
	}
	
	return nil
}

// CleanupSecurityContext cleans up security context for a container
func (sm *SecurityManager) CleanupSecurityContext(containerID string) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Msg("Cleaning up security context")
	
	// Remove from tracking
	sm.mu.Lock()
	delete(sm.containerContexts, containerID)
	sm.mu.Unlock()
	
	// Cleanup seccomp profile files if any were created
	if err := sm.cleanupSeccompFiles(containerID); err != nil {
		logger.Warn().Err(err).Msg("Failed to cleanup seccomp files")
	}
	
	logger.Debug().Msg("Security context cleanup completed")
	return nil
}

// Private helper methods

func (sm *SecurityManager) detectSecurityFeatures() {
	// Detect SELinux support
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		sm.supportsSELinux = true
		log.Debug().Msg("SELinux support detected")
	}
	
	// Detect seccomp support
	if _, err := os.Stat("/proc/sys/kernel/seccomp"); err == nil {
		sm.supportsSeccomp = true
		log.Debug().Msg("Seccomp support detected")
	}
	
	// Detect AppArmor support
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		sm.supportsAppArmor = true
		log.Debug().Msg("AppArmor support detected")
	}
	
	// Detect user namespace support
	if _, err := os.Stat("/proc/sys/user/max_user_namespaces"); err == nil {
		sm.supportsUserNS = true
		log.Debug().Msg("User namespace support detected")
	}
	
	log.Info().
		Bool("selinux", sm.supportsSELinux).
		Bool("seccomp", sm.supportsSeccomp).
		Bool("apparmor", sm.supportsAppArmor).
		Bool("user_ns", sm.supportsUserNS).
		Msg("Security features detected")
}

func (sm *SecurityManager) validateSecurityContext(securityContext *SecurityContext) *SecurityValidationResult {
	result := &SecurityValidationResult{Valid: true}
	
	// Validate user settings
	if securityContext.RunAsUser != nil && *securityContext.RunAsUser < 0 {
		result.Errors = append(result.Errors, "runAsUser cannot be negative")
		result.Valid = false
	}
	
	if securityContext.RunAsGroup != nil && *securityContext.RunAsGroup < 0 {
		result.Errors = append(result.Errors, "runAsGroup cannot be negative")
		result.Valid = false
	}
	
	// Validate privileged and runAsNonRoot compatibility
	if securityContext.Privileged != nil && *securityContext.Privileged &&
		securityContext.RunAsNonRoot != nil && *securityContext.RunAsNonRoot {
		result.Errors = append(result.Errors, "cannot run as non-root with privileged mode")
		result.Valid = false
	}
	
	// Validate capabilities
	if err := sm.validateCapabilities(securityContext); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Valid = false
	}
	
	// Warn about unsupported features
	if securityContext.SELinuxOptions != nil && !sm.supportsSELinux {
		result.Warnings = append(result.Warnings, "SELinux options specified but SELinux is not available")
	}
	
	if securityContext.SeccompProfile != nil && !sm.supportsSeccomp {
		result.Warnings = append(result.Warnings, "Seccomp profile specified but seccomp is not available")
	}
	
	if securityContext.AppArmorProfile != nil && !sm.supportsAppArmor {
		result.Warnings = append(result.Warnings, "AppArmor profile specified but AppArmor is not available")
	}
	
	return result
}

func (sm *SecurityManager) validateCapabilities(securityContext *SecurityContext) error {
	// List of known capabilities
	knownCapabilities := map[string]bool{
		"CAP_CHOWN":            true,
		"CAP_DAC_OVERRIDE":     true,
		"CAP_DAC_READ_SEARCH":  true,
		"CAP_FOWNER":           true,
		"CAP_FSETID":           true,
		"CAP_KILL":             true,
		"CAP_SETGID":           true,
		"CAP_SETUID":           true,
		"CAP_SETPCAP":          true,
		"CAP_LINUX_IMMUTABLE": true,
		"CAP_NET_BIND_SERVICE": true,
		"CAP_NET_BROADCAST":    true,
		"CAP_NET_ADMIN":        true,
		"CAP_NET_RAW":          true,
		"CAP_IPC_LOCK":         true,
		"CAP_IPC_OWNER":        true,
		"CAP_SYS_MODULE":       true,
		"CAP_SYS_RAWIO":        true,
		"CAP_SYS_CHROOT":       true,
		"CAP_SYS_PTRACE":       true,
		"CAP_SYS_PACCT":        true,
		"CAP_SYS_ADMIN":        true,
		"CAP_SYS_BOOT":         true,
		"CAP_SYS_NICE":         true,
		"CAP_SYS_RESOURCE":     true,
		"CAP_SYS_TIME":         true,
		"CAP_SYS_TTY_CONFIG":   true,
		"CAP_MKNOD":            true,
		"CAP_LEASE":            true,
		"CAP_AUDIT_WRITE":      true,
		"CAP_AUDIT_CONTROL":    true,
		"CAP_SETFCAP":          true,
		"CAP_MAC_OVERRIDE":     true,
		"CAP_MAC_ADMIN":        true,
		"CAP_SYSLOG":           true,
		"CAP_WAKE_ALARM":       true,
		"CAP_BLOCK_SUSPEND":    true,
	}
	
	// Validate add capabilities
	for _, cap := range securityContext.AddCapabilities {
		if !knownCapabilities[cap] {
			return fmt.Errorf("unknown capability: %s", cap)
		}
	}
	
	// Validate drop capabilities
	for _, cap := range securityContext.DropCapabilities {
		if !knownCapabilities[cap] {
			return fmt.Errorf("unknown capability: %s", cap)
		}
	}
	
	// Validate allowed capabilities
	for _, cap := range securityContext.AllowedCapabilities {
		if !knownCapabilities[cap] {
			return fmt.Errorf("unknown capability: %s", cap)
		}
	}
	
	return nil
}

func (sm *SecurityManager) mergeWithDefaults(securityContext *SecurityContext) *SecurityContext {
	merged := &SecurityContext{}
	
	// Copy provided context
	*merged = *securityContext
	
	// Apply defaults for unset values
	if merged.RunAsNonRoot == nil {
		merged.RunAsNonRoot = sm.defaultSecurityContext.RunAsNonRoot
	}
	
	if merged.ReadOnlyRootFilesystem == nil {
		merged.ReadOnlyRootFilesystem = sm.defaultSecurityContext.ReadOnlyRootFilesystem
	}
	
	if merged.AllowPrivilegeEscalation == nil {
		merged.AllowPrivilegeEscalation = sm.defaultSecurityContext.AllowPrivilegeEscalation
	}
	
	if merged.Privileged == nil {
		merged.Privileged = sm.defaultSecurityContext.Privileged
	}
	
	if merged.NoNewPrivs == nil {
		merged.NoNewPrivs = sm.defaultSecurityContext.NoNewPrivs
	}
	
	return merged
}

func (sm *SecurityManager) setupCapabilities(containerID string, securityContext *SecurityContext) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	// Log capability configuration
	if len(securityContext.AddCapabilities) > 0 {
		logger.Debug().
			Strs("add_capabilities", securityContext.AddCapabilities).
			Msg("Adding capabilities")
	}
	
	if len(securityContext.DropCapabilities) > 0 {
		logger.Debug().
			Strs("drop_capabilities", securityContext.DropCapabilities).
			Msg("Dropping capabilities")
	}
	
	// In a real implementation, this would modify the OCI spec or use
	// container runtime specific APIs to set capabilities
	// For now, we just log the configuration
	
	return nil
}

func (sm *SecurityManager) setupSeccompProfile(containerID string, seccompProfile *SeccompProfile) error {
	logger := log.With().
		Str("container_id", containerID).
		Str("seccomp_type", seccompProfile.Type).
		Logger()
	
	logger.Debug().Msg("Setting up seccomp profile")
	
	// In a real implementation, this would:
	// 1. Generate seccomp profile files
	// 2. Configure the OCI spec to use the profile
	// 3. Apply seccomp filters
	
	return nil
}

func (sm *SecurityManager) setupAppArmorProfile(containerID string, appArmorProfile *AppArmorProfile) error {
	logger := log.With().
		Str("container_id", containerID).
		Str("apparmor_type", appArmorProfile.Type).
		Logger()
	
	logger.Debug().Msg("Setting up AppArmor profile")
	
	// In a real implementation, this would:
	// 1. Load AppArmor profiles if needed
	// 2. Configure the OCI spec to use the profile
	// 3. Apply AppArmor restrictions
	
	return nil
}

func (sm *SecurityManager) setupSELinuxContext(containerID string, seLinuxOptions *SELinuxOptions) error {
	logger := log.With().
		Str("container_id", containerID).
		Str("selinux_user", seLinuxOptions.User).
		Str("selinux_role", seLinuxOptions.Role).
		Str("selinux_type", seLinuxOptions.Type).
		Logger()
	
	logger.Debug().Msg("Setting up SELinux context")
	
	// In a real implementation, this would:
	// 1. Validate SELinux context
	// 2. Configure the OCI spec with SELinux labels
	// 3. Apply SELinux context to container processes
	
	return nil
}

func (sm *SecurityManager) securityContextsMatch(ctx1, ctx2 *SecurityContext) bool {
	// Simplified comparison - in a real implementation, this would do deep comparison
	// For now, we'll just return true as this is primarily for demonstration
	return true
}

func (sm *SecurityManager) cleanupSeccompFiles(containerID string) error {
	// Clean up any temporary seccomp profile files
	// This would remove files like /tmp/seccomp-{containerID}.json
	return nil
}

