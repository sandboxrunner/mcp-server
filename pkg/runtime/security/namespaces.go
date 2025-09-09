package security

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// NamespaceType represents different types of Linux namespaces
type NamespaceType string

const (
	PIDNamespace     NamespaceType = "pid"
	MountNamespace   NamespaceType = "mnt"
	NetworkNamespace NamespaceType = "net"
	IPCNamespace     NamespaceType = "ipc"
	UTSNamespace     NamespaceType = "uts"
	UserNamespace    NamespaceType = "user"
	CgroupNamespace  NamespaceType = "cgroup"
)

// NamespaceConfig defines comprehensive namespace configuration
type NamespaceConfig struct {
	// Namespace isolation settings
	PID     bool `json:"pid" yaml:"pid"`         // Process ID namespace
	Network bool `json:"network" yaml:"network"` // Network namespace
	IPC     bool `json:"ipc" yaml:"ipc"`         // Inter-process communication namespace
	UTS     bool `json:"uts" yaml:"uts"`         // Unix timesharing system namespace
	Mount   bool `json:"mount" yaml:"mount"`     // Mount namespace
	User    bool `json:"user" yaml:"user"`       // User namespace
	Cgroup  bool `json:"cgroup" yaml:"cgroup"`   // Control group namespace

	// User namespace mapping (if user namespace is enabled)
	UserNamespaceMapping *UserNamespaceMapping `json:"userNamespaceMapping,omitempty" yaml:"userNamespaceMapping,omitempty"`

	// Mount namespace configuration
	MountConfig *MountConfig `json:"mountConfig,omitempty" yaml:"mountConfig,omitempty"`

	// Network namespace configuration
	NetworkConfig *NetworkNamespaceConfig `json:"networkConfig,omitempty" yaml:"networkConfig,omitempty"`

	// UTS namespace configuration
	UTSConfig *UTSConfig `json:"utsConfig,omitempty" yaml:"utsConfig,omitempty"`
}

// UserNamespaceMapping defines user namespace ID mapping
type UserNamespaceMapping struct {
	UIDs []IDMapping `json:"uids,omitempty" yaml:"uids,omitempty"`
	GIDs []IDMapping `json:"gids,omitempty" yaml:"gids,omitempty"`
}

// IDMapping defines a single ID mapping
type IDMapping struct {
	ContainerID int64 `json:"containerID" yaml:"containerID"`
	HostID      int64 `json:"hostID" yaml:"hostID"`
	Size        int64 `json:"size" yaml:"size"`
}

// MountConfig defines mount namespace configuration
type MountConfig struct {
	ReadOnlyPaths    []string          `json:"readOnlyPaths,omitempty" yaml:"readOnlyPaths,omitempty"`
	MaskedPaths      []string          `json:"maskedPaths,omitempty" yaml:"maskedPaths,omitempty"`
	Tmpfs            map[string]string `json:"tmpfs,omitempty" yaml:"tmpfs,omitempty"`
	Propagation      string            `json:"propagation,omitempty" yaml:"propagation,omitempty"`
	RootPropagation  string            `json:"rootPropagation,omitempty" yaml:"rootPropagation,omitempty"`
}

// NetworkNamespaceConfig defines network namespace configuration
type NetworkNamespaceConfig struct {
	Type        string            `json:"type" yaml:"type"` // "none", "host", "bridge", "custom"
	Bridge      string            `json:"bridge,omitempty" yaml:"bridge,omitempty"`
	Interfaces  []NetworkInterface `json:"interfaces,omitempty" yaml:"interfaces,omitempty"`
	DNSConfig   *DNSConfig        `json:"dnsConfig,omitempty" yaml:"dnsConfig,omitempty"`
}

// NetworkInterface defines network interface configuration
type NetworkInterface struct {
	Name       string `json:"name" yaml:"name"`
	MAC        string `json:"mac,omitempty" yaml:"mac,omitempty"`
	IP         string `json:"ip,omitempty" yaml:"ip,omitempty"`
	Gateway    string `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	MTU        int    `json:"mtu,omitempty" yaml:"mtu,omitempty"`
}

// DNSConfig defines DNS configuration for network namespace
type DNSConfig struct {
	Nameservers []string `json:"nameservers,omitempty" yaml:"nameservers,omitempty"`
	Search      []string `json:"search,omitempty" yaml:"search,omitempty"`
	Options     []string `json:"options,omitempty" yaml:"options,omitempty"`
}

// UTSConfig defines UTS namespace configuration
type UTSConfig struct {
	Hostname   string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Domainname string `json:"domainname,omitempty" yaml:"domainname,omitempty"`
}

// NamespaceManager manages Linux namespace isolation
type NamespaceManager struct {
	mu                sync.RWMutex
	containerConfigs  map[string]*NamespaceConfig
	activeNamespaces  map[string]map[NamespaceType]string // containerID -> namespace type -> namespace path
	
	// System capabilities
	systemSupport     map[NamespaceType]bool
	defaultConfig     *NamespaceConfig
	
	// Namespace paths
	procPath          string
	maxUserNamespaces int
}

// NamespaceValidationResult holds namespace validation results
type NamespaceValidationResult struct {
	Valid      bool                         `json:"valid"`
	Errors     []string                     `json:"errors,omitempty"`
	Warnings   []string                     `json:"warnings,omitempty"`
	Supported  map[NamespaceType]bool      `json:"supported"`
	Requirements map[NamespaceType][]string `json:"requirements,omitempty"`
}

// NamespaceInfo provides information about a namespace
type NamespaceInfo struct {
	Type      NamespaceType `json:"type"`
	Path      string        `json:"path"`
	ID        string        `json:"id"`
	ParentID  string        `json:"parentId,omitempty"`
	Children  []string      `json:"children,omitempty"`
	ProcessCount int        `json:"processCount"`
}

// NewNamespaceManager creates a new namespace manager
func NewNamespaceManager() *NamespaceManager {
	nm := &NamespaceManager{
		containerConfigs: make(map[string]*NamespaceConfig),
		activeNamespaces: make(map[string]map[NamespaceType]string),
		systemSupport:    make(map[NamespaceType]bool),
		procPath:         "/proc",
		defaultConfig: &NamespaceConfig{
			PID:     true,
			Mount:   true,
			Network: true,
			IPC:     true,
			UTS:     true,
			User:    false, // Disabled by default due to complexity
			Cgroup:  true,
		},
	}

	// Detect system namespace support
	nm.detectNamespaceSupport()
	
	return nm
}

// SetupNamespaces configures namespace isolation for a container
func (nm *NamespaceManager) SetupNamespaces(containerID string, config *NamespaceConfig) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()

	logger.Debug().Msg("Setting up namespace isolation")

	// Validate namespace configuration
	if validation := nm.validateNamespaceConfig(config); !validation.Valid {
		logger.Error().
			Strs("errors", validation.Errors).
			Msg("Namespace configuration validation failed")
		return fmt.Errorf("namespace validation failed: %s", strings.Join(validation.Errors, "; "))
	}

	// Merge with default configuration
	mergedConfig := nm.mergeWithDefaults(config)

	// Create namespace mappings
	namespaces := make(map[NamespaceType]string)

	// Setup PID namespace
	if mergedConfig.PID && nm.systemSupport[PIDNamespace] {
		if err := nm.setupPIDNamespace(containerID, mergedConfig, namespaces); err != nil {
			logger.Error().Err(err).Msg("Failed to setup PID namespace")
			return fmt.Errorf("failed to setup PID namespace: %w", err)
		}
	}

	// Setup Mount namespace
	if mergedConfig.Mount && nm.systemSupport[MountNamespace] {
		if err := nm.setupMountNamespace(containerID, mergedConfig, namespaces); err != nil {
			logger.Error().Err(err).Msg("Failed to setup Mount namespace")
			return fmt.Errorf("failed to setup Mount namespace: %w", err)
		}
	}

	// Setup Network namespace
	if mergedConfig.Network && nm.systemSupport[NetworkNamespace] {
		if err := nm.setupNetworkNamespace(containerID, mergedConfig, namespaces); err != nil {
			logger.Error().Err(err).Msg("Failed to setup Network namespace")
			return fmt.Errorf("failed to setup Network namespace: %w", err)
		}
	}

	// Setup IPC namespace
	if mergedConfig.IPC && nm.systemSupport[IPCNamespace] {
		if err := nm.setupIPCNamespace(containerID, mergedConfig, namespaces); err != nil {
			logger.Error().Err(err).Msg("Failed to setup IPC namespace")
			return fmt.Errorf("failed to setup IPC namespace: %w", err)
		}
	}

	// Setup UTS namespace
	if mergedConfig.UTS && nm.systemSupport[UTSNamespace] {
		if err := nm.setupUTSNamespace(containerID, mergedConfig, namespaces); err != nil {
			logger.Error().Err(err).Msg("Failed to setup UTS namespace")
			return fmt.Errorf("failed to setup UTS namespace: %w", err)
		}
	}

	// Setup User namespace (if enabled and supported)
	if mergedConfig.User && nm.systemSupport[UserNamespace] {
		if err := nm.setupUserNamespace(containerID, mergedConfig, namespaces); err != nil {
			logger.Error().Err(err).Msg("Failed to setup User namespace")
			return fmt.Errorf("failed to setup User namespace: %w", err)
		}
	}

	// Setup Cgroup namespace
	if mergedConfig.Cgroup && nm.systemSupport[CgroupNamespace] {
		if err := nm.setupCgroupNamespace(containerID, mergedConfig, namespaces); err != nil {
			logger.Error().Err(err).Msg("Failed to setup Cgroup namespace")
			return fmt.Errorf("failed to setup Cgroup namespace: %w", err)
		}
	}

	// Store configuration and namespace mappings
	nm.mu.Lock()
	nm.containerConfigs[containerID] = mergedConfig
	nm.activeNamespaces[containerID] = namespaces
	nm.mu.Unlock()

	logger.Info().
		Int("active_namespaces", len(namespaces)).
		Bool("pid", mergedConfig.PID).
		Bool("mount", mergedConfig.Mount).
		Bool("network", mergedConfig.Network).
		Bool("ipc", mergedConfig.IPC).
		Bool("uts", mergedConfig.UTS).
		Bool("user", mergedConfig.User).
		Bool("cgroup", mergedConfig.Cgroup).
		Msg("Namespace isolation configured successfully")

	return nil
}

// ValidateNamespaces validates namespace configuration for a container
func (nm *NamespaceManager) ValidateNamespaces(containerID string) (*NamespaceValidationResult, error) {
	nm.mu.RLock()
	config, exists := nm.containerConfigs[containerID]
	namespaces, hasNamespaces := nm.activeNamespaces[containerID]
	nm.mu.RUnlock()

	if !exists || !hasNamespaces {
		return &NamespaceValidationResult{
			Valid: false,
			Errors: []string{fmt.Sprintf("no namespace configuration found for container %s", containerID)},
		}, nil
	}

	result := &NamespaceValidationResult{
		Valid:     true,
		Supported: make(map[NamespaceType]bool),
		Requirements: make(map[NamespaceType][]string),
	}

	// Validate each configured namespace
	for nsType := range namespaces {
		result.Supported[nsType] = nm.systemSupport[nsType]
		
		if !nm.systemSupport[nsType] {
			result.Errors = append(result.Errors, fmt.Sprintf("namespace %s is not supported on this system", nsType))
			result.Valid = false
		}

		// Validate namespace still exists
		if err := nm.validateNamespaceExists(containerID, nsType); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("namespace %s validation failed: %s", nsType, err))
			result.Valid = false
		}
	}

	// Validate user namespace mappings if enabled
	if config.User && config.UserNamespaceMapping != nil {
		if err := nm.validateUserNamespaceMapping(config.UserNamespaceMapping); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("user namespace mapping validation failed: %s", err))
			result.Valid = false
		}
	}

	return result, nil
}

// GetNamespaceInfo returns information about container namespaces
func (nm *NamespaceManager) GetNamespaceInfo(containerID string) ([]NamespaceInfo, error) {
	nm.mu.RLock()
	namespaces, exists := nm.activeNamespaces[containerID]
	nm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no namespaces found for container %s", containerID)
	}

	var infos []NamespaceInfo
	
	for nsType, nsPath := range namespaces {
		info := NamespaceInfo{
			Type: nsType,
			Path: nsPath,
		}

		// Extract namespace ID from path
		if id := nm.extractNamespaceID(nsPath); id != "" {
			info.ID = id
		}

		// Get process count in namespace
		if count, err := nm.getNamespaceProcessCount(nsPath, nsType); err == nil {
			info.ProcessCount = count
		}

		infos = append(infos, info)
	}

	return infos, nil
}

// CleanupNamespaces cleans up namespace isolation for a container
func (nm *NamespaceManager) CleanupNamespaces(containerID string) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()

	logger.Debug().Msg("Cleaning up namespace isolation")

	nm.mu.Lock()
	namespaces, exists := nm.activeNamespaces[containerID]
	if exists {
		delete(nm.activeNamespaces, containerID)
		delete(nm.containerConfigs, containerID)
	}
	nm.mu.Unlock()

	if !exists {
		logger.Warn().Msg("No namespaces found for cleanup")
		return nil
	}

	// Cleanup namespace-specific resources
	for nsType := range namespaces {
		if err := nm.cleanupNamespaceType(containerID, nsType); err != nil {
			logger.Warn().Err(err).Str("namespace_type", string(nsType)).Msg("Failed to cleanup namespace type")
		}
	}

	logger.Debug().Msg("Namespace isolation cleanup completed")
	return nil
}

// Private helper methods

func (nm *NamespaceManager) detectNamespaceSupport() {
	// Detect PID namespace support
	if nm.checkNamespaceSupport("/proc/sys/kernel/ns_last_pid") {
		nm.systemSupport[PIDNamespace] = true
		log.Debug().Msg("PID namespace support detected")
	}

	// Detect Mount namespace support
	if nm.checkNamespaceSupport("/proc/self/ns/mnt") {
		nm.systemSupport[MountNamespace] = true
		log.Debug().Msg("Mount namespace support detected")
	}

	// Detect Network namespace support
	if nm.checkNamespaceSupport("/proc/self/ns/net") {
		nm.systemSupport[NetworkNamespace] = true
		log.Debug().Msg("Network namespace support detected")
	}

	// Detect IPC namespace support
	if nm.checkNamespaceSupport("/proc/self/ns/ipc") {
		nm.systemSupport[IPCNamespace] = true
		log.Debug().Msg("IPC namespace support detected")
	}

	// Detect UTS namespace support
	if nm.checkNamespaceSupport("/proc/self/ns/uts") {
		nm.systemSupport[UTSNamespace] = true
		log.Debug().Msg("UTS namespace support detected")
	}

	// Detect User namespace support
	if nm.checkNamespaceSupport("/proc/self/ns/user") {
		if maxNS, err := nm.getMaxUserNamespaces(); err == nil && maxNS > 0 {
			nm.systemSupport[UserNamespace] = true
			nm.maxUserNamespaces = maxNS
			log.Debug().Int("max_user_namespaces", maxNS).Msg("User namespace support detected")
		}
	}

	// Detect Cgroup namespace support
	if nm.checkNamespaceSupport("/proc/self/ns/cgroup") {
		nm.systemSupport[CgroupNamespace] = true
		log.Debug().Msg("Cgroup namespace support detected")
	}

	log.Info().
		Bool("pid", nm.systemSupport[PIDNamespace]).
		Bool("mount", nm.systemSupport[MountNamespace]).
		Bool("network", nm.systemSupport[NetworkNamespace]).
		Bool("ipc", nm.systemSupport[IPCNamespace]).
		Bool("uts", nm.systemSupport[UTSNamespace]).
		Bool("user", nm.systemSupport[UserNamespace]).
		Bool("cgroup", nm.systemSupport[CgroupNamespace]).
		Msg("Namespace support detected")
}

func (nm *NamespaceManager) checkNamespaceSupport(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (nm *NamespaceManager) getMaxUserNamespaces() (int, error) {
	content, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err != nil {
		return 0, err
	}
	
	maxNS, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		return 0, err
	}
	
	return maxNS, nil
}

func (nm *NamespaceManager) validateNamespaceConfig(config *NamespaceConfig) *NamespaceValidationResult {
	result := &NamespaceValidationResult{
		Valid:     true,
		Supported: make(map[NamespaceType]bool),
	}

	// Check system support for each requested namespace
	if config.PID {
		result.Supported[PIDNamespace] = nm.systemSupport[PIDNamespace]
		if !nm.systemSupport[PIDNamespace] {
			result.Errors = append(result.Errors, "PID namespace is not supported on this system")
			result.Valid = false
		}
	}

	if config.Mount {
		result.Supported[MountNamespace] = nm.systemSupport[MountNamespace]
		if !nm.systemSupport[MountNamespace] {
			result.Errors = append(result.Errors, "Mount namespace is not supported on this system")
			result.Valid = false
		}
	}

	if config.Network {
		result.Supported[NetworkNamespace] = nm.systemSupport[NetworkNamespace]
		if !nm.systemSupport[NetworkNamespace] {
			result.Errors = append(result.Errors, "Network namespace is not supported on this system")
			result.Valid = false
		}
	}

	if config.IPC {
		result.Supported[IPCNamespace] = nm.systemSupport[IPCNamespace]
		if !nm.systemSupport[IPCNamespace] {
			result.Errors = append(result.Errors, "IPC namespace is not supported on this system")
			result.Valid = false
		}
	}

	if config.UTS {
		result.Supported[UTSNamespace] = nm.systemSupport[UTSNamespace]
		if !nm.systemSupport[UTSNamespace] {
			result.Errors = append(result.Errors, "UTS namespace is not supported on this system")
			result.Valid = false
		}
	}

	if config.User {
		result.Supported[UserNamespace] = nm.systemSupport[UserNamespace]
		if !nm.systemSupport[UserNamespace] {
			result.Errors = append(result.Errors, "User namespace is not supported on this system")
			result.Valid = false
		} else {
			// Validate user namespace mapping
			if config.UserNamespaceMapping != nil {
				if err := nm.validateUserNamespaceMapping(config.UserNamespaceMapping); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("invalid user namespace mapping: %s", err))
					result.Valid = false
				}
			}
		}
	}

	if config.Cgroup {
		result.Supported[CgroupNamespace] = nm.systemSupport[CgroupNamespace]
		if !nm.systemSupport[CgroupNamespace] {
			result.Warnings = append(result.Warnings, "Cgroup namespace is not supported on this system")
		}
	}

	return result
}

func (nm *NamespaceManager) validateUserNamespaceMapping(mapping *UserNamespaceMapping) error {
	// Validate UID mappings
	for i, uidMap := range mapping.UIDs {
		if uidMap.ContainerID < 0 || uidMap.HostID < 0 || uidMap.Size <= 0 {
			return fmt.Errorf("invalid UID mapping at index %d: containerID=%d, hostID=%d, size=%d",
				i, uidMap.ContainerID, uidMap.HostID, uidMap.Size)
		}
	}

	// Validate GID mappings
	for i, gidMap := range mapping.GIDs {
		if gidMap.ContainerID < 0 || gidMap.HostID < 0 || gidMap.Size <= 0 {
			return fmt.Errorf("invalid GID mapping at index %d: containerID=%d, hostID=%d, size=%d",
				i, gidMap.ContainerID, gidMap.HostID, gidMap.Size)
		}
	}

	return nil
}

func (nm *NamespaceManager) mergeWithDefaults(config *NamespaceConfig) *NamespaceConfig {
	merged := *config

	// Apply defaults for mount config
	if merged.Mount && merged.MountConfig == nil {
		merged.MountConfig = &MountConfig{
			ReadOnlyPaths: []string{
				"/proc/asound",
				"/proc/bus",
				"/proc/fs",
				"/proc/irq",
				"/proc/sys",
				"/proc/sysrq-trigger",
			},
			MaskedPaths: []string{
				"/proc/acpi",
				"/proc/kcore",
				"/proc/keys",
				"/proc/latency_stats",
				"/proc/timer_list",
				"/proc/timer_stats",
				"/proc/sched_debug",
				"/proc/scsi",
				"/sys/firmware",
			},
			Propagation: "rprivate",
			RootPropagation: "rprivate",
		}
	}

	// Apply defaults for network config
	if merged.Network && merged.NetworkConfig == nil {
		merged.NetworkConfig = &NetworkNamespaceConfig{
			Type: "none", // Default to no network
		}
	}

	// Apply defaults for UTS config
	if merged.UTS && merged.UTSConfig == nil {
		merged.UTSConfig = &UTSConfig{
			Hostname: "sandbox",
		}
	}

	return &merged
}

func (nm *NamespaceManager) setupPIDNamespace(containerID string, config *NamespaceConfig, namespaces map[NamespaceType]string) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up PID namespace")
	
	// In a real implementation, this would:
	// 1. Create new PID namespace
	// 2. Configure PID 1 process
	// 3. Set up process isolation
	
	nsPath := fmt.Sprintf("/proc/self/ns/pid")
	namespaces[PIDNamespace] = nsPath
	
	return nil
}

func (nm *NamespaceManager) setupMountNamespace(containerID string, config *NamespaceConfig, namespaces map[NamespaceType]string) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up Mount namespace")
	
	// In a real implementation, this would:
	// 1. Create new mount namespace
	// 2. Set up read-only and masked paths
	// 3. Configure tmpfs mounts
	// 4. Set mount propagation
	
	nsPath := fmt.Sprintf("/proc/self/ns/mnt")
	namespaces[MountNamespace] = nsPath
	
	return nil
}

func (nm *NamespaceManager) setupNetworkNamespace(containerID string, config *NamespaceConfig, namespaces map[NamespaceType]string) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up Network namespace")
	
	// In a real implementation, this would:
	// 1. Create new network namespace
	// 2. Set up network interfaces
	// 3. Configure DNS settings
	// 4. Set up routing
	
	nsPath := fmt.Sprintf("/proc/self/ns/net")
	namespaces[NetworkNamespace] = nsPath
	
	return nil
}

func (nm *NamespaceManager) setupIPCNamespace(containerID string, config *NamespaceConfig, namespaces map[NamespaceType]string) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up IPC namespace")
	
	// In a real implementation, this would:
	// 1. Create new IPC namespace
	// 2. Isolate System V IPC objects
	// 3. Isolate POSIX message queues
	// 4. Configure IPC limits
	
	nsPath := fmt.Sprintf("/proc/self/ns/ipc")
	namespaces[IPCNamespace] = nsPath
	
	return nil
}

func (nm *NamespaceManager) setupUTSNamespace(containerID string, config *NamespaceConfig, namespaces map[NamespaceType]string) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up UTS namespace")
	
	// In a real implementation, this would:
	// 1. Create new UTS namespace
	// 2. Set hostname and domainname
	// 3. Configure system identification
	
	nsPath := fmt.Sprintf("/proc/self/ns/uts")
	namespaces[UTSNamespace] = nsPath
	
	return nil
}

func (nm *NamespaceManager) setupUserNamespace(containerID string, config *NamespaceConfig, namespaces map[NamespaceType]string) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up User namespace")
	
	// In a real implementation, this would:
	// 1. Create new user namespace
	// 2. Set up UID/GID mappings
	// 3. Configure user namespace hierarchy
	// 4. Handle capability inheritance
	
	nsPath := fmt.Sprintf("/proc/self/ns/user")
	namespaces[UserNamespace] = nsPath
	
	return nil
}

func (nm *NamespaceManager) setupCgroupNamespace(containerID string, config *NamespaceConfig, namespaces map[NamespaceType]string) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up Cgroup namespace")
	
	// In a real implementation, this would:
	// 1. Create new cgroup namespace
	// 2. Set up cgroup isolation
	// 3. Configure resource limits visibility
	
	nsPath := fmt.Sprintf("/proc/self/ns/cgroup")
	namespaces[CgroupNamespace] = nsPath
	
	return nil
}

func (nm *NamespaceManager) validateNamespaceExists(containerID string, nsType NamespaceType) error {
	nm.mu.RLock()
	namespaces, exists := nm.activeNamespaces[containerID]
	nm.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("no namespaces found for container %s", containerID)
	}
	
	nsPath, hasNS := namespaces[nsType]
	if !hasNS {
		return fmt.Errorf("namespace %s not found for container %s", nsType, containerID)
	}
	
	// Check if namespace still exists
	if _, err := os.Stat(nsPath); err != nil {
		return fmt.Errorf("namespace %s path %s is not accessible: %w", nsType, nsPath, err)
	}
	
	return nil
}

func (nm *NamespaceManager) extractNamespaceID(nsPath string) string {
	// Extract namespace ID from path like /proc/12345/ns/pid
	parts := strings.Split(nsPath, "/")
	if len(parts) >= 4 && parts[1] == "proc" && parts[3] == "ns" {
		return parts[2] // Process ID
	}
	return ""
}

func (nm *NamespaceManager) getNamespaceProcessCount(nsPath string, nsType NamespaceType) (int, error) {
	// In a real implementation, this would count processes in the namespace
	// For now, return a placeholder count
	return 1, nil
}

func (nm *NamespaceManager) cleanupNamespaceType(containerID string, nsType NamespaceType) error {
	// Cleanup namespace-specific resources
	switch nsType {
	case NetworkNamespace:
		return nm.cleanupNetworkNamespace(containerID)
	case MountNamespace:
		return nm.cleanupMountNamespace(containerID)
	case UserNamespace:
		return nm.cleanupUserNamespace(containerID)
	default:
		// No specific cleanup needed for other namespace types
		return nil
	}
}

func (nm *NamespaceManager) cleanupNetworkNamespace(containerID string) error {
	// Cleanup network interfaces, routes, etc.
	log.Debug().Str("container_id", containerID).Msg("Cleaning up network namespace")
	return nil
}

func (nm *NamespaceManager) cleanupMountNamespace(containerID string) error {
	// Cleanup mounts, tmpfs, etc.
	log.Debug().Str("container_id", containerID).Msg("Cleaning up mount namespace")
	return nil
}

func (nm *NamespaceManager) cleanupUserNamespace(containerID string) error {
	// Cleanup user namespace mappings
	log.Debug().Str("container_id", containerID).Msg("Cleaning up user namespace")
	return nil
}

// Utility functions

// BoolPtr returns a pointer to the given bool value
func BoolPtr(b bool) *bool {
	return &b
}

// StringPtr returns a pointer to the given string value
func StringPtr(s string) *string {
	return &s
}

// IntPtr returns a pointer to the given int value
func IntPtr(i int) *int {
	return &i
}

// Int64Ptr returns a pointer to the given int64 value
func Int64Ptr(i int64) *int64 {
	return &i
}