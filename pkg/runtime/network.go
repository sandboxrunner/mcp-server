package runtime

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// NetworkMode defines the type of network configuration
type NetworkMode string

const (
	NetworkModeNone   NetworkMode = "none"     // No network access
	NetworkModeBridge NetworkMode = "bridge"   // Bridge network with NAT
	NetworkModeHost   NetworkMode = "host"     // Use host network stack
	NetworkModeCustom NetworkMode = "custom"   // Custom network configuration
)

// NetworkIsolationLevel defines the level of network isolation
type NetworkIsolationLevel string

const (
	IsolationLevelNone     NetworkIsolationLevel = "none"     // No isolation
	IsolationLevelBasic    NetworkIsolationLevel = "basic"    // Basic namespace isolation
	IsolationLevelStrict   NetworkIsolationLevel = "strict"   // Strict isolation with firewall rules
	IsolationLevelComplete NetworkIsolationLevel = "complete" // Complete isolation (no external access)
)

// PortMapping defines port forwarding configuration
type PortMapping struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"` // tcp, udp
	HostIP        string `json:"hostIP,omitempty"`
}

// DNSConfig defines DNS resolution configuration
type DNSConfig struct {
	Nameservers []string          `json:"nameservers"`
	Search      []string          `json:"search"`
	Options     []string          `json:"options"`
	ExtraHosts  map[string]string `json:"extraHosts"` // hostname -> IP
}

// FirewallRule defines a firewall rule
type FirewallRule struct {
	ID          string            `json:"id"`
	Action      FirewallAction    `json:"action"`    // allow, deny, drop
	Direction   TrafficDirection  `json:"direction"` // ingress, egress
	Protocol    string            `json:"protocol"`  // tcp, udp, icmp, all
	SourceIP    string            `json:"sourceIP,omitempty"`
	SourcePorts []int             `json:"sourcePorts,omitempty"`
	DestIP      string            `json:"destIP,omitempty"`
	DestPorts   []int             `json:"destPorts,omitempty"`
	Priority    int               `json:"priority"` // Higher number = higher priority
}

// FirewallAction defines what to do with matching traffic
type FirewallAction string

const (
	FirewallActionAllow FirewallAction = "allow"
	FirewallActionDeny  FirewallAction = "deny"
	FirewallActionDrop  FirewallAction = "drop"
)

// TrafficDirection defines traffic direction
type TrafficDirection string

const (
	TrafficDirectionIngress TrafficDirection = "ingress"
	TrafficDirectionEgress  TrafficDirection = "egress"
)

// BandwidthLimit defines bandwidth limiting configuration
type BandwidthLimit struct {
	Ingress BandwidthRule `json:"ingress"`
	Egress  BandwidthRule `json:"egress"`
}

// BandwidthRule defines a bandwidth limitation rule
type BandwidthRule struct {
	Rate     string `json:"rate"`     // e.g., "1mbps", "100kbps"
	Burst    string `json:"burst"`    // burst allowance
	Priority int    `json:"priority"` // QoS priority (0-7)
}

// NetworkConfig defines complete network configuration for a container
type NetworkConfig struct {
	Mode               NetworkMode           `json:"mode"`
	IsolationLevel     NetworkIsolationLevel `json:"isolationLevel"`
	PortMappings       []PortMapping         `json:"portMappings"`
	DNS                DNSConfig             `json:"dns"`
	FirewallRules      []FirewallRule        `json:"firewallRules"`
	BandwidthLimits    *BandwidthLimit       `json:"bandwidthLimits,omitempty"`
	EnableIPForwarding bool                  `json:"enableIPForwarding"`
	
	// Advanced options
	BridgeName    string            `json:"bridgeName,omitempty"`
	NetworkName   string            `json:"networkName,omitempty"`
	IPAddress     string            `json:"ipAddress,omitempty"`
	Gateway       string            `json:"gateway,omitempty"`
	Subnet        string            `json:"subnet,omitempty"`
	MTU           int               `json:"mtu,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"` // NET_ADMIN, NET_RAW, etc.
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`    // bridge, veth, etc.
	IPAddress  string   `json:"ipAddress"`
	MACAddress string   `json:"macAddress"`
	State      string   `json:"state"`   // up, down
	MTU        int      `json:"mtu"`
	RxBytes    int64    `json:"rxBytes"`
	TxBytes    int64    `json:"txBytes"`
	RxPackets  int64    `json:"rxPackets"`
	TxPackets  int64    `json:"txPackets"`
}

// NetworkManager manages container networking
type NetworkManager struct {
	mu              sync.RWMutex
	containerNets   map[string]*ContainerNetworkState
	bridgeInterfaces map[string]*BridgeInterface
	
	// Network namespace management
	netnsPath string
	
	// System capabilities
	hasNetAdmin bool
	hasNetRaw   bool
}

// ContainerNetworkState tracks network state for a container
type ContainerNetworkState struct {
	ContainerID     string             `json:"containerID"`
	NetworkConfig   *NetworkConfig     `json:"networkConfig"`
	Interfaces      []NetworkInterface `json:"interfaces"`
	NamespaceID     string             `json:"namespaceID"`
	BridgeName      string             `json:"bridgeName,omitempty"`
	VethPairHost    string             `json:"vethPairHost,omitempty"`
	VethPairGuest   string             `json:"vethPairGuest,omitempty"`
	IPAddress       string             `json:"ipAddress"`
	Gateway         string             `json:"gateway"`
	ActiveRules     []FirewallRule     `json:"activeRules"`
	BandwidthActive bool               `json:"bandwidthActive"`
	CreatedAt       time.Time          `json:"createdAt"`
	UpdatedAt       time.Time          `json:"updatedAt"`
}

// BridgeInterface represents a bridge network interface
type BridgeInterface struct {
	Name        string    `json:"name"`
	IPAddress   string    `json:"ipAddress"`
	Subnet      string    `json:"subnet"`
	MTU         int       `json:"mtu"`
	State       string    `json:"state"`
	Containers  []string  `json:"containers"`
	CreatedAt   time.Time `json:"createdAt"`
}

// NetworkManagerConfig defines configuration for the network manager
type NetworkManagerConfig struct {
	NetnsPath      string   `json:"netnsPath"`
	DefaultBridge  string   `json:"defaultBridge"`
	DefaultSubnet  string   `json:"defaultSubnet"`
	EnableFirewall bool     `json:"enableFirewall"`
	EnableQoS      bool     `json:"enableQoS"`
	RequiredCaps   []string `json:"requiredCaps"`
}

// NewNetworkManager creates a new network manager
func NewNetworkManager(config *NetworkManagerConfig) (*NetworkManager, error) {
	if config == nil {
		config = DefaultNetworkManagerConfig()
	}
	
	// Ensure network namespace path exists
	if err := os.MkdirAll(config.NetnsPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create netns path: %w", err)
	}
	
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        config.NetnsPath,
	}
	
	// Check system capabilities
	nm.checkSystemCapabilities()
	
	// Initialize default bridge if specified
	if config.DefaultBridge != "" {
		if err := nm.createDefaultBridge(config.DefaultBridge, config.DefaultSubnet); err != nil {
			log.Warn().Err(err).Str("bridge", config.DefaultBridge).Msg("Failed to create default bridge")
		}
	}
	
	log.Info().
		Str("netns_path", config.NetnsPath).
		Bool("net_admin", nm.hasNetAdmin).
		Bool("net_raw", nm.hasNetRaw).
		Msg("Network manager initialized")
	
	return nm, nil
}

// DefaultNetworkManagerConfig returns default network manager configuration
func DefaultNetworkManagerConfig() *NetworkManagerConfig {
	return &NetworkManagerConfig{
		NetnsPath:      "/var/run/netns",
		DefaultBridge:  "sandbox-br0",
		DefaultSubnet:  "172.20.0.0/16",
		EnableFirewall: true,
		EnableQoS:      true,
		RequiredCaps:   []string{"NET_ADMIN", "NET_RAW"},
	}
}

// SetupContainerNetwork sets up networking for a container
func (nm *NetworkManager) SetupContainerNetwork(ctx context.Context, containerID string, config *NetworkConfig) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	if config == nil {
		config = DefaultNetworkConfig()
	}
	
	log.Info().
		Str("container_id", containerID).
		Str("network_mode", string(config.Mode)).
		Str("isolation_level", string(config.IsolationLevel)).
		Msg("Setting up container network")
	
	// Validate configuration
	if err := nm.validateNetworkConfig(config); err != nil {
		return fmt.Errorf("invalid network configuration: %w", err)
	}
	
	// Create container network state
	netState := &ContainerNetworkState{
		ContainerID:   containerID,
		NetworkConfig: config,
		Interfaces:    make([]NetworkInterface, 0),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	
	// Setup based on network mode
	switch config.Mode {
	case NetworkModeNone:
		err := nm.setupNetworkNone(ctx, netState)
		if err != nil {
			return fmt.Errorf("failed to setup none network: %w", err)
		}
	case NetworkModeBridge:
		err := nm.setupNetworkBridge(ctx, netState)
		if err != nil {
			return fmt.Errorf("failed to setup bridge network: %w", err)
		}
	case NetworkModeHost:
		err := nm.setupNetworkHost(ctx, netState)
		if err != nil {
			return fmt.Errorf("failed to setup host network: %w", err)
		}
	case NetworkModeCustom:
		err := nm.setupNetworkCustom(ctx, netState)
		if err != nil {
			return fmt.Errorf("failed to setup custom network: %w", err)
		}
	default:
		return fmt.Errorf("unsupported network mode: %s", config.Mode)
	}
	
	// Apply firewall rules
	if len(config.FirewallRules) > 0 {
		if err := nm.applyFirewallRules(ctx, netState); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to apply firewall rules")
		}
	}
	
	// Apply bandwidth limits
	if config.BandwidthLimits != nil {
		if err := nm.applyBandwidthLimits(ctx, netState); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to apply bandwidth limits")
		}
	}
	
	// Configure DNS
	if err := nm.configureDNS(ctx, netState); err != nil {
		log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to configure DNS")
	}
	
	// Setup port mappings
	if err := nm.setupPortMappings(ctx, netState); err != nil {
		log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to setup port mappings")
	}
	
	// Store network state
	nm.containerNets[containerID] = netState
	
	log.Info().
		Str("container_id", containerID).
		Str("ip_address", netState.IPAddress).
		Str("gateway", netState.Gateway).
		Int("interfaces", len(netState.Interfaces)).
		Msg("Container network setup completed")
	
	return nil
}

// CleanupContainerNetwork cleans up networking for a container
func (nm *NetworkManager) CleanupContainerNetwork(ctx context.Context, containerID string) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	netState, exists := nm.containerNets[containerID]
	if !exists {
		log.Debug().Str("container_id", containerID).Msg("No network state found for cleanup")
		return nil
	}
	
	log.Info().Str("container_id", containerID).Msg("Cleaning up container network")
	
	// Remove port mappings
	if err := nm.cleanupPortMappings(ctx, netState); err != nil {
		log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to cleanup port mappings")
	}
	
	// Remove bandwidth limits
	if netState.BandwidthActive {
		if err := nm.removeBandwidthLimits(ctx, netState); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to remove bandwidth limits")
		}
	}
	
	// Remove firewall rules
	if len(netState.ActiveRules) > 0 {
		if err := nm.removeFirewallRules(ctx, netState); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to remove firewall rules")
		}
	}
	
	// Cleanup network interfaces based on mode
	switch netState.NetworkConfig.Mode {
	case NetworkModeBridge:
		err := nm.cleanupNetworkBridge(ctx, netState)
		if err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to cleanup bridge network")
		}
	case NetworkModeCustom:
		err := nm.cleanupNetworkCustom(ctx, netState)
		if err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to cleanup custom network")
		}
	}
	
	// Remove network namespace
	if netState.NamespaceID != "" {
		if err := nm.removeNetworkNamespace(ctx, netState.NamespaceID); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Str("namespace_id", netState.NamespaceID).Msg("Failed to remove network namespace")
		}
	}
	
	// Remove from tracking
	delete(nm.containerNets, containerID)
	
	log.Info().Str("container_id", containerID).Msg("Container network cleanup completed")
	return nil
}

// GetContainerNetworkState returns the network state for a container
func (nm *NetworkManager) GetContainerNetworkState(containerID string) (*ContainerNetworkState, error) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	state, exists := nm.containerNets[containerID]
	if !exists {
		return nil, fmt.Errorf("no network state found for container %s", containerID)
	}
	
	// Return a copy
	stateCopy := *state
	stateCopy.Interfaces = make([]NetworkInterface, len(state.Interfaces))
	copy(stateCopy.Interfaces, state.Interfaces)
	stateCopy.ActiveRules = make([]FirewallRule, len(state.ActiveRules))
	copy(stateCopy.ActiveRules, state.ActiveRules)
	
	return &stateCopy, nil
}

// ListContainerNetworks returns all container network states
func (nm *NetworkManager) ListContainerNetworks() map[string]*ContainerNetworkState {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	result := make(map[string]*ContainerNetworkState)
	for containerID, state := range nm.containerNets {
		// Return a copy
		stateCopy := *state
		stateCopy.Interfaces = make([]NetworkInterface, len(state.Interfaces))
		copy(stateCopy.Interfaces, state.Interfaces)
		stateCopy.ActiveRules = make([]FirewallRule, len(state.ActiveRules))
		copy(stateCopy.ActiveRules, state.ActiveRules)
		result[containerID] = &stateCopy
	}
	
	return result
}

// UpdateFirewallRules updates firewall rules for a container
func (nm *NetworkManager) UpdateFirewallRules(ctx context.Context, containerID string, rules []FirewallRule) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	netState, exists := nm.containerNets[containerID]
	if !exists {
		return fmt.Errorf("no network state found for container %s", containerID)
	}
	
	// Remove existing rules
	if err := nm.removeFirewallRules(ctx, netState); err != nil {
		return fmt.Errorf("failed to remove existing firewall rules: %w", err)
	}
	
	// Update configuration
	netState.NetworkConfig.FirewallRules = rules
	
	// Apply new rules
	if err := nm.applyFirewallRules(ctx, netState); err != nil {
		return fmt.Errorf("failed to apply new firewall rules: %w", err)
	}
	
	netState.UpdatedAt = time.Now()
	
	log.Info().
		Str("container_id", containerID).
		Int("rules", len(rules)).
		Msg("Firewall rules updated")
	
	return nil
}

// UpdateBandwidthLimits updates bandwidth limits for a container
func (nm *NetworkManager) UpdateBandwidthLimits(ctx context.Context, containerID string, limits *BandwidthLimit) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	netState, exists := nm.containerNets[containerID]
	if !exists {
		return fmt.Errorf("no network state found for container %s", containerID)
	}
	
	// Remove existing limits
	if netState.BandwidthActive {
		if err := nm.removeBandwidthLimits(ctx, netState); err != nil {
			return fmt.Errorf("failed to remove existing bandwidth limits: %w", err)
		}
	}
	
	// Update configuration
	netState.NetworkConfig.BandwidthLimits = limits
	
	// Apply new limits if provided
	if limits != nil {
		if err := nm.applyBandwidthLimits(ctx, netState); err != nil {
			return fmt.Errorf("failed to apply new bandwidth limits: %w", err)
		}
	}
	
	netState.UpdatedAt = time.Now()
	
	log.Info().
		Str("container_id", containerID).
		Bool("limits_active", limits != nil).
		Msg("Bandwidth limits updated")
	
	return nil
}

// GetNetworkStatistics returns network statistics for a container
func (nm *NetworkManager) GetNetworkStatistics(containerID string) (map[string]interface{}, error) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	netState, exists := nm.containerNets[containerID]
	if !exists {
		return nil, fmt.Errorf("no network state found for container %s", containerID)
	}
	
	stats := make(map[string]interface{})
	stats["container_id"] = containerID
	stats["network_mode"] = string(netState.NetworkConfig.Mode)
	stats["isolation_level"] = string(netState.NetworkConfig.IsolationLevel)
	stats["ip_address"] = netState.IPAddress
	stats["gateway"] = netState.Gateway
	stats["interfaces"] = len(netState.Interfaces)
	stats["active_rules"] = len(netState.ActiveRules)
	stats["bandwidth_active"] = netState.BandwidthActive
	stats["created_at"] = netState.CreatedAt
	stats["updated_at"] = netState.UpdatedAt
	
	// Get interface statistics
	interfaceStats := make([]map[string]interface{}, 0, len(netState.Interfaces))
	for _, iface := range netState.Interfaces {
		ifaceStats := map[string]interface{}{
			"name":       iface.Name,
			"type":       iface.Type,
			"ip_address": iface.IPAddress,
			"state":      iface.State,
			"mtu":        iface.MTU,
			"rx_bytes":   iface.RxBytes,
			"tx_bytes":   iface.TxBytes,
			"rx_packets": iface.RxPackets,
			"tx_packets": iface.TxPackets,
		}
		interfaceStats = append(interfaceStats, ifaceStats)
	}
	stats["interface_stats"] = interfaceStats
	
	return stats, nil
}

// Private methods for network setup

// setupNetworkNone configures no network access
func (nm *NetworkManager) setupNetworkNone(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Setting up none network mode")
	
	// Create network namespace
	namespaceID := fmt.Sprintf("sandbox-%s", netState.ContainerID)
	if err := nm.createNetworkNamespace(ctx, namespaceID); err != nil {
		return fmt.Errorf("failed to create network namespace: %w", err)
	}
	
	netState.NamespaceID = namespaceID
	
	// Add loopback interface
	loInterface := NetworkInterface{
		Name:      "lo",
		Type:      "loopback",
		IPAddress: "127.0.0.1",
		State:     "up",
		MTU:       65536,
	}
	netState.Interfaces = append(netState.Interfaces, loInterface)
	
	return nil
}

// setupNetworkHost configures host network mode
func (nm *NetworkManager) setupNetworkHost(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Setting up host network mode")
	
	// Host mode uses the host network stack directly
	// No network namespace isolation
	
	// Get host interfaces (simplified)
	interfaces, err := nm.getHostNetworkInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get host interfaces: %w", err)
	}
	
	netState.Interfaces = interfaces
	
	// Use host gateway
	gateway, err := nm.getDefaultGateway()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get default gateway")
	} else {
		netState.Gateway = gateway
	}
	
	return nil
}

// setupNetworkBridge configures bridge network mode
func (nm *NetworkManager) setupNetworkBridge(ctx context.Context, netState *ContainerNetworkState) error {
	config := netState.NetworkConfig
	
	log.Debug().Str("container_id", netState.ContainerID).Msg("Setting up bridge network mode")
	
	// Create network namespace
	namespaceID := fmt.Sprintf("sandbox-%s", netState.ContainerID)
	if err := nm.createNetworkNamespace(ctx, namespaceID); err != nil {
		return fmt.Errorf("failed to create network namespace: %w", err)
	}
	netState.NamespaceID = namespaceID
	
	// Determine bridge name
	bridgeName := config.BridgeName
	if bridgeName == "" {
		bridgeName = "sandbox-br0"
	}
	
	// Create or get bridge
	bridge, err := nm.getOrCreateBridge(bridgeName, config.Subnet)
	if err != nil {
		return fmt.Errorf("failed to create bridge: %w", err)
	}
	netState.BridgeName = bridgeName
	
	// Create veth pair
	vethHost := fmt.Sprintf("veth-%s-host", netState.ContainerID[:8])
	vethGuest := fmt.Sprintf("veth-%s-guest", netState.ContainerID[:8])
	
	if err := nm.createVethPair(vethHost, vethGuest); err != nil {
		return fmt.Errorf("failed to create veth pair: %w", err)
	}
	
	netState.VethPairHost = vethHost
	netState.VethPairGuest = vethGuest
	
	// Attach host veth to bridge
	if err := nm.attachInterfaceToBridge(vethHost, bridgeName); err != nil {
		return fmt.Errorf("failed to attach veth to bridge: %w", err)
	}
	
	// Move guest veth to container namespace
	if err := nm.moveInterfaceToNamespace(vethGuest, namespaceID); err != nil {
		return fmt.Errorf("failed to move interface to namespace: %w", err)
	}
	
	// Configure IP address in namespace
	if config.IPAddress != "" {
		netState.IPAddress = config.IPAddress
	} else {
		// Allocate IP from bridge subnet
		ip, err := nm.allocateIPFromBridge(bridge)
		if err != nil {
			return fmt.Errorf("failed to allocate IP: %w", err)
		}
		netState.IPAddress = ip
	}
	
	// Configure gateway
	if config.Gateway != "" {
		netState.Gateway = config.Gateway
	} else {
		netState.Gateway = nm.getBridgeGateway(bridge)
	}
	
	// Configure interface in namespace
	if err := nm.configureInterfaceInNamespace(namespaceID, vethGuest, netState.IPAddress, netState.Gateway); err != nil {
		return fmt.Errorf("failed to configure interface in namespace: %w", err)
	}
	
	// Add interface information
	guestInterface := NetworkInterface{
		Name:      vethGuest,
		Type:      "veth",
		IPAddress: netState.IPAddress,
		State:     "up",
		MTU:       1500,
	}
	if config.MTU > 0 {
		guestInterface.MTU = config.MTU
	}
	
	netState.Interfaces = append(netState.Interfaces, guestInterface)
	
	// Add loopback
	loInterface := NetworkInterface{
		Name:      "lo",
		Type:      "loopback",
		IPAddress: "127.0.0.1",
		State:     "up",
		MTU:       65536,
	}
	netState.Interfaces = append(netState.Interfaces, loInterface)
	
	return nil
}

// setupNetworkCustom configures custom network mode
func (nm *NetworkManager) setupNetworkCustom(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Setting up custom network mode")
	
	// Custom network setup would be implemented based on specific requirements
	// For now, default to bridge-like setup
	return nm.setupNetworkBridge(ctx, netState)
}

// Network namespace operations

// createNetworkNamespace creates a new network namespace
func (nm *NetworkManager) createNetworkNamespace(ctx context.Context, namespaceID string) error {
	namespacePath := filepath.Join(nm.netnsPath, namespaceID)
	
	// Create namespace file
	if _, err := os.Create(namespacePath); err != nil {
		return fmt.Errorf("failed to create namespace file: %w", err)
	}
	
	// Create the network namespace using unshare
	cmd := exec.CommandContext(ctx, "ip", "netns", "add", namespaceID)
	if err := cmd.Run(); err != nil {
		os.Remove(namespacePath) // Cleanup on failure
		return fmt.Errorf("failed to create network namespace: %w", err)
	}
	
	log.Debug().Str("namespace_id", namespaceID).Msg("Network namespace created")
	return nil
}

// removeNetworkNamespace removes a network namespace
func (nm *NetworkManager) removeNetworkNamespace(ctx context.Context, namespaceID string) error {
	cmd := exec.CommandContext(ctx, "ip", "netns", "delete", namespaceID)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete network namespace: %w", err)
	}
	
	log.Debug().Str("namespace_id", namespaceID).Msg("Network namespace removed")
	return nil
}

// Bridge operations

// getOrCreateBridge gets or creates a bridge interface
func (nm *NetworkManager) getOrCreateBridge(bridgeName, subnet string) (*BridgeInterface, error) {
	// Check if bridge already exists
	if bridge, exists := nm.bridgeInterfaces[bridgeName]; exists {
		return bridge, nil
	}
	
	// Create new bridge
	if err := nm.createBridge(bridgeName, subnet); err != nil {
		return nil, fmt.Errorf("failed to create bridge: %w", err)
	}
	
	// Parse subnet to get gateway IP
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet: %w", err)
	}
	
	gatewayIP := nm.getNetworkGatewayIP(network)
	
	bridge := &BridgeInterface{
		Name:       bridgeName,
		IPAddress:  gatewayIP,
		Subnet:     subnet,
		MTU:        1500,
		State:      "up",
		Containers: make([]string, 0),
		CreatedAt:  time.Now(),
	}
	
	nm.bridgeInterfaces[bridgeName] = bridge
	return bridge, nil
}

// createBridge creates a bridge interface
func (nm *NetworkManager) createBridge(bridgeName, subnet string) error {
	// Create bridge
	cmd := exec.Command("ip", "link", "add", "name", bridgeName, "type", "bridge")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create bridge link: %w", err)
	}
	
	// Set bridge up
	cmd = exec.Command("ip", "link", "set", "dev", bridgeName, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring bridge up: %w", err)
	}
	
	// Assign IP to bridge
	if subnet != "" {
		_, network, err := net.ParseCIDR(subnet)
		if err == nil {
			gatewayIP := nm.getNetworkGatewayIP(network)
			cmd = exec.Command("ip", "addr", "add", gatewayIP+"/"+strings.Split(subnet, "/")[1], "dev", bridgeName)
			if err := cmd.Run(); err != nil {
				log.Warn().Err(err).Str("bridge", bridgeName).Msg("Failed to assign IP to bridge")
			}
		}
	}
	
	log.Debug().Str("bridge", bridgeName).Str("subnet", subnet).Msg("Bridge created")
	return nil
}

// Helper methods

// validateNetworkConfig validates network configuration
func (nm *NetworkManager) validateNetworkConfig(config *NetworkConfig) error {
	// Validate network mode
	switch config.Mode {
	case NetworkModeNone, NetworkModeBridge, NetworkModeHost, NetworkModeCustom:
		// Valid modes
	default:
		return fmt.Errorf("invalid network mode: %s", config.Mode)
	}
	
	// Validate isolation level
	switch config.IsolationLevel {
	case IsolationLevelNone, IsolationLevelBasic, IsolationLevelStrict, IsolationLevelComplete:
		// Valid levels
	default:
		return fmt.Errorf("invalid isolation level: %s", config.IsolationLevel)
	}
	
	// Validate port mappings
	for _, mapping := range config.PortMappings {
		if mapping.HostPort <= 0 || mapping.HostPort > 65535 {
			return fmt.Errorf("invalid host port: %d", mapping.HostPort)
		}
		if mapping.ContainerPort <= 0 || mapping.ContainerPort > 65535 {
			return fmt.Errorf("invalid container port: %d", mapping.ContainerPort)
		}
		if mapping.Protocol != "tcp" && mapping.Protocol != "udp" {
			return fmt.Errorf("invalid protocol: %s", mapping.Protocol)
		}
	}
	
	// Validate firewall rules
	for _, rule := range config.FirewallRules {
		if rule.Action != FirewallActionAllow && rule.Action != FirewallActionDeny && rule.Action != FirewallActionDrop {
			return fmt.Errorf("invalid firewall action: %s", rule.Action)
		}
		if rule.Direction != TrafficDirectionIngress && rule.Direction != TrafficDirectionEgress {
			return fmt.Errorf("invalid traffic direction: %s", rule.Direction)
		}
	}
	
	return nil
}

// checkSystemCapabilities checks if the system has required network capabilities
func (nm *NetworkManager) checkSystemCapabilities() {
	// Check for NET_ADMIN capability (simplified check)
	cmd := exec.Command("ip", "link", "show")
	if err := cmd.Run(); err != nil {
		log.Warn().Msg("NET_ADMIN capability may not be available")
		nm.hasNetAdmin = false
	} else {
		nm.hasNetAdmin = true
	}
	
	// Check for NET_RAW capability (simplified check)
	// In a real implementation, you'd check actual capabilities
	nm.hasNetRaw = true
}

// createDefaultBridge creates the default bridge if it doesn't exist
func (nm *NetworkManager) createDefaultBridge(bridgeName, subnet string) error {
	// Check if bridge already exists
	cmd := exec.Command("ip", "link", "show", bridgeName)
	if err := cmd.Run(); err == nil {
		log.Debug().Str("bridge", bridgeName).Msg("Default bridge already exists")
		return nil
	}
	
	// Create the bridge
	return nm.createBridge(bridgeName, subnet)
}

// Placeholder implementations for complex operations
// In a full implementation, these would contain actual network configuration logic

func (nm *NetworkManager) createVethPair(hostVeth, guestVeth string) error {
	cmd := exec.Command("ip", "link", "add", hostVeth, "type", "veth", "peer", "name", guestVeth)
	return cmd.Run()
}

func (nm *NetworkManager) attachInterfaceToBridge(interface_, bridge string) error {
	cmd := exec.Command("ip", "link", "set", interface_, "master", bridge)
	if err := cmd.Run(); err != nil {
		return err
	}
	
	cmd = exec.Command("ip", "link", "set", "dev", interface_, "up")
	return cmd.Run()
}

func (nm *NetworkManager) moveInterfaceToNamespace(interface_, namespace string) error {
	cmd := exec.Command("ip", "link", "set", interface_, "netns", namespace)
	return cmd.Run()
}

func (nm *NetworkManager) configureInterfaceInNamespace(namespace, interface_, ipAddress, gateway string) error {
	// Configure IP
	cmd := exec.Command("ip", "netns", "exec", namespace, "ip", "addr", "add", ipAddress, "dev", interface_)
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Bring interface up
	cmd = exec.Command("ip", "netns", "exec", namespace, "ip", "link", "set", "dev", interface_, "up")
	if err := cmd.Run(); err != nil {
		return err
	}
	
	// Configure gateway
	if gateway != "" {
		cmd = exec.Command("ip", "netns", "exec", namespace, "ip", "route", "add", "default", "via", gateway)
		cmd.Run() // Ignore errors for route setup
	}
	
	return nil
}

func (nm *NetworkManager) allocateIPFromBridge(bridge *BridgeInterface) (string, error) {
	// Simple IP allocation - in production, use proper IPAM
	_, network, err := net.ParseCIDR(bridge.Subnet)
	if err != nil {
		return "", err
	}
	
	// Get the next available IP (simplified)
	ip := network.IP
	ip[len(ip)-1] += byte(len(bridge.Containers) + 10) // Simple offset
	
	return ip.String(), nil
}

func (nm *NetworkManager) getBridgeGateway(bridge *BridgeInterface) string {
	return bridge.IPAddress
}

func (nm *NetworkManager) getNetworkGatewayIP(network *net.IPNet) string {
	ip := network.IP
	ip[len(ip)-1] += 1 // Gateway is typically .1
	return ip.String()
}

func (nm *NetworkManager) getHostNetworkInterfaces() ([]NetworkInterface, error) {
	// Simplified - return basic interface info
	return []NetworkInterface{
		{
			Name:      "eth0",
			Type:      "ethernet",
			IPAddress: "host-ip",
			State:     "up",
			MTU:       1500,
		},
	}, nil
}

func (nm *NetworkManager) getDefaultGateway() (string, error) {
	// Simplified gateway detection
	return "192.168.1.1", nil
}

// Firewall and bandwidth operations (placeholder implementations)

func (nm *NetworkManager) applyFirewallRules(ctx context.Context, netState *ContainerNetworkState) error {
	// Apply iptables rules based on firewall configuration
	log.Debug().Str("container_id", netState.ContainerID).Int("rules", len(netState.NetworkConfig.FirewallRules)).Msg("Applying firewall rules")
	
	netState.ActiveRules = make([]FirewallRule, len(netState.NetworkConfig.FirewallRules))
	copy(netState.ActiveRules, netState.NetworkConfig.FirewallRules)
	
	return nil
}

func (nm *NetworkManager) removeFirewallRules(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Int("rules", len(netState.ActiveRules)).Msg("Removing firewall rules")
	
	netState.ActiveRules = make([]FirewallRule, 0)
	return nil
}

func (nm *NetworkManager) applyBandwidthLimits(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Applying bandwidth limits")
	
	netState.BandwidthActive = true
	return nil
}

func (nm *NetworkManager) removeBandwidthLimits(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Removing bandwidth limits")
	
	netState.BandwidthActive = false
	return nil
}

func (nm *NetworkManager) configureDNS(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Configuring DNS")
	return nil
}

func (nm *NetworkManager) setupPortMappings(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Int("mappings", len(netState.NetworkConfig.PortMappings)).Msg("Setting up port mappings")
	return nil
}

func (nm *NetworkManager) cleanupPortMappings(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Cleaning up port mappings")
	return nil
}

func (nm *NetworkManager) cleanupNetworkBridge(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Cleaning up bridge network")
	
	// Remove veth interfaces
	if netState.VethPairHost != "" {
		cmd := exec.CommandContext(ctx, "ip", "link", "delete", netState.VethPairHost)
		cmd.Run() // Ignore errors
	}
	
	return nil
}

func (nm *NetworkManager) cleanupNetworkCustom(ctx context.Context, netState *ContainerNetworkState) error {
	log.Debug().Str("container_id", netState.ContainerID).Msg("Cleaning up custom network")
	return nil
}

// DefaultNetworkConfig returns a default network configuration
func DefaultNetworkConfig() *NetworkConfig {
	return &NetworkConfig{
		Mode:           NetworkModeBridge,
		IsolationLevel: IsolationLevelBasic,
		PortMappings:   make([]PortMapping, 0),
		DNS: DNSConfig{
			Nameservers: []string{"8.8.8.8", "8.8.4.4"},
			Search:      []string{},
			Options:     []string{},
			ExtraHosts:  make(map[string]string),
		},
		FirewallRules:      make([]FirewallRule, 0),
		EnableIPForwarding: false,
		MTU:               1500,
	}
}