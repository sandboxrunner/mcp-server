package runtime

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNetworkManager(t *testing.T) {
	config := DefaultNetworkManagerConfig()
	config.NetnsPath = "/tmp/test-netns"
	
	nm, err := NewNetworkManager(config)
	assert.NoError(t, err)
	assert.NotNil(t, nm)
	assert.Equal(t, config.NetnsPath, nm.netnsPath)
	assert.NotNil(t, nm.containerNets)
	assert.NotNil(t, nm.bridgeInterfaces)
}

func TestDefaultNetworkManagerConfig(t *testing.T) {
	config := DefaultNetworkManagerConfig()
	
	assert.Equal(t, "/var/run/netns", config.NetnsPath)
	assert.Equal(t, "sandbox-br0", config.DefaultBridge)
	assert.Equal(t, "172.20.0.0/16", config.DefaultSubnet)
	assert.True(t, config.EnableFirewall)
	assert.True(t, config.EnableQoS)
	assert.Contains(t, config.RequiredCaps, "NET_ADMIN")
	assert.Contains(t, config.RequiredCaps, "NET_RAW")
}

func TestDefaultNetworkConfig(t *testing.T) {
	config := DefaultNetworkConfig()
	
	assert.Equal(t, NetworkModeBridge, config.Mode)
	assert.Equal(t, IsolationLevelBasic, config.IsolationLevel)
	assert.Equal(t, 0, len(config.PortMappings))
	assert.Equal(t, 0, len(config.FirewallRules))
	assert.False(t, config.EnableIPForwarding)
	assert.Equal(t, 1500, config.MTU)
	assert.Equal(t, 2, len(config.DNS.Nameservers))
	assert.Contains(t, config.DNS.Nameservers, "8.8.8.8")
	assert.Contains(t, config.DNS.Nameservers, "8.8.4.4")
}

func TestNetworkModeValidation(t *testing.T) {
	nm := &NetworkManager{}
	
	validModes := []NetworkMode{
		NetworkModeNone,
		NetworkModeBridge,
		NetworkModeHost,
		NetworkModeCustom,
	}
	
	for _, mode := range validModes {
		config := &NetworkConfig{
			Mode:           mode,
			IsolationLevel: IsolationLevelBasic,
		}
		
		err := nm.validateNetworkConfig(config)
		assert.NoError(t, err, "Mode %s should be valid", mode)
	}
	
	// Test invalid mode
	config := &NetworkConfig{
		Mode:           "invalid",
		IsolationLevel: IsolationLevelBasic,
	}
	err := nm.validateNetworkConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid network mode")
}

func TestIsolationLevelValidation(t *testing.T) {
	nm := &NetworkManager{}
	
	validLevels := []NetworkIsolationLevel{
		IsolationLevelNone,
		IsolationLevelBasic,
		IsolationLevelStrict,
		IsolationLevelComplete,
	}
	
	for _, level := range validLevels {
		config := &NetworkConfig{
			Mode:           NetworkModeBridge,
			IsolationLevel: level,
		}
		
		err := nm.validateNetworkConfig(config)
		assert.NoError(t, err, "Isolation level %s should be valid", level)
	}
	
	// Test invalid isolation level
	config := &NetworkConfig{
		Mode:           NetworkModeBridge,
		IsolationLevel: "invalid",
	}
	err := nm.validateNetworkConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid isolation level")
}

func TestPortMappingValidation(t *testing.T) {
	nm := &NetworkManager{}
	
	tests := []struct {
		name        string
		mapping     PortMapping
		shouldError bool
	}{
		{
			name: "valid_tcp_mapping",
			mapping: PortMapping{
				HostPort:      8080,
				ContainerPort: 80,
				Protocol:      "tcp",
			},
			shouldError: false,
		},
		{
			name: "valid_udp_mapping",
			mapping: PortMapping{
				HostPort:      53,
				ContainerPort: 53,
				Protocol:      "udp",
			},
			shouldError: false,
		},
		{
			name: "invalid_host_port_zero",
			mapping: PortMapping{
				HostPort:      0,
				ContainerPort: 80,
				Protocol:      "tcp",
			},
			shouldError: true,
		},
		{
			name: "invalid_host_port_too_high",
			mapping: PortMapping{
				HostPort:      70000,
				ContainerPort: 80,
				Protocol:      "tcp",
			},
			shouldError: true,
		},
		{
			name: "invalid_container_port_zero",
			mapping: PortMapping{
				HostPort:      8080,
				ContainerPort: 0,
				Protocol:      "tcp",
			},
			shouldError: true,
		},
		{
			name: "invalid_protocol",
			mapping: PortMapping{
				HostPort:      8080,
				ContainerPort: 80,
				Protocol:      "invalid",
			},
			shouldError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &NetworkConfig{
				Mode:           NetworkModeBridge,
				IsolationLevel: IsolationLevelBasic,
				PortMappings:   []PortMapping{tt.mapping},
			}
			
			err := nm.validateNetworkConfig(config)
			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFirewallRuleValidation(t *testing.T) {
	nm := &NetworkManager{}
	
	tests := []struct {
		name        string
		rule        FirewallRule
		shouldError bool
	}{
		{
			name: "valid_allow_rule",
			rule: FirewallRule{
				ID:        "test-1",
				Action:    FirewallActionAllow,
				Direction: TrafficDirectionIngress,
				Protocol:  "tcp",
			},
			shouldError: false,
		},
		{
			name: "valid_deny_rule",
			rule: FirewallRule{
				ID:        "test-2",
				Action:    FirewallActionDeny,
				Direction: TrafficDirectionEgress,
				Protocol:  "udp",
			},
			shouldError: false,
		},
		{
			name: "invalid_action",
			rule: FirewallRule{
				ID:        "test-3",
				Action:    "invalid",
				Direction: TrafficDirectionIngress,
				Protocol:  "tcp",
			},
			shouldError: true,
		},
		{
			name: "invalid_direction",
			rule: FirewallRule{
				ID:        "test-4",
				Action:    FirewallActionAllow,
				Direction: "invalid",
				Protocol:  "tcp",
			},
			shouldError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &NetworkConfig{
				Mode:           NetworkModeBridge,
				IsolationLevel: IsolationLevelBasic,
				FirewallRules:  []FirewallRule{tt.rule},
			}
			
			err := nm.validateNetworkConfig(config)
			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSetupContainerNetworkNone(t *testing.T) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/test-netns",
	}
	
	containerID := "test-container"
	config := &NetworkConfig{
		Mode:           NetworkModeNone,
		IsolationLevel: IsolationLevelBasic,
	}
	
	// Mock context
	ctx := context.Background()
	
	// Setup network (this will mostly be placeholder operations in our test)
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	assert.NoError(t, err)
	
	// Verify network state was created
	netState, err := nm.GetContainerNetworkState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, containerID, netState.ContainerID)
	assert.Equal(t, NetworkModeNone, netState.NetworkConfig.Mode)
	assert.True(t, len(netState.Interfaces) > 0) // Should have loopback
	
	// Find loopback interface
	var loInterface *NetworkInterface
	for _, iface := range netState.Interfaces {
		if iface.Type == "loopback" {
			loInterface = &iface
			break
		}
	}
	assert.NotNil(t, loInterface)
	assert.Equal(t, "lo", loInterface.Name)
	assert.Equal(t, "127.0.0.1", loInterface.IPAddress)
}

func TestSetupContainerNetworkHost(t *testing.T) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/test-netns",
	}
	
	containerID := "test-container"
	config := &NetworkConfig{
		Mode:           NetworkModeHost,
		IsolationLevel: IsolationLevelNone,
	}
	
	ctx := context.Background()
	
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	assert.NoError(t, err)
	
	// Verify network state
	netState, err := nm.GetContainerNetworkState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, NetworkModeHost, netState.NetworkConfig.Mode)
	assert.True(t, len(netState.Interfaces) > 0) // Should have host interfaces
}

func TestSetupContainerNetworkBridge(t *testing.T) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/test-netns",
	}
	
	containerID := "test-container"
	config := &NetworkConfig{
		Mode:           NetworkModeBridge,
		IsolationLevel: IsolationLevelBasic,
		BridgeName:     "test-br0",
		Subnet:         "172.20.0.0/16",
	}
	
	ctx := context.Background()
	
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	assert.NoError(t, err)
	
	// Verify network state
	netState, err := nm.GetContainerNetworkState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, NetworkModeBridge, netState.NetworkConfig.Mode)
	assert.Equal(t, "test-br0", netState.BridgeName)
	assert.NotEmpty(t, netState.NamespaceID)
	assert.NotEmpty(t, netState.VethPairHost)
	assert.NotEmpty(t, netState.VethPairGuest)
	assert.NotEmpty(t, netState.IPAddress)
	assert.True(t, len(netState.Interfaces) >= 2) // veth + loopback
}

func TestCleanupContainerNetwork(t *testing.T) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/test-netns",
	}
	
	containerID := "test-container"
	config := DefaultNetworkConfig()
	
	ctx := context.Background()
	
	// Setup network first
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	assert.NoError(t, err)
	
	// Verify it was set up
	_, err = nm.GetContainerNetworkState(containerID)
	assert.NoError(t, err)
	
	// Cleanup network
	err = nm.CleanupContainerNetwork(ctx, containerID)
	assert.NoError(t, err)
	
	// Verify it was cleaned up
	_, err = nm.GetContainerNetworkState(containerID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no network state found")
}

func TestUpdateFirewallRules(t *testing.T) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/test-netns",
	}
	
	containerID := "test-container"
	config := DefaultNetworkConfig()
	
	ctx := context.Background()
	
	// Setup network first
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	assert.NoError(t, err)
	
	// Define new firewall rules
	newRules := []FirewallRule{
		{
			ID:        "rule-1",
			Action:    FirewallActionAllow,
			Direction: TrafficDirectionIngress,
			Protocol:  "tcp",
			DestPorts: []int{80, 443},
		},
		{
			ID:        "rule-2",
			Action:    FirewallActionDeny,
			Direction: TrafficDirectionEgress,
			Protocol:  "udp",
			DestPorts: []int{53},
		},
	}
	
	// Update firewall rules
	err = nm.UpdateFirewallRules(ctx, containerID, newRules)
	assert.NoError(t, err)
	
	// Verify rules were updated
	netState, err := nm.GetContainerNetworkState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(netState.NetworkConfig.FirewallRules))
	assert.Equal(t, 2, len(netState.ActiveRules))
	assert.Equal(t, "rule-1", netState.ActiveRules[0].ID)
	assert.Equal(t, "rule-2", netState.ActiveRules[1].ID)
}

func TestUpdateBandwidthLimits(t *testing.T) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/test-netns",
	}
	
	containerID := "test-container"
	config := DefaultNetworkConfig()
	
	ctx := context.Background()
	
	// Setup network first
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	assert.NoError(t, err)
	
	// Define bandwidth limits
	limits := &BandwidthLimit{
		Ingress: BandwidthRule{
			Rate:     "1mbps",
			Burst:    "100kb",
			Priority: 5,
		},
		Egress: BandwidthRule{
			Rate:     "500kbps",
			Burst:    "50kb",
			Priority: 3,
		},
	}
	
	// Update bandwidth limits
	err = nm.UpdateBandwidthLimits(ctx, containerID, limits)
	assert.NoError(t, err)
	
	// Verify limits were updated
	netState, err := nm.GetContainerNetworkState(containerID)
	assert.NoError(t, err)
	assert.NotNil(t, netState.NetworkConfig.BandwidthLimits)
	assert.Equal(t, "1mbps", netState.NetworkConfig.BandwidthLimits.Ingress.Rate)
	assert.Equal(t, "500kbps", netState.NetworkConfig.BandwidthLimits.Egress.Rate)
	assert.True(t, netState.BandwidthActive)
	
	// Remove bandwidth limits
	err = nm.UpdateBandwidthLimits(ctx, containerID, nil)
	assert.NoError(t, err)
	
	netState, err = nm.GetContainerNetworkState(containerID)
	assert.NoError(t, err)
	assert.Nil(t, netState.NetworkConfig.BandwidthLimits)
	assert.False(t, netState.BandwidthActive)
}

func TestGetNetworkStatistics(t *testing.T) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/test-netns",
	}
	
	containerID := "test-container"
	config := DefaultNetworkConfig()
	config.FirewallRules = []FirewallRule{
		{
			ID:        "test-rule",
			Action:    FirewallActionAllow,
			Direction: TrafficDirectionIngress,
			Protocol:  "tcp",
		},
	}
	
	ctx := context.Background()
	
	// Setup network
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	assert.NoError(t, err)
	
	// Get statistics
	stats, err := nm.GetNetworkStatistics(containerID)
	assert.NoError(t, err)
	
	// Verify statistics
	assert.Equal(t, containerID, stats["container_id"])
	assert.Equal(t, string(NetworkModeBridge), stats["network_mode"])
	assert.Equal(t, string(IsolationLevelBasic), stats["isolation_level"])
	assert.NotEmpty(t, stats["ip_address"])
	assert.NotEmpty(t, stats["gateway"])
	assert.Greater(t, stats["interfaces"], 0)
	assert.Equal(t, 1, stats["active_rules"])
	assert.False(t, stats["bandwidth_active"].(bool))
	assert.NotNil(t, stats["created_at"])
	assert.NotNil(t, stats["updated_at"])
	
	// Verify interface stats
	interfaceStats, ok := stats["interface_stats"].([]map[string]interface{})
	assert.True(t, ok)
	assert.True(t, len(interfaceStats) > 0)
	
	for _, ifaceStats := range interfaceStats {
		assert.Contains(t, ifaceStats, "name")
		assert.Contains(t, ifaceStats, "type")
		assert.Contains(t, ifaceStats, "ip_address")
		assert.Contains(t, ifaceStats, "state")
		assert.Contains(t, ifaceStats, "mtu")
	}
}

func TestListContainerNetworks(t *testing.T) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/test-netns",
	}
	
	ctx := context.Background()
	
	// Setup multiple container networks
	containers := []string{"container-1", "container-2", "container-3"}
	for _, containerID := range containers {
		config := DefaultNetworkConfig()
		err := nm.SetupContainerNetwork(ctx, containerID, config)
		assert.NoError(t, err)
	}
	
	// List all networks
	networks := nm.ListContainerNetworks()
	assert.Equal(t, 3, len(networks))
	
	// Verify each container is present
	for _, containerID := range containers {
		netState, exists := networks[containerID]
		assert.True(t, exists, "Container %s should be in network list", containerID)
		assert.Equal(t, containerID, netState.ContainerID)
		assert.Equal(t, NetworkModeBridge, netState.NetworkConfig.Mode)
	}
}

func TestNetworkGatewayIP(t *testing.T) {
	nm := &NetworkManager{}
	
	tests := []struct {
		name     string
		cidr     string
		expected string
	}{
		{
			name:     "class_c_network",
			cidr:     "192.168.1.0/24",
			expected: "192.168.1.1",
		},
		{
			name:     "class_b_network",
			cidr:     "172.16.0.0/16",
			expected: "172.16.0.1",
		},
		{
			name:     "class_a_network",
			cidr:     "10.0.0.0/8",
			expected: "10.0.0.1",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, network, err := net.ParseCIDR(tt.cidr)
			require.NoError(t, err)
			
			gatewayIP := nm.getNetworkGatewayIP(network)
			assert.Equal(t, tt.expected, gatewayIP)
		})
	}
}

func TestAllocateIPFromBridge(t *testing.T) {
	nm := &NetworkManager{}
	
	bridge := &BridgeInterface{
		Name:       "test-br0",
		Subnet:     "172.20.0.0/16",
		IPAddress:  "172.20.0.1",
		Containers: []string{"container1", "container2"}, // 2 existing containers
	}
	
	ip, err := nm.allocateIPFromBridge(bridge)
	assert.NoError(t, err)
	assert.NotEmpty(t, ip)
	
	// Verify IP is in the correct range
	allocatedIP := net.ParseIP(ip)
	assert.NotNil(t, allocatedIP)
	
	_, network, err := net.ParseCIDR(bridge.Subnet)
	require.NoError(t, err)
	assert.True(t, network.Contains(allocatedIP))
}

func TestContainerNetworkState(t *testing.T) {
	containerID := "test-container"
	config := DefaultNetworkConfig()
	
	state := &ContainerNetworkState{
		ContainerID:   containerID,
		NetworkConfig: config,
		Interfaces:    make([]NetworkInterface, 0),
		NamespaceID:   "sandbox-test",
		IPAddress:     "172.20.0.10",
		Gateway:       "172.20.0.1",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	
	assert.Equal(t, containerID, state.ContainerID)
	assert.Equal(t, NetworkModeBridge, state.NetworkConfig.Mode)
	assert.Equal(t, "172.20.0.10", state.IPAddress)
	assert.Equal(t, "172.20.0.1", state.Gateway)
	assert.Equal(t, "sandbox-test", state.NamespaceID)
	assert.Equal(t, 0, len(state.Interfaces))
	assert.Equal(t, 0, len(state.ActiveRules))
	assert.False(t, state.BandwidthActive)
}

func TestBridgeInterface(t *testing.T) {
	bridge := &BridgeInterface{
		Name:       "test-bridge",
		IPAddress:  "172.20.0.1",
		Subnet:     "172.20.0.0/16",
		MTU:        1500,
		State:      "up",
		Containers: []string{"container1", "container2"},
		CreatedAt:  time.Now(),
	}
	
	assert.Equal(t, "test-bridge", bridge.Name)
	assert.Equal(t, "172.20.0.1", bridge.IPAddress)
	assert.Equal(t, "172.20.0.0/16", bridge.Subnet)
	assert.Equal(t, 1500, bridge.MTU)
	assert.Equal(t, "up", bridge.State)
	assert.Equal(t, 2, len(bridge.Containers))
	assert.Contains(t, bridge.Containers, "container1")
	assert.Contains(t, bridge.Containers, "container2")
}

// Benchmark tests

func BenchmarkSetupContainerNetwork(b *testing.B) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/benchmark-netns",
	}
	
	ctx := context.Background()
	config := DefaultNetworkConfig()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		containerID := fmt.Sprintf("benchmark-container-%d", i)
		err := nm.SetupContainerNetwork(ctx, containerID, config)
		require.NoError(b, err)
		
		// Cleanup to avoid memory issues in benchmark
		nm.CleanupContainerNetwork(ctx, containerID)
	}
}

func BenchmarkGetNetworkStatistics(b *testing.B) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/benchmark-netns",
	}
	
	ctx := context.Background()
	config := DefaultNetworkConfig()
	containerID := "benchmark-container"
	
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	require.NoError(b, err)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := nm.GetNetworkStatistics(containerID)
		require.NoError(b, err)
	}
}

func BenchmarkUpdateFirewallRules(b *testing.B) {
	nm := &NetworkManager{
		containerNets:    make(map[string]*ContainerNetworkState),
		bridgeInterfaces: make(map[string]*BridgeInterface),
		netnsPath:        "/tmp/benchmark-netns",
	}
	
	ctx := context.Background()
	config := DefaultNetworkConfig()
	containerID := "benchmark-container"
	
	err := nm.SetupContainerNetwork(ctx, containerID, config)
	require.NoError(b, err)
	
	rules := []FirewallRule{
		{
			ID:        "bench-rule-1",
			Action:    FirewallActionAllow,
			Direction: TrafficDirectionIngress,
			Protocol:  "tcp",
			DestPorts: []int{80},
		},
		{
			ID:        "bench-rule-2",
			Action:    FirewallActionDeny,
			Direction: TrafficDirectionEgress,
			Protocol:  "udp",
			DestPorts: []int{53},
		},
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		err := nm.UpdateFirewallRules(ctx, containerID, rules)
		require.NoError(b, err)
	}
}

// Helper function for require.NoError with *testing.B
func requireNoError(b *testing.B, err error) {
	if err != nil {
		b.Fatalf("Expected no error, got: %v", err)
	}
}

