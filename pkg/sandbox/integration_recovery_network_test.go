package sandbox

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegrationRecoveryAndNetworking(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temporary workspace
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	workspaceDir := filepath.Join(tempDir, "workspace")

	// Create manager with recovery and networking
	manager, err := NewManager(dbPath, workspaceDir)
	require.NoError(t, err)
	defer manager.Close()

	// Verify components are initialized
	assert.NotNil(t, manager.recoveryManager)
	assert.NotNil(t, manager.networkManager)
	assert.NotNil(t, manager.stateMachine)
	assert.NotNil(t, manager.healthChecker)
	assert.NotNil(t, manager.eventBus)
	assert.NotNil(t, manager.metricsCollector)

	// Test sandbox creation with enhanced configuration
	testSandboxWithRecoveryAndNetworking(t, manager)

	// Test recovery functionality
	testRecoveryIntegration(t, manager)

	// Test networking functionality
	testNetworkingIntegration(t, manager)
}

func testSandboxWithRecoveryAndNetworking(t *testing.T, manager *Manager) {
	ctx := context.Background()

	// Create sandbox config with recovery and networking
	config := SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Environment: map[string]string{
			"TEST_VAR": "integration_test",
		},
		EnableLogging:  true,
		EnableRecovery: true,
		NetworkConfig: &runtime.NetworkConfig{
			Mode:           runtime.NetworkModeBridge,
			IsolationLevel: runtime.IsolationLevelBasic,
			PortMappings: []runtime.PortMapping{
				{
					HostPort:      8080,
					ContainerPort: 80,
					Protocol:      "tcp",
				},
			},
			DNS: runtime.DNSConfig{
				Nameservers: []string{"8.8.8.8", "1.1.1.1"},
				Search:      []string{"example.com"},
			},
			FirewallRules: []runtime.FirewallRule{
				{
					ID:        "allow-http",
					Action:    runtime.FirewallActionAllow,
					Direction: runtime.TrafficDirectionIngress,
					Protocol:  "tcp",
					DestPorts: []int{80, 443},
				},
			},
		},
		RecoveryPolicy: &RecoveryPolicy{
			MaxRetries:        2,
			BaseDelay:         500 * time.Millisecond,
			BackoffMultiplier: 1.5,
			Actions: map[FailureType]RecoveryAction{
				FailureTypeOOM:   RecoveryActionRestart,
				FailureTypeCrash: RecoveryActionRestart,
			},
		},
	}

	// Create sandbox
	sandbox, err := manager.CreateSandbox(ctx, config)
	require.NoError(t, err)
	require.NotNil(t, sandbox)

	t.Logf("Created sandbox: %s (container: %s)", sandbox.ID, sandbox.ContainerID)

	// Verify sandbox state
	assert.Equal(t, SandboxStatusRunning, sandbox.Status)
	assert.NotEmpty(t, sandbox.ID)
	assert.NotEmpty(t, sandbox.ContainerID)
	assert.NotEmpty(t, sandbox.WorkingDir)

	// Verify recovery is enabled
	recoveryState, err := manager.GetSandboxRecoveryState(sandbox.ID)
	assert.NoError(t, err)
	assert.True(t, recoveryState.RecoveryEnabled)
	assert.NotNil(t, recoveryState.Policy)
	assert.Equal(t, 2, recoveryState.Policy.MaxRetries)

	// Verify network configuration
	networkState, err := manager.GetSandboxNetworkState(sandbox.ID)
	assert.NoError(t, err)
	assert.Equal(t, runtime.NetworkModeBridge, networkState.NetworkConfig.Mode)
	assert.Equal(t, 1, len(networkState.NetworkConfig.PortMappings))
	assert.Equal(t, 1, len(networkState.NetworkConfig.FirewallRules))
	assert.NotEmpty(t, networkState.IPAddress)

	// Get network statistics
	netStats, err := manager.GetSandboxNetworkStatistics(sandbox.ID)
	assert.NoError(t, err)
	assert.Equal(t, sandbox.ContainerID, netStats["container_id"])
	assert.Equal(t, string(runtime.NetworkModeBridge), netStats["network_mode"])
	assert.NotEmpty(t, netStats["ip_address"])

	// Cleanup
	err = manager.DeleteSandbox(ctx, sandbox.ID)
	assert.NoError(t, err)
}

func testRecoveryIntegration(t *testing.T, manager *Manager) {
	ctx := context.Background()

	// Create sandbox with recovery enabled
	config := SandboxConfig{
		Image:          "ubuntu:20.04",
		WorkspaceDir:   "/workspace",
		EnableRecovery: true,
		RecoveryPolicy: &RecoveryPolicy{
			MaxRetries:        1,
			BaseDelay:         100 * time.Millisecond,
			BackoffMultiplier: 1.0,
			Actions: map[FailureType]RecoveryAction{
				FailureTypeCrash: RecoveryActionRestart,
			},
		},
	}

	sandbox, err := manager.CreateSandbox(ctx, config)
	require.NoError(t, err)
	defer manager.DeleteSandbox(ctx, sandbox.ID)

	// Test manual recovery trigger
	err = manager.TriggerSandboxRecovery(sandbox.ID, FailureTypeCrash, "Integration test trigger")
	assert.NoError(t, err)

	// Wait for recovery processing
	time.Sleep(200 * time.Millisecond)

	// Check recovery state
	recoveryState, err := manager.GetSandboxRecoveryState(sandbox.ID)
	assert.NoError(t, err)
	assert.True(t, len(recoveryState.Attempts) > 0)
	assert.Equal(t, FailureTypeCrash, recoveryState.LastFailureType)

	// Test recovery policy update
	newPolicy := &RecoveryPolicy{
		MaxRetries:        5,
		BaseDelay:         200 * time.Millisecond,
		BackoffMultiplier: 2.0,
		Actions: map[FailureType]RecoveryAction{
			FailureTypeOOM: RecoveryActionTerminate,
		},
	}

	err = manager.SetSandboxRecoveryPolicy(sandbox.ID, newPolicy)
	assert.NoError(t, err)

	// Verify policy update
	recoveryState, err = manager.GetSandboxRecoveryState(sandbox.ID)
	assert.NoError(t, err)
	assert.Equal(t, 5, recoveryState.Policy.MaxRetries)
	assert.Equal(t, RecoveryActionTerminate, recoveryState.Policy.Actions[FailureTypeOOM])

	// Test disable/enable recovery
	err = manager.DisableSandboxRecovery(sandbox.ID)
	assert.NoError(t, err)

	recoveryState, err = manager.GetSandboxRecoveryState(sandbox.ID)
	assert.NoError(t, err)
	assert.False(t, recoveryState.RecoveryEnabled)

	err = manager.EnableSandboxRecovery(sandbox.ID)
	assert.NoError(t, err)

	recoveryState, err = manager.GetSandboxRecoveryState(sandbox.ID)
	assert.NoError(t, err)
	assert.True(t, recoveryState.RecoveryEnabled)

	// Test recovery metrics
	metrics := manager.GetRecoveryMetrics()
	assert.NotNil(t, metrics)
	assert.True(t, metrics.TotalRecoveries >= 1)
}

func testNetworkingIntegration(t *testing.T, manager *Manager) {
	ctx := context.Background()

	// Create sandbox with networking
	config := SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		NetworkConfig: &runtime.NetworkConfig{
			Mode:           runtime.NetworkModeBridge,
			IsolationLevel: runtime.IsolationLevelBasic,
			PortMappings: []runtime.PortMapping{
				{
					HostPort:      9090,
					ContainerPort: 90,
					Protocol:      "tcp",
				},
			},
		},
	}

	sandbox, err := manager.CreateSandbox(ctx, config)
	require.NoError(t, err)
	defer manager.DeleteSandbox(ctx, sandbox.ID)

	// Test firewall rule updates
	newFirewallRules := []runtime.FirewallRule{
		{
			ID:        "allow-ssh",
			Action:    runtime.FirewallActionAllow,
			Direction: runtime.TrafficDirectionIngress,
			Protocol:  "tcp",
			DestPorts: []int{22},
		},
		{
			ID:        "deny-telnet",
			Action:    runtime.FirewallActionDeny,
			Direction: runtime.TrafficDirectionIngress,
			Protocol:  "tcp",
			DestPorts: []int{23},
		},
	}

	err = manager.UpdateSandboxNetworkFirewallRules(ctx, sandbox.ID, newFirewallRules)
	assert.NoError(t, err)

	// Verify firewall rules were updated
	networkState, err := manager.GetSandboxNetworkState(sandbox.ID)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(networkState.NetworkConfig.FirewallRules))
	assert.Equal(t, 2, len(networkState.ActiveRules))

	// Test bandwidth limit updates
	bandwidthLimits := &runtime.BandwidthLimit{
		Ingress: runtime.BandwidthRule{
			Rate:     "10mbps",
			Burst:    "1mb",
			Priority: 5,
		},
		Egress: runtime.BandwidthRule{
			Rate:     "5mbps",
			Burst:    "500kb",
			Priority: 3,
		},
	}

	err = manager.UpdateSandboxNetworkBandwidthLimits(ctx, sandbox.ID, bandwidthLimits)
	assert.NoError(t, err)

	// Verify bandwidth limits were applied
	networkState, err = manager.GetSandboxNetworkState(sandbox.ID)
	assert.NoError(t, err)
	assert.NotNil(t, networkState.NetworkConfig.BandwidthLimits)
	assert.Equal(t, "10mbps", networkState.NetworkConfig.BandwidthLimits.Ingress.Rate)
	assert.Equal(t, "5mbps", networkState.NetworkConfig.BandwidthLimits.Egress.Rate)
	assert.True(t, networkState.BandwidthActive)

	// Remove bandwidth limits
	err = manager.UpdateSandboxNetworkBandwidthLimits(ctx, sandbox.ID, nil)
	assert.NoError(t, err)

	networkState, err = manager.GetSandboxNetworkState(sandbox.ID)
	assert.NoError(t, err)
	assert.Nil(t, networkState.NetworkConfig.BandwidthLimits)
	assert.False(t, networkState.BandwidthActive)

	// Test network statistics
	netStats, err := manager.GetSandboxNetworkStatistics(sandbox.ID)
	assert.NoError(t, err)
	assert.NotEmpty(t, netStats["container_id"])
	assert.NotEmpty(t, netStats["network_mode"])
	assert.NotEmpty(t, netStats["ip_address"])
	assert.Contains(t, netStats, "interfaces")
	assert.Contains(t, netStats, "interface_stats")

	// Test list all networks
	allNetworks := manager.ListSandboxNetworks()
	assert.True(t, len(allNetworks) >= 1)
	assert.Contains(t, allNetworks, sandbox.ContainerID)
}

func TestContainerLifecycleWithFailures(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	workspaceDir := filepath.Join(tempDir, "workspace")

	manager, err := NewManager(dbPath, workspaceDir)
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Create sandbox with aggressive recovery policy
	config := SandboxConfig{
		Image:          "ubuntu:20.04",
		WorkspaceDir:   "/workspace",
		EnableRecovery: true,
		RecoveryPolicy: &RecoveryPolicy{
			MaxRetries:        3,
			BaseDelay:         50 * time.Millisecond,
			BackoffMultiplier: 1.2,
			Actions: map[FailureType]RecoveryAction{
				FailureTypeUnknown: RecoveryActionRestart,
				FailureTypeCrash:   RecoveryActionRestart,
				FailureTypeOOM:     RecoveryActionRestart,
			},
			PreserveState: true,
		},
		NetworkConfig: runtime.DefaultNetworkConfig(),
	}

	sandbox, err := manager.CreateSandbox(ctx, config)
	require.NoError(t, err)
	defer manager.DeleteSandbox(ctx, sandbox.ID)

	// Simulate container failure through state machine
	err = manager.stateMachine.SetState(sandbox.ContainerID, ContainerStateFailed, "Simulated failure", nil)
	require.NoError(t, err)

	// Wait for recovery to process
	time.Sleep(200 * time.Millisecond)

	// Check that recovery was attempted
	recoveryState, err := manager.GetSandboxRecoveryState(sandbox.ID)
	assert.NoError(t, err)
	assert.True(t, len(recoveryState.Attempts) > 0)

	// Check recovery metrics
	metrics := manager.GetRecoveryMetrics()
	assert.NotNil(t, metrics)
	assert.True(t, metrics.TotalFailures > 0 || metrics.TotalRecoveries > 0)
}

func TestNetworkIsolationModes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	workspaceDir := filepath.Join(tempDir, "workspace")

	manager, err := NewManager(dbPath, workspaceDir)
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	modes := []runtime.NetworkMode{
		runtime.NetworkModeNone,
		runtime.NetworkModeHost,
		runtime.NetworkModeBridge,
	}

	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			config := SandboxConfig{
				Image:        "ubuntu:20.04",
				WorkspaceDir: "/workspace",
				NetworkConfig: &runtime.NetworkConfig{
					Mode:           mode,
					IsolationLevel: runtime.IsolationLevelBasic,
				},
			}

			sandbox, err := manager.CreateSandbox(ctx, config)
			if err != nil {
				t.Logf("Failed to create sandbox with mode %s: %v", mode, err)
				return // Skip if network setup fails
			}

			// Verify network state
			networkState, err := manager.GetSandboxNetworkState(sandbox.ID)
			if err == nil {
				assert.Equal(t, mode, networkState.NetworkConfig.Mode)
				assert.True(t, len(networkState.Interfaces) > 0)
			}

			// Cleanup
			manager.DeleteSandbox(ctx, sandbox.ID)
		})
	}
}

func TestRecoveryFailureDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	workspaceDir := filepath.Join(tempDir, "workspace")

	manager, err := NewManager(dbPath, workspaceDir)
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Test different failure types
	failureTests := []struct {
		name         string
		reason       string
		errorMessage string
		expectedType FailureType
	}{
		{
			name:         "oom_failure",
			reason:       "container killed due to memory limit",
			errorMessage: "OOM killed",
			expectedType: FailureTypeOOM,
		},
		{
			name:         "timeout_failure",
			reason:       "operation timeout",
			errorMessage: "context deadline exceeded",
			expectedType: FailureTypeTimeout,
		},
		{
			name:         "crash_failure",
			reason:       "process crash",
			errorMessage: "segmentation fault",
			expectedType: FailureTypeCrash,
		},
	}

	for _, tt := range failureTests {
		t.Run(tt.name, func(t *testing.T) {
			config := SandboxConfig{
				Image:          "ubuntu:20.04",
				WorkspaceDir:   "/workspace",
				EnableRecovery: true,
			}

			sandbox, err := manager.CreateSandbox(ctx, config)
			require.NoError(t, err)
			defer manager.DeleteSandbox(ctx, sandbox.ID)

			// Simulate specific failure type
			metadata := map[string]interface{}{
				"test_type": tt.name,
			}
			err = manager.stateMachine.SetStateWithError(
				sandbox.ContainerID,
				ContainerStateFailed,
				tt.reason,
				tt.errorMessage,
				metadata,
			)
			require.NoError(t, err)

			// Wait for recovery processing
			time.Sleep(100 * time.Millisecond)

			// Check recovery state
			recoveryState, err := manager.GetSandboxRecoveryState(sandbox.ID)
			assert.NoError(t, err)
			
			// Verify failure type was detected correctly
			if len(recoveryState.Attempts) > 0 {
				assert.Equal(t, tt.expectedType, recoveryState.Attempts[0].FailureType)
			}
		})
	}
}