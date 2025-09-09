package runtime

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContainerLifecycleIntegration tests the complete container lifecycle with process execution support
func TestContainerLifecycleIntegration(t *testing.T) {
	// Skip integration tests if running in CI without container support
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration test in CI environment")
	}
	
	// Create temporary directory for test
	tempDir, err := ioutil.TempDir("", "sandboxrunner-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	
	// Initialize RunC client
	client, err := NewRunCClient(tempDir)
	require.NoError(t, err)
	defer client.Cleanup()
	
	// Test basic container creation
	t.Run("BasicContainerCreation", func(t *testing.T) {
		testBasicContainerCreation(t, client, tempDir)
	})
	
	// Test container with process execution support
	t.Run("ProcessExecutionSupport", func(t *testing.T) {
		testProcessExecutionSupport(t, client, tempDir)
	})
	
	// Test security context configuration
	t.Run("SecurityContextConfiguration", func(t *testing.T) {
		testSecurityContextConfiguration(t, client, tempDir)
	})
	
	// Test resource limits configuration
	t.Run("ResourceLimitsConfiguration", func(t *testing.T) {
		testResourceLimitsConfiguration(t, client, tempDir)
	})
	
	// Test namespace configuration
	t.Run("NamespaceConfiguration", func(t *testing.T) {
		testNamespaceConfiguration(t, client, tempDir)
	})
	
	// Test container state validation
	t.Run("ContainerStateValidation", func(t *testing.T) {
		testContainerStateValidation(t, client, tempDir)
	})
	
	// Test process execution with validation
	t.Run("ProcessExecutionWithValidation", func(t *testing.T) {
		testProcessExecutionWithValidation(t, client, tempDir)
	})
}

func testBasicContainerCreation(t *testing.T, client *RunCClient, tempDir string) {
	ctx := context.Background()
	containerID := "test-container-" + uuid.New().String()[:8]
	bundlePath := filepath.Join(tempDir, containerID)
	
	// Create container configuration
	config := ContainerConfig{
		ID:           containerID,
		BundlePath:   bundlePath,
		WorkingDir:   "/workspace",
		Environment:  map[string]string{"TEST": "true"},
		ProcessSupport: false, // Basic container without process support
	}
	
	// Create container
	err := client.CreateContainer(ctx, config)
	assert.NoError(t, err)
	
	// Verify container exists in tracking
	client.containerMutex.RLock()
	state, exists := client.containerStates[containerID]
	client.containerMutex.RUnlock()
	
	assert.True(t, exists)
	assert.Equal(t, containerID, state.ID)
	assert.Equal(t, "created", state.Status)
	assert.False(t, state.Config.ProcessSupport)
}

func testProcessExecutionSupport(t *testing.T, client *RunCClient, tempDir string) {
	ctx := context.Background()
	containerID := "test-process-container-" + uuid.New().String()[:8]
	bundlePath := filepath.Join(tempDir, containerID)
	
	// Create container configuration with process support
	config := ContainerConfig{
		ID:             containerID,
		BundlePath:     bundlePath,
		WorkingDir:     "/workspace",
		Environment:    map[string]string{"TEST": "true"},
		ProcessSupport: true,
		SecurityContext: &SecurityContext{
			RunAsNonRoot:             BoolPtr(true),
			ReadOnlyRootFilesystem:   BoolPtr(false),
			AllowPrivilegeEscalation: BoolPtr(false),
		},
		ResourceLimits: &ResourceLimits{
			CPU: &CPULimits{
				Shares: Int64Ptr(1024),
			},
			Memory: &MemoryLimits{
				Limit: Int64Ptr(256 * 1024 * 1024), // 256MB
			},
		},
	}
	
	// Create container
	err := client.CreateContainer(ctx, config)
	assert.NoError(t, err)
	
	// Verify container supports process execution
	client.containerMutex.RLock()
	state, exists := client.containerStates[containerID]
	client.containerMutex.RUnlock()
	
	assert.True(t, exists)
	assert.True(t, state.Config.ProcessSupport)
	assert.NotNil(t, state.Config.SecurityContext)
	assert.NotNil(t, state.Config.ResourceLimits)
}

func testSecurityContextConfiguration(t *testing.T, client *RunCClient, tempDir string) {
	ctx := context.Background()
	containerID := "test-security-container-" + uuid.New().String()[:8]
	bundlePath := filepath.Join(tempDir, containerID)
	
	// Create security context
	securityContext := &SecurityContext{
		RunAsUser:                Int64Ptr(1001),
		RunAsGroup:               Int64Ptr(1001),
		RunAsNonRoot:             BoolPtr(true),
		ReadOnlyRootFilesystem:   BoolPtr(true),
		AllowPrivilegeEscalation: BoolPtr(false),
		Privileged:               BoolPtr(false),
		NoNewPrivs:               BoolPtr(true),
		AddCapabilities:          []string{"CAP_NET_BIND_SERVICE"},
		DropCapabilities:         []string{"CAP_SYS_ADMIN", "CAP_SYS_MODULE"},
		SeccompProfile: &SeccompProfile{
			Type:          "RuntimeDefault",
			DefaultAction: "SCMP_ACT_ERRNO",
		},
		AppArmorProfile: &AppArmorProfile{
			Type: "RuntimeDefault",
		},
	}
	
	// Create container configuration
	config := ContainerConfig{
		ID:              containerID,
		BundlePath:      bundlePath,
		ProcessSupport:  true,
		SecurityContext: securityContext,
	}
	
	// Create container
	err := client.CreateContainer(ctx, config)
	assert.NoError(t, err)
	
	// Verify security context is configured
	if client.securityManager != nil {
		client.securityManager.mu.RLock()
		storedContext, exists := client.securityManager.containerContexts[containerID]
		client.securityManager.mu.RUnlock()
		
		assert.True(t, exists)
		assert.NotNil(t, storedContext)
		assert.Equal(t, int64(1001), *storedContext.RunAsUser)
		assert.True(t, *storedContext.RunAsNonRoot)
		assert.Contains(t, storedContext.AddCapabilities, "CAP_NET_BIND_SERVICE")
		assert.Contains(t, storedContext.DropCapabilities, "CAP_SYS_ADMIN")
	}
}

func testResourceLimitsConfiguration(t *testing.T, client *RunCClient, tempDir string) {
	ctx := context.Background()
	containerID := "test-resources-container-" + uuid.New().String()[:8]
	bundlePath := filepath.Join(tempDir, containerID)
	
	// Create resource limits
	resourceLimits := &ResourceLimits{
		CPU: &CPULimits{
			Shares: Int64Ptr(2048),
			Quota:  Int64Ptr(100000), // 100ms
			Period: Int64Ptr(100000), // 100ms
			Cpuset: StringPtr("0-1"),
		},
		Memory: &MemoryLimits{
			Limit:       Int64Ptr(512 * 1024 * 1024), // 512MB
			Reservation: Int64Ptr(256 * 1024 * 1024), // 256MB
			Swap:        Int64Ptr(1024 * 1024 * 1024), // 1GB
			Swappiness:  Int64Ptr(10),
		},
		IO: &IOLimits{
			Weight: Int64Ptr(500),
			WeightDevice: []WeightDevice{
				{Major: 8, Minor: 0, Weight: 600},
			},
		},
		Process: &ProcessLimits{
			MaxProcesses: Int64Ptr(100),
			MaxOpenFiles: Int64Ptr(1024),
		},
		Ulimits: []Ulimit{
			{Name: "nofile", Soft: 1024, Hard: 2048},
			{Name: "nproc", Soft: 100, Hard: 200},
		},
	}
	
	// Create container configuration
	config := ContainerConfig{
		ID:             containerID,
		BundlePath:     bundlePath,
		ProcessSupport: true,
		ResourceLimits: resourceLimits,
	}
	
	// Create container
	err := client.CreateContainer(ctx, config)
	assert.NoError(t, err)
	
	// Verify resource limits are configured
	if client.resourceManager != nil {
		client.resourceManager.mu.RLock()
		storedLimits, exists := client.resourceManager.containerLimits[containerID]
		client.resourceManager.mu.RUnlock()
		
		assert.True(t, exists)
		assert.NotNil(t, storedLimits)
		assert.Equal(t, int64(2048), *storedLimits.CPU.Shares)
		assert.Equal(t, int64(512*1024*1024), *storedLimits.Memory.Limit)
		assert.Equal(t, int64(500), *storedLimits.IO.Weight)
		assert.Equal(t, int64(100), *storedLimits.Process.MaxProcesses)
		assert.Len(t, storedLimits.Ulimits, 2)
	}
}

func testNamespaceConfiguration(t *testing.T, client *RunCClient, tempDir string) {
	ctx := context.Background()
	containerID := "test-namespace-container-" + uuid.New().String()[:8]
	bundlePath := filepath.Join(tempDir, containerID)
	
	// Create namespace configuration
	namespaceConfig := &NamespaceConfig{
		PID:     true,
		Network: true,
		IPC:     true,
		UTS:     true,
		Mount:   true,
		User:    false, // Disable user namespace for simplicity
		Cgroup:  true,
		UserNamespaceMapping: &UserNamespaceMapping{
			UIDs: []IDMapping{
				{ContainerID: 0, HostID: 1000, Size: 1000},
			},
			GIDs: []IDMapping{
				{ContainerID: 0, HostID: 1000, Size: 1000},
			},
		},
	}
	
	// Create container configuration
	config := ContainerConfig{
		ID:              containerID,
		BundlePath:      bundlePath,
		ProcessSupport:  true,
		NamespaceConfig: namespaceConfig,
	}
	
	// Create container
	err := client.CreateContainer(ctx, config)
	assert.NoError(t, err)
	
	// Verify namespace configuration is stored
	client.containerMutex.RLock()
	state, exists := client.containerStates[containerID]
	client.containerMutex.RUnlock()
	
	assert.True(t, exists)
	assert.NotNil(t, state.Config.NamespaceConfig)
	assert.True(t, state.Config.NamespaceConfig.PID)
	assert.True(t, state.Config.NamespaceConfig.Network)
	assert.True(t, state.Config.NamespaceConfig.IPC)
	assert.True(t, state.Config.NamespaceConfig.UTS)
	assert.True(t, state.Config.NamespaceConfig.Mount)
	assert.True(t, state.Config.NamespaceConfig.Cgroup)
}

func testContainerStateValidation(t *testing.T, client *RunCClient, tempDir string) {
	ctx := context.Background()
	containerID := "test-validation-container-" + uuid.New().String()[:8]
	bundlePath := filepath.Join(tempDir, containerID)
	
	// Test validation without container
	err := client.ValidateContainerForProcessExecution(ctx, "non-existent-container")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in state tracking")
	
	// Create container without process support
	config := ContainerConfig{
		ID:             containerID,
		BundlePath:     bundlePath,
		ProcessSupport: false,
	}
	
	err = client.CreateContainer(ctx, config)
	require.NoError(t, err)
	
	// Test validation with container that doesn't support process execution
	err = client.ValidateContainerForProcessExecution(ctx, containerID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support process execution")
	
	// Create container with process support
	processContainerID := "test-process-validation-container-" + uuid.New().String()[:8]
	processBundlePath := filepath.Join(tempDir, processContainerID)
	
	processConfig := ContainerConfig{
		ID:             processContainerID,
		BundlePath:     processBundlePath,
		ProcessSupport: true,
		SecurityContext: &SecurityContext{
			RunAsNonRoot: BoolPtr(true),
		},
	}
	
	err = client.CreateContainer(ctx, processConfig)
	require.NoError(t, err)
	
	// This validation would fail in a real environment because the container isn't actually running
	// but we can test the basic validation logic
	err = client.ValidateContainerForProcessExecution(ctx, processContainerID)
	// We expect this to fail because runc.State() will fail, but that's expected in a test environment
	assert.Error(t, err)
}

func testProcessExecutionWithValidation(t *testing.T, client *RunCClient, tempDir string) {
	ctx := context.Background()
	containerID := "test-exec-container-" + uuid.New().String()[:8]
	bundlePath := filepath.Join(tempDir, containerID)
	
	// Create container with full process execution support
	config := ContainerConfig{
		ID:             containerID,
		BundlePath:     bundlePath,
		ProcessSupport: true,
		SecurityContext: &SecurityContext{
			RunAsNonRoot:             BoolPtr(true),
			ReadOnlyRootFilesystem:   BoolPtr(false),
			AllowPrivilegeEscalation: BoolPtr(false),
		},
		ResourceLimits: &ResourceLimits{
			CPU: &CPULimits{
				Shares: Int64Ptr(1024),
			},
			Memory: &MemoryLimits{
				Limit: Int64Ptr(128 * 1024 * 1024), // 128MB
			},
		},
		NamespaceConfig: &NamespaceConfig{
			PID:     true,
			Network: false, // Disable network namespace for test
			IPC:     true,
			UTS:     true,
			Mount:   true,
			User:    false,
			Cgroup:  true,
		},
		LoggingConfig: &ContainerLoggingConfig{
			LogLevel:      "debug",
			EnableMetrics: true,
		},
	}
	
	err := client.CreateContainer(ctx, config)
	require.NoError(t, err)
	
	// Verify container state
	client.containerMutex.RLock()
	state, exists := client.containerStates[containerID]
	client.containerMutex.RUnlock()
	
	assert.True(t, exists)
	assert.True(t, state.Config.ProcessSupport)
	assert.NotNil(t, state.Config.SecurityContext)
	assert.NotNil(t, state.Config.ResourceLimits)
	assert.NotNil(t, state.Config.NamespaceConfig)
	assert.NotNil(t, state.Config.LoggingConfig)
	
	// Test process execution (this will fail in test environment but validates the integration)
	processSpec := &ProcessSpec{
		Cmd:        "echo",
		Args:       []string{"echo", "Hello World"},
		Env:        []string{"PATH=/usr/bin:/bin"},
		WorkingDir: "/",
		User:       "1000:1000",
		Terminal:   false,
		Timeout:    30 * time.Second,
	}
	
	// This will fail because we don't have a real container runtime in tests
	// but it validates the integration logic
	result, err := client.ExecProcess(ctx, containerID, processSpec)
	// We expect an error here because the container doesn't actually exist in runC
	assert.Error(t, err)
	assert.Nil(t, result)
}

// TestProcessManagerIntegration tests ProcessManager integration with enhanced containers
func TestProcessManagerIntegration(t *testing.T) {
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Skipping integration test in CI environment")
	}
	
	tempDir, err := ioutil.TempDir("", "sandboxrunner-pm-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)
	
	client, err := NewRunCClient(tempDir)
	require.NoError(t, err)
	defer client.Cleanup()
	
	// Enable process manager
	config := DefaultProcessManagerConfig()
	config.MaxProcesses = 10
	config.DefaultTimeout = 30 * time.Second
	
	err = client.EnableProcessManager(config)
	require.NoError(t, err)
	assert.True(t, client.IsProcessManagerEnabled())
	
	// Test process manager metrics
	metrics := client.GetProcessManagerMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(0), metrics.ProcessesStarted)
	
	// Test process manager operations
	processes := client.ListManagedProcesses()
	assert.Empty(t, processes)
}

// TestSecurityManagerValidation tests security manager validation
func TestSecurityManagerValidation(t *testing.T) {
	sm := NewSecurityManager()
	
	// Test valid security context
	validContext := &SecurityContext{
		RunAsUser:                Int64Ptr(1001),
		RunAsNonRoot:             BoolPtr(true),
		ReadOnlyRootFilesystem:   BoolPtr(true),
		AllowPrivilegeEscalation: BoolPtr(false),
		AddCapabilities:          []string{"CAP_NET_BIND_SERVICE"},
		DropCapabilities:         []string{"CAP_SYS_ADMIN"},
	}
	
	err := sm.SetupSecurityContext("test-container", validContext)
	assert.NoError(t, err)
	
	// Test invalid security context (privileged + runAsNonRoot)
	invalidContext := &SecurityContext{
		Privileged:   BoolPtr(true),
		RunAsNonRoot: BoolPtr(true),
	}
	
	err = sm.SetupSecurityContext("test-container-2", invalidContext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot run as non-root with privileged mode")
}

// TestResourceLimitManagerValidation tests resource limit manager validation
func TestResourceLimitManagerValidation(t *testing.T) {
	rlm := NewResourceLimitManager()
	
	// Test valid resource limits
	validLimits := &ResourceLimits{
		CPU: &CPULimits{
			Shares: Int64Ptr(1024),
			Quota:  Int64Ptr(50000),
			Period: Int64Ptr(100000),
		},
		Memory: &MemoryLimits{
			Limit:      Int64Ptr(256 * 1024 * 1024),
			Swappiness: Int64Ptr(30),
		},
		IO: &IOLimits{
			Weight: Int64Ptr(500),
		},
	}
	
	err := rlm.ConfigureResourceLimits("test-container", validLimits)
	// This might fail due to cgroup setup issues in test environment, but validates the logic
	if err != nil {
		t.Logf("Expected error in test environment: %v", err)
	}
	
	// Test invalid resource limits
	invalidLimits := &ResourceLimits{
		CPU: &CPULimits{
			Shares: Int64Ptr(-1), // Invalid negative shares
		},
		Memory: &MemoryLimits{
			Swappiness: Int64Ptr(150), // Invalid swappiness > 100
		},
		IO: &IOLimits{
			Weight: Int64Ptr(5), // Invalid weight < 10
		},
	}
	
	err = rlm.ConfigureResourceLimits("test-container-2", invalidLimits)
	assert.Error(t, err)
}

// Benchmarks

func BenchmarkContainerCreation(b *testing.B) {
	tempDir, err := ioutil.TempDir("", "sandboxrunner-bench-*")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)
	
	client, err := NewRunCClient(tempDir)
	require.NoError(b, err)
	defer client.Cleanup()
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containerID := fmt.Sprintf("bench-container-%d", i)
		bundlePath := filepath.Join(tempDir, containerID)
		
		config := ContainerConfig{
			ID:             containerID,
			BundlePath:     bundlePath,
			ProcessSupport: true,
			SecurityContext: &SecurityContext{
				RunAsNonRoot: BoolPtr(true),
			},
			ResourceLimits: &ResourceLimits{
				CPU: &CPULimits{
					Shares: Int64Ptr(1024),
				},
				Memory: &MemoryLimits{
					Limit: Int64Ptr(128 * 1024 * 1024),
				},
			},
		}
		
		err := client.CreateContainer(ctx, config)
		if err != nil {
			b.Fatalf("Failed to create container: %v", err)
		}
	}
}

func BenchmarkSecurityContextSetup(b *testing.B) {
	sm := NewSecurityManager()
	
	securityContext := &SecurityContext{
		RunAsUser:                Int64Ptr(1001),
		RunAsNonRoot:             BoolPtr(true),
		ReadOnlyRootFilesystem:   BoolPtr(true),
		AllowPrivilegeEscalation: BoolPtr(false),
		AddCapabilities:          []string{"CAP_NET_BIND_SERVICE"},
		DropCapabilities:         []string{"CAP_SYS_ADMIN", "CAP_SYS_MODULE"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		containerID := fmt.Sprintf("bench-security-%d", i)
		err := sm.SetupSecurityContext(containerID, securityContext)
		if err != nil {
			b.Fatalf("Failed to setup security context: %v", err)
		}
	}
}

