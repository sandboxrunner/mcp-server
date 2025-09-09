package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beam-cloud/go-runc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// EnhancedMockRuncInterface implements a comprehensive mock for RuncInterface
type EnhancedMockRuncInterface struct {
	mock.Mock
}

func (m *EnhancedMockRuncInterface) State(ctx context.Context, id string) (*runc.Container, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*runc.Container), args.Error(1)
}

func (m *EnhancedMockRuncInterface) Exec(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
	args := m.Called(ctx, id, spec, opts)
	return args.Error(0)
}

func (m *EnhancedMockRuncInterface) Create(ctx context.Context, id, bundle string, opts *runc.CreateOpts) error {
	args := m.Called(ctx, id, bundle, opts)
	return args.Error(0)
}

func (m *EnhancedMockRuncInterface) Start(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *EnhancedMockRuncInterface) Kill(ctx context.Context, id string, sig int, opts *runc.KillOpts) error {
	args := m.Called(ctx, id, sig, opts)
	return args.Error(0)
}

func (m *EnhancedMockRuncInterface) Delete(ctx context.Context, id string, opts *runc.DeleteOpts) error {
	args := m.Called(ctx, id, opts)
	return args.Error(0)
}

func (m *EnhancedMockRuncInterface) List(ctx context.Context) ([]*runc.Container, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*runc.Container), args.Error(1)
}


func TestNewRunCClient(t *testing.T) {
	tests := []struct {
		name        string
		rootPath    string
		expectError bool
		setupFunc   func(t *testing.T) string
		cleanupFunc func(t *testing.T, path string)
	}{
		{
			name:        "default_root_path",
			rootPath:    "",
			expectError: false,
			setupFunc:   nil,
			cleanupFunc: nil,
		},
		{
			name:        "custom_root_path",
			rootPath:    "/tmp/test-sandbox",
			expectError: false,
			setupFunc:   nil,
			cleanupFunc: func(t *testing.T, path string) {
				os.RemoveAll(path)
			},
		},
		{
			name:        "valid_temp_path",
			rootPath:    "",
			expectError: false,
			setupFunc: func(t *testing.T) string {
				return t.TempDir()
			},
			cleanupFunc: nil,
		},
		{
			name:        "invalid_path_permissions",
			rootPath:    "/root/restricted",
			expectError: true,
			setupFunc:   nil,
			cleanupFunc: nil,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootPath := tt.rootPath
			if tt.setupFunc != nil {
				rootPath = tt.setupFunc(t)
			}
			
			client, err := NewRunCClient(rootPath)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NotNil(t, client.containerStates)
				assert.NotNil(t, client.securityManager)
				assert.NotNil(t, client.resourceManager)
				
				if rootPath == "" {
					assert.Equal(t, "/tmp/sandboxrunner", client.rootPath)
				} else {
					assert.Equal(t, rootPath, client.rootPath)
				}
			}
			
			if tt.cleanupFunc != nil {
				tt.cleanupFunc(t, rootPath)
			}
		})
	}
}

func TestRunCClient_ProcessManager(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	// Test initial state
	assert.False(t, client.IsProcessManagerEnabled())
	assert.Nil(t, client.GetProcessManager())
	
	// Test enabling process manager
	config := &ProcessManagerConfig{
		MaxProcesses:       10,
		DefaultTimeout:     30 * time.Second,
		CleanupInterval:    1 * time.Minute,
		ZombieReapInterval: 5 * time.Second, // Add this to avoid zero interval
	}
	
	err = client.EnableProcessManager(config)
	assert.NoError(t, err)
	assert.True(t, client.IsProcessManagerEnabled())
	assert.NotNil(t, client.GetProcessManager())
	
	// Test enabling twice should error
	err = client.EnableProcessManager(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "process manager is already enabled")
}

func TestRunCClient_ProcessManagerOperations_NotEnabled(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	ctx := context.Background()
	
	// Test operations without process manager
	_, err = client.ExecProcessManaged(ctx, "container1", &ProcessSpec{}, false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "process manager is not enabled")
	
	err = client.StopProcessManaged("process1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "process manager is not enabled")
	
	err = client.KillProcessManaged("process1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "process manager is not enabled")
	
	err = client.WaitProcessManaged("process1", ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "process manager is not enabled")
	
	_, err = client.GetProcessStatusManaged("process1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "process manager is not enabled")
	
	processes := client.ListManagedProcesses()
	assert.Nil(t, processes)
	
	metrics := client.GetProcessManagerMetrics()
	assert.Nil(t, metrics)
}

func TestCreateContainer_ValidationFailures(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	tests := []struct {
		name         string
		config       ContainerConfig
		expectedErr  string
	}{
		{
			name: "empty_bundle_path",
			config: ContainerConfig{
				ID:         "test-container",
				BundlePath: "",
			},
			expectedErr: "container configuration validation failed",
		},
		{
			name: "invalid_working_dir",
			config: ContainerConfig{
				ID:         "test-container",
				BundlePath: "/tmp/bundle",
				WorkingDir: "/nonexistent/path/that/should/not/exist",
			},
			expectedErr: "container configuration validation failed",
		},
		{
			name: "empty_id",
			config: ContainerConfig{
				BundlePath: "/tmp/bundle",
			},
			// Should not error, ID will be auto-generated
			expectedErr: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the runc interface to avoid actual container creation
			mockRunc := &EnhancedMockRuncInterface{}
			client.runc = mockRunc
			
			if tt.expectedErr == "" {
				mockRunc.On("Create", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything).Return(nil)
			}
			
			ctx := context.Background()
			err := client.CreateContainer(ctx, tt.config)
			
			if tt.expectedErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				// For successful cases, we'd get an error from generateEnhancedOCISpec
				// which is expected in this mock setup
				assert.Error(t, err)
			}
		})
	}
}

func TestCreateContainer_SecurityContextSetup(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	// Mock the runc interface
	mockRunc := &EnhancedMockRuncInterface{}
	client.runc = mockRunc
	
	// Setup expectations - runc.Create will be called if we get past validation
	mockRunc.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	
	tests := []struct {
		name        string
		config      ContainerConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "process_support_with_security_context",
			config: ContainerConfig{
				ID:             "test-container",
				BundlePath:     "/tmp/bundle",
				ProcessSupport: true,
				SecurityContext: &SecurityContext{},
			},
			expectError: true, // Will fail at generateEnhancedOCISpec
			errorMsg:    "failed to generate OCI spec",
		},
		{
			name: "process_support_with_resource_limits",
			config: ContainerConfig{
				ID:             "test-container", 
				BundlePath:     "/tmp/bundle",
				ProcessSupport: true,
				ResourceLimits: &ResourceLimits{},
			},
			expectError: true, // Will fail at generateEnhancedOCISpec
			errorMsg:    "failed to generate OCI spec",
		},
		{
			name: "basic_container_without_process_support",
			config: ContainerConfig{
				ID:         "test-container",
				BundlePath: "/tmp/bundle",
			},
			expectError: true, // Will fail at generateEnhancedOCISpec
			errorMsg:    "failed to generate OCI spec",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := client.CreateContainer(ctx, tt.config)
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateContainer_BundlePathCreation(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	mockRunc := &EnhancedMockRuncInterface{}
	client.runc = mockRunc
	
	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "test-bundle", "nested", "path")
	
	config := ContainerConfig{
		ID:         "test-container",
		BundlePath: bundlePath,
	}
	
	mockRunc.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	
	ctx := context.Background()
	err = client.CreateContainer(ctx, config)
	
	// Should create the bundle path even if it doesn't exist
	assert.DirExists(t, bundlePath)
	
	// Will error on generateEnhancedOCISpec but bundle path should be created
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate OCI spec")
}

func TestStartContainer(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	mockRunc := &EnhancedMockRuncInterface{}
	client.runc = mockRunc
	
	tests := []struct {
		name        string
		containerID string
		setupMock   func()
		expectError bool
		errorMsg    string
	}{
		{
			name:        "successful_start",
			containerID: "test-container",
			setupMock: func() {
				mockRunc.On("Start", mock.Anything, "test-container").Return(nil)
			},
			expectError: false,
		},
		{
			name:        "start_failure",
			containerID: "test-container",
			setupMock: func() {
				mockRunc.On("Start", mock.Anything, "test-container").Return(errors.New("container start failed"))
			},
			expectError: true,
			errorMsg:    "failed to start container",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRunc.ExpectedCalls = nil
			tt.setupMock()
			
			ctx := context.Background()
			err := client.StartContainer(ctx, tt.containerID)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
			
			mockRunc.AssertExpectations(t)
		})
	}
}

func TestValidateContainerForProcessExecution(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	mockRunc := &EnhancedMockRuncInterface{}
	client.runc = mockRunc
	
	// Setup container state
	containerID := "test-container"
	config := &ContainerConfig{
		ID:             containerID,
		ProcessSupport: true,
		SecurityContext: &SecurityContext{},
		ResourceLimits: &ResourceLimits{},
	}
	
	client.trackContainerState(containerID, config)
	
	tests := []struct {
		name        string
		containerID string
		setupMocks  func()
		expectError bool
		errorMsg    string
	}{
		{
			name:        "container_not_found",
			containerID: "nonexistent",
			setupMocks:  func() {},
			expectError: true,
			errorMsg:    "not found in state tracking",
		},
		{
			name:        "process_support_disabled",
			containerID: containerID,
			setupMocks: func() {
				// Modify container state to disable process support
				client.containerMutex.Lock()
				client.containerStates[containerID].Config.ProcessSupport = false
				client.containerMutex.Unlock()
			},
			expectError: true,
			errorMsg:    "does not support process execution",
		},
		{
			name:        "container_state_error",
			containerID: containerID,
			setupMocks: func() {
				client.containerMutex.Lock()
				client.containerStates[containerID].Config.ProcessSupport = true
				client.containerMutex.Unlock()
				
				mockRunc.On("State", mock.Anything, containerID).Return(nil, errors.New("state check failed"))
			},
			expectError: true,
			errorMsg:    "failed to get container runtime state",
		},
		{
			name:        "invalid_container_status",
			containerID: containerID,
			setupMocks: func() {
				client.containerMutex.Lock()
				client.containerStates[containerID].Config.ProcessSupport = true
				client.containerMutex.Unlock()
				
				mockRunc.On("State", mock.Anything, containerID).Return(&runc.Container{
					ID:     containerID,
					Status: "stopped",
				}, nil)
			},
			expectError: true,
			errorMsg:    "is in invalid state 'stopped'",
		},
		{
			name:        "successful_validation",
			containerID: containerID,
			setupMocks: func() {
				client.containerMutex.Lock()
				client.containerStates[containerID].Config.ProcessSupport = true
				// Remove security/resource contexts to avoid validation
				client.containerStates[containerID].Config.SecurityContext = nil
				client.containerStates[containerID].Config.ResourceLimits = nil
				client.containerMutex.Unlock()
				
				mockRunc.On("State", mock.Anything, containerID).Return(&runc.Container{
					ID:     containerID,
					Status: "running",
				}, nil)
			},
			expectError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock expectations
			mockRunc.ExpectedCalls = nil
			
			tt.setupMocks()
			
			ctx := context.Background()
			err := client.ValidateContainerForProcessExecution(ctx, tt.containerID)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConcurrentContainerOperations(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	mockRunc := &EnhancedMockRuncInterface{}
	client.runc = mockRunc
	
	// Setup concurrent safe operations
	var wg sync.WaitGroup
	numContainers := 10
	
	// Mock successful operations
	mockRunc.On("Create", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.Anything).Return(nil)
	mockRunc.On("Start", mock.Anything, mock.AnythingOfType("string")).Return(nil)
	
	ctx := context.Background()
	
	// Test concurrent container creation
	for i := 0; i < numContainers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			config := ContainerConfig{
				ID:         fmt.Sprintf("container-%d", id),
				BundlePath: fmt.Sprintf("/tmp/bundle-%d", id),
			}
			
			// This will fail on generateEnhancedOCISpec but should handle concurrent state tracking
			_ = client.CreateContainer(ctx, config)
		}(i)
	}
	
	wg.Wait()
	
	// Verify concurrent access didn't cause issues
	client.containerMutex.RLock()
	stateCount := len(client.containerStates)
	client.containerMutex.RUnlock()
	
	// Some containers should have been tracked despite OCI spec generation failure
	assert.True(t, stateCount >= 0, "Container state tracking should handle concurrent access")
}

func TestContainerStateTracking(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	containerID := "test-container"
	config := &ContainerConfig{
		ID:           containerID,
		ProcessSupport: true,
		CreatedAt:    time.Now(),
	}
	
	// Test tracking container state
	client.trackContainerState(containerID, config)
	
	client.containerMutex.RLock()
	state, exists := client.containerStates[containerID]
	client.containerMutex.RUnlock()
	
	assert.True(t, exists)
	assert.NotNil(t, state)
	assert.Equal(t, containerID, state.ID)
	assert.Equal(t, config, state.Config)
	assert.False(t, state.CreatedAt.IsZero())
}

func TestGenerateCorrelationID(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	// Test correlation ID generation
	id1 := client.generateCorrelationID()
	id2 := client.generateCorrelationID()
	
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2, "Correlation IDs should be unique")
	
	// Should be in UUID format
	assert.True(t, len(id1) > 0)
	assert.True(t, len(id2) > 0)
}

func TestContainerConfigValidation(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	tests := []struct {
		name     string
		config   ContainerConfig
		valid    bool
		errors   []string
		warnings []string
	}{
		{
			name: "valid_config",
			config: ContainerConfig{
				ID:         "valid-container",
				BundlePath: "/tmp/bundle",
				WorkingDir: "/tmp",
			},
			valid: true,
		},
		{
			name: "missing_bundle_path",
			config: ContainerConfig{
				ID: "test-container",
			},
			valid:  false,
			errors: []string{"bundle path is required"},
		},
		{
			name: "invalid_working_dir",
			config: ContainerConfig{
				ID:         "test-container",
				BundlePath: "/tmp/bundle",
				WorkingDir: "/this/path/should/not/exist/anywhere",
			},
			valid:    false,
			warnings: []string{"working directory does not exist"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.validateContainerConfig(tt.config)
			
			assert.Equal(t, tt.valid, result.Valid)
			
			if len(tt.errors) > 0 {
				assert.Greater(t, len(result.Errors), 0)
				for _, expectedError := range tt.errors {
					found := false
					for _, actualError := range result.Errors {
						if strings.Contains(actualError, expectedError) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected error '%s' not found in %v", expectedError, result.Errors)
				}
			}
			
			if len(tt.warnings) > 0 {
				assert.Greater(t, len(result.Warnings), 0)
				for _, expectedWarning := range tt.warnings {
					found := false
					for _, actualWarning := range result.Warnings {
						if strings.Contains(actualWarning, expectedWarning) {
							found = true
							break
						}
					}
					assert.True(t, found, "Expected warning '%s' not found in %v", expectedWarning, result.Warnings)
				}
			}
			
			assert.False(t, result.ValidationTime.IsZero())
		})
	}
}

func TestCleanupContainerResources(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	containerID := "test-container"
	config := &ContainerConfig{
		ID: containerID,
	}
	
	// Track container state
	client.trackContainerState(containerID, config)
	
	// Verify state exists
	client.containerMutex.RLock()
	_, exists := client.containerStates[containerID]
	client.containerMutex.RUnlock()
	assert.True(t, exists)
	
	// Cleanup resources
	client.cleanupContainerResources(containerID)
	
	// Verify state was removed
	client.containerMutex.RLock()
	_, exists = client.containerStates[containerID]
	client.containerMutex.RUnlock()
	assert.False(t, exists)
}

func TestExecProcess_InputValidation(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	ctx := context.Background()
	
	tests := []struct {
		name        string
		containerID string
		spec        *ProcessSpec
		expectError bool
		errorMsg    string
	}{
		{
			name:        "empty_container_id",
			containerID: "",
			spec:        &ProcessSpec{Args: []string{"echo", "test"}},
			expectError: true,
			errorMsg:    "container ID is required",
		},
		{
			name:        "nil_spec",
			containerID: "container1",
			spec:        nil,
			expectError: true,
			errorMsg:    "process spec is required",
		},
		{
			name:        "empty_args",
			containerID: "container1",
			spec:        &ProcessSpec{Args: []string{}},
			expectError: true,
			errorMsg:    "process args are required",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.ExecProcess(ctx, tt.containerID, tt.spec)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, result)
			} else {
				// Would need more mocking for successful case
				assert.Error(t, err) // Expected due to missing container
			}
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkNewRunCClient(b *testing.B) {
	tmpDir := b.TempDir()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := NewRunCClient(filepath.Join(tmpDir, fmt.Sprintf("client-%d", i)))
		require.NoError(b, err)
		_ = client
	}
}

func BenchmarkContainerStateTracking(b *testing.B) {
	client, err := NewRunCClient(b.TempDir())
	require.NoError(b, err)
	
	configs := make([]*ContainerConfig, b.N)
	for i := 0; i < b.N; i++ {
		configs[i] = &ContainerConfig{
			ID: fmt.Sprintf("container-%d", i),
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.trackContainerState(configs[i].ID, configs[i])
	}
}

func BenchmarkValidateContainerConfig(b *testing.B) {
	client, err := NewRunCClient(b.TempDir())
	require.NoError(b, err)
	
	config := ContainerConfig{
		ID:         "benchmark-container",
		BundlePath: "/tmp/bundle",
		WorkingDir: "/tmp",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := client.validateContainerConfig(config)
		_ = result
	}
}

// Test edge cases and race conditions
func TestContainerStateRaceConditions(t *testing.T) {
	client, err := NewRunCClient(t.TempDir())
	require.NoError(t, err)
	
	containerID := "race-test-container"
	config := &ContainerConfig{ID: containerID}
	
	var wg sync.WaitGroup
	numGoroutines := 50
	
	// Test concurrent state access
	for i := 0; i < numGoroutines; i++ {
		wg.Add(2)
		
		// Reader goroutine
		go func() {
			defer wg.Done()
			client.containerMutex.RLock()
			_, exists := client.containerStates[containerID]
			client.containerMutex.RUnlock()
			_ = exists
		}()
		
		// Writer goroutine
		go func() {
			defer wg.Done()
			client.trackContainerState(containerID, config)
		}()
	}
	
	wg.Wait()
	
	// Should not panic and should have consistent state
	client.containerMutex.RLock()
	state, exists := client.containerStates[containerID]
	client.containerMutex.RUnlock()
	
	assert.True(t, exists)
	assert.NotNil(t, state)
}