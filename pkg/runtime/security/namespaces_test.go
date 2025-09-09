package security

import (
	"fmt"
	"testing"
	"time"
)

func TestNewNamespaceManager(t *testing.T) {
	nm := NewNamespaceManager()
	
	if nm == nil {
		t.Fatal("NewNamespaceManager returned nil")
	}
	
	if nm.containerConfigs == nil {
		t.Error("containerConfigs map not initialized")
	}
	
	if nm.activeNamespaces == nil {
		t.Error("activeNamespaces map not initialized")
	}
	
	if nm.defaultConfig == nil {
		t.Error("defaultConfig not initialized")
	}
	
	// Test default configuration
	if !nm.defaultConfig.PID {
		t.Error("PID namespace should be enabled by default")
	}
	
	if !nm.defaultConfig.Mount {
		t.Error("Mount namespace should be enabled by default")
	}
	
	if nm.defaultConfig.User {
		t.Error("User namespace should be disabled by default")
	}
}

func TestSetupNamespaces(t *testing.T) {
	nm := NewNamespaceManager()
	containerID := "test-container-123"
	
	config := &NamespaceConfig{
		PID:     true,
		Mount:   true,
		Network: true,
		IPC:     true,
		UTS:     true,
		User:    false,
		Cgroup:  true,
	}
	
	err := nm.SetupNamespaces(containerID, config)
	if err != nil {
		t.Fatalf("SetupNamespaces failed: %v", err)
	}
	
	// Verify configuration was stored
	nm.mu.RLock()
	storedConfig, exists := nm.containerConfigs[containerID]
	nm.mu.RUnlock()
	
	if !exists {
		t.Error("Configuration was not stored")
	}
	
	if storedConfig.PID != config.PID {
		t.Error("PID namespace configuration not preserved")
	}
	
	// Verify active namespaces were created
	nm.mu.RLock()
	namespaces, hasNamespaces := nm.activeNamespaces[containerID]
	nm.mu.RUnlock()
	
	if !hasNamespaces {
		t.Error("Active namespaces were not created")
	}
	
	if len(namespaces) == 0 {
		t.Error("No active namespaces were created")
	}
}

func TestValidateNamespaces(t *testing.T) {
	nm := NewNamespaceManager()
	containerID := "test-container-validation"
	
	// Test validation without setup
	result, err := nm.ValidateNamespaces(containerID)
	if err != nil {
		t.Fatalf("ValidateNamespaces failed: %v", err)
	}
	
	if result.Valid {
		t.Error("Validation should fail for non-existent container")
	}
	
	if len(result.Errors) == 0 {
		t.Error("Should have validation errors for non-existent container")
	}
	
	// Setup namespaces first
	config := &NamespaceConfig{
		PID:   true,
		Mount: true,
		UTS:   true,
	}
	
	err = nm.SetupNamespaces(containerID, config)
	if err != nil {
		t.Fatalf("SetupNamespaces failed: %v", err)
	}
	
	// Test validation after setup
	result, err = nm.ValidateNamespaces(containerID)
	if err != nil {
		t.Fatalf("ValidateNamespaces failed after setup: %v", err)
	}
	
	if !result.Valid {
		t.Errorf("Validation should pass after setup. Errors: %v", result.Errors)
	}
	
	if len(result.Supported) == 0 {
		t.Error("Supported namespaces should be populated")
	}
}

func TestGetNamespaceInfo(t *testing.T) {
	nm := NewNamespaceManager()
	containerID := "test-container-info"
	
	// Test info for non-existent container
	_, err := nm.GetNamespaceInfo(containerID)
	if err == nil {
		t.Error("Should return error for non-existent container")
	}
	
	// Setup namespaces
	config := &NamespaceConfig{
		PID:     true,
		Network: true,
		UTS:     true,
	}
	
	err = nm.SetupNamespaces(containerID, config)
	if err != nil {
		t.Fatalf("SetupNamespaces failed: %v", err)
	}
	
	// Get namespace info
	infos, err := nm.GetNamespaceInfo(containerID)
	if err != nil {
		t.Fatalf("GetNamespaceInfo failed: %v", err)
	}
	
	if len(infos) == 0 {
		t.Error("Should return namespace information")
	}
	
	// Verify namespace types
	foundTypes := make(map[NamespaceType]bool)
	for _, info := range infos {
		foundTypes[info.Type] = true
		
		if info.Path == "" {
			t.Errorf("Namespace path should not be empty for type %s", info.Type)
		}
	}
	
	expectedTypes := []NamespaceType{PIDNamespace, NetworkNamespace, UTSNamespace}
	for _, expectedType := range expectedTypes {
		if !foundTypes[expectedType] {
			t.Errorf("Expected namespace type %s not found", expectedType)
		}
	}
}

func TestCleanupNamespaces(t *testing.T) {
	nm := NewNamespaceManager()
	containerID := "test-container-cleanup"
	
	// Setup namespaces first
	config := &NamespaceConfig{
		PID:   true,
		Mount: true,
	}
	
	err := nm.SetupNamespaces(containerID, config)
	if err != nil {
		t.Fatalf("SetupNamespaces failed: %v", err)
	}
	
	// Verify setup
	nm.mu.RLock()
	_, configExists := nm.containerConfigs[containerID]
	_, namespacesExist := nm.activeNamespaces[containerID]
	nm.mu.RUnlock()
	
	if !configExists || !namespacesExist {
		t.Fatal("Setup verification failed")
	}
	
	// Test cleanup
	err = nm.CleanupNamespaces(containerID)
	if err != nil {
		t.Fatalf("CleanupNamespaces failed: %v", err)
	}
	
	// Verify cleanup
	nm.mu.RLock()
	_, configStillExists := nm.containerConfigs[containerID]
	_, namespacesStillExist := nm.activeNamespaces[containerID]
	nm.mu.RUnlock()
	
	if configStillExists {
		t.Error("Configuration should be cleaned up")
	}
	
	if namespacesStillExist {
		t.Error("Active namespaces should be cleaned up")
	}
}

func TestNamespaceConfigValidation(t *testing.T) {
	nm := NewNamespaceManager()
	
	testCases := []struct {
		name        string
		config      *NamespaceConfig
		shouldFail  bool
		description string
	}{
		{
			name: "valid basic config",
			config: &NamespaceConfig{
				PID:   true,
				Mount: true,
			},
			shouldFail:  false,
			description: "Basic valid configuration should pass",
		},
		{
			name: "user namespace with valid mapping",
			config: &NamespaceConfig{
				User: true,
				UserNamespaceMapping: &UserNamespaceMapping{
					UIDs: []IDMapping{{ContainerID: 0, HostID: 1000, Size: 1}},
					GIDs: []IDMapping{{ContainerID: 0, HostID: 1000, Size: 1}},
				},
			},
			shouldFail:  false,
			description: "User namespace with valid mapping should pass",
		},
		{
			name: "user namespace with invalid mapping",
			config: &NamespaceConfig{
				User: true,
				UserNamespaceMapping: &UserNamespaceMapping{
					UIDs: []IDMapping{{ContainerID: -1, HostID: 1000, Size: 1}},
				},
			},
			shouldFail:  true,
			description: "User namespace with invalid mapping should fail",
		},
		{
			name: "all namespaces enabled",
			config: &NamespaceConfig{
				PID:     true,
				Mount:   true,
				Network: true,
				IPC:     true,
				UTS:     true,
				User:    false, // Keep disabled to avoid mapping requirements
				Cgroup:  true,
			},
			shouldFail:  false,
			description: "All non-user namespaces enabled should pass",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := nm.validateNamespaceConfig(tc.config)
			
			if tc.shouldFail && result.Valid {
				t.Errorf("%s: expected validation to fail but it passed", tc.description)
			}
			
			if !tc.shouldFail && !result.Valid {
				t.Errorf("%s: expected validation to pass but it failed. Errors: %v", tc.description, result.Errors)
			}
		})
	}
}

func TestUserNamespaceMapping(t *testing.T) {
	nm := NewNamespaceManager()
	
	testCases := []struct {
		name     string
		mapping  *UserNamespaceMapping
		valid    bool
	}{
		{
			name: "valid mapping",
			mapping: &UserNamespaceMapping{
				UIDs: []IDMapping{{ContainerID: 0, HostID: 1000, Size: 1000}},
				GIDs: []IDMapping{{ContainerID: 0, HostID: 1000, Size: 1000}},
			},
			valid: true,
		},
		{
			name: "negative container ID",
			mapping: &UserNamespaceMapping{
				UIDs: []IDMapping{{ContainerID: -1, HostID: 1000, Size: 1000}},
			},
			valid: false,
		},
		{
			name: "negative host ID",
			mapping: &UserNamespaceMapping{
				UIDs: []IDMapping{{ContainerID: 0, HostID: -1, Size: 1000}},
			},
			valid: false,
		},
		{
			name: "zero size",
			mapping: &UserNamespaceMapping{
				UIDs: []IDMapping{{ContainerID: 0, HostID: 1000, Size: 0}},
			},
			valid: false,
		},
		{
			name: "negative size",
			mapping: &UserNamespaceMapping{
				GIDs: []IDMapping{{ContainerID: 0, HostID: 1000, Size: -1}},
			},
			valid: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := nm.validateUserNamespaceMapping(tc.mapping)
			
			if tc.valid && err != nil {
				t.Errorf("Expected mapping to be valid, but got error: %v", err)
			}
			
			if !tc.valid && err == nil {
				t.Error("Expected mapping to be invalid, but validation passed")
			}
		})
	}
}

func TestMergeWithDefaults(t *testing.T) {
	nm := NewNamespaceManager()
	
	// Test with config that enables specific namespaces
	config := &NamespaceConfig{
		PID:     true,
		Mount:   true,
		Network: true,
		UTS:     true,
	}
	
	merged := nm.mergeWithDefaults(config)
	
	if merged.PID != true {
		t.Error("PID setting should be preserved")
	}
	
	if merged.Mount && merged.MountConfig == nil {
		t.Error("Default MountConfig should be applied when Mount is enabled")
	}
	
	if merged.Network && merged.NetworkConfig == nil {
		t.Error("Default NetworkConfig should be applied when Network is enabled")
	}
	
	if merged.UTS && merged.UTSConfig == nil {
		t.Error("Default UTSConfig should be applied when UTS is enabled")
	}
	
	// Test default mount config (only when Mount is enabled)
	if merged.Mount && merged.MountConfig != nil {
		if len(merged.MountConfig.ReadOnlyPaths) == 0 {
			t.Error("Default read-only paths should be set")
		}
		
		if len(merged.MountConfig.MaskedPaths) == 0 {
			t.Error("Default masked paths should be set")
		}
	}
	
	// Test default network config (only when Network is enabled)
	if merged.Network && merged.NetworkConfig != nil {
		if merged.NetworkConfig.Type != "none" {
			t.Error("Default network type should be 'none'")
		}
	}
	
	// Test default UTS config (only when UTS is enabled)
	if merged.UTS && merged.UTSConfig != nil {
		if merged.UTSConfig.Hostname != "sandbox" {
			t.Error("Default hostname should be 'sandbox'")
		}
	}
}

func TestNamespaceSupport(t *testing.T) {
	nm := NewNamespaceManager()
	
	// Test system support detection
	if len(nm.systemSupport) == 0 {
		t.Error("System support detection should populate systemSupport map")
	}
	
	// Test common namespaces that should be supported on most Linux systems
	commonNamespaces := []NamespaceType{
		PIDNamespace,
		MountNamespace,
		NetworkNamespace,
		IPCNamespace,
		UTSNamespace,
	}
	
	for _, nsType := range commonNamespaces {
		if _, exists := nm.systemSupport[nsType]; !exists {
			t.Errorf("System support check should include %s namespace", nsType)
		}
	}
}

func TestUtilityFunctions(t *testing.T) {
	// Test BoolPtr
	b := true
	ptr := BoolPtr(b)
	if ptr == nil || *ptr != b {
		t.Error("BoolPtr failed")
	}
	
	// Test StringPtr
	s := "test"
	sPtr := StringPtr(s)
	if sPtr == nil || *sPtr != s {
		t.Error("StringPtr failed")
	}
	
	// Test IntPtr
	i := 42
	iPtr := IntPtr(i)
	if iPtr == nil || *iPtr != i {
		t.Error("IntPtr failed")
	}
	
	// Test Int64Ptr
	i64 := int64(42)
	i64Ptr := Int64Ptr(i64)
	if i64Ptr == nil || *i64Ptr != i64 {
		t.Error("Int64Ptr failed")
	}
}

func TestConcurrentAccess(t *testing.T) {
	nm := NewNamespaceManager()
	
	// Test concurrent setup and cleanup
	done := make(chan bool, 10)
	
	for i := 0; i < 10; i++ {
		go func(id int) {
			containerID := fmt.Sprintf("concurrent-test-%d", id)
			config := &NamespaceConfig{
				PID:   true,
				Mount: true,
			}
			
			err := nm.SetupNamespaces(containerID, config)
			if err != nil {
				t.Errorf("Concurrent setup failed for %s: %v", containerID, err)
			}
			
			// Small delay
			time.Sleep(10 * time.Millisecond)
			
			err = nm.CleanupNamespaces(containerID)
			if err != nil {
				t.Errorf("Concurrent cleanup failed for %s: %v", containerID, err)
			}
			
			done <- true
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent test timed out")
		}
	}
}

func TestNamespaceExtractionAndProcessCount(t *testing.T) {
	nm := NewNamespaceManager()
	
	// Test namespace ID extraction
	testCases := []struct {
		path       string
		expectedID string
	}{
		{"/proc/12345/ns/pid", "12345"},
		{"/proc/1/ns/mnt", "1"},
		{"/invalid/path", ""},
		{"", ""},
	}
	
	for _, tc := range testCases {
		id := nm.extractNamespaceID(tc.path)
		if id != tc.expectedID {
			t.Errorf("Expected ID %s for path %s, got %s", tc.expectedID, tc.path, id)
		}
	}
	
	// Test process count (placeholder implementation)
	count, err := nm.getNamespaceProcessCount("/proc/self/ns/pid", PIDNamespace)
	if err != nil {
		t.Errorf("getNamespaceProcessCount failed: %v", err)
	}
	
	if count < 0 {
		t.Error("Process count should be non-negative")
	}
}