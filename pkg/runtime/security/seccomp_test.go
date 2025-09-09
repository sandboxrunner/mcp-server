package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSeccompManager(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	
	if sm == nil {
		t.Fatal("NewSeccompManager returned nil")
	}
	
	if sm.containerConfigs == nil {
		t.Error("containerConfigs map not initialized")
	}
	
	if sm.containerProfiles == nil {
		t.Error("containerProfiles map not initialized")
	}
	
	if sm.activeFilters == nil {
		t.Error("activeFilters map not initialized")
	}
	
	if sm.profileTemplates == nil {
		t.Error("profileTemplates map not initialized")
	}
	
	// Test that profile templates were initialized
	if len(sm.profileTemplates) == 0 {
		t.Error("Profile templates should be initialized")
	}
	
	// Verify specific profile templates exist
	expectedProfiles := []SeccompProfileType{
		ProfileTypeDefault,
		ProfileTypeRestricted,
		ProfileTypeNetworking,
		ProfileTypeFilesystem,
		ProfileTypeCompute,
		ProfileTypePrivileged,
	}
	
	for _, profileType := range expectedProfiles {
		if _, exists := sm.profileTemplates[profileType]; !exists {
			t.Errorf("Profile template %s should be initialized", profileType)
		}
	}
}

func TestSetupSeccompFilter(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	containerID := "test-container-seccomp"
	
	config := &SeccompConfig{
		ProfileType:     ProfileTypeDefault,
		NoNewPrivs:      true,
		ViolationAction: SeccompActionErrno,
		AuditConfig: &SeccompAuditConfig{
			Enabled:       true,
			LogViolations: true,
		},
	}
	
	// Mock system support
	sm.systemSupport = true
	sm.supportedActions[SeccompActionErrno] = true
	
	err := sm.SetupSeccompFilter(containerID, config)
	if err != nil {
		t.Fatalf("SetupSeccompFilter failed: %v", err)
	}
	
	// Verify configuration was stored
	sm.mu.RLock()
	storedConfig, exists := sm.containerConfigs[containerID]
	profile, hasProfile := sm.containerProfiles[containerID]
	profilePath, hasPath := sm.activeFilters[containerID]
	sm.mu.RUnlock()
	
	if !exists {
		t.Error("Configuration was not stored")
	}
	
	if !hasProfile {
		t.Error("Profile was not stored")
	}
	
	if !hasPath {
		t.Error("Profile path was not stored")
	}
	
	if storedConfig.ProfileType != ProfileTypeDefault {
		t.Error("Profile type was not preserved")
	}
	
	if profile.DefaultAction == "" {
		t.Error("Profile should have default action")
	}
	
	// Check that profile file was created
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Error("Profile file should be created")
	}
}

func TestValidateSeccompFilter(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	containerID := "test-container-validation"
	
	// Mock system support
	sm.systemSupport = true
	sm.supportedActions[SeccompActionErrno] = true
	
	// Test validation without setup
	result, err := sm.ValidateSeccompFilter(containerID)
	if err != nil {
		t.Fatalf("ValidateSeccompFilter failed: %v", err)
	}
	
	if result.Valid {
		t.Error("Validation should fail for non-existent container")
	}
	
	if len(result.Errors) == 0 {
		t.Error("Should have validation errors for non-existent container")
	}
	
	// Setup seccomp filter first
	config := &SeccompConfig{
		ProfileType:     ProfileTypeRestricted,
		NoNewPrivs:      true,
		ViolationAction: SeccompActionKill,
	}
	
	sm.supportedActions[SeccompActionKill] = true
	
	err = sm.SetupSeccompFilter(containerID, config)
	if err != nil {
		t.Fatalf("SetupSeccompFilter failed: %v", err)
	}
	
	// Test validation after setup
	result, err = sm.ValidateSeccompFilter(containerID)
	if err != nil {
		t.Fatalf("ValidateSeccompFilter failed after setup: %v", err)
	}
	
	if !result.Valid {
		t.Errorf("Validation should pass after setup. Errors: %v", result.Errors)
	}
	
	if result.ProfileStats == nil {
		t.Error("Profile stats should be generated")
	}
}

func TestGetSeccompProfile(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	containerID := "test-container-profile"
	
	// Mock system support
	sm.systemSupport = true
	sm.supportedActions[SeccompActionErrno] = true
	
	// Test profile for non-existent container
	_, err := sm.GetSeccompProfile(containerID)
	if err == nil {
		t.Error("Should return error for non-existent container")
	}
	
	// Setup seccomp filter
	config := &SeccompConfig{
		ProfileType:     ProfileTypeDefault,
		DefaultAction:   SeccompActionErrno,
		NoNewPrivs:      true,
	}
	
	err = sm.SetupSeccompFilter(containerID, config)
	if err != nil {
		t.Fatalf("SetupSeccompFilter failed: %v", err)
	}
	
	// Get seccomp profile
	profile, err := sm.GetSeccompProfile(containerID)
	if err != nil {
		t.Fatalf("GetSeccompProfile failed: %v", err)
	}
	
	if profile == nil {
		t.Error("Profile should not be nil")
	}
	
	if profile.DefaultAction != SeccompActionErrno {
		t.Error("Default action should match configuration")
	}
	
	if len(profile.Syscalls) == 0 {
		t.Error("Profile should have syscall rules")
	}
}

func TestAuditSyscall(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	containerID := "test-container-audit"
	
	// Test auditing syscall
	sm.AuditSyscall(containerID, 1234, "open", SeccompActionAllow, []uint64{1, 2, 3})
	
	// Check audit log
	entries := sm.GetAuditLog(containerID, 10)
	if len(entries) == 0 {
		t.Error("Audit log should contain entry")
	}
	
	entry := entries[0]
	if entry.ContainerID != containerID {
		t.Error("Container ID should match")
	}
	
	if entry.PID != 1234 {
		t.Error("PID should match")
	}
	
	if entry.Syscall != "open" {
		t.Error("Syscall should match")
	}
	
	if entry.Action != SeccompActionAllow {
		t.Error("Action should match")
	}
	
	if len(entry.Args) != 3 {
		t.Error("Args should match")
	}
}

func TestSeccompConfigValidation(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	
	// Mock system support
	sm.systemSupport = true
	sm.supportedActions[SeccompActionErrno] = true
	sm.supportedActions[SeccompActionKill] = true
	
	testCases := []struct {
		name        string
		config      *SeccompConfig
		shouldFail  bool
		description string
	}{
		{
			name: "valid default profile",
			config: &SeccompConfig{
				ProfileType:     ProfileTypeDefault,
				NoNewPrivs:      true,
				ViolationAction: SeccompActionErrno,
			},
			shouldFail:  false,
			description: "Default profile should be valid",
		},
		{
			name: "empty profile type",
			config: &SeccompConfig{
				NoNewPrivs: true,
			},
			shouldFail:  true,
			description: "Empty profile type should fail",
		},
		{
			name: "unknown profile type",
			config: &SeccompConfig{
				ProfileType: "unknown_profile",
			},
			shouldFail:  true,
			description: "Unknown profile type should fail",
		},
		{
			name: "custom profile without profile or path",
			config: &SeccompConfig{
				ProfileType: ProfileTypeCustom,
			},
			shouldFail:  true,
			description: "Custom profile type without profile or path should fail",
		},
		{
			name: "custom profile with valid profile",
			config: &SeccompConfig{
				ProfileType: ProfileTypeCustom,
				CustomProfile: &SeccompProfile{
					DefaultAction: SeccompActionErrno,
					Syscalls: []SeccompSyscall{
						{
							Names:  []string{"read", "write"},
							Action: SeccompActionAllow,
						},
					},
				},
			},
			shouldFail:  false,
			description: "Custom profile with valid profile should pass",
		},
		{
			name: "unsupported default action",
			config: &SeccompConfig{
				ProfileType:   ProfileTypeDefault,
				DefaultAction: "UNSUPPORTED_ACTION",
			},
			shouldFail:  true,
			description: "Unsupported default action should fail",
		},
		{
			name: "unsupported violation action",
			config: &SeccompConfig{
				ProfileType:     ProfileTypeDefault,
				ViolationAction: "UNSUPPORTED_ACTION",
			},
			shouldFail:  true,
			description: "Unsupported violation action should fail",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := sm.validateSeccompConfig(tc.config)
			
			if tc.shouldFail && result.Valid {
				t.Errorf("%s: expected validation to fail but it passed", tc.description)
			}
			
			if !tc.shouldFail && !result.Valid {
				t.Errorf("%s: expected validation to pass but it failed. Errors: %v", tc.description, result.Errors)
			}
		})
	}
}

func TestSeccompProfileValidation(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	
	// Mock system support
	sm.supportedActions[SeccompActionAllow] = true
	sm.supportedActions[SeccompActionErrno] = true
	sm.supportedActions[SeccompActionKill] = true
	
	testCases := []struct {
		name        string
		profile     *SeccompProfile
		shouldFail  bool
		description string
	}{
		{
			name: "valid profile",
			profile: &SeccompProfile{
				DefaultAction: SeccompActionErrno,
				Syscalls: []SeccompSyscall{
					{
						Names:  []string{"read", "write"},
						Action: SeccompActionAllow,
					},
				},
			},
			shouldFail:  false,
			description: "Valid profile should pass",
		},
		{
			name: "unsupported default action",
			profile: &SeccompProfile{
				DefaultAction: "INVALID_ACTION",
			},
			shouldFail:  true,
			description: "Unsupported default action should fail",
		},
		{
			name: "syscall rule with no names",
			profile: &SeccompProfile{
				DefaultAction: SeccompActionErrno,
				Syscalls: []SeccompSyscall{
					{
						Names:  []string{},
						Action: SeccompActionAllow,
					},
				},
			},
			shouldFail:  true,
			description: "Syscall rule with no names should fail",
		},
		{
			name: "syscall rule with unsupported action",
			profile: &SeccompProfile{
				DefaultAction: SeccompActionErrno,
				Syscalls: []SeccompSyscall{
					{
						Names:  []string{"read"},
						Action: "INVALID_ACTION",
					},
				},
			},
			shouldFail:  true,
			description: "Syscall rule with unsupported action should fail",
		},
		{
			name: "syscall arg with invalid index",
			profile: &SeccompProfile{
				DefaultAction: SeccompActionErrno,
				Syscalls: []SeccompSyscall{
					{
						Names:  []string{"open"},
						Action: SeccompActionAllow,
						Args: []SeccompArg{
							{
								Index: 10, // Invalid, max is 5
								Value: 0,
								Op:    SeccompOpEqual,
							},
						},
					},
				},
			},
			shouldFail:  true,
			description: "Syscall arg with invalid index should fail",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := sm.validateSeccompProfile(tc.profile)
			
			if tc.shouldFail && err == nil {
				t.Errorf("%s: expected validation to fail but it passed", tc.description)
			}
			
			if !tc.shouldFail && err != nil {
				t.Errorf("%s: expected validation to pass but it failed: %v", tc.description, err)
			}
		})
	}
}

func TestProfileGeneration(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	containerID := "test-container-generation"
	
	// Mock system support
	sm.systemSupport = true
	
	testCases := []struct {
		name        string
		config      *SeccompConfig
		shouldFail  bool
		description string
	}{
		{
			name: "default profile",
			config: &SeccompConfig{
				ProfileType: ProfileTypeDefault,
			},
			shouldFail:  false,
			description: "Should generate default profile",
		},
		{
			name: "restricted profile",
			config: &SeccompConfig{
				ProfileType: ProfileTypeRestricted,
			},
			shouldFail:  false,
			description: "Should generate restricted profile",
		},
		{
			name: "networking profile",
			config: &SeccompConfig{
				ProfileType: ProfileTypeNetworking,
			},
			shouldFail:  false,
			description: "Should generate networking profile",
		},
		{
			name: "custom profile",
			config: &SeccompConfig{
				ProfileType: ProfileTypeCustom,
				CustomProfile: &SeccompProfile{
					DefaultAction: SeccompActionErrno,
					Syscalls: []SeccompSyscall{
						{
							Names:  []string{"read", "write", "close"},
							Action: SeccompActionAllow,
						},
					},
				},
			},
			shouldFail:  false,
			description: "Should use custom profile",
		},
		{
			name: "unknown profile type",
			config: &SeccompConfig{
				ProfileType: "unknown",
			},
			shouldFail:  true,
			description: "Should fail for unknown profile type",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			profile, err := sm.generateSeccompProfile(containerID, tc.config)
			
			if tc.shouldFail && err == nil {
				t.Errorf("%s: expected generation to fail but it passed", tc.description)
			}
			
			if !tc.shouldFail && err != nil {
				t.Errorf("%s: expected generation to pass but it failed: %v", tc.description, err)
			}
			
			if !tc.shouldFail && profile == nil {
				t.Errorf("%s: profile should not be nil", tc.description)
			}
			
			if !tc.shouldFail && profile != nil {
				if profile.DefaultAction == "" {
					t.Error("Generated profile should have default action")
				}
			}
		})
	}
}

func TestProfileIO(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	containerID := "test-container-io"
	
	// Create test profile
	profile := &SeccompProfile{
		DefaultAction: SeccompActionErrno,
		Architecture:  []SeccompArch{SeccompArchX86_64},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write", "close"},
				Action: SeccompActionAllow,
			},
			{
				Names:  []string{"ptrace"},
				Action: SeccompActionKill,
			},
		},
	}
	
	// Test writing profile
	profilePath, err := sm.writeSeccompProfile(containerID, profile)
	if err != nil {
		t.Fatalf("writeSeccompProfile failed: %v", err)
	}
	
	// Check file exists
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Error("Profile file should be created")
	}
	
	// Verify file content
	data, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("Failed to read profile file: %v", err)
	}
	
	var loadedProfile SeccompProfile
	if err := json.Unmarshal(data, &loadedProfile); err != nil {
		t.Fatalf("Failed to parse profile JSON: %v", err)
	}
	
	if loadedProfile.DefaultAction != profile.DefaultAction {
		t.Error("Default action should be preserved")
	}
	
	if len(loadedProfile.Syscalls) != len(profile.Syscalls) {
		t.Error("Syscalls should be preserved")
	}
	
	// Test loading profile from file
	testProfilePath := filepath.Join(tempDir, "test-profile.json")
	testData, _ := json.MarshalIndent(profile, "", "  ")
	os.WriteFile(testProfilePath, testData, 0644)
	
	loadedFromFile, err := sm.loadSeccompProfile(testProfilePath)
	if err != nil {
		t.Fatalf("loadSeccompProfile failed: %v", err)
	}
	
	if loadedFromFile.DefaultAction != profile.DefaultAction {
		t.Error("Loaded profile should match original")
	}
}

func TestCleanupSeccompFilter(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	containerID := "test-container-cleanup"
	
	// Mock system support
	sm.systemSupport = true
	sm.supportedActions[SeccompActionErrno] = true
	
	// Setup seccomp filter first
	config := &SeccompConfig{
		ProfileType:     ProfileTypeDefault,
		NoNewPrivs:      true,
		ViolationAction: SeccompActionErrno,
	}
	
	err := sm.SetupSeccompFilter(containerID, config)
	if err != nil {
		t.Fatalf("SetupSeccompFilter failed: %v", err)
	}
	
	// Verify setup
	sm.mu.RLock()
	_, configExists := sm.containerConfigs[containerID]
	_, profileExists := sm.containerProfiles[containerID]
	profilePath, pathExists := sm.activeFilters[containerID]
	sm.mu.RUnlock()
	
	if !configExists || !profileExists || !pathExists {
		t.Fatal("Setup verification failed")
	}
	
	// Verify profile file exists
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Fatal("Profile file should exist before cleanup")
	}
	
	// Test cleanup
	err = sm.CleanupSeccompFilter(containerID)
	if err != nil {
		t.Fatalf("CleanupSeccompFilter failed: %v", err)
	}
	
	// Verify cleanup
	sm.mu.RLock()
	_, configStillExists := sm.containerConfigs[containerID]
	_, profileStillExists := sm.containerProfiles[containerID]
	_, pathStillExists := sm.activeFilters[containerID]
	sm.mu.RUnlock()
	
	if configStillExists {
		t.Error("Configuration should be cleaned up")
	}
	
	if profileStillExists {
		t.Error("Profile should be cleaned up")
	}
	
	if pathStillExists {
		t.Error("Profile path should be cleaned up")
	}
	
	// Verify profile file is removed
	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Error("Profile file should be removed")
	}
}

func TestProfileStats(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	
	// Create test profile with various actions
	profile := &SeccompProfile{
		DefaultAction: SeccompActionErrno,
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write", "close"},
				Action: SeccompActionAllow,
			},
			{
				Names:  []string{"open", "openat"},
				Action: SeccompActionAllow,
			},
			{
				Names:  []string{"ptrace", "process_vm_readv"},
				Action: SeccompActionKill,
			},
			{
				Names:  []string{"mount", "umount2"},
				Action: SeccompActionErrno,
			},
		},
	}
	
	stats := sm.generateProfileStats(profile)
	
	if stats == nil {
		t.Fatal("Profile stats should not be nil")
	}
	
	expectedTotalSyscalls := 3 + 2 + 2 + 2 // Sum of syscalls in each rule
	if stats.TotalSyscalls != expectedTotalSyscalls {
		t.Errorf("Expected %d total syscalls, got %d", expectedTotalSyscalls, stats.TotalSyscalls)
	}
	
	expectedAllowed := 3 + 2 // read, write, close, open, openat
	if stats.AllowedSyscalls != expectedAllowed {
		t.Errorf("Expected %d allowed syscalls, got %d", expectedAllowed, stats.AllowedSyscalls)
	}
	
	expectedBlocked := 2 + 2 // ptrace, process_vm_readv, mount, umount2
	if stats.BlockedSyscalls != expectedBlocked {
		t.Errorf("Expected %d blocked syscalls, got %d", expectedBlocked, stats.BlockedSyscalls)
	}
	
	// Check action counts
	if stats.ActionCounts[SeccompActionAllow] != 5 {
		t.Error("Allow action count should be correct")
	}
	
	if stats.ActionCounts[SeccompActionKill] != 2 {
		t.Error("Kill action count should be correct")
	}
	
	if stats.ActionCounts[SeccompActionErrno] != 2 {
		t.Error("Errno action count should be correct")
	}
	
	if stats.RiskAssessment == "" {
		t.Error("Risk assessment should be set")
	}
	
	if stats.Coverage < 0 || stats.Coverage > 100 {
		t.Error("Coverage should be between 0 and 100")
	}
}

func TestConcurrentSeccompOperations(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	
	// Mock system support
	sm.systemSupport = true
	sm.supportedActions[SeccompActionErrno] = true
	
	// Test concurrent setup and cleanup
	done := make(chan bool, 10)
	
	for i := 0; i < 10; i++ {
		go func(id int) {
			containerID := fmt.Sprintf("concurrent-seccomp-test-%d", id)
			config := &SeccompConfig{
				ProfileType:     ProfileTypeDefault,
				NoNewPrivs:      true,
				ViolationAction: SeccompActionErrno,
			}
			
			err := sm.SetupSeccompFilter(containerID, config)
			if err != nil {
				t.Errorf("Concurrent setup failed for %s: %v", containerID, err)
			}
			
			// Audit some syscalls
			sm.AuditSyscall(containerID, 1234, "open", SeccompActionAllow, []uint64{1, 2})
			sm.AuditSyscall(containerID, 1234, "ptrace", SeccompActionKill, []uint64{})
			
			// Small delay
			time.Sleep(10 * time.Millisecond)
			
			err = sm.CleanupSeccompFilter(containerID)
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

func TestDeepCopyProfile(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	
	original := &SeccompProfile{
		DefaultAction: SeccompActionErrno,
		Architecture:  []SeccompArch{SeccompArchX86_64, SeccompArchNative},
		Syscalls: []SeccompSyscall{
			{
				Names:  []string{"read", "write"},
				Action: SeccompActionAllow,
				Args: []SeccompArg{
					{
						Index: 0,
						Value: 1,
						Op:    SeccompOpEqual,
					},
				},
			},
		},
		Flags: []string{"flag1", "flag2"},
	}
	
	copy := sm.deepCopyProfile(original)
	
	// Test that copy is independent
	if copy == original {
		t.Error("Copy should be a different object")
	}
	
	if copy.DefaultAction != original.DefaultAction {
		t.Error("Default action should be copied")
	}
	
	if len(copy.Architecture) != len(original.Architecture) {
		t.Error("Architecture should be copied")
	}
	
	if len(copy.Syscalls) != len(original.Syscalls) {
		t.Error("Syscalls should be copied")
	}
	
	if len(copy.Flags) != len(original.Flags) {
		t.Error("Flags should be copied")
	}
	
	// Test deep copy - modify original shouldn't affect copy
	original.Syscalls[0].Names[0] = "modified"
	original.Syscalls[0].Args[0].Value = 999
	
	if copy.Syscalls[0].Names[0] == "modified" {
		t.Error("Deep copy failed: syscall names should be independent")
	}
	
	if copy.Syscalls[0].Args[0].Value == 999 {
		t.Error("Deep copy failed: syscall args should be independent")
	}
}

func TestTemplateVariableApplication(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	
	profile := &SeccompProfile{
		DefaultAction: SeccompActionErrno,
		ListenerPath:  "{{.SocketPath}}",
		Syscalls: []SeccompSyscall{
			{
				Names:   []string{"{{.AllowedSyscall}}", "write"},
				Action:  SeccompActionAllow,
				Comment: "Allow {{.AllowedSyscall}} syscall",
			},
		},
	}
	
	vars := map[string]string{
		"SocketPath":     "/tmp/seccomp.sock",
		"AllowedSyscall": "read",
	}
	
	result := sm.applyTemplateVars(profile, vars)
	
	if result.ListenerPath != "/tmp/seccomp.sock" {
		t.Error("Template variable substitution failed for ListenerPath")
	}
	
	if len(result.Syscalls) == 0 {
		t.Fatal("Syscalls should be preserved")
	}
	
	if result.Syscalls[0].Names[0] != "read" {
		t.Error("Template variable substitution failed for syscall name")
	}
	
	if result.Syscalls[0].Comment != "Allow read syscall" {
		t.Error("Template variable substitution failed for comment")
	}
}

func TestSystemSupportDetection(t *testing.T) {
	tempDir := t.TempDir()
	sm := NewSeccompManager(tempDir)
	
	// Test that system support was checked
	// Note: In test environment, this may be false, which is okay
	if sm.supportedActions == nil {
		t.Error("Supported actions map should be initialized")
	}
	
	// Test basic actions that should always be checked
	expectedActions := []SeccompAction{
		SeccompActionAllow,
		SeccompActionErrno,
		SeccompActionKill,
		SeccompActionKillProcess,
	}
	
	for _, action := range expectedActions {
		if _, exists := sm.supportedActions[action]; !exists {
			t.Errorf("Action %s should be checked for support", action)
		}
	}
}