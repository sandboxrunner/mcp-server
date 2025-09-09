package security

import (
	"fmt"
	"testing"
	"time"
)

func TestNewCapabilityManager(t *testing.T) {
	cm := NewCapabilityManager()
	
	if cm == nil {
		t.Fatal("NewCapabilityManager returned nil")
	}
	
	if cm.containerCapabilities == nil {
		t.Error("containerCapabilities map not initialized")
	}
	
	if cm.activeStates == nil {
		t.Error("activeStates map not initialized")
	}
	
	if cm.systemCapabilities == nil {
		t.Error("systemCapabilities map not initialized")
	}
	
	if cm.supportInfo == nil {
		t.Error("supportInfo map not initialized")
	}
	
	if cm.securityProfiles == nil {
		t.Error("securityProfiles map not initialized")
	}
	
	// Test that capability info was initialized
	if len(cm.supportInfo) == 0 {
		t.Error("Capability support info should be initialized")
	}
	
	// Test that security profiles were initialized
	if len(cm.securityProfiles) == 0 {
		t.Error("Security profiles should be initialized")
	}
	
	// Verify specific profiles exist
	expectedProfiles := []SecurityProfile{
		ProfileRestricted, ProfileDefault, ProfileNetworking, 
		ProfileFilesystem, ProfilePrivileged,
	}
	
	for _, profile := range expectedProfiles {
		if _, exists := cm.securityProfiles[profile]; !exists {
			t.Errorf("Security profile %s should be initialized", profile)
		}
	}
}

func TestSetupCapabilities(t *testing.T) {
	cm := NewCapabilityManager()
	containerID := "test-container-caps"
	
	config := &CapabilityConfig{
		Profile: ProfileDefault,
		Add: []Capability{
			CapNetBindService,
		},
		Drop: []Capability{
			CapSysAdmin,
			CapNetAdmin,
		},
		NoNewPrivs:              true,
		AllowPrivilegeEscalation: false,
	}
	
	err := cm.SetupCapabilities(containerID, config)
	if err != nil {
		t.Fatalf("SetupCapabilities failed: %v", err)
	}
	
	// Verify configuration was stored
	cm.mu.RLock()
	storedConfig, exists := cm.containerCapabilities[containerID]
	state, hasState := cm.activeStates[containerID]
	cm.mu.RUnlock()
	
	if !exists {
		t.Error("Configuration was not stored")
	}
	
	if !hasState {
		t.Error("Capability state was not stored")
	}
	
	if storedConfig.Profile != ProfileDefault {
		t.Error("Profile was not preserved")
	}
	
	if len(storedConfig.Add) != len(config.Add) {
		t.Error("Add capabilities were not preserved")
	}
	
	if len(storedConfig.Drop) != len(config.Drop) {
		t.Error("Drop capabilities were not preserved")
	}
	
	if state == nil {
		t.Error("Capability state should not be nil")
	}
}

func TestValidateCapabilities(t *testing.T) {
	cm := NewCapabilityManager()
	containerID := "test-container-validation"
	
	// Test validation without setup
	result, err := cm.ValidateCapabilities(containerID)
	if err != nil {
		t.Fatalf("ValidateCapabilities failed: %v", err)
	}
	
	if result.Valid {
		t.Error("Validation should fail for non-existent container")
	}
	
	if len(result.Errors) == 0 {
		t.Error("Should have validation errors for non-existent container")
	}
	
	// Setup capabilities first
	config := &CapabilityConfig{
		Profile: ProfileDefault,
		Add:     []Capability{CapNetBindService},
		Drop:    []Capability{CapSysAdmin},
		NoNewPrivs: true,
	}
	
	err = cm.SetupCapabilities(containerID, config)
	if err != nil {
		t.Fatalf("SetupCapabilities failed: %v", err)
	}
	
	// Test validation after setup
	result, err = cm.ValidateCapabilities(containerID)
	if err != nil {
		t.Fatalf("ValidateCapabilities failed after setup: %v", err)
	}
	
	if !result.Valid {
		t.Errorf("Validation should pass after setup. Errors: %v", result.Errors)
	}
}

func TestGetCapabilityState(t *testing.T) {
	cm := NewCapabilityManager()
	containerID := "test-container-state"
	
	// Test state for non-existent container
	_, err := cm.GetCapabilityState(containerID)
	if err == nil {
		t.Error("Should return error for non-existent container")
	}
	
	// Setup capabilities
	config := &CapabilityConfig{
		Keep: []Capability{
			CapNetBindService,
			CapKill,
		},
		Add: []Capability{
			CapChown,
		},
		Ambient: []Capability{
			CapNetBindService,
		},
	}
	
	err = cm.SetupCapabilities(containerID, config)
	if err != nil {
		t.Fatalf("SetupCapabilities failed: %v", err)
	}
	
	// Get capability state
	state, err := cm.GetCapabilityState(containerID)
	if err != nil {
		t.Fatalf("GetCapabilityState failed: %v", err)
	}
	
	if state == nil {
		t.Error("State should not be nil")
	}
	
	// Verify state contains expected capabilities
	if len(state.Effective) == 0 {
		t.Error("Effective capabilities should not be empty")
	}
	
	if len(state.Permitted) == 0 {
		t.Error("Permitted capabilities should not be empty")
	}
	
	// Check ambient capabilities
	found := false
	for _, cap := range state.Ambient {
		if cap == CapNetBindService {
			found = true
			break
		}
	}
	if !found {
		t.Error("Ambient capability should include CAP_NET_BIND_SERVICE")
	}
}

func TestAuditCapabilityUsage(t *testing.T) {
	cm := NewCapabilityManager()
	containerID := "test-container-audit"
	
	// Test auditing capability usage
	cm.AuditCapabilityUsage(containerID, CapSysAdmin, "use", "test-process")
	
	// Check audit log
	entries := cm.GetAuditLog(containerID, 10)
	if len(entries) == 0 {
		t.Error("Audit log should contain entry")
	}
	
	entry := entries[0]
	if entry.ContainerID != containerID {
		t.Error("Container ID should match")
	}
	
	if entry.Capability != CapSysAdmin {
		t.Error("Capability should match")
	}
	
	if entry.Action != "use" {
		t.Error("Action should match")
	}
	
	if entry.Process != "test-process" {
		t.Error("Process should match")
	}
	
	if entry.RiskLevel == "" {
		t.Error("Risk level should be set")
	}
}

func TestCapabilityConfigValidation(t *testing.T) {
	cm := NewCapabilityManager()
	
	testCases := []struct {
		name        string
		config      *CapabilityConfig
		shouldFail  bool
		description string
	}{
		{
			name: "valid default profile",
			config: &CapabilityConfig{
				Profile:                 ProfileDefault,
				NoNewPrivs:              true,
				AllowPrivilegeEscalation: false,
			},
			shouldFail:  false,
			description: "Default profile should be valid",
		},
		{
			name: "valid capability additions",
			config: &CapabilityConfig{
				Add: []Capability{
					CapNetBindService,
					CapKill,
				},
				NoNewPrivs: true,
			},
			shouldFail:  false,
			description: "Valid capability additions should pass",
		},
		{
			name: "invalid capability",
			config: &CapabilityConfig{
				Add: []Capability{
					"CAP_INVALID_CAPABILITY",
				},
			},
			shouldFail:  true,
			description: "Invalid capability should fail validation",
		},
		{
			name: "high risk configuration",
			config: &CapabilityConfig{
				Add: []Capability{
					CapSysAdmin,
					CapNetAdmin,
				},
				AllowPrivilegeEscalation: true,
			},
			shouldFail:  false, // Should validate but with high risk
			description: "High risk config should validate with warnings",
		},
		{
			name: "privilege escalation without NoNewPrivs",
			config: &CapabilityConfig{
				AllowPrivilegeEscalation: true,
				NoNewPrivs:              false,
			},
			shouldFail:  false, // Valid but risky
			description: "Privilege escalation config should be valid but risky",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := cm.validateCapabilityConfig(tc.config)
			
			if tc.shouldFail && result.Valid {
				t.Errorf("%s: expected validation to fail but it passed", tc.description)
			}
			
			if !tc.shouldFail && !result.Valid {
				t.Errorf("%s: expected validation to pass but it failed. Errors: %v", tc.description, result.Errors)
			}
			
			// Check risk assessment
			if result.RiskAssessment != nil {
				if result.RiskAssessment.OverallRisk == "" {
					t.Error("Risk assessment should have overall risk")
				}
			}
		})
	}
}

func TestSecurityProfiles(t *testing.T) {
	cm := NewCapabilityManager()
	
	// Test restricted profile
	restrictedProfile := cm.securityProfiles[ProfileRestricted]
	if restrictedProfile == nil {
		t.Error("Restricted profile should exist")
	}
	
	if len(restrictedProfile.Drop) == 0 {
		t.Error("Restricted profile should drop capabilities")
	}
	
	if !restrictedProfile.NoNewPrivs {
		t.Error("Restricted profile should have NoNewPrivs enabled")
	}
	
	if restrictedProfile.AllowPrivilegeEscalation {
		t.Error("Restricted profile should not allow privilege escalation")
	}
	
	// Test privileged profile
	privilegedProfile := cm.securityProfiles[ProfilePrivileged]
	if privilegedProfile == nil {
		t.Error("Privileged profile should exist")
	}
	
	if privilegedProfile.NoNewPrivs {
		t.Error("Privileged profile should not have NoNewPrivs")
	}
	
	if !privilegedProfile.AllowPrivilegeEscalation {
		t.Error("Privileged profile should allow privilege escalation")
	}
}

func TestCapabilityStateValidation(t *testing.T) {
	cm := NewCapabilityManager()
	
	testCases := []struct {
		name        string
		state       *CapabilityState
		shouldFail  bool
		description string
	}{
		{
			name: "valid state",
			state: &CapabilityState{
				Effective:   []Capability{CapKill, CapNetBindService},
				Permitted:   []Capability{CapKill, CapNetBindService, CapChown},
				Inheritable: []Capability{CapNetBindService},
				Ambient:     []Capability{CapNetBindService},
			},
			shouldFail:  false,
			description: "Valid capability state should pass",
		},
		{
			name: "effective not in permitted",
			state: &CapabilityState{
				Effective: []Capability{CapSysAdmin},
				Permitted: []Capability{CapKill},
			},
			shouldFail:  true,
			description: "Effective caps not in permitted should fail",
		},
		{
			name: "ambient not in inheritable",
			state: &CapabilityState{
				Effective:   []Capability{CapKill},
				Permitted:   []Capability{CapKill, CapNetBindService},
				Inheritable: []Capability{CapKill},
				Ambient:     []Capability{CapNetBindService},
			},
			shouldFail:  true,
			description: "Ambient caps not in inheritable should fail",
		},
		{
			name: "ambient not in permitted",
			state: &CapabilityState{
				Effective:   []Capability{CapKill},
				Permitted:   []Capability{CapKill},
				Inheritable: []Capability{CapKill, CapNetBindService},
				Ambient:     []Capability{CapNetBindService},
			},
			shouldFail:  true,
			description: "Ambient caps not in permitted should fail",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := cm.validateCapabilityState(tc.state)
			
			if tc.shouldFail && err == nil {
				t.Errorf("%s: expected validation to fail but it passed", tc.description)
			}
			
			if !tc.shouldFail && err != nil {
				t.Errorf("%s: expected validation to pass but it failed: %v", tc.description, err)
			}
		})
	}
}

func TestProfileMerging(t *testing.T) {
	cm := NewCapabilityManager()
	
	config := &CapabilityConfig{
		Profile: ProfileDefault,
		Add: []Capability{
			CapChown,
		},
		Drop: []Capability{
			CapSysModule,
		},
		Ambient: []Capability{
			CapNetBindService,
		},
		NoNewPrivs: false, // Override profile setting
	}
	
	merged := cm.mergeWithProfile(config)
	
	// Should have profile capabilities plus additions
	if len(merged.Add) == 0 {
		t.Error("Merged config should have capabilities from profile and config")
	}
	
	if len(merged.Drop) == 0 {
		t.Error("Merged config should have dropped capabilities from profile and config")
	}
	
	// Config settings should override profile
	if merged.NoNewPrivs != false {
		t.Error("Config NoNewPrivs should override profile setting")
	}
	
	// Should include custom additions
	found := false
	for _, cap := range merged.Add {
		if cap == CapChown {
			found = true
			break
		}
	}
	if !found {
		t.Error("Custom capability addition should be included")
	}
}

func TestCleanupCapabilities(t *testing.T) {
	cm := NewCapabilityManager()
	containerID := "test-container-cleanup"
	
	// Setup capabilities first
	config := &CapabilityConfig{
		Profile: ProfileDefault,
		Add:     []Capability{CapKill},
	}
	
	err := cm.SetupCapabilities(containerID, config)
	if err != nil {
		t.Fatalf("SetupCapabilities failed: %v", err)
	}
	
	// Verify setup
	cm.mu.RLock()
	_, configExists := cm.containerCapabilities[containerID]
	_, stateExists := cm.activeStates[containerID]
	cm.mu.RUnlock()
	
	if !configExists || !stateExists {
		t.Fatal("Setup verification failed")
	}
	
	// Test cleanup
	err = cm.CleanupCapabilities(containerID)
	if err != nil {
		t.Fatalf("CleanupCapabilities failed: %v", err)
	}
	
	// Verify cleanup
	cm.mu.RLock()
	_, configStillExists := cm.containerCapabilities[containerID]
	_, stateStillExists := cm.activeStates[containerID]
	cm.mu.RUnlock()
	
	if configStillExists {
		t.Error("Configuration should be cleaned up")
	}
	
	if stateStillExists {
		t.Error("State should be cleaned up")
	}
}

func TestCapabilityAuditing(t *testing.T) {
	cm := NewCapabilityManager()
	containerID := "test-container-auditing"
	
	// Test different capability actions
	testCases := []struct {
		capability Capability
		action     string
		process    string
	}{
		{CapSysAdmin, "use", "test-process-1"},
		{CapNetAdmin, "drop", "test-process-2"},
		{CapKill, "escalate", "test-process-3"},
	}
	
	for _, tc := range testCases {
		cm.AuditCapabilityUsage(containerID, tc.capability, tc.action, tc.process)
	}
	
	// Get all audit entries for the container
	entries := cm.GetAuditLog(containerID, 10)
	if len(entries) != len(testCases) {
		t.Errorf("Expected %d audit entries, got %d", len(testCases), len(entries))
	}
	
	// Verify entries (entries are in reverse chronological order)
	for i, entry := range entries {
		tc := testCases[len(testCases)-1-i] // Reverse order
		
		if entry.ContainerID != containerID {
			t.Errorf("Entry %d: wrong container ID", i)
		}
		
		if entry.Capability != tc.capability {
			t.Errorf("Entry %d: wrong capability", i)
		}
		
		if entry.Action != tc.action {
			t.Errorf("Entry %d: wrong action", i)
		}
		
		if entry.Process != tc.process {
			t.Errorf("Entry %d: wrong process", i)
		}
	}
	
	// Test audit log with empty container filter
	allEntries := cm.GetAuditLog("", 20)
	if len(allEntries) < len(testCases) {
		t.Error("Should return all entries when container ID is empty")
	}
}

func TestConcurrentCapabilityOperations(t *testing.T) {
	cm := NewCapabilityManager()
	
	// Test concurrent setup and cleanup
	done := make(chan bool, 10)
	
	for i := 0; i < 10; i++ {
		go func(id int) {
			containerID := fmt.Sprintf("concurrent-caps-test-%d", id)
			config := &CapabilityConfig{
				Profile: ProfileDefault,
				Add:     []Capability{CapKill},
			}
			
			err := cm.SetupCapabilities(containerID, config)
			if err != nil {
				t.Errorf("Concurrent setup failed for %s: %v", containerID, err)
			}
			
			// Audit some usage
			cm.AuditCapabilityUsage(containerID, CapKill, "use", "test-process")
			
			// Small delay
			time.Sleep(10 * time.Millisecond)
			
			err = cm.CleanupCapabilities(containerID)
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

func TestUniqueCapabilities(t *testing.T) {
	cm := NewCapabilityManager()
	
	// Test deduplication
	caps := []Capability{
		CapKill,
		CapNetBindService,
		CapKill, // Duplicate
		CapChown,
		CapNetBindService, // Duplicate
	}
	
	unique := cm.uniqueCapabilities(caps)
	
	if len(unique) != 3 {
		t.Errorf("Expected 3 unique capabilities, got %d", len(unique))
	}
	
	// Test sorting
	expectedOrder := []Capability{CapChown, CapKill, CapNetBindService}
	for i, expected := range expectedOrder {
		if i >= len(unique) || unique[i] != expected {
			t.Errorf("Expected capability %s at position %d, got %s", expected, i, unique[i])
		}
	}
}

func TestCapabilityInfo(t *testing.T) {
	cm := NewCapabilityManager()
	
	// Test that capability info is populated
	testCapabilities := []Capability{
		CapSysAdmin,
		CapNetAdmin,
		CapKill,
		CapChown,
		CapNetBindService,
	}
	
	for _, cap := range testCapabilities {
		info, exists := cm.supportInfo[cap]
		if !exists {
			t.Errorf("Capability info should exist for %s", cap)
			continue
		}
		
		if info.Name != cap {
			t.Errorf("Capability name should match: expected %s, got %s", cap, info.Name)
		}
		
		if info.Description == "" {
			t.Errorf("Capability %s should have description", cap)
		}
		
		if info.Risk == "" {
			t.Errorf("Capability %s should have risk level", cap)
		}
		
		if info.Category == "" {
			t.Errorf("Capability %s should have category", cap)
		}
		
		// Verify risk levels are valid
		validRisks := []string{"low", "medium", "high", "critical"}
		validRisk := false
		for _, validLevel := range validRisks {
			if info.Risk == validLevel {
				validRisk = true
				break
			}
		}
		if !validRisk {
			t.Errorf("Capability %s has invalid risk level: %s", cap, info.Risk)
		}
	}
}