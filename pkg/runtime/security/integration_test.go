package security

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// TestSecurityIntegration tests the integration between all security components
func TestSecurityIntegration(t *testing.T) {
	tempDir := t.TempDir()
	containerID := "integration-test-container"
	
	// Initialize all managers
	nm := NewNamespaceManager()
	cm := NewCapabilityManager()
	sm := NewSeccompManager(filepath.Join(tempDir, "seccomp"))
	mm := NewMACManager(filepath.Join(tempDir, "mac"))
	pm := NewProfileManager(filepath.Join(tempDir, "profiles"), filepath.Join(tempDir, "templates"))
	
	auditConfig := &AuditConfig{
		Enabled:     true,
		LogPath:     filepath.Join(tempDir, "audit.log"),
		BufferSize:  100,
		FlushInterval: 100 * time.Millisecond,
	}
	auditor, err := NewSecurityAuditor(auditConfig)
	if err != nil {
		t.Fatalf("Failed to create security auditor: %v", err)
	}
	defer auditor.Shutdown()
	
	complianceManager := NewComplianceManager(filepath.Join(tempDir, "compliance"))
	defer complianceManager.Shutdown()
	
	// Test 1: Create and apply a comprehensive security profile
	t.Run("SecurityProfileIntegration", func(t *testing.T) {
		// Create a security profile with all components
		profile := &SecurityProfileSpec{
			Name:        "integration-test-profile",
			Version:     "1.0",
			Description: "Integration test security profile",
			Type:        ProfileTypeContainer,
			Level:       ProfileLevelStandard,
			Enabled:     true,
			Created:     time.Now(),
			Updated:     time.Now(),
			Namespaces: &NamespaceConfig{
				PID:     true,
				Mount:   true,
				Network: true,
				IPC:     true,
				UTS:     true,
				User:    false,
				Cgroup:  true,
			},
			Capabilities: &CapabilityConfig{
				Profile: ProfileDefault,
				Drop: []Capability{
					CapSysAdmin,
					CapNetAdmin,
				},
				NoNewPrivs:              true,
				AllowPrivilegeEscalation: false,
			},
			Seccomp: &SeccompConfig{
				ProfileType:     ProfileTypeDefault,
				NoNewPrivs:      true,
				ViolationAction: SeccompActionErrno,
			},
			MAC: &MACConfig{
				Type: MACTypeAppArmor,
				AppArmor: &AppArmorConfig{
					ProfileName: "integration-test-apparmor",
					Mode:        MACModeEnforce,
				},
			},
		}
		
		// Create the profile
		err := pm.CreateProfile(profile)
		if err != nil {
			t.Fatalf("Failed to create security profile: %v", err)
		}
		
		// Apply the profile to container
		err = nm.SetupNamespaces(containerID, profile.Namespaces)
		if err != nil {
			t.Fatalf("Failed to setup namespaces: %v", err)
		}
		
		err = cm.SetupCapabilities(containerID, profile.Capabilities)
		if err != nil {
			t.Fatalf("Failed to setup capabilities: %v", err)
		}
		
		// Mock system support for seccomp and MAC
		sm.systemSupport = true
		sm.supportedActions[SeccompActionErrno] = true
		mm.appArmorSupport = true
		
		err = sm.SetupSeccompFilter(containerID, profile.Seccomp)
		if err != nil {
			t.Fatalf("Failed to setup seccomp filter: %v", err)
		}
		
		err = mm.SetupMAC(containerID, profile.MAC)
		if err != nil {
			t.Fatalf("Failed to setup MAC: %v", err)
		}
		
		// Log audit events for the setup
		auditor.LogEvent(AuditEvent{
			ContainerID: containerID,
			Type:        AuditEventProfileLoaded,
			Severity:    SeverityInfo,
			Source:      "integration-test",
			Action:      "apply_profile",
			Result:      "success",
			Message:     "Security profile applied successfully",
		})
	})
	
	// Test 2: Validate all security components
	t.Run("SecurityValidation", func(t *testing.T) {
		// Validate namespaces
		nsResult, err := nm.ValidateNamespaces(containerID)
		if err != nil {
			t.Fatalf("Failed to validate namespaces: %v", err)
		}
		if !nsResult.Valid {
			t.Errorf("Namespace validation failed: %v", nsResult.Errors)
		}
		
		// Validate capabilities
		capResult, err := cm.ValidateCapabilities(containerID)
		if err != nil {
			t.Fatalf("Failed to validate capabilities: %v", err)
		}
		if !capResult.Valid {
			t.Errorf("Capability validation failed: %v", capResult.Errors)
		}
		
		// Validate seccomp
		seccompResult, err := sm.ValidateSeccompFilter(containerID)
		if err != nil {
			t.Fatalf("Failed to validate seccomp: %v", err)
		}
		if !seccompResult.Valid {
			t.Errorf("Seccomp validation failed: %v", seccompResult.Errors)
		}
		
		// Validate MAC
		macResult, err := mm.ValidateMAC(containerID)
		if err != nil {
			t.Fatalf("Failed to validate MAC: %v", err)
		}
		if !macResult.Valid {
			t.Errorf("MAC validation failed: %v", macResult.Errors)
		}
	})
	
	// Test 3: Simulate security violations and audit logging
	t.Run("SecurityViolations", func(t *testing.T) {
		// Simulate capability violation
		cm.AuditCapabilityUsage(containerID, CapSysAdmin, "use", "malicious-process")
		
		violation := SecurityViolation{
			ContainerID:  containerID,
			Type:         ViolationCapability,
			Severity:     SeverityError,
			PolicyName:   "integration-test-policy",
			ProfileName:  "integration-test-profile",
			ViolatedRule: "CAP_SYS_ADMIN usage",
			Subject:      "malicious-process",
			Object:       "capability",
			Action:       "use",
			Expected:     "denied",
			Actual:       "attempted",
			Description:  "Process attempted to use CAP_SYS_ADMIN",
			Impact:       "High security risk",
			RiskScore:    0.9,
			Status:       "open",
		}
		
		auditor.LogViolation(violation)
		
		// Simulate syscall violation
		sm.AuditSyscall(containerID, 1234, "ptrace", SeccompActionKill, []uint64{1, 2})
		
		auditor.LogEvent(AuditEvent{
			ContainerID: containerID,
			Type:        AuditEventSyscallDenied,
			Severity:    SeverityWarning,
			Source:      "seccomp",
			Action:      "syscall_denied",
			Result:      "killed",
			Message:     "Dangerous syscall ptrace was killed",
		})
		
		// Give time for processing
		time.Sleep(200 * time.Millisecond)
		
		// Query violations
		violations, err := auditor.QueryViolations(ViolationQuery{
			ContainerID: containerID,
			Limit:       10,
		})
		if err != nil {
			t.Fatalf("Failed to query violations: %v", err)
		}
		
		if len(violations) == 0 {
			t.Error("Should have violations recorded")
		}
		
		// Query audit events
		events, err := auditor.QueryEvents(AuditQuery{
			ContainerID: containerID,
			Limit:       10,
		})
		if err != nil {
			t.Fatalf("Failed to query events: %v", err)
		}
		
		if len(events) == 0 {
			t.Error("Should have audit events recorded")
		}
	})
	
	// Test 4: Run compliance assessment
	t.Run("ComplianceAssessment", func(t *testing.T) {
		// Run compliance assessment using built-in CIS policy
		assessment, err := complianceManager.RunComplianceAssessment(containerID, "cis-docker")
		if err != nil {
			t.Fatalf("Failed to run compliance assessment: %v", err)
		}
		
		if assessment == nil {
			t.Fatal("Assessment should not be nil")
		}
		
		if assessment.ContainerID != containerID {
			t.Error("Assessment container ID should match")
		}
		
		if assessment.Framework != FrameworkCIS {
			t.Error("Assessment framework should be CIS")
		}
		
		if len(assessment.CheckResults) == 0 {
			t.Error("Assessment should have check results")
		}
		
		if assessment.OverallScore < 0 || assessment.OverallScore > assessment.MaxScore {
			t.Error("Overall score should be within valid range")
		}
	})
	
	// Test 5: Test profile management and templates
	t.Run("ProfileManagement", func(t *testing.T) {
		// Create profile from template
		templateVars := map[string]interface{}{
			"Name":               "webapp-test",
			"Description":        "Test web application",
			"SecurityLevel":      "standard",
			"AllowNetwork":       true,
			"CapabilityProfile":  "default",
			"SeccompProfile":     "default",
			"WorkDir":           "/app",
			"AllowedPorts": []map[string]interface{}{
				{"Port": 8080, "Protocol": "tcp", "Type": "inbound"},
			},
		}
		
		webappProfile, err := pm.CreateFromTemplate("webapp", "webapp-test-profile", templateVars)
		if err != nil {
			t.Fatalf("Failed to create profile from template: %v", err)
		}
		
		if webappProfile.Name != "webapp-test-profile" {
			t.Error("Profile name should match")
		}
		
		// List profiles
		profiles, err := pm.ListProfiles(&ProfileQuery{
			Type:  ProfileTypeApplication,
			Limit: 10,
		})
		if err != nil {
			t.Fatalf("Failed to list profiles: %v", err)
		}
		
		found := false
		for _, p := range profiles {
			if p.Name == "webapp-test-profile" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Should find created profile in list")
		}
	})
	
	// Test 6: Test security statistics and monitoring
	t.Run("SecurityMonitoring", func(t *testing.T) {
		// Get audit statistics
		stats := auditor.GetStatistics()
		if stats == nil {
			t.Fatal("Statistics should not be nil")
		}
		
		if stats.TotalEvents == 0 {
			t.Error("Should have recorded events")
		}
		
		if stats.ViolationCount == 0 {
			t.Error("Should have recorded violations")
		}
		
		// Check container statistics
		if len(stats.TopContainers) == 0 {
			t.Error("Should have container statistics")
		}
		
		// Get capability audit log
		capEntries := cm.GetAuditLog(containerID, 10)
		if len(capEntries) == 0 {
			t.Error("Should have capability audit entries")
		}
		
		// Get seccomp audit log
		seccompEntries := sm.GetAuditLog(containerID, 10)
		if len(seccompEntries) == 0 {
			t.Error("Should have seccomp audit entries")
		}
	})
	
	// Test 7: Cleanup all security components
	t.Run("SecurityCleanup", func(t *testing.T) {
		// Cleanup in reverse order of setup
		err := mm.CleanupMAC(containerID)
		if err != nil {
			t.Errorf("Failed to cleanup MAC: %v", err)
		}
		
		err = sm.CleanupSeccompFilter(containerID)
		if err != nil {
			t.Errorf("Failed to cleanup seccomp: %v", err)
		}
		
		err = cm.CleanupCapabilities(containerID)
		if err != nil {
			t.Errorf("Failed to cleanup capabilities: %v", err)
		}
		
		err = nm.CleanupNamespaces(containerID)
		if err != nil {
			t.Errorf("Failed to cleanup namespaces: %v", err)
		}
		
		// Verify cleanup
		_, err = nm.GetNamespaceInfo(containerID)
		if err == nil {
			t.Error("Namespace info should not be available after cleanup")
		}
		
		_, err = cm.GetCapabilityState(containerID)
		if err == nil {
			t.Error("Capability state should not be available after cleanup")
		}
		
		_, err = sm.GetSeccompProfile(containerID)
		if err == nil {
			t.Error("Seccomp profile should not be available after cleanup")
		}
	})
}

// TestSecurityProfileLifecycle tests the complete lifecycle of a security profile
func TestSecurityProfileLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	pm := NewProfileManager(filepath.Join(tempDir, "profiles"), filepath.Join(tempDir, "templates"))
	
	// Test profile creation
	profile := &SecurityProfileSpec{
		Name:        "lifecycle-test",
		Version:     "1.0",
		Description: "Profile lifecycle test",
		Type:        ProfileTypeContainer,
		Level:       ProfileLevelStandard,
		Enabled:     true,
		Tags:        []string{"test", "lifecycle"},
		Namespaces: &NamespaceConfig{
			PID:   true,
			Mount: true,
		},
		Capabilities: &CapabilityConfig{
			Profile:    ProfileDefault,
			NoNewPrivs: true,
		},
	}
	
	// Create
	err := pm.CreateProfile(profile)
	if err != nil {
		t.Fatalf("Failed to create profile: %v", err)
	}
	
	// Retrieve
	retrieved, err := pm.GetProfile("lifecycle-test")
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}
	
	if retrieved.Name != profile.Name {
		t.Error("Retrieved profile name should match")
	}
	
	// Update
	profile.Description = "Updated description"
	profile.Version = "1.1"
	err = pm.UpdateProfile(profile)
	if err != nil {
		t.Fatalf("Failed to update profile: %v", err)
	}
	
	// Verify update
	updated, err := pm.GetProfile("lifecycle-test")
	if err != nil {
		t.Fatalf("Failed to get updated profile: %v", err)
	}
	
	if updated.Description != "Updated description" {
		t.Error("Profile should be updated")
	}
	
	if updated.Version != "1.1" {
		t.Error("Profile version should be updated")
	}
	
	// Export
	exported, err := pm.ExportProfile("lifecycle-test")
	if err != nil {
		t.Fatalf("Failed to export profile: %v", err)
	}
	
	if len(exported) == 0 {
		t.Error("Exported data should not be empty")
	}
	
	// Delete
	err = pm.DeleteProfile("lifecycle-test")
	if err != nil {
		t.Fatalf("Failed to delete profile: %v", err)
	}
	
	// Verify deletion
	_, err = pm.GetProfile("lifecycle-test")
	if err == nil {
		t.Error("Profile should not exist after deletion")
	}
	
	// Import
	imported, err := pm.ImportProfile(exported)
	if err != nil {
		t.Fatalf("Failed to import profile: %v", err)
	}
	
	if imported.Name != "lifecycle-test" {
		t.Error("Imported profile name should match")
	}
}

// TestErrorHandling tests error handling across security components
func TestErrorHandling(t *testing.T) {
	tempDir := t.TempDir()
	containerID := "error-test-container"
	
	nm := NewNamespaceManager()
	cm := NewCapabilityManager()
	sm := NewSeccompManager(tempDir)
	
	// Test invalid configurations
	t.Run("InvalidConfigurations", func(t *testing.T) {
		// Invalid namespace configuration
		invalidNSConfig := &NamespaceConfig{
			User: true,
			UserNamespaceMapping: &UserNamespaceMapping{
				UIDs: []IDMapping{{ContainerID: -1, HostID: 1000, Size: 1}}, // Invalid
			},
		}
		
		err := nm.SetupNamespaces(containerID, invalidNSConfig)
		if err == nil {
			t.Error("Should fail with invalid namespace configuration")
		}
		
		// Invalid capability configuration
		invalidCapConfig := &CapabilityConfig{
			Add: []Capability{"INVALID_CAPABILITY"},
		}
		
		err = cm.SetupCapabilities(containerID, invalidCapConfig)
		if err == nil {
			t.Error("Should fail with invalid capability configuration")
		}
		
		// Invalid seccomp configuration
		invalidSeccompConfig := &SeccompConfig{
			ProfileType: "", // Empty
		}
		
		err = sm.SetupSeccompFilter(containerID, invalidSeccompConfig)
		if err == nil {
			t.Error("Should fail with invalid seccomp configuration")
		}
	})
	
	// Test operations on non-existent containers
	t.Run("NonExistentContainer", func(t *testing.T) {
		nonExistentID := "non-existent-container"
		
		// Namespace operations
		_, err := nm.ValidateNamespaces(nonExistentID)
		if err != nil {
			// This should return a validation result, not an error
			t.Errorf("ValidateNamespaces should return validation result, not error: %v", err)
		}
		
		_, err = nm.GetNamespaceInfo(nonExistentID)
		if err == nil {
			t.Error("GetNamespaceInfo should fail for non-existent container")
		}
		
		// Capability operations
		_, err = cm.GetCapabilityState(nonExistentID)
		if err == nil {
			t.Error("GetCapabilityState should fail for non-existent container")
		}
		
		// Seccomp operations
		_, err = sm.GetSeccompProfile(nonExistentID)
		if err == nil {
			t.Error("GetSeccompProfile should fail for non-existent container")
		}
	})
}

// TestConcurrentSecurityOperations tests concurrent operations across all security components
func TestConcurrentSecurityOperations(t *testing.T) {
	tempDir := t.TempDir()
	
	nm := NewNamespaceManager()
	cm := NewCapabilityManager()
	sm := NewSeccompManager(filepath.Join(tempDir, "seccomp"))
	
	// Mock system support
	sm.systemSupport = true
	sm.supportedActions[SeccompActionErrno] = true
	
	done := make(chan bool, 30)
	
	// Concurrent operations on different containers
	for i := 0; i < 10; i++ {
		go func(id int) {
			containerID := fmt.Sprintf("concurrent-test-%d", id)
			
			// Setup namespaces
			nsConfig := &NamespaceConfig{PID: true, Mount: true}
			err := nm.SetupNamespaces(containerID, nsConfig)
			if err != nil {
				t.Errorf("Concurrent namespace setup failed: %v", err)
			}
			
			// Setup capabilities
			capConfig := &CapabilityConfig{
				Profile:    ProfileDefault,
				NoNewPrivs: true,
			}
			err = cm.SetupCapabilities(containerID, capConfig)
			if err != nil {
				t.Errorf("Concurrent capability setup failed: %v", err)
			}
			
			// Setup seccomp
			seccompConfig := &SeccompConfig{
				ProfileType:     ProfileTypeDefault,
				ViolationAction: SeccompActionErrno,
			}
			err = sm.SetupSeccompFilter(containerID, seccompConfig)
			if err != nil {
				t.Errorf("Concurrent seccomp setup failed: %v", err)
			}
			
			done <- true
		}(i)
	}
	
	// Concurrent validation operations
	for i := 0; i < 10; i++ {
		go func(id int) {
			containerID := fmt.Sprintf("concurrent-test-%d", id)
			
			// Wait a bit to ensure setup is done
			time.Sleep(100 * time.Millisecond)
			
			// Validate
			_, _ = nm.ValidateNamespaces(containerID)
			_, _ = cm.ValidateCapabilities(containerID)
			_, _ = sm.ValidateSeccompFilter(containerID)
			
			done <- true
		}(i)
	}
	
	// Concurrent cleanup operations
	for i := 0; i < 10; i++ {
		go func(id int) {
			containerID := fmt.Sprintf("concurrent-test-%d", id)
			
			// Wait to ensure setup and validation are done
			time.Sleep(200 * time.Millisecond)
			
			// Cleanup
			_ = sm.CleanupSeccompFilter(containerID)
			_ = cm.CleanupCapabilities(containerID)
			_ = nm.CleanupNamespaces(containerID)
			
			done <- true
		}(i)
	}
	
	// Wait for all operations to complete
	for i := 0; i < 30; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(10 * time.Second):
			t.Fatal("Concurrent operations timed out")
		}
	}
}

// TestSecurityMetricsAndReporting tests metrics collection and reporting
func TestSecurityMetricsAndReporting(t *testing.T) {
	tempDir := t.TempDir()
	
	auditConfig := &AuditConfig{
		Enabled:     true,
		LogPath:     filepath.Join(tempDir, "audit.log"),
		BufferSize:  100,
		FlushInterval: 50 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(auditConfig)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}
	defer auditor.Shutdown()
	
	complianceManager := NewComplianceManager(filepath.Join(tempDir, "compliance"))
	defer complianceManager.Shutdown()
	
	containerID := "metrics-test-container"
	
	// Generate various security events
	events := []AuditEvent{
		{
			ContainerID: containerID,
			Type:        AuditEventSecurityViolation,
			Severity:    SeverityError,
		},
		{
			ContainerID: containerID,
			Type:        AuditEventCapabilityUsage,
			Severity:    SeverityWarning,
		},
		{
			ContainerID: containerID,
			Type:        AuditEventSyscallDenied,
			Severity:    SeverityCritical,
		},
	}
	
	violations := []SecurityViolation{
		{
			ContainerID: containerID,
			Type:        ViolationCapability,
			Severity:    SeverityError,
			RiskScore:   0.8,
		},
		{
			ContainerID: containerID,
			Type:        ViolationSyscall,
			Severity:    SeverityWarning,
			RiskScore:   0.6,
		},
	}
	
	// Log events and violations
	for _, event := range events {
		auditor.LogEvent(event)
	}
	
	for _, violation := range violations {
		auditor.LogViolation(violation)
	}
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Test statistics
	stats := auditor.GetStatistics()
	if stats.TotalEvents != int64(len(events)) {
		t.Errorf("Expected %d events, got %d", len(events), stats.TotalEvents)
	}
	
	if stats.ViolationCount != int64(len(violations)) {
		t.Errorf("Expected %d violations, got %d", len(violations), stats.ViolationCount)
	}
	
	// Test compliance assessment
	assessment, err := complianceManager.RunComplianceAssessment(containerID, "cis-docker")
	if err != nil {
		t.Fatalf("Failed to run compliance assessment: %v", err)
	}
	
	if assessment.ContainerID != containerID {
		t.Error("Assessment should be for correct container")
	}
	
	// Test compliance reporting
	report, err := complianceManager.GenerateComplianceReport(containerID, []ComplianceFramework{FrameworkCIS}, "summary")
	if err != nil {
		t.Fatalf("Failed to generate compliance report: %v", err)
	}
	
	if len(report) == 0 {
		t.Error("Report should not be empty")
	}
}