package security

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSecurityAuditor(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:         true,
		LogLevel:        SeverityInfo,
		LogPath:         filepath.Join(tempDir, "audit.log"),
		MaxLogSize:      1024 * 1024,
		MaxLogFiles:     5,
		RetentionDays:   30,
		BufferSize:      100,
		FlushInterval:   time.Second,
		MinimumSeverity: SeverityInfo,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	if auditor == nil {
		t.Fatal("NewSecurityAuditor returned nil")
	}
	
	if auditor.config != config {
		t.Error("Configuration should be stored")
	}
	
	if auditor.eventBuffer == nil {
		t.Error("Event buffer should be initialized")
	}
	
	if auditor.violationBuffer == nil {
		t.Error("Violation buffer should be initialized")
	}
	
	if auditor.statistics == nil {
		t.Error("Statistics should be initialized")
	}
	
	// Test that log file was created
	if _, err := os.Stat(config.LogPath); os.IsNotExist(err) {
		t.Error("Log file should be created")
	}
}

func TestLogEvent(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:         true,
		LogPath:         filepath.Join(tempDir, "audit.log"),
		BufferSize:      100,
		FlushInterval:   100 * time.Millisecond,
		MinimumSeverity: SeverityInfo,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Test logging event
	event := AuditEvent{
		ContainerID: "test-container",
		Type:        AuditEventSecurityViolation,
		Severity:    SeverityError,
		Source:      "test",
		Action:      "test_action",
		Result:      "denied",
		Message:     "Test security violation",
		ProcessInfo: &ProcessInfo{
			PID:     1234,
			Command: "test-command",
			User:    "test-user",
		},
	}
	
	auditor.LogEvent(event)
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Check that event was stored
	auditor.mu.RLock()
	eventsCount := len(auditor.events)
	auditor.mu.RUnlock()
	
	if eventsCount == 0 {
		t.Error("Event should be stored")
	}
	
	// Query events
	query := AuditQuery{
		ContainerID: "test-container",
		Type:        AuditEventSecurityViolation,
		Limit:       10,
	}
	
	events, err := auditor.QueryEvents(query)
	if err != nil {
		t.Fatalf("QueryEvents failed: %v", err)
	}
	
	if len(events) == 0 {
		t.Error("Query should return events")
	}
	
	foundEvent := events[0]
	if foundEvent.ContainerID != event.ContainerID {
		t.Error("Container ID should match")
	}
	
	if foundEvent.Type != event.Type {
		t.Error("Event type should match")
	}
	
	if foundEvent.Severity != event.Severity {
		t.Error("Severity should match")
	}
}

func TestLogViolation(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:     true,
		LogPath:     filepath.Join(tempDir, "audit.log"),
		BufferSize:  100,
		FlushInterval: 100 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Test logging violation
	violation := SecurityViolation{
		ContainerID:     "test-container",
		Type:            ViolationCapability,
		Severity:        SeverityError,
		PolicyName:      "test-policy",
		ProfileName:     "test-profile",
		ViolatedRule:    "CAP_SYS_ADMIN",
		Subject:         "test-process",
		Object:          "capability",
		Action:          "use",
		Expected:        "denied",
		Actual:          "allowed",
		Description:     "Unauthorized capability usage",
		Impact:          "High security risk",
		RiskScore:       0.8,
		Status:          "open",
	}
	
	auditor.LogViolation(violation)
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Check that violation was stored
	auditor.mu.RLock()
	violationsCount := len(auditor.violations)
	auditor.mu.RUnlock()
	
	if violationsCount == 0 {
		t.Error("Violation should be stored")
	}
	
	// Query violations
	query := ViolationQuery{
		ContainerID: "test-container",
		Type:        ViolationCapability,
		Limit:       10,
	}
	
	violations, err := auditor.QueryViolations(query)
	if err != nil {
		t.Fatalf("QueryViolations failed: %v", err)
	}
	
	if len(violations) == 0 {
		t.Error("Query should return violations")
	}
	
	foundViolation := violations[0]
	if foundViolation.ContainerID != violation.ContainerID {
		t.Error("Container ID should match")
	}
	
	if foundViolation.Type != violation.Type {
		t.Error("Violation type should match")
	}
	
	if foundViolation.RiskScore != violation.RiskScore {
		t.Error("Risk score should match")
	}
}

func TestQueryEvents(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:     true,
		LogPath:     filepath.Join(tempDir, "audit.log"),
		BufferSize:  100,
		FlushInterval: 50 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Log multiple events
	events := []AuditEvent{
		{
			ContainerID: "container-1",
			Type:        AuditEventCapabilityUsage,
			Severity:    SeverityInfo,
			Source:      "test",
			Action:      "use_capability",
			Result:      "allowed",
		},
		{
			ContainerID: "container-1",
			Type:        AuditEventSyscallDenied,
			Severity:    SeverityWarning,
			Source:      "test",
			Action:      "syscall",
			Result:      "denied",
		},
		{
			ContainerID: "container-2",
			Type:        AuditEventSecurityViolation,
			Severity:    SeverityError,
			Source:      "test",
			Action:      "violation",
			Result:      "blocked",
		},
	}
	
	for _, event := range events {
		auditor.LogEvent(event)
	}
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Test different queries
	testCases := []struct {
		name           string
		query          AuditQuery
		expectedCount  int
		description    string
	}{
		{
			name: "all events",
			query: AuditQuery{
				Limit: 10,
			},
			expectedCount: 3,
			description:   "Should return all events",
		},
		{
			name: "events by container",
			query: AuditQuery{
				ContainerID: "container-1",
				Limit:       10,
			},
			expectedCount: 2,
			description:   "Should return events for specific container",
		},
		{
			name: "events by type",
			query: AuditQuery{
				Type:  AuditEventSecurityViolation,
				Limit: 10,
			},
			expectedCount: 1,
			description:   "Should return events of specific type",
		},
		{
			name: "events by severity",
			query: AuditQuery{
				Severity: SeverityError,
				Limit:    10,
			},
			expectedCount: 1,
			description:   "Should return events with specific severity",
		},
		{
			name: "limited results",
			query: AuditQuery{
				Limit: 1,
			},
			expectedCount: 1,
			description:   "Should respect limit",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results, err := auditor.QueryEvents(tc.query)
			if err != nil {
				t.Fatalf("QueryEvents failed: %v", err)
			}
			
			if len(results) != tc.expectedCount {
				t.Errorf("%s: expected %d results, got %d", tc.description, tc.expectedCount, len(results))
			}
		})
	}
}

func TestGetStatistics(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:     true,
		LogPath:     filepath.Join(tempDir, "audit.log"),
		BufferSize:  100,
		FlushInterval: 50 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Log some events and violations
	events := []AuditEvent{
		{
			ContainerID: "container-1",
			Type:        AuditEventCapabilityUsage,
			Severity:    SeverityInfo,
		},
		{
			ContainerID: "container-1",
			Type:        AuditEventSyscallDenied,
			Severity:    SeverityWarning,
		},
		{
			ContainerID: "container-2",
			Type:        AuditEventSecurityViolation,
			Severity:    SeverityError,
		},
	}
	
	for _, event := range events {
		auditor.LogEvent(event)
	}
	
	violations := []SecurityViolation{
		{
			ContainerID: "container-1",
			Type:        ViolationCapability,
			Severity:    SeverityError,
		},
		{
			ContainerID: "container-2",
			Type:        ViolationSyscall,
			Severity:    SeverityWarning,
		},
	}
	
	for _, violation := range violations {
		auditor.LogViolation(violation)
	}
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Get statistics
	stats := auditor.GetStatistics()
	
	if stats == nil {
		t.Fatal("Statistics should not be nil")
	}
	
	if stats.TotalEvents != int64(len(events)) {
		t.Errorf("Expected %d total events, got %d", len(events), stats.TotalEvents)
	}
	
	if stats.ViolationCount != int64(len(violations)) {
		t.Errorf("Expected %d violations, got %d", len(violations), stats.ViolationCount)
	}
	
	// Check event type counts
	if stats.EventsByType[AuditEventCapabilityUsage] != 1 {
		t.Error("Capability usage event count should be 1")
	}
	
	if stats.EventsByType[AuditEventSyscallDenied] != 1 {
		t.Error("Syscall denied event count should be 1")
	}
	
	if stats.EventsByType[AuditEventSecurityViolation] != 1 {
		t.Error("Security violation event count should be 1")
	}
	
	// Check severity counts
	if stats.EventsBySeverity[SeverityInfo] != 1 {
		t.Error("Info severity event count should be 1")
	}
	
	if stats.EventsBySeverity[SeverityWarning] != 1 {
		t.Error("Warning severity event count should be 1")
	}
	
	if stats.EventsBySeverity[SeverityError] != 1 {
		t.Error("Error severity event count should be 1")
	}
	
	// Check container statistics
	if len(stats.TopContainers) == 0 {
		t.Error("Should have container statistics")
	}
}

func TestResolveViolation(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:     true,
		LogPath:     filepath.Join(tempDir, "audit.log"),
		BufferSize:  100,
		FlushInterval: 50 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Log a violation
	violation := SecurityViolation{
		ID:          "test-violation-1",
		ContainerID: "test-container",
		Type:        ViolationCapability,
		Severity:    SeverityError,
		Status:      "open",
	}
	
	auditor.LogViolation(violation)
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Test resolving non-existent violation
	err = auditor.ResolveViolation("non-existent", "test resolution")
	if err == nil {
		t.Error("Should return error for non-existent violation")
	}
	
	// Test resolving existing violation
	resolution := "Fixed by updating security policy"
	err = auditor.ResolveViolation("test-violation-1", resolution)
	if err != nil {
		t.Fatalf("ResolveViolation failed: %v", err)
	}
	
	// Verify violation was resolved
	auditor.mu.RLock()
	found := false
	for _, v := range auditor.violations {
		if v.ID == "test-violation-1" {
			found = true
			if v.Status != "resolved" {
				t.Error("Violation status should be 'resolved'")
			}
			if v.Resolution != resolution {
				t.Error("Resolution should be stored")
			}
			if v.ResolvedAt == nil {
				t.Error("ResolvedAt should be set")
			}
			break
		}
	}
	auditor.mu.RUnlock()
	
	if !found {
		t.Error("Violation should still exist but be marked as resolved")
	}
}

func TestEventFiltering(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:         true,
		LogPath:         filepath.Join(tempDir, "audit.log"),
		BufferSize:      100,
		FlushInterval:   50 * time.Millisecond,
		MinimumSeverity: SeverityWarning, // Filter out Info events
		EventTypes: []AuditEventType{
			AuditEventSecurityViolation,
			AuditEventCapabilityUsage,
		},
		ExcludedEventTypes: []AuditEventType{
			AuditEventSyscallDenied,
		},
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Log events with different severities and types
	events := []AuditEvent{
		{
			Type:     AuditEventCapabilityUsage,
			Severity: SeverityInfo, // Should be filtered out by severity
		},
		{
			Type:     AuditEventCapabilityUsage,
			Severity: SeverityError, // Should be included
		},
		{
			Type:     AuditEventSyscallDenied,
			Severity: SeverityError, // Should be filtered out by excluded type
		},
		{
			Type:     AuditEventSecurityViolation,
			Severity: SeverityWarning, // Should be included
		},
		{
			Type:     AuditEventNamespaceAccess,
			Severity: SeverityError, // Should be filtered out by allowed types
		},
	}
	
	for _, event := range events {
		auditor.LogEvent(event)
	}
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Check filtered results
	auditor.mu.RLock()
	eventsCount := len(auditor.events)
	auditor.mu.RUnlock()
	
	// Should only have 2 events: CapabilityUsage with Error severity and SecurityViolation with Warning severity
	expectedCount := 2
	if eventsCount != expectedCount {
		t.Errorf("Expected %d events after filtering, got %d", expectedCount, eventsCount)
	}
}

func TestRiskScoreCalculation(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:       true,
		LogPath:       filepath.Join(tempDir, "audit.log"),
		BufferSize:    100,
		FlushInterval: 50 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	testCases := []struct {
		name           string
		event          AuditEvent
		expectedRisk   float64
		riskTolerance  float64
		description    string
	}{
		{
			name: "critical security violation",
			event: AuditEvent{
				Type:     AuditEventSecurityViolation,
				Severity: SeverityCritical,
			},
			expectedRisk:  1.0,
			riskTolerance: 0.1,
			description:   "Critical security violation should have maximum risk",
		},
		{
			name: "info capability usage",
			event: AuditEvent{
				Type:     AuditEventCapabilityUsage,
				Severity: SeverityInfo,
			},
			expectedRisk:  0.4, // Base 0.1 + type 0.3
			riskTolerance: 0.1,
			description:   "Info capability usage should have low-medium risk",
		},
		{
			name: "warning syscall denied",
			event: AuditEvent{
				Type:     AuditEventSyscallDenied,
				Severity: SeverityWarning,
			},
			expectedRisk:  0.6, // Base 0.3 + type 0.3
			riskTolerance: 0.1,
			description:   "Warning syscall denied should have medium risk",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			risk := auditor.calculateRiskScore(tc.event)
			
			if risk < 0 || risk > 1 {
				t.Errorf("Risk score should be between 0 and 1, got %f", risk)
			}
			
			if risk < tc.expectedRisk-tc.riskTolerance || risk > tc.expectedRisk+tc.riskTolerance {
				t.Errorf("%s: expected risk around %f, got %f", tc.description, tc.expectedRisk, risk)
			}
		})
	}
}

func TestLogRotation(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")
	
	config := &AuditConfig{
		Enabled:     true,
		LogPath:     logPath,
		MaxLogSize:  100, // Very small size to trigger rotation
		MaxLogFiles: 3,
		BufferSize:  10,
		FlushInterval: 10 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Log many events to exceed log size
	for i := 0; i < 20; i++ {
		event := AuditEvent{
			ContainerID: "test-container",
			Type:        AuditEventSecurityViolation,
			Severity:    SeverityError,
			Message:     "This is a test message that should make the log file grow in size",
		}
		auditor.LogEvent(event)
	}
	
	// Give time for processing and potential rotation
	time.Sleep(500 * time.Millisecond)
	
	// Check if original log file exists
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		t.Error("Original log file should exist")
	}
}

func TestCleanup(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:       true,
		LogPath:       filepath.Join(tempDir, "audit.log"),
		RetentionDays: 1, // Very short retention for testing
		BufferSize:    100,
		FlushInterval: 50 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Log events with past timestamps
	now := time.Now()
	events := []AuditEvent{
		{
			ID:          "old-event",
			Timestamp:   now.AddDate(0, 0, -2), // 2 days old
			ContainerID: "test-container",
			Type:        AuditEventSecurityViolation,
			Severity:    SeverityError,
		},
		{
			ID:          "recent-event",
			Timestamp:   now,
			ContainerID: "test-container",
			Type:        AuditEventCapabilityUsage,
			Severity:    SeverityInfo,
		},
	}
	
	// Directly add to events to control timestamps
	auditor.mu.Lock()
	auditor.events = append(auditor.events, events...)
	auditor.mu.Unlock()
	
	// Perform cleanup
	auditor.performCleanup()
	
	// Check that old events were removed
	auditor.mu.RLock()
	remainingCount := len(auditor.events)
	var foundOld, foundRecent bool
	for _, event := range auditor.events {
		if event.ID == "old-event" {
			foundOld = true
		}
		if event.ID == "recent-event" {
			foundRecent = true
		}
	}
	auditor.mu.RUnlock()
	
	if remainingCount != 1 {
		t.Errorf("Expected 1 event after cleanup, got %d", remainingCount)
	}
	
	if foundOld {
		t.Error("Old event should be removed")
	}
	
	if !foundRecent {
		t.Error("Recent event should be preserved")
	}
}

func TestConcurrentAuditOperations(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:     true,
		LogPath:     filepath.Join(tempDir, "audit.log"),
		BufferSize:  1000,
		FlushInterval: 100 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Test concurrent event logging
	done := make(chan bool, 20)
	
	// Log events concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			event := AuditEvent{
				ContainerID: fmt.Sprintf("container-%d", id),
				Type:        AuditEventCapabilityUsage,
				Severity:    SeverityInfo,
				Action:      fmt.Sprintf("action-%d", id),
			}
			auditor.LogEvent(event)
			done <- true
		}(i)
	}
	
	// Log violations concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			violation := SecurityViolation{
				ContainerID: fmt.Sprintf("container-%d", id),
				Type:        ViolationCapability,
				Severity:    SeverityError,
				Status:      "open",
			}
			auditor.LogViolation(violation)
			done <- true
		}(i)
	}
	
	// Wait for all operations to complete
	for i := 0; i < 20; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent test timed out")
		}
	}
	
	// Give time for processing
	time.Sleep(500 * time.Millisecond)
	
	// Verify all events and violations were processed
	stats := auditor.GetStatistics()
	
	if stats.TotalEvents < 10 {
		t.Errorf("Expected at least 10 events, got %d", stats.TotalEvents)
	}
	
	if stats.ViolationCount < 10 {
		t.Errorf("Expected at least 10 violations, got %d", stats.ViolationCount)
	}
}

func TestEventFilterInterface(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:     true,
		LogPath:     filepath.Join(tempDir, "audit.log"),
		BufferSize:  100,
		FlushInterval: 50 * time.Millisecond,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Create a custom filter
	filter := &testEventFilter{
		allowedContainers: map[string]bool{
			"allowed-container": true,
		},
	}
	
	auditor.AddEventFilter(filter)
	
	// Log events for different containers
	events := []AuditEvent{
		{
			ContainerID: "allowed-container",
			Type:        AuditEventCapabilityUsage,
			Severity:    SeverityInfo,
		},
		{
			ContainerID: "blocked-container",
			Type:        AuditEventCapabilityUsage,
			Severity:    SeverityInfo,
		},
	}
	
	for _, event := range events {
		auditor.LogEvent(event)
	}
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Check that only allowed events were stored
	auditor.mu.RLock()
	eventsCount := len(auditor.events)
	var foundAllowed, foundBlocked bool
	for _, event := range auditor.events {
		if event.ContainerID == "allowed-container" {
			foundAllowed = true
		}
		if event.ContainerID == "blocked-container" {
			foundBlocked = true
		}
	}
	auditor.mu.RUnlock()
	
	if eventsCount != 1 {
		t.Errorf("Expected 1 event after filtering, got %d", eventsCount)
	}
	
	if !foundAllowed {
		t.Error("Allowed event should be stored")
	}
	
	if foundBlocked {
		t.Error("Blocked event should not be stored")
	}
}

func TestRealtimeListener(t *testing.T) {
	tempDir := t.TempDir()
	config := &AuditConfig{
		Enabled:           true,
		LogPath:           filepath.Join(tempDir, "audit.log"),
		BufferSize:        100,
		FlushInterval:     50 * time.Millisecond,
		RealTimeMonitoring: true,
	}
	
	auditor, err := NewSecurityAuditor(config)
	if err != nil {
		t.Fatalf("NewSecurityAuditor failed: %v", err)
	}
	
	defer auditor.Shutdown()
	
	// Create a test listener
	listener := &testRealtimeListener{
		eventsChan:     make(chan AuditEvent, 10),
		violationsChan: make(chan SecurityViolation, 10),
	}
	
	auditor.AddRealtimeListener(listener)
	
	// Log an event
	event := AuditEvent{
		ContainerID: "test-container",
		Type:        AuditEventSecurityViolation,
		Severity:    SeverityError,
	}
	
	auditor.LogEvent(event)
	
	// Log a violation
	violation := SecurityViolation{
		ContainerID: "test-container",
		Type:        ViolationCapability,
		Severity:    SeverityError,
	}
	
	auditor.LogViolation(violation)
	
	// Give time for processing
	time.Sleep(200 * time.Millisecond)
	
	// Check that listener received notifications
	select {
	case receivedEvent := <-listener.eventsChan:
		if receivedEvent.ContainerID != event.ContainerID {
			t.Error("Received event should match logged event")
		}
	case <-time.After(time.Second):
		t.Error("Listener should have received event notification")
	}
	
	select {
	case receivedViolation := <-listener.violationsChan:
		if receivedViolation.ContainerID != violation.ContainerID {
			t.Error("Received violation should match logged violation")
		}
	case <-time.After(time.Second):
		t.Error("Listener should have received violation notification")
	}
}

// Test helper implementations

type testEventFilter struct {
	allowedContainers map[string]bool
}

func (f *testEventFilter) ShouldInclude(event AuditEvent) bool {
	return f.allowedContainers[event.ContainerID]
}

type testRealtimeListener struct {
	eventsChan     chan AuditEvent
	violationsChan chan SecurityViolation
}

func (l *testRealtimeListener) OnEvent(event AuditEvent) {
	select {
	case l.eventsChan <- event:
	default:
		// Channel full, drop event
	}
}

func (l *testRealtimeListener) OnViolation(violation SecurityViolation) {
	select {
	case l.violationsChan <- violation:
	default:
		// Channel full, drop violation
	}
}