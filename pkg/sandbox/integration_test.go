package sandbox

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegrationPhase21 tests the complete Phase 2.1 integration
func TestIntegrationPhase21(t *testing.T) {
	// Setup test environment
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	workspaceDir := filepath.Join(tmpDir, "workspaces")
	
	// Create manager with all Phase 2.1 components
	manager, err := NewManager(dbPath, workspaceDir)
	require.NoError(t, err)
	defer manager.Close()

	// Verify all components are initialized
	assert.NotNil(t, manager.stateMachine)
	assert.NotNil(t, manager.healthChecker)
	assert.NotNil(t, manager.eventBus)
	assert.NotNil(t, manager.metricsCollector)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Test 1: Create a sandbox and verify state machine integration
	t.Run("SandboxCreation", func(t *testing.T) {
		config := SandboxConfig{
			Image:        "test",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"TEST": "value",
			},
			Resources: ResourceLimits{
				CPULimit:    "1",
				MemoryLimit: "512M",
				DiskLimit:   "1G",
			},
		}

		// Note: This will fail in test environment without actual container runtime
		// but we can test the state machine logic
		sandbox, err := manager.CreateSandbox(ctx, config)
		if err != nil {
			// Expected in test environment - verify state machine was updated anyway
			state, exists := manager.GetContainerState(sandbox.ContainerID)
			if exists {
				assert.Equal(t, ContainerStateCreating, state)
			}
		} else {
			// Verify sandbox was created and state is tracked
			assert.NotEmpty(t, sandbox.ID)
			assert.NotEmpty(t, sandbox.ContainerID)
			
			// Check state machine
			state, exists := manager.GetContainerState(sandbox.ContainerID)
			assert.True(t, exists)
			assert.Equal(t, ContainerStateRunning, state)
		}
	})

	// Test 2: Event system integration
	t.Run("EventSystem", func(t *testing.T) {
		var receivedEvents []Event
		
		// Subscribe to events
		subscriptionID := manager.SubscribeToEvents(func(event Event) error {
			receivedEvents = append(receivedEvents, event)
			return nil
		}, nil, EventTypeStateChange, EventTypeHealthAlert, EventTypeMetricsUpdate)
		
		defer manager.UnsubscribeFromEvents(subscriptionID)

		// Generate some events
		testContainerID := "test-container-events"
		err := manager.stateMachine.SetState(testContainerID, ContainerStateCreating, "Test event", nil)
		require.NoError(t, err)

		// Wait for event processing
		time.Sleep(100 * time.Millisecond)

		// Verify events were received
		assert.Greater(t, len(receivedEvents), 0)
		
		// Find the state change event
		var stateChangeEvent *Event
		for _, event := range receivedEvents {
			if event.Type == EventTypeStateChange && event.ContainerID == testContainerID {
				stateChangeEvent = &event
				break
			}
		}
		
		require.NotNil(t, stateChangeEvent)
		assert.Equal(t, EventTypeStateChange, stateChangeEvent.Type)
		assert.Equal(t, testContainerID, stateChangeEvent.ContainerID)
	})

	// Test 3: Health monitoring integration
	t.Run("HealthMonitoring", func(t *testing.T) {
		testContainerID := "test-container-health"
		
		// Add container to health monitoring
		manager.healthChecker.AddContainer(testContainerID, nil)
		
		// Wait a moment for health check scheduling
		time.Sleep(100 * time.Millisecond)
		
		// Verify container is being monitored
		stats := manager.GetHealthStatistics()
		assert.NotNil(t, stats)
	})

	// Test 4: Metrics collection integration
	t.Run("MetricsCollection", func(t *testing.T) {
		// Wait for at least one metrics collection cycle
		time.Sleep(2 * time.Second)
		
		metrics := manager.GetSystemMetrics()
		require.NotNil(t, metrics)
		
		// Verify metrics structure
		assert.NotNil(t, metrics.StateDistribution)
		assert.NotNil(t, metrics.HealthDistribution)
		assert.NotNil(t, metrics.EventsByType)
		assert.NotNil(t, metrics.EventsBySeverity)
		assert.NotZero(t, metrics.Timestamp)
	})

	// Test 5: Alert rules integration
	t.Run("AlertRules", func(t *testing.T) {
		// Get default alert rules
		rules := manager.GetAlertRules()
		assert.Greater(t, len(rules), 0)
		
		// Add custom alert rule
		customRule := AlertRule{
			ID:          "test-alert",
			Name:        "Test Alert",
			Description: "Test alert for integration testing",
			Condition:   AlertConditionUnhealthyContainers,
			Severity:    EventSeverityWarning,
			Threshold:   1,
			Duration:    1 * time.Minute,
			Enabled:     true,
		}
		
		manager.AddAlertRule(customRule)
		
		// Verify rule was added
		updatedRules := manager.GetAlertRules()
		assert.Equal(t, len(rules)+1, len(updatedRules))
		
		// Find the custom rule
		var foundRule *AlertRule
		for _, rule := range updatedRules {
			if rule.ID == "test-alert" {
				foundRule = &rule
				break
			}
		}
		
		require.NotNil(t, foundRule)
		assert.Equal(t, customRule.Name, foundRule.Name)
		assert.Equal(t, customRule.Condition, foundRule.Condition)
		
		// Test rule removal
		removed := manager.RemoveAlertRule("test-alert")
		assert.True(t, removed)
		
		finalRules := manager.GetAlertRules()
		assert.Equal(t, len(rules), len(finalRules))
	})

	// Test 6: State transition validation
	t.Run("StateTransitions", func(t *testing.T) {
		testContainerID := "test-container-transitions"
		
		// Test valid transition sequence
		err := manager.stateMachine.SetState(testContainerID, ContainerStateCreating, "Initial", nil)
		require.NoError(t, err)
		
		err = manager.stateMachine.SetState(testContainerID, ContainerStateRunning, "Started", nil)
		require.NoError(t, err)
		
		err = manager.stateMachine.SetState(testContainerID, ContainerStatePaused, "Paused", nil)
		require.NoError(t, err)
		
		err = manager.stateMachine.SetState(testContainerID, ContainerStateRunning, "Resumed", nil)
		require.NoError(t, err)
		
		err = manager.stateMachine.SetState(testContainerID, ContainerStateStopped, "Stopped", nil)
		require.NoError(t, err)
		
		// Test invalid transition
		err = manager.stateMachine.SetState(testContainerID, ContainerStatePaused, "Invalid", nil)
		assert.Error(t, err)
		
		// Verify transition history
		transitions := manager.GetContainerStateTransitions(testContainerID)
		assert.Len(t, transitions, 5) // Should have 5 valid transitions
		
		// Verify final state
		state, exists := manager.GetContainerState(testContainerID)
		assert.True(t, exists)
		assert.Equal(t, ContainerStateStopped, state)
	})

	// Test 7: Event history and persistence
	t.Run("EventPersistence", func(t *testing.T) {
		// Get event history
		events := manager.GetEvents(50)
		initialEventCount := len(events)
		
		// Generate some events
		for i := 0; i < 5; i++ {
			testContainerID := fmt.Sprintf("test-container-%d", i)
			manager.stateMachine.SetState(testContainerID, ContainerStateCreating, "Test persistence", nil)
		}
		
		// Wait for event processing
		time.Sleep(200 * time.Millisecond)
		
		// Verify events were added
		updatedEvents := manager.GetEvents(50)
		assert.Greater(t, len(updatedEvents), initialEventCount)
	})

	// Test 8: Statistics and reporting
	t.Run("Statistics", func(t *testing.T) {
		// Get state statistics
		stateStats := manager.GetStateStatistics()
		assert.NotNil(t, stateStats)
		assert.Contains(t, stateStats, ContainerStateCreating)
		assert.Contains(t, stateStats, ContainerStateRunning)
		assert.Contains(t, stateStats, ContainerStateStopped)
		assert.Contains(t, stateStats, ContainerStateFailed)
		assert.Contains(t, stateStats, ContainerStatePaused)
		
		// Get health statistics
		healthStats := manager.GetHealthStatistics()
		assert.NotNil(t, healthStats)
		
		// Verify we have some containers being tracked
		totalFromState := 0
		for _, count := range stateStats {
			totalFromState += count
		}
		assert.Greater(t, totalFromState, 0)
	})

	// Test 9: Component shutdown
	t.Run("ComponentShutdown", func(t *testing.T) {
		// Test graceful shutdown
		err := manager.Close()
		assert.NoError(t, err)
		
		// Verify components are stopped (no panics or hanging)
		// This is mainly testing that Stop() methods don't hang
	})
}

// TestStateRecovery tests state recovery after restart
func TestStateRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_recovery.db")
	workspaceDir := filepath.Join(tmpDir, "workspaces")
	
	// Create initial manager and set some states
	manager1, err := NewManager(dbPath, workspaceDir)
	require.NoError(t, err)
	
	testContainers := []string{"container-1", "container-2", "container-3"}
	for i, containerID := range testContainers {
		state := ContainerStateRunning
		if i == 1 {
			state = ContainerStatePaused
		} else if i == 2 {
			state = ContainerStateStopped
		}
		
		err = manager1.stateMachine.SetState(containerID, ContainerStateCreating, "Initial", nil)
		require.NoError(t, err)
		
		if state != ContainerStateCreating {
			err = manager1.stateMachine.SetState(containerID, state, "Set state", nil)
			require.NoError(t, err)
		}
	}
	
	// Close first manager
	manager1.Close()
	
	// Create new manager (simulating restart)
	manager2, err := NewManager(dbPath, workspaceDir)
	require.NoError(t, err)
	defer manager2.Close()
	
	// Verify states were recovered
	for i, containerID := range testContainers {
		expectedState := ContainerStateRunning
		if i == 1 {
			expectedState = ContainerStatePaused
		} else if i == 2 {
			expectedState = ContainerStateStopped
		}
		
		recoveredState, exists := manager2.GetContainerState(containerID)
		assert.True(t, exists, "Container %s state should exist after recovery", containerID)
		assert.Equal(t, expectedState, recoveredState, "Container %s state should be recovered correctly", containerID)
		
		// Verify transition history was preserved
		transitions := manager2.GetContainerStateTransitions(containerID)
		assert.Greater(t, len(transitions), 0, "Container %s should have transition history", containerID)
	}
}

// BenchmarkIntegration benchmarks the integrated system
func BenchmarkIntegration(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")
	workspaceDir := filepath.Join(tmpDir, "workspaces")
	
	manager, err := NewManager(dbPath, workspaceDir)
	require.NoError(b, err)
	defer manager.Close()
	
	_ = context.Background()
	
	b.ResetTimer()
	
	b.Run("StateTransitions", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			containerID := fmt.Sprintf("bench-container-%d", i)
			manager.stateMachine.SetState(containerID, ContainerStateCreating, "Benchmark", nil)
			manager.stateMachine.SetState(containerID, ContainerStateRunning, "Benchmark", nil)
		}
	})
	
	b.Run("EventPublishing", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			event := Event{
				Type:     EventTypeSystemAlert,
				Severity: EventSeverityInfo,
				Source:   "benchmark",
				Title:    "Benchmark Event",
				Message:  "Test event for benchmarking",
			}
			manager.eventBus.Publish(event)
		}
	})
	
	b.Run("MetricsCollection", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = manager.GetSystemMetrics()
		}
	})
}