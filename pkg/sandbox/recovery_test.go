package sandbox

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestRunCClient creates a real RunCClient for testing
func createTestRunCClient(t *testing.T) *runtime.RunCClient {
	tempDir := t.TempDir()
	client, err := runtime.NewRunCClient(tempDir)
	require.NoError(t, err)
	return client
}

// createBenchRunCClient creates a real RunCClient for benchmarks  
func createBenchRunCClient(b *testing.B) *runtime.RunCClient {
	tempDir := b.TempDir()
	client, err := runtime.NewRunCClient(tempDir)
	require.NoError(b, err)
	return client
}

// MockRunCClient is no longer needed since we use real RunCClient
// But keeping the type for backward compatibility in the helper functions
type MockRunCClient = runtime.RunCClient

// Helper function to create test database
func createTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	return db
}

// Helper function to create test database for benchmarks
func createBenchDB(b *testing.B) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(b, err)
	return db
}

// Helper function to create test recovery manager
func createTestRecoveryManager(t *testing.T) (*RecoveryManager, *MockRunCClient, *StateMachine, *EventBus) {
	db := createTestDB(t)
	
	stateMachine, err := NewStateMachine(db)
	require.NoError(t, err)
	
	eventBus := NewEventBus(100, nil)
	runCClient := createTestRunCClient(t)
	
	rm, err := NewRecoveryManager(db, runCClient, stateMachine, eventBus)
	require.NoError(t, err)
	
	return rm, runCClient, stateMachine, eventBus
}

// Helper function to create recovery manager for benchmarks
func createBenchRecoveryManager(b *testing.B) (*RecoveryManager, *MockRunCClient, *StateMachine, *EventBus) {
	db := createBenchDB(b)
	
	stateMachine, err := NewStateMachine(db)
	require.NoError(b, err)
	
	eventBus := NewEventBus(100, nil)
	runCClient := createBenchRunCClient(b)
	
	rm, err := NewRecoveryManager(db, runCClient, stateMachine, eventBus)
	require.NoError(b, err)
	
	return rm, runCClient, stateMachine, eventBus
}

func TestNewRecoveryManager(t *testing.T) {
	db := createTestDB(t)
	stateMachine, err := NewStateMachine(db)
	require.NoError(t, err)
	
	eventBus := NewEventBus(100, nil)
	runCClient := createTestRunCClient(t)
	
	rm, err := NewRecoveryManager(db, runCClient, stateMachine, eventBus)
	assert.NoError(t, err)
	assert.NotNil(t, rm)
	assert.NotNil(t, rm.defaultPolicy)
	assert.Equal(t, 3, rm.defaultPolicy.MaxRetries)
	
	// Cleanup
	rm.Stop()
}

func TestDefaultRecoveryPolicy(t *testing.T) {
	policy := DefaultRecoveryPolicy()
	
	assert.Equal(t, 3, policy.MaxRetries)
	assert.Equal(t, 1*time.Second, policy.BaseDelay)
	assert.Equal(t, 60*time.Second, policy.MaxDelay)
	assert.Equal(t, 2.0, policy.BackoffMultiplier)
	assert.Equal(t, 0.1, policy.JitterPercent)
	assert.True(t, policy.PreserveState)
	assert.Equal(t, 30*time.Second, policy.HealthCheckTimeout)
	assert.Equal(t, 5*time.Minute, policy.RecoveryTimeout)
	
	// Check default actions
	assert.Equal(t, RecoveryActionRestart, policy.Actions[FailureTypeOOM])
	assert.Equal(t, RecoveryActionRestart, policy.Actions[FailureTypeCrash])
	assert.Equal(t, RecoveryActionRecreate, policy.Actions[FailureTypeCorrupted])
}

func TestSetRecoveryPolicy(t *testing.T) {
	rm, _, _, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	containerID := "test-container"
	policy := &RecoveryPolicy{
		MaxRetries:        5,
		BaseDelay:         2 * time.Second,
		BackoffMultiplier: 1.5,
		Actions: map[FailureType]RecoveryAction{
			FailureTypeOOM: RecoveryActionTerminate,
		},
	}
	
	err := rm.SetRecoveryPolicy(containerID, policy)
	assert.NoError(t, err)
	
	// Verify policy was set
	state, err := rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, 5, state.Policy.MaxRetries)
	assert.Equal(t, 2*time.Second, state.Policy.BaseDelay)
	assert.Equal(t, RecoveryActionTerminate, state.Policy.Actions[FailureTypeOOM])
}

func TestEnableDisableRecovery(t *testing.T) {
	rm, _, _, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	containerID := "test-container"
	
	// Test enable
	err := rm.EnableRecovery(containerID)
	assert.NoError(t, err)
	
	state, err := rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.True(t, state.RecoveryEnabled)
	
	// Test disable
	err = rm.DisableRecovery(containerID)
	assert.NoError(t, err)
	
	state, err = rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.False(t, state.RecoveryEnabled)
}

func TestTriggerManualRecovery(t *testing.T) {
	rm, _, _, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	containerID := "test-container"
	
	// Enable recovery first
	err := rm.EnableRecovery(containerID)
	require.NoError(t, err)
	
	// Note: Using real RunCClient for testing
	
	// Trigger manual recovery
	err = rm.TriggerRecovery(containerID, FailureTypeCrash, "manual test")
	assert.NoError(t, err)
	
	// Wait for processing
	time.Sleep(100 * time.Millisecond)
	
	// Verify state was updated
	state, err := rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, FailureTypeCrash, state.LastFailureType)
	assert.True(t, len(state.Attempts) > 0)
	
}

func TestResetRecoveryState(t *testing.T) {
	rm, _, _, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	containerID := "test-container"
	
	// Enable recovery and set some state
	err := rm.EnableRecovery(containerID)
	require.NoError(t, err)
	
	rm.mu.Lock()
	state := rm.getOrCreateRecoveryState(containerID)
	state.CurrentRetries = 3
	state.LastFailureTime = time.Now()
	state.LastFailureType = FailureTypeOOM
	state.Attempts = append(state.Attempts, RecoveryAttempt{
		ID:          "test-attempt",
		ContainerID: containerID,
		AttemptNum:  1,
	})
	rm.mu.Unlock()
	
	// Reset state
	err = rm.ResetRecoveryState(containerID)
	assert.NoError(t, err)
	
	// Verify reset
	state, err = rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, 0, state.CurrentRetries)
	assert.True(t, state.LastFailureTime.IsZero())
	assert.Equal(t, 0, len(state.Attempts))
}

func TestRecoveryMetrics(t *testing.T) {
	rm, _, _, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	// Initial metrics should be empty
	metrics := rm.GetRecoveryMetrics()
	assert.Equal(t, int64(0), metrics.TotalRecoveries)
	assert.Equal(t, int64(0), metrics.SuccessfulRecoveries)
	assert.Equal(t, int64(0), metrics.FailedRecoveries)
	
	// Update metrics manually for testing
	rm.updateRecoveryMetrics(FailureTypeOOM, RecoveryActionRestart, true, time.Second)
	rm.updateRecoveryMetrics(FailureTypeCrash, RecoveryActionRestart, false, 2*time.Second)
	
	metrics = rm.GetRecoveryMetrics()
	assert.Equal(t, int64(2), metrics.TotalRecoveries)
	assert.Equal(t, int64(1), metrics.SuccessfulRecoveries)
	assert.Equal(t, int64(1), metrics.FailedRecoveries)
	assert.Equal(t, int64(1), metrics.FailuresByType[FailureTypeOOM])
	assert.Equal(t, int64(1), metrics.FailuresByType[FailureTypeCrash])
	assert.Equal(t, int64(2), metrics.ActionsByType[RecoveryActionRestart])
}

func TestCleanupContainer(t *testing.T) {
	rm, _, _, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	containerID := "test-container"
	
	// Create recovery state
	err := rm.EnableRecovery(containerID)
	require.NoError(t, err)
	
	// Verify state exists
	_, err = rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	
	// Cleanup container
	err = rm.CleanupContainer(containerID)
	assert.NoError(t, err)
	
	// Verify state was removed
	_, err = rm.GetRecoveryState(containerID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no recovery state found")
}

func TestDetectFailureType(t *testing.T) {
	rm, _, _, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	tests := []struct {
		name        string
		transition  StateTransition
		expectedType FailureType
	}{
		{
			name: "OOM failure",
			transition: StateTransition{
				ErrorMessage: "container killed due to OOM",
				Reason:       "out of memory",
			},
			expectedType: FailureTypeOOM,
		},
		{
			name: "Timeout failure",
			transition: StateTransition{
				ErrorMessage: "operation timed out",
				Reason:       "timeout exceeded",
			},
			expectedType: FailureTypeTimeout,
		},
		{
			name: "Crash failure",
			transition: StateTransition{
				ErrorMessage: "process crashed with signal 11",
				Reason:       "segmentation fault",
			},
			expectedType: FailureTypeCrash,
		},
		{
			name: "Network failure",
			transition: StateTransition{
				ErrorMessage: "network connection failed",
				Reason:       "dns resolution error",
			},
			expectedType: FailureTypeNetwork,
		},
		{
			name: "Unknown failure",
			transition: StateTransition{
				ErrorMessage: "something went wrong",
				Reason:       "unknown error",
			},
			expectedType: FailureTypeUnknown,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failureType := rm.detectFailureType(tt.transition)
			assert.Equal(t, tt.expectedType, failureType)
		})
	}
}

func TestCalculateBackoffDelay(t *testing.T) {
	rm, _, _, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	policy := &RecoveryPolicy{
		BaseDelay:         1 * time.Second,
		MaxDelay:          60 * time.Second,
		BackoffMultiplier: 2.0,
		JitterPercent:     0.0, // Disable jitter for predictable tests
	}
	
	tests := []struct {
		retryCount   int
		expectedMin  time.Duration
		expectedMax  time.Duration
	}{
		{1, 1 * time.Second, 1 * time.Second},
		{2, 2 * time.Second, 2 * time.Second},
		{3, 4 * time.Second, 4 * time.Second},
		{4, 8 * time.Second, 8 * time.Second},
		{10, 60 * time.Second, 60 * time.Second}, // Should be capped at max delay
	}
	
	for _, tt := range tests {
		t.Run(fmt.Sprintf("retry_%d", tt.retryCount), func(t *testing.T) {
			delay := rm.calculateBackoffDelay(policy, tt.retryCount)
			assert.GreaterOrEqual(t, delay, tt.expectedMin)
			assert.LessOrEqual(t, delay, tt.expectedMax)
		})
	}
}

func TestPerformRecoveryActions(t *testing.T) {
	rm, _, stateMachine, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	containerID := "test-container"
	policy := DefaultRecoveryPolicy()
	
	// Test restart action
	t.Run("restart_action", func(t *testing.T) {
		// Note: Using real RunCClient for testing
		
		attempt := &RecoveryAttempt{
			ID:          "test-restart",
			ContainerID: containerID,
		}
		
		err := rm.performRecoveryAction(containerID, RecoveryActionRestart, policy, attempt)
		assert.NoError(t, err)
		
		// Verify state machine was updated
		state, exists := stateMachine.GetState(containerID)
		if exists {
			assert.Equal(t, ContainerStateRunning, state)
		}
	})
	
	// Test terminate action
	t.Run("terminate_action", func(t *testing.T) {
		// Note: Using real RunCClient for testing
		
		attempt := &RecoveryAttempt{
			ID:          "test-terminate",
			ContainerID: containerID,
		}
		
		err := rm.performRecoveryAction(containerID, RecoveryActionTerminate, policy, attempt)
		assert.NoError(t, err)
	})
	
}

func TestRecoveryPersistence(t *testing.T) {
	db := createTestDB(t)
	stateMachine, err := NewStateMachine(db)
	require.NoError(t, err)
	
	eventBus := NewEventBus(100, nil)
	mockRunC := createTestRunCClient(t)
	
	// Create first recovery manager
	rm1, err := NewRecoveryManager(db, mockRunC, stateMachine, eventBus)
	require.NoError(t, err)
	
	containerID := "test-container"
	policy := &RecoveryPolicy{
		MaxRetries:   10,
		BaseDelay:    5 * time.Second,
		PreserveState: false,
		Actions: map[FailureType]RecoveryAction{
			FailureTypeOOM: RecoveryActionTerminate,
		},
	}
	
	// Set policy and state
	err = rm1.SetRecoveryPolicy(containerID, policy)
	require.NoError(t, err)
	
	rm1.mu.Lock()
	state := rm1.getOrCreateRecoveryState(containerID)
	state.CurrentRetries = 2
	state.LastFailureType = FailureTypeOOM
	state.LastFailureTime = time.Now()
	rm1.persistRecoveryState(state)
	rm1.mu.Unlock()
	
	rm1.Stop()
	
	// Create second recovery manager with same database
	rm2, err := NewRecoveryManager(db, mockRunC, stateMachine, eventBus)
	require.NoError(t, err)
	defer rm2.Stop()
	
	// Verify state was loaded
	loadedState, err := rm2.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, 2, loadedState.CurrentRetries)
	assert.Equal(t, FailureTypeOOM, loadedState.LastFailureType)
	assert.NotNil(t, loadedState.Policy)
	assert.Equal(t, 10, loadedState.Policy.MaxRetries)
	assert.Equal(t, RecoveryActionTerminate, loadedState.Policy.Actions[FailureTypeOOM])
}

func TestRecoveryWithMaxRetries(t *testing.T) {
	rm, _, stateMachine, _ := createTestRecoveryManager(t)
	defer rm.Stop()
	
	containerID := "test-container"
	
	// Set policy with low max retries
	policy := &RecoveryPolicy{
		MaxRetries:        1,
		BaseDelay:         10 * time.Millisecond,
		BackoffMultiplier: 1.0,
		Actions: map[FailureType]RecoveryAction{
			FailureTypeCrash: RecoveryActionRestart,
		},
	}
	
	err := rm.SetRecoveryPolicy(containerID, policy)
	require.NoError(t, err)
	
	// Set initial state
	err = stateMachine.SetState(containerID, ContainerStateRunning, "Initial state", nil)
	require.NoError(t, err)
	
	// Note: Using real RunCClient for testing
	
	// Trigger first failure -> should attempt recovery
	err = stateMachine.SetState(containerID, ContainerStateFailed, "First failure", nil)
	require.NoError(t, err)
	
	// Wait for recovery to complete
	time.Sleep(50 * time.Millisecond)
	
	// Verify recovery was attempted
	state, err := rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(state.Attempts))
	
	// Trigger second failure -> should NOT attempt recovery (max retries exceeded)
	err = stateMachine.SetState(containerID, ContainerStateFailed, "Second failure", nil)
	require.NoError(t, err)
	
	// Wait a bit to ensure no recovery is attempted
	time.Sleep(50 * time.Millisecond)
	
	// Should still only have 1 attempt
	state, err = rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(state.Attempts))
	
}

func TestRecoveryStateTransitionCallback(t *testing.T) {
	rm, _, stateMachine, eventBus := createTestRecoveryManager(t)
	defer rm.Stop()
	
	containerID := "test-container"
	
	// Enable recovery
	err := rm.EnableRecovery(containerID)
	require.NoError(t, err)
	
	// Note: Using real RunCClient for testing
	
	// Subscribe to events to verify recovery was triggered
	recoveryTriggered := make(chan bool, 1)
	eventBus.Subscribe(func(event Event) error {
		if event.Type == EventTypeRecovery {
			recoveryTriggered <- true
		}
		return nil
	}, nil, EventTypeRecovery)
	
	// Set initial state
	err = stateMachine.SetState(containerID, ContainerStateRunning, "Initial state", nil)
	require.NoError(t, err)
	
	// Trigger failure state transition
	err = stateMachine.SetState(containerID, ContainerStateFailed, "Container failed", nil)
	require.NoError(t, err)
	
	// Wait for recovery to be triggered
	select {
	case <-recoveryTriggered:
		// Recovery was triggered
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Recovery was not triggered within timeout")
	}
	
	// Verify recovery state was updated
	state, err := rm.GetRecoveryState(containerID)
	assert.NoError(t, err)
	assert.Equal(t, FailureTypeUnknown, state.LastFailureType) // Default for generic failure
	assert.True(t, len(state.Attempts) > 0)
	
}

// Benchmark tests

func BenchmarkRecoveryManager_TriggerRecovery(b *testing.B) {
	rm, _, _, _ := createBenchRecoveryManager(b)
	defer rm.Stop()
	
	containerID := "benchmark-container"
	err := rm.EnableRecovery(containerID)
	require.NoError(b, err)
	
	// Note: Using real RunCClient for testing
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		err := rm.TriggerRecovery(containerID, FailureTypeCrash, "benchmark test")
		require.NoError(b, err)
		
		// Reset retry count to allow multiple recoveries
		rm.ResetRecoveryState(containerID)
	}
}

func BenchmarkRecoveryManager_GetRecoveryState(b *testing.B) {
	rm, _, _, _ := createBenchRecoveryManager(b)
	defer rm.Stop()
	
	containerID := "benchmark-container"
	err := rm.EnableRecovery(containerID)
	require.NoError(b, err)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, err := rm.GetRecoveryState(containerID)
		require.NoError(b, err)
	}
}

// Helper function for require.NoError with *testing.B
func requireNoError(b *testing.B, err error) {
	if err != nil {
		b.Fatalf("Expected no error, got: %v", err)
	}
}