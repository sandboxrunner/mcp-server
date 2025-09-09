package sandbox

import (
	"database/sql"
	"sync"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStateMachine(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)
	assert.NotNil(t, sm)

	sm.Stop()
}

func TestContainerStateValidation(t *testing.T) {
	tests := []struct {
		name  string
		state ContainerState
		valid bool
	}{
		{"Creating state", ContainerStateCreating, true},
		{"Running state", ContainerStateRunning, true},
		{"Paused state", ContainerStatePaused, true},
		{"Stopped state", ContainerStateStopped, true},
		{"Failed state", ContainerStateFailed, true},
		{"Invalid state", ContainerState("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.state.IsValid())
		})
	}
}

func TestContainerStateTransitions(t *testing.T) {
	tests := []struct {
		name         string
		from         ContainerState
		to           ContainerState
		shouldAllow  bool
	}{
		// Valid transitions from Creating
		{"Creating to Running", ContainerStateCreating, ContainerStateRunning, true},
		{"Creating to Failed", ContainerStateCreating, ContainerStateFailed, true},
		{"Creating to Paused (invalid)", ContainerStateCreating, ContainerStatePaused, false},
		
		// Valid transitions from Running
		{"Running to Paused", ContainerStateRunning, ContainerStatePaused, true},
		{"Running to Stopped", ContainerStateRunning, ContainerStateStopped, true},
		{"Running to Failed", ContainerStateRunning, ContainerStateFailed, true},
		{"Running to Creating (invalid)", ContainerStateRunning, ContainerStateCreating, false},
		
		// Valid transitions from Paused
		{"Paused to Running", ContainerStatePaused, ContainerStateRunning, true},
		{"Paused to Stopped", ContainerStatePaused, ContainerStateStopped, true},
		{"Paused to Failed", ContainerStatePaused, ContainerStateFailed, true},
		{"Paused to Creating (invalid)", ContainerStatePaused, ContainerStateCreating, false},
		
		// Valid transitions from Stopped
		{"Stopped to Running", ContainerStateStopped, ContainerStateRunning, true},
		{"Stopped to Failed", ContainerStateStopped, ContainerStateFailed, true},
		{"Stopped to Paused (invalid)", ContainerStateStopped, ContainerStatePaused, false},
		
		// Valid transitions from Failed
		{"Failed to Running", ContainerStateFailed, ContainerStateRunning, true},
		{"Failed to Creating", ContainerStateFailed, ContainerStateCreating, true},
		{"Failed to Paused (invalid)", ContainerStateFailed, ContainerStatePaused, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.shouldAllow, tt.from.CanTransitionTo(tt.to))
		})
	}
}

func TestStateMachineSetState(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)
	defer sm.Stop()

	containerID := "test-container-1"

	// Test initial state setting
	err = sm.SetState(containerID, ContainerStateCreating, "Initial creation", nil)
	assert.NoError(t, err)

	state, exists := sm.GetState(containerID)
	assert.True(t, exists)
	assert.Equal(t, ContainerStateCreating, state)

	// Test valid transition
	err = sm.SetState(containerID, ContainerStateRunning, "Container started", map[string]interface{}{
		"startup_time": 1.5,
	})
	assert.NoError(t, err)

	state, exists = sm.GetState(containerID)
	assert.True(t, exists)
	assert.Equal(t, ContainerStateRunning, state)

	// Test invalid transition
	err = sm.SetState(containerID, ContainerStateCreating, "Invalid transition", nil)
	assert.Error(t, err)

	// State should remain unchanged after invalid transition
	state, exists = sm.GetState(containerID)
	assert.True(t, exists)
	assert.Equal(t, ContainerStateRunning, state)
}

func TestStateMachineTransitionHistory(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)
	defer sm.Stop()

	containerID := "test-container-history"

	// Create a series of state transitions
	transitions := []struct {
		state  ContainerState
		reason string
	}{
		{ContainerStateCreating, "Initial creation"},
		{ContainerStateRunning, "Container started"},
		{ContainerStatePaused, "Paused for maintenance"},
		{ContainerStateRunning, "Resumed from maintenance"},
		{ContainerStateStopped, "Graceful shutdown"},
	}

	for _, tr := range transitions {
		err = sm.SetState(containerID, tr.state, tr.reason, nil)
		require.NoError(t, err)
		time.Sleep(1 * time.Millisecond) // Ensure timestamps differ
	}

	// Check transition history
	history := sm.GetTransitions(containerID)
	assert.Len(t, history, len(transitions))

	// Verify transition sequence
	for i, tr := range transitions {
		assert.Equal(t, tr.state, history[i].To)
		assert.Equal(t, tr.reason, history[i].Reason)
		assert.Equal(t, containerID, history[i].ContainerID)
	}

	// Verify from states (should be previous state)
	assert.Equal(t, ContainerState(""), history[0].From) // First transition has no previous state
	assert.Equal(t, ContainerStateCreating, history[1].From)
	assert.Equal(t, ContainerStateRunning, history[2].From)
	assert.Equal(t, ContainerStatePaused, history[3].From)
	assert.Equal(t, ContainerStateRunning, history[4].From)
}

func TestStateMachineCallbacks(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)
	defer sm.Stop()

	var callbackTransitions []StateTransition
	var callbackMutex sync.Mutex

	// Register callback
	sm.RegisterCallback(func(transition StateTransition) {
		callbackMutex.Lock()
		defer callbackMutex.Unlock()
		callbackTransitions = append(callbackTransitions, transition)
	})

	containerID := "test-container-callback"

	// Make some state changes
	err = sm.SetState(containerID, ContainerStateCreating, "Initial state", nil)
	require.NoError(t, err)

	err = sm.SetState(containerID, ContainerStateRunning, "Started", nil)
	require.NoError(t, err)

	// Wait a bit for async callback processing
	time.Sleep(100 * time.Millisecond)

	// Check callbacks were called
	callbackMutex.Lock()
	defer callbackMutex.Unlock()
	assert.Len(t, callbackTransitions, 2)
	assert.Equal(t, ContainerStateCreating, callbackTransitions[0].To)
	assert.Equal(t, ContainerStateRunning, callbackTransitions[1].To)
}

func TestStateMachineRecovery(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)

	containerID := "test-container-recovery"

	// Set initial state
	err = sm.SetState(containerID, ContainerStateRunning, "Running normally", nil)
	require.NoError(t, err)

	sm.Stop()

	// Create new state machine (simulating restart)
	sm2, err := NewStateMachine(db)
	require.NoError(t, err)
	defer sm2.Stop()

	// Check state was recovered
	state, exists := sm2.GetState(containerID)
	assert.True(t, exists)
	assert.Equal(t, ContainerStateRunning, state)

	// Test recovery with state mismatch
	err = sm2.RecoverState(containerID, ContainerStateStopped)
	assert.NoError(t, err)

	// Should transition to expected state
	state, exists = sm2.GetState(containerID)
	assert.True(t, exists)
	assert.Equal(t, ContainerStateStopped, state)

	// Test recovery with invalid transition
	err = sm2.RecoverState(containerID, ContainerStateCreating)
	assert.NoError(t, err)

	// Should transition to failed state since transition is invalid
	state, exists = sm2.GetState(containerID)
	assert.True(t, exists)
	assert.Equal(t, ContainerStateFailed, state)
}

func TestStateMachineRemoveContainer(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)
	defer sm.Stop()

	containerID := "test-container-remove"

	// Set state
	err = sm.SetState(containerID, ContainerStateRunning, "Running", nil)
	require.NoError(t, err)

	// Verify state exists
	_, exists := sm.GetState(containerID)
	assert.True(t, exists)

	// Remove container
	err = sm.RemoveContainer(containerID)
	assert.NoError(t, err)

	// Verify state is removed
	_, exists = sm.GetState(containerID)
	assert.False(t, exists)

	// Verify transitions are removed
	history := sm.GetTransitions(containerID)
	assert.Nil(t, history)
}

func TestStateMachineStatistics(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)
	defer sm.Stop()

	// Create containers in different states
	containers := map[string]ContainerState{
		"container1": ContainerStateRunning,
		"container2": ContainerStateRunning,
		"container3": ContainerStatePaused,
		"container4": ContainerStateFailed,
		"container5": ContainerStateStopped,
	}

	for id, state := range containers {
		err = sm.SetState(id, ContainerStateCreating, "Initial", nil)
		require.NoError(t, err)
		if state != ContainerStateCreating {
			err = sm.SetState(id, state, "Transition", nil)
			require.NoError(t, err)
		}
	}

	stats := sm.GetStateStatistics()
	assert.Equal(t, 2, stats[ContainerStateRunning])
	assert.Equal(t, 1, stats[ContainerStatePaused])
	assert.Equal(t, 1, stats[ContainerStateFailed])
	assert.Equal(t, 1, stats[ContainerStateStopped])
	assert.Equal(t, 0, stats[ContainerStateCreating])
}

func TestValidateTransitionMatrix(t *testing.T) {
	matrix := ValidateTransitionMatrix()
	
	// Test some known valid transitions
	assert.Contains(t, matrix[string(ContainerStateCreating)], string(ContainerStateRunning))
	assert.Contains(t, matrix[string(ContainerStateRunning)], string(ContainerStatePaused))
	assert.Contains(t, matrix[string(ContainerStatePaused)], string(ContainerStateRunning))
	
	// Test some known invalid transitions
	assert.NotContains(t, matrix[string(ContainerStateCreating)], string(ContainerStatePaused))
	assert.NotContains(t, matrix[string(ContainerStateStopped)], string(ContainerStatePaused))
}

func TestStateMachineWithError(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)
	defer sm.Stop()

	containerID := "test-container-error"

	// Set state with error
	err = sm.SetStateWithError(containerID, ContainerStateFailed, "Container crashed", "Out of memory", map[string]interface{}{
		"memory_usage": "95%",
		"oom_killed": true,
	})
	assert.NoError(t, err)

	// Check transition history includes error
	history := sm.GetTransitions(containerID)
	assert.Len(t, history, 1)
	assert.Equal(t, "Out of memory", history[0].ErrorMessage)
	assert.NotNil(t, history[0].Metadata)
	assert.Equal(t, "95%", history[0].Metadata["memory_usage"])
}

func TestIsTerminal(t *testing.T) {
	tests := []struct {
		state    ContainerState
		terminal bool
	}{
		{ContainerStateCreating, false},
		{ContainerStateRunning, false},
		{ContainerStatePaused, false},
		{ContainerStateStopped, true},
		{ContainerStateFailed, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			assert.Equal(t, tt.terminal, tt.state.IsTerminal())
		})
	}
}

func TestGetAllStates(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(t, err)
	defer sm.Stop()

	// Add multiple containers
	containers := []string{"container1", "container2", "container3"}
	for _, id := range containers {
		err = sm.SetState(id, ContainerStateRunning, "Running", nil)
		require.NoError(t, err)
	}

	states := sm.GetAllStates()
	assert.Len(t, states, len(containers))
	
	for _, id := range containers {
		state, exists := states[id]
		assert.True(t, exists)
		assert.Equal(t, ContainerStateRunning, state)
	}
}

// setupTestDB creates a test database
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	return db
}

// Benchmark tests

func BenchmarkStateMachineSetState(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(b, err)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(b, err)
	defer sm.Stop()

	containerID := "benchmark-container"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := ContainerStateRunning
		if i%2 == 0 {
			state = ContainerStatePaused
		}
		sm.SetState(containerID, state, "Benchmark transition", nil)
	}
}

func BenchmarkStateMachineGetState(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(b, err)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(b, err)
	defer sm.Stop()

	containerID := "benchmark-container"
	sm.SetState(containerID, ContainerStateRunning, "Initial state", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.GetState(containerID)
	}
}

func BenchmarkStateMachineTransitionHistory(b *testing.B) {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(b, err)
	defer db.Close()

	sm, err := NewStateMachine(db)
	require.NoError(b, err)
	defer sm.Stop()

	containerID := "benchmark-container"
	
	// Create some history
	states := []ContainerState{ContainerStateCreating, ContainerStateRunning, ContainerStatePaused, ContainerStateRunning}
	for _, state := range states {
		sm.SetState(containerID, state, "Benchmark", nil)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm.GetTransitions(containerID)
	}
}