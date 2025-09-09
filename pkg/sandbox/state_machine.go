package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ContainerState represents the current state of a container
type ContainerState string

const (
	// ContainerStateCreating indicates the container is being created
	ContainerStateCreating ContainerState = "creating"
	// ContainerStateRunning indicates the container is running normally
	ContainerStateRunning ContainerState = "running"
	// ContainerStatePaused indicates the container is paused
	ContainerStatePaused ContainerState = "paused"
	// ContainerStateStopped indicates the container has stopped
	ContainerStateStopped ContainerState = "stopped"
	// ContainerStateFailed indicates the container has failed or crashed
	ContainerStateFailed ContainerState = "failed"
)

// IsValid returns true if the container state is valid
func (cs ContainerState) IsValid() bool {
	switch cs {
	case ContainerStateCreating, ContainerStateRunning, ContainerStatePaused, ContainerStateStopped, ContainerStateFailed:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if the container state is terminal
func (cs ContainerState) IsTerminal() bool {
	return cs == ContainerStateStopped || cs == ContainerStateFailed
}

// CanTransitionTo checks if a transition from current state to target state is valid
func (cs ContainerState) CanTransitionTo(target ContainerState) bool {
	switch cs {
	case ContainerStateCreating:
		return target == ContainerStateRunning || target == ContainerStateFailed
	case ContainerStateRunning:
		return target == ContainerStatePaused || target == ContainerStateStopped || target == ContainerStateFailed
	case ContainerStatePaused:
		return target == ContainerStateRunning || target == ContainerStateStopped || target == ContainerStateFailed
	case ContainerStateStopped:
		return target == ContainerStateRunning || target == ContainerStateFailed
	case ContainerStateFailed:
		return target == ContainerStateRunning || target == ContainerStateCreating
	default:
		return false
	}
}

// StateTransition represents a state change event
type StateTransition struct {
	ID           string                 `json:"id"`
	ContainerID  string                 `json:"container_id"`
	From         ContainerState         `json:"from"`
	To           ContainerState         `json:"to"`
	Timestamp    time.Time              `json:"timestamp"`
	Reason       string                 `json:"reason"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
}

// StateChangeCallback is called when a container state changes
type StateChangeCallback func(transition StateTransition)

// StateMachine manages container state transitions and callbacks
type StateMachine struct {
	db           *sql.DB
	mu           sync.RWMutex
	states       map[string]ContainerState    // containerID -> state
	callbacks    []StateChangeCallback        // callbacks for state changes
	transitions  map[string][]StateTransition // containerID -> transitions
	eventChan    chan StateTransition         // channel for async event processing
	ctx          context.Context
	cancel       context.CancelFunc
	stopOnce     sync.Once
}

// NewStateMachine creates a new state machine instance
func NewStateMachine(db *sql.DB) (*StateMachine, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	sm := &StateMachine{
		db:          db,
		states:      make(map[string]ContainerState),
		callbacks:   make([]StateChangeCallback, 0),
		transitions: make(map[string][]StateTransition),
		eventChan:   make(chan StateTransition, 100),
		ctx:         ctx,
		cancel:      cancel,
	}

	// Create state machine tables
	if err := sm.createTables(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create state machine tables: %w", err)
	}

	// Load existing state from database
	if err := sm.loadStateFromDB(); err != nil {
		log.Warn().Err(err).Msg("Failed to load existing state from database")
	}

	// Start event processing goroutine
	go sm.processEvents()

	log.Info().Msg("State machine initialized")
	return sm, nil
}

// RegisterCallback registers a callback for state changes
func (sm *StateMachine) RegisterCallback(callback StateChangeCallback) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	
	sm.callbacks = append(sm.callbacks, callback)
}

// GetState returns the current state of a container
func (sm *StateMachine) GetState(containerID string) (ContainerState, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	state, exists := sm.states[containerID]
	return state, exists
}

// SetState attempts to transition a container to a new state
func (sm *StateMachine) SetState(containerID string, newState ContainerState, reason string, metadata map[string]interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	return sm.setStateUnlocked(containerID, newState, reason, metadata, "")
}

// SetStateWithError attempts to transition a container to a new state with an error message
func (sm *StateMachine) SetStateWithError(containerID string, newState ContainerState, reason string, errorMessage string, metadata map[string]interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	return sm.setStateUnlocked(containerID, newState, reason, metadata, errorMessage)
}

// setStateUnlocked performs state transition without acquiring lock (internal use)
func (sm *StateMachine) setStateUnlocked(containerID string, newState ContainerState, reason string, metadata map[string]interface{}, errorMessage string) error {
	if !newState.IsValid() {
		return fmt.Errorf("invalid state: %s", newState)
	}

	currentState, exists := sm.states[containerID]
	if !exists {
		// First time setting state - allow any state
		log.Info().
			Str("container_id", containerID).
			Str("state", string(newState)).
			Str("reason", reason).
			Msg("Container state initialized")
	} else {
		// Validate transition
		if !currentState.CanTransitionTo(newState) {
			return fmt.Errorf("invalid state transition for container %s: %s -> %s", containerID, currentState, newState)
		}
	}

	// Create transition record
	transition := StateTransition{
		ID:           fmt.Sprintf("%s-%d", containerID, time.Now().UnixNano()),
		ContainerID:  containerID,
		From:         currentState,
		To:           newState,
		Timestamp:    time.Now(),
		Reason:       reason,
		Metadata:     metadata,
		ErrorMessage: errorMessage,
	}

	// Update in-memory state
	sm.states[containerID] = newState

	// Store transition history
	if sm.transitions[containerID] == nil {
		sm.transitions[containerID] = make([]StateTransition, 0)
	}
	sm.transitions[containerID] = append(sm.transitions[containerID], transition)

	// Send event for async processing
	select {
	case sm.eventChan <- transition:
	default:
		log.Warn().
			Str("container_id", containerID).
			Msg("Event channel full, dropping state change event")
	}

	log.Info().
		Str("container_id", containerID).
		Str("from", string(currentState)).
		Str("to", string(newState)).
		Str("reason", reason).
		Msg("Container state transition")

	return nil
}

// GetTransitions returns all state transitions for a container
func (sm *StateMachine) GetTransitions(containerID string) []StateTransition {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	transitions, exists := sm.transitions[containerID]
	if !exists {
		return nil
	}

	// Return a copy to prevent race conditions
	result := make([]StateTransition, len(transitions))
	copy(result, transitions)
	return result
}

// GetAllStates returns all container states
func (sm *StateMachine) GetAllStates() map[string]ContainerState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	result := make(map[string]ContainerState)
	for containerID, state := range sm.states {
		result[containerID] = state
	}
	return result
}

// RemoveContainer removes a container from state tracking
func (sm *StateMachine) RemoveContainer(containerID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.states, containerID)
	delete(sm.transitions, containerID)

	// Remove from database
	query := `DELETE FROM container_states WHERE container_id = ?`
	if _, err := sm.db.Exec(query, containerID); err != nil {
		log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to remove container state from database")
	}

	query = `DELETE FROM state_transitions WHERE container_id = ?`
	if _, err := sm.db.Exec(query, containerID); err != nil {
		log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to remove container transitions from database")
	}

	log.Info().Str("container_id", containerID).Msg("Container removed from state machine")
	return nil
}

// RecoverState attempts to recover container states after restart
func (sm *StateMachine) RecoverState(containerID string, expectedState ContainerState) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	currentState, exists := sm.states[containerID]
	if !exists {
		// No state found, initialize with expected state
		return sm.setStateUnlocked(containerID, expectedState, "State recovery", nil, "")
	}

	if currentState != expectedState {
		log.Warn().
			Str("container_id", containerID).
			Str("current_state", string(currentState)).
			Str("expected_state", string(expectedState)).
			Msg("State mismatch detected during recovery")

		// Attempt to transition to expected state
		if currentState.CanTransitionTo(expectedState) {
			return sm.setStateUnlocked(containerID, expectedState, "State recovery - mismatch corrected", nil, "")
		} else {
			// Force transition to failed state if recovery is not possible
			return sm.setStateUnlocked(containerID, ContainerStateFailed, "State recovery failed - invalid transition", nil, 
				fmt.Sprintf("Cannot transition from %s to %s", currentState, expectedState))
		}
	}

	return nil
}

// Stop stops the state machine
func (sm *StateMachine) Stop() {
	sm.stopOnce.Do(func() {
		log.Info().Msg("Stopping state machine")
		sm.cancel()
	})
}

// processEvents processes state change events asynchronously
func (sm *StateMachine) processEvents() {
	for {
		select {
		case <-sm.ctx.Done():
			log.Info().Msg("State machine event processor stopped")
			return
		case transition := <-sm.eventChan:
			sm.handleStateChangeEvent(transition)
		}
	}
}

// handleStateChangeEvent processes a state change event
func (sm *StateMachine) handleStateChangeEvent(transition StateTransition) {
	// Persist to database
	if err := sm.persistTransition(transition); err != nil {
		log.Error().Err(err).
			Str("container_id", transition.ContainerID).
			Msg("Failed to persist state transition")
	}

	// Notify callbacks
	sm.mu.RLock()
	callbacks := make([]StateChangeCallback, len(sm.callbacks))
	copy(callbacks, sm.callbacks)
	sm.mu.RUnlock()

	for _, callback := range callbacks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error().
						Interface("panic", r).
						Str("container_id", transition.ContainerID).
						Msg("State change callback panicked")
				}
			}()
			callback(transition)
		}()
	}
}

// persistTransition saves a state transition to the database
func (sm *StateMachine) persistTransition(transition StateTransition) error {
	metadataJSON, _ := json.Marshal(transition.Metadata)

	// Update current state
	query := `INSERT OR REPLACE INTO container_states 
		(container_id, state, updated_at, last_transition_id)
		VALUES (?, ?, ?, ?)`
	
	_, err := sm.db.Exec(query, transition.ContainerID, string(transition.To), 
		transition.Timestamp, transition.ID)
	if err != nil {
		return fmt.Errorf("failed to update container state: %w", err)
	}

	// Insert transition record
	query = `INSERT INTO state_transitions 
		(id, container_id, from_state, to_state, timestamp, reason, metadata, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	
	_, err = sm.db.Exec(query, transition.ID, transition.ContainerID,
		string(transition.From), string(transition.To), transition.Timestamp,
		transition.Reason, string(metadataJSON), transition.ErrorMessage)
	if err != nil {
		return fmt.Errorf("failed to insert state transition: %w", err)
	}

	return nil
}

// loadStateFromDB loads existing container states from database
func (sm *StateMachine) loadStateFromDB() error {
	// Load current states
	query := `SELECT container_id, state FROM container_states`
	rows, err := sm.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query container states: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var containerID string
		var stateStr string
		
		if err := rows.Scan(&containerID, &stateStr); err != nil {
			log.Warn().Err(err).Msg("Failed to scan container state row")
			continue
		}

		sm.states[containerID] = ContainerState(stateStr)
	}

	// Load transition history
	query = `SELECT id, container_id, from_state, to_state, timestamp, reason, metadata, error_message 
		FROM state_transitions ORDER BY timestamp ASC`
	rows, err = sm.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query state transitions: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var transition StateTransition
		var fromStateStr, toStateStr, metadataStr sql.NullString
		
		err := rows.Scan(&transition.ID, &transition.ContainerID,
			&fromStateStr, &toStateStr, &transition.Timestamp,
			&transition.Reason, &metadataStr, &transition.ErrorMessage)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan transition row")
			continue
		}

		if fromStateStr.Valid {
			transition.From = ContainerState(fromStateStr.String)
		}
		if toStateStr.Valid {
			transition.To = ContainerState(toStateStr.String)
		}
		if metadataStr.Valid && metadataStr.String != "" {
			json.Unmarshal([]byte(metadataStr.String), &transition.Metadata)
		}

		if sm.transitions[transition.ContainerID] == nil {
			sm.transitions[transition.ContainerID] = make([]StateTransition, 0)
		}
		sm.transitions[transition.ContainerID] = append(
			sm.transitions[transition.ContainerID], transition)
	}

	log.Info().Int("states", len(sm.states)).Msg("Loaded container states from database")
	return nil
}

// createTables creates the necessary database tables for state management
func (sm *StateMachine) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS container_states (
			container_id TEXT PRIMARY KEY,
			state TEXT NOT NULL,
			updated_at DATETIME NOT NULL,
			last_transition_id TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS state_transitions (
			id TEXT PRIMARY KEY,
			container_id TEXT NOT NULL,
			from_state TEXT,
			to_state TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			reason TEXT,
			metadata TEXT,
			error_message TEXT,
			FOREIGN KEY (container_id) REFERENCES container_states(container_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_container_states_state ON container_states(state)`,
		`CREATE INDEX IF NOT EXISTS idx_state_transitions_container ON state_transitions(container_id)`,
		`CREATE INDEX IF NOT EXISTS idx_state_transitions_timestamp ON state_transitions(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_state_transitions_from_to ON state_transitions(from_state, to_state)`,
	}

	for _, query := range queries {
		if _, err := sm.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query %s: %w", query, err)
		}
	}

	return nil
}

// GetStateStatistics returns statistics about container states
func (sm *StateMachine) GetStateStatistics() map[ContainerState]int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := make(map[ContainerState]int)
	
	// Initialize with zero counts for all states
	stats[ContainerStateCreating] = 0
	stats[ContainerStateRunning] = 0
	stats[ContainerStatePaused] = 0
	stats[ContainerStateStopped] = 0
	stats[ContainerStateFailed] = 0

	// Count actual states
	for _, state := range sm.states {
		stats[state]++
	}

	return stats
}

// ValidateTransitionMatrix ensures the state transition rules are correct
func ValidateTransitionMatrix() map[string][]string {
	validTransitions := make(map[string][]string)
	
	states := []ContainerState{
		ContainerStateCreating,
		ContainerStateRunning,
		ContainerStatePaused,
		ContainerStateStopped,
		ContainerStateFailed,
	}

	for _, from := range states {
		validTransitions[string(from)] = make([]string, 0)
		for _, to := range states {
			if from.CanTransitionTo(to) {
				validTransitions[string(from)] = append(validTransitions[string(from)], string(to))
			}
		}
	}

	return validTransitions
}