package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
)

// RecoveryAction defines the type of recovery action
type RecoveryAction string

const (
	RecoveryActionRestart   RecoveryAction = "restart"
	RecoveryActionRecreate  RecoveryAction = "recreate"
	RecoveryActionTerminate RecoveryAction = "terminate"
	RecoveryActionManual    RecoveryAction = "manual"
)

// FailureType categorizes different types of container failures
type FailureType string

const (
	FailureTypeOOM         FailureType = "oom_kill"
	FailureTypeCrash       FailureType = "crash"
	FailureTypeTimeout     FailureType = "timeout"
	FailureTypeUnresponsive FailureType = "unresponsive"
	FailureTypeCorrupted   FailureType = "corrupted"
	FailureTypeNetwork     FailureType = "network"
	FailureTypeResource    FailureType = "resource"
	FailureTypeUnknown     FailureType = "unknown"
)

// RecoveryPolicy defines recovery behavior for different failure types
type RecoveryPolicy struct {
	MaxRetries         int                            `json:"maxRetries"`
	BaseDelay          time.Duration                  `json:"baseDelay"`
	MaxDelay           time.Duration                  `json:"maxDelay"`
	BackoffMultiplier  float64                        `json:"backoffMultiplier"`
	JitterPercent      float64                        `json:"jitterPercent"`
	Actions            map[FailureType]RecoveryAction `json:"actions"`
	PreserveState      bool                           `json:"preserveState"`
	HealthCheckTimeout time.Duration                  `json:"healthCheckTimeout"`
	RecoveryTimeout    time.Duration                  `json:"recoveryTimeout"`
}

// RecoveryAttempt represents a single recovery attempt
type RecoveryAttempt struct {
	ID          string         `json:"id"`
	ContainerID string         `json:"containerID"`
	AttemptNum  int            `json:"attemptNum"`
	Action      RecoveryAction `json:"action"`
	FailureType FailureType    `json:"failureType"`
	StartTime   time.Time      `json:"startTime"`
	EndTime     *time.Time     `json:"endTime,omitempty"`
	Success     bool           `json:"success"`
	Error       string         `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RecoveryState tracks recovery state for a container
type RecoveryState struct {
	ContainerID      string            `json:"containerID"`
	CurrentRetries   int               `json:"currentRetries"`
	LastFailureTime  time.Time         `json:"lastFailureTime"`
	LastFailureType  FailureType       `json:"lastFailureType"`
	RecoveryEnabled  bool              `json:"recoveryEnabled"`
	LastRecoveryTime *time.Time        `json:"lastRecoveryTime,omitempty"`
	Attempts         []RecoveryAttempt `json:"attempts"`
	StateData        map[string]interface{} `json:"stateData,omitempty"`
	Policy           *RecoveryPolicy   `json:"policy,omitempty"`
}

// RecoveryMetrics tracks recovery statistics
type RecoveryMetrics struct {
	TotalFailures       int64                       `json:"totalFailures"`
	TotalRecoveries     int64                       `json:"totalRecoveries"`
	SuccessfulRecoveries int64                      `json:"successfulRecoveries"`
	FailedRecoveries    int64                       `json:"failedRecoveries"`
	AverageRecoveryTime time.Duration               `json:"averageRecoveryTime"`
	FailuresByType      map[FailureType]int64       `json:"failuresByType"`
	ActionsByType       map[RecoveryAction]int64    `json:"actionsByType"`
	LastUpdated         time.Time                   `json:"lastUpdated"`
}

// RecoveryManager handles container recovery operations
type RecoveryManager struct {
	db             *sql.DB
	runcClient     *runtime.RunCClient
	stateMachine   *StateMachine
	eventBus       *EventBus
	defaultPolicy  *RecoveryPolicy
	
	// Recovery state tracking
	recoveryStates map[string]*RecoveryState
	mu             sync.RWMutex
	
	// Background processing
	ctx              context.Context
	cancel           context.CancelFunc
	recoveryQueue    chan RecoveryRequest
	stopOnce         sync.Once
	
	// Metrics
	metrics *RecoveryMetrics
}

// RecoveryRequest represents a recovery request
type RecoveryRequest struct {
	ContainerID string
	FailureType FailureType
	Reason      string
	Metadata    map[string]interface{}
	Manual      bool
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(db *sql.DB, runcClient *runtime.RunCClient, stateMachine *StateMachine, eventBus *EventBus) (*RecoveryManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	rm := &RecoveryManager{
		db:             db,
		runcClient:     runcClient,
		stateMachine:   stateMachine,
		eventBus:       eventBus,
		defaultPolicy:  DefaultRecoveryPolicy(),
		recoveryStates: make(map[string]*RecoveryState),
		ctx:            ctx,
		cancel:         cancel,
		recoveryQueue:  make(chan RecoveryRequest, 100),
		metrics:        NewRecoveryMetrics(),
	}
	
	// Create recovery tables
	if err := rm.createTables(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create recovery tables: %w", err)
	}
	
	// Load existing recovery states
	if err := rm.loadRecoveryStates(); err != nil {
		log.Warn().Err(err).Msg("Failed to load recovery states from database")
	}
	
	// Register state machine callback for failure detection
	rm.stateMachine.RegisterCallback(rm.handleStateTransition)
	
	// Start background recovery processor
	go rm.processRecoveryRequests()
	
	// Start metrics updater
	go rm.updateMetricsPeriodically()
	
	log.Info().Msg("Recovery manager initialized")
	return rm, nil
}

// DefaultRecoveryPolicy returns a sensible default recovery policy
func DefaultRecoveryPolicy() *RecoveryPolicy {
	return &RecoveryPolicy{
		MaxRetries:        3,
		BaseDelay:         1 * time.Second,
		MaxDelay:          60 * time.Second,
		BackoffMultiplier: 2.0,
		JitterPercent:     0.1,
		Actions: map[FailureType]RecoveryAction{
			FailureTypeOOM:         RecoveryActionRestart,
			FailureTypeCrash:       RecoveryActionRestart,
			FailureTypeTimeout:     RecoveryActionRestart,
			FailureTypeUnresponsive: RecoveryActionRestart,
			FailureTypeCorrupted:   RecoveryActionRecreate,
			FailureTypeNetwork:     RecoveryActionRestart,
			FailureTypeResource:    RecoveryActionRestart,
			FailureTypeUnknown:     RecoveryActionRestart,
		},
		PreserveState:      true,
		HealthCheckTimeout: 30 * time.Second,
		RecoveryTimeout:    5 * time.Minute,
	}
}

// SetRecoveryPolicy sets the recovery policy for a container
func (rm *RecoveryManager) SetRecoveryPolicy(containerID string, policy *RecoveryPolicy) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	state, exists := rm.recoveryStates[containerID]
	if !exists {
		state = &RecoveryState{
			ContainerID:     containerID,
			RecoveryEnabled: true,
			Attempts:        make([]RecoveryAttempt, 0),
			StateData:       make(map[string]interface{}),
		}
		rm.recoveryStates[containerID] = state
	}
	
	state.Policy = policy
	
	// Persist to database
	if err := rm.persistRecoveryState(state); err != nil {
		return fmt.Errorf("failed to persist recovery policy: %w", err)
	}
	
	log.Info().Str("container_id", containerID).Msg("Recovery policy updated")
	return nil
}

// EnableRecovery enables automatic recovery for a container
func (rm *RecoveryManager) EnableRecovery(containerID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	state := rm.getOrCreateRecoveryState(containerID)
	state.RecoveryEnabled = true
	
	if err := rm.persistRecoveryState(state); err != nil {
		return fmt.Errorf("failed to enable recovery: %w", err)
	}
	
	log.Info().Str("container_id", containerID).Msg("Recovery enabled")
	return nil
}

// DisableRecovery disables automatic recovery for a container
func (rm *RecoveryManager) DisableRecovery(containerID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	state := rm.getOrCreateRecoveryState(containerID)
	state.RecoveryEnabled = false
	
	if err := rm.persistRecoveryState(state); err != nil {
		return fmt.Errorf("failed to disable recovery: %w", err)
	}
	
	log.Info().Str("container_id", containerID).Msg("Recovery disabled")
	return nil
}

// TriggerRecovery manually triggers recovery for a container
func (rm *RecoveryManager) TriggerRecovery(containerID string, failureType FailureType, reason string) error {
	request := RecoveryRequest{
		ContainerID: containerID,
		FailureType: failureType,
		Reason:      reason,
		Manual:      true,
		Metadata: map[string]interface{}{
			"triggered_by": "manual",
			"timestamp":    time.Now(),
		},
	}
	
	select {
	case rm.recoveryQueue <- request:
		log.Info().
			Str("container_id", containerID).
			Str("failure_type", string(failureType)).
			Str("reason", reason).
			Msg("Manual recovery triggered")
		return nil
	default:
		return fmt.Errorf("recovery queue is full, cannot trigger manual recovery")
	}
}

// ResetRecoveryState resets the recovery state for a container
func (rm *RecoveryManager) ResetRecoveryState(containerID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	state := rm.getOrCreateRecoveryState(containerID)
	state.CurrentRetries = 0
	state.LastFailureTime = time.Time{}
	state.LastRecoveryTime = nil
	state.Attempts = make([]RecoveryAttempt, 0)
	
	if err := rm.persistRecoveryState(state); err != nil {
		return fmt.Errorf("failed to reset recovery state: %w", err)
	}
	
	log.Info().Str("container_id", containerID).Msg("Recovery state reset")
	return nil
}

// GetRecoveryState returns the current recovery state for a container
func (rm *RecoveryManager) GetRecoveryState(containerID string) (*RecoveryState, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	state, exists := rm.recoveryStates[containerID]
	if !exists {
		return nil, fmt.Errorf("no recovery state found for container %s", containerID)
	}
	
	// Return a copy to prevent modification
	stateCopy := *state
	stateCopy.Attempts = make([]RecoveryAttempt, len(state.Attempts))
	copy(stateCopy.Attempts, state.Attempts)
	
	if state.StateData != nil {
		stateCopy.StateData = make(map[string]interface{})
		for k, v := range state.StateData {
			stateCopy.StateData[k] = v
		}
	}
	
	return &stateCopy, nil
}

// GetRecoveryMetrics returns current recovery metrics
func (rm *RecoveryManager) GetRecoveryMetrics() *RecoveryMetrics {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	// Return a copy
	metricsCopy := *rm.metrics
	metricsCopy.FailuresByType = make(map[FailureType]int64)
	metricsCopy.ActionsByType = make(map[RecoveryAction]int64)
	
	for k, v := range rm.metrics.FailuresByType {
		metricsCopy.FailuresByType[k] = v
	}
	for k, v := range rm.metrics.ActionsByType {
		metricsCopy.ActionsByType[k] = v
	}
	
	return &metricsCopy
}

// CleanupContainer removes recovery state for a deleted container
func (rm *RecoveryManager) CleanupContainer(containerID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	delete(rm.recoveryStates, containerID)
	
	// Remove from database
	query := `DELETE FROM recovery_states WHERE container_id = ?`
	if _, err := rm.db.Exec(query, containerID); err != nil {
		return fmt.Errorf("failed to cleanup recovery state: %w", err)
	}
	
	query = `DELETE FROM recovery_attempts WHERE container_id = ?`
	if _, err := rm.db.Exec(query, containerID); err != nil {
		log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to cleanup recovery attempts")
	}
	
	log.Info().Str("container_id", containerID).Msg("Recovery state cleaned up")
	return nil
}

// Stop stops the recovery manager
func (rm *RecoveryManager) Stop() {
	rm.stopOnce.Do(func() {
		log.Info().Msg("Stopping recovery manager")
		rm.cancel()
	})
}

// Private methods

// handleStateTransition processes state transitions to detect failures
func (rm *RecoveryManager) handleStateTransition(transition StateTransition) {
	if transition.To != ContainerStateFailed {
		return
	}
	
	// Determine failure type from metadata and error message
	failureType := rm.detectFailureType(transition)
	
	// Check if recovery is enabled for this container
	rm.mu.RLock()
	state, exists := rm.recoveryStates[transition.ContainerID]
	recoveryEnabled := exists && state.RecoveryEnabled
	rm.mu.RUnlock()
	
	if !recoveryEnabled {
		log.Debug().
			Str("container_id", transition.ContainerID).
			Msg("Recovery disabled for container, skipping automatic recovery")
		return
	}
	
	// Queue recovery request
	request := RecoveryRequest{
		ContainerID: transition.ContainerID,
		FailureType: failureType,
		Reason:      transition.Reason,
		Metadata: map[string]interface{}{
			"state_transition_id": transition.ID,
			"error_message":       transition.ErrorMessage,
			"timestamp":          transition.Timestamp,
		},
		Manual: false,
	}
	
	select {
	case rm.recoveryQueue <- request:
		log.Info().
			Str("container_id", transition.ContainerID).
			Str("failure_type", string(failureType)).
			Msg("Automatic recovery queued")
	default:
		log.Error().
			Str("container_id", transition.ContainerID).
			Msg("Recovery queue full, dropping recovery request")
	}
}

// processRecoveryRequests processes recovery requests from the queue
func (rm *RecoveryManager) processRecoveryRequests() {
	for {
		select {
		case <-rm.ctx.Done():
			log.Info().Msg("Recovery request processor stopped")
			return
		case request := <-rm.recoveryQueue:
			rm.processRecoveryRequest(request)
		}
	}
}

// processRecoveryRequest processes a single recovery request
func (rm *RecoveryManager) processRecoveryRequest(request RecoveryRequest) {
	logger := log.With().
		Str("container_id", request.ContainerID).
		Str("failure_type", string(request.FailureType)).
		Bool("manual", request.Manual).
		Logger()
	
	logger.Info().Msg("Processing recovery request")
	
	// Get recovery state
	rm.mu.Lock()
	state := rm.getOrCreateRecoveryState(request.ContainerID)
	
	// Check if we've exceeded max retries
	policy := state.Policy
	if policy == nil {
		policy = rm.defaultPolicy
	}
	
	if state.CurrentRetries >= policy.MaxRetries && !request.Manual {
		logger.Error().
			Int("current_retries", state.CurrentRetries).
			Int("max_retries", policy.MaxRetries).
			Msg("Max retries exceeded, not attempting recovery")
		rm.mu.Unlock()
		return
	}
	
	// Update failure tracking
	state.LastFailureTime = time.Now()
	state.LastFailureType = request.FailureType
	if !request.Manual {
		state.CurrentRetries++
	}
	rm.mu.Unlock()
	
	// Determine recovery action
	action, exists := policy.Actions[request.FailureType]
	if !exists {
		action = RecoveryActionRestart
	}
	
	// Handle manual recovery action override
	if request.Manual && action == RecoveryActionManual {
		logger.Info().Msg("Manual recovery action requires external intervention")
		return
	}
	
	// Create recovery attempt
	attempt := RecoveryAttempt{
		ID:          fmt.Sprintf("recovery-%s", uuid.New().String()[:8]),
		ContainerID: request.ContainerID,
		AttemptNum:  state.CurrentRetries,
		Action:      action,
		FailureType: request.FailureType,
		StartTime:   time.Now(),
		Metadata:    request.Metadata,
	}
	
	// Calculate backoff delay (except for manual recovery)
	if !request.Manual && state.CurrentRetries > 1 {
		delay := rm.calculateBackoffDelay(policy, state.CurrentRetries)
		logger.Info().Dur("delay", delay).Msg("Waiting before recovery attempt")
		
		select {
		case <-rm.ctx.Done():
			return
		case <-time.After(delay):
		}
	}
	
	// Perform recovery action
	err := rm.performRecoveryAction(request.ContainerID, action, policy, &attempt)
	
	// Update attempt result
	endTime := time.Now()
	attempt.EndTime = &endTime
	attempt.Success = (err == nil)
	if err != nil {
		attempt.Error = err.Error()
	}
	
	// Update state and persist
	rm.mu.Lock()
	state.Attempts = append(state.Attempts, attempt)
	if attempt.Success {
		now := time.Now()
		state.LastRecoveryTime = &now
		state.CurrentRetries = 0 // Reset on success
	}
	rm.persistRecoveryState(state)
	rm.mu.Unlock()
	
	// Update metrics
	rm.updateRecoveryMetrics(request.FailureType, action, attempt.Success, endTime.Sub(attempt.StartTime))
	
	// Publish recovery event
	eventData := map[string]interface{}{
		"attempt_id":     attempt.ID,
		"action":         string(action),
		"failure_type":   string(request.FailureType),
		"success":        attempt.Success,
		"duration_ms":    endTime.Sub(attempt.StartTime).Milliseconds(),
		"attempt_number": attempt.AttemptNum,
	}
	
	if err != nil {
		eventData["error"] = err.Error()
	}
	
	event := NewRecoveryEvent(request.ContainerID, "recovery-manager", eventData)
	rm.eventBus.Publish(event)
	
	if attempt.Success {
		logger.Info().
			Str("attempt_id", attempt.ID).
			Str("action", string(action)).
			Dur("duration", endTime.Sub(attempt.StartTime)).
			Msg("Recovery successful")
	} else {
		logger.Error().
			Str("attempt_id", attempt.ID).
			Str("action", string(action)).
			Err(err).
			Dur("duration", endTime.Sub(attempt.StartTime)).
			Msg("Recovery failed")
	}
}

// performRecoveryAction performs the actual recovery action
func (rm *RecoveryManager) performRecoveryAction(containerID string, action RecoveryAction, policy *RecoveryPolicy, attempt *RecoveryAttempt) error {
	ctx, cancel := context.WithTimeout(rm.ctx, policy.RecoveryTimeout)
	defer cancel()
	
	logger := log.With().
		Str("container_id", containerID).
		Str("action", string(action)).
		Str("attempt_id", attempt.ID).
		Logger()
	
	switch action {
	case RecoveryActionRestart:
		return rm.performRestart(ctx, containerID, policy, logger)
	case RecoveryActionRecreate:
		return rm.performRecreate(ctx, containerID, policy, logger)
	case RecoveryActionTerminate:
		return rm.performTerminate(ctx, containerID, logger)
	default:
		return fmt.Errorf("unsupported recovery action: %s", action)
	}
}

// performRestart restarts a failed container
func (rm *RecoveryManager) performRestart(ctx context.Context, containerID string, policy *RecoveryPolicy, logger zerolog.Logger) error {
	logger.Info().Msg("Performing container restart")
	
	// Preserve state if required
	var preservedState bool
	if policy.PreserveState {
		_ = rm.preserveContainerState(ctx, containerID)
		preservedState = true
	}
	
	// Stop container if it's still running
	if err := rm.runcClient.StopContainer(ctx, containerID); err != nil {
		logger.Debug().Err(err).Msg("Failed to stop container (may already be stopped)")
	}
	
	// Start container
	if err := rm.runcClient.StartContainer(ctx, containerID); err != nil {
		return fmt.Errorf("failed to start container: %w", err)
	}
	
	// Update state machine
	if err := rm.stateMachine.SetState(containerID, ContainerStateRunning, "Recovery restart", map[string]interface{}{
		"recovery_action": "restart",
		"preserved_state": preservedState,
	}); err != nil {
		logger.Warn().Err(err).Msg("Failed to update state machine after restart")
	}
	
	// Restore state if preserved
	if preservedState {
		rm.restoreContainerState(ctx, containerID, make(map[string]interface{}))
	}
	
	// Perform health check
	return rm.verifyRecovery(ctx, containerID, policy.HealthCheckTimeout)
}

// performRecreate recreates a corrupted container
func (rm *RecoveryManager) performRecreate(ctx context.Context, containerID string, policy *RecoveryPolicy, logger zerolog.Logger) error {
	logger.Info().Msg("Performing container recreation")
	
	// This would require access to the original container configuration
	// For now, we'll implement a basic recreation that stops and starts
	// In a full implementation, we'd need to recreate from the original spec
	
	// Preserve state if required
	if policy.PreserveState {
		_ = rm.preserveContainerState(ctx, containerID)
	}
	
	// Stop and delete container
	if err := rm.runcClient.StopContainer(ctx, containerID); err != nil {
		logger.Debug().Err(err).Msg("Failed to stop container during recreation")
	}
	
	if err := rm.runcClient.DeleteContainer(ctx, containerID); err != nil {
		logger.Debug().Err(err).Msg("Failed to delete container during recreation")
	}
	
	// Update state machine to creating
	if err := rm.stateMachine.SetState(containerID, ContainerStateCreating, "Recovery recreation", map[string]interface{}{
		"recovery_action": "recreate",
	}); err != nil {
		logger.Warn().Err(err).Msg("Failed to update state machine during recreation")
	}
	
	// TODO: In a full implementation, we would recreate the container from original spec
	// For now, return an error indicating this needs to be handled at a higher level
	return fmt.Errorf("container recreation requires sandbox manager intervention")
}

// performTerminate permanently terminates a container
func (rm *RecoveryManager) performTerminate(ctx context.Context, containerID string, logger zerolog.Logger) error {
	logger.Info().Msg("Performing container termination")
	
	// Stop container
	if err := rm.runcClient.StopContainer(ctx, containerID); err != nil {
		logger.Debug().Err(err).Msg("Failed to stop container during termination")
	}
	
	// Delete container
	if err := rm.runcClient.DeleteContainer(ctx, containerID); err != nil {
		logger.Debug().Err(err).Msg("Failed to delete container during termination")
	}
	
	// Update state machine
	if err := rm.stateMachine.SetState(containerID, ContainerStateStopped, "Recovery termination", map[string]interface{}{
		"recovery_action": "terminate",
		"terminated":      true,
	}); err != nil {
		logger.Warn().Err(err).Msg("Failed to update state machine after termination")
	}
	
	return nil
}

// verifyRecovery verifies that recovery was successful
func (rm *RecoveryManager) verifyRecovery(ctx context.Context, containerID string, timeout time.Duration) error {
	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	
	// Wait for container to be in running state
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-verifyCtx.Done():
			return fmt.Errorf("recovery verification timed out")
		case <-ticker.C:
			state, err := rm.runcClient.GetProcessStatus(verifyCtx, containerID, "")
			if err != nil {
				continue
			}
			
			if state.Running {
				return nil
			}
		}
	}
}

// preserveContainerState preserves container state before recovery
func (rm *RecoveryManager) preserveContainerState(ctx context.Context, containerID string) map[string]interface{} {
	stateData := make(map[string]interface{})
	stateData["preservation_time"] = time.Now()
	
	// In a full implementation, this would preserve:
	// - Environment variables
	// - File system state
	// - Process state
	// - Network connections
	// - Resource allocations
	
	log.Debug().Str("container_id", containerID).Msg("Container state preserved")
	return stateData
}

// restoreContainerState restores container state after recovery
func (rm *RecoveryManager) restoreContainerState(ctx context.Context, containerID string, stateData map[string]interface{}) {
	// In a full implementation, this would restore the preserved state
	log.Debug().Str("container_id", containerID).Msg("Container state restored")
}

// calculateBackoffDelay calculates the backoff delay with jitter
func (rm *RecoveryManager) calculateBackoffDelay(policy *RecoveryPolicy, retryCount int) time.Duration {
	// Exponential backoff: baseDelay * (multiplier ^ (retryCount - 1))
	delay := float64(policy.BaseDelay) * math.Pow(policy.BackoffMultiplier, float64(retryCount-1))
	
	// Cap at max delay
	if time.Duration(delay) > policy.MaxDelay {
		delay = float64(policy.MaxDelay)
	}
	
	// Add jitter to prevent thundering herd
	if policy.JitterPercent > 0 {
		jitter := delay * policy.JitterPercent * (rand.Float64()*2 - 1) // -jitterPercent to +jitterPercent
		delay += jitter
	}
	
	// Ensure positive delay
	if delay < 0 {
		delay = float64(policy.BaseDelay)
	}
	
	return time.Duration(delay)
}

// detectFailureType determines the failure type from state transition
func (rm *RecoveryManager) detectFailureType(transition StateTransition) FailureType {
	errorMsg := transition.ErrorMessage
	reason := transition.Reason
	
	// Check for OOM kill
	if contains(errorMsg, "oom", "killed", "memory") || contains(reason, "oom", "memory") {
		return FailureTypeOOM
	}
	
	// Check for timeout
	if contains(errorMsg, "timeout", "deadline") || contains(reason, "timeout") {
		return FailureTypeTimeout
	}
	
	// Check for crash
	if contains(errorMsg, "crash", "segfault", "signal") || contains(reason, "crash") {
		return FailureTypeCrash
	}
	
	// Check for network issues
	if contains(errorMsg, "network", "connection", "dns") || contains(reason, "network") {
		return FailureTypeNetwork
	}
	
	// Check for resource issues
	if contains(errorMsg, "resource", "limit", "quota") || contains(reason, "resource") {
		return FailureTypeResource
	}
	
	// Check for corruption
	if contains(errorMsg, "corrupt", "invalid", "malformed") || contains(reason, "corrupt") {
		return FailureTypeCorrupted
	}
	
	// Check for unresponsive
	if contains(reason, "health", "unresponsive", "check") {
		return FailureTypeUnresponsive
	}
	
	return FailureTypeUnknown
}

// Helper functions

func (rm *RecoveryManager) getOrCreateRecoveryState(containerID string) *RecoveryState {
	state, exists := rm.recoveryStates[containerID]
	if !exists {
		state = &RecoveryState{
			ContainerID:     containerID,
			RecoveryEnabled: true,
			Attempts:        make([]RecoveryAttempt, 0),
			StateData:       make(map[string]interface{}),
		}
		rm.recoveryStates[containerID] = state
	}
	return state
}

func (rm *RecoveryManager) updateRecoveryMetrics(failureType FailureType, action RecoveryAction, success bool, duration time.Duration) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.metrics.TotalRecoveries++
	if success {
		rm.metrics.SuccessfulRecoveries++
	} else {
		rm.metrics.FailedRecoveries++
	}
	
	if rm.metrics.FailuresByType == nil {
		rm.metrics.FailuresByType = make(map[FailureType]int64)
	}
	rm.metrics.FailuresByType[failureType]++
	
	if rm.metrics.ActionsByType == nil {
		rm.metrics.ActionsByType = make(map[RecoveryAction]int64)
	}
	rm.metrics.ActionsByType[action]++
	
	// Update average recovery time
	totalTime := time.Duration(rm.metrics.AverageRecoveryTime.Nanoseconds()*int64(rm.metrics.TotalRecoveries-1)) + duration
	rm.metrics.AverageRecoveryTime = totalTime / time.Duration(rm.metrics.TotalRecoveries)
	
	rm.metrics.LastUpdated = time.Now()
}

func (rm *RecoveryManager) updateMetricsPeriodically() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.persistMetrics()
		}
	}
}

func contains(str string, substrings ...string) bool {
	for _, sub := range substrings {
		if len(str) > 0 && len(sub) > 0 {
			// Simple case-insensitive contains check
			strLower := strings.ToLower(str)
			subLower := strings.ToLower(sub)
			if len(strLower) >= len(subLower) {
				for i := 0; i <= len(strLower)-len(subLower); i++ {
					if strLower[i:i+len(subLower)] == subLower {
						return true
					}
				}
			}
		}
	}
	return false
}

// Database operations

func (rm *RecoveryManager) createTables() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS recovery_states (
			container_id TEXT PRIMARY KEY,
			current_retries INTEGER NOT NULL DEFAULT 0,
			last_failure_time DATETIME,
			last_failure_type TEXT,
			recovery_enabled BOOLEAN NOT NULL DEFAULT 1,
			last_recovery_time DATETIME,
			state_data TEXT,
			policy TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS recovery_attempts (
			id TEXT PRIMARY KEY,
			container_id TEXT NOT NULL,
			attempt_num INTEGER NOT NULL,
			action TEXT NOT NULL,
			failure_type TEXT NOT NULL,
			start_time DATETIME NOT NULL,
			end_time DATETIME,
			success BOOLEAN,
			error_message TEXT,
			metadata TEXT,
			FOREIGN KEY (container_id) REFERENCES recovery_states(container_id)
		)`,
		`CREATE TABLE IF NOT EXISTS recovery_metrics (
			id INTEGER PRIMARY KEY,
			total_failures INTEGER NOT NULL DEFAULT 0,
			total_recoveries INTEGER NOT NULL DEFAULT 0,
			successful_recoveries INTEGER NOT NULL DEFAULT 0,
			failed_recoveries INTEGER NOT NULL DEFAULT 0,
			average_recovery_time_ns INTEGER NOT NULL DEFAULT 0,
			failures_by_type TEXT,
			actions_by_type TEXT,
			last_updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_recovery_attempts_container ON recovery_attempts(container_id)`,
		`CREATE INDEX IF NOT EXISTS idx_recovery_attempts_time ON recovery_attempts(start_time)`,
		`CREATE INDEX IF NOT EXISTS idx_recovery_states_updated ON recovery_states(updated_at)`,
	}
	
	for _, query := range queries {
		if _, err := rm.db.Exec(query); err != nil {
			return fmt.Errorf("failed to execute query %s: %w", query, err)
		}
	}
	
	return nil
}

func (rm *RecoveryManager) persistRecoveryState(state *RecoveryState) error {
	stateDataJSON, _ := json.Marshal(state.StateData)
	policyJSON, _ := json.Marshal(state.Policy)
	
	query := `INSERT OR REPLACE INTO recovery_states 
		(container_id, current_retries, last_failure_time, last_failure_type, 
		 recovery_enabled, last_recovery_time, state_data, policy, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	
	_, err := rm.db.Exec(query, 
		state.ContainerID, state.CurrentRetries, state.LastFailureTime,
		string(state.LastFailureType), state.RecoveryEnabled, state.LastRecoveryTime,
		string(stateDataJSON), string(policyJSON))
	
	if err != nil {
		return fmt.Errorf("failed to persist recovery state: %w", err)
	}
	
	// Persist attempts
	for _, attempt := range state.Attempts {
		if err := rm.persistRecoveryAttempt(&attempt); err != nil {
			log.Warn().Err(err).Str("attempt_id", attempt.ID).Msg("Failed to persist recovery attempt")
		}
	}
	
	return nil
}

func (rm *RecoveryManager) persistRecoveryAttempt(attempt *RecoveryAttempt) error {
	metadataJSON, _ := json.Marshal(attempt.Metadata)
	
	query := `INSERT OR REPLACE INTO recovery_attempts 
		(id, container_id, attempt_num, action, failure_type, start_time, end_time, 
		 success, error_message, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	_, err := rm.db.Exec(query,
		attempt.ID, attempt.ContainerID, attempt.AttemptNum, string(attempt.Action),
		string(attempt.FailureType), attempt.StartTime, attempt.EndTime,
		attempt.Success, attempt.Error, string(metadataJSON))
	
	return err
}

func (rm *RecoveryManager) loadRecoveryStates() error {
	query := `SELECT container_id, current_retries, last_failure_time, last_failure_type,
		recovery_enabled, last_recovery_time, state_data, policy FROM recovery_states`
	
	rows, err := rm.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query recovery states: %w", err)
	}
	defer rows.Close()
	
	for rows.Next() {
		var state RecoveryState
		var lastFailureTime, lastRecoveryTime sql.NullTime
		var stateDataJSON, policyJSON string
		var lastFailureTypeStr string
		
		err := rows.Scan(
			&state.ContainerID, &state.CurrentRetries, &lastFailureTime, &lastFailureTypeStr,
			&state.RecoveryEnabled, &lastRecoveryTime, &stateDataJSON, &policyJSON)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan recovery state row")
			continue
		}
		
		if lastFailureTime.Valid {
			state.LastFailureTime = lastFailureTime.Time
		}
		if lastRecoveryTime.Valid {
			state.LastRecoveryTime = &lastRecoveryTime.Time
		}
		state.LastFailureType = FailureType(lastFailureTypeStr)
		
		if stateDataJSON != "" {
			json.Unmarshal([]byte(stateDataJSON), &state.StateData)
		}
		if policyJSON != "" {
			json.Unmarshal([]byte(policyJSON), &state.Policy)
		}
		
		// Load attempts
		state.Attempts = rm.loadRecoveryAttempts(state.ContainerID)
		
		rm.recoveryStates[state.ContainerID] = &state
	}
	
	log.Info().Int("states", len(rm.recoveryStates)).Msg("Loaded recovery states from database")
	return nil
}

func (rm *RecoveryManager) loadRecoveryAttempts(containerID string) []RecoveryAttempt {
	query := `SELECT id, attempt_num, action, failure_type, start_time, end_time,
		success, error_message, metadata FROM recovery_attempts 
		WHERE container_id = ? ORDER BY start_time ASC`
	
	rows, err := rm.db.Query(query, containerID)
	if err != nil {
		log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to load recovery attempts")
		return make([]RecoveryAttempt, 0)
	}
	defer rows.Close()
	
	var attempts []RecoveryAttempt
	for rows.Next() {
		var attempt RecoveryAttempt
		var endTime sql.NullTime
		var success sql.NullBool
		var errorMessage, metadataJSON sql.NullString
		var actionStr, failureTypeStr string
		
		err := rows.Scan(
			&attempt.ID, &attempt.AttemptNum, &actionStr, &failureTypeStr,
			&attempt.StartTime, &endTime, &success, &errorMessage, &metadataJSON)
		if err != nil {
			log.Warn().Err(err).Msg("Failed to scan recovery attempt row")
			continue
		}
		
		attempt.ContainerID = containerID
		attempt.Action = RecoveryAction(actionStr)
		attempt.FailureType = FailureType(failureTypeStr)
		
		if endTime.Valid {
			attempt.EndTime = &endTime.Time
		}
		if success.Valid {
			attempt.Success = success.Bool
		}
		if errorMessage.Valid {
			attempt.Error = errorMessage.String
		}
		if metadataJSON.Valid && metadataJSON.String != "" {
			json.Unmarshal([]byte(metadataJSON.String), &attempt.Metadata)
		}
		
		attempts = append(attempts, attempt)
	}
	
	return attempts
}

func (rm *RecoveryManager) persistMetrics() error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	failuresByTypeJSON, _ := json.Marshal(rm.metrics.FailuresByType)
	actionsByTypeJSON, _ := json.Marshal(rm.metrics.ActionsByType)
	
	query := `INSERT OR REPLACE INTO recovery_metrics 
		(id, total_failures, total_recoveries, successful_recoveries, failed_recoveries,
		 average_recovery_time_ns, failures_by_type, actions_by_type, last_updated)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
	
	_, err := rm.db.Exec(query,
		rm.metrics.TotalFailures, rm.metrics.TotalRecoveries,
		rm.metrics.SuccessfulRecoveries, rm.metrics.FailedRecoveries,
		rm.metrics.AverageRecoveryTime.Nanoseconds(),
		string(failuresByTypeJSON), string(actionsByTypeJSON))
	
	return err
}

// NewRecoveryMetrics creates a new RecoveryMetrics instance
func NewRecoveryMetrics() *RecoveryMetrics {
	return &RecoveryMetrics{
		FailuresByType:  make(map[FailureType]int64),
		ActionsByType:   make(map[RecoveryAction]int64),
		LastUpdated:     time.Now(),
	}
}

