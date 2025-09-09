package runtime

import (
	"fmt"
	"sync"
	"time"
)

// ProcessState represents the current state of a managed process
type ProcessState int

const (
	// ProcessStateCreated indicates the process has been created but not started
	ProcessStateCreated ProcessState = iota
	// ProcessStateRunning indicates the process is currently running
	ProcessStateRunning
	// ProcessStateStopped indicates the process has stopped normally
	ProcessStateStopped
	// ProcessStateFailed indicates the process has failed or crashed
	ProcessStateFailed
	// ProcessStateUnknown indicates the process state is unknown
	ProcessStateUnknown
)

// String returns the string representation of the process state
func (ps ProcessState) String() string {
	switch ps {
	case ProcessStateCreated:
		return "created"
	case ProcessStateRunning:
		return "running"
	case ProcessStateStopped:
		return "stopped"
	case ProcessStateFailed:
		return "failed"
	case ProcessStateUnknown:
		return "unknown"
	default:
		return "invalid"
	}
}

// IsValid returns true if the process state is valid
func (ps ProcessState) IsValid() bool {
	return ps >= ProcessStateCreated && ps <= ProcessStateUnknown
}

// IsTerminal returns true if the process state is terminal (stopped or failed)
func (ps ProcessState) IsTerminal() bool {
	return ps == ProcessStateStopped || ps == ProcessStateFailed
}

// CanTransitionTo checks if a transition from current state to target state is valid
func (ps ProcessState) CanTransitionTo(target ProcessState) bool {
	switch ps {
	case ProcessStateCreated:
		return target == ProcessStateRunning || target == ProcessStateFailed
	case ProcessStateRunning:
		return target == ProcessStateStopped || target == ProcessStateFailed || target == ProcessStateUnknown
	case ProcessStateStopped:
		return false // Terminal state
	case ProcessStateFailed:
		return false // Terminal state
	case ProcessStateUnknown:
		return target == ProcessStateRunning || target == ProcessStateStopped || target == ProcessStateFailed
	default:
		return false
	}
}

// ManagedProcess represents a process being managed by the ProcessManager
type ManagedProcess struct {
	// Process metadata
	ID          string    `json:"id"`
	PID         int32     `json:"pid"`
	ContainerID string    `json:"containerId"`
	StartTime   time.Time `json:"startTime"`
	EndTime     *time.Time `json:"endTime,omitempty"`
	
	// Process execution details
	Spec     *ProcessSpec `json:"spec"`
	ExitCode *int32       `json:"exitCode,omitempty"`
	
	// State management (thread-safe)
	mu       sync.RWMutex
	state    ProcessState     `json:"state"`
	stateTransitions []StateTransition `json:"stateTransitions,omitempty"`
	
	// Resource tracking
	ResourceUsage *ProcessResourceUsage `json:"resourceUsage,omitempty"`
	
	// Internal fields for process management
	cancel     func()        // Context cancellation function
	done       chan struct{} // Channel signaling process completion
	lastError  error         // Last error encountered
}

// StateTransition represents a state change event
type StateTransition struct {
	From      ProcessState `json:"from"`
	To        ProcessState `json:"to"`
	Timestamp time.Time    `json:"timestamp"`
	Reason    string       `json:"reason,omitempty"`
}

// ProcessResourceUsage holds resource usage information for a process
type ProcessResourceUsage struct {
	mu sync.RWMutex
	
	// CPU metrics
	CPUPercent    float64 `json:"cpuPercent"`
	CPUTime       int64   `json:"cpuTime"`       // Total CPU time in nanoseconds
	CPUUserTime   int64   `json:"cpuUserTime"`   // User CPU time in nanoseconds
	CPUSystemTime int64   `json:"cpuSystemTime"` // System CPU time in nanoseconds
	
	// Memory metrics (in bytes)
	MemoryRSS     int64 `json:"memoryRss"`     // Resident Set Size
	MemoryVMS     int64 `json:"memoryVms"`     // Virtual Memory Size
	MemorySwap    int64 `json:"memorySwap"`    // Swap usage
	MemoryPercent float64 `json:"memoryPercent"` // Memory usage percentage
	
	// IO metrics
	ReadBytes    int64 `json:"readBytes"`
	WriteBytes   int64 `json:"writeBytes"`
	ReadOps      int64 `json:"readOps"`
	WriteOps     int64 `json:"writeOps"`
	
	// Network metrics (if available)
	NetBytesRecv int64 `json:"netBytesRecv"`
	NetBytesSent int64 `json:"netBytesSent"`
	
	// File descriptor count
	FDCount int32 `json:"fdCount"`
	
	// Thread count
	ThreadCount int32 `json:"threadCount"`
	
	// Collection metadata
	LastUpdate    time.Time `json:"lastUpdate"`
	SampleCount   int64     `json:"sampleCount"`
	CollectionErr error     `json:"collectionError,omitempty"`
}

// NewManagedProcess creates a new managed process
func NewManagedProcess(id, containerID string, spec *ProcessSpec) *ManagedProcess {
	return &ManagedProcess{
		ID:          id,
		ContainerID: containerID,
		Spec:        spec,
		StartTime:   time.Now(),
		state:       ProcessStateCreated,
		done:        make(chan struct{}),
		stateTransitions: []StateTransition{
			{
				From:      ProcessStateUnknown,
				To:        ProcessStateCreated,
				Timestamp: time.Now(),
				Reason:    "Process created",
			},
		},
		ResourceUsage: &ProcessResourceUsage{
			LastUpdate: time.Now(),
		},
	}
}

// GetState returns the current state of the process (thread-safe)
func (mp *ManagedProcess) GetState() ProcessState {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.state
}

// SetState changes the process state if the transition is valid (thread-safe)
func (mp *ManagedProcess) SetState(newState ProcessState, reason string) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	
	if !mp.state.CanTransitionTo(newState) {
		return fmt.Errorf("invalid state transition from %s to %s", mp.state, newState)
	}
	
	oldState := mp.state
	mp.state = newState
	
	// Record state transition
	transition := StateTransition{
		From:      oldState,
		To:        newState,
		Timestamp: time.Now(),
		Reason:    reason,
	}
	mp.stateTransitions = append(mp.stateTransitions, transition)
	
	// Set end time if terminal state
	if newState.IsTerminal() && mp.EndTime == nil {
		endTime := time.Now()
		mp.EndTime = &endTime
		close(mp.done)
	}
	
	return nil
}

// GetStateTransitions returns a copy of all state transitions
func (mp *ManagedProcess) GetStateTransitions() []StateTransition {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	
	transitions := make([]StateTransition, len(mp.stateTransitions))
	copy(transitions, mp.stateTransitions)
	return transitions
}

// IsRunning returns true if the process is in running state
func (mp *ManagedProcess) IsRunning() bool {
	return mp.GetState() == ProcessStateRunning
}

// IsTerminal returns true if the process is in a terminal state
func (mp *ManagedProcess) IsTerminal() bool {
	return mp.GetState().IsTerminal()
}

// Duration returns the duration the process has been running
func (mp *ManagedProcess) Duration() time.Duration {
	if mp.EndTime != nil {
		return mp.EndTime.Sub(mp.StartTime)
	}
	return time.Since(mp.StartTime)
}

// Wait waits for the process to reach a terminal state
func (mp *ManagedProcess) Wait() <-chan struct{} {
	return mp.done
}

// SetPID sets the system process ID
func (mp *ManagedProcess) SetPID(pid int32) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.PID = pid
}

// SetExitCode sets the process exit code
func (mp *ManagedProcess) SetExitCode(exitCode int32) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.ExitCode = &exitCode
}

// SetError sets the last error encountered
func (mp *ManagedProcess) SetError(err error) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.lastError = err
}

// GetError returns the last error encountered
func (mp *ManagedProcess) GetError() error {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	return mp.lastError
}

// SetCancel sets the cancellation function
func (mp *ManagedProcess) SetCancel(cancel func()) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	mp.cancel = cancel
}

// Cancel cancels the process context if available
func (mp *ManagedProcess) Cancel() {
	mp.mu.RLock()
	cancel := mp.cancel
	mp.mu.RUnlock()
	
	if cancel != nil {
		cancel()
	}
}

// UpdateResourceUsage updates the resource usage metrics (thread-safe)
func (mp *ManagedProcess) UpdateResourceUsage(usage *ProcessResourceUsage) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	
	if mp.ResourceUsage == nil {
		mp.ResourceUsage = &ProcessResourceUsage{}
	}
	
	mp.ResourceUsage.mu.Lock()
	defer mp.ResourceUsage.mu.Unlock()
	
	*mp.ResourceUsage = *usage
	mp.ResourceUsage.LastUpdate = time.Now()
	mp.ResourceUsage.SampleCount++
}

// GetResourceUsage returns a copy of the current resource usage (thread-safe)
func (mp *ManagedProcess) GetResourceUsage() *ProcessResourceUsage {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	
	if mp.ResourceUsage == nil {
		return nil
	}
	
	mp.ResourceUsage.mu.RLock()
	defer mp.ResourceUsage.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	usage := *mp.ResourceUsage
	return &usage
}

// ToProcess converts ManagedProcess to the legacy Process struct for compatibility
func (mp *ManagedProcess) ToProcess() *Process {
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	
	return &Process{
		ID:          mp.ID,
		PID:         mp.PID,
		Status:      mp.state.String(),
		StartTime:   mp.StartTime,
		ExitCode:    mp.ExitCode,
		ContainerID: mp.ContainerID,
	}
}