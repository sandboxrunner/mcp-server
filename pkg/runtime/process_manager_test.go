package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/beam-cloud/go-runc"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// MockRuncInterface implements RuncInterface for testing
type MockRuncInterface struct {
	mu            sync.RWMutex
	containers    map[string]*runc.Container
	processes     map[string]*ProcessResult
	execCallback  func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error
	stateCallback func(ctx context.Context, id string) (*runc.Container, error)
	killCallback  func(ctx context.Context, id string, sig int, opts *runc.KillOpts) error
	shouldFail    map[string]bool
}

func NewMockRuncInterface() *MockRuncInterface {
	return &MockRuncInterface{
		containers: make(map[string]*runc.Container),
		processes:  make(map[string]*ProcessResult),
		shouldFail: make(map[string]bool),
	}
}

func (m *MockRuncInterface) State(ctx context.Context, id string) (*runc.Container, error) {
	if m.stateCallback != nil {
		return m.stateCallback(ctx, id)
	}
	
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if container, exists := m.containers[id]; exists {
		return container, nil
	}
	
	// Default running container
	return &runc.Container{
		ID:     id,
		Status: "running",
		Pid:    12345,
	}, nil
}

func (m *MockRuncInterface) Exec(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
	if m.execCallback != nil {
		return m.execCallback(ctx, id, spec, opts)
	}
	
	m.mu.RLock()
	shouldFail := m.shouldFail["exec"]
	m.mu.RUnlock()
	
	if shouldFail {
		return errors.New("mock exec failure")
	}
	
	// Simulate process start
	if opts.Started != nil {
		select {
		case opts.Started <- 12345:
		case <-time.After(100 * time.Millisecond):
		}
	}
	
	// Simulate process execution
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func (m *MockRuncInterface) Create(ctx context.Context, id, bundle string, opts *runc.CreateOpts) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.containers[id] = &runc.Container{
		ID:     id,
		Status: "created",
		Pid:    0,
	}
	return nil
}

func (m *MockRuncInterface) Start(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if container, exists := m.containers[id]; exists {
		container.Status = "running"
		container.Pid = 12345
	}
	return nil
}

func (m *MockRuncInterface) Kill(ctx context.Context, id string, sig int, opts *runc.KillOpts) error {
	if m.killCallback != nil {
		return m.killCallback(ctx, id, sig, opts)
	}
	
	m.mu.RLock()
	shouldFail := m.shouldFail["kill"]
	m.mu.RUnlock()
	
	if shouldFail {
		return errors.New("mock kill failure")
	}
	
	m.mu.Lock()
	if container, exists := m.containers[id]; exists {
		container.Status = "stopped"
		container.Pid = 0
	}
	m.mu.Unlock()
	
	return nil
}

func (m *MockRuncInterface) Delete(ctx context.Context, id string, opts *runc.DeleteOpts) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	delete(m.containers, id)
	return nil
}

func (m *MockRuncInterface) List(ctx context.Context) ([]*runc.Container, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	containers := make([]*runc.Container, 0, len(m.containers))
	for _, container := range m.containers {
		containers = append(containers, container)
	}
	return containers, nil
}

func (m *MockRuncInterface) SetShouldFail(operation string, shouldFail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail[operation] = shouldFail
}

func (m *MockRuncInterface) SetExecCallback(callback func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error) {
	m.execCallback = callback
}

func (m *MockRuncInterface) SetStateCallback(callback func(ctx context.Context, id string) (*runc.Container, error)) {
	m.stateCallback = callback
}

func (m *MockRuncInterface) SetKillCallback(callback func(ctx context.Context, id string, sig int, opts *runc.KillOpts) error) {
	m.killCallback = callback
}

// Test helper functions
func createTestProcessManager(t *testing.T) (*ProcessManager, *MockRuncInterface) {
	mockRunc := NewMockRuncInterface()
	
	runCClient := &RunCClient{
		runc:     mockRunc,
		rootPath: "/tmp/test",
	}
	
	config := &ProcessManagerConfig{
		CleanupInterval:         100 * time.Millisecond,
		ZombieReapInterval:      50 * time.Millisecond,
		MaxProcesses:            10,
		DefaultTimeout:          5 * time.Second,
		KillTimeout:            1 * time.Second,
		GracefulShutdownTimeout: 2 * time.Second,
		TerminationSignal:       syscall.SIGTERM,
		KillSignal:              syscall.SIGKILL,
		EnableEvents:            true,
		EnableResourceMonitor:   false, // Disable for tests to avoid system dependencies
		EventBufferSize:         100,
	}
	
	pm, err := NewProcessManager(runCClient, config)
	if err != nil {
		t.Fatalf("Failed to create ProcessManager: %v", err)
	}
	
	return pm, mockRunc
}

func createTestProcessSpec() *ProcessSpec {
	return &ProcessSpec{
		Cmd:        "echo",
		Args:       []string{"echo", "hello", "world"},
		Env:        []string{"PATH=/usr/bin"},
		WorkingDir: "/tmp",
		User:       "0:0",
		Terminal:   false,
		Timeout:    1 * time.Second,
	}
}

// Test ProcessManager Creation
func TestNewProcessManager(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		if pm == nil {
			t.Fatal("ProcessManager should not be nil")
		}
		
		if len(pm.processes) != 0 {
			t.Errorf("Expected 0 processes, got %d", len(pm.processes))
		}
	})
	
	t.Run("nil runC client", func(t *testing.T) {
		_, err := NewProcessManager(nil, nil)
		if err == nil {
			t.Error("Expected error for nil runC client")
		}
	})
	
	t.Run("default configuration", func(t *testing.T) {
		mockRunc := NewMockRuncInterface()
		runCClient := &RunCClient{runc: mockRunc, rootPath: "/tmp/test"}
		
		pm, err := NewProcessManager(runCClient, nil)
		if err != nil {
			t.Fatalf("Failed to create ProcessManager with default config: %v", err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		if pm.config == nil {
			t.Error("Expected default configuration to be set")
		}
	})
}

// Test Process Starting
func TestProcessManager_Start(t *testing.T) {
	t.Run("successful start", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		spec := createTestProcessSpec()
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       false,
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		if process == nil {
			t.Fatal("Process should not be nil")
		}
		
		if process.ID == "" {
			t.Error("Process ID should not be empty")
		}
		
		if process.ContainerID != "test-container" {
			t.Errorf("Expected container ID 'test-container', got '%s'", process.ContainerID)
		}
	})
	
	t.Run("missing process spec", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		options := ProcessStartOptions{
			ContainerID: "test-container",
		}
		
		_, err := pm.Start(options)
		if err == nil {
			t.Error("Expected error for missing process spec")
		}
	})
	
	t.Run("missing container ID", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		spec := createTestProcessSpec()
		options := ProcessStartOptions{
			Spec: spec,
		}
		
		_, err := pm.Start(options)
		if err == nil {
			t.Error("Expected error for missing container ID")
		}
	})
	
	t.Run("async start", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		spec := createTestProcessSpec()
		
		var startCalled, exitCalled bool
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       true,
			OnStart: func(p *ManagedProcess) {
				startCalled = true
			},
			OnExit: func(p *ManagedProcess, exitCode int32) {
				exitCalled = true
			},
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start async process: %v", err)
		}
		
		// Wait for process to complete
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		
		if err := pm.Wait(process.ID, ctx); err != nil {
			t.Errorf("Failed to wait for process: %v", err)
		}
		
		// Give callbacks time to execute
		time.Sleep(100 * time.Millisecond)
		
		if !startCalled {
			t.Error("OnStart callback should have been called")
		}
		
		if !exitCalled {
			t.Error("OnExit callback should have been called")
		}
	})
	
	t.Run("process limit exceeded", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		// Set a low limit
		pm.config.MaxProcesses = 1
		
		spec := createTestProcessSpec()
		spec.Timeout = 10 * time.Second // Long running to fill up limit
		
		// Start first process
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "container-1",
			Async:       true,
		}
		
		_, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start first process: %v", err)
		}
		
		// Try to start second process (should fail)
		options.ContainerID = "container-2"
		_, err = pm.Start(options)
		if err == nil {
			t.Error("Expected error when exceeding process limit")
		}
	})
}

// Test Process Stopping
func TestProcessManager_Stop(t *testing.T) {
	t.Run("successful stop", func(t *testing.T) {
		pm, mockRunc := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		// Mock a long-running process that responds to SIGTERM
		mockRunc.SetExecCallback(func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			if opts.Started != nil {
				opts.Started <- 12345
			}
			
			// Wait for context cancellation (simulating SIGTERM response)
			<-ctx.Done()
			return ctx.Err()
		})
		
		spec := createTestProcessSpec()
		spec.Timeout = 10 * time.Second // Long timeout
		
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       true,
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		// Wait for process to start
		time.Sleep(200 * time.Millisecond)
		
		// Stop the process
		err = pm.Stop(process.ID)
		if err != nil {
			t.Errorf("Failed to stop process: %v", err)
		}
		
		// Verify process is stopped
		state := process.GetState()
		if !state.IsTerminal() {
			t.Errorf("Expected terminal state, got %s", state)
		}
	})
	
	t.Run("process not found", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		err := pm.Stop("non-existent-process")
		if err == nil {
			t.Error("Expected error for non-existent process")
		}
	})
	
	t.Run("already terminated process", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		spec := createTestProcessSpec()
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       false,
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		// Wait for process to complete naturally
		time.Sleep(500 * time.Millisecond)
		
		// Try to stop already terminated process
		err = pm.Stop(process.ID)
		if err == nil {
			t.Error("Expected error when stopping already terminated process")
		}
	})
}

// Test Process Killing
func TestProcessManager_Kill(t *testing.T) {
	t.Run("successful kill", func(t *testing.T) {
		pm, mockRunc := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		// Mock a process that doesn't respond to SIGTERM but responds to SIGKILL
		mockRunc.SetExecCallback(func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			if opts.Started != nil {
				opts.Started <- 12345
			}
			
			// Simulate hanging process that only responds to SIGKILL
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(30 * time.Second):
				return nil
			}
		})
		
		spec := createTestProcessSpec()
		spec.Timeout = 30 * time.Second
		
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       true,
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		// Wait for process to start
		time.Sleep(200 * time.Millisecond)
		
		// Kill the process
		err = pm.Kill(process.ID)
		if err != nil {
			t.Errorf("Failed to kill process: %v", err)
		}
		
		// Verify process is in failed state
		state := process.GetState()
		if state != ProcessStateFailed {
			t.Errorf("Expected failed state, got %s", state)
		}
	})
	
	t.Run("kill signal failure", func(t *testing.T) {
		pm, mockRunc := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		// Mock kill failure
		mockRunc.SetKillCallback(func(ctx context.Context, id string, sig int, opts *runc.KillOpts) error {
			return errors.New("mock kill failure")
		})
		
		spec := createTestProcessSpec()
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       true,
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		// Wait for process to start
		time.Sleep(200 * time.Millisecond)
		
		// Try to kill (should fail)
		err = pm.Kill(process.ID)
		if err == nil {
			t.Error("Expected error when kill signal fails")
		}
	})
}

// Test Process Waiting
func TestProcessManager_Wait(t *testing.T) {
	t.Run("wait for completion", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		spec := createTestProcessSpec()
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       true,
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		
		err = pm.Wait(process.ID, ctx)
		if err != nil {
			t.Errorf("Failed to wait for process: %v", err)
		}
		
		if !process.IsTerminal() {
			t.Error("Process should be terminal after wait completes")
		}
	})
	
	t.Run("wait timeout", func(t *testing.T) {
		pm, mockRunc := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		// Mock a long-running process
		mockRunc.SetExecCallback(func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			if opts.Started != nil {
				opts.Started <- 12345
			}
			
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(10 * time.Second):
				return nil
			}
		})
		
		spec := createTestProcessSpec()
		spec.Timeout = 10 * time.Second
		
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       true,
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		// Wait with short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		
		err = pm.Wait(process.ID, ctx)
		if err == nil {
			t.Error("Expected timeout error")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Expected timeout error, got %v", err)
		}
	})
}

// Test Process Status
func TestProcessManager_GetStatus(t *testing.T) {
	t.Run("get status of running process", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		spec := createTestProcessSpec()
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       false,
		}
		
		process, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		status, err := pm.GetStatus(process.ID)
		if err != nil {
			t.Errorf("Failed to get status: %v", err)
		}
		
		if !status.IsTerminal() {
			// Process might still be running or just completed
			if status != ProcessStateRunning && !status.IsTerminal() {
				t.Errorf("Expected running or terminal state, got %s", status)
			}
		}
	})
	
	t.Run("get status of non-existent process", func(t *testing.T) {
		pm, _ := createTestProcessManager(t)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pm.Shutdown(ctx)
		}()
		
		_, err := pm.GetStatus("non-existent")
		if err == nil {
			t.Error("Expected error for non-existent process")
		}
	})
}

// Test Process Listing
func TestProcessManager_ListProcesses(t *testing.T) {
	pm, _ := createTestProcessManager(t)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pm.Shutdown(ctx)
	}()
	
	// Start multiple processes
	spec := createTestProcessSpec()
	
	for i := 0; i < 3; i++ {
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: fmt.Sprintf("container-%d", i),
			Async:       true,
		}
		
		_, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process %d: %v", i, err)
		}
	}
	
	processes := pm.ListProcesses()
	if len(processes) != 3 {
		t.Errorf("Expected 3 processes, got %d", len(processes))
	}
	
	// Verify unique container IDs
	containerIDs := make(map[string]bool)
	for _, process := range processes {
		containerIDs[process.ContainerID] = true
	}
	
	if len(containerIDs) != 3 {
		t.Errorf("Expected 3 unique container IDs, got %d", len(containerIDs))
	}
}

// Test Metrics
func TestProcessManager_GetMetrics(t *testing.T) {
	pm, _ := createTestProcessManager(t)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pm.Shutdown(ctx)
	}()
	
	initialMetrics := pm.GetMetrics()
	
	spec := createTestProcessSpec()
	options := ProcessStartOptions{
		Spec:        spec,
		ContainerID: "test-container",
		Async:       false,
	}
	
	_, err := pm.Start(options)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	
	finalMetrics := pm.GetMetrics()
	
	if finalMetrics.ProcessesStarted <= initialMetrics.ProcessesStarted {
		t.Error("ProcessesStarted should have increased")
	}
	
	if finalMetrics.ProcessesCompleted <= initialMetrics.ProcessesCompleted {
		t.Error("ProcessesCompleted should have increased")
	}
}

// Test Shutdown
func TestProcessManager_Shutdown(t *testing.T) {
	t.Run("graceful shutdown", func(t *testing.T) {
		pm, mockRunc := createTestProcessManager(t)
		
		// Mock a process that responds to shutdown
		mockRunc.SetExecCallback(func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			if opts.Started != nil {
				opts.Started <- 12345
			}
			
			<-ctx.Done()
			return ctx.Err()
		})
		
		// Start a process
		spec := createTestProcessSpec()
		spec.Timeout = 10 * time.Second
		
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       true,
		}
		
		_, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		// Wait for process to start
		time.Sleep(200 * time.Millisecond)
		
		// Shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		err = pm.Shutdown(ctx)
		if err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}
		
		// Verify all processes are terminated
		processes := pm.ListProcesses()
		for _, process := range processes {
			if !process.IsTerminal() {
				t.Errorf("Process %s should be terminal after shutdown", process.ID)
			}
		}
	})
	
	t.Run("shutdown timeout", func(t *testing.T) {
		pm, mockRunc := createTestProcessManager(t)
		
		// Mock a process that doesn't respond to shutdown
		mockRunc.SetExecCallback(func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			if opts.Started != nil {
				opts.Started <- 12345
			}
			
			// Ignore context cancellation
			time.Sleep(10 * time.Second)
			return nil
		})
		
		// Start a process
		spec := createTestProcessSpec()
		spec.Timeout = 30 * time.Second
		
		options := ProcessStartOptions{
			Spec:        spec,
			ContainerID: "test-container",
			Async:       true,
		}
		
		_, err := pm.Start(options)
		if err != nil {
			t.Fatalf("Failed to start process: %v", err)
		}
		
		// Wait for process to start
		time.Sleep(200 * time.Millisecond)
		
		// Shutdown with short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		
		err = pm.Shutdown(ctx)
		// Should complete even with timeout as it forces shutdown
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("Unexpected shutdown error: %v", err)
		}
	})
}

// Test Event System Integration
func TestProcessManager_Events(t *testing.T) {
	pm, _ := createTestProcessManager(t)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pm.Shutdown(ctx)
	}()
	
	if pm.eventBus == nil {
		t.Fatal("Event bus should be initialized")
	}
	
	// Subscribe to events
	var receivedEvents []*ProcessEvent
	var eventMutex sync.Mutex
	
	subscriptionID := pm.eventBus.Subscribe(
		[]ProcessEventType{ProcessEventStart, ProcessEventExit},
		func(event *ProcessEvent) {
			eventMutex.Lock()
			receivedEvents = append(receivedEvents, event)
			eventMutex.Unlock()
		},
	)
	
	defer pm.eventBus.Unsubscribe(subscriptionID)
	
	// Start a process
	spec := createTestProcessSpec()
	options := ProcessStartOptions{
		Spec:        spec,
		ContainerID: "test-container",
		Async:       false,
	}
	
	_, err := pm.Start(options)
	if err != nil {
		t.Fatalf("Failed to start process: %v", err)
	}
	
	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)
	
	eventMutex.Lock()
	eventCount := len(receivedEvents)
	eventMutex.Unlock()
	
	if eventCount < 1 {
		t.Errorf("Expected at least 1 event, got %d", eventCount)
	}
}

// Test Zombie Reaper
func TestZombieReaper(t *testing.T) {
	t.Run("track and untrack PID", func(t *testing.T) {
		reaper := NewZombieReaper(100 * time.Millisecond)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			reaper.Shutdown(ctx)
		}()
		
		// Track a PID
		reaper.TrackPID(12345, "test-process")
		
		reaper.mu.RLock()
		processID := reaper.trackedPIDs[12345]
		reaper.mu.RUnlock()
		
		if processID != "test-process" {
			t.Errorf("Expected 'test-process', got '%s'", processID)
		}
		
		// Untrack the PID
		reaper.UntrackPID(12345)
		
		reaper.mu.RLock()
		_, exists := reaper.trackedPIDs[12345]
		reaper.mu.RUnlock()
		
		if exists {
			t.Error("PID should have been untracked")
		}
	})
	
	t.Run("metrics", func(t *testing.T) {
		reaper := NewZombieReaper(100 * time.Millisecond)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			reaper.Shutdown(ctx)
		}()
		
		metrics := reaper.GetMetrics()
		
		// Should have default values
		if metrics.ZombiesDetected != 0 {
			t.Errorf("Expected 0 zombies detected initially, got %d", metrics.ZombiesDetected)
		}
	})
}

// Benchmark tests
func BenchmarkProcessManager_StartStop(b *testing.B) {
	pm, _ := createTestProcessManager(nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		pm.Shutdown(ctx)
	}()
	
	spec := createTestProcessSpec()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			options := ProcessStartOptions{
				Spec:        spec,
				ContainerID: fmt.Sprintf("bench-container-%d", i),
				Async:       false,
			}
			
			process, err := pm.Start(options)
			if err != nil {
				b.Fatalf("Failed to start process: %v", err)
			}
			
			// Let process complete naturally
			_ = process
			i++
		}
	})
}

func BenchmarkProcessManager_Concurrent(b *testing.B) {
	pm, _ := createTestProcessManager(nil)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		pm.Shutdown(ctx)
	}()
	
	pm.config.MaxProcesses = 1000 // Increase limit for benchmark
	spec := createTestProcessSpec()
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			options := ProcessStartOptions{
				Spec:        spec,
				ContainerID: fmt.Sprintf("bench-concurrent-%d", i),
				Async:       true,
			}
			
			_, err := pm.Start(options)
			if err != nil {
				b.Fatalf("Failed to start process: %v", err)
			}
			i++
		}
	})
}