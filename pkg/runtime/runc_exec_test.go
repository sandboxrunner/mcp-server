package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/beam-cloud/go-runc"
	"github.com/opencontainers/runtime-spec/specs-go"
)

// MockRunC implements a mock version of runc.Runc for testing
type MockRunC struct {
	stateFunc  func(ctx context.Context, id string) (*runc.Container, error)
	execFunc   func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error
	createFunc func(ctx context.Context, id, bundle string, opts *runc.CreateOpts) error
	startFunc  func(ctx context.Context, id string) error
	killFunc   func(ctx context.Context, id string, sig int, opts *runc.KillOpts) error
	deleteFunc func(ctx context.Context, id string, opts *runc.DeleteOpts) error
	listFunc   func(ctx context.Context) ([]*runc.Container, error)
}

func (m *MockRunC) State(ctx context.Context, id string) (*runc.Container, error) {
	if m.stateFunc != nil {
		return m.stateFunc(ctx, id)
	}
	return &runc.Container{
		ID:     id,
		Status: "running",
		Pid:    12345,
	}, nil
}

func (m *MockRunC) Exec(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
	if m.execFunc != nil {
		return m.execFunc(ctx, id, spec, opts)
	}
	// Simulate successful execution
	if opts.Started != nil {
		select {
		case opts.Started <- 9999:
		default:
		}
	}
	return nil
}

func (m *MockRunC) Create(ctx context.Context, id, bundle string, opts *runc.CreateOpts) error {
	if m.createFunc != nil {
		return m.createFunc(ctx, id, bundle, opts)
	}
	return nil
}

func (m *MockRunC) Start(ctx context.Context, id string) error {
	if m.startFunc != nil {
		return m.startFunc(ctx, id)
	}
	return nil
}

func (m *MockRunC) Kill(ctx context.Context, id string, sig int, opts *runc.KillOpts) error {
	if m.killFunc != nil {
		return m.killFunc(ctx, id, sig, opts)
	}
	return nil
}

func (m *MockRunC) Delete(ctx context.Context, id string, opts *runc.DeleteOpts) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, id, opts)
	}
	return nil
}

func (m *MockRunC) List(ctx context.Context) ([]*runc.Container, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx)
	}
	return []*runc.Container{}, nil
}

func TestRunCClient_ExecProcess_ValidInput(t *testing.T) {
	client := &RunCClient{
		runc: &MockRunC{},
		rootPath: "/tmp/test",
	}

	spec := NewProcessSpec("/bin/echo", []string{"hello", "world"})
	spec.WithWorkingDir("/tmp").WithUser("1000:1000")

	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "test-container", spec)

	if err != nil {
		t.Fatalf("ExecProcess failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Process == nil {
		t.Fatal("Expected non-nil process in result")
	}

	if result.Process.ContainerID != "test-container" {
		t.Errorf("Expected container ID 'test-container', got '%s'", result.Process.ContainerID)
	}

	if result.Process.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", result.Process.Status)
	}

	if result.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", result.ExitCode)
	}

	if result.Process.PID != 9999 {
		t.Errorf("Expected PID 9999, got %d", result.Process.PID)
	}
}

func TestRunCClient_ExecProcess_EmptyContainerID(t *testing.T) {
	client := &RunCClient{
		runc: &MockRunC{},
		rootPath: "/tmp/test",
	}

	spec := NewProcessSpec("/bin/echo", []string{"hello"})
	
	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "", spec)

	if err == nil {
		t.Fatal("Expected error for empty container ID")
	}

	if result != nil {
		t.Fatal("Expected nil result for invalid input")
	}

	if err.Error() != "container ID cannot be empty" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRunCClient_ExecProcess_NilSpec(t *testing.T) {
	client := &RunCClient{
		runc: &MockRunC{},
		rootPath: "/tmp/test",
	}
	
	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "test-container", nil)

	if err == nil {
		t.Fatal("Expected error for nil spec")
	}

	if result != nil {
		t.Fatal("Expected nil result for invalid input")
	}

	if err.Error() != "process spec cannot be nil" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRunCClient_ExecProcess_EmptyArgs(t *testing.T) {
	client := &RunCClient{
		runc: &MockRunC{},
		rootPath: "/tmp/test",
	}

	spec := &ProcessSpec{
		Cmd:  "/bin/echo",
		Args: []string{}, // empty args
	}
	
	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "test-container", spec)

	if err == nil {
		t.Fatal("Expected error for empty args")
	}

	if result != nil {
		t.Fatal("Expected nil result for invalid input")
	}

	if err.Error() != "process args cannot be empty" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRunCClient_ExecProcess_ContainerNotFound(t *testing.T) {
	mockRunC := &MockRunC{
		stateFunc: func(ctx context.Context, id string) (*runc.Container, error) {
			return nil, errors.New("container not found")
		},
	}

	client := &RunCClient{
		runc: mockRunC,
		rootPath: "/tmp/test",
	}

	spec := NewProcessSpec("/bin/echo", []string{"hello"})
	
	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "non-existent-container", spec)

	if err == nil {
		t.Fatal("Expected error for non-existent container")
	}

	if result != nil {
		t.Fatal("Expected nil result for non-existent container")
	}

	expectedErr := "container not found or not accessible: container not found"
	if err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got '%s'", expectedErr, err.Error())
	}
}

func TestRunCClient_ExecProcess_ContainerNotRunning(t *testing.T) {
	mockRunC := &MockRunC{
		stateFunc: func(ctx context.Context, id string) (*runc.Container, error) {
			return &runc.Container{
				ID:     id,
				Status: "stopped",
				Pid:    0,
			}, nil
		},
	}

	client := &RunCClient{
		runc: mockRunC,
		rootPath: "/tmp/test",
	}

	spec := NewProcessSpec("/bin/echo", []string{"hello"})
	
	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "stopped-container", spec)

	if err == nil {
		t.Fatal("Expected error for stopped container")
	}

	if result != nil {
		t.Fatal("Expected nil result for stopped container")
	}

	expectedErr := "container stopped-container is not running (status: stopped)"
	if err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got '%s'", expectedErr, err.Error())
	}
}

func TestRunCClient_ExecProcess_TimeoutExceeded(t *testing.T) {
	mockRunC := &MockRunC{
		execFunc: func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			// Simulate timeout
			return context.DeadlineExceeded
		},
	}

	client := &RunCClient{
		runc: mockRunC,
		rootPath: "/tmp/test",
	}

	spec := NewProcessSpec("/bin/sleep", []string{"10"})
	spec.WithTimeout(1 * time.Millisecond) // Very short timeout
	
	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "test-container", spec)

	if err != nil {
		t.Fatalf("ExecProcess failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Process.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", result.Process.Status)
	}

	if result.ExitCode != 124 {
		t.Errorf("Expected exit code 124 (timeout), got %d", result.ExitCode)
	}

	if result.Error != context.DeadlineExceeded {
		t.Errorf("Expected timeout error, got %v", result.Error)
	}
}

func TestRunCClient_ExecProcess_ExitError(t *testing.T) {
	mockRunC := &MockRunC{
		execFunc: func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			// Simulate process exit with non-zero code
			return &runc.ExitError{Status: 1}
		},
	}

	client := &RunCClient{
		runc: mockRunC,
		rootPath: "/tmp/test",
	}

	spec := NewProcessSpec("/bin/false", []string{})
	
	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "test-container", spec)

	if err != nil {
		t.Fatalf("ExecProcess failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Process.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", result.Process.Status)
	}

	if result.ExitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", result.ExitCode)
	}

	exitErr, ok := result.Error.(*runc.ExitError)
	if !ok {
		t.Errorf("Expected ExitError, got %T", result.Error)
	} else if exitErr.Status != 1 {
		t.Errorf("Expected exit status 1, got %d", exitErr.Status)
	}
}

func TestRunCClient_ExecProcess_OtherError(t *testing.T) {
	mockRunC := &MockRunC{
		execFunc: func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			return errors.New("permission denied")
		},
	}

	client := &RunCClient{
		runc: mockRunC,
		rootPath: "/tmp/test",
	}

	spec := NewProcessSpec("/bin/echo", []string{"hello"})
	
	ctx := context.Background()
	result, err := client.ExecProcess(ctx, "test-container", spec)

	if err != nil {
		t.Fatalf("ExecProcess failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Process.Status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", result.Process.Status)
	}

	if result.ExitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", result.ExitCode)
	}

	if result.Error.Error() != "permission denied" {
		t.Errorf("Expected 'permission denied' error, got %v", result.Error)
	}
}

func TestRunCClient_ExecProcessLegacy_BackwardCompatibility(t *testing.T) {
	client := &RunCClient{
		runc: &MockRunC{},
		rootPath: "/tmp/test",
	}

	config := ProcessConfig{
		Args: []string{"/bin/echo", "hello"},
		Env:  map[string]string{"HOME": "/tmp"},
		Cwd:  "/var/tmp",
		User: "1000:1000",
	}

	ctx := context.Background()
	exitCode, err := client.ExecProcessLegacy(ctx, "test-container", config)

	if err != nil {
		t.Fatalf("ExecProcessLegacy failed: %v", err)
	}

	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}
}

func TestRunCClient_ExecProcessLegacy_Error(t *testing.T) {
	mockRunC := &MockRunC{
		execFunc: func(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
			return &runc.ExitError{Status: 1}
		},
	}

	client := &RunCClient{
		runc: mockRunC,
		rootPath: "/tmp/test",
	}

	config := ProcessConfig{
		Args: []string{"/bin/false"},
	}

	ctx := context.Background()
	exitCode, err := client.ExecProcessLegacy(ctx, "test-container", config)

	if err == nil {
		t.Error("Expected error from ExecProcessLegacy")
	}

	// Process failed with exit code 1, not -1
	if exitCode != 1 {
		t.Errorf("Expected exit code 1, got %d", exitCode)
	}
}