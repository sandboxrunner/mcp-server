package runtime

import (
	"context"
	"os"
	"strings"
	"testing"
)

// MockRunCClient is a mock implementation of RunCClient for testing
type MockRunCClient struct {
	processResults map[string]*ProcessResult
	containers     map[string]bool
}

// NewMockRunCClient creates a new mock RunC client
func NewMockRunCClient() *MockRunCClient {
	return &MockRunCClient{
		processResults: make(map[string]*ProcessResult),
		containers:     make(map[string]bool),
	}
}

// ExecProcess mocks process execution
func (m *MockRunCClient) ExecProcess(ctx context.Context, containerID string, spec *ProcessSpec) (*ProcessResult, error) {
	// Check if container exists
	if !m.containers[containerID] {
		return &ProcessResult{
			ExitCode: 1,
			Stderr:   []byte("container not found"),
		}, nil
	}

	// Create a key based on the command
	key := strings.Join(spec.Args, " ")

	// Handle common commands
	switch {
	case strings.HasPrefix(key, "cat "):
		return m.handleCat(spec.Args)
	case strings.HasPrefix(key, "tee "):
		return m.handleTee(spec.Args)
	case strings.HasPrefix(key, "touch "):
		return m.handleTouch(spec.Args)
	case strings.HasPrefix(key, "rm "):
		return m.handleRm(spec.Args)
	case strings.HasPrefix(key, "stat "):
		return m.handleStat(spec.Args)
	case strings.HasPrefix(key, "ls "):
		return m.handleLs(spec.Args)
	case strings.HasPrefix(key, "mkdir "):
		return m.handleMkdir(spec.Args)
	case strings.HasPrefix(key, "chmod "):
		return m.handleChmod(spec.Args)
	case strings.HasPrefix(key, "cp "):
		return m.handleCp(spec.Args)
	case strings.HasPrefix(key, "mv "):
		return m.handleMv(spec.Args)
	default:
		// Check if we have a pre-defined result
		if result, exists := m.processResults[key]; exists {
			return result, nil
		}

		// Default success
		return &ProcessResult{
			ExitCode: 0,
			Stdout:   []byte("mock output"),
		}, nil
	}
}

// AddContainer adds a mock container
func (m *MockRunCClient) AddContainer(containerID string) {
	m.containers[containerID] = true
}

// SetProcessResult sets a mock process result
func (m *MockRunCClient) SetProcessResult(command string, result *ProcessResult) {
	m.processResults[command] = result
}

// Mock command handlers
func (m *MockRunCClient) handleCat(args []string) (*ProcessResult, error) {
	if len(args) < 2 {
		return &ProcessResult{ExitCode: 1, Stderr: []byte("missing file argument")}, nil
	}

	filePath := args[1]
	
	// Mock file contents based on path
	switch filePath {
	case "/workspace/test.txt":
		return &ProcessResult{
			ExitCode: 0,
			Stdout:   []byte("test file content"),
		}, nil
	case "/workspace/large.txt":
		return &ProcessResult{
			ExitCode: 0,
			Stdout:   []byte(strings.Repeat("large file content\n", 100)),
		}, nil
	default:
		return &ProcessResult{
			ExitCode: 1,
			Stderr:   []byte("No such file or directory"),
		}, nil
	}
}

func (m *MockRunCClient) handleTee(args []string) (*ProcessResult, error) {
	if len(args) < 2 {
		return &ProcessResult{ExitCode: 1, Stderr: []byte("missing file argument")}, nil
	}

	return &ProcessResult{
		ExitCode: 0,
		Stdout:   []byte(""),
	}, nil
}

func (m *MockRunCClient) handleTouch(args []string) (*ProcessResult, error) {
	if len(args) < 2 {
		return &ProcessResult{ExitCode: 1, Stderr: []byte("missing file argument")}, nil
	}

	return &ProcessResult{
		ExitCode: 0,
		Stdout:   []byte(""),
	}, nil
}

func (m *MockRunCClient) handleRm(args []string) (*ProcessResult, error) {
	if len(args) < 2 {
		return &ProcessResult{ExitCode: 1, Stderr: []byte("missing file argument")}, nil
	}

	return &ProcessResult{
		ExitCode: 0,
		Stdout:   []byte(""),
	}, nil
}

func (m *MockRunCClient) handleStat(args []string) (*ProcessResult, error) {
	if len(args) < 4 { // stat -c format file
		return &ProcessResult{ExitCode: 1, Stderr: []byte("missing arguments")}, nil
	}

	filePath := args[len(args)-1]
	
	switch filePath {
	case "/workspace/test.txt":
		// Format: name|size|mode_hex|mod_time_unix|owner|group|uid|gid
		return &ProcessResult{
			ExitCode: 0,
			Stdout:   []byte("/workspace/test.txt|17|81a4|1609459200|root|root|0|0"),
		}, nil
	case "/workspace/dir":
		return &ProcessResult{
			ExitCode: 0,
			Stdout:   []byte("/workspace/dir|4096|41ed|1609459200|root|root|0|0"),
		}, nil
	default:
		return &ProcessResult{
			ExitCode: 1,
			Stderr:   []byte("No such file or directory"),
		}, nil
	}
}

func (m *MockRunCClient) handleLs(args []string) (*ProcessResult, error) {
	if len(args) < 4 { // ls -la --time-style=+%s path
		return &ProcessResult{ExitCode: 1, Stderr: []byte("missing arguments")}, nil
	}

	dirPath := args[len(args)-1]
	
	switch dirPath {
	case "/workspace":
		return &ProcessResult{
			ExitCode: 0,
			Stdout: []byte(`total 8
drwxr-xr-x 2 root root 4096 1609459200 .
drwxr-xr-x 3 root root 4096 1609459200 ..
-rw-r--r-- 1 root root 17 1609459200 test.txt
drwxr-xr-x 2 root root 4096 1609459200 subdir`),
		}, nil
	default:
		return &ProcessResult{
			ExitCode: 1,
			Stderr:   []byte("No such file or directory"),
		}, nil
	}
}

func (m *MockRunCClient) handleMkdir(args []string) (*ProcessResult, error) {
	return &ProcessResult{ExitCode: 0, Stdout: []byte("")}, nil
}

func (m *MockRunCClient) handleChmod(args []string) (*ProcessResult, error) {
	return &ProcessResult{ExitCode: 0, Stdout: []byte("")}, nil
}

func (m *MockRunCClient) handleCp(args []string) (*ProcessResult, error) {
	return &ProcessResult{ExitCode: 0, Stdout: []byte("")}, nil
}

func (m *MockRunCClient) handleMv(args []string) (*ProcessResult, error) {
	return &ProcessResult{ExitCode: 0, Stdout: []byte("")}, nil
}

// Test suite for ContainerFileSystem

func TestNewContainerFileSystem(t *testing.T) {
	client := NewMockRunCClient()
	cfs := NewContainerFileSystem(client)

	if cfs == nil {
		t.Fatal("NewContainerFileSystem returned nil")
	}

	if cfs.client == nil {
		t.Error("ContainerFileSystem client not set correctly")
	}

	if cfs.pathValidator == nil {
		t.Error("PathValidator not initialized")
	}

	if cfs.fileLock == nil {
		t.Error("FileLockManager not initialized")
	}

	if cfs.fileMonitor == nil {
		t.Error("FileMonitor not initialized")
	}
}

func TestReadFile(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	tests := []struct {
		name         string
		filePath     string
		expectError  bool
		expectedData string
	}{
		{
			name:         "read existing file",
			filePath:     "/workspace/test.txt",
			expectError:  false,
			expectedData: "test file content",
		},
		{
			name:        "read non-existent file",
			filePath:    "/workspace/missing.txt",
			expectError: true,
		},
		{
			name:        "invalid path",
			filePath:    "../../../etc/passwd",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := cfs.ReadFile(ctx, "test-container", tt.filePath)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if string(data) != tt.expectedData {
				t.Errorf("expected %s, got %s", tt.expectedData, string(data))
			}
		})
	}
}

func TestWriteFile(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	tests := []struct {
		name        string
		filePath    string
		data        []byte
		mode        os.FileMode
		expectError bool
	}{
		{
			name:        "write valid file",
			filePath:    "/workspace/output.txt",
			data:        []byte("test data"),
			mode:        0644,
			expectError: false,
		},
		{
			name:        "write empty file",
			filePath:    "/workspace/empty.txt",
			data:        []byte{},
			mode:        0644,
			expectError: false,
		},
		{
			name:        "invalid path",
			filePath:    "../../../etc/passwd",
			data:        []byte("malicious"),
			mode:        0644,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := cfs.WriteFile(ctx, "test-container", tt.filePath, tt.data, tt.mode)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestWriteFileAtomic(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test atomic write
	data := []byte("atomic test data")
	err := cfs.WriteFileAtomic(ctx, "test-container", "/workspace/atomic.txt", data, 0644)
	if err != nil {
		t.Errorf("WriteFileAtomic failed: %v", err)
	}
}

func TestReadFileAtomic(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test atomic read of existing file
	_, err := cfs.ReadFileAtomic(ctx, "test-container", "/workspace/test.txt")
	if err != nil {
		t.Errorf("ReadFileAtomic failed: %v", err)
	}
}

func TestStatFile(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test stat existing file
	info, err := cfs.StatFile(ctx, "test-container", "/workspace/test.txt")
	if err != nil {
		t.Fatalf("StatFile failed: %v", err)
	}

	if info.Name != "test.txt" {
		t.Errorf("expected name test.txt, got %s", info.Name)
	}

	if info.Size != 17 {
		t.Errorf("expected size 17, got %d", info.Size)
	}

	// Test stat non-existent file
	_, err = cfs.StatFile(ctx, "test-container", "/workspace/missing.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestListDir(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test list existing directory
	files, err := cfs.ListDir(ctx, "test-container", "/workspace")
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}

	if len(files) == 0 {
		t.Error("expected files in directory")
	}

	// Check for expected files
	foundTest := false
	for _, file := range files {
		if file.Name == "test.txt" {
			foundTest = true
			break
		}
	}

	if !foundTest {
		t.Error("expected to find test.txt in directory listing")
	}
}

func TestFileOperations(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test create file
	err := cfs.CreateFile(ctx, "test-container", "/workspace/created.txt", 0644)
	if err != nil {
		t.Errorf("CreateFile failed: %v", err)
	}

	// Test delete file
	err = cfs.DeleteFile(ctx, "test-container", "/workspace/created.txt")
	if err != nil {
		t.Errorf("DeleteFile failed: %v", err)
	}

	// Test chmod
	err = cfs.ChmodFile(ctx, "test-container", "/workspace/test.txt", 0755)
	if err != nil {
		t.Errorf("ChmodFile failed: %v", err)
	}

	// Test chown
	err = cfs.ChownFile(ctx, "test-container", "/workspace/test.txt", "user", "group")
	if err != nil {
		t.Errorf("ChownFile failed: %v", err)
	}
}

func TestDirectoryOperations(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test create directory
	err := cfs.MakeDir(ctx, "test-container", "/workspace/newdir", 0755)
	if err != nil {
		t.Errorf("MakeDir failed: %v", err)
	}

	// Test remove directory
	err = cfs.RemoveDir(ctx, "test-container", "/workspace/newdir")
	if err != nil {
		t.Errorf("RemoveDir failed: %v", err)
	}
}

func TestFileCopyMove(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test copy file
	err := cfs.CopyFile(ctx, "test-container", "/workspace/test.txt", "/workspace/test_copy.txt")
	if err != nil {
		t.Errorf("CopyFile failed: %v", err)
	}

	// Test move file
	err = cfs.MoveFile(ctx, "test-container", "/workspace/test_copy.txt", "/workspace/test_moved.txt")
	if err != nil {
		t.Errorf("MoveFile failed: %v", err)
	}
}

func TestStreamOperations(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test stream read
	reader, err := cfs.StreamReadFile(ctx, "test-container", "/workspace/large.txt", 0, 100)
	if err != nil {
		t.Errorf("StreamReadFile failed: %v", err)
	}
	if reader != nil {
		reader.Close()
	}

	// Test stream write
	writer, err := cfs.StreamWriteFile(ctx, "test-container", "/workspace/stream.txt", 0644)
	if err != nil {
		t.Errorf("StreamWriteFile failed: %v", err)
	}
	if writer != nil {
		writer.Write([]byte("stream test"))
		writer.Close()
	}
}

func TestPathValidation(t *testing.T) {
	client := NewMockRunCClient()
	cfs := NewContainerFileSystem(client)

	tests := []struct {
		path        string
		expectValid bool
	}{
		{"/workspace/file.txt", true},
		{"/tmp/temp.txt", true},
		{"/usr/local/bin/app", true},
		{"../../../etc/passwd", false},
		{"/etc/passwd", false},
		{"/proc/version", false},
		{"/sys/kernel", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := cfs.ValidatePath(tt.path)
			isValid := (err == nil)

			if isValid != tt.expectValid {
				t.Errorf("path %s: expected valid=%v, got valid=%v (error: %v)",
					tt.path, tt.expectValid, isValid, err)
			}
		})
	}
}

func TestPathSanitization(t *testing.T) {
	client := NewMockRunCClient()
	cfs := NewContainerFileSystem(client)

	tests := []struct {
		input    string
		expected string
	}{
		{"file.txt", "/file.txt"},
		{"./file.txt", "/file.txt"},
		{"../file.txt", "/file.txt"},
		{"dir//file.txt", "/dir/file.txt"},
		{"/workspace/../file.txt", "/file.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cfs.SanitizePath(tt.input)
			if result != tt.expected {
				t.Errorf("input %s: expected %s, got %s", tt.input, tt.expected, result)
			}
		})
	}
}

func TestConcurrentAccess(t *testing.T) {
	client := NewMockRunCClient()
	client.AddContainer("test-container")
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()
	filePath := "/workspace/concurrent.txt"

	// Test concurrent writes
	numGoroutines := 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			data := []byte("data from goroutine " + string(rune('0'+id)))
			err := cfs.WriteFileAtomic(ctx, "test-container", filePath, data, 0644)
			if err != nil {
				t.Errorf("concurrent write %d failed: %v", id, err)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

func TestErrorConditions(t *testing.T) {
	client := NewMockRunCClient()
	// Don't add container to test error conditions
	cfs := NewContainerFileSystem(client)

	ctx := context.Background()

	// Test operations on non-existent container
	_, err := cfs.ReadFile(ctx, "missing-container", "/workspace/test.txt")
	if err == nil {
		t.Error("expected error for non-existent container")
	}

	err = cfs.WriteFile(ctx, "missing-container", "/workspace/test.txt", []byte("data"), 0644)
	if err == nil {
		t.Error("expected error for non-existent container")
	}
}

// Benchmark tests

func BenchmarkReadFile(b *testing.B) {
	client := NewMockRunCClient()
	client.AddContainer("bench-container")
	cfs := NewContainerFileSystem(client)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cfs.ReadFile(ctx, "bench-container", "/workspace/test.txt")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteFile(b *testing.B) {
	client := NewMockRunCClient()
	client.AddContainer("bench-container")
	cfs := NewContainerFileSystem(client)
	ctx := context.Background()
	data := []byte("benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := cfs.WriteFile(ctx, "bench-container", "/workspace/bench.txt", data, 0644)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteFileAtomic(b *testing.B) {
	client := NewMockRunCClient()
	client.AddContainer("bench-container")
	cfs := NewContainerFileSystem(client)
	ctx := context.Background()
	data := []byte("atomic benchmark test data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := cfs.WriteFileAtomic(ctx, "bench-container", "/workspace/atomic_bench.txt", data, 0644)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStatFile(b *testing.B) {
	client := NewMockRunCClient()
	client.AddContainer("bench-container")
	cfs := NewContainerFileSystem(client)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cfs.StatFile(ctx, "bench-container", "/workspace/test.txt")
		if err != nil {
			b.Fatal(err)
		}
	}
}