package tools

import (
	"context"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockContainerFS is a mock implementation of runtime.ContainerFS for testing
type MockContainerFS struct {
	mock.Mock
}

func (m *MockContainerFS) ReadFile(ctx context.Context, containerID, filePath string) ([]byte, error) {
	args := m.Called(ctx, containerID, filePath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockContainerFS) WriteFile(ctx context.Context, containerID, filePath string, data []byte, mode os.FileMode) error {
	args := m.Called(ctx, containerID, filePath, data, mode)
	return args.Error(0)
}

func (m *MockContainerFS) WriteFileAtomic(ctx context.Context, containerID, filePath string, data []byte, mode os.FileMode) error {
	args := m.Called(ctx, containerID, filePath, data, mode)
	return args.Error(0)
}

func (m *MockContainerFS) AppendFile(ctx context.Context, containerID, filePath string, data []byte) error {
	args := m.Called(ctx, containerID, filePath, data)
	return args.Error(0)
}

func (m *MockContainerFS) CreateFile(ctx context.Context, containerID, filePath string, mode os.FileMode) error {
	args := m.Called(ctx, containerID, filePath, mode)
	return args.Error(0)
}

func (m *MockContainerFS) DeleteFile(ctx context.Context, containerID, filePath string) error {
	args := m.Called(ctx, containerID, filePath)
	return args.Error(0)
}

func (m *MockContainerFS) StatFile(ctx context.Context, containerID, filePath string) (*runtime.ContainerFileInfo, error) {
	args := m.Called(ctx, containerID, filePath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*runtime.ContainerFileInfo), args.Error(1)
}

func (m *MockContainerFS) ChmodFile(ctx context.Context, containerID, filePath string, mode os.FileMode) error {
	args := m.Called(ctx, containerID, filePath, mode)
	return args.Error(0)
}

func (m *MockContainerFS) ChownFile(ctx context.Context, containerID, filePath, owner, group string) error {
	args := m.Called(ctx, containerID, filePath, owner, group)
	return args.Error(0)
}

func (m *MockContainerFS) MakeDir(ctx context.Context, containerID, dirPath string, mode os.FileMode) error {
	args := m.Called(ctx, containerID, dirPath, mode)
	return args.Error(0)
}

func (m *MockContainerFS) RemoveDir(ctx context.Context, containerID, dirPath string) error {
	args := m.Called(ctx, containerID, dirPath)
	return args.Error(0)
}

func (m *MockContainerFS) ListDir(ctx context.Context, containerID, dirPath string) ([]*runtime.ContainerFileInfo, error) {
	args := m.Called(ctx, containerID, dirPath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*runtime.ContainerFileInfo), args.Error(1)
}

func (m *MockContainerFS) ReadFileAtomic(ctx context.Context, containerID, filePath string) ([]byte, error) {
	args := m.Called(ctx, containerID, filePath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockContainerFS) CopyFile(ctx context.Context, containerID, srcPath, dstPath string) error {
	args := m.Called(ctx, containerID, srcPath, dstPath)
	return args.Error(0)
}

func (m *MockContainerFS) MoveFile(ctx context.Context, containerID, srcPath, dstPath string) error {
	args := m.Called(ctx, containerID, srcPath, dstPath)
	return args.Error(0)
}

func (m *MockContainerFS) CopyFromHost(ctx context.Context, containerID, hostPath, containerPath string) error {
	args := m.Called(ctx, containerID, hostPath, containerPath)
	return args.Error(0)
}

func (m *MockContainerFS) CopyToHost(ctx context.Context, containerID, containerPath, hostPath string) error {
	args := m.Called(ctx, containerID, containerPath, hostPath)
	return args.Error(0)
}

func (m *MockContainerFS) StreamReadFile(ctx context.Context, containerID, filePath string, offset, size int64) (io.ReadCloser, error) {
	args := m.Called(ctx, containerID, filePath, offset, size)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.ReadCloser), args.Error(1)
}

func (m *MockContainerFS) StreamWriteFile(ctx context.Context, containerID, filePath string, mode os.FileMode) (io.WriteCloser, error) {
	args := m.Called(ctx, containerID, filePath, mode)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(io.WriteCloser), args.Error(1)
}

func (m *MockContainerFS) ValidatePath(filePath string) error {
	args := m.Called(filePath)
	return args.Error(0)
}

func (m *MockContainerFS) SanitizePath(filePath string) string {
	args := m.Called(filePath)
	return args.String(0)
}

func (m *MockContainerFS) IsPathSecure(filePath string) bool {
	args := m.Called(filePath)
	return args.Bool(0)
}

func (m *MockContainerFS) WatchFile(ctx context.Context, containerID, filePath string) (<-chan runtime.FileEvent, error) {
	args := m.Called(ctx, containerID, filePath)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(<-chan runtime.FileEvent), args.Error(1)
}

func (m *MockContainerFS) StopWatch(containerID, filePath string) error {
	args := m.Called(containerID, filePath)
	return args.Error(0)
}

// MockSandboxManager is a mock implementation of sandbox.SandboxManagerInterface for testing
type MockSandboxManager struct {
	mock.Mock
}

// Implement SandboxManagerInterface methods
func (m *MockSandboxManager) GetSandbox(sandboxID string) (*sandbox.Sandbox, error) {
	args := m.Called(sandboxID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sandbox.Sandbox), args.Error(1)
}

func (m *MockSandboxManager) CreateSandbox(ctx context.Context, config sandbox.SandboxConfig) (*sandbox.Sandbox, error) {
	args := m.Called(ctx, config)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sandbox.Sandbox), args.Error(1)
}

func (m *MockSandboxManager) ListSandboxes() ([]*sandbox.Sandbox, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*sandbox.Sandbox), args.Error(1)
}

func (m *MockSandboxManager) StopSandbox(ctx context.Context, sandboxID string) error {
	args := m.Called(ctx, sandboxID)
	return args.Error(0)
}

func (m *MockSandboxManager) DeleteSandbox(ctx context.Context, sandboxID string) error {
	args := m.Called(ctx, sandboxID)
	return args.Error(0)
}

func (m *MockSandboxManager) GetSandboxLogs(ctx context.Context, sandboxID string) ([]byte, error) {
	args := m.Called(ctx, sandboxID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSandboxManager) UpdateSandboxMetadata(sandboxID string, metadata map[string]interface{}) error {
	args := m.Called(sandboxID, metadata)
	return args.Error(0)
}

// Ensure MockSandboxManager implements SandboxManagerInterface
var _ sandbox.SandboxManagerInterface = (*MockSandboxManager)(nil)

// Test EnhancedUploadFileTool
func TestEnhancedUploadFileTool_Execute(t *testing.T) {
	ctx := context.Background()
	mockFS := new(MockContainerFS)
	mockManager := new(MockSandboxManager)

	// Create test sandbox
	testSandbox := &sandbox.Sandbox{
		ID:          "test-sandbox",
		ContainerID: "test-container",
		Status:      sandbox.SandboxStatusRunning,
		WorkingDir:  "/workspace",
	}

	// Create tool
	tool := NewEnhancedUploadFileTool(mockManager, mockFS)

	t.Run("successful upload", func(t *testing.T) {
		// Setup mocks
		mockManager.On("GetSandbox", "test-sandbox").Return(testSandbox, nil)
		mockFS.On("SanitizePath", "/test/file.txt").Return("/test/file.txt")
		mockFS.On("ValidatePath", "/test/file.txt").Return(nil)
		mockFS.On("StatFile", ctx, "test-container", "/test/file.txt").Return(nil, os.ErrNotExist)
		mockFS.On("MakeDir", ctx, "test-container", "/test", os.FileMode(0755)).Return(nil)
		mockFS.On("WriteFileAtomic", ctx, "test-container", "/test/file.txt", mock.Anything, os.FileMode(0644)).Return(nil)
		mockFS.On("StatFile", ctx, "test-container", "/test/file.txt").Return(&runtime.ContainerFileInfo{
			Path:    "/test/file.txt",
			Size:    11,
			ModTime: time.Now(),
		}, nil)

		params := map[string]interface{}{
			"sandbox_id": "test-sandbox",
			"path":       "/test/file.txt",
			"content":    "test content",
			"encoding":   "utf8",
		}

		result, err := tool.Execute(ctx, params)

		assert.NoError(t, err)
		assert.False(t, result.IsError)
		assert.Contains(t, result.Text, "File uploaded successfully")
		assert.Equal(t, "test-sandbox", result.Metadata["sandbox_id"])
		assert.Equal(t, "test-container", result.Metadata["container_id"])

		mockManager.AssertExpectations(t)
		mockFS.AssertExpectations(t)
	})

	t.Run("sandbox not found", func(t *testing.T) {
		mockManager.On("GetSandbox", "nonexistent").Return((*sandbox.Sandbox)(nil), fmt.Errorf("not found"))

		params := map[string]interface{}{
			"sandbox_id": "nonexistent",
			"path":       "/test/file.txt",
			"content":    "test content",
		}

		result, err := tool.Execute(ctx, params)

		assert.NoError(t, err)
		assert.True(t, result.IsError)
		assert.Contains(t, result.Text, "Sandbox not found")

		mockManager.AssertExpectations(t)
	})

	t.Run("invalid path", func(t *testing.T) {
		mockManager.On("GetSandbox", "test-sandbox").Return(testSandbox, nil)
		mockFS.On("SanitizePath", "invalid-path").Return("invalid-path")
		mockFS.On("ValidatePath", "invalid-path").Return(fmt.Errorf("invalid path"))

		params := map[string]interface{}{
			"sandbox_id": "test-sandbox",
			"path":       "invalid-path",
			"content":    "test content",
		}

		result, err := tool.Execute(ctx, params)

		assert.NoError(t, err)
		assert.True(t, result.IsError)
		assert.Contains(t, result.Text, "Invalid file path")

		mockManager.AssertExpectations(t)
		mockFS.AssertExpectations(t)
	})
}

// Test QuotaManager
func TestQuotaManager(t *testing.T) {
	qm := NewQuotaManager()

	t.Run("set and check quota", func(t *testing.T) {
		// Set quota
		qm.SetQuota("test-sandbox", 1000, 10, 100)

		// Check within limits
		err := qm.CheckQuota("test-sandbox", 500)
		assert.NoError(t, err)

		// Check exceeding limits
		err = qm.CheckQuota("test-sandbox", 1500)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "size quota exceeded")
	})

	t.Run("update usage", func(t *testing.T) {
		qm.SetQuota("test-sandbox", 1000, 10, 100)

		// Update usage
		qm.UpdateUsage("test-sandbox", 300)

		// Check updated usage
		usage := qm.GetUsage("test-sandbox")
		assert.Equal(t, int64(300), usage.CurrentSize)
		assert.Equal(t, int64(1), usage.CurrentFiles)
	})

	t.Run("no quota set", func(t *testing.T) {
		// Should allow operation when no quota is set
		err := qm.CheckQuota("unlimited-sandbox", 999999)
		assert.NoError(t, err)
	})
}

// Test FileOperationAuditor
func TestFileOperationAuditor(t *testing.T) {
	auditor := NewFileOperationAuditor()

	t.Run("log operation", func(t *testing.T) {
		entry := &FileOperationAudit{
			Operation: "test_operation",
			SandboxID: "test-sandbox",
			Path:      "/test/file.txt",
			Size:      100,
			Success:   true,
			Timestamp: time.Now(),
		}

		auditor.LogOperation(entry)

		// Get audit entries
		entries := auditor.GetAuditEntries("test-sandbox", "", 10)
		assert.Len(t, entries, 1)
		assert.Equal(t, "test_operation", entries[0].Operation)
		assert.Equal(t, "test-sandbox", entries[0].SandboxID)
	})

	t.Run("get audit summary", func(t *testing.T) {
		// Log multiple operations
		for i := 0; i < 5; i++ {
			entry := &FileOperationAudit{
				Operation: "test_operation",
				SandboxID: "test-sandbox",
				Path:      fmt.Sprintf("/test/file%d.txt", i),
				Size:      100,
				Success:   i%2 == 0, // Alternate success/failure
				Timestamp: time.Now(),
				Duration:  time.Millisecond * 100,
			}
			auditor.LogOperation(entry)
		}

		summary := auditor.GetAuditSummary("test-sandbox")
		assert.Equal(t, 6, summary.TotalOps) // 5 new + 1 from previous test
		assert.Equal(t, 4, summary.SuccessOps)
		assert.Equal(t, 2, summary.FailedOps)
		assert.Equal(t, int64(600), summary.TotalSize)
	})
}

// Test BackupManager
func TestBackupManager(t *testing.T) {
	ctx := context.Background()
	mockFS := new(MockContainerFS)
	bm := NewBackupManager(mockFS)

	t.Run("create backup", func(t *testing.T) {
		fileInfo := &runtime.ContainerFileInfo{
			Path:    "/test/file.txt",
			Size:    100,
			ModTime: time.Now(),
			IsDir:   false,
		}

		mockFS.On("StatFile", ctx, "test-container", "/test/file.txt").Return(fileInfo, nil)
		mockFS.On("MakeDir", ctx, "test-container", mock.AnythingOfType("string"), os.FileMode(0755)).Return(nil)
		mockFS.On("CopyFile", ctx, "test-container", "/test/file.txt", mock.AnythingOfType("string")).Return(nil)
		mockFS.On("ReadFile", ctx, "test-container", "/test/file.txt").Return([]byte("test content"), nil)

		err := bm.CreateBackup(ctx, "test-container", "/test/file.txt")
		assert.NoError(t, err)

		// Check backup was created
		backups := bm.ListBackups("test-container")
		assert.Len(t, backups, 1)
		assert.Equal(t, "/test/file.txt", backups[0].OriginalPath)

		mockFS.AssertExpectations(t)
	})

	t.Run("backup directory fails", func(t *testing.T) {
		fileInfo := &runtime.ContainerFileInfo{
			Path:  "/test/dir",
			IsDir: true,
		}

		mockFS.On("StatFile", ctx, "test-container", "/test/dir").Return(fileInfo, nil)

		err := bm.CreateBackup(ctx, "test-container", "/test/dir")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot backup directory")

		mockFS.AssertExpectations(t)
	})
}

// Benchmark tests
func BenchmarkEnhancedUploadFileTool_Execute(b *testing.B) {
	ctx := context.Background()
	mockFS := new(MockContainerFS)
	mockManager := new(MockSandboxManager)

	testSandbox := &sandbox.Sandbox{
		ID:          "test-sandbox",
		ContainerID: "test-container",
		Status:      sandbox.SandboxStatusRunning,
		WorkingDir:  "/workspace",
	}

	tool := NewEnhancedUploadFileTool(mockManager, mockFS)

	// Setup mocks for all iterations
	mockManager.On("GetSandbox", "test-sandbox").Return(testSandbox, nil).Times(b.N)
	mockFS.On("SanitizePath", "/test/file.txt").Return("/test/file.txt").Times(b.N)
	mockFS.On("ValidatePath", "/test/file.txt").Return(nil).Times(b.N)
	mockFS.On("StatFile", ctx, "test-container", "/test/file.txt").Return(nil, os.ErrNotExist).Times(b.N)
	mockFS.On("MakeDir", ctx, "test-container", "/test", os.FileMode(0755)).Return(nil).Times(b.N)
	mockFS.On("WriteFileAtomic", ctx, "test-container", "/test/file.txt", mock.Anything, os.FileMode(0644)).Return(nil).Times(b.N)
	mockFS.On("StatFile", ctx, "test-container", "/test/file.txt").Return(&runtime.ContainerFileInfo{
		Path:    "/test/file.txt",
		Size:    11,
		ModTime: time.Now(),
	}, nil).Times(b.N)

	params := map[string]interface{}{
		"sandbox_id": "test-sandbox",
		"path":       "/test/file.txt",
		"content":    "test content",
		"encoding":   "utf8",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tool.Execute(ctx, params)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQuotaManager_CheckQuota(b *testing.B) {
	qm := NewQuotaManager()
	qm.SetQuota("test-sandbox", 1000000, 10000, 100000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = qm.CheckQuota("test-sandbox", 500)
	}
}

// Helper function to setup test environment
func setupTestEnvironment() (*MockContainerFS, *MockSandboxManager, *sandbox.Sandbox) {
	mockFS := new(MockContainerFS)
	mockManager := new(MockSandboxManager)

	testSandbox := &sandbox.Sandbox{
		ID:          "test-sandbox",
		ContainerID: "test-container",
		Status:      sandbox.SandboxStatusRunning,
		WorkingDir:  "/workspace",
	}

	return mockFS, mockManager, testSandbox
}

// Integration test for full workflow
func TestFileSystemToolsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()
	mockFS, mockManager, testSandbox := setupTestEnvironment()

	// Setup mocks for upload
	mockManager.On("GetSandbox", "test-sandbox").Return(testSandbox, nil).Once()
	mockFS.On("SanitizePath", "/integration/test.txt").Return("/integration/test.txt").Once()
	mockFS.On("ValidatePath", "/integration/test.txt").Return(nil).Once()
	mockFS.On("StatFile", ctx, "test-container", "/integration/test.txt").Return(nil, os.ErrNotExist).Once()
	mockFS.On("MakeDir", ctx, "test-container", "/integration", os.FileMode(0755)).Return(nil).Once()
	mockFS.On("WriteFileAtomic", ctx, "test-container", "/integration/test.txt", mock.Anything, os.FileMode(0644)).Return(nil).Once()
	mockFS.On("StatFile", ctx, "test-container", "/integration/test.txt").Return(&runtime.ContainerFileInfo{
		Path:    "/integration/test.txt",
		Size:    21, // Length of "integration test data"
		ModTime: time.Now(),
	}, nil).Once()

	// Test upload
	uploadTool := NewEnhancedUploadFileTool(mockManager, mockFS)
	uploadParams := map[string]interface{}{
		"sandbox_id": "test-sandbox",
		"path":       "/integration/test.txt",
		"content":    "integration test data",
		"encoding":   "utf8",
	}

	uploadResult, err := uploadTool.Execute(ctx, uploadParams)
	assert.NoError(t, err)
	assert.False(t, uploadResult.IsError)

	// Setup mocks for download
	mockManager.On("GetSandbox", "test-sandbox").Return(testSandbox, nil).Once()
	mockFS.On("SanitizePath", "/integration/test.txt").Return("/integration/test.txt").Once()
	mockFS.On("ValidatePath", "/integration/test.txt").Return(nil).Once()
	mockFS.On("StatFile", ctx, "test-container", "/integration/test.txt").Return(&runtime.ContainerFileInfo{
		Path:    "/integration/test.txt",
		Size:    21, // Length of "integration test data"
		ModTime: time.Now(),
		IsDir:   false,
	}, nil).Once()
	mockFS.On("ReadFile", ctx, "test-container", "/integration/test.txt").Return([]byte("integration test data"), nil).Once()

	// Test download
	downloadTool := NewEnhancedDownloadFileTool(mockManager, mockFS)
	downloadParams := map[string]interface{}{
		"sandbox_id": "test-sandbox",
		"path":       "/integration/test.txt",
		"encoding":   "utf8",
	}

	downloadResult, err := downloadTool.Execute(ctx, downloadParams)
	assert.NoError(t, err)
	assert.False(t, downloadResult.IsError)
	assert.Contains(t, downloadResult.Text, "integration test data")

	mockManager.AssertExpectations(t)
	mockFS.AssertExpectations(t)
}
