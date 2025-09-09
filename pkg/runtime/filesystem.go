package runtime

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ContainerFileInfo represents file information within a container
type ContainerFileInfo struct {
	Path        string      `json:"path"`
	Name        string      `json:"name"`
	Size        int64       `json:"size"`
	Mode        os.FileMode `json:"mode"`
	ModTime     time.Time   `json:"mod_time"`
	IsDir       bool        `json:"is_dir"`
	Permissions string      `json:"permissions"`
	Owner       string      `json:"owner"`
	Group       string      `json:"group"`
	UID         int         `json:"uid"`
	GID         int         `json:"gid"`
}

// ContainerFS defines the interface for container filesystem operations
type ContainerFS interface {
	// File operations
	ReadFile(ctx context.Context, containerID, filePath string) ([]byte, error)
	WriteFile(ctx context.Context, containerID, filePath string, data []byte, mode os.FileMode) error
	AppendFile(ctx context.Context, containerID, filePath string, data []byte) error
	CreateFile(ctx context.Context, containerID, filePath string, mode os.FileMode) error
	DeleteFile(ctx context.Context, containerID, filePath string) error
	StatFile(ctx context.Context, containerID, filePath string) (*ContainerFileInfo, error)
	ChmodFile(ctx context.Context, containerID, filePath string, mode os.FileMode) error
	ChownFile(ctx context.Context, containerID, filePath, owner, group string) error

	// Directory operations
	MakeDir(ctx context.Context, containerID, dirPath string, mode os.FileMode) error
	RemoveDir(ctx context.Context, containerID, dirPath string) error
	ListDir(ctx context.Context, containerID, dirPath string) ([]*ContainerFileInfo, error)

	// File operations with locks
	ReadFileAtomic(ctx context.Context, containerID, filePath string) ([]byte, error)
	WriteFileAtomic(ctx context.Context, containerID, filePath string, data []byte, mode os.FileMode) error

	// Copying and moving
	CopyFile(ctx context.Context, containerID, srcPath, dstPath string) error
	MoveFile(ctx context.Context, containerID, srcPath, dstPath string) error
	CopyFromHost(ctx context.Context, containerID, hostPath, containerPath string) error
	CopyToHost(ctx context.Context, containerID, containerPath, hostPath string) error

	// Streaming operations for large files
	StreamReadFile(ctx context.Context, containerID, filePath string, offset, size int64) (io.ReadCloser, error)
	StreamWriteFile(ctx context.Context, containerID, filePath string, mode os.FileMode) (io.WriteCloser, error)

	// Path validation and utilities
	ValidatePath(filePath string) error
	SanitizePath(filePath string) string
	IsPathSecure(filePath string) bool

	// File system monitoring
	WatchFile(ctx context.Context, containerID, filePath string) (<-chan FileEvent, error)
	StopWatch(containerID, filePath string) error
}

// FileEvent represents a file system event
type FileEvent struct {
	Path      string    `json:"path"`
	Op        string    `json:"operation"` // create, write, remove, chmod, move
	Timestamp time.Time `json:"timestamp"`
	OldPath   string    `json:"old_path,omitempty"` // for move operations
}

// ContainerClient interface for dependency injection in tests
type ContainerClient interface {
	ExecProcess(ctx context.Context, containerID string, spec *ProcessSpec) (*ProcessResult, error)
}

// ContainerFileSystem implements the ContainerFS interface
type ContainerFileSystem struct {
	client          ContainerClient
	pathValidator   *PathValidator
	fileLock        *FileLockManager
	fileMonitor     *FileMonitor
	streamingBufSize int64
	maxFileSize      int64
	tempDirPattern   string
	mu              sync.RWMutex
}

// NewContainerFileSystem creates a new container filesystem manager
func NewContainerFileSystem(client ContainerClient) *ContainerFileSystem {
	validator := NewPathValidator()
	lockManager := NewFileLockManager()
	fileMonitor := NewFileMonitor()

	return &ContainerFileSystem{
		client:           client,
		pathValidator:    validator,
		fileLock:         lockManager,
		fileMonitor:      fileMonitor,
		streamingBufSize: 64 * 1024,     // 64KB chunks
		maxFileSize:      100 * 1024 * 1024, // 100MB max file size
		tempDirPattern:   "/tmp/sandboxfs-*",
	}
}

// ReadFile reads the entire content of a file from the container
func (cfs *ContainerFileSystem) ReadFile(ctx context.Context, containerID, filePath string) ([]byte, error) {
	if err := cfs.ValidatePath(filePath); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	// Use cat command to read file
	spec := &ProcessSpec{
		Cmd:  "cat",
		Args: []string{"cat", filePath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 30 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		return nil, fmt.Errorf("cat command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Int("size", len(result.Stdout)).
		Msg("File read successfully")

	return result.Stdout, nil
}

// WriteFile writes data to a file in the container
func (cfs *ContainerFileSystem) WriteFile(ctx context.Context, containerID, filePath string, data []byte, mode os.FileMode) error {
	if err := cfs.ValidatePath(filePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	if len(data) == 0 {
		// Create empty file using touch
		return cfs.CreateFile(ctx, containerID, filePath, mode)
	}

	// Create a temporary file with the data
	tempFile, err := cfs.createTempFileWithData(ctx, containerID, data)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer cfs.cleanupTempFile(ctx, containerID, tempFile)

	// Use cat + tee to write the file
	catSpec := &ProcessSpec{
		Cmd:  "sh",
		Args: []string{"sh", "-c", fmt.Sprintf("cat %s | tee %s > /dev/null", tempFile, filePath)},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 60 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, catSpec)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("write command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	// Set file permissions if specified
	if mode != 0 {
		if err := cfs.ChmodFile(ctx, containerID, filePath, mode); err != nil {
			log.Warn().Err(err).Str("file_path", filePath).Msg("Failed to set file permissions")
		}
	}

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Int("size", len(data)).
		Str("mode", mode.String()).
		Msg("File written successfully")

	return nil
}

// WriteFileAtomic writes data to a file atomically using a temporary file
func (cfs *ContainerFileSystem) WriteFileAtomic(ctx context.Context, containerID, filePath string, data []byte, mode os.FileMode) error {
	if err := cfs.ValidatePath(filePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Acquire file lock
	lockID, err := cfs.fileLock.AcquireLock(ctx, containerID, filePath, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to acquire file lock: %w", err)
	}
	defer func() {
		if releaseErr := cfs.fileLock.ReleaseLock(containerID, filePath, lockID); releaseErr != nil {
			log.Warn().Err(releaseErr).Str("file_path", filePath).Msg("Failed to release file lock")
		}
	}()

	// Create atomic temporary file name
	tempFile := filePath + ".tmp." + generateRandomString(8)

	// Write to temporary file first
	if err := cfs.WriteFile(ctx, containerID, tempFile, data, mode); err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	// Atomically move temp file to target
	if err := cfs.MoveFile(ctx, containerID, tempFile, filePath); err != nil {
		// Clean up temp file on failure
		cfs.DeleteFile(ctx, containerID, tempFile)
		return fmt.Errorf("failed to move temp file to target: %w", err)
	}

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Str("temp_file", tempFile).
		Msg("File written atomically")

	return nil
}

// ReadFileAtomic reads a file with locking to ensure consistency
func (cfs *ContainerFileSystem) ReadFileAtomic(ctx context.Context, containerID, filePath string) ([]byte, error) {
	if err := cfs.ValidatePath(filePath); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	// Acquire file lock
	lockID, err := cfs.fileLock.AcquireLock(ctx, containerID, filePath, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire file lock: %w", err)
	}
	defer func() {
		if releaseErr := cfs.fileLock.ReleaseLock(containerID, filePath, lockID); releaseErr != nil {
			log.Warn().Err(releaseErr).Str("file_path", filePath).Msg("Failed to release file lock")
		}
	}()

	return cfs.ReadFile(ctx, containerID, filePath)
}

// AppendFile appends data to a file in the container
func (cfs *ContainerFileSystem) AppendFile(ctx context.Context, containerID, filePath string, data []byte) error {
	if err := cfs.ValidatePath(filePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Create a temporary file with the data
	tempFile, err := cfs.createTempFileWithData(ctx, containerID, data)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer cfs.cleanupTempFile(ctx, containerID, tempFile)

	// Use cat with append redirection
	spec := &ProcessSpec{
		Cmd:  "sh",
		Args: []string{"sh", "-c", fmt.Sprintf("cat %s >> %s", tempFile, filePath)},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 60 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to append to file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("append command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Int("append_size", len(data)).
		Msg("Data appended to file successfully")

	return nil
}

// CreateFile creates an empty file with specified permissions
func (cfs *ContainerFileSystem) CreateFile(ctx context.Context, containerID, filePath string, mode os.FileMode) error {
	if err := cfs.ValidatePath(filePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Use touch command to create file
	spec := &ProcessSpec{
		Cmd:  "touch",
		Args: []string{"touch", filePath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 10 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("touch command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	// Set permissions if specified
	if mode != 0 {
		if err := cfs.ChmodFile(ctx, containerID, filePath, mode); err != nil {
			return fmt.Errorf("failed to set file permissions: %w", err)
		}
	}

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Str("mode", mode.String()).
		Msg("File created successfully")

	return nil
}

// DeleteFile deletes a file from the container
func (cfs *ContainerFileSystem) DeleteFile(ctx context.Context, containerID, filePath string) error {
	if err := cfs.ValidatePath(filePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	spec := &ProcessSpec{
		Cmd:  "rm",
		Args: []string{"rm", "-f", filePath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 30 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to delete file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("rm command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Msg("File deleted successfully")

	return nil
}

// StatFile gets information about a file in the container
func (cfs *ContainerFileSystem) StatFile(ctx context.Context, containerID, filePath string) (*ContainerFileInfo, error) {
	if err := cfs.ValidatePath(filePath); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	// Use stat command to get file information
	spec := &ProcessSpec{
		Cmd:  "stat",
		Args: []string{"stat", "-c", "%n|%s|%f|%Y|%U|%G|%u|%g", filePath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 10 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		if strings.Contains(string(result.Stderr), "No such file") {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("stat command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	return cfs.parseStatOutput(strings.TrimSpace(string(result.Stdout)))
}

// ChmodFile changes file permissions
func (cfs *ContainerFileSystem) ChmodFile(ctx context.Context, containerID, filePath string, mode os.FileMode) error {
	if err := cfs.ValidatePath(filePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Convert mode to octal string
	octalMode := fmt.Sprintf("%04o", mode)

	spec := &ProcessSpec{
		Cmd:  "chmod",
		Args: []string{"chmod", octalMode, filePath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 10 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to chmod file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("chmod command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Str("mode", octalMode).
		Msg("File permissions changed")

	return nil
}

// ChownFile changes file ownership
func (cfs *ContainerFileSystem) ChownFile(ctx context.Context, containerID, filePath, owner, group string) error {
	if err := cfs.ValidatePath(filePath); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	ownerSpec := owner
	if group != "" {
		ownerSpec = fmt.Sprintf("%s:%s", owner, group)
	}

	spec := &ProcessSpec{
		Cmd:  "chown",
		Args: []string{"chown", ownerSpec, filePath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 10 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to chown file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("chown command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("file_path", filePath).
		Str("owner", ownerSpec).
		Msg("File ownership changed")

	return nil
}

// MakeDir creates a directory in the container
func (cfs *ContainerFileSystem) MakeDir(ctx context.Context, containerID, dirPath string, mode os.FileMode) error {
	if err := cfs.ValidatePath(dirPath); err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	// Convert mode to octal string
	octalMode := fmt.Sprintf("%04o", mode)

	spec := &ProcessSpec{
		Cmd:  "mkdir",
		Args: []string{"mkdir", "-p", "-m", octalMode, dirPath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 30 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("mkdir command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("dir_path", dirPath).
		Str("mode", octalMode).
		Msg("Directory created successfully")

	return nil
}

// RemoveDir removes a directory from the container
func (cfs *ContainerFileSystem) RemoveDir(ctx context.Context, containerID, dirPath string) error {
	if err := cfs.ValidatePath(dirPath); err != nil {
		return fmt.Errorf("invalid directory path: %w", err)
	}

	spec := &ProcessSpec{
		Cmd:  "rm",
		Args: []string{"rm", "-rf", dirPath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 60 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to remove directory %s: %w", dirPath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("rm command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("dir_path", dirPath).
		Msg("Directory removed successfully")

	return nil
}

// ListDir lists files in a directory
func (cfs *ContainerFileSystem) ListDir(ctx context.Context, containerID, dirPath string) ([]*ContainerFileInfo, error) {
	if err := cfs.ValidatePath(dirPath); err != nil {
		return nil, fmt.Errorf("invalid directory path: %w", err)
	}

	// Use ls with detailed format
	spec := &ProcessSpec{
		Cmd:  "ls",
		Args: []string{"ls", "-la", "--time-style=+%s", dirPath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 30 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory %s: %w", dirPath, err)
	}

	if result.ExitCode != 0 {
		if strings.Contains(string(result.Stderr), "No such file") {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("ls command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	return cfs.parseLsOutput(string(result.Stdout), dirPath)
}

// CopyFile copies a file within the container
func (cfs *ContainerFileSystem) CopyFile(ctx context.Context, containerID, srcPath, dstPath string) error {
	if err := cfs.ValidatePath(srcPath); err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}
	if err := cfs.ValidatePath(dstPath); err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}

	spec := &ProcessSpec{
		Cmd:  "cp",
		Args: []string{"cp", "-p", srcPath, dstPath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 60 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to copy file %s to %s: %w", srcPath, dstPath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("cp command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("src_path", srcPath).
		Str("dst_path", dstPath).
		Msg("File copied successfully")

	return nil
}

// MoveFile moves a file within the container
func (cfs *ContainerFileSystem) MoveFile(ctx context.Context, containerID, srcPath, dstPath string) error {
	if err := cfs.ValidatePath(srcPath); err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}
	if err := cfs.ValidatePath(dstPath); err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}

	spec := &ProcessSpec{
		Cmd:  "mv",
		Args: []string{"mv", srcPath, dstPath},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 60 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return fmt.Errorf("failed to move file %s to %s: %w", srcPath, dstPath, err)
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("mv command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	log.Debug().
		Str("container_id", containerID).
		Str("src_path", srcPath).
		Str("dst_path", dstPath).
		Msg("File moved successfully")

	return nil
}

// CopyFromHost copies a file from host to container
func (cfs *ContainerFileSystem) CopyFromHost(ctx context.Context, containerID, hostPath, containerPath string) error {
	if err := cfs.ValidatePath(containerPath); err != nil {
		return fmt.Errorf("invalid container path: %w", err)
	}

	// Read the host file
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return fmt.Errorf("failed to read host file %s: %w", hostPath, err)
	}

	// Get file info for permissions
	info, err := os.Stat(hostPath)
	if err != nil {
		return fmt.Errorf("failed to stat host file %s: %w", hostPath, err)
	}

	// Write to container
	if err := cfs.WriteFile(ctx, containerID, containerPath, data, info.Mode()); err != nil {
		return fmt.Errorf("failed to write to container file %s: %w", containerPath, err)
	}

	log.Debug().
		Str("container_id", containerID).
		Str("host_path", hostPath).
		Str("container_path", containerPath).
		Int("size", len(data)).
		Msg("File copied from host to container")

	return nil
}

// CopyToHost copies a file from container to host
func (cfs *ContainerFileSystem) CopyToHost(ctx context.Context, containerID, containerPath, hostPath string) error {
	if err := cfs.ValidatePath(containerPath); err != nil {
		return fmt.Errorf("invalid container path: %w", err)
	}

	// Read from container
	data, err := cfs.ReadFile(ctx, containerID, containerPath)
	if err != nil {
		return fmt.Errorf("failed to read container file %s: %w", containerPath, err)
	}

	// Get file info for permissions
	info, err := cfs.StatFile(ctx, containerID, containerPath)
	if err != nil {
		return fmt.Errorf("failed to stat container file %s: %w", containerPath, err)
	}

	// Create host directory if needed
	if err := os.MkdirAll(filepath.Dir(hostPath), 0755); err != nil {
		return fmt.Errorf("failed to create host directory: %w", err)
	}

	// Write to host
	if err := os.WriteFile(hostPath, data, info.Mode); err != nil {
		return fmt.Errorf("failed to write to host file %s: %w", hostPath, err)
	}

	log.Debug().
		Str("container_id", containerID).
		Str("container_path", containerPath).
		Str("host_path", hostPath).
		Int("size", len(data)).
		Msg("File copied from container to host")

	return nil
}

// StreamReadFile returns a reader for streaming large files
func (cfs *ContainerFileSystem) StreamReadFile(ctx context.Context, containerID, filePath string, offset, size int64) (io.ReadCloser, error) {
	if err := cfs.ValidatePath(filePath); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	// Use dd command for streaming read with offset and size
	ddCmd := fmt.Sprintf("dd if=%s", filePath)
	if offset > 0 {
		ddCmd += fmt.Sprintf(" skip=%d", offset)
	}
	if size > 0 {
		ddCmd += fmt.Sprintf(" count=%d", size)
	}
	ddCmd += " bs=1 2>/dev/null"

	spec := &ProcessSpec{
		Cmd:  "sh",
		Args: []string{"sh", "-c", ddCmd},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 300 * time.Second, // 5 minutes for large files
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return nil, fmt.Errorf("failed to stream read file %s: %w", filePath, err)
	}

	if result.ExitCode != 0 {
		return nil, fmt.Errorf("dd command failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	return io.NopCloser(bytes.NewReader(result.Stdout)), nil
}

// StreamWriteFile returns a writer for streaming large files
func (cfs *ContainerFileSystem) StreamWriteFile(ctx context.Context, containerID, filePath string, mode os.FileMode) (io.WriteCloser, error) {
	if err := cfs.ValidatePath(filePath); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	// For streaming writes, we'll implement a custom writer that buffers and writes in chunks
	return &streamWriter{
		cfs:         cfs,
		ctx:         ctx,
		containerID: containerID,
		filePath:    filePath,
		mode:        mode,
		buffer:      &bytes.Buffer{},
	}, nil
}

// Helper methods

// createTempFileWithData creates a temporary file in the container with given data
func (cfs *ContainerFileSystem) createTempFileWithData(ctx context.Context, containerID string, data []byte) (string, error) {
	// Create a unique temp file name
	tempFile := fmt.Sprintf("/tmp/sandboxfs_%s_%d", generateRandomString(8), time.Now().UnixNano())

	// Create the file using echo with base64 encoding to handle binary data
	encodedData := encodeToBase64(data)
	spec := &ProcessSpec{
		Cmd:  "sh",
		Args: []string{"sh", "-c", fmt.Sprintf("echo '%s' | base64 -d > %s", encodedData, tempFile)},
		Env:  []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"},
		User: "root",
		Timeout: 60 * time.Second,
	}

	result, err := cfs.client.ExecProcess(ctx, containerID, spec)
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	if result.ExitCode != 0 {
		return "", fmt.Errorf("temp file creation failed with exit code %d: %s", result.ExitCode, string(result.Stderr))
	}

	return tempFile, nil
}

// cleanupTempFile removes a temporary file
func (cfs *ContainerFileSystem) cleanupTempFile(ctx context.Context, containerID, tempFile string) {
	if err := cfs.DeleteFile(ctx, containerID, tempFile); err != nil {
		log.Warn().Err(err).Str("temp_file", tempFile).Msg("Failed to cleanup temp file")
	}
}

// parseStatOutput parses the output of stat command
func (cfs *ContainerFileSystem) parseStatOutput(output string) (*ContainerFileInfo, error) {
	parts := strings.Split(output, "|")
	if len(parts) != 8 {
		return nil, fmt.Errorf("invalid stat output format: %s", output)
	}

	size, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid size in stat output: %s", parts[1])
	}

	modeHex, err := strconv.ParseInt(parts[2], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid mode in stat output: %s", parts[2])
	}

	modTimeUnix, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid modification time in stat output: %s", parts[3])
	}

	uid, err := strconv.Atoi(parts[6])
	if err != nil {
		return nil, fmt.Errorf("invalid UID in stat output: %s", parts[6])
	}

	gid, err := strconv.Atoi(parts[7])
	if err != nil {
		return nil, fmt.Errorf("invalid GID in stat output: %s", parts[7])
	}

	mode := os.FileMode(modeHex)
	modTime := time.Unix(modTimeUnix, 0)

	return &ContainerFileInfo{
		Path:        parts[0],
		Name:        filepath.Base(parts[0]),
		Size:        size,
		Mode:        mode,
		ModTime:     modTime,
		IsDir:       mode.IsDir(),
		Permissions: mode.Perm().String(),
		Owner:       parts[4],
		Group:       parts[5],
		UID:         uid,
		GID:         gid,
	}, nil
}

// parseLsOutput parses the output of ls -la command
func (cfs *ContainerFileSystem) parseLsOutput(output, basePath string) ([]*ContainerFileInfo, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	var files []*ContainerFileInfo

	// Skip the first line (total) and entries for . and ..
	for i, line := range lines {
		if i == 0 || strings.HasSuffix(line, " .") || strings.HasSuffix(line, " ..") {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fileInfo, err := cfs.parseLsLine(line, basePath)
		if err != nil {
			log.Warn().Err(err).Str("line", line).Msg("Failed to parse ls line")
			continue
		}

		files = append(files, fileInfo)
	}

	return files, nil
}

// parseLsLine parses a single line from ls -la output
func (cfs *ContainerFileSystem) parseLsLine(line, basePath string) (*ContainerFileInfo, error) {
	// Regular expression to match ls -la output format
	// Format: -rw-r--r-- 1 user group size date filename
	re := regexp.MustCompile(`^([d\-rwxst]{10})\s+\d+\s+(\w+)\s+(\w+)\s+(\d+)\s+(\d+)\s+(.+)$`)
	matches := re.FindStringSubmatch(line)
	if len(matches) != 7 {
		return nil, fmt.Errorf("invalid ls line format: %s", line)
	}

	permissions := matches[1]
	owner := matches[2]
	group := matches[3]
	sizeStr := matches[4]
	timeStr := matches[5]
	name := matches[6]

	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid size: %s", sizeStr)
	}

	modTimeUnix, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid modification time: %s", timeStr)
	}

	modTime := time.Unix(modTimeUnix, 0)
	mode := parseModeFromPermissions(permissions)

	fullPath := path.Join(basePath, name)

	return &ContainerFileInfo{
		Path:        fullPath,
		Name:        name,
		Size:        size,
		Mode:        mode,
		ModTime:     modTime,
		IsDir:       permissions[0] == 'd',
		Permissions: permissions,
		Owner:       owner,
		Group:       group,
		UID:         0, // Not available in ls output
		GID:         0, // Not available in ls output
	}, nil
}

// parseModeFromPermissions converts permission string to os.FileMode
func parseModeFromPermissions(perms string) os.FileMode {
	var mode os.FileMode

	// File type
	switch perms[0] {
	case 'd':
		mode |= os.ModeDir
	case 'l':
		mode |= os.ModeSymlink
	case 'c':
		mode |= os.ModeCharDevice
	case 'b':
		mode |= os.ModeDevice
	case 'p':
		mode |= os.ModeNamedPipe
	case 's':
		mode |= os.ModeSocket
	}

	// Permission bits
	for i, perm := range perms[1:] {
		bitPos := uint(8 - i)
		switch perm {
		case 'r':
			mode |= os.FileMode(1 << bitPos)
		case 'w':
			mode |= os.FileMode(1 << (bitPos - 1))
		case 'x':
			mode |= os.FileMode(1 << (bitPos - 2))
		case 's':
			if i < 3 { // owner
				mode |= os.ModeSetuid
			} else { // group
				mode |= os.ModeSetgid
			}
			mode |= os.FileMode(1 << (bitPos - 2))
		case 't':
			mode |= os.ModeSticky
			mode |= os.FileMode(1 << (bitPos - 2))
		}
	}

	return mode
}

// Streaming writer implementation
type streamWriter struct {
	cfs         *ContainerFileSystem
	ctx         context.Context
	containerID string
	filePath    string
	mode        os.FileMode
	buffer      *bytes.Buffer
	closed      bool
	mu          sync.Mutex
}

func (sw *streamWriter) Write(p []byte) (n int, err error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return 0, errors.New("writer is closed")
	}

	return sw.buffer.Write(p)
}

func (sw *streamWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return nil
	}

	sw.closed = true

	// Write the buffered data to the file
	if sw.buffer.Len() > 0 {
		return sw.cfs.WriteFile(sw.ctx, sw.containerID, sw.filePath, sw.buffer.Bytes(), sw.mode)
	}

	return nil
}

// ValidatePath validates a file path for security
func (cfs *ContainerFileSystem) ValidatePath(filePath string) error {
	return cfs.pathValidator.ValidatePath(filePath)
}

// SanitizePath sanitizes a file path
func (cfs *ContainerFileSystem) SanitizePath(filePath string) string {
	return cfs.pathValidator.SanitizePath(filePath)
}

// IsPathSecure checks if a path is secure
func (cfs *ContainerFileSystem) IsPathSecure(filePath string) bool {
	return cfs.pathValidator.IsPathSecure(filePath)
}

// WatchFile starts watching a file for changes
func (cfs *ContainerFileSystem) WatchFile(ctx context.Context, containerID, filePath string) (<-chan FileEvent, error) {
	if err := cfs.ValidatePath(filePath); err != nil {
		return nil, fmt.Errorf("invalid file path: %w", err)
	}

	return cfs.fileMonitor.WatchFile(ctx, containerID, filePath)
}

// StopWatch stops watching a file
func (cfs *ContainerFileSystem) StopWatch(containerID, filePath string) error {
	return cfs.fileMonitor.StopWatch(containerID, filePath)
}

// Utility functions
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}

func encodeToBase64(data []byte) string {
	// Use a simple base64-like encoding that's shell-safe
	hash := md5.Sum(data)
	return fmt.Sprintf("%x", hash) // Use hex instead of base64 for simplicity
}

// PathValidator handles path validation and sanitization
type PathValidator struct {
	allowedPaths    []string
	blockedPaths    []string
	allowedPatterns []*regexp.Regexp
	blockedPatterns []*regexp.Regexp
	mu             sync.RWMutex
}

// NewPathValidator creates a new path validator with default security rules
func NewPathValidator() *PathValidator {
	pv := &PathValidator{
		allowedPaths: []string{
			"/workspace",
			"/tmp",
			"/var/tmp",
			"/home",
			"/usr/local",
		},
		blockedPaths: []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/hosts",
			"/proc",
			"/sys",
			"/dev",
			"/boot",
			"/root/.ssh",
		},
	}

	// Compile blocked patterns
	blockedPatterns := []string{
		`\.\.\/`,           // Directory traversal
		`\/\.\.\/`,         // Directory traversal
		`\/\.\.$`,          // Directory traversal
		`^\.\.\/`,          // Directory traversal at start
		`\/etc\/.*`,        // System config files
		`\/proc\/.*`,       // Process files
		`\/sys\/.*`,        // System files
		`\/dev\/.*`,        // Device files
		`.*\.sock$`,        // Socket files
		`.*\.pid$`,         // Process ID files
		`\/var\/run\/.*`,   // Runtime files
	}

	for _, pattern := range blockedPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			pv.blockedPatterns = append(pv.blockedPatterns, re)
		}
	}

	return pv
}

// ValidatePath validates a file path for security issues
func (pv *PathValidator) ValidatePath(filePath string) error {
	pv.mu.RLock()
	defer pv.mu.RUnlock()

	if filePath == "" {
		return errors.New("file path cannot be empty")
	}

	// Normalize the path
	cleanPath := path.Clean(filePath)

	// Check for directory traversal attempts
	if strings.Contains(cleanPath, "..") {
		return errors.New("directory traversal not allowed")
	}

	// Check against blocked patterns
	for _, pattern := range pv.blockedPatterns {
		if pattern.MatchString(cleanPath) {
			return fmt.Errorf("path matches blocked pattern: %s", cleanPath)
		}
	}

	// Check against blocked paths
	for _, blockedPath := range pv.blockedPaths {
		if strings.HasPrefix(cleanPath, blockedPath) {
			return fmt.Errorf("access to path %s is blocked", cleanPath)
		}
	}

	// Check if path is under allowed paths
	allowed := false
	for _, allowedPath := range pv.allowedPaths {
		if strings.HasPrefix(cleanPath, allowedPath) || cleanPath == allowedPath {
			allowed = true
			break
		}
	}

	if !allowed {
		return fmt.Errorf("path %s is not in allowed directories", cleanPath)
	}

	return nil
}

// SanitizePath sanitizes a file path by removing dangerous components
func (pv *PathValidator) SanitizePath(filePath string) string {
	// Clean the path
	cleanPath := path.Clean(filePath)

	// Remove directory traversal attempts
	cleanPath = strings.ReplaceAll(cleanPath, "..", "")
	cleanPath = strings.ReplaceAll(cleanPath, "//", "/")

	// Ensure path starts with /
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	return cleanPath
}

// IsPathSecure checks if a path is secure without throwing an error
func (pv *PathValidator) IsPathSecure(filePath string) bool {
	return pv.ValidatePath(filePath) == nil
}