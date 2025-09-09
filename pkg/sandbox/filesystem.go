package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// FileInfo represents file information
type FileInfo struct {
	Name        string      `json:"name"`
	Path        string      `json:"path"`
	Size        int64       `json:"size"`
	Mode        os.FileMode `json:"mode"`
	ModTime     time.Time   `json:"mod_time"`
	IsDir       bool        `json:"is_dir"`
	Permissions string      `json:"permissions"`
	Owner       string      `json:"owner"`
	Group       string      `json:"group"`
}

// FileSearchResult represents a search result
type FileSearchResult struct {
	File      FileInfo `json:"file"`
	LineNum   int      `json:"line_num"`
	Line      string   `json:"line"`
	Match     string   `json:"match"`
	Context   []string `json:"context"`
}

// FileSystemManager handles file system operations within sandboxes
type FileSystemManager struct {
	manager *Manager
}

// NewFileSystemManager creates a new file system manager
func NewFileSystemManager(manager *Manager) *FileSystemManager {
	return &FileSystemManager{
		manager: manager,
	}
}

// UploadFile uploads a file to the sandbox
func (fsm *FileSystemManager) UploadFile(ctx context.Context, sandboxID, containerPath string, data []byte, mode os.FileMode) error {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return fmt.Errorf("sandbox not found: %w", err)
	}

	if sandbox.Status != SandboxStatusRunning {
		return fmt.Errorf("sandbox is not running")
	}

	// For simplicity, we'll write to the host filesystem and rely on bind mounts
	// In a production system, you might want to use the container's file system directly
	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(hostPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write file
	if err := os.WriteFile(hostPath, data, mode); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("container_path", containerPath).
		Str("host_path", hostPath).
		Int("size", len(data)).
		Msg("File uploaded successfully")

	return nil
}

// DownloadFile downloads a file from the sandbox
func (fsm *FileSystemManager) DownloadFile(ctx context.Context, sandboxID, containerPath string) ([]byte, error) {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sandbox not found: %w", err)
	}

	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(hostPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", containerPath)
	}

	// Read file
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	log.Debug().
		Str("sandbox_id", sandboxID).
		Str("container_path", containerPath).
		Int("size", len(data)).
		Msg("File downloaded")

	return data, nil
}

// DeleteFile deletes a file from the sandbox
func (fsm *FileSystemManager) DeleteFile(ctx context.Context, sandboxID, containerPath string) error {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return fmt.Errorf("sandbox not found: %w", err)
	}

	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Check if file exists
	if _, err := os.Stat(hostPath); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", containerPath)
	}

	// Delete file
	if err := os.Remove(hostPath); err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("container_path", containerPath).
		Msg("File deleted successfully")

	return nil
}

// CreateDirectory creates a directory in the sandbox
func (fsm *FileSystemManager) CreateDirectory(ctx context.Context, sandboxID, containerPath string, mode os.FileMode) error {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return fmt.Errorf("sandbox not found: %w", err)
	}

	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Create directory
	if err := os.MkdirAll(hostPath, mode); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("container_path", containerPath).
		Str("mode", mode.String()).
		Msg("Directory created successfully")

	return nil
}

// DeleteDirectory deletes a directory from the sandbox
func (fsm *FileSystemManager) DeleteDirectory(ctx context.Context, sandboxID, containerPath string) error {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return fmt.Errorf("sandbox not found: %w", err)
	}

	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Check if directory exists
	if _, err := os.Stat(hostPath); os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", containerPath)
	}

	// Delete directory recursively
	if err := os.RemoveAll(hostPath); err != nil {
		return fmt.Errorf("failed to delete directory: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("container_path", containerPath).
		Msg("Directory deleted successfully")

	return nil
}

// StatFile gets file information
func (fsm *FileSystemManager) StatFile(ctx context.Context, sandboxID, containerPath string) (*FileInfo, error) {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sandbox not found: %w", err)
	}

	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Get file info
	info, err := os.Stat(hostPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	fileInfo := &FileInfo{
		Name:        info.Name(),
		Path:        containerPath,
		Size:        info.Size(),
		Mode:        info.Mode(),
		ModTime:     info.ModTime(),
		IsDir:       info.IsDir(),
		Permissions: info.Mode().Perm().String(),
		Owner:       "root", // Simplified
		Group:       "root", // Simplified
	}

	return fileInfo, nil
}

// ListFiles lists files in a directory
func (fsm *FileSystemManager) ListFiles(ctx context.Context, sandboxID, containerPath string) ([]*FileInfo, error) {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sandbox not found: %w", err)
	}

	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Check if directory exists
	if _, err := os.Stat(hostPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", containerPath)
	}

	// Read directory
	entries, err := os.ReadDir(hostPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var files []*FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			log.Warn().Err(err).Str("entry", entry.Name()).Msg("Failed to get entry info")
			continue
		}

		fileInfo := &FileInfo{
			Name:        info.Name(),
			Path:        filepath.Join(containerPath, info.Name()),
			Size:        info.Size(),
			Mode:        info.Mode(),
			ModTime:     info.ModTime(),
			IsDir:       info.IsDir(),
			Permissions: info.Mode().Perm().String(),
			Owner:       "root", // Simplified
			Group:       "root", // Simplified
		}

		files = append(files, fileInfo)
	}

	return files, nil
}

// FindInFiles searches for a pattern in files
func (fsm *FileSystemManager) FindInFiles(ctx context.Context, sandboxID, containerPath, pattern string) ([]*FileSearchResult, error) {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return nil, fmt.Errorf("sandbox not found: %w", err)
	}

	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Compile regex pattern
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	var results []*FileSearchResult

	// Walk through files
	err = filepath.Walk(hostPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking
		}

		// Skip directories and binary files
		if info.IsDir() || fsm.isBinaryFile(filePath) {
			return nil
		}

		// Convert back to container path
		relPath, err := filepath.Rel(hostPath, filePath)
		if err != nil {
			return nil
		}
		containerFilePath := filepath.Join(containerPath, relPath)

		// Search in file
		fileResults, err := fsm.searchInFile(filePath, containerFilePath, regex)
		if err != nil {
			log.Debug().Err(err).Str("file", filePath).Msg("Failed to search in file")
			return nil
		}

		results = append(results, fileResults...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return results, nil
}

// ReplaceInFiles replaces text in files
func (fsm *FileSystemManager) ReplaceInFiles(ctx context.Context, sandboxID, containerPath, pattern, newString string) (int, error) {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return 0, fmt.Errorf("sandbox not found: %w", err)
	}

	hostPath, err := fsm.containerPathToHostPath(sandbox, containerPath)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve container path: %w", err)
	}

	// Compile regex pattern
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return 0, fmt.Errorf("invalid regex pattern: %w", err)
	}

	replacementCount := 0

	// Walk through files
	err = filepath.Walk(hostPath, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Continue walking
		}

		// Skip directories and binary files
		if info.IsDir() || fsm.isBinaryFile(filePath) {
			return nil
		}

		// Read file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			log.Debug().Err(err).Str("file", filePath).Msg("Failed to read file")
			return nil
		}

		// Perform replacement
		originalContent := string(content)
		newContent := regex.ReplaceAllString(originalContent, newString)

		// Check if content changed
		if originalContent != newContent {
			// Write back to file
			if err := os.WriteFile(filePath, []byte(newContent), info.Mode()); err != nil {
				log.Warn().Err(err).Str("file", filePath).Msg("Failed to write file after replacement")
				return nil
			}

			// Count replacements
			matches := regex.FindAllString(originalContent, -1)
			replacementCount += len(matches)

			log.Debug().
				Str("file", filePath).
				Int("replacements", len(matches)).
				Msg("Performed text replacement")
		}

		return nil
	})

	if err != nil {
		return 0, fmt.Errorf("failed to walk directory: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("container_path", containerPath).
		Int("total_replacements", replacementCount).
		Msg("Text replacement completed")

	return replacementCount, nil
}

// CopyFile copies a file within the sandbox
func (fsm *FileSystemManager) CopyFile(ctx context.Context, sandboxID, srcPath, dstPath string) error {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return fmt.Errorf("sandbox not found: %w", err)
	}

	srcHostPath, err := fsm.containerPathToHostPath(sandbox, srcPath)
	if err != nil {
		return fmt.Errorf("failed to resolve source path: %w", err)
	}

	dstHostPath, err := fsm.containerPathToHostPath(sandbox, dstPath)
	if err != nil {
		return fmt.Errorf("failed to resolve destination path: %w", err)
	}

	// Read source file
	data, err := os.ReadFile(srcHostPath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	// Get source file info for mode
	srcInfo, err := os.Stat(srcHostPath)
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	// Ensure destination directory exists
	dstDir := filepath.Dir(dstHostPath)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Write destination file
	if err := os.WriteFile(dstHostPath, data, srcInfo.Mode()); err != nil {
		return fmt.Errorf("failed to write destination file: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("src_path", srcPath).
		Str("dst_path", dstPath).
		Msg("File copied successfully")

	return nil
}

// MoveFile moves a file within the sandbox
func (fsm *FileSystemManager) MoveFile(ctx context.Context, sandboxID, srcPath, dstPath string) error {
	sandbox, err := fsm.manager.GetSandbox(sandboxID)
	if err != nil {
		return fmt.Errorf("sandbox not found: %w", err)
	}

	srcHostPath, err := fsm.containerPathToHostPath(sandbox, srcPath)
	if err != nil {
		return fmt.Errorf("failed to resolve source path: %w", err)
	}

	dstHostPath, err := fsm.containerPathToHostPath(sandbox, dstPath)
	if err != nil {
		return fmt.Errorf("failed to resolve destination path: %w", err)
	}

	// Ensure destination directory exists
	dstDir := filepath.Dir(dstHostPath)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Move file
	if err := os.Rename(srcHostPath, dstHostPath); err != nil {
		return fmt.Errorf("failed to move file: %w", err)
	}

	log.Info().
		Str("sandbox_id", sandboxID).
		Str("src_path", srcPath).
		Str("dst_path", dstPath).
		Msg("File moved successfully")

	return nil
}

// Helper methods

// containerPathToHostPath converts a container path to the corresponding host path
func (fsm *FileSystemManager) containerPathToHostPath(sandbox *Sandbox, containerPath string) (string, error) {
	// Handle absolute paths that start with /workspace
	if strings.HasPrefix(containerPath, "/workspace") {
		relPath := strings.TrimPrefix(containerPath, "/workspace")
		if relPath == "" {
			relPath = "/"
		}
		return filepath.Join(sandbox.WorkingDir, relPath), nil
	}

	// Handle relative paths
	if !filepath.IsAbs(containerPath) {
		return filepath.Join(sandbox.WorkingDir, containerPath), nil
	}

	// For other absolute paths, we can't easily map them without more container info
	return "", fmt.Errorf("cannot map container path to host path: %s", containerPath)
}

// isBinaryFile checks if a file is likely a binary file
func (fsm *FileSystemManager) isBinaryFile(filePath string) bool {
	// Simple heuristic: check file extension
	ext := strings.ToLower(filepath.Ext(filePath))
	binaryExts := []string{
		".bin", ".exe", ".dll", ".so", ".dylib",
		".jpg", ".jpeg", ".png", ".gif", ".bmp",
		".mp3", ".mp4", ".avi", ".mov", ".zip",
		".tar", ".gz", ".7z", ".rar", ".pdf",
	}

	for _, binaryExt := range binaryExts {
		if ext == binaryExt {
			return true
		}
	}

	return false
}

// searchInFile searches for a pattern in a single file
func (fsm *FileSystemManager) searchInFile(filePath, containerPath string, regex *regexp.Regexp) ([]*FileSearchResult, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var results []*FileSearchResult

	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	fileInfo := FileInfo{
		Name:        info.Name(),
		Path:        containerPath,
		Size:        info.Size(),
		Mode:        info.Mode(),
		ModTime:     info.ModTime(),
		IsDir:       false,
		Permissions: info.Mode().Perm().String(),
		Owner:       "root",
		Group:       "root",
	}

	for i, line := range lines {
		if regex.MatchString(line) {
			// Find all matches in the line
			matches := regex.FindAllString(line, -1)
			for _, match := range matches {
				result := &FileSearchResult{
					File:    fileInfo,
					LineNum: i + 1,
					Line:    line,
					Match:   match,
				}

				// Add context lines (2 before and 2 after)
				contextStart := max(0, i-2)
				contextEnd := min(len(lines), i+3)
				result.Context = lines[contextStart:contextEnd]

				results = append(results, result)
			}
		}
	}

	return results, nil
}

// Utility functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}