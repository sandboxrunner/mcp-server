package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
)

// UploadFileTool uploads files to a sandbox using container filesystem
type UploadFileTool struct {
	*BaseTool
	manager       *sandbox.Manager
	containerFS   runtime.ContainerFS
	maxFileSize   int64
	quotaManager  *QuotaManager
	auditLogger   *FileOperationAuditor
	backupManager *BackupManager
}

// NewUploadFileTool creates a new upload file tool with container integration
func NewUploadFileTool(manager *sandbox.Manager, containerFS runtime.ContainerFS) *UploadFileTool {
	quotaManager := NewQuotaManager()
	auditLogger := NewFileOperationAuditor()
	backupManager := NewBackupManager(containerFS)

	return &UploadFileTool{
		BaseTool: NewBaseTool(
			"upload_file",
			"Uploads a file to the sandbox environment using secure container filesystem",
			EnhancedFileContentSchema(),
		),
		manager:       manager,
		containerFS:   containerFS,
		maxFileSize:   10 * 1024 * 1024, // 10MB default
		quotaManager:  quotaManager,
		auditLogger:   auditLogger,
		backupManager: backupManager,
	}
}

// Execute uploads a file to a sandbox
func (t *UploadFileTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	path, err := validator.ExtractString(params, "path", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	content, err := validator.ExtractString(params, "content", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	encoding, _ := validator.ExtractString(params, "encoding", false, "utf8")

	// Get sandbox
	sb, err := t.manager.GetSandbox(sandboxID)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox not found: %v", err),
			IsError: true,
		}, nil
	}

	// Decode content based on encoding
	var fileContent []byte
	switch encoding {
	case "base64":
		fileContent, err = base64.StdEncoding.DecodeString(content)
		if err != nil {
			return &ToolResult{
				Text:    fmt.Sprintf("Failed to decode base64 content: %v", err),
				IsError: true,
			}, nil
		}
	case "utf8":
		fileContent = []byte(content)
	default:
		return &ToolResult{
			Text:    fmt.Sprintf("Unsupported encoding: %s", encoding),
			IsError: true,
		}, nil
	}

	// Construct full file path in sandbox workspace
	fullPath := filepath.Join(sb.WorkingDir, strings.TrimPrefix(path, "/"))

	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to create directory: %v", err),
			IsError: true,
		}, nil
	}

	// Write file
	if err := os.WriteFile(fullPath, fileContent, 0644); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to write file: %v", err),
			IsError: true,
		}, nil
	}

	// Get file info
	fileInfo, _ := os.Stat(fullPath)

	result := fmt.Sprintf("File uploaded successfully:\nPath: %s\nSize: %d bytes\nEncoding: %s",
		path, len(fileContent), encoding)

	return &ToolResult{
		Text:    result,
		IsError: false,
		Metadata: map[string]interface{}{
			"sandbox_id": sandboxID,
			"path":       path,
			"size":       len(fileContent),
			"encoding":   encoding,
			"modified":   fileInfo.ModTime(),
		},
	}, nil
}

// DownloadFileTool downloads files from a sandbox
type DownloadFileTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewDownloadFileTool creates a new download file tool
func NewDownloadFileTool(manager *sandbox.Manager) *DownloadFileTool {
	return &DownloadFileTool{
		BaseTool: NewBaseTool(
			"download_file",
			"Downloads a file from the sandbox environment",
			map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandbox_id": map[string]interface{}{
						"type":        "string",
						"description": "The unique identifier of the sandbox",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "The file path to download",
					},
					"encoding": map[string]interface{}{
						"type":        "string",
						"description": "Content encoding (base64 or utf8)",
						"enum":        []string{"base64", "utf8"},
						"default":     "utf8",
					},
				},
				"required": []string{"sandbox_id", "path"},
			},
		),
		manager: manager,
	}
}

// Execute downloads a file from a sandbox
func (t *DownloadFileTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	path, err := validator.ExtractString(params, "path", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	encoding, _ := validator.ExtractString(params, "encoding", false, "utf8")

	// Get sandbox
	sb, err := t.manager.GetSandbox(sandboxID)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox not found: %v", err),
			IsError: true,
		}, nil
	}

	// Construct full file path
	fullPath := filepath.Join(sb.WorkingDir, strings.TrimPrefix(path, "/"))

	// Check if file exists
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &ToolResult{
				Text:    fmt.Sprintf("File not found: %s", path),
				IsError: true,
			}, nil
		}
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to access file: %v", err),
			IsError: true,
		}, nil
	}

	if fileInfo.IsDir() {
		return &ToolResult{
			Text:    fmt.Sprintf("Path is a directory, not a file: %s", path),
			IsError: true,
		}, nil
	}

	// Read file
	fileContent, err := os.ReadFile(fullPath)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to read file: %v", err),
			IsError: true,
		}, nil
	}

	// Encode content based on requested encoding
	var encodedContent string
	switch encoding {
	case "base64":
		encodedContent = base64.StdEncoding.EncodeToString(fileContent)
	case "utf8":
		encodedContent = string(fileContent)
	default:
		return &ToolResult{
			Text:    fmt.Sprintf("Unsupported encoding: %s", encoding),
			IsError: true,
		}, nil
	}

	result := fmt.Sprintf("File downloaded successfully:\nPath: %s\nSize: %d bytes\nEncoding: %s\nModified: %s\n\nContent:\n%s",
		path, len(fileContent), encoding, fileInfo.ModTime().Format(time.RFC3339), encodedContent)

	return &ToolResult{
		Text:    result,
		IsError: false,
		Metadata: map[string]interface{}{
			"sandbox_id": sandboxID,
			"path":       path,
			"size":       len(fileContent),
			"encoding":   encoding,
			"modified":   fileInfo.ModTime(),
			"content":    encodedContent,
		},
	}, nil
}

// ListFilesTool lists directory contents in a sandbox
type ListFilesTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewListFilesTool creates a new list files tool
func NewListFilesTool(manager *sandbox.Manager) *ListFilesTool {
	return &ListFilesTool{
		BaseTool: NewBaseTool(
			"list_files",
			"Lists files and directories in the sandbox environment",
			map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandbox_id": map[string]interface{}{
						"type":        "string",
						"description": "The unique identifier of the sandbox",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Directory path to list (defaults to /workspace)",
						"default":     "/workspace",
					},
					"recursive": map[string]interface{}{
						"type":        "boolean",
						"description": "List files recursively",
						"default":     false,
					},
				},
				"required": []string{"sandbox_id"},
			},
		),
		manager: manager,
	}
}

// Execute lists files in a sandbox directory
func (t *ListFilesTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	path, _ := validator.ExtractString(params, "path", false, "/workspace")
	recursive, _ := validator.ExtractBool(params, "recursive", false, false)

	// Get sandbox
	sb, err := t.manager.GetSandbox(sandboxID)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox not found: %v", err),
			IsError: true,
		}, nil
	}

	// Construct full directory path
	fullPath := filepath.Join(sb.WorkingDir, strings.TrimPrefix(path, "/"))

	// Check if directory exists
	dirInfo, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &ToolResult{
				Text:    fmt.Sprintf("Directory not found: %s", path),
				IsError: true,
			}, nil
		}
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to access directory: %v", err),
			IsError: true,
		}, nil
	}

	if !dirInfo.IsDir() {
		return &ToolResult{
			Text:    fmt.Sprintf("Path is not a directory: %s", path),
			IsError: true,
		}, nil
	}

	var files []map[string]interface{}

	if recursive {
		err = filepath.Walk(fullPath, func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip the root directory itself
			if filePath == fullPath {
				return nil
			}

			relPath, _ := filepath.Rel(fullPath, filePath)
			files = append(files, map[string]interface{}{
				"name":     info.Name(),
				"path":     filepath.Join(path, relPath),
				"size":     info.Size(),
				"is_dir":   info.IsDir(),
				"mode":     info.Mode().String(),
				"modified": info.ModTime().Format(time.RFC3339),
			})

			return nil
		})
	} else {
		entries, err := os.ReadDir(fullPath)
		if err == nil {
			for _, entry := range entries {
				info, err := entry.Info()
				if err != nil {
					continue
				}

				files = append(files, map[string]interface{}{
					"name":     info.Name(),
					"path":     filepath.Join(path, info.Name()),
					"size":     info.Size(),
					"is_dir":   info.IsDir(),
					"mode":     info.Mode().String(),
					"modified": info.ModTime().Format(time.RFC3339),
				})
			}
		}
	}

	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to list directory: %v", err),
			IsError: true,
		}, nil
	}

	filesJSON, _ := json.MarshalIndent(files, "", "  ")

	result := fmt.Sprintf("Directory listing for %s (%d items):\n%s",
		path, len(files), string(filesJSON))

	return &ToolResult{
		Text:    result,
		IsError: false,
		Metadata: map[string]interface{}{
			"sandbox_id": sandboxID,
			"path":       path,
			"recursive":  recursive,
			"count":      len(files),
			"files":      files,
		},
	}, nil
}

// ReadFileTool reads file contents from a sandbox
type ReadFileTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewReadFileTool creates a new read file tool
func NewReadFileTool(manager *sandbox.Manager) *ReadFileTool {
	return &ReadFileTool{
		BaseTool: NewBaseTool(
			"read_file",
			"Reads the contents of a file in the sandbox environment",
			map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"sandbox_id": map[string]interface{}{
						"type":        "string",
						"description": "The unique identifier of the sandbox",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "The file path to read",
					},
					"encoding": map[string]interface{}{
						"type":        "string",
						"description": "Content encoding (base64 or utf8)",
						"enum":        []string{"base64", "utf8"},
						"default":     "utf8",
					},
					"max_size": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum file size to read in bytes",
						"default":     1048576, // 1MB
					},
				},
				"required": []string{"sandbox_id", "path"},
			},
		),
		manager: manager,
	}
}

// Execute reads a file from a sandbox
func (t *ReadFileTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	path, err := validator.ExtractString(params, "path", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	encoding, _ := validator.ExtractString(params, "encoding", false, "utf8")
	maxSize, _ := validator.ExtractInt(params, "max_size", false, 1048576)

	// Get sandbox
	sb, err := t.manager.GetSandbox(sandboxID)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox not found: %v", err),
			IsError: true,
		}, nil
	}

	// Construct full file path
	fullPath := filepath.Join(sb.WorkingDir, strings.TrimPrefix(path, "/"))

	// Check if file exists and get info
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &ToolResult{
				Text:    fmt.Sprintf("File not found: %s", path),
				IsError: true,
			}, nil
		}
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to access file: %v", err),
			IsError: true,
		}, nil
	}

	if fileInfo.IsDir() {
		return &ToolResult{
			Text:    fmt.Sprintf("Path is a directory, not a file: %s", path),
			IsError: true,
		}, nil
	}

	// Check file size
	if fileInfo.Size() > int64(maxSize) {
		return &ToolResult{
			Text:    fmt.Sprintf("File too large: %d bytes (max: %d bytes)", fileInfo.Size(), maxSize),
			IsError: true,
		}, nil
	}

	// Read file
	fileContent, err := os.ReadFile(fullPath)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to read file: %v", err),
			IsError: true,
		}, nil
	}

	// Encode content based on requested encoding
	var encodedContent string
	switch encoding {
	case "base64":
		encodedContent = base64.StdEncoding.EncodeToString(fileContent)
	case "utf8":
		encodedContent = string(fileContent)
	default:
		return &ToolResult{
			Text:    fmt.Sprintf("Unsupported encoding: %s", encoding),
			IsError: true,
		}, nil
	}

	result := fmt.Sprintf("File: %s\nSize: %d bytes\nEncoding: %s\nModified: %s\n\nContent:\n%s",
		path, len(fileContent), encoding, fileInfo.ModTime().Format(time.RFC3339), encodedContent)

	return &ToolResult{
		Text:    result,
		IsError: false,
		Metadata: map[string]interface{}{
			"sandbox_id": sandboxID,
			"path":       path,
			"size":       len(fileContent),
			"encoding":   encoding,
			"modified":   fileInfo.ModTime(),
		},
	}, nil
}

// WriteFileTool writes file contents to a sandbox
type WriteFileTool struct {
	*BaseTool
	manager *sandbox.Manager
}

// NewWriteFileTool creates a new write file tool
func NewWriteFileTool(manager *sandbox.Manager) *WriteFileTool {
	return &WriteFileTool{
		BaseTool: NewBaseTool(
			"write_file",
			"Writes content to a file in the sandbox environment",
			FileContentSchema(),
		),
		manager: manager,
	}
}

// Execute writes content to a file in a sandbox
func (t *WriteFileTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	validator := NewValidator()

	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	path, err := validator.ExtractString(params, "path", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	content, err := validator.ExtractString(params, "content", true, "")
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Invalid parameters: %v", err),
			IsError: true,
		}, nil
	}

	encoding, _ := validator.ExtractString(params, "encoding", false, "utf8")

	// Get sandbox
	sb, err := t.manager.GetSandbox(sandboxID)
	if err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Sandbox not found: %v", err),
			IsError: true,
		}, nil
	}

	// Decode content based on encoding
	var fileContent []byte
	switch encoding {
	case "base64":
		fileContent, err = base64.StdEncoding.DecodeString(content)
		if err != nil {
			return &ToolResult{
				Text:    fmt.Sprintf("Failed to decode base64 content: %v", err),
				IsError: true,
			}, nil
		}
	case "utf8":
		fileContent = []byte(content)
	default:
		return &ToolResult{
			Text:    fmt.Sprintf("Unsupported encoding: %s", encoding),
			IsError: true,
		}, nil
	}

	// Construct full file path in sandbox workspace
	fullPath := filepath.Join(sb.WorkingDir, strings.TrimPrefix(path, "/"))

	// Create directory if it doesn't exist
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to create directory: %v", err),
			IsError: true,
		}, nil
	}

	// Write file
	if err := os.WriteFile(fullPath, fileContent, 0644); err != nil {
		return &ToolResult{
			Text:    fmt.Sprintf("Failed to write file: %v", err),
			IsError: true,
		}, nil
	}

	// Get updated file info
	fileInfo, _ := os.Stat(fullPath)

	result := fmt.Sprintf("File written successfully:\nPath: %s\nSize: %d bytes\nEncoding: %s\nModified: %s",
		path, len(fileContent), encoding, fileInfo.ModTime().Format(time.RFC3339))

	return &ToolResult{
		Text:    result,
		IsError: false,
		Metadata: map[string]interface{}{
			"sandbox_id": sandboxID,
			"path":       path,
			"size":       len(fileContent),
			"encoding":   encoding,
			"modified":   fileInfo.ModTime(),
		},
	}, nil
}
