package tools

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"path"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
)

// EnhancedUploadFileTool uploads files to a sandbox using container filesystem
type EnhancedUploadFileTool struct {
	*BaseTool
	manager       sandbox.SandboxManagerInterface
	containerFS   runtime.ContainerFS
	maxFileSize   int64
	quotaManager  *QuotaManager
	auditLogger   *FileOperationAuditor
	backupManager *BackupManager
}

// NewEnhancedUploadFileTool creates a new enhanced upload file tool with container integration
func NewEnhancedUploadFileTool(manager sandbox.SandboxManagerInterface, containerFS runtime.ContainerFS) *EnhancedUploadFileTool {
	quotaManager := NewQuotaManager()
	auditLogger := NewFileOperationAuditor()
	backupManager := NewBackupManager(containerFS)

	return &EnhancedUploadFileTool{
		BaseTool: NewBaseTool(
			"enhanced_upload_file",
			"Uploads a file to the sandbox environment using secure container filesystem with backup and audit",
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

// Execute uploads a file to a sandbox with enhanced security and features
func (t *EnhancedUploadFileTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	startTime := time.Now()
	validator := NewValidator()

	// Extract parameters
	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return t.createErrorResult("Invalid sandbox_id parameter", err)
	}

	filePath, err := validator.ExtractString(params, "path", true, "")
	if err != nil {
		return t.createErrorResult("Invalid path parameter", err)
	}

	content, err := validator.ExtractString(params, "content", true, "")
	if err != nil {
		return t.createErrorResult("Invalid content parameter", err)
	}

	encoding, _ := validator.ExtractString(params, "encoding", false, "utf8")
	createBackup, _ := validator.ExtractBool(params, "create_backup", false, true)
	forceOverwrite, _ := validator.ExtractBool(params, "force_overwrite", false, false)

	// Get sandbox and validate
	sb, err := t.manager.GetSandbox(sandboxID)
	if err != nil {
		return t.createAuditedErrorResult(sandboxID, filePath, "get_sandbox", "Sandbox not found", err, startTime)
	}

	// Validate container is running
	if sb.Status != sandbox.SandboxStatusRunning {
		return t.createAuditedErrorResult(sandboxID, filePath, "validate_status",
			fmt.Sprintf("Sandbox is not running: %s", sb.Status), nil, startTime)
	}

	// Validate and sanitize path
	filePath = t.containerFS.SanitizePath(filePath)
	if err := t.containerFS.ValidatePath(filePath); err != nil {
		return t.createAuditedErrorResult(sandboxID, filePath, "validate_path", "Invalid file path", err, startTime)
	}

	// Decode content based on encoding
	var fileContent []byte
	switch encoding {
	case "base64":
		fileContent, err = base64.StdEncoding.DecodeString(content)
		if err != nil {
			return t.createAuditedErrorResult(sandboxID, filePath, "decode_content", "Failed to decode base64 content", err, startTime)
		}
	case "utf8":
		fileContent = []byte(content)
	default:
		return t.createAuditedErrorResult(sandboxID, filePath, "decode_content",
			fmt.Sprintf("Unsupported encoding: %s", encoding), nil, startTime)
	}

	// Check file size limits
	if int64(len(fileContent)) > t.maxFileSize {
		return t.createAuditedErrorResult(sandboxID, filePath, "size_check",
			fmt.Sprintf("File too large: %d bytes (max: %d bytes)", len(fileContent), t.maxFileSize), nil, startTime)
	}

	// Check quota before upload
	if err := t.quotaManager.CheckQuota(sandboxID, int64(len(fileContent))); err != nil {
		return t.createAuditedErrorResult(sandboxID, filePath, "quota_check", "Quota exceeded", err, startTime)
	}

	// Check if file exists and handle overwrite/backup
	existingFile, err := t.containerFS.StatFile(ctx, sb.ContainerID, filePath)
	fileExists := (err == nil && !existingFile.IsDir)

	if fileExists && !forceOverwrite {
		// Check if user wants to proceed with overwrite
		log.Warn().
			Str("sandbox_id", sandboxID).
			Str("file_path", filePath).
			Msg("File exists, overwrite not forced")
	}

	// Create backup if requested and file exists
	var backupCreated bool
	if fileExists && createBackup {
		if err := t.backupManager.CreateBackup(ctx, sb.ContainerID, filePath); err != nil {
			log.Warn().Err(err).Str("file_path", filePath).Msg("Failed to create backup before upload")
		} else {
			backupCreated = true
		}
	}

	// Create parent directories if needed
	parentDir := path.Dir(filePath)
	if parentDir != "/" && parentDir != "." {
		if err := t.containerFS.MakeDir(ctx, sb.ContainerID, parentDir, 0755); err != nil {
			// Check if directory already exists
			if _, statErr := t.containerFS.StatFile(ctx, sb.ContainerID, parentDir); statErr != nil {
				return t.createAuditedErrorResult(sandboxID, filePath, "create_dir",
					"Failed to create parent directory", err, startTime)
			}
		}
	}

	// Write file using container filesystem with atomic operation
	if err := t.containerFS.WriteFileAtomic(ctx, sb.ContainerID, filePath, fileContent, 0644); err != nil {
		return t.createAuditedErrorResult(sandboxID, filePath, "write_file", "Failed to write file", err, startTime)
	}

	// Update quota usage
	t.quotaManager.UpdateUsage(sandboxID, int64(len(fileContent)))

	// Calculate checksum for verification
	checksum := fmt.Sprintf("%x", md5.Sum(fileContent))

	// Get updated file info from container
	fileInfo, err := t.containerFS.StatFile(ctx, sb.ContainerID, filePath)
	if err != nil {
		log.Warn().Err(err).Str("file_path", filePath).Msg("Failed to get file info after write")
	}

	// Create successful audit entry
	duration := time.Since(startTime)
	auditEntry := &FileOperationAudit{
		Operation:   "enhanced_upload_file",
		SandboxID:   sandboxID,
		ContainerID: sb.ContainerID,
		Path:        filePath,
		Size:        int64(len(fileContent)),
		Encoding:    encoding,
		Timestamp:   time.Now(),
		Success:     true,
		Checksum:    checksum,
		Duration:    duration,
		Metadata: map[string]interface{}{
			"backup_created":  backupCreated,
			"file_existed":    fileExists,
			"force_overwrite": forceOverwrite,
		},
	}
	t.auditLogger.LogOperation(auditEntry)

	// Create success response
	result := fmt.Sprintf(`File uploaded successfully:
Path: %s
Size: %d bytes
Encoding: %s
Checksum: %s
Container: %s
Backup Created: %v
Duration: %v`,
		filePath, len(fileContent), encoding, checksum, sb.ContainerID, backupCreated, duration)

	metadata := map[string]interface{}{
		"sandbox_id":     sandboxID,
		"container_id":   sb.ContainerID,
		"path":           filePath,
		"size":           len(fileContent),
		"encoding":       encoding,
		"checksum":       checksum,
		"backup_created": backupCreated,
		"file_existed":   fileExists,
		"quota_used":     t.quotaManager.GetUsage(sandboxID),
		"duration_ms":    duration.Milliseconds(),
	}

	if fileInfo != nil {
		metadata["modified"] = fileInfo.ModTime
		metadata["permissions"] = fileInfo.Permissions
		metadata["owner"] = fileInfo.Owner
		metadata["group"] = fileInfo.Group
	}

	return &ToolResult{
		Text:     result,
		IsError:  false,
		Metadata: metadata,
	}, nil
}

// EnhancedDownloadFileTool downloads files from a sandbox using container filesystem
type EnhancedDownloadFileTool struct {
	*BaseTool
	manager     sandbox.SandboxManagerInterface
	containerFS runtime.ContainerFS
	maxFileSize int64
	auditLogger *FileOperationAuditor
}

// NewEnhancedDownloadFileTool creates a new enhanced download file tool
func NewEnhancedDownloadFileTool(manager sandbox.SandboxManagerInterface, containerFS runtime.ContainerFS) *EnhancedDownloadFileTool {
	auditLogger := NewFileOperationAuditor()

	return &EnhancedDownloadFileTool{
		BaseTool: NewBaseTool(
			"enhanced_download_file",
			"Downloads a file from the sandbox environment using secure container filesystem",
			EnhancedFileReadSchema(),
		),
		manager:     manager,
		containerFS: containerFS,
		maxFileSize: 100 * 1024 * 1024, // 100MB default
		auditLogger: auditLogger,
	}
}

// Execute downloads a file from a sandbox with enhanced security features
func (t *EnhancedDownloadFileTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	startTime := time.Now()
	validator := NewValidator()

	// Extract parameters
	sandboxID, err := validator.ExtractString(params, "sandbox_id", true, "")
	if err != nil {
		return t.createErrorResult("Invalid sandbox_id parameter", err)
	}

	filePath, err := validator.ExtractString(params, "path", true, "")
	if err != nil {
		return t.createErrorResult("Invalid path parameter", err)
	}

	encoding, _ := validator.ExtractString(params, "encoding", false, "utf8")
	maxSize, _ := validator.ExtractInt(params, "max_size", false, 1048576) // 1MB default
	offset, _ := validator.ExtractInt(params, "offset", false, 0)
	length, _ := validator.ExtractInt(params, "length", false, 0)

	// Get sandbox and validate
	sb, err := t.manager.GetSandbox(sandboxID)
	if err != nil {
		return t.createAuditedErrorResult(sandboxID, filePath, "get_sandbox", "Sandbox not found", err, startTime)
	}

	// Validate container is running
	if sb.Status != sandbox.SandboxStatusRunning {
		return t.createAuditedErrorResult(sandboxID, filePath, "validate_status",
			fmt.Sprintf("Sandbox is not running: %s", sb.Status), nil, startTime)
	}

	// Validate and sanitize path
	filePath = t.containerFS.SanitizePath(filePath)
	if err := t.containerFS.ValidatePath(filePath); err != nil {
		return t.createAuditedErrorResult(sandboxID, filePath, "validate_path", "Invalid file path", err, startTime)
	}

	// Get file info from container
	fileInfo, err := t.containerFS.StatFile(ctx, sb.ContainerID, filePath)
	if err != nil {
		return t.createAuditedErrorResult(sandboxID, filePath, "stat_file", "File not found", err, startTime)
	}

	if fileInfo.IsDir {
		return t.createAuditedErrorResult(sandboxID, filePath, "file_type",
			"Path is a directory, not a file", nil, startTime)
	}

	// Check file size limits
	if fileInfo.Size > int64(maxSize) {
		return t.createAuditedErrorResult(sandboxID, filePath, "size_check",
			fmt.Sprintf("File too large: %d bytes (max: %d bytes)", fileInfo.Size, maxSize), nil, startTime)
	}

	// Read file content from container
	var fileContent []byte
	if length > 0 && offset > 0 {
		// Use streaming read for partial content
		reader, err := t.containerFS.StreamReadFile(ctx, sb.ContainerID, filePath, int64(offset), int64(length))
		if err != nil {
			return t.createAuditedErrorResult(sandboxID, filePath, "stream_read",
				"Failed to create stream reader", err, startTime)
		}
		defer reader.Close()

		// Read content from stream
		buffer := make([]byte, length)
		n, err := reader.Read(buffer)
		if err != nil && err.Error() != "EOF" {
			return t.createAuditedErrorResult(sandboxID, filePath, "read_stream",
				"Failed to read from stream", err, startTime)
		}
		fileContent = buffer[:n]
	} else {
		// Read entire file
		fileContent, err = t.containerFS.ReadFile(ctx, sb.ContainerID, filePath)
		if err != nil {
			return t.createAuditedErrorResult(sandboxID, filePath, "read_file",
				"Failed to read file", err, startTime)
		}
	}

	// Encode content based on requested encoding
	var encodedContent string
	switch encoding {
	case "base64":
		encodedContent = base64.StdEncoding.EncodeToString(fileContent)
	case "utf8":
		encodedContent = string(fileContent)
	default:
		return t.createAuditedErrorResult(sandboxID, filePath, "encode_content",
			fmt.Sprintf("Unsupported encoding: %s", encoding), nil, startTime)
	}

	// Calculate checksum
	checksum := fmt.Sprintf("%x", md5.Sum(fileContent))
	duration := time.Since(startTime)

	// Create successful audit entry
	auditEntry := &FileOperationAudit{
		Operation:   "enhanced_download_file",
		SandboxID:   sandboxID,
		ContainerID: sb.ContainerID,
		Path:        filePath,
		Size:        int64(len(fileContent)),
		Encoding:    encoding,
		Timestamp:   time.Now(),
		Success:     true,
		Checksum:    checksum,
		Duration:    duration,
		Metadata: map[string]interface{}{
			"offset":    offset,
			"length":    length,
			"max_size":  maxSize,
			"file_size": fileInfo.Size,
		},
	}
	t.auditLogger.LogOperation(auditEntry)

	result := fmt.Sprintf(`File downloaded successfully:
Path: %s
Size: %d bytes
Encoding: %s
Checksum: %s
Modified: %s
Duration: %v

Content:
%s`, filePath, len(fileContent), encoding, checksum, fileInfo.ModTime.Format(time.RFC3339),
		duration, encodedContent)

	return &ToolResult{
		Text:    result,
		IsError: false,
		Metadata: map[string]interface{}{
			"sandbox_id":   sandboxID,
			"container_id": sb.ContainerID,
			"path":         filePath,
			"size":         len(fileContent),
			"encoding":     encoding,
			"checksum":     checksum,
			"modified":     fileInfo.ModTime,
			"permissions":  fileInfo.Permissions,
			"owner":        fileInfo.Owner,
			"group":        fileInfo.Group,
			"content":      encodedContent,
			"duration_ms":  duration.Milliseconds(),
		},
	}, nil
}

// Helper methods

func (t *EnhancedUploadFileTool) createErrorResult(message string, err error) (*ToolResult, error) {
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}
	return &ToolResult{
		Text:    errorMsg,
		IsError: true,
	}, nil
}

func (t *EnhancedUploadFileTool) createAuditedErrorResult(sandboxID, filePath, operation, message string, err error, startTime time.Time) (*ToolResult, error) {
	duration := time.Since(startTime)

	// Create audit entry for failed operation
	auditEntry := &FileOperationAudit{
		Operation: "enhanced_upload_file",
		SandboxID: sandboxID,
		Path:      filePath,
		Timestamp: time.Now(),
		Success:   false,
		Error:     message,
		Duration:  duration,
		Metadata: map[string]interface{}{
			"failed_operation": operation,
		},
	}
	if err != nil {
		auditEntry.Error = fmt.Sprintf("%s: %v", message, err)
	}
	t.auditLogger.LogOperation(auditEntry)

	return t.createErrorResult(message, err)
}

func (t *EnhancedDownloadFileTool) createErrorResult(message string, err error) (*ToolResult, error) {
	errorMsg := message
	if err != nil {
		errorMsg = fmt.Sprintf("%s: %v", message, err)
	}
	return &ToolResult{
		Text:    errorMsg,
		IsError: true,
	}, nil
}

func (t *EnhancedDownloadFileTool) createAuditedErrorResult(sandboxID, filePath, operation, message string, err error, startTime time.Time) (*ToolResult, error) {
	duration := time.Since(startTime)

	// Create audit entry for failed operation
	auditEntry := &FileOperationAudit{
		Operation: "enhanced_download_file",
		SandboxID: sandboxID,
		Path:      filePath,
		Timestamp: time.Now(),
		Success:   false,
		Error:     message,
		Duration:  duration,
		Metadata: map[string]interface{}{
			"failed_operation": operation,
		},
	}
	if err != nil {
		auditEntry.Error = fmt.Sprintf("%s: %v", message, err)
	}
	t.auditLogger.LogOperation(auditEntry)

	return t.createErrorResult(message, err)
}
