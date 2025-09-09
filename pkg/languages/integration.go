package languages

import (
	"context"
	"fmt"
	"time"
)

// CodeExecutor provides a high-level interface for code execution
type CodeExecutor struct {
	manager *Manager
}

// NewCodeExecutor creates a new code executor
func NewCodeExecutor(workspaceDir string) *CodeExecutor {
	return &CodeExecutor{
		manager: NewManager(workspaceDir),
	}
}

// ExecuteCodeRequest represents a code execution request
type ExecuteCodeRequest struct {
	Code        string            `json:"code"`
	Language    string            `json:"language,omitempty"`    // Optional, will auto-detect if empty
	Filename    string            `json:"filename,omitempty"`    // Optional, helps with detection
	Packages    []string          `json:"packages,omitempty"`    // Packages to install
	Environment map[string]string `json:"environment,omitempty"` // Environment variables
	Options     map[string]string `json:"options,omitempty"`     // Language-specific options
	Timeout     int               `json:"timeout,omitempty"`     // Timeout in seconds
	WorkingDir  string            `json:"working_dir,omitempty"` // Working directory
	Files       map[string]string `json:"files,omitempty"`       // Additional files
	Stdin       string            `json:"stdin,omitempty"`       // Standard input
}

// ExecuteCodeResponse represents the execution result
type ExecuteCodeResponse struct {
	Language      string            `json:"language"`
	Success       bool              `json:"success"`
	ExitCode      int               `json:"exit_code"`
	Stdout        string            `json:"stdout"`
	Stderr        string            `json:"stderr"`
	Duration      string            `json:"duration"`    // Duration as string (e.g., "1.23s")
	DurationMs    int64             `json:"duration_ms"` // Duration in milliseconds
	Command       string            `json:"command"`     // Command that was executed
	DetectionInfo *DetectionResult  `json:"detection_info,omitempty"`
	Error         string            `json:"error,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	Files         map[string]string `json:"files,omitempty"` // Created/modified files
}

// Execute executes code with automatic language detection and comprehensive error handling
func (ce *CodeExecutor) Execute(ctx context.Context, req *ExecuteCodeRequest) *ExecuteCodeResponse {
	// Convert request to internal format
	execReq := &ExecutionRequest{
		Code:        req.Code,
		WorkingDir:  req.WorkingDir,
		Environment: req.Environment,
		Options:     req.Options,
		Files:       req.Files,
		Stdin:       req.Stdin,
		Packages:    req.Packages,
	}

	// Set timeout
	if req.Timeout > 0 {
		execReq.Timeout = time.Duration(req.Timeout) * time.Second
	} else {
		execReq.Timeout = 30 * time.Second // Default timeout
	}

	// Language detection or validation
	var detectionResult *DetectionResult
	if req.Language == "" {
		// Auto-detect language
		detectionResult = ce.manager.GetBestLanguageMatch(req.Code, req.Filename)
		if detectionResult == nil {
			return &ExecuteCodeResponse{
				Success: false,
				Error:   "Unable to detect programming language from code",
			}
		}
		execReq.Language = detectionResult.Language
	} else {
		// Validate provided language
		language := Language(req.Language)
		if _, err := ce.manager.GetHandler(language); err != nil {
			return &ExecuteCodeResponse{
				Success: false,
				Error:   fmt.Sprintf("Unsupported language: %s", req.Language),
			}
		}
		execReq.Language = language

		// Still provide detection info for debugging
		detectionResult = ce.manager.GetBestLanguageMatch(req.Code, req.Filename)
	}

	// Execute the code
	result, err := ce.manager.ExecuteCode(ctx, execReq)

	// Build response
	response := &ExecuteCodeResponse{
		Language:      string(execReq.Language),
		Success:       result.ExitCode == 0 && err == nil,
		ExitCode:      result.ExitCode,
		Stdout:        result.Stdout,
		Stderr:        result.Stderr,
		Duration:      result.Duration.String(),
		DurationMs:    result.Duration.Nanoseconds() / 1000000,
		Command:       result.Command,
		DetectionInfo: detectionResult,
		Metadata:      result.Metadata,
		Files:         result.Files,
	}

	// Handle errors
	if err != nil {
		response.Error = err.Error()
	}
	if result.Error != nil {
		if response.Error == "" {
			response.Error = result.Error.Error()
		} else {
			response.Error = fmt.Sprintf("%s: %s", response.Error, result.Error.Error())
		}
	}

	return response
}

// GetSupportedLanguages returns information about all supported languages
func (ce *CodeExecutor) GetSupportedLanguages() map[string]*LanguageInfoResponse {
	languages := make(map[string]*LanguageInfoResponse)

	allInfo, err := ce.manager.GetAllLanguagesInfo()
	if err != nil {
		return languages
	}

	for lang, info := range allInfo {
		languages[string(lang)] = &LanguageInfoResponse{
			Name:              string(info.Language),
			Extensions:        info.Extensions,
			DefaultImage:      info.DefaultImage,
			PackageManager:    info.PackageManagerName,
			IsCompiled:        info.IsCompiled,
			HasPackageManager: info.HasPackageManager,
			DefaultTimeout:    info.DefaultTimeout.String(),
		}
	}

	return languages
}

// DetectLanguage detects the language from code
func (ce *CodeExecutor) DetectLanguage(code string, filename string) []*DetectionResult {
	results := ce.manager.DetectLanguage(code, filename)

	// Convert to pointer slice for JSON marshaling
	var ptrResults []*DetectionResult
	for i := range results {
		ptrResults = append(ptrResults, &results[i])
	}

	return ptrResults
}

// ValidateCode validates code syntax if possible
func (ce *CodeExecutor) ValidateCode(language string, code string) *ValidationResponse {
	lang := Language(language)

	// Check if language is supported
	if _, err := ce.manager.GetHandler(lang); err != nil {
		return &ValidationResponse{
			Valid: false,
			Error: fmt.Sprintf("Unsupported language: %s", language),
		}
	}

	// Validate code
	if err := ce.manager.ValidateCode(lang, code); err != nil {
		return &ValidationResponse{
			Valid: false,
			Error: err.Error(),
		}
	}

	return &ValidationResponse{
		Valid: true,
	}
}

// InstallPackages installs packages for a specific language
func (ce *CodeExecutor) InstallPackages(ctx context.Context, language string, packages []string, workingDir string) *PackageInstallResponse {
	lang := Language(language)

	err := ce.manager.InstallPackages(ctx, lang, packages, workingDir, make(map[string]string))
	if err != nil {
		return &PackageInstallResponse{
			Success: false,
			Error:   err.Error(),
		}
	}

	return &PackageInstallResponse{
		Success:           true,
		InstalledPackages: packages,
	}
}

// Response types for API compatibility

// LanguageInfoResponse represents language information in API responses
type LanguageInfoResponse struct {
	Name              string   `json:"name"`
	Extensions        []string `json:"extensions"`
	DefaultImage      string   `json:"default_image"`
	PackageManager    string   `json:"package_manager"`
	IsCompiled        bool     `json:"is_compiled"`
	HasPackageManager bool     `json:"has_package_manager"`
	DefaultTimeout    string   `json:"default_timeout"`
}

// ValidationResponse represents code validation results
type ValidationResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// PackageInstallResponse represents package installation results
type PackageInstallResponse struct {
	Success           bool     `json:"success"`
	InstalledPackages []string `json:"installed_packages,omitempty"`
	FailedPackages    []string `json:"failed_packages,omitempty"`
	Error             string   `json:"error,omitempty"`
	Output            string   `json:"output,omitempty"`
}
