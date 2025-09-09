package languages

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manager manages language handlers and execution
type Manager struct {
	handlerRegistry *HandlerRegistry
	detector        *Detector
	imageRegistry   *ImageRegistry
	packageRegistry *PackageManagerRegistry
	workspaceDir    string
	defaultTimeout  time.Duration
}

// NewManager creates a new language manager
func NewManager(workspaceDir string) *Manager {
	if workspaceDir == "" {
		workspaceDir = "/tmp/sandbox-workspace"
	}

	manager := &Manager{
		handlerRegistry: NewHandlerRegistry(),
		detector:        NewDetector(),
		imageRegistry:   NewImageRegistry(),
		packageRegistry: NewPackageManagerRegistry(),
		workspaceDir:    workspaceDir,
		defaultTimeout:  30 * time.Second,
	}

	return manager
}

// RegisterHandler registers a language handler
func (m *Manager) RegisterHandler(handler LanguageHandler) {
	m.handlerRegistry.RegisterHandler(handler)
}

// GetHandler returns a handler for the specified language
func (m *Manager) GetHandler(language Language) (LanguageHandler, error) {
	return m.handlerRegistry.GetHandler(language)
}

// GetSupportedLanguages returns all supported languages
func (m *Manager) GetSupportedLanguages() []Language {
	return m.handlerRegistry.GetSupportedLanguages()
}

// DetectLanguage detects the language from code and optional filename
func (m *Manager) DetectLanguage(code string, filename string) []DetectionResult {
	return m.detector.DetectLanguage(code, filename)
}

// GetBestLanguageMatch returns the most confident language detection
func (m *Manager) GetBestLanguageMatch(code string, filename string) *DetectionResult {
	return m.detector.GetBestMatch(code, filename)
}

// ExecuteCode executes code with automatic language detection if not specified
func (m *Manager) ExecuteCode(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	// Auto-detect language if not specified
	if req.Language == "" {
		detection := m.detector.GetBestMatch(req.Code, "")
		if detection == nil {
			return nil, NewLanguageError("unable to detect language", "", ErrorTypeValidation)
		}
		req.Language = detection.Language
	}

	// Get handler for the language
	handler, err := m.GetHandler(req.Language)
	if err != nil {
		return nil, err
	}

	// Set default working directory if not specified
	if req.WorkingDir == "" {
		req.WorkingDir = filepath.Join(m.workspaceDir, string(req.Language))
	}

	// Set default timeout if not specified
	if req.Timeout == 0 {
		req.Timeout = handler.GetDefaultTimeout()
		if req.Timeout == 0 {
			req.Timeout = m.defaultTimeout
		}
	}

	// Create working directory
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return nil, NewEnvironmentError(
			fmt.Sprintf("failed to create working directory: %v", err),
			req.Language,
			err.Error(),
		)
	}

	// Prepare execution
	if err := handler.PrepareExecution(ctx, req); err != nil {
		return nil, err
	}

	// Install packages if specified
	if len(req.Packages) > 0 {
		if err := m.InstallPackages(ctx, req.Language, req.Packages, req.WorkingDir, req.Options); err != nil {
			return nil, err
		}
	}

	// Execute code
	result, err := handler.Execute(ctx, req)
	if err != nil {
		return result, err
	}

	// Cleanup
	defer func() {
		if cleanupErr := handler.Cleanup(ctx, req); cleanupErr != nil {
			// Log cleanup error but don't fail the execution
			fmt.Printf("Warning: cleanup failed: %v\n", cleanupErr)
		}
	}()

	return result, nil
}

// InstallPackages installs packages for a specific language
func (m *Manager) InstallPackages(ctx context.Context, language Language, packages []string, workingDir string, options map[string]string) error {
	packageManager := m.packageRegistry.GetPackageManager(language)
	if packageManager == nil {
		return NewPackageError(
			fmt.Sprintf("no package manager available for language: %s", language),
			language,
			"",
		)
	}

	installReq := &PackageInstallRequest{
		Packages:    packages,
		Language:    language,
		WorkingDir:  workingDir,
		Environment: make(map[string]string),
		Options:     options,
	}

	result, err := packageManager.InstallPackages(ctx, installReq.Packages, installReq.WorkingDir, installReq.Options)
	if err != nil {
		return NewPackageError(
			fmt.Sprintf("failed to install packages: %v", err),
			language,
			err.Error(),
		)
	}

	if !result.Success {
		return NewPackageError(
			fmt.Sprintf("package installation failed: %s", result.Output),
			language,
			result.Output,
		)
	}

	return nil
}

// SetupEnvironment sets up the environment for a specific language
func (m *Manager) SetupEnvironment(ctx context.Context, language Language, workingDir string, version string, options map[string]string) (*EnvironmentSetupResult, error) {
	handler, err := m.GetHandler(language)
	if err != nil {
		return nil, err
	}

	req := &EnvironmentSetupRequest{
		Language:   language,
		WorkingDir: workingDir,
		Version:    version,
		Options:    options,
	}

	return handler.SetupEnvironment(ctx, req)
}

// GetDefaultImage returns the default container image for a language
func (m *Manager) GetDefaultImage(language Language) string {
	return m.imageRegistry.GetDefaultImage(language)
}

// GetImages returns available images for a language
func (m *Manager) GetImages(language Language) []ImageConfig {
	return m.imageRegistry.GetImages(language)
}

// GetBestImage returns the best image for given requirements
func (m *Manager) GetBestImage(language Language, version string, packages []string) *ImageConfig {
	return m.imageRegistry.GetBestImage(language, version, packages)
}

// ValidateCode validates code syntax if possible
func (m *Manager) ValidateCode(language Language, code string) error {
	handler, err := m.GetHandler(language)
	if err != nil {
		return err
	}

	return handler.ValidateCode(code)
}

// GetLanguageInfo returns detailed information about a language
func (m *Manager) GetLanguageInfo(language Language) (*LanguageInfo, error) {
	handler, err := m.GetHandler(language)
	if err != nil {
		return nil, err
	}

	packageManager := m.packageRegistry.GetPackageManager(language)

	info := &LanguageInfo{
		Language:          language,
		Extensions:        handler.GetSupportedExtensions(),
		DefaultImage:      handler.GetDefaultImage(),
		ImageVersions:     handler.GetImageVersions(),
		PackageManager:    handler.GetPackageManager(),
		DefaultTimeout:    handler.GetDefaultTimeout(),
		IsCompiled:        handler.IsCompiled(),
		AvailableImages:   m.imageRegistry.GetImages(language),
		HasPackageManager: packageManager != nil,
	}

	if packageManager != nil {
		info.PackageManagerName = packageManager.GetName()
		info.ConfigFiles = packageManager.GetConfigFiles()
	}

	return info, nil
}

// GetAllLanguagesInfo returns information about all supported languages
func (m *Manager) GetAllLanguagesInfo() (map[Language]*LanguageInfo, error) {
	info := make(map[Language]*LanguageInfo)

	for _, language := range m.GetSupportedLanguages() {
		langInfo, err := m.GetLanguageInfo(language)
		if err != nil {
			continue // Skip languages with errors
		}
		info[language] = langInfo
	}

	return info, nil
}

// CreateExecutionPlan creates an execution plan for multi-file projects
func (m *Manager) CreateExecutionPlan(files map[string]string, mainFile string) (*ExecutionPlan, error) {
	if mainFile == "" {
		// Try to detect main file
		for filename := range files {
			if m.isMainFile(filename) {
				mainFile = filename
				break
			}
		}
		if mainFile == "" {
			return nil, fmt.Errorf("no main file specified or detected")
		}
	}

	mainCode, exists := files[mainFile]
	if !exists {
		return nil, fmt.Errorf("main file not found in provided files: %s", mainFile)
	}

	// Detect language from main file
	detection := m.detector.GetBestMatch(mainCode, mainFile)
	if detection == nil {
		return nil, fmt.Errorf("unable to detect language from main file: %s", mainFile)
	}

	plan := &ExecutionPlan{
		Language:     detection.Language,
		MainFile:     mainFile,
		Files:        files,
		Dependencies: make([]string, 0),
		BuildSteps:   make([]string, 0),
		RunCommand:   "",
	}

	// Get handler to fill in execution details
	handler, err := m.GetHandler(detection.Language)
	if err != nil {
		return nil, err
	}

	// Create a dummy request to get commands
	req := &ExecutionRequest{
		Code:     mainCode,
		Language: detection.Language,
		Files:    files,
	}

	if handler.IsCompiled() {
		plan.BuildSteps = append(plan.BuildSteps, handler.GetCompileCommand(req))
	}
	plan.RunCommand = handler.GetRunCommand(req)

	return plan, nil
}

// CleanupWorkspace cleans up temporary files and directories
func (m *Manager) CleanupWorkspace(workspaceDir string) error {
	if workspaceDir == "" || workspaceDir == "/" {
		return fmt.Errorf("invalid workspace directory: %s", workspaceDir)
	}

	// Only clean up directories under our workspace
	if !strings.HasPrefix(workspaceDir, m.workspaceDir) {
		return fmt.Errorf("workspace directory outside allowed area: %s", workspaceDir)
	}

	return os.RemoveAll(workspaceDir)
}

func (m *Manager) isMainFile(filename string) bool {
	lowerName := strings.ToLower(filename)

	// Common main file patterns
	mainPatterns := []string{
		"main.",
		"index.",
		"app.",
		"run.",
		"start.",
	}

	for _, pattern := range mainPatterns {
		if strings.HasPrefix(lowerName, pattern) {
			return true
		}
	}

	// Language-specific patterns
	if strings.HasSuffix(lowerName, "main.go") ||
		strings.HasSuffix(lowerName, "main.py") ||
		strings.HasSuffix(lowerName, "main.java") ||
		strings.HasSuffix(lowerName, "main.rs") ||
		strings.HasSuffix(lowerName, "main.c") ||
		strings.HasSuffix(lowerName, "main.cpp") {
		return true
	}

	return false
}

// LanguageInfo contains detailed information about a language
type LanguageInfo struct {
	Language           Language      `json:"language"`
	Extensions         []string      `json:"extensions"`
	DefaultImage       string        `json:"default_image"`
	ImageVersions      []string      `json:"image_versions"`
	PackageManager     string        `json:"package_manager"`
	PackageManagerName string        `json:"package_manager_name"`
	DefaultTimeout     time.Duration `json:"default_timeout"`
	IsCompiled         bool          `json:"is_compiled"`
	AvailableImages    []ImageConfig `json:"available_images"`
	HasPackageManager  bool          `json:"has_package_manager"`
	ConfigFiles        []string      `json:"config_files,omitempty"`
}

// ExecutionPlan represents a multi-file execution plan
type ExecutionPlan struct {
	Language     Language          `json:"language"`
	MainFile     string            `json:"main_file"`
	Files        map[string]string `json:"files"`
	Dependencies []string          `json:"dependencies"`
	BuildSteps   []string          `json:"build_steps"`
	RunCommand   string            `json:"run_command"`
}
