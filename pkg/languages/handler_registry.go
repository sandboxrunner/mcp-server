package languages

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// HandlerRegistry manages all language handlers
type HandlerRegistry struct {
	handlers map[Language]LanguageHandler
}

// NewHandlerRegistry creates a new handler registry with all built-in handlers
func NewHandlerRegistry() *HandlerRegistry {
	registry := &HandlerRegistry{
		handlers: make(map[Language]LanguageHandler),
	}

	// Register all built-in handlers
	registry.registerBuiltinHandlers()

	return registry
}

// RegisterHandler registers a language handler
func (r *HandlerRegistry) RegisterHandler(handler LanguageHandler) {
	r.handlers[handler.GetLanguage()] = handler
}

// GetHandler returns a handler for the specified language
func (r *HandlerRegistry) GetHandler(language Language) (LanguageHandler, error) {
	handler, exists := r.handlers[language]
	if !exists {
		return nil, NewLanguageError(
			"no handler registered for language: "+string(language),
			language,
			ErrorTypeNotSupported,
		)
	}
	return handler, nil
}

// GetSupportedLanguages returns all supported languages
func (r *HandlerRegistry) GetSupportedLanguages() []Language {
	var langs []Language
	for lang := range r.handlers {
		langs = append(langs, lang)
	}
	return langs
}

// HasHandler checks if a handler exists for the language
func (r *HandlerRegistry) HasHandler(language Language) bool {
	_, exists := r.handlers[language]
	return exists
}

// GetAllHandlers returns all registered handlers
func (r *HandlerRegistry) GetAllHandlers() map[Language]LanguageHandler {
	// Return a copy to prevent external modification
	result := make(map[Language]LanguageHandler)
	for lang, handler := range r.handlers {
		result[lang] = handler
	}
	return result
}

// registerBuiltinHandlers registers all the built-in language handlers
func (r *HandlerRegistry) registerBuiltinHandlers() {
	// Register implemented handlers
	r.RegisterHandler(NewPythonHandler())
	r.RegisterHandler(NewJavaScriptHandler())
	r.RegisterHandler(NewTypeScriptHandler())
	r.RegisterHandler(NewGoHandler())
	r.RegisterHandler(NewRustHandler())
	r.RegisterHandler(NewJavaHandler())
	r.RegisterHandler(NewCPPHandler())
	r.RegisterHandler(NewCSharpHandler("/workspace"))
	r.RegisterHandler(NewShellHandler())

	// Register stub handlers for languages not yet fully implemented
	r.RegisterHandler(NewStubHandler(LanguageC, []string{".c", ".h"}, "gcc:latest"))
	r.RegisterHandler(NewStubHandler(LanguageRuby, []string{".rb"}, "ruby:3.3-alpine"))
	r.RegisterHandler(NewStubHandler(LanguagePHP, []string{".php"}, "php:8.3-cli-alpine"))
	r.RegisterHandler(NewStubHandler(LanguageR, []string{".r", ".R"}, "r-base:latest"))
	r.RegisterHandler(NewStubHandler(LanguageLua, []string{".lua"}, "alpine:latest"))
	r.RegisterHandler(NewStubHandler(LanguagePerl, []string{".pl", ".pm"}, "perl:slim"))
}

// StubHandler provides a basic implementation for languages not yet fully implemented
type StubHandler struct {
	*BaseHandler
}

// NewStubHandler creates a new stub handler
func NewStubHandler(language Language, extensions []string, defaultImage string) *StubHandler {
	return &StubHandler{
		BaseHandler: NewBaseHandler(
			language,
			extensions,
			defaultImage,
			[]string{defaultImage},
			"",    // No package manager
			30,    // 30 second timeout
			false, // Assume interpreted for simplicity
		),
	}
}

// DetectLanguage provides basic detection based on file extension
func (h *StubHandler) DetectLanguage(code string, filename string) float64 {
	for _, ext := range h.GetSupportedExtensions() {
		if strings.HasSuffix(strings.ToLower(filename), ext) {
			return 0.8
		}
	}
	return 0.0
}

// PrepareExecution creates basic workspace
func (h *StubHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	return os.MkdirAll(req.WorkingDir, 0755)
}

// Execute returns a not-implemented error
func (h *StubHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	return &ExecutionResult{
		Language: h.GetLanguage(),
		ExitCode: -1,
		Stderr:   fmt.Sprintf("Execution for %s is not yet implemented", h.GetLanguage()),
		Error: NewLanguageError(
			fmt.Sprintf("Language %s execution not yet implemented", h.GetLanguage()),
			h.GetLanguage(),
			ErrorTypeNotSupported,
		),
	}, nil
}

// InstallPackages returns not-implemented
func (h *StubHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	return &PackageInstallResult{
		Success: false,
		Output:  fmt.Sprintf("Package installation for %s is not yet implemented", h.GetLanguage()),
		Error:   fmt.Errorf("not implemented"),
	}, nil
}

// SetupEnvironment returns a basic setup result
func (h *StubHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	return &EnvironmentSetupResult{
		Success:     false,
		Version:     "unknown",
		Path:        string(h.GetLanguage()),
		Environment: make(map[string]string),
		Output:      fmt.Sprintf("Environment setup for %s is not yet implemented", h.GetLanguage()),
		Error:       fmt.Errorf("not implemented"),
	}, nil
}

// GetRequiredFiles returns basic file structure
func (h *StubHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)

	ext := ".txt"
	if len(h.GetSupportedExtensions()) > 0 {
		ext = h.GetSupportedExtensions()[0]
	}

	files["main"+ext] = req.Code
	return files
}

// GetCompileCommand returns empty for stub
func (h *StubHandler) GetCompileCommand(req *ExecutionRequest) string {
	return ""
}

// GetRunCommand returns a placeholder
func (h *StubHandler) GetRunCommand(req *ExecutionRequest) string {
	return fmt.Sprintf("echo 'Running %s not implemented'", h.GetLanguage())
}

// ValidateCode performs basic validation
func (h *StubHandler) ValidateCode(code string) error {
	return h.BaseHandler.ValidateCode(code)
}
