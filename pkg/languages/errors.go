package languages

import (
	"fmt"
)

// LanguageError represents a language-specific error
type LanguageError struct {
	Message  string   `json:"message"`
	Language Language `json:"language"`
	Type     string   `json:"type"`
	Code     string   `json:"code,omitempty"`
	Details  string   `json:"details,omitempty"`
}

// Error implements the error interface
func (e *LanguageError) Error() string {
	return fmt.Sprintf("[%s:%s] %s", e.Language, e.Type, e.Message)
}

// NewLanguageError creates a new language error
func NewLanguageError(message string, language Language, errorType string) *LanguageError {
	return &LanguageError{
		Message:  message,
		Language: language,
		Type:     errorType,
	}
}

// NewCompilationError creates a compilation error
func NewCompilationError(message string, language Language, code string) *LanguageError {
	return &LanguageError{
		Message:  message,
		Language: language,
		Type:     "compilation",
		Code:     code,
	}
}

// NewRuntimeError creates a runtime error
func NewRuntimeError(message string, language Language, details string) *LanguageError {
	return &LanguageError{
		Message:  message,
		Language: language,
		Type:     "runtime",
		Details:  details,
	}
}

// NewPackageError creates a package installation error
func NewPackageError(message string, language Language, details string) *LanguageError {
	return &LanguageError{
		Message:  message,
		Language: language,
		Type:     "package",
		Details:  details,
	}
}

// NewEnvironmentError creates an environment setup error
func NewEnvironmentError(message string, language Language, details string) *LanguageError {
	return &LanguageError{
		Message:  message,
		Language: language,
		Type:     "environment",
		Details:  details,
	}
}

// Common error types
const (
	ErrorTypeValidation   = "validation"
	ErrorTypeCompilation  = "compilation"
	ErrorTypeRuntime      = "runtime"
	ErrorTypePackage      = "package"
	ErrorTypeEnvironment  = "environment"
	ErrorTypeTimeout      = "timeout"
	ErrorTypePermission   = "permission"
	ErrorTypeNotSupported = "not_supported"
)
