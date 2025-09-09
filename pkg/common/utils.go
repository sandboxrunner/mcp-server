package common

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Retry executes a function with retry logic based on the provided configuration
func Retry(ctx context.Context, config RetryConfig, fn func() error) error {
	var lastErr error
	delay := config.InitialDelay

	for attempt := 1; attempt <= config.MaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := fn(); err != nil {
			lastErr = err

			// If this was the last attempt, return the error
			if attempt == config.MaxAttempts {
				break
			}

			// Wait before retrying
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}

			// Calculate next delay with exponential backoff
			delay = time.Duration(float64(delay) * config.Multiplier)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		} else {
			// Success
			return nil
		}
	}

	return lastErr
}

// IsContextDone checks if context is cancelled or timed out
func IsContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// SanitizePath sanitizes a file path to prevent directory traversal attacks
func SanitizePath(path string) string {
	// Clean the path
	path = filepath.Clean(path)

	// Remove any ../ components
	parts := strings.Split(path, string(os.PathSeparator))
	var cleanParts []string

	for _, part := range parts {
		if part != ".." && part != "." && part != "" {
			cleanParts = append(cleanParts, part)
		}
	}

	return string(os.PathSeparator) + filepath.Join(cleanParts...)
}

// ValidateFilePath validates that a file path is safe to use
func ValidateFilePath(path string) error {
	if path == "" {
		return NewSandboxError(ErrCodeInvalidArgument, "path cannot be empty", "")
	}

	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return NewSandboxError(ErrCodeInvalidArgument, "path contains null bytes", "")
	}

	// Clean the path
	cleanPath := SanitizePath(path)
	if cleanPath != path {
		return NewSandboxError(ErrCodeInvalidArgument, "path contains unsafe components", fmt.Sprintf("cleaned path: %s", cleanPath))
	}

	return nil
}

// EnsureDirectoryExists creates a directory if it doesn't exist
func EnsureDirectoryExists(path string, perm os.FileMode) error {
	if err := ValidateFilePath(path); err != nil {
		return err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, perm); err != nil {
			return NewSandboxError(ErrCodeInternalError, "failed to create directory", err.Error())
		}
	} else if err != nil {
		return NewSandboxError(ErrCodeInternalError, "failed to check directory", err.Error())
	}

	return nil
}

// GenerateRandomString generates a random string of specified length
func GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	
	rand.Seed(time.Now().UnixNano())
	result := make([]byte, length)
	
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	
	return string(result)
}

// FormatBytes formats byte count as human-readable string
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

// FormatDuration formats duration as human-readable string
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// TruncateString truncates a string to a maximum length
func TruncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	
	if maxLength <= 3 {
		return s[:maxLength]
	}
	
	return s[:maxLength-3] + "..."
}

// Contains checks if a slice contains a specific value
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveFromSlice removes an item from a slice
func RemoveFromSlice(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// MergeStringMaps merges multiple string maps, with later maps overriding earlier ones
func MergeStringMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	
	return result
}

// GetEnvWithDefault returns environment variable value or default if not set
func GetEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// IsValidEnvironmentKey checks if a string is a valid environment variable key
func IsValidEnvironmentKey(key string) bool {
	if key == "" {
		return false
	}
	
	// Environment variable names must start with a letter or underscore
	first := key[0]
	if !((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') || first == '_') {
		return false
	}
	
	// Remaining characters must be letters, digits, or underscores
	for _, char := range key[1:] {
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') || 
			  (char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}
	
	return true
}

// ParseCommand parses a command string into arguments, handling quoted strings
func ParseCommand(cmd string) []string {
	var args []string
	var currentArg strings.Builder
	var inQuotes bool
	var quoteChar rune
	
	for i, char := range cmd {
		switch {
		case char == '"' || char == '\'':
			if !inQuotes {
				inQuotes = true
				quoteChar = char
			} else if char == quoteChar {
				inQuotes = false
				quoteChar = 0
			} else {
				currentArg.WriteRune(char)
			}
		case char == ' ' && !inQuotes:
			if currentArg.Len() > 0 {
				args = append(args, currentArg.String())
				currentArg.Reset()
			}
		case char == '\\' && i < len(cmd)-1:
			// Handle escape sequences
			next := rune(cmd[i+1])
			if next == '\\' || next == '"' || next == '\'' {
				currentArg.WriteRune(next)
				// Skip the next character
				continue
			} else {
				currentArg.WriteRune(char)
			}
		default:
			currentArg.WriteRune(char)
		}
	}
	
	if currentArg.Len() > 0 {
		args = append(args, currentArg.String())
	}
	
	return args
}

// TimeoutContext creates a context with timeout and returns both context and cancel func
func TimeoutContext(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, timeout)
}

// SafeClose closes a closer and logs any error
func SafeClose(closer interface{ Close() error }, name string) {
	if closer != nil {
		if err := closer.Close(); err != nil {
			// In a real application, you'd use a proper logger here
			fmt.Printf("Warning: failed to close %s: %v\n", name, err)
		}
	}
}

// CoalesceString returns the first non-empty string from the provided strings
func CoalesceString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// MinDuration returns the minimum of two durations
func MinDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// MaxDuration returns the maximum of two durations
func MaxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

// ClampInt clamps an integer value between min and max
func ClampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// ClampInt64 clamps an int64 value between min and max
func ClampInt64(value, min, max int64) int64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// IsAbsolutePath checks if a path is absolute
func IsAbsolutePath(path string) bool {
	return filepath.IsAbs(path)
}

// JoinPaths safely joins paths, ensuring no directory traversal
func JoinPaths(base string, paths ...string) string {
	result := base
	
	for _, path := range paths {
		// Sanitize each path component
		cleanPath := SanitizePath(path)
		if filepath.IsAbs(cleanPath) {
			// If it's absolute, make it relative
			cleanPath = strings.TrimPrefix(cleanPath, string(os.PathSeparator))
		}
		result = filepath.Join(result, cleanPath)
	}
	
	return result
}