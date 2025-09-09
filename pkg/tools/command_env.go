package tools

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// CommandEnvironment manages environment setup for command execution
type CommandEnvironment struct {
	mutex         sync.RWMutex
	baseEnv       map[string]string
	languagePaths map[string][]string
	defaultShell  string
	workingDir    string
	userContext   *UserContext
	pathSeparator string
	sensitiveVars []string
	expandVars    bool
}

// UserContext represents the user context for command execution
type UserContext struct {
	Username string
	UID      int
	GID      int
	Home     string
	Shell    string
}

// EnvironmentOptions provides configuration for environment setup
type EnvironmentOptions struct {
	BaseEnvironment  map[string]string
	WorkingDirectory string
	Language         string
	User             string
	Shell            string
	ExpandVariables  bool
	FilterSensitive  bool
	CustomPaths      []string
	AdditionalEnv    map[string]string
}

// NewCommandEnvironment creates a new command environment manager
func NewCommandEnvironment(opts EnvironmentOptions) (*CommandEnvironment, error) {
	env := &CommandEnvironment{
		baseEnv:       make(map[string]string),
		languagePaths: make(map[string][]string),
		pathSeparator: ":",
		sensitiveVars: []string{
			"SSH_PRIVATE_KEY", "SSH_KEY", "PRIVATE_KEY",
			"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY",
			"DATABASE_URL", "DB_PASSWORD", "MYSQL_PASSWORD",
			"POSTGRES_PASSWORD", "REDIS_PASSWORD", "AWS_SECRET",
			"GCP_CREDENTIALS", "AZURE_CLIENT_SECRET",
		},
		expandVars: opts.ExpandVariables,
	}

	// Initialize base environment
	if err := env.initializeBaseEnvironment(opts.BaseEnvironment); err != nil {
		return nil, fmt.Errorf("failed to initialize base environment: %w", err)
	}

	// Setup language-specific paths
	env.initializeLanguagePaths()

	// Setup working directory
	if err := env.setWorkingDirectory(opts.WorkingDirectory); err != nil {
		return nil, fmt.Errorf("failed to set working directory: %w", err)
	}

	// Setup user context
	if err := env.setupUserContext(opts.User); err != nil {
		return nil, fmt.Errorf("failed to setup user context: %w", err)
	}

	// Detect and set default shell
	env.detectDefaultShell(opts.Shell)

	// Apply custom paths and additional environment
	if len(opts.CustomPaths) > 0 {
		env.addCustomPaths(opts.CustomPaths)
	}

	if len(opts.AdditionalEnv) > 0 {
		env.addEnvironmentVariables(opts.AdditionalEnv, opts.FilterSensitive)
	}

	return env, nil
}

// initializeBaseEnvironment sets up the base environment variables
func (ce *CommandEnvironment) initializeBaseEnvironment(baseEnv map[string]string) error {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	// Copy provided base environment
	if baseEnv != nil {
		for k, v := range baseEnv {
			ce.baseEnv[k] = v
		}
	}

	// Set essential environment variables if not present
	essentialVars := map[string]string{
		"PATH":   "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME":   "/root",
		"USER":   "root",
		"SHELL":  "/bin/bash",
		"TERM":   "xterm-256color",
		"LANG":   "en_US.UTF-8",
		"LC_ALL": "en_US.UTF-8",
	}

	for key, defaultValue := range essentialVars {
		if _, exists := ce.baseEnv[key]; !exists {
			ce.baseEnv[key] = defaultValue
		}
	}

	return nil
}

// initializeLanguagePaths sets up language-specific PATH configurations
func (ce *CommandEnvironment) initializeLanguagePaths() {
	ce.languagePaths = map[string][]string{
		"python": {
			"/usr/local/bin",
			"/usr/bin",
			"/opt/python/bin",
			"/home/.local/bin",
		},
		"node": {
			"/usr/local/bin",
			"/usr/bin",
			"/opt/node/bin",
			"/home/.npm-global/bin",
		},
		"javascript": {
			"/usr/local/bin",
			"/usr/bin",
			"/opt/node/bin",
			"/home/.npm-global/bin",
		},
		"typescript": {
			"/usr/local/bin",
			"/usr/bin",
			"/opt/node/bin",
			"/home/.npm-global/bin",
		},
		"go": {
			"/usr/local/go/bin",
			"/usr/local/bin",
			"/usr/bin",
			"/home/go/bin",
			"/root/go/bin",
		},
		"rust": {
			"/home/.cargo/bin",
			"/usr/local/bin",
			"/usr/bin",
		},
		"java": {
			"/usr/local/bin",
			"/usr/bin",
			"/opt/java/bin",
			"/usr/lib/jvm/default-java/bin",
		},
		"c": {
			"/usr/local/bin",
			"/usr/bin",
			"/usr/local/gcc/bin",
		},
		"cpp": {
			"/usr/local/bin",
			"/usr/bin",
			"/usr/local/gcc/bin",
		},
		"csharp": {
			"/usr/local/bin",
			"/usr/bin",
			"/opt/dotnet",
		},
		"ruby": {
			"/usr/local/bin",
			"/usr/bin",
			"/home/.gem/ruby/bin",
		},
		"php": {
			"/usr/local/bin",
			"/usr/bin",
			"/opt/php/bin",
		},
		"shell": {
			"/usr/local/sbin",
			"/usr/local/bin",
			"/usr/sbin",
			"/usr/bin",
			"/sbin",
			"/bin",
		},
		"bash": {
			"/usr/local/sbin",
			"/usr/local/bin",
			"/usr/sbin",
			"/usr/bin",
			"/sbin",
			"/bin",
		},
	}
}

// setWorkingDirectory validates and sets the working directory
func (ce *CommandEnvironment) setWorkingDirectory(workingDir string) error {
	if workingDir == "" {
		workingDir = "/workspace"
	}

	// Resolve absolute path
	absPath, err := filepath.Abs(workingDir)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Validate path is within allowed directories
	allowedPrefixes := []string{"/workspace", "/tmp", "/home", "/root"}
	isAllowed := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(absPath, prefix) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		return fmt.Errorf("working directory %s is not within allowed paths", absPath)
	}

	ce.workingDir = absPath
	return nil
}

// setupUserContext configures user context for command execution
func (ce *CommandEnvironment) setupUserContext(username string) error {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	// Default to root if not specified
	if username == "" {
		username = "root"
	}

	// Create user context
	userCtx := &UserContext{
		Username: username,
		UID:      0, // Default to root
		GID:      0, // Default to root group
		Home:     "/root",
		Shell:    "/bin/bash",
	}

	// Try to get user information if not root
	if username != "root" {
		if u, err := user.Lookup(username); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil {
				userCtx.UID = uid
			}
			if gid, err := strconv.Atoi(u.Gid); err == nil {
				userCtx.GID = gid
			}
			userCtx.Home = u.HomeDir
		} else {
			log.Warn().Str("username", username).Err(err).Msg("Could not lookup user, using defaults")
		}
	}

	ce.userContext = userCtx

	// Update environment with user context
	ce.baseEnv["USER"] = userCtx.Username
	ce.baseEnv["HOME"] = userCtx.Home
	ce.baseEnv["LOGNAME"] = userCtx.Username

	return nil
}

// detectDefaultShell detects and sets the default shell
func (ce *CommandEnvironment) detectDefaultShell(preferredShell string) {
	shells := []string{preferredShell, "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash"}

	for _, shell := range shells {
		if shell == "" {
			continue
		}

		if _, err := os.Stat(shell); err == nil {
			ce.defaultShell = shell
			ce.baseEnv["SHELL"] = shell
			return
		}
	}

	// Fallback to sh
	ce.defaultShell = "/bin/sh"
	ce.baseEnv["SHELL"] = "/bin/sh"
}

// addCustomPaths adds custom paths to the PATH environment variable
func (ce *CommandEnvironment) addCustomPaths(paths []string) {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	currentPath := ce.baseEnv["PATH"]
	pathParts := strings.Split(currentPath, ce.pathSeparator)

	// Add custom paths to the beginning of PATH
	for i := len(paths) - 1; i >= 0; i-- {
		path := paths[i]
		if path != "" && !ce.containsPath(pathParts, path) {
			pathParts = append([]string{path}, pathParts...)
		}
	}

	ce.baseEnv["PATH"] = strings.Join(pathParts, ce.pathSeparator)
}

// addEnvironmentVariables adds additional environment variables with optional filtering
func (ce *CommandEnvironment) addEnvironmentVariables(env map[string]string, filterSensitive bool) {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	for key, value := range env {
		// Filter sensitive variables if requested
		if filterSensitive && ce.isSensitiveVariable(key) {
			log.Warn().Str("key", key).Msg("Filtered sensitive environment variable")
			continue
		}

		ce.baseEnv[key] = value
	}
}

// PrepareEnvironmentForLanguage prepares environment variables for a specific language
func (ce *CommandEnvironment) PrepareEnvironmentForLanguage(language string) ([]string, error) {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	// Start with base environment
	env := make(map[string]string)
	for k, v := range ce.baseEnv {
		env[k] = v
	}

	// Add language-specific paths
	if langPaths, exists := ce.languagePaths[language]; exists {
		currentPath := env["PATH"]
		pathParts := strings.Split(currentPath, ce.pathSeparator)

		// Prepend language-specific paths
		for i := len(langPaths) - 1; i >= 0; i-- {
			path := langPaths[i]
			if path != "" && !ce.containsPath(pathParts, path) {
				pathParts = append([]string{path}, pathParts...)
			}
		}

		env["PATH"] = strings.Join(pathParts, ce.pathSeparator)
	}

	// Add language-specific environment variables
	ce.addLanguageSpecificEnv(env, language)

	// Expand variables if enabled
	if ce.expandVars {
		if err := ce.expandEnvironmentVariables(env); err != nil {
			return nil, fmt.Errorf("failed to expand environment variables: %w", err)
		}
	}

	// Convert to slice format
	var envSlice []string
	for key, value := range env {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", key, value))
	}

	return envSlice, nil
}

// addLanguageSpecificEnv adds language-specific environment variables
func (ce *CommandEnvironment) addLanguageSpecificEnv(env map[string]string, language string) {
	switch language {
	case "python":
		env["PYTHONUNBUFFERED"] = "1"
		env["PYTHONDONTWRITEBYTECODE"] = "1"
		env["PYTHONIOENCODING"] = "utf-8"
		env["PIP_NO_CACHE_DIR"] = "1"

	case "node", "javascript", "typescript":
		env["NODE_ENV"] = "development"
		env["NPM_CONFIG_CACHE"] = "/tmp/.npm"
		env["NPM_CONFIG_PROGRESS"] = "false"

	case "go":
		env["GOCACHE"] = "/tmp/.cache/go-build"
		env["GOMODCACHE"] = "/tmp/.cache/go-mod"
		env["CGO_ENABLED"] = "1"

	case "rust":
		env["CARGO_HOME"] = "/tmp/.cargo"
		env["RUSTUP_HOME"] = "/tmp/.rustup"

	case "java":
		env["JAVA_HOME"] = "/usr/lib/jvm/default-java"
		env["MAVEN_OPTS"] = "-Dmaven.repo.local=/tmp/.m2/repository"

	case "csharp":
		env["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1"
		env["DOTNET_NOLOGO"] = "1"
		env["NUGET_PACKAGES"] = "/tmp/.nuget/packages"

	case "ruby":
		env["GEM_HOME"] = "/tmp/.gem"
		env["GEM_PATH"] = "/tmp/.gem"

	case "php":
		env["PHP_INI_SCAN_DIR"] = "/usr/local/etc/php/conf.d"

	case "shell", "bash":
		env["HISTFILE"] = "/tmp/.bash_history"
		env["HISTSIZE"] = "1000"
	}
}

// GetUserContext returns the current user context
func (ce *CommandEnvironment) GetUserContext() *UserContext {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	if ce.userContext == nil {
		return &UserContext{
			Username: "root",
			UID:      0,
			GID:      0,
			Home:     "/root",
			Shell:    "/bin/bash",
		}
	}

	// Return a copy to prevent modification
	return &UserContext{
		Username: ce.userContext.Username,
		UID:      ce.userContext.UID,
		GID:      ce.userContext.GID,
		Home:     ce.userContext.Home,
		Shell:    ce.userContext.Shell,
	}
}

// GetDefaultShell returns the detected default shell
func (ce *CommandEnvironment) GetDefaultShell() string {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()
	return ce.defaultShell
}

// GetWorkingDirectory returns the configured working directory
func (ce *CommandEnvironment) GetWorkingDirectory() string {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()
	return ce.workingDir
}

// UpdateEnvironmentVariable updates or sets an environment variable
func (ce *CommandEnvironment) UpdateEnvironmentVariable(key, value string) error {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	if ce.isSensitiveVariable(key) {
		return fmt.Errorf("cannot update sensitive variable: %s", key)
	}

	ce.baseEnv[key] = value
	return nil
}

// RemoveEnvironmentVariable removes an environment variable
func (ce *CommandEnvironment) RemoveEnvironmentVariable(key string) error {
	ce.mutex.Lock()
	defer ce.mutex.Unlock()

	// Don't allow removal of essential variables
	essentialVars := map[string]bool{
		"PATH": true, "HOME": true, "USER": true, "SHELL": true,
	}

	if essentialVars[key] {
		return fmt.Errorf("cannot remove essential variable: %s", key)
	}

	delete(ce.baseEnv, key)
	return nil
}

// GetEnvironmentVariables returns a copy of all environment variables
func (ce *CommandEnvironment) GetEnvironmentVariables(filterSensitive bool) map[string]string {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	env := make(map[string]string)
	for k, v := range ce.baseEnv {
		if filterSensitive && ce.isSensitiveVariable(k) {
			continue
		}
		env[k] = v
	}

	return env
}

// expandEnvironmentVariables expands variable references in environment values
func (ce *CommandEnvironment) expandEnvironmentVariables(env map[string]string) error {
	// Simple variable expansion - handles $VAR and ${VAR} patterns
	for key, value := range env {
		expanded := ce.expandVariableReferences(value, env)
		env[key] = expanded
	}

	return nil
}

// expandVariableReferences expands variable references in a string
func (ce *CommandEnvironment) expandVariableReferences(value string, env map[string]string) string {
	// Handle ${VAR} patterns
	result := value
	for i := 0; i < 10; i++ { // Limit iterations to prevent infinite loops
		startPos := strings.Index(result, "${")
		if startPos == -1 {
			break
		}

		endPos := strings.Index(result[startPos:], "}")
		if endPos == -1 {
			break
		}

		endPos += startPos
		varName := result[startPos+2 : endPos]

		if replacement, exists := env[varName]; exists {
			result = result[:startPos] + replacement + result[endPos+1:]
		} else {
			// Variable not found, leave as is
			break
		}
	}

	// Handle $VAR patterns (simple version)
	for varName, varValue := range env {
		pattern := "$" + varName
		result = strings.ReplaceAll(result, pattern, varValue)
	}

	return result
}

// isSensitiveVariable checks if a variable name indicates sensitive data
func (ce *CommandEnvironment) isSensitiveVariable(key string) bool {
	upperKey := strings.ToUpper(key)

	for _, sensitive := range ce.sensitiveVars {
		if strings.Contains(upperKey, strings.ToUpper(sensitive)) {
			return true
		}
	}

	return false
}

// containsPath checks if a path is already in the path slice
func (ce *CommandEnvironment) containsPath(paths []string, target string) bool {
	for _, path := range paths {
		if path == target {
			return true
		}
	}
	return false
}

// Clone creates a copy of the command environment
func (ce *CommandEnvironment) Clone() (*CommandEnvironment, error) {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	clone := &CommandEnvironment{
		baseEnv:       make(map[string]string),
		languagePaths: make(map[string][]string),
		defaultShell:  ce.defaultShell,
		workingDir:    ce.workingDir,
		pathSeparator: ce.pathSeparator,
		sensitiveVars: make([]string, len(ce.sensitiveVars)),
		expandVars:    ce.expandVars,
	}

	// Copy base environment
	for k, v := range ce.baseEnv {
		clone.baseEnv[k] = v
	}

	// Copy language paths
	for lang, paths := range ce.languagePaths {
		clone.languagePaths[lang] = make([]string, len(paths))
		copy(clone.languagePaths[lang], paths)
	}

	// Copy user context
	if ce.userContext != nil {
		clone.userContext = &UserContext{
			Username: ce.userContext.Username,
			UID:      ce.userContext.UID,
			GID:      ce.userContext.GID,
			Home:     ce.userContext.Home,
			Shell:    ce.userContext.Shell,
		}
	}

	// Copy sensitive vars
	copy(clone.sensitiveVars, ce.sensitiveVars)

	return clone, nil
}

// Validate performs validation checks on the environment configuration
func (ce *CommandEnvironment) Validate() error {
	ce.mutex.RLock()
	defer ce.mutex.RUnlock()

	// Check essential variables
	essential := []string{"PATH", "HOME", "USER", "SHELL"}
	for _, key := range essential {
		if value, exists := ce.baseEnv[key]; !exists || value == "" {
			return fmt.Errorf("essential environment variable %s is missing or empty", key)
		}
	}

	// Validate working directory
	if ce.workingDir == "" {
		return fmt.Errorf("working directory is not set")
	}

	// Validate user context
	if ce.userContext == nil {
		return fmt.Errorf("user context is not set")
	}

	// Validate shell exists
	if ce.defaultShell != "" {
		if _, err := os.Stat(ce.defaultShell); err != nil {
			return fmt.Errorf("default shell %s does not exist: %w", ce.defaultShell, err)
		}
	}

	return nil
}
