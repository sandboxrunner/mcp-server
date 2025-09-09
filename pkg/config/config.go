package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config represents the MCP server configuration
type Config struct {
	Server    ServerConfig    `yaml:"server" mapstructure:"server"`
	Sandbox   SandboxConfig   `yaml:"sandbox" mapstructure:"sandbox"`
	Logging   LoggingConfig   `yaml:"logging" mapstructure:"logging"`
	Tools     ToolsConfig     `yaml:"tools" mapstructure:"tools"`
	Resources ResourcesConfig `yaml:"resources" mapstructure:"resources"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Name         string        `yaml:"name" mapstructure:"name"`
	Version      string        `yaml:"version" mapstructure:"version"`
	Protocol     string        `yaml:"protocol" mapstructure:"protocol"`
	Address      string        `yaml:"address" mapstructure:"address"`
	Port         int           `yaml:"port" mapstructure:"port"`
	ReadTimeout  time.Duration `yaml:"read_timeout" mapstructure:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout" mapstructure:"write_timeout"`
	EnableHTTP   bool          `yaml:"enable_http" mapstructure:"enable_http"`
}

// SandboxConfig holds sandbox-related configuration
type SandboxConfig struct {
	WorkspaceDir     string            `yaml:"workspace_dir" mapstructure:"workspace_dir"`
	DatabasePath     string            `yaml:"database_path" mapstructure:"database_path"`
	DefaultImage     string            `yaml:"default_image" mapstructure:"default_image"`
	DefaultResources ResourceLimits    `yaml:"default_resources" mapstructure:"default_resources"`
	Environment      map[string]string `yaml:"environment" mapstructure:"environment"`
	NetworkMode      string            `yaml:"network_mode" mapstructure:"network_mode"`
	EnableLogging    bool              `yaml:"enable_logging" mapstructure:"enable_logging"`
	CleanupInterval  time.Duration     `yaml:"cleanup_interval" mapstructure:"cleanup_interval"`
	MaxSandboxes     int               `yaml:"max_sandboxes" mapstructure:"max_sandboxes"`
}

// ResourceLimits defines default resource constraints
type ResourceLimits struct {
	CPULimit    string `yaml:"cpu_limit" mapstructure:"cpu_limit"`
	MemoryLimit string `yaml:"memory_limit" mapstructure:"memory_limit"`
	DiskLimit   string `yaml:"disk_limit" mapstructure:"disk_limit"`
}

// LoggingConfig holds logging-related configuration
type LoggingConfig struct {
	Level      string `yaml:"level" mapstructure:"level"`
	Format     string `yaml:"format" mapstructure:"format"`
	OutputFile string `yaml:"output_file" mapstructure:"output_file"`
	MaxSize    int    `yaml:"max_size" mapstructure:"max_size"`
	MaxBackups int    `yaml:"max_backups" mapstructure:"max_backups"`
	MaxAge     int    `yaml:"max_age" mapstructure:"max_age"`
	Compress   bool   `yaml:"compress" mapstructure:"compress"`
}

// ToolsConfig holds tools-related configuration
type ToolsConfig struct {
	EnabledTools       []string          `yaml:"enabled_tools" mapstructure:"enabled_tools"`
	DisabledTools      []string          `yaml:"disabled_tools" mapstructure:"disabled_tools"`
	DefaultTimeout     time.Duration     `yaml:"default_timeout" mapstructure:"default_timeout"`
	MaxOutputSize      int               `yaml:"max_output_size" mapstructure:"max_output_size"`
	CustomTools        map[string]string `yaml:"custom_tools" mapstructure:"custom_tools"`
	ValidationLevel    string            `yaml:"validation_level" mapstructure:"validation_level"`
	EnableStreaming    bool              `yaml:"enable_streaming" mapstructure:"enable_streaming"`
	EnableCaching      bool              `yaml:"enable_caching" mapstructure:"enable_caching"`
	CacheConfig        CacheConfig       `yaml:"cache" mapstructure:"cache"`
	StreamConfig       StreamConfig      `yaml:"streaming" mapstructure:"streaming"`
	EnvironmentConfig  EnvironmentConfig `yaml:"environment" mapstructure:"environment"`
}

// CacheConfig holds command caching configuration
type CacheConfig struct {
	DatabasePath     string        `yaml:"database_path" mapstructure:"database_path"`
	MaxEntries       int64         `yaml:"max_entries" mapstructure:"max_entries"`
	DefaultTTL       time.Duration `yaml:"default_ttl" mapstructure:"default_ttl"`
	CleanupInterval  time.Duration `yaml:"cleanup_interval" mapstructure:"cleanup_interval"`
	CompressionLevel int           `yaml:"compression_level" mapstructure:"compression_level"`
	CompressionMin   int64         `yaml:"compression_min" mapstructure:"compression_min"`
	EnableWarming    bool          `yaml:"enable_warming" mapstructure:"enable_warming"`
	WarmCommands     []string      `yaml:"warm_commands" mapstructure:"warm_commands"`
	MaxCacheSize     int64         `yaml:"max_cache_size" mapstructure:"max_cache_size"`
}

// StreamConfig holds output streaming configuration
type StreamConfig struct {
	BufferSize     int           `yaml:"buffer_size" mapstructure:"buffer_size"`
	FlushInterval  time.Duration `yaml:"flush_interval" mapstructure:"flush_interval"`
	MaxChunkSize   int           `yaml:"max_chunk_size" mapstructure:"max_chunk_size"`
	EnableANSI     bool          `yaml:"enable_ansi" mapstructure:"enable_ansi"`
	FilterANSI     bool          `yaml:"filter_ansi" mapstructure:"filter_ansi"`
	DetectProgress bool          `yaml:"detect_progress" mapstructure:"detect_progress"`
	EnableJSON     bool          `yaml:"enable_json" mapstructure:"enable_json"`
	Compress       bool          `yaml:"compress" mapstructure:"compress"`
	CompressionMin int           `yaml:"compression_min" mapstructure:"compression_min"`
}

// EnvironmentConfig holds command environment configuration
type EnvironmentConfig struct {
	ExpandVariables   bool              `yaml:"expand_variables" mapstructure:"expand_variables"`
	FilterSensitive   bool              `yaml:"filter_sensitive" mapstructure:"filter_sensitive"`
	CustomPaths       []string          `yaml:"custom_paths" mapstructure:"custom_paths"`
	DefaultShell      string            `yaml:"default_shell" mapstructure:"default_shell"`
	DefaultUser       string            `yaml:"default_user" mapstructure:"default_user"`
	SensitivePatterns []string          `yaml:"sensitive_patterns" mapstructure:"sensitive_patterns"`
}

// ResourcesConfig holds resources-related configuration
type ResourcesConfig struct {
	MaxFileSize   int64 `yaml:"max_file_size" mapstructure:"max_file_size"`
	MaxFiles      int   `yaml:"max_files" mapstructure:"max_files"`
	TempDir       string `yaml:"temp_dir" mapstructure:"temp_dir"`
	CacheDir      string `yaml:"cache_dir" mapstructure:"cache_dir"`
	CleanupOnExit bool   `yaml:"cleanup_on_exit" mapstructure:"cleanup_on_exit"`
}

// Default configuration values
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Name:         "SandboxRunner MCP Server",
			Version:      "1.0.0",
			Protocol:     "stdio",
			Address:      "localhost",
			Port:         3000,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			EnableHTTP:   false,
		},
		Sandbox: SandboxConfig{
			WorkspaceDir: "/tmp/sandboxrunner/workspaces",
			DatabasePath: "/tmp/sandboxrunner/sandboxes.db",
			DefaultImage: "ubuntu:22.04",
			DefaultResources: ResourceLimits{
				CPULimit:    "1.0",
				MemoryLimit: "1G",
				DiskLimit:   "10G",
			},
			Environment: map[string]string{
				"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			},
			NetworkMode:      "none",
			EnableLogging:    true,
			CleanupInterval:  5 * time.Minute,
			MaxSandboxes:     10,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "json",
			OutputFile: "",
			MaxSize:    100,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		},
		Tools: ToolsConfig{
			EnabledTools: []string{
				"create_sandbox",
				"list_sandboxes",
				"terminate_sandbox",
				"exec_command",
				"run_code",
				"upload_file",
				"download_file",
				"list_files",
				"read_file",
				"write_file",
			},
			DisabledTools:     []string{},
			DefaultTimeout:    30 * time.Second,
			MaxOutputSize:     1024 * 1024, // 1MB
			CustomTools:       map[string]string{},
			ValidationLevel:   "strict",
			EnableStreaming:   true,
			EnableCaching:     true,
			CacheConfig: CacheConfig{
				DatabasePath:     "/tmp/sandboxrunner/command_cache.db",
				MaxEntries:       10000,
				DefaultTTL:       24 * time.Hour,
				CleanupInterval:  1 * time.Hour,
				CompressionLevel: 6,
				CompressionMin:   1024,
				EnableWarming:    true,
				WarmCommands: []string{
					"ls -la", "pwd", "whoami", "date", "ps aux",
					"df -h", "free -m", "uptime", "env", "uname -a",
				},
				MaxCacheSize: 100 * 1024 * 1024, // 100MB
			},
			StreamConfig: StreamConfig{
				BufferSize:     64 * 1024, // 64KB
				FlushInterval:  100 * time.Millisecond,
				MaxChunkSize:   32 * 1024, // 32KB
				EnableANSI:     true,
				FilterANSI:     false,
				DetectProgress: true,
				EnableJSON:     true,
				Compress:       true,
				CompressionMin: 1024,
			},
			EnvironmentConfig: EnvironmentConfig{
				ExpandVariables: true,
				FilterSensitive: true,
				CustomPaths:     []string{},
				DefaultShell:    "/bin/bash",
				DefaultUser:     "root",
				SensitivePatterns: []string{
					"PASSWORD", "SECRET", "TOKEN", "API_KEY",
					"PRIVATE_KEY", "SSH_KEY", "DATABASE_URL",
				},
			},
		},
		Resources: ResourcesConfig{
			MaxFileSize:   10 * 1024 * 1024, // 10MB
			MaxFiles:      1000,
			TempDir:       "/tmp/sandboxrunner/temp",
			CacheDir:      "/tmp/sandboxrunner/cache",
			CleanupOnExit: true,
		},
	}
}

// LoadConfig loads configuration from files and environment variables
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()
	
	// Initialize viper
	v := viper.New()
	
	// Set config file path if provided
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Search for config file in common locations
		v.SetConfigName("mcp-sandboxd")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("./config")
		v.AddConfigPath("$HOME/.config/sandboxrunner")
		v.AddConfigPath("/etc/sandboxrunner")
	}
	
	// Environment variable settings
	v.SetEnvPrefix("SANDBOXRUNNER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	
	// Read config file if it exists
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK, we'll use defaults
	}
	
	// Unmarshal into config struct
	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return config, nil
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(configPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Marshal config to YAML
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Validate server config
	if c.Server.Name == "" {
		return fmt.Errorf("server name cannot be empty")
	}
	
	if c.Server.Protocol != "stdio" && c.Server.Protocol != "http" {
		return fmt.Errorf("invalid protocol: %s (must be 'stdio' or 'http')", c.Server.Protocol)
	}
	
	if c.Server.EnableHTTP && (c.Server.Port < 1 || c.Server.Port > 65535) {
		return fmt.Errorf("invalid port: %d (must be between 1 and 65535)", c.Server.Port)
	}
	
	// Validate sandbox config
	if c.Sandbox.WorkspaceDir == "" {
		return fmt.Errorf("sandbox workspace directory cannot be empty")
	}
	
	if c.Sandbox.DatabasePath == "" {
		return fmt.Errorf("sandbox database path cannot be empty")
	}
	
	if c.Sandbox.DefaultImage == "" {
		return fmt.Errorf("default sandbox image cannot be empty")
	}
	
	if c.Sandbox.MaxSandboxes < 1 {
		return fmt.Errorf("max sandboxes must be at least 1")
	}
	
	// Validate logging config
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid log level: %s (must be debug, info, warn, or error)", c.Logging.Level)
	}
	
	validFormats := map[string]bool{
		"json": true, "text": true, "console": true,
	}
	if !validFormats[c.Logging.Format] {
		return fmt.Errorf("invalid log format: %s (must be json, text, or console)", c.Logging.Format)
	}
	
	// Validate tools config
	if c.Tools.DefaultTimeout <= 0 {
		return fmt.Errorf("default tool timeout must be positive")
	}
	
	if c.Tools.MaxOutputSize < 1024 {
		return fmt.Errorf("max output size must be at least 1024 bytes")
	}
	
	validValidationLevels := map[string]bool{
		"strict": true, "moderate": true, "permissive": true,
	}
	if !validValidationLevels[c.Tools.ValidationLevel] {
		return fmt.Errorf("invalid validation level: %s (must be strict, moderate, or permissive)", c.Tools.ValidationLevel)
	}
	
	// Validate resources config
	if c.Resources.MaxFileSize < 1024 {
		return fmt.Errorf("max file size must be at least 1024 bytes")
	}
	
	if c.Resources.MaxFiles < 1 {
		return fmt.Errorf("max files must be at least 1")
	}
	
	return nil
}

// IsToolEnabled checks if a tool is enabled
func (c *Config) IsToolEnabled(toolName string) bool {
	// Check if explicitly disabled
	for _, disabled := range c.Tools.DisabledTools {
		if disabled == toolName {
			return false
		}
	}
	
	// If enabled tools list is empty, all tools are enabled by default
	if len(c.Tools.EnabledTools) == 0 {
		return true
	}
	
	// Check if explicitly enabled
	for _, enabled := range c.Tools.EnabledTools {
		if enabled == toolName {
			return true
		}
	}
	
	return false
}

// GetEnabledTools returns the list of enabled tools
func (c *Config) GetEnabledTools() []string {
	if len(c.Tools.EnabledTools) == 0 {
		// Return all default tools minus disabled ones
		defaultTools := []string{
			"create_sandbox",
			"list_sandboxes",
			"terminate_sandbox",
			"exec_command",
			"run_code",
			"upload_file",
			"download_file",
			"list_files",
			"read_file",
			"write_file",
		}
		
		var enabled []string
		for _, tool := range defaultTools {
			if c.IsToolEnabled(tool) {
				enabled = append(enabled, tool)
			}
		}
		return enabled
	}
	
	// Return explicitly enabled tools minus disabled ones
	var enabled []string
	for _, tool := range c.Tools.EnabledTools {
		if c.IsToolEnabled(tool) {
			enabled = append(enabled, tool)
		}
	}
	return enabled
}

// CreateDirectories creates necessary directories based on configuration
func (c *Config) CreateDirectories() error {
	dirs := []string{
		c.Sandbox.WorkspaceDir,
		c.Resources.TempDir,
		c.Resources.CacheDir,
	}
	
	// Add log file directory if specified
	if c.Logging.OutputFile != "" {
		dirs = append(dirs, filepath.Dir(c.Logging.OutputFile))
	}
	
	// Add database directory
	if c.Sandbox.DatabasePath != "" {
		dirs = append(dirs, filepath.Dir(c.Sandbox.DatabasePath))
	}
	
	for _, dir := range dirs {
		if dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
	}
	
	return nil
}