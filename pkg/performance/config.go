package performance

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/viper"
)

// Config holds performance testing configuration
type Config struct {
	// General settings
	OutputDir       string        `mapstructure:"output_dir"`
	TempDir         string        `mapstructure:"temp_dir"`
	LogLevel        string        `mapstructure:"log_level"`
	TestTimeout     time.Duration `mapstructure:"test_timeout"`
	
	// Container settings
	ContainerImage  string `mapstructure:"container_image"`
	NetworkMode     string `mapstructure:"network_mode"`
	
	// Resource limits
	DefaultCPULimit    string `mapstructure:"default_cpu_limit"`
	DefaultMemoryLimit string `mapstructure:"default_memory_limit"`
	DefaultDiskLimit   string `mapstructure:"default_disk_limit"`
	
	// Performance targets
	Targets PerformanceTargets `mapstructure:"targets"`
	
	// Test settings
	Benchmarks BenchmarkConfig `mapstructure:"benchmarks"`
	LoadTests  LoadTestConfig  `mapstructure:"load_tests"`
	Memory     MemoryConfig    `mapstructure:"memory"`
	Profiling  ProfilingConfig `mapstructure:"profiling"`
}

// PerformanceTargets defines the performance goals
type PerformanceTargets struct {
	ContainerStartupMs    int     `mapstructure:"container_startup_ms"`
	CommandOverheadMs     int     `mapstructure:"command_overhead_ms"`
	MemoryPerSandboxMB    float64 `mapstructure:"memory_per_sandbox_mb"`
	MaxConcurrentSandboxes int    `mapstructure:"max_concurrent_sandboxes"`
	APIResponseP99Ms      int     `mapstructure:"api_response_p99_ms"`
	ThroughputRPS         float64 `mapstructure:"throughput_rps"`
	ErrorRatePercent      float64 `mapstructure:"error_rate_percent"`
}

// BenchmarkConfig holds benchmark test configuration
type BenchmarkConfig struct {
	Enabled               bool          `mapstructure:"enabled"`
	Iterations            int           `mapstructure:"iterations"`
	WarmupIterations      int           `mapstructure:"warmup_iterations"`
	TestContainerLifecycle bool         `mapstructure:"test_container_lifecycle"`
	TestToolExecution     bool          `mapstructure:"test_tool_execution"`
	TestLanguageExecution bool          `mapstructure:"test_language_execution"`
	TestFileOperations    bool          `mapstructure:"test_file_operations"`
	TestConcurrency       bool          `mapstructure:"test_concurrency"`
	MaxConcurrency        int           `mapstructure:"max_concurrency"`
	BenchmarkTimeout      time.Duration `mapstructure:"benchmark_timeout"`
}

// LoadTestConfig holds load test configuration
type LoadTestConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	SustainedLoad     bool          `mapstructure:"sustained_load"`
	BurstTraffic      bool          `mapstructure:"burst_traffic"`
	MemoryPressure    bool          `mapstructure:"memory_pressure"`
	ResourceExhaustion bool         `mapstructure:"resource_exhaustion"`
	LongRunningOps    bool          `mapstructure:"long_running_ops"`
	
	// Sustained load settings
	SustainedDuration    time.Duration `mapstructure:"sustained_duration"`
	SustainedConcurrency int           `mapstructure:"sustained_concurrency"`
	
	// Burst settings
	BurstSize        int           `mapstructure:"burst_size"`
	BurstDuration    time.Duration `mapstructure:"burst_duration"`
	BurstRestPeriod  time.Duration `mapstructure:"burst_rest_period"`
	NumBursts        int           `mapstructure:"num_bursts"`
	
	// Memory pressure settings
	MemoryTestSandboxes  int    `mapstructure:"memory_test_sandboxes"`
	MemoryPerSandbox     string `mapstructure:"memory_per_sandbox"`
	
	// Long-running operation settings
	LongRunningDuration time.Duration `mapstructure:"long_running_duration"`
}

// MemoryConfig holds memory testing configuration
type MemoryConfig struct {
	Enabled               bool          `mapstructure:"enabled"`
	LeakDetection         bool          `mapstructure:"leak_detection"`
	GoroutineLeakDetection bool         `mapstructure:"goroutine_leak_detection"`
	ConcurrentMemoryTest  bool          `mapstructure:"concurrent_memory_test"`
	LargeDataHandling     bool          `mapstructure:"large_data_handling"`
	
	// Memory monitoring
	ProfileInterval     time.Duration `mapstructure:"profile_interval"`
	GCBeforeTest        bool          `mapstructure:"gc_before_test"`
	
	// Test data sizes
	SmallDataSizeKB     int `mapstructure:"small_data_size_kb"`
	MediumDataSizeKB    int `mapstructure:"medium_data_size_kb"`
	LargeDataSizeMB     int `mapstructure:"large_data_size_mb"`
}

// ProfilingConfig holds profiling configuration
type ProfilingConfig struct {
	Enabled           bool          `mapstructure:"enabled"`
	CPUProfile        bool          `mapstructure:"cpu_profile"`
	MemoryProfile     bool          `mapstructure:"memory_profile"`
	BlockProfile      bool          `mapstructure:"block_profile"`
	MutexProfile      bool          `mapstructure:"mutex_profile"`
	GoroutineProfile  bool          `mapstructure:"goroutine_profile"`
	Trace             bool          `mapstructure:"trace"`
	
	ProfileDuration   time.Duration `mapstructure:"profile_duration"`
	OutputDir         string        `mapstructure:"output_dir"`
	AutoAnalysis      bool          `mapstructure:"auto_analysis"`
}

// DefaultConfig returns the default performance testing configuration
func DefaultConfig() *Config {
	return &Config{
		OutputDir:       filepath.Join(os.TempDir(), "sandboxrunner-perf"),
		TempDir:         os.TempDir(),
		LogLevel:        "info",
		TestTimeout:     30 * time.Minute,
		ContainerImage:  "ubuntu:22.04",
		NetworkMode:     "none",
		
		DefaultCPULimit:    "0.5",
		DefaultMemoryLimit: "128m",
		DefaultDiskLimit:   "1g",
		
		Targets: PerformanceTargets{
			ContainerStartupMs:     500,
			CommandOverheadMs:      100,
			MemoryPerSandboxMB:     50.0,
			MaxConcurrentSandboxes: 100,
			APIResponseP99Ms:       200,
			ThroughputRPS:          100.0,
			ErrorRatePercent:       5.0,
		},
		
		Benchmarks: BenchmarkConfig{
			Enabled:                true,
			Iterations:             100,
			WarmupIterations:       10,
			TestContainerLifecycle: true,
			TestToolExecution:      true,
			TestLanguageExecution:  true,
			TestFileOperations:     true,
			TestConcurrency:        true,
			MaxConcurrency:         runtime.NumCPU() * 4,
			BenchmarkTimeout:       10 * time.Minute,
		},
		
		LoadTests: LoadTestConfig{
			Enabled:            true,
			SustainedLoad:      true,
			BurstTraffic:       true,
			MemoryPressure:     true,
			ResourceExhaustion: true,
			LongRunningOps:     true,
			
			SustainedDuration:    2 * time.Minute,
			SustainedConcurrency: 50,
			
			BurstSize:       100,
			BurstDuration:   10 * time.Second,
			BurstRestPeriod: 10 * time.Second,
			NumBursts:       5,
			
			MemoryTestSandboxes: 100,
			MemoryPerSandbox:    "128m",
			
			LongRunningDuration: 5 * time.Minute,
		},
		
		Memory: MemoryConfig{
			Enabled:                true,
			LeakDetection:          true,
			GoroutineLeakDetection: true,
			ConcurrentMemoryTest:   true,
			LargeDataHandling:      true,
			
			ProfileInterval:  500 * time.Millisecond,
			GCBeforeTest:     true,
			
			SmallDataSizeKB:  1,
			MediumDataSizeKB: 10,
			LargeDataSizeMB:  1,
		},
		
		Profiling: ProfilingConfig{
			Enabled:          false, // Enable explicitly when needed
			CPUProfile:       true,
			MemoryProfile:    true,
			BlockProfile:     true,
			MutexProfile:     true,
			GoroutineProfile: true,
			Trace:            true,
			
			ProfileDuration: 2 * time.Minute,
			OutputDir:       filepath.Join(os.TempDir(), "sandboxrunner-profiles"),
			AutoAnalysis:    false,
		},
	}
}

// LoadConfig loads configuration from file or environment variables
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()
	
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		viper.SetConfigName("performance")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("/etc/sandboxrunner")
		viper.AddConfigPath("$HOME/.sandboxrunner")
	}
	
	// Environment variable support
	viper.SetEnvPrefix("PERF")
	viper.AutomaticEnv()
	
	// Try to read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is ok, we'll use defaults
	}
	
	// Unmarshal config
	if err := viper.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Validate and create directories
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return config, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Create output directories
	if err := os.MkdirAll(c.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", c.OutputDir, err)
	}
	
	if c.Profiling.OutputDir != "" {
		if err := os.MkdirAll(c.Profiling.OutputDir, 0755); err != nil {
			return fmt.Errorf("failed to create profiling output directory %s: %w", c.Profiling.OutputDir, err)
		}
	}
	
	// Validate performance targets
	if c.Targets.ContainerStartupMs <= 0 {
		return fmt.Errorf("container startup target must be positive")
	}
	
	if c.Targets.CommandOverheadMs <= 0 {
		return fmt.Errorf("command overhead target must be positive")
	}
	
	if c.Targets.MemoryPerSandboxMB <= 0 {
		return fmt.Errorf("memory per sandbox target must be positive")
	}
	
	if c.Targets.MaxConcurrentSandboxes <= 0 {
		return fmt.Errorf("max concurrent sandboxes must be positive")
	}
	
	// Validate benchmark settings
	if c.Benchmarks.Enabled {
		if c.Benchmarks.Iterations <= 0 {
			return fmt.Errorf("benchmark iterations must be positive")
		}
		
		if c.Benchmarks.MaxConcurrency <= 0 {
			c.Benchmarks.MaxConcurrency = runtime.NumCPU() * 2
		}
	}
	
	return nil
}

// GetOutputPath returns a path relative to the output directory
func (c *Config) GetOutputPath(filename string) string {
	return filepath.Join(c.OutputDir, filename)
}

// GetProfilingOutputPath returns a path relative to the profiling output directory
func (c *Config) GetProfilingOutputPath(filename string) string {
	outputDir := c.Profiling.OutputDir
	if outputDir == "" {
		outputDir = c.OutputDir
	}
	return filepath.Join(outputDir, filename)
}

// IsTestEnabled checks if a specific test type is enabled
func (c *Config) IsTestEnabled(testType string) bool {
	switch testType {
	case "benchmarks":
		return c.Benchmarks.Enabled
	case "load":
		return c.LoadTests.Enabled
	case "memory":
		return c.Memory.Enabled
	case "profiling":
		return c.Profiling.Enabled
	case "container_lifecycle":
		return c.Benchmarks.Enabled && c.Benchmarks.TestContainerLifecycle
	case "tool_execution":
		return c.Benchmarks.Enabled && c.Benchmarks.TestToolExecution
	case "language_execution":
		return c.Benchmarks.Enabled && c.Benchmarks.TestLanguageExecution
	case "file_operations":
		return c.Benchmarks.Enabled && c.Benchmarks.TestFileOperations
	case "concurrency":
		return c.Benchmarks.Enabled && c.Benchmarks.TestConcurrency
	case "sustained_load":
		return c.LoadTests.Enabled && c.LoadTests.SustainedLoad
	case "burst_traffic":
		return c.LoadTests.Enabled && c.LoadTests.BurstTraffic
	case "memory_pressure":
		return c.LoadTests.Enabled && c.LoadTests.MemoryPressure
	case "resource_exhaustion":
		return c.LoadTests.Enabled && c.LoadTests.ResourceExhaustion
	case "long_running":
		return c.LoadTests.Enabled && c.LoadTests.LongRunningOps
	case "leak_detection":
		return c.Memory.Enabled && c.Memory.LeakDetection
	case "goroutine_leak":
		return c.Memory.Enabled && c.Memory.GoroutineLeakDetection
	case "concurrent_memory":
		return c.Memory.Enabled && c.Memory.ConcurrentMemoryTest
	case "large_data":
		return c.Memory.Enabled && c.Memory.LargeDataHandling
	default:
		return false
	}
}

// GenerateConfigTemplate generates a configuration template file
func GenerateConfigTemplate(filepath string) error {
	config := DefaultConfig()
	
	viper.Set("output_dir", config.OutputDir)
	viper.Set("temp_dir", config.TempDir)
	viper.Set("log_level", config.LogLevel)
	viper.Set("test_timeout", config.TestTimeout)
	viper.Set("container_image", config.ContainerImage)
	viper.Set("network_mode", config.NetworkMode)
	viper.Set("default_cpu_limit", config.DefaultCPULimit)
	viper.Set("default_memory_limit", config.DefaultMemoryLimit)
	viper.Set("default_disk_limit", config.DefaultDiskLimit)
	
	// Performance targets
	viper.Set("targets.container_startup_ms", config.Targets.ContainerStartupMs)
	viper.Set("targets.command_overhead_ms", config.Targets.CommandOverheadMs)
	viper.Set("targets.memory_per_sandbox_mb", config.Targets.MemoryPerSandboxMB)
	viper.Set("targets.max_concurrent_sandboxes", config.Targets.MaxConcurrentSandboxes)
	viper.Set("targets.api_response_p99_ms", config.Targets.APIResponseP99Ms)
	viper.Set("targets.throughput_rps", config.Targets.ThroughputRPS)
	viper.Set("targets.error_rate_percent", config.Targets.ErrorRatePercent)
	
	// Benchmark settings
	viper.Set("benchmarks.enabled", config.Benchmarks.Enabled)
	viper.Set("benchmarks.iterations", config.Benchmarks.Iterations)
	viper.Set("benchmarks.warmup_iterations", config.Benchmarks.WarmupIterations)
	viper.Set("benchmarks.test_container_lifecycle", config.Benchmarks.TestContainerLifecycle)
	viper.Set("benchmarks.test_tool_execution", config.Benchmarks.TestToolExecution)
	viper.Set("benchmarks.test_language_execution", config.Benchmarks.TestLanguageExecution)
	viper.Set("benchmarks.test_file_operations", config.Benchmarks.TestFileOperations)
	viper.Set("benchmarks.test_concurrency", config.Benchmarks.TestConcurrency)
	viper.Set("benchmarks.max_concurrency", config.Benchmarks.MaxConcurrency)
	viper.Set("benchmarks.benchmark_timeout", config.Benchmarks.BenchmarkTimeout)
	
	// Load test settings
	viper.Set("load_tests.enabled", config.LoadTests.Enabled)
	viper.Set("load_tests.sustained_load", config.LoadTests.SustainedLoad)
	viper.Set("load_tests.burst_traffic", config.LoadTests.BurstTraffic)
	viper.Set("load_tests.memory_pressure", config.LoadTests.MemoryPressure)
	viper.Set("load_tests.resource_exhaustion", config.LoadTests.ResourceExhaustion)
	viper.Set("load_tests.long_running_ops", config.LoadTests.LongRunningOps)
	
	viper.Set("load_tests.sustained_duration", config.LoadTests.SustainedDuration)
	viper.Set("load_tests.sustained_concurrency", config.LoadTests.SustainedConcurrency)
	
	viper.Set("load_tests.burst_size", config.LoadTests.BurstSize)
	viper.Set("load_tests.burst_duration", config.LoadTests.BurstDuration)
	viper.Set("load_tests.burst_rest_period", config.LoadTests.BurstRestPeriod)
	viper.Set("load_tests.num_bursts", config.LoadTests.NumBursts)
	
	viper.Set("load_tests.memory_test_sandboxes", config.LoadTests.MemoryTestSandboxes)
	viper.Set("load_tests.memory_per_sandbox", config.LoadTests.MemoryPerSandbox)
	
	viper.Set("load_tests.long_running_duration", config.LoadTests.LongRunningDuration)
	
	// Memory settings
	viper.Set("memory.enabled", config.Memory.Enabled)
	viper.Set("memory.leak_detection", config.Memory.LeakDetection)
	viper.Set("memory.goroutine_leak_detection", config.Memory.GoroutineLeakDetection)
	viper.Set("memory.concurrent_memory_test", config.Memory.ConcurrentMemoryTest)
	viper.Set("memory.large_data_handling", config.Memory.LargeDataHandling)
	
	viper.Set("memory.profile_interval", config.Memory.ProfileInterval)
	viper.Set("memory.gc_before_test", config.Memory.GCBeforeTest)
	
	viper.Set("memory.small_data_size_kb", config.Memory.SmallDataSizeKB)
	viper.Set("memory.medium_data_size_kb", config.Memory.MediumDataSizeKB)
	viper.Set("memory.large_data_size_mb", config.Memory.LargeDataSizeMB)
	
	// Profiling settings
	viper.Set("profiling.enabled", config.Profiling.Enabled)
	viper.Set("profiling.cpu_profile", config.Profiling.CPUProfile)
	viper.Set("profiling.memory_profile", config.Profiling.MemoryProfile)
	viper.Set("profiling.block_profile", config.Profiling.BlockProfile)
	viper.Set("profiling.mutex_profile", config.Profiling.MutexProfile)
	viper.Set("profiling.goroutine_profile", config.Profiling.GoroutineProfile)
	viper.Set("profiling.trace", config.Profiling.Trace)
	
	viper.Set("profiling.profile_duration", config.Profiling.ProfileDuration)
	viper.Set("profiling.output_dir", config.Profiling.OutputDir)
	viper.Set("profiling.auto_analysis", config.Profiling.AutoAnalysis)
	
	return viper.WriteConfigAs(filepath)
}