package resources

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// CPUController manages CPU resource limiting and monitoring
type CPUController struct {
	mu             sync.RWMutex
	cgroupVersion  int
	cgroupRoot     string
	subsystemPath  string // For cgroup v1
	defaultPeriod  int64   // Default CPU period in microseconds (100ms)
	containers     map[string]*CPULimits
	metrics        map[string]*CPUMetrics
	metricsHistory map[string][]*CPUMetrics
	maxHistorySize int
}

// CPULimits defines comprehensive CPU resource limits
type CPULimits struct {
	// CPU percentage (0-100 * number of cores)
	CPUPercent *float64 `json:"cpu_percent,omitempty"`
	
	// CPU shares (relative weight, 2-262144, default 1024)
	Shares *int64 `json:"shares,omitempty"`
	
	// CPU quota in microseconds per period
	Quota *int64 `json:"quota,omitempty"`
	
	// CPU period in microseconds (1000-1000000, default 100000)
	Period *int64 `json:"period,omitempty"`
	
	// CPU cores the container can use (e.g., "0-3" or "1,3")
	Cpuset *string `json:"cpuset,omitempty"`
	
	// CPU cores memory nodes (NUMA) 
	CpusetMems *string `json:"cpuset_mems,omitempty"`
	
	// CPU idle time enforcement
	Idle *bool `json:"idle,omitempty"`
	
	// CPU real-time settings
	RealtimePeriod  *int64 `json:"realtime_period,omitempty"`
	RealtimeRuntime *int64 `json:"realtime_runtime,omitempty"`
	
	// CPU burst allowance (cgroup v2)
	BurstAllowance *int64 `json:"burst_allowance,omitempty"`
	
	// CPU weight (cgroup v2, 1-10000, equivalent to shares)
	Weight *int64 `json:"weight,omitempty"`
}

// CPUMetrics holds CPU usage and throttling metrics
type CPUMetrics struct {
	ContainerID     string    `json:"container_id"`
	Timestamp       time.Time `json:"timestamp"`
	
	// Usage metrics
	UsagePercent    float64   `json:"usage_percent"`
	UsageNanos      int64     `json:"usage_nanos"`
	SystemNanos     int64     `json:"system_nanos"`
	UserNanos       int64     `json:"user_nanos"`
	
	// Throttling metrics
	ThrottleCount   int64     `json:"throttle_count"`
	ThrottleTime    int64     `json:"throttle_time_nanos"`
	
	// Per-core usage
	PerCoreUsage    []int64   `json:"per_core_usage"`
	
	// Configuration at time of measurement
	Shares          int64     `json:"shares"`
	Quota           int64     `json:"quota"`
	Period          int64     `json:"period"`
	
	// Load averages
	LoadAverage1    float64   `json:"load_average_1m"`
	LoadAverage5    float64   `json:"load_average_5m"`
	LoadAverage15   float64   `json:"load_average_15m"`
}

// CPUStats holds detailed CPU statistics
type CPUStats struct {
	CPUUsage        CPUUsageStats    `json:"cpu_usage"`
	ThrottlingData  ThrottlingStats  `json:"throttling_data"`
	PerCPUUsage     []int64          `json:"percpu_usage"`
	SystemUsage     int64            `json:"system_usage"`
}

// CPUUsageStats holds CPU usage statistics
type CPUUsageStats struct {
	TotalUsage        int64   `json:"total_usage"`
	UsageInKernelmode int64   `json:"usage_in_kernelmode"`
	UsageInUsermode   int64   `json:"usage_in_usermode"`
}

// ThrottlingStats holds CPU throttling statistics
type ThrottlingStats struct {
	Periods          int64 `json:"periods"`
	ThrottledPeriods int64 `json:"throttled_periods"`
	ThrottledTime    int64 `json:"throttled_time"`
}

// NewCPUController creates a new CPU resource controller
func NewCPUController(cgroupVersion int, cgroupRoot string) *CPUController {
	controller := &CPUController{
		cgroupVersion:  cgroupVersion,
		cgroupRoot:     cgroupRoot,
		defaultPeriod:  100000, // 100ms default period
		containers:     make(map[string]*CPULimits),
		metrics:        make(map[string]*CPUMetrics),
		metricsHistory: make(map[string][]*CPUMetrics),
		maxHistorySize: 100, // Keep last 100 measurements
	}
	
	if cgroupVersion == 1 {
		controller.subsystemPath = filepath.Join(cgroupRoot, "cpu")
	}
	
	log.Info().
		Int("cgroup_version", cgroupVersion).
		Str("cgroup_root", cgroupRoot).
		Msg("CPU controller initialized")
	
	return controller
}

// ApplyCPULimits applies CPU limits to a container
func (c *CPUController) ApplyCPULimits(containerID string, limits *CPULimits) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Interface("limits", limits).Msg("Applying CPU limits")
	
	// Validate limits
	if err := c.validateCPULimits(limits); err != nil {
		return fmt.Errorf("invalid CPU limits: %w", err)
	}
	
	// Calculate quota from percentage if provided
	if limits.CPUPercent != nil && limits.Quota == nil {
		period := c.defaultPeriod
		if limits.Period != nil {
			period = *limits.Period
		}
		quota := int64(*limits.CPUPercent / 100.0 * float64(period))
		limits.Quota = &quota
		limits.Period = &period
	}
	
	cgroupPath := c.getContainerCgroupPath(containerID)
	
	// Create cgroup if it doesn't exist
	if err := c.createCPUCgroup(cgroupPath); err != nil {
		return fmt.Errorf("failed to create CPU cgroup: %w", err)
	}
	
	// Apply limits based on cgroup version
	if c.cgroupVersion == 2 {
		if err := c.applyCPULimitsV2(cgroupPath, limits); err != nil {
			return fmt.Errorf("failed to apply CPU limits v2: %w", err)
		}
	} else {
		if err := c.applyCPULimitsV1(cgroupPath, limits); err != nil {
			return fmt.Errorf("failed to apply CPU limits v1: %w", err)
		}
	}
	
	// Store limits for monitoring
	c.mu.Lock()
	c.containers[containerID] = limits
	c.mu.Unlock()
	
	logger.Info().
		Interface("applied_limits", limits).
		Msg("CPU limits applied successfully")
	
	return nil
}

// GetCPUUsage gets current CPU usage metrics for a container
func (c *CPUController) GetCPUUsage(containerID string) (*CPUMetrics, error) {
	cgroupPath := c.getContainerCgroupPath(containerID)
	
	metrics := &CPUMetrics{
		ContainerID: containerID,
		Timestamp:   time.Now(),
	}
	
	if c.cgroupVersion == 2 {
		if err := c.getCPUUsageV2(cgroupPath, metrics); err != nil {
			return nil, fmt.Errorf("failed to get CPU usage v2: %w", err)
		}
	} else {
		if err := c.getCPUUsageV1(cgroupPath, metrics); err != nil {
			return nil, fmt.Errorf("failed to get CPU usage v1: %w", err)
		}
	}
	
	// Calculate load averages
	c.calculateLoadAverages(containerID, metrics)
	
	// Store metrics for history
	c.storeMetrics(containerID, metrics)
	
	return metrics, nil
}

// GetCPUStats gets detailed CPU statistics for a container
func (c *CPUController) GetCPUStats(containerID string) (*CPUStats, error) {
	cgroupPath := c.getContainerCgroupPath(containerID)
	
	if c.cgroupVersion == 2 {
		return c.getCPUStatsV2(cgroupPath)
	}
	return c.getCPUStatsV1(cgroupPath)
}

// GetCPUThrottleMetrics gets CPU throttling metrics
func (c *CPUController) GetCPUThrottleMetrics(containerID string) (*ThrottlingStats, error) {
	cgroupPath := c.getContainerCgroupPath(containerID)
	
	if c.cgroupVersion == 2 {
		return c.getThrottleMetricsV2(cgroupPath)
	}
	return c.getThrottleMetricsV1(cgroupPath)
}

// SetCPUPinning pins container to specific CPU cores
func (c *CPUController) SetCPUPinning(containerID string, cpus string, mems string) error {
	logger := log.With().
		Str("container_id", containerID).
		Str("cpus", cpus).
		Str("mems", mems).
		Logger()
	
	logger.Debug().Msg("Setting CPU pinning")
	
	cgroupPath := c.getContainerCgroupPath(containerID)
	
	if c.cgroupVersion == 2 {
		// Set CPU cores
		if cpus != "" {
			if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpuset.cpus"), cpus); err != nil {
				return fmt.Errorf("failed to set CPU cores: %w", err)
			}
		}
		
		// Set memory nodes
		if mems != "" {
			if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpuset.mems"), mems); err != nil {
				return fmt.Errorf("failed to set memory nodes: %w", err)
			}
		}
	} else {
		// cgroup v1 has separate cpuset subsystem
		cpusetPath := filepath.Join(c.cgroupRoot, "cpuset", "sandboxrunner", containerID)
		
		if err := os.MkdirAll(cpusetPath, 0755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to create cpuset cgroup: %w", err)
		}
		
		if cpus != "" {
			if err := c.writeCgroupFile(filepath.Join(cpusetPath, "cpuset.cpus"), cpus); err != nil {
				return fmt.Errorf("failed to set CPU cores: %w", err)
			}
		}
		
		if mems != "" {
			if err := c.writeCgroupFile(filepath.Join(cpusetPath, "cpuset.mems"), mems); err != nil {
				return fmt.Errorf("failed to set memory nodes: %w", err)
			}
		}
	}
	
	logger.Info().Msg("CPU pinning configured successfully")
	return nil
}

// GetCPUHistory gets CPU metrics history for a container
func (c *CPUController) GetCPUHistory(containerID string) []*CPUMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	history := c.metricsHistory[containerID]
	if history == nil {
		return []*CPUMetrics{}
	}
	
	// Return a copy to avoid race conditions
	result := make([]*CPUMetrics, len(history))
	copy(result, history)
	return result
}

// RemoveCPULimits removes CPU limits for a container
func (c *CPUController) RemoveCPULimits(containerID string) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Msg("Removing CPU limits")
	
	cgroupPath := c.getContainerCgroupPath(containerID)
	
	// Remove cgroup
	if err := c.removeCPUCgroup(cgroupPath); err != nil {
		logger.Warn().Err(err).Msg("Failed to remove CPU cgroup")
	}
	
	// Remove from tracking
	c.mu.Lock()
	delete(c.containers, containerID)
	delete(c.metrics, containerID)
	delete(c.metricsHistory, containerID)
	c.mu.Unlock()
	
	logger.Debug().Msg("CPU limits removed")
	return nil
}

// Private helper methods

func (c *CPUController) validateCPULimits(limits *CPULimits) error {
	if limits.CPUPercent != nil && (*limits.CPUPercent < 0 || *limits.CPUPercent > 800) { // 8 cores max
		return fmt.Errorf("CPU percentage must be between 0 and 800")
	}
	
	if limits.Shares != nil && (*limits.Shares < 2 || *limits.Shares > 262144) {
		return fmt.Errorf("CPU shares must be between 2 and 262144")
	}
	
	if limits.Period != nil && (*limits.Period < 1000 || *limits.Period > 1000000) {
		return fmt.Errorf("CPU period must be between 1000 and 1000000 microseconds")
	}
	
	if limits.Quota != nil && limits.Period != nil && *limits.Quota > *limits.Period*8 {
		return fmt.Errorf("CPU quota cannot exceed 8 times the period")
	}
	
	if limits.Weight != nil && (*limits.Weight < 1 || *limits.Weight > 10000) {
		return fmt.Errorf("CPU weight must be between 1 and 10000")
	}
	
	return nil
}

func (c *CPUController) getContainerCgroupPath(containerID string) string {
	if c.cgroupVersion == 2 {
		return filepath.Join(c.cgroupRoot, "sandboxrunner", containerID)
	}
	return filepath.Join(c.subsystemPath, "sandboxrunner", containerID)
}

func (c *CPUController) createCPUCgroup(cgroupPath string) error {
	if err := os.MkdirAll(cgroupPath, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create cgroup directory: %w", err)
	}
	return nil
}

func (c *CPUController) removeCPUCgroup(cgroupPath string) error {
	return os.RemoveAll(cgroupPath)
}

func (c *CPUController) applyCPULimitsV1(cgroupPath string, limits *CPULimits) error {
	// Set CPU shares
	if limits.Shares != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.shares"), 
			strconv.FormatInt(*limits.Shares, 10)); err != nil {
			return fmt.Errorf("failed to set CPU shares: %w", err)
		}
	}
	
	// Set CPU period
	if limits.Period != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.cfs_period_us"), 
			strconv.FormatInt(*limits.Period, 10)); err != nil {
			return fmt.Errorf("failed to set CPU period: %w", err)
		}
	}
	
	// Set CPU quota
	if limits.Quota != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.cfs_quota_us"), 
			strconv.FormatInt(*limits.Quota, 10)); err != nil {
			return fmt.Errorf("failed to set CPU quota: %w", err)
		}
	}
	
	// Set real-time settings
	if limits.RealtimePeriod != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.rt_period_us"), 
			strconv.FormatInt(*limits.RealtimePeriod, 10)); err != nil {
			return fmt.Errorf("failed to set CPU RT period: %w", err)
		}
	}
	
	if limits.RealtimeRuntime != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.rt_runtime_us"), 
			strconv.FormatInt(*limits.RealtimeRuntime, 10)); err != nil {
			return fmt.Errorf("failed to set CPU RT runtime: %w", err)
		}
	}
	
	return nil
}

func (c *CPUController) applyCPULimitsV2(cgroupPath string, limits *CPULimits) error {
	// Set CPU weight (equivalent to shares)
	if limits.Weight != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.weight"), 
			strconv.FormatInt(*limits.Weight, 10)); err != nil {
			return fmt.Errorf("failed to set CPU weight: %w", err)
		}
	} else if limits.Shares != nil {
		// Convert shares to weight for cgroup v2
		weight := (*limits.Shares * 10000) / 1024
		if weight < 1 {
			weight = 1
		} else if weight > 10000 {
			weight = 10000
		}
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.weight"), 
			strconv.FormatInt(weight, 10)); err != nil {
			return fmt.Errorf("failed to set CPU weight: %w", err)
		}
	}
	
	// Set CPU max (quota and period)
	if limits.Quota != nil && limits.Period != nil {
		maxValue := fmt.Sprintf("%d %d", *limits.Quota, *limits.Period)
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.max"), maxValue); err != nil {
			return fmt.Errorf("failed to set CPU max: %w", err)
		}
	} else if limits.Quota != nil {
		maxValue := fmt.Sprintf("%d %d", *limits.Quota, c.defaultPeriod)
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.max"), maxValue); err != nil {
			return fmt.Errorf("failed to set CPU max: %w", err)
		}
	}
	
	// Set CPU burst allowance (cgroup v2 feature)
	if limits.BurstAllowance != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpu.max.burst"), 
			strconv.FormatInt(*limits.BurstAllowance, 10)); err != nil {
			return fmt.Errorf("failed to set CPU burst allowance: %w", err)
		}
	}
	
	// Set CPU pinning
	if limits.Cpuset != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpuset.cpus"), *limits.Cpuset); err != nil {
			return fmt.Errorf("failed to set CPU set: %w", err)
		}
	}
	
	if limits.CpusetMems != nil {
		if err := c.writeCgroupFile(filepath.Join(cgroupPath, "cpuset.mems"), *limits.CpusetMems); err != nil {
			return fmt.Errorf("failed to set CPU memory nodes: %w", err)
		}
	}
	
	return nil
}

func (c *CPUController) getCPUUsageV1(cgroupPath string, metrics *CPUMetrics) error {
	// Read CPU usage statistics
	usageFile := filepath.Join(cgroupPath, "cpuacct.usage")
	if usageStr, err := c.readCgroupFile(usageFile); err == nil {
		if usage, err := strconv.ParseInt(usageStr, 10, 64); err == nil {
			metrics.UsageNanos = usage
		}
	}
	
	// Read per-CPU usage
	perCPUFile := filepath.Join(cgroupPath, "cpuacct.usage_percpu")
	if perCPUStr, err := c.readCgroupFile(perCPUFile); err == nil {
		cpuUsages := strings.Fields(perCPUStr)
		metrics.PerCoreUsage = make([]int64, len(cpuUsages))
		for i, usageStr := range cpuUsages {
			if usage, err := strconv.ParseInt(usageStr, 10, 64); err == nil {
				metrics.PerCoreUsage[i] = usage
			}
		}
	}
	
	// Read CPU statistics
	statFile := filepath.Join(cgroupPath, "cpuacct.stat")
	if statStr, err := c.readCgroupFile(statFile); err == nil {
		c.parseCPUStatV1(statStr, metrics)
	}
	
	// Read throttling data
	throttleFile := filepath.Join(cgroupPath, "cpu.stat")
	if throttleStr, err := c.readCgroupFile(throttleFile); err == nil {
		c.parseThrottleDataV1(throttleStr, metrics)
	}
	
	// Read current limits for context
	c.getCurrentLimitsV1(cgroupPath, metrics)
	
	return nil
}

func (c *CPUController) getCPUUsageV2(cgroupPath string, metrics *CPUMetrics) error {
	// Read CPU statistics
	statFile := filepath.Join(cgroupPath, "cpu.stat")
	if statStr, err := c.readCgroupFile(statFile); err == nil {
		c.parseCPUStatV2(statStr, metrics)
	}
	
	// Read current limits for context
	c.getCurrentLimitsV2(cgroupPath, metrics)
	
	return nil
}

func (c *CPUController) getCPUStatsV1(cgroupPath string) (*CPUStats, error) {
	stats := &CPUStats{}
	
	// Read usage statistics
	if usageStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpuacct.usage")); err == nil {
		if usage, err := strconv.ParseInt(usageStr, 10, 64); err == nil {
			stats.CPUUsage.TotalUsage = usage
		}
	}
	
	// Read user/system usage
	if statStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpuacct.stat")); err == nil {
		lines := strings.Split(statStr, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				value, _ := strconv.ParseInt(fields[1], 10, 64)
				switch fields[0] {
				case "user":
					stats.CPUUsage.UsageInUsermode = value
				case "system":
					stats.CPUUsage.UsageInKernelmode = value
				}
			}
		}
	}
	
	// Read per-CPU usage
	if perCPUStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpuacct.usage_percpu")); err == nil {
		cpuUsages := strings.Fields(perCPUStr)
		stats.PerCPUUsage = make([]int64, len(cpuUsages))
		for i, usageStr := range cpuUsages {
			if usage, err := strconv.ParseInt(usageStr, 10, 64); err == nil {
				stats.PerCPUUsage[i] = usage
			}
		}
	}
	
	// Read throttling data
	if throttleStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpu.stat")); err == nil {
		c.parseThrottleStatsV1(throttleStr, &stats.ThrottlingData)
	}
	
	return stats, nil
}

func (c *CPUController) getCPUStatsV2(cgroupPath string) (*CPUStats, error) {
	stats := &CPUStats{}
	
	// Read CPU statistics
	if statStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpu.stat")); err == nil {
		c.parseCPUStatsV2(statStr, stats)
	}
	
	return stats, nil
}

func (c *CPUController) getThrottleMetricsV1(cgroupPath string) (*ThrottlingStats, error) {
	throttling := &ThrottlingStats{}
	
	throttleFile := filepath.Join(cgroupPath, "cpu.stat")
	if throttleStr, err := c.readCgroupFile(throttleFile); err == nil {
		c.parseThrottleStatsV1(throttleStr, throttling)
	}
	
	return throttling, nil
}

func (c *CPUController) getThrottleMetricsV2(cgroupPath string) (*ThrottlingStats, error) {
	throttling := &ThrottlingStats{}
	
	statFile := filepath.Join(cgroupPath, "cpu.stat")
	if statStr, err := c.readCgroupFile(statFile); err == nil {
		lines := strings.Split(statStr, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				value, _ := strconv.ParseInt(fields[1], 10, 64)
				switch fields[0] {
				case "nr_periods":
					throttling.Periods = value
				case "nr_throttled":
					throttling.ThrottledPeriods = value
				case "throttled_usec":
					throttling.ThrottledTime = value * 1000 // Convert to nanoseconds
				}
			}
		}
	}
	
	return throttling, nil
}

func (c *CPUController) parseCPUStatV1(statStr string, metrics *CPUMetrics) {
	lines := strings.Split(statStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "user":
				metrics.UserNanos = value * 10000000 // Convert from USER_HZ to nanoseconds
			case "system":
				metrics.SystemNanos = value * 10000000
			}
		}
	}
}

func (c *CPUController) parseCPUStatV2(statStr string, metrics *CPUMetrics) {
	lines := strings.Split(statStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "usage_usec":
				metrics.UsageNanos = value * 1000 // Convert to nanoseconds
			case "user_usec":
				metrics.UserNanos = value * 1000
			case "system_usec":
				metrics.SystemNanos = value * 1000
			case "nr_periods":
				// Handle throttling data
			case "nr_throttled":
				metrics.ThrottleCount = value
			case "throttled_usec":
				metrics.ThrottleTime = value * 1000
			}
		}
	}
}

func (c *CPUController) parseThrottleDataV1(statStr string, metrics *CPUMetrics) {
	lines := strings.Split(statStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "nr_throttled":
				metrics.ThrottleCount = value
			case "throttled_time":
				metrics.ThrottleTime = value
			}
		}
	}
}

func (c *CPUController) parseThrottleStatsV1(statStr string, throttling *ThrottlingStats) {
	lines := strings.Split(statStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "nr_periods":
				throttling.Periods = value
			case "nr_throttled":
				throttling.ThrottledPeriods = value
			case "throttled_time":
				throttling.ThrottledTime = value
			}
		}
	}
}

func (c *CPUController) parseCPUStatsV2(statStr string, stats *CPUStats) {
	lines := strings.Split(statStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "usage_usec":
				stats.CPUUsage.TotalUsage = value * 1000
			case "user_usec":
				stats.CPUUsage.UsageInUsermode = value * 1000
			case "system_usec":
				stats.CPUUsage.UsageInKernelmode = value * 1000
			case "nr_periods":
				stats.ThrottlingData.Periods = value
			case "nr_throttled":
				stats.ThrottlingData.ThrottledPeriods = value
			case "throttled_usec":
				stats.ThrottlingData.ThrottledTime = value * 1000
			}
		}
	}
}

func (c *CPUController) getCurrentLimitsV1(cgroupPath string, metrics *CPUMetrics) {
	if sharesStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpu.shares")); err == nil {
		if shares, err := strconv.ParseInt(sharesStr, 10, 64); err == nil {
			metrics.Shares = shares
		}
	}
	
	if quotaStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpu.cfs_quota_us")); err == nil {
		if quota, err := strconv.ParseInt(quotaStr, 10, 64); err == nil {
			metrics.Quota = quota
		}
	}
	
	if periodStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpu.cfs_period_us")); err == nil {
		if period, err := strconv.ParseInt(periodStr, 10, 64); err == nil {
			metrics.Period = period
		}
	}
}

func (c *CPUController) getCurrentLimitsV2(cgroupPath string, metrics *CPUMetrics) {
	if weightStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpu.weight")); err == nil {
		if weight, err := strconv.ParseInt(weightStr, 10, 64); err == nil {
			// Convert weight back to shares equivalent for consistency
			metrics.Shares = (weight * 1024) / 10000
		}
	}
	
	if maxStr, err := c.readCgroupFile(filepath.Join(cgroupPath, "cpu.max")); err == nil {
		fields := strings.Fields(maxStr)
		if len(fields) >= 2 && fields[0] != "max" {
			if quota, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
				metrics.Quota = quota
			}
			if period, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				metrics.Period = period
			}
		}
	}
}

func (c *CPUController) calculateLoadAverages(containerID string, metrics *CPUMetrics) {
	c.mu.RLock()
	history := c.metricsHistory[containerID]
	c.mu.RUnlock()
	
	if len(history) < 2 {
		return
	}
	
	// Calculate load averages based on CPU usage history
	now := time.Now()
	var load1m, load5m, load15m []float64
	
	for _, m := range history {
		age := now.Sub(m.Timestamp)
		if age <= time.Minute {
			load1m = append(load1m, m.UsagePercent)
		}
		if age <= 5*time.Minute {
			load5m = append(load5m, m.UsagePercent)
		}
		if age <= 15*time.Minute {
			load15m = append(load15m, m.UsagePercent)
		}
	}
	
	metrics.LoadAverage1 = c.calculateAverage(load1m)
	metrics.LoadAverage5 = c.calculateAverage(load5m)
	metrics.LoadAverage15 = c.calculateAverage(load15m)
}

func (c *CPUController) calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func (c *CPUController) storeMetrics(containerID string, metrics *CPUMetrics) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.metrics[containerID] = metrics
	
	history := c.metricsHistory[containerID]
	history = append(history, metrics)
	
	// Keep only the last maxHistorySize entries
	if len(history) > c.maxHistorySize {
		history = history[len(history)-c.maxHistorySize:]
	}
	
	c.metricsHistory[containerID] = history
}

func (c *CPUController) writeCgroupFile(filePath, content string) error {
	return os.WriteFile(filePath, []byte(content), 0644)
}

func (c *CPUController) readCgroupFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// GetSystemCPUInfo gets system-wide CPU information
func GetSystemCPUInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})
	
	// Read /proc/cpuinfo
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/cpuinfo: %w", err)
	}
	defer file.Close()
	
	var cpuCount int
	processors := make([]map[string]string, 0)
	currentProc := make(map[string]string)
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if len(currentProc) > 0 {
				processors = append(processors, currentProc)
				currentProc = make(map[string]string)
				cpuCount++
			}
			continue
		}
		
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			currentProc[key] = value
		}
	}
	
	if len(currentProc) > 0 {
		processors = append(processors, currentProc)
		cpuCount++
	}
	
	info["cpu_count"] = cpuCount
	info["processors"] = processors
	
	// Read load average
	if loadavg, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(loadavg))
		if len(fields) >= 3 {
			info["load_average_1m"] = fields[0]
			info["load_average_5m"] = fields[1]
			info["load_average_15m"] = fields[2]
		}
	}
	
	return info, nil
}