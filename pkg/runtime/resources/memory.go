package resources

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// MemoryController manages memory resource limiting and monitoring
type MemoryController struct {
	mu               sync.RWMutex
	cgroupVersion    int
	cgroupRoot       string
	subsystemPath    string // For cgroup v1
	containers       map[string]*MemoryLimits
	metrics          map[string]*MemoryMetrics
	metricsHistory   map[string][]*MemoryMetrics
	maxHistorySize   int
	oomNotifyEnabled bool
	oomEventChan     chan OOMEvent
	pressureThresholds map[string]*MemoryPressureConfig
}

// MemoryLimits defines comprehensive memory resource limits
type MemoryLimits struct {
	// Memory limit in bytes
	Limit *int64 `json:"limit,omitempty"`
	
	// Memory soft limit (reservation) in bytes
	Reservation *int64 `json:"reservation,omitempty"`
	
	// Swap limit in bytes (memory + swap total)
	Swap *int64 `json:"swap,omitempty"`
	
	// Kernel memory limit in bytes (cgroup v1)
	Kernel *int64 `json:"kernel,omitempty"`
	
	// Kernel TCP memory limit in bytes (cgroup v1)
	KernelTCP *int64 `json:"kernel_tcp,omitempty"`
	
	// OOM killer disable flag
	DisableOOMKiller *bool `json:"disable_oom_killer,omitempty"`
	
	// Memory swappiness (0-100)
	Swappiness *int64 `json:"swappiness,omitempty"`
	
	// Use hierarchy accounting
	UseHierarchy *bool `json:"use_hierarchy,omitempty"`
	
	// Memory high watermark (cgroup v2)
	High *int64 `json:"high,omitempty"`
	
	// Memory low protection (cgroup v2)
	Low *int64 `json:"low,omitempty"`
	
	// Memory minimum protection (cgroup v2)
	Min *int64 `json:"min,omitempty"`
}

// MemoryMetrics holds comprehensive memory usage metrics
type MemoryMetrics struct {
	ContainerID     string    `json:"container_id"`
	Timestamp       time.Time `json:"timestamp"`
	
	// Basic usage
	UsageBytes      int64     `json:"usage_bytes"`
	LimitBytes      int64     `json:"limit_bytes"`
	UsagePercent    float64   `json:"usage_percent"`
	
	// Detailed memory breakdown
	RSSBytes        int64     `json:"rss_bytes"`
	CacheBytes      int64     `json:"cache_bytes"`
	BufferBytes     int64     `json:"buffer_bytes"`
	SwapBytes       int64     `json:"swap_bytes"`
	
	// Kernel memory
	KernelUsage     int64     `json:"kernel_usage"`
	KernelTCPUsage  int64     `json:"kernel_tcp_usage"`
	
	// Memory activity
	PageFaults      int64     `json:"page_faults"`
	MajorPageFaults int64     `json:"major_page_faults"`
	
	// Memory pressure
	PressureAvg10   float64   `json:"pressure_avg10"`
	PressureAvg60   float64   `json:"pressure_avg60"`
	PressureAvg300  float64   `json:"pressure_avg300"`
	PressureTotal   int64     `json:"pressure_total"`
	
	// Swap activity
	SwapIn          int64     `json:"swap_in"`
	SwapOut         int64     `json:"swap_out"`
	
	// OOM events
	OOMKillCount    int64     `json:"oom_kill_count"`
	
	// Hierarchical memory
	HierarchicalMemoryLimit int64 `json:"hierarchical_memory_limit"`
	HierarchicalMemswLimit  int64 `json:"hierarchical_memsw_limit"`
}

// MemoryStats holds detailed memory statistics
type MemoryStats struct {
	Usage             int64                  `json:"usage"`
	MaxUsage          int64                  `json:"max_usage"`
	Limit             int64                  `json:"limit"`
	Stats             map[string]int64       `json:"stats"`
	Failcnt           int64                  `json:"failcnt"`
}

// MemoryPressureConfig defines memory pressure notification configuration
type MemoryPressureConfig struct {
	Level     string `json:"level"`     // low, medium, critical
	Threshold int64  `json:"threshold"` // bytes
	EventFD   int    `json:"event_fd"`
}

// OOMEvent represents an out-of-memory event
type OOMEvent struct {
	ContainerID string    `json:"container_id"`
	Timestamp   time.Time `json:"timestamp"`
	ProcessPID  int       `json:"process_pid"`
	ProcessName string    `json:"process_name"`
	MemoryUsage int64     `json:"memory_usage"`
	MemoryLimit int64     `json:"memory_limit"`
}

// MemoryLeakDetection holds memory leak detection configuration
type MemoryLeakDetection struct {
	Enabled           bool          `json:"enabled"`
	CheckInterval     time.Duration `json:"check_interval"`
	GrowthThreshold   float64       `json:"growth_threshold"`   // Percentage growth per check
	SampleWindow      int           `json:"sample_window"`      // Number of samples to consider
	AlertThreshold    int           `json:"alert_threshold"`    // Number of consecutive alerts
}

// NewMemoryController creates a new memory resource controller
func NewMemoryController(cgroupVersion int, cgroupRoot string) *MemoryController {
	controller := &MemoryController{
		cgroupVersion:      cgroupVersion,
		cgroupRoot:         cgroupRoot,
		containers:         make(map[string]*MemoryLimits),
		metrics:            make(map[string]*MemoryMetrics),
		metricsHistory:     make(map[string][]*MemoryMetrics),
		maxHistorySize:     100,
		oomNotifyEnabled:   true,
		oomEventChan:       make(chan OOMEvent, 100),
		pressureThresholds: make(map[string]*MemoryPressureConfig),
	}
	
	if cgroupVersion == 1 {
		controller.subsystemPath = filepath.Join(cgroupRoot, "memory")
	}
	
	// Start OOM notification monitoring if enabled
	if controller.oomNotifyEnabled {
		go controller.monitorOOMEvents()
	}
	
	log.Info().
		Int("cgroup_version", cgroupVersion).
		Str("cgroup_root", cgroupRoot).
		Bool("oom_notify_enabled", controller.oomNotifyEnabled).
		Msg("Memory controller initialized")
	
	return controller
}

// ApplyMemoryLimits applies memory limits to a container
func (m *MemoryController) ApplyMemoryLimits(containerID string, limits *MemoryLimits) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Interface("limits", limits).Msg("Applying memory limits")
	
	// Validate limits
	if err := m.validateMemoryLimits(limits); err != nil {
		return fmt.Errorf("invalid memory limits: %w", err)
	}
	
	cgroupPath := m.getContainerCgroupPath(containerID)
	
	// Create cgroup if it doesn't exist
	if err := m.createMemoryCgroup(cgroupPath); err != nil {
		return fmt.Errorf("failed to create memory cgroup: %w", err)
	}
	
	// Apply limits based on cgroup version
	if m.cgroupVersion == 2 {
		if err := m.applyMemoryLimitsV2(cgroupPath, limits); err != nil {
			return fmt.Errorf("failed to apply memory limits v2: %w", err)
		}
	} else {
		if err := m.applyMemoryLimitsV1(cgroupPath, limits); err != nil {
			return fmt.Errorf("failed to apply memory limits v1: %w", err)
		}
	}
	
	// Set up OOM notification if enabled
	if m.oomNotifyEnabled {
		if err := m.setupOOMNotification(containerID, cgroupPath); err != nil {
			logger.Warn().Err(err).Msg("Failed to setup OOM notification")
		}
	}
	
	// Store limits for monitoring
	m.mu.Lock()
	m.containers[containerID] = limits
	m.mu.Unlock()
	
	logger.Info().
		Interface("applied_limits", limits).
		Msg("Memory limits applied successfully")
	
	return nil
}

// GetMemoryUsage gets current memory usage metrics for a container
func (m *MemoryController) GetMemoryUsage(containerID string) (*MemoryMetrics, error) {
	cgroupPath := m.getContainerCgroupPath(containerID)
	
	metrics := &MemoryMetrics{
		ContainerID: containerID,
		Timestamp:   time.Now(),
	}
	
	if m.cgroupVersion == 2 {
		if err := m.getMemoryUsageV2(cgroupPath, metrics); err != nil {
			return nil, fmt.Errorf("failed to get memory usage v2: %w", err)
		}
	} else {
		if err := m.getMemoryUsageV1(cgroupPath, metrics); err != nil {
			return nil, fmt.Errorf("failed to get memory usage v1: %w", err)
		}
	}
	
	// Calculate usage percentage
	if metrics.LimitBytes > 0 {
		metrics.UsagePercent = float64(metrics.UsageBytes) / float64(metrics.LimitBytes) * 100.0
	}
	
	// Get memory pressure information
	m.getMemoryPressure(cgroupPath, metrics)
	
	// Store metrics for history
	m.storeMetrics(containerID, metrics)
	
	return metrics, nil
}

// GetMemoryStats gets detailed memory statistics for a container
func (m *MemoryController) GetMemoryStats(containerID string) (*MemoryStats, error) {
	cgroupPath := m.getContainerCgroupPath(containerID)
	
	if m.cgroupVersion == 2 {
		return m.getMemoryStatsV2(cgroupPath)
	}
	return m.getMemoryStatsV1(cgroupPath)
}

// SetupMemoryPressureNotification sets up memory pressure notifications
func (m *MemoryController) SetupMemoryPressureNotification(containerID string, level string, threshold int64) error {
	logger := log.With().
		Str("container_id", containerID).
		Str("level", level).
		Int64("threshold", threshold).
		Logger()
	
	logger.Debug().Msg("Setting up memory pressure notification")
	
	cgroupPath := m.getContainerCgroupPath(containerID)
	
	// Create eventfd for notifications
	eventFD, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, 0, 0x80000, 0) // EFD_CLOEXEC = 0x80000
	if errno != 0 {
		return fmt.Errorf("failed to create eventfd: %v", errno)
	}
	
	config := &MemoryPressureConfig{
		Level:     level,
		Threshold: threshold,
		EventFD:   int(eventFD),
	}
	
	if m.cgroupVersion == 2 {
		// cgroup v2 uses pressure files
		if err := m.setupPressureNotificationV2(cgroupPath, config); err != nil {
			syscall.Close(int(eventFD))
			return fmt.Errorf("failed to setup pressure notification v2: %w", err)
		}
	} else {
		// cgroup v1 uses memory.pressure_level
		if err := m.setupPressureNotificationV1(cgroupPath, config); err != nil {
			syscall.Close(int(eventFD))
			return fmt.Errorf("failed to setup pressure notification v1: %w", err)
		}
	}
	
	m.mu.Lock()
	m.pressureThresholds[containerID] = config
	m.mu.Unlock()
	
	logger.Info().Msg("Memory pressure notification configured")
	return nil
}

// DetectMemoryLeaks analyzes memory usage patterns to detect potential leaks
func (m *MemoryController) DetectMemoryLeaks(containerID string, config *MemoryLeakDetection) (bool, error) {
	if !config.Enabled {
		return false, nil
	}
	
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	m.mu.RLock()
	history := m.metricsHistory[containerID]
	m.mu.RUnlock()
	
	if len(history) < config.SampleWindow {
		return false, nil // Not enough samples
	}
	
	// Get recent samples
	recentHistory := history[len(history)-config.SampleWindow:]
	
	// Calculate memory growth trend
	var growthRates []float64
	for i := 1; i < len(recentHistory); i++ {
		prev := recentHistory[i-1]
		curr := recentHistory[i]
		
		if prev.UsageBytes > 0 {
			growthRate := float64(curr.UsageBytes-prev.UsageBytes) / float64(prev.UsageBytes) * 100.0
			growthRates = append(growthRates, growthRate)
		}
	}
	
	// Check if growth rate consistently exceeds threshold
	exceedCount := 0
	for _, rate := range growthRates {
		if rate > config.GrowthThreshold {
			exceedCount++
		}
	}
	
	isLeaking := exceedCount >= config.AlertThreshold
	
	if isLeaking {
		logger.Warn().
			Float64("avg_growth_rate", m.calculateAverage(growthRates)).
			Float64("threshold", config.GrowthThreshold).
			Int("exceed_count", exceedCount).
			Int("alert_threshold", config.AlertThreshold).
			Msg("Potential memory leak detected")
	}
	
	return isLeaking, nil
}

// GetMemoryHistory gets memory metrics history for a container
func (m *MemoryController) GetMemoryHistory(containerID string) []*MemoryMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	history := m.metricsHistory[containerID]
	if history == nil {
		return []*MemoryMetrics{}
	}
	
	// Return a copy to avoid race conditions
	result := make([]*MemoryMetrics, len(history))
	copy(result, history)
	return result
}

// GetOOMEvents returns a channel for receiving OOM events
func (m *MemoryController) GetOOMEvents() <-chan OOMEvent {
	return m.oomEventChan
}

// RemoveMemoryLimits removes memory limits for a container
func (m *MemoryController) RemoveMemoryLimits(containerID string) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Msg("Removing memory limits")
	
	// Close pressure notification eventfd if exists
	m.mu.Lock()
	if config := m.pressureThresholds[containerID]; config != nil {
		syscall.Close(config.EventFD)
		delete(m.pressureThresholds, containerID)
	}
	
	// Remove from tracking
	delete(m.containers, containerID)
	delete(m.metrics, containerID)
	delete(m.metricsHistory, containerID)
	m.mu.Unlock()
	
	cgroupPath := m.getContainerCgroupPath(containerID)
	
	// Remove cgroup
	if err := m.removeMemoryCgroup(cgroupPath); err != nil {
		logger.Warn().Err(err).Msg("Failed to remove memory cgroup")
	}
	
	logger.Debug().Msg("Memory limits removed")
	return nil
}

// Private helper methods

func (m *MemoryController) validateMemoryLimits(limits *MemoryLimits) error {
	if limits.Limit != nil && *limits.Limit < 0 {
		return fmt.Errorf("memory limit cannot be negative")
	}
	
	if limits.Reservation != nil && *limits.Reservation < 0 {
		return fmt.Errorf("memory reservation cannot be negative")
	}
	
	if limits.Swap != nil && limits.Limit != nil && *limits.Swap < *limits.Limit {
		return fmt.Errorf("swap limit cannot be less than memory limit")
	}
	
	if limits.Swappiness != nil && (*limits.Swappiness < 0 || *limits.Swappiness > 100) {
		return fmt.Errorf("swappiness must be between 0 and 100")
	}
	
	if limits.High != nil && limits.Limit != nil && *limits.High > *limits.Limit {
		return fmt.Errorf("memory high cannot exceed memory limit")
	}
	
	if limits.Low != nil && limits.High != nil && *limits.Low > *limits.High {
		return fmt.Errorf("memory low cannot exceed memory high")
	}
	
	return nil
}

func (m *MemoryController) getContainerCgroupPath(containerID string) string {
	if m.cgroupVersion == 2 {
		return filepath.Join(m.cgroupRoot, "sandboxrunner", containerID)
	}
	return filepath.Join(m.subsystemPath, "sandboxrunner", containerID)
}

func (m *MemoryController) createMemoryCgroup(cgroupPath string) error {
	if err := os.MkdirAll(cgroupPath, 0755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("failed to create cgroup directory: %w", err)
	}
	return nil
}

func (m *MemoryController) removeMemoryCgroup(cgroupPath string) error {
	return os.RemoveAll(cgroupPath)
}

func (m *MemoryController) applyMemoryLimitsV1(cgroupPath string, limits *MemoryLimits) error {
	// Set memory limit
	if limits.Limit != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.limit_in_bytes"), 
			strconv.FormatInt(*limits.Limit, 10)); err != nil {
			return fmt.Errorf("failed to set memory limit: %w", err)
		}
	}
	
	// Set memory soft limit (reservation)
	if limits.Reservation != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.soft_limit_in_bytes"), 
			strconv.FormatInt(*limits.Reservation, 10)); err != nil {
			return fmt.Errorf("failed to set memory reservation: %w", err)
		}
	}
	
	// Set swap limit
	if limits.Swap != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.memsw.limit_in_bytes"), 
			strconv.FormatInt(*limits.Swap, 10)); err != nil {
			return fmt.Errorf("failed to set swap limit: %w", err)
		}
	}
	
	// Set kernel memory limit
	if limits.Kernel != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.kmem.limit_in_bytes"), 
			strconv.FormatInt(*limits.Kernel, 10)); err != nil {
			return fmt.Errorf("failed to set kernel memory limit: %w", err)
		}
	}
	
	// Set kernel TCP memory limit
	if limits.KernelTCP != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.kmem.tcp.limit_in_bytes"), 
			strconv.FormatInt(*limits.KernelTCP, 10)); err != nil {
			return fmt.Errorf("failed to set kernel TCP memory limit: %w", err)
		}
	}
	
	// Set swappiness
	if limits.Swappiness != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.swappiness"), 
			strconv.FormatInt(*limits.Swappiness, 10)); err != nil {
			return fmt.Errorf("failed to set swappiness: %w", err)
		}
	}
	
	// Disable OOM killer if requested
	if limits.DisableOOMKiller != nil && *limits.DisableOOMKiller {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.oom_control"), "1"); err != nil {
			return fmt.Errorf("failed to disable OOM killer: %w", err)
		}
	}
	
	// Enable hierarchy accounting
	if limits.UseHierarchy != nil && *limits.UseHierarchy {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.use_hierarchy"), "1"); err != nil {
			return fmt.Errorf("failed to enable hierarchy: %w", err)
		}
	}
	
	return nil
}

func (m *MemoryController) applyMemoryLimitsV2(cgroupPath string, limits *MemoryLimits) error {
	// Set memory limit
	if limits.Limit != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.max"), 
			strconv.FormatInt(*limits.Limit, 10)); err != nil {
			return fmt.Errorf("failed to set memory limit: %w", err)
		}
	}
	
	// Set memory high watermark
	if limits.High != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.high"), 
			strconv.FormatInt(*limits.High, 10)); err != nil {
			return fmt.Errorf("failed to set memory high: %w", err)
		}
	}
	
	// Set memory low protection
	if limits.Low != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.low"), 
			strconv.FormatInt(*limits.Low, 10)); err != nil {
			return fmt.Errorf("failed to set memory low: %w", err)
		}
	}
	
	// Set memory minimum protection
	if limits.Min != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.min"), 
			strconv.FormatInt(*limits.Min, 10)); err != nil {
			return fmt.Errorf("failed to set memory min: %w", err)
		}
	}
	
	// Set swap limit
	if limits.Swap != nil {
		if err := m.writeCgroupFile(filepath.Join(cgroupPath, "memory.swap.max"), 
			strconv.FormatInt(*limits.Swap, 10)); err != nil {
			return fmt.Errorf("failed to set swap limit: %w", err)
		}
	}
	
	return nil
}

func (m *MemoryController) getMemoryUsageV1(cgroupPath string, metrics *MemoryMetrics) error {
	// Read current memory usage
	if usageStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.usage_in_bytes")); err == nil {
		if usage, err := strconv.ParseInt(usageStr, 10, 64); err == nil {
			metrics.UsageBytes = usage
		}
	}
	
	// Read memory limit
	if limitStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.limit_in_bytes")); err == nil {
		if limit, err := strconv.ParseInt(limitStr, 10, 64); err == nil {
			metrics.LimitBytes = limit
		}
	}
	
	// Read memory statistics
	if statStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.stat")); err == nil {
		m.parseMemoryStatV1(statStr, metrics)
	}
	
	// Read OOM control
	if oomStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.oom_control")); err == nil {
		m.parseOOMControlV1(oomStr, metrics)
	}
	
	// Read failcnt
	if failcntStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.failcnt")); err == nil {
		// This indicates OOM events
		if failcnt, err := strconv.ParseInt(failcntStr, 10, 64); err == nil {
			metrics.OOMKillCount = failcnt
		}
	}
	
	return nil
}

func (m *MemoryController) getMemoryUsageV2(cgroupPath string, metrics *MemoryMetrics) error {
	// Read current memory usage
	if currentStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.current")); err == nil {
		if current, err := strconv.ParseInt(currentStr, 10, 64); err == nil {
			metrics.UsageBytes = current
		}
	}
	
	// Read memory limit
	if maxStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.max")); err == nil {
		if maxStr != "max" {
			if max, err := strconv.ParseInt(maxStr, 10, 64); err == nil {
				metrics.LimitBytes = max
			}
		}
	}
	
	// Read memory statistics
	if statStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.stat")); err == nil {
		m.parseMemoryStatV2(statStr, metrics)
	}
	
	// Read memory events
	if eventsStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.events")); err == nil {
		m.parseMemoryEventsV2(eventsStr, metrics)
	}
	
	// Read swap usage
	if swapCurrentStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.swap.current")); err == nil {
		if swapCurrent, err := strconv.ParseInt(swapCurrentStr, 10, 64); err == nil {
			metrics.SwapBytes = swapCurrent
		}
	}
	
	return nil
}

func (m *MemoryController) getMemoryStatsV1(cgroupPath string) (*MemoryStats, error) {
	stats := &MemoryStats{
		Stats: make(map[string]int64),
	}
	
	// Read usage
	if usageStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.usage_in_bytes")); err == nil {
		if usage, err := strconv.ParseInt(usageStr, 10, 64); err == nil {
			stats.Usage = usage
		}
	}
	
	// Read max usage
	if maxUsageStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.max_usage_in_bytes")); err == nil {
		if maxUsage, err := strconv.ParseInt(maxUsageStr, 10, 64); err == nil {
			stats.MaxUsage = maxUsage
		}
	}
	
	// Read limit
	if limitStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.limit_in_bytes")); err == nil {
		if limit, err := strconv.ParseInt(limitStr, 10, 64); err == nil {
			stats.Limit = limit
		}
	}
	
	// Read failcnt
	if failcntStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.failcnt")); err == nil {
		if failcnt, err := strconv.ParseInt(failcntStr, 10, 64); err == nil {
			stats.Failcnt = failcnt
		}
	}
	
	// Read detailed statistics
	if statStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.stat")); err == nil {
		m.parseDetailedMemoryStats(statStr, stats.Stats)
	}
	
	return stats, nil
}

func (m *MemoryController) getMemoryStatsV2(cgroupPath string) (*MemoryStats, error) {
	stats := &MemoryStats{
		Stats: make(map[string]int64),
	}
	
	// Read current usage
	if currentStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.current")); err == nil {
		if current, err := strconv.ParseInt(currentStr, 10, 64); err == nil {
			stats.Usage = current
		}
	}
	
	// Read peak usage
	if peakStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.peak")); err == nil {
		if peak, err := strconv.ParseInt(peakStr, 10, 64); err == nil {
			stats.MaxUsage = peak
		}
	}
	
	// Read limit
	if maxStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.max")); err == nil {
		if maxStr != "max" {
			if max, err := strconv.ParseInt(maxStr, 10, 64); err == nil {
				stats.Limit = max
			}
		}
	}
	
	// Read detailed statistics
	if statStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.stat")); err == nil {
		m.parseDetailedMemoryStats(statStr, stats.Stats)
	}
	
	// Read events for failcnt
	if eventsStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.events")); err == nil {
		lines := strings.Split(eventsStr, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "oom" {
				if oom, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					stats.Failcnt = oom
				}
			}
		}
	}
	
	return stats, nil
}

func (m *MemoryController) getMemoryPressure(cgroupPath string, metrics *MemoryMetrics) {
	if m.cgroupVersion == 2 {
		// cgroup v2 has memory.pressure file
		if pressureStr, err := m.readCgroupFile(filepath.Join(cgroupPath, "memory.pressure")); err == nil {
			m.parseMemoryPressureV2(pressureStr, metrics)
		}
	}
	// cgroup v1 doesn't have built-in pressure metrics
}

func (m *MemoryController) parseMemoryStatV1(statStr string, metrics *MemoryMetrics) {
	lines := strings.Split(statStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "cache":
				metrics.CacheBytes = value
			case "rss":
				metrics.RSSBytes = value
			case "rss_huge":
				// Add to RSS
				metrics.RSSBytes += value
			case "mapped_file":
				// Part of cache
			case "pgpgin":
				// Page-ins
			case "pgpgout":
				// Page-outs
			case "swap":
				metrics.SwapBytes = value
			case "pgfault":
				metrics.PageFaults = value
			case "pgmajfault":
				metrics.MajorPageFaults = value
			case "hierarchical_memory_limit":
				metrics.HierarchicalMemoryLimit = value
			case "hierarchical_memsw_limit":
				metrics.HierarchicalMemswLimit = value
			}
		}
	}
}

func (m *MemoryController) parseMemoryStatV2(statStr string, metrics *MemoryMetrics) {
	lines := strings.Split(statStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "anon":
				metrics.RSSBytes = value
			case "file":
				metrics.CacheBytes = value
			case "kernel_stack":
				// Add to kernel usage
				metrics.KernelUsage += value
			case "slab":
				// Add to kernel usage
				metrics.KernelUsage += value
			case "sock":
				// Network memory
				metrics.KernelTCPUsage = value
			case "pgfault":
				metrics.PageFaults = value
			case "pgmajfault":
				metrics.MajorPageFaults = value
			case "pgscan":
				// Memory pressure indicator
			case "pgsteal":
				// Memory reclaim activity
			}
		}
	}
}

func (m *MemoryController) parseMemoryEventsV2(eventsStr string, metrics *MemoryMetrics) {
	lines := strings.Split(eventsStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			value, _ := strconv.ParseInt(fields[1], 10, 64)
			switch fields[0] {
			case "low":
				// Memory under low threshold
			case "high":
				// Memory over high threshold
			case "max":
				// Memory allocation failures
			case "oom":
				metrics.OOMKillCount = value
			case "oom_kill":
				// Alternative OOM event name
				metrics.OOMKillCount = value
			}
		}
	}
}

func (m *MemoryController) parseMemoryPressureV2(pressureStr string, metrics *MemoryMetrics) {
	lines := strings.Split(pressureStr, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "some") {
			// Parse pressure averages
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "avg10=") {
					if val, err := strconv.ParseFloat(strings.TrimPrefix(part, "avg10="), 64); err == nil {
						metrics.PressureAvg10 = val
					}
				} else if strings.HasPrefix(part, "avg60=") {
					if val, err := strconv.ParseFloat(strings.TrimPrefix(part, "avg60="), 64); err == nil {
						metrics.PressureAvg60 = val
					}
				} else if strings.HasPrefix(part, "avg300=") {
					if val, err := strconv.ParseFloat(strings.TrimPrefix(part, "avg300="), 64); err == nil {
						metrics.PressureAvg300 = val
					}
				} else if strings.HasPrefix(part, "total=") {
					if val, err := strconv.ParseInt(strings.TrimPrefix(part, "total="), 10, 64); err == nil {
						metrics.PressureTotal = val
					}
				}
			}
		}
	}
}

func (m *MemoryController) parseOOMControlV1(oomStr string, metrics *MemoryMetrics) {
	lines := strings.Split(oomStr, "\n")
	for _, line := range lines {
		if strings.Contains(line, "oom_kill_disable") && strings.Contains(line, "0") {
			// OOM killer is enabled
		}
		if strings.Contains(line, "under_oom") && strings.Contains(line, "1") {
			// Currently under OOM
		}
	}
}

func (m *MemoryController) parseDetailedMemoryStats(statStr string, stats map[string]int64) {
	lines := strings.Split(statStr, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			if value, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				stats[fields[0]] = value
			}
		}
	}
}

func (m *MemoryController) setupOOMNotification(containerID, cgroupPath string) error {
	// This is a simplified implementation
	// In a real implementation, you would set up eventfd-based notifications
	log.Debug().
		Str("container_id", containerID).
		Str("cgroup_path", cgroupPath).
		Msg("OOM notification setup (placeholder)")
	return nil
}

func (m *MemoryController) setupPressureNotificationV1(cgroupPath string, config *MemoryPressureConfig) error {
	// cgroup v1 memory pressure notifications via memory.pressure_level
	// This is a simplified placeholder
	return nil
}

func (m *MemoryController) setupPressureNotificationV2(cgroupPath string, config *MemoryPressureConfig) error {
	// cgroup v2 pressure notifications via memory.pressure
	// This is a simplified placeholder
	return nil
}

func (m *MemoryController) monitorOOMEvents() {
	// Background goroutine to monitor OOM events
	// This is a simplified implementation
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			// Check for OOM events in dmesg or other system logs
			// This is a placeholder for actual OOM event detection
		}
	}
}

func (m *MemoryController) storeMetrics(containerID string, metrics *MemoryMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.metrics[containerID] = metrics
	
	history := m.metricsHistory[containerID]
	history = append(history, metrics)
	
	// Keep only the last maxHistorySize entries
	if len(history) > m.maxHistorySize {
		history = history[len(history)-m.maxHistorySize:]
	}
	
	m.metricsHistory[containerID] = history
}

func (m *MemoryController) calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func (m *MemoryController) writeCgroupFile(filePath, content string) error {
	return os.WriteFile(filePath, []byte(content), 0644)
}

func (m *MemoryController) readCgroupFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// GetSystemMemoryInfo gets system-wide memory information
func GetSystemMemoryInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})
	
	// Read /proc/meminfo
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/meminfo: %w", err)
	}
	defer file.Close()
	
	meminfo := make(map[string]int64)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.TrimSuffix(parts[0], ":")
			value := strings.TrimSuffix(parts[1], " kB")
			if val, err := strconv.ParseInt(value, 10, 64); err == nil {
				meminfo[key] = val * 1024 // Convert to bytes
			}
		}
	}
	
	info["meminfo"] = meminfo
	
	// Calculate derived metrics
	if total, ok := meminfo["MemTotal"]; ok {
		if free, ok := meminfo["MemFree"]; ok {
			if buffers, ok := meminfo["Buffers"]; ok {
				if cached, ok := meminfo["Cached"]; ok {
					used := total - free - buffers - cached
					info["memory_used"] = used
					info["memory_usage_percent"] = float64(used) / float64(total) * 100.0
				}
			}
		}
	}
	
	return info, nil
}