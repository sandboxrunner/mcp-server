package resources

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
)

// DiskController manages disk resource limiting and monitoring
type DiskController struct {
	mu                sync.RWMutex
	containers        map[string]*DiskLimits
	metrics           map[string]*DiskMetrics
	metricsHistory    map[string][]*DiskMetrics
	maxHistorySize    int
	quotaEnabled      bool
	quotaType         string // "xfs", "ext4", "project"
	basePath          string
	projectIDCounter  uint32
	projectIDs        map[string]uint32
	cleanupPolicies   map[string]*CleanupPolicy
	ioThrottling      map[string]*IOThrottleConfig
}

// DiskLimits defines comprehensive disk resource limits
type DiskLimits struct {
	// Space limits
	SoftLimit     *int64 `json:"soft_limit,omitempty"`     // Soft limit in bytes
	HardLimit     *int64 `json:"hard_limit,omitempty"`     // Hard limit in bytes
	
	// Inode limits
	InodeSoftLimit *int64 `json:"inode_soft_limit,omitempty"` // Soft inode limit
	InodeHardLimit *int64 `json:"inode_hard_limit,omitempty"` // Hard inode limit
	
	// File count limits
	MaxFiles      *int64 `json:"max_files,omitempty"`      // Maximum number of files
	MaxDirs       *int64 `json:"max_dirs,omitempty"`       // Maximum number of directories
	
	// Size limits for specific paths
	TempDirLimit  *int64 `json:"temp_dir_limit,omitempty"` // Temp directory limit
	LogDirLimit   *int64 `json:"log_dir_limit,omitempty"`  // Log directory limit
	CacheLimit    *int64 `json:"cache_limit,omitempty"`    // Cache directory limit
	
	// I/O throttling limits
	ReadBPS       *int64 `json:"read_bps,omitempty"`       // Read bytes per second
	WriteBPS      *int64 `json:"write_bps,omitempty"`      // Write bytes per second
	ReadIOPS      *int64 `json:"read_iops,omitempty"`      // Read operations per second
	WriteIOPS     *int64 `json:"write_iops,omitempty"`     // Write operations per second
	
	// Automatic cleanup configuration
	EnableCleanup *bool  `json:"enable_cleanup,omitempty"` // Enable automatic cleanup
	GracePeriod   *int64 `json:"grace_period,omitempty"`   // Grace period in seconds
}

// DiskMetrics holds comprehensive disk usage metrics
type DiskMetrics struct {
	ContainerID     string    `json:"container_id"`
	Timestamp       time.Time `json:"timestamp"`
	
	// Space usage
	UsedBytes       int64     `json:"used_bytes"`
	AvailableBytes  int64     `json:"available_bytes"`
	TotalBytes      int64     `json:"total_bytes"`
	UsagePercent    float64   `json:"usage_percent"`
	
	// Inode usage
	UsedInodes      int64     `json:"used_inodes"`
	AvailableInodes int64     `json:"available_inodes"`
	TotalInodes     int64     `json:"total_inodes"`
	InodePercent    float64   `json:"inode_percent"`
	
	// File counts
	FileCount       int64     `json:"file_count"`
	DirCount        int64     `json:"dir_count"`
	LinkCount       int64     `json:"link_count"`
	
	// I/O statistics
	ReadBytes       int64     `json:"read_bytes"`
	WriteBytes      int64     `json:"write_bytes"`
	ReadOps         int64     `json:"read_ops"`
	WriteOps        int64     `json:"write_ops"`
	ReadLatency     float64   `json:"read_latency_ms"`
	WriteLatency    float64   `json:"write_latency_ms"`
	
	// Directory-specific usage
	TempDirUsage    int64     `json:"temp_dir_usage"`
	LogDirUsage     int64     `json:"log_dir_usage"`
	CacheDirUsage   int64     `json:"cache_dir_usage"`
	
	// Quota status
	QuotaEnabled    bool      `json:"quota_enabled"`
	QuotaExceeded   bool      `json:"quota_exceeded"`
	GracePeriodLeft int64     `json:"grace_period_left"`
}

// DiskStats holds detailed disk statistics
type DiskStats struct {
	Device          string            `json:"device"`
	MountPoint      string            `json:"mount_point"`
	FilesystemType  string            `json:"filesystem_type"`
	BlockSize       int64             `json:"block_size"`
	TotalBlocks     int64             `json:"total_blocks"`
	FreeBlocks      int64             `json:"free_blocks"`
	AvailableBlocks int64             `json:"available_blocks"`
	TotalInodes     int64             `json:"total_inodes"`
	FreeInodes      int64             `json:"free_inodes"`
	IOStats         map[string]int64  `json:"io_stats"`
}

// CleanupPolicy defines automatic cleanup behavior
type CleanupPolicy struct {
	Enabled         bool              `json:"enabled"`
	ThresholdPercent float64          `json:"threshold_percent"`
	RetentionPeriod time.Duration     `json:"retention_period"`
	FilePatterns    []string          `json:"file_patterns"`
	Directories     []string          `json:"directories"`
	PreserveCount   int               `json:"preserve_count"`
	SortBy          string            `json:"sort_by"` // "size", "mtime", "atime"
	DryRun          bool              `json:"dry_run"`
}

// IOThrottleConfig defines I/O throttling configuration
type IOThrottleConfig struct {
	DeviceMajor   int   `json:"device_major"`
	DeviceMinor   int   `json:"device_minor"`
	ReadBPS       int64 `json:"read_bps"`
	WriteBPS      int64 `json:"write_bps"`
	ReadIOPS      int64 `json:"read_iops"`
	WriteIOPS     int64 `json:"write_iops"`
	Enabled       bool  `json:"enabled"`
}

// QuotaInfo holds quota information for a project/user
type QuotaInfo struct {
	ProjectID       uint32 `json:"project_id"`
	BlocksUsed      int64  `json:"blocks_used"`
	BlocksSoftLimit int64  `json:"blocks_soft_limit"`
	BlocksHardLimit int64  `json:"blocks_hard_limit"`
	InodesUsed      int64  `json:"inodes_used"`
	InodesSoftLimit int64  `json:"inodes_soft_limit"`
	InodesHardLimit int64  `json:"inodes_hard_limit"`
	GracePeriod     int64  `json:"grace_period"`
}

// NewDiskController creates a new disk resource controller
func NewDiskController(basePath string) *DiskController {
	controller := &DiskController{
		containers:       make(map[string]*DiskLimits),
		metrics:          make(map[string]*DiskMetrics),
		metricsHistory:   make(map[string][]*DiskMetrics),
		maxHistorySize:   100,
		basePath:         basePath,
		projectIDCounter: 1000, // Start from 1000 to avoid conflicts
		projectIDs:       make(map[string]uint32),
		cleanupPolicies:  make(map[string]*CleanupPolicy),
		ioThrottling:     make(map[string]*IOThrottleConfig),
	}
	
	// Detect quota support
	controller.detectQuotaSupport()
	
	log.Info().
		Str("base_path", basePath).
		Bool("quota_enabled", controller.quotaEnabled).
		Str("quota_type", controller.quotaType).
		Msg("Disk controller initialized")
	
	return controller
}

// ApplyDiskLimits applies disk limits to a container
func (d *DiskController) ApplyDiskLimits(containerID string, limits *DiskLimits) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Interface("limits", limits).Msg("Applying disk limits")
	
	// Validate limits
	if err := d.validateDiskLimits(limits); err != nil {
		return fmt.Errorf("invalid disk limits: %w", err)
	}
	
	containerPath := filepath.Join(d.basePath, containerID)
	
	// Ensure container directory exists
	if err := os.MkdirAll(containerPath, 0755); err != nil {
		return fmt.Errorf("failed to create container directory: %w", err)
	}
	
	// Apply quota limits if supported
	if d.quotaEnabled {
		if err := d.applyQuotaLimits(containerID, containerPath, limits); err != nil {
			return fmt.Errorf("failed to apply quota limits: %w", err)
		}
	}
	
	// Apply I/O throttling if specified
	if limits.ReadBPS != nil || limits.WriteBPS != nil || limits.ReadIOPS != nil || limits.WriteIOPS != nil {
		if err := d.applyIOThrottling(containerID, limits); err != nil {
			logger.Warn().Err(err).Msg("Failed to apply I/O throttling")
		}
	}
	
	// Set up cleanup policy if enabled
	if limits.EnableCleanup != nil && *limits.EnableCleanup {
		policy := d.createDefaultCleanupPolicy(limits)
		d.mu.Lock()
		d.cleanupPolicies[containerID] = policy
		d.mu.Unlock()
	}
	
	// Store limits for monitoring
	d.mu.Lock()
	d.containers[containerID] = limits
	d.mu.Unlock()
	
	logger.Info().
		Interface("applied_limits", limits).
		Msg("Disk limits applied successfully")
	
	return nil
}

// GetDiskUsage gets current disk usage metrics for a container
func (d *DiskController) GetDiskUsage(containerID string) (*DiskMetrics, error) {
	containerPath := filepath.Join(d.basePath, containerID)
	
	metrics := &DiskMetrics{
		ContainerID: containerID,
		Timestamp:   time.Now(),
	}
	
	// Get basic disk usage
	if err := d.getDiskUsage(containerPath, metrics); err != nil {
		return nil, fmt.Errorf("failed to get disk usage: %w", err)
	}
	
	// Get quota information if enabled
	if d.quotaEnabled {
		if err := d.getQuotaUsage(containerID, metrics); err != nil {
			log.Warn().Err(err).Str("container_id", containerID).Msg("Failed to get quota usage")
		}
	}
	
	// Get I/O statistics
	d.getIOStats(containerID, metrics)
	
	// Get directory-specific usage
	d.getDirectoryUsage(containerPath, metrics)
	
	// Calculate usage percentages
	if metrics.TotalBytes > 0 {
		metrics.UsagePercent = float64(metrics.UsedBytes) / float64(metrics.TotalBytes) * 100.0
	}
	if metrics.TotalInodes > 0 {
		metrics.InodePercent = float64(metrics.UsedInodes) / float64(metrics.TotalInodes) * 100.0
	}
	
	// Store metrics for history
	d.storeMetrics(containerID, metrics)
	
	return metrics, nil
}

// GetDiskStats gets detailed disk statistics for a container
func (d *DiskController) GetDiskStats(containerID string) (*DiskStats, error) {
	containerPath := filepath.Join(d.basePath, containerID)
	return d.getDiskStats(containerPath)
}

// SetupCleanupPolicy configures automatic cleanup for a container
func (d *DiskController) SetupCleanupPolicy(containerID string, policy *CleanupPolicy) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Interface("policy", policy).Msg("Setting up cleanup policy")
	
	d.mu.Lock()
	d.cleanupPolicies[containerID] = policy
	d.mu.Unlock()
	
	logger.Info().Msg("Cleanup policy configured")
	return nil
}

// RunCleanup executes cleanup for a container based on its policy
func (d *DiskController) RunCleanup(containerID string) (*CleanupResult, error) {
	d.mu.RLock()
	policy := d.cleanupPolicies[containerID]
	d.mu.RUnlock()
	
	if policy == nil || !policy.Enabled {
		return &CleanupResult{}, nil
	}
	
	containerPath := filepath.Join(d.basePath, containerID)
	return d.executeCleanup(containerPath, policy)
}

// GetDiskHistory gets disk metrics history for a container
func (d *DiskController) GetDiskHistory(containerID string) []*DiskMetrics {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	history := d.metricsHistory[containerID]
	if history == nil {
		return []*DiskMetrics{}
	}
	
	// Return a copy to avoid race conditions
	result := make([]*DiskMetrics, len(history))
	copy(result, history)
	return result
}

// RemoveDiskLimits removes disk limits for a container
func (d *DiskController) RemoveDiskLimits(containerID string) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Msg("Removing disk limits")
	
	// Remove quota if enabled
	if d.quotaEnabled {
		if err := d.removeQuotaLimits(containerID); err != nil {
			logger.Warn().Err(err).Msg("Failed to remove quota limits")
		}
	}
	
	// Remove I/O throttling
	d.removeIOThrottling(containerID)
	
	// Remove from tracking
	d.mu.Lock()
	delete(d.containers, containerID)
	delete(d.metrics, containerID)
	delete(d.metricsHistory, containerID)
	delete(d.cleanupPolicies, containerID)
	delete(d.ioThrottling, containerID)
	if projectID, exists := d.projectIDs[containerID]; exists {
		delete(d.projectIDs, containerID)
		// Could reuse project IDs, but for safety we don't
		_ = projectID
	}
	d.mu.Unlock()
	
	logger.Debug().Msg("Disk limits removed")
	return nil
}

// Private helper methods

func (d *DiskController) validateDiskLimits(limits *DiskLimits) error {
	if limits.SoftLimit != nil && *limits.SoftLimit < 0 {
		return fmt.Errorf("soft limit cannot be negative")
	}
	
	if limits.HardLimit != nil && *limits.HardLimit < 0 {
		return fmt.Errorf("hard limit cannot be negative")
	}
	
	if limits.SoftLimit != nil && limits.HardLimit != nil && *limits.SoftLimit > *limits.HardLimit {
		return fmt.Errorf("soft limit cannot exceed hard limit")
	}
	
	if limits.InodeSoftLimit != nil && *limits.InodeSoftLimit < 0 {
		return fmt.Errorf("inode soft limit cannot be negative")
	}
	
	if limits.InodeHardLimit != nil && *limits.InodeHardLimit < 0 {
		return fmt.Errorf("inode hard limit cannot be negative")
	}
	
	if limits.InodeSoftLimit != nil && limits.InodeHardLimit != nil && *limits.InodeSoftLimit > *limits.InodeHardLimit {
		return fmt.Errorf("inode soft limit cannot exceed hard limit")
	}
	
	return nil
}

func (d *DiskController) detectQuotaSupport() {
	// Check for XFS project quota support
	if d.checkXFSQuotaSupport() {
		d.quotaEnabled = true
		d.quotaType = "xfs"
		return
	}
	
	// Check for ext4 quota support
	if d.checkExt4QuotaSupport() {
		d.quotaEnabled = true
		d.quotaType = "ext4"
		return
	}
	
	// Fallback to manual tracking
	d.quotaEnabled = false
	d.quotaType = "manual"
}

func (d *DiskController) checkXFSQuotaSupport() bool {
	// Check if xfs_quota command is available
	if _, err := exec.LookPath("xfs_quota"); err != nil {
		return false
	}
	
	// Check if filesystem supports project quotas
	cmd := exec.Command("xfs_quota", "-x", "-c", "print", d.basePath)
	if err := cmd.Run(); err != nil {
		return false
	}
	
	return true
}

func (d *DiskController) checkExt4QuotaSupport() bool {
	// Check if quotacheck command is available
	if _, err := exec.LookPath("quotacheck"); err != nil {
		return false
	}
	
	// Check if quota is enabled on the filesystem
	cmd := exec.Command("findmnt", "-n", "-o", "OPTIONS", d.basePath)
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	
	return strings.Contains(string(output), "quota") || strings.Contains(string(output), "usrquota")
}

func (d *DiskController) applyQuotaLimits(containerID, containerPath string, limits *DiskLimits) error {
	switch d.quotaType {
	case "xfs":
		return d.applyXFSQuotaLimits(containerID, containerPath, limits)
	case "ext4":
		return d.applyExt4QuotaLimits(containerID, containerPath, limits)
	default:
		return nil // Manual tracking, no quota enforcement
	}
}

func (d *DiskController) applyXFSQuotaLimits(containerID, containerPath string, limits *DiskLimits) error {
	// Get or assign project ID
	d.mu.Lock()
	projectID, exists := d.projectIDs[containerID]
	if !exists {
		projectID = d.projectIDCounter
		d.projectIDCounter++
		d.projectIDs[containerID] = projectID
	}
	d.mu.Unlock()
	
	// Set project ID for the directory
	cmd := exec.Command("xfs_quota", "-x", "-c", fmt.Sprintf("project -s -p %s %d", containerPath, projectID))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set project ID: %w", err)
	}
	
	// Set quota limits
	var quotaCommands []string
	
	if limits.HardLimit != nil || limits.SoftLimit != nil {
		soft := int64(0)
		if limits.SoftLimit != nil {
			soft = *limits.SoftLimit / 1024 // Convert to KB
		}
		hard := int64(0)
		if limits.HardLimit != nil {
			hard = *limits.HardLimit / 1024 // Convert to KB
		}
		
		quotaCommands = append(quotaCommands, 
			fmt.Sprintf("limit -p bsoft=%d bhard=%d %d", soft, hard, projectID))
	}
	
	if limits.InodeHardLimit != nil || limits.InodeSoftLimit != nil {
		soft := int64(0)
		if limits.InodeSoftLimit != nil {
			soft = *limits.InodeSoftLimit
		}
		hard := int64(0)
		if limits.InodeHardLimit != nil {
			hard = *limits.InodeHardLimit
		}
		
		quotaCommands = append(quotaCommands, 
			fmt.Sprintf("limit -p isoft=%d ihard=%d %d", soft, hard, projectID))
	}
	
	// Execute quota commands
	for _, quotaCmd := range quotaCommands {
		cmd := exec.Command("xfs_quota", "-x", "-c", quotaCmd, d.basePath)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set quota limits: %w", err)
		}
	}
	
	return nil
}

func (d *DiskController) applyExt4QuotaLimits(containerID, containerPath string, limits *DiskLimits) error {
	// ext4 quota implementation would go here
	// This is a placeholder for the implementation
	return fmt.Errorf("ext4 quota not implemented yet")
}

func (d *DiskController) applyIOThrottling(containerID string, limits *DiskLimits) error {
	// Get device information for the container path
	deviceMajor, deviceMinor, err := d.getDeviceNumbers(d.basePath)
	if err != nil {
		return fmt.Errorf("failed to get device numbers: %w", err)
	}
	
	config := &IOThrottleConfig{
		DeviceMajor: deviceMajor,
		DeviceMinor: deviceMinor,
		Enabled:     true,
	}
	
	if limits.ReadBPS != nil {
		config.ReadBPS = *limits.ReadBPS
	}
	if limits.WriteBPS != nil {
		config.WriteBPS = *limits.WriteBPS
	}
	if limits.ReadIOPS != nil {
		config.ReadIOPS = *limits.ReadIOPS
	}
	if limits.WriteIOPS != nil {
		config.WriteIOPS = *limits.WriteIOPS
	}
	
	d.mu.Lock()
	d.ioThrottling[containerID] = config
	d.mu.Unlock()
	
	// Apply I/O throttling via cgroups would be done in the calling code
	// This is a placeholder for the implementation
	
	return nil
}

func (d *DiskController) getDiskUsage(containerPath string, metrics *DiskMetrics) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(containerPath, &stat); err != nil {
		return fmt.Errorf("failed to get filesystem stats: %w", err)
	}
	
	metrics.TotalBytes = int64(stat.Blocks) * int64(stat.Bsize)
	metrics.AvailableBytes = int64(stat.Bavail) * int64(stat.Bsize)
	metrics.UsedBytes = metrics.TotalBytes - int64(stat.Bfree)*int64(stat.Bsize)
	
	metrics.TotalInodes = int64(stat.Files)
	metrics.AvailableInodes = int64(stat.Ffree)
	metrics.UsedInodes = metrics.TotalInodes - metrics.AvailableInodes
	
	// Get file counts
	fileCount, dirCount, linkCount, err := d.countFiles(containerPath)
	if err == nil {
		metrics.FileCount = fileCount
		metrics.DirCount = dirCount
		metrics.LinkCount = linkCount
	}
	
	return nil
}

func (d *DiskController) getQuotaUsage(containerID string, metrics *DiskMetrics) error {
	if d.quotaType != "xfs" {
		return nil // Only implemented for XFS
	}
	
	d.mu.RLock()
	projectID, exists := d.projectIDs[containerID]
	d.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("no project ID found for container")
	}
	
	// Get quota report
	cmd := exec.Command("xfs_quota", "-x", "-c", fmt.Sprintf("report -p -N %d", projectID), d.basePath)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get quota report: %w", err)
	}
	
	// Parse quota output
	quotaInfo, err := d.parseXFSQuotaOutput(string(output))
	if err != nil {
		return fmt.Errorf("failed to parse quota output: %w", err)
	}
	
	metrics.QuotaEnabled = true
	metrics.QuotaExceeded = quotaInfo.BlocksUsed > quotaInfo.BlocksHardLimit || 
						   quotaInfo.InodesUsed > quotaInfo.InodesHardLimit
	metrics.GracePeriodLeft = quotaInfo.GracePeriod
	
	// Override usage with quota data
	metrics.UsedBytes = quotaInfo.BlocksUsed * 1024 // Convert from KB
	metrics.UsedInodes = quotaInfo.InodesUsed
	
	return nil
}

func (d *DiskController) getIOStats(containerID string, metrics *DiskMetrics) {
	// Read I/O stats from /proc/diskstats or cgroup I/O stats
	// This is a simplified placeholder implementation
	
	// In a real implementation, you would:
	// 1. Read from /proc/diskstats
	// 2. Or read from cgroup blkio.throttle.io_service_bytes
	// 3. Calculate rates and latencies
	
	metrics.ReadBytes = 0
	metrics.WriteBytes = 0
	metrics.ReadOps = 0
	metrics.WriteOps = 0
	metrics.ReadLatency = 0.0
	metrics.WriteLatency = 0.0
}

func (d *DiskController) getDirectoryUsage(containerPath string, metrics *DiskMetrics) {
	// Get usage for specific directories
	tempDir := filepath.Join(containerPath, "tmp")
	if size, err := d.getDirSize(tempDir); err == nil {
		metrics.TempDirUsage = size
	}
	
	logDir := filepath.Join(containerPath, "logs")
	if size, err := d.getDirSize(logDir); err == nil {
		metrics.LogDirUsage = size
	}
	
	cacheDir := filepath.Join(containerPath, "cache")
	if size, err := d.getDirSize(cacheDir); err == nil {
		metrics.CacheDirUsage = size
	}
}

func (d *DiskController) getDiskStats(containerPath string) (*DiskStats, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(containerPath, &stat); err != nil {
		return nil, fmt.Errorf("failed to get filesystem stats: %w", err)
	}
	
	// Get mount information
	device, mountPoint, fsType, err := d.getMountInfo(containerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get mount info: %w", err)
	}
	
	stats := &DiskStats{
		Device:          device,
		MountPoint:      mountPoint,
		FilesystemType:  fsType,
		BlockSize:       int64(stat.Bsize),
		TotalBlocks:     int64(stat.Blocks),
		FreeBlocks:      int64(stat.Bfree),
		AvailableBlocks: int64(stat.Bavail),
		TotalInodes:     int64(stat.Files),
		FreeInodes:      int64(stat.Ffree),
		IOStats:         make(map[string]int64),
	}
	
	// Get I/O statistics from /proc/diskstats
	ioStats, err := d.getDeviceIOStats(device)
	if err == nil {
		stats.IOStats = ioStats
	}
	
	return stats, nil
}

func (d *DiskController) countFiles(dirPath string) (files, dirs, links int64, err error) {
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		
		mode := info.Mode()
		if mode.IsRegular() {
			files++
		} else if mode.IsDir() {
			dirs++
		} else if mode&os.ModeSymlink != 0 {
			links++
		}
		
		return nil
	})
	
	return files, dirs, links, err
}

func (d *DiskController) getDirSize(dirPath string) (int64, error) {
	var size int64
	
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	
	return size, err
}

func (d *DiskController) getMountInfo(path string) (device, mountPoint, fsType string, err error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return "", "", "", fmt.Errorf("failed to open /proc/mounts: %w", err)
	}
	defer file.Close()
	
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get absolute path: %w", err)
	}
	
	scanner := bufio.NewScanner(file)
	bestMatch := ""
	
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			mountPt := fields[1]
			if strings.HasPrefix(absPath, mountPt) && len(mountPt) > len(bestMatch) {
				device = fields[0]
				mountPoint = mountPt
				fsType = fields[2]
				bestMatch = mountPt
			}
		}
	}
	
	if bestMatch == "" {
		return "", "", "", fmt.Errorf("mount point not found for path: %s", path)
	}
	
	return device, mountPoint, fsType, nil
}

func (d *DiskController) getDeviceNumbers(path string) (major, minor int, err error) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, 0, fmt.Errorf("failed to stat path: %w", err)
	}
	
	dev := stat.Dev
	major = int((dev >> 8) & 0xff)
	minor = int(dev & 0xff)
	
	return major, minor, nil
}

func (d *DiskController) getDeviceIOStats(device string) (map[string]int64, error) {
	stats := make(map[string]int64)
	
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return stats, fmt.Errorf("failed to open /proc/diskstats: %w", err)
	}
	defer file.Close()
	
	deviceName := filepath.Base(device)
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 14 && fields[2] == deviceName {
			// Parse diskstats format
			if val, err := strconv.ParseInt(fields[5], 10, 64); err == nil {
				stats["read_sectors"] = val
			}
			if val, err := strconv.ParseInt(fields[9], 10, 64); err == nil {
				stats["write_sectors"] = val
			}
			if val, err := strconv.ParseInt(fields[3], 10, 64); err == nil {
				stats["read_ios"] = val
			}
			if val, err := strconv.ParseInt(fields[7], 10, 64); err == nil {
				stats["write_ios"] = val
			}
			break
		}
	}
	
	return stats, nil
}

func (d *DiskController) parseXFSQuotaOutput(output string) (*QuotaInfo, error) {
	// Parse XFS quota output
	// Format: ProjectID Used Soft Hard Warn/Grace
	
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			projectID, err := strconv.ParseUint(fields[0], 10, 32)
			if err != nil {
				continue
			}
			
			used, _ := strconv.ParseInt(fields[1], 10, 64)
			soft, _ := strconv.ParseInt(fields[2], 10, 64)
			hard, _ := strconv.ParseInt(fields[3], 10, 64)
			
			return &QuotaInfo{
				ProjectID:       uint32(projectID),
				BlocksUsed:      used,
				BlocksSoftLimit: soft,
				BlocksHardLimit: hard,
				InodesUsed:      0, // Would need separate inode report
				InodesSoftLimit: 0,
				InodesHardLimit: 0,
				GracePeriod:     0,
			}, nil
		}
	}
	
	return nil, fmt.Errorf("failed to parse quota output")
}

func (d *DiskController) createDefaultCleanupPolicy(limits *DiskLimits) *CleanupPolicy {
	policy := &CleanupPolicy{
		Enabled:         true,
		ThresholdPercent: 80.0, // Start cleanup at 80% usage
		RetentionPeriod: 7 * 24 * time.Hour, // Keep files for 7 days
		FilePatterns:    []string{"*.tmp", "*.log", "*.cache", "core.*"},
		Directories:     []string{"tmp", "logs", "cache"},
		PreserveCount:   10, // Keep at least 10 newest files
		SortBy:          "atime", // Sort by access time
		DryRun:          false,
	}
	
	if limits.GracePeriod != nil {
		policy.RetentionPeriod = time.Duration(*limits.GracePeriod) * time.Second
	}
	
	return policy
}

type CleanupResult struct {
	FilesRemoved  int   `json:"files_removed"`
	SpaceFreed    int64 `json:"space_freed"`
	Errors        []string `json:"errors"`
}

func (d *DiskController) executeCleanup(containerPath string, policy *CleanupPolicy) (*CleanupResult, error) {
	result := &CleanupResult{
		Errors: make([]string, 0),
	}
	
	for _, dir := range policy.Directories {
		dirPath := filepath.Join(containerPath, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			continue
		}
		
		files, err := d.findFilesForCleanup(dirPath, policy)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("error finding files in %s: %v", dir, err))
			continue
		}
		
		for _, file := range files {
			if !policy.DryRun {
				if info, err := os.Stat(file); err == nil {
					result.SpaceFreed += info.Size()
				}
				
				if err := os.Remove(file); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("error removing %s: %v", file, err))
					continue
				}
			}
			result.FilesRemoved++
		}
	}
	
	return result, nil
}

func (d *DiskController) findFilesForCleanup(dirPath string, policy *CleanupPolicy) ([]string, error) {
	var candidateFiles []string
	cutoffTime := time.Now().Add(-policy.RetentionPeriod)
	
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		
		if info.IsDir() {
			return nil
		}
		
		// Check file patterns
		matched := false
		for _, pattern := range policy.FilePatterns {
			if matched, _ = filepath.Match(pattern, info.Name()); matched {
				break
			}
		}
		
		if !matched {
			return nil
		}
		
		// Check retention period
		var checkTime time.Time
		switch policy.SortBy {
		case "mtime":
			checkTime = info.ModTime()
		case "atime":
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				checkTime = time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
			} else {
				checkTime = info.ModTime() // Fallback
			}
		default:
			checkTime = info.ModTime()
		}
		
		if checkTime.Before(cutoffTime) {
			candidateFiles = append(candidateFiles, path)
		}
		
		return nil
	})
	
	if err != nil {
		return nil, err
	}
	
	// Preserve minimum number of files
	if len(candidateFiles) <= policy.PreserveCount {
		return []string{}, nil
	}
	
	return candidateFiles[:len(candidateFiles)-policy.PreserveCount], nil
}

func (d *DiskController) removeQuotaLimits(containerID string) error {
	if d.quotaType != "xfs" {
		return nil
	}
	
	d.mu.RLock()
	projectID, exists := d.projectIDs[containerID]
	d.mu.RUnlock()
	
	if !exists {
		return nil
	}
	
	// Remove quota limits
	cmd := exec.Command("xfs_quota", "-x", "-c", fmt.Sprintf("limit -p bsoft=0 bhard=0 %d", projectID), d.basePath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove block quota: %w", err)
	}
	
	cmd = exec.Command("xfs_quota", "-x", "-c", fmt.Sprintf("limit -p isoft=0 ihard=0 %d", projectID), d.basePath)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove inode quota: %w", err)
	}
	
	return nil
}

func (d *DiskController) removeIOThrottling(containerID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	if config := d.ioThrottling[containerID]; config != nil {
		config.Enabled = false
		// In a real implementation, you would remove cgroup I/O throttling here
	}
}

func (d *DiskController) storeMetrics(containerID string, metrics *DiskMetrics) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	d.metrics[containerID] = metrics
	
	history := d.metricsHistory[containerID]
	history = append(history, metrics)
	
	// Keep only the last maxHistorySize entries
	if len(history) > d.maxHistorySize {
		history = history[len(history)-d.maxHistorySize:]
	}
	
	d.metricsHistory[containerID] = history
}

// GetSystemDiskInfo gets system-wide disk information
func GetSystemDiskInfo() (map[string]interface{}, error) {
	info := make(map[string]interface{})
	
	// Get mount points
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/mounts: %w", err)
	}
	defer file.Close()
	
	mounts := make([]map[string]interface{}, 0)
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			mount := map[string]interface{}{
				"device":     fields[0],
				"mountpoint": fields[1],
				"fstype":     fields[2],
				"options":    fields[3],
			}
			
			// Get disk usage for this mount
			var stat syscall.Statfs_t
			if err := syscall.Statfs(fields[1], &stat); err == nil {
				mount["total_bytes"] = int64(stat.Blocks) * int64(stat.Bsize)
				mount["free_bytes"] = int64(stat.Bfree) * int64(stat.Bsize)
				mount["available_bytes"] = int64(stat.Bavail) * int64(stat.Bsize)
				mount["total_inodes"] = int64(stat.Files)
				mount["free_inodes"] = int64(stat.Ffree)
			}
			
			mounts = append(mounts, mount)
		}
	}
	
	info["mounts"] = mounts
	
	return info, nil
}