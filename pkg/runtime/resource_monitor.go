package runtime

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ResourceMonitor tracks resource usage for managed processes
type ResourceMonitor struct {
	mu             sync.RWMutex
	processes      map[string]*ManagedProcess
	interval       time.Duration
	enabled        bool
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	eventBus       *ProcessEventBus
	metrics        *MonitorMetrics
	systemInfo     *SystemInfo
	
	// Configuration
	config *ResourceMonitorConfig
}

// ResourceMonitorConfig holds configuration for the resource monitor
type ResourceMonitorConfig struct {
	// Collection interval
	CollectionInterval time.Duration `json:"collectionInterval"`
	
	// Enable specific metrics collection
	EnableCPUMetrics     bool `json:"enableCpuMetrics"`
	EnableMemoryMetrics  bool `json:"enableMemoryMetrics"`
	EnableIOMetrics      bool `json:"enableIoMetrics"`
	EnableNetworkMetrics bool `json:"enableNetworkMetrics"`
	
	// Thresholds for alerts
	CPUAlertThreshold    float64 `json:"cpuAlertThreshold"`    // Percentage
	MemoryAlertThreshold float64 `json:"memoryAlertThreshold"` // Percentage
	
	// History settings
	HistorySize     int           `json:"historySize"`
	RetentionPeriod time.Duration `json:"retentionPeriod"`
	
	// Performance settings
	MaxConcurrentCollections int `json:"maxConcurrentCollections"`
	CollectionTimeout        time.Duration `json:"collectionTimeout"`
}

// MonitorMetrics tracks resource monitor performance
type MonitorMetrics struct {
	mu sync.RWMutex
	
	// Collection statistics
	CollectionsTotal   int64         `json:"collectionsTotal"`
	CollectionsSuccess int64         `json:"collectionsSuccess"`
	CollectionsFailed  int64         `json:"collectionsFailed"`
	AverageLatency     time.Duration `json:"averageLatency"`
	LastCollection     time.Time     `json:"lastCollection"`
	
	// Process statistics
	ProcessesMonitored int `json:"processesMonitored"`
	
	// System resource usage
	SystemCPUPercent    float64 `json:"systemCpuPercent"`
	SystemMemoryPercent float64 `json:"systemMemoryPercent"`
	SystemLoadAverage   float64 `json:"systemLoadAverage"`
}

// SystemInfo holds system-wide information
type SystemInfo struct {
	mu sync.RWMutex
	
	// System specs
	CPUCores      int   `json:"cpuCores"`
	TotalMemory   int64 `json:"totalMemory"`
	TotalSwap     int64 `json:"totalSwap"`
	PageSize      int64 `json:"pageSize"`
	ClockTicks    int64 `json:"clockTicks"`
	
	// Runtime info
	BootTime      time.Time `json:"bootTime"`
	LastUpdate    time.Time `json:"lastUpdate"`
	KernelVersion string    `json:"kernelVersion"`
}

// ProcessResourceHistory holds historical resource usage data
type ProcessResourceHistory struct {
	mu      sync.RWMutex
	samples []*ResourceSample
	maxSize int
}

// ResourceSample represents a single resource usage measurement
type ResourceSample struct {
	Timestamp     time.Time                `json:"timestamp"`
	Usage         *ProcessResourceUsage    `json:"usage"`
	SystemMetrics *SystemResourceSnapshot  `json:"systemMetrics,omitempty"`
}

// SystemResourceSnapshot represents system-wide resource usage at a point in time
type SystemResourceSnapshot struct {
	CPUPercent       float64 `json:"cpuPercent"`
	MemoryPercent    float64 `json:"memoryPercent"`
	SwapPercent      float64 `json:"swapPercent"`
	LoadAverage      float64 `json:"loadAverage"`
	NetworkBytesRecv int64   `json:"networkBytesRecv"`
	NetworkBytesSent int64   `json:"networkBytesSent"`
	DiskBytesRead    int64   `json:"diskBytesRead"`
	DiskBytesWrite   int64   `json:"diskBytesWrite"`
}

// DefaultResourceMonitorConfig returns default configuration
func DefaultResourceMonitorConfig() *ResourceMonitorConfig {
	return &ResourceMonitorConfig{
		CollectionInterval:       2 * time.Second,
		EnableCPUMetrics:         true,
		EnableMemoryMetrics:      true,
		EnableIOMetrics:          true,
		EnableNetworkMetrics:     false, // Disabled by default as it requires container network namespace access
		CPUAlertThreshold:        80.0,  // 80%
		MemoryAlertThreshold:     90.0,  // 90%
		HistorySize:              100,   // Keep 100 samples
		RetentionPeriod:          10 * time.Minute,
		MaxConcurrentCollections: 10,
		CollectionTimeout:        5 * time.Second,
	}
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(config *ResourceMonitorConfig, eventBus *ProcessEventBus) *ResourceMonitor {
	if config == nil {
		config = DefaultResourceMonitorConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	monitor := &ResourceMonitor{
		processes: make(map[string]*ManagedProcess),
		interval:  config.CollectionInterval,
		enabled:   true,
		ctx:       ctx,
		cancel:    cancel,
		eventBus:  eventBus,
		config:    config,
		metrics: &MonitorMetrics{
			LastCollection: time.Now(),
		},
		systemInfo: &SystemInfo{
			LastUpdate: time.Now(),
		},
	}
	
	// Initialize system information
	if err := monitor.initializeSystemInfo(); err != nil {
		log.Warn().Err(err).Msg("Failed to initialize system information")
	}
	
	// Start monitoring goroutine
	monitor.wg.Add(1)
	go monitor.monitorRoutine()
	
	log.Info().
		Dur("interval", config.CollectionInterval).
		Bool("cpu_enabled", config.EnableCPUMetrics).
		Bool("memory_enabled", config.EnableMemoryMetrics).
		Bool("io_enabled", config.EnableIOMetrics).
		Msg("Resource monitor started")
	
	return monitor
}

// AddProcess adds a process to be monitored
func (rm *ResourceMonitor) AddProcess(process *ManagedProcess) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	rm.processes[process.ID] = process
	
	log.Debug().
		Str("process_id", process.ID).
		Int32("pid", process.PID).
		Msg("Added process to resource monitoring")
}

// RemoveProcess removes a process from monitoring
func (rm *ResourceMonitor) RemoveProcess(processID string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	
	delete(rm.processes, processID)
	
	log.Debug().
		Str("process_id", processID).
		Msg("Removed process from resource monitoring")
}

// GetProcessUsage returns current resource usage for a process
func (rm *ResourceMonitor) GetProcessUsage(processID string) *ProcessResourceUsage {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	
	if process, exists := rm.processes[processID]; exists {
		return process.GetResourceUsage()
	}
	
	return nil
}

// GetMetrics returns monitor metrics
func (rm *ResourceMonitor) GetMetrics() MonitorMetrics {
	rm.metrics.mu.RLock()
	defer rm.metrics.mu.RUnlock()
	
	return *rm.metrics
}

// GetSystemInfo returns system information
func (rm *ResourceMonitor) GetSystemInfo() SystemInfo {
	rm.systemInfo.mu.RLock()
	defer rm.systemInfo.mu.RUnlock()
	
	return *rm.systemInfo
}

// Shutdown gracefully shuts down the resource monitor
func (rm *ResourceMonitor) Shutdown(ctx context.Context) error {
	rm.cancel()
	
	done := make(chan struct{})
	go func() {
		rm.wg.Wait()
		close(done)
	}()
	
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		log.Info().Msg("Resource monitor shut down successfully")
		return nil
	}
}

// monitorRoutine is the main monitoring loop
func (rm *ResourceMonitor) monitorRoutine() {
	defer rm.wg.Done()
	
	ticker := time.NewTicker(rm.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			rm.collectAllMetrics()
		case <-rm.ctx.Done():
			return
		}
	}
}

// collectAllMetrics collects metrics for all monitored processes
func (rm *ResourceMonitor) collectAllMetrics() {
	rm.mu.RLock()
	processes := make([]*ManagedProcess, 0, len(rm.processes))
	for _, process := range rm.processes {
		if process.IsRunning() && process.PID > 0 {
			processes = append(processes, process)
		}
	}
	rm.mu.RUnlock()
	
	if len(processes) == 0 {
		return
	}
	
	startTime := time.Now()
	
	// Update metrics
	rm.metrics.mu.Lock()
	rm.metrics.CollectionsTotal++
	rm.metrics.ProcessesMonitored = len(processes)
	rm.metrics.mu.Unlock()
	
	// Collect metrics concurrently with rate limiting
	semaphore := make(chan struct{}, rm.config.MaxConcurrentCollections)
	var wg sync.WaitGroup
	successCount := int64(0)
	
	for _, process := range processes {
		wg.Add(1)
		go func(p *ManagedProcess) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			if rm.collectProcessMetrics(p) {
				successCount++
			}
		}(process)
	}
	
	wg.Wait()
	
	// Update final metrics
	duration := time.Since(startTime)
	rm.metrics.mu.Lock()
	rm.metrics.CollectionsSuccess += successCount
	rm.metrics.CollectionsFailed += int64(len(processes)) - successCount
	rm.metrics.LastCollection = time.Now()
	
	// Update average latency
	if rm.metrics.AverageLatency == 0 {
		rm.metrics.AverageLatency = duration
	} else {
		rm.metrics.AverageLatency = (rm.metrics.AverageLatency + duration) / 2
	}
	rm.metrics.mu.Unlock()
	
	log.Debug().
		Int("processes", len(processes)).
		Int64("successful", successCount).
		Dur("duration", duration).
		Msg("Completed resource collection cycle")
}

// collectProcessMetrics collects metrics for a single process
func (rm *ResourceMonitor) collectProcessMetrics(process *ManagedProcess) bool {
	ctx, cancel := context.WithTimeout(rm.ctx, rm.config.CollectionTimeout)
	defer cancel()
	
	usage, err := rm.getProcessResourceUsage(ctx, process.PID)
	if err != nil {
		log.Debug().
			Err(err).
			Str("process_id", process.ID).
			Int32("pid", process.PID).
			Msg("Failed to collect process metrics")
		
		// Update usage with error
		usage = &ProcessResourceUsage{
			CollectionErr: err,
			LastUpdate:    time.Now(),
		}
	}
	
	// Update process usage
	process.UpdateResourceUsage(usage)
	
	// Publish resource update event if event bus is available
	if rm.eventBus != nil && err == nil {
		rm.eventBus.PublishResourceUpdate(process.ID, process.ContainerID, process.PID, usage)
	}
	
	// Check for threshold alerts
	rm.checkThresholds(process, usage)
	
	return err == nil
}

// getProcessResourceUsage collects resource usage for a specific PID
func (rm *ResourceMonitor) getProcessResourceUsage(ctx context.Context, pid int32) (*ProcessResourceUsage, error) {
	usage := &ProcessResourceUsage{
		LastUpdate: time.Now(),
	}
	
	// Read /proc/[pid]/stat for CPU and memory info
	if rm.config.EnableCPUMetrics || rm.config.EnableMemoryMetrics {
		if err := rm.collectProcStat(pid, usage); err != nil {
			return usage, fmt.Errorf("failed to collect proc stat: %w", err)
		}
	}
	
	// Read /proc/[pid]/status for additional memory info
	if rm.config.EnableMemoryMetrics {
		if err := rm.collectProcStatus(pid, usage); err != nil {
			log.Debug().Err(err).Msg("Failed to collect proc status")
		}
	}
	
	// Read /proc/[pid]/io for I/O metrics
	if rm.config.EnableIOMetrics {
		if err := rm.collectProcIO(pid, usage); err != nil {
			log.Debug().Err(err).Msg("Failed to collect proc I/O")
		}
	}
	
	// Calculate CPU percentage (requires previous sample for accurate calculation)
	if rm.config.EnableCPUMetrics {
		rm.calculateCPUPercent(usage)
	}
	
	// Calculate memory percentage
	if rm.config.EnableMemoryMetrics {
		rm.calculateMemoryPercent(usage)
	}
	
	return usage, nil
}

// collectProcStat reads /proc/[pid]/stat file
func (rm *ResourceMonitor) collectProcStat(pid int32, usage *ProcessResourceUsage) error {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", statPath, err)
	}
	
	fields := strings.Fields(string(data))
	if len(fields) < 24 {
		return fmt.Errorf("insufficient fields in stat file: %d", len(fields))
	}
	
	// Parse relevant fields
	// Field indices based on proc(5) man page
	utime, _ := strconv.ParseInt(fields[13], 10, 64)   // User CPU time
	stime, _ := strconv.ParseInt(fields[14], 10, 64)   // System CPU time
	vsize, _ := strconv.ParseInt(fields[22], 10, 64)   // Virtual memory size
	rss, _ := strconv.ParseInt(fields[23], 10, 64)     // Resident set size (pages)
	
	// Convert to nanoseconds (assuming USER_HZ = 100)
	userHz := int64(100) // This should ideally be obtained from sysconf(_SC_CLK_TCK)
	usage.CPUUserTime = utime * (1000000000 / userHz)
	usage.CPUSystemTime = stime * (1000000000 / userHz)
	usage.CPUTime = usage.CPUUserTime + usage.CPUSystemTime
	
	// Convert memory values
	usage.MemoryVMS = vsize
	usage.MemoryRSS = rss * rm.systemInfo.PageSize // Convert from pages to bytes
	
	return nil
}

// collectProcStatus reads /proc/[pid]/status file for additional memory information
func (rm *ResourceMonitor) collectProcStatus(pid int32, usage *ProcessResourceUsage) error {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	file, err := os.Open(statusPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", statusPath, err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		
		switch fields[0] {
		case "VmSwap:":
			if len(fields) >= 3 && fields[2] == "kB" {
				if swap, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					usage.MemorySwap = swap * 1024 // Convert kB to bytes
				}
			}
		case "FDSize:":
			if fdCount, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				usage.FDCount = int32(fdCount)
			}
		case "Threads:":
			if threads, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				usage.ThreadCount = int32(threads)
			}
		}
	}
	
	return scanner.Err()
}

// collectProcIO reads /proc/[pid]/io file for I/O metrics
func (rm *ResourceMonitor) collectProcIO(pid int32, usage *ProcessResourceUsage) error {
	ioPath := fmt.Sprintf("/proc/%d/io", pid)
	file, err := os.Open(ioPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", ioPath, err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		
		switch fields[0] {
		case "read_bytes:":
			usage.ReadBytes = value
		case "write_bytes:":
			usage.WriteBytes = value
		case "syscr:":
			usage.ReadOps = value
		case "syscw:":
			usage.WriteOps = value
		}
	}
	
	return scanner.Err()
}

// calculateCPUPercent calculates CPU usage percentage
func (rm *ResourceMonitor) calculateCPUPercent(usage *ProcessResourceUsage) {
	// This is a simplified calculation
	// For accurate CPU percentage, we would need to compare with previous sample
	// and system total CPU time
	
	// For now, we'll use a basic estimation
	totalCPUTime := usage.CPUTime
	if totalCPUTime > 0 && rm.systemInfo.CPUCores > 0 {
		// This is an approximation - real implementation would need time delta
		usage.CPUPercent = float64(totalCPUTime) / float64(time.Second) / float64(rm.systemInfo.CPUCores) * 100.0
		
		// Cap at reasonable values
		if usage.CPUPercent > 100.0 {
			usage.CPUPercent = 100.0
		}
	}
}

// calculateMemoryPercent calculates memory usage percentage
func (rm *ResourceMonitor) calculateMemoryPercent(usage *ProcessResourceUsage) {
	if rm.systemInfo.TotalMemory > 0 {
		usage.MemoryPercent = float64(usage.MemoryRSS) / float64(rm.systemInfo.TotalMemory) * 100.0
	}
}

// checkThresholds checks if any thresholds are exceeded and publishes alerts
func (rm *ResourceMonitor) checkThresholds(process *ManagedProcess, usage *ProcessResourceUsage) {
	if rm.eventBus == nil {
		return
	}
	
	// Check CPU threshold
	if rm.config.EnableCPUMetrics && usage.CPUPercent > rm.config.CPUAlertThreshold {
		rm.eventBus.PublishError(
			process.ID,
			process.ContainerID,
			process.PID,
			fmt.Errorf("CPU usage (%.2f%%) exceeded threshold (%.2f%%)", 
				usage.CPUPercent, rm.config.CPUAlertThreshold),
		)
	}
	
	// Check memory threshold
	if rm.config.EnableMemoryMetrics && usage.MemoryPercent > rm.config.MemoryAlertThreshold {
		rm.eventBus.PublishError(
			process.ID,
			process.ContainerID,
			process.PID,
			fmt.Errorf("Memory usage (%.2f%%) exceeded threshold (%.2f%%)",
				usage.MemoryPercent, rm.config.MemoryAlertThreshold),
		)
	}
}

// initializeSystemInfo initializes system information
func (rm *ResourceMonitor) initializeSystemInfo() error {
	rm.systemInfo.mu.Lock()
	defer rm.systemInfo.mu.Unlock()
	
	// Get number of CPU cores
	if cores, err := rm.getCPUCores(); err == nil {
		rm.systemInfo.CPUCores = cores
	}
	
	// Get total memory
	if memory, err := rm.getTotalMemory(); err == nil {
		rm.systemInfo.TotalMemory = memory
	}
	
	// Get page size
	rm.systemInfo.PageSize = int64(os.Getpagesize())
	
	// Get clock ticks per second
	rm.systemInfo.ClockTicks = 100 // Default USER_HZ, should be obtained from sysconf
	
	rm.systemInfo.LastUpdate = time.Now()
	
	return nil
}

// getCPUCores returns the number of CPU cores
func (rm *ResourceMonitor) getCPUCores() (int, error) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0, err
	}
	
	lines := strings.Split(string(data), "\n")
	cores := 0
	
	for _, line := range lines {
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}
	
	if cores == 0 {
		cores = 1 // Fallback
	}
	
	return cores, nil
}

// getTotalMemory returns total system memory in bytes
func (rm *ResourceMonitor) getTotalMemory() (int64, error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, err := strconv.ParseInt(fields[1], 10, 64)
				if err == nil {
					return totalKB * 1024, nil // Convert kB to bytes
				}
			}
		}
	}
	
	return 0, fmt.Errorf("could not find MemTotal in /proc/meminfo")
}

// NewProcessResourceHistory creates a new resource history tracker
func NewProcessResourceHistory(maxSize int) *ProcessResourceHistory {
	return &ProcessResourceHistory{
		samples: make([]*ResourceSample, 0, maxSize),
		maxSize: maxSize,
	}
}

// AddSample adds a resource usage sample to the history
func (prh *ProcessResourceHistory) AddSample(usage *ProcessResourceUsage) {
	prh.mu.Lock()
	defer prh.mu.Unlock()
	
	sample := &ResourceSample{
		Timestamp: time.Now(),
		Usage:     usage,
	}
	
	if len(prh.samples) >= prh.maxSize {
		// Remove oldest sample
		copy(prh.samples, prh.samples[1:])
		prh.samples[len(prh.samples)-1] = sample
	} else {
		prh.samples = append(prh.samples, sample)
	}
}

// GetSamples returns a copy of all samples
func (prh *ProcessResourceHistory) GetSamples() []*ResourceSample {
	prh.mu.RLock()
	defer prh.mu.RUnlock()
	
	samples := make([]*ResourceSample, len(prh.samples))
	copy(samples, prh.samples)
	return samples
}

// GetLatestSample returns the most recent sample
func (prh *ProcessResourceHistory) GetLatestSample() *ResourceSample {
	prh.mu.RLock()
	defer prh.mu.RUnlock()
	
	if len(prh.samples) == 0 {
		return nil
	}
	
	return prh.samples[len(prh.samples)-1]
}