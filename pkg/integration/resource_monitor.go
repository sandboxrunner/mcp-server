package integration

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ResourceUsage represents current resource utilization metrics
type ResourceUsage struct {
	// Memory metrics
	MemoryUsedMB     float64
	MemoryAvailableMB float64
	MemoryPercent    float64
	
	// CPU metrics
	CPUPercent       float64
	LoadAverage1Min  float64
	
	// Disk metrics
	DiskUsedMB       float64
	DiskAvailableMB  float64
	DiskPercent      float64
	
	// Process metrics
	ActiveProcesses  int
	TotalThreads     int
	
	// Container-specific metrics
	ActiveContainers int
	
	// Timestamps
	Timestamp        time.Time
}

// ResourceMonitor provides real-time resource monitoring capabilities
type ResourceMonitor struct {
	usage     ResourceUsage
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	
	// Configuration
	updateInterval time.Duration
	
	// Historical data
	history       []ResourceUsage
	maxHistory    int
	
	// Alerting
	memoryThreshold float64
	cpuThreshold    float64
	alertCallback   func(ResourceUsage)
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor() *ResourceMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	monitor := &ResourceMonitor{
		ctx:             ctx,
		cancel:          cancel,
		updateInterval:  time.Second,
		maxHistory:      60, // Keep 1 minute of history
		memoryThreshold: 80.0, // Alert at 80% memory usage
		cpuThreshold:    90.0,  // Alert at 90% CPU usage
		history:         make([]ResourceUsage, 0, 60),
	}
	
	monitor.start()
	return monitor
}

// start begins resource monitoring in a background goroutine
func (m *ResourceMonitor) start() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(m.updateInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.updateUsage()
			}
		}
	}()
}

// updateUsage collects current resource usage metrics
func (m *ResourceMonitor) updateUsage() {
	usage := ResourceUsage{
		Timestamp: time.Now(),
	}
	
	// Collect Go runtime memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	usage.MemoryUsedMB = float64(memStats.Alloc) / (1024 * 1024)
	usage.MemoryAvailableMB = float64(memStats.Sys) / (1024 * 1024)
	
	if usage.MemoryAvailableMB > 0 {
		usage.MemoryPercent = (usage.MemoryUsedMB / usage.MemoryAvailableMB) * 100
	}
	
	// Collect system metrics (simplified - in real implementation would use proper system APIs)
	usage.CPUPercent = m.getCPUUsage()
	usage.LoadAverage1Min = m.getLoadAverage()
	usage.ActiveProcesses = runtime.NumGoroutine() // Simplified
	usage.TotalThreads = runtime.GOMAXPROCS(0)
	
	// Update current usage
	m.mu.Lock()
	m.usage = usage
	
	// Add to history
	m.history = append(m.history, usage)
	if len(m.history) > m.maxHistory {
		m.history = m.history[1:]
	}
	m.mu.Unlock()
	
	// Check for alerts
	m.checkAlerts(usage)
	
	log.Debug().
		Float64("memory_mb", usage.MemoryUsedMB).
		Float64("memory_percent", usage.MemoryPercent).
		Float64("cpu_percent", usage.CPUPercent).
		Int("goroutines", usage.ActiveProcesses).
		Msg("Resource usage updated")
}

// getCPUUsage returns current CPU utilization percentage (simplified implementation)
func (m *ResourceMonitor) getCPUUsage() float64 {
	// This is a simplified implementation
	// In production, you'd want to use proper system APIs like /proc/stat on Linux
	return float64(runtime.NumGoroutine()) * 0.1 // Rough approximation
}

// getLoadAverage returns the 1-minute load average (simplified implementation)
func (m *ResourceMonitor) getLoadAverage() float64 {
	// This is a simplified implementation
	// In production, you'd read from /proc/loadavg on Linux
	return float64(runtime.NumGoroutine()) * 0.01
}

// checkAlerts checks if resource usage exceeds thresholds and triggers alerts
func (m *ResourceMonitor) checkAlerts(usage ResourceUsage) {
	if m.alertCallback == nil {
		return
	}
	
	alertTriggered := false
	
	if usage.MemoryPercent > m.memoryThreshold {
		log.Warn().
			Float64("memory_percent", usage.MemoryPercent).
			Float64("threshold", m.memoryThreshold).
			Msg("Memory usage threshold exceeded")
		alertTriggered = true
	}
	
	if usage.CPUPercent > m.cpuThreshold {
		log.Warn().
			Float64("cpu_percent", usage.CPUPercent).
			Float64("threshold", m.cpuThreshold).
			Msg("CPU usage threshold exceeded")
		alertTriggered = true
	}
	
	if alertTriggered {
		go m.alertCallback(usage)
	}
}

// GetCurrentUsage returns the current resource usage snapshot
func (m *ResourceMonitor) GetCurrentUsage() ResourceUsage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.usage
}

// GetHistory returns historical resource usage data
func (m *ResourceMonitor) GetHistory() []ResourceUsage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	history := make([]ResourceUsage, len(m.history))
	copy(history, m.history)
	return history
}

// GetAverageUsage calculates average resource usage over the specified duration
func (m *ResourceMonitor) GetAverageUsage(duration time.Duration) ResourceUsage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if len(m.history) == 0 {
		return ResourceUsage{}
	}
	
	cutoff := time.Now().Add(-duration)
	var relevant []ResourceUsage
	
	for _, usage := range m.history {
		if usage.Timestamp.After(cutoff) {
			relevant = append(relevant, usage)
		}
	}
	
	if len(relevant) == 0 {
		return m.usage
	}
	
	// Calculate averages
	avg := ResourceUsage{Timestamp: time.Now()}
	for _, usage := range relevant {
		avg.MemoryUsedMB += usage.MemoryUsedMB
		avg.MemoryPercent += usage.MemoryPercent
		avg.CPUPercent += usage.CPUPercent
		avg.ActiveProcesses += usage.ActiveProcesses
	}
	
	count := float64(len(relevant))
	avg.MemoryUsedMB /= count
	avg.MemoryPercent /= count
	avg.CPUPercent /= count
	avg.ActiveProcesses = int(float64(avg.ActiveProcesses) / count)
	
	return avg
}

// GetPeakUsage returns the peak resource usage over the specified duration
func (m *ResourceMonitor) GetPeakUsage(duration time.Duration) ResourceUsage {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	if len(m.history) == 0 {
		return ResourceUsage{}
	}
	
	cutoff := time.Now().Add(-duration)
	var peak ResourceUsage
	
	for _, usage := range m.history {
		if usage.Timestamp.After(cutoff) {
			if usage.MemoryPercent > peak.MemoryPercent {
				peak.MemoryPercent = usage.MemoryPercent
				peak.MemoryUsedMB = usage.MemoryUsedMB
			}
			if usage.CPUPercent > peak.CPUPercent {
				peak.CPUPercent = usage.CPUPercent
			}
		}
	}
	
	peak.Timestamp = time.Now()
	return peak
}

// SetAlertThresholds configures resource usage alert thresholds
func (m *ResourceMonitor) SetAlertThresholds(memoryPercent, cpuPercent float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.memoryThreshold = memoryPercent
	m.cpuThreshold = cpuPercent
}

// SetAlertCallback sets the function to call when resource thresholds are exceeded
func (m *ResourceMonitor) SetAlertCallback(callback func(ResourceUsage)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alertCallback = callback
}

// SetUpdateInterval configures how frequently resource usage is updated
func (m *ResourceMonitor) SetUpdateInterval(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateInterval = interval
}

// WaitForResourceStabilization waits for resource usage to stabilize within thresholds
func (m *ResourceMonitor) WaitForResourceStabilization(ctx context.Context, memoryThreshold, cpuThreshold float64, stabilityDuration time.Duration) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	stableStart := time.Time{}
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			usage := m.GetCurrentUsage()
			
			isStable := usage.MemoryPercent <= memoryThreshold && usage.CPUPercent <= cpuThreshold
			
			if isStable {
				if stableStart.IsZero() {
					stableStart = time.Now()
				} else if time.Since(stableStart) >= stabilityDuration {
					return nil // Stabilized
				}
			} else {
				stableStart = time.Time{} // Reset stability timer
			}
		}
	}
}

// Stop terminates the resource monitor
func (m *ResourceMonitor) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

// ResourceSnapshot captures a point-in-time view of resources for testing
type ResourceSnapshot struct {
	Before ResourceUsage
	After  ResourceUsage
	Delta  ResourceUsage
}

// TakeSnapshot captures current resource usage for before/after comparison
func (m *ResourceMonitor) TakeSnapshot() ResourceUsage {
	return m.GetCurrentUsage()
}

// CompareSnapshots creates a ResourceSnapshot comparing two points in time
func (m *ResourceMonitor) CompareSnapshots(before, after ResourceUsage) ResourceSnapshot {
	return ResourceSnapshot{
		Before: before,
		After:  after,
		Delta: ResourceUsage{
			MemoryUsedMB:  after.MemoryUsedMB - before.MemoryUsedMB,
			MemoryPercent: after.MemoryPercent - before.MemoryPercent,
			CPUPercent:    after.CPUPercent - before.CPUPercent,
			ActiveProcesses: after.ActiveProcesses - before.ActiveProcesses,
			Timestamp:     after.Timestamp,
		},
	}
}

// PrintUsageSummary logs a summary of current resource usage
func (m *ResourceMonitor) PrintUsageSummary() {
	usage := m.GetCurrentUsage()
	
	log.Info().
		Float64("memory_used_mb", usage.MemoryUsedMB).
		Float64("memory_percent", usage.MemoryPercent).
		Float64("cpu_percent", usage.CPUPercent).
		Int("active_processes", usage.ActiveProcesses).
		Int("active_containers", usage.ActiveContainers).
		Msg("Current resource usage summary")
}