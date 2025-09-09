package monitoring

import (
	"runtime"
	"runtime/debug"
	"time"
	"os"
	"syscall"
	"bufio"
	"strings"
	"strconv"
	"fmt"
)

// ProcessCollector collects process-level metrics
type ProcessCollector struct {
	processStartTime time.Time
}

// NewProcessCollector creates a new process collector
func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{
		processStartTime: time.Now(),
	}
}

// Describe describes the metrics
func (pc *ProcessCollector) Describe(ch chan<- *Metric) {
	ch <- &Metric{
		Name: "process_cpu_seconds_total",
		Type: MetricTypeCounter,
		Help: "Total user and system CPU time spent in seconds",
	}
	ch <- &Metric{
		Name: "process_open_fds",
		Type: MetricTypeGauge,
		Help: "Number of open file descriptors",
	}
	ch <- &Metric{
		Name: "process_max_fds",
		Type: MetricTypeGauge,
		Help: "Maximum number of open file descriptors",
	}
	ch <- &Metric{
		Name: "process_virtual_memory_bytes",
		Type: MetricTypeGauge,
		Help: "Virtual memory size in bytes",
	}
	ch <- &Metric{
		Name: "process_resident_memory_bytes",
		Type: MetricTypeGauge,
		Help: "Resident memory size in bytes",
	}
	ch <- &Metric{
		Name: "process_start_time_seconds",
		Type: MetricTypeGauge,
		Help: "Start time of the process since unix epoch in seconds",
	}
}

// Collect collects the metrics
func (pc *ProcessCollector) Collect(ch chan<- *Metric) {
	now := time.Now()
	
	// CPU time
	if cpuTime := pc.getCPUTime(); cpuTime >= 0 {
		ch <- &Metric{
			Name: "process_cpu_seconds_total",
			Type: MetricTypeCounter,
			Help: "Total user and system CPU time spent in seconds",
			Values: []MetricValue{{
				Value:     cpuTime,
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}
	}

	// File descriptors
	if openFDs := pc.getOpenFDs(); openFDs >= 0 {
		ch <- &Metric{
			Name: "process_open_fds",
			Type: MetricTypeGauge,
			Help: "Number of open file descriptors",
			Values: []MetricValue{{
				Value:     float64(openFDs),
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}
	}

	if maxFDs := pc.getMaxFDs(); maxFDs >= 0 {
		ch <- &Metric{
			Name: "process_max_fds",
			Type: MetricTypeGauge,
			Help: "Maximum number of open file descriptors",
			Values: []MetricValue{{
				Value:     float64(maxFDs),
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}
	}

	// Memory usage
	if vmSize, rssSize := pc.getMemoryUsage(); vmSize >= 0 && rssSize >= 0 {
		ch <- &Metric{
			Name: "process_virtual_memory_bytes",
			Type: MetricTypeGauge,
			Help: "Virtual memory size in bytes",
			Values: []MetricValue{{
				Value:     float64(vmSize),
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}

		ch <- &Metric{
			Name: "process_resident_memory_bytes",
			Type: MetricTypeGauge,
			Help: "Resident memory size in bytes",
			Values: []MetricValue{{
				Value:     float64(rssSize),
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}
	}

	// Process start time
	ch <- &Metric{
		Name: "process_start_time_seconds",
		Type: MetricTypeGauge,
		Help: "Start time of the process since unix epoch in seconds",
		Values: []MetricValue{{
			Value:     float64(pc.processStartTime.Unix()),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}
}

// getCPUTime returns the total CPU time in seconds
func (pc *ProcessCollector) getCPUTime() float64 {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &rusage); err != nil {
		return -1
	}
	
	userTime := float64(rusage.Utime.Sec) + float64(rusage.Utime.Usec)/1e6
	sysTime := float64(rusage.Stime.Sec) + float64(rusage.Stime.Usec)/1e6
	return userTime + sysTime
}

// getOpenFDs returns the number of open file descriptors
func (pc *ProcessCollector) getOpenFDs() int {
	// Count files in /proc/self/fd
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(entries)
}

// getMaxFDs returns the maximum number of file descriptors
func (pc *ProcessCollector) getMaxFDs() int {
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		return -1
	}
	return int(rlimit.Cur)
}

// getMemoryUsage returns virtual and resident memory size in bytes
func (pc *ProcessCollector) getMemoryUsage() (int64, int64) {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return -1, -1
	}
	defer file.Close()

	var vmSize, rssSize int64 = -1, -1
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmSize:") {
			if size, err := pc.parseMemoryLine(line); err == nil {
				vmSize = size * 1024 // Convert KB to bytes
			}
		} else if strings.HasPrefix(line, "VmRSS:") {
			if size, err := pc.parseMemoryLine(line); err == nil {
				rssSize = size * 1024 // Convert KB to bytes
			}
		}
		
		if vmSize >= 0 && rssSize >= 0 {
			break
		}
	}
	
	return vmSize, rssSize
}

// parseMemoryLine parses a memory line from /proc/self/status
func (pc *ProcessCollector) parseMemoryLine(line string) (int64, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0, fmt.Errorf("invalid memory line format")
	}
	return strconv.ParseInt(fields[1], 10, 64)
}

// GoCollector collects Go runtime metrics
type GoCollector struct{}

// NewGoCollector creates a new Go collector
func NewGoCollector() *GoCollector {
	return &GoCollector{}
}

// Describe describes the metrics
func (gc *GoCollector) Describe(ch chan<- *Metric) {
	ch <- &Metric{
		Name: "go_goroutines",
		Type: MetricTypeGauge,
		Help: "Number of goroutines that currently exist",
	}
	ch <- &Metric{
		Name: "go_threads",
		Type: MetricTypeGauge,
		Help: "Number of OS threads created",
	}
	ch <- &Metric{
		Name: "go_gc_duration_seconds",
		Type: MetricTypeSummary,
		Help: "A summary of the pause duration of garbage collection cycles",
	}
	ch <- &Metric{
		Name: "go_memstats_alloc_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes allocated and still in use",
	}
	ch <- &Metric{
		Name: "go_memstats_alloc_bytes_total",
		Type: MetricTypeCounter,
		Help: "Total number of bytes allocated, even if freed",
	}
	ch <- &Metric{
		Name: "go_memstats_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes obtained from system",
	}
	ch <- &Metric{
		Name: "go_memstats_lookups_total",
		Type: MetricTypeCounter,
		Help: "Total number of pointer lookups",
	}
	ch <- &Metric{
		Name: "go_memstats_mallocs_total",
		Type: MetricTypeCounter,
		Help: "Total number of mallocs",
	}
	ch <- &Metric{
		Name: "go_memstats_frees_total",
		Type: MetricTypeCounter,
		Help: "Total number of frees",
	}
	ch <- &Metric{
		Name: "go_memstats_heap_alloc_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes allocated and still in use",
	}
	ch <- &Metric{
		Name: "go_memstats_heap_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes obtained from system",
	}
	ch <- &Metric{
		Name: "go_memstats_heap_idle_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes waiting to be used",
	}
	ch <- &Metric{
		Name: "go_memstats_heap_inuse_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes that are in use",
	}
	ch <- &Metric{
		Name: "go_memstats_heap_released_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes released to OS",
	}
	ch <- &Metric{
		Name: "go_memstats_heap_objects",
		Type: MetricTypeGauge,
		Help: "Number of allocated objects",
	}
	ch <- &Metric{
		Name: "go_memstats_stack_inuse_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes in use by the stack allocator",
	}
	ch <- &Metric{
		Name: "go_memstats_stack_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes obtained from system for stack allocator",
	}
	ch <- &Metric{
		Name: "go_memstats_mspan_inuse_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes in use by mspan structures",
	}
	ch <- &Metric{
		Name: "go_memstats_mspan_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used for mspan structures obtained from system",
	}
	ch <- &Metric{
		Name: "go_memstats_mcache_inuse_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes in use by mcache structures",
	}
	ch <- &Metric{
		Name: "go_memstats_mcache_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used for mcache structures obtained from system",
	}
	ch <- &Metric{
		Name: "go_memstats_buck_hash_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used by the profiling bucket hash table",
	}
	ch <- &Metric{
		Name: "go_memstats_gc_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used for garbage collection system metadata",
	}
	ch <- &Metric{
		Name: "go_memstats_other_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used for other system allocations",
	}
	ch <- &Metric{
		Name: "go_memstats_next_gc_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes when next garbage collection will take place",
	}
	ch <- &Metric{
		Name: "go_memstats_last_gc_time_seconds",
		Type: MetricTypeGauge,
		Help: "Number of seconds since 1970 of last garbage collection",
	}
	ch <- &Metric{
		Name: "go_memstats_gc_cpu_fraction",
		Type: MetricTypeGauge,
		Help: "The fraction of this program's available CPU time used by the GC since the program started",
	}
}

// Collect collects the metrics
func (gc *GoCollector) Collect(ch chan<- *Metric) {
	now := time.Now()
	
	// Basic Go runtime metrics
	ch <- &Metric{
		Name: "go_goroutines",
		Type: MetricTypeGauge,
		Help: "Number of goroutines that currently exist",
		Values: []MetricValue{{
			Value:     float64(runtime.NumGoroutine()),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Memory allocation metrics
	ch <- &Metric{
		Name: "go_memstats_alloc_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes allocated and still in use",
		Values: []MetricValue{{
			Value:     float64(memStats.Alloc),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_alloc_bytes_total",
		Type: MetricTypeCounter,
		Help: "Total number of bytes allocated, even if freed",
		Values: []MetricValue{{
			Value:     float64(memStats.TotalAlloc),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes obtained from system",
		Values: []MetricValue{{
			Value:     float64(memStats.Sys),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_lookups_total",
		Type: MetricTypeCounter,
		Help: "Total number of pointer lookups",
		Values: []MetricValue{{
			Value:     float64(memStats.Lookups),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_mallocs_total",
		Type: MetricTypeCounter,
		Help: "Total number of mallocs",
		Values: []MetricValue{{
			Value:     float64(memStats.Mallocs),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_frees_total",
		Type: MetricTypeCounter,
		Help: "Total number of frees",
		Values: []MetricValue{{
			Value:     float64(memStats.Frees),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	// Heap metrics
	ch <- &Metric{
		Name: "go_memstats_heap_alloc_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes allocated and still in use",
		Values: []MetricValue{{
			Value:     float64(memStats.HeapAlloc),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_heap_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes obtained from system",
		Values: []MetricValue{{
			Value:     float64(memStats.HeapSys),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_heap_idle_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes waiting to be used",
		Values: []MetricValue{{
			Value:     float64(memStats.HeapIdle),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_heap_inuse_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes that are in use",
		Values: []MetricValue{{
			Value:     float64(memStats.HeapInuse),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_heap_released_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes released to OS",
		Values: []MetricValue{{
			Value:     float64(memStats.HeapReleased),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_heap_objects",
		Type: MetricTypeGauge,
		Help: "Number of allocated objects",
		Values: []MetricValue{{
			Value:     float64(memStats.HeapObjects),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	// Stack metrics
	ch <- &Metric{
		Name: "go_memstats_stack_inuse_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes in use by the stack allocator",
		Values: []MetricValue{{
			Value:     float64(memStats.StackInuse),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_stack_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes obtained from system for stack allocator",
		Values: []MetricValue{{
			Value:     float64(memStats.StackSys),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	// Other allocator metrics
	ch <- &Metric{
		Name: "go_memstats_mspan_inuse_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes in use by mspan structures",
		Values: []MetricValue{{
			Value:     float64(memStats.MSpanInuse),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_mspan_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used for mspan structures obtained from system",
		Values: []MetricValue{{
			Value:     float64(memStats.MSpanSys),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_mcache_inuse_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes in use by mcache structures",
		Values: []MetricValue{{
			Value:     float64(memStats.MCacheInuse),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_mcache_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used for mcache structures obtained from system",
		Values: []MetricValue{{
			Value:     float64(memStats.MCacheSys),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_buck_hash_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used by the profiling bucket hash table",
		Values: []MetricValue{{
			Value:     float64(memStats.BuckHashSys),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_gc_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used for garbage collection system metadata",
		Values: []MetricValue{{
			Value:     float64(memStats.GCSys),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_other_sys_bytes",
		Type: MetricTypeGauge,
		Help: "Number of bytes used for other system allocations",
		Values: []MetricValue{{
			Value:     float64(memStats.OtherSys),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	// GC metrics
	ch <- &Metric{
		Name: "go_memstats_next_gc_bytes",
		Type: MetricTypeGauge,
		Help: "Number of heap bytes when next garbage collection will take place",
		Values: []MetricValue{{
			Value:     float64(memStats.NextGC),
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_last_gc_time_seconds",
		Type: MetricTypeGauge,
		Help: "Number of seconds since 1970 of last garbage collection",
		Values: []MetricValue{{
			Value:     float64(memStats.LastGC) / 1e9,
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	ch <- &Metric{
		Name: "go_memstats_gc_cpu_fraction",
		Type: MetricTypeGauge,
		Help: "The fraction of this program's available CPU time used by the GC since the program started",
		Values: []MetricValue{{
			Value:     memStats.GCCPUFraction,
			Timestamp: now,
			Labels:    make(MetricLabels),
		}},
	}

	// GC duration summary (simplified)
	if memStats.NumGC > 0 {
		// Calculate average GC pause time from recent GCs
		var totalPause time.Duration
		count := int(memStats.NumGC)
		if count > 256 {
			count = 256 // Only look at recent GCs
		}
		
		for i := 0; i < count; i++ {
			totalPause += time.Duration(memStats.PauseNs[i])
		}
		
		avgPause := float64(totalPause) / float64(count) / 1e9 // Convert to seconds
		
		ch <- &Metric{
			Name: "go_gc_duration_seconds",
			Type: MetricTypeSummary,
			Help: "A summary of the pause duration of garbage collection cycles",
			Values: []MetricValue{
				{
					Value:     avgPause,
					Timestamp: now,
					Labels:    MetricLabels{"quantile": "0.5"},
				},
				{
					Value:     avgPause * 1.5, // Approximate 90th percentile
					Timestamp: now,
					Labels:    MetricLabels{"quantile": "0.9"},
				},
				{
					Value:     float64(count),
					Timestamp: now,
					Labels:    make(MetricLabels),
					Metadata:  map[string]interface{}{"suffix": "_count"},
				},
				{
					Value:     float64(totalPause) / 1e9,
					Timestamp: now,
					Labels:    make(MetricLabels),
					Metadata:  map[string]interface{}{"suffix": "_sum"},
				},
			},
		}
	}
}

// BuildInfoCollector collects build information
type BuildInfoCollector struct {
	buildInfo *debug.BuildInfo
}

// NewBuildInfoCollector creates a new build info collector
func NewBuildInfoCollector() *BuildInfoCollector {
	buildInfo, _ := debug.ReadBuildInfo()
	return &BuildInfoCollector{
		buildInfo: buildInfo,
	}
}

// Describe describes the metrics
func (bic *BuildInfoCollector) Describe(ch chan<- *Metric) {
	ch <- &Metric{
		Name: "go_build_info",
		Type: MetricTypeGauge,
		Help: "Build information about the main Go module",
	}
}

// Collect collects the metrics
func (bic *BuildInfoCollector) Collect(ch chan<- *Metric) {
	if bic.buildInfo == nil {
		return
	}

	now := time.Now()
	labels := make(MetricLabels)
	
	// Add main module info
	if bic.buildInfo.Main.Path != "" {
		labels["path"] = bic.buildInfo.Main.Path
	}
	if bic.buildInfo.Main.Version != "" {
		labels["version"] = bic.buildInfo.Main.Version
	}
	if bic.buildInfo.Main.Sum != "" {
		labels["checksum"] = bic.buildInfo.Main.Sum
	}

	// Add build settings
	for _, setting := range bic.buildInfo.Settings {
		switch setting.Key {
		case "GOARCH":
			labels["goarch"] = setting.Value
		case "GOOS":
			labels["goos"] = setting.Value
		case "GOVERSION":
			labels["goversion"] = setting.Value
		case "vcs.revision":
			labels["revision"] = setting.Value
		case "vcs.time":
			labels["build_time"] = setting.Value
		case "vcs.modified":
			labels["modified"] = setting.Value
		}
	}

	ch <- &Metric{
		Name: "go_build_info",
		Type: MetricTypeGauge,
		Help: "Build information about the main Go module",
		Values: []MetricValue{{
			Value:     1,
			Timestamp: now,
			Labels:    labels,
		}},
	}
}

// SandboxMetricsCollector collects sandbox-specific metrics
type SandboxMetricsCollector struct {
	metricsGetter func() map[string]interface{}
}

// NewSandboxMetricsCollector creates a new sandbox metrics collector
func NewSandboxMetricsCollector(metricsGetter func() map[string]interface{}) *SandboxMetricsCollector {
	return &SandboxMetricsCollector{
		metricsGetter: metricsGetter,
	}
}

// Describe describes the metrics
func (smc *SandboxMetricsCollector) Describe(ch chan<- *Metric) {
	ch <- &Metric{
		Name: "sandbox_containers_total",
		Type: MetricTypeGauge,
		Help: "Total number of containers",
	}
	ch <- &Metric{
		Name: "sandbox_containers_by_state",
		Type: MetricTypeGauge,
		Help: "Number of containers by state",
		Labels: []string{"state"},
	}
	ch <- &Metric{
		Name: "sandbox_containers_by_health",
		Type: MetricTypeGauge,
		Help: "Number of containers by health status",
		Labels: []string{"health"},
	}
	ch <- &Metric{
		Name: "sandbox_events_total",
		Type: MetricTypeCounter,
		Help: "Total number of events",
	}
	ch <- &Metric{
		Name: "sandbox_events_by_type",
		Type: MetricTypeCounter,
		Help: "Number of events by type",
		Labels: []string{"type"},
	}
	ch <- &Metric{
		Name: "sandbox_events_by_severity",
		Type: MetricTypeCounter,
		Help: "Number of events by severity",
		Labels: []string{"severity"},
	}
	ch <- &Metric{
		Name: "sandbox_startup_duration_seconds",
		Type: MetricTypeGauge,
		Help: "Average container startup duration in seconds",
	}
	ch <- &Metric{
		Name: "sandbox_health_check_duration_seconds",
		Type: MetricTypeGauge,
		Help: "Average health check duration in seconds",
	}
	ch <- &Metric{
		Name: "sandbox_resource_usage_ratio",
		Type: MetricTypeGauge,
		Help: "Resource usage as a ratio (0-1)",
		Labels: []string{"resource"},
	}
}

// Collect collects the metrics
func (smc *SandboxMetricsCollector) Collect(ch chan<- *Metric) {
	if smc.metricsGetter == nil {
		return
	}

	metrics := smc.metricsGetter()
	now := time.Now()

	// Total containers
	if totalContainers, ok := metrics["total_containers"].(int); ok {
		ch <- &Metric{
			Name: "sandbox_containers_total",
			Type: MetricTypeGauge,
			Help: "Total number of containers",
			Values: []MetricValue{{
				Value:     float64(totalContainers),
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}
	}

	// Containers by state
	if stateDistribution, ok := metrics["state_distribution"].(map[interface{}]interface{}); ok {
		for state, count := range stateDistribution {
			if stateStr, ok := state.(string); ok {
				if countInt, ok := count.(int); ok {
					ch <- &Metric{
						Name: "sandbox_containers_by_state",
						Type: MetricTypeGauge,
						Help: "Number of containers by state",
						Values: []MetricValue{{
							Value:     float64(countInt),
							Timestamp: now,
							Labels:    MetricLabels{"state": stateStr},
						}},
					}
				}
			}
		}
	}

	// Health containers
	healthMetrics := map[string]string{
		"healthy_containers":   "healthy",
		"unhealthy_containers": "unhealthy",
		"warning_containers":   "warning",
		"unknown_health_containers": "unknown",
	}

	for key, healthStatus := range healthMetrics {
		if value, ok := metrics[key].(int); ok {
			ch <- &Metric{
				Name: "sandbox_containers_by_health",
				Type: MetricTypeGauge,
				Help: "Number of containers by health status",
				Values: []MetricValue{{
					Value:     float64(value),
					Timestamp: now,
					Labels:    MetricLabels{"health": healthStatus},
				}},
			}
		}
	}

	// Total events
	if totalEvents, ok := metrics["total_events"].(int); ok {
		ch <- &Metric{
			Name: "sandbox_events_total",
			Type: MetricTypeCounter,
			Help: "Total number of events",
			Values: []MetricValue{{
				Value:     float64(totalEvents),
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}
	}

	// Events by type
	if eventsByType, ok := metrics["events_by_type"].(map[interface{}]interface{}); ok {
		for eventType, count := range eventsByType {
			if typeStr, ok := eventType.(string); ok {
				if countInt, ok := count.(int); ok {
					ch <- &Metric{
						Name: "sandbox_events_by_type",
						Type: MetricTypeCounter,
						Help: "Number of events by type",
						Values: []MetricValue{{
							Value:     float64(countInt),
							Timestamp: now,
							Labels:    MetricLabels{"type": typeStr},
						}},
					}
				}
			}
		}
	}

	// Events by severity
	if eventsBySeverity, ok := metrics["events_by_severity"].(map[interface{}]interface{}); ok {
		for severity, count := range eventsBySeverity {
			if severityStr, ok := severity.(string); ok {
				if countInt, ok := count.(int); ok {
					ch <- &Metric{
						Name: "sandbox_events_by_severity",
						Type: MetricTypeCounter,
						Help: "Number of events by severity",
						Values: []MetricValue{{
							Value:     float64(countInt),
							Timestamp: now,
							Labels:    MetricLabels{"severity": severityStr},
						}},
					}
				}
			}
		}
	}

	// Startup duration
	if avgStartupTime, ok := metrics["average_startup_time"]; ok {
		var seconds float64
		switch v := avgStartupTime.(type) {
		case time.Duration:
			seconds = v.Seconds()
		case float64:
			seconds = v
		case int64:
			seconds = float64(v) / 1e9 // Assume nanoseconds
		}

		ch <- &Metric{
			Name: "sandbox_startup_duration_seconds",
			Type: MetricTypeGauge,
			Help: "Average container startup duration in seconds",
			Values: []MetricValue{{
				Value:     seconds,
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}
	}

	// Health check duration
	if avgHealthCheckTime, ok := metrics["average_health_check_time"]; ok {
		var seconds float64
		switch v := avgHealthCheckTime.(type) {
		case time.Duration:
			seconds = v.Seconds()
		case float64:
			seconds = v
		case int64:
			seconds = float64(v) / 1e9 // Assume nanoseconds
		}

		ch <- &Metric{
			Name: "sandbox_health_check_duration_seconds",
			Type: MetricTypeGauge,
			Help: "Average health check duration in seconds",
			Values: []MetricValue{{
				Value:     seconds,
				Timestamp: now,
				Labels:    make(MetricLabels),
			}},
		}
	}

	// Resource usage
	resourceMetrics := map[string]string{
		"total_cpu_usage":    "cpu",
		"total_memory_usage": "memory",
		"total_disk_usage":   "disk",
	}

	for key, resourceType := range resourceMetrics {
		if value, ok := metrics[key].(float64); ok {
			ch <- &Metric{
				Name: "sandbox_resource_usage_ratio",
				Type: MetricTypeGauge,
				Help: "Resource usage as a ratio (0-1)",
				Values: []MetricValue{{
					Value:     value,
					Timestamp: now,
					Labels:    MetricLabels{"resource": resourceType},
				}},
			}
		}
	}
}