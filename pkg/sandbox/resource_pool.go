package sandbox

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ResourcePool manages shared resources across multiple containers
type ResourcePool struct {
	mu                    sync.RWMutex
	name                  string
	poolID                string
	totalResources        *PoolResources
	availableResources    *PoolResources
	allocatedResources    map[string]*PoolResources // containerID -> resources
	reservations          map[string]*ResourceReservation
	waitQueue             []*ResourceRequest
	allocationStrategy    AllocationStrategy
	fairShareEnabled      bool
	preemptionEnabled     bool
	resourceAccounting    *ResourceAccounting
	schedulingPolicies    map[string]*SchedulingPolicy
	poolStatistics        *PoolStatistics
	alertThresholds       *AlertThresholds
	hooks                 *ResourcePoolHooks
	ctx                   context.Context
	cancel                context.CancelFunc
}

// PoolResources represents resources available in the pool
type PoolResources struct {
	CPU    *CPUResource    `json:"cpu"`
	Memory *MemoryResource `json:"memory"`
	Disk   *DiskResource   `json:"disk"`
	Custom map[string]int64 `json:"custom,omitempty"` // Custom resource types
}

// CPUResource represents CPU resources
type CPUResource struct {
	Cores       float64 `json:"cores"`        // CPU cores (can be fractional)
	Shares      int64   `json:"shares"`       // CPU shares
	Quota       int64   `json:"quota"`        // CPU quota in microseconds
	Period      int64   `json:"period"`       // CPU period in microseconds
	Pinned      []int   `json:"pinned"`       // Pinned CPU cores
	Reserved    float64 `json:"reserved"`     // Reserved cores
	Available   float64 `json:"available"`    // Available cores
}

// MemoryResource represents memory resources
type MemoryResource struct {
	Total     int64 `json:"total"`      // Total memory in bytes
	Used      int64 `json:"used"`       // Used memory in bytes
	Available int64 `json:"available"`  // Available memory in bytes
	Reserved  int64 `json:"reserved"`   // Reserved memory in bytes
	Cached    int64 `json:"cached"`     // Cached memory in bytes
	Swap      int64 `json:"swap"`       // Swap space in bytes
}

// DiskResource represents disk resources
type DiskResource struct {
	Total        int64 `json:"total"`         // Total disk space in bytes
	Used         int64 `json:"used"`          // Used disk space in bytes
	Available    int64 `json:"available"`     // Available disk space in bytes
	Reserved     int64 `json:"reserved"`      // Reserved disk space in bytes
	Inodes       int64 `json:"inodes"`        // Total inodes
	InodesUsed   int64 `json:"inodes_used"`   // Used inodes
	IOPS         int64 `json:"iops"`          // I/O operations per second
	Bandwidth    int64 `json:"bandwidth"`     // Disk bandwidth in bytes/sec
}

// ResourceRequest represents a request for resources
type ResourceRequest struct {
	ContainerID   string         `json:"container_id"`
	Resources     *PoolResources `json:"resources"`
	Priority      int            `json:"priority"`
	Timeout       time.Duration  `json:"timeout"`
	RequestTime   time.Time      `json:"request_time"`
	ResponseChan  chan *AllocationResult `json:"-"`
	Context       context.Context `json:"-"`
	Requirements  *ResourceRequirements `json:"requirements"`
}

// ResourceRequirements defines specific requirements for resource allocation
type ResourceRequirements struct {
	CPUAffinity      []int     `json:"cpu_affinity,omitempty"`      // Required CPU affinity
	MemoryNodes      []int     `json:"memory_nodes,omitempty"`      // Required NUMA nodes
	DiskType         string    `json:"disk_type,omitempty"`         // Required disk type (SSD, HDD)
	NetworkBandwidth int64     `json:"network_bandwidth,omitempty"` // Required network bandwidth
	GPUCount         int       `json:"gpu_count,omitempty"`         // Required GPU count
	Exclusive        bool      `json:"exclusive"`                   // Exclusive resource access
	Collocate        []string  `json:"collocate,omitempty"`         // Containers to collocate with
	AntiCollocate    []string  `json:"anti_collocate,omitempty"`    // Containers to avoid
}

// AllocationResult represents the result of a resource allocation
type AllocationResult struct {
	Success     bool           `json:"success"`
	Resources   *PoolResources `json:"resources,omitempty"`
	Error       error          `json:"error,omitempty"`
	AllocatedAt time.Time      `json:"allocated_at"`
	ExpiresAt   *time.Time     `json:"expires_at,omitempty"`
	ReservationID string       `json:"reservation_id,omitempty"`
}

// ResourceReservation represents a resource reservation
type ResourceReservation struct {
	ID           string         `json:"id"`
	ContainerID  string         `json:"container_id"`
	Resources    *PoolResources `json:"resources"`
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    *time.Time     `json:"expires_at,omitempty"`
	Active       bool           `json:"active"`
	Preemptible  bool           `json:"preemptible"`
}

// AllocationStrategy defines how resources are allocated
type AllocationStrategy int

const (
	FirstFit AllocationStrategy = iota
	BestFit
	WorstFit
	NextFit
	BinPacking
	FairShare
	Priority
	DominantResourceFairness
)

// SchedulingPolicy defines scheduling policies for containers
type SchedulingPolicy struct {
	Name               string            `json:"name"`
	Priority           int               `json:"priority"`
	Weight             float64           `json:"weight"`
	MaxConcurrency     int               `json:"max_concurrency"`
	ResourceLimits     *PoolResources    `json:"resource_limits"`
	TimeQuota          time.Duration     `json:"time_quota"`
	Preemptible        bool              `json:"preemptible"`
	Overcommit         float64           `json:"overcommit"` // Overcommit ratio (1.0 = no overcommit)
	Labels             map[string]string `json:"labels"`
}

// ResourceAccounting tracks resource usage and billing
type ResourceAccounting struct {
	mu                  sync.RWMutex
	usageRecords        map[string][]*UsageRecord
	billingPeriod       time.Duration
	costRates           *CostRates
	quotas              map[string]*ResourceQuota
	usageAlerts         map[string]*UsageAlert
	reportingInterval   time.Duration
	lastReport          time.Time
}

// UsageRecord represents a resource usage record
type UsageRecord struct {
	ContainerID   string         `json:"container_id"`
	Resources     *PoolResources `json:"resources"`
	StartTime     time.Time      `json:"start_time"`
	EndTime       time.Time      `json:"end_time"`
	Duration      time.Duration  `json:"duration"`
	Cost          float64        `json:"cost"`
	Labels        map[string]string `json:"labels"`
}

// CostRates defines cost rates for different resource types
type CostRates struct {
	CPUPerCoreHour    float64            `json:"cpu_per_core_hour"`
	MemoryPerGBHour   float64            `json:"memory_per_gb_hour"`
	DiskPerGBHour     float64            `json:"disk_per_gb_hour"`
	NetworkPerGBHour  float64            `json:"network_per_gb_hour"`
	CustomRates       map[string]float64 `json:"custom_rates"`
}

// ResourceQuota defines resource quotas for users/projects
type ResourceQuota struct {
	UserID            string         `json:"user_id"`
	ProjectID         string         `json:"project_id"`
	MaxResources      *PoolResources `json:"max_resources"`
	UsedResources     *PoolResources `json:"used_resources"`
	BillingLimit      float64        `json:"billing_limit"`
	CurrentCost       float64        `json:"current_cost"`
	ResetPeriod       time.Duration  `json:"reset_period"`
	LastReset         time.Time      `json:"last_reset"`
	Warnings          []string       `json:"warnings"`
}

// UsageAlert defines usage alert thresholds
type UsageAlert struct {
	Threshold         float64   `json:"threshold"`      // Percentage threshold
	ResourceType      string    `json:"resource_type"`  // CPU, Memory, Disk
	AlertType         string    `json:"alert_type"`     // WARNING, CRITICAL
	Recipients        []string  `json:"recipients"`
	Enabled           bool      `json:"enabled"`
	LastTriggered     time.Time `json:"last_triggered"`
	CooldownPeriod    time.Duration `json:"cooldown_period"`
}

// PoolStatistics holds resource pool statistics
type PoolStatistics struct {
	mu                    sync.RWMutex
	totalAllocations      int64
	successfulAllocations int64
	failedAllocations     int64
	preemptions           int64
	avgAllocationTime     time.Duration
	avgUtilization        map[string]float64 // resource type -> utilization %
	peakUtilization       map[string]float64
	historicalData        []*UtilizationSnapshot
	bottleneckAnalysis    *BottleneckAnalysis
}

// UtilizationSnapshot represents resource utilization at a point in time
type UtilizationSnapshot struct {
	Timestamp     time.Time              `json:"timestamp"`
	Utilization   map[string]float64     `json:"utilization"`
	ActiveContainers int                 `json:"active_containers"`
	QueueLength   int                    `json:"queue_length"`
}

// BottleneckAnalysis identifies resource bottlenecks
type BottleneckAnalysis struct {
	PrimaryBottleneck   string    `json:"primary_bottleneck"`
	SecondaryBottleneck string    `json:"secondary_bottleneck"`
	BottleneckSeverity  float64   `json:"bottleneck_severity"`
	RecommendedActions  []string  `json:"recommended_actions"`
	LastAnalysis        time.Time `json:"last_analysis"`
}

// AlertThresholds defines alert thresholds for the pool
type AlertThresholds struct {
	CPUUtilization    float64 `json:"cpu_utilization"`
	MemoryUtilization float64 `json:"memory_utilization"`
	DiskUtilization   float64 `json:"disk_utilization"`
	QueueLength       int     `json:"queue_length"`
	AllocationFailureRate float64 `json:"allocation_failure_rate"`
}

// ResourcePoolHooks defines hooks for resource pool events
type ResourcePoolHooks struct {
	PreAllocation  func(request *ResourceRequest) error
	PostAllocation func(request *ResourceRequest, result *AllocationResult) error
	PreRelease     func(containerID string, resources *PoolResources) error
	PostRelease    func(containerID string, resources *PoolResources) error
	OnPreemption   func(preemptedID string, preemptorID string) error
}

// NewResourcePool creates a new resource pool
func NewResourcePool(name, poolID string, totalResources *PoolResources) *ResourcePool {
	ctx, cancel := context.WithCancel(context.Background())
	
	pool := &ResourcePool{
		name:               name,
		poolID:             poolID,
		totalResources:     totalResources,
		availableResources: copyPoolResources(totalResources),
		allocatedResources: make(map[string]*PoolResources),
		reservations:       make(map[string]*ResourceReservation),
		waitQueue:          make([]*ResourceRequest, 0),
		allocationStrategy: FirstFit,
		fairShareEnabled:   true,
		preemptionEnabled:  false,
		schedulingPolicies: make(map[string]*SchedulingPolicy),
		poolStatistics:     &PoolStatistics{
			avgUtilization:  make(map[string]float64),
			peakUtilization: make(map[string]float64),
			historicalData:  make([]*UtilizationSnapshot, 0),
		},
		alertThresholds: &AlertThresholds{
			CPUUtilization:        80.0,
			MemoryUtilization:     85.0,
			DiskUtilization:       90.0,
			QueueLength:           10,
			AllocationFailureRate: 5.0,
		},
		ctx:    ctx,
		cancel: cancel,
	}
	
	// Initialize resource accounting
	pool.resourceAccounting = &ResourceAccounting{
		usageRecords:      make(map[string][]*UsageRecord),
		billingPeriod:     24 * time.Hour,
		quotas:            make(map[string]*ResourceQuota),
		usageAlerts:       make(map[string]*UsageAlert),
		reportingInterval: time.Hour,
		costRates: &CostRates{
			CPUPerCoreHour:   0.10,
			MemoryPerGBHour:  0.05,
			DiskPerGBHour:    0.01,
			NetworkPerGBHour: 0.02,
			CustomRates:      make(map[string]float64),
		},
	}
	
	// Start background processing
	go pool.processWaitQueue()
	go pool.collectStatistics()
	go pool.monitorAlerts()
	go pool.cleanupExpiredReservations()
	
	log.Info().
		Str("pool_name", name).
		Str("pool_id", poolID).
		Interface("total_resources", totalResources).
		Msg("Resource pool initialized")
	
	return pool
}

// Close gracefully shuts down the resource pool and stops all background goroutines
func (rp *ResourcePool) Close() {
	if rp.cancel != nil {
		rp.cancel()
	}
}

// AllocateResources allocates resources for a container
func (rp *ResourcePool) AllocateResources(ctx context.Context, request *ResourceRequest) (*AllocationResult, error) {
	logger := log.With().
		Str("pool_id", rp.poolID).
		Str("container_id", request.ContainerID).
		Logger()
	
	logger.Debug().
		Interface("requested_resources", request.Resources).
		Int("priority", request.Priority).
		Msg("Processing resource allocation request")
	
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	// Pre-allocation hook
	if rp.hooks != nil && rp.hooks.PreAllocation != nil {
		if err := rp.hooks.PreAllocation(request); err != nil {
			return &AllocationResult{
				Success: false,
				Error:   fmt.Errorf("pre-allocation hook failed: %w", err),
			}, nil
		}
	}
	
	// Check if resources are available
	if rp.canAllocate(request.Resources) {
		// Direct allocation
		result := rp.performAllocation(request)
		
		// Post-allocation hook
		if rp.hooks != nil && rp.hooks.PostAllocation != nil {
			if err := rp.hooks.PostAllocation(request, result); err != nil {
				logger.Warn().Err(err).Msg("Post-allocation hook failed")
			}
		}
		
		logger.Info().
			Bool("success", result.Success).
			Msg("Resource allocation completed")
		
		return result, nil
	}
	
	// Try preemption if enabled
	if rp.preemptionEnabled {
		if preemptedResources := rp.attemptPreemption(request); preemptedResources != nil {
			result := rp.performAllocation(request)
			logger.Info().
				Interface("preempted_resources", preemptedResources).
				Msg("Resource allocation completed via preemption")
			return result, nil
		}
	}
	
	// Add to wait queue
	request.ResponseChan = make(chan *AllocationResult, 1)
	request.Context = ctx
	rp.addToWaitQueue(request)
	
	logger.Info().
		Int("queue_position", len(rp.waitQueue)).
		Msg("Added to resource allocation wait queue")
	
	// Wait for allocation or timeout
	select {
	case result := <-request.ResponseChan:
		return result, nil
	case <-ctx.Done():
		rp.removeFromWaitQueue(request)
		return &AllocationResult{
			Success: false,
			Error:   ctx.Err(),
		}, nil
	case <-time.After(request.Timeout):
		rp.removeFromWaitQueue(request)
		return &AllocationResult{
			Success: false,
			Error:   fmt.Errorf("allocation timeout"),
		}, nil
	}
}

// ReleaseResources releases resources allocated to a container
func (rp *ResourcePool) ReleaseResources(containerID string) error {
	logger := log.With().
		Str("pool_id", rp.poolID).
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().Msg("Releasing resources")
	
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	allocatedResources, exists := rp.allocatedResources[containerID]
	if !exists {
		return fmt.Errorf("no resources allocated for container %s", containerID)
	}
	
	// Pre-release hook
	if rp.hooks != nil && rp.hooks.PreRelease != nil {
		if err := rp.hooks.PreRelease(containerID, allocatedResources); err != nil {
			logger.Warn().Err(err).Msg("Pre-release hook failed")
		}
	}
	
	// Return resources to the pool
	rp.returnResources(allocatedResources)
	
	// Remove from allocated resources
	delete(rp.allocatedResources, containerID)
	
	// Record usage for accounting
	rp.recordResourceUsage(containerID, allocatedResources)
	
	// Post-release hook
	if rp.hooks != nil && rp.hooks.PostRelease != nil {
		if err := rp.hooks.PostRelease(containerID, allocatedResources); err != nil {
			logger.Warn().Err(err).Msg("Post-release hook failed")
		}
	}
	
	// Try to allocate resources to waiting requests (internal version without lock)
	rp.tryAllocateFromQueueInternal()
	
	logger.Info().
		Interface("released_resources", allocatedResources).
		Msg("Resources released successfully")
	
	return nil
}

// ReserveResources creates a resource reservation
func (rp *ResourcePool) ReserveResources(containerID string, resources *PoolResources, duration *time.Duration) (*ResourceReservation, error) {
	logger := log.With().
		Str("pool_id", rp.poolID).
		Str("container_id", containerID).
		Logger()
	
	logger.Debug().
		Interface("resources", resources).
		Dur("duration", *duration).
		Msg("Creating resource reservation")
	
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	if !rp.canAllocate(resources) {
		return nil, fmt.Errorf("insufficient resources for reservation")
	}
	
	reservationID := fmt.Sprintf("res-%s-%d", containerID, time.Now().UnixNano())
	
	var expiresAt *time.Time
	if duration != nil {
		exp := time.Now().Add(*duration)
		expiresAt = &exp
	}
	
	reservation := &ResourceReservation{
		ID:          reservationID,
		ContainerID: containerID,
		Resources:   copyPoolResources(resources),
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		Active:      true,
		Preemptible: false,
	}
	
	// Reserve the resources
	rp.reserveResources(resources)
	rp.reservations[reservationID] = reservation
	
	logger.Info().
		Str("reservation_id", reservationID).
		Msg("Resource reservation created")
	
	return reservation, nil
}

// GetPoolStatistics returns pool statistics
func (rp *ResourcePool) GetPoolStatistics() *PoolStatistics {
	rp.poolStatistics.mu.RLock()
	defer rp.poolStatistics.mu.RUnlock()
	
	// Return a copy to avoid race conditions
	stats := &PoolStatistics{
		totalAllocations:      rp.poolStatistics.totalAllocations,
		successfulAllocations: rp.poolStatistics.successfulAllocations,
		failedAllocations:     rp.poolStatistics.failedAllocations,
		preemptions:           rp.poolStatistics.preemptions,
		avgAllocationTime:     rp.poolStatistics.avgAllocationTime,
		avgUtilization:        make(map[string]float64),
		peakUtilization:       make(map[string]float64),
		historicalData:        make([]*UtilizationSnapshot, len(rp.poolStatistics.historicalData)),
	}
	
	for k, v := range rp.poolStatistics.avgUtilization {
		stats.avgUtilization[k] = v
	}
	for k, v := range rp.poolStatistics.peakUtilization {
		stats.peakUtilization[k] = v
	}
	copy(stats.historicalData, rp.poolStatistics.historicalData)
	
	return stats
}

// GetResourceUsageReport generates a resource usage report
func (rp *ResourcePool) GetResourceUsageReport(startTime, endTime time.Time) (*UsageReport, error) {
	rp.resourceAccounting.mu.RLock()
	defer rp.resourceAccounting.mu.RUnlock()
	
	report := &UsageReport{
		StartTime:    startTime,
		EndTime:      endTime,
		TotalCost:    0,
		UsageByContainer: make(map[string]*ContainerUsage),
		ResourceBreakdown: make(map[string]float64),
	}
	
	for containerID, records := range rp.resourceAccounting.usageRecords {
		containerUsage := &ContainerUsage{
			ContainerID: containerID,
			TotalCost:   0,
			Records:     make([]*UsageRecord, 0),
		}
		
		for _, record := range records {
			if record.StartTime.After(startTime) && record.EndTime.Before(endTime) {
				containerUsage.Records = append(containerUsage.Records, record)
				containerUsage.TotalCost += record.Cost
				report.TotalCost += record.Cost
			}
		}
		
		if len(containerUsage.Records) > 0 {
			report.UsageByContainer[containerID] = containerUsage
		}
	}
	
	return report, nil
}

// UsageReport represents a resource usage report
type UsageReport struct {
	StartTime         time.Time                    `json:"start_time"`
	EndTime           time.Time                    `json:"end_time"`
	TotalCost         float64                      `json:"total_cost"`
	UsageByContainer  map[string]*ContainerUsage   `json:"usage_by_container"`
	ResourceBreakdown map[string]float64           `json:"resource_breakdown"`
}

// ContainerUsage represents usage for a specific container
type ContainerUsage struct {
	ContainerID string         `json:"container_id"`
	TotalCost   float64        `json:"total_cost"`
	Records     []*UsageRecord `json:"records"`
}

// Private helper methods

func (rp *ResourcePool) canAllocate(requested *PoolResources) bool {
	if requested.CPU != nil && rp.availableResources.CPU != nil {
		if requested.CPU.Cores > rp.availableResources.CPU.Available {
			return false
		}
	}
	
	if requested.Memory != nil && rp.availableResources.Memory != nil {
		if requested.Memory.Total > rp.availableResources.Memory.Available {
			return false
		}
	}
	
	if requested.Disk != nil && rp.availableResources.Disk != nil {
		if requested.Disk.Total > rp.availableResources.Disk.Available {
			return false
		}
	}
	
	return true
}

func (rp *ResourcePool) performAllocation(request *ResourceRequest) *AllocationResult {
	startTime := time.Now()
	
	// Allocate the resources
	rp.allocateResources(request.Resources)
	rp.allocatedResources[request.ContainerID] = copyPoolResources(request.Resources)
	
	// Update statistics
	rp.poolStatistics.mu.Lock()
	rp.poolStatistics.totalAllocations++
	rp.poolStatistics.successfulAllocations++
	allocationTime := time.Since(startTime)
	rp.updateAvgAllocationTime(allocationTime)
	rp.poolStatistics.mu.Unlock()
	
	return &AllocationResult{
		Success:     true,
		Resources:   copyPoolResources(request.Resources),
		AllocatedAt: time.Now(),
	}
}

func (rp *ResourcePool) allocateResources(resources *PoolResources) {
	if resources.CPU != nil && rp.availableResources.CPU != nil {
		rp.availableResources.CPU.Available -= resources.CPU.Cores
	}
	
	if resources.Memory != nil && rp.availableResources.Memory != nil {
		rp.availableResources.Memory.Available -= resources.Memory.Total
	}
	
	if resources.Disk != nil && rp.availableResources.Disk != nil {
		rp.availableResources.Disk.Available -= resources.Disk.Total
	}
}

func (rp *ResourcePool) returnResources(resources *PoolResources) {
	if resources.CPU != nil && rp.availableResources.CPU != nil {
		rp.availableResources.CPU.Available += resources.CPU.Cores
	}
	
	if resources.Memory != nil && rp.availableResources.Memory != nil {
		rp.availableResources.Memory.Available += resources.Memory.Total
	}
	
	if resources.Disk != nil && rp.availableResources.Disk != nil {
		rp.availableResources.Disk.Available += resources.Disk.Total
	}
}

func (rp *ResourcePool) reserveResources(resources *PoolResources) {
	if resources.CPU != nil && rp.availableResources.CPU != nil {
		rp.availableResources.CPU.Reserved += resources.CPU.Cores
		rp.availableResources.CPU.Available -= resources.CPU.Cores
	}
	
	if resources.Memory != nil && rp.availableResources.Memory != nil {
		rp.availableResources.Memory.Reserved += resources.Memory.Total
		rp.availableResources.Memory.Available -= resources.Memory.Total
	}
	
	if resources.Disk != nil && rp.availableResources.Disk != nil {
		rp.availableResources.Disk.Reserved += resources.Disk.Total
		rp.availableResources.Disk.Available -= resources.Disk.Total
	}
}

func (rp *ResourcePool) attemptPreemption(request *ResourceRequest) *PoolResources {
	// Find preemptible containers with lower priority
	candidates := make([]*preemptionCandidate, 0)
	
	for containerID, resources := range rp.allocatedResources {
		if policy := rp.schedulingPolicies[containerID]; policy != nil && policy.Preemptible {
			if policy.Priority < request.Priority {
				candidates = append(candidates, &preemptionCandidate{
					containerID: containerID,
					resources:   resources,
					priority:    policy.Priority,
				})
			}
		}
	}
	
	if len(candidates) == 0 {
		return nil
	}
	
	// Sort by priority (lowest first)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].priority < candidates[j].priority
	})
	
	// Try to preempt enough resources
	var preemptedResources *PoolResources
	for _, candidate := range candidates {
		// Preempt this container
		rp.preemptContainer(candidate.containerID)
		
		if preemptedResources == nil {
			preemptedResources = copyPoolResources(candidate.resources)
		} else {
			addPoolResources(preemptedResources, candidate.resources)
		}
		
		// Check if we have enough resources now
		if rp.canAllocate(request.Resources) {
			rp.poolStatistics.mu.Lock()
			rp.poolStatistics.preemptions++
			rp.poolStatistics.mu.Unlock()
			return preemptedResources
		}
	}
	
	return nil
}

type preemptionCandidate struct {
	containerID string
	resources   *PoolResources
	priority    int
}

func (rp *ResourcePool) preemptContainer(containerID string) {
	logger := log.With().
		Str("pool_id", rp.poolID).
		Str("container_id", containerID).
		Logger()
	
	logger.Info().Msg("Preempting container")
	
	if resources := rp.allocatedResources[containerID]; resources != nil {
		rp.returnResources(resources)
		delete(rp.allocatedResources, containerID)
		
		// Trigger preemption hook
		if rp.hooks != nil && rp.hooks.OnPreemption != nil {
			if err := rp.hooks.OnPreemption(containerID, ""); err != nil {
				logger.Warn().Err(err).Msg("Preemption hook failed")
			}
		}
	}
}

func (rp *ResourcePool) addToWaitQueue(request *ResourceRequest) {
	rp.waitQueue = append(rp.waitQueue, request)
	
	// Sort by priority (highest first)
	sort.Slice(rp.waitQueue, func(i, j int) bool {
		return rp.waitQueue[i].Priority > rp.waitQueue[j].Priority
	})
}

func (rp *ResourcePool) removeFromWaitQueue(request *ResourceRequest) {
	for i, req := range rp.waitQueue {
		if req.ContainerID == request.ContainerID {
			rp.waitQueue = append(rp.waitQueue[:i], rp.waitQueue[i+1:]...)
			break
		}
	}
}

func (rp *ResourcePool) processWaitQueue() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-rp.ctx.Done():
			return
		case <-ticker.C:
			rp.tryAllocateFromQueue()
		}
	}
}

func (rp *ResourcePool) tryAllocateFromQueue() {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	
	rp.tryAllocateFromQueueInternal()
}

func (rp *ResourcePool) tryAllocateFromQueueInternal() {
	i := 0
	for i < len(rp.waitQueue) {
		request := rp.waitQueue[i]
		
		if rp.canAllocate(request.Resources) {
			// Remove from queue
			rp.waitQueue = append(rp.waitQueue[:i], rp.waitQueue[i+1:]...)
			
			// Allocate resources
			result := rp.performAllocation(request)
			
			// Send result
			select {
			case request.ResponseChan <- result:
			default:
				// Channel might be closed due to timeout
			}
		} else {
			i++
		}
	}
}

func (rp *ResourcePool) collectStatistics() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-rp.ctx.Done():
			return
		case <-ticker.C:
			rp.updateUtilizationMetrics()
			rp.performBottleneckAnalysis()
		}
	}
}

func (rp *ResourcePool) updateUtilizationMetrics() {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	
	rp.poolStatistics.mu.Lock()
	defer rp.poolStatistics.mu.Unlock()
	
	snapshot := &UtilizationSnapshot{
		Timestamp:        time.Now(),
		Utilization:      make(map[string]float64),
		ActiveContainers: len(rp.allocatedResources),
		QueueLength:      len(rp.waitQueue),
	}
	
	// Calculate CPU utilization
	if rp.totalResources.CPU != nil && rp.availableResources.CPU != nil {
		used := rp.totalResources.CPU.Cores - rp.availableResources.CPU.Available
		utilization := (used / rp.totalResources.CPU.Cores) * 100.0
		snapshot.Utilization["cpu"] = utilization
		rp.updateAvgUtilization("cpu", utilization)
	}
	
	// Calculate memory utilization
	if rp.totalResources.Memory != nil && rp.availableResources.Memory != nil {
		used := rp.totalResources.Memory.Total - rp.availableResources.Memory.Available
		utilization := (float64(used) / float64(rp.totalResources.Memory.Total)) * 100.0
		snapshot.Utilization["memory"] = utilization
		rp.updateAvgUtilization("memory", utilization)
	}
	
	// Calculate disk utilization
	if rp.totalResources.Disk != nil && rp.availableResources.Disk != nil {
		used := rp.totalResources.Disk.Total - rp.availableResources.Disk.Available
		utilization := (float64(used) / float64(rp.totalResources.Disk.Total)) * 100.0
		snapshot.Utilization["disk"] = utilization
		rp.updateAvgUtilization("disk", utilization)
	}
	
	// Store snapshot
	rp.poolStatistics.historicalData = append(rp.poolStatistics.historicalData, snapshot)
	
	// Keep only last 1000 snapshots
	if len(rp.poolStatistics.historicalData) > 1000 {
		rp.poolStatistics.historicalData = rp.poolStatistics.historicalData[len(rp.poolStatistics.historicalData)-1000:]
	}
}

func (rp *ResourcePool) updateAvgUtilization(resourceType string, utilization float64) {
	current := rp.poolStatistics.avgUtilization[resourceType]
	rp.poolStatistics.avgUtilization[resourceType] = (current + utilization) / 2.0
	
	if utilization > rp.poolStatistics.peakUtilization[resourceType] {
		rp.poolStatistics.peakUtilization[resourceType] = utilization
	}
}

func (rp *ResourcePool) updateAvgAllocationTime(duration time.Duration) {
	current := rp.poolStatistics.avgAllocationTime
	count := rp.poolStatistics.totalAllocations
	rp.poolStatistics.avgAllocationTime = time.Duration((int64(current)*count + int64(duration)) / (count + 1))
}

func (rp *ResourcePool) performBottleneckAnalysis() {
	rp.poolStatistics.mu.Lock()
	defer rp.poolStatistics.mu.Unlock()
	
	if len(rp.poolStatistics.historicalData) < 10 {
		return // Need more data
	}
	
	// Analyze recent utilization trends
	recent := rp.poolStatistics.historicalData[len(rp.poolStatistics.historicalData)-10:]
	
	avgUtilization := make(map[string]float64)
	for _, snapshot := range recent {
		for resourceType, util := range snapshot.Utilization {
			avgUtilization[resourceType] += util
		}
	}
	
	for resourceType := range avgUtilization {
		avgUtilization[resourceType] /= float64(len(recent))
	}
	
	// Find primary bottleneck
	var primaryBottleneck string
	var maxUtilization float64
	
	for resourceType, utilization := range avgUtilization {
		if utilization > maxUtilization {
			maxUtilization = utilization
			primaryBottleneck = resourceType
		}
	}
	
	// Update bottleneck analysis
	if rp.poolStatistics.bottleneckAnalysis == nil {
		rp.poolStatistics.bottleneckAnalysis = &BottleneckAnalysis{}
	}
	
	rp.poolStatistics.bottleneckAnalysis.PrimaryBottleneck = primaryBottleneck
	rp.poolStatistics.bottleneckAnalysis.BottleneckSeverity = maxUtilization
	rp.poolStatistics.bottleneckAnalysis.LastAnalysis = time.Now()
	
	// Generate recommendations
	recommendations := make([]string, 0)
	if maxUtilization > 90 {
		recommendations = append(recommendations, fmt.Sprintf("Critical: %s utilization is very high (%.1f%%)", primaryBottleneck, maxUtilization))
		recommendations = append(recommendations, fmt.Sprintf("Consider adding more %s resources", primaryBottleneck))
	} else if maxUtilization > 75 {
		recommendations = append(recommendations, fmt.Sprintf("Warning: %s utilization is high (%.1f%%)", primaryBottleneck, maxUtilization))
		recommendations = append(recommendations, "Monitor resource usage and plan for scaling")
	}
	
	rp.poolStatistics.bottleneckAnalysis.RecommendedActions = recommendations
}

func (rp *ResourcePool) monitorAlerts() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-rp.ctx.Done():
			return
		case <-ticker.C:
			rp.checkAlertThresholds()
		}
	}
}

func (rp *ResourcePool) checkAlertThresholds() {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	
	// Check CPU utilization
	if rp.totalResources.CPU != nil && rp.availableResources.CPU != nil {
		used := rp.totalResources.CPU.Cores - rp.availableResources.CPU.Available
		utilization := (used / rp.totalResources.CPU.Cores) * 100.0
		
		if utilization > rp.alertThresholds.CPUUtilization {
			log.Warn().
				Str("pool_id", rp.poolID).
				Float64("cpu_utilization", utilization).
				Float64("threshold", rp.alertThresholds.CPUUtilization).
				Msg("CPU utilization alert")
		}
	}
	
	// Check memory utilization
	if rp.totalResources.Memory != nil && rp.availableResources.Memory != nil {
		used := rp.totalResources.Memory.Total - rp.availableResources.Memory.Available
		utilization := (float64(used) / float64(rp.totalResources.Memory.Total)) * 100.0
		
		if utilization > rp.alertThresholds.MemoryUtilization {
			log.Warn().
				Str("pool_id", rp.poolID).
				Float64("memory_utilization", utilization).
				Float64("threshold", rp.alertThresholds.MemoryUtilization).
				Msg("Memory utilization alert")
		}
	}
	
	// Check queue length
	if len(rp.waitQueue) > rp.alertThresholds.QueueLength {
		log.Warn().
			Str("pool_id", rp.poolID).
			Int("queue_length", len(rp.waitQueue)).
			Int("threshold", rp.alertThresholds.QueueLength).
			Msg("Wait queue length alert")
	}
}

func (rp *ResourcePool) cleanupExpiredReservations() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-rp.ctx.Done():
			return
		case <-ticker.C:
			rp.mu.Lock()
			now := time.Now()
			
			for reservationID, reservation := range rp.reservations {
				if reservation.ExpiresAt != nil && now.After(*reservation.ExpiresAt) {
					// Return reserved resources
					rp.returnResources(reservation.Resources)
					
					// Remove reservation
					delete(rp.reservations, reservationID)
					
					log.Info().
						Str("pool_id", rp.poolID).
						Str("reservation_id", reservationID).
						Msg("Expired reservation cleaned up")
				}
			}
			
			rp.mu.Unlock()
		}
	}
}

func (rp *ResourcePool) recordResourceUsage(containerID string, resources *PoolResources) {
	rp.resourceAccounting.mu.Lock()
	defer rp.resourceAccounting.mu.Unlock()
	
	// Find the start time from allocated time (simplified)
	endTime := time.Now()
	startTime := endTime.Add(-time.Hour) // Placeholder - should track actual allocation time
	
	// Calculate cost
	cost := rp.calculateCost(resources, endTime.Sub(startTime))
	
	record := &UsageRecord{
		ContainerID: containerID,
		Resources:   copyPoolResources(resources),
		StartTime:   startTime,
		EndTime:     endTime,
		Duration:    endTime.Sub(startTime),
		Cost:        cost,
		Labels:      make(map[string]string),
	}
	
	rp.resourceAccounting.usageRecords[containerID] = append(rp.resourceAccounting.usageRecords[containerID], record)
}

func (rp *ResourcePool) calculateCost(resources *PoolResources, duration time.Duration) float64 {
	hours := duration.Hours()
	cost := 0.0
	
	if resources.CPU != nil {
		cost += resources.CPU.Cores * rp.resourceAccounting.costRates.CPUPerCoreHour * hours
	}
	
	if resources.Memory != nil {
		gb := float64(resources.Memory.Total) / (1024 * 1024 * 1024)
		cost += gb * rp.resourceAccounting.costRates.MemoryPerGBHour * hours
	}
	
	if resources.Disk != nil {
		gb := float64(resources.Disk.Total) / (1024 * 1024 * 1024)
		cost += gb * rp.resourceAccounting.costRates.DiskPerGBHour * hours
	}
	
	return cost
}

// Utility functions

func copyPoolResources(src *PoolResources) *PoolResources {
	if src == nil {
		return nil
	}
	
	dst := &PoolResources{}
	
	if src.CPU != nil {
		dst.CPU = &CPUResource{
			Cores:     src.CPU.Cores,
			Shares:    src.CPU.Shares,
			Quota:     src.CPU.Quota,
			Period:    src.CPU.Period,
			Reserved:  src.CPU.Reserved,
			Available: src.CPU.Available,
		}
		if src.CPU.Pinned != nil {
			dst.CPU.Pinned = make([]int, len(src.CPU.Pinned))
			copy(dst.CPU.Pinned, src.CPU.Pinned)
		}
	}
	
	if src.Memory != nil {
		dst.Memory = &MemoryResource{
			Total:     src.Memory.Total,
			Used:      src.Memory.Used,
			Available: src.Memory.Available,
			Reserved:  src.Memory.Reserved,
			Cached:    src.Memory.Cached,
			Swap:      src.Memory.Swap,
		}
	}
	
	if src.Disk != nil {
		dst.Disk = &DiskResource{
			Total:        src.Disk.Total,
			Used:         src.Disk.Used,
			Available:    src.Disk.Available,
			Reserved:     src.Disk.Reserved,
			Inodes:       src.Disk.Inodes,
			InodesUsed:   src.Disk.InodesUsed,
			IOPS:         src.Disk.IOPS,
			Bandwidth:    src.Disk.Bandwidth,
		}
	}
	
	if src.Custom != nil {
		dst.Custom = make(map[string]int64)
		for k, v := range src.Custom {
			dst.Custom[k] = v
		}
	}
	
	return dst
}

func addPoolResources(dst, src *PoolResources) {
	if src.CPU != nil && dst.CPU != nil {
		dst.CPU.Cores += src.CPU.Cores
		dst.CPU.Available += src.CPU.Available
	}
	
	if src.Memory != nil && dst.Memory != nil {
		dst.Memory.Total += src.Memory.Total
		dst.Memory.Available += src.Memory.Available
	}
	
	if src.Disk != nil && dst.Disk != nil {
		dst.Disk.Total += src.Disk.Total
		dst.Disk.Available += src.Disk.Available
	}
}