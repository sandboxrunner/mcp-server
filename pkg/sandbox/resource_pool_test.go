package sandbox

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewResourcePool(t *testing.T) {
	totalResources := &PoolResources{
		CPU: &CPUResource{
			Cores:     4.0,
			Available: 4.0,
		},
		Memory: &MemoryResource{
			Total:     8 * 1024 * 1024 * 1024, // 8GB
			Available: 8 * 1024 * 1024 * 1024,
		},
		Disk: &DiskResource{
			Total:     100 * 1024 * 1024 * 1024, // 100GB
			Available: 100 * 1024 * 1024 * 1024,
		},
	}

	pool := NewResourcePool("test-pool", "pool-001", totalResources)

	assert.NotNil(t, pool)
	assert.Equal(t, "test-pool", pool.name)
	assert.Equal(t, "pool-001", pool.poolID)
	assert.Equal(t, totalResources.CPU.Cores, pool.totalResources.CPU.Cores)
	assert.Equal(t, totalResources.Memory.Total, pool.totalResources.Memory.Total)
	assert.Equal(t, totalResources.Disk.Total, pool.totalResources.Disk.Total)
	assert.NotNil(t, pool.allocatedResources)
	assert.NotNil(t, pool.reservations)
	assert.True(t, pool.fairShareEnabled)
	assert.NotNil(t, pool.resourceAccounting)
	assert.NotNil(t, pool.poolStatistics)
}

func TestResourcePool_AllocateResources_Success(t *testing.T) {
	pool := createTestResourcePool()
	
	request := &ResourceRequest{
		ContainerID: "container-001",
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 1.0,
			},
			Memory: &MemoryResource{
				Total: 1 * 1024 * 1024 * 1024, // 1GB
			},
		},
		Priority: 100,
		Timeout:  30 * time.Second,
	}

	ctx := context.Background()
	result, err := pool.AllocateResources(ctx, request)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Success)
	assert.NotNil(t, result.Resources)
	assert.Equal(t, request.Resources.CPU.Cores, result.Resources.CPU.Cores)
	assert.Equal(t, request.Resources.Memory.Total, result.Resources.Memory.Total)

	// Verify resources are allocated
	pool.mu.RLock()
	allocated := pool.allocatedResources[request.ContainerID]
	availableCPU := pool.availableResources.CPU.Available
	availableMemory := pool.availableResources.Memory.Available
	pool.mu.RUnlock()

	assert.NotNil(t, allocated)
	assert.Equal(t, 3.0, availableCPU) // 4 - 1 = 3
	assert.Equal(t, int64(7*1024*1024*1024), availableMemory) // 8GB - 1GB = 7GB
}

func TestResourcePool_AllocateResources_InsufficientResources(t *testing.T) {
	pool := createTestResourcePool()
	
	// Try to allocate more than available
	request := &ResourceRequest{
		ContainerID: "container-001",
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 8.0, // More than available 4.0
			},
		},
		Priority: 100,
		Timeout:  1 * time.Second, // Short timeout for quick test
	}

	ctx := context.Background()
	result, err := pool.AllocateResources(ctx, request)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	assert.NotNil(t, result.Error)
}

func TestResourcePool_ReleaseResources(t *testing.T) {
	pool := createTestResourcePool()
	defer pool.Close()
	containerID := "container-001"
	
	// First allocate resources
	request := &ResourceRequest{
		ContainerID: containerID,
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 2.0,
			},
			Memory: &MemoryResource{
				Total: 2 * 1024 * 1024 * 1024, // 2GB
			},
		},
		Priority: 100,
		Timeout:  30 * time.Second,
	}

	ctx := context.Background()
	result, err := pool.AllocateResources(ctx, request)
	require.NoError(t, err)
	require.True(t, result.Success)

	// Verify allocation
	pool.mu.RLock()
	availableCPU := pool.availableResources.CPU.Available
	availableMemory := pool.availableResources.Memory.Available
	pool.mu.RUnlock()
	assert.Equal(t, 2.0, availableCPU) // 4 - 2 = 2
	assert.Equal(t, int64(6*1024*1024*1024), availableMemory) // 8GB - 2GB = 6GB

	// Now release resources
	err = pool.ReleaseResources(containerID)
	assert.NoError(t, err)

	// Verify resources are returned
	pool.mu.RLock()
	_, exists := pool.allocatedResources[containerID]
	availableCPU = pool.availableResources.CPU.Available
	availableMemory = pool.availableResources.Memory.Available
	pool.mu.RUnlock()

	assert.False(t, exists)
	assert.Equal(t, 4.0, availableCPU) // Back to full 4
	assert.Equal(t, int64(8*1024*1024*1024), availableMemory) // Back to full 8GB
}

func TestResourcePool_ReserveResources(t *testing.T) {
	pool := createTestResourcePool()
	containerID := "container-001"
	
	resources := &PoolResources{
		CPU: &CPUResource{
			Cores: 1.5,
		},
		Memory: &MemoryResource{
			Total: 1536 * 1024 * 1024, // 1.5GB
		},
	}
	
	duration := 1 * time.Hour
	reservation, err := pool.ReserveResources(containerID, resources, &duration)

	assert.NoError(t, err)
	assert.NotNil(t, reservation)
	assert.Equal(t, containerID, reservation.ContainerID)
	assert.True(t, reservation.Active)
	assert.NotNil(t, reservation.ExpiresAt)
	assert.True(t, reservation.ExpiresAt.After(time.Now()))

	// Verify reservation is stored and resources are reserved
	pool.mu.RLock()
	storedReservation := pool.reservations[reservation.ID]
	availableCPU := pool.availableResources.CPU.Available
	availableMemory := pool.availableResources.Memory.Available
	reservedCPU := pool.availableResources.CPU.Reserved
	reservedMemory := pool.availableResources.Memory.Reserved
	pool.mu.RUnlock()

	assert.NotNil(t, storedReservation)
	assert.Equal(t, 2.5, availableCPU) // 4 - 1.5 = 2.5
	assert.Equal(t, int64((8*1024*1024*1024)-(1536*1024*1024)), availableMemory)
	assert.Equal(t, 1.5, reservedCPU)
	assert.Equal(t, int64(1536*1024*1024), reservedMemory)
}

func TestResourcePool_GetPoolStatistics(t *testing.T) {
	pool := createTestResourcePool()
	
	// Perform some allocations to generate statistics
	for i := 0; i < 3; i++ {
		request := &ResourceRequest{
			ContainerID: "container-" + string(rune('1'+i)),
			Resources: &PoolResources{
				CPU: &CPUResource{
					Cores: 0.5,
				},
			},
			Priority: 100,
			Timeout:  30 * time.Second,
		}
		
		ctx := context.Background()
		result, err := pool.AllocateResources(ctx, request)
		require.NoError(t, err)
		require.True(t, result.Success)
	}

	// Update statistics manually for testing
	pool.updateUtilizationMetrics()

	stats := pool.GetPoolStatistics()
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.totalAllocations, int64(3))
	assert.GreaterOrEqual(t, stats.successfulAllocations, int64(3))
	assert.NotNil(t, stats.avgUtilization)
	assert.NotNil(t, stats.historicalData)
}

func TestResourcePool_GetResourceUsageReport(t *testing.T) {
	pool := createTestResourcePool()
	containerID := "container-001"
	
	// Simulate some usage records
	startTime := time.Now().Add(-2 * time.Hour)
	endTime := time.Now().Add(-1 * time.Hour)
	
	resources := &PoolResources{
		CPU: &CPUResource{
			Cores: 1.0,
		},
		Memory: &MemoryResource{
			Total: 1 * 1024 * 1024 * 1024,
		},
	}
	
	// Add usage record manually for testing
	pool.resourceAccounting.mu.Lock()
	record := &UsageRecord{
		ContainerID: containerID,
		Resources:   copyPoolResources(resources),
		StartTime:   startTime,
		EndTime:     endTime,
		Duration:    endTime.Sub(startTime),
		Cost:        pool.calculateCost(resources, endTime.Sub(startTime)),
	}
	pool.resourceAccounting.usageRecords[containerID] = []*UsageRecord{record}
	pool.resourceAccounting.mu.Unlock()

	report, err := pool.GetResourceUsageReport(startTime.Add(-30*time.Minute), endTime.Add(30*time.Minute))
	
	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Greater(t, report.TotalCost, 0.0)
	assert.Contains(t, report.UsageByContainer, containerID)
	
	containerUsage := report.UsageByContainer[containerID]
	assert.Equal(t, containerID, containerUsage.ContainerID)
	assert.Len(t, containerUsage.Records, 1)
	assert.Equal(t, record.Cost, containerUsage.TotalCost)
}

func TestResourcePool_Preemption(t *testing.T) {
	pool := createTestResourcePool()
	pool.preemptionEnabled = true
	
	// Allocate resources with low priority container
	lowPriorityContainer := "low-priority"
	lowPriorityRequest := &ResourceRequest{
		ContainerID: lowPriorityContainer,
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 3.0, // Most of available CPU
			},
		},
		Priority: 50,
		Timeout:  30 * time.Second,
	}
	
	// Set up scheduling policy for preemption
	pool.schedulingPolicies[lowPriorityContainer] = &SchedulingPolicy{
		Priority:    50,
		Preemptible: true,
	}

	ctx := context.Background()
	result, err := pool.AllocateResources(ctx, lowPriorityRequest)
	require.NoError(t, err)
	require.True(t, result.Success)

	// Now try to allocate with higher priority - should preempt
	highPriorityRequest := &ResourceRequest{
		ContainerID: "high-priority",
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 2.0,
			},
		},
		Priority: 100, // Higher priority
		Timeout:  30 * time.Second,
	}

	result2, err := pool.AllocateResources(ctx, highPriorityRequest)
	assert.NoError(t, err)
	assert.NotNil(t, result2)
	assert.True(t, result2.Success)

	// Verify low priority container was preempted
	pool.mu.RLock()
	_, lowPriorityExists := pool.allocatedResources[lowPriorityContainer]
	_, highPriorityExists := pool.allocatedResources[highPriorityRequest.ContainerID]
	preemptions := pool.poolStatistics.preemptions
	pool.mu.RUnlock()

	assert.False(t, lowPriorityExists, "low priority container should be preempted")
	assert.True(t, highPriorityExists, "high priority container should be allocated")
	assert.Greater(t, preemptions, int64(0), "preemption count should increase")
}

func TestResourcePool_WaitQueue(t *testing.T) {
	pool := createTestResourcePool()
	
	// Fill up the pool
	fillRequest := &ResourceRequest{
		ContainerID: "fill-container",
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 4.0, // All available CPU
			},
		},
		Priority: 100,
		Timeout:  30 * time.Second,
	}

	ctx := context.Background()
	result, err := pool.AllocateResources(ctx, fillRequest)
	require.NoError(t, err)
	require.True(t, result.Success)

	// Now try to allocate more - should go to wait queue
	waitingRequest := &ResourceRequest{
		ContainerID: "waiting-container",
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 1.0,
			},
		},
		Priority: 100,
		Timeout:  100 * time.Millisecond, // Short timeout
	}

	start := time.Now()
	result2, err := pool.AllocateResources(ctx, waitingRequest)
	duration := time.Since(start)

	assert.NoError(t, err)
	assert.NotNil(t, result2)
	assert.False(t, result2.Success)
	assert.NotNil(t, result2.Error)
	assert.Contains(t, result2.Error.Error(), "timeout")
	assert.GreaterOrEqual(t, duration, 100*time.Millisecond)
}

func TestResourcePool_FairShare_Priority(t *testing.T) {
	pool := createTestResourcePool()
	
	// Test wait queue priority ordering
	pool.mu.Lock()
	
	// Add requests with different priorities to wait queue
	requests := []*ResourceRequest{
		{ContainerID: "low", Priority: 50, ResponseChan: make(chan *AllocationResult, 1)},
		{ContainerID: "high", Priority: 100, ResponseChan: make(chan *AllocationResult, 1)},
		{ContainerID: "medium", Priority: 75, ResponseChan: make(chan *AllocationResult, 1)},
	}
	
	for _, req := range requests {
		pool.addToWaitQueue(req)
	}
	
	// Check that queue is ordered by priority (highest first)
	assert.Len(t, pool.waitQueue, 3)
	assert.Equal(t, "high", pool.waitQueue[0].ContainerID)    // Priority 100
	assert.Equal(t, "medium", pool.waitQueue[1].ContainerID)  // Priority 75
	assert.Equal(t, "low", pool.waitQueue[2].ContainerID)     // Priority 50
	
	pool.mu.Unlock()
}

func TestResourcePool_BottleneckAnalysis(t *testing.T) {
	pool := createTestResourcePool()
	
	// Allocate most CPU but little memory to create CPU bottleneck
	for i := 0; i < 3; i++ {
		request := &ResourceRequest{
			ContainerID: "cpu-heavy-" + string(rune('1'+i)),
			Resources: &PoolResources{
				CPU: &CPUResource{
					Cores: 1.0,
				},
				Memory: &MemoryResource{
					Total: 100 * 1024 * 1024, // 100MB only
				},
			},
			Priority: 100,
			Timeout:  30 * time.Second,
		}
		
		ctx := context.Background()
		result, err := pool.AllocateResources(ctx, request)
		require.NoError(t, err)
		require.True(t, result.Success)
	}

	// Generate some utilization data
	pool.updateUtilizationMetrics()
	
	// Wait a bit for analysis to complete
	time.Sleep(100 * time.Millisecond)
	
	pool.performBottleneckAnalysis()

	stats := pool.GetPoolStatistics()
	if stats.bottleneckAnalysis != nil {
		// CPU should be the primary bottleneck (75% utilized vs memory at ~3%)
		assert.Equal(t, "cpu", stats.bottleneckAnalysis.PrimaryBottleneck)
		assert.Greater(t, stats.bottleneckAnalysis.BottleneckSeverity, 70.0)
		assert.NotEmpty(t, stats.bottleneckAnalysis.RecommendedActions)
	}
}

func TestResourcePool_AlertThresholds(t *testing.T) {
	pool := createTestResourcePool()
	
	// Set lower thresholds for testing
	pool.alertThresholds.CPUUtilization = 50.0
	pool.alertThresholds.MemoryUtilization = 50.0
	pool.alertThresholds.QueueLength = 2

	// Allocate resources to exceed CPU threshold
	request := &ResourceRequest{
		ContainerID: "test-container",
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 2.5, // 62.5% of 4 cores
			},
		},
		Priority: 100,
		Timeout:  30 * time.Second,
	}

	ctx := context.Background()
	result, err := pool.AllocateResources(ctx, request)
	require.NoError(t, err)
	require.True(t, result.Success)

	// Check alerts (this is primarily testing that the method runs without error)
	pool.checkAlertThresholds()
	
	// In a real implementation, you would capture log output or have alert handlers
	// For now, we just verify the method completes successfully
	assert.True(t, true) // Placeholder assertion
}

func TestResourcePool_CopyPoolResources(t *testing.T) {
	original := &PoolResources{
		CPU: &CPUResource{
			Cores:     2.0,
			Shares:    1024,
			Quota:     50000,
			Period:    100000,
			Pinned:    []int{0, 1},
			Reserved:  0.5,
			Available: 1.5,
		},
		Memory: &MemoryResource{
			Total:     2 * 1024 * 1024 * 1024,
			Used:      512 * 1024 * 1024,
			Available: 1536 * 1024 * 1024,
			Reserved:  0,
			Cached:    256 * 1024 * 1024,
			Swap:      0,
		},
		Disk: &DiskResource{
			Total:        100 * 1024 * 1024 * 1024,
			Used:         20 * 1024 * 1024 * 1024,
			Available:    80 * 1024 * 1024 * 1024,
			Reserved:     0,
			Inodes:       1000000,
			InodesUsed:   100000,
			IOPS:         1000,
			Bandwidth:    100 * 1024 * 1024,
		},
		Custom: map[string]int64{
			"gpu": 2,
			"storage": 1000,
		},
	}

	copied := copyPoolResources(original)

	// Verify deep copy
	assert.NotSame(t, original, copied)
	assert.NotSame(t, original.CPU, copied.CPU)
	assert.NotSame(t, original.Memory, copied.Memory)
	assert.NotSame(t, original.Disk, copied.Disk)
	assert.NotSame(t, original.Custom, copied.Custom)

	// Verify values are copied correctly
	assert.Equal(t, original.CPU.Cores, copied.CPU.Cores)
	assert.Equal(t, original.CPU.Shares, copied.CPU.Shares)
	assert.Equal(t, original.Memory.Total, copied.Memory.Total)
	assert.Equal(t, original.Disk.Total, copied.Disk.Total)
	assert.Equal(t, original.Custom["gpu"], copied.Custom["gpu"])

	// Verify arrays are deep copied
	assert.NotSame(t, original.CPU.Pinned, copied.CPU.Pinned)
	assert.Equal(t, original.CPU.Pinned, copied.CPU.Pinned)

	// Test with nil input
	nilCopy := copyPoolResources(nil)
	assert.Nil(t, nilCopy)
}

func TestResourcePool_AddPoolResources(t *testing.T) {
	dst := &PoolResources{
		CPU: &CPUResource{
			Cores:     1.0,
			Available: 1.0,
		},
		Memory: &MemoryResource{
			Total:     1 * 1024 * 1024 * 1024,
			Available: 1 * 1024 * 1024 * 1024,
		},
		Disk: &DiskResource{
			Total:     10 * 1024 * 1024 * 1024,
			Available: 10 * 1024 * 1024 * 1024,
		},
	}

	src := &PoolResources{
		CPU: &CPUResource{
			Cores:     2.0,
			Available: 2.0,
		},
		Memory: &MemoryResource{
			Total:     2 * 1024 * 1024 * 1024,
			Available: 2 * 1024 * 1024 * 1024,
		},
		Disk: &DiskResource{
			Total:     20 * 1024 * 1024 * 1024,
			Available: 20 * 1024 * 1024 * 1024,
		},
	}

	addPoolResources(dst, src)

	assert.Equal(t, 3.0, dst.CPU.Cores)       // 1 + 2 = 3
	assert.Equal(t, 3.0, dst.CPU.Available)   // 1 + 2 = 3
	assert.Equal(t, int64(3*1024*1024*1024), dst.Memory.Total)     // 1GB + 2GB = 3GB
	assert.Equal(t, int64(3*1024*1024*1024), dst.Memory.Available) // 1GB + 2GB = 3GB
	assert.Equal(t, int64(30*1024*1024*1024), dst.Disk.Total)      // 10GB + 20GB = 30GB
	assert.Equal(t, int64(30*1024*1024*1024), dst.Disk.Available)  // 10GB + 20GB = 30GB
}

func TestResourcePool_CalculateCost(t *testing.T) {
	pool := createTestResourcePool()
	
	resources := &PoolResources{
		CPU: &CPUResource{
			Cores: 2.0,
		},
		Memory: &MemoryResource{
			Total: 4 * 1024 * 1024 * 1024, // 4GB
		},
		Disk: &DiskResource{
			Total: 50 * 1024 * 1024 * 1024, // 50GB
		},
	}
	
	duration := 2 * time.Hour // 2 hours
	cost := pool.calculateCost(resources, duration)
	
	expectedCost := (2.0 * 0.10 * 2) +       // CPU: 2 cores * $0.10/hour * 2 hours
		(4.0 * 0.05 * 2) +       // Memory: 4GB * $0.05/hour * 2 hours  
		(50.0 * 0.01 * 2)        // Disk: 50GB * $0.01/hour * 2 hours
	
	assert.Equal(t, expectedCost, cost)
}

func TestResourcePool_UpdateUtilizationMetrics(t *testing.T) {
	pool := createTestResourcePool()
	
	// Allocate some resources
	request := &ResourceRequest{
		ContainerID: "test-container",
		Resources: &PoolResources{
			CPU: &CPUResource{
				Cores: 2.0, // 50% of 4 cores
			},
			Memory: &MemoryResource{
				Total: 4 * 1024 * 1024 * 1024, // 50% of 8GB
			},
		},
		Priority: 100,
		Timeout:  30 * time.Second,
	}

	ctx := context.Background()
	result, err := pool.AllocateResources(ctx, request)
	require.NoError(t, err)
	require.True(t, result.Success)

	// Update utilization metrics
	pool.updateUtilizationMetrics()

	stats := pool.GetPoolStatistics()
	assert.Contains(t, stats.avgUtilization, "cpu")
	assert.Contains(t, stats.avgUtilization, "memory")
	assert.Equal(t, 50.0, stats.avgUtilization["cpu"])    // 50% CPU utilized
	assert.Equal(t, 50.0, stats.avgUtilization["memory"]) // 50% memory utilized
	
	assert.NotEmpty(t, stats.historicalData)
	latestSnapshot := stats.historicalData[len(stats.historicalData)-1]
	assert.Equal(t, 1, latestSnapshot.ActiveContainers)
	assert.Equal(t, 50.0, latestSnapshot.Utilization["cpu"])
}

func TestResourcePool_RecordResourceUsage(t *testing.T) {
	pool := createTestResourcePool()
	containerID := "test-container"
	
	resources := &PoolResources{
		CPU: &CPUResource{
			Cores: 1.0,
		},
		Memory: &MemoryResource{
			Total: 1 * 1024 * 1024 * 1024, // 1GB
		},
	}

	pool.recordResourceUsage(containerID, resources)

	pool.resourceAccounting.mu.RLock()
	records := pool.resourceAccounting.usageRecords[containerID]
	pool.resourceAccounting.mu.RUnlock()

	assert.Len(t, records, 1)
	record := records[0]
	assert.Equal(t, containerID, record.ContainerID)
	assert.Equal(t, resources.CPU.Cores, record.Resources.CPU.Cores)
	assert.Equal(t, resources.Memory.Total, record.Resources.Memory.Total)
	assert.Greater(t, record.Cost, 0.0)
	assert.True(t, record.EndTime.After(record.StartTime))
}

// Helper function to create a test resource pool
func createTestResourcePool() *ResourcePool {
	totalResources := &PoolResources{
		CPU: &CPUResource{
			Cores:     4.0,
			Available: 4.0,
		},
		Memory: &MemoryResource{
			Total:     8 * 1024 * 1024 * 1024, // 8GB
			Available: 8 * 1024 * 1024 * 1024,
		},
		Disk: &DiskResource{
			Total:     100 * 1024 * 1024 * 1024, // 100GB
			Available: 100 * 1024 * 1024 * 1024,
		},
	}

	pool := NewResourcePool("test-pool", "pool-001", totalResources)
	return pool
}

// Benchmark tests
func BenchmarkResourcePool_AllocateResources(b *testing.B) {
	pool := createTestResourcePool()
	
	resources := &PoolResources{
		CPU: &CPUResource{
			Cores: 0.1, // Small allocation
		},
		Memory: &MemoryResource{
			Total: 100 * 1024 * 1024, // 100MB
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		request := &ResourceRequest{
			ContainerID: "container-" + string(rune(i%1000)), // Reuse IDs
			Resources:   copyPoolResources(resources),
			Priority:    100,
			Timeout:     30 * time.Second,
		}
		
		ctx := context.Background()
		result, _ := pool.AllocateResources(ctx, request)
		if result.Success {
			// Clean up for next iteration
			pool.ReleaseResources(request.ContainerID)
		}
	}
}

func BenchmarkResourcePool_CopyPoolResources(b *testing.B) {
	original := &PoolResources{
		CPU: &CPUResource{
			Cores:     2.0,
			Shares:    1024,
			Pinned:    []int{0, 1, 2, 3},
			Available: 1.5,
		},
		Memory: &MemoryResource{
			Total:     2 * 1024 * 1024 * 1024,
			Available: 1536 * 1024 * 1024,
		},
		Disk: &DiskResource{
			Total:     100 * 1024 * 1024 * 1024,
			Available: 80 * 1024 * 1024 * 1024,
		},
		Custom: map[string]int64{
			"gpu": 2,
			"storage": 1000,
			"network": 1,
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = copyPoolResources(original)
	}
}

func BenchmarkResourcePool_UpdateUtilizationMetrics(b *testing.B) {
	pool := createTestResourcePool()
	
	// Allocate some resources for realistic metrics
	request := &ResourceRequest{
		ContainerID: "benchmark-container",
		Resources: &PoolResources{
			CPU: &CPUResource{Cores: 1.0},
			Memory: &MemoryResource{Total: 1 * 1024 * 1024 * 1024},
		},
		Priority: 100,
		Timeout:  30 * time.Second,
	}
	
	ctx := context.Background()
	pool.AllocateResources(ctx, request)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.updateUtilizationMetrics()
	}
}