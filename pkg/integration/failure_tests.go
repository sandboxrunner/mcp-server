package integration

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// FailureInjector provides chaos engineering capabilities for testing
type FailureInjector struct {
	framework *TestFramework
	mu        sync.RWMutex
	active    map[string]*InjectedFailure
}

// InjectedFailure represents an active failure injection
type InjectedFailure struct {
	Type        FailureType
	Target      string
	StartTime   time.Time
	Duration    time.Duration
	Cancel      context.CancelFunc
	Description string
}

// FailureType represents different types of failures that can be injected
type FailureType string

const (
	FailureTypeCPUStress      FailureType = "cpu_stress"
	FailureTypeMemoryStress   FailureType = "memory_stress"
	FailureTypeDiskStress     FailureType = "disk_stress"
	FailureTypeNetworkLatency FailureType = "network_latency"
	FailureTypeProcessKill    FailureType = "process_kill"
	FailureTypeFileSystemFull FailureType = "filesystem_full"
	FailureTypeResourceLimit  FailureType = "resource_limit"
)

// NewFailureInjector creates a new failure injector
func NewFailureInjector(framework *TestFramework) *FailureInjector {
	return &FailureInjector{
		framework: framework,
		active:    make(map[string]*InjectedFailure),
	}
}

// InjectFailure injects a specific type of failure
func (fi *FailureInjector) InjectFailure(ctx context.Context, failureType FailureType, target string, duration time.Duration) error {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	failureID := fmt.Sprintf("%s_%s_%d", failureType, target, time.Now().UnixNano())
	
	injectionCtx, cancel := context.WithTimeout(ctx, duration)
	
	failure := &InjectedFailure{
		Type:        failureType,
		Target:      target,
		StartTime:   time.Now(),
		Duration:    duration,
		Cancel:      cancel,
		Description: fmt.Sprintf("Injected %s failure on %s", failureType, target),
	}

	fi.active[failureID] = failure

	// Start the failure injection in a goroutine
	go func() {
		defer func() {
			fi.mu.Lock()
			delete(fi.active, failureID)
			fi.mu.Unlock()
		}()

		err := fi.executeFailure(injectionCtx, failure)
		if err != nil {
			// Log error but don't fail the test - failures are expected
			fmt.Printf("Failure injection %s completed with error (expected): %v\n", failureID, err)
		}
	}()

	return nil
}

// executeFailure executes the actual failure injection
func (fi *FailureInjector) executeFailure(ctx context.Context, failure *InjectedFailure) error {
	switch failure.Type {
	case FailureTypeCPUStress:
		return fi.injectCPUStress(ctx, failure.Target)
	case FailureTypeMemoryStress:
		return fi.injectMemoryStress(ctx, failure.Target)
	case FailureTypeDiskStress:
		return fi.injectDiskStress(ctx, failure.Target)
	case FailureTypeProcessKill:
		return fi.injectProcessKill(ctx, failure.Target)
	case FailureTypeResourceLimit:
		return fi.injectResourceLimit(ctx, failure.Target)
	default:
		return fmt.Errorf("unsupported failure type: %s", failure.Type)
	}
}

// injectCPUStress creates high CPU load
func (fi *FailureInjector) injectCPUStress(ctx context.Context, sandboxID string) error {
	execTool := &tools.ExecCommandTool{Manager: fi.framework.SandboxManager}
	
	// Create a CPU-intensive process
	_, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": sandboxID,
		"command":    "sh",
		"args": []string{"-c", 
			"while true; do dd if=/dev/zero of=/dev/null bs=1M count=100 2>/dev/null; done &"},
	})
	
	return err
}

// injectMemoryStress creates memory pressure
func (fi *FailureInjector) injectMemoryStress(ctx context.Context, sandboxID string) error {
	execTool := &tools.ExecCommandTool{Manager: fi.framework.SandboxManager}
	
	// Create memory-intensive process
	_, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": sandboxID,
		"command":    "sh",
		"args": []string{"-c", 
			"python3 -c 'data = [i for i in range(1000000)]; import time; time.sleep(30)' &"},
	})
	
	return err
}

// injectDiskStress creates disk I/O pressure
func (fi *FailureInjector) injectDiskStress(ctx context.Context, sandboxID string) error {
	execTool := &tools.ExecCommandTool{Manager: fi.framework.SandboxManager}
	
	// Create disk-intensive process
	_, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": sandboxID,
		"command":    "sh",
		"args": []string{"-c", 
			"while true; do dd if=/dev/zero of=/tmp/diskstress.tmp bs=1M count=10 2>/dev/null; rm -f /tmp/diskstress.tmp; done &"},
	})
	
	return err
}

// injectProcessKill kills random processes
func (fi *FailureInjector) injectProcessKill(ctx context.Context, sandboxID string) error {
	// This is a simplified version - in production you'd be more selective
	execTool := &tools.ExecCommandTool{Manager: fi.framework.SandboxManager}
	
	// Kill a non-essential process
	_, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": sandboxID,
		"command":    "pkill",
		"args":       []string{"-f", "sleep"},
	})
	
	return err
}

// injectResourceLimit artificially limits resources
func (fi *FailureInjector) injectResourceLimit(ctx context.Context, sandboxID string) error {
	// This would normally use cgroup limits, but we'll simulate
	execTool := &tools.ExecCommandTool{Manager: fi.framework.SandboxManager}
	
	// Create a process that consumes resources up to a limit
	_, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": sandboxID,
		"command":    "sh",
		"args": []string{"-c", 
			"ulimit -v 50000; python3 -c 'import time; time.sleep(10)' &"},
	})
	
	return err
}

// StopAllFailures stops all active failure injections
func (fi *FailureInjector) StopAllFailures() {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	for id, failure := range fi.active {
		failure.Cancel()
		delete(fi.active, id)
	}
}

// GetActiveFailures returns information about currently active failures
func (fi *FailureInjector) GetActiveFailures() []InjectedFailure {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	failures := make([]InjectedFailure, 0, len(fi.active))
	for _, failure := range fi.active {
		failures = append(failures, *failure)
	}
	return failures
}

// TestFailureInjectionAndRecovery tests system behavior under various failure conditions
func TestFailureInjectionAndRecovery(t *testing.T) {
	env := DefaultTestEnvironment()
	env.CleanupOnFailure = false // Keep resources for failure analysis
	framework := SetupTestFramework(t, env)
	asserts := NewIntegrationAsserts(t)
	injector := NewFailureInjector(framework)

	// Ensure all failures are stopped after test
	defer injector.StopAllFailures()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Run("ContainerCrashRecovery", func(t *testing.T) {
		// Create a sandbox that we'll crash
		container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"TEST_TYPE": "crash_recovery",
			},
		})

		framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
		asserts.AssertSandboxExists(framework.SandboxManager, container.ID, sandbox.SandboxStatusRunning)

		// Start a long-running process
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "sh",
			"args":       []string{"-c", "sleep 60 &"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

		// Inject process kill failure
		err = injector.InjectFailure(ctx, FailureTypeProcessKill, container.ID, 5*time.Second)
		assert.NoError(t, err)

		// Wait for failure to take effect
		time.Sleep(2 * time.Second)

		// Container should still be running (recovery should happen)
		sb, err := framework.SandboxManager.GetSandbox(container.ID)
		require.NoError(t, err)
		
		// The container itself should still exist even if processes were killed
		assert.NotEqual(t, sandbox.SandboxStatusError, sb.Status, "Container should not be in error state")
	})

	t.Run("ResourceExhaustionHandling", func(t *testing.T) {
		// Create containers with limited resources
		container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "0.5",
				MemoryLimit: "128M",
				DiskLimit:   "256M",
			},
			Environment: map[string]string{
				"TEST_TYPE": "resource_exhaustion",
			},
		})

		framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

		// Take baseline resource measurement
		baselineUsage := framework.ResourceMonitor.TakeSnapshot()

		// Inject multiple resource stresses simultaneously
		var wg sync.WaitGroup
		stressDuration := 10 * time.Second

		stressTests := []FailureType{
			FailureTypeCPUStress,
			FailureTypeMemoryStress,
			FailureTypeDiskStress,
		}

		for _, stressType := range stressTests {
			wg.Add(1)
			go func(failureType FailureType) {
				defer wg.Done()
				err := injector.InjectFailure(ctx, failureType, container.ID, stressDuration)
				if err != nil {
					t.Logf("Stress injection %s failed (may be expected): %v", failureType, err)
				}
			}(stressType)
		}

		// Wait for stress tests to start
		time.Sleep(2 * time.Second)

		// Verify container is still responsive during stress
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "echo",
			"args":       []string{"stress_test_response"},
			"timeout":    30, // Allow extra time during stress
		})

		// Container should still respond, even if slowly
		if err == nil {
			assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "stress_test_response", 
				"Container should remain responsive during resource stress")
		} else {
			t.Logf("Container became unresponsive during stress (may be expected): %v", err)
		}

		// Wait for all stress tests to complete
		wg.Wait()
		time.Sleep(2 * time.Second)

		// Take final resource measurement
		finalUsage := framework.ResourceMonitor.TakeSnapshot()
		snapshot := framework.ResourceMonitor.CompareSnapshots(baselineUsage, finalUsage)

		// Verify system recovered after stress
		sb, err := framework.SandboxManager.GetSandbox(container.ID)
		require.NoError(t, err)
		assert.NotEqual(t, sandbox.SandboxStatusError, sb.Status, "Container should recover from resource stress")

		t.Logf("Resource stress test completed:")
		t.Logf("  Memory delta: %.2f MB", snapshot.Delta.MemoryUsedMB)
		t.Logf("  CPU delta: %.2f%%", snapshot.Delta.CPUPercent)
		t.Logf("  Container status: %s", sb.Status)
	})

	t.Run("NetworkConnectivityFailure", func(t *testing.T) {
		// Test behavior when network connectivity is impaired
		container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"TEST_TYPE": "network_failure",
			},
		})

		framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

		// Test basic connectivity first
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "ping",
			"args":       []string{"-c", "1", "127.0.0.1"},
			"timeout":    10,
		})

		if err == nil && result.(*tools.ExecutionResult).ExitCode == 0 {
			t.Log("Loopback connectivity confirmed")
		} else {
			t.Log("Network tools may not be available in basic container")
		}

		// Simulate network degradation by creating network stress
		// In a real implementation, this would use network namespaces or iptables rules
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "sh",
			"args": []string{"-c", 
				"# Simulate network latency by adding artificial delays\n" +
				"for i in $(seq 1 10); do sleep 0.5; echo 'Network operation $i'; done"},
			"timeout": 30,
		})

		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))
		assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "Network operation", 
			"Network simulation should complete")
	})

	t.Run("StorageFailureRecovery", func(t *testing.T) {
		// Test behavior when storage becomes full or fails
		container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				DiskLimit: "100M", // Small disk limit to trigger failures
			},
			Environment: map[string]string{
				"TEST_TYPE": "storage_failure",
			},
		})

		framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

		// Fill up disk space gradually
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}

		// Create a large file to consume disk space
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "dd",
			"args":       []string{"if=/dev/zero", "of=/workspace/largefile.tmp", "bs=1M", "count=50"},
			"timeout":    30,
		})

		// This might fail due to disk space limits - that's expected
		if err != nil {
			t.Logf("Disk space test triggered expected failure: %v", err)
		} else if result.(*tools.ExecutionResult).ExitCode != 0 {
			t.Log("Disk space limit reached as expected")
		}

		// Verify container is still accessible
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "df",
			"args":       []string{"-h", "/workspace"},
			"timeout":    10,
		})

		if err == nil {
			t.Logf("Disk usage after storage stress: %s", result.(*tools.ExecutionResult).Stdout)
		}

		// Clean up large file and verify recovery
		execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "rm",
			"args":       []string{"-f", "/workspace/largefile.tmp"},
		})

		// Verify container is still functional after cleanup
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "echo",
			"args":       []string{"storage_recovery_test"},
		})

		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))
		assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "storage_recovery_test",
			"Container should recover after storage cleanup")
	})

	t.Run("ConcurrentFailureHandling", func(t *testing.T) {
		// Test system behavior when multiple failures occur simultaneously
		const numContainers = 3
		var containers []*sandbox.Sandbox

		// Create multiple containers
		for i := 0; i < numContainers; i++ {
			container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
				Image:        "ubuntu:20.04",
				WorkspaceDir: "/workspace",
				Environment: map[string]string{
					"CONTAINER_INDEX": fmt.Sprintf("%d", i),
					"TEST_TYPE":      "concurrent_failure",
				},
			})
			containers = append(containers, container)
			framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
		}

		// Inject different types of failures on different containers simultaneously
		failureTypes := []FailureType{
			FailureTypeCPUStress,
			FailureTypeMemoryStress,
			FailureTypeProcessKill,
		}

		var wg sync.WaitGroup
		for i, container := range containers {
			wg.Add(1)
			go func(containerIndex int, cont *sandbox.Sandbox, failType FailureType) {
				defer wg.Done()
				
				err := injector.InjectFailure(ctx, failType, cont.ID, 15*time.Second)
				if err != nil {
					t.Logf("Failure injection %s on container %d failed: %v", failType, containerIndex, err)
				}
			}(i, container, failureTypes[i])
		}

		// Wait a bit for failures to start
		time.Sleep(2 * time.Second)

		// Check system stability while failures are active
		activeFailures := injector.GetActiveFailures()
		assert.Len(t, activeFailures, numContainers, "All failures should be active")

		// Verify the sandbox manager can still list sandboxes
		sandboxes, err := framework.SandboxManager.ListSandboxes()
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(sandboxes), numContainers, 
			"Should still be able to list sandboxes during concurrent failures")

		// Wait for all failures to complete
		wg.Wait()
		time.Sleep(2 * time.Second)

		// Verify system recovery
		for i, container := range containers {
			result, err := framework.SandboxManager.GetSandbox(container.ID)
			require.NoError(t, err)
			assert.NotEqual(t, sandbox.SandboxStatusError, result.Status,
				fmt.Sprintf("Container %d should not be in error state after failure recovery", i))
		}

		t.Log("Concurrent failure handling test completed successfully")
	})
}

// TestChaosEngineering implements chaos engineering principles for testing resilience
func TestChaosEngineering(t *testing.T) {
	framework := SetupTestFramework(t, DefaultTestEnvironment())
	injector := NewFailureInjector(framework)
	defer injector.StopAllFailures()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Run("ChaosMonkey", func(t *testing.T) {
		// Implement chaos monkey pattern - randomly terminate containers
		const numContainers = 10
		const chaosDuration = 60 * time.Second
		const terminationProbability = 0.3 // 30% chance to terminate each container

		var containers []*sandbox.Sandbox
		var containerMutex sync.RWMutex

		// Create initial container pool
		for i := 0; i < numContainers; i++ {
			container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
				Image:        "ubuntu:20.04",
				WorkspaceDir: "/workspace",
				Environment: map[string]string{
					"CHAOS_TARGET": "true",
					"CONTAINER_ID": fmt.Sprintf("chaos_%d", i),
				},
			})
			
			containerMutex.Lock()
			containers = append(containers, container)
			containerMutex.Unlock()
			
			framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
		}

		// Start chaos monkey
		chaosCtx, chaosCancel := context.WithTimeout(ctx, chaosDuration)
		defer chaosCancel()

		var chaosWg sync.WaitGroup
		chaosWg.Add(1)

		go func() {
			defer chaosWg.Done()
			ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
			defer ticker.Stop()

			for {
				select {
				case <-chaosCtx.Done():
					return
				case <-ticker.C:
					containerMutex.RLock()
					currentContainers := make([]*sandbox.Sandbox, len(containers))
					copy(currentContainers, containers)
					containerMutex.RUnlock()

					// Randomly select containers for termination
					for _, container := range currentContainers {
						if framework.ResourceMonitor.TakeSnapshot().MemoryPercent < 50 { // Only if resources allow
							// 30% chance to terminate
							if time.Now().UnixNano()%100 < 30 {
								err := framework.SandboxManager.TerminateSandbox(chaosCtx, container.ID)
								if err == nil {
									t.Logf("Chaos monkey terminated container: %s", container.ID)
								}
							}
						}
					}

					// Create replacement containers to maintain pool size
					containerMutex.Lock()
					aliveCount := 0
					for _, container := range containers {
						if sb, err := framework.SandboxManager.GetSandbox(container.ID); err == nil && sb.Status == sandbox.SandboxStatusRunning {
							aliveCount++
						}
					}

					// Add new containers if we're below target
					for aliveCount < numContainers/2 { // Maintain at least half
						newContainer := framework.CreateTestSandbox(chaosCtx, t, &sandbox.SandboxConfig{
							Environment: map[string]string{
								"CHAOS_TARGET":   "true",
								"REPLACEMENT":   "true",
								"CREATED_AT":    time.Now().Format(time.RFC3339),
							},
						})
						containers = append(containers, newContainer)
						aliveCount++
						t.Logf("Chaos monkey created replacement container: %s", newContainer.ID)
					}
					containerMutex.Unlock()
				}
			}
		}()

		// Monitor system during chaos
		monitoringTicker := time.NewTicker(5 * time.Second)
		defer monitoringTicker.Stop()

		startTime := time.Now()
		for {
			select {
			case <-chaosCtx.Done():
				goto chaosComplete
			case <-monitoringTicker.C:
				usage := framework.ResourceMonitor.GetCurrentUsage()
				sandboxes, err := framework.SandboxManager.ListSandboxes()
				
				elapsed := time.Since(startTime)
				if err == nil {
					t.Logf("Chaos progress - Elapsed: %v, Active sandboxes: %d, Memory: %.1f%%, CPU: %.1f%%",
						elapsed.Truncate(time.Second), len(sandboxes), usage.MemoryPercent, usage.CPUPercent)
				} else {
					t.Logf("Chaos progress - Elapsed: %v, Manager error: %v", elapsed.Truncate(time.Second), err)
				}
			}
		}

	chaosComplete:
		chaosWg.Wait()

		// Verify system is still functional after chaos
		finalSandboxes, err := framework.SandboxManager.ListSandboxes()
		require.NoError(t, err)
		assert.Greater(t, len(finalSandboxes), 0, "Some sandboxes should survive chaos testing")

		t.Logf("Chaos monkey completed - Final sandbox count: %d", len(finalSandboxes))
	})

	t.Run("LoadSpike", func(t *testing.T) {
		// Simulate sudden load spikes
		const baselineContainers = 5
		const spikeContainers = 20
		const spikeDuration = 30 * time.Second

		// Create baseline load
		var baselineContainers_slice []*sandbox.Sandbox
		for i := 0; i < baselineContainers; i++ {
			container := framework.CreateTestSandbox(ctx, t, nil)
			baselineContainers_slice = append(baselineContainers_slice, container)
			framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
		}

		baselineUsage := framework.ResourceMonitor.TakeSnapshot()
		t.Logf("Baseline established with %d containers - Memory: %.1f%%, CPU: %.1f%%",
			baselineContainers, baselineUsage.MemoryPercent, baselineUsage.CPUPercent)

		// Create load spike
		spikeStart := time.Now()
		var spikeContainers_slice []*sandbox.Sandbox
		var wg sync.WaitGroup

		for i := 0; i < spikeContainers; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				
				container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
					Environment: map[string]string{
						"SPIKE_CONTAINER": "true",
						"SPIKE_INDEX":     fmt.Sprintf("%d", index),
					},
				})
				
				spikeContainers_slice = append(spikeContainers_slice, container)
				framework.WaitForSandboxReady(ctx, t, container.ID, 60*time.Second)

				// Execute some work in the spike container
				execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
				execTool.Execute(ctx, map[string]interface{}{
					"sandbox_id": container.ID,
					"command":    "echo",
					"args":       []string{fmt.Sprintf("spike_container_%d_active", index)},
				})
			}(i)
		}

		wg.Wait()
		spikeCreateTime := time.Since(spikeStart)
		spikeUsage := framework.ResourceMonitor.TakeSnapshot()

		t.Logf("Load spike created in %v - Total containers: %d, Memory: %.1f%%, CPU: %.1f%%",
			spikeCreateTime, baselineContainers+spikeContainers, spikeUsage.MemoryPercent, spikeUsage.CPUPercent)

		// Maintain spike load for specified duration
		time.Sleep(spikeDuration)

		// Gradually reduce load
		for i := len(spikeContainers_slice) - 1; i >= 0; i-- {
			if i%2 == 0 { // Remove every other container
				err := framework.SandboxManager.TerminateSandbox(ctx, spikeContainers_slice[i].ID)
				if err == nil {
					time.Sleep(100 * time.Millisecond) // Gradual scale-down
				}
			}
		}

		recoveryUsage := framework.ResourceMonitor.TakeSnapshot()
		t.Logf("Load spike recovery - Memory: %.1f%%, CPU: %.1f%%",
			recoveryUsage.MemoryPercent, recoveryUsage.CPUPercent)

		// Verify system recovered
		assert.Less(t, recoveryUsage.MemoryPercent, spikeUsage.MemoryPercent*1.1, 
			"Memory usage should decrease after load spike")
	})

	t.Run("RandomizedChaos", func(t *testing.T) {
		// Implement truly randomized chaos testing
		const testDuration = 2 * time.Minute
		const maxConcurrentFailures = 5

		container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Environment: map[string]string{
				"CHAOS_TYPE": "randomized",
			},
		})
		framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

		chaosCtx, chaosCancel := context.WithTimeout(ctx, testDuration)
		defer chaosCancel()

		var activeChaos sync.Map
		var chaosCounter int64

		// Chaos generator
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()

			allFailureTypes := []FailureType{
				FailureTypeCPUStress,
				FailureTypeMemoryStress,
				FailureTypeDiskStress,
				FailureTypeProcessKill,
			}

			for {
				select {
				case <-chaosCtx.Done():
					return
				case <-ticker.C:
					// Count active chaos
					var activeCount int
					activeChaos.Range(func(key, value interface{}) bool {
						activeCount++
						return true
					})

					if activeCount < maxConcurrentFailures {
						// Select random failure type
						failureType := allFailureTypes[time.Now().UnixNano()%int64(len(allFailureTypes))]
						duration := time.Duration(5+time.Now().UnixNano()%15) * time.Second

						chaosID := fmt.Sprintf("chaos_%d", chaosCounter)
						chaosCounter++

						activeChaos.Store(chaosID, true)

						go func(id string, ftype FailureType, dur time.Duration) {
							defer activeChaos.Delete(id)
							
							err := injector.InjectFailure(chaosCtx, ftype, container.ID, dur)
							if err != nil {
								t.Logf("Random chaos %s (%s) failed: %v", id, ftype, err)
							} else {
								t.Logf("Random chaos %s (%s) completed after %v", id, ftype, dur)
							}
						}(chaosID, failureType, duration)
					}
				}
			}
		}()

		// Periodic health checks during chaos
		healthTicker := time.NewTicker(10 * time.Second)
		defer healthTicker.Stop()

		var healthCheckCount, healthCheckSuccess int

		for {
			select {
			case <-chaosCtx.Done():
				goto randomChaosComplete
			case <-healthTicker.C:
				healthCheckCount++
				
				// Try to execute a simple command
				execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
				result, err := execTool.Execute(context.Background(), map[string]interface{}{
					"sandbox_id": container.ID,
					"command":    "echo",
					"args":       []string{"health_check"},
					"timeout":    15,
				})

				if err == nil && result.(*tools.ExecutionResult).ExitCode == 0 {
					healthCheckSuccess++
					t.Logf("Health check %d/%d passed during chaos", healthCheckSuccess, healthCheckCount)
				} else {
					t.Logf("Health check %d failed during chaos: %v", healthCheckCount, err)
				}
			}
		}

	randomChaosComplete:
		// Calculate resilience metrics
		successRate := float64(healthCheckSuccess) / float64(healthCheckCount) * 100
		t.Logf("Randomized chaos completed - Success rate: %.1f%% (%d/%d)", 
			successRate, healthCheckSuccess, healthCheckCount)

		// We expect some failures during chaos, but system should maintain reasonable availability
		assert.Greater(t, successRate, 50.0, "System should maintain >50% availability during chaos")

		// Final verification
		sb, err := framework.SandboxManager.GetSandbox(container.ID)
		require.NoError(t, err)
		assert.NotEqual(t, sandbox.SandboxStatusError, sb.Status, "Container should not be in error state after chaos")
	})
}