package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// TestMultiContainerOrchestration tests creating and managing multiple containers simultaneously
func TestMultiContainerOrchestration(t *testing.T) {
	framework := SetupTestFramework(t, DefaultTestEnvironment())
	asserts := NewIntegrationAsserts(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Run("ConcurrentContainerCreation", func(t *testing.T) {
		const numContainers = 5
		results := make(chan *sandbox.Sandbox, numContainers)
		errors := make(chan error, numContainers)

		var wg sync.WaitGroup

		// Create containers concurrently
		for i := 0; i < numContainers; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				config := &sandbox.SandboxConfig{
					Image:        "ubuntu:20.04",
					WorkspaceDir: "/workspace",
					Environment: map[string]string{
						"CONTAINER_ID": fmt.Sprintf("container_%d", index),
						"TEST_MODE":   "concurrent",
					},
					Resources: sandbox.ResourceLimits{
						CPULimit:    framework.Config.Sandbox.DefaultResources.CPULimit,
						MemoryLimit: framework.Config.Sandbox.DefaultResources.MemoryLimit,
						DiskLimit:   framework.Config.Sandbox.DefaultResources.DiskLimit,
					},
				}

				sb, err := framework.SandboxManager.CreateSandbox(ctx, *config)
				if err != nil {
					errors <- fmt.Errorf("container %d creation failed: %w", index, err)
					return
				}

				framework.ActiveContainers.Store(sb.ID, sb)
				results <- sb
			}(i)
		}

		// Wait for all creations to complete
		go func() {
			wg.Wait()
			close(results)
			close(errors)
		}()

		// Collect results
		var sandboxes []*sandbox.Sandbox
		var creationErrors []error

		for result := range results {
			sandboxes = append(sandboxes, result)
		}

		for err := range errors {
			creationErrors = append(creationErrors, err)
		}

		// Verify results
		assert.Empty(t, creationErrors, "No creation errors should occur")
		assert.Len(t, sandboxes, numContainers, "All containers should be created")

		// Wait for all containers to be ready
		for _, sb := range sandboxes {
			framework.WaitForSandboxReady(ctx, t, sb.ID, 30*time.Second)
			asserts.AssertSandboxExists(framework.SandboxManager, sb.ID, sandbox.SandboxStatusRunning)
		}
	})

	t.Run("CrossContainerCommunication", func(t *testing.T) {
		// Create two containers for communication testing
		container1 := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"ROLE": "sender",
			},
		})

		container2 := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Environment: map[string]string{
				"ROLE": "receiver",
			},
		})

		framework.WaitForSandboxReady(ctx, t, container1.ID, 30*time.Second)
		framework.WaitForSandboxReady(ctx, t, container2.ID, 30*time.Second)

		// Create test files in both containers
		testData := "Hello from container communication test!"

		// Write data to container1
		execTool := tools.NewExecCommandTool(framework.SandboxManager)
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container1.ID,
			"command":    "echo " + testData,
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result)

		// Verify both containers are isolated (no direct communication)
		// This test demonstrates container isolation rather than communication
		result1, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container1.ID,
			"command":    "hostname",
		})
		require.NoError(t, err)
		hostname1 := result1.Text

		result2, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container2.ID,
			"command":    "hostname",
		})
		require.NoError(t, err)
		hostname2 := result2.Text

		// Containers should have different hostnames (isolation)
		assert.NotEqual(t, hostname1, hostname2, "Containers should be isolated with different hostnames")
	})

	t.Run("LoadBalancingAcrossContainers", func(t *testing.T) {
		const numContainers = 3
		const tasksPerContainer = 10

		// Create containers for load balancing test
		var containers []*sandbox.Sandbox
		for i := 0; i < numContainers; i++ {
			container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
				Image:        "ubuntu:20.04",
				WorkspaceDir: "/workspace",
				Environment: map[string]string{
					"WORKER_ID": fmt.Sprintf("worker_%d", i),
				},
			})
			containers = append(containers, container)
			framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
		}

		// Execute tasks across containers in round-robin fashion
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		var wg sync.WaitGroup
		results := make(chan *tools.ExecutionResult, numContainers*tasksPerContainer)
		errors := make(chan error, numContainers*tasksPerContainer)

		for i := 0; i < numContainers*tasksPerContainer; i++ {
			wg.Add(1)
			go func(taskID int) {
				defer wg.Done()

				containerIndex := taskID % numContainers
				container := containers[containerIndex]

				result, err := execTool.Execute(ctx, map[string]interface{}{
					"sandbox_id": container.ID,
					"command":    "echo",
					"args":       []string{fmt.Sprintf("Task_%d_in_Container_%d", taskID, containerIndex)},
				})

				if err != nil {
					errors <- fmt.Errorf("task %d failed: %w", taskID, err)
					return
				}

				results <- result.(*tools.ExecutionResult)
			}(i)
		}

		go func() {
			wg.Wait()
			close(results)
			close(errors)
		}()

		// Collect results
		var successCount int
		var executionErrors []error

		for result := range results {
			if result.ExitCode == 0 {
				successCount++
			}
		}

		for err := range errors {
			executionErrors = append(executionErrors, err)
		}

		// Verify load balancing worked
		assert.Empty(t, executionErrors, "No execution errors should occur")
		assert.Equal(t, numContainers*tasksPerContainer, successCount, "All tasks should complete successfully")
	})

	t.Run("ContainerResourceIsolation", func(t *testing.T) {
		// Create containers with different resource limits
		lowResourceContainer := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "0.1",
				MemoryLimit: "64M",
				DiskLimit:   "128M",
			},
		})

		highResourceContainer := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Image:        "ubuntu:20.04",
			WorkspaceDir: "/workspace",
			Resources: sandbox.ResourceLimits{
				CPULimit:    "1.0",
				MemoryLimit: "512M",
				DiskLimit:   "1G",
			},
		})

		framework.WaitForSandboxReady(ctx, t, lowResourceContainer.ID, 30*time.Second)
		framework.WaitForSandboxReady(ctx, t, highResourceContainer.ID, 30*time.Second)

		// Verify containers are created with different resource limits
		asserts.AssertSandboxExists(framework.SandboxManager, lowResourceContainer.ID, sandbox.SandboxStatusRunning)
		asserts.AssertSandboxExists(framework.SandboxManager, highResourceContainer.ID, sandbox.SandboxStatusRunning)

		// Test memory usage in both containers
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}

		// Check available memory in low-resource container
		result1, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": lowResourceContainer.ID,
			"command":    "free",
			"args":       []string{"-m"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result1.(*tools.ExecutionResult))

		// Check available memory in high-resource container
		result2, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": highResourceContainer.ID,
			"command":    "free",
			"args":       []string{"-m"},
		})
		require.NoError(t, err)
		asserts.AssertExecutionSuccess(result2.(*tools.ExecutionResult))

		// The containers should show different available memory
		assert.NotEqual(t, result1.(*tools.ExecutionResult).Stdout, result2.(*tools.ExecutionResult).Stdout,
			"Containers with different resource limits should show different memory availability")
	})

	t.Run("ContainerLifecycleManagement", func(t *testing.T) {
		// Test creating, stopping, and cleaning up multiple containers
		const numContainers = 4
		var sandboxIDs []string

		// Create containers
		for i := 0; i < numContainers; i++ {
			container := framework.CreateTestSandbox(ctx, t, nil)
			sandboxIDs = append(sandboxIDs, container.ID)
			framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
		}

		// Verify all containers are running
		for _, id := range sandboxIDs {
			asserts.AssertSandboxExists(framework.SandboxManager, id, sandbox.SandboxStatusRunning)
		}

		// Terminate half the containers
		for i := 0; i < numContainers/2; i++ {
			err := framework.SandboxManager.TerminateSandbox(ctx, sandboxIDs[i])
			require.NoError(t, err)
		}

		// Wait for termination to complete
		time.Sleep(2 * time.Second)

		// Verify terminated containers are stopped
		for i := 0; i < numContainers/2; i++ {
			sb, err := framework.SandboxManager.GetSandbox(sandboxIDs[i])
			require.NoError(t, err)
			assert.Equal(t, sandbox.SandboxStatusStopped, sb.Status)
		}

		// Verify remaining containers are still running
		for i := numContainers / 2; i < numContainers; i++ {
			asserts.AssertSandboxExists(framework.SandboxManager, sandboxIDs[i], sandbox.SandboxStatusRunning)
		}
	})
}

// TestContainerPerformance tests performance characteristics of container operations
func TestContainerPerformance(t *testing.T) {
	env := DefaultTestEnvironment()
	env.MaxConcurrentSandboxes = 20
	framework := SetupTestFramework(t, env)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Run("ContainerStartupTime", func(t *testing.T) {
		const numSamples = 10
		var startupTimes []time.Duration

		for i := 0; i < numSamples; i++ {
			start := time.Now()
			
			container := framework.CreateTestSandbox(ctx, t, nil)
			framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
			
			startupTime := time.Since(start)
			startupTimes = append(startupTimes, startupTime)
		}

		// Calculate average startup time
		var total time.Duration
		for _, duration := range startupTimes {
			total += duration
		}
		avgStartupTime := total / time.Duration(len(startupTimes))

		// Performance assertions
		assert.Less(t, avgStartupTime, 500*time.Millisecond, "Average container startup time should be under 500ms")
		
		t.Logf("Container startup performance:")
		t.Logf("  Average: %v", avgStartupTime)
		t.Logf("  Samples: %v", startupTimes)
	})

	t.Run("HighConcurrencyCreation", func(t *testing.T) {
		const targetContainers = 100
		const batchSize = 10
		
		startTime := time.Now()
		var allContainers []*sandbox.Sandbox
		
		// Create containers in batches to avoid overwhelming the system
		for batch := 0; batch < targetContainers/batchSize; batch++ {
			batchStart := time.Now()
			var wg sync.WaitGroup
			results := make(chan *sandbox.Sandbox, batchSize)
			errors := make(chan error, batchSize)

			// Create batch of containers
			for i := 0; i < batchSize; i++ {
				wg.Add(1)
				go func(containerIndex int) {
					defer wg.Done()

					config := &sandbox.SandboxConfig{
						Image:        "ubuntu:20.04",
						WorkspaceDir: "/workspace",
						Environment: map[string]string{
							"BATCH":      fmt.Sprintf("%d", batch),
							"BATCH_ID":   fmt.Sprintf("%d", containerIndex),
							"TEST_MODE":  "high_concurrency",
						},
					}

					sb, err := framework.SandboxManager.CreateSandbox(ctx, *config)
					if err != nil {
						errors <- err
						return
					}

					framework.ActiveContainers.Store(sb.ID, sb)
					results <- sb
				}(i)
			}

			// Wait for batch completion
			go func() {
				wg.Wait()
				close(results)
				close(errors)
			}()

			// Collect batch results
			var batchContainers []*sandbox.Sandbox
			var batchErrors []error

			for result := range results {
				batchContainers = append(batchContainers, result)
			}

			for err := range errors {
				batchErrors = append(batchErrors, err)
			}

			// Verify batch success
			assert.Empty(t, batchErrors, fmt.Sprintf("Batch %d should complete without errors", batch))
			assert.Len(t, batchContainers, batchSize, fmt.Sprintf("Batch %d should create all containers", batch))

			allContainers = append(allContainers, batchContainers...)
			batchDuration := time.Since(batchStart)
			
			t.Logf("Batch %d completed in %v (%d containers)", batch, batchDuration, len(batchContainers))
		}

		totalDuration := time.Since(startTime)
		
		// Performance assertions
		assert.Len(t, allContainers, targetContainers, "All containers should be created")
		assert.Less(t, totalDuration, 60*time.Second, "Should create 100 containers within 60 seconds")
		
		t.Logf("High concurrency performance:")
		t.Logf("  Total containers: %d", len(allContainers))
		t.Logf("  Total time: %v", totalDuration)
		t.Logf("  Average per container: %v", totalDuration/time.Duration(len(allContainers)))
		
		// Resource usage summary
		framework.ResourceMonitor.PrintUsageSummary()
	})

	t.Run("SustainedLoad", func(t *testing.T) {
		const loadDuration = 30 * time.Second
		const operationsPerSecond = 5
		
		startTime := time.Now()
		var operationCount int
		var errors []error
		
		ticker := time.NewTicker(time.Second / operationsPerSecond)
		defer ticker.Stop()
		
		loadCtx, loadCancel := context.WithTimeout(ctx, loadDuration)
		defer loadCancel()
		
		// Take baseline resource snapshot
		baselineUsage := framework.ResourceMonitor.TakeSnapshot()
		
		for {
			select {
			case <-loadCtx.Done():
				goto loadComplete
			case <-ticker.C:
				// Perform container operation (create and terminate quickly)
				go func() {
					config := &sandbox.SandboxConfig{
						Image:        "ubuntu:20.04",
						WorkspaceDir: "/workspace",
						Resources: sandbox.ResourceLimits{
							CPULimit:    "0.1",
							MemoryLimit: "64M",
						},
					}

					sb, err := framework.SandboxManager.CreateSandbox(ctx, *config)
					if err != nil {
						errors = append(errors, err)
						return
					}

					operationCount++

					// Quickly terminate to maintain steady state
					go func() {
						time.Sleep(100 * time.Millisecond)
						framework.SandboxManager.TerminateSandbox(ctx, sb.ID)
					}()
				}()
			}
		}

	loadComplete:
		actualDuration := time.Since(startTime)
		
		// Take final resource snapshot
		finalUsage := framework.ResourceMonitor.TakeSnapshot()
		snapshot := framework.ResourceMonitor.CompareSnapshots(baselineUsage, finalUsage)
		
		// Performance assertions
		expectedOperations := int(loadDuration.Seconds()) * operationsPerSecond
		assert.GreaterOrEqual(t, operationCount, expectedOperations*80/100, "Should achieve at least 80% of target operations")
		assert.Less(t, len(errors), operationCount*10/100, "Error rate should be below 10%")
		
		t.Logf("Sustained load performance:")
		t.Logf("  Duration: %v", actualDuration)
		t.Logf("  Operations: %d", operationCount)
		t.Logf("  Operations/second: %.2f", float64(operationCount)/actualDuration.Seconds())
		t.Logf("  Error rate: %.2f%%", float64(len(errors))/float64(operationCount)*100)
		t.Logf("  Memory delta: %.2f MB", snapshot.Delta.MemoryUsedMB)
		t.Logf("  CPU delta: %.2f%%", snapshot.Delta.CPUPercent)
	})
}

// TestContainerScaling tests scaling behavior under different loads
func TestContainerScaling(t *testing.T) {
	env := DefaultTestEnvironment()
	env.MaxConcurrentSandboxes = 50
	framework := SetupTestFramework(t, env)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	t.Run("ScaleUp", func(t *testing.T) {
		// Test scaling from 1 to 25 containers
		scaleLevels := []int{1, 5, 10, 15, 20, 25}
		var allContainers []*sandbox.Sandbox

		for _, targetScale := range scaleLevels {
			scaleStart := time.Now()
			
			// Create containers to reach target scale
			containersToCreate := targetScale - len(allContainers)
			if containersToCreate <= 0 {
				continue
			}

			var wg sync.WaitGroup
			results := make(chan *sandbox.Sandbox, containersToCreate)
			errors := make(chan error, containersToCreate)

			for i := 0; i < containersToCreate; i++ {
				wg.Add(1)
				go func(index int) {
					defer wg.Done()

					container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
						Environment: map[string]string{
							"SCALE_LEVEL": fmt.Sprintf("%d", targetScale),
							"INDEX":      fmt.Sprintf("%d", index),
						},
					})

					results <- container
				}(i)
			}

			go func() {
				wg.Wait()
				close(results)
				close(errors)
			}()

			// Collect results
			var newContainers []*sandbox.Sandbox
			for result := range results {
				newContainers = append(newContainers, result)
			}

			var scaleErrors []error
			for err := range errors {
				scaleErrors = append(scaleErrors, err)
			}

			allContainers = append(allContainers, newContainers...)
			scaleDuration := time.Since(scaleStart)

			// Verify scaling success
			assert.Empty(t, scaleErrors, fmt.Sprintf("Scale to %d should succeed", targetScale))
			assert.Len(t, allContainers, targetScale, fmt.Sprintf("Should have %d containers", targetScale))

			// Wait for all containers to be ready
			for _, container := range newContainers {
				framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
			}

			t.Logf("Scaled to %d containers in %v", targetScale, scaleDuration)
		}

		// Verify all containers are operational
		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
		successCount := 0

		for _, container := range allContainers {
			result, err := execTool.Execute(ctx, map[string]interface{}{
				"sandbox_id": container.ID,
				"command":    "echo",
				"args":       []string{"operational"},
			})

			if err == nil && result.(*tools.ExecutionResult).ExitCode == 0 {
				successCount++
			}
		}

		assert.Equal(t, len(allContainers), successCount, "All scaled containers should be operational")
	})

	t.Run("ScaleDown", func(t *testing.T) {
		// Create containers to scale down from
		const initialScale = 20
		var containers []*sandbox.Sandbox

		// Create initial containers
		for i := 0; i < initialScale; i++ {
			container := framework.CreateTestSandbox(ctx, t, nil)
			containers = append(containers, container)
			framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
		}

		// Scale down in steps
		scaleTargets := []int{15, 10, 5, 1}

		for _, target := range scaleTargets {
			scaleStart := time.Now()
			
			containersToRemove := len(containers) - target
			if containersToRemove <= 0 {
				continue
			}

			// Terminate containers
			var wg sync.WaitGroup
			for i := 0; i < containersToRemove; i++ {
				wg.Add(1)
				go func(container *sandbox.Sandbox) {
					defer wg.Done()
					err := framework.SandboxManager.TerminateSandbox(ctx, container.ID)
					require.NoError(t, err)
				}(containers[len(containers)-1-i])
			}

			wg.Wait()

			// Update containers list
			containers = containers[:target]
			scaleDuration := time.Since(scaleStart)

			// Wait for termination to complete
			time.Sleep(1 * time.Second)

			// Verify remaining containers are still operational
			execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}
			operationalCount := 0

			for _, container := range containers {
				result, err := execTool.Execute(ctx, map[string]interface{}{
					"sandbox_id": container.ID,
					"command":    "echo",
					"args":       []string{"still_operational"},
				})

				if err == nil && result.(*tools.ExecutionResult).ExitCode == 0 {
					operationalCount++
				}
			}

			assert.Equal(t, target, operationalCount, fmt.Sprintf("Should have %d operational containers after scale down", target))
			t.Logf("Scaled down to %d containers in %v", target, scaleDuration)
		}
	})
}