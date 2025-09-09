package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// IntegrationTestSuite provides a comprehensive test suite for SandboxRunner integration testing
type IntegrationTestSuite struct {
	suite.Suite
	framework *TestFramework
	ctx       context.Context
	cancel    context.CancelFunc
}

// SetupSuite initializes the test suite
func (suite *IntegrationTestSuite) SetupSuite() {
	env := DefaultTestEnvironment()
	env.MaxConcurrentSandboxes = 50
	env.DefaultTimeout = 2 * time.Minute
	env.EnableMetrics = true
	env.EnableLogging = true
	env.LogLevel = "info"

	suite.framework = SetupTestFramework(suite.T(), env)
	suite.ctx, suite.cancel = context.WithTimeout(context.Background(), 30*time.Minute)

	suite.T().Log("Integration test suite initialized")
	suite.T().Logf("Test directory: %s", suite.framework.TestDir)
	suite.T().Logf("Workspace directory: %s", suite.framework.WorkspaceDir)
}

// TearDownSuite cleans up the test suite
func (suite *IntegrationTestSuite) TearDownSuite() {
	if suite.cancel != nil {
		suite.cancel()
	}

	if suite.framework != nil {
		suite.framework.Cleanup(suite.T())
	}

	suite.T().Log("Integration test suite cleanup completed")
}

// TestBasicSandboxOperations tests fundamental sandbox operations
func (suite *IntegrationTestSuite) TestBasicSandboxOperations() {
	suite.T().Run("CreateAndManageSandboxes", func(t *testing.T) {
		// Test basic sandbox lifecycle
		container := suite.framework.CreateTestSandbox(suite.ctx, t, nil)
		suite.framework.WaitForSandboxReady(suite.ctx, t, container.ID, 30*time.Second)
		
		// Verify sandbox exists and is running
		sb, err := suite.framework.SandboxManager.GetSandbox(container.ID)
		suite.Require().NoError(err)
		suite.Equal(container.ID, sb.ID)
		
		// List sandboxes
		sandboxes, err := suite.framework.SandboxManager.ListSandboxes()
		suite.Require().NoError(err)
		suite.GreaterOrEqual(len(sandboxes), 1)
		
		t.Log("Basic sandbox operations completed successfully")
	})
}

// TestMultiContainerScenarios tests multi-container orchestration
func (suite *IntegrationTestSuite) TestMultiContainerScenarios() {
	suite.T().Run("ConcurrentOperations", func(t *testing.T) {
		TestMultiContainerOrchestration(t)
	})
	
	suite.T().Run("PerformanceUnderLoad", func(t *testing.T) {
		TestContainerPerformance(t)
	})
	
	suite.T().Run("ScalingBehavior", func(t *testing.T) {
		TestContainerScaling(t)
	})
}

// TestEndToEndWorkflows tests complete user workflows
func (suite *IntegrationTestSuite) TestEndToEndWorkflows() {
	suite.T().Run("UserJourneys", func(t *testing.T) {
		TestEndToEndUserJourneys(t)
	})
}

// TestFailureRecovery tests system resilience and failure recovery
func (suite *IntegrationTestSuite) TestFailureRecovery() {
	suite.T().Run("FailureInjection", func(t *testing.T) {
		TestFailureInjectionAndRecovery(t)
	})
	
	suite.T().Run("ChaosEngineering", func(t *testing.T) {
		TestChaosEngineering(t)
	})
}

// TestSecurityCompliance tests security boundaries and compliance
func (suite *IntegrationTestSuite) TestSecurityCompliance() {
	suite.T().Run("SecurityBoundaries", func(t *testing.T) {
		TestSecurityBoundaries(t)
	})
	
	suite.T().Run("SecurityConfiguration", func(t *testing.T) {
		TestSecurityConfiguration(t)
	})
}

// TestPerformanceMetrics tests performance characteristics
func (suite *IntegrationTestSuite) TestPerformanceMetrics() {
	suite.T().Run("ResourceUtilization", func(t *testing.T) {
		// Take baseline measurement
		baseline := suite.framework.ResourceMonitor.TakeSnapshot()
		
		// Create multiple sandboxes
		const numContainers = 10
		for i := 0; i < numContainers; i++ {
			container := suite.framework.CreateTestSandbox(suite.ctx, t, nil)
			suite.framework.WaitForSandboxReady(suite.ctx, t, container.ID, 30*time.Second)
		}
		
		// Wait for resource usage to stabilize
		time.Sleep(5 * time.Second)
		
		// Take final measurement
		final := suite.framework.ResourceMonitor.TakeSnapshot()
		snapshot := suite.framework.ResourceMonitor.CompareSnapshots(baseline, final)
		
		// Log performance metrics
		t.Logf("Performance metrics after creating %d containers:", numContainers)
		t.Logf("  Memory delta: %.2f MB", snapshot.Delta.MemoryUsedMB)
		t.Logf("  CPU delta: %.2f%%", snapshot.Delta.CPUPercent)
		t.Logf("  Active containers: %d", suite.framework.GetActiveSandboxCount())
		
		// Basic performance assertions
		suite.Less(snapshot.Delta.MemoryUsedMB, 1000.0, "Memory usage should be reasonable")
		suite.Less(snapshot.Delta.CPUPercent, 50.0, "CPU usage should be manageable")
	})
	
	suite.T().Run("ResponseTimes", func(t *testing.T) {
		container := suite.framework.CreateTestSandbox(suite.ctx, t, nil)
		suite.framework.WaitForSandboxReady(suite.ctx, t, container.ID, 30*time.Second)
		
		// Measure response times for common operations
		operations := []struct {
			name string
			fn   func() error
		}{
			{
				"ListSandboxes",
				func() error {
					_, err := suite.framework.SandboxManager.ListSandboxes()
					return err
				},
			},
			{
				"GetSandbox",
				func() error {
					_, err := suite.framework.SandboxManager.GetSandbox(container.ID)
					return err
				},
			},
		}
		
		for _, op := range operations {
			start := time.Now()
			err := op.fn()
			duration := time.Since(start)
			
			suite.Require().NoError(err)
			suite.Less(duration, 1*time.Second, fmt.Sprintf("%s should respond quickly", op.name))
			
			t.Logf("%s response time: %v", op.name, duration)
		}
	})
}

// TestResourceLeakDetection tests for resource leaks
func (suite *IntegrationTestSuite) TestResourceLeakDetection() {
	suite.T().Run("MemoryLeaks", func(t *testing.T) {
		// Take baseline measurement
		baseline := suite.framework.ResourceMonitor.TakeSnapshot()
		
		// Create and destroy containers multiple times
		const cycles = 10
		for cycle := 0; cycle < cycles; cycle++ {
			container := suite.framework.CreateTestSandbox(suite.ctx, t, nil)
			suite.framework.WaitForSandboxReady(suite.ctx, t, container.ID, 30*time.Second)
			
			// Use the container briefly
			time.Sleep(100 * time.Millisecond)
			
			// Terminate container
			err := suite.framework.SandboxManager.TerminateSandbox(suite.ctx, container.ID)
			suite.Require().NoError(err)
			
			// Wait for cleanup
			time.Sleep(100 * time.Millisecond)
		}
		
		// Allow time for garbage collection
		time.Sleep(2 * time.Second)
		
		// Take final measurement
		final := suite.framework.ResourceMonitor.TakeSnapshot()
		snapshot := suite.framework.ResourceMonitor.CompareSnapshots(baseline, final)
		
		t.Logf("Resource leak detection after %d create/destroy cycles:", cycles)
		t.Logf("  Memory delta: %.2f MB", snapshot.Delta.MemoryUsedMB)
		t.Logf("  Active processes: %d", snapshot.After.ActiveProcesses)
		
		// Should not have significant memory growth after cleanup
		suite.Less(snapshot.Delta.MemoryUsedMB, 100.0, "Should not have significant memory leaks")
	})
}

// TestLongRunningStability tests system stability over extended periods
func (suite *IntegrationTestSuite) TestLongRunningStability() {
	suite.T().Run("SustainedOperation", func(t *testing.T) {
		// Skip long-running test in CI/short test runs
		if testing.Short() {
			t.Skip("Skipping long-running stability test in short mode")
		}
		
		const testDuration = 5 * time.Minute
		const operationInterval = 10 * time.Second
		
		startTime := time.Now()
		var operationCount int
		var errorCount int
		
		ctx, cancel := context.WithTimeout(suite.ctx, testDuration)
		defer cancel()
		
		t.Logf("Starting sustained operation test for %v", testDuration)
		
		for {
			select {
			case <-ctx.Done():
				goto stabilityComplete
			default:
				// Perform a container operation
				container := suite.framework.CreateTestSandbox(ctx, t, nil)
				if container != nil {
					operationCount++
					
					// Use container briefly then clean up
					time.Sleep(1 * time.Second)
					err := suite.framework.SandboxManager.TerminateSandbox(ctx, container.ID)
					if err != nil {
						errorCount++
						t.Logf("Error during cleanup: %v", err)
					}
				} else {
					errorCount++
				}
				
				// Wait before next operation
				time.Sleep(operationInterval)
			}
		}
		
	stabilityComplete:
		duration := time.Since(startTime)
		successRate := float64(operationCount-errorCount) / float64(operationCount) * 100
		
		t.Logf("Sustained operation test completed:")
		t.Logf("  Duration: %v", duration)
		t.Logf("  Operations: %d", operationCount)
		t.Logf("  Errors: %d", errorCount)
		t.Logf("  Success rate: %.2f%%", successRate)
		
		suite.Greater(successRate, 95.0, "Should maintain high success rate during sustained operation")
		suite.Greater(operationCount, 10, "Should perform meaningful number of operations")
	})
}

// TestIntegration runs the complete integration test suite
func TestIntegration(t *testing.T) {
	suite.Run(t, new(IntegrationTestSuite))
}

// Example test functions for direct execution
func TestQuickIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}
	
	framework := SetupTestFramework(t, DefaultTestEnvironment())
	defer framework.Cleanup(t)
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	
	// Quick smoke test
	container := framework.CreateTestSandbox(ctx, t, nil)
	framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
	
	// Verify basic functionality
	sb, err := framework.SandboxManager.GetSandbox(container.ID)
	if err != nil {
		t.Fatalf("Failed to get sandbox: %v", err)
	}
	
	if sb.Status != "running" {
		t.Fatalf("Expected sandbox to be running, got: %s", sb.Status)
	}
	
	t.Log("Quick integration test passed")
}

// Benchmark functions for performance testing
func BenchmarkSandboxCreation(b *testing.B) {
	framework := SetupTestFramework(&testing.T{}, DefaultTestEnvironment())
	defer framework.Cleanup(&testing.T{})
	
	ctx := context.Background()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		container := framework.CreateTestSandbox(ctx, &testing.T{}, nil)
		framework.WaitForSandboxReady(ctx, &testing.T{}, container.ID, 30*time.Second)
		
		// Clean up immediately for accurate benchmarking
		framework.SandboxManager.TerminateSandbox(ctx, container.ID)
	}
}

func BenchmarkConcurrentSandboxes(b *testing.B) {
	framework := SetupTestFramework(&testing.T{}, DefaultTestEnvironment())
	defer framework.Cleanup(&testing.T{})
	
	ctx := context.Background()
	
	b.ResetTimer()
	
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			container := framework.CreateTestSandbox(ctx, &testing.T{}, nil)
			framework.WaitForSandboxReady(ctx, &testing.T{}, container.ID, 30*time.Second)
			framework.SandboxManager.TerminateSandbox(ctx, container.ID)
		}
	})
}