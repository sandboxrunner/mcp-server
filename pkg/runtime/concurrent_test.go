package runtime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultExecutorConfig(t *testing.T) {
	config := DefaultExecutorConfig()
	
	assert.NotNil(t, config)
	assert.Greater(t, config.MaxWorkers, 0)
	assert.Greater(t, config.MinWorkers, 0)
	assert.LessOrEqual(t, config.MinWorkers, config.MaxWorkers)
	assert.Greater(t, config.TaskQueueSize, 0)
	assert.Greater(t, config.DefaultTimeout, time.Duration(0))
	assert.True(t, config.StealingEnabled)
	assert.True(t, config.DeadlockDetection)
	assert.True(t, config.MetricsEnabled)
}

func TestNewConcurrentExecutor(t *testing.T) {
	tests := []struct {
		name      string
		config    *ExecutorConfig
		wantError bool
	}{
		{
			name:      "Valid default configuration",
			config:    DefaultExecutorConfig(),
			wantError: false,
		},
		{
			name:      "Nil configuration uses default",
			config:    nil,
			wantError: false,
		},
		{
			name: "Custom configuration",
			config: &ExecutorConfig{
				MaxWorkers:        8,
				MinWorkers:        2,
				WorkerIdleTimeout: 5 * time.Minute,
				TaskQueueSize:     500,
				ResultBufferSize:  100,
				DefaultTimeout:    15 * time.Second,
				MaxConcurrency:    4,
				StealingEnabled:   true,
				StealingInterval:  200 * time.Millisecond,
				DeadlockDetection: true,
				DeadlockTimeout:   5 * time.Second,
				MetricsEnabled:    true,
				HealthChecks:      true,
				AutoOptimization:  false,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor, err := NewConcurrentExecutor(tt.config)
			
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, executor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, executor)
				
				// Clean up
				if executor != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					executor.Close(ctx)
				}
			}
		})
	}
}

func TestSimpleTask(t *testing.T) {
	// Test creating a simple task
	executed := false
	task := NewSimpleTask("test_task", func(ctx context.Context) (interface{}, error) {
		executed = true
		return "test_result", nil
	})
	
	assert.Equal(t, "test_task", task.ID())
	assert.Equal(t, 5, task.Priority()) // Default priority
	assert.Empty(t, task.Dependencies())
	assert.Equal(t, 30*time.Second, task.Timeout())
	assert.NotNil(t, task.Metadata())
	
	// Test task execution
	ctx := context.Background()
	result, err := task.Execute(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "test_result", result)
	assert.True(t, executed)
	
	// Test task configuration
	task.SetPriority(10).
		SetDependencies([]string{"dep1", "dep2"}).
		SetTimeout(1 * time.Minute).
		SetMetadata("key", "value")
	
	assert.Equal(t, 10, task.Priority())
	assert.Equal(t, []string{"dep1", "dep2"}, task.Dependencies())
	assert.Equal(t, 1*time.Minute, task.Timeout())
	assert.Equal(t, "value", task.Metadata()["key"])
}

func TestConcurrentExecutor_Execute(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        4,
		MinWorkers:        2,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     100,
		ResultBufferSize:  50,
		DefaultTimeout:    10 * time.Second,
		MaxConcurrency:    3,
		StealingEnabled:   false, // Disable for simpler testing
		DeadlockDetection: false, // Disable for simpler testing
		MetricsEnabled:    true,
		HealthChecks:      false, // Disable for simpler testing
		AutoOptimization:  false, // Disable for simpler testing
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	// Test successful task execution
	task := NewSimpleTask("success_task", func(ctx context.Context) (interface{}, error) {
		time.Sleep(10 * time.Millisecond) // Simulate work
		return "success_result", nil
	})

	result, err := executor.Execute(ctx, task)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "success_task", result.TaskID)
	assert.Equal(t, TaskStatusCompleted, result.Status)
	assert.Equal(t, "success_result", result.Result)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.ExecutionTime, time.Duration(0))
	assert.NotZero(t, result.StartTime)
	assert.NotZero(t, result.EndTime)

	// Test task with error
	errorTask := NewSimpleTask("error_task", func(ctx context.Context) (interface{}, error) {
		return nil, fmt.Errorf("task error")
	})

	result, err = executor.Execute(ctx, errorTask)
	assert.NoError(t, err) // Execute itself should not error
	assert.NotNil(t, result)
	assert.Equal(t, "error_task", result.TaskID)
	assert.Equal(t, TaskStatusFailed, result.Status)
	assert.Nil(t, result.Result)
	assert.NotNil(t, result.Error)
	assert.Equal(t, "task error", result.Error.Error())
}

func TestConcurrentExecutor_ExecuteMany(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        6,
		MinWorkers:        3,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     200,
		ResultBufferSize:  100,
		DefaultTimeout:    10 * time.Second,
		MaxConcurrency:    5,
		StealingEnabled:   false,
		DeadlockDetection: false,
		MetricsEnabled:    true,
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	// Create multiple tasks
	taskCount := 10
	tasks := make([]Task, taskCount)
	for i := 0; i < taskCount; i++ {
		taskID := fmt.Sprintf("task_%d", i)
		expectedResult := fmt.Sprintf("result_%d", i)
		
		tasks[i] = NewSimpleTask(taskID, func(ctx context.Context) (interface{}, error) {
			time.Sleep(time.Duration(i%5+1) * time.Millisecond) // Varying work time
			return expectedResult, nil
		})
	}

	// Execute all tasks
	results, err := executor.ExecuteMany(ctx, tasks)
	assert.NoError(t, err)
	assert.Len(t, results, taskCount)

	// Verify all results
	for i, result := range results {
		assert.Equal(t, fmt.Sprintf("task_%d", i), result.TaskID)
		assert.Equal(t, TaskStatusCompleted, result.Status)
		assert.NotNil(t, result.Result)
		assert.Nil(t, result.Error)
		assert.Greater(t, result.ExecutionTime, time.Duration(0))
	}
}

func TestConcurrentExecutor_ConcurrentExecution(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        10,
		MinWorkers:        5,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     1000,
		ResultBufferSize:  500,
		DefaultTimeout:    30 * time.Second,
		MaxConcurrency:    8,
		StealingEnabled:   false,
		DeadlockDetection: false,
		MetricsEnabled:    true,
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	const numGoroutines = 20
	const tasksPerGoroutine = 5

	var wg sync.WaitGroup
	ctx := context.Background()
	errors := make(chan error, numGoroutines*tasksPerGoroutine)
	results := make(chan *TaskResult, numGoroutines*tasksPerGoroutine)

	// Execute tasks concurrently from multiple goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			for j := 0; j < tasksPerGoroutine; j++ {
				taskID := fmt.Sprintf("concurrent_task_%d_%d", id, j)
				task := NewSimpleTask(taskID, func(ctx context.Context) (interface{}, error) {
					time.Sleep(time.Duration(j%3+1) * time.Millisecond)
					return fmt.Sprintf("result_%d_%d", id, j), nil
				})
				
				result, err := executor.Execute(ctx, task)
				if err != nil {
					errors <- fmt.Errorf("execute failed for %s: %w", taskID, err)
					continue
				}
				
				results <- result
			}
		}(i)
	}

	wg.Wait()
	close(errors)
	close(results)

	// Check for errors
	var errorCount int
	for err := range errors {
		t.Errorf("Concurrent execution error: %v", err)
		errorCount++
		if errorCount > 10 { // Limit error output
			break
		}
	}

	// Verify results
	var resultCount int
	for result := range results {
		assert.Equal(t, TaskStatusCompleted, result.Status)
		assert.NotNil(t, result.Result)
		assert.Nil(t, result.Error)
		resultCount++
	}

	expectedResults := numGoroutines * tasksPerGoroutine
	assert.Equal(t, expectedResults, resultCount, "Should have received all results")
}

func TestConcurrentExecutor_Pipeline(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        4,
		MinWorkers:        2,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     100,
		ResultBufferSize:  50,
		DefaultTimeout:    10 * time.Second,
		MaxConcurrency:    3,
		StealingEnabled:   false,
		DeadlockDetection: false,
		MetricsEnabled:    false,
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	// Create pipeline stages
	stages := []PipelineStage{
		{
			Name:        "multiply",
			Concurrency: 1,
			BufferSize:  10,
			Timeout:     5 * time.Second,
			Processor: func(ctx context.Context, input interface{}) (interface{}, error) {
				if num, ok := input.(int); ok {
					return num * 2, nil
				}
				return nil, fmt.Errorf("invalid input type")
			},
		},
		{
			Name:        "add",
			Concurrency: 1,
			BufferSize:  10,
			Timeout:     5 * time.Second,
			Processor: func(ctx context.Context, input interface{}) (interface{}, error) {
				if num, ok := input.(int); ok {
					return num + 10, nil
				}
				return nil, fmt.Errorf("invalid input type")
			},
		},
		{
			Name:        "stringify",
			Concurrency: 1,
			BufferSize:  10,
			Timeout:     5 * time.Second,
			Processor: func(ctx context.Context, input interface{}) (interface{}, error) {
				if num, ok := input.(int); ok {
					return fmt.Sprintf("result_%d", num), nil
				}
				return nil, fmt.Errorf("invalid input type")
			},
		},
	}

	// Execute pipeline with input 5
	// Expected: 5 * 2 + 10 = 20, then "result_20"
	input := 5
	result, err := executor.Pipeline(ctx, stages, input)
	
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "result_20", result.Result)
	assert.Nil(t, result.Error)
	assert.Greater(t, result.ExecutionTime, time.Duration(0))
	assert.NotZero(t, result.StartTime)
	assert.NotZero(t, result.EndTime)
}

func TestConcurrentExecutor_FanOut(t *testing.T) {
	config := DefaultExecutorConfig()
	config.MaxWorkers = 6
	config.MinWorkers = 3
	config.StealingEnabled = false
	config.DeadlockDetection = false

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	// Create tasks for fan-out
	input := "shared_input"
	tasks := []Task{
		NewSimpleTask("fanout_task_1", func(ctx context.Context) (interface{}, error) {
			return fmt.Sprintf("processed_%s_by_1", input), nil
		}),
		NewSimpleTask("fanout_task_2", func(ctx context.Context) (interface{}, error) {
			return fmt.Sprintf("processed_%s_by_2", input), nil
		}),
		NewSimpleTask("fanout_task_3", func(ctx context.Context) (interface{}, error) {
			return fmt.Sprintf("processed_%s_by_3", input), nil
		}),
	}

	// Execute fan-out
	results, err := executor.FanOut(ctx, input, tasks)
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	// Verify results
	for i, result := range results {
		assert.Equal(t, fmt.Sprintf("fanout_task_%d", i+1), result.TaskID)
		assert.Equal(t, TaskStatusCompleted, result.Status)
		assert.Contains(t, result.Result, "processed_shared_input_by")
		assert.Nil(t, result.Error)
	}
}

func TestConcurrentExecutor_FanIn(t *testing.T) {
	config := DefaultExecutorConfig()
	config.MaxWorkers = 4
	config.MinWorkers = 2

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	// Create mock task results
	results := []*TaskResult{
		{
			TaskID: "result_1",
			Status: TaskStatusCompleted,
			Result: 10,
		},
		{
			TaskID: "result_2",
			Status: TaskStatusCompleted,
			Result: 20,
		},
		{
			TaskID: "result_3",
			Status: TaskStatusCompleted,
			Result: 30,
		},
	}

	// Create aggregator that sums all results
	aggregator := func(results []*TaskResult) (interface{}, error) {
		sum := 0
		for _, result := range results {
			if result.Status == TaskStatusCompleted {
				if num, ok := result.Result.(int); ok {
					sum += num
				}
			}
		}
		return sum, nil
	}

	// Execute fan-in
	fanInResult, err := executor.FanIn(ctx, results, aggregator)
	assert.NoError(t, err)
	assert.NotNil(t, fanInResult)
	assert.Equal(t, TaskStatusCompleted, fanInResult.Status)
	assert.Equal(t, 60, fanInResult.Result) // 10 + 20 + 30
	assert.Nil(t, fanInResult.Error)
	assert.Equal(t, 3, fanInResult.Metadata["input_count"])
}

func TestConcurrentExecutor_WorkStealing(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        6,
		MinWorkers:        3,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     200,
		ResultBufferSize:  100,
		DefaultTimeout:    10 * time.Second,
		MaxConcurrency:    5,
		StealingEnabled:   true,  // Enable work stealing
		StealingInterval:  50 * time.Millisecond,
		DeadlockDetection: false,
		MetricsEnabled:    false,
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	// Create many tasks to trigger work stealing
	taskCount := 50
	tasks := make([]Task, taskCount)
	for i := 0; i < taskCount; i++ {
		taskID := fmt.Sprintf("steal_task_%d", i)
		expectedResult := fmt.Sprintf("stolen_result_%d", i)
		
		tasks[i] = NewSimpleTask(taskID, func(ctx context.Context) (interface{}, error) {
			time.Sleep(time.Duration(i%10+1) * time.Millisecond) // Varying work time
			return expectedResult, nil
		})
	}

	// Execute with work stealing
	results, err := executor.WorkStealing(ctx, tasks)
	assert.NoError(t, err)
	assert.Len(t, results, taskCount)

	// Verify all results
	for i, result := range results {
		assert.Equal(t, fmt.Sprintf("steal_task_%d", i), result.TaskID)
		assert.Equal(t, TaskStatusCompleted, result.Status)
		assert.NotNil(t, result.Result)
		assert.Nil(t, result.Error)
	}
}

func TestConcurrentExecutor_Stats(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        4,
		MinWorkers:        2,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     100,
		ResultBufferSize:  50,
		DefaultTimeout:    10 * time.Second,
		MaxConcurrency:    3,
		StealingEnabled:   false,
		DeadlockDetection: false,
		MetricsEnabled:    true,
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	// Wait a moment for initialization
	time.Sleep(100 * time.Millisecond)

	ctx := context.Background()

	// Execute some tasks to generate stats
	for i := 0; i < 5; i++ {
		task := NewSimpleTask(fmt.Sprintf("stats_task_%d", i), func(ctx context.Context) (interface{}, error) {
			return fmt.Sprintf("result_%d", i), nil
		})
		
		_, err := executor.Execute(ctx, task)
		require.NoError(t, err)
	}

	// Get stats
	stats := executor.Stats()
	assert.NotNil(t, stats)
	assert.Greater(t, stats.TotalTasks, int64(0))
	assert.GreaterOrEqual(t, stats.TotalWorkers, config.MinWorkers)
	assert.LessOrEqual(t, stats.TotalWorkers, config.MaxWorkers)
	assert.Equal(t, config.MaxWorkers, stats.MaxWorkers)
	assert.GreaterOrEqual(t, stats.QueueCapacity, config.TaskQueueSize)
	assert.Greater(t, stats.GoroutineCount, 0)
	assert.NotZero(t, stats.LastUpdate)
	assert.Greater(t, stats.UptimeDuration, time.Duration(0))
}

func TestConcurrentExecutor_Health(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        4,
		MinWorkers:        2,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     100,
		ResultBufferSize:  50,
		DefaultTimeout:    10 * time.Second,
		MaxConcurrency:    3,
		StealingEnabled:   false,
		DeadlockDetection: false,
		MetricsEnabled:    false,
		HealthChecks:      true,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	// Wait a moment for initialization
	time.Sleep(100 * time.Millisecond)

	// Get health status
	health := executor.Health()
	assert.NotNil(t, health)
	assert.NotNil(t, health.Issues)
	assert.NotNil(t, health.Recommendations)
	assert.NotZero(t, health.LastCheck)
	
	// Health status should be valid
	validStatuses := []ExecutorHealthStatus{ExecutorHealthStatusHealthy, ExecutorHealthStatusDegraded, ExecutorHealthStatusUnhealthy}
	assert.Contains(t, validStatuses, health.Status)
	
	// Error rate should be reasonable for a new executor
	assert.GreaterOrEqual(t, health.ErrorRate, 0.0)
	assert.LessOrEqual(t, health.ErrorRate, 1.0)
}

func TestConcurrentExecutor_TaskTimeout(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        2,
		MinWorkers:        1,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     50,
		ResultBufferSize:  25,
		DefaultTimeout:    100 * time.Millisecond, // Short default timeout
		MaxConcurrency:    2,
		StealingEnabled:   false,
		DeadlockDetection: false,
		MetricsEnabled:    false,
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	// Create a task that takes longer than the timeout
	task := NewSimpleTask("timeout_task", func(ctx context.Context) (interface{}, error) {
		time.Sleep(200 * time.Millisecond) // Longer than default timeout
		return "should_timeout", nil
	}).SetTimeout(50 * time.Millisecond) // Even shorter task-specific timeout

	result, err := executor.Execute(ctx, task)
	assert.NoError(t, err) // Execute itself should not error
	assert.NotNil(t, result)
	assert.Equal(t, "timeout_task", result.TaskID)
	assert.Equal(t, TaskStatusTimeout, result.Status)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "timeout")
}

func TestConcurrentExecutor_ContextCancellation(t *testing.T) {
	config := DefaultExecutorConfig()
	config.MaxWorkers = 2
	config.MinWorkers = 1

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	// Create a context that will be cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	task := NewSimpleTask("cancel_task", func(ctx context.Context) (interface{}, error) {
		time.Sleep(100 * time.Millisecond) // Longer than context timeout
		return "should_be_cancelled", nil
	})

	_, err = executor.Execute(ctx, task)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestConcurrentExecutor_ValidationErrors(t *testing.T) {
	config := DefaultExecutorConfig()
	config.MaxWorkers = 2
	config.MinWorkers = 1

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	// Test nil task
	_, err = executor.Execute(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "task cannot be nil")

	// Test nil aggregator in FanIn
	results := []*TaskResult{{TaskID: "test", Status: TaskStatusCompleted, Result: 42}}
	_, err = executor.FanIn(ctx, results, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aggregator function is required")

	// Test empty pipeline
	_, err = executor.Pipeline(ctx, []PipelineStage{}, "input")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pipeline must have at least one stage")
}

func BenchmarkConcurrentExecutor_Execute(b *testing.B) {
	config := &ExecutorConfig{
		MaxWorkers:        20,
		MinWorkers:        10,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     10000,
		ResultBufferSize:  5000,
		DefaultTimeout:    30 * time.Second,
		MaxConcurrency:    15,
		StealingEnabled:   false, // Disable for consistent benchmarking
		DeadlockDetection: false,
		MetricsEnabled:    false, // Disable for performance
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(b, err)
	require.NotNil(b, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			task := NewSimpleTask(fmt.Sprintf("bench_task_%d", i), func(ctx context.Context) (interface{}, error) {
				// Minimal work to focus on concurrency overhead
				return i, nil
			})
			
			_, err := executor.Execute(ctx, task)
			if err != nil {
				b.Errorf("Execute failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkConcurrentExecutor_ExecuteMany(b *testing.B) {
	config := &ExecutorConfig{
		MaxWorkers:        25,
		MinWorkers:        15,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     20000,
		ResultBufferSize:  10000,
		DefaultTimeout:    30 * time.Second,
		MaxConcurrency:    20,
		StealingEnabled:   false,
		DeadlockDetection: false,
		MetricsEnabled:    false,
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(b, err)
	require.NotNil(b, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()
	batchSize := 100

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Create batch of tasks
			tasks := make([]Task, batchSize)
			for j := 0; j < batchSize; j++ {
				taskID := fmt.Sprintf("bench_batch_task_%d_%d", i, j)
				tasks[j] = NewSimpleTask(taskID, func(ctx context.Context) (interface{}, error) {
					return taskID, nil
				})
			}
			
			_, err := executor.ExecuteMany(ctx, tasks)
			if err != nil {
				b.Errorf("ExecuteMany failed: %v", err)
			}
			i++
		}
	})
}

func BenchmarkConcurrentExecutor_WorkStealing(b *testing.B) {
	config := &ExecutorConfig{
		MaxWorkers:        30,
		MinWorkers:        20,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     30000,
		ResultBufferSize:  15000,
		DefaultTimeout:    30 * time.Second,
		MaxConcurrency:    25,
		StealingEnabled:   true, // Enable work stealing for this benchmark
		StealingInterval:  10 * time.Millisecond,
		DeadlockDetection: false,
		MetricsEnabled:    false,
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(b, err)
	require.NotNil(b, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	ctx := context.Background()
	batchSize := 200

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Create batch of tasks
			tasks := make([]Task, batchSize)
			for j := 0; j < batchSize; j++ {
				taskID := fmt.Sprintf("bench_steal_task_%d_%d", i, j)
				tasks[j] = NewSimpleTask(taskID, func(ctx context.Context) (interface{}, error) {
					return taskID, nil
				})
			}
			
			_, err := executor.WorkStealing(ctx, tasks)
			if err != nil {
				b.Errorf("WorkStealing failed: %v", err)
			}
			i++
		}
	})
}

// Test concurrent access with high contention
func TestConcurrentExecutor_HighContention(t *testing.T) {
	config := &ExecutorConfig{
		MaxWorkers:        8,
		MinWorkers:        4,
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     2000,
		ResultBufferSize:  1000,
		DefaultTimeout:    10 * time.Second,
		MaxConcurrency:    6,
		StealingEnabled:   true,
		StealingInterval:  25 * time.Millisecond,
		DeadlockDetection: false, // Disable to focus on concurrency
		MetricsEnabled:    false, // Disable to reduce overhead
		HealthChecks:      false,
		AutoOptimization:  false,
	}

	executor, err := NewConcurrentExecutor(config)
	require.NoError(t, err)
	require.NotNil(t, executor)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		executor.Close(ctx)
	}()

	const numWorkers = 100
	const tasksPerWorker = 20

	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64
	ctx := context.Background()

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			for j := 0; j < tasksPerWorker; j++ {
				taskID := fmt.Sprintf("contention_task_%d_%d", workerID, j)
				task := NewSimpleTask(taskID, func(ctx context.Context) (interface{}, error) {
					// Simulate some work
					time.Sleep(time.Duration(j%5+1) * time.Microsecond)
					return fmt.Sprintf("result_%d_%d", workerID, j), nil
				})
				
				result, err := executor.Execute(ctx, task)
				if err != nil || result.Status != TaskStatusCompleted {
					atomic.AddInt64(&errorCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}
		}(i)
	}

	wg.Wait()

	totalExpected := numWorkers * tasksPerWorker
	totalActual := successCount + errorCount
	
	// Allow for some minor discrepancies but ensure most tasks completed
	assert.GreaterOrEqual(t, successCount, int64(float64(totalExpected)*0.95), 
		"At least 95%% of tasks should succeed")
	assert.Equal(t, int64(totalExpected), totalActual, 
		"Total processed should equal expected")
	
	t.Logf("High contention test: %d/%d tasks succeeded (%.2f%%)", 
		successCount, totalExpected, float64(successCount)/float64(totalExpected)*100)
}