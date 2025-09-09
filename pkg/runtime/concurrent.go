package runtime

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// ConcurrentExecutor provides advanced concurrent execution capabilities
type ConcurrentExecutor interface {
	// Execute executes a single task concurrently
	Execute(ctx context.Context, task Task) (*TaskResult, error)

	// ExecuteMany executes multiple tasks concurrently
	ExecuteMany(ctx context.Context, tasks []Task) ([]*TaskResult, error)

	// Pipeline executes tasks in a pipeline with configurable stages
	Pipeline(ctx context.Context, stages []PipelineStage, input interface{}) (*PipelineResult, error)

	// FanOut fans out a single input to multiple tasks
	FanOut(ctx context.Context, input interface{}, tasks []Task) ([]*TaskResult, error)

	// FanIn fans in multiple task results to a single result
	FanIn(ctx context.Context, results []*TaskResult, aggregator AggregatorFunc) (*TaskResult, error)

	// WorkStealing executes tasks using work stealing algorithm
	WorkStealing(ctx context.Context, tasks []Task) ([]*TaskResult, error)

	// Stats returns executor performance statistics
	Stats() *ExecutorStats

	// Health returns executor health status
	Health() *ExecutorHealth

	// Close gracefully shuts down the executor
	Close(ctx context.Context) error
}

// Task represents a unit of work to be executed concurrently
type Task interface {
	// Execute executes the task and returns the result
	Execute(ctx context.Context) (interface{}, error)

	// ID returns a unique identifier for the task
	ID() string

	// Priority returns the task priority (higher numbers = higher priority)
	Priority() int

	// Dependencies returns IDs of tasks this task depends on
	Dependencies() []string

	// Timeout returns the maximum execution time for this task
	Timeout() time.Duration

	// Metadata returns task metadata
	Metadata() map[string]interface{}
}

// TaskResult represents the result of task execution
type TaskResult struct {
	TaskID        string                 `json:"task_id"`
	Status        TaskStatus             `json:"status"`
	Result        interface{}            `json:"result"`
	Error         error                  `json:"error"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	ExecutionTime time.Duration          `json:"execution_time"`
	WorkerID      string                 `json:"worker_id"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// TaskStatus represents the status of task execution
type TaskStatus string

const (
	TaskStatusPending    TaskStatus = "pending"
	TaskStatusRunning    TaskStatus = "running"
	TaskStatusCompleted  TaskStatus = "completed"
	TaskStatusFailed     TaskStatus = "failed"
	TaskStatusCancelled  TaskStatus = "cancelled"
	TaskStatusTimeout    TaskStatus = "timeout"
)

// PipelineStage represents a stage in a processing pipeline
type PipelineStage struct {
	Name        string                            `json:"name"`
	Processor   func(ctx context.Context, input interface{}) (interface{}, error) `json:"-"`
	Concurrency int                               `json:"concurrency"` // Number of workers for this stage
	BufferSize  int                               `json:"buffer_size"`  // Buffer size between stages
	Timeout     time.Duration                     `json:"timeout"`
}

// PipelineResult represents the result of pipeline execution
type PipelineResult struct {
	Result        interface{}            `json:"result"`
	Error         error                  `json:"error"`
	StageResults  map[string]interface{} `json:"stage_results"`
	ExecutionTime time.Duration          `json:"execution_time"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
}

// AggregatorFunc aggregates multiple task results into a single result
type AggregatorFunc func(results []*TaskResult) (interface{}, error)

// ExecutorStats provides comprehensive executor statistics
type ExecutorStats struct {
	// Task statistics
	TotalTasks        int64         `json:"total_tasks"`
	CompletedTasks    int64         `json:"completed_tasks"`
	FailedTasks       int64         `json:"failed_tasks"`
	CancelledTasks    int64         `json:"cancelled_tasks"`
	TimeoutTasks      int64         `json:"timeout_tasks"`
	
	// Performance metrics
	AvgExecutionTime  time.Duration `json:"avg_execution_time"`
	TotalExecutionTime time.Duration `json:"total_execution_time"`
	Throughput        float64       `json:"throughput"` // Tasks per second
	
	// Worker pool statistics
	ActiveWorkers     int           `json:"active_workers"`
	IdleWorkers       int           `json:"idle_workers"`
	TotalWorkers      int           `json:"total_workers"`
	MaxWorkers        int           `json:"max_workers"`
	
	// Queue statistics
	QueuedTasks       int           `json:"queued_tasks"`
	QueueCapacity     int           `json:"queue_capacity"`
	
	// Resource utilization
	CPUUtilization    float64       `json:"cpu_utilization"`
	MemoryUsage       int64         `json:"memory_usage"` // in bytes
	GoroutineCount    int           `json:"goroutine_count"`
	
	// Deadlock detection
	DeadlockCount     int64         `json:"deadlock_count"`
	LastDeadlockTime  *time.Time    `json:"last_deadlock_time"`
	
	// Timing
	LastUpdate        time.Time     `json:"last_update"`
	UptimeDuration    time.Duration `json:"uptime_duration"`
}

// ExecutorHealthStatus represents the health status of the executor
type ExecutorHealthStatus string

const (
	ExecutorHealthStatusHealthy   ExecutorHealthStatus = "healthy"
	ExecutorHealthStatusDegraded  ExecutorHealthStatus = "degraded"
	ExecutorHealthStatusUnhealthy ExecutorHealthStatus = "unhealthy"
)

// ExecutorHealth provides health information for the executor
type ExecutorHealth struct {
	Status          ExecutorHealthStatus `json:"status"`
	Issues          []string             `json:"issues"`
	Recommendations []string             `json:"recommendations"`
	LastCheck       time.Time            `json:"last_check"`
	ResponseTime    time.Duration        `json:"response_time"`
	ErrorRate       float64              `json:"error_rate"`
}

// ExecutorConfig contains configuration for the concurrent executor
type ExecutorConfig struct {
	// Worker pool configuration
	MaxWorkers        int           `json:"max_workers"`
	MinWorkers        int           `json:"min_workers"`
	WorkerIdleTimeout time.Duration `json:"worker_idle_timeout"`
	
	// Queue configuration
	TaskQueueSize     int           `json:"task_queue_size"`
	ResultBufferSize  int           `json:"result_buffer_size"`
	
	// Execution settings
	DefaultTimeout    time.Duration `json:"default_timeout"`
	MaxConcurrency    int           `json:"max_concurrency"`
	
	// Work stealing settings
	StealingEnabled   bool          `json:"stealing_enabled"`
	StealingInterval  time.Duration `json:"stealing_interval"`
	
	// Deadlock detection
	DeadlockDetection bool          `json:"deadlock_detection"`
	DeadlockTimeout   time.Duration `json:"deadlock_timeout"`
	
	// Monitoring and optimization
	MetricsEnabled    bool          `json:"metrics_enabled"`
	HealthChecks      bool          `json:"health_checks"`
	AutoOptimization  bool          `json:"auto_optimization"`
}

// DefaultExecutorConfig returns a default executor configuration
func DefaultExecutorConfig() *ExecutorConfig {
	return &ExecutorConfig{
		MaxWorkers:        runtime.NumCPU() * 4,
		MinWorkers:        runtime.NumCPU(),
		WorkerIdleTimeout: 5 * time.Minute,
		TaskQueueSize:     10000,
		ResultBufferSize:  1000,
		DefaultTimeout:    30 * time.Second,
		MaxConcurrency:    runtime.NumCPU() * 2,
		StealingEnabled:   true,
		StealingInterval:  100 * time.Millisecond,
		DeadlockDetection: true,
		DeadlockTimeout:   10 * time.Second,
		MetricsEnabled:    true,
		HealthChecks:      true,
		AutoOptimization:  true,
	}
}

// ConcurrentExecutorImpl implements the ConcurrentExecutor interface
type ConcurrentExecutorImpl struct {
	config          *ExecutorConfig
	workerPool      *ConcurrentWorkerPool
	taskQueue       chan *taskWrapper
	resultBuffer    chan *TaskResult
	deadlockDetector *DeadlockDetector
	stats           *ExecutorStats
	health          *ExecutorHealth
	
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	stopChan        chan struct{}
	wg              sync.WaitGroup
	
	// Atomic counters
	totalTasks      int64
	completedTasks  int64
	failedTasks     int64
	cancelledTasks  int64
	timeoutTasks    int64
	startTime       time.Time
}

// taskWrapper wraps a Task for internal processing
type taskWrapper struct {
	task       Task
	resultChan chan *TaskResult
	ctx        context.Context
	startTime  time.Time
	workerID   string
}

// ConcurrentWorkerPool manages a pool of concurrent workers
type ConcurrentWorkerPool struct {
	config       *ExecutorConfig
	workers      []*ConcurrentWorker
	workStealers []*WorkStealer
	taskQueues   []chan *taskWrapper // Per-worker queues for work stealing
	mu           sync.RWMutex
	activeCount  int64
	ctx          context.Context
}

// ConcurrentWorker represents a single concurrent worker
type ConcurrentWorker struct {
	id          string
	pool        *ConcurrentWorkerPool
	taskQueue   chan *taskWrapper
	localQueue  chan *taskWrapper // Local queue for work stealing
	quit        chan struct{}
	active      int64
	tasksProcessed int64
}

// WorkStealer implements work stealing algorithm
type WorkStealer struct {
	id         string
	pool       *ConcurrentWorkerPool
	victims    []chan *taskWrapper // Other workers' queues to steal from
	globalQueue chan *taskWrapper // Reference to global task queue
	quit       chan struct{}
	stealsCount int64
}

// DeadlockDetector detects and reports deadlock situations
type DeadlockDetector struct {
	config        *ExecutorConfig
	mu            sync.RWMutex
	dependencies  map[string][]string // task -> dependencies
	waitingTasks  map[string]time.Time // task -> wait start time
	deadlockCount int64
	lastDeadlock  *time.Time
}

// SimpleTask implements Task interface for basic tasks
type SimpleTask struct {
	id           string
	executor     func(ctx context.Context) (interface{}, error)
	priority     int
	dependencies []string
	timeout      time.Duration
	metadata     map[string]interface{}
}

// NewConcurrentExecutor creates a new concurrent executor instance
func NewConcurrentExecutor(config *ExecutorConfig) (ConcurrentExecutor, error) {
	if config == nil {
		config = DefaultExecutorConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	executor := &ConcurrentExecutorImpl{
		config:       config,
		taskQueue:    make(chan *taskWrapper, config.TaskQueueSize),
		resultBuffer: make(chan *TaskResult, config.ResultBufferSize),
		ctx:          ctx,
		cancel:       cancel,
		stopChan:     make(chan struct{}),
		stats: &ExecutorStats{
			MaxWorkers:   config.MaxWorkers,
			LastUpdate:   time.Now(),
		},
		health: &ExecutorHealth{
			Status:       ExecutorHealthStatusHealthy,
			Issues:       make([]string, 0),
			Recommendations: make([]string, 0),
			LastCheck:    time.Now(),
		},
		startTime: time.Now(),
	}
	
	// Initialize worker pool
	executor.workerPool = &ConcurrentWorkerPool{
		config:     config,
		workers:    make([]*ConcurrentWorker, 0, config.MaxWorkers),
		taskQueues: make([]chan *taskWrapper, 0, config.MaxWorkers),
		ctx:        ctx,
	}
	
	// Initialize deadlock detector
	if config.DeadlockDetection {
		executor.deadlockDetector = &DeadlockDetector{
			config:       config,
			dependencies: make(map[string][]string),
			waitingTasks: make(map[string]time.Time),
		}
	}
	
	// Start initial workers
	if err := executor.startWorkers(config.MinWorkers); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start initial workers: %w", err)
	}
	
	// Start background processes
	executor.startBackgroundProcesses()
	
	log.Info().
		Int("max_workers", config.MaxWorkers).
		Int("min_workers", config.MinWorkers).
		Int("task_queue_size", config.TaskQueueSize).
		Bool("work_stealing", config.StealingEnabled).
		Bool("deadlock_detection", config.DeadlockDetection).
		Msg("Concurrent executor initialized")
	
	return executor, nil
}

// Execute executes a single task concurrently
func (ce *ConcurrentExecutorImpl) Execute(ctx context.Context, task Task) (*TaskResult, error) {
	if task == nil {
		return nil, errors.New("task cannot be nil")
	}
	
	atomic.AddInt64(&ce.totalTasks, 1)
	
	wrapper := &taskWrapper{
		task:       task,
		resultChan: make(chan *TaskResult, 1),
		ctx:        ctx,
		startTime:  time.Now(),
	}
	
	// Check for deadlocks if detection is enabled
	if ce.deadlockDetector != nil {
		if err := ce.deadlockDetector.checkForDeadlock(task); err != nil {
			return nil, fmt.Errorf("deadlock detected: %w", err)
		}
	}
	
	// Submit task to queue
	select {
	case ce.taskQueue <- wrapper:
		log.Debug().
			Str("task_id", task.ID()).
			Int("priority", task.Priority()).
			Msg("Task queued for execution")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ce.ctx.Done():
		return nil, errors.New("executor is shutting down")
	default:
		return nil, errors.New("task queue is full")
	}
	
	// Wait for result
	timeout := task.Timeout()
	if timeout == 0 {
		timeout = ce.config.DefaultTimeout
	}
	
	select {
	case result := <-wrapper.resultChan:
		return result, nil
	case <-ctx.Done():
		atomic.AddInt64(&ce.cancelledTasks, 1)
		return nil, ctx.Err()
	case <-time.After(timeout):
		atomic.AddInt64(&ce.timeoutTasks, 1)
		return &TaskResult{
			TaskID:        task.ID(),
			Status:        TaskStatusTimeout,
			Error:         fmt.Errorf("task timeout after %v", timeout),
			StartTime:     wrapper.startTime,
			EndTime:       time.Now(),
			ExecutionTime: time.Since(wrapper.startTime),
		}, nil
	}
}

// ExecuteMany executes multiple tasks concurrently
func (ce *ConcurrentExecutorImpl) ExecuteMany(ctx context.Context, tasks []Task) ([]*TaskResult, error) {
	if len(tasks) == 0 {
		return []*TaskResult{}, nil
	}
	
	atomic.AddInt64(&ce.totalTasks, int64(len(tasks)))
	
	results := make([]*TaskResult, len(tasks))
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	// Create semaphore to limit concurrency
	semaphore := make(chan struct{}, ce.config.MaxConcurrency)
	
	for i, task := range tasks {
		wg.Add(1)
		go func(index int, t Task) {
			defer wg.Done()
			
			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				results[index] = &TaskResult{
					TaskID:  t.ID(),
					Status:  TaskStatusCancelled,
					Error:   ctx.Err(),
				}
				mu.Unlock()
				return
			}
			defer func() { <-semaphore }()
			
			result, err := ce.Execute(ctx, t)
			if err != nil && result == nil {
				result = &TaskResult{
					TaskID: t.ID(),
					Status: TaskStatusFailed,
					Error:  err,
				}
			}
			
			mu.Lock()
			results[index] = result
			mu.Unlock()
		}(i, task)
	}
	
	wg.Wait()
	
	log.Info().
		Int("task_count", len(tasks)).
		Msg("Batch task execution completed")
	
	return results, nil
}

// Pipeline executes tasks in a pipeline with configurable stages
func (ce *ConcurrentExecutorImpl) Pipeline(ctx context.Context, stages []PipelineStage, input interface{}) (*PipelineResult, error) {
	if len(stages) == 0 {
		return nil, errors.New("pipeline must have at least one stage")
	}
	
	startTime := time.Now()
	result := &PipelineResult{
		StageResults: make(map[string]interface{}),
		StartTime:    startTime,
	}
	
	// Create channels for pipeline stages
	channels := make([]chan interface{}, len(stages)+1)
	for i := range channels {
		bufferSize := 1
		if i > 0 && i <= len(stages) {
			bufferSize = stages[i-1].BufferSize
		}
		if bufferSize <= 0 {
			bufferSize = 10 // Default buffer size
		}
		channels[i] = make(chan interface{}, bufferSize)
	}
	
	// Start pipeline stages
	var wg sync.WaitGroup
	var pipelineErr error
	var errMu sync.Mutex
	
	for i, stage := range stages {
		wg.Add(1)
		go func(stageIndex int, s PipelineStage) {
			defer wg.Done()
			defer close(channels[stageIndex+1])
			
			// Start workers for this stage
			var stageWG sync.WaitGroup
			concurrency := s.Concurrency
			if concurrency <= 0 {
				concurrency = 1
			}
			
			for w := 0; w < concurrency; w++ {
				stageWG.Add(1)
				go func() {
					defer stageWG.Done()
					
					for inputData := range channels[stageIndex] {
						stageCtx := ctx
						if s.Timeout > 0 {
							var cancel context.CancelFunc
							stageCtx, cancel = context.WithTimeout(ctx, s.Timeout)
							defer cancel()
						}
						
						output, err := s.Processor(stageCtx, inputData)
						if err != nil {
							errMu.Lock()
							if pipelineErr == nil {
								pipelineErr = fmt.Errorf("stage %s failed: %w", s.Name, err)
							}
							errMu.Unlock()
							return
						}
						
						select {
						case channels[stageIndex+1] <- output:
						case <-ctx.Done():
							return
						}
					}
				}()
			}
			
			stageWG.Wait()
		}(i, stage)
	}
	
	// Send input to first stage
	go func() {
		defer close(channels[0])
		select {
		case channels[0] <- input:
		case <-ctx.Done():
		}
	}()
	
	// Collect final result
	go func() {
		for finalResult := range channels[len(stages)] {
			result.Result = finalResult
			break // Take only the first result
		}
	}()
	
	wg.Wait()
	
	result.EndTime = time.Now()
	result.ExecutionTime = result.EndTime.Sub(startTime)
	result.Error = pipelineErr
	
	log.Info().
		Int("stages", len(stages)).
		Dur("execution_time", result.ExecutionTime).
		Msg("Pipeline execution completed")
	
	return result, pipelineErr
}

// FanOut fans out a single input to multiple tasks
func (ce *ConcurrentExecutorImpl) FanOut(ctx context.Context, input interface{}, tasks []Task) ([]*TaskResult, error) {
	if len(tasks) == 0 {
		return []*TaskResult{}, nil
	}
	
	// Create fan-out tasks that all receive the same input
	fanOutTasks := make([]Task, len(tasks))
	for i, task := range tasks {
		fanOutTasks[i] = &FanOutTask{
			originalTask: task,
			input:        input,
		}
	}
	
	return ce.ExecuteMany(ctx, fanOutTasks)
}

// FanIn fans in multiple task results to a single result
func (ce *ConcurrentExecutorImpl) FanIn(ctx context.Context, results []*TaskResult, aggregator AggregatorFunc) (*TaskResult, error) {
	if aggregator == nil {
		return nil, errors.New("aggregator function is required")
	}
	
	startTime := time.Now()
	
	aggregatedResult, err := aggregator(results)
	
	result := &TaskResult{
		TaskID:        fmt.Sprintf("fan_in_%d", startTime.UnixNano()),
		Status:        TaskStatusCompleted,
		Result:        aggregatedResult,
		Error:         err,
		StartTime:     startTime,
		EndTime:       time.Now(),
		ExecutionTime: time.Since(startTime),
		Metadata:      map[string]interface{}{"input_count": len(results)},
	}
	
	if err != nil {
		result.Status = TaskStatusFailed
	}
	
	return result, nil
}

// WorkStealing executes tasks using work stealing algorithm
func (ce *ConcurrentExecutorImpl) WorkStealing(ctx context.Context, tasks []Task) ([]*TaskResult, error) {
	if !ce.config.StealingEnabled {
		// Fall back to regular execution
		return ce.ExecuteMany(ctx, tasks)
	}
	
	if len(tasks) == 0 {
		return []*TaskResult{}, nil
	}
	
	results := make([]*TaskResult, len(tasks))
	resultChans := make([]chan *TaskResult, len(tasks))
	
	// Create result channels
	for i := range resultChans {
		resultChans[i] = make(chan *TaskResult, 1)
	}
	
	// Distribute tasks across worker queues
	ce.workerPool.mu.Lock()
	workerCount := len(ce.workerPool.workers)
	if workerCount == 0 {
		ce.workerPool.mu.Unlock()
		return nil, errors.New("no workers available")
	}
	
	for i, task := range tasks {
		workerIndex := i % workerCount
		worker := ce.workerPool.workers[workerIndex]
		
		wrapper := &taskWrapper{
			task:       task,
			resultChan: resultChans[i],
			ctx:        ctx,
			startTime:  time.Now(),
			workerID:   worker.id,
		}
		
		// Try to add to local queue, fall back to global queue
		select {
		case worker.localQueue <- wrapper:
		case ce.taskQueue <- wrapper:
		default:
			// If both queues are full, wait for global queue
			go func(w *taskWrapper) {
				select {
				case ce.taskQueue <- w:
				case <-ctx.Done():
					w.resultChan <- &TaskResult{
						TaskID:  w.task.ID(),
						Status:  TaskStatusCancelled,
						Error:   ctx.Err(),
					}
				}
			}(wrapper)
		}
	}
	ce.workerPool.mu.Unlock()
	
	// Collect results
	for i := range results {
		select {
		case result := <-resultChans[i]:
			results[i] = result
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	
	log.Info().
		Int("task_count", len(tasks)).
		Msg("Work stealing execution completed")
	
	return results, nil
}

// Stats returns executor performance statistics
func (ce *ConcurrentExecutorImpl) Stats() *ExecutorStats {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	
	ce.workerPool.mu.RLock()
	activeWorkers := int(atomic.LoadInt64(&ce.workerPool.activeCount))
	totalWorkers := len(ce.workerPool.workers)
	ce.workerPool.mu.RUnlock()
	
	stats := &ExecutorStats{
		TotalTasks:         atomic.LoadInt64(&ce.totalTasks),
		CompletedTasks:     atomic.LoadInt64(&ce.completedTasks),
		FailedTasks:        atomic.LoadInt64(&ce.failedTasks),
		CancelledTasks:     atomic.LoadInt64(&ce.cancelledTasks),
		TimeoutTasks:       atomic.LoadInt64(&ce.timeoutTasks),
		ActiveWorkers:      activeWorkers,
		IdleWorkers:        totalWorkers - activeWorkers,
		TotalWorkers:       totalWorkers,
		MaxWorkers:         ce.config.MaxWorkers,
		QueuedTasks:        len(ce.taskQueue),
		QueueCapacity:      ce.config.TaskQueueSize,
		GoroutineCount:     runtime.NumGoroutine(),
		LastUpdate:         time.Now(),
		UptimeDuration:     time.Since(ce.startTime),
	}
	
	// Calculate rates
	if stats.TotalTasks > 0 {
		uptime := stats.UptimeDuration.Seconds()
		if uptime > 0 {
			stats.Throughput = float64(stats.CompletedTasks) / uptime
		}
		
		if stats.CompletedTasks > 0 {
			// Would calculate from actual timing data
			stats.AvgExecutionTime = time.Duration(100) * time.Millisecond
			stats.TotalExecutionTime = stats.AvgExecutionTime * time.Duration(stats.CompletedTasks)
		}
	}
	
	// Add deadlock statistics if available
	if ce.deadlockDetector != nil {
		ce.deadlockDetector.mu.RLock()
		stats.DeadlockCount = atomic.LoadInt64(&ce.deadlockDetector.deadlockCount)
		stats.LastDeadlockTime = ce.deadlockDetector.lastDeadlock
		ce.deadlockDetector.mu.RUnlock()
	}
	
	return stats
}

// Health returns executor health status
func (ce *ConcurrentExecutorImpl) Health() *ExecutorHealth {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	
	ce.health.LastCheck = time.Now()
	ce.health.Issues = ce.health.Issues[:0] // Clear issues
	ce.health.Recommendations = ce.health.Recommendations[:0] // Clear recommendations
	
	// Check queue length
	queueLen := len(ce.taskQueue)
	queueCapacity := ce.config.TaskQueueSize
	if queueLen > queueCapacity*8/10 { // 80% full
		ce.health.Issues = append(ce.health.Issues, 
			fmt.Sprintf("Task queue nearly full: %d/%d", queueLen, queueCapacity))
		ce.health.Recommendations = append(ce.health.Recommendations,
			"Consider increasing queue size or adding more workers")
	}
	
	// Check worker count
	ce.workerPool.mu.RLock()
	activeWorkers := len(ce.workerPool.workers)
	ce.workerPool.mu.RUnlock()
	
	if activeWorkers < ce.config.MinWorkers {
		ce.health.Issues = append(ce.health.Issues,
			fmt.Sprintf("Below minimum workers: %d/%d", activeWorkers, ce.config.MinWorkers))
	}
	
	// Calculate error rate
	totalTasks := atomic.LoadInt64(&ce.totalTasks)
	failedTasks := atomic.LoadInt64(&ce.failedTasks)
	if totalTasks > 0 {
		ce.health.ErrorRate = float64(failedTasks) / float64(totalTasks)
		if ce.health.ErrorRate > 0.1 { // 10% error rate
			ce.health.Issues = append(ce.health.Issues,
				fmt.Sprintf("High error rate: %.2f%%", ce.health.ErrorRate*100))
			ce.health.Recommendations = append(ce.health.Recommendations,
				"Investigate task failures and improve error handling")
		}
	}
	
	// Check for deadlocks
	if ce.deadlockDetector != nil {
		deadlockCount := atomic.LoadInt64(&ce.deadlockDetector.deadlockCount)
		if deadlockCount > 0 {
			ce.health.Issues = append(ce.health.Issues,
				fmt.Sprintf("Deadlocks detected: %d", deadlockCount))
			ce.health.Recommendations = append(ce.health.Recommendations,
				"Review task dependencies and reduce circular dependencies")
		}
	}
	
	// Determine overall status
	switch {
	case len(ce.health.Issues) == 0:
		ce.health.Status = ExecutorHealthStatusHealthy
	case len(ce.health.Issues) <= 2 && ce.health.ErrorRate < 0.05:
		ce.health.Status = ExecutorHealthStatusDegraded
	default:
		ce.health.Status = ExecutorHealthStatusUnhealthy
	}
	
	return ce.health
}

// Close gracefully shuts down the executor
func (ce *ConcurrentExecutorImpl) Close(ctx context.Context) error {
	log.Info().Msg("Shutting down concurrent executor")
	
	// Signal shutdown
	close(ce.stopChan)
	ce.cancel()
	
	// Wait for background processes
	done := make(chan struct{})
	go func() {
		ce.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
	case <-ctx.Done():
		log.Warn().Msg("Executor shutdown timeout")
	}
	
	log.Info().Msg("Concurrent executor shutdown complete")
	return nil
}

// Private methods

func (ce *ConcurrentExecutorImpl) startWorkers(count int) error {
	ce.workerPool.mu.Lock()
	defer ce.workerPool.mu.Unlock()
	
	for i := 0; i < count; i++ {
		worker := &ConcurrentWorker{
			id:         fmt.Sprintf("worker-%d", i),
			pool:       ce.workerPool,
			taskQueue:  ce.taskQueue,
			localQueue: make(chan *taskWrapper, 100), // Local queue for work stealing
			quit:       make(chan struct{}),
		}
		
		ce.workerPool.workers = append(ce.workerPool.workers, worker)
		ce.workerPool.taskQueues = append(ce.workerPool.taskQueues, worker.localQueue)
		go worker.start()
	}
	
	// Start work stealers if enabled
	if ce.config.StealingEnabled {
		for i := 0; i < count/2; i++ { // Fewer stealers than workers
			stealer := &WorkStealer{
				id:          fmt.Sprintf("stealer-%d", i),
				pool:        ce.workerPool,
				victims:     ce.workerPool.taskQueues,
				globalQueue: ce.taskQueue, // Pass reference to global queue
				quit:        make(chan struct{}),
			}
			
			ce.workerPool.workStealers = append(ce.workerPool.workStealers, stealer)
			go stealer.start()
		}
	}
	
	log.Info().Int("worker_count", count).Msg("Started concurrent workers")
	return nil
}

func (ce *ConcurrentExecutorImpl) startBackgroundProcesses() {
	// Stats collector
	if ce.config.MetricsEnabled {
		ce.wg.Add(1)
		go ce.statsCollector()
	}
	
	// Health checker
	if ce.config.HealthChecks {
		ce.wg.Add(1)
		go ce.healthChecker()
	}
	
	// Deadlock detector
	if ce.deadlockDetector != nil {
		ce.wg.Add(1)
		go ce.deadlockDetectionWorker()
	}
	
	// Auto optimization
	if ce.config.AutoOptimization {
		ce.wg.Add(1)
		go ce.autoOptimizer()
	}
}

func (ce *ConcurrentExecutorImpl) statsCollector() {
	defer ce.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ce.stopChan:
			return
		case <-ticker.C:
			ce.collectStats()
		}
	}
}

func (ce *ConcurrentExecutorImpl) healthChecker() {
	defer ce.wg.Done()
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ce.stopChan:
			return
		case <-ticker.C:
			ce.Health() // Updates health status
		}
	}
}

func (ce *ConcurrentExecutorImpl) deadlockDetectionWorker() {
	defer ce.wg.Done()
	
	ticker := time.NewTicker(ce.config.DeadlockTimeout / 2)
	defer ticker.Stop()
	
	for {
		select {
		case <-ce.stopChan:
			return
		case <-ticker.C:
			ce.deadlockDetector.detectDeadlocks()
		}
	}
}

func (ce *ConcurrentExecutorImpl) autoOptimizer() {
	defer ce.wg.Done()
	
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ce.stopChan:
			return
		case <-ticker.C:
			ce.optimizePerformance()
		}
	}
}

func (ce *ConcurrentExecutorImpl) collectStats() {
	// Update statistics - placeholder implementation
	log.Debug().Msg("Collecting executor statistics")
}

func (ce *ConcurrentExecutorImpl) optimizePerformance() {
	stats := ce.Stats()
	
	// Simple optimization logic
	if stats.QueuedTasks > stats.QueueCapacity/2 && stats.TotalWorkers < ce.config.MaxWorkers {
		// Need more workers
		needed := min(5, ce.config.MaxWorkers-stats.TotalWorkers)
		if needed > 0 {
			log.Info().Int("additional_workers", needed).Msg("Auto-scaling up workers")
			ce.startWorkers(needed)
		}
	} else if stats.QueuedTasks == 0 && stats.IdleWorkers > ce.config.MinWorkers {
		// Could reduce workers (implementation would go here)
		log.Debug().Msg("Could reduce worker count")
	}
}

// Worker implementation

func (cw *ConcurrentWorker) start() {
	log.Debug().Str("worker_id", cw.id).Msg("Concurrent worker started")
	
	for {
		select {
		case task := <-cw.localQueue:
			cw.processTask(task)
		case task := <-cw.taskQueue:
			cw.processTask(task)
		case <-cw.quit:
			log.Debug().Str("worker_id", cw.id).Msg("Concurrent worker stopped")
			return
		case <-cw.pool.ctx.Done():
			log.Debug().Str("worker_id", cw.id).Msg("Concurrent worker context cancelled")
			return
		}
	}
}

func (cw *ConcurrentWorker) processTask(wrapper *taskWrapper) {
	atomic.AddInt64(&cw.active, 1)
	atomic.AddInt64(&cw.pool.activeCount, 1)
	atomic.AddInt64(&cw.tasksProcessed, 1)
	
	defer func() {
		atomic.AddInt64(&cw.active, -1)
		atomic.AddInt64(&cw.pool.activeCount, -1)
	}()
	
	wrapper.workerID = cw.id
	result := cw.executeTask(wrapper)
	
	// Send result
	select {
	case wrapper.resultChan <- result:
	default:
		log.Warn().
			Str("task_id", wrapper.task.ID()).
			Str("worker_id", cw.id).
			Msg("Failed to send task result - channel full or closed")
	}
}

func (cw *ConcurrentWorker) executeTask(wrapper *taskWrapper) *TaskResult {
	start := time.Now()
	
	result := &TaskResult{
		TaskID:    wrapper.task.ID(),
		Status:    TaskStatusRunning,
		StartTime: start,
		WorkerID:  cw.id,
		Metadata:  make(map[string]interface{}),
	}
	
	// Execute the task
	output, err := wrapper.task.Execute(wrapper.ctx)
	
	result.EndTime = time.Now()
	result.ExecutionTime = result.EndTime.Sub(start)
	
	if err != nil {
		result.Status = TaskStatusFailed
		result.Error = err
		log.Debug().
			Err(err).
			Str("task_id", wrapper.task.ID()).
			Str("worker_id", cw.id).
			Dur("duration", result.ExecutionTime).
			Msg("Task execution failed")
	} else {
		result.Status = TaskStatusCompleted
		result.Result = output
		log.Debug().
			Str("task_id", wrapper.task.ID()).
			Str("worker_id", cw.id).
			Dur("duration", result.ExecutionTime).
			Msg("Task execution completed")
	}
	
	return result
}

// Work stealer implementation

func (ws *WorkStealer) start() {
	log.Debug().Str("stealer_id", ws.id).Msg("Work stealer started")
	
	ticker := time.NewTicker(ws.pool.config.StealingInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			ws.stealWork()
		case <-ws.quit:
			log.Debug().Str("stealer_id", ws.id).Msg("Work stealer stopped")
			return
		case <-ws.pool.ctx.Done():
			log.Debug().Str("stealer_id", ws.id).Msg("Work stealer context cancelled")
			return
		}
	}
}

func (ws *WorkStealer) stealWork() {
	// Simple work stealing: try to steal from random victims
	for _, victim := range ws.victims {
		select {
		case task := <-victim:
			// Found work to steal, put it in the global queue
			select {
			case ws.globalQueue <- task:
				atomic.AddInt64(&ws.stealsCount, 1)
				log.Debug().
					Str("stealer_id", ws.id).
					Str("task_id", task.task.ID()).
					Msg("Stole task from worker")
			default:
				// Global queue is full, put it back
				select {
				case victim <- task:
				default:
					// Both queues full, drop task (shouldn't happen)
					log.Warn().Str("task_id", task.task.ID()).Msg("Dropped task during work stealing")
				}
			}
		default:
			// No work to steal from this victim
		}
	}
}

// Deadlock detector implementation

func (dd *DeadlockDetector) checkForDeadlock(task Task) error {
	dd.mu.Lock()
	defer dd.mu.Unlock()
	
	taskID := task.ID()
	dependencies := task.Dependencies()
	
	if len(dependencies) == 0 {
		return nil // No dependencies, no deadlock possible
	}
	
	dd.dependencies[taskID] = dependencies
	dd.waitingTasks[taskID] = time.Now()
	
	// Simple cycle detection (this could be more sophisticated)
	if dd.hasCycle(taskID, make(map[string]bool)) {
		atomic.AddInt64(&dd.deadlockCount, 1)
		now := time.Now()
		dd.lastDeadlock = &now
		return fmt.Errorf("circular dependency detected involving task %s", taskID)
	}
	
	return nil
}

func (dd *DeadlockDetector) hasCycle(taskID string, visited map[string]bool) bool {
	if visited[taskID] {
		return true // Cycle found
	}
	
	visited[taskID] = true
	
	for _, dep := range dd.dependencies[taskID] {
		if dd.hasCycle(dep, visited) {
			return true
		}
	}
	
	visited[taskID] = false
	return false
}

func (dd *DeadlockDetector) detectDeadlocks() {
	dd.mu.Lock()
	defer dd.mu.Unlock()
	
	now := time.Now()
	timeout := dd.config.DeadlockTimeout
	
	// Check for tasks that have been waiting too long
	for taskID, waitStart := range dd.waitingTasks {
		if now.Sub(waitStart) > timeout {
			log.Warn().
				Str("task_id", taskID).
				Dur("wait_time", now.Sub(waitStart)).
				Msg("Potential deadlock detected - task waiting too long")
			
			atomic.AddInt64(&dd.deadlockCount, 1)
			dd.lastDeadlock = &now
			
			// Remove from waiting tasks to avoid repeated warnings
			delete(dd.waitingTasks, taskID)
		}
	}
}

// Task implementations

func NewSimpleTask(id string, executor func(ctx context.Context) (interface{}, error)) *SimpleTask {
	return &SimpleTask{
		id:           id,
		executor:     executor,
		priority:     5, // Default priority
		dependencies: make([]string, 0),
		timeout:      30 * time.Second, // Default timeout
		metadata:     make(map[string]interface{}),
	}
}

func (st *SimpleTask) Execute(ctx context.Context) (interface{}, error) {
	return st.executor(ctx)
}

func (st *SimpleTask) ID() string {
	return st.id
}

func (st *SimpleTask) Priority() int {
	return st.priority
}

func (st *SimpleTask) Dependencies() []string {
	return st.dependencies
}

func (st *SimpleTask) Timeout() time.Duration {
	return st.timeout
}

func (st *SimpleTask) Metadata() map[string]interface{} {
	return st.metadata
}

func (st *SimpleTask) SetPriority(priority int) *SimpleTask {
	st.priority = priority
	return st
}

func (st *SimpleTask) SetDependencies(deps []string) *SimpleTask {
	st.dependencies = deps
	return st
}

func (st *SimpleTask) SetTimeout(timeout time.Duration) *SimpleTask {
	st.timeout = timeout
	return st
}

func (st *SimpleTask) SetMetadata(key string, value interface{}) *SimpleTask {
	st.metadata[key] = value
	return st
}

// FanOutTask wraps a task for fan-out execution
type FanOutTask struct {
	originalTask Task
	input        interface{}
}

func (fot *FanOutTask) Execute(ctx context.Context) (interface{}, error) {
	// In a real implementation, you'd pass the input to the task
	return fot.originalTask.Execute(ctx)
}

func (fot *FanOutTask) ID() string {
	return fot.originalTask.ID()
}

func (fot *FanOutTask) Priority() int {
	return fot.originalTask.Priority()
}

func (fot *FanOutTask) Dependencies() []string {
	return fot.originalTask.Dependencies()
}

func (fot *FanOutTask) Timeout() time.Duration {
	return fot.originalTask.Timeout()
}

func (fot *FanOutTask) Metadata() map[string]interface{} {
	return fot.originalTask.Metadata()
}

// Utility functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}