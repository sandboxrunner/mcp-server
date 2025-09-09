package tools

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// BatchProcessor provides high-throughput batch processing capabilities
type BatchProcessor interface {
	// Submit submits a request for batch processing
	Submit(ctx context.Context, request *BatchRequest) (*BatchResult, error)

	// SubmitMany submits multiple requests for batch processing
	SubmitMany(ctx context.Context, requests []*BatchRequest) ([]*BatchResult, error)

	// GetProgress returns the progress of a batch operation
	GetProgress(batchID string) (*BatchProgress, error)

	// Cancel cancels a batch operation
	Cancel(batchID string) error

	// Stats returns batch processing statistics
	Stats() *BatchStats

	// Health returns health status of the batch processor
	Health() *BatchHealthReport

	// Optimize optimizes batch processing parameters
	Optimize() error

	// Close gracefully shuts down the batch processor
	Close(ctx context.Context) error
}

// BatchRequest represents a request for batch processing
type BatchRequest struct {
	ID          string                 `json:"id"`
	Type        BatchRequestType       `json:"type"`
	Priority    int                    `json:"priority"`
	Payload     interface{}            `json:"payload"`
	Metadata    map[string]interface{} `json:"metadata"`
	Timeout     time.Duration          `json:"timeout"`
	RetryPolicy *RetryPolicy           `json:"retry_policy"`
	Tags        []string               `json:"tags"`
	Dependencies []string              `json:"dependencies"` // IDs of requests this depends on
	CreatedAt   time.Time              `json:"created_at"`
}

// BatchRequestType defines the type of batch request
type BatchRequestType string

const (
	BatchTypeCommand      BatchRequestType = "command"
	BatchTypeFileOp       BatchRequestType = "file_op"
	BatchTypeCodeExec     BatchRequestType = "code_exec"
	BatchTypeDataProcess  BatchRequestType = "data_process"
	BatchTypeCustom       BatchRequestType = "custom"
)

// BatchResult represents the result of a batch operation
type BatchResult struct {
	RequestID    string                 `json:"request_id"`
	BatchID      string                 `json:"batch_id"`
	Status       BatchStatus            `json:"status"`
	Output       interface{}            `json:"output"`
	Error        string                 `json:"error,omitempty"`
	ExecutionTime time.Duration         `json:"execution_time"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      time.Time              `json:"end_time"`
	Metadata     map[string]interface{} `json:"metadata"`
	Retries      int                    `json:"retries"`
}

// BatchStatus represents the status of a batch operation
type BatchStatus string

const (
	BatchStatusPending    BatchStatus = "pending"
	BatchStatusQueued     BatchStatus = "queued"
	BatchStatusProcessing BatchStatus = "processing"
	BatchStatusCompleted  BatchStatus = "completed"
	BatchStatusFailed     BatchStatus = "failed"
	BatchStatusCancelled  BatchStatus = "cancelled"
	BatchStatusRetrying   BatchStatus = "retrying"
)

// BatchProgress provides progress information for a batch operation
type BatchProgress struct {
	BatchID         string              `json:"batch_id"`
	Status          BatchStatus         `json:"status"`
	TotalRequests   int                 `json:"total_requests"`
	CompletedCount  int                 `json:"completed_count"`
	FailedCount     int                 `json:"failed_count"`
	PendingCount    int                 `json:"pending_count"`
	ProgressPercent float64             `json:"progress_percent"`
	EstimatedETA    *time.Time          `json:"estimated_eta"`
	StartTime       time.Time           `json:"start_time"`
	LastUpdate      time.Time           `json:"last_update"`
	RequestProgress map[string]*RequestProgress `json:"request_progress"`
}

// RequestProgress provides progress information for an individual request
type RequestProgress struct {
	RequestID     string        `json:"request_id"`
	Status        BatchStatus   `json:"status"`
	ProgressPercent float64     `json:"progress_percent"`
	CurrentStage  string        `json:"current_stage"`
	ElapsedTime   time.Duration `json:"elapsed_time"`
	Error         string        `json:"error,omitempty"`
}

// BatchStats provides comprehensive batch processing statistics
type BatchStats struct {
	// Overall statistics
	TotalBatches      int64         `json:"total_batches"`
	TotalRequests     int64         `json:"total_requests"`
	CompletedBatches  int64         `json:"completed_batches"`
	FailedBatches     int64         `json:"failed_batches"`
	CancelledBatches  int64         `json:"cancelled_batches"`
	
	// Performance metrics
	AvgBatchTime      time.Duration `json:"avg_batch_time"`
	AvgRequestTime    time.Duration `json:"avg_request_time"`
	Throughput        float64       `json:"throughput"`        // Requests per second
	SuccessRate       float64       `json:"success_rate"`
	
	// Queue statistics
	QueueLength       int           `json:"queue_length"`
	ProcessingCount   int           `json:"processing_count"`
	ActiveWorkers     int           `json:"active_workers"`
	MaxWorkers        int           `json:"max_workers"`
	
	// Resource utilization
	CPUUtilization    float64       `json:"cpu_utilization"`
	MemoryUtilization float64       `json:"memory_utilization"`
	
	// Timing
	LastUpdate        time.Time     `json:"last_update"`
	UptimeDuration    time.Duration `json:"uptime_duration"`
}

// BatchHealthStatus represents the health status for batch processing
type BatchHealthStatus string

const (
	BatchHealthStatusHealthy   BatchHealthStatus = "healthy"
	BatchHealthStatusDegraded  BatchHealthStatus = "degraded"
	BatchHealthStatusUnhealthy BatchHealthStatus = "unhealthy"
)

// BatchHealthMetrics provides detailed health metrics
type BatchHealthMetrics struct {
	OverallScore        float64   `json:"overall_score"`
	AvgResponseTime     time.Duration `json:"avg_response_time"`
	MaxResponseTime     time.Duration `json:"max_response_time"`
	ErrorRate           float64   `json:"error_rate"`
	ThroughputPerSec    float64   `json:"throughput_per_sec"`
}

// BatchHealthReport provides health information for the batch processor
type BatchHealthReport struct {
	Timestamp      time.Time              `json:"timestamp"`
	Status         BatchHealthStatus      `json:"status"`
	Issues         []string               `json:"issues"`
	Recommendations []string              `json:"recommendations"`
	Metrics        *BatchHealthMetrics    `json:"metrics"`
}

// RetryPolicy defines retry behavior for failed requests
type RetryPolicy struct {
	MaxRetries      int           `json:"max_retries"`
	InitialDelay    time.Duration `json:"initial_delay"`
	MaxDelay        time.Duration `json:"max_delay"`
	BackoffFactor   float64       `json:"backoff_factor"`
	RetryableErrors []string      `json:"retryable_errors"`
}

// BatchConfig contains configuration for the batch processor
type BatchConfig struct {
	// Worker configuration
	MaxWorkers        int           `json:"max_workers"`
	MinWorkers        int           `json:"min_workers"`
	WorkerIdleTimeout time.Duration `json:"worker_idle_timeout"`
	
	// Queue configuration
	MaxQueueSize      int           `json:"max_queue_size"`
	BatchSize         int           `json:"batch_size"`         // Optimal batch size
	BatchTimeout      time.Duration `json:"batch_timeout"`     // Max time to wait for batch to fill
	
	// Processing configuration
	MaxConcurrency    int           `json:"max_concurrency"`   // Max concurrent requests per batch
	RequestTimeout    time.Duration `json:"request_timeout"`   // Default request timeout
	
	// Retry configuration
	DefaultRetryPolicy *RetryPolicy `json:"default_retry_policy"`
	
	// Optimization settings
	AdaptiveSizing    bool          `json:"adaptive_sizing"`   // Automatically adjust batch sizes
	LoadBalancing     bool          `json:"load_balancing"`    // Enable load balancing
	ResourceMonitoring bool         `json:"resource_monitoring"` // Enable resource monitoring
	
	// Monitoring and logging
	MetricsEnabled    bool          `json:"metrics_enabled"`
	ProgressTracking  bool          `json:"progress_tracking"`
	DetailedLogging   bool          `json:"detailed_logging"`
}

// DefaultBatchConfig returns a default batch processing configuration
func DefaultBatchConfig() *BatchConfig {
	return &BatchConfig{
		MaxWorkers:        50,
		MinWorkers:        5,
		WorkerIdleTimeout: 5 * time.Minute,
		MaxQueueSize:      10000,
		BatchSize:         100,
		BatchTimeout:      5 * time.Second,
		MaxConcurrency:    10,
		RequestTimeout:    30 * time.Second,
		DefaultRetryPolicy: &RetryPolicy{
			MaxRetries:      3,
			InitialDelay:    1 * time.Second,
			MaxDelay:        30 * time.Second,
			BackoffFactor:   2.0,
			RetryableErrors: []string{"timeout", "network_error", "temporary_failure"},
		},
		AdaptiveSizing:     true,
		LoadBalancing:      true,
		ResourceMonitoring: true,
		MetricsEnabled:     true,
		ProgressTracking:   true,
		DetailedLogging:    false,
	}
}

// BatchProcessorImpl implements the BatchProcessor interface
type BatchProcessorImpl struct {
	config        *BatchConfig
	requestQueue  chan *batchItem
	workerPool    *WorkerPool
	batchTracker  *BatchTracker
	optimizer     *BatchOptimizer
	stats         *BatchStats
	healthMonitor *HealthMonitor
	
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	stopChan      chan struct{}
	wg            sync.WaitGroup
	
	// Atomic counters
	totalBatches    int64
	totalRequests   int64
	completedReqs   int64
	failedReqs      int64
	startTime       time.Time
}

// batchItem represents an internal batch processing item
type batchItem struct {
	request    *BatchRequest
	resultChan chan *BatchResult
	ctx        context.Context
	batchID    string
	retryCount int
	startTime  time.Time
}

// WorkerPool manages a pool of batch processing workers
type WorkerPool struct {
	config       *BatchConfig
	workers      []*Worker
	workQueue    chan *batchItem
	mu           sync.RWMutex
	activeCount  int64
	ctx          context.Context
}

// Worker represents a single batch processing worker
type Worker struct {
	id        int
	pool      *WorkerPool
	workQueue chan *batchItem
	quit      chan struct{}
	active    int64
}

// BatchTracker tracks batch progress and manages dependencies
type BatchTracker struct {
	batches     map[string]*BatchInfo
	mu          sync.RWMutex
	progressChan chan *ProgressUpdate
}

// BatchInfo contains information about a batch operation
type BatchInfo struct {
	ID            string
	Requests      []*batchItem
	Results       map[string]*BatchResult
	Status        BatchStatus
	StartTime     time.Time
	LastUpdate    time.Time
	Dependencies  []string
	mu            sync.RWMutex
}

// ProgressUpdate represents a progress update for a batch
type ProgressUpdate struct {
	BatchID   string
	RequestID string
	Status    BatchStatus
	Progress  float64
	Stage     string
	Error     error
}

// BatchOptimizer handles dynamic optimization of batch processing
type BatchOptimizer struct {
	config          *BatchConfig
	mu              sync.RWMutex
	performanceData []PerformanceDataPoint
	optimizeInterval time.Duration
}

// PerformanceDataPoint represents a performance measurement
type PerformanceDataPoint struct {
	Timestamp       time.Time
	BatchSize       int
	ProcessingTime  time.Duration
	Throughput      float64
	ResourceUsage   ResourceUsage
}

// ResourceUsage represents resource utilization metrics
type ResourceUsage struct {
	CPUPercent    float64
	MemoryMB      float64
	GoroutineCount int
}

// HealthMonitor monitors the health of the batch processor
type HealthMonitor struct {
	mu           sync.RWMutex
	lastCheck    time.Time
	issues       []string
	errorRate    float64
	responseTime time.Duration
}

// NewBatchProcessor creates a new batch processor instance
func NewBatchProcessor(config *BatchConfig) (BatchProcessor, error) {
	if config == nil {
		config = DefaultBatchConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	processor := &BatchProcessorImpl{
		config:       config,
		requestQueue: make(chan *batchItem, config.MaxQueueSize),
		ctx:          ctx,
		cancel:       cancel,
		stopChan:     make(chan struct{}),
		stats: &BatchStats{
			MaxWorkers: config.MaxWorkers,
			LastUpdate: time.Now(),
		},
		startTime: time.Now(),
	}
	
	// Initialize worker pool
	processor.workerPool = &WorkerPool{
		config:    config,
		workers:   make([]*Worker, 0, config.MaxWorkers),
		workQueue: processor.requestQueue,
		ctx:       ctx,
	}
	
	// Initialize batch tracker
	processor.batchTracker = &BatchTracker{
		batches:      make(map[string]*BatchInfo),
		progressChan: make(chan *ProgressUpdate, 1000),
	}
	
	// Initialize optimizer
	if config.AdaptiveSizing {
		processor.optimizer = &BatchOptimizer{
			config:           config,
			performanceData:  make([]PerformanceDataPoint, 0),
			optimizeInterval: 5 * time.Minute,
		}
	}
	
	// Initialize health monitor
	processor.healthMonitor = &HealthMonitor{
		lastCheck: time.Now(),
		issues:    make([]string, 0),
	}
	
	// Start initial workers
	if err := processor.startWorkers(config.MinWorkers); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start initial workers: %w", err)
	}
	
	// Start background processes
	processor.startBackgroundProcesses()
	
	log.Info().
		Int("max_workers", config.MaxWorkers).
		Int("min_workers", config.MinWorkers).
		Int("batch_size", config.BatchSize).
		Msg("Batch processor initialized")
	
	return processor, nil
}

// Submit submits a request for batch processing
func (bp *BatchProcessorImpl) Submit(ctx context.Context, request *BatchRequest) (*BatchResult, error) {
	if request == nil {
		return nil, errors.New("request cannot be nil")
	}
	
	// Validate request
	if err := bp.validateRequest(request); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	
	// Set defaults
	if request.ID == "" {
		request.ID = fmt.Sprintf("req_%d", time.Now().UnixNano())
	}
	if request.CreatedAt.IsZero() {
		request.CreatedAt = time.Now()
	}
	if request.Timeout == 0 {
		request.Timeout = bp.config.RequestTimeout
	}
	
	// Create batch item
	item := &batchItem{
		request:    request,
		resultChan: make(chan *BatchResult, 1),
		ctx:        ctx,
		batchID:    fmt.Sprintf("batch_%d", time.Now().UnixNano()),
		startTime:  time.Now(),
	}
	
	atomic.AddInt64(&bp.totalRequests, 1)
	
	// Track the batch
	bp.batchTracker.trackBatch(item.batchID, []*batchItem{item})
	
	// Submit to queue
	select {
	case bp.requestQueue <- item:
		log.Debug().
			Str("request_id", request.ID).
			Str("batch_id", item.batchID).
			Str("type", string(request.Type)).
			Msg("Request queued for batch processing")
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-bp.ctx.Done():
		return nil, errors.New("batch processor is shutting down")
	default:
		return nil, errors.New("request queue is full")
	}
	
	// Wait for result
	select {
	case result := <-item.resultChan:
		return result, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(request.Timeout):
		return nil, fmt.Errorf("request timeout after %v", request.Timeout)
	}
}

// SubmitMany submits multiple requests for batch processing
func (bp *BatchProcessorImpl) SubmitMany(ctx context.Context, requests []*BatchRequest) ([]*BatchResult, error) {
	if len(requests) == 0 {
		return []*BatchResult{}, nil
	}
	
	batchID := fmt.Sprintf("batch_%d", time.Now().UnixNano())
	items := make([]*batchItem, 0, len(requests))
	results := make([]*BatchResult, len(requests))
	
	// Create batch items
	for i, request := range requests {
		if err := bp.validateRequest(request); err != nil {
			return nil, fmt.Errorf("invalid request at index %d: %w", i, err)
		}
		
		// Set defaults
		if request.ID == "" {
			request.ID = fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), i)
		}
		if request.CreatedAt.IsZero() {
			request.CreatedAt = time.Now()
		}
		if request.Timeout == 0 {
			request.Timeout = bp.config.RequestTimeout
		}
		
		item := &batchItem{
			request:    request,
			resultChan: make(chan *BatchResult, 1),
			ctx:        ctx,
			batchID:    batchID,
			startTime:  time.Now(),
		}
		
		items = append(items, item)
	}
	
	atomic.AddInt64(&bp.totalBatches, 1)
	atomic.AddInt64(&bp.totalRequests, int64(len(requests)))
	
	// Track the batch
	bp.batchTracker.trackBatch(batchID, items)
	
	// Submit items to queue
	for _, item := range items {
		select {
		case bp.requestQueue <- item:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-bp.ctx.Done():
			return nil, errors.New("batch processor is shutting down")
		default:
			return nil, errors.New("request queue is full")
		}
	}
	
	log.Info().
		Str("batch_id", batchID).
		Int("request_count", len(requests)).
		Msg("Batch submitted for processing")
	
	// Collect results
	for i, item := range items {
		select {
		case result := <-item.resultChan:
			results[i] = result
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(item.request.Timeout):
			results[i] = &BatchResult{
				RequestID:    item.request.ID,
				BatchID:      batchID,
				Status:       BatchStatusFailed,
				Error:        "request timeout",
				StartTime:    item.startTime,
				EndTime:      time.Now(),
				ExecutionTime: time.Since(item.startTime),
			}
		}
	}
	
	return results, nil
}

// GetProgress returns the progress of a batch operation
func (bp *BatchProcessorImpl) GetProgress(batchID string) (*BatchProgress, error) {
	return bp.batchTracker.getProgress(batchID)
}

// Cancel cancels a batch operation
func (bp *BatchProcessorImpl) Cancel(batchID string) error {
	return bp.batchTracker.cancelBatch(batchID)
}

// Stats returns batch processing statistics
func (bp *BatchProcessorImpl) Stats() *BatchStats {
	bp.mu.RLock()
	defer bp.mu.RUnlock()
	
	stats := &BatchStats{
		TotalBatches:      atomic.LoadInt64(&bp.totalBatches),
		TotalRequests:     atomic.LoadInt64(&bp.totalRequests),
		CompletedBatches:  0, // Would be calculated from batch tracker
		FailedBatches:     0, // Would be calculated from batch tracker
		CancelledBatches:  0, // Would be calculated from batch tracker
		QueueLength:       len(bp.requestQueue),
		ProcessingCount:   int(atomic.LoadInt64(&bp.workerPool.activeCount)),
		ActiveWorkers:     len(bp.workerPool.workers),
		MaxWorkers:        bp.config.MaxWorkers,
		LastUpdate:        time.Now(),
		UptimeDuration:    time.Since(bp.startTime),
	}
	
	// Calculate rates
	if stats.TotalRequests > 0 {
		completed := atomic.LoadInt64(&bp.completedReqs)
		
		stats.SuccessRate = float64(completed) / float64(stats.TotalRequests)
		
		if uptime := stats.UptimeDuration.Seconds(); uptime > 0 {
			stats.Throughput = float64(completed) / uptime
		}
	}
	
	return stats
}

// Health returns health status of the batch processor
func (bp *BatchProcessorImpl) Health() *BatchHealthReport {
	bp.healthMonitor.mu.RLock()
	defer bp.healthMonitor.mu.RUnlock()
	
	report := &BatchHealthReport{
		Timestamp:       time.Now(),
		Issues:          make([]string, len(bp.healthMonitor.issues)),
		Recommendations: make([]string, 0),
		Metrics: &BatchHealthMetrics{
			ErrorRate:       bp.healthMonitor.errorRate,
			AvgResponseTime: bp.healthMonitor.responseTime,
		},
	}
	
	copy(report.Issues, bp.healthMonitor.issues)
	
	// Determine status
	switch {
	case len(report.Issues) == 0:
		report.Status = BatchHealthStatusHealthy
	case len(report.Issues) <= 2 && bp.healthMonitor.errorRate < 0.1:
		report.Status = BatchHealthStatusDegraded
		report.Recommendations = append(report.Recommendations, "Monitor for performance issues")
	default:
		report.Status = BatchHealthStatusUnhealthy
		report.Recommendations = append(report.Recommendations, "Immediate attention required")
	}
	
	return report
}

// Optimize optimizes batch processing parameters
func (bp *BatchProcessorImpl) Optimize() error {
	if bp.optimizer == nil {
		return nil
	}
	
	log.Info().Msg("Starting batch processor optimization")
	
	// Analyze performance data and adjust parameters
	bp.optimizer.mu.Lock()
	defer bp.optimizer.mu.Unlock()
	
	if len(bp.optimizer.performanceData) < 10 {
		return nil // Need more data
	}
	
	// Simple optimization logic
	recent := bp.optimizer.performanceData[len(bp.optimizer.performanceData)-10:]
	
	var avgThroughput float64
	for _, dp := range recent {
		avgThroughput += dp.Throughput
	}
	avgThroughput /= float64(len(recent))
	
	// Adjust batch size based on throughput
	if avgThroughput < 10 { // Low throughput
		bp.config.BatchSize = minInt(bp.config.BatchSize+10, 200)
		log.Info().Int("new_batch_size", bp.config.BatchSize).Msg("Increased batch size")
	} else if avgThroughput > 100 { // High throughput
		bp.config.BatchSize = maxInt(bp.config.BatchSize-5, 10)
		log.Info().Int("new_batch_size", bp.config.BatchSize).Msg("Decreased batch size")
	}
	
	return nil
}

// Close gracefully shuts down the batch processor
func (bp *BatchProcessorImpl) Close(ctx context.Context) error {
	log.Info().Msg("Shutting down batch processor")
	
	// Signal shutdown
	close(bp.stopChan)
	bp.cancel()
	
	// Wait for background processes
	done := make(chan struct{})
	go func() {
		bp.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
	case <-ctx.Done():
		log.Warn().Msg("Batch processor shutdown timeout")
	}
	
	log.Info().Msg("Batch processor shutdown complete")
	return nil
}

// Private methods

func (bp *BatchProcessorImpl) validateRequest(request *BatchRequest) error {
	if request == nil {
		return errors.New("request is nil")
	}
	
	if request.Type == "" {
		return errors.New("request type is required")
	}
	
	if request.Payload == nil {
		return errors.New("request payload is required")
	}
	
	return nil
}

func (bp *BatchProcessorImpl) startWorkers(count int) error {
	bp.workerPool.mu.Lock()
	defer bp.workerPool.mu.Unlock()
	
	for i := 0; i < count; i++ {
		worker := &Worker{
			id:        len(bp.workerPool.workers),
			pool:      bp.workerPool,
			workQueue: bp.workerPool.workQueue,
			quit:      make(chan struct{}),
		}
		
		bp.workerPool.workers = append(bp.workerPool.workers, worker)
		go worker.start()
	}
	
	log.Info().Int("worker_count", count).Msg("Started batch processing workers")
	return nil
}

func (bp *BatchProcessorImpl) startBackgroundProcesses() {
	// Progress tracker
	bp.wg.Add(1)
	go bp.progressTracker()
	
	// Stats collector
	if bp.config.MetricsEnabled {
		bp.wg.Add(1)
		go bp.statsCollector()
	}
	
	// Health monitor
	bp.wg.Add(1)
	go bp.healthChecker()
	
	// Optimizer
	if bp.optimizer != nil {
		bp.wg.Add(1)
		go bp.optimizationWorker()
	}
}

func (bp *BatchProcessorImpl) progressTracker() {
	defer bp.wg.Done()
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-bp.stopChan:
			return
		case <-ticker.C:
			// Update progress for all active batches
			bp.batchTracker.updateProgress()
		case update := <-bp.batchTracker.progressChan:
			bp.batchTracker.processProgressUpdate(update)
		}
	}
}

func (bp *BatchProcessorImpl) statsCollector() {
	defer bp.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-bp.stopChan:
			return
		case <-ticker.C:
			bp.collectStats()
		}
	}
}

func (bp *BatchProcessorImpl) healthChecker() {
	defer bp.wg.Done()
	
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-bp.stopChan:
			return
		case <-ticker.C:
			bp.checkHealth()
		}
	}
}

func (bp *BatchProcessorImpl) optimizationWorker() {
	defer bp.wg.Done()
	
	ticker := time.NewTicker(bp.optimizer.optimizeInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-bp.stopChan:
			return
		case <-ticker.C:
			if err := bp.Optimize(); err != nil {
				log.Warn().Err(err).Msg("Optimization failed")
			}
		}
	}
}

func (bp *BatchProcessorImpl) collectStats() {
	// Collect performance data for optimization
	if bp.optimizer != nil {
		dataPoint := PerformanceDataPoint{
			Timestamp:      time.Now(),
			BatchSize:      bp.config.BatchSize,
			ProcessingTime: time.Since(bp.startTime) / time.Duration(atomic.LoadInt64(&bp.totalRequests)),
			Throughput:     bp.Stats().Throughput,
			ResourceUsage: ResourceUsage{
				CPUPercent:     0, // Would collect actual CPU usage
				MemoryMB:       0, // Would collect actual memory usage
				GoroutineCount: 0, // Would collect goroutine count
			},
		}
		
		bp.optimizer.mu.Lock()
		bp.optimizer.performanceData = append(bp.optimizer.performanceData, dataPoint)
		if len(bp.optimizer.performanceData) > 1000 { // Keep last 1000 points
			bp.optimizer.performanceData = bp.optimizer.performanceData[1:]
		}
		bp.optimizer.mu.Unlock()
	}
}

func (bp *BatchProcessorImpl) checkHealth() {
	bp.healthMonitor.mu.Lock()
	defer bp.healthMonitor.mu.Unlock()
	
	bp.healthMonitor.lastCheck = time.Now()
	bp.healthMonitor.issues = bp.healthMonitor.issues[:0] // Clear issues
	
	// Check queue length
	queueLen := len(bp.requestQueue)
	if queueLen > bp.config.MaxQueueSize*8/10 { // 80% full
		bp.healthMonitor.issues = append(bp.healthMonitor.issues, 
			fmt.Sprintf("Queue nearly full: %d/%d", queueLen, bp.config.MaxQueueSize))
	}
	
	// Check worker count
	activeWorkers := len(bp.workerPool.workers)
	if activeWorkers < bp.config.MinWorkers {
		bp.healthMonitor.issues = append(bp.healthMonitor.issues,
			fmt.Sprintf("Below minimum workers: %d/%d", activeWorkers, bp.config.MinWorkers))
	}
	
	// Calculate error rate
	totalReqs := atomic.LoadInt64(&bp.totalRequests)
	failedReqs := atomic.LoadInt64(&bp.failedReqs)
	if totalReqs > 0 {
		bp.healthMonitor.errorRate = float64(failedReqs) / float64(totalReqs)
		if bp.healthMonitor.errorRate > 0.1 { // 10% error rate
			bp.healthMonitor.issues = append(bp.healthMonitor.issues,
				fmt.Sprintf("High error rate: %.2f%%", bp.healthMonitor.errorRate*100))
		}
	}
}

// Worker implementation

func (w *Worker) start() {
	log.Debug().Int("worker_id", w.id).Msg("Worker started")
	
	for {
		select {
		case work := <-w.workQueue:
			w.processItem(work)
		case <-w.quit:
			log.Debug().Int("worker_id", w.id).Msg("Worker stopped")
			return
		case <-w.pool.ctx.Done():
			log.Debug().Int("worker_id", w.id).Msg("Worker context cancelled")
			return
		}
	}
}

func (w *Worker) processItem(item *batchItem) {
	atomic.AddInt64(&w.active, 1)
	atomic.AddInt64(&w.pool.activeCount, 1)
	defer func() {
		atomic.AddInt64(&w.active, -1)
		atomic.AddInt64(&w.pool.activeCount, -1)
	}()
	
	log.Debug().
		Int("worker_id", w.id).
		Str("request_id", item.request.ID).
		Str("type", string(item.request.Type)).
		Msg("Processing request")
	
	result := w.executeRequest(item)
	
	// Send result
	select {
	case item.resultChan <- result:
	default:
		log.Warn().
			Str("request_id", item.request.ID).
			Msg("Failed to send result - channel full or closed")
	}
}

func (w *Worker) executeRequest(item *batchItem) *BatchResult {
	start := time.Now()
	
	result := &BatchResult{
		RequestID: item.request.ID,
		BatchID:   item.batchID,
		Status:    BatchStatusProcessing,
		StartTime: start,
		Metadata:  make(map[string]interface{}),
	}
	
	// Execute based on request type
	output, err := w.processRequestByType(item.request)
	
	result.EndTime = time.Now()
	result.ExecutionTime = result.EndTime.Sub(start)
	
	if err != nil {
		result.Status = BatchStatusFailed
		result.Error = err.Error()
		log.Warn().
			Err(err).
			Str("request_id", item.request.ID).
			Str("type", string(item.request.Type)).
			Dur("duration", result.ExecutionTime).
			Msg("Request processing failed")
	} else {
		result.Status = BatchStatusCompleted
		result.Output = output
		log.Debug().
			Str("request_id", item.request.ID).
			Str("type", string(item.request.Type)).
			Dur("duration", result.ExecutionTime).
			Msg("Request processing completed")
	}
	
	return result
}

func (w *Worker) processRequestByType(request *BatchRequest) (interface{}, error) {
	// This is where actual request processing would happen
	// For now, simulate processing with a small delay
	
	switch request.Type {
	case BatchTypeCommand:
		// Simulate command execution
		time.Sleep(10 * time.Millisecond)
		return map[string]interface{}{
			"command": request.Payload,
			"output":  "Command executed successfully",
			"exit_code": 0,
		}, nil
		
	case BatchTypeFileOp:
		// Simulate file operation
		time.Sleep(5 * time.Millisecond)
		return map[string]interface{}{
			"operation": request.Payload,
			"status":    "completed",
		}, nil
		
	case BatchTypeCodeExec:
		// Simulate code execution
		time.Sleep(20 * time.Millisecond)
		return map[string]interface{}{
			"code":   request.Payload,
			"result": "Code executed successfully",
		}, nil
		
	case BatchTypeDataProcess:
		// Simulate data processing
		time.Sleep(15 * time.Millisecond)
		return map[string]interface{}{
			"data":      request.Payload,
			"processed": true,
		}, nil
		
	default:
		// Custom processing
		time.Sleep(10 * time.Millisecond)
		return map[string]interface{}{
			"type":   request.Type,
			"result": "Processed",
		}, nil
	}
}

// BatchTracker implementation

func (bt *BatchTracker) trackBatch(batchID string, items []*batchItem) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	
	batchInfo := &BatchInfo{
		ID:          batchID,
		Requests:    items,
		Results:     make(map[string]*BatchResult),
		Status:      BatchStatusQueued,
		StartTime:   time.Now(),
		LastUpdate:  time.Now(),
	}
	
	bt.batches[batchID] = batchInfo
}

func (bt *BatchTracker) getProgress(batchID string) (*BatchProgress, error) {
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	
	batch, exists := bt.batches[batchID]
	if !exists {
		return nil, errors.New("batch not found")
	}
	
	batch.mu.RLock()
	defer batch.mu.RUnlock()
	
	progress := &BatchProgress{
		BatchID:         batchID,
		Status:          batch.Status,
		TotalRequests:   len(batch.Requests),
		StartTime:       batch.StartTime,
		LastUpdate:      batch.LastUpdate,
		RequestProgress: make(map[string]*RequestProgress),
	}
	
	// Count completed and failed requests
	for requestID, result := range batch.Results {
		switch result.Status {
		case BatchStatusCompleted:
			progress.CompletedCount++
		case BatchStatusFailed:
			progress.FailedCount++
		default:
			progress.PendingCount++
		}
		
		progress.RequestProgress[requestID] = &RequestProgress{
			RequestID:       requestID,
			Status:          result.Status,
			ProgressPercent: 100.0,
			ElapsedTime:     result.ExecutionTime,
		}
	}
	
	// Calculate overall progress
	if progress.TotalRequests > 0 {
		progress.ProgressPercent = float64(progress.CompletedCount+progress.FailedCount) / float64(progress.TotalRequests) * 100.0
	}
	
	return progress, nil
}

func (bt *BatchTracker) cancelBatch(batchID string) error {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	
	batch, exists := bt.batches[batchID]
	if !exists {
		return errors.New("batch not found")
	}
	
	batch.mu.Lock()
	defer batch.mu.Unlock()
	
	batch.Status = BatchStatusCancelled
	batch.LastUpdate = time.Now()
	
	log.Info().Str("batch_id", batchID).Msg("Batch cancelled")
	return nil
}

func (bt *BatchTracker) updateProgress() {
	// Update progress for all active batches
	bt.mu.RLock()
	defer bt.mu.RUnlock()
	
	for _, batch := range bt.batches {
		batch.mu.Lock()
		batch.LastUpdate = time.Now()
		batch.mu.Unlock()
	}
}

func (bt *BatchTracker) processProgressUpdate(update *ProgressUpdate) {
	bt.mu.Lock()
	defer bt.mu.Unlock()
	
	batch, exists := bt.batches[update.BatchID]
	if !exists {
		return
	}
	
	batch.mu.Lock()
	defer batch.mu.Unlock()
	
	// Update result status
	if result, exists := batch.Results[update.RequestID]; exists {
		result.Status = update.Status
		if update.Error != nil {
			result.Error = update.Error.Error()
		}
	}
	
	batch.LastUpdate = time.Now()
}

// Utility functions

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}