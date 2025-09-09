package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
)

// ConnectionPool manages a pool of container connections for optimal resource utilization
type ConnectionPool interface {
	// Get retrieves a connection from the pool
	Get(ctx context.Context) (*PooledConnection, error)

	// Put returns a connection to the pool
	Put(conn *PooledConnection) error

	// Size returns current pool size statistics
	Size() PoolSizeInfo

	// Health performs health checks on all connections
	Health(ctx context.Context) (*PoolHealthReport, error)

	// Warm pre-warms connections in the pool
	Warm(ctx context.Context, count int) error

	// Stats returns pool performance statistics
	Stats() *PoolStats

	// Resize dynamically resizes the pool
	Resize(minSize, maxSize int) error

	// Close gracefully shuts down the pool
	Close(ctx context.Context) error
}

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	ID            string
	Runtime       RuncInterface
	CreatedAt     time.Time
	LastUsedAt    time.Time
	UsageCount    int64
	IsHealthy     bool
	Metadata      map[string]interface{}
	mu            sync.RWMutex
	pool          *ContainerConnectionPool
	inUse         bool
	healthScore   float64
	recycleAfter  int64  // Recycle after this many uses
	maxIdleTime   time.Duration
}

// PoolSizeInfo provides information about pool sizing
type PoolSizeInfo struct {
	MinSize     int `json:"min_size"`
	MaxSize     int `json:"max_size"`
	CurrentSize int `json:"current_size"`
	ActiveSize  int `json:"active_size"`
	IdleSize    int `json:"idle_size"`
	WaitingCount int `json:"waiting_count"`
}

// PoolHealthReport contains health check results for the entire pool
type PoolHealthReport struct {
	Timestamp        time.Time                       `json:"timestamp"`
	OverallHealth    PoolHealthStatus                `json:"overall_health"`
	TotalConnections int                             `json:"total_connections"`
	HealthyCount     int                             `json:"healthy_count"`
	UnhealthyCount   int                             `json:"unhealthy_count"`
	ConnectionHealth map[string]*ConnectionHealth    `json:"connection_health"`
	Recommendations  []string                        `json:"recommendations"`
	Metrics          *PoolHealthMetrics              `json:"metrics"`
}

// ConnectionHealth represents health status of a single connection
type ConnectionHealth struct {
	ConnectionID     string        `json:"connection_id"`
	Status          HealthStatus  `json:"status"`
	HealthScore     float64       `json:"health_score"`
	LastHealthCheck time.Time     `json:"last_health_check"`
	ResponseTime    time.Duration `json:"response_time"`
	ErrorCount      int64         `json:"error_count"`
	Issues          []string      `json:"issues"`
}

// PoolHealthStatus represents overall pool health
type PoolHealthStatus string

const (
	HealthStatusHealthy   PoolHealthStatus = "healthy"
	HealthStatusDegraded  PoolHealthStatus = "degraded"
	HealthStatusUnhealthy PoolHealthStatus = "unhealthy"
)

// HealthStatus for individual connections
type HealthStatus string

const (
	ConnectionHealthy   HealthStatus = "healthy"
	ConnectionDegraded  HealthStatus = "degraded"
	ConnectionUnhealthy HealthStatus = "unhealthy"
	ConnectionUnknown   HealthStatus = "unknown"
)

// PoolHealthMetrics provides detailed health metrics
type PoolHealthMetrics struct {
	AvgResponseTime   time.Duration `json:"avg_response_time"`
	MaxResponseTime   time.Duration `json:"max_response_time"`
	MinResponseTime   time.Duration `json:"min_response_time"`
	ErrorRate         float64       `json:"error_rate"`
	ThroughputPerSec  float64       `json:"throughput_per_sec"`
	UtilizationRate   float64       `json:"utilization_rate"`
}

// PoolStats provides comprehensive pool performance statistics
type PoolStats struct {
	// Connection statistics
	TotalConnections      int64         `json:"total_connections"`
	ActiveConnections     int64         `json:"active_connections"`
	IdleConnections      int64         `json:"idle_connections"`
	CreatedConnections   int64         `json:"created_connections"`
	DestroyedConnections int64         `json:"destroyed_connections"`
	RecycledConnections  int64         `json:"recycled_connections"`

	// Performance metrics
	AcquisitionTime      time.Duration `json:"acquisition_time"`      // Average time to acquire connection
	UtilizationRate      float64       `json:"utilization_rate"`      // Percentage of pool being used
	HitRate              float64       `json:"hit_rate"`              // Cache hit rate
	MissRate             float64       `json:"miss_rate"`             // Cache miss rate

	// Quality metrics
	HealthScore          float64       `json:"health_score"`          // Overall pool health score
	ErrorRate            float64       `json:"error_rate"`            // Error rate across all connections
	AvgResponseTime      time.Duration `json:"avg_response_time"`     // Average response time

	// Optimization metrics
	OptimalSize          int           `json:"optimal_size"`          // Recommended optimal size
	FragmentationRatio   float64       `json:"fragmentation_ratio"`   // Pool fragmentation
	ThroughputPerSec     float64       `json:"throughput_per_sec"`    // Operations per second
	
	// Timing statistics
	LastStatsUpdate      time.Time     `json:"last_stats_update"`
	CollectionStartTime  time.Time     `json:"collection_start_time"`
}

// PoolConfig contains configuration for the connection pool
type PoolConfig struct {
	MinSize            int           `json:"min_size"`              // Minimum pool size
	MaxSize            int           `json:"max_size"`              // Maximum pool size  
	InitialSize        int           `json:"initial_size"`          // Initial pool size
	MaxIdleTime        time.Duration `json:"max_idle_time"`         // Max idle time before recycling
	HealthCheckInterval time.Duration `json:"health_check_interval"` // Interval for health checks
	ConnectionTimeout  time.Duration `json:"connection_timeout"`    // Connection acquisition timeout
	RecycleThreshold   int64         `json:"recycle_threshold"`     // Usage count before recycling
	WarmupEnabled      bool          `json:"warmup_enabled"`        // Enable connection warming
	WarmupSize         int           `json:"warmup_size"`           // Number of connections to warm up
	AdaptiveSizing     bool          `json:"adaptive_sizing"`       // Enable adaptive pool sizing
	MetricsEnabled     bool          `json:"metrics_enabled"`       // Enable metrics collection
	LogLevel           string        `json:"log_level"`             // Logging level for pool operations
}

// DefaultPoolConfig returns a default pool configuration
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MinSize:            5,
		MaxSize:            50,
		InitialSize:        10,
		MaxIdleTime:        30 * time.Minute,
		HealthCheckInterval: 5 * time.Minute,
		ConnectionTimeout:  30 * time.Second,
		RecycleThreshold:   1000,
		WarmupEnabled:      true,
		WarmupSize:         5,
		AdaptiveSizing:     true,
		MetricsEnabled:     true,
		LogLevel:          "info",
	}
}

// ContainerConnectionPool implements ConnectionPool interface
type ContainerConnectionPool struct {
	config            *PoolConfig
	connections       []*PooledConnection
	availableConns    chan *PooledConnection
	busyConns         map[string]*PooledConnection
	mu                sync.RWMutex
	stats             *PoolStats
	healthChecker     *HealthChecker
	optimizer         *PoolOptimizer
	factory           ConnectionFactory
	ctx               context.Context
	cancel            context.CancelFunc
	stopChan          chan struct{}
	wg                sync.WaitGroup
	metricsCollector  *MetricsCollector
	
	// Atomic counters for performance
	totalCreated    int64
	totalDestroyed  int64
	totalRecycled   int64
	totalRequests   int64
	totalHits       int64
	totalMisses     int64
	totalErrors     int64
}

// ConnectionFactory creates new connections
type ConnectionFactory func(ctx context.Context) (RuncInterface, error)

// HealthChecker performs health checks on connections
type HealthChecker struct {
	interval      time.Duration
	timeout       time.Duration
	mu            sync.RWMutex
	checks        map[string]*HealthCheckResult
	checkHistory  []PoolHealthReport
}

// HealthCheckResult contains result of a single health check
type HealthCheckResult struct {
	ConnectionID string
	Timestamp    time.Time
	Success      bool
	ResponseTime time.Duration
	Error        error
	Score        float64
}

// PoolOptimizer handles dynamic pool optimization
type PoolOptimizer struct {
	enabled          bool
	adjustInterval   time.Duration
	utilizationHigh  float64  // High utilization threshold
	utilizationLow   float64  // Low utilization threshold
	scaleUpFactor    float64  // Factor for scaling up
	scaleDownFactor  float64  // Factor for scaling down
	history          []UtilizationSnapshot
	predictions      []UtilizationPrediction
}

// UtilizationSnapshot captures utilization at a point in time
type UtilizationSnapshot struct {
	Timestamp    time.Time
	Utilization  float64
	ActiveConns  int
	TotalConns   int
	QueueLength  int
	ResponseTime time.Duration
}

// UtilizationPrediction contains predicted utilization patterns
type UtilizationPrediction struct {
	Timestamp          time.Time
	PredictedUtil      float64
	Confidence         float64
	RecommendedSize    int
	ReasonCode         string
}

// MetricsCollector gathers and processes pool metrics
type MetricsCollector struct {
	enabled       bool
	interval      time.Duration
	samples       []MetricSample
	aggregated    *AggregatedMetrics
	mu            sync.RWMutex
}

// MetricSample represents a single metric sample
type MetricSample struct {
	Timestamp    time.Time
	Metric       string
	Value        float64
	Labels       map[string]string
}

// AggregatedMetrics contains aggregated metric data
type AggregatedMetrics struct {
	Counters     map[string]int64
	Gauges       map[string]float64
	Histograms   map[string][]float64
	LastUpdate   time.Time
}

// NewConnectionPool creates a new container connection pool
func NewConnectionPool(config *PoolConfig, factory ConnectionFactory) (ConnectionPool, error) {
	if config == nil {
		config = DefaultPoolConfig()
	}
	
	if factory == nil {
		return nil, errors.New("connection factory is required")
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pool := &ContainerConnectionPool{
		config:         config,
		connections:    make([]*PooledConnection, 0, config.MaxSize),
		availableConns: make(chan *PooledConnection, config.MaxSize),
		busyConns:      make(map[string]*PooledConnection),
		stats: &PoolStats{
			CollectionStartTime: time.Now(),
			LastStatsUpdate:     time.Now(),
		},
		factory:  factory,
		ctx:      ctx,
		cancel:   cancel,
		stopChan: make(chan struct{}),
	}
	
	// Initialize health checker
	pool.healthChecker = &HealthChecker{
		interval:     config.HealthCheckInterval,
		timeout:      30 * time.Second,
		checks:       make(map[string]*HealthCheckResult),
		checkHistory: make([]PoolHealthReport, 0),
	}
	
	// Initialize optimizer if enabled
	if config.AdaptiveSizing {
		pool.optimizer = &PoolOptimizer{
			enabled:          true,
			adjustInterval:   5 * time.Minute,
			utilizationHigh:  0.8,  // 80% utilization
			utilizationLow:   0.2,  // 20% utilization
			scaleUpFactor:    1.5,
			scaleDownFactor:  0.8,
			history:         make([]UtilizationSnapshot, 0),
			predictions:     make([]UtilizationPrediction, 0),
		}
	}
	
	// Initialize metrics collector if enabled
	if config.MetricsEnabled {
		pool.metricsCollector = &MetricsCollector{
			enabled:    true,
			interval:   30 * time.Second,
			samples:    make([]MetricSample, 0),
			aggregated: &AggregatedMetrics{
				Counters:   make(map[string]int64),
				Gauges:     make(map[string]float64),
				Histograms: make(map[string][]float64),
				LastUpdate: time.Now(),
			},
		}
	}
	
	// Create initial connections
	if err := pool.initializeConnections(ctx, config.InitialSize); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize connections: %w", err)
	}
	
	// Start background processes
	pool.startBackgroundProcesses()
	
	// Warm up connections if enabled
	if config.WarmupEnabled && config.WarmupSize > 0 {
		go func() {
			time.Sleep(1 * time.Second) // Allow pool to stabilize
			if err := pool.Warm(ctx, config.WarmupSize); err != nil {
				log.Warn().Err(err).Msg("Connection pool warm-up failed")
			}
		}()
	}
	
	log.Info().
		Int("min_size", config.MinSize).
		Int("max_size", config.MaxSize).
		Int("initial_size", config.InitialSize).
		Msg("Container connection pool initialized")
	
	return pool, nil
}

// Get retrieves a connection from the pool
func (p *ContainerConnectionPool) Get(ctx context.Context) (*PooledConnection, error) {
	start := time.Now()
	atomic.AddInt64(&p.totalRequests, 1)
	
	// Try to get from available connections first
	select {
	case conn := <-p.availableConns:
		if conn.isHealthy() {
			p.mu.Lock()
			conn.inUse = true
			conn.LastUsedAt = time.Now()
			atomic.AddInt64(&conn.UsageCount, 1)
			p.busyConns[conn.ID] = conn
			atomic.AddInt64(&p.totalHits, 1)
			p.mu.Unlock()
			
			p.updateAcquisitionTime(time.Since(start))
			return conn, nil
		} else {
			// Connection is unhealthy, destroy and try again
			p.destroyConnection(conn)
			atomic.AddInt64(&p.totalMisses, 1)
		}
	default:
		atomic.AddInt64(&p.totalMisses, 1)
	}
	
	// Check if we can create a new connection
	p.mu.RLock()
	canCreate := len(p.connections) < p.config.MaxSize
	p.mu.RUnlock()
	
	if canCreate {
		conn, err := p.createConnection(ctx)
		if err != nil {
			atomic.AddInt64(&p.totalErrors, 1)
			return nil, fmt.Errorf("failed to create new connection: %w", err)
		}
		
		p.mu.Lock()
		conn.inUse = true
		conn.LastUsedAt = time.Now()
		atomic.AddInt64(&conn.UsageCount, 1)
		p.busyConns[conn.ID] = conn
		p.mu.Unlock()
		
		p.updateAcquisitionTime(time.Since(start))
		return conn, nil
	}
	
	// Wait for an available connection with timeout
	select {
	case conn := <-p.availableConns:
		if conn.isHealthy() {
			p.mu.Lock()
			conn.inUse = true
			conn.LastUsedAt = time.Now()
			atomic.AddInt64(&conn.UsageCount, 1)
			p.busyConns[conn.ID] = conn
			p.mu.Unlock()
			
			p.updateAcquisitionTime(time.Since(start))
			return conn, nil
		} else {
			p.destroyConnection(conn)
			return nil, errors.New("no healthy connections available")
		}
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(p.config.ConnectionTimeout):
		return nil, errors.New("connection acquisition timeout")
	}
}

// Put returns a connection to the pool
func (p *ContainerConnectionPool) Put(conn *PooledConnection) error {
	if conn == nil {
		return errors.New("connection is nil")
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Remove from busy connections
	delete(p.busyConns, conn.ID)
	conn.inUse = false
	
	// Check if connection should be recycled
	if p.shouldRecycleConnection(conn) {
		p.destroyConnection(conn)
		atomic.AddInt64(&p.totalRecycled, 1)
		
		// Try to create a replacement connection asynchronously
		go func() {
			ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
			defer cancel()
			
			if newConn, err := p.createConnection(ctx); err == nil {
				select {
				case p.availableConns <- newConn:
				case <-p.ctx.Done():
					p.destroyConnection(newConn)
				}
			}
		}()
		
		return nil
	}
	
	// Return to available connections
	select {
	case p.availableConns <- conn:
		return nil
	default:
		// Channel is full, destroy the connection
		p.destroyConnection(conn)
		return nil
	}
}

// Size returns current pool size statistics
func (p *ContainerConnectionPool) Size() PoolSizeInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	return PoolSizeInfo{
		MinSize:     p.config.MinSize,
		MaxSize:     p.config.MaxSize,
		CurrentSize: len(p.connections),
		ActiveSize:  len(p.busyConns),
		IdleSize:    len(p.availableConns),
		WaitingCount: 0, // TODO: Track waiting requests
	}
}

// Health performs health checks on all connections
func (p *ContainerConnectionPool) Health(ctx context.Context) (*PoolHealthReport, error) {
	report := &PoolHealthReport{
		Timestamp:        time.Now(),
		ConnectionHealth: make(map[string]*ConnectionHealth),
		Recommendations:  make([]string, 0),
		Metrics: &PoolHealthMetrics{},
	}
	
	p.mu.RLock()
	allConnections := make([]*PooledConnection, 0, len(p.connections))
	allConnections = append(allConnections, p.connections...)
	p.mu.RUnlock()
	
	report.TotalConnections = len(allConnections)
	
	var healthyCount, unhealthyCount int
	var totalResponseTime time.Duration
	var errorCount int64
	
	// Check each connection's health
	for _, conn := range allConnections {
		health := p.checkConnectionHealth(ctx, conn)
		report.ConnectionHealth[conn.ID] = health
		
		switch health.Status {
		case ConnectionHealthy:
			healthyCount++
		case ConnectionDegraded:
			healthyCount++ // Count as healthy but note degradation
		default:
			unhealthyCount++
			errorCount += health.ErrorCount
		}
		
		totalResponseTime += health.ResponseTime
	}
	
	report.HealthyCount = healthyCount
	report.UnhealthyCount = unhealthyCount
	
	// Calculate overall health status
	healthRatio := float64(healthyCount) / float64(report.TotalConnections)
	switch {
	case healthRatio >= 0.9:
		report.OverallHealth = HealthStatusHealthy
	case healthRatio >= 0.7:
		report.OverallHealth = HealthStatusDegraded
		report.Recommendations = append(report.Recommendations, 
			"Pool health is degraded - consider scaling up or investigating connection issues")
	default:
		report.OverallHealth = HealthStatusUnhealthy
		report.Recommendations = append(report.Recommendations, 
			"Pool health is critical - immediate attention required")
	}
	
	// Calculate metrics
	if report.TotalConnections > 0 {
		report.Metrics.AvgResponseTime = totalResponseTime / time.Duration(report.TotalConnections)
		report.Metrics.ErrorRate = float64(errorCount) / float64(report.TotalConnections)
	}
	
	// Store health check results
	p.healthChecker.mu.Lock()
	p.healthChecker.checkHistory = append(p.healthChecker.checkHistory, *report)
	if len(p.healthChecker.checkHistory) > 100 { // Keep last 100 reports
		p.healthChecker.checkHistory = p.healthChecker.checkHistory[1:]
	}
	p.healthChecker.mu.Unlock()
	
	return report, nil
}

// Warm pre-warms connections in the pool
func (p *ContainerConnectionPool) Warm(ctx context.Context, count int) error {
	log.Info().Int("count", count).Msg("Starting connection pool warm-up")
	
	warmed := 0
	for i := 0; i < count; i++ {
		conn, err := p.Get(ctx)
		if err != nil {
			log.Warn().Err(err).Int("warmed", warmed).Msg("Failed to warm connection")
			continue
		}
		
		// Perform a simple operation to warm the connection
		if err := p.warmConnection(ctx, conn); err != nil {
			log.Warn().Err(err).Str("conn_id", conn.ID).Msg("Failed to warm connection")
			p.Put(conn) // Still return it to pool
			continue
		}
		
		if err := p.Put(conn); err != nil {
			log.Warn().Err(err).Str("conn_id", conn.ID).Msg("Failed to return warmed connection")
			continue
		}
		
		warmed++
	}
	
	log.Info().Int("warmed", warmed).Int("requested", count).Msg("Connection pool warm-up completed")
	return nil
}

// Stats returns pool performance statistics
func (p *ContainerConnectionPool) Stats() *PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	stats := &PoolStats{
		TotalConnections:      int64(len(p.connections)),
		ActiveConnections:     int64(len(p.busyConns)),
		IdleConnections:      int64(len(p.availableConns)),
		CreatedConnections:   atomic.LoadInt64(&p.totalCreated),
		DestroyedConnections: atomic.LoadInt64(&p.totalDestroyed),
		RecycledConnections:  atomic.LoadInt64(&p.totalRecycled),
		AcquisitionTime:      p.stats.AcquisitionTime,
		LastStatsUpdate:      time.Now(),
		CollectionStartTime:  p.stats.CollectionStartTime,
	}
	
	// Calculate utilization rate
	if stats.TotalConnections > 0 {
		stats.UtilizationRate = float64(stats.ActiveConnections) / float64(stats.TotalConnections)
	}
	
	// Calculate hit/miss rates
	totalRequests := atomic.LoadInt64(&p.totalRequests)
	if totalRequests > 0 {
		stats.HitRate = float64(atomic.LoadInt64(&p.totalHits)) / float64(totalRequests)
		stats.MissRate = float64(atomic.LoadInt64(&p.totalMisses)) / float64(totalRequests)
	}
	
	// Calculate error rate
	totalErrors := atomic.LoadInt64(&p.totalErrors)
	if totalRequests > 0 {
		stats.ErrorRate = float64(totalErrors) / float64(totalRequests)
	}
	
	// Update internal stats
	p.stats.UtilizationRate = stats.UtilizationRate
	p.stats.HitRate = stats.HitRate
	p.stats.MissRate = stats.MissRate
	p.stats.ErrorRate = stats.ErrorRate
	p.stats.LastStatsUpdate = stats.LastStatsUpdate
	
	return stats
}

// Resize dynamically resizes the pool
func (p *ContainerConnectionPool) Resize(minSize, maxSize int) error {
	if minSize < 0 || maxSize < minSize {
		return errors.New("invalid pool size parameters")
	}
	
	p.mu.Lock()
	defer p.mu.Unlock()
	
	oldMin, oldMax := p.config.MinSize, p.config.MaxSize
	p.config.MinSize = minSize
	p.config.MaxSize = maxSize
	
	log.Info().
		Int("old_min", oldMin).Int("old_max", oldMax).
		Int("new_min", minSize).Int("new_max", maxSize).
		Msg("Resizing connection pool")
	
	// If we need to grow the pool
	currentSize := len(p.connections)
	if currentSize < minSize {
		needed := minSize - currentSize
		ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
		defer cancel()
		
		for i := 0; i < needed; i++ {
			conn, err := p.createConnection(ctx)
			if err != nil {
				log.Warn().Err(err).Int("created", i).Msg("Failed to create connection during resize")
				break
			}
			
			select {
			case p.availableConns <- conn:
			default:
				// Channel full, this shouldn't happen but handle it
				p.destroyConnection(conn)
				break
			}
		}
	}
	
	// If we need to shrink the pool (only shrink idle connections)
	if currentSize > maxSize {
		excess := currentSize - maxSize
		for i := 0; i < excess; i++ {
			select {
			case conn := <-p.availableConns:
				p.destroyConnection(conn)
			default:
				// No more idle connections to remove
				break
			}
		}
	}
	
	return nil
}

// Close gracefully shuts down the pool
func (p *ContainerConnectionPool) Close(ctx context.Context) error {
	log.Info().Msg("Shutting down connection pool")
	
	// Signal shutdown
	close(p.stopChan)
	p.cancel()
	
	// Wait for background processes to finish
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
	case <-ctx.Done():
		log.Warn().Msg("Connection pool shutdown timeout")
	}
	
	// Close all connections
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// Close available connections
	close(p.availableConns)
	for conn := range p.availableConns {
		p.destroyConnection(conn)
	}
	
	// Close busy connections (this might be aggressive)
	for _, conn := range p.busyConns {
		p.destroyConnection(conn)
	}
	
	log.Info().Msg("Connection pool shutdown complete")
	return nil
}

// Private methods

func (p *ContainerConnectionPool) initializeConnections(ctx context.Context, count int) error {
	for i := 0; i < count; i++ {
		conn, err := p.createConnection(ctx)
		if err != nil {
			return fmt.Errorf("failed to create initial connection %d: %w", i, err)
		}
		
		select {
		case p.availableConns <- conn:
		case <-ctx.Done():
			p.destroyConnection(conn)
			return ctx.Err()
		}
	}
	
	return nil
}

func (p *ContainerConnectionPool) createConnection(ctx context.Context) (*PooledConnection, error) {
	runtime, err := p.factory(ctx)
	if err != nil {
		return nil, err
	}
	
	conn := &PooledConnection{
		ID:           fmt.Sprintf("conn-%d", time.Now().UnixNano()),
		Runtime:      runtime,
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		IsHealthy:    true,
		Metadata:     make(map[string]interface{}),
		pool:         p,
		recycleAfter: p.config.RecycleThreshold,
		maxIdleTime:  p.config.MaxIdleTime,
		healthScore:  1.0,
	}
	
	p.mu.Lock()
	p.connections = append(p.connections, conn)
	p.mu.Unlock()
	
	atomic.AddInt64(&p.totalCreated, 1)
	
	log.Debug().
		Str("conn_id", conn.ID).
		Int("total_connections", len(p.connections)).
		Msg("Created new connection")
	
	return conn, nil
}

func (p *ContainerConnectionPool) destroyConnection(conn *PooledConnection) {
	if conn == nil {
		return
	}
	
	p.mu.Lock()
	// Remove from connections slice
	for i, c := range p.connections {
		if c.ID == conn.ID {
			p.connections = append(p.connections[:i], p.connections[i+1:]...)
			break
		}
	}
	// Remove from busy connections if present
	delete(p.busyConns, conn.ID)
	p.mu.Unlock()
	
	atomic.AddInt64(&p.totalDestroyed, 1)
	
	log.Debug().
		Str("conn_id", conn.ID).
		Int64("usage_count", conn.UsageCount).
		Msg("Destroyed connection")
}

func (p *ContainerConnectionPool) shouldRecycleConnection(conn *PooledConnection) bool {
	// Check usage count threshold
	if conn.UsageCount >= conn.recycleAfter {
		return true
	}
	
	// Check idle time
	if time.Since(conn.LastUsedAt) > conn.maxIdleTime {
		return true
	}
	
	// Check health score
	if conn.healthScore < 0.5 {
		return true
	}
	
	return false
}

func (p *ContainerConnectionPool) updateAcquisitionTime(duration time.Duration) {
	// Simple moving average
	current := p.stats.AcquisitionTime
	p.stats.AcquisitionTime = (current + duration) / 2
}

func (p *ContainerConnectionPool) startBackgroundProcesses() {
	// Health checker
	p.wg.Add(1)
	go p.healthCheckWorker()
	
	// Pool optimizer
	if p.optimizer != nil && p.optimizer.enabled {
		p.wg.Add(1)
		go p.optimizerWorker()
	}
	
	// Metrics collector
	if p.metricsCollector != nil && p.metricsCollector.enabled {
		p.wg.Add(1)
		go p.metricsWorker()
	}
	
	// Connection recycler
	p.wg.Add(1)
	go p.connectionRecyclerWorker()
}

func (p *ContainerConnectionPool) healthCheckWorker() {
	defer p.wg.Done()
	
	ticker := time.NewTicker(p.healthChecker.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(p.ctx, p.healthChecker.timeout)
			if _, err := p.Health(ctx); err != nil {
				log.Warn().Err(err).Msg("Health check failed")
			}
			cancel()
		}
	}
}

func (p *ContainerConnectionPool) optimizerWorker() {
	defer p.wg.Done()
	
	ticker := time.NewTicker(p.optimizer.adjustInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.optimizePoolSize()
		}
	}
}

func (p *ContainerConnectionPool) metricsWorker() {
	defer p.wg.Done()
	
	ticker := time.NewTicker(p.metricsCollector.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.collectMetrics()
		}
	}
}

func (p *ContainerConnectionPool) connectionRecyclerWorker() {
	defer p.wg.Done()
	
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.recycleIdleConnections()
		}
	}
}

func (p *ContainerConnectionPool) checkConnectionHealth(ctx context.Context, conn *PooledConnection) *ConnectionHealth {
	start := time.Now()
	health := &ConnectionHealth{
		ConnectionID:     conn.ID,
		LastHealthCheck:  start,
		Issues:          make([]string, 0),
	}
	
	// Perform basic health check
	// In a real implementation, this would test the actual connection
	// For now, we'll simulate based on connection age and usage
	
	age := time.Since(conn.CreatedAt)
	idleTime := time.Since(conn.LastUsedAt)
	
	health.ResponseTime = time.Since(start)
	
	// Calculate health score
	score := 1.0
	
	// Penalize old connections
	if age > 24*time.Hour {
		score -= 0.2
		health.Issues = append(health.Issues, "Connection is old")
	}
	
	// Penalize idle connections
	if idleTime > p.config.MaxIdleTime/2 {
		score -= 0.1
		health.Issues = append(health.Issues, "Connection has been idle")
	}
	
	// Penalize high usage
	if conn.UsageCount > p.config.RecycleThreshold/2 {
		score -= 0.1
		health.Issues = append(health.Issues, "High usage count")
	}
	
	health.HealthScore = score
	conn.healthScore = score
	
	// Determine status
	switch {
	case score >= 0.8:
		health.Status = ConnectionHealthy
		conn.IsHealthy = true
	case score >= 0.6:
		health.Status = ConnectionDegraded
		conn.IsHealthy = true
	default:
		health.Status = ConnectionUnhealthy
		conn.IsHealthy = false
	}
	
	return health
}

func (p *ContainerConnectionPool) warmConnection(ctx context.Context, conn *PooledConnection) error {
	// Perform a simple operation to warm the connection
	// This is a placeholder - in real implementation you'd perform actual operations
	time.Sleep(10 * time.Millisecond) // Simulate work
	return nil
}

func (p *ContainerConnectionPool) optimizePoolSize() {
	stats := p.Stats()
	
	snapshot := UtilizationSnapshot{
		Timestamp:    time.Now(),
		Utilization:  stats.UtilizationRate,
		ActiveConns:  int(stats.ActiveConnections),
		TotalConns:   int(stats.TotalConnections),
		ResponseTime: stats.AcquisitionTime,
	}
	
	p.optimizer.history = append(p.optimizer.history, snapshot)
	if len(p.optimizer.history) > 100 { // Keep last 100 snapshots
		p.optimizer.history = p.optimizer.history[1:]
	}
	
	// Simple optimization logic
	if stats.UtilizationRate > p.optimizer.utilizationHigh {
		// Scale up
		newSize := int(float64(p.config.MaxSize) * p.optimizer.scaleUpFactor)
		if newSize > p.config.MaxSize {
			newSize = int(float64(p.config.MaxSize) * 1.2) // 20% increase
			if newSize > 100 { // Hard limit
				newSize = 100
			}
		}
		
		if newSize > p.config.MaxSize {
			log.Info().
				Float64("utilization", stats.UtilizationRate).
				Int("current_max", p.config.MaxSize).
				Int("suggested_max", newSize).
				Msg("Pool optimization suggests scaling up")
			
			p.Resize(p.config.MinSize, newSize)
		}
	} else if stats.UtilizationRate < p.optimizer.utilizationLow {
		// Scale down (but not below current usage)
		newSize := int(float64(p.config.MaxSize) * p.optimizer.scaleDownFactor)
		if newSize < int(stats.ActiveConnections)+5 { // Keep some buffer
			newSize = int(stats.ActiveConnections) + 5
		}
		if newSize < p.config.MinSize {
			newSize = p.config.MinSize
		}
		
		if newSize < p.config.MaxSize {
			log.Info().
				Float64("utilization", stats.UtilizationRate).
				Int("current_max", p.config.MaxSize).
				Int("suggested_max", newSize).
				Msg("Pool optimization suggests scaling down")
			
			p.Resize(p.config.MinSize, newSize)
		}
	}
}

func (p *ContainerConnectionPool) collectMetrics() {
	stats := p.Stats()
	now := time.Now()
	
	metrics := []MetricSample{
		{Timestamp: now, Metric: "pool.total_connections", Value: float64(stats.TotalConnections)},
		{Timestamp: now, Metric: "pool.active_connections", Value: float64(stats.ActiveConnections)},
		{Timestamp: now, Metric: "pool.idle_connections", Value: float64(stats.IdleConnections)},
		{Timestamp: now, Metric: "pool.utilization_rate", Value: stats.UtilizationRate},
		{Timestamp: now, Metric: "pool.hit_rate", Value: stats.HitRate},
		{Timestamp: now, Metric: "pool.error_rate", Value: stats.ErrorRate},
		{Timestamp: now, Metric: "pool.acquisition_time_ms", Value: float64(stats.AcquisitionTime.Nanoseconds()) / 1e6},
	}
	
	p.metricsCollector.mu.Lock()
	p.metricsCollector.samples = append(p.metricsCollector.samples, metrics...)
	
	// Keep only recent samples (last 1000)
	if len(p.metricsCollector.samples) > 1000 {
		p.metricsCollector.samples = p.metricsCollector.samples[len(p.metricsCollector.samples)-1000:]
	}
	
	// Update aggregated metrics
	for _, metric := range metrics {
		switch metric.Metric {
		case "pool.total_connections", "pool.active_connections", "pool.idle_connections":
			p.metricsCollector.aggregated.Counters[metric.Metric] = int64(metric.Value)
		default:
			p.metricsCollector.aggregated.Gauges[metric.Metric] = metric.Value
		}
	}
	
	p.metricsCollector.aggregated.LastUpdate = now
	p.metricsCollector.mu.Unlock()
}

func (p *ContainerConnectionPool) recycleIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	recycled := 0
	
	// Check idle connections in the channel (non-blocking)
	for {
		select {
		case conn := <-p.availableConns:
			if p.shouldRecycleConnection(conn) {
				p.destroyConnection(conn)
				recycled++
				
				// Create replacement if needed
				if len(p.connections) < p.config.MinSize {
					go func() {
						ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
						defer cancel()
						
						if newConn, err := p.createConnection(ctx); err == nil {
							select {
							case p.availableConns <- newConn:
							case <-p.ctx.Done():
								p.destroyConnection(newConn)
							}
						}
					}()
				}
			} else {
				// Return connection to pool
				select {
				case p.availableConns <- conn:
				default:
					// Channel full, destroy connection
					p.destroyConnection(conn)
				}
			}
		default:
			// No more connections in channel
			goto done
		}
	}
	
done:
	if recycled > 0 {
		log.Info().Int("recycled", recycled).Msg("Recycled idle connections")
	}
}

// Connection methods

func (c *PooledConnection) isHealthy() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.IsHealthy
}

func (c *PooledConnection) GetID() string {
	return c.ID
}

func (c *PooledConnection) GetUsageCount() int64 {
	return atomic.LoadInt64(&c.UsageCount)
}

func (c *PooledConnection) GetAge() time.Duration {
	return time.Since(c.CreatedAt)
}

func (c *PooledConnection) GetIdleTime() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.LastUsedAt)
}

func (c *PooledConnection) SetMetadata(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Metadata[key] = value
}

func (c *PooledConnection) GetMetadata(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	value, exists := c.Metadata[key]
	return value, exists
}

// GetRuntime returns the underlying runtime interface
func (c *PooledConnection) GetRuntime() RuncInterface {
	return c.Runtime
}