package runtime

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/beam-cloud/go-runc"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockRuncInterfaceForPool implements RuncInterface for testing
type MockRuncInterfaceForPool struct {
	mock.Mock
}

func (m *MockRuncInterfaceForPool) State(ctx context.Context, id string) (*runc.Container, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(*runc.Container), args.Error(1)
}

func (m *MockRuncInterfaceForPool) Exec(ctx context.Context, id string, spec specs.Process, opts *runc.ExecOpts) error {
	args := m.Called(ctx, id, spec, opts)
	return args.Error(0)
}

func (m *MockRuncInterfaceForPool) Create(ctx context.Context, id, bundle string, opts *runc.CreateOpts) error {
	args := m.Called(ctx, id, bundle, opts)
	return args.Error(0)
}

func (m *MockRuncInterfaceForPool) Start(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRuncInterfaceForPool) Kill(ctx context.Context, id string, sig int, opts *runc.KillOpts) error {
	args := m.Called(ctx, id, sig, opts)
	return args.Error(0)
}

func (m *MockRuncInterfaceForPool) Delete(ctx context.Context, id string, opts *runc.DeleteOpts) error {
	args := m.Called(ctx, id, opts)
	return args.Error(0)
}

func (m *MockRuncInterfaceForPool) List(ctx context.Context) ([]*runc.Container, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*runc.Container), args.Error(1)
}

// Test helpers

func createMockConnectionFactory() ConnectionFactory {
	return func(ctx context.Context) (RuncInterface, error) {
		mockRuntime := new(MockRuncInterfaceForPool)
		// Set up basic expectations for health checks
		mockRuntime.On("State", mock.Anything, mock.Anything).Return(&runc.Container{}, nil).Maybe()
		return mockRuntime, nil
	}
}

func TestNewConnectionPool(t *testing.T) {
	tests := []struct {
		name      string
		config    *PoolConfig
		factory   ConnectionFactory
		wantError bool
	}{
		{
			name:      "Valid configuration",
			config:    DefaultPoolConfig(),
			factory:   createMockConnectionFactory(),
			wantError: false,
		},
		{
			name:      "Nil configuration uses default",
			config:    nil,
			factory:   createMockConnectionFactory(),
			wantError: false,
		},
		{
			name:      "Nil factory returns error",
			config:    DefaultPoolConfig(),
			factory:   nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := NewConnectionPool(tt.config, tt.factory)
			
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, pool)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pool)
				
				// Clean up
				if pool != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					pool.Close(ctx)
				}
			}
		})
	}
}

func TestConnectionPool_GetAndPut(t *testing.T) {
	config := &PoolConfig{
		MinSize:             2,
		MaxSize:             5,
		InitialSize:         2,
		MaxIdleTime:         1 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		ConnectionTimeout:   5 * time.Second,
		RecycleThreshold:    100,
		WarmupEnabled:       false,
		AdaptiveSizing:      false,
		MetricsEnabled:      true,
	}

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	ctx := context.Background()

	// Test getting a connection
	conn1, err := pool.Get(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, conn1)
	assert.True(t, conn1.isHealthy())

	// Test putting it back
	err = pool.Put(conn1)
	assert.NoError(t, err)

	// Test getting another connection (should reuse)
	conn2, err := pool.Get(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, conn2)
	
	// Could be the same connection reused
	if conn1.ID == conn2.ID {
		assert.Greater(t, conn2.GetUsageCount(), int64(0))
	}

	err = pool.Put(conn2)
	assert.NoError(t, err)
}

func TestConnectionPool_ConcurrentAccess(t *testing.T) {
	config := &PoolConfig{
		MinSize:             5,
		MaxSize:             20,
		InitialSize:         5,
		MaxIdleTime:         1 * time.Minute,
		HealthCheckInterval: 30 * time.Second,
		ConnectionTimeout:   5 * time.Second,
		RecycleThreshold:    100,
		WarmupEnabled:       false,
		AdaptiveSizing:      false,
		MetricsEnabled:      true,
	}

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	const numGoroutines = 50
	const operationsPerGoroutine = 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*operationsPerGoroutine)

	// Start multiple goroutines that get and put connections
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				
				conn, err := pool.Get(ctx)
				if err != nil {
					errors <- err
					cancel()
					continue
				}
				
				// Simulate some work
				time.Sleep(1 * time.Millisecond)
				
				if err := pool.Put(conn); err != nil {
					errors <- err
				}
				
				cancel()
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}

	// Verify pool statistics
	stats := pool.Stats()
	assert.Greater(t, stats.TotalConnections, int64(0))
	assert.GreaterOrEqual(t, stats.CreatedConnections, int64(config.InitialSize))
}

func TestConnectionPool_Size(t *testing.T) {
	config := DefaultPoolConfig()
	config.InitialSize = 3

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	// Wait a moment for initialization
	time.Sleep(100 * time.Millisecond)

	size := pool.Size()
	assert.Equal(t, config.MinSize, size.MinSize)
	assert.Equal(t, config.MaxSize, size.MaxSize)
	assert.GreaterOrEqual(t, size.CurrentSize, config.InitialSize)
	assert.GreaterOrEqual(t, size.IdleSize, 0)
}

func TestConnectionPool_Health(t *testing.T) {
	config := DefaultPoolConfig()
	config.InitialSize = 3

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	// Wait for initialization
	time.Sleep(100 * time.Millisecond)

	ctx := context.Background()
	report, err := pool.Health(ctx)
	
	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Greater(t, report.TotalConnections, 0)
	assert.NotEmpty(t, report.ConnectionHealth)
	assert.NotZero(t, report.Timestamp)
}

func TestConnectionPool_Warm(t *testing.T) {
	config := DefaultPoolConfig()
	config.WarmupEnabled = false // Disable automatic warmup

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	ctx := context.Background()
	warmCount := 3
	
	err = pool.Warm(ctx, warmCount)
	assert.NoError(t, err)

	// Verify that connections were warmed (this is a simplified check)
	stats := pool.Stats()
	assert.GreaterOrEqual(t, stats.TotalConnections, int64(warmCount))
}

func TestConnectionPool_Stats(t *testing.T) {
	config := DefaultPoolConfig()
	config.MetricsEnabled = true

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	// Wait for initialization
	time.Sleep(100 * time.Millisecond)

	stats := pool.Stats()
	assert.NotNil(t, stats)
	assert.GreaterOrEqual(t, stats.TotalConnections, int64(0))
	assert.GreaterOrEqual(t, stats.CreatedConnections, int64(0))
	assert.NotZero(t, stats.LastStatsUpdate)
	assert.NotZero(t, stats.CollectionStartTime)
}

func TestConnectionPool_Resize(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinSize = 2
	config.MaxSize = 10
	config.InitialSize = 5

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	// Wait for initialization
	time.Sleep(200 * time.Millisecond)

	// Test resize up
	err = pool.Resize(5, 20)
	assert.NoError(t, err)

	size := pool.Size()
	assert.Equal(t, 5, size.MinSize)
	assert.Equal(t, 20, size.MaxSize)

	// Test resize down
	err = pool.Resize(2, 8)
	assert.NoError(t, err)

	size = pool.Size()
	assert.Equal(t, 2, size.MinSize)
	assert.Equal(t, 8, size.MaxSize)

	// Test invalid resize
	err = pool.Resize(-1, 5)
	assert.Error(t, err)

	err = pool.Resize(10, 5)
	assert.Error(t, err)
}

func TestConnectionPool_ConnectionRecycling(t *testing.T) {
	config := &PoolConfig{
		MinSize:             2,
		MaxSize:             5,
		InitialSize:         2,
		MaxIdleTime:         100 * time.Millisecond, // Very short idle time
		HealthCheckInterval: 50 * time.Millisecond,
		ConnectionTimeout:   5 * time.Second,
		RecycleThreshold:    2, // Low threshold for testing
		WarmupEnabled:       false,
		AdaptiveSizing:      false,
		MetricsEnabled:      true,
	}

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	ctx := context.Background()

	// Get and use a connection multiple times to trigger recycling
	for i := 0; i < 5; i++ {
		conn, err := pool.Get(ctx)
		require.NoError(t, err)
		
		// Simulate work
		time.Sleep(10 * time.Millisecond)
		
		err = pool.Put(conn)
		require.NoError(t, err)
	}

	// Wait for recycling to potentially happen
	time.Sleep(200 * time.Millisecond)

	stats := pool.Stats()
	// At least some connections should have been created
	assert.GreaterOrEqual(t, stats.CreatedConnections, int64(config.InitialSize))
}

func TestConnectionPool_Close(t *testing.T) {
	config := DefaultPoolConfig()
	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	// Wait for initialization
	time.Sleep(100 * time.Millisecond)

	// Get some connections to make them busy
	ctx := context.Background()
	conn1, err := pool.Get(ctx)
	require.NoError(t, err)
	
	conn2, err := pool.Get(ctx)
	require.NoError(t, err)

	// Close the pool
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	err = pool.Close(closeCtx)
	assert.NoError(t, err)

	// Verify that further operations fail or timeout
	_, err = pool.Get(ctx)
	assert.Error(t, err)

	// Clean up the connections we got before closing
	pool.Put(conn1) // These might error, which is expected
	pool.Put(conn2)
}

func TestPooledConnection_Methods(t *testing.T) {
	config := DefaultPoolConfig()
	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(t, err)
	require.NotNil(t, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	ctx := context.Background()
	conn, err := pool.Get(ctx)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Test connection methods
	assert.NotEmpty(t, conn.GetID())
	assert.GreaterOrEqual(t, conn.GetUsageCount(), int64(1))
	assert.GreaterOrEqual(t, conn.GetAge(), time.Duration(0))
	assert.GreaterOrEqual(t, conn.GetIdleTime(), time.Duration(0))
	assert.True(t, conn.isHealthy())
	assert.NotNil(t, conn.GetRuntime())

	// Test metadata
	conn.SetMetadata("test_key", "test_value")
	value, exists := conn.GetMetadata("test_key")
	assert.True(t, exists)
	assert.Equal(t, "test_value", value)

	_, exists = conn.GetMetadata("nonexistent_key")
	assert.False(t, exists)

	err = pool.Put(conn)
	assert.NoError(t, err)
}

func BenchmarkConnectionPool_GetPut(b *testing.B) {
	config := &PoolConfig{
		MinSize:             10,
		MaxSize:             100,
		InitialSize:         50,
		MaxIdleTime:         1 * time.Hour,
		HealthCheckInterval: 1 * time.Hour, // Disable for benchmark
		ConnectionTimeout:   5 * time.Second,
		RecycleThreshold:    10000,
		WarmupEnabled:       false,
		AdaptiveSizing:      false,
		MetricsEnabled:      false, // Disable for benchmark
	}

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(b, err)
	require.NotNil(b, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	// Wait for initialization
	time.Sleep(200 * time.Millisecond)

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := pool.Get(ctx)
			if err != nil {
				b.Errorf("Get failed: %v", err)
				continue
			}

			err = pool.Put(conn)
			if err != nil {
				b.Errorf("Put failed: %v", err)
			}
		}
	})
}

func BenchmarkConnectionPool_ConcurrentAccess(b *testing.B) {
	config := &PoolConfig{
		MinSize:             20,
		MaxSize:             200,
		InitialSize:         100,
		MaxIdleTime:         1 * time.Hour,
		HealthCheckInterval: 1 * time.Hour, // Disable for benchmark
		ConnectionTimeout:   5 * time.Second,
		RecycleThreshold:    100000,
		WarmupEnabled:       false,
		AdaptiveSizing:      false,
		MetricsEnabled:      false, // Disable for benchmark
	}

	pool, err := NewConnectionPool(config, createMockConnectionFactory())
	require.NoError(b, err)
	require.NotNil(b, pool)

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pool.Close(ctx)
	}()

	// Wait for initialization
	time.Sleep(500 * time.Millisecond)

	ctx := context.Background()

	b.ResetTimer()
	b.SetParallelism(10) // Simulate 10 concurrent workers
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := pool.Get(ctx)
			if err != nil {
				b.Errorf("Get failed: %v", err)
				continue
			}

			// Simulate some work
			time.Sleep(10 * time.Microsecond)

			err = pool.Put(conn)
			if err != nil {
				b.Errorf("Put failed: %v", err)
			}
		}
	})
}