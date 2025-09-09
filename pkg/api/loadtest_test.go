package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// LoadTestConfig holds configuration for load tests
type LoadTestConfig struct {
	Duration       time.Duration
	Concurrency    int
	RequestsPerSec int
	RampUpTime     time.Duration
}

// LoadTestResults holds results from load testing
type LoadTestResults struct {
	TotalRequests      int64
	SuccessfulRequests int64
	FailedRequests     int64
	AverageLatency     time.Duration
	MinLatency         time.Duration
	MaxLatency         time.Duration
	RequestsPerSecond  float64
	ErrorRate          float64
	Duration           time.Duration
	ErrorsByType       map[string]int64
}

// TestLoadTesting_HTTPServer tests HTTP server under load
func TestLoadTesting_HTTPServer(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	
	config := LoadTestConfig{
		Duration:       30 * time.Second,
		Concurrency:    50,
		RequestsPerSec: 100,
		RampUpTime:     5 * time.Second,
	}
	
	// Create test server
	httpServer := createTestHTTPServer(nil)
	server := httptest.NewServer(httpServer.GetRouter())
	defer server.Close()
	
	results := runLoadTest(t, server.URL, config)
	
	// Verify results
	assert.Greater(t, results.TotalRequests, int64(0))
	assert.Greater(t, results.SuccessfulRequests, int64(0))
	assert.Less(t, results.ErrorRate, 0.05) // Less than 5% error rate
	assert.Greater(t, results.RequestsPerSecond, 0.0)
	
	t.Logf("Load test results:")
	t.Logf("  Total requests: %d", results.TotalRequests)
	t.Logf("  Successful requests: %d", results.SuccessfulRequests)
	t.Logf("  Failed requests: %d", results.FailedRequests)
	t.Logf("  Error rate: %.2f%%", results.ErrorRate*100)
	t.Logf("  Requests per second: %.2f", results.RequestsPerSecond)
	t.Logf("  Average latency: %v", results.AverageLatency)
	t.Logf("  Min latency: %v", results.MinLatency)
	t.Logf("  Max latency: %v", results.MaxLatency)
}

// TestLoadTesting_RESTAPIEndpoints tests REST API endpoints under load
func TestLoadTesting_RESTAPIEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	
	// Create test API with mock data
	api, mockManager := createTestRESTAPI(nil)
	
	// Setup mock responses
	sandboxes := generateMockSandboxes(100)
	mockManager.On("ListSandboxes", mock.Anything).Return(sandboxes, nil)
	mockManager.On("GetSandbox", mock.Anything, mock.AnythingOfType("string")).Return(sandboxes[0], nil)
	
	// Add tools to registry
	listTool := &MockTool{name: "list_files"}
	listTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text: `[{"name": "file1.txt", "size": 100}]`,
	}, nil)
	api.toolRegistry.RegisterTool(listTool)
	
	server := httptest.NewServer(api.router)
	defer server.Close()
	
	// Test different endpoints concurrently
	endpoints := []string{
		"/api/v1/sandboxes",
		"/api/v1/sandboxes/sb1",
		"/api/v1/sandboxes/sb1/files",
		"/api/v1/tools",
	}
	
	config := LoadTestConfig{
		Duration:    10 * time.Second,
		Concurrency: 20,
		RampUpTime:  2 * time.Second,
	}
	
	var wg sync.WaitGroup
	results := make([]*LoadTestResults, len(endpoints))
	
	for i, endpoint := range endpoints {
		wg.Add(1)
		go func(i int, endpoint string) {
			defer wg.Done()
			results[i] = runLoadTestForEndpoint(t, server.URL+endpoint, config)
		}(i, endpoint)
	}
	
	wg.Wait()
	
	// Verify all endpoints performed well
	for i, result := range results {
		t.Logf("Endpoint %s:", endpoints[i])
		t.Logf("  Requests/sec: %.2f", result.RequestsPerSecond)
		t.Logf("  Error rate: %.2f%%", result.ErrorRate*100)
		t.Logf("  Avg latency: %v", result.AverageLatency)
		
		assert.Greater(t, result.RequestsPerSecond, 10.0, "Endpoint %s too slow", endpoints[i])
		assert.Less(t, result.ErrorRate, 0.1, "Endpoint %s error rate too high", endpoints[i])
	}
}

// TestLoadTesting_WebSocketConnections tests WebSocket connections under load
func TestLoadTesting_WebSocketConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	
	httpServer := createTestHTTPServer(nil)
	server := httptest.NewServer(httpServer.GetRouter())
	defer server.Close()
	
	wsURL := "ws" + server.URL[4:] + "/mcp/ws"
	
	concurrency := 50
	duration := 10 * time.Second
	
	var (
		connectionsEstablished int64
		connectionsFailed      int64
		messagesExchanged      int64
	)
	
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	var wg sync.WaitGroup
	
	// Launch concurrent WebSocket connections
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
			if err != nil {
				atomic.AddInt64(&connectionsFailed, 1)
				return
			}
			defer conn.Close()
			
			atomic.AddInt64(&connectionsEstablished, 1)
			
			// Send periodic messages
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					message := map[string]interface{}{
						"jsonrpc": "2.0",
						"method":  "ping",
						"id":      fmt.Sprintf("%d_%d", id, time.Now().UnixNano()),
					}
					
					if err := conn.WriteJSON(message); err != nil {
						return
					}
					
					// Try to read response with short timeout
					conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					var response map[string]interface{}
					if conn.ReadJSON(&response) == nil {
						atomic.AddInt64(&messagesExchanged, 1)
					}
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	t.Logf("WebSocket load test results:")
	t.Logf("  Connections established: %d/%d", connectionsEstablished, concurrency)
	t.Logf("  Connections failed: %d", connectionsFailed)
	t.Logf("  Messages exchanged: %d", messagesExchanged)
	
	// Verify acceptable connection success rate
	successRate := float64(connectionsEstablished) / float64(concurrency)
	assert.Greater(t, successRate, 0.8, "WebSocket connection success rate too low")
}

// TestLoadTesting_ConcurrentSandboxOperations tests concurrent sandbox operations
func TestLoadTesting_ConcurrentSandboxOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	
	api, mockManager := createTestRESTAPI(nil)
	
	// Setup mock responses for CRUD operations
	testSandbox := &sandbox.Sandbox{
		ID:          "load-test-sb",
		ContainerID: "container-load-test",
		Status:      sandbox.SandboxStatusRunning,
		WorkingDir:  "/tmp/load-test",
		Environment: map[string]string{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Config: sandbox.SandboxConfig{
			Image: "ubuntu:22.04",
		},
		Metadata: map[string]interface{}{"name": "load-test-sandbox"},
	}
	
	mockManager.On("ListSandboxes", mock.Anything).Return([]*sandbox.Sandbox{testSandbox}, nil)
	mockManager.On("GetSandbox", mock.Anything, mock.AnythingOfType("string")).Return(testSandbox, nil)
	
	// Add tools
	createTool := &MockTool{name: "create_sandbox"}
	createTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text: `{"id": "new-sandbox"}`,
	}, nil)
	api.toolRegistry.RegisterTool(createTool)
	
	terminateTool := &MockTool{name: "terminate_sandbox"}
	terminateTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text: "terminated",
	}, nil)
	api.toolRegistry.RegisterTool(terminateTool)
	
	server := httptest.NewServer(api.router)
	defer server.Close()
	
	concurrency := 20
	duration := 5 * time.Second
	
	var (
		listOperations   int64
		getOperations    int64
		createOperations int64
		deleteOperations int64
		errors           int64
	)
	
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	
	var wg sync.WaitGroup
	
	// Launch concurrent operations
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			
			client := &http.Client{Timeout: 5 * time.Second}
			
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Randomly choose operation
					switch id % 4 {
					case 0: // List sandboxes
						resp, err := client.Get(server.URL + "/api/v1/sandboxes")
						if err != nil || resp.StatusCode != http.StatusOK {
							atomic.AddInt64(&errors, 1)
						} else {
							atomic.AddInt64(&listOperations, 1)
						}
						if resp != nil {
							resp.Body.Close()
						}
						
					case 1: // Get sandbox
						resp, err := client.Get(server.URL + "/api/v1/sandboxes/test-id")
						if err != nil || resp.StatusCode != http.StatusOK {
							atomic.AddInt64(&errors, 1)
						} else {
							atomic.AddInt64(&getOperations, 1)
						}
						if resp != nil {
							resp.Body.Close()
						}
						
					case 2: // Create sandbox
						createReq := CreateSandboxRequest{
							Image: "ubuntu:22.04",
							Name:  fmt.Sprintf("load-test-%d", id),
						}
						jsonBody, _ := json.Marshal(createReq)
						
						resp, err := client.Post(server.URL+"/api/v1/sandboxes", "application/json", bytes.NewReader(jsonBody))
						if err != nil || resp.StatusCode != http.StatusCreated {
							atomic.AddInt64(&errors, 1)
						} else {
							atomic.AddInt64(&createOperations, 1)
						}
						if resp != nil {
							resp.Body.Close()
						}
						
					case 3: // Delete sandbox
						req, _ := http.NewRequest("DELETE", server.URL+"/api/v1/sandboxes/test-id", nil)
						resp, err := client.Do(req)
						if err != nil || resp.StatusCode != http.StatusNoContent {
							atomic.AddInt64(&errors, 1)
						} else {
							atomic.AddInt64(&deleteOperations, 1)
						}
						if resp != nil {
							resp.Body.Close()
						}
					}
					
					time.Sleep(10 * time.Millisecond) // Small delay between operations
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	totalOperations := listOperations + getOperations + createOperations + deleteOperations
	errorRate := float64(errors) / float64(totalOperations+errors)
	
	t.Logf("Concurrent operations results:")
	t.Logf("  List operations: %d", listOperations)
	t.Logf("  Get operations: %d", getOperations)
	t.Logf("  Create operations: %d", createOperations)
	t.Logf("  Delete operations: %d", deleteOperations)
	t.Logf("  Total operations: %d", totalOperations)
	t.Logf("  Errors: %d", errors)
	t.Logf("  Error rate: %.2f%%", errorRate*100)
	
	assert.Greater(t, totalOperations, int64(100), "Too few operations performed")
	assert.Less(t, errorRate, 0.05, "Error rate too high")
}

// TestLoadTesting_MemoryUsage tests memory usage under load
func TestLoadTesting_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}
	
	// This test would need proper memory profiling tools
	// For now, it's a placeholder that demonstrates how such tests could be structured
	
	api, mockManager := createTestRESTAPI(nil)
	
	// Generate large dataset
	sandboxes := generateMockSandboxes(1000)
	mockManager.On("ListSandboxes", mock.Anything).Return(sandboxes, nil)
	
	server := httptest.NewServer(api.router)
	defer server.Close()
	
	// Perform many requests to test memory usage
	client := &http.Client{Timeout: 10 * time.Second}
	
	for i := 0; i < 100; i++ {
		resp, err := client.Get(server.URL + "/api/v1/sandboxes")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}
	
	// In a real implementation, you would:
	// 1. Collect memory statistics before/after
	// 2. Check for memory leaks
	// 3. Verify GC behavior
	// 4. Monitor goroutine counts
}

// Helper functions

func runLoadTest(t *testing.T, baseURL string, config LoadTestConfig) *LoadTestResults {
	return runLoadTestForEndpoint(t, baseURL+"/health", config)
}

func runLoadTestForEndpoint(t *testing.T, url string, config LoadTestConfig) *LoadTestResults {
	var (
		totalRequests      int64
		successfulRequests int64
		failedRequests     int64
		totalLatency       int64
		minLatency         int64 = 9999999999 // Initialize to large value
		maxLatency         int64
		errorsByType       = make(map[string]int64)
		errorsByTypeMutex  sync.RWMutex
	)
	
	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), config.Duration)
	defer cancel()
	
	// Rate limiter for requests per second
	requestInterval := time.Second / time.Duration(config.RequestsPerSec)
	ticker := time.NewTicker(requestInterval)
	defer ticker.Stop()
	
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, config.Concurrency)
	
	// Ramp up gradually
	rampUpTicker := time.NewTicker(config.RampUpTime / time.Duration(config.Concurrency))
	defer rampUpTicker.Stop()
	
	activeWorkers := 0
	
	requestLoop:
	for {
		select {
		case <-ctx.Done():
			break requestLoop
		case <-ticker.C:
			// Ramp up control
			if activeWorkers < config.Concurrency {
				select {
				case <-rampUpTicker.C:
					activeWorkers++
				default:
				}
			}
			
			if activeWorkers == 0 {
				continue
			}
			
			select {
			case semaphore <- struct{}{}:
				wg.Add(1)
				go func() {
					defer func() {
						<-semaphore
						wg.Done()
					}()
					
					start := time.Now()
					resp, err := http.Get(url)
					latency := time.Since(start).Nanoseconds()
					
					atomic.AddInt64(&totalRequests, 1)
					atomic.AddInt64(&totalLatency, latency)
					
					// Update min/max latency
					for {
						current := atomic.LoadInt64(&minLatency)
						if latency >= current || atomic.CompareAndSwapInt64(&minLatency, current, latency) {
							break
						}
					}
					for {
						current := atomic.LoadInt64(&maxLatency)
						if latency <= current || atomic.CompareAndSwapInt64(&maxLatency, current, latency) {
							break
						}
					}
					
					if err != nil {
						atomic.AddInt64(&failedRequests, 1)
						
						errorsByTypeMutex.Lock()
						errorsByType["network_error"]++
						errorsByTypeMutex.Unlock()
					} else {
						defer resp.Body.Close()
						
						if resp.StatusCode >= 200 && resp.StatusCode < 300 {
							atomic.AddInt64(&successfulRequests, 1)
						} else {
							atomic.AddInt64(&failedRequests, 1)
							
							errorsByTypeMutex.Lock()
							errorsByType[fmt.Sprintf("http_%d", resp.StatusCode)]++
							errorsByTypeMutex.Unlock()
						}
					}
				}()
			default:
				// Skip request if too many concurrent requests
			}
		}
	}
	
	wg.Wait()
	duration := time.Since(startTime)
	
	avgLatency := time.Duration(totalLatency / max(totalRequests, 1))
	requestsPerSec := float64(totalRequests) / duration.Seconds()
	errorRate := float64(failedRequests) / float64(max(totalRequests, 1))
	
	return &LoadTestResults{
		TotalRequests:      totalRequests,
		SuccessfulRequests: successfulRequests,
		FailedRequests:     failedRequests,
		AverageLatency:     avgLatency,
		MinLatency:         time.Duration(minLatency),
		MaxLatency:         time.Duration(maxLatency),
		RequestsPerSecond:  requestsPerSec,
		ErrorRate:          errorRate,
		Duration:           duration,
		ErrorsByType:       errorsByType,
	}
}

func generateMockSandboxes(count int) []*sandbox.Sandbox {
	sandboxes := make([]*sandbox.Sandbox, count)
	statuses := []sandbox.SandboxStatus{
		sandbox.SandboxStatusCreating,
		sandbox.SandboxStatusRunning,
		sandbox.SandboxStatusStopped,
	}
	images := []string{"ubuntu:22.04", "python:3.9", "node:18", "golang:1.19"}
	
	for i := 0; i < count; i++ {
		sandboxes[i] = &sandbox.Sandbox{
			ID:          fmt.Sprintf("sb%d", i+1),
			ContainerID: fmt.Sprintf("container-sb%d", i+1),
			Status:      statuses[i%len(statuses)],
			WorkingDir:  fmt.Sprintf("/tmp/sb%d", i+1),
			Environment: map[string]string{},
			CreatedAt:   time.Now().Add(-time.Duration(i) * time.Minute),
			UpdatedAt:   time.Now(),
			Config: sandbox.SandboxConfig{
				Image: images[i%len(images)],
			},
			Metadata: map[string]interface{}{
				"name": fmt.Sprintf("sandbox-%d", i+1),
			},
		}
	}
	
	return sandboxes
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// Benchmark tests for performance measurement

// BenchmarkAPI_ListSandboxes benchmarks the list sandboxes endpoint
func BenchmarkAPI_ListSandboxes(b *testing.B) {
	api, mockManager := createTestRESTAPI(nil)
	
	sandboxes := generateMockSandboxes(100)
	mockManager.On("ListSandboxes", mock.Anything).Return(sandboxes, nil)
	
	req := httptest.NewRequest("GET", "/api/v1/sandboxes", nil)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			api.router.ServeHTTP(w, req)
		}
	})
}

// BenchmarkAPI_CreateSandbox benchmarks sandbox creation
func BenchmarkAPI_CreateSandbox(b *testing.B) {
	api, _ := createTestRESTAPI(nil)
	
	createTool := &MockTool{name: "create_sandbox"}
	createTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text: `{"id": "new-sandbox"}`,
	}, nil)
	api.toolRegistry.RegisterTool(createTool)
	
	createReq := CreateSandboxRequest{
		Image: "ubuntu:22.04",
		Name:  "benchmark-sandbox",
	}
	jsonBody, _ := json.Marshal(createReq)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("POST", "/api/v1/sandboxes", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			
			w := httptest.NewRecorder()
			api.router.ServeHTTP(w, req)
		}
	})
}

// BenchmarkAPI_QueryParsing benchmarks query parameter parsing
func BenchmarkAPI_QueryParsing(b *testing.B) {
	api, _ := createTestRESTAPI(nil)
	
	values := map[string][]string{
		"page_size":     {"50"},
		"page_offset":   {"100"},
		"sort_by":       {"name"},
		"sort_order":    {"desc"},
		"filter_status": {"running"},
		"filter_image":  {"ubuntu"},
		"filter_name":   {"test"},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		api.parseQueryParams(values)
	}
}

// BenchmarkAPI_JSONMarshaling benchmarks JSON response marshaling
func BenchmarkAPI_JSONMarshaling(b *testing.B) {
	sandboxes := generateMockSandboxes(100)
	restSandboxes := make([]SandboxResponse, len(sandboxes))
	
	for i, sb := range sandboxes {
		restSandboxes[i] = SandboxResponse{
			ID:        sb.ID,
			Name:      sb.Metadata["name"].(string),
			Image:     sb.Config.Image,
			Status:    string(sb.Status),
			CreatedAt: sb.CreatedAt,
			UpdatedAt: sb.UpdatedAt,
		}
	}
	
	response := ListResponse{
		Data:      restSandboxes,
		Total:     len(restSandboxes),
		Timestamp: time.Now(),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		json.Marshal(response)
	}
}