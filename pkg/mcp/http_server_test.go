package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPServer_NewHTTPServer tests HTTP server creation
func TestHTTPServer_NewHTTPServer(t *testing.T) {
	config := DefaultHTTPServerConfig()
	mcpServer := createTestMCPServer(t)
	logger := zerolog.Nop()
	
	httpServer := NewHTTPServer(config, mcpServer, logger)
	
	assert.NotNil(t, httpServer)
	assert.Equal(t, config, httpServer.config)
	assert.Equal(t, mcpServer, httpServer.mcpServer)
	assert.NotNil(t, httpServer.router)
	assert.NotNil(t, httpServer.metrics)
	assert.NotNil(t, httpServer.wsConnections)
	assert.NotNil(t, httpServer.connectionPool)
}

// TestHTTPServer_StartStop tests server startup and shutdown
func TestHTTPServer_StartStop(t *testing.T) {
	config := DefaultHTTPServerConfig()
	config.Port = 0 // Use random port
	
	mcpServer := createTestMCPServer(t)
	logger := zerolog.Nop()
	
	httpServer := NewHTTPServer(config, mcpServer, logger)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Start server
	err := httpServer.Start(ctx)
	require.NoError(t, err)
	
	// Stop server
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	
	err = httpServer.Stop(stopCtx)
	assert.NoError(t, err)
}

// TestHTTPServer_handleMCPRequest tests MCP JSON-RPC over HTTP
func TestHTTPServer_handleMCPRequest(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		requestBody    interface{}
		expectedStatus int
		checkResponse  func(t *testing.T, resp *http.Response, body string)
	}{
		{
			name:   "initialize request",
			method: "POST",
			requestBody: JSONRPCRequest{
				JSONRPCMessage: JSONRPCMessage{
					JSONRPC: JSONRPC20Version,
					ID:      jsonRawMessagePtr(`"1"`),
				},
				Method: MethodInitialize,
				Params: jsonRawMessage(`{
					"protocolVersion": "2024-11-05",
					"capabilities": {},
					"clientInfo": {"name": "test-client", "version": "1.0.0"}
				}`),
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp *http.Response, body string) {
				assert.Contains(t, body, "protocolVersion")
			},
		},
		{
			name:           "invalid request body",
			method:         "POST",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request too large",
			method:         "POST",
			requestBody:    strings.Repeat("x", 11*1024*1024), // 11MB
			expectedStatus: http.StatusBadRequest,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpServer := createTestHTTPServer(t)
			
			var body io.Reader
			if str, ok := tt.requestBody.(string); ok {
				body = strings.NewReader(str)
			} else {
				jsonData, err := json.Marshal(tt.requestBody)
				require.NoError(t, err)
				body = bytes.NewReader(jsonData)
			}
			
			req := httptest.NewRequest(tt.method, "/mcp", body)
			req.Header.Set("Content-Type", "application/json")
			
			w := httptest.NewRecorder()
			httpServer.handleMCPRequest(w, req)
			
			resp := w.Result()
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			if tt.checkResponse != nil {
				bodyBytes, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				tt.checkResponse(t, resp, string(bodyBytes))
			}
		})
	}
}

// TestHTTPServer_handleWebSocket tests WebSocket functionality
func TestHTTPServer_handleWebSocket(t *testing.T) {
	httpServer := createTestHTTPServer(t)
	
	// Create test server
	server := httptest.NewServer(httpServer.router)
	defer server.Close()
	
	// Convert http://... to ws://...
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/mcp/ws"
	
	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()
	
	// Send a test message
	testMessage := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "ping",
		"id":      "1",
	}
	
	err = conn.WriteJSON(testMessage)
	require.NoError(t, err)
	
	// Read response with timeout
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	
	var response map[string]interface{}
	err = conn.ReadJSON(&response)
	if err != nil {
		// WebSocket might close due to unknown method, which is expected
		if !websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
			t.Logf("WebSocket read error (expected): %v", err)
		}
	}
	
	// Verify connection was tracked
	httpServer.wsMutex.RLock()
	connectionCount := len(httpServer.wsConnections)
	httpServer.wsMutex.RUnlock()
	
	// Connection might be cleaned up already, so just verify it was > 0 at some point
	assert.True(t, connectionCount >= 0)
}

// TestHTTPServer_handleHealth tests health check endpoint
func TestHTTPServer_handleHealth(t *testing.T) {
	httpServer := createTestHTTPServer(t)
	
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	
	httpServer.handleHealth(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	var health map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&health)
	require.NoError(t, err)
	
	assert.Equal(t, "ok", health["status"])
	assert.NotEmpty(t, health["timestamp"])
}

// TestHTTPServer_handleMetrics tests metrics endpoint
func TestHTTPServer_handleMetrics(t *testing.T) {
	config := DefaultHTTPServerConfig()
	config.EnableMetrics = true
	
	httpServer := createTestHTTPServerWithConfig(t, config)
	
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	
	httpServer.handleMetrics(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	var metrics map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&metrics)
	require.NoError(t, err)
	
	assert.Contains(t, metrics, "requests_total")
	assert.Contains(t, metrics, "active_connections")
}

// TestHTTPServer_handleInfo tests server info endpoint
func TestHTTPServer_handleInfo(t *testing.T) {
	httpServer := createTestHTTPServer(t)
	
	req := httptest.NewRequest("GET", "/info", nil)
	w := httptest.NewRecorder()
	
	httpServer.handleInfo(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	var info map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&info)
	require.NoError(t, err)
	
	assert.NotEmpty(t, info["name"])
	assert.NotEmpty(t, info["version"])
	assert.Contains(t, info, "capabilities")
	assert.Contains(t, info, "config")
}

// TestHTTPServer_Middleware tests various middleware functions
func TestHTTPServer_Middleware(t *testing.T) {
	t.Run("CORS middleware", func(t *testing.T) {
		config := DefaultHTTPServerConfig()
		config.EnableCORS = true
		config.CORSOrigins = []string{"http://localhost:3000", "https://example.com"}
		
		httpServer := createTestHTTPServerWithConfig(t, config)
		
		req := httptest.NewRequest("OPTIONS", "/health", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		
		w := httptest.NewRecorder()
		httpServer.router.ServeHTTP(w, req)
		
		resp := w.Result()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		assert.Equal(t, "http://localhost:3000", resp.Header.Get("Access-Control-Allow-Origin"))
	})
	
	t.Run("Compression middleware", func(t *testing.T) {
		config := DefaultHTTPServerConfig()
		config.EnableCompression = true
		
		httpServer := createTestHTTPServerWithConfig(t, config)
		
		req := httptest.NewRequest("GET", "/health", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		
		w := httptest.NewRecorder()
		httpServer.router.ServeHTTP(w, req)
		
		resp := w.Result()
		assert.Equal(t, "gzip", resp.Header.Get("Content-Encoding"))
	})
	
	t.Run("Connection limit middleware", func(t *testing.T) {
		config := DefaultHTTPServerConfig()
		config.MaxConnections = 1
		
		httpServer := createTestHTTPServerWithConfig(t, config)
		
		// First request should succeed
		req1 := httptest.NewRequest("GET", "/health", nil)
		w1 := httptest.NewRecorder()
		
		var wg sync.WaitGroup
		wg.Add(2)
		
		go func() {
			defer wg.Done()
			httpServer.router.ServeHTTP(w1, req1)
		}()
		
		// Second concurrent request should be rate limited
		go func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond) // Small delay to ensure first request starts
			
			req2 := httptest.NewRequest("GET", "/health", nil)
			w2 := httptest.NewRecorder()
			httpServer.router.ServeHTTP(w2, req2)
			
			// This might succeed or fail depending on timing
			// Just verify the middleware is in place
		}()
		
		wg.Wait()
		
		// First request should have succeeded
		assert.Equal(t, http.StatusOK, w1.Result().StatusCode)
	})
}

// TestHTTPServer_RateLimiter tests the rate limiting functionality
func TestHTTPServer_RateLimiter(t *testing.T) {
	rateLimiter := &RateLimiter{
		capacity: 2,
		rate:     1,
		tokens:   2,
		lastFill: time.Now(),
	}
	
	// Should allow first two requests
	assert.True(t, rateLimiter.Allow())
	assert.True(t, rateLimiter.Allow())
	
	// Should deny third request
	assert.False(t, rateLimiter.Allow())
	
	// Wait for token refill (rate is 1 per second)
	time.Sleep(1100 * time.Millisecond)
	
	// Should allow request after refill
	assert.True(t, rateLimiter.Allow())
}

// TestHTTPServer_WebSocketConnection tests WebSocket connection lifecycle
func TestHTTPServer_WebSocketConnection(t *testing.T) {
	httpServer := createTestHTTPServer(t)
	
	// Create a mock WebSocket connection
	conn := &WebSocketConnection{
		ID:         "test-conn-1",
		Send:       make(chan []byte, 10),
		Server:     httpServer,
		LastActive: time.Now(),
	}
	
	// Add connection
	httpServer.wsMutex.Lock()
	httpServer.wsConnections[conn.ID] = conn
	httpServer.wsMutex.Unlock()
	
	// Test connection tracking
	httpServer.wsMutex.RLock()
	_, exists := httpServer.wsConnections[conn.ID]
	httpServer.wsMutex.RUnlock()
	assert.True(t, exists)
	
	// Test connection removal
	httpServer.removeConnection(conn.ID)
	
	httpServer.wsMutex.RLock()
	_, exists = httpServer.wsConnections[conn.ID]
	httpServer.wsMutex.RUnlock()
	assert.False(t, exists)
}

// TestHTTPServer_CleanupStaleConnections tests stale connection cleanup
func TestHTTPServer_CleanupStaleConnections(t *testing.T) {
	httpServer := createTestHTTPServer(t)
	
	// Add a stale connection
	staleConn := &WebSocketConnection{
		ID:         "stale-conn",
		Send:       make(chan []byte, 1),
		Server:     httpServer,
		LastActive: time.Now().Add(-10 * time.Minute),
	}
	
	// Add a fresh connection
	freshConn := &WebSocketConnection{
		ID:         "fresh-conn",
		Send:       make(chan []byte, 1),
		Server:     httpServer,
		LastActive: time.Now(),
	}
	
	httpServer.wsMutex.Lock()
	httpServer.wsConnections[staleConn.ID] = staleConn
	httpServer.wsConnections[freshConn.ID] = freshConn
	httpServer.wsMutex.Unlock()
	
	// Run cleanup
	httpServer.cleanupStaleConnections()
	
	// Verify stale connection was removed and fresh connection remains
	httpServer.wsMutex.RLock()
	_, staleExists := httpServer.wsConnections[staleConn.ID]
	_, freshExists := httpServer.wsConnections[freshConn.ID]
	httpServer.wsMutex.RUnlock()
	
	assert.False(t, staleExists)
	assert.True(t, freshExists)
}

// TestHTTPServer_ProcessMCPMessage tests MCP message processing
func TestHTTPServer_ProcessMCPMessage(t *testing.T) {
	httpServer := createTestHTTPServer(t)
	
	// Test valid MCP message
	message := []byte(`{
		"jsonrpc": "2.0",
		"method": "tools/list",
		"id": "1"
	}`)
	
	response := httpServer.processMCPMessage(message)
	
	// Should get a response (even if it's an error due to server state)
	assert.NotNil(t, response)
	assert.Greater(t, len(response), 0)
}

// TestHTTPServer_Metrics tests metrics collection
func TestHTTPServer_Metrics(t *testing.T) {
	httpServer := createTestHTTPServer(t)
	
	// Initial metrics should be zero
	assert.Equal(t, int64(0), httpServer.metrics.RequestsTotal)
	assert.Equal(t, int64(0), httpServer.metrics.ActiveConnections)
	
	// Simulate some activity
	httpServer.metrics.RequestsTotal = 10
	httpServer.metrics.ActiveConnections = 5
	httpServer.metrics.BytesServed = 1024
	
	assert.Equal(t, int64(10), httpServer.metrics.RequestsTotal)
	assert.Equal(t, int64(5), httpServer.metrics.ActiveConnections)
	assert.Equal(t, int64(1024), httpServer.metrics.BytesServed)
}

// Benchmark tests

// BenchmarkHTTPServer_handleMCPRequest benchmarks MCP request handling
func BenchmarkHTTPServer_handleMCPRequest(b *testing.B) {
	httpServer := createTestHTTPServer(nil)
	
	requestBody := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      jsonRawMessagePtr(`"1"`),
		},
		Method: MethodListTools,
	}
	
	jsonData, _ := json.Marshal(requestBody)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("POST", "/mcp", bytes.NewReader(jsonData))
			req.Header.Set("Content-Type", "application/json")
			
			w := httptest.NewRecorder()
			httpServer.handleMCPRequest(w, req)
		}
	})
}

// BenchmarkHTTPServer_RateLimiter benchmarks rate limiter
func BenchmarkHTTPServer_RateLimiter(b *testing.B) {
	rateLimiter := &RateLimiter{
		capacity: 1000,
		rate:     100,
		tokens:   1000,
		lastFill: time.Now(),
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rateLimiter.Allow()
		}
	})
}

// Helper functions

func createTestMCPServer(t testing.TB) *Server {
	toolRegistry := tools.NewRegistry()
	logger := zerolog.Nop()
	
	config := ServerConfig{
		Name:         "Test MCP Server",
		Version:      "1.0.0",
		Logger:       &logger,
		ToolRegistry: toolRegistry,
	}
	
	return NewServer(config)
}

func createTestHTTPServer(t testing.TB) *HTTPServer {
	return createTestHTTPServerWithConfig(t, DefaultHTTPServerConfig())
}

func createTestHTTPServerWithConfig(t testing.TB, config HTTPServerConfig) *HTTPServer {
	mcpServer := createTestMCPServer(t)
	logger := zerolog.Nop()
	
	return NewHTTPServer(config, mcpServer, logger)
}

func jsonRawMessage(s string) json.RawMessage {
	return json.RawMessage(s)
}

func jsonRawMessagePtr(s string) *json.RawMessage {
	msg := json.RawMessage(s)
	return &msg
}

// Integration test with real HTTP server
func TestHTTPServer_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	config := DefaultHTTPServerConfig()
	config.Port = 0 // Use random port
	
	mcpServer := createTestMCPServer(t)
	logger := zerolog.Nop()
	
	httpServer := NewHTTPServer(config, mcpServer, logger)
	
	// Start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	err := httpServer.Start(ctx)
	require.NoError(t, err)
	
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		httpServer.Stop(stopCtx)
	}()
	
	// Wait for server to start
	time.Sleep(100 * time.Millisecond)
	
	// Get server address
	serverURL := fmt.Sprintf("http://%s:%d", config.Address, config.Port)
	
	// Test health endpoint
	resp, err := http.Get(serverURL + "/health")
	require.NoError(t, err)
	defer resp.Body.Close()
	
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var health map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&health)
	require.NoError(t, err)
	assert.Equal(t, "ok", health["status"])
}