package mcp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// HTTPServerConfig holds configuration for the HTTP server
type HTTPServerConfig struct {
	Address              string
	Port                 int
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	EnableCORS           bool
	CORSOrigins          []string
	CORSMethods          []string
	CORSHeaders          []string
	EnableCompression    bool
	CompressionLevel     int
	CompressionMinSize   int
	EnableMetrics        bool
	EnableWebSocket      bool
	WebSocketOriginCheck bool
	MaxConnections       int
	MaxRequestSize       int64
	RateLimitRPS         int
	RateLimitBurst       int
}

// DefaultHTTPServerConfig returns default HTTP server configuration
func DefaultHTTPServerConfig() HTTPServerConfig {
	return HTTPServerConfig{
		Address:              "localhost",
		Port:                 3000,
		ReadTimeout:          30 * time.Second,
		WriteTimeout:         30 * time.Second,
		EnableCORS:           true,
		CORSOrigins:          []string{"*"},
		CORSMethods:          []string{"GET", "POST", "OPTIONS"},
		CORSHeaders:          []string{"Content-Type", "Authorization"},
		EnableCompression:    true,
		CompressionLevel:     6,
		CompressionMinSize:   1024,
		EnableMetrics:        true,
		EnableWebSocket:      true,
		WebSocketOriginCheck: true,
		MaxConnections:       1000,
		MaxRequestSize:       10 * 1024 * 1024, // 10MB
		RateLimitRPS:         100,
		RateLimitBurst:       200,
	}
}

// HTTPServer wraps an MCP server for HTTP transport
type HTTPServer struct {
	config         HTTPServerConfig
	mcpServer      *Server
	httpServer     *http.Server
	router         *mux.Router
	logger         zerolog.Logger
	metrics        *HTTPMetrics
	upgrader       websocket.Upgrader
	wsConnections  map[string]*WebSocketConnection
	wsMutex        sync.RWMutex
	connectionPool *ConnectionPool
	
	// Shutdown management
	shutdown chan struct{}
	wg       sync.WaitGroup
}

// HTTPMetrics holds HTTP server metrics
type HTTPMetrics struct {
	RequestsTotal        int64
	RequestDuration      int64 // Average in microseconds
	ActiveConnections    int64
	WebSocketConnections int64
	ErrorsTotal          int64
	BytesServed          int64
	CompressionRatio     float64
	mutex                sync.RWMutex
}

// WebSocketConnection represents a WebSocket connection
type WebSocketConnection struct {
	ID         string
	Conn       *websocket.Conn
	Send       chan []byte
	Server     *HTTPServer
	LastActive time.Time
	mutex      sync.RWMutex
}

// ConnectionPool manages HTTP connection limits
type ConnectionPool struct {
	current     int64
	max         int64
	semaphore   chan struct{}
	rateLimiter *RateLimiter
}

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	tokens   int64
	capacity int64
	rate     int64
	lastFill time.Time
	mutex    sync.Mutex
}

// GetRouter returns the HTTP server's router
func (s *HTTPServer) GetRouter() *mux.Router {
	return s.router
}

// NewHTTPServer creates a new HTTP server for MCP
func NewHTTPServer(config HTTPServerConfig, mcpServer *Server, logger zerolog.Logger) *HTTPServer {
	metrics := &HTTPMetrics{}
	
	// Configure WebSocket upgrader
	upgrader := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			if !config.WebSocketOriginCheck {
				return true
			}
			// Check origin against configured origins
			origin := r.Header.Get("Origin")
			for _, allowedOrigin := range config.CORSOrigins {
				if allowedOrigin == "*" || allowedOrigin == origin {
					return true
				}
			}
			return false
		},
	}

	// Create connection pool
	connectionPool := &ConnectionPool{
		max:       int64(config.MaxConnections),
		semaphore: make(chan struct{}, config.MaxConnections),
		rateLimiter: &RateLimiter{
			capacity: int64(config.RateLimitBurst),
			rate:     int64(config.RateLimitRPS),
			tokens:   int64(config.RateLimitBurst),
			lastFill: time.Now(),
		},
	}

	server := &HTTPServer{
		config:         config,
		mcpServer:      mcpServer,
		router:         mux.NewRouter(),
		logger:         logger,
		metrics:        metrics,
		upgrader:       upgrader,
		wsConnections:  make(map[string]*WebSocketConnection),
		connectionPool: connectionPool,
		shutdown:       make(chan struct{}),
	}

	server.setupRoutes()
	return server
}

// Start starts the HTTP server
func (s *HTTPServer) Start(ctx context.Context) error {
	s.logger.Info().
		Str("address", fmt.Sprintf("%s:%d", s.config.Address, s.config.Port)).
		Bool("websocket_enabled", s.config.EnableWebSocket).
		Bool("compression_enabled", s.config.EnableCompression).
		Bool("metrics_enabled", s.config.EnableMetrics).
		Msg("Starting HTTP server")

	// Create HTTP server
	s.httpServer = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", s.config.Address, s.config.Port),
		Handler:        s.router,
		ReadTimeout:    s.config.ReadTimeout,
		WriteTimeout:   s.config.WriteTimeout,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Start server in goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error().Err(err).Msg("HTTP server listen error")
		}
	}()

	// Start cleanup goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.cleanupWorker(ctx)
	}()

	return nil
}

// Stop stops the HTTP server
func (s *HTTPServer) Stop(ctx context.Context) error {
	s.logger.Info().Msg("Stopping HTTP server")
	
	// Signal shutdown
	close(s.shutdown)
	
	// Close all WebSocket connections
	s.wsMutex.Lock()
	for id, conn := range s.wsConnections {
		conn.Close()
		delete(s.wsConnections, id)
	}
	s.wsMutex.Unlock()
	
	// Shutdown HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error().Err(err).Msg("HTTP server shutdown error")
			return err
		}
	}
	
	// Wait for goroutines
	s.wg.Wait()
	
	s.logger.Info().Msg("HTTP server stopped")
	return nil
}

// setupRoutes configures HTTP routes
func (s *HTTPServer) setupRoutes() {
	// Apply middleware
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.metricsMiddleware)
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.compressionMiddleware)
	s.router.Use(s.connectionLimitMiddleware)
	s.router.Use(s.rateLimitMiddleware)

	// MCP JSON-RPC over HTTP
	s.router.HandleFunc("/mcp", s.handleMCPRequest).Methods("POST", "OPTIONS")
	
	// WebSocket endpoint
	if s.config.EnableWebSocket {
		s.router.HandleFunc("/mcp/ws", s.handleWebSocket)
	}
	
	// Health check
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	
	// Metrics endpoint
	if s.config.EnableMetrics {
		s.router.HandleFunc("/metrics", s.handleMetrics).Methods("GET")
	}
	
	// Server info
	s.router.HandleFunc("/info", s.handleInfo).Methods("GET")
}

// handleMCPRequest handles HTTP-based MCP JSON-RPC requests
func (s *HTTPServer) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	// Limit request size
	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxRequestSize)
	
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to read request body")
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	
	// Create a pipe to communicate with MCP server
	pr, pw := io.Pipe()
	var responseBuffer bytes.Buffer
	
	// Configure MCP server to use pipe for I/O
	originalReader := s.mcpServer.reader
	originalWriter := s.mcpServer.writer
	s.mcpServer.reader = pr
	s.mcpServer.writer = &responseBuffer
	
	// Restore original I/O when done
	defer func() {
		s.mcpServer.reader = originalReader
		s.mcpServer.writer = originalWriter
		pr.Close()
		pw.Close()
	}()
	
	// Write request to pipe
	go func() {
		defer pw.Close()
		if _, err := pw.Write(body); err != nil {
			s.logger.Error().Err(err).Msg("Failed to write to pipe")
		}
	}()
	
	// Process message with timeout
	ctx, cancel := context.WithTimeout(r.Context(), s.config.WriteTimeout)
	defer cancel()
	
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.mcpServer.processMessage(body)
	}()
	
	select {
	case <-done:
		// Success
	case <-ctx.Done():
		s.logger.Error().Msg("MCP request timeout")
		http.Error(w, "Request timeout", http.StatusRequestTimeout)
		return
	}
	
	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// Write response
	if responseBuffer.Len() > 0 {
		if _, err := w.Write(responseBuffer.Bytes()); err != nil {
			s.logger.Error().Err(err).Msg("Failed to write response")
		}
	}
}

// handleWebSocket handles WebSocket connections
func (s *HTTPServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade connection
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Error().Err(err).Msg("WebSocket upgrade failed")
		return
	}
	
	// Create connection object
	wsConn := &WebSocketConnection{
		ID:         generateConnectionID(),
		Conn:       conn,
		Send:       make(chan []byte, 256),
		Server:     s,
		LastActive: time.Now(),
	}
	
	// Add to connections map
	s.wsMutex.Lock()
	s.wsConnections[wsConn.ID] = wsConn
	atomic.AddInt64(&s.metrics.WebSocketConnections, 1)
	s.wsMutex.Unlock()
	
	s.logger.Info().
		Str("connection_id", wsConn.ID).
		Str("remote_addr", r.RemoteAddr).
		Msg("WebSocket connection established")
	
	// Start connection handlers
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		wsConn.readPump()
	}()
	go func() {
		defer s.wg.Done()
		wsConn.writePump()
	}()
}

// handleHealth handles health check requests
func (s *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   s.mcpServer.info.Version,
		"uptime":    time.Since(time.Now()).String(), // This would need to be tracked properly
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// handleMetrics handles metrics requests
func (s *HTTPServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.config.EnableMetrics {
		http.Error(w, "Metrics disabled", http.StatusNotFound)
		return
	}
	
	s.metrics.mutex.RLock()
	metrics := map[string]interface{}{
		"requests_total":         atomic.LoadInt64(&s.metrics.RequestsTotal),
		"average_duration_us":    atomic.LoadInt64(&s.metrics.RequestDuration),
		"active_connections":     atomic.LoadInt64(&s.metrics.ActiveConnections),
		"websocket_connections":  atomic.LoadInt64(&s.metrics.WebSocketConnections),
		"errors_total":          atomic.LoadInt64(&s.metrics.ErrorsTotal),
		"bytes_served":          atomic.LoadInt64(&s.metrics.BytesServed),
		"compression_ratio":     s.metrics.CompressionRatio,
		"timestamp":             time.Now().Format(time.RFC3339),
	}
	s.metrics.mutex.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metrics)
}

// handleInfo handles server info requests
func (s *HTTPServer) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"name":         s.mcpServer.info.Name,
		"version":      s.mcpServer.info.Version,
		"capabilities": s.mcpServer.capabilities,
		"config": map[string]interface{}{
			"websocket_enabled":    s.config.EnableWebSocket,
			"compression_enabled":  s.config.EnableCompression,
			"cors_enabled":        s.config.EnableCORS,
			"metrics_enabled":     s.config.EnableMetrics,
			"max_connections":     s.config.MaxConnections,
			"max_request_size":    s.config.MaxRequestSize,
		},
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// Middleware functions

func (s *HTTPServer) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapped, r)
		
		duration := time.Since(start)
		
		s.logger.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_addr", r.RemoteAddr).
			Int("status", wrapped.statusCode).
			Dur("duration", duration).
			Int64("bytes", wrapped.bytes).
			Msg("HTTP request")
	})
}

func (s *HTTPServer) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.EnableMetrics {
			next.ServeHTTP(w, r)
			return
		}
		
		start := time.Now()
		atomic.AddInt64(&s.metrics.ActiveConnections, 1)
		
		defer func() {
			atomic.AddInt64(&s.metrics.ActiveConnections, -1)
			atomic.AddInt64(&s.metrics.RequestsTotal, 1)
			
			duration := time.Since(start).Microseconds()
			atomic.StoreInt64(&s.metrics.RequestDuration, duration)
		}()
		
		next.ServeHTTP(w, r)
	})
}

func (s *HTTPServer) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.EnableCORS {
			next.ServeHTTP(w, r)
			return
		}
		
		origin := r.Header.Get("Origin")
		
		// Check if origin is allowed
		allowed := false
		for _, allowedOrigin := range s.config.CORSOrigins {
			if allowedOrigin == "*" || allowedOrigin == origin {
				allowed = true
				break
			}
		}
		
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", strings.Join(s.config.CORSMethods, ", "))
			w.Header().Set("Access-Control-Allow-Headers", strings.Join(s.config.CORSHeaders, ", "))
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		
		// Handle preflight
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}

func (s *HTTPServer) compressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.config.EnableCompression {
			next.ServeHTTP(w, r)
			return
		}
		
		// Check if client accepts gzip
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		
		// Create gzip writer
		gz, err := gzip.NewWriterLevel(w, s.config.CompressionLevel)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		defer gz.Close()
		
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length")
		
		// Wrap response writer
		gzw := &gzipResponseWriter{ResponseWriter: w, gw: gz}
		next.ServeHTTP(gzw, r)
	})
}

func (s *HTTPServer) connectionLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.connectionPool.semaphore <- struct{}{}:
			defer func() { <-s.connectionPool.semaphore }()
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "Too many connections", http.StatusTooManyRequests)
			atomic.AddInt64(&s.metrics.ErrorsTotal, 1)
		}
	})
}

func (s *HTTPServer) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.connectionPool.rateLimiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			atomic.AddInt64(&s.metrics.ErrorsTotal, 1)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WebSocket connection methods

func (conn *WebSocketConnection) readPump() {
	defer func() {
		conn.Server.removeConnection(conn.ID)
		conn.Conn.Close()
	}()
	
	conn.Conn.SetReadLimit(conn.Server.config.MaxRequestSize)
	conn.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.Conn.SetPongHandler(func(string) error {
		conn.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	
	for {
		_, message, err := conn.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				conn.Server.logger.Error().Err(err).Str("connection_id", conn.ID).Msg("WebSocket error")
			}
			break
		}
		
		conn.updateLastActive()
		
		// Process MCP message
		go func() {
			response := conn.Server.processMCPMessage(message)
			if response != nil {
				select {
				case conn.Send <- response:
				default:
					conn.Server.logger.Warn().
						Str("connection_id", conn.ID).
						Msg("WebSocket send channel blocked")
					conn.Close()
				}
			}
		}()
	}
}

func (conn *WebSocketConnection) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		conn.Conn.Close()
	}()
	
	for {
		select {
		case message, ok := <-conn.Send:
			conn.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				conn.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			
			if err := conn.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				conn.Server.logger.Error().Err(err).Str("connection_id", conn.ID).Msg("WebSocket write error")
				return
			}
			
		case <-ticker.C:
			conn.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (conn *WebSocketConnection) Close() {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	
	select {
	case <-conn.Send:
	default:
		close(conn.Send)
	}
}

func (conn *WebSocketConnection) updateLastActive() {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	conn.LastActive = time.Now()
}

// Helper methods

func (s *HTTPServer) removeConnection(id string) {
	s.wsMutex.Lock()
	defer s.wsMutex.Unlock()
	
	if _, exists := s.wsConnections[id]; exists {
		delete(s.wsConnections, id)
		atomic.AddInt64(&s.metrics.WebSocketConnections, -1)
		s.logger.Info().Str("connection_id", id).Msg("WebSocket connection removed")
	}
}

func (s *HTTPServer) processMCPMessage(message []byte) []byte {
	// Create a buffer to capture MCP server response
	var responseBuffer bytes.Buffer
	
	// Temporarily redirect MCP server output
	originalWriter := s.mcpServer.writer
	s.mcpServer.writer = &responseBuffer
	
	// Process the message
	s.mcpServer.processMessage(message)
	
	// Restore original writer
	s.mcpServer.writer = originalWriter
	
	if responseBuffer.Len() > 0 {
		return responseBuffer.Bytes()
	}
	return nil
}

func (s *HTTPServer) cleanupWorker(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		case <-ticker.C:
			s.cleanupStaleConnections()
		}
	}
}

func (s *HTTPServer) cleanupStaleConnections() {
	s.wsMutex.Lock()
	defer s.wsMutex.Unlock()
	
	staleThreshold := time.Now().Add(-5 * time.Minute)
	
	for id, conn := range s.wsConnections {
		conn.mutex.RLock()
		lastActive := conn.LastActive
		conn.mutex.RUnlock()
		
		if lastActive.Before(staleThreshold) {
			s.logger.Info().
				Str("connection_id", id).
				Time("last_active", lastActive).
				Msg("Closing stale WebSocket connection")
			
			conn.Close()
			delete(s.wsConnections, id)
			atomic.AddInt64(&s.metrics.WebSocketConnections, -1)
		}
	}
}

// Rate limiter methods

func (rl *RateLimiter) Allow() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	
	now := time.Now()
	elapsed := now.Sub(rl.lastFill)
	
	// Add tokens based on elapsed time
	tokensToAdd := int64(elapsed.Seconds()) * rl.rate
	if tokensToAdd > 0 {
		rl.tokens = min(rl.capacity, rl.tokens+tokensToAdd)
		rl.lastFill = now
	}
	
	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	
	return false
}

// Utility types and functions

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	bytes      int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytes += int64(n)
	return n, err
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gw *gzip.Writer
}

func (grw *gzipResponseWriter) Write(b []byte) (int, error) {
	return grw.gw.Write(b)
}

func generateConnectionID() string {
	return fmt.Sprintf("ws_%d", time.Now().UnixNano())
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}