package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// Server represents an MCP server instance
type Server struct {
	info         ServerInfo
	capabilities ServerCapabilities
	state        ServerState
	stateMu      sync.RWMutex
	
	// I/O
	reader io.Reader
	writer io.Writer
	
	// Tool registry
	toolRegistry *tools.Registry
	
	// Resource and Prompt managers
	resourceManager *ResourceManager
	promptManager   *PromptManager
	streamManager   *StreamManager
	subscriptionManager *SubscriptionManager
	
	// Client info (set during initialization)
	clientInfo   *ClientInfo
	clientCaps   *ClientCapabilities
	
	// Logging
	logger       zerolog.Logger
	logLevel     LogLevel
	
	// Shutdown
	shutdownCh   chan struct{}
	shutdownOnce sync.Once
	
	// Request tracking
	activeRequests map[string]*RequestContext
	requestsMu     sync.RWMutex
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Name                string
	Version             string
	Reader              io.Reader
	Writer              io.Writer
	Logger              *zerolog.Logger
	ToolRegistry        *tools.Registry
	ResourceConfig      *ResourceConfig
	PromptConfig        *PromptConfig
	StreamConfig        *StreamConfig
	SubscriptionConfig  *SubscriptionConfig
}

// NewServer creates a new MCP server
func NewServer(config ServerConfig) *Server {
	// Use provided logger or default to stdout
	var logger zerolog.Logger
	if config.Logger != nil {
		logger = *config.Logger
	} else {
		logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
	
	// Default I/O to stdin/stdout
	reader := config.Reader
	if reader == nil {
		reader = os.Stdin
	}
	
	writer := config.Writer
	if writer == nil {
		writer = os.Stdout
	}
	
	// Create tool registry if not provided
	toolRegistry := config.ToolRegistry
	if toolRegistry == nil {
		toolRegistry = tools.NewRegistry()
	}

	// Initialize resource manager with default config if not provided
	var resourceManager *ResourceManager
	if config.ResourceConfig != nil {
		resourceManager = NewResourceManager(*config.ResourceConfig)
	} else {
		resourceManager = NewResourceManager(ResourceConfig{
			EnableCaching:     true,
			CacheTTL:          time.Hour,
			MaxCacheSize:      1000,
			EnableVersioning:  true,
			TemplateDirectory: "",
			EnableMetrics:     true,
		})
	}

	// Initialize prompt manager with default config if not provided
	var promptManager *PromptManager
	if config.PromptConfig != nil {
		promptManager = NewPromptManager(*config.PromptConfig)
	} else {
		promptManager = NewPromptManager(PromptConfig{
			EnableCaching:      true,
			CacheTTL:           time.Hour,
			MaxCacheSize:       1000,
			EnableValidation:   true,
			EnableComposition:  true,
			EnableContext:      true,
			TemplateDirectory:  "",
			EnableMetrics:      true,
			MaxPromptLength:    10000,
			EnableVersioning:   true,
		})
	}

	// Initialize stream manager with default config if not provided
	var streamManager *StreamManager
	if config.StreamConfig != nil {
		streamManager = NewStreamManager(*config.StreamConfig)
	} else {
		streamManager = NewStreamManager(StreamConfig{
			MaxConcurrentStreams: 100,
			DefaultChunkSize:     8192,
			MaxChunkSize:         65536,
			BufferSize:           1024,
			ProgressInterval:     time.Second,
			EnableBackpressure:   true,
			EnableMultiplexing:   true,
			EnableMetrics:        true,
			MaxRetries:           3,
			RetryDelay:           time.Second,
		})
	}

	// Initialize subscription manager with default config if not provided
	var subscriptionManager *SubscriptionManager
	if config.SubscriptionConfig != nil {
		subscriptionManager = NewSubscriptionManager(*config.SubscriptionConfig)
	} else {
		subscriptionManager = NewSubscriptionManager(SubscriptionConfig{
			MaxSubscribers:   1000,
			DefaultBatchSize: 10,
			DefaultBatchWait: time.Second,
			EnableBatching:   true,
			EnableReconnection: true,
			EnableMetrics:    true,
			CleanupInterval:  time.Minute,
			EventTTL:         time.Hour,
		})
	}
	
	server := &Server{
		info: ServerInfo{
			Name:    config.Name,
			Version: config.Version,
		},
		capabilities: ServerCapabilities{
			Tools: &ToolsCapability{
				ListChanged: boolPtr(false),
			},
			Resources: &ResourcesCapability{
				Subscribe:   boolPtr(true), // Enable resource subscriptions
				ListChanged: boolPtr(true), // Enable resource change notifications
			},
			Prompts: &PromptsCapability{
				ListChanged: boolPtr(true), // Enable prompt change notifications
			},
			Logging: &LoggingCapability{},
		},
		state:               ServerStateUninitialized,
		reader:              reader,
		writer:              writer,
		toolRegistry:        toolRegistry,
		resourceManager:     resourceManager,
		promptManager:       promptManager,
		streamManager:       streamManager,
		subscriptionManager: subscriptionManager,
		logger:              logger,
		logLevel:            LogLevelInfo,
		shutdownCh:          make(chan struct{}),
		activeRequests:      make(map[string]*RequestContext),
	}
	
	return server
}

// Run starts the MCP server and processes messages
func (s *Server) Run(ctx context.Context) error {
	s.logger.Info().
		Str("name", s.info.Name).
		Str("version", s.info.Version).
		Msg("Starting MCP server")

	// Start subscription manager if available
	if s.subscriptionManager != nil {
		if err := s.subscriptionManager.Start(ctx); err != nil {
			s.logger.Error().Err(err).Msg("Failed to start subscription manager")
			return err
		}
	}
	
	scanner := bufio.NewScanner(s.reader)
	
	for {
		select {
		case <-ctx.Done():
			s.logger.Info().Msg("Server context cancelled")
			s.cleanup()
			return ctx.Err()
		case <-s.shutdownCh:
			s.logger.Info().Msg("Server shutdown requested")
			s.cleanup()
			return nil
		default:
		}
		
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				s.logger.Error().Err(err).Msg("Error reading input")
				s.cleanup()
				return err
			}
			// EOF reached
			s.logger.Info().Msg("Input stream closed")
			s.cleanup()
			return nil
		}
		
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		
		// Process the message in a goroutine to avoid blocking
		go s.processMessage(line)
	}
}

// processMessage handles a single JSON-RPC message
func (s *Server) processMessage(data []byte) {
	s.logger.Debug().
		RawJSON("message", data).
		Msg("Processing message")
	
	// Try to parse as request first
	var req JSONRPCRequest
	if err := json.Unmarshal(data, &req); err == nil && req.Method != "" {
		s.handleRequest(&req)
		return
	}
	
	// Try to parse as response
	var resp JSONRPCResponse
	if err := json.Unmarshal(data, &resp); err == nil && (resp.Result != nil || resp.Error != nil) {
		s.handleResponse(&resp)
		return
	}
	
	// Try to parse as notification
	var notif JSONRPCNotification
	if err := json.Unmarshal(data, &notif); err == nil && notif.Method != "" {
		s.handleNotification(&notif)
		return
	}
	
	// Invalid message
	s.sendErrorResponse(nil, ErrorCodeInvalidRequest, "Invalid JSON-RPC message", nil)
}

// handleRequest processes JSON-RPC requests
func (s *Server) handleRequest(req *JSONRPCRequest) {
	requestID := ""
	if req.ID != nil {
		requestID = string(*req.ID)
	}
	
	// Create request context
	reqCtx := &RequestContext{
		RequestID:    requestID,
		StartTime:    time.Now(),
		ClientInfo:   s.clientInfo,
		Capabilities: s.clientCaps,
	}
	
	// Track active request
	if requestID != "" {
		s.requestsMu.Lock()
		s.activeRequests[requestID] = reqCtx
		s.requestsMu.Unlock()
		
		defer func() {
			s.requestsMu.Lock()
			delete(s.activeRequests, requestID)
			s.requestsMu.Unlock()
		}()
	}
	
	s.logger.Debug().
		Str("method", req.Method).
		Str("request_id", requestID).
		Msg("Handling request")
	
	switch req.Method {
	case MethodInitialize:
		s.handleInitialize(req)
	case MethodShutdown:
		s.handleShutdown(req)
	case MethodListTools:
		s.handleListTools(req)
	case MethodCallTool:
		s.handleCallTool(req)
	case MethodListResources:
		s.handleListResources(req)
	case MethodReadResource:
		s.handleReadResource(req)
	case MethodListPrompts:
		s.handleListPrompts(req)
	case MethodGetPrompt:
		s.handleGetPrompt(req)
	case MethodSetLevel:
		s.handleSetLevel(req)
	default:
		s.sendErrorResponse(req.ID, ErrorCodeMethodNotFound, 
			fmt.Sprintf("Method not found: %s", req.Method), nil)
	}
}

// handleResponse processes JSON-RPC responses
func (s *Server) handleResponse(resp *JSONRPCResponse) {
	// Handle responses to requests we sent (if any)
	s.logger.Debug().
		RawJSON("response", func() []byte {
			data, _ := json.Marshal(resp)
			return data
		}()).
		Msg("Received response")
}

// handleNotification processes JSON-RPC notifications
func (s *Server) handleNotification(notif *JSONRPCNotification) {
	s.logger.Debug().
		Str("method", notif.Method).
		Msg("Handling notification")
	
	switch notif.Method {
	case MethodInitialized:
		s.handleInitialized(notif)
	case MethodExit:
		s.handleExit()
	default:
		s.logger.Warn().
			Str("method", notif.Method).
			Msg("Unknown notification method")
	}
}

// Method handlers

func (s *Server) handleInitialize(req *JSONRPCRequest) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	
	if s.state != ServerStateUninitialized {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidRequest, 
			"Server already initialized", nil)
		return
	}
	
	var params InitializeParams
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			s.sendErrorResponse(req.ID, ErrorCodeInvalidParams, 
				"Invalid initialize parameters", nil)
			return
		}
	}
	
	// Store client info
	s.clientInfo = &params.ClientInfo
	s.clientCaps = &params.Capabilities
	
	s.state = ServerStateReady
	
	result := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities:    s.capabilities,
		ServerInfo:      s.info,
	}
	
	s.sendSuccessResponse(req.ID, result)
	
	s.logger.Info().
		Str("client_name", params.ClientInfo.Name).
		Str("client_version", params.ClientInfo.Version).
		Str("protocol_version", params.ProtocolVersion).
		Msg("Server initialized")
}

func (s *Server) handleInitialized(notif *JSONRPCNotification) {
	s.logger.Info().Msg("Client initialized")
}

func (s *Server) handleShutdown(req *JSONRPCRequest) {
	s.stateMu.Lock()
	s.state = ServerStateShuttingDown
	s.stateMu.Unlock()
	
	s.logger.Info().Msg("Shutdown requested")
	s.sendSuccessResponse(req.ID, nil)
}

func (s *Server) handleExit() {
	s.logger.Info().Msg("Exit requested")
	s.shutdownOnce.Do(func() {
		close(s.shutdownCh)
	})
}

func (s *Server) handleListTools(req *JSONRPCRequest) {
	if !s.isReady() {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidRequest, 
			"Server not initialized", nil)
		return
	}
	
	tools := s.toolRegistry.ListTools()
	mcpTools := make([]Tool, len(tools))
	
	for i, tool := range tools {
		mcpTools[i] = Tool{
			Name:        tool.Name(),
			Description: tool.Description(),
			InputSchema: s.convertToolSchema(tool.Schema()),
		}
	}
	
	result := ListToolsResult{
		Tools: mcpTools,
	}
	
	s.sendSuccessResponse(req.ID, result)
}

func (s *Server) handleCallTool(req *JSONRPCRequest) {
	if !s.isReady() {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidRequest, 
			"Server not initialized", nil)
		return
	}
	
	var params CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidParams, 
			"Invalid call tool parameters", nil)
		return
	}
	
	tool := s.toolRegistry.GetTool(params.Name)
	if tool == nil {
		s.sendErrorResponse(req.ID, ErrorCodeToolNotFound, 
			fmt.Sprintf("Tool not found: %s", params.Name), nil)
		return
	}
	
	// Execute tool
	ctx := context.Background()
	result, err := tool.Execute(ctx, params.Arguments)
	if err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeToolError, 
			fmt.Sprintf("Tool execution failed: %v", err), nil)
		return
	}
	
	// Convert result to MCP format
	content := []ToolContent{
		{
			Type: "text",
			Text: result.Text,
		},
	}
	
	toolResult := CallToolResult{
		Content: content,
		IsError: &result.IsError,
	}
	
	s.sendSuccessResponse(req.ID, toolResult)
}

func (s *Server) handleListResources(req *JSONRPCRequest) {
	if !s.isReady() {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidRequest, 
			"Server not initialized", nil)
		return
	}

	// Parse any filters from parameters
	filters := make(map[string]string)
	if req.Params != nil {
		var params map[string]interface{}
		if err := json.Unmarshal(req.Params, &params); err == nil {
			if filtersParam, ok := params["filters"].(map[string]interface{}); ok {
				for k, v := range filtersParam {
					if str, ok := v.(string); ok {
						filters[k] = str
					}
				}
			}
		}
	}

	ctx := context.Background()
	resources, err := s.resourceManager.ListResources(ctx, filters)
	if err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeInternalError, 
			fmt.Sprintf("Failed to list resources: %v", err), nil)
		return
	}

	result := ListResourcesResult{
		Resources: resources,
	}
	s.sendSuccessResponse(req.ID, result)
}

func (s *Server) handleReadResource(req *JSONRPCRequest) {
	if !s.isReady() {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidRequest, 
			"Server not initialized", nil)
		return
	}

	var params ReadResourceParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidParams, 
			"Invalid read resource parameters", nil)
		return
	}
	
	ctx := context.Background()
	content, err := s.resourceManager.GetResource(ctx, params.URI)
	if err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeResourceNotFound, 
			fmt.Sprintf("Resource not found: %s", params.URI), nil)
		return
	}

	result := ReadResourceResult{
		Contents: []ResourceContent{*content},
	}
	s.sendSuccessResponse(req.ID, result)
}

func (s *Server) handleListPrompts(req *JSONRPCRequest) {
	if !s.isReady() {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidRequest, 
			"Server not initialized", nil)
		return
	}

	// Parse any filters from parameters
	filters := make(map[string]string)
	if req.Params != nil {
		var params map[string]interface{}
		if err := json.Unmarshal(req.Params, &params); err == nil {
			if filtersParam, ok := params["filters"].(map[string]interface{}); ok {
				for k, v := range filtersParam {
					if str, ok := v.(string); ok {
						filters[k] = str
					}
				}
			}
		}
	}

	ctx := context.Background()
	prompts, err := s.promptManager.ListPrompts(ctx, filters)
	if err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeInternalError, 
			fmt.Sprintf("Failed to list prompts: %v", err), nil)
		return
	}

	result := ListPromptsResult{
		Prompts: prompts,
	}
	s.sendSuccessResponse(req.ID, result)
}

func (s *Server) handleGetPrompt(req *JSONRPCRequest) {
	if !s.isReady() {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidRequest, 
			"Server not initialized", nil)
		return
	}

	var params GetPromptParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidParams, 
			"Invalid get prompt parameters", nil)
		return
	}
	
	ctx := context.Background()
	result, err := s.promptManager.GetPrompt(ctx, params.Name, params.Arguments)
	if err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeMethodNotFound, 
			fmt.Sprintf("Prompt not found: %s", params.Name), nil)
		return
	}

	s.sendSuccessResponse(req.ID, result)
}

func (s *Server) handleSetLevel(req *JSONRPCRequest) {
	var params SetLevelParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendErrorResponse(req.ID, ErrorCodeInvalidParams, 
			"Invalid set level parameters", nil)
		return
	}
	
	s.logLevel = params.Level
	s.logger.Info().
		Str("level", string(params.Level)).
		Msg("Log level changed")
	
	s.sendSuccessResponse(req.ID, nil)
}

// Helper methods

func (s *Server) isReady() bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state == ServerStateReady
}

func (s *Server) convertToolSchema(schema map[string]interface{}) ToolInputSchema {
	inputSchema := ToolInputSchema{
		Type: "object",
		Properties: make(map[string]ToolPropertySchema),
		Required: []string{},
	}
	
	if properties, ok := schema["properties"].(map[string]interface{}); ok {
		for name, prop := range properties {
			if propMap, ok := prop.(map[string]interface{}); ok {
				propSchema := ToolPropertySchema{}
				
				if propType, ok := propMap["type"].(string); ok {
					propSchema.Type = propType
				}
				
				if desc, ok := propMap["description"].(string); ok {
					propSchema.Description = desc
				}
				
				if def := propMap["default"]; def != nil {
					propSchema.Default = def
				}
				
				if enumVals, ok := propMap["enum"].([]interface{}); ok {
					propSchema.Enum = make([]string, len(enumVals))
					for i, val := range enumVals {
						if str, ok := val.(string); ok {
							propSchema.Enum[i] = str
						}
					}
				}
				
				inputSchema.Properties[name] = propSchema
			}
		}
	}
	
	if required, ok := schema["required"].([]interface{}); ok {
		for _, req := range required {
			if str, ok := req.(string); ok {
				inputSchema.Required = append(inputSchema.Required, str)
			}
		}
	}
	
	return inputSchema
}

func (s *Server) sendSuccessResponse(id *json.RawMessage, result interface{}) {
	var resultData json.RawMessage
	if result != nil {
		data, err := json.Marshal(result)
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to marshal response result")
			s.sendErrorResponse(id, ErrorCodeInternalError, "Failed to marshal result", nil)
			return
		}
		resultData = data
	}
	
	response := JSONRPCResponse{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      id,
		},
		Result: resultData,
	}
	
	s.sendMessage(response)
}

func (s *Server) sendErrorResponse(id *json.RawMessage, code int, message string, data interface{}) {
	var errorData json.RawMessage
	if data != nil {
		dataBytes, err := json.Marshal(data)
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to marshal error data")
		} else {
			errorData = dataBytes
		}
	}
	
	response := JSONRPCResponse{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      id,
		},
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    errorData,
		},
	}
	
	s.sendMessage(response)
}

func (s *Server) sendNotification(method string, params interface{}) {
	var paramsData json.RawMessage
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to marshal notification params")
			return
		}
		paramsData = data
	}
	
	notification := JSONRPCNotification{
		JSONRPC: JSONRPC20Version,
		Method:  method,
		Params:  paramsData,
	}
	
	s.sendMessage(notification)
}

func (s *Server) sendMessage(message interface{}) {
	data, err := json.Marshal(message)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to marshal message")
		return
	}
	
	data = append(data, '\n')
	
	if _, err := s.writer.Write(data); err != nil {
		s.logger.Error().Err(err).Msg("Failed to write message")
	}
	
	s.logger.Debug().
		RawJSON("message", data[:len(data)-1]). // Remove newline for logging
		Msg("Sent message")
}

// LogMessage sends a log message notification to the client
func (s *Server) LogMessage(level LogLevel, logger string, data interface{}) {
	params := LogMessageParams{
		Level:  level,
		Logger: logger,
		Data:   data,
	}
	
	s.sendNotification(MethodLog, params)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() {
	s.shutdownOnce.Do(func() {
		close(s.shutdownCh)
	})
}

// cleanup performs cleanup operations for the server
func (s *Server) cleanup() {
	s.logger.Info().Msg("Starting server cleanup")

	// Stop subscription manager
	if s.subscriptionManager != nil {
		if err := s.subscriptionManager.Stop(); err != nil {
			s.logger.Error().Err(err).Msg("Failed to stop subscription manager")
		}
	}

	// Clean up stream manager
	if s.streamManager != nil {
		s.streamManager.CleanupCompletedStreams()
	}

	s.logger.Info().Msg("Server cleanup completed")
}

// Utility functions
func boolPtr(b bool) *bool {
	return &b
}