package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_NewServer(t *testing.T) {
	logger := zerolog.Nop()
	toolRegistry := tools.NewRegistry()

	config := ServerConfig{
		Name:         "test-server",
		Version:      "1.0.0",
		Logger:       &logger,
		ToolRegistry: toolRegistry,
		ResourceConfig: &ResourceConfig{
			EnableCaching: true,
			EnableMetrics: true,
		},
		PromptConfig: &PromptConfig{
			EnableCaching:     true,
			EnableValidation:  true,
			EnableComposition: true,
			EnableMetrics:     true,
		},
		StreamConfig: &StreamConfig{
			MaxConcurrentStreams: 10,
			EnableMetrics:        true,
		},
		SubscriptionConfig: &SubscriptionConfig{
			MaxSubscribers: 100,
			EnableMetrics:  true,
		},
	}

	server := NewServer(config)
	assert.NotNil(t, server)
	assert.Equal(t, config.Name, server.info.Name)
	assert.Equal(t, config.Version, server.info.Version)
	assert.Equal(t, ServerStateUninitialized, server.state)
	assert.NotNil(t, server.resourceManager)
	assert.NotNil(t, server.promptManager)
	assert.NotNil(t, server.streamManager)
	assert.NotNil(t, server.subscriptionManager)

	// Verify capabilities are properly set
	assert.NotNil(t, server.capabilities.Resources)
	assert.True(t, *server.capabilities.Resources.Subscribe)
	assert.True(t, *server.capabilities.Resources.ListChanged)
	assert.True(t, *server.capabilities.Prompts.ListChanged)
}

func TestServer_NewServerWithDefaults(t *testing.T) {
	config := ServerConfig{
		Name:    "default-server",
		Version: "1.0.0",
	}

	server := NewServer(config)
	assert.NotNil(t, server)
	assert.NotNil(t, server.toolRegistry)
	assert.NotNil(t, server.resourceManager)
	assert.NotNil(t, server.promptManager)
	assert.NotNil(t, server.streamManager)
	assert.NotNil(t, server.subscriptionManager)
}

func TestServer_Initialize(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)

	// Prepare initialize request
	initParams := InitializeParams{
		ProtocolVersion: "2024-11-05",
		Capabilities: ClientCapabilities{
			Experimental: map[string]interface{}{},
		},
		ClientInfo: ClientInfo{
			Name:    "test-client",
			Version: "1.0.0",
		},
	}

	paramsData, err := json.Marshal(initParams)
	require.NoError(t, err)

	id := json.RawMessage(`"1"`)
	initRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id,
		},
		Method: MethodInitialize,
		Params: paramsData,
	}

	requestData, err := json.Marshal(initRequest)
	require.NoError(t, err)

	inputBuffer.WriteString(string(requestData) + "\n")

	// Process the initialize request
	server.processMessage(requestData)

	// Wait for processing to complete
	time.Sleep(time.Millisecond * 100)

	// Verify server state changed
	assert.Equal(t, ServerStateReady, server.state)
	assert.NotNil(t, server.clientInfo)
	assert.Equal(t, "test-client", server.clientInfo.Name)

	// Verify response was sent
	output := outputBuffer.String()
	assert.Contains(t, output, "result")
	assert.Contains(t, output, "2024-11-05")
}

func TestServer_ListResources(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	server.state = ServerStateReady // Skip initialization

	// Register a test resource
	resource := Resource{
		URI:         "test://resource1",
		Name:        "Test Resource",
		Description: "A test resource",
		MimeType:    "text/plain",
	}
	err := server.resourceManager.RegisterResource(resource, nil)
	require.NoError(t, err)

	// Prepare list resources request
	id2 := json.RawMessage(`"2"`)
	listRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id2,
		},
		Method: MethodListResources,
	}

	requestData, err := json.Marshal(listRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify response
	output := outputBuffer.String()
	assert.Contains(t, output, "result")
	assert.Contains(t, output, "test://resource1")
	assert.Contains(t, output, "Test Resource")
}

func TestServer_ReadResource(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	server.state = ServerStateReady

	// Register a test resource
	resource := Resource{
		URI:         "test://resource1",
		Name:        "Test Resource",
		Description: "A test resource",
		MimeType:    "text/plain",
	}
	err := server.resourceManager.RegisterResource(resource, nil)
	require.NoError(t, err)

	// Prepare read resource request
	readParams := ReadResourceParams{
		URI: "test://resource1",
	}
	paramsData, err := json.Marshal(readParams)
	require.NoError(t, err)

	id3 := json.RawMessage(`"3"`)
	readRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id3,
		},
		Method: MethodReadResource,
		Params: paramsData,
	}

	requestData, err := json.Marshal(readRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify response
	output := outputBuffer.String()
	assert.Contains(t, output, "result")
	assert.Contains(t, output, "contents")
}

func TestServer_ListPrompts(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	server.state = ServerStateReady

	// Register a test prompt
	prompt := Prompt{
		Name:        "test-prompt",
		Description: "A test prompt",
		Arguments: []PromptArgument{
			{
				Name:        "subject",
				Description: "The subject",
				Required:    boolPtr(true),
			},
		},
	}
	err := server.promptManager.RegisterPrompt(prompt, nil)
	require.NoError(t, err)

	// Prepare list prompts request
	id4 := json.RawMessage(`"4"`)
	listRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id4,
		},
		Method: MethodListPrompts,
	}

	requestData, err := json.Marshal(listRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify response
	output := outputBuffer.String()
	assert.Contains(t, output, "result")
	assert.Contains(t, output, "test-prompt")
}

func TestServer_GetPrompt(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	server.state = ServerStateReady

	// Register a test prompt
	prompt := Prompt{
		Name:        "greeting-prompt",
		Description: "A greeting prompt",
		Arguments: []PromptArgument{
			{
				Name:        "name",
				Description: "The name to greet",
				Required:    boolPtr(true),
			},
		},
	}
	err := server.promptManager.RegisterPrompt(prompt, nil)
	require.NoError(t, err)

	// Prepare get prompt request
	getParams := GetPromptParams{
		Name: "greeting-prompt",
		Arguments: map[string]interface{}{
			"name": "Alice",
		},
	}
	paramsData, err := json.Marshal(getParams)
	require.NoError(t, err)

	id5 := json.RawMessage(`"5"`)
	getRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id5,
		},
		Method: MethodGetPrompt,
		Params: paramsData,
	}

	requestData, err := json.Marshal(getRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify response
	output := outputBuffer.String()
	assert.Contains(t, output, "result")
	assert.Contains(t, output, "messages")
}

func TestServer_ListTools(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	// Create a mock tool registry with a test tool
	toolRegistry := tools.NewRegistry()
	
	config := ServerConfig{
		Name:         "test-server",
		Version:      "1.0.0",
		Reader:       &inputBuffer,
		Writer:       &outputBuffer,
		ToolRegistry: toolRegistry,
	}

	server := NewServer(config)
	server.state = ServerStateReady

	// Prepare list tools request
	id6 := json.RawMessage(`"6"`)
	listRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id6,
		},
		Method: MethodListTools,
	}

	requestData, err := json.Marshal(listRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify response
	output := outputBuffer.String()
	assert.Contains(t, output, "result")
	assert.Contains(t, output, "tools")
}

func TestServer_HandleInvalidRequest(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)

	// Process invalid JSON
	server.processMessage([]byte("invalid json"))

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify error response
	output := outputBuffer.String()
	assert.Contains(t, output, "error")
	assert.Contains(t, output, "Invalid JSON-RPC message")
}

func TestServer_HandleMethodNotFound(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	server.state = ServerStateReady

	// Prepare request with unknown method
	id7 := json.RawMessage(`"7"`)
	unknownRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id7,
		},
		Method: "unknown/method",
	}

	requestData, err := json.Marshal(unknownRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify error response
	output := outputBuffer.String()
	assert.Contains(t, output, "error")
	assert.Contains(t, output, "Method not found")
}

func TestServer_HandleUninitializedRequest(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	// Don't set state to ready - leave uninitialized

	// Prepare list resources request without initialization
	id8 := json.RawMessage(`"8"`)
	listRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id8,
		},
		Method: MethodListResources,
	}

	requestData, err := json.Marshal(listRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify error response
	output := outputBuffer.String()
	assert.Contains(t, output, "error")
	assert.Contains(t, output, "Server not initialized")
}

func TestServer_Shutdown(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	server.state = ServerStateReady

	// Prepare shutdown request
	id9 := json.RawMessage(`"9"`)
	shutdownRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id9,
		},
		Method: MethodShutdown,
	}

	requestData, err := json.Marshal(shutdownRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify server state changed
	assert.Equal(t, ServerStateShuttingDown, server.state)

	// Verify response was sent
	output := outputBuffer.String()
	assert.Contains(t, output, "result")
}

func TestServer_SetLogLevel(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	server.state = ServerStateReady

	// Prepare set level request
	setLevelParams := SetLevelParams{
		Level: LogLevelDebug,
	}
	paramsData, err := json.Marshal(setLevelParams)
	require.NoError(t, err)

	id10 := json.RawMessage(`"10"`)
	setLevelRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &id10,
		},
		Method: MethodSetLevel,
		Params: paramsData,
	}

	requestData, err := json.Marshal(setLevelRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify log level changed
	assert.Equal(t, LogLevelDebug, server.logLevel)

	// Verify response was sent
	output := outputBuffer.String()
	assert.Contains(t, output, "result")
}

func TestServer_RunWithEOF(t *testing.T) {
	// Create a reader that will immediately return EOF
	reader := strings.NewReader("")
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  reader,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := server.Run(ctx)
	assert.NoError(t, err) // EOF should not be treated as an error
}

func TestServer_RunWithContext(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()

	err := server.Run(ctx)
	assert.Equal(t, context.DeadlineExceeded, err)
}

func TestServer_LogMessage(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)

	// Send a log message
	server.LogMessage(LogLevelInfo, "test-logger", map[string]interface{}{
		"message": "test log message",
		"data":    123,
	})

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify notification was sent
	output := outputBuffer.String()
	assert.Contains(t, output, "notifications/message")
	assert.Contains(t, output, "test log message")
	assert.Contains(t, output, "info")
}

func TestServer_RequestTracking(t *testing.T) {
	var inputBuffer bytes.Buffer
	var outputBuffer bytes.Buffer

	config := ServerConfig{
		Name:    "test-server",
		Version: "1.0.0",
		Reader:  &inputBuffer,
		Writer:  &outputBuffer,
	}

	server := NewServer(config)
	server.state = ServerStateReady

	// Prepare list resources request with ID
	idTrack := json.RawMessage(`"track-test"`)
	listRequest := JSONRPCRequest{
		JSONRPCMessage: JSONRPCMessage{
			JSONRPC: JSONRPC20Version,
			ID:      &idTrack,
		},
		Method: MethodListResources,
	}

	requestData, err := json.Marshal(listRequest)
	require.NoError(t, err)

	// Process the request
	server.processMessage(requestData)

	// Wait for processing
	time.Sleep(time.Millisecond * 100)

	// Verify request was tracked and removed
	server.requestsMu.RLock()
	_, exists := server.activeRequests["track-test"]
	server.requestsMu.RUnlock()
	assert.False(t, exists, "Request should be removed from active requests after processing")
}

