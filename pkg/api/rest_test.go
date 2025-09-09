package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/sandboxrunner/mcp-server/pkg/mcp"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock sandbox manager for testing
type MockSandboxManager struct {
	mock.Mock
}

func (m *MockSandboxManager) CreateSandbox(ctx context.Context, config sandbox.SandboxConfig) (*sandbox.Sandbox, error) {
	args := m.Called(ctx, config)
	return args.Get(0).(*sandbox.Sandbox), args.Error(1)
}

func (m *MockSandboxManager) GetSandbox(sandboxID string) (*sandbox.Sandbox, error) {
	args := m.Called(sandboxID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*sandbox.Sandbox), args.Error(1)
}

func (m *MockSandboxManager) ListSandboxes() ([]*sandbox.Sandbox, error) {
	args := m.Called()
	return args.Get(0).([]*sandbox.Sandbox), args.Error(1)
}

func (m *MockSandboxManager) StopSandbox(ctx context.Context, sandboxID string) error {
	args := m.Called(ctx, sandboxID)
	return args.Error(0)
}

func (m *MockSandboxManager) DeleteSandbox(ctx context.Context, sandboxID string) error {
	args := m.Called(ctx, sandboxID)
	return args.Error(0)
}

func (m *MockSandboxManager) GetSandboxLogs(ctx context.Context, sandboxID string) ([]byte, error) {
	args := m.Called(ctx, sandboxID)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSandboxManager) UpdateSandboxMetadata(sandboxID string, metadata map[string]interface{}) error {
	args := m.Called(sandboxID, metadata)
	return args.Error(0)
}

func (m *MockSandboxManager) Close() error {
	args := m.Called()
	return args.Error(0)
}

// TestNewRESTAPI tests REST API creation
func TestNewRESTAPI(t *testing.T) {
	config := DefaultRESTAPIConfig()
	sandboxManager := &MockSandboxManager{}
	toolRegistry := tools.NewRegistry()
	mcpServer := createTestMCPServer(t)
	logger := zerolog.Nop()
	
	api := NewRESTAPI(config, sandboxManager, toolRegistry, mcpServer, logger)
	
	assert.NotNil(t, api)
	assert.Equal(t, config, api.config)
	assert.Equal(t, sandboxManager, api.sandboxManager)
	assert.NotNil(t, api.router)
	assert.NotNil(t, api.openAPISpec)
}

// TestRESTAPI_ListSandboxes tests sandbox listing
func TestRESTAPI_ListSandboxes(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		mockResponse   []*sandbox.Sandbox
		mockError      error
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:        "successful list",
			queryParams: "",
			mockResponse: []*sandbox.Sandbox{
				{
					ID:          "sb1",
					ContainerID: "container-sb1",
					Status:      sandbox.SandboxStatusRunning,
					WorkingDir:  "/tmp/sb1",
					Environment: map[string]string{},
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
					Config: sandbox.SandboxConfig{
						Image: "ubuntu:22.04",
					},
					Metadata: map[string]interface{}{"name": "test-sandbox-1"},
				},
				{
					ID:          "sb2",
					ContainerID: "container-sb2",
					Status:      sandbox.SandboxStatusStopped,
					WorkingDir:  "/tmp/sb2",
					Environment: map[string]string{},
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
					Config: sandbox.SandboxConfig{
						Image: "python:3.9",
					},
					Metadata: map[string]interface{}{"name": "test-sandbox-2"},
				},
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response ListResponse
				err := json.Unmarshal([]byte(body), &response)
				require.NoError(t, err)
				
				sandboxes := response.Data.([]interface{})
				assert.Len(t, sandboxes, 2)
				assert.Equal(t, 2, response.Total)
			},
		},
		{
			name:        "with pagination",
			queryParams: "page_size=1&page_offset=0",
			mockResponse: []*sandbox.Sandbox{
				{
					ID:          "sb1",
					ContainerID: "container-sb1",
					Status:      sandbox.SandboxStatusRunning,
					WorkingDir:  "/tmp/sb1",
					Environment: map[string]string{},
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
					Config: sandbox.SandboxConfig{
						Image: "ubuntu:22.04",
					},
					Metadata: map[string]interface{}{"name": "test-sandbox-1"},
				},
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response ListResponse
				err := json.Unmarshal([]byte(body), &response)
				require.NoError(t, err)
				
				assert.Equal(t, 1, response.Total)
			},
		},
		{
			name:           "manager error",
			queryParams:    "",
			mockResponse:   nil,
			mockError:      fmt.Errorf("database error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, mockManager := createTestRESTAPI(t)
			
			mockManager.On("ListSandboxes", mock.Anything).Return(tt.mockResponse, tt.mockError)
			
			req := httptest.NewRequest("GET", "/api/v1/sandboxes?"+tt.queryParams, nil)
			w := httptest.NewRecorder()
			
			api.router.ServeHTTP(w, req)
			
			resp := w.Result()
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			if tt.checkResponse != nil {
				body := w.Body.String()
				tt.checkResponse(t, body)
			}
			
			mockManager.AssertExpectations(t)
		})
	}
}

// TestRESTAPI_CreateSandbox tests sandbox creation
func TestRESTAPI_CreateSandbox(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    CreateSandboxRequest
		mockResponse   *sandbox.Sandbox
		mockError      error
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "successful creation",
			requestBody: CreateSandboxRequest{
				Name:  "test-sandbox",
				Image: "ubuntu:22.04",
				Resources: map[string]interface{}{
					"cpu":    "1.0",
					"memory": "1G",
				},
			},
			mockResponse: &sandbox.Sandbox{
				ID:          "sb1",
				ContainerID: "container-sb1",
				Status:      sandbox.SandboxStatusCreating,
				WorkingDir:  "/tmp/sb1",
				Environment: map[string]string{},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Config: sandbox.SandboxConfig{
					Image: "ubuntu:22.04",
				},
				Metadata: map[string]interface{}{"name": "test-sandbox"},
			},
			mockError:      nil,
			expectedStatus: http.StatusCreated,
			checkResponse: func(t *testing.T, body string) {
				var response CreateSandboxResponse
				err := json.Unmarshal([]byte(body), &response)
				require.NoError(t, err)
				
				assert.Equal(t, "sb1", response.ID)
				assert.Equal(t, "test-sandbox", response.Name)
			},
		},
		{
			name: "invalid request body",
			requestBody: CreateSandboxRequest{
				Image: "", // Missing required field
			},
			expectedStatus: http.StatusBadRequest,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, _ := createTestRESTAPI(t)
			
			// Add create tool to registry
			createTool := &MockTool{name: "create_sandbox"}
			if tt.mockResponse != nil {
				resultText, _ := json.Marshal(map[string]interface{}{
					"id": tt.mockResponse.ID,
				})
				createTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
					Text: string(resultText),
				}, tt.mockError)
			} else {
				createTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
					Text: "error",
				}, tt.mockError)
			}
			
			api.toolRegistry.RegisterTool(createTool)
			
			jsonBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/api/v1/sandboxes", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			
			w := httptest.NewRecorder()
			api.router.ServeHTTP(w, req)
			
			resp := w.Result()
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			if tt.checkResponse != nil {
				body := w.Body.String()
				tt.checkResponse(t, body)
			}
		})
	}
}

// TestRESTAPI_GetSandbox tests getting individual sandbox
func TestRESTAPI_GetSandbox(t *testing.T) {
	tests := []struct {
		name           string
		sandboxID      string
		mockResponse   *sandbox.Sandbox
		mockError      error
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:      "successful get",
			sandboxID: "sb1",
			mockResponse: &sandbox.Sandbox{
				ID:          "sb1",
				ContainerID: "container-sb1",
				Status:      sandbox.SandboxStatusRunning,
				WorkingDir:  "/tmp/sb1",
				Environment: map[string]string{},
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
				Config: sandbox.SandboxConfig{
					Image: "ubuntu:22.04",
				},
				Metadata: map[string]interface{}{"name": "test-sandbox"},
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response SandboxResponse
				err := json.Unmarshal([]byte(body), &response)
				require.NoError(t, err)
				
				assert.Equal(t, "sb1", response.ID)
				assert.Equal(t, "test-sandbox", response.Name)
			},
		},
		{
			name:           "sandbox not found",
			sandboxID:      "nonexistent",
			mockResponse:   nil,
			mockError:      sandbox.ErrSandboxNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "manager error",
			sandboxID:      "sb1",
			mockResponse:   nil,
			mockError:      fmt.Errorf("database error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, mockManager := createTestRESTAPI(t)
			
			mockManager.On("GetSandbox", mock.Anything, tt.sandboxID).Return(tt.mockResponse, tt.mockError)
			
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/sandboxes/%s", tt.sandboxID), nil)
			w := httptest.NewRecorder()
			
			api.router.ServeHTTP(w, req)
			
			resp := w.Result()
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			if tt.checkResponse != nil {
				body := w.Body.String()
				tt.checkResponse(t, body)
			}
			
			mockManager.AssertExpectations(t)
		})
	}
}

// TestRESTAPI_DeleteSandbox tests sandbox deletion
func TestRESTAPI_DeleteSandbox(t *testing.T) {
	tests := []struct {
		name           string
		sandboxID      string
		mockError      error
		expectedStatus int
	}{
		{
			name:           "successful deletion",
			sandboxID:      "sb1",
			mockError:      nil,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "tool error",
			sandboxID:      "sb1",
			mockError:      fmt.Errorf("termination failed"),
			expectedStatus: http.StatusInternalServerError,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api, _ := createTestRESTAPI(t)
			
			// Add terminate tool to registry
			terminateTool := &MockTool{name: "terminate_sandbox"}
			terminateTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
				Text: "terminated",
			}, tt.mockError)
			
			api.toolRegistry.RegisterTool(terminateTool)
			
			req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/sandboxes/%s", tt.sandboxID), nil)
			w := httptest.NewRecorder()
			
			api.router.ServeHTTP(w, req)
			
			resp := w.Result()
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
		})
	}
}

// TestRESTAPI_ListFiles tests file listing
func TestRESTAPI_ListFiles(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	// Add list files tool
	listTool := &MockTool{name: "list_files"}
	files := []map[string]interface{}{
		{"name": "file1.txt", "size": 100, "is_dir": false},
		{"name": "dir1", "size": 0, "is_dir": true},
	}
	filesJSON, _ := json.Marshal(files)
	
	listTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text: string(filesJSON),
	}, nil)
	
	api.toolRegistry.RegisterTool(listTool)
	
	req := httptest.NewRequest("GET", "/api/v1/sandboxes/sb1/files?path=/home", nil)
	w := httptest.NewRecorder()
	
	api.router.ServeHTTP(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var response map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	
	assert.Equal(t, "/home", response["path"])
	assert.NotEmpty(t, response["files"])
}

// TestRESTAPI_GetFile tests file retrieval
func TestRESTAPI_GetFile(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	// Add read file tool
	readTool := &MockTool{name: "read_file"}
	readTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text: "file content",
	}, nil)
	
	api.toolRegistry.RegisterTool(readTool)
	
	req := httptest.NewRequest("GET", "/api/v1/sandboxes/sb1/files/test.txt", nil)
	w := httptest.NewRecorder()
	
	api.router.ServeHTTP(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var response FileResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	
	assert.Equal(t, "test.txt", response.Path)
	assert.Equal(t, "file content", response.Content)
}

// TestRESTAPI_ListTools tests tool listing
func TestRESTAPI_ListTools(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	// Add some mock tools
	tool1 := &MockTool{name: "tool1", description: "Test tool 1"}
	tool2 := &MockTool{name: "tool2", description: "Test tool 2"}
	
	api.toolRegistry.RegisterTool(tool1)
	api.toolRegistry.RegisterTool(tool2)
	
	req := httptest.NewRequest("GET", "/api/v1/tools", nil)
	w := httptest.NewRecorder()
	
	api.router.ServeHTTP(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var response ListResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	
	tools := response.Data.([]interface{})
	assert.Len(t, tools, 2)
	assert.Equal(t, 2, response.Total)
}

// TestRESTAPI_ExecuteTool tests tool execution
func TestRESTAPI_ExecuteTool(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	// Add test tool
	testTool := &MockTool{name: "test_tool"}
	testTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text:    "execution result",
		IsError: false,
	}, nil)
	
	api.toolRegistry.RegisterTool(testTool)
	
	request := ExecuteToolRequest{
		Arguments: map[string]interface{}{
			"arg1": "value1",
		},
	}
	
	jsonBody, _ := json.Marshal(request)
	req := httptest.NewRequest("POST", "/api/v1/tools/test_tool/execute", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var response ExecuteToolResponse
	err := json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(t, err)
	
	assert.Equal(t, "execution result", response.Result)
	assert.False(t, response.IsError)
}

// TestRESTAPI_Middleware tests middleware functions
func TestRESTAPI_Middleware(t *testing.T) {
	t.Run("versioning middleware", func(t *testing.T) {
		config := DefaultRESTAPIConfig()
		config.EnableVersioning = true
		config.SupportedVersions = []APIVersion{V1}
		
		api, _ := createTestRESTAPIWithConfig(t, config)
		
		// Test unsupported version
		req := httptest.NewRequest("GET", "/api/v1/sandboxes", nil)
		req.Header.Set("API-Version", "v999")
		
		w := httptest.NewRecorder()
		api.router.ServeHTTP(w, req)
		
		// Should still work since URL version takes precedence
		// This test verifies the middleware is in place
		assert.NotEqual(t, http.StatusBadRequest, w.Result().StatusCode)
	})
}

// TestRESTAPI_QueryParams tests query parameter parsing
func TestRESTAPI_QueryParams(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	values := url.Values{}
	values.Set("page_size", "50")
	values.Set("page_offset", "100")
	values.Set("sort_by", "name")
	values.Set("sort_order", "desc")
	values.Set("filter_status", "running")
	values.Set("filter_image", "ubuntu")
	
	params := api.parseQueryParams(values)
	
	assert.Equal(t, 50, params.PageSize)
	assert.Equal(t, 100, params.PageOffset)
	assert.Equal(t, "name", params.SortBy)
	assert.Equal(t, "desc", params.SortOrder)
	assert.Equal(t, "running", params.Filters["status"])
	assert.Equal(t, "ubuntu", params.Filters["image"])
}

// TestRESTAPI_Filtering tests filtering functionality
func TestRESTAPI_Filtering(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	sandboxes := []SandboxResponse{
		{ID: "sb1", Status: "running", Image: "ubuntu:22.04", Name: "test1"},
		{ID: "sb2", Status: "stopped", Image: "python:3.9", Name: "test2"},
		{ID: "sb3", Status: "running", Image: "ubuntu:20.04", Name: "prod1"},
	}
	
	// Filter by status
	filtered := api.filterSandboxes(sandboxes, map[string]string{"status": "running"})
	assert.Len(t, filtered, 2)
	
	// Filter by image
	filtered = api.filterSandboxes(sandboxes, map[string]string{"image": "ubuntu"})
	assert.Len(t, filtered, 2)
	
	// Filter by name
	filtered = api.filterSandboxes(sandboxes, map[string]string{"name": "test"})
	assert.Len(t, filtered, 2)
	
	// Multiple filters
	filtered = api.filterSandboxes(sandboxes, map[string]string{
		"status": "running",
		"image":  "ubuntu",
	})
	assert.Len(t, filtered, 2)
}

// TestRESTAPI_OpenAPISpec tests OpenAPI specification generation
func TestRESTAPI_OpenAPISpec(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	req := httptest.NewRequest("GET", "/api/openapi.json", nil)
	w := httptest.NewRecorder()
	
	api.router.ServeHTTP(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	
	var spec map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&spec)
	require.NoError(t, err)
	
	assert.Equal(t, "3.0.3", spec["openapi"])
	assert.NotEmpty(t, spec["info"])
	assert.NotEmpty(t, spec["paths"])
	assert.NotEmpty(t, spec["components"])
}

// TestRESTAPI_APIDocs tests API documentation endpoint
func TestRESTAPI_APIDocs(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	req := httptest.NewRequest("GET", "/api/docs", nil)
	w := httptest.NewRecorder()
	
	api.router.ServeHTTP(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/html", resp.Header.Get("Content-Type"))
	
	body := w.Body.String()
	assert.Contains(t, body, "Swagger")
	assert.Contains(t, body, "/api/openapi.json")
}

// TestRESTAPI_ErrorHandling tests error handling
func TestRESTAPI_ErrorHandling(t *testing.T) {
	api, _ := createTestRESTAPI(t)
	
	// Test 404
	req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
	w := httptest.NewRecorder()
	
	api.router.ServeHTTP(w, req)
	
	resp := w.Result()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Benchmark tests

// BenchmarkRESTAPI_ListSandboxes benchmarks sandbox listing
func BenchmarkRESTAPI_ListSandboxes(b *testing.B) {
	api, mockManager := createTestRESTAPI(nil)
	
	sandboxes := make([]*sandbox.Sandbox, 100)
	for i := 0; i < 100; i++ {
		sandboxes[i] = &sandbox.Sandbox{
			ID:          fmt.Sprintf("sb%d", i),
			ContainerID: fmt.Sprintf("container-sb%d", i),
			Status:      sandbox.SandboxStatusRunning,
			WorkingDir:  fmt.Sprintf("/tmp/sb%d", i),
			Environment: map[string]string{},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			Config: sandbox.SandboxConfig{
				Image: "ubuntu:22.04",
			},
			Metadata: map[string]interface{}{"name": fmt.Sprintf("sandbox-%d", i)},
		}
	}
	
	mockManager.On("ListSandboxes", mock.Anything).Return(sandboxes, nil)
	
	req := httptest.NewRequest("GET", "/api/v1/sandboxes", nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		api.router.ServeHTTP(w, req)
	}
}

// Helper functions and mocks

// Mock tool for testing
type MockTool struct {
	mock.Mock
	name        string
	description string
	schema      map[string]interface{}
}

func (m *MockTool) Name() string {
	if m.name != "" {
		return m.name
	}
	return "mock-tool"
}

func (m *MockTool) Description() string {
	if m.description != "" {
		return m.description
	}
	return "Mock tool for testing"
}

func (m *MockTool) Schema() map[string]interface{} {
	if m.schema != nil {
		return m.schema
	}
	return map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"arg1": map[string]interface{}{
				"type": "string",
			},
		},
	}
}

func (m *MockTool) Execute(ctx context.Context, args map[string]interface{}) (*tools.ToolResult, error) {
	mockArgs := m.Called(ctx, args)
	return mockArgs.Get(0).(*tools.ToolResult), mockArgs.Error(1)
}

func createTestMCPServer(t testing.TB) *mcp.Server {
	if t == nil {
		// For benchmarks
		config := mcp.ServerConfig{
			Name:    "Test Server",
			Version: "1.0.0",
		}
		return mcp.NewServer(config)
	}
	
	toolRegistry := tools.NewRegistry()
	logger := zerolog.Nop()
	
	config := mcp.ServerConfig{
		Name:         "Test MCP Server",
		Version:      "1.0.0",
		Logger:       &logger,
		ToolRegistry: toolRegistry,
	}
	
	return mcp.NewServer(config)
}

func createTestRESTAPI(t testing.TB) (*RESTAPI, *MockSandboxManager) {
	return createTestRESTAPIWithConfig(t, DefaultRESTAPIConfig())
}

func createTestRESTAPIWithConfig(t testing.TB, config RESTAPIConfig) (*RESTAPI, *MockSandboxManager) {
	mockManager := &MockSandboxManager{}
	toolRegistry := tools.NewRegistry()
	mcpServer := createTestMCPServer(t)
	logger := zerolog.Nop()
	
	api := NewRESTAPI(config, mockManager, toolRegistry, mcpServer, logger)
	
	return api, mockManager
}

// Integration test for full API workflow
func TestRESTAPI_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	api, mockManager := createTestRESTAPI(t)
	
	// Setup mock responses for a complete workflow
	testSandbox := &sandbox.Sandbox{
		ID:          "integration-test-sb",
		ContainerID: "container-integration-test",
		Status:      sandbox.SandboxStatusRunning,
		WorkingDir:  "/tmp/integration-test",
		Environment: map[string]string{},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Config: sandbox.SandboxConfig{
			Image: "ubuntu:22.04",
		},
		Metadata: map[string]interface{}{"name": "integration-test"},
	}
	
	// Mock list (initially empty)
	mockManager.On("ListSandboxes", mock.Anything).Return([]*sandbox.Sandbox{}, nil).Once()
	
	// Mock creation
	createTool := &MockTool{name: "create_sandbox"}
	resultText, _ := json.Marshal(map[string]interface{}{"id": testSandbox.ID})
	createTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text: string(resultText),
	}, nil)
	api.toolRegistry.RegisterTool(createTool)
	
	// Mock get after creation
	mockManager.On("GetSandbox", mock.Anything, testSandbox.ID).Return(testSandbox, nil)
	
	// Mock list after creation
	mockManager.On("ListSandboxes", mock.Anything).Return([]*sandbox.Sandbox{testSandbox}, nil).Once()
	
	// Mock termination
	terminateTool := &MockTool{name: "terminate_sandbox"}
	terminateTool.On("Execute", mock.Anything, mock.Anything).Return(&tools.ToolResult{
		Text: "terminated",
	}, nil)
	api.toolRegistry.RegisterTool(terminateTool)
	
	server := httptest.NewServer(api.router)
	defer server.Close()
	
	client := &http.Client{Timeout: 10 * time.Second}
	
	// 1. List sandboxes (should be empty)
	resp, err := client.Get(server.URL + "/api/v1/sandboxes")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	
	// 2. Create sandbox
	createReq := CreateSandboxRequest{
		Name:  "integration-test",
		Image: "ubuntu:22.04",
	}
	jsonBody, _ := json.Marshal(createReq)
	
	resp, err = client.Post(server.URL+"/api/v1/sandboxes", "application/json", bytes.NewReader(jsonBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()
	
	// 3. Get created sandbox
	resp, err = client.Get(server.URL + "/api/v1/sandboxes/" + testSandbox.ID)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	
	// 4. List sandboxes (should have one)
	resp, err = client.Get(server.URL + "/api/v1/sandboxes")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
	
	// 5. Delete sandbox
	req, _ := http.NewRequest("DELETE", server.URL+"/api/v1/sandboxes/"+testSandbox.ID, nil)
	resp, err = client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	resp.Body.Close()
	
	mockManager.AssertExpectations(t)
}