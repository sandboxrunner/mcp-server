package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/sandboxrunner/mcp-server/pkg/mcp"
	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// APIVersion represents API version
type APIVersion string

const (
	V1 APIVersion = "v1"
	V2 APIVersion = "v2"
)

// RESTAPIConfig holds REST API configuration
type RESTAPIConfig struct {
	BasePath           string
	DefaultPageSize    int
	MaxPageSize        int
	EnableVersioning   bool
	SupportedVersions  []APIVersion
	DefaultVersion     APIVersion
	EnableFiltering    bool
	EnableSorting      bool
	EnableFieldSelection bool
	RequestTimeout     time.Duration
	MaxRetries         int
	EnableETag         bool
	EnableRateLimit    bool
	EnableValidation   bool
}

// DefaultRESTAPIConfig returns default REST API configuration
func DefaultRESTAPIConfig() RESTAPIConfig {
	return RESTAPIConfig{
		BasePath:           "/api",
		DefaultPageSize:    20,
		MaxPageSize:        100,
		EnableVersioning:   true,
		SupportedVersions:  []APIVersion{V1, V2},
		DefaultVersion:     V1,
		EnableFiltering:    true,
		EnableSorting:      true,
		EnableFieldSelection: true,
		RequestTimeout:     30 * time.Second,
		MaxRetries:         3,
		EnableETag:         true,
		EnableRateLimit:    true,
		EnableValidation:   true,
	}
}

// RESTAPI provides RESTful HTTP API for sandbox operations
type RESTAPI struct {
	config         RESTAPIConfig
	sandboxManager sandbox.SandboxManagerInterface
	toolRegistry   *tools.Registry
	mcpServer      *mcp.Server
	router         *mux.Router
	logger         zerolog.Logger
	openAPISpec    *OpenAPISpec
}

// NewRESTAPI creates a new REST API instance
func NewRESTAPI(config RESTAPIConfig, sandboxManager sandbox.SandboxManagerInterface, toolRegistry *tools.Registry, mcpServer *mcp.Server, logger zerolog.Logger) *RESTAPI {
	api := &RESTAPI{
		config:         config,
		sandboxManager: sandboxManager,
		toolRegistry:   toolRegistry,
		mcpServer:      mcpServer,
		router:         mux.NewRouter(),
		logger:         logger,
		openAPISpec:    generateOpenAPISpec(config),
	}
	
	api.setupRoutes()
	return api
}

// GetRouter returns the configured router
func (api *RESTAPI) GetRouter() *mux.Router {
	return api.router
}

// setupRoutes configures all REST API routes
func (api *RESTAPI) setupRoutes() {
	// Apply middleware
	api.router.Use(api.versioningMiddleware)
	api.router.Use(api.validationMiddleware)
	api.router.Use(api.etagMiddleware)
	
	// API base path
	apiRouter := api.router.PathPrefix(api.config.BasePath).Subrouter()
	
	// OpenAPI spec endpoint
	apiRouter.HandleFunc("/openapi.json", api.handleOpenAPISpec).Methods("GET")
	apiRouter.HandleFunc("/docs", api.handleAPIDocs).Methods("GET")
	
	// V1 routes
	v1Router := apiRouter.PathPrefix("/v1").Subrouter()
	api.setupV1Routes(v1Router)
	
	// V2 routes (if supported)
	if api.isVersionSupported(V2) {
		v2Router := apiRouter.PathPrefix("/v2").Subrouter()
		api.setupV2Routes(v2Router)
	}
	
	// Default version routes (without version prefix)
	if api.config.EnableVersioning {
		defaultRouter := apiRouter.PathPrefix("").Subrouter()
		api.setupDefaultRoutes(defaultRouter)
	}
}

// setupV1Routes configures version 1 API routes
func (api *RESTAPI) setupV1Routes(router *mux.Router) {
	// Sandboxes
	router.HandleFunc("/sandboxes", api.handleListSandboxes).Methods("GET")
	router.HandleFunc("/sandboxes", api.handleCreateSandbox).Methods("POST")
	router.HandleFunc("/sandboxes/{id}", api.handleGetSandbox).Methods("GET")
	router.HandleFunc("/sandboxes/{id}", api.handleUpdateSandbox).Methods("PUT", "PATCH")
	router.HandleFunc("/sandboxes/{id}", api.handleDeleteSandbox).Methods("DELETE")
	router.HandleFunc("/sandboxes/{id}/start", api.handleStartSandbox).Methods("POST")
	router.HandleFunc("/sandboxes/{id}/stop", api.handleStopSandbox).Methods("POST")
	router.HandleFunc("/sandboxes/{id}/restart", api.handleRestartSandbox).Methods("POST")
	
	// Files
	router.HandleFunc("/sandboxes/{id}/files", api.handleListFiles).Methods("GET")
	router.HandleFunc("/sandboxes/{id}/files", api.handleUploadFile).Methods("POST")
	router.HandleFunc("/sandboxes/{id}/files/{path:.*}", api.handleGetFile).Methods("GET")
	router.HandleFunc("/sandboxes/{id}/files/{path:.*}", api.handleUpdateFile).Methods("PUT")
	router.HandleFunc("/sandboxes/{id}/files/{path:.*}", api.handleDeleteFile).Methods("DELETE")
	
	// Commands
	router.HandleFunc("/sandboxes/{id}/exec", api.handleExecuteCommand).Methods("POST")
	router.HandleFunc("/sandboxes/{id}/code", api.handleRunCode).Methods("POST")
	
	// Tools
	router.HandleFunc("/tools", api.handleListTools).Methods("GET")
	router.HandleFunc("/tools/{name}", api.handleGetTool).Methods("GET")
	router.HandleFunc("/tools/{name}/execute", api.handleExecuteTool).Methods("POST")
	
	// Resources
	router.HandleFunc("/resources", api.handleListResources).Methods("GET")
	router.HandleFunc("/resources/{uri:.*}", api.handleGetResource).Methods("GET")
	
	// Prompts
	router.HandleFunc("/prompts", api.handleListPrompts).Methods("GET")
	router.HandleFunc("/prompts/{name}", api.handleGetPrompt).Methods("GET")
}

// setupV2Routes configures version 2 API routes (future expansion)
func (api *RESTAPI) setupV2Routes(router *mux.Router) {
	// V2 can have enhanced features like bulk operations, async operations, etc.
	api.setupV1Routes(router) // Start with V1 compatibility
	
	// V2-specific enhancements
	router.HandleFunc("/sandboxes:batch", api.handleBatchSandboxes).Methods("POST")
	router.HandleFunc("/sandboxes/{id}/logs", api.handleGetSandboxLogs).Methods("GET")
	router.HandleFunc("/sandboxes/{id}/metrics", api.handleGetSandboxMetrics).Methods("GET")
}

// setupDefaultRoutes configures default version routes
func (api *RESTAPI) setupDefaultRoutes(router *mux.Router) {
	switch api.config.DefaultVersion {
	case V2:
		api.setupV2Routes(router)
	default:
		api.setupV1Routes(router)
	}
}

// Sandbox handlers

func (api *RESTAPI) handleListSandboxes(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	params := api.parseQueryParams(r.URL.Query())
	
	// Get sandboxes from manager
	sandboxes, err := api.sandboxManager.ListSandboxes()
	if err != nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list sandboxes", err)
		return
	}
	
	// Convert to REST format
	restSandboxes := make([]SandboxResponse, len(sandboxes))
	for i, sb := range sandboxes {
		restSandboxes[i] = api.convertSandboxToResponse(sb)
	}
	
	// Apply filtering
	if api.config.EnableFiltering && len(params.Filters) > 0 {
		restSandboxes = api.filterSandboxes(restSandboxes, params.Filters)
	}
	
	// Apply sorting
	if api.config.EnableSorting && params.SortBy != "" {
		restSandboxes = api.sortSandboxes(restSandboxes, params.SortBy, params.SortOrder)
	}
	
	// Apply pagination
	total := len(restSandboxes)
	paginatedSandboxes, pagination := api.paginateResults(restSandboxes, params.PageSize, params.PageOffset)
	
	response := ListResponse{
		Data:       paginatedSandboxes,
		Pagination: pagination,
		Total:      total,
		Timestamp:  time.Now(),
	}
	
	api.writeJSONResponse(w, http.StatusOK, response)
}

func (api *RESTAPI) handleCreateSandbox(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	var req CreateSandboxRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	// Validate request
	if err := api.validateCreateSandboxRequest(req); err != nil {
		api.writeErrorResponse(w, http.StatusBadRequest, "Validation failed", err)
		return
	}
	
	// Create sandbox using tool
	createTool := api.toolRegistry.GetTool("create_sandbox")
	if createTool == nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Create sandbox tool not available", nil)
		return
	}
	
	args := map[string]interface{}{
		"image":       req.Image,
		"name":        req.Name,
		"resources":   req.Resources,
		"environment": req.Environment,
	}
	
	result, err := createTool.Execute(ctx, args)
	if err != nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create sandbox", err)
		return
	}
	
	// Parse result and return sandbox info
	var sandboxData map[string]interface{}
	if err := json.Unmarshal([]byte(result.Text), &sandboxData); err == nil {
		response := CreateSandboxResponse{
			ID:        sandboxData["id"].(string),
			Name:      req.Name,
			Image:     req.Image,
			Status:    "created",
			CreatedAt: time.Now(),
		}
		api.writeJSONResponse(w, http.StatusCreated, response)
	} else {
		api.writeJSONResponse(w, http.StatusCreated, map[string]interface{}{
			"message": result.Text,
		})
	}
}

func (api *RESTAPI) handleGetSandbox(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sandboxID := vars["id"]
	
	// Get sandbox info
	sb, err := api.sandboxManager.GetSandbox(sandboxID)
	if err != nil {
		if err != nil && err.Error() == "sandbox not found" {
			api.writeErrorResponse(w, http.StatusNotFound, "Sandbox not found", err)
		} else {
			api.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get sandbox", err)
		}
		return
	}
	
	response := api.convertSandboxToResponse(sb)
	api.writeJSONResponse(w, http.StatusOK, response)
}

func (api *RESTAPI) handleDeleteSandbox(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sandboxID := vars["id"]
	
	ctx := r.Context()
	
	// Use terminate tool
	terminateTool := api.toolRegistry.GetTool("terminate_sandbox")
	if terminateTool == nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Terminate sandbox tool not available", nil)
		return
	}
	
	args := map[string]interface{}{
		"sandbox_id": sandboxID,
	}
	
	_, err := terminateTool.Execute(ctx, args)
	if err != nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Failed to terminate sandbox", err)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

// File handlers

func (api *RESTAPI) handleListFiles(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sandboxID := vars["id"]
	
	ctx := r.Context()
	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}
	
	// Use list files tool
	listTool := api.toolRegistry.GetTool("list_files")
	if listTool == nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "List files tool not available", nil)
		return
	}
	
	args := map[string]interface{}{
		"sandbox_id": sandboxID,
		"path":       path,
	}
	
	result, err := listTool.Execute(ctx, args)
	if err != nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list files", err)
		return
	}
	
	// Parse and format response
	var files []interface{}
	if err := json.Unmarshal([]byte(result.Text), &files); err == nil {
		api.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"path":  path,
			"files": files,
		})
	} else {
		api.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"message": result.Text,
		})
	}
}

func (api *RESTAPI) handleGetFile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sandboxID := vars["id"]
	filePath := vars["path"]
	
	ctx := r.Context()
	
	// Use read file tool
	readTool := api.toolRegistry.GetTool("read_file")
	if readTool == nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Read file tool not available", nil)
		return
	}
	
	args := map[string]interface{}{
		"sandbox_id": sandboxID,
		"path":       filePath,
	}
	
	result, err := readTool.Execute(ctx, args)
	if err != nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read file", err)
		return
	}
	
	response := FileResponse{
		Path:    filePath,
		Content: result.Text,
		Size:    int64(len(result.Text)),
	}
	
	api.writeJSONResponse(w, http.StatusOK, response)
}

// Tool handlers

func (api *RESTAPI) handleListTools(w http.ResponseWriter, r *http.Request) {
	params := api.parseQueryParams(r.URL.Query())
	
	tools := api.toolRegistry.ListTools()
	restTools := make([]ToolResponse, len(tools))
	
	for i, tool := range tools {
		restTools[i] = ToolResponse{
			Name:        tool.Name(),
			Description: tool.Description(),
			Schema:      tool.Schema(),
		}
	}
	
	// Apply filtering if enabled
	if api.config.EnableFiltering && len(params.Filters) > 0 {
		restTools = api.filterTools(restTools, params.Filters)
	}
	
	response := ListResponse{
		Data:      restTools,
		Total:     len(restTools),
		Timestamp: time.Now(),
	}
	
	api.writeJSONResponse(w, http.StatusOK, response)
}

func (api *RESTAPI) handleExecuteTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	toolName := vars["name"]
	
	ctx := r.Context()
	
	var req ExecuteToolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}
	
	tool := api.toolRegistry.GetTool(toolName)
	if tool == nil {
		api.writeErrorResponse(w, http.StatusNotFound, "Tool not found", nil)
		return
	}
	
	result, err := tool.Execute(ctx, req.Arguments)
	if err != nil {
		api.writeErrorResponse(w, http.StatusInternalServerError, "Tool execution failed", err)
		return
	}
	
	response := ExecuteToolResponse{
		Result:    result.Text,
		IsError:   result.IsError,
		Timestamp: time.Now(),
	}
	
	api.writeJSONResponse(w, http.StatusOK, response)
}

// Middleware functions

func (api *RESTAPI) versioningMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !api.config.EnableVersioning {
			next.ServeHTTP(w, r)
			return
		}
		
		// Extract version from URL or header
		version := api.extractAPIVersion(r)
		if version != "" && !api.isVersionSupported(APIVersion(version)) {
			api.writeErrorResponse(w, http.StatusBadRequest, "Unsupported API version", nil)
			return
		}
		
		// Set version in context
		ctx := context.WithValue(r.Context(), "api_version", version)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (api *RESTAPI) validationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !api.config.EnableValidation {
			next.ServeHTTP(w, r)
			return
		}
		
		// Add request validation logic here
		// For now, just pass through
		next.ServeHTTP(w, r)
	})
}

func (api *RESTAPI) etagMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !api.config.EnableETag {
			next.ServeHTTP(w, r)
			return
		}
		
		// Add ETag support for caching
		// For now, just pass through
		next.ServeHTTP(w, r)
	})
}

// Helper functions

func (api *RESTAPI) parseQueryParams(values url.Values) QueryParams {
	params := QueryParams{
		PageSize:   api.config.DefaultPageSize,
		PageOffset: 0,
		Filters:    make(map[string]string),
		SortOrder:  "asc",
	}
	
	// Parse pagination
	if size := values.Get("page_size"); size != "" {
		if s, err := strconv.Atoi(size); err == nil && s > 0 {
			if s > api.config.MaxPageSize {
				params.PageSize = api.config.MaxPageSize
			} else {
				params.PageSize = s
			}
		}
	}
	
	if offset := values.Get("page_offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			params.PageOffset = o
		}
	}
	
	// Parse sorting
	params.SortBy = values.Get("sort_by")
	if order := values.Get("sort_order"); order == "desc" {
		params.SortOrder = "desc"
	}
	
	// Parse filters
	for key, vals := range values {
		if strings.HasPrefix(key, "filter_") && len(vals) > 0 {
			filterKey := strings.TrimPrefix(key, "filter_")
			params.Filters[filterKey] = vals[0]
		}
	}
	
	return params
}

func (api *RESTAPI) extractAPIVersion(r *http.Request) string {
	// Check Accept header first
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/vnd.sandboxrunner.v") {
		parts := strings.Split(accept, ".v")
		if len(parts) > 1 {
			version := strings.Split(parts[1], "+")[0]
			return version
		}
	}
	
	// Check custom header
	if version := r.Header.Get("API-Version"); version != "" {
		return version
	}
	
	// Default to configured default
	return string(api.config.DefaultVersion)
}

func (api *RESTAPI) isVersionSupported(version APIVersion) bool {
	for _, v := range api.config.SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

func (api *RESTAPI) convertSandboxToResponse(sb *sandbox.Sandbox) SandboxResponse {
	return SandboxResponse{
		ID:          sb.ID,
		Name:        "", // Name not available in sandbox struct
		Image:       sb.Config.Image,
		Status:      string(sb.Status),
		Environment: sb.Environment,
		CreatedAt:   sb.CreatedAt,
		UpdatedAt:   sb.UpdatedAt,
		Metadata:    sb.Metadata,
	}
}

func (api *RESTAPI) writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		api.logger.Error().Err(err).Msg("Failed to encode JSON response")
	}
}

func (api *RESTAPI) writeErrorResponse(w http.ResponseWriter, status int, message string, err error) {
	errorResponse := ErrorResponse{
		Error: Error{
			Code:      status,
			Message:   message,
			Timestamp: time.Now(),
		},
	}
	
	if err != nil {
		errorResponse.Error.Details = err.Error()
		api.logger.Error().Err(err).Str("message", message).Msg("API error")
	}
	
	api.writeJSONResponse(w, status, errorResponse)
}

// Pagination and filtering helper functions
func (api *RESTAPI) paginateResults(data interface{}, pageSize, offset int) (interface{}, PaginationInfo) {
	// This is a simplified implementation
	// In a real implementation, you'd use reflection or type assertions
	
	pagination := PaginationInfo{
		PageSize:   pageSize,
		PageOffset: offset,
		HasNext:    false,
		HasPrev:    offset > 0,
	}
	
	// For now, return data as-is
	// Real implementation would slice the data based on pagination
	return data, pagination
}

func (api *RESTAPI) filterSandboxes(sandboxes []SandboxResponse, filters map[string]string) []SandboxResponse {
	if len(filters) == 0 {
		return sandboxes
	}
	
	var filtered []SandboxResponse
	for _, sb := range sandboxes {
		match := true
		
		if status, ok := filters["status"]; ok && sb.Status != status {
			match = false
		}
		
		if image, ok := filters["image"]; ok && !strings.Contains(sb.Image, image) {
			match = false
		}
		
		if name, ok := filters["name"]; ok && !strings.Contains(sb.Name, name) {
			match = false
		}
		
		if match {
			filtered = append(filtered, sb)
		}
	}
	
	return filtered
}

func (api *RESTAPI) sortSandboxes(sandboxes []SandboxResponse, sortBy, sortOrder string) []SandboxResponse {
	// Simplified sorting implementation
	// Real implementation would use reflection or a more sophisticated sorting approach
	return sandboxes
}

func (api *RESTAPI) filterTools(tools []ToolResponse, filters map[string]string) []ToolResponse {
	if len(filters) == 0 {
		return tools
	}
	
	var filtered []ToolResponse
	for _, tool := range tools {
		match := true
		
		if name, ok := filters["name"]; ok && !strings.Contains(tool.Name, name) {
			match = false
		}
		
		if match {
			filtered = append(filtered, tool)
		}
	}
	
	return filtered
}

// Validation functions
func (api *RESTAPI) validateCreateSandboxRequest(req CreateSandboxRequest) error {
	if req.Image == "" {
		return fmt.Errorf("image is required")
	}
	return nil
}

// Placeholder handlers for future implementation
func (api *RESTAPI) handleUpdateSandbox(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleStartSandbox(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleStopSandbox(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleRestartSandbox(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleUpdateFile(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleExecuteCommand(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleRunCode(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleGetTool(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleListResources(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleGetResource(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleListPrompts(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleGetPrompt(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "Feature not implemented", nil)
}

func (api *RESTAPI) handleBatchSandboxes(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "V2 feature not implemented", nil)
}

func (api *RESTAPI) handleGetSandboxLogs(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "V2 feature not implemented", nil)
}

func (api *RESTAPI) handleGetSandboxMetrics(w http.ResponseWriter, r *http.Request) {
	api.writeErrorResponse(w, http.StatusNotImplemented, "V2 feature not implemented", nil)
}

func (api *RESTAPI) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	api.writeJSONResponse(w, http.StatusOK, api.openAPISpec)
}

func (api *RESTAPI) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	// Serve Swagger UI or similar documentation
	html := `<!DOCTYPE html>
<html>
<head>
    <title>SandboxRunner API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.25.0/swagger-ui.css" />
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@3.25.0/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '/api/openapi.json',
            dom_id: '#swagger-ui',
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.presets.standalone
            ]
        });
    </script>
</body>
</html>`
	
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}