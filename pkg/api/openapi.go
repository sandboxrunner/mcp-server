package api

import (
	"encoding/json"
)

// OpenAPISpec represents the OpenAPI 3.0 specification
type OpenAPISpec struct {
	OpenAPI    string                 `json:"openapi"`
	Info       OpenAPIInfo            `json:"info"`
	Servers    []OpenAPIServer        `json:"servers,omitempty"`
	Paths      map[string]OpenAPIPath `json:"paths"`
	Components OpenAPIComponents      `json:"components,omitempty"`
	Security   []map[string][]string  `json:"security,omitempty"`
	Tags       []OpenAPITag           `json:"tags,omitempty"`
}

// OpenAPIInfo contains API information
type OpenAPIInfo struct {
	Title          string         `json:"title"`
	Description    string         `json:"description"`
	TermsOfService string         `json:"termsOfService,omitempty"`
	Contact        *OpenAPIContact `json:"contact,omitempty"`
	License        *OpenAPILicense `json:"license,omitempty"`
	Version        string         `json:"version"`
}

// OpenAPIContact contains contact information
type OpenAPIContact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

// OpenAPILicense contains license information
type OpenAPILicense struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// OpenAPIServer represents a server
type OpenAPIServer struct {
	URL         string                            `json:"url"`
	Description string                            `json:"description,omitempty"`
	Variables   map[string]OpenAPIServerVariable  `json:"variables,omitempty"`
}

// OpenAPIServerVariable represents a server variable
type OpenAPIServerVariable struct {
	Enum        []string `json:"enum,omitempty"`
	Default     string   `json:"default,omitempty"`
	Description string   `json:"description,omitempty"`
}

// OpenAPIPath represents paths and operations
type OpenAPIPath map[string]OpenAPIOperation

// OpenAPIOperation represents an HTTP operation
type OpenAPIOperation struct {
	Tags        []string                     `json:"tags,omitempty"`
	Summary     string                       `json:"summary,omitempty"`
	Description string                       `json:"description,omitempty"`
	OperationID string                       `json:"operationId,omitempty"`
	Parameters  []OpenAPIParameter           `json:"parameters,omitempty"`
	RequestBody *OpenAPIRequestBody          `json:"requestBody,omitempty"`
	Responses   map[string]OpenAPIResponse   `json:"responses"`
	Deprecated  bool                         `json:"deprecated,omitempty"`
	Security    []map[string][]string        `json:"security,omitempty"`
}

// OpenAPIParameter represents a parameter
type OpenAPIParameter struct {
	Name            string                 `json:"name"`
	In              string                 `json:"in"`
	Description     string                 `json:"description,omitempty"`
	Required        bool                   `json:"required,omitempty"`
	Deprecated      bool                   `json:"deprecated,omitempty"`
	AllowEmptyValue bool                   `json:"allowEmptyValue,omitempty"`
	Schema          *OpenAPISchema         `json:"schema,omitempty"`
	Example         interface{}            `json:"example,omitempty"`
}

// OpenAPIRequestBody represents a request body
type OpenAPIRequestBody struct {
	Description string                       `json:"description,omitempty"`
	Content     map[string]OpenAPIMediaType  `json:"content"`
	Required    bool                         `json:"required,omitempty"`
}

// OpenAPIResponse represents a response
type OpenAPIResponse struct {
	Description string                      `json:"description"`
	Headers     map[string]OpenAPIHeader    `json:"headers,omitempty"`
	Content     map[string]OpenAPIMediaType `json:"content,omitempty"`
}

// OpenAPIHeader represents a header
type OpenAPIHeader struct {
	Description     string         `json:"description,omitempty"`
	Required        bool           `json:"required,omitempty"`
	Deprecated      bool           `json:"deprecated,omitempty"`
	AllowEmptyValue bool           `json:"allowEmptyValue,omitempty"`
	Schema          *OpenAPISchema `json:"schema,omitempty"`
}

// OpenAPIMediaType represents a media type
type OpenAPIMediaType struct {
	Schema   *OpenAPISchema         `json:"schema,omitempty"`
	Example  interface{}            `json:"example,omitempty"`
	Examples map[string]OpenAPIExample `json:"examples,omitempty"`
}

// OpenAPIExample represents an example
type OpenAPIExample struct {
	Summary       string      `json:"summary,omitempty"`
	Description   string      `json:"description,omitempty"`
	Value         interface{} `json:"value,omitempty"`
	ExternalValue string      `json:"externalValue,omitempty"`
}

// OpenAPISchema represents a schema
type OpenAPISchema struct {
	Type                 string                    `json:"type,omitempty"`
	Format               string                    `json:"format,omitempty"`
	Description          string                    `json:"description,omitempty"`
	Enum                 []interface{}             `json:"enum,omitempty"`
	Default              interface{}               `json:"default,omitempty"`
	Example              interface{}               `json:"example,omitempty"`
	Properties           map[string]*OpenAPISchema `json:"properties,omitempty"`
	Items                *OpenAPISchema            `json:"items,omitempty"`
	Required             []string                  `json:"required,omitempty"`
	AdditionalProperties interface{}               `json:"additionalProperties,omitempty"`
	Ref                  string                    `json:"$ref,omitempty"`
	AllOf                []*OpenAPISchema          `json:"allOf,omitempty"`
	OneOf                []*OpenAPISchema          `json:"oneOf,omitempty"`
	AnyOf                []*OpenAPISchema          `json:"anyOf,omitempty"`
	Not                  *OpenAPISchema            `json:"not,omitempty"`
	Minimum              *float64                  `json:"minimum,omitempty"`
	Maximum              *float64                  `json:"maximum,omitempty"`
	MinLength            *int                      `json:"minLength,omitempty"`
	MaxLength            *int                      `json:"maxLength,omitempty"`
	Pattern              string                    `json:"pattern,omitempty"`
	MinItems             *int                      `json:"minItems,omitempty"`
	MaxItems             *int                      `json:"maxItems,omitempty"`
	UniqueItems          bool                      `json:"uniqueItems,omitempty"`
}

// OpenAPIComponents holds reusable objects
type OpenAPIComponents struct {
	Schemas         map[string]*OpenAPISchema      `json:"schemas,omitempty"`
	Responses       map[string]OpenAPIResponse     `json:"responses,omitempty"`
	Parameters      map[string]OpenAPIParameter    `json:"parameters,omitempty"`
	Examples        map[string]OpenAPIExample      `json:"examples,omitempty"`
	RequestBodies   map[string]OpenAPIRequestBody  `json:"requestBodies,omitempty"`
	Headers         map[string]OpenAPIHeader       `json:"headers,omitempty"`
	SecuritySchemes map[string]OpenAPISecurityScheme `json:"securitySchemes,omitempty"`
}

// OpenAPISecurityScheme represents a security scheme
type OpenAPISecurityScheme struct {
	Type         string      `json:"type"`
	Description  string      `json:"description,omitempty"`
	Name         string      `json:"name,omitempty"`
	In           string      `json:"in,omitempty"`
	Scheme       string      `json:"scheme,omitempty"`
	BearerFormat string      `json:"bearerFormat,omitempty"`
	Flows        interface{} `json:"flows,omitempty"`
	OpenIDConnectURL string `json:"openIdConnectUrl,omitempty"`
}

// OpenAPITag represents a tag
type OpenAPITag struct {
	Name         string `json:"name"`
	Description  string `json:"description,omitempty"`
	ExternalDocs interface{} `json:"externalDocs,omitempty"`
}

// generateOpenAPISpec generates the OpenAPI specification
func generateOpenAPISpec(config RESTAPIConfig) *OpenAPISpec {
	spec := &OpenAPISpec{
		OpenAPI: "3.0.3",
		Info: OpenAPIInfo{
			Title:       "SandboxRunner API",
			Description: "RESTful API for managing sandboxes and executing code in isolated environments",
			Version:     "1.0.0",
			Contact: &OpenAPIContact{
				Name: "SandboxRunner Team",
				URL:  "https://github.com/sandboxrunner/mcp-server",
			},
			License: &OpenAPILicense{
				Name: "MIT",
				URL:  "https://opensource.org/licenses/MIT",
			},
		},
		Servers: []OpenAPIServer{
			{
				URL:         "{protocol}://{host}:{port}" + config.BasePath,
				Description: "SandboxRunner API Server",
				Variables: map[string]OpenAPIServerVariable{
					"protocol": {
						Enum:    []string{"http", "https"},
						Default: "http",
					},
					"host": {
						Default: "localhost",
					},
					"port": {
						Default: "3000",
					},
				},
			},
		},
		Tags: []OpenAPITag{
			{Name: "sandboxes", Description: "Sandbox management operations"},
			{Name: "files", Description: "File operations within sandboxes"},
			{Name: "execution", Description: "Code and command execution"},
			{Name: "tools", Description: "Available tools and their operations"},
			{Name: "resources", Description: "Resource management"},
			{Name: "prompts", Description: "Prompt operations"},
			{Name: "system", Description: "System and health endpoints"},
		},
		Paths:      generatePaths(),
		Components: generateComponents(),
	}

	return spec
}

// generatePaths generates the paths section of the OpenAPI spec
func generatePaths() map[string]OpenAPIPath {
	paths := make(map[string]OpenAPIPath)

	// Sandboxes paths
	paths["/v1/sandboxes"] = OpenAPIPath{
		"get": OpenAPIOperation{
			Tags:        []string{"sandboxes"},
			Summary:     "List sandboxes",
			Description: "Retrieve a list of all sandboxes with optional filtering and pagination",
			OperationID: "listSandboxes",
			Parameters: []OpenAPIParameter{
				{
					Name:        "page_size",
					In:          "query",
					Description: "Number of items per page",
					Schema:      &OpenAPISchema{Type: "integer", Default: 20, Minimum: float64Ptr(1), Maximum: float64Ptr(100)},
				},
				{
					Name:        "page_offset",
					In:          "query",
					Description: "Offset for pagination",
					Schema:      &OpenAPISchema{Type: "integer", Default: 0, Minimum: float64Ptr(0)},
				},
				{
					Name:        "filter_status",
					In:          "query",
					Description: "Filter by sandbox status",
					Schema:      &OpenAPISchema{Type: "string", Enum: []interface{}{"created", "running", "stopped", "terminated"}},
				},
				{
					Name:        "sort_by",
					In:          "query",
					Description: "Sort by field",
					Schema:      &OpenAPISchema{Type: "string", Enum: []interface{}{"created_at", "updated_at", "name", "status"}},
				},
				{
					Name:        "sort_order",
					In:          "query",
					Description: "Sort order",
					Schema:      &OpenAPISchema{Type: "string", Enum: []interface{}{"asc", "desc"}, Default: "asc"},
				},
			},
			Responses: map[string]OpenAPIResponse{
				"200": {
					Description: "Successful response",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{
								Ref: "#/components/schemas/SandboxListResponse",
							},
						},
					},
				},
				"400": {
					Description: "Bad request",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/ErrorResponse"},
						},
					},
				},
				"500": {
					Description: "Internal server error",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/ErrorResponse"},
						},
					},
				},
			},
		},
		"post": OpenAPIOperation{
			Tags:        []string{"sandboxes"},
			Summary:     "Create a new sandbox",
			Description: "Create a new sandbox with the specified configuration",
			OperationID: "createSandbox",
			RequestBody: &OpenAPIRequestBody{
				Description: "Sandbox creation request",
				Required:    true,
				Content: map[string]OpenAPIMediaType{
					"application/json": {
						Schema: &OpenAPISchema{Ref: "#/components/schemas/CreateSandboxRequest"},
					},
				},
			},
			Responses: map[string]OpenAPIResponse{
				"201": {
					Description: "Sandbox created successfully",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/CreateSandboxResponse"},
						},
					},
				},
				"400": {
					Description: "Bad request",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/ErrorResponse"},
						},
					},
				},
				"500": {
					Description: "Internal server error",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/ErrorResponse"},
						},
					},
				},
			},
		},
	}

	// Individual sandbox paths
	paths["/v1/sandboxes/{id}"] = OpenAPIPath{
		"get": OpenAPIOperation{
			Tags:        []string{"sandboxes"},
			Summary:     "Get sandbox details",
			Description: "Retrieve detailed information about a specific sandbox",
			OperationID: "getSandbox",
			Parameters: []OpenAPIParameter{
				{
					Name:        "id",
					In:          "path",
					Description: "Sandbox ID",
					Required:    true,
					Schema:      &OpenAPISchema{Type: "string"},
				},
			},
			Responses: map[string]OpenAPIResponse{
				"200": {
					Description: "Sandbox details",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/SandboxResponse"},
						},
					},
				},
				"404": {
					Description: "Sandbox not found",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/ErrorResponse"},
						},
					},
				},
			},
		},
		"delete": OpenAPIOperation{
			Tags:        []string{"sandboxes"},
			Summary:     "Delete sandbox",
			Description: "Terminate and delete a sandbox",
			OperationID: "deleteSandbox",
			Parameters: []OpenAPIParameter{
				{
					Name:        "id",
					In:          "path",
					Description: "Sandbox ID",
					Required:    true,
					Schema:      &OpenAPISchema{Type: "string"},
				},
			},
			Responses: map[string]OpenAPIResponse{
				"204": {Description: "Sandbox deleted successfully"},
				"404": {
					Description: "Sandbox not found",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/ErrorResponse"},
						},
					},
				},
			},
		},
	}

	// Files paths
	paths["/v1/sandboxes/{id}/files"] = OpenAPIPath{
		"get": OpenAPIOperation{
			Tags:        []string{"files"},
			Summary:     "List files in sandbox",
			Description: "List files and directories in the specified sandbox path",
			OperationID: "listSandboxFiles",
			Parameters: []OpenAPIParameter{
				{
					Name:        "id",
					In:          "path",
					Description: "Sandbox ID",
					Required:    true,
					Schema:      &OpenAPISchema{Type: "string"},
				},
				{
					Name:        "path",
					In:          "query",
					Description: "Directory path to list",
					Schema:      &OpenAPISchema{Type: "string", Default: "/"},
				},
			},
			Responses: map[string]OpenAPIResponse{
				"200": {
					Description: "File list",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/FileListResponse"},
						},
					},
				},
			},
		},
	}

	// Tools paths
	paths["/v1/tools"] = OpenAPIPath{
		"get": OpenAPIOperation{
			Tags:        []string{"tools"},
			Summary:     "List available tools",
			Description: "Retrieve a list of all available tools",
			OperationID: "listTools",
			Responses: map[string]OpenAPIResponse{
				"200": {
					Description: "Tool list",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/ToolListResponse"},
						},
					},
				},
			},
		},
	}

	paths["/v1/tools/{name}/execute"] = OpenAPIPath{
		"post": OpenAPIOperation{
			Tags:        []string{"tools"},
			Summary:     "Execute a tool",
			Description: "Execute a tool with the provided arguments",
			OperationID: "executeTool",
			Parameters: []OpenAPIParameter{
				{
					Name:        "name",
					In:          "path",
					Description: "Tool name",
					Required:    true,
					Schema:      &OpenAPISchema{Type: "string"},
				},
			},
			RequestBody: &OpenAPIRequestBody{
				Description: "Tool execution request",
				Required:    true,
				Content: map[string]OpenAPIMediaType{
					"application/json": {
						Schema: &OpenAPISchema{Ref: "#/components/schemas/ExecuteToolRequest"},
					},
				},
			},
			Responses: map[string]OpenAPIResponse{
				"200": {
					Description: "Tool execution result",
					Content: map[string]OpenAPIMediaType{
						"application/json": {
							Schema: &OpenAPISchema{Ref: "#/components/schemas/ExecuteToolResponse"},
						},
					},
				},
			},
		},
	}

	return paths
}

// generateComponents generates the components section of the OpenAPI spec
func generateComponents() OpenAPIComponents {
	schemas := make(map[string]*OpenAPISchema)

	// Error response schema
	schemas["ErrorResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"error"},
		Properties: map[string]*OpenAPISchema{
			"error": {Ref: "#/components/schemas/Error"},
		},
	}

	schemas["Error"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"code", "message", "timestamp"},
		Properties: map[string]*OpenAPISchema{
			"code":       {Type: "integer"},
			"message":    {Type: "string"},
			"details":    {Type: "string"},
			"timestamp":  {Type: "string", Format: "date-time"},
			"request_id": {Type: "string"},
		},
	}

	// Sandbox schemas
	schemas["SandboxResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"id", "image", "status", "created_at"},
		Properties: map[string]*OpenAPISchema{
			"id":          {Type: "string"},
			"name":        {Type: "string"},
			"image":       {Type: "string"},
			"status":      {Type: "string", Enum: []interface{}{"created", "running", "stopped", "terminated"}},
			"resources":   {Type: "object", AdditionalProperties: true},
			"environment": {Type: "object", AdditionalProperties: &OpenAPISchema{Type: "string"}},
			"created_at":  {Type: "string", Format: "date-time"},
			"updated_at":  {Type: "string", Format: "date-time"},
			"expires_at":  {Type: "string", Format: "date-time"},
			"metadata":    {Type: "object", AdditionalProperties: true},
		},
	}

	schemas["CreateSandboxRequest"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"image"},
		Properties: map[string]*OpenAPISchema{
			"name":        {Type: "string", MinLength: intPtr(1), MaxLength: intPtr(255)},
			"image":       {Type: "string", MinLength: intPtr(1)},
			"resources":   {Type: "object", AdditionalProperties: true},
			"environment": {Type: "object", AdditionalProperties: &OpenAPISchema{Type: "string"}},
			"metadata":    {Type: "object", AdditionalProperties: true},
			"ttl":         {Type: "string", Pattern: "^[0-9]+(ns|us|µs|ms|s|m|h)$"},
		},
	}

	schemas["CreateSandboxResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"id", "image", "status", "created_at"},
		Properties: map[string]*OpenAPISchema{
			"id":         {Type: "string"},
			"name":       {Type: "string"},
			"image":      {Type: "string"},
			"status":     {Type: "string"},
			"created_at": {Type: "string", Format: "date-time"},
			"expires_at": {Type: "string", Format: "date-time"},
		},
	}

	// List response schemas
	schemas["SandboxListResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"data", "total", "timestamp"},
		Properties: map[string]*OpenAPISchema{
			"data": {
				Type: "array",
				Items: &OpenAPISchema{Ref: "#/components/schemas/SandboxResponse"},
			},
			"pagination": {Ref: "#/components/schemas/PaginationInfo"},
			"total":      {Type: "integer"},
			"timestamp":  {Type: "string", Format: "date-time"},
			"version":    {Type: "string"},
		},
	}

	schemas["PaginationInfo"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"page_size", "page_offset", "has_next", "has_prev"},
		Properties: map[string]*OpenAPISchema{
			"page_size":   {Type: "integer"},
			"page_offset": {Type: "integer"},
			"has_next":    {Type: "boolean"},
			"has_prev":    {Type: "boolean"},
			"next_offset": {Type: "integer"},
			"prev_offset": {Type: "integer"},
		},
	}

	// File schemas
	schemas["FileResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"path", "size", "is_dir"},
		Properties: map[string]*OpenAPISchema{
			"path":         {Type: "string"},
			"name":         {Type: "string"},
			"size":         {Type: "integer", Format: "int64"},
			"mod_time":     {Type: "string", Format: "date-time"},
			"is_dir":       {Type: "boolean"},
			"content":      {Type: "string"},
			"content_type": {Type: "string"},
			"encoding":     {Type: "string"},
			"checksum":     {Type: "string"},
			"metadata":     {Type: "object", AdditionalProperties: true},
		},
	}

	schemas["FileListResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"path", "files", "total", "timestamp"},
		Properties: map[string]*OpenAPISchema{
			"path": {Type: "string"},
			"files": {
				Type: "array",
				Items: &OpenAPISchema{Ref: "#/components/schemas/FileResponse"},
			},
			"total":     {Type: "integer"},
			"timestamp": {Type: "string", Format: "date-time"},
		},
	}

	// Tool schemas
	schemas["ToolResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"name", "description", "schema"},
		Properties: map[string]*OpenAPISchema{
			"name":        {Type: "string"},
			"description": {Type: "string"},
			"schema":      {Type: "object", AdditionalProperties: true},
			"version":     {Type: "string"},
			"category":    {Type: "string"},
			"tags":        {Type: "array", Items: &OpenAPISchema{Type: "string"}},
			"deprecated":  {Type: "boolean"},
		},
	}

	schemas["ToolListResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"data", "total", "timestamp"},
		Properties: map[string]*OpenAPISchema{
			"data": {
				Type: "array",
				Items: &OpenAPISchema{Ref: "#/components/schemas/ToolResponse"},
			},
			"total":     {Type: "integer"},
			"timestamp": {Type: "string", Format: "date-time"},
		},
	}

	schemas["ExecuteToolRequest"] = &OpenAPISchema{
		Type: "object",
		Properties: map[string]*OpenAPISchema{
			"arguments": {Type: "object", AdditionalProperties: true},
			"options":   {Ref: "#/components/schemas/ToolExecutionOptions"},
		},
	}

	schemas["ToolExecutionOptions"] = &OpenAPISchema{
		Type: "object",
		Properties: map[string]*OpenAPISchema{
			"timeout":      {Type: "string", Pattern: "^[0-9]+(ns|us|µs|ms|s|m|h)$"},
			"async":        {Type: "boolean"},
			"stream":       {Type: "boolean"},
			"retry_policy": {Ref: "#/components/schemas/RetryPolicy"},
		},
	}

	schemas["RetryPolicy"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"max_retries"},
		Properties: map[string]*OpenAPISchema{
			"max_retries":    {Type: "integer", Minimum: float64Ptr(0)},
			"initial_delay":  {Type: "string", Pattern: "^[0-9]+(ns|us|µs|ms|s|m|h)$"},
			"backoff_factor": {Type: "number", Minimum: float64Ptr(1.0)},
			"max_delay":      {Type: "string", Pattern: "^[0-9]+(ns|us|µs|ms|s|m|h)$"},
		},
	}

	schemas["ExecuteToolResponse"] = &OpenAPISchema{
		Type: "object",
		Required: []string{"result", "is_error", "duration", "timestamp"},
		Properties: map[string]*OpenAPISchema{
			"result":       {AdditionalProperties: true},
			"is_error":     {Type: "boolean"},
			"execution_id": {Type: "string"},
			"duration":     {Type: "string", Pattern: "^[0-9]+(ns|us|µs|ms|s|m|h)$"},
			"timestamp":    {Type: "string", Format: "date-time"},
			"metadata":     {Type: "object", AdditionalProperties: true},
		},
	}

	return OpenAPIComponents{
		Schemas: schemas,
	}
}

// Helper functions
func float64Ptr(f float64) *float64 {
	return &f
}

func intPtr(i int) *int {
	return &i
}

// MarshalJSON implements custom JSON marshaling for OpenAPISchema
func (s *OpenAPISchema) MarshalJSON() ([]byte, error) {
	type Alias OpenAPISchema
	return json.Marshal((*Alias)(s))
}