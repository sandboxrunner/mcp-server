package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResourceManager_NewResourceManager(t *testing.T) {
	config := ResourceConfig{
		EnableCaching:     true,
		CacheTTL:          time.Hour,
		MaxCacheSize:      100,
		EnableVersioning:  true,
		TemplateDirectory: "",
		EnableMetrics:     true,
	}

	rm := NewResourceManager(config)
	assert.NotNil(t, rm)
	assert.Equal(t, config, rm.config)
	assert.NotNil(t, rm.resources)
	assert.NotNil(t, rm.cache)
	assert.NotNil(t, rm.templates)
	assert.NotNil(t, rm.generators)
	assert.NotNil(t, rm.metrics)
}

func TestResourceManager_RegisterResource(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{EnableMetrics: true})
	
	resource := Resource{
		URI:         "test://example",
		Name:        "Test Resource",
		Description: "A test resource",
		MimeType:    "text/plain",
	}
	
	metadata := map[string]interface{}{
		"category": "test",
		"priority": "high",
	}

	err := rm.RegisterResource(resource, metadata)
	assert.NoError(t, err)

	// Verify resource was registered
	rm.mu.RLock()
	entry, exists := rm.resources[resource.URI]
	rm.mu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, resource.URI, entry.URI)
	assert.Equal(t, resource.Name, entry.Name)
	assert.NotEmpty(t, entry.Version)
	assert.NotZero(t, entry.CreatedAt)
	assert.Equal(t, metadata, entry.Metadata)
}

func TestResourceManager_ListResources(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{EnableMetrics: true})
	
	// Register test resources
	resources := []Resource{
		{URI: "test://resource1", Name: "Resource 1", MimeType: "text/plain"},
		{URI: "test://resource2", Name: "Resource 2", MimeType: "application/json"},
		{URI: "file://resource3", Name: "Resource 3", MimeType: "text/plain"},
	}

	for _, resource := range resources {
		metadata := map[string]interface{}{"generator": "test"}
		err := rm.RegisterResource(resource, metadata)
		require.NoError(t, err)
	}

	ctx := context.Background()

	// Test listing all resources
	allResources, err := rm.ListResources(ctx, nil)
	assert.NoError(t, err)
	assert.Len(t, allResources, 3)

	// Test filtering by type
	filters := map[string]string{"type": "text/plain"}
	filteredResources, err := rm.ListResources(ctx, filters)
	assert.NoError(t, err)
	assert.Len(t, filteredResources, 2)

	// Test filtering by generator
	filters = map[string]string{"generator": "test"}
	filteredResources, err = rm.ListResources(ctx, filters)
	assert.NoError(t, err)
	assert.Len(t, filteredResources, 3)
}

func TestResourceManager_GetResource(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{
		EnableCaching: true,
		CacheTTL:      time.Hour,
		EnableMetrics: true,
	})
	
	resource := Resource{
		URI:         "test://example",
		Name:        "Test Resource",
		Description: "A test resource",
		MimeType:    "text/plain",
	}

	err := rm.RegisterResource(resource, nil)
	require.NoError(t, err)

	ctx := context.Background()

	// Test getting existing resource
	content, err := rm.GetResource(ctx, resource.URI)
	assert.NoError(t, err)
	assert.NotNil(t, content)
	assert.Equal(t, resource.URI, content.URI)
	assert.Equal(t, resource.MimeType, content.MimeType)

	// Test getting non-existing resource
	_, err = rm.GetResource(ctx, "test://nonexistent")
	assert.Error(t, err)
}

func TestResourceManager_RegisterTemplate(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{})

	template := &ResourceTemplate{
		Name:        "test-template",
		Description: "A test template",
		Template:    "Hello {{name}}!",
		Parameters: []TemplateParameter{
			{
				Name:        "name",
				Type:        "string",
				Description: "Name to greet",
				Required:    true,
			},
		},
		OutputType: "text/plain",
	}

	err := rm.RegisterTemplate(template)
	assert.NoError(t, err)

	// Verify template was registered
	rm.templatesMu.RLock()
	registered, exists := rm.templates[template.Name]
	rm.templatesMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, template.Name, registered.Name)
	assert.Equal(t, template.Template, registered.Template)
}

func TestResourceManager_GenerateFromTemplate(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{EnableMetrics: true})

	template := &ResourceTemplate{
		Name:        "greeting-template",
		Description: "Greeting template",
		Template:    "Hello {{name}}! Welcome to {{place}}.",
		Parameters: []TemplateParameter{
			{Name: "name", Type: "string", Required: true},
			{Name: "place", Type: "string", Required: true},
		},
		OutputType: "text/plain",
	}

	err := rm.RegisterTemplate(template)
	require.NoError(t, err)

	ctx := context.Background()
	params := map[string]interface{}{
		"name":  "John",
		"place": "SandboxRunner",
	}

	content, err := rm.GenerateFromTemplate(ctx, template.Name, params)
	assert.NoError(t, err)
	assert.NotNil(t, content)
	assert.Equal(t, "text/plain", content.MimeType)
	assert.Contains(t, content.Text, "Hello John!")
	assert.Contains(t, content.Text, "Welcome to SandboxRunner")
}

func TestResourceManager_LoadTemplatesFromDirectory(t *testing.T) {
	// Create temporary directory with template files
	tmpDir := t.TempDir()
	
	templateContent := `{
		"name": "test-template",
		"description": "Test template from file",
		"template": "Template content: {{value}}",
		"parameters": [
			{
				"name": "value",
				"type": "string",
				"required": true
			}
		],
		"outputType": "text/plain"
	}`

	templateFile := filepath.Join(tmpDir, "test-template.json")
	err := os.WriteFile(templateFile, []byte(templateContent), 0644)
	require.NoError(t, err)

	rm := NewResourceManager(ResourceConfig{})

	err = rm.LoadTemplatesFromDirectory(tmpDir)
	assert.NoError(t, err)

	// Verify template was loaded
	rm.templatesMu.RLock()
	template, exists := rm.templates["test-template"]
	rm.templatesMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, "test-template", template.Name)
	assert.Equal(t, "Test template from file", template.Description)
}

func TestResourceManager_Caching(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{
		EnableCaching: true,
		CacheTTL:      time.Second,
		MaxCacheSize:  10,
		EnableMetrics: true,
	})

	resource := Resource{
		URI:      "test://cached",
		Name:     "Cached Resource",
		MimeType: "text/plain",
	}

	err := rm.RegisterResource(resource, nil)
	require.NoError(t, err)

	ctx := context.Background()

	// First call should cache the result
	content1, err := rm.GetResource(ctx, resource.URI)
	assert.NoError(t, err)
	assert.NotNil(t, content1)

	// Second call should use cache
	content2, err := rm.GetResource(ctx, resource.URI)
	assert.NoError(t, err)
	assert.NotNil(t, content2)

	// Verify cache hit metrics
	metrics := rm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.True(t, metrics.CacheHits > 0)

	// Wait for cache to expire
	time.Sleep(time.Second + time.Millisecond*100)

	// Third call should miss cache
	content3, err := rm.GetResource(ctx, resource.URI)
	assert.NoError(t, err)
	assert.NotNil(t, content3)
}

func TestResourceManager_Metrics(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{
		EnableMetrics: true,
		EnableCaching: true,
	})

	// Register some resources
	for i := 0; i < 5; i++ {
		resource := Resource{
			URI:      fmt.Sprintf("test://resource%d", i),
			Name:     fmt.Sprintf("Resource %d", i),
			MimeType: "text/plain",
		}
		err := rm.RegisterResource(resource, nil)
		require.NoError(t, err)
	}

	metrics := rm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(5), metrics.TotalResources)
	assert.NotZero(t, metrics.LastUpdated)
}

func TestBuiltinGenerators(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{})

	// Test file generator info
	fileGen := rm.generators["file"]
	assert.NotNil(t, fileGen)
	
	info := fileGen.GetInfo()
	assert.Equal(t, "file", info.Name)
	assert.Contains(t, info.Description, "files")

	// Test config generator info
	configGen := rm.generators["config"]
	assert.NotNil(t, configGen)
	
	configInfo := configGen.GetInfo()
	assert.Equal(t, "config", configInfo.Name)
	assert.Contains(t, configInfo.Description, "config")

	// Test schema generator info
	schemaGen := rm.generators["schema"]
	assert.NotNil(t, schemaGen)
	
	schemaInfo := schemaGen.GetInfo()
	assert.Equal(t, "schema", schemaInfo.Name)
	assert.Contains(t, schemaInfo.Description, "schema")
}

func TestResourceManager_ConcurrentAccess(t *testing.T) {
	rm := NewResourceManager(ResourceConfig{
		EnableCaching: true,
		EnableMetrics: true,
	})

	// Register a resource
	resource := Resource{
		URI:      "test://concurrent",
		Name:     "Concurrent Resource",
		MimeType: "text/plain",
	}
	err := rm.RegisterResource(resource, nil)
	require.NoError(t, err)

	ctx := context.Background()
	const numGoroutines = 10
	const numRequests = 100

	// Test concurrent reads
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < numRequests; j++ {
				content, err := rm.GetResource(ctx, resource.URI)
				assert.NoError(t, err)
				assert.NotNil(t, content)
			}
		}()
	}

	// Test concurrent template generation
	template := &ResourceTemplate{
		Name:       "concurrent-template",
		Template:   "Value: {{value}}",
		Parameters: []TemplateParameter{{Name: "value", Type: "string", Required: true}},
		OutputType: "text/plain",
	}
	err = rm.RegisterTemplate(template)
	require.NoError(t, err)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			params := map[string]interface{}{"value": fmt.Sprintf("test-%d", id)}
			content, err := rm.GenerateFromTemplate(ctx, template.Name, params)
			assert.NoError(t, err)
			assert.NotNil(t, content)
		}(i)
	}

	// Give goroutines time to complete
	time.Sleep(time.Second)

	// Verify metrics were updated
	metrics := rm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.True(t, metrics.TotalResources > 0)
}