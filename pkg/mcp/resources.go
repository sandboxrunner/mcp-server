package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// ResourceManager manages MCP resources with caching and versioning
type ResourceManager struct {
	resources   map[string]*ResourceEntry
	cache       map[string]*CachedResource
	templates   map[string]*ResourceTemplate
	generators  map[string]ResourceGenerator
	mu          sync.RWMutex
	cacheMu     sync.RWMutex
	templatesMu sync.RWMutex
	config      ResourceConfig
	metrics     *ResourceMetrics
}

// ResourceEntry represents a managed resource with metadata
type ResourceEntry struct {
	Resource
	Version     string                 `json:"version"`
	CreatedAt   time.Time              `json:"createdAt"`
	UpdatedAt   time.Time              `json:"updatedAt"`
	AccessCount int64                  `json:"accessCount"`
	Metadata    map[string]interface{} `json:"metadata"`
	Tags        []string               `json:"tags"`
	Generator   string                 `json:"generator,omitempty"`
}

// CachedResource represents a cached resource content
type CachedResource struct {
	Content   ResourceContent `json:"content"`
	Version   string          `json:"version"`
	ExpiresAt time.Time       `json:"expiresAt"`
	HitCount  int64           `json:"hitCount"`
}

// ResourceTemplate defines a template for generating resources
type ResourceTemplate struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Template    string                 `json:"template"`
	Parameters  []TemplateParameter    `json:"parameters"`
	OutputType  string                 `json:"outputType"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// TemplateParameter defines a template parameter
type TemplateParameter struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Options     []string    `json:"options,omitempty"`
}

// ResourceGenerator defines a function for dynamically generating resources
type ResourceGenerator interface {
	Generate(ctx context.Context, params map[string]interface{}) (*ResourceContent, error)
	GetInfo() GeneratorInfo
}

// GeneratorInfo provides information about a resource generator
type GeneratorInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  []TemplateParameter    `json:"parameters"`
	OutputTypes []string               `json:"outputTypes"`
	Version     string                 `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ResourceConfig holds configuration for resource management
type ResourceConfig struct {
	EnableCaching     bool          `json:"enableCaching"`
	CacheTTL          time.Duration `json:"cacheTTL"`
	MaxCacheSize      int           `json:"maxCacheSize"`
	EnableVersioning  bool          `json:"enableVersioning"`
	TemplateDirectory string        `json:"templateDirectory"`
	EnableMetrics     bool          `json:"enableMetrics"`
}

// ResourceMetrics tracks resource usage and performance
type ResourceMetrics struct {
	TotalResources   int64              `json:"totalResources"`
	CacheHitRate     float64            `json:"cacheHitRate"`
	CacheHits        int64              `json:"cacheHits"`
	CacheMisses      int64              `json:"cacheMisses"`
	ResourceAccess   map[string]int64   `json:"resourceAccess"`
	GenerationTime   map[string]float64 `json:"generationTime"`
	TemplateUsage    map[string]int64   `json:"templateUsage"`
	LastUpdated      time.Time          `json:"lastUpdated"`
	mu               sync.RWMutex
}

// Built-in resource generators
type FileResourceGenerator struct {
	rootPath string
}

type ConfigResourceGenerator struct {
	configPath string
}

type SchemaResourceGenerator struct {
	schemaPath string
}

// NewResourceManager creates a new resource manager
func NewResourceManager(config ResourceConfig) *ResourceManager {
	rm := &ResourceManager{
		resources:  make(map[string]*ResourceEntry),
		cache:      make(map[string]*CachedResource),
		templates:  make(map[string]*ResourceTemplate),
		generators: make(map[string]ResourceGenerator),
		config:     config,
		metrics: &ResourceMetrics{
			ResourceAccess: make(map[string]int64),
			GenerationTime: make(map[string]float64),
			TemplateUsage:  make(map[string]int64),
			LastUpdated:    time.Now(),
		},
	}

	// Register built-in generators
	rm.RegisterGenerator("file", &FileResourceGenerator{rootPath: "."})
	rm.RegisterGenerator("config", &ConfigResourceGenerator{configPath: "config"})
	rm.RegisterGenerator("schema", &SchemaResourceGenerator{schemaPath: "schemas"})

	// Load templates from directory if specified
	if config.TemplateDirectory != "" {
		if err := rm.LoadTemplatesFromDirectory(config.TemplateDirectory); err != nil {
			log.Warn().Err(err).Str("dir", config.TemplateDirectory).Msg("Failed to load templates")
		}
	}

	return rm
}

// RegisterResource adds a new resource to the manager
func (rm *ResourceManager) RegisterResource(resource Resource, metadata map[string]interface{}) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	entry := &ResourceEntry{
		Resource:    resource,
		Version:     rm.generateVersion(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		AccessCount: 0,
		Metadata:    metadata,
		Tags:        []string{},
	}

	rm.resources[resource.URI] = entry
	rm.updateMetrics()

	log.Info().
		Str("uri", resource.URI).
		Str("name", resource.Name).
		Str("version", entry.Version).
		Msg("Resource registered")

	return nil
}

// RegisterGenerator adds a resource generator
func (rm *ResourceManager) RegisterGenerator(name string, generator ResourceGenerator) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.generators[name] = generator

	log.Info().
		Str("name", name).
		Str("description", generator.GetInfo().Description).
		Msg("Resource generator registered")
}

// RegisterTemplate adds a resource template
func (rm *ResourceManager) RegisterTemplate(template *ResourceTemplate) error {
	rm.templatesMu.Lock()
	defer rm.templatesMu.Unlock()

	if err := rm.validateTemplate(template); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	rm.templates[template.Name] = template

	log.Info().
		Str("name", template.Name).
		Str("description", template.Description).
		Msg("Resource template registered")

	return nil
}

// ListResources returns all registered resources
func (rm *ResourceManager) ListResources(ctx context.Context, filters map[string]string) ([]Resource, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	resources := make([]Resource, 0, len(rm.resources))

	for _, entry := range rm.resources {
		// Apply filters
		if rm.matchesFilters(entry, filters) {
			resources = append(resources, entry.Resource)
		}
	}

	// Update metrics
	if rm.config.EnableMetrics {
		rm.metrics.mu.Lock()
		rm.metrics.LastUpdated = time.Now()
		rm.metrics.mu.Unlock()
	}

	return resources, nil
}

// GetResource retrieves a resource by URI
func (rm *ResourceManager) GetResource(ctx context.Context, uri string) (*ResourceContent, error) {
	start := time.Now()
	defer func() {
		if rm.config.EnableMetrics {
			duration := time.Since(start).Seconds()
			rm.metrics.mu.Lock()
			rm.metrics.GenerationTime[uri] = duration
			rm.metrics.ResourceAccess[uri]++
			rm.metrics.LastUpdated = time.Now()
			rm.metrics.mu.Unlock()
		}
	}()

	// Check cache first
	if rm.config.EnableCaching {
		if cached := rm.getCachedResource(uri); cached != nil {
			rm.updateCacheMetrics(true)
			return &cached.Content, nil
		}
		rm.updateCacheMetrics(false)
	}

	// Get resource entry
	rm.mu.RLock()
	entry, exists := rm.resources[uri]
	rm.mu.RUnlock()

	if !exists {
		// Try to generate resource dynamically
		return rm.generateDynamicResource(ctx, uri)
	}

	// Update access count
	rm.mu.Lock()
	entry.AccessCount++
	entry.UpdatedAt = time.Now()
	rm.mu.Unlock()

	// Read resource content
	content, err := rm.readResourceContent(ctx, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to read resource %s: %w", uri, err)
	}

	// Cache the result
	if rm.config.EnableCaching {
		rm.cacheResource(uri, content, entry.Version)
	}

	return content, nil
}

// GenerateFromTemplate creates a resource from a template
func (rm *ResourceManager) GenerateFromTemplate(ctx context.Context, templateName string, params map[string]interface{}) (*ResourceContent, error) {
	rm.templatesMu.RLock()
	template, exists := rm.templates[templateName]
	rm.templatesMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateName)
	}

	// Validate parameters
	if err := rm.validateTemplateParams(template, params); err != nil {
		return nil, fmt.Errorf("invalid template parameters: %w", err)
	}

	// Generate content
	content, err := rm.processTemplate(template, params)
	if err != nil {
		return nil, fmt.Errorf("failed to process template: %w", err)
	}

	// Update metrics
	if rm.config.EnableMetrics {
		rm.metrics.mu.Lock()
		rm.metrics.TemplateUsage[templateName]++
		rm.metrics.LastUpdated = time.Now()
		rm.metrics.mu.Unlock()
	}

	return content, nil
}

// LoadTemplatesFromDirectory loads templates from a directory
func (rm *ResourceManager) LoadTemplatesFromDirectory(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		var template ResourceTemplate
		if err := json.Unmarshal(data, &template); err != nil {
			return err
		}

		return rm.RegisterTemplate(&template)
	})
}

// GetMetrics returns current resource metrics
func (rm *ResourceManager) GetMetrics() *ResourceMetrics {
	if !rm.config.EnableMetrics {
		return nil
	}

	rm.metrics.mu.RLock()
	defer rm.metrics.mu.RUnlock()

	// Create a copy to avoid concurrent access
	metrics := &ResourceMetrics{
		TotalResources:   rm.metrics.TotalResources,
		CacheHitRate:     rm.metrics.CacheHitRate,
		CacheHits:        rm.metrics.CacheHits,
		CacheMisses:      rm.metrics.CacheMisses,
		ResourceAccess:   make(map[string]int64),
		GenerationTime:   make(map[string]float64),
		TemplateUsage:    make(map[string]int64),
		LastUpdated:      rm.metrics.LastUpdated,
	}

	for k, v := range rm.metrics.ResourceAccess {
		metrics.ResourceAccess[k] = v
	}
	for k, v := range rm.metrics.GenerationTime {
		metrics.GenerationTime[k] = v
	}
	for k, v := range rm.metrics.TemplateUsage {
		metrics.TemplateUsage[k] = v
	}

	return metrics
}

// Private helper methods

func (rm *ResourceManager) generateVersion() string {
	return fmt.Sprintf("v%d", time.Now().Unix())
}

func (rm *ResourceManager) matchesFilters(entry *ResourceEntry, filters map[string]string) bool {
	for key, value := range filters {
		switch key {
		case "type":
			if entry.MimeType != value {
				return false
			}
		case "tag":
			found := false
			for _, tag := range entry.Tags {
				if tag == value {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case "generator":
			if entry.Generator != value {
				return false
			}
		}
	}
	return true
}

func (rm *ResourceManager) getCachedResource(uri string) *CachedResource {
	rm.cacheMu.RLock()
	defer rm.cacheMu.RUnlock()

	cached, exists := rm.cache[uri]
	if !exists || time.Now().After(cached.ExpiresAt) {
		return nil
	}

	cached.HitCount++
	return cached
}

func (rm *ResourceManager) cacheResource(uri string, content *ResourceContent, version string) {
	if !rm.config.EnableCaching {
		return
	}

	rm.cacheMu.Lock()
	defer rm.cacheMu.Unlock()

	// Check cache size limit
	if len(rm.cache) >= rm.config.MaxCacheSize {
		rm.evictOldestCacheEntry()
	}

	rm.cache[uri] = &CachedResource{
		Content:   *content,
		Version:   version,
		ExpiresAt: time.Now().Add(rm.config.CacheTTL),
		HitCount:  0,
	}
}

func (rm *ResourceManager) evictOldestCacheEntry() {
	var oldestURI string
	var oldestTime time.Time

	for uri, cached := range rm.cache {
		if oldestURI == "" || cached.ExpiresAt.Before(oldestTime) {
			oldestURI = uri
			oldestTime = cached.ExpiresAt
		}
	}

	if oldestURI != "" {
		delete(rm.cache, oldestURI)
	}
}

func (rm *ResourceManager) updateCacheMetrics(hit bool) {
	if !rm.config.EnableMetrics {
		return
	}

	rm.metrics.mu.Lock()
	defer rm.metrics.mu.Unlock()

	if hit {
		rm.metrics.CacheHits++
	} else {
		rm.metrics.CacheMisses++
	}

	total := rm.metrics.CacheHits + rm.metrics.CacheMisses
	if total > 0 {
		rm.metrics.CacheHitRate = float64(rm.metrics.CacheHits) / float64(total)
	}
}

func (rm *ResourceManager) updateMetrics() {
	if !rm.config.EnableMetrics {
		return
	}

	rm.metrics.mu.Lock()
	rm.metrics.TotalResources = int64(len(rm.resources))
	rm.metrics.LastUpdated = time.Now()
	rm.metrics.mu.Unlock()
}

func (rm *ResourceManager) generateDynamicResource(ctx context.Context, uri string) (*ResourceContent, error) {
	// Parse URI to determine generator
	parts := strings.Split(uri, "://")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid resource URI format: %s", uri)
	}

	scheme := parts[0]
	generator, exists := rm.generators[scheme]
	if !exists {
		return nil, fmt.Errorf("resource not found: %s", uri)
	}

	// Extract parameters from URI path
	params := make(map[string]interface{})
	params["path"] = parts[1]

	return generator.Generate(ctx, params)
}

func (rm *ResourceManager) readResourceContent(ctx context.Context, entry *ResourceEntry) (*ResourceContent, error) {
	// For now, return a simple text content
	// In a real implementation, this would read from files, databases, etc.
	content := &ResourceContent{
		URI:      entry.URI,
		MimeType: entry.MimeType,
		Text:     fmt.Sprintf("Resource: %s\nDescription: %s\nVersion: %s", entry.Name, entry.Description, entry.Version),
	}

	return content, nil
}

func (rm *ResourceManager) validateTemplate(template *ResourceTemplate) error {
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if template.Template == "" {
		return fmt.Errorf("template content is required")
	}
	return nil
}

func (rm *ResourceManager) validateTemplateParams(template *ResourceTemplate, params map[string]interface{}) error {
	for _, param := range template.Parameters {
		if param.Required {
			if _, exists := params[param.Name]; !exists {
				return fmt.Errorf("required parameter missing: %s", param.Name)
			}
		}
	}
	return nil
}

func (rm *ResourceManager) processTemplate(template *ResourceTemplate, params map[string]interface{}) (*ResourceContent, error) {
	// Simple template processing - in a real implementation, use a proper template engine
	content := template.Template

	for key, value := range params {
		placeholder := fmt.Sprintf("{{%s}}", key)
		content = strings.ReplaceAll(content, placeholder, fmt.Sprintf("%v", value))
	}

	return &ResourceContent{
		URI:      fmt.Sprintf("template://%s", template.Name),
		MimeType: template.OutputType,
		Text:     content,
	}, nil
}

// Built-in generator implementations

func (fg *FileResourceGenerator) Generate(ctx context.Context, params map[string]interface{}) (*ResourceContent, error) {
	path, ok := params["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path parameter required")
	}

	fullPath := filepath.Join(fg.rootPath, path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return &ResourceContent{
		URI:      fmt.Sprintf("file://%s", path),
		MimeType: getMimeTypeByPath(fullPath),
		Text:     string(data),
	}, nil
}

func (fg *FileResourceGenerator) GetInfo() GeneratorInfo {
	return GeneratorInfo{
		Name:        "file",
		Description: "Generates resources from files",
		Parameters: []TemplateParameter{
			{
				Name:        "path",
				Type:        "string",
				Description: "File path relative to root",
				Required:    true,
			},
		},
		OutputTypes: []string{"text/plain", "application/json", "text/yaml"},
		Version:     "1.0.0",
	}
}

func (cg *ConfigResourceGenerator) Generate(ctx context.Context, params map[string]interface{}) (*ResourceContent, error) {
	path, ok := params["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path parameter required")
	}

	fullPath := filepath.Join(cg.configPath, path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return &ResourceContent{
		URI:      fmt.Sprintf("config://%s", path),
		MimeType: "application/json",
		Text:     string(data),
	}, nil
}

func (cg *ConfigResourceGenerator) GetInfo() GeneratorInfo {
	return GeneratorInfo{
		Name:        "config",
		Description: "Generates resources from configuration files",
		Parameters: []TemplateParameter{
			{
				Name:        "path",
				Type:        "string",
				Description: "Config file path",
				Required:    true,
			},
		},
		OutputTypes: []string{"application/json", "text/yaml"},
		Version:     "1.0.0",
	}
}

func (sg *SchemaResourceGenerator) Generate(ctx context.Context, params map[string]interface{}) (*ResourceContent, error) {
	path, ok := params["path"].(string)
	if !ok {
		return nil, fmt.Errorf("path parameter required")
	}

	fullPath := filepath.Join(sg.schemaPath, path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema file: %w", err)
	}

	return &ResourceContent{
		URI:      fmt.Sprintf("schema://%s", path),
		MimeType: "application/json",
		Text:     string(data),
	}, nil
}

func (sg *SchemaResourceGenerator) GetInfo() GeneratorInfo {
	return GeneratorInfo{
		Name:        "schema",
		Description: "Generates resources from JSON schema files",
		Parameters: []TemplateParameter{
			{
				Name:        "path",
				Type:        "string",
				Description: "Schema file path",
				Required:    true,
			},
		},
		OutputTypes: []string{"application/json"},
		Version:     "1.0.0",
	}
}

// Utility function to determine MIME type
func getMimeTypeByPath(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "text/yaml"
	case ".xml":
		return "application/xml"
	case ".html":
		return "text/html"
	case ".css":
		return "text/css"
	case ".js":
		return "application/javascript"
	case ".md":
		return "text/markdown"
	default:
		return "text/plain"
	}
}