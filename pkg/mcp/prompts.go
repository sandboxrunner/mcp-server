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

// PromptManager manages MCP prompts with templates, validation, and analytics
type PromptManager struct {
	prompts     map[string]*PromptEntry
	templates   map[string]*PromptTemplate
	composers   map[string]PromptComposer
	validators  map[string]PromptValidator
	cache       map[string]*CachedPrompt
	mu          sync.RWMutex
	cacheMu     sync.RWMutex
	templatesMu sync.RWMutex
	config      PromptConfig
	metrics     *PromptMetrics
	contextInjectors map[string]ContextInjector
}

// PromptEntry represents a managed prompt with metadata
type PromptEntry struct {
	Prompt
	Version       string                 `json:"version"`
	CreatedAt     time.Time              `json:"createdAt"`
	UpdatedAt     time.Time              `json:"updatedAt"`
	UsageCount    int64                  `json:"usageCount"`
	Metadata      map[string]interface{} `json:"metadata"`
	Tags          []string               `json:"tags"`
	Category      string                 `json:"category"`
	Composer      string                 `json:"composer,omitempty"`
	ValidatorName string                 `json:"validator,omitempty"`
	IsTemplate    bool                   `json:"isTemplate"`
}

// PromptTemplate defines a template for generating prompts
type PromptTemplate struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Template        string                 `json:"template"`
	Parameters      []TemplateParameter    `json:"parameters"`
	OutputFormat    string                 `json:"outputFormat"`
	ValidationRules []ValidationRule       `json:"validationRules"`
	ContextRules    []ContextRule          `json:"contextRules"`
	Metadata        map[string]interface{} `json:"metadata"`
	Examples        []PromptExample        `json:"examples"`
}

// PromptExample shows how to use a template
type PromptExample struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Expected    string                 `json:"expected"`
}

// ValidationRule defines prompt validation criteria
type ValidationRule struct {
	Type        string                 `json:"type"`
	Field       string                 `json:"field,omitempty"`
	Constraint  string                 `json:"constraint"`
	Message     string                 `json:"message"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// ContextRule defines context injection rules
type ContextRule struct {
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Transform   string                 `json:"transform,omitempty"`
	Condition   string                 `json:"condition,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// CachedPrompt represents a cached prompt result
type CachedPrompt struct {
	Result    *GetPromptResult `json:"result"`
	Version   string           `json:"version"`
	ExpiresAt time.Time        `json:"expiresAt"`
	HitCount  int64            `json:"hitCount"`
	Hash      string           `json:"hash"`
}

// PromptComposer defines an interface for composing complex prompts
type PromptComposer interface {
	Compose(ctx context.Context, prompts []string, params map[string]interface{}) (*GetPromptResult, error)
	GetInfo() ComposerInfo
}

// ComposerInfo provides information about a prompt composer
type ComposerInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  []TemplateParameter    `json:"parameters"`
	Strategies  []string               `json:"strategies"`
	Version     string                 `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PromptValidator defines an interface for validating prompts
type PromptValidator interface {
	Validate(ctx context.Context, prompt *GetPromptResult, rules []ValidationRule) (*ValidationResult, error)
	GetInfo() ValidatorInfo
}

// ValidatorInfo provides information about a prompt validator
type ValidatorInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	RuleTypes   []string               `json:"ruleTypes"`
	Version     string                 `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ValidationResult contains validation results
type ValidationResult struct {
	IsValid   bool                   `json:"isValid"`
	Errors    []ValidationError      `json:"errors"`
	Warnings  []ValidationWarning    `json:"warnings"`
	Score     float64                `json:"score"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Type        string                 `json:"type"`
	Message     string                 `json:"message"`
	Field       string                 `json:"field,omitempty"`
	Rule        string                 `json:"rule"`
	Severity    string                 `json:"severity"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Type        string                 `json:"type"`
	Message     string                 `json:"message"`
	Field       string                 `json:"field,omitempty"`
	Rule        string                 `json:"rule"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// ContextInjector defines an interface for injecting context into prompts
type ContextInjector interface {
	Inject(ctx context.Context, prompt *GetPromptResult, rules []ContextRule) (*GetPromptResult, error)
	GetInfo() InjectorInfo
}

// InjectorInfo provides information about a context injector
type InjectorInfo struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	SourceTypes []string               `json:"sourceTypes"`
	Version     string                 `json:"version"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PromptConfig holds configuration for prompt management
type PromptConfig struct {
	EnableCaching      bool          `json:"enableCaching"`
	CacheTTL           time.Duration `json:"cacheTTL"`
	MaxCacheSize       int           `json:"maxCacheSize"`
	EnableValidation   bool          `json:"enableValidation"`
	EnableComposition  bool          `json:"enableComposition"`
	EnableContext      bool          `json:"enableContext"`
	TemplateDirectory  string        `json:"templateDirectory"`
	EnableMetrics      bool          `json:"enableMetrics"`
	MaxPromptLength    int           `json:"maxPromptLength"`
	EnableVersioning   bool          `json:"enableVersioning"`
}

// PromptMetrics tracks prompt usage and performance
type PromptMetrics struct {
	TotalPrompts      int64              `json:"totalPrompts"`
	CacheHitRate      float64            `json:"cacheHitRate"`
	CacheHits         int64              `json:"cacheHits"`
	CacheMisses       int64              `json:"cacheMisses"`
	PromptUsage       map[string]int64   `json:"promptUsage"`
	TemplateUsage     map[string]int64   `json:"templateUsage"`
	CompositionTime   map[string]float64 `json:"compositionTime"`
	ValidationTime    map[string]float64 `json:"validationTime"`
	ContextTime       map[string]float64 `json:"contextTime"`
	ValidationErrors  int64              `json:"validationErrors"`
	ValidationWarnings int64             `json:"validationWarnings"`
	LastUpdated       time.Time          `json:"lastUpdated"`
	mu                sync.RWMutex
}

// Built-in composers, validators, and injectors
type ChainComposer struct{}
type MergeComposer struct{}
type ConditionalComposer struct{}

type LengthValidator struct{}
type FormatValidator struct{}
type ContentValidator struct{}

type SystemContextInjector struct{}
type UserContextInjector struct{}
type MetadataInjector struct{}

// NewPromptManager creates a new prompt manager
func NewPromptManager(config PromptConfig) *PromptManager {
	pm := &PromptManager{
		prompts:          make(map[string]*PromptEntry),
		templates:        make(map[string]*PromptTemplate),
		composers:        make(map[string]PromptComposer),
		validators:       make(map[string]PromptValidator),
		cache:            make(map[string]*CachedPrompt),
		contextInjectors: make(map[string]ContextInjector),
		config:           config,
		metrics: &PromptMetrics{
			PromptUsage:    make(map[string]int64),
			TemplateUsage:  make(map[string]int64),
			CompositionTime: make(map[string]float64),
			ValidationTime: make(map[string]float64),
			ContextTime:    make(map[string]float64),
			LastUpdated:    time.Now(),
		},
	}

	// Register built-in composers
	if config.EnableComposition {
		pm.RegisterComposer("chain", &ChainComposer{})
		pm.RegisterComposer("merge", &MergeComposer{})
		pm.RegisterComposer("conditional", &ConditionalComposer{})
	}

	// Register built-in validators
	if config.EnableValidation {
		pm.RegisterValidator("length", &LengthValidator{})
		pm.RegisterValidator("format", &FormatValidator{})
		pm.RegisterValidator("content", &ContentValidator{})
	}

	// Register built-in context injectors
	if config.EnableContext {
		pm.RegisterContextInjector("system", &SystemContextInjector{})
		pm.RegisterContextInjector("user", &UserContextInjector{})
		pm.RegisterContextInjector("metadata", &MetadataInjector{})
	}

	// Load templates from directory if specified
	if config.TemplateDirectory != "" {
		if err := pm.LoadTemplatesFromDirectory(config.TemplateDirectory); err != nil {
			log.Warn().Err(err).Str("dir", config.TemplateDirectory).Msg("Failed to load prompt templates")
		}
	}

	return pm
}

// RegisterPrompt adds a new prompt to the manager
func (pm *PromptManager) RegisterPrompt(prompt Prompt, metadata map[string]interface{}) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	entry := &PromptEntry{
		Prompt:       prompt,
		Version:      pm.generateVersion(),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		UsageCount:   0,
		Metadata:     metadata,
		Tags:         []string{},
		Category:     "default",
		IsTemplate:   false,
	}

	pm.prompts[prompt.Name] = entry
	pm.updateMetrics()

	log.Info().
		Str("name", prompt.Name).
		Str("description", prompt.Description).
		Str("version", entry.Version).
		Msg("Prompt registered")

	return nil
}

// RegisterTemplate adds a prompt template
func (pm *PromptManager) RegisterTemplate(template *PromptTemplate) error {
	pm.templatesMu.Lock()
	defer pm.templatesMu.Unlock()

	if err := pm.validateTemplate(template); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	pm.templates[template.Name] = template

	log.Info().
		Str("name", template.Name).
		Str("description", template.Description).
		Msg("Prompt template registered")

	return nil
}

// RegisterComposer adds a prompt composer
func (pm *PromptManager) RegisterComposer(name string, composer PromptComposer) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.composers[name] = composer

	log.Info().
		Str("name", name).
		Str("description", composer.GetInfo().Description).
		Msg("Prompt composer registered")
}

// RegisterValidator adds a prompt validator
func (pm *PromptManager) RegisterValidator(name string, validator PromptValidator) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.validators[name] = validator

	log.Info().
		Str("name", name).
		Str("description", validator.GetInfo().Description).
		Msg("Prompt validator registered")
}

// RegisterContextInjector adds a context injector
func (pm *PromptManager) RegisterContextInjector(name string, injector ContextInjector) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.contextInjectors[name] = injector

	log.Info().
		Str("name", name).
		Str("description", injector.GetInfo().Description).
		Msg("Context injector registered")
}

// ListPrompts returns all registered prompts
func (pm *PromptManager) ListPrompts(ctx context.Context, filters map[string]string) ([]Prompt, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	prompts := make([]Prompt, 0, len(pm.prompts))

	for _, entry := range pm.prompts {
		if pm.matchesFilters(entry, filters) {
			prompts = append(prompts, entry.Prompt)
		}
	}

	// Update metrics
	if pm.config.EnableMetrics {
		pm.metrics.mu.Lock()
		pm.metrics.LastUpdated = time.Now()
		pm.metrics.mu.Unlock()
	}

	return prompts, nil
}

// GetPrompt retrieves and processes a prompt
func (pm *PromptManager) GetPrompt(ctx context.Context, name string, arguments map[string]interface{}) (*GetPromptResult, error) {
	start := time.Now()
	defer func() {
		if pm.config.EnableMetrics {
			duration := time.Since(start).Seconds()
			pm.metrics.mu.Lock()
			pm.metrics.CompositionTime[name] = duration
			pm.metrics.PromptUsage[name]++
			pm.metrics.LastUpdated = time.Now()
			pm.metrics.mu.Unlock()
		}
	}()

	// Check cache first
	if pm.config.EnableCaching {
		cacheKey := pm.generateCacheKey(name, arguments)
		if cached := pm.getCachedPrompt(cacheKey); cached != nil {
			pm.updateCacheMetrics(true)
			return cached.Result, nil
		}
		pm.updateCacheMetrics(false)
	}

	// Get prompt entry
	pm.mu.RLock()
	entry, exists := pm.prompts[name]
	pm.mu.RUnlock()

	if !exists {
		// Try to generate from template
		return pm.generateFromTemplate(ctx, name, arguments)
	}

	// Update usage count
	pm.mu.Lock()
	entry.UsageCount++
	entry.UpdatedAt = time.Now()
	pm.mu.Unlock()

	// Process the prompt
	result, err := pm.processPrompt(ctx, entry, arguments)
	if err != nil {
		return nil, fmt.Errorf("failed to process prompt %s: %w", name, err)
	}

	// Apply validation if enabled
	if pm.config.EnableValidation && entry.ValidatorName != "" {
		if err := pm.validatePromptResult(ctx, result, entry); err != nil {
			log.Warn().Err(err).Str("prompt", name).Msg("Prompt validation failed")
		}
	}

	// Apply context injection if enabled
	if pm.config.EnableContext {
		result, err = pm.injectContext(ctx, result, entry, arguments)
		if err != nil {
			log.Warn().Err(err).Str("prompt", name).Msg("Context injection failed")
		}
	}

	// Cache the result
	if pm.config.EnableCaching {
		cacheKey := pm.generateCacheKey(name, arguments)
		pm.cachePrompt(cacheKey, result, entry.Version)
	}

	return result, nil
}

// ComposePrompts combines multiple prompts using a composer
func (pm *PromptManager) ComposePrompts(ctx context.Context, strategy string, promptNames []string, params map[string]interface{}) (*GetPromptResult, error) {
	if !pm.config.EnableComposition {
		return nil, fmt.Errorf("prompt composition is disabled")
	}

	composer, exists := pm.composers[strategy]
	if !exists {
		return nil, fmt.Errorf("composer not found: %s", strategy)
	}

	start := time.Now()
	result, err := composer.Compose(ctx, promptNames, params)
	
	if pm.config.EnableMetrics {
		duration := time.Since(start).Seconds()
		pm.metrics.mu.Lock()
		pm.metrics.CompositionTime[strategy] = duration
		pm.metrics.mu.Unlock()
	}

	return result, err
}

// LoadTemplatesFromDirectory loads templates from a directory
func (pm *PromptManager) LoadTemplatesFromDirectory(dir string) error {
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

		var template PromptTemplate
		if err := json.Unmarshal(data, &template); err != nil {
			return err
		}

		return pm.RegisterTemplate(&template)
	})
}

// GetMetrics returns current prompt metrics
func (pm *PromptManager) GetMetrics() *PromptMetrics {
	if !pm.config.EnableMetrics {
		return nil
	}

	pm.metrics.mu.RLock()
	defer pm.metrics.mu.RUnlock()

	// Create a copy to avoid concurrent access
	metrics := &PromptMetrics{
		TotalPrompts:       pm.metrics.TotalPrompts,
		CacheHitRate:       pm.metrics.CacheHitRate,
		CacheHits:          pm.metrics.CacheHits,
		CacheMisses:        pm.metrics.CacheMisses,
		PromptUsage:        make(map[string]int64),
		TemplateUsage:      make(map[string]int64),
		CompositionTime:    make(map[string]float64),
		ValidationTime:     make(map[string]float64),
		ContextTime:        make(map[string]float64),
		ValidationErrors:   pm.metrics.ValidationErrors,
		ValidationWarnings: pm.metrics.ValidationWarnings,
		LastUpdated:        pm.metrics.LastUpdated,
	}

	for k, v := range pm.metrics.PromptUsage {
		metrics.PromptUsage[k] = v
	}
	for k, v := range pm.metrics.TemplateUsage {
		metrics.TemplateUsage[k] = v
	}
	for k, v := range pm.metrics.CompositionTime {
		metrics.CompositionTime[k] = v
	}
	for k, v := range pm.metrics.ValidationTime {
		metrics.ValidationTime[k] = v
	}
	for k, v := range pm.metrics.ContextTime {
		metrics.ContextTime[k] = v
	}

	return metrics
}

// Private helper methods

func (pm *PromptManager) generateVersion() string {
	return fmt.Sprintf("v%d", time.Now().Unix())
}

func (pm *PromptManager) generateCacheKey(name string, arguments map[string]interface{}) string {
	// Simple cache key generation - in production, use proper hashing
	key := name
	for k, v := range arguments {
		key += fmt.Sprintf("-%s:%v", k, v)
	}
	return key
}

func (pm *PromptManager) matchesFilters(entry *PromptEntry, filters map[string]string) bool {
	for key, value := range filters {
		switch key {
		case "category":
			if entry.Category != value {
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
		case "template":
			if (value == "true") != entry.IsTemplate {
				return false
			}
		}
	}
	return true
}

func (pm *PromptManager) getCachedPrompt(key string) *CachedPrompt {
	pm.cacheMu.RLock()
	defer pm.cacheMu.RUnlock()

	cached, exists := pm.cache[key]
	if !exists || time.Now().After(cached.ExpiresAt) {
		return nil
	}

	cached.HitCount++
	return cached
}

func (pm *PromptManager) cachePrompt(key string, result *GetPromptResult, version string) {
	if !pm.config.EnableCaching {
		return
	}

	pm.cacheMu.Lock()
	defer pm.cacheMu.Unlock()

	// Check cache size limit
	if len(pm.cache) >= pm.config.MaxCacheSize {
		pm.evictOldestCacheEntry()
	}

	pm.cache[key] = &CachedPrompt{
		Result:    result,
		Version:   version,
		ExpiresAt: time.Now().Add(pm.config.CacheTTL),
		HitCount:  0,
		Hash:      key,
	}
}

func (pm *PromptManager) evictOldestCacheEntry() {
	var oldestKey string
	var oldestTime time.Time

	for key, cached := range pm.cache {
		if oldestKey == "" || cached.ExpiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = cached.ExpiresAt
		}
	}

	if oldestKey != "" {
		delete(pm.cache, oldestKey)
	}
}

func (pm *PromptManager) updateCacheMetrics(hit bool) {
	if !pm.config.EnableMetrics {
		return
	}

	pm.metrics.mu.Lock()
	defer pm.metrics.mu.Unlock()

	if hit {
		pm.metrics.CacheHits++
	} else {
		pm.metrics.CacheMisses++
	}

	total := pm.metrics.CacheHits + pm.metrics.CacheMisses
	if total > 0 {
		pm.metrics.CacheHitRate = float64(pm.metrics.CacheHits) / float64(total)
	}
}

func (pm *PromptManager) updateMetrics() {
	if !pm.config.EnableMetrics {
		return
	}

	pm.metrics.mu.Lock()
	pm.metrics.TotalPrompts = int64(len(pm.prompts))
	pm.metrics.LastUpdated = time.Now()
	pm.metrics.mu.Unlock()
}

func (pm *PromptManager) validateTemplate(template *PromptTemplate) error {
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if template.Template == "" {
		return fmt.Errorf("template content is required")
	}
	return nil
}

func (pm *PromptManager) generateFromTemplate(ctx context.Context, name string, arguments map[string]interface{}) (*GetPromptResult, error) {
	pm.templatesMu.RLock()
	template, exists := pm.templates[name]
	pm.templatesMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("prompt not found: %s", name)
	}

	// Validate parameters
	if err := pm.validateTemplateParams(template, arguments); err != nil {
		return nil, fmt.Errorf("invalid template parameters: %w", err)
	}

	// Generate content
	content := pm.processTemplate(template, arguments)

	// Update metrics
	if pm.config.EnableMetrics {
		pm.metrics.mu.Lock()
		pm.metrics.TemplateUsage[name]++
		pm.metrics.LastUpdated = time.Now()
		pm.metrics.mu.Unlock()
	}

	result := &GetPromptResult{
		Description: template.Description,
		Messages: []PromptMessage{
			{
				Role: "user",
				Content: PromptContent{
					Type: "text",
					Text: content,
				},
			},
		},
	}

	return result, nil
}

func (pm *PromptManager) validateTemplateParams(template *PromptTemplate, params map[string]interface{}) error {
	for _, param := range template.Parameters {
		if param.Required {
			if _, exists := params[param.Name]; !exists {
				return fmt.Errorf("required parameter missing: %s", param.Name)
			}
		}
	}
	return nil
}

func (pm *PromptManager) processTemplate(template *PromptTemplate, params map[string]interface{}) string {
	// Simple template processing - in a real implementation, use a proper template engine
	content := template.Template

	for key, value := range params {
		placeholder := fmt.Sprintf("{{%s}}", key)
		content = strings.ReplaceAll(content, placeholder, fmt.Sprintf("%v", value))
	}

	return content
}

func (pm *PromptManager) processPrompt(ctx context.Context, entry *PromptEntry, arguments map[string]interface{}) (*GetPromptResult, error) {
	// For now, return a simple prompt result
	// In a real implementation, this would process the prompt based on its type and arguments
	result := &GetPromptResult{
		Description: entry.Description,
		Messages: []PromptMessage{
			{
				Role: "user",
				Content: PromptContent{
					Type: "text",
					Text: fmt.Sprintf("Prompt: %s\nArguments: %v", entry.Name, arguments),
				},
			},
		},
	}

	return result, nil
}

func (pm *PromptManager) validatePromptResult(ctx context.Context, result *GetPromptResult, entry *PromptEntry) error {
	validator, exists := pm.validators[entry.ValidatorName]
	if !exists {
		return fmt.Errorf("validator not found: %s", entry.ValidatorName)
	}

	start := time.Now()
	validationResult, err := validator.Validate(ctx, result, []ValidationRule{})
	
	if pm.config.EnableMetrics {
		duration := time.Since(start).Seconds()
		pm.metrics.mu.Lock()
		pm.metrics.ValidationTime[entry.ValidatorName] = duration
		if !validationResult.IsValid {
			pm.metrics.ValidationErrors++
		}
		pm.metrics.ValidationWarnings += int64(len(validationResult.Warnings))
		pm.metrics.mu.Unlock()
	}

	if err != nil {
		return err
	}

	if !validationResult.IsValid {
		return fmt.Errorf("prompt validation failed: %d errors", len(validationResult.Errors))
	}

	return nil
}

func (pm *PromptManager) injectContext(ctx context.Context, result *GetPromptResult, entry *PromptEntry, arguments map[string]interface{}) (*GetPromptResult, error) {
	// Apply default context injection
	for injectorName, injector := range pm.contextInjectors {
		start := time.Now()
		newResult, err := injector.Inject(ctx, result, []ContextRule{})
		
		if pm.config.EnableMetrics {
			duration := time.Since(start).Seconds()
			pm.metrics.mu.Lock()
			pm.metrics.ContextTime[injectorName] = duration
			pm.metrics.mu.Unlock()
		}

		if err != nil {
			log.Warn().Err(err).Str("injector", injectorName).Msg("Context injection failed")
			continue
		}
		
		result = newResult
	}

	return result, nil
}

// Built-in composer implementations

func (cc *ChainComposer) Compose(ctx context.Context, prompts []string, params map[string]interface{}) (*GetPromptResult, error) {
	// Chain prompts sequentially
	messages := []PromptMessage{}
	description := "Chained prompts: " + strings.Join(prompts, " -> ")

	for i, promptName := range prompts {
		messages = append(messages, PromptMessage{
			Role: "user",
			Content: PromptContent{
				Type: "text",
				Text: fmt.Sprintf("Step %d - %s", i+1, promptName),
			},
		})
	}

	return &GetPromptResult{
		Description: description,
		Messages:    messages,
	}, nil
}

func (cc *ChainComposer) GetInfo() ComposerInfo {
	return ComposerInfo{
		Name:        "chain",
		Description: "Chains prompts sequentially",
		Strategies:  []string{"sequential", "pipeline"},
		Version:     "1.0.0",
	}
}

func (mc *MergeComposer) Compose(ctx context.Context, prompts []string, params map[string]interface{}) (*GetPromptResult, error) {
	// Merge prompts into a single message
	description := "Merged prompts: " + strings.Join(prompts, " + ")
	text := strings.Join(prompts, "\n\n")

	return &GetPromptResult{
		Description: description,
		Messages: []PromptMessage{
			{
				Role: "user",
				Content: PromptContent{
					Type: "text",
					Text: text,
				},
			},
		},
	}, nil
}

func (mc *MergeComposer) GetInfo() ComposerInfo {
	return ComposerInfo{
		Name:        "merge",
		Description: "Merges prompts into a single message",
		Strategies:  []string{"concatenate", "combine"},
		Version:     "1.0.0",
	}
}

func (cc *ConditionalComposer) Compose(ctx context.Context, prompts []string, params map[string]interface{}) (*GetPromptResult, error) {
	// Select prompts based on conditions
	condition, _ := params["condition"].(string)
	description := fmt.Sprintf("Conditional prompts (condition: %s)", condition)

	var selectedPrompts []string
	if condition == "all" {
		selectedPrompts = prompts
	} else if len(prompts) > 0 {
		selectedPrompts = prompts[:1] // Just take the first one for now
	}

	messages := []PromptMessage{}
	for _, promptName := range selectedPrompts {
		messages = append(messages, PromptMessage{
			Role: "user",
			Content: PromptContent{
				Type: "text",
				Text: promptName,
			},
		})
	}

	return &GetPromptResult{
		Description: description,
		Messages:    messages,
	}, nil
}

func (cc *ConditionalComposer) GetInfo() ComposerInfo {
	return ComposerInfo{
		Name:        "conditional",
		Description: "Selects prompts based on conditions",
		Strategies:  []string{"if-then", "switch", "filter"},
		Version:     "1.0.0",
	}
}

// Built-in validator implementations

func (lv *LengthValidator) Validate(ctx context.Context, prompt *GetPromptResult, rules []ValidationRule) (*ValidationResult, error) {
	result := &ValidationResult{
		IsValid:  true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Score:    1.0,
		Metadata: make(map[string]interface{}),
	}

	totalLength := 0
	for _, message := range prompt.Messages {
		totalLength += len(message.Content.Text)
	}

	if totalLength > 10000 { // Example limit
		result.IsValid = false
		result.Errors = append(result.Errors, ValidationError{
			Type:     "length",
			Message:  fmt.Sprintf("Prompt too long: %d characters", totalLength),
			Rule:     "max_length",
			Severity: "error",
		})
	}

	if totalLength > 5000 { // Warning threshold
		result.Warnings = append(result.Warnings, ValidationWarning{
			Type:    "length",
			Message: fmt.Sprintf("Prompt is long: %d characters", totalLength),
			Rule:    "recommended_length",
		})
	}

	return result, nil
}

func (lv *LengthValidator) GetInfo() ValidatorInfo {
	return ValidatorInfo{
		Name:        "length",
		Description: "Validates prompt length constraints",
		RuleTypes:   []string{"max_length", "min_length", "recommended_length"},
		Version:     "1.0.0",
	}
}

func (fv *FormatValidator) Validate(ctx context.Context, prompt *GetPromptResult, rules []ValidationRule) (*ValidationResult, error) {
	result := &ValidationResult{
		IsValid:  true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Score:    1.0,
		Metadata: make(map[string]interface{}),
	}

	// Validate message format
	for _, message := range prompt.Messages {
		if message.Role == "" {
			result.IsValid = false
			result.Errors = append(result.Errors, ValidationError{
				Type:     "format",
				Message:  "Message role is required",
				Field:    "role",
				Rule:     "required_role",
				Severity: "error",
			})
		}

		if message.Content.Type == "" {
			result.IsValid = false
			result.Errors = append(result.Errors, ValidationError{
				Type:     "format",
				Message:  "Message content type is required",
				Field:    "content.type",
				Rule:     "required_type",
				Severity: "error",
			})
		}
	}

	return result, nil
}

func (fv *FormatValidator) GetInfo() ValidatorInfo {
	return ValidatorInfo{
		Name:        "format",
		Description: "Validates prompt format and structure",
		RuleTypes:   []string{"required_role", "required_type", "valid_structure"},
		Version:     "1.0.0",
	}
}

func (cv *ContentValidator) Validate(ctx context.Context, prompt *GetPromptResult, rules []ValidationRule) (*ValidationResult, error) {
	result := &ValidationResult{
		IsValid:  true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
		Score:    1.0,
		Metadata: make(map[string]interface{}),
	}

	// Basic content validation
	for _, message := range prompt.Messages {
		if strings.TrimSpace(message.Content.Text) == "" {
			result.Warnings = append(result.Warnings, ValidationWarning{
				Type:    "content",
				Message: "Empty message content",
				Field:   "content.text",
				Rule:    "non_empty_content",
			})
		}
	}

	return result, nil
}

func (cv *ContentValidator) GetInfo() ValidatorInfo {
	return ValidatorInfo{
		Name:        "content",
		Description: "Validates prompt content quality",
		RuleTypes:   []string{"non_empty_content", "appropriate_content", "content_quality"},
		Version:     "1.0.0",
	}
}

// Built-in context injector implementations

func (sci *SystemContextInjector) Inject(ctx context.Context, prompt *GetPromptResult, rules []ContextRule) (*GetPromptResult, error) {
	// Inject system context
	systemMessage := PromptMessage{
		Role: "system",
		Content: PromptContent{
			Type: "text",
			Text: "System context: Current time: " + time.Now().Format(time.RFC3339),
		},
	}

	// Prepend system message
	messages := append([]PromptMessage{systemMessage}, prompt.Messages...)
	
	return &GetPromptResult{
		Description: prompt.Description,
		Messages:    messages,
	}, nil
}

func (sci *SystemContextInjector) GetInfo() InjectorInfo {
	return InjectorInfo{
		Name:        "system",
		Description: "Injects system context into prompts",
		SourceTypes: []string{"time", "environment", "system_info"},
		Version:     "1.0.0",
	}
}

func (uci *UserContextInjector) Inject(ctx context.Context, prompt *GetPromptResult, rules []ContextRule) (*GetPromptResult, error) {
	// Inject user context (for now, just add a context note)
	if len(prompt.Messages) > 0 {
		lastMessage := &prompt.Messages[len(prompt.Messages)-1]
		lastMessage.Content.Text += "\n\n[User context injected]"
	}

	return prompt, nil
}

func (uci *UserContextInjector) GetInfo() InjectorInfo {
	return InjectorInfo{
		Name:        "user",
		Description: "Injects user-specific context into prompts",
		SourceTypes: []string{"user_profile", "preferences", "history"},
		Version:     "1.0.0",
	}
}

func (mi *MetadataInjector) Inject(ctx context.Context, prompt *GetPromptResult, rules []ContextRule) (*GetPromptResult, error) {
	// Inject metadata context
	metadataMessage := PromptMessage{
		Role: "system",
		Content: PromptContent{
			Type: "text",
			Text: fmt.Sprintf("Metadata: Generated at %s", time.Now().Format(time.RFC3339)),
		},
	}

	prompt.Messages = append(prompt.Messages, metadataMessage)
	
	return prompt, nil
}

func (mi *MetadataInjector) GetInfo() InjectorInfo {
	return InjectorInfo{
		Name:        "metadata",
		Description: "Injects metadata context into prompts",
		SourceTypes: []string{"timestamp", "version", "generation_info"},
		Version:     "1.0.0",
	}
}