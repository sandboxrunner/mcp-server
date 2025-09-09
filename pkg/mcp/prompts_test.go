package mcp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPromptManager_NewPromptManager(t *testing.T) {
	config := PromptConfig{
		EnableCaching:     true,
		CacheTTL:          time.Hour,
		MaxCacheSize:      100,
		EnableValidation:  true,
		EnableComposition: true,
		EnableContext:     true,
		EnableMetrics:     true,
	}

	pm := NewPromptManager(config)
	assert.NotNil(t, pm)
	assert.Equal(t, config, pm.config)
	assert.NotNil(t, pm.prompts)
	assert.NotNil(t, pm.templates)
	assert.NotNil(t, pm.composers)
	assert.NotNil(t, pm.validators)
	assert.NotNil(t, pm.cache)
	assert.NotNil(t, pm.contextInjectors)
	assert.NotNil(t, pm.metrics)
}

func TestPromptManager_RegisterPrompt(t *testing.T) {
	pm := NewPromptManager(PromptConfig{EnableMetrics: true})

	prompt := Prompt{
		Name:        "test-prompt",
		Description: "A test prompt",
		Arguments: []PromptArgument{
			{
				Name:        "subject",
				Description: "The subject of the prompt",
				Required:    boolPtr(true),
			},
		},
	}

	metadata := map[string]interface{}{
		"category": "test",
		"priority": "high",
	}

	err := pm.RegisterPrompt(prompt, metadata)
	assert.NoError(t, err)

	// Verify prompt was registered
	pm.mu.RLock()
	entry, exists := pm.prompts[prompt.Name]
	pm.mu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, prompt.Name, entry.Name)
	assert.Equal(t, prompt.Description, entry.Description)
	assert.NotEmpty(t, entry.Version)
	assert.NotZero(t, entry.CreatedAt)
	assert.Equal(t, metadata, entry.Metadata)
}

func TestPromptManager_ListPrompts(t *testing.T) {
	pm := NewPromptManager(PromptConfig{EnableMetrics: true})

	// Register test prompts
	prompts := []Prompt{
		{Name: "prompt1", Description: "First prompt"},
		{Name: "prompt2", Description: "Second prompt"},
		{Name: "prompt3", Description: "Third prompt"},
	}

	for i, prompt := range prompts {
		metadata := map[string]interface{}{
			"category": fmt.Sprintf("cat%d", i%2),
		}
		err := pm.RegisterPrompt(prompt, metadata)
		require.NoError(t, err)

		// Set category in entry
		pm.mu.Lock()
		if entry, exists := pm.prompts[prompt.Name]; exists {
			entry.Category = fmt.Sprintf("cat%d", i%2)
		}
		pm.mu.Unlock()
	}

	ctx := context.Background()

	// Test listing all prompts
	allPrompts, err := pm.ListPrompts(ctx, nil)
	assert.NoError(t, err)
	assert.Len(t, allPrompts, 3)

	// Test filtering by category
	filters := map[string]string{"category": "cat0"}
	filteredPrompts, err := pm.ListPrompts(ctx, filters)
	assert.NoError(t, err)
	assert.Len(t, filteredPrompts, 2)
}

func TestPromptManager_GetPrompt(t *testing.T) {
	pm := NewPromptManager(PromptConfig{
		EnableCaching: true,
		CacheTTL:      time.Hour,
		EnableMetrics: true,
	})

	prompt := Prompt{
		Name:        "test-prompt",
		Description: "A test prompt",
		Arguments: []PromptArgument{
			{
				Name:        "name",
				Description: "Name parameter",
				Required:    boolPtr(true),
			},
		},
	}

	err := pm.RegisterPrompt(prompt, nil)
	require.NoError(t, err)

	ctx := context.Background()
	arguments := map[string]interface{}{
		"name": "John",
	}

	// Test getting existing prompt
	result, err := pm.GetPrompt(ctx, prompt.Name, arguments)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, prompt.Description, result.Description)
	assert.Len(t, result.Messages, 1)

	// Test getting non-existing prompt
	_, err = pm.GetPrompt(ctx, "nonexistent-prompt", nil)
	assert.Error(t, err)
}

func TestPromptManager_RegisterTemplate(t *testing.T) {
	pm := NewPromptManager(PromptConfig{})

	template := &PromptTemplate{
		Name:        "greeting-template",
		Description: "A greeting template",
		Template:    "Hello {{name}}! How are you today?",
		Parameters: []TemplateParameter{
			{
				Name:        "name",
				Type:        "string",
				Description: "Name to greet",
				Required:    true,
			},
		},
		OutputFormat: "text",
		ValidationRules: []ValidationRule{
			{
				Type:       "length",
				Constraint: "max:100",
				Message:    "Template output too long",
			},
		},
	}

	err := pm.RegisterTemplate(template)
	assert.NoError(t, err)

	// Verify template was registered
	pm.templatesMu.RLock()
	registered, exists := pm.templates[template.Name]
	pm.templatesMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, template.Name, registered.Name)
	assert.Equal(t, template.Template, registered.Template)
	assert.Len(t, registered.ValidationRules, 1)
}

func TestPromptManager_GenerateFromTemplate(t *testing.T) {
	pm := NewPromptManager(PromptConfig{EnableMetrics: true})

	template := &PromptTemplate{
		Name:        "greeting-template",
		Description: "Greeting template",
		Template:    "Hello {{name}}! Welcome to {{platform}}.",
		Parameters: []TemplateParameter{
			{Name: "name", Type: "string", Required: true},
			{Name: "platform", Type: "string", Required: true},
		},
		OutputFormat: "text",
	}

	err := pm.RegisterTemplate(template)
	require.NoError(t, err)

	ctx := context.Background()
	arguments := map[string]interface{}{
		"name":     "Alice",
		"platform": "SandboxRunner",
	}

	result, err := pm.GetPrompt(ctx, template.Name, arguments)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, template.Description, result.Description)
	assert.Len(t, result.Messages, 1)
	assert.Contains(t, result.Messages[0].Content.Text, "Hello Alice!")
	assert.Contains(t, result.Messages[0].Content.Text, "Welcome to SandboxRunner")
}

func TestPromptManager_ComposePrompts(t *testing.T) {
	pm := NewPromptManager(PromptConfig{
		EnableComposition: true,
		EnableMetrics:     true,
	})

	// Register some prompts
	prompts := []string{"prompt1", "prompt2", "prompt3"}
	for _, name := range prompts {
		prompt := Prompt{
			Name:        name,
			Description: fmt.Sprintf("Description for %s", name),
		}
		err := pm.RegisterPrompt(prompt, nil)
		require.NoError(t, err)
	}

	ctx := context.Background()

	// Test chain composition
	params := map[string]interface{}{"strategy": "sequential"}
	result, err := pm.ComposePrompts(ctx, "chain", prompts, params)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Description, "Chained prompts")

	// Test merge composition
	result, err = pm.ComposePrompts(ctx, "merge", prompts, params)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Description, "Merged prompts")

	// Test conditional composition
	result, err = pm.ComposePrompts(ctx, "conditional", prompts, map[string]interface{}{"condition": "all"})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Description, "Conditional prompts")
}

func TestPromptManager_BuiltinComposers(t *testing.T) {
	// Test ChainComposer
	chain := &ChainComposer{}
	info := chain.GetInfo()
	assert.Equal(t, "chain", info.Name)
	assert.Contains(t, info.Description, "chain")

	ctx := context.Background()
	prompts := []string{"step1", "step2", "step3"}
	result, err := chain.Compose(ctx, prompts, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Messages, 3)

	// Test MergeComposer
	merge := &MergeComposer{}
	mergeInfo := merge.GetInfo()
	assert.Equal(t, "merge", mergeInfo.Name)
	assert.Contains(t, mergeInfo.Description, "merge")

	result, err = merge.Compose(ctx, prompts, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Messages, 1)

	// Test ConditionalComposer
	conditional := &ConditionalComposer{}
	condInfo := conditional.GetInfo()
	assert.Equal(t, "conditional", condInfo.Name)
	assert.Contains(t, condInfo.Description, "condition")

	result, err = conditional.Compose(ctx, prompts, map[string]interface{}{"condition": "first"})
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestPromptManager_BuiltinValidators(t *testing.T) {
	ctx := context.Background()
	prompt := &GetPromptResult{
		Description: "Test prompt",
		Messages: []PromptMessage{
			{
				Role: "user",
				Content: PromptContent{
					Type: "text",
					Text: "This is a test message",
				},
			},
		},
	}

	// Test LengthValidator
	lengthValidator := &LengthValidator{}
	info := lengthValidator.GetInfo()
	assert.Equal(t, "length", info.Name)
	assert.Contains(t, info.RuleTypes, "max_length")

	result, err := lengthValidator.Validate(ctx, prompt, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.IsValid)

	// Test FormatValidator
	formatValidator := &FormatValidator{}
	formatInfo := formatValidator.GetInfo()
	assert.Equal(t, "format", formatInfo.Name)
	assert.Contains(t, formatInfo.RuleTypes, "required_role")

	result, err = formatValidator.Validate(ctx, prompt, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.IsValid)

	// Test ContentValidator
	contentValidator := &ContentValidator{}
	contentInfo := contentValidator.GetInfo()
	assert.Equal(t, "content", contentInfo.Name)
	assert.Contains(t, contentInfo.RuleTypes, "non_empty_content")

	result, err = contentValidator.Validate(ctx, prompt, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.IsValid)
}

func TestPromptManager_BuiltinInjectors(t *testing.T) {
	ctx := context.Background()
	prompt := &GetPromptResult{
		Description: "Test prompt",
		Messages: []PromptMessage{
			{
				Role: "user",
				Content: PromptContent{
					Type: "text",
					Text: "Original message",
				},
			},
		},
	}

	// Test SystemContextInjector
	systemInjector := &SystemContextInjector{}
	info := systemInjector.GetInfo()
	assert.Equal(t, "system", info.Name)
	assert.Contains(t, info.SourceTypes, "time")

	result, err := systemInjector.Inject(ctx, prompt, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Messages, 2) // Original + system message

	// Test UserContextInjector
	userInjector := &UserContextInjector{}
	userInfo := userInjector.GetInfo()
	assert.Equal(t, "user", userInfo.Name)
	assert.Contains(t, userInfo.SourceTypes, "user_profile")

	result, err = userInjector.Inject(ctx, prompt, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.Messages[0].Content.Text, "[User context injected]")

	// Test MetadataInjector
	metadataInjector := &MetadataInjector{}
	metaInfo := metadataInjector.GetInfo()
	assert.Equal(t, "metadata", metaInfo.Name)
	assert.Contains(t, metaInfo.SourceTypes, "timestamp")

	result, err = metadataInjector.Inject(ctx, prompt, nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Messages, 2) // Original + metadata message
}

func TestPromptManager_Caching(t *testing.T) {
	pm := NewPromptManager(PromptConfig{
		EnableCaching: true,
		CacheTTL:      time.Second,
		MaxCacheSize:  10,
		EnableMetrics: true,
	})

	prompt := Prompt{
		Name:        "cached-prompt",
		Description: "A cached prompt",
	}

	err := pm.RegisterPrompt(prompt, nil)
	require.NoError(t, err)

	ctx := context.Background()
	arguments := map[string]interface{}{"key": "value"}

	// First call should cache the result
	result1, err := pm.GetPrompt(ctx, prompt.Name, arguments)
	assert.NoError(t, err)
	assert.NotNil(t, result1)

	// Second call should use cache
	result2, err := pm.GetPrompt(ctx, prompt.Name, arguments)
	assert.NoError(t, err)
	assert.NotNil(t, result2)

	// Verify cache hit metrics
	metrics := pm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.True(t, metrics.CacheHits > 0)
}

func TestPromptManager_Metrics(t *testing.T) {
	pm := NewPromptManager(PromptConfig{
		EnableMetrics: true,
		EnableCaching: true,
	})

	// Register some prompts
	for i := 0; i < 5; i++ {
		prompt := Prompt{
			Name:        fmt.Sprintf("prompt-%d", i),
			Description: fmt.Sprintf("Test prompt %d", i),
		}
		err := pm.RegisterPrompt(prompt, nil)
		require.NoError(t, err)
	}

	metrics := pm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, int64(5), metrics.TotalPrompts)
	assert.NotZero(t, metrics.LastUpdated)
}

func TestPromptManager_ConcurrentAccess(t *testing.T) {
	pm := NewPromptManager(PromptConfig{
		EnableCaching:     true,
		EnableComposition: true,
		EnableMetrics:     true,
	})

	// Register a prompt
	prompt := Prompt{
		Name:        "concurrent-prompt",
		Description: "Concurrent access test prompt",
	}
	err := pm.RegisterPrompt(prompt, nil)
	require.NoError(t, err)

	ctx := context.Background()
	const numGoroutines = 10
	const numRequests = 50

	// Test concurrent prompt access
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numRequests; j++ {
				arguments := map[string]interface{}{
					"id":    id,
					"count": j,
				}
				result, err := pm.GetPrompt(ctx, prompt.Name, arguments)
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		}(i)
	}

	// Test concurrent template registration
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			template := &PromptTemplate{
				Name:        fmt.Sprintf("concurrent-template-%d", id),
				Description: fmt.Sprintf("Concurrent template %d", id),
				Template:    fmt.Sprintf("Template %d: {{value}}", id),
				Parameters: []TemplateParameter{
					{Name: "value", Type: "string", Required: true},
				},
				OutputFormat: "text",
			}
			err := pm.RegisterTemplate(template)
			assert.NoError(t, err)
		}(i)
	}

	// Give goroutines time to complete
	time.Sleep(time.Second)

	// Verify metrics were updated
	metrics := pm.GetMetrics()
	assert.NotNil(t, metrics)
	assert.True(t, metrics.TotalPrompts > 0)
}

func TestPromptManager_ValidationErrors(t *testing.T) {
	pm := NewPromptManager(PromptConfig{})

	// Test invalid template registration
	invalidTemplate := &PromptTemplate{
		Name:        "", // Empty name should fail
		Description: "Invalid template",
	}

	err := pm.RegisterTemplate(invalidTemplate)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "template name is required")

	// Test invalid template content
	invalidTemplate2 := &PromptTemplate{
		Name:        "invalid-template",
		Description: "Invalid template",
		Template:    "", // Empty template should fail
	}

	err = pm.RegisterTemplate(invalidTemplate2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "template content is required")
}

