package tools

import (
	"context"
	"testing"
)

func TestRegistry(t *testing.T) {
	registry := NewRegistry()

	// Test empty registry
	if registry.Count() != 0 {
		t.Errorf("Expected empty registry, got %d tools", registry.Count())
	}

	// Test registering a tool
	tool := &mockTool{name: "test_tool"}
	err := registry.RegisterTool(tool)
	if err != nil {
		t.Errorf("Failed to register tool: %v", err)
	}

	if registry.Count() != 1 {
		t.Errorf("Expected 1 tool, got %d", registry.Count())
	}

	// Test getting a tool
	retrieved := registry.GetTool("test_tool")
	if retrieved == nil {
		t.Error("Failed to retrieve registered tool")
	}

	if retrieved.Name() != "test_tool" {
		t.Errorf("Expected tool name 'test_tool', got '%s'", retrieved.Name())
	}

	// Test listing tools
	tools := registry.ListTools()
	if len(tools) != 1 {
		t.Errorf("Expected 1 tool in list, got %d", len(tools))
	}

	// Test tool names
	names := registry.ToolNames()
	if len(names) != 1 || names[0] != "test_tool" {
		t.Errorf("Expected tool names ['test_tool'], got %v", names)
	}

	// Test has tool
	if !registry.HasTool("test_tool") {
		t.Error("Expected HasTool to return true for registered tool")
	}

	if registry.HasTool("nonexistent") {
		t.Error("Expected HasTool to return false for nonexistent tool")
	}

	// Test unregistering
	registry.UnregisterTool("test_tool")
	if registry.Count() != 0 {
		t.Errorf("Expected empty registry after unregister, got %d tools", registry.Count())
	}
}

func TestValidator(t *testing.T) {
	validator := NewValidator()

	params := map[string]interface{}{
		"string_param": "hello",
		"int_param":    42,
		"bool_param":   true,
		"map_param": map[string]interface{}{
			"key": "value",
		},
		"slice_param": []interface{}{"a", "b", "c"},
	}

	// Test extracting string
	str, err := validator.ExtractString(params, "string_param", true, "")
	if err != nil {
		t.Errorf("Failed to extract string: %v", err)
	}
	if str != "hello" {
		t.Errorf("Expected 'hello', got '%s'", str)
	}

	// Test extracting int
	num, err := validator.ExtractInt(params, "int_param", true, 0)
	if err != nil {
		t.Errorf("Failed to extract int: %v", err)
	}
	if num != 42 {
		t.Errorf("Expected 42, got %d", num)
	}

	// Test extracting bool
	boolean, err := validator.ExtractBool(params, "bool_param", true, false)
	if err != nil {
		t.Errorf("Failed to extract bool: %v", err)
	}
	if !boolean {
		t.Error("Expected true, got false")
	}

	// Test extracting map
	mapParam, err := validator.ExtractMap(params, "map_param", true)
	if err != nil {
		t.Errorf("Failed to extract map: %v", err)
	}
	if mapParam["key"] != "value" {
		t.Errorf("Expected map value 'value', got '%v'", mapParam["key"])
	}

	// Test extracting slice
	sliceParam, err := validator.ExtractSlice(params, "slice_param", true)
	if err != nil {
		t.Errorf("Failed to extract slice: %v", err)
	}
	if len(sliceParam) != 3 {
		t.Errorf("Expected slice length 3, got %d", len(sliceParam))
	}

	// Test missing required parameter
	_, err = validator.ExtractString(params, "missing_param", true, "")
	if err == nil {
		t.Error("Expected error for missing required parameter")
	}

	// Test default value for optional parameter
	defaultStr, err := validator.ExtractString(params, "missing_param", false, "default")
	if err != nil {
		t.Errorf("Failed to get default value: %v", err)
	}
	if defaultStr != "default" {
		t.Errorf("Expected 'default', got '%s'", defaultStr)
	}
}

func TestToolError(t *testing.T) {
	err := NewToolError("TEST_ERROR", "Test error message", "Additional details")

	if err.Code != "TEST_ERROR" {
		t.Errorf("Expected code 'TEST_ERROR', got '%s'", err.Code)
	}

	if err.Message != "Test error message" {
		t.Errorf("Expected message 'Test error message', got '%s'", err.Message)
	}

	if err.Details != "Additional details" {
		t.Errorf("Expected details 'Additional details', got '%s'", err.Details)
	}

	if err.Error() != "Test error message" {
		t.Errorf("Expected Error() to return message, got '%s'", err.Error())
	}
}

func TestBaseTool(t *testing.T) {
	schema := map[string]interface{}{
		"type": "object",
		"properties": map[string]interface{}{
			"param": map[string]interface{}{
				"type": "string",
			},
		},
	}

	tool := NewBaseTool("test_tool", "Test tool description", schema)

	if tool.Name() != "test_tool" {
		t.Errorf("Expected name 'test_tool', got '%s'", tool.Name())
	}

	if tool.Description() != "Test tool description" {
		t.Errorf("Expected description 'Test tool description', got '%s'", tool.Description())
	}

	returnedSchema := tool.Schema()
	if returnedSchema["type"] != "object" {
		t.Errorf("Expected schema type 'object', got '%v'", returnedSchema["type"])
	}
}

// Mock tool for testing
type mockTool struct {
	name        string
	description string
	schema      map[string]interface{}
}

func (mt *mockTool) Name() string {
	return mt.name
}

func (mt *mockTool) Description() string {
	if mt.description != "" {
		return mt.description
	}
	return "Mock tool for testing"
}

func (mt *mockTool) Schema() map[string]interface{} {
	if mt.schema != nil {
		return mt.schema
	}
	return map[string]interface{}{
		"type":       "object",
		"properties": map[string]interface{}{},
	}
}

func (mt *mockTool) Execute(ctx context.Context, params map[string]interface{}) (*ToolResult, error) {
	return &ToolResult{
		Text:    "Mock tool executed successfully",
		IsError: false,
	}, nil
}
