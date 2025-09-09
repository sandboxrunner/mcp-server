package tools

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

// Validator provides parameter validation functionality
type Validator struct{}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateParams validates parameters against a JSON schema
func (v *Validator) ValidateParams(params map[string]interface{}, schema map[string]interface{}) error {
	// Convert schema to JSON string
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return fmt.Errorf("failed to marshal schema: %w", err)
	}

	// Convert params to JSON string
	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal params: %w", err)
	}

	// Create schema and document loaders
	schemaLoader := gojsonschema.NewBytesLoader(schemaBytes)
	documentLoader := gojsonschema.NewBytesLoader(paramsBytes)

	// Validate
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, desc.String())
		}
		return fmt.Errorf("validation errors: %s", strings.Join(errors, "; "))
	}

	return nil
}

// ExtractParam extracts and validates a parameter from the params map
func (v *Validator) ExtractParam(params map[string]interface{}, key string, required bool, defaultValue interface{}) (interface{}, error) {
	value, exists := params[key]

	if !exists {
		if required {
			return nil, &ValidationError{
				Field:   key,
				Message: "required parameter missing",
			}
		}
		return defaultValue, nil
	}

	return value, nil
}

// ExtractString extracts a string parameter
func (v *Validator) ExtractString(params map[string]interface{}, key string, required bool, defaultValue string) (string, error) {
	value, err := v.ExtractParam(params, key, required, defaultValue)
	if err != nil {
		return "", err
	}

	if value == nil {
		return defaultValue, nil
	}

	str, ok := value.(string)
	if !ok {
		return "", &ValidationError{
			Field:   key,
			Message: fmt.Sprintf("expected string, got %T", value),
		}
	}

	return str, nil
}

// ExtractInt extracts an integer parameter
func (v *Validator) ExtractInt(params map[string]interface{}, key string, required bool, defaultValue int) (int, error) {
	value, err := v.ExtractParam(params, key, required, defaultValue)
	if err != nil {
		return 0, err
	}

	if value == nil {
		return defaultValue, nil
	}

	// Handle various numeric types
	switch v := value.(type) {
	case int:
		return v, nil
	case int64:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		i, err := strconv.Atoi(v)
		if err != nil {
			return 0, &ValidationError{
				Field:   key,
				Message: fmt.Sprintf("invalid integer: %s", v),
			}
		}
		return i, nil
	default:
		return 0, &ValidationError{
			Field:   key,
			Message: fmt.Sprintf("expected integer, got %T", value),
		}
	}
}

// ExtractBool extracts a boolean parameter
func (v *Validator) ExtractBool(params map[string]interface{}, key string, required bool, defaultValue bool) (bool, error) {
	value, err := v.ExtractParam(params, key, required, defaultValue)
	if err != nil {
		return false, err
	}

	if value == nil {
		return defaultValue, nil
	}

	switch v := value.(type) {
	case bool:
		return v, nil
	case string:
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false, &ValidationError{
				Field:   key,
				Message: fmt.Sprintf("invalid boolean: %s", v),
			}
		}
		return b, nil
	default:
		return false, &ValidationError{
			Field:   key,
			Message: fmt.Sprintf("expected boolean, got %T", value),
		}
	}
}

// ExtractMap extracts a map parameter
func (v *Validator) ExtractMap(params map[string]interface{}, key string, required bool) (map[string]interface{}, error) {
	value, err := v.ExtractParam(params, key, required, nil)
	if err != nil {
		return nil, err
	}

	if value == nil {
		return make(map[string]interface{}), nil
	}

	m, ok := value.(map[string]interface{})
	if !ok {
		return nil, &ValidationError{
			Field:   key,
			Message: fmt.Sprintf("expected object, got %T", value),
		}
	}

	return m, nil
}

// ExtractStringMap extracts a map[string]string parameter
func (v *Validator) ExtractStringMap(params map[string]interface{}, key string, required bool) (map[string]string, error) {
	rawMap, err := v.ExtractMap(params, key, required)
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for k, v := range rawMap {
		str, ok := v.(string)
		if !ok {
			return nil, &ValidationError{
				Field:   key,
				Message: fmt.Sprintf("expected string value for key %s, got %T", k, v),
			}
		}
		result[k] = str
	}

	return result, nil
}

// ExtractSlice extracts a slice parameter
func (v *Validator) ExtractSlice(params map[string]interface{}, key string, required bool) ([]interface{}, error) {
	value, err := v.ExtractParam(params, key, required, nil)
	if err != nil {
		return nil, err
	}

	if value == nil {
		return []interface{}{}, nil
	}

	slice, ok := value.([]interface{})
	if !ok {
		return nil, &ValidationError{
			Field:   key,
			Message: fmt.Sprintf("expected array, got %T", value),
		}
	}

	return slice, nil
}

// ExtractStringSlice extracts a []string parameter
func (v *Validator) ExtractStringSlice(params map[string]interface{}, key string, required bool) ([]string, error) {
	rawSlice, err := v.ExtractSlice(params, key, required)
	if err != nil {
		return nil, err
	}

	result := make([]string, len(rawSlice))
	for i, v := range rawSlice {
		str, ok := v.(string)
		if !ok {
			return nil, &ValidationError{
				Field:   key,
				Message: fmt.Sprintf("expected string at index %d, got %T", i, v),
			}
		}
		result[i] = str
	}

	return result, nil
}

// ValidateEnum validates that a value is in the allowed enum values
func (v *Validator) ValidateEnum(value string, field string, allowedValues []string) error {
	for _, allowed := range allowedValues {
		if value == allowed {
			return nil
		}
	}

	return &ValidationError{
		Field:   field,
		Message: fmt.Sprintf("value '%s' not in allowed values: %v", value, allowedValues),
	}
}

// ValidateRequired validates that required fields are present and not empty
func (v *Validator) ValidateRequired(params map[string]interface{}, requiredFields []string) error {
	for _, field := range requiredFields {
		value, exists := params[field]
		if !exists {
			return &ValidationError{
				Field:   field,
				Message: "required field missing",
			}
		}

		// Check if value is empty based on its type
		if v.isEmpty(value) {
			return &ValidationError{
				Field:   field,
				Message: "required field is empty",
			}
		}
	}

	return nil
}

// isEmpty checks if a value is considered empty
func (v *Validator) isEmpty(value interface{}) bool {
	if value == nil {
		return true
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.String:
		return rv.Len() == 0
	case reflect.Array, reflect.Slice, reflect.Map:
		return rv.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}

// ConvertToStruct converts a map to a struct using JSON marshaling/unmarshaling
func (v *Validator) ConvertToStruct(params map[string]interface{}, target interface{}) error {
	// Marshal params to JSON
	jsonData, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("failed to marshal params: %w", err)
	}

	// Unmarshal into target struct
	if err := json.Unmarshal(jsonData, target); err != nil {
		return fmt.Errorf("failed to unmarshal into struct: %w", err)
	}

	return nil
}
