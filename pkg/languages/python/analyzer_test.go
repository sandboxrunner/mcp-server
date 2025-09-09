package python

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewCodeAnalyzer(t *testing.T) {
	// Test with nil config (should use defaults)
	analyzer := NewCodeAnalyzer(nil)
	
	if analyzer.config == nil {
		t.Error("Config should not be nil")
	}
	
	if !analyzer.config.EnableSyntaxValidation {
		t.Error("Syntax validation should be enabled by default")
	}
	
	if !analyzer.config.EnableSecurityScanning {
		t.Error("Security scanning should be enabled by default")
	}
	
	if analyzer.securityScanner == nil {
		t.Error("Security scanner should be initialized")
	}
	
	// Test with custom config
	customConfig := &AnalysisConfig{
		EnableSyntaxValidation: false,
		MaxComplexity:         15,
	}
	
	analyzer = NewCodeAnalyzer(customConfig)
	
	if analyzer.config.EnableSyntaxValidation {
		t.Error("Syntax validation should be disabled")
	}
	
	if analyzer.config.MaxComplexity != 15 {
		t.Errorf("Expected max complexity 15, got %d", analyzer.config.MaxComplexity)
	}
}

func TestCodeAnalyzer_parseImports(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	code := `
import os
import sys
from datetime import datetime, timedelta
from requests import get as http_get
import numpy as np
from . import local_module
from ..parent import parent_module
# This is a comment
import json  # Another comment
`
	
	imports, dependencies := analyzer.parseImports(code)
	
	// Check imports
	if len(imports) == 0 {
		t.Error("Should detect imports")
	}
	
	// Check for specific imports
	importNames := make(map[string]bool)
	for _, imp := range imports {
		importNames[imp.Module] = true
	}
	
	expectedImports := []string{"os", "sys", "datetime", "requests", "numpy", "json"}
	for _, expected := range expectedImports {
		if !importNames[expected] {
			t.Errorf("Expected to find import: %s", expected)
		}
	}
	
	// Check dependencies (should exclude standard library)
	dependencySet := make(map[string]bool)
	for _, dep := range dependencies {
		dependencySet[dep] = true
	}
	
	expectedDeps := []string{"requests", "numpy"}
	for _, expected := range expectedDeps {
		if !dependencySet[expected] {
			t.Errorf("Expected dependency: %s", expected)
		}
	}
	
	// Standard library modules should not be in dependencies
	standardLibs := []string{"os", "sys", "json"}
	for _, stdlib := range standardLibs {
		if dependencySet[stdlib] {
			t.Errorf("Standard library module %s should not be in dependencies", stdlib)
		}
	}
}

func TestCodeAnalyzer_parseImportStatement(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	standardModules := map[string]bool{"os": true, "sys": true, "json": true}
	
	tests := []struct {
		name     string
		line     string
		expected *ImportStatement
	}{
		{
			name: "Simple import",
			line: "import os",
			expected: &ImportStatement{
				Type:        ImportTypeImport,
				Module:      "os",
				LineNumber:  1,
				IsStandard:  true,
				IsThirdParty: false,
			},
		},
		{
			name: "Import with alias",
			line: "import numpy as np",
			expected: &ImportStatement{
				Type:        ImportTypeImport,
				Module:      "numpy",
				Alias:       "np",
				LineNumber:  1,
				IsStandard:  false,
				IsThirdParty: true,
			},
		},
		{
			name: "From import",
			line: "from datetime import datetime",
			expected: &ImportStatement{
				Type:       ImportTypeFromImport,
				Module:     "datetime",
				Items:      []string{"datetime"},
				LineNumber: 1,
				IsStandard: false,
				IsThirdParty: true,
			},
		},
		{
			name: "Relative import",
			line: "from . import local_module",
			expected: &ImportStatement{
				Type:       ImportTypeFromImport,
				Module:     "local_module",
				Items:      []string{"local_module"},
				Level:      1,
				LineNumber: 1,
				IsLocal:    true,
			},
		},
		{
			name:     "Not an import",
			line:     "print('hello')",
			expected: nil,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.parseImportStatement(tt.line, 1, standardModules)
			
			if tt.expected == nil && result != nil {
				t.Error("Expected nil but got result")
				return
			}
			
			if tt.expected != nil && result == nil {
				t.Error("Expected result but got nil")
				return
			}
			
			if tt.expected != nil && result != nil {
				if result.Type != tt.expected.Type {
					t.Errorf("Expected type %s, got %s", tt.expected.Type, result.Type)
				}
				if result.Module != tt.expected.Module {
					t.Errorf("Expected module %s, got %s", tt.expected.Module, result.Module)
				}
				if result.Alias != tt.expected.Alias {
					t.Errorf("Expected alias %s, got %s", tt.expected.Alias, result.Alias)
				}
				if result.Level != tt.expected.Level {
					t.Errorf("Expected level %d, got %d", tt.expected.Level, result.Level)
				}
			}
		})
	}
}

func TestCodeAnalyzer_parseFunctions(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	code := `
def simple_function():
    pass

def function_with_params(arg1, arg2="default"):
    return arg1 + arg2

async def async_function():
    await something()

@decorator
def decorated_function():
    """This is a docstring."""
    pass

class MyClass:
    def method(self):
        pass
    
    @classmethod
    def class_method(cls):
        pass
    
    @staticmethod
    def static_method():
        pass
`
	
	functions := analyzer.parseFunctions(code)
	
	if len(functions) == 0 {
		t.Error("Should detect functions")
	}
	
	// Check for specific functions
	functionNames := make(map[string]*FunctionInfo)
	for _, fn := range functions {
		functionNames[fn.Name] = fn
	}
	
	expectedFunctions := []string{"simple_function", "function_with_params", "async_function", "decorated_function", "method", "class_method", "static_method"}
	for _, expected := range expectedFunctions {
		if _, found := functionNames[expected]; !found {
			t.Errorf("Expected to find function: %s", expected)
		}
	}
	
	// Check async function
	if asyncFunc, found := functionNames["async_function"]; found {
		if !asyncFunc.IsAsync {
			t.Error("async_function should be marked as async")
		}
	}
	
	// Check method
	if method, found := functionNames["method"]; found {
		if !method.IsMethod {
			t.Error("method should be marked as method")
		}
	}
	
	// Check class method
	if classMethod, found := functionNames["class_method"]; found {
		if !classMethod.IsClassMethod {
			t.Error("class_method should be marked as class method")
		}
	}
	
	// Check static method
	if staticMethod, found := functionNames["static_method"]; found {
		if !staticMethod.IsStaticMethod {
			t.Error("static_method should be marked as static method")
		}
	}
	
	// Check decorated function
	if decoratedFunc, found := functionNames["decorated_function"]; found {
		if len(decoratedFunc.Decorators) == 0 {
			t.Error("decorated_function should have decorators")
		}
		if decoratedFunc.Docstring == "" {
			t.Error("decorated_function should have docstring")
		}
	}
}

func TestCodeAnalyzer_parseClasses(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	code := `
class SimpleClass:
    pass

class InheritedClass(BaseClass, Mixin):
    """Class with docstring."""
    pass

@dataclass
class DecoratedClass:
    pass

class AbstractClass(ABC):
    pass
`
	
	classes := analyzer.parseClasses(code)
	
	if len(classes) == 0 {
		t.Error("Should detect classes")
	}
	
	// Check for specific classes
	classNames := make(map[string]*ClassInfo)
	for _, cls := range classes {
		classNames[cls.Name] = cls
	}
	
	expectedClasses := []string{"SimpleClass", "InheritedClass", "DecoratedClass", "AbstractClass"}
	for _, expected := range expectedClasses {
		if _, found := classNames[expected]; !found {
			t.Errorf("Expected to find class: %s", expected)
		}
	}
	
	// Check inherited class
	if inheritedClass, found := classNames["InheritedClass"]; found {
		if len(inheritedClass.BaseClasses) != 2 {
			t.Errorf("Expected 2 base classes, got %d", len(inheritedClass.BaseClasses))
		}
		expectedBases := []string{"BaseClass", "Mixin"}
		for i, expected := range expectedBases {
			if i >= len(inheritedClass.BaseClasses) || inheritedClass.BaseClasses[i] != expected {
				t.Errorf("Expected base class %s", expected)
			}
		}
		if inheritedClass.Docstring == "" {
			t.Error("InheritedClass should have docstring")
		}
	}
	
	// Check decorated class
	if decoratedClass, found := classNames["DecoratedClass"]; found {
		if len(decoratedClass.Decorators) == 0 {
			t.Error("DecoratedClass should have decorators")
		}
	}
}

func TestCodeAnalyzer_parseVariables(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	code := `
CONSTANT = "constant value"
variable = 42
typed_var: int = 100
string_var: str = "hello"
    indented_var = "local"
`
	
	variables := analyzer.parseVariables(code)
	
	if len(variables) == 0 {
		t.Error("Should detect variables")
	}
	
	// Check for specific variables
	variableNames := make(map[string]*VariableInfo)
	for _, variable := range variables {
		variableNames[variable.Name] = variable
	}
	
	expectedVariables := []string{"CONSTANT", "variable", "typed_var", "string_var", "indented_var"}
	for _, expected := range expectedVariables {
		if _, found := variableNames[expected]; !found {
			t.Errorf("Expected to find variable: %s", expected)
		}
	}
	
	// Check constant
	if constant, found := variableNames["CONSTANT"]; found {
		if !constant.IsConstant {
			t.Error("CONSTANT should be marked as constant")
		}
		if !constant.IsGlobal {
			t.Error("CONSTANT should be marked as global")
		}
	}
	
	// Check typed variable
	if typedVar, found := variableNames["typed_var"]; found {
		if typedVar.Type != "int" {
			t.Errorf("Expected type 'int', got '%s'", typedVar.Type)
		}
	}
	
	// Check indented variable
	if indentedVar, found := variableNames["indented_var"]; found {
		if indentedVar.Scope != "local" {
			t.Errorf("Expected scope 'local', got '%s'", indentedVar.Scope)
		}
	}
}

func TestCodeAnalyzer_validateSyntax(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	tests := []struct {
		name        string
		code        string
		expectError bool
	}{
		{
			name: "Valid Python code",
			code: `
def hello():
    print("Hello, World!")
    return True
`,
			expectError: false,
		},
		{
			name: "Invalid indentation",
			code: `
def hello():
print("Invalid indentation")
`,
			expectError: true,
		},
		{
			name: "Empty code",
			code: "",
			expectError: false,
		},
		{
			name: "Only comments",
			code: "# This is just a comment",
			expectError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := analyzer.validateSyntax(tt.code)
			
			if tt.expectError && len(errors) == 0 {
				t.Error("Expected syntax errors but got none")
			}
			
			if !tt.expectError && len(errors) > 0 {
				t.Errorf("Expected no syntax errors but got: %v", errors)
			}
		})
	}
}

func TestCodeAnalyzer_analyzeTypeHints(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	code := `
def function(param: int) -> str:
    variable: List[str] = []
    another: Optional[int] = None
    return "result"
`
	
	typeHints := analyzer.analyzeTypeHints(code)
	
	if len(typeHints) == 0 {
		t.Error("Should detect type hints")
	}
	
	// Check for specific type hints
	typeMap := make(map[string]string)
	for _, hint := range typeHints {
		// Extract variable name from location for testing
		// This is simplified - in practice you'd parse the location better
		parts := strings.Fields(hint.Type)
		if len(parts) > 0 {
			typeMap[parts[0]] = hint.Type
		}
	}
}

func TestCodeAnalyzer_analyzeDocstrings(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	code := `
def function():
    """This is a single line docstring."""
    pass

def another_function():
    """
    This is a multi-line docstring.
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        Description of return value
    """
    pass

class MyClass:
    '''Class docstring with single quotes.'''
    pass
`
	
	docstrings := analyzer.analyzeDocstrings(code)
	
	if len(docstrings) == 0 {
		t.Error("Should detect docstrings")
	}
	
	// Check that we found docstrings
	for _, docstring := range docstrings {
		if docstring.Content == "" {
			t.Error("Docstring content should not be empty")
		}
		if docstring.LineNumber == 0 {
			t.Error("Docstring should have line number")
		}
	}
}

func TestCodeAnalyzer_detectDocstringStyle(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	tests := []struct {
		content  string
		expected DocstringStyle
	}{
		{
			content: `
Args:
    param1: Description
Returns:
    Value description
`,
			expected: DocstringStyleGoogle,
		},
		{
			content: `
Parameters
----------
param1 : str
    Description

Returns
-------
str
    Description
`,
			expected: DocstringStyleNumPy,
		},
		{
			content: `
:param param1: Description
:return: Return description
`,
			expected: DocstringStyleSphinx,
		},
		{
			content: "Just a simple description",
			expected: DocstringStyleUnknown,
		},
	}
	
	for _, tt := range tests {
		result := analyzer.detectDocstringStyle(tt.content)
		if result != tt.expected {
			t.Errorf("Expected %s, got %s for content: %s", tt.expected, result, tt.content)
		}
	}
}

func TestCodeAnalyzer_Analyze(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	code := `
import requests
import os

def fetch_data(url: str) -> dict:
    """Fetch data from URL.
    
    Args:
        url: The URL to fetch data from
        
    Returns:
        dict: The response data
    """
    response = requests.get(url)
    return response.json()

class DataProcessor:
    """Process data from various sources."""
    
    def __init__(self):
        self.data = []
    
    def process(self, data):
        # Simple processing
        processed = []
        for item in data:
            if item:
                processed.append(item.upper())
        return processed
`
	
	req := &AnalysisRequest{
		Code:     code,
		Filename: "test.py",
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	result, err := analyzer.Analyze(ctx, req)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}
	
	if !result.Success {
		t.Error("Analysis should be successful")
	}
	
	if !result.SyntaxValid {
		t.Error("Code should be syntactically valid")
	}
	
	if len(result.Imports) == 0 {
		t.Error("Should detect imports")
	}
	
	if len(result.Functions) == 0 {
		t.Error("Should detect functions")
	}
	
	if len(result.Classes) == 0 {
		t.Error("Should detect classes")
	}
	
	if len(result.Dependencies) == 0 {
		t.Error("Should detect dependencies")
	}
	
	// Check specific imports
	importFound := false
	for _, imp := range result.Imports {
		if imp.Module == "requests" {
			importFound = true
			break
		}
	}
	if !importFound {
		t.Error("Should detect requests import")
	}
	
	// Check specific functions
	functionFound := false
	for _, fn := range result.Functions {
		if fn.Name == "fetch_data" {
			functionFound = true
			if fn.ReturnType != "dict" {
				t.Errorf("Expected return type 'dict', got '%s'", fn.ReturnType)
			}
			break
		}
	}
	if !functionFound {
		t.Error("Should detect fetch_data function")
	}
	
	// Check specific classes
	classFound := false
	for _, cls := range result.Classes {
		if cls.Name == "DataProcessor" {
			classFound = true
			break
		}
	}
	if !classFound {
		t.Error("Should detect DataProcessor class")
	}
	
	if result.Duration == 0 {
		t.Error("Duration should be recorded")
	}
}

func TestCodeAnalyzer_generateWarnings(t *testing.T) {
	config := &AnalysisConfig{
		RequiredDocstrings: true,
		MaxComplexity:     5,
	}
	analyzer := NewCodeAnalyzer(config)
	
	result := &AnalysisResult{
		Functions: []*FunctionInfo{
			{
				Name:       "function_without_docstring",
				LineNumber: 1,
				Docstring:  "",
				Complexity: 3,
			},
			{
				Name:       "complex_function",
				LineNumber: 10,
				Docstring:  "Has docstring",
				Complexity: 8,
			},
		},
	}
	
	warnings := analyzer.generateWarnings(result)
	
	if len(warnings) == 0 {
		t.Error("Should generate warnings")
	}
	
	// Check for missing docstring warning
	foundDocstringWarning := false
	foundComplexityWarning := false
	
	for _, warning := range warnings {
		if warning.Type == WarningTypeMissingDocstring {
			foundDocstringWarning = true
		}
		if warning.Type == WarningTypeComplexity {
			foundComplexityWarning = true
		}
	}
	
	if !foundDocstringWarning {
		t.Error("Should generate missing docstring warning")
	}
	
	if !foundComplexityWarning {
		t.Error("Should generate complexity warning")
	}
}

func TestCodeAnalyzer_parseDecorators(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	tests := []struct {
		decoratorStr string
		expected     []string
	}{
		{"@decorator", []string{"decorator"}},
		{"@decorator1 @decorator2", []string{"decorator1", "decorator2"}},
		{"@classmethod", []string{"classmethod"}},
		{"", []string{}},
	}
	
	for _, tt := range tests {
		result := analyzer.parseDecorators(tt.decoratorStr)
		
		if len(result) != len(tt.expected) {
			t.Errorf("Expected %d decorators, got %d", len(tt.expected), len(result))
			continue
		}
		
		for i, expected := range tt.expected {
			if result[i] != expected {
				t.Errorf("Expected decorator %s, got %s", expected, result[i])
			}
		}
	}
}

func TestCodeAnalyzer_parseParameters(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	
	tests := []struct {
		paramStr string
		expected []*ParameterInfo
	}{
		{
			paramStr: "self",
			expected: []*ParameterInfo{
				{Name: "self", IsRequired: true},
			},
		},
		{
			paramStr: "arg1, arg2=default",
			expected: []*ParameterInfo{
				{Name: "arg1", IsRequired: true},
				{Name: "arg2", DefaultValue: "default", IsRequired: false},
			},
		},
		{
			paramStr: "*args, **kwargs",
			expected: []*ParameterInfo{
				{Name: "args", IsVarArgs: true, IsRequired: true},
				{Name: "kwargs", IsKwArgs: true, IsRequired: true},
			},
		},
		{
			paramStr: "param: int",
			expected: []*ParameterInfo{
				{Name: "param", Type: "int", IsRequired: true},
			},
		},
	}
	
	for _, tt := range tests {
		result := analyzer.parseParameters(tt.paramStr)
		
		if len(result) != len(tt.expected) {
			t.Errorf("Expected %d parameters, got %d for input: %s", len(tt.expected), len(result), tt.paramStr)
			continue
		}
		
		for i, expected := range tt.expected {
			if result[i].Name != expected.Name {
				t.Errorf("Expected parameter name %s, got %s", expected.Name, result[i].Name)
			}
			if result[i].Type != expected.Type {
				t.Errorf("Expected parameter type %s, got %s", expected.Type, result[i].Type)
			}
			if result[i].DefaultValue != expected.DefaultValue {
				t.Errorf("Expected default value %s, got %s", expected.DefaultValue, result[i].DefaultValue)
			}
			if result[i].IsRequired != expected.IsRequired {
				t.Errorf("Expected IsRequired %v, got %v", expected.IsRequired, result[i].IsRequired)
			}
			if result[i].IsVarArgs != expected.IsVarArgs {
				t.Errorf("Expected IsVarArgs %v, got %v", expected.IsVarArgs, result[i].IsVarArgs)
			}
			if result[i].IsKwArgs != expected.IsKwArgs {
				t.Errorf("Expected IsKwArgs %v, got %v", expected.IsKwArgs, result[i].IsKwArgs)
			}
		}
	}
}

// Benchmark tests

func BenchmarkCodeAnalyzer_parseImports(b *testing.B) {
	analyzer := NewCodeAnalyzer(nil)
	code := `
import os
import sys
import json
from datetime import datetime
from requests import get
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from sklearn.linear_model import LinearRegression
import matplotlib.pyplot as plt
`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = analyzer.parseImports(code)
	}
}

func BenchmarkCodeAnalyzer_parseFunctions(b *testing.B) {
	analyzer := NewCodeAnalyzer(nil)
	code := `
def function1():
    pass

def function2(arg1, arg2="default"):
    return arg1 + arg2

@decorator
def function3():
    """Docstring"""
    pass

async def function4():
    await something()

class MyClass:
    def method1(self):
        pass
    
    @classmethod
    def method2(cls):
        pass
`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.parseFunctions(code)
	}
}

func BenchmarkCodeAnalyzer_validateSyntax(b *testing.B) {
	analyzer := NewCodeAnalyzer(nil)
	code := `
def hello_world():
    print("Hello, World!")
    for i in range(10):
        if i % 2 == 0:
            print(f"Even: {i}")
        else:
            print(f"Odd: {i}")
    return True

class Calculator:
    def __init__(self):
        self.value = 0
    
    def add(self, x):
        self.value += x
        return self
    
    def multiply(self, x):
        self.value *= x
        return self
`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.validateSyntax(code)
	}
}

func BenchmarkCodeAnalyzer_Analyze(b *testing.B) {
	analyzer := NewCodeAnalyzer(nil)
	code := `
import requests
import json
from typing import Dict, List, Optional

def fetch_user_data(user_id: int) -> Optional[Dict]:
    """Fetch user data from API.
    
    Args:
        user_id: The ID of the user to fetch
        
    Returns:
        User data dictionary or None if not found
    """
    url = f"https://api.example.com/users/{user_id}"
    response = requests.get(url)
    
    if response.status_code == 200:
        return response.json()
    return None

class UserManager:
    """Manage user operations."""
    
    def __init__(self):
        self.users: List[Dict] = []
    
    def add_user(self, user_data: Dict) -> bool:
        """Add a user to the manager."""
        if self.validate_user(user_data):
            self.users.append(user_data)
            return True
        return False
    
    def validate_user(self, user_data: Dict) -> bool:
        """Validate user data."""
        required_fields = ['id', 'name', 'email']
        return all(field in user_data for field in required_fields)
`
	
	req := &AnalysisRequest{
		Code:     code,
		Filename: "test.py",
	}
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := analyzer.Analyze(ctx, req)
		if err != nil {
			b.Fatalf("Analysis failed: %v", err)
		}
	}
}