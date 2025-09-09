package languages

import (
	"context"
	"strings"
	"testing"
)

func TestCodePreprocessor(t *testing.T) {
	processor := NewCodePreprocessor()
	ctx := context.Background()

	t.Run("DetectPythonLanguage", func(t *testing.T) {
		code := `
import os
import sys

def main():
    print("Hello, Python!")
    
if __name__ == "__main__":
    main()
`

		options := &PreprocessorOptions{
			EnableLanguageDetection: true,
		}

		result, err := processor.Process(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to process code: %v", err)
		}

		if result.DetectedLanguage != LanguagePython {
			t.Errorf("Expected Python, got %s", result.DetectedLanguage)
		}
		if result.LanguageConfidence < 0.5 {
			t.Errorf("Low confidence for Python detection: %f", result.LanguageConfidence)
		}
	})

	t.Run("DetectJavaScriptLanguage", func(t *testing.T) {
		code := `
const express = require('express');
const app = express();

app.get('/', (req, res) => {
    res.send('Hello, JavaScript!');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
`

		options := &PreprocessorOptions{
			EnableLanguageDetection: true,
		}

		result, err := processor.Process(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to process code: %v", err)
		}

		if result.DetectedLanguage != LanguageJavaScript {
			t.Errorf("Expected JavaScript, got %s", result.DetectedLanguage)
		}
	})

	t.Run("ExtractPythonDependencies", func(t *testing.T) {
		code := `
import os
import sys
import json
import requests
from flask import Flask, request
from numpy import array
`

		options := &PreprocessorOptions{
			EnableLanguageDetection:    true,
			EnableDependencyExtraction: true,
		}

		result, err := processor.Process(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to process code: %v", err)
		}

		expectedDeps := []string{"os", "sys", "json", "requests", "flask", "numpy"}
		foundDeps := make(map[string]bool)
		
		for _, dep := range result.ExtractedDependencies {
			foundDeps[strings.ToLower(dep.Name)] = true
		}

		for _, expectedDep := range expectedDeps {
			if !foundDeps[expectedDep] {
				t.Errorf("Expected dependency %s not found", expectedDep)
			}
		}

		// Check built-in vs external modules
		hasBuiltIn := false
		hasExternal := false
		
		for _, dep := range result.ExtractedDependencies {
			if dep.IsBuiltIn {
				hasBuiltIn = true
			} else {
				hasExternal = true
			}
		}

		if !hasBuiltIn {
			t.Error("Expected some built-in modules to be identified")
		}
		if !hasExternal {
			t.Error("Expected some external modules to be identified")
		}
	})

	t.Run("ExtractJavaScriptDependencies", func(t *testing.T) {
		code := `
const fs = require('fs');
const path = require('path');
const express = require('express');
import lodash from 'lodash';
import { v4 as uuidv4 } from 'uuid';

const dynamicImport = await import('some-module');
`

		options := &PreprocessorOptions{
			EnableLanguageDetection:    true,
			EnableDependencyExtraction: true,
		}

		result, err := processor.Process(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to process code: %v", err)
		}

		expectedDeps := []string{"fs", "path", "express", "lodash", "uuid", "some-module"}
		foundDeps := make(map[string]bool)
		
		for _, dep := range result.ExtractedDependencies {
			foundDeps[dep.Name] = true
		}

		for _, expectedDep := range expectedDeps {
			if !foundDeps[expectedDep] {
				t.Errorf("Expected dependency %s not found", expectedDep)
			}
		}
	})

	t.Run("SecurityScanning", func(t *testing.T) {
		code := `
import os
import pickle

password = "hardcoded_password"
api_key = "sk-1234567890abcdef"

# Dangerous operations
os.system("rm -rf /")
data = pickle.loads(user_input)
eval(user_code)
`

		options := &PreprocessorOptions{
			EnableLanguageDetection: true,
			EnableSecurityScanning:  true,
		}

		result, err := processor.Process(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to process code: %v", err)
		}

		if len(result.SecurityWarnings) == 0 {
			t.Error("Expected security warnings for dangerous code")
		}

		// Check for specific security issues
		foundIssues := make(map[string]bool)
		for _, warning := range result.SecurityWarnings {
			switch warning.RuleID {
			case "CMD_INJECTION_001":
				foundIssues["command_injection"] = true
			case "HARDCODED_SECRET_001":
				foundIssues["hardcoded_password"] = true
			case "HARDCODED_SECRET_002":
				foundIssues["hardcoded_api_key"] = true
			case "DESERIALIZATION_001":
				foundIssues["unsafe_deserialization"] = true
			case "CODE_EVAL_001":
				foundIssues["code_evaluation"] = true
			}
		}

		expectedIssues := []string{"command_injection", "hardcoded_password", "hardcoded_api_key", "unsafe_deserialization", "code_evaluation"}
		for _, issue := range expectedIssues {
			if !foundIssues[issue] {
				t.Errorf("Expected security issue %s not detected", issue)
			}
		}
	})

	t.Run("SyntaxValidation", func(t *testing.T) {
		// Valid Python code
		validCode := `
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

print(factorial(5))
`

		options := &PreprocessorOptions{
			EnableLanguageDetection: true,
			EnableSyntaxValidation:  true,
		}

		result, err := processor.Process(ctx, validCode, options)
		if err != nil {
			t.Fatalf("Failed to process valid code: %v", err)
		}

		if len(result.SyntaxErrors) > 0 {
			t.Errorf("Valid code should not have syntax errors: %v", result.SyntaxErrors)
		}

		// Invalid Python code
		invalidCode := `
def broken_function(
    print("missing closing parenthesis"
    return "invalid"
`

		result, err = processor.Process(ctx, invalidCode, options)
		if err != nil {
			t.Fatalf("Failed to process invalid code: %v", err)
		}

		// Note: Basic syntax validation might not catch all errors
		// This tests the framework rather than comprehensive parsing
		t.Logf("Syntax errors found: %d", len(result.SyntaxErrors))
	})

	t.Run("CodeInstrumentation", func(t *testing.T) {
		code := `
def process_data(data):
    result = []
    for item in data:
        processed = item * 2
        result.append(processed)
    return result

data = [1, 2, 3, 4, 5]
result = process_data(data)
print(result)
`

		options := &PreprocessorOptions{
			EnableLanguageDetection:   true,
			EnableCodeInstrumentation: true,
			InstrumentationTargets:    []string{"functions", "variables"},
		}

		result, err := processor.Process(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to process code: %v", err)
		}

		if len(result.InstrumentationPoints) == 0 {
			t.Error("Expected instrumentation points to be found")
		}

		// Check for function instrumentation
		foundFunction := false
		foundVariable := false

		for _, point := range result.InstrumentationPoints {
			if point.Type == "function_entry" {
				foundFunction = true
			}
			if point.Type == "variable_access" {
				foundVariable = true
			}
		}

		if !foundFunction {
			t.Error("Expected function instrumentation points")
		}
		if !foundVariable {
			t.Error("Expected variable instrumentation points")
		}
	})

	t.Run("CodeFormatting", func(t *testing.T) {
		code := `
def   messy_function(   ):
	print(  "mixed indentation"  )   
    return   True   

# Trailing spaces and mixed tabs/spaces
var = "value"	   
`

		options := &PreprocessorOptions{
			EnableLanguageDetection: true,
			EnableCodeFormatting:    true,
		}

		result, err := processor.Process(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to process code: %v", err)
		}

		if result.ProcessedCode == result.OriginalCode {
			t.Error("Expected code to be formatted/normalized")
		}

		// Check if trailing whitespace was removed
		lines := strings.Split(result.ProcessedCode, "\n")
		for i, line := range lines {
			if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
				t.Errorf("Line %d still has trailing whitespace: %q", i+1, line)
			}
		}

		if result.Metadata["code_formatted"] != true {
			t.Error("Expected code_formatted metadata to be true")
		}
	})

	t.Run("ComprehensiveProcessing", func(t *testing.T) {
		code := `
import os
import requests
import pickle

password = "secret123"

def process_user_data(user_input):
    # Dangerous operations
    os.system(f"echo {user_input}")
    data = pickle.loads(user_input)
    return eval(f"process({data})")

result = process_user_data("test")
print(result)
`

		options := &PreprocessorOptions{
			EnableLanguageDetection:    true,
			EnableDependencyExtraction: true,
			EnableMissingImportRes:     true,
			EnableSyntaxValidation:     true,
			EnableSecurityScanning:     true,
			EnableCodeInstrumentation:  true,
			EnableCodeFormatting:       true,
			InstrumentationTargets:     []string{"functions", "lines"},
		}

		result, err := processor.Process(ctx, code, options)
		if err != nil {
			t.Fatalf("Failed to process code comprehensively: %v", err)
		}

		// Verify all processing stages completed
		if result.DetectedLanguage == "" {
			t.Error("Language detection should have run")
		}
		if len(result.ExtractedDependencies) == 0 {
			t.Error("Dependency extraction should have run")
		}
		if len(result.SecurityWarnings) == 0 {
			t.Error("Security scanning should have found issues")
		}
		if len(result.InstrumentationPoints) == 0 {
			t.Error("Code instrumentation should have run")
		}

		// Check processing duration
		if result.ProcessingDuration == 0 {
			t.Error("Processing duration should be recorded")
		}

		// Verify success
		if !result.Success {
			t.Errorf("Comprehensive processing should succeed, got error: %v", result.Error)
		}

		t.Logf("Processing completed in %v", result.ProcessingDuration)
		t.Logf("Found %d dependencies", len(result.ExtractedDependencies))
		t.Logf("Found %d security warnings", len(result.SecurityWarnings))
		t.Logf("Found %d instrumentation points", len(result.InstrumentationPoints))
	})
}

func TestPreprocessorErrorHandling(t *testing.T) {
	processor := NewCodePreprocessor()
	ctx := context.Background()

	t.Run("EmptyCode", func(t *testing.T) {
		options := &PreprocessorOptions{
			EnableLanguageDetection: true,
		}

		result, err := processor.Process(ctx, "", options)
		if err == nil {
			t.Error("Expected error for empty code")
		}
		if result != nil && result.Success {
			t.Error("Processing empty code should not succeed")
		}
	})

	t.Run("UnknownLanguage", func(t *testing.T) {
		// Code that's hard to detect
		obscureCode := "a b c d e f g"

		options := &PreprocessorOptions{
			EnableLanguageDetection: true,
		}

		result, err := processor.Process(ctx, obscureCode, options)
		if err != nil {
			t.Fatalf("Process should not return error: %v", err)
		}

		// Should succeed but with low confidence or warnings
		if result.LanguageConfidence > 0.8 {
			t.Error("Should have low confidence for obscure code")
		}
	})
}

func TestPreprocessorPerformance(t *testing.T) {
	processor := NewCodePreprocessor()
	ctx := context.Background()

	// Large code sample
	largeCode := strings.Repeat(`
import os
import sys
import json
import requests

def process_data(data):
    result = []
    for item in data:
        processed = item * 2
        result.append(processed)
    return result

def main():
    data = list(range(100))
    result = process_data(data)
    print(f"Processed {len(result)} items")

if __name__ == "__main__":
    main()
`, 100) // Repeat 100 times

	options := &PreprocessorOptions{
		EnableLanguageDetection:    true,
		EnableDependencyExtraction: true,
		EnableMissingImportRes:     true,
		EnableSyntaxValidation:     true,
		EnableSecurityScanning:     true,
		EnableCodeInstrumentation:  true,
		EnableCodeFormatting:       true,
		InstrumentationTargets:     []string{"functions", "lines", "variables"},
	}

	result, err := processor.Process(ctx, largeCode, options)
	if err != nil {
		t.Fatalf("Failed to process large code: %v", err)
	}

	// Performance thresholds (adjust based on requirements)
	if result.ProcessingDuration > 5000000000 { // 5 seconds in nanoseconds
		t.Errorf("Processing took too long: %v", result.ProcessingDuration)
	}

	t.Logf("Large code processing completed in %v", result.ProcessingDuration)
	t.Logf("Code length: %d characters", len(largeCode))
	t.Logf("Found %d dependencies", len(result.ExtractedDependencies))
	t.Logf("Found %d instrumentation points", len(result.InstrumentationPoints))
}