package python

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// CodeAnalyzer performs comprehensive Python code analysis
type CodeAnalyzer struct {
	config         *AnalysisConfig
	securityScanner *SecurityScanner
	complexityCalculator *ComplexityCalculator
}

// AnalysisConfig configures code analysis behavior
type AnalysisConfig struct {
	EnableSyntaxValidation   bool     `json:"enable_syntax_validation"`
	EnableSecurityScanning   bool     `json:"enable_security_scanning"`
	EnableComplexityAnalysis bool     `json:"enable_complexity_analysis"`
	EnableTypeHintAnalysis   bool     `json:"enable_type_hint_analysis"`
	EnableDocstringAnalysis  bool     `json:"enable_docstring_analysis"`
	IgnoredPatterns         []string `json:"ignored_patterns"`
	MaxComplexity           int      `json:"max_complexity"`
	RequiredDocstrings      bool     `json:"required_docstrings"`
}

// NewCodeAnalyzer creates a new Python code analyzer
func NewCodeAnalyzer(config *AnalysisConfig) *CodeAnalyzer {
	if config == nil {
		config = &AnalysisConfig{
			EnableSyntaxValidation:   true,
			EnableSecurityScanning:   true,
			EnableComplexityAnalysis: true,
			EnableTypeHintAnalysis:   true,
			EnableDocstringAnalysis:  true,
			MaxComplexity:           10,
			RequiredDocstrings:      false,
		}
	}
	
	return &CodeAnalyzer{
		config:                  config,
		securityScanner:         NewSecurityScanner(),
		complexityCalculator:    NewComplexityCalculator(),
	}
}

// AnalysisRequest contains parameters for code analysis
type AnalysisRequest struct {
	Code        string            `json:"code"`
	Filename    string            `json:"filename"`
	Environment map[string]string `json:"environment"`
	Options     map[string]string `json:"options"`
}

// AnalysisResult contains the results of code analysis
type AnalysisResult struct {
	Success         bool                   `json:"success"`
	SyntaxValid     bool                   `json:"syntax_valid"`
	Imports         []*ImportStatement     `json:"imports"`
	Dependencies    []string               `json:"dependencies"`
	Functions       []*FunctionInfo        `json:"functions"`
	Classes         []*ClassInfo           `json:"classes"`
	Variables       []*VariableInfo        `json:"variables"`
	TypeHints       []*TypeHintInfo        `json:"type_hints"`
	Docstrings      []*DocstringInfo       `json:"docstrings"`
	SecurityIssues  []*SecurityIssue       `json:"security_issues"`
	ComplexityMetrics *ComplexityMetrics   `json:"complexity_metrics"`
	SyntaxErrors    []*SyntaxError         `json:"syntax_errors"`
	Warnings        []*AnalysisWarning     `json:"warnings"`
	Metadata        map[string]interface{} `json:"metadata"`
	Duration        time.Duration          `json:"duration"`
}

// ImportStatement represents a Python import statement
type ImportStatement struct {
	Type        ImportType `json:"type"`
	Module      string     `json:"module"`
	Alias       string     `json:"alias"`
	Items       []string   `json:"items"`
	Level       int        `json:"level"` // For relative imports
	LineNumber  int        `json:"line_number"`
	IsStandard  bool       `json:"is_standard"`
	IsThirdParty bool      `json:"is_third_party"`
	IsLocal     bool       `json:"is_local"`
}

// ImportType represents the type of import statement
type ImportType string

const (
	ImportTypeImport     ImportType = "import"
	ImportTypeFromImport ImportType = "from_import"
)

// FunctionInfo contains information about a function
type FunctionInfo struct {
	Name         string                 `json:"name"`
	LineNumber   int                    `json:"line_number"`
	EndLine      int                    `json:"end_line"`
	Parameters   []*ParameterInfo       `json:"parameters"`
	ReturnType   string                 `json:"return_type"`
	Decorators   []string               `json:"decorators"`
	Docstring    string                 `json:"docstring"`
	IsAsync      bool                   `json:"is_async"`
	IsMethod     bool                   `json:"is_method"`
	IsClassMethod bool                  `json:"is_class_method"`
	IsStaticMethod bool                 `json:"is_static_method"`
	Complexity   int                    `json:"complexity"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ParameterInfo contains information about function parameters
type ParameterInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	DefaultValue string `json:"default_value"`
	IsRequired   bool   `json:"is_required"`
	IsVarArgs    bool   `json:"is_var_args"`
	IsKwArgs     bool   `json:"is_kw_args"`
}

// ClassInfo contains information about a class
type ClassInfo struct {
	Name         string                 `json:"name"`
	LineNumber   int                    `json:"line_number"`
	EndLine      int                    `json:"end_line"`
	BaseClasses  []string               `json:"base_classes"`
	Methods      []*FunctionInfo        `json:"methods"`
	Properties   []*PropertyInfo        `json:"properties"`
	Decorators   []string               `json:"decorators"`
	Docstring    string                 `json:"docstring"`
	IsAbstract   bool                   `json:"is_abstract"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// PropertyInfo contains information about class properties
type PropertyInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	LineNumber int    `json:"line_number"`
	HasGetter  bool   `json:"has_getter"`
	HasSetter  bool   `json:"has_setter"`
	HasDeleter bool   `json:"has_deleter"`
}

// VariableInfo contains information about variables
type VariableInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Value      string `json:"value"`
	LineNumber int    `json:"line_number"`
	Scope      string `json:"scope"`
	IsGlobal   bool   `json:"is_global"`
	IsConstant bool   `json:"is_constant"`
}

// TypeHintInfo contains information about type hints
type TypeHintInfo struct {
	Location   string `json:"location"`
	Type       string `json:"type"`
	LineNumber int    `json:"line_number"`
	IsValid    bool   `json:"is_valid"`
	Error      string `json:"error,omitempty"`
}

// DocstringInfo contains information about docstrings
type DocstringInfo struct {
	Location     string                 `json:"location"`
	Content      string                 `json:"content"`
	Style        DocstringStyle         `json:"style"`
	LineNumber   int                    `json:"line_number"`
	IsComplete   bool                   `json:"is_complete"`
	MissingParts []string               `json:"missing_parts"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// DocstringStyle represents the docstring style
type DocstringStyle string

const (
	DocstringStyleGoogle   DocstringStyle = "google"
	DocstringStyleNumPy    DocstringStyle = "numpy"
	DocstringStyleSphinx   DocstringStyle = "sphinx"
	DocstringStyleEpytext  DocstringStyle = "epytext"
	DocstringStyleUnknown  DocstringStyle = "unknown"
)

// SecurityIssue represents a security vulnerability
type SecurityIssue struct {
	Type        SecurityIssueType `json:"type"`
	Severity    SeverityLevel     `json:"severity"`
	Message     string            `json:"message"`
	LineNumber  int               `json:"line_number"`
	Column      int               `json:"column"`
	Rule        string            `json:"rule"`
	Suggestion  string            `json:"suggestion"`
	CWE         string            `json:"cwe,omitempty"`
}

// SecurityIssueType represents the type of security issue
type SecurityIssueType string

const (
	SecurityIssueTypeInjection       SecurityIssueType = "injection"
	SecurityIssueTypeHardcodedSecret SecurityIssueType = "hardcoded_secret"
	SecurityIssueTypeInsecureRandom  SecurityIssueType = "insecure_random"
	SecurityIssueTypePathTraversal   SecurityIssueType = "path_traversal"
	SecurityIssueTypeXSS             SecurityIssueType = "xss"
	SecurityIssueTypeDeserialization SecurityIssueType = "deserialization"
	SecurityIssueTypeDangerous       SecurityIssueType = "dangerous_function"
)

// SeverityLevel represents the severity of an issue
type SeverityLevel string

const (
	SeverityLevelInfo     SeverityLevel = "info"
	SeverityLevelLow      SeverityLevel = "low"
	SeverityLevelMedium   SeverityLevel = "medium"
	SeverityLevelHigh     SeverityLevel = "high"
	SeverityLevelCritical SeverityLevel = "critical"
)

// ComplexityMetrics contains code complexity metrics
type ComplexityMetrics struct {
	CyclomaticComplexity int                    `json:"cyclomatic_complexity"`
	LinesOfCode          int                    `json:"lines_of_code"`
	PhysicalLines        int                    `json:"physical_lines"`
	LogicalLines         int                    `json:"logical_lines"`
	CommentLines         int                    `json:"comment_lines"`
	BlankLines           int                    `json:"blank_lines"`
	FunctionCount        int                    `json:"function_count"`
	ClassCount           int                    `json:"class_count"`
	MethodCount          int                    `json:"method_count"`
	Maintainability      float64                `json:"maintainability"`
	TechnicalDebt        time.Duration          `json:"technical_debt"`
	Metadata             map[string]interface{} `json:"metadata"`
}

// SyntaxError represents a Python syntax error
type SyntaxError struct {
	Message    string `json:"message"`
	LineNumber int    `json:"line_number"`
	Column     int    `json:"column"`
	Text       string `json:"text"`
}

// AnalysisWarning represents an analysis warning
type AnalysisWarning struct {
	Type       WarningType `json:"type"`
	Message    string      `json:"message"`
	LineNumber int         `json:"line_number"`
	Suggestion string      `json:"suggestion"`
}

// WarningType represents the type of warning
type WarningType string

const (
	WarningTypeUnusedImport    WarningType = "unused_import"
	WarningTypeUnusedVariable  WarningType = "unused_variable"
	WarningTypeMissingDocstring WarningType = "missing_docstring"
	WarningTypeComplexity     WarningType = "complexity"
	WarningTypeDeprecated     WarningType = "deprecated"
)

// Analyze performs comprehensive analysis of Python code
func (ca *CodeAnalyzer) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResult, error) {
	startTime := time.Now()
	
	result := &AnalysisResult{
		Metadata: make(map[string]interface{}),
	}
	
	// Validate syntax first
	if ca.config.EnableSyntaxValidation {
		syntaxErrors := ca.validateSyntax(req.Code)
		result.SyntaxErrors = syntaxErrors
		result.SyntaxValid = len(syntaxErrors) == 0
		
		if !result.SyntaxValid {
			result.Duration = time.Since(startTime)
			return result, nil
		}
	}
	
	// Parse imports
	imports, deps := ca.parseImports(req.Code)
	result.Imports = imports
	result.Dependencies = deps
	
	// Analyze functions and classes
	result.Functions = ca.parseFunctions(req.Code)
	result.Classes = ca.parseClasses(req.Code)
	result.Variables = ca.parseVariables(req.Code)
	
	// Analyze type hints
	if ca.config.EnableTypeHintAnalysis {
		result.TypeHints = ca.analyzeTypeHints(req.Code)
	}
	
	// Analyze docstrings
	if ca.config.EnableDocstringAnalysis {
		result.Docstrings = ca.analyzeDocstrings(req.Code)
	}
	
	// Security scanning
	if ca.config.EnableSecurityScanning {
		result.SecurityIssues = ca.securityScanner.Scan(req.Code)
	}
	
	// Complexity analysis
	if ca.config.EnableComplexityAnalysis {
		result.ComplexityMetrics = ca.complexityCalculator.Calculate(req.Code)
	}
	
	// Generate warnings
	result.Warnings = ca.generateWarnings(result)
	
	result.Success = true
	result.Duration = time.Since(startTime)
	
	return result, nil
}

// validateSyntax validates Python syntax using a simple parser
func (ca *CodeAnalyzer) validateSyntax(code string) []*SyntaxError {
	var errors []*SyntaxError
	
	lines := strings.Split(code, "\n")
	
	// Simple syntax validation - check for basic issues
	indentStack := []int{0}
	
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		
		// Check indentation
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		
		// Validate indentation consistency
		if strings.HasSuffix(trimmed, ":") {
			// Start of new block
			indentStack = append(indentStack, indent)
		} else {
			// Check if indentation matches any level in stack
			validIndent := false
			for _, stackIndent := range indentStack {
				if indent == stackIndent {
					validIndent = true
					break
				}
			}
			
			if !validIndent && indent > 0 {
				errors = append(errors, &SyntaxError{
					Message:    "IndentationError: unexpected indent",
					LineNumber: lineNum + 1,
					Column:     1,
					Text:       line,
				})
			}
		}
		
		// Check for basic syntax patterns
		if err := ca.checkBasicSyntax(trimmed, lineNum+1); err != nil {
			errors = append(errors, err)
		}
	}
	
	return errors
}

// checkBasicSyntax performs basic syntax checks
func (ca *CodeAnalyzer) checkBasicSyntax(line string, lineNum int) *SyntaxError {
	// Check for unmatched parentheses, brackets, braces
	parens := 0
	brackets := 0
	braces := 0
	inString := false
	stringChar := byte(0)
	
	for i, char := range []byte(line) {
		switch char {
		case '"', '\'':
			if !inString {
				inString = true
				stringChar = char
			} else if char == stringChar {
				inString = false
			}
		case '(':
			if !inString {
				parens++
			}
		case ')':
			if !inString {
				parens--
				if parens < 0 {
					return &SyntaxError{
						Message:    "SyntaxError: unmatched ')'",
						LineNumber: lineNum,
						Column:     i + 1,
						Text:       line,
					}
				}
			}
		case '[':
			if !inString {
				brackets++
			}
		case ']':
			if !inString {
				brackets--
				if brackets < 0 {
					return &SyntaxError{
						Message:    "SyntaxError: unmatched ']'",
						LineNumber: lineNum,
						Column:     i + 1,
						Text:       line,
					}
				}
			}
		case '{':
			if !inString {
				braces++
			}
		case '}':
			if !inString {
				braces--
				if braces < 0 {
					return &SyntaxError{
						Message:    "SyntaxError: unmatched '}'",
						LineNumber: lineNum,
						Column:     i + 1,
						Text:       line,
					}
				}
			}
		}
	}
	
	return nil
}

// parseImports extracts import statements from Python code
func (ca *CodeAnalyzer) parseImports(code string) ([]*ImportStatement, []string) {
	var imports []*ImportStatement
	var dependencies []string
	
	lines := strings.Split(code, "\n")
	
	// Standard library modules (partial list)
	standardModules := map[string]bool{
		"os": true, "sys": true, "re": true, "json": true, "time": true,
		"datetime": true, "collections": true, "itertools": true, "functools": true,
		"pathlib": true, "urllib": true, "http": true, "logging": true,
		"unittest": true, "pytest": true, "math": true, "random": true,
		"string": true, "io": true, "contextlib": true, "threading": true,
		"multiprocessing": true, "subprocess": true, "socket": true, "ssl": true,
	}
	
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Match import statements
		if importStmt := ca.parseImportStatement(trimmed, lineNum+1, standardModules); importStmt != nil {
			imports = append(imports, importStmt)
			
			// Add to dependencies if not standard library
			if !importStmt.IsStandard {
				dependencies = append(dependencies, importStmt.Module)
			}
		}
	}
	
	// Remove duplicates from dependencies
	dependencies = ca.removeDuplicates(dependencies)
	
	return imports, dependencies
}

// parseImportStatement parses a single import statement
func (ca *CodeAnalyzer) parseImportStatement(line string, lineNum int, standardModules map[string]bool) *ImportStatement {
	// Match "import module" or "import module as alias"
	importRegex := regexp.MustCompile(`^import\s+([a-zA-Z_][a-zA-Z0-9_.]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_.]*)*)(?:\s+as\s+([a-zA-Z_][a-zA-Z0-9_]*))?`)
	
	// Match "from module import item" or "from module import item as alias"
	fromImportRegex := regexp.MustCompile(`^from\s+(\.*)([a-zA-Z_][a-zA-Z0-9_.]*)\s+import\s+(.+)`)
	
	if matches := fromImportRegex.FindStringSubmatch(line); matches != nil {
		level := len(matches[1]) // Number of dots for relative imports
		module := matches[2]
		items := strings.Split(matches[3], ",")
		
		// Clean up items
		for i, item := range items {
			items[i] = strings.TrimSpace(item)
		}
		
		return &ImportStatement{
			Type:         ImportTypeFromImport,
			Module:       module,
			Items:        items,
			Level:        level,
			LineNumber:   lineNum,
			IsStandard:   standardModules[module],
			IsThirdParty: !standardModules[module] && level == 0,
			IsLocal:      level > 0,
		}
	}
	
	if matches := importRegex.FindStringSubmatch(line); matches != nil {
		modules := strings.Split(matches[1], ",")
		module := strings.TrimSpace(modules[0])
		alias := matches[2]
		
		return &ImportStatement{
			Type:         ImportTypeImport,
			Module:       module,
			Alias:        alias,
			LineNumber:   lineNum,
			IsStandard:   standardModules[module],
			IsThirdParty: !standardModules[module],
			IsLocal:      false,
		}
	}
	
	return nil
}

// parseFunctions extracts function definitions from Python code
func (ca *CodeAnalyzer) parseFunctions(code string) []*FunctionInfo {
	var functions []*FunctionInfo
	
	lines := strings.Split(code, "\n")
	
	funcRegex := regexp.MustCompile(`^(\s*)((?:@\w+\s+)*)(async\s+)?def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)(?:\s*->\s*([^:]+))?:`)
	
	for lineNum, line := range lines {
		if matches := funcRegex.FindStringSubmatch(line); matches != nil {
			indent := matches[1]
			decorators := ca.parseDecorators(matches[2])
			isAsync := matches[3] != ""
			name := matches[4]
			params := ca.parseParameters(matches[5])
			returnType := strings.TrimSpace(matches[6])
			
			// Determine if it's a method based on indentation and parameters
			isMethod := len(indent) > 0 && len(params) > 0 && params[0].Name == "self"
			isClassMethod := false
			isStaticMethod := false
			
			// Check decorators for method types
			for _, decorator := range decorators {
				switch decorator {
				case "classmethod":
					isClassMethod = true
				case "staticmethod":
					isStaticMethod = true
				}
			}
			
			// Get docstring
			docstring := ca.extractDocstring(lines, lineNum+1)
			
			function := &FunctionInfo{
				Name:           name,
				LineNumber:     lineNum + 1,
				Parameters:     params,
				ReturnType:     returnType,
				Decorators:     decorators,
				Docstring:      docstring,
				IsAsync:        isAsync,
				IsMethod:       isMethod,
				IsClassMethod:  isClassMethod,
				IsStaticMethod: isStaticMethod,
				Metadata:       make(map[string]interface{}),
			}
			
			// Calculate complexity (simplified)
			function.Complexity = ca.calculateFunctionComplexity(lines, lineNum)
			
			functions = append(functions, function)
		}
	}
	
	return functions
}

// parseClasses extracts class definitions from Python code
func (ca *CodeAnalyzer) parseClasses(code string) []*ClassInfo {
	var classes []*ClassInfo
	
	lines := strings.Split(code, "\n")
	
	classRegex := regexp.MustCompile(`^(\s*)((?:@\w+\s+)*)class\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(([^)]*)\))?\s*:`)
	
	for lineNum, line := range lines {
		if matches := classRegex.FindStringSubmatch(line); matches != nil {
			name := matches[3]
			baseClassesStr := matches[4]
			decorators := ca.parseDecorators(matches[2])
			
			var baseClasses []string
			if baseClassesStr != "" {
				baseClasses = strings.Split(baseClassesStr, ",")
				for i, base := range baseClasses {
					baseClasses[i] = strings.TrimSpace(base)
				}
			}
			
			// Get docstring
			docstring := ca.extractDocstring(lines, lineNum+1)
			
			// Check if abstract
			isAbstract := false
			for _, decorator := range decorators {
				if decorator == "abstractmethod" || strings.Contains(decorator, "ABC") {
					isAbstract = true
					break
				}
			}
			
			class := &ClassInfo{
				Name:        name,
				LineNumber:  lineNum + 1,
				BaseClasses: baseClasses,
				Decorators:  decorators,
				Docstring:   docstring,
				IsAbstract:  isAbstract,
				Metadata:    make(map[string]interface{}),
			}
			
			classes = append(classes, class)
		}
	}
	
	return classes
}

// parseVariables extracts variable assignments from Python code
func (ca *CodeAnalyzer) parseVariables(code string) []*VariableInfo {
	var variables []*VariableInfo
	
	lines := strings.Split(code, "\n")
	
	// Simple variable assignment pattern
	varRegex := regexp.MustCompile(`^(\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*(?::\s*([^=]+))?\s*=\s*(.+)`)
	
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		
		if matches := varRegex.FindStringSubmatch(line); matches != nil {
			indent := matches[1]
			name := matches[2]
			typeHint := strings.TrimSpace(matches[3])
			value := strings.TrimSpace(matches[4])
			
			// Determine scope
			scope := "local"
			if len(indent) == 0 {
				scope = "global"
			}
			
			// Check if constant (all uppercase)
			isConstant := strings.ToUpper(name) == name && len(name) > 1
			
			variable := &VariableInfo{
				Name:       name,
				Type:       typeHint,
				Value:      value,
				LineNumber: lineNum + 1,
				Scope:      scope,
				IsGlobal:   scope == "global",
				IsConstant: isConstant,
			}
			
			variables = append(variables, variable)
		}
	}
	
	return variables
}

// analyzeTypeHints analyzes type hints in the code
func (ca *CodeAnalyzer) analyzeTypeHints(code string) []*TypeHintInfo {
	var typeHints []*TypeHintInfo
	
	lines := strings.Split(code, "\n")
	
	// Pattern for type hints
	typeHintRegex := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*([^=]+)`)
	
	for lineNum, line := range lines {
		matches := typeHintRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			typeHint := &TypeHintInfo{
				Location:   fmt.Sprintf("line %d", lineNum+1),
				Type:       strings.TrimSpace(match[2]),
				LineNumber: lineNum + 1,
				IsValid:    ca.validateTypeHint(match[2]),
			}
			
			typeHints = append(typeHints, typeHint)
		}
	}
	
	return typeHints
}

// analyzeDocstrings analyzes docstrings in the code
func (ca *CodeAnalyzer) analyzeDocstrings(code string) []*DocstringInfo {
	var docstrings []*DocstringInfo
	
	lines := strings.Split(code, "\n")
	
	// Look for triple-quoted strings
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		
		if strings.HasPrefix(line, `"""`) || strings.HasPrefix(line, "'''") {
			quote := line[:3]
			content := line[3:]
			startLine := i + 1
			
			// Single line docstring
			if strings.HasSuffix(content, quote) && len(content) > 3 {
				docstring := &DocstringInfo{
					Location:   fmt.Sprintf("line %d", startLine),
					Content:    content[:len(content)-3],
					LineNumber: startLine,
					Style:      ca.detectDocstringStyle(content),
					IsComplete: true,
				}
				docstrings = append(docstrings, docstring)
				continue
			}
			
			// Multi-line docstring
			var docContent []string
			docContent = append(docContent, content)
			
			i++
			for i < len(lines) {
				line := lines[i]
				if strings.Contains(line, quote) {
					// End of docstring
					endIdx := strings.Index(line, quote)
					docContent = append(docContent, line[:endIdx])
					break
				}
				docContent = append(docContent, line)
				i++
			}
			
			fullContent := strings.Join(docContent, "\n")
			docstring := &DocstringInfo{
				Location:   fmt.Sprintf("lines %d-%d", startLine, i+1),
				Content:    fullContent,
				LineNumber: startLine,
				Style:      ca.detectDocstringStyle(fullContent),
				IsComplete: true,
			}
			
			docstrings = append(docstrings, docstring)
		}
	}
	
	return docstrings
}

// generateWarnings generates analysis warnings
func (ca *CodeAnalyzer) generateWarnings(result *AnalysisResult) []*AnalysisWarning {
	var warnings []*AnalysisWarning
	
	// Check for missing docstrings
	if ca.config.RequiredDocstrings {
		for _, function := range result.Functions {
			if function.Docstring == "" {
				warnings = append(warnings, &AnalysisWarning{
					Type:       WarningTypeMissingDocstring,
					Message:    fmt.Sprintf("Function '%s' is missing a docstring", function.Name),
					LineNumber: function.LineNumber,
					Suggestion: "Add a docstring to describe the function's purpose",
				})
			}
		}
	}
	
	// Check complexity warnings
	if ca.config.EnableComplexityAnalysis {
		for _, function := range result.Functions {
			if function.Complexity > ca.config.MaxComplexity {
				warnings = append(warnings, &AnalysisWarning{
					Type:       WarningTypeComplexity,
					Message:    fmt.Sprintf("Function '%s' has high complexity (%d)", function.Name, function.Complexity),
					LineNumber: function.LineNumber,
					Suggestion: "Consider breaking this function into smaller functions",
				})
			}
		}
	}
	
	return warnings
}

// Helper functions

func (ca *CodeAnalyzer) parseDecorators(decoratorStr string) []string {
	var decorators []string
	if decoratorStr != "" {
		parts := strings.Fields(decoratorStr)
		for _, part := range parts {
			if strings.HasPrefix(part, "@") {
				decorators = append(decorators, part[1:])
			}
		}
	}
	return decorators
}

func (ca *CodeAnalyzer) parseParameters(paramStr string) []*ParameterInfo {
	var params []*ParameterInfo
	
	if paramStr == "" {
		return params
	}
	
	paramList := strings.Split(paramStr, ",")
	for _, param := range paramList {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}
		
		paramInfo := &ParameterInfo{
			IsRequired: true,
		}
		
		// Handle *args and **kwargs
		if strings.HasPrefix(param, "**") {
			paramInfo.Name = param[2:]
			paramInfo.IsKwArgs = true
		} else if strings.HasPrefix(param, "*") {
			paramInfo.Name = param[1:]
			paramInfo.IsVarArgs = true
		} else {
			// Handle regular parameters with type hints and defaults
			parts := strings.Split(param, "=")
			nameAndType := strings.TrimSpace(parts[0])
			
			if len(parts) > 1 {
				paramInfo.DefaultValue = strings.TrimSpace(parts[1])
				paramInfo.IsRequired = false
			}
			
			// Parse name and type
			if strings.Contains(nameAndType, ":") {
				typeParts := strings.Split(nameAndType, ":")
				paramInfo.Name = strings.TrimSpace(typeParts[0])
				paramInfo.Type = strings.TrimSpace(typeParts[1])
			} else {
				paramInfo.Name = nameAndType
			}
		}
		
		params = append(params, paramInfo)
	}
	
	return params
}

func (ca *CodeAnalyzer) extractDocstring(lines []string, startLine int) string {
	if startLine >= len(lines) {
		return ""
	}
	
	// Look for docstring on the next non-empty line
	for i := startLine; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		
		if strings.HasPrefix(line, `"""`) || strings.HasPrefix(line, "'''") {
			quote := line[:3]
			content := line[3:]
			
			// Single line docstring
			if strings.HasSuffix(content, quote) && len(content) > 3 {
				return content[:len(content)-3]
			}
			
			// Multi-line docstring
			var docContent []string
			docContent = append(docContent, content)
			
			for j := i + 1; j < len(lines); j++ {
				line := lines[j]
				if strings.Contains(line, quote) {
					endIdx := strings.Index(line, quote)
					docContent = append(docContent, line[:endIdx])
					break
				}
				docContent = append(docContent, line)
			}
			
			return strings.Join(docContent, "\n")
		}
		
		// If we hit non-docstring code, stop looking
		break
	}
	
	return ""
}

func (ca *CodeAnalyzer) calculateFunctionComplexity(lines []string, startLine int) int {
	complexity := 1 // Base complexity
	
	// Look for complexity-increasing constructs
	complexityKeywords := []string{
		"if", "elif", "else", "for", "while", "try", "except", "finally",
		"and", "or", "break", "continue", "return",
	}
	
	// Simple complexity calculation based on keywords
	for i := startLine; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		
		// Stop at next function or class definition
		if strings.HasPrefix(line, "def ") || strings.HasPrefix(line, "class ") {
			break
		}
		
		for _, keyword := range complexityKeywords {
			if strings.Contains(line, keyword) {
				complexity++
			}
		}
	}
	
	return complexity
}

func (ca *CodeAnalyzer) validateTypeHint(typeHint string) bool {
	// Basic type hint validation
	typeHint = strings.TrimSpace(typeHint)
	
	// Check for common valid type patterns
	validPatterns := []string{
		`^[a-zA-Z_][a-zA-Z0-9_.]*$`,                    // Simple types
		`^[a-zA-Z_][a-zA-Z0-9_.]*\[[^\]]+\]$`,          // Generic types
		`^Union\[[^\]]+\]$`,                            // Union types
		`^Optional\[[^\]]+\]$`,                         // Optional types
		`^List\[[^\]]+\]$`,                             // List types
		`^Dict\[[^\]]+\]$`,                             // Dict types
	}
	
	for _, pattern := range validPatterns {
		if matched, _ := regexp.MatchString(pattern, typeHint); matched {
			return true
		}
	}
	
	return false
}

func (ca *CodeAnalyzer) detectDocstringStyle(content string) DocstringStyle {
	// Simple docstring style detection
	if strings.Contains(content, "Args:") || strings.Contains(content, "Returns:") {
		return DocstringStyleGoogle
	}
	
	if strings.Contains(content, "Parameters") || strings.Contains(content, "--------") {
		return DocstringStyleNumPy
	}
	
	if strings.Contains(content, ":param") || strings.Contains(content, ":return") {
		return DocstringStyleSphinx
	}
	
	return DocstringStyleUnknown
}

func (ca *CodeAnalyzer) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}