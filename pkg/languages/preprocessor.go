package languages

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PreprocessorOptions contains options for code preprocessing
type PreprocessorOptions struct {
	EnableLanguageDetection    bool              `json:"enable_language_detection"`
	EnableDependencyExtraction bool              `json:"enable_dependency_extraction"`
	EnableMissingImportRes     bool              `json:"enable_missing_import_resolution"`
	EnableSyntaxValidation     bool              `json:"enable_syntax_validation"`
	EnableSecurityScanning     bool              `json:"enable_security_scanning"`
	EnableCodeInstrumentation  bool              `json:"enable_code_instrumentation"`
	EnableCodeFormatting       bool              `json:"enable_code_formatting"`
	CustomConfig               map[string]string `json:"custom_config,omitempty"`
	SecurityRules              []SecurityRule    `json:"security_rules,omitempty"`
	InstrumentationTargets     []string          `json:"instrumentation_targets,omitempty"`
}

// PreprocessorResult contains the result of code preprocessing
type PreprocessorResult struct {
	OriginalCode           string                 `json:"original_code"`
	ProcessedCode          string                 `json:"processed_code"`
	DetectedLanguage       Language               `json:"detected_language"`
	LanguageConfidence     float64                `json:"language_confidence"`
	ExtractedDependencies  []Dependency           `json:"extracted_dependencies"`
	MissingDependencies    []string               `json:"missing_dependencies"`
	ResolvedImports        []ImportResolution     `json:"resolved_imports"`
	SyntaxErrors           []SyntaxError          `json:"syntax_errors"`
	SecurityWarnings       []SecurityWarning      `json:"security_warnings"`
	InstrumentationPoints  []InstrumentationPoint `json:"instrumentation_points"`
	Metadata               map[string]interface{} `json:"metadata"`
	ProcessingDuration     time.Duration          `json:"processing_duration"`
	Warnings               []string               `json:"warnings"`
	Success                bool                   `json:"success"`
	Error                  error                  `json:"error,omitempty"`
}

// Dependency represents an extracted dependency
type Dependency struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Type        string `json:"type"` // import, require, include, etc.
	Source      string `json:"source,omitempty"`
	LineNumber  int    `json:"line_number"`
	IsBuiltIn   bool   `json:"is_built_in"`
	IsResolved  bool   `json:"is_resolved"`
	ImportPath  string `json:"import_path,omitempty"`
}

// ImportResolution represents a resolved import
type ImportResolution struct {
	Original     string `json:"original"`
	Resolved     string `json:"resolved"`
	PackageName  string `json:"package_name,omitempty"`
	ModulePath   string `json:"module_path,omitempty"`
	IsStandardLib bool  `json:"is_standard_lib"`
	IsThirdParty bool   `json:"is_third_party"`
}

// SyntaxError represents a syntax error found during validation
type SyntaxError struct {
	Message    string `json:"message"`
	LineNumber int    `json:"line_number"`
	Column     int    `json:"column"`
	Severity   string `json:"severity"` // error, warning, info
	Code       string `json:"code,omitempty"`
}

// SecurityWarning represents a security issue found during scanning
type SecurityWarning struct {
	RuleID      string `json:"rule_id"`
	Message     string `json:"message"`
	LineNumber  int    `json:"line_number"`
	Severity    string `json:"severity"` // critical, high, medium, low
	Category    string `json:"category"`
	Suggestion  string `json:"suggestion,omitempty"`
	CodeSnippet string `json:"code_snippet,omitempty"`
}

// SecurityRule represents a security scanning rule
type SecurityRule struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Pattern     *regexp.Regexp   `json:"-"`
	Languages   []Language       `json:"languages"`
	Severity    string           `json:"severity"`
	Category    string           `json:"category"`
	Suggestion  string           `json:"suggestion"`
}

// InstrumentationPoint represents a code instrumentation point
type InstrumentationPoint struct {
	Type        string `json:"type"` // function_entry, function_exit, line, variable_access
	LineNumber  int    `json:"line_number"`
	Function    string `json:"function,omitempty"`
	Variable    string `json:"variable,omitempty"`
	Code        string `json:"code"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CodePreprocessor handles code preprocessing tasks
type CodePreprocessor struct {
	detector       *Detector
	securityRules  []SecurityRule
	builtInModules map[Language][]string
	standardLibs   map[Language]map[string]bool
	metrics        map[string]interface{}
}

// NewCodePreprocessor creates a new code preprocessor
func NewCodePreprocessor() *CodePreprocessor {
	return &CodePreprocessor{
		detector:       NewDetector(),
		securityRules:  getDefaultSecurityRules(),
		builtInModules: getBuiltInModules(),
		standardLibs:   getStandardLibraries(),
		metrics:        make(map[string]interface{}),
	}
}

// Process performs comprehensive code preprocessing
func (p *CodePreprocessor) Process(ctx context.Context, code string, options *PreprocessorOptions) (*PreprocessorResult, error) {
	startTime := time.Now()
	
	result := &PreprocessorResult{
		OriginalCode:          code,
		ProcessedCode:         code,
		ExtractedDependencies: []Dependency{},
		MissingDependencies:   []string{},
		ResolvedImports:       []ImportResolution{},
		SyntaxErrors:          []SyntaxError{},
		SecurityWarnings:      []SecurityWarning{},
		InstrumentationPoints: []InstrumentationPoint{},
		Metadata:              make(map[string]interface{}),
		Warnings:              []string{},
		Success:               true,
	}

	// Step 1: Language Detection
	if options.EnableLanguageDetection {
		if err := p.detectLanguage(code, result); err != nil {
			result.Error = err
			result.Success = false
			return result, err
		}
	}

	// Step 2: Dependency Extraction
	if options.EnableDependencyExtraction {
		if err := p.extractDependencies(code, result); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Dependency extraction warning: %v", err))
		}
	}

	// Step 3: Missing Import Resolution
	if options.EnableMissingImportRes {
		if err := p.resolveMissingImports(code, result); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Import resolution warning: %v", err))
		}
	}

	// Step 4: Syntax Validation
	if options.EnableSyntaxValidation {
		if err := p.validateSyntax(code, result); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Syntax validation warning: %v", err))
		}
	}

	// Step 5: Security Scanning
	if options.EnableSecurityScanning {
		rules := options.SecurityRules
		if len(rules) == 0 {
			rules = p.securityRules
		}
		if err := p.scanSecurity(code, rules, result); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Security scanning warning: %v", err))
		}
	}

	// Step 6: Code Instrumentation
	if options.EnableCodeInstrumentation {
		targets := options.InstrumentationTargets
		if len(targets) == 0 {
			targets = []string{"functions", "lines"}
		}
		if err := p.instrumentCode(code, targets, result); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Code instrumentation warning: %v", err))
		}
	}

	// Step 7: Code Formatting
	if options.EnableCodeFormatting {
		if err := p.formatCode(code, result); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Code formatting warning: %v", err))
		}
	}

	result.ProcessingDuration = time.Since(startTime)

	// Update metrics
	p.updateMetrics(result)

	return result, nil
}

// detectLanguage detects the programming language of the code
func (p *CodePreprocessor) detectLanguage(code string, result *PreprocessorResult) error {
	detection := p.detector.GetBestMatch(code, "")
	if detection == nil {
		return fmt.Errorf("failed to detect language")
	}

	result.DetectedLanguage = detection.Language
	result.LanguageConfidence = detection.Confidence
	result.Metadata["detection_reason"] = detection.Reason

	return nil
}

// extractDependencies extracts dependencies from code
func (p *CodePreprocessor) extractDependencies(code string, result *PreprocessorResult) error {
	lang := result.DetectedLanguage
	if lang == "" {
		// Try to detect language first
		detection := p.detector.GetBestMatch(code, "")
		if detection == nil {
			return fmt.Errorf("language detection required for dependency extraction")
		}
		lang = detection.Language
	}

	dependencies, err := p.extractDependenciesByLanguage(code, lang)
	if err != nil {
		return fmt.Errorf("failed to extract dependencies: %w", err)
	}

	result.ExtractedDependencies = dependencies
	result.Metadata["dependency_count"] = len(dependencies)

	return nil
}

// resolveMissingImports resolves missing imports and suggests packages
func (p *CodePreprocessor) resolveMissingImports(code string, result *PreprocessorResult) error {
	lang := result.DetectedLanguage
	if lang == "" {
		return fmt.Errorf("language detection required for import resolution")
	}

	// Check each dependency for resolution
	for i, dep := range result.ExtractedDependencies {
		resolution, err := p.resolveImport(dep, lang)
		if err == nil {
			result.ResolvedImports = append(result.ResolvedImports, *resolution)
			result.ExtractedDependencies[i].IsResolved = true
		} else {
			result.MissingDependencies = append(result.MissingDependencies, dep.Name)
		}
	}

	return nil
}

// validateSyntax performs basic syntax validation
func (p *CodePreprocessor) validateSyntax(code string, result *PreprocessorResult) error {
	lang := result.DetectedLanguage
	if lang == "" {
		return fmt.Errorf("language detection required for syntax validation")
	}

	syntaxErrors := p.validateSyntaxByLanguage(code, lang)
	result.SyntaxErrors = syntaxErrors

	if len(syntaxErrors) > 0 {
		result.Metadata["has_syntax_errors"] = true
		result.Metadata["syntax_error_count"] = len(syntaxErrors)
	}

	return nil
}

// scanSecurity scans code for security issues
func (p *CodePreprocessor) scanSecurity(code string, rules []SecurityRule, result *PreprocessorResult) error {
	lang := result.DetectedLanguage
	lines := strings.Split(code, "\n")

	for _, rule := range rules {
		// Check if rule applies to this language
		if len(rule.Languages) > 0 {
			languageMatches := false
			for _, ruleLanguage := range rule.Languages {
				if ruleLanguage == lang {
					languageMatches = true
					break
				}
			}
			if !languageMatches {
				continue
			}
		}

		// Scan each line for pattern matches
		for i, line := range lines {
			if rule.Pattern.MatchString(line) {
				warning := SecurityWarning{
					RuleID:      rule.ID,
					Message:     rule.Description,
					LineNumber:  i + 1,
					Severity:    rule.Severity,
					Category:    rule.Category,
					Suggestion:  rule.Suggestion,
					CodeSnippet: strings.TrimSpace(line),
				}
				result.SecurityWarnings = append(result.SecurityWarnings, warning)
			}
		}
	}

	// Sort warnings by severity
	sort.Slice(result.SecurityWarnings, func(i, j int) bool {
		severityOrder := map[string]int{
			"critical": 0,
			"high":     1,
			"medium":   2,
			"low":      3,
		}
		return severityOrder[result.SecurityWarnings[i].Severity] < severityOrder[result.SecurityWarnings[j].Severity]
	})

	return nil
}

// instrumentCode adds instrumentation points to the code
func (p *CodePreprocessor) instrumentCode(code string, targets []string, result *PreprocessorResult) error {
	lang := result.DetectedLanguage
	lines := strings.Split(code, "\n")

	for _, target := range targets {
		switch target {
		case "functions":
			points := p.findFunctionInstrumentationPoints(lines, lang)
			result.InstrumentationPoints = append(result.InstrumentationPoints, points...)
		case "lines":
			points := p.findLineInstrumentationPoints(lines, lang)
			result.InstrumentationPoints = append(result.InstrumentationPoints, points...)
		case "variables":
			points := p.findVariableInstrumentationPoints(lines, lang)
			result.InstrumentationPoints = append(result.InstrumentationPoints, points...)
		}
	}

	return nil
}

// formatCode normalizes code formatting
func (p *CodePreprocessor) formatCode(code string, result *PreprocessorResult) error {
	lang := result.DetectedLanguage
	
	// Basic formatting normalization
	lines := strings.Split(code, "\n")
	var formattedLines []string

	for _, line := range lines {
		// Remove trailing whitespace
		trimmed := strings.TrimRight(line, " \t")
		
		// Normalize indentation based on language
		if lang == LanguagePython {
			// Convert tabs to 4 spaces for Python
			trimmed = strings.ReplaceAll(trimmed, "\t", "    ")
		}
		
		formattedLines = append(formattedLines, trimmed)
	}

	result.ProcessedCode = strings.Join(formattedLines, "\n")
	
	// Check if formatting changed
	if result.ProcessedCode != result.OriginalCode {
		result.Metadata["code_formatted"] = true
	}

	return nil
}

// Language-specific dependency extraction
func (p *CodePreprocessor) extractDependenciesByLanguage(code string, lang Language) ([]Dependency, error) {
	var dependencies []Dependency
	lines := strings.Split(code, "\n")

	switch lang {
	case LanguagePython:
		dependencies = p.extractPythonDependencies(lines)
	case LanguageJavaScript, LanguageTypeScript:
		dependencies = p.extractJavaScriptDependencies(lines)
	case LanguageGo:
		dependencies = p.extractGoDependencies(lines)
	case LanguageRust:
		dependencies = p.extractRustDependencies(lines)
	case LanguageJava:
		dependencies = p.extractJavaDependencies(lines)
	case LanguageC, LanguageCPP:
		dependencies = p.extractCDependencies(lines)
	case LanguageCSharp:
		dependencies = p.extractCSharpDependencies(lines)
	}

	// Mark built-in modules
	p.markBuiltInModules(dependencies, lang)

	return dependencies, nil
}

// Language-specific dependency extractors
func (p *CodePreprocessor) extractPythonDependencies(lines []string) []Dependency {
	var deps []Dependency
	
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^\s*import\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)`),
		regexp.MustCompile(`^\s*from\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\s+import`),
	}

	for i, line := range lines {
		for _, pattern := range patterns {
			matches := pattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				moduleName := strings.Split(matches[1], ".")[0]
				deps = append(deps, Dependency{
					Name:       moduleName,
					Type:       "import",
					LineNumber: i + 1,
					ImportPath: matches[1],
				})
			}
		}
	}

	return removeDuplicateDependencies(deps)
}

func (p *CodePreprocessor) extractJavaScriptDependencies(lines []string) []Dependency {
	var deps []Dependency
	
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`require\s*\(\s*['"]([^'"]+)['"]\s*\)`),
		regexp.MustCompile(`^\s*import\s+(?:.*\s+from\s+)?['"]([^'"]+)['"]`),
		regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`),
	}

	for i, line := range lines {
		for _, pattern := range patterns {
			matches := pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 && !strings.HasPrefix(match[1], ".") {
					deps = append(deps, Dependency{
						Name:       match[1],
						Type:       "import",
						LineNumber: i + 1,
						ImportPath: match[1],
					})
				}
			}
		}
	}

	return removeDuplicateDependencies(deps)
}

func (p *CodePreprocessor) extractGoDependencies(lines []string) []Dependency {
	var deps []Dependency
	
	importPattern := regexp.MustCompile(`^\s*"([^"]+)"\s*$`)
	singleImportPattern := regexp.MustCompile(`^\s*import\s+"([^"]+)"`)

	inImportBlock := false
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		
		if strings.HasPrefix(trimmedLine, "import (") {
			inImportBlock = true
			continue
		}
		
		if inImportBlock && strings.Contains(trimmedLine, ")") {
			inImportBlock = false
			continue
		}

		if inImportBlock {
			matches := importPattern.FindStringSubmatch(line)
			if len(matches) > 1 && !strings.HasPrefix(matches[1], ".") {
				deps = append(deps, Dependency{
					Name:       matches[1],
					Type:       "import",
					LineNumber: i + 1,
					ImportPath: matches[1],
				})
			}
		} else {
			matches := singleImportPattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				deps = append(deps, Dependency{
					Name:       matches[1],
					Type:       "import",
					LineNumber: i + 1,
					ImportPath: matches[1],
				})
			}
		}
	}

	return removeDuplicateDependencies(deps)
}

func (p *CodePreprocessor) extractRustDependencies(lines []string) []Dependency {
	var deps []Dependency
	
	usePattern := regexp.MustCompile(`^\s*use\s+([a-zA-Z_][a-zA-Z0-9_]*)::\w+`)

	for i, line := range lines {
		matches := usePattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			crateName := matches[1]
			if !isRustStdCrate(crateName) {
				deps = append(deps, Dependency{
					Name:       crateName,
					Type:       "use",
					LineNumber: i + 1,
					ImportPath: matches[1],
				})
			}
		}
	}

	return removeDuplicateDependencies(deps)
}

func (p *CodePreprocessor) extractJavaDependencies(lines []string) []Dependency {
	var deps []Dependency
	
	importPattern := regexp.MustCompile(`^\s*import\s+(?:static\s+)?([a-zA-Z_][a-zA-Z0-9_.]*)\s*;`)

	for i, line := range lines {
		matches := importPattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			importPath := matches[1]
			if !strings.HasPrefix(importPath, "java.lang.") {
				deps = append(deps, Dependency{
					Name:       importPath,
					Type:       "import",
					LineNumber: i + 1,
					ImportPath: importPath,
				})
			}
		}
	}

	return removeDuplicateDependencies(deps)
}

func (p *CodePreprocessor) extractCDependencies(lines []string) []Dependency {
	var deps []Dependency
	
	includePattern := regexp.MustCompile(`^\s*#include\s*[<"]([^>"]+)[>"]`)

	for i, line := range lines {
		matches := includePattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			headerName := matches[1]
			deps = append(deps, Dependency{
				Name:       headerName,
				Type:       "include",
				LineNumber: i + 1,
				ImportPath: headerName,
			})
		}
	}

	return removeDuplicateDependencies(deps)
}

func (p *CodePreprocessor) extractCSharpDependencies(lines []string) []Dependency {
	var deps []Dependency
	
	usingPattern := regexp.MustCompile(`^\s*using\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*;`)

	for i, line := range lines {
		matches := usingPattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			namespaceName := matches[1]
			deps = append(deps, Dependency{
				Name:       namespaceName,
				Type:       "using",
				LineNumber: i + 1,
				ImportPath: namespaceName,
			})
		}
	}

	return removeDuplicateDependencies(deps)
}

// Import resolution
func (p *CodePreprocessor) resolveImport(dep Dependency, lang Language) (*ImportResolution, error) {
	// Check if it's a standard library module
	if stdLibs, exists := p.standardLibs[lang]; exists {
		if stdLibs[dep.Name] {
			return &ImportResolution{
				Original:      dep.Name,
				Resolved:      dep.Name,
				PackageName:   dep.Name,
				IsStandardLib: true,
				IsThirdParty:  false,
			}, nil
		}
	}

	// For now, mark as third-party if not standard library
	return &ImportResolution{
		Original:      dep.Name,
		Resolved:      dep.Name,
		PackageName:   dep.Name,
		IsStandardLib: false,
		IsThirdParty:  true,
	}, nil
}

// Syntax validation by language
func (p *CodePreprocessor) validateSyntaxByLanguage(code string, lang Language) []SyntaxError {
	var errors []SyntaxError
	lines := strings.Split(code, "\n")

	// Basic syntax checks (can be enhanced with actual parsers)
	switch lang {
	case LanguagePython:
		errors = append(errors, p.validatePythonSyntax(lines)...)
	case LanguageJavaScript:
		errors = append(errors, p.validateJavaScriptSyntax(lines)...)
	case LanguageGo:
		errors = append(errors, p.validateGoSyntax(lines)...)
	}

	return errors
}

// Basic Python syntax validation
func (p *CodePreprocessor) validatePythonSyntax(lines []string) []SyntaxError {
	var errors []SyntaxError
	
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		
		// Check for basic syntax issues
		if strings.HasSuffix(trimmed, ":") && !regexp.MustCompile(`(if|else|elif|for|while|def|class|try|except|finally|with)\s`).MatchString(trimmed) {
			errors = append(errors, SyntaxError{
				Message:    "Invalid colon usage",
				LineNumber: i + 1,
				Severity:   "warning",
			})
		}
	}

	return errors
}

func (p *CodePreprocessor) validateJavaScriptSyntax(lines []string) []SyntaxError {
	var errors []SyntaxError
	
	// Basic JavaScript syntax checks
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		
		// Check for unclosed braces/brackets
		openBraces := strings.Count(line, "{")
		closeBraces := strings.Count(line, "}")
		if openBraces > 0 && closeBraces > 0 && openBraces != closeBraces {
			errors = append(errors, SyntaxError{
				Message:    "Mismatched braces",
				LineNumber: i + 1,
				Severity:   "error",
			})
		}
	}

	return errors
}

func (p *CodePreprocessor) validateGoSyntax(lines []string) []SyntaxError {
	var errors []SyntaxError
	
	// Basic Go syntax checks
	hasPackageDeclaration := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		
		if strings.HasPrefix(trimmed, "package ") {
			hasPackageDeclaration = true
		}
	}
	
	if !hasPackageDeclaration {
		errors = append(errors, SyntaxError{
			Message:    "Missing package declaration",
			LineNumber: 1,
			Severity:   "error",
		})
	}

	return errors
}

// Instrumentation point finding
func (p *CodePreprocessor) findFunctionInstrumentationPoints(lines []string, lang Language) []InstrumentationPoint {
	var points []InstrumentationPoint
	
	var functionPattern *regexp.Regexp
	switch lang {
	case LanguagePython:
		functionPattern = regexp.MustCompile(`^\s*def\s+(\w+)\s*\(`)
	case LanguageJavaScript, LanguageTypeScript:
		functionPattern = regexp.MustCompile(`(?:function\s+(\w+)|(\w+)\s*=\s*(?:function|\(.*\)\s*=>))`)
	case LanguageGo:
		functionPattern = regexp.MustCompile(`^\s*func\s+(\w+)\s*\(`)
	case LanguageJava:
		functionPattern = regexp.MustCompile(`(?:public|private|protected)?\s*(?:static\s+)?(?:\w+\s+)*(\w+)\s*\(`)
	}

	if functionPattern != nil {
		for i, line := range lines {
			matches := functionPattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				functionName := matches[1]
				if functionName == "" && len(matches) > 2 {
					functionName = matches[2]
				}
				
				points = append(points, InstrumentationPoint{
					Type:       "function_entry",
					LineNumber: i + 1,
					Function:   functionName,
					Code:       strings.TrimSpace(line),
				})
			}
		}
	}

	return points
}

func (p *CodePreprocessor) findLineInstrumentationPoints(lines []string, lang Language) []InstrumentationPoint {
	var points []InstrumentationPoint
	
	// Instrument every non-empty, non-comment line
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		
		// Skip comments
		isComment := false
		switch lang {
		case LanguagePython:
			isComment = strings.HasPrefix(trimmed, "#")
		case LanguageJavaScript, LanguageTypeScript, LanguageJava, LanguageC, LanguageCPP, LanguageCSharp:
			isComment = strings.HasPrefix(trimmed, "//")
		case LanguageGo:
			isComment = strings.HasPrefix(trimmed, "//")
		}
		
		if !isComment {
			points = append(points, InstrumentationPoint{
				Type:       "line",
				LineNumber: lineNum + 1,
				Code:       trimmed,
			})
		}
	}

	return points
}

func (p *CodePreprocessor) findVariableInstrumentationPoints(lines []string, lang Language) []InstrumentationPoint {
	var points []InstrumentationPoint
	
	var variablePattern *regexp.Regexp
	switch lang {
	case LanguagePython:
		variablePattern = regexp.MustCompile(`^\s*(\w+)\s*=`)
	case LanguageJavaScript, LanguageTypeScript:
		variablePattern = regexp.MustCompile(`(?:var|let|const)\s+(\w+)`)
	case LanguageGo:
		variablePattern = regexp.MustCompile(`(?:var\s+(\w+)|(\w+)\s*:=)`)
	case LanguageJava:
		variablePattern = regexp.MustCompile(`(?:\w+\s+)?(\w+)\s*=`)
	}

	if variablePattern != nil {
		for i, line := range lines {
			matches := variablePattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				variableName := matches[1]
				if variableName == "" && len(matches) > 2 {
					variableName = matches[2]
				}
				
				points = append(points, InstrumentationPoint{
					Type:       "variable_access",
					LineNumber: i + 1,
					Variable:   variableName,
					Code:       strings.TrimSpace(line),
				})
			}
		}
	}

	return points
}

// Helper functions
func (p *CodePreprocessor) markBuiltInModules(dependencies []Dependency, lang Language) {
	if builtIns, exists := p.builtInModules[lang]; exists {
		builtInMap := make(map[string]bool)
		for _, module := range builtIns {
			builtInMap[module] = true
		}
		
		for i := range dependencies {
			if builtInMap[dependencies[i].Name] {
				dependencies[i].IsBuiltIn = true
			}
		}
	}
}

func (p *CodePreprocessor) updateMetrics(result *PreprocessorResult) {
	p.metrics["last_processed"] = time.Now()
	p.metrics["processing_duration"] = result.ProcessingDuration
	p.metrics["detected_language"] = string(result.DetectedLanguage)
	p.metrics["language_confidence"] = result.LanguageConfidence
	p.metrics["dependency_count"] = len(result.ExtractedDependencies)
	p.metrics["security_warning_count"] = len(result.SecurityWarnings)
	p.metrics["syntax_error_count"] = len(result.SyntaxErrors)
	p.metrics["instrumentation_point_count"] = len(result.InstrumentationPoints)
}

// Utility functions
func removeDuplicateDependencies(deps []Dependency) []Dependency {
	seen := make(map[string]bool)
	var result []Dependency
	
	for _, dep := range deps {
		if !seen[dep.Name] {
			seen[dep.Name] = true
			result = append(result, dep)
		}
	}
	
	return result
}

func isRustStdCrate(crateName string) bool {
	stdCrates := []string{
		"std", "core", "alloc", "proc_macro", "test",
		"collections", "fmt", "io", "net", "sync", "thread", "time",
	}
	
	for _, std := range stdCrates {
		if crateName == std {
			return true
		}
	}
	return false
}