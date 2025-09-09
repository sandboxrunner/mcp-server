package languages

import (
	"path/filepath"
	"regexp"
	"strings"
)

// DetectionResult holds language detection results
type DetectionResult struct {
	Language   Language `json:"language"`
	Confidence float64  `json:"confidence"`
	Reason     string   `json:"reason"`
}

// Detector handles language detection from various sources
type Detector struct {
	extensionMap map[string][]Language
	shebangMap   map[string]Language
	patterns     map[Language]*regexp.Regexp
	keywords     map[Language][]string
}

// NewDetector creates a new language detector
func NewDetector() *Detector {
	d := &Detector{
		extensionMap: make(map[string][]Language),
		shebangMap:   make(map[string]Language),
		patterns:     make(map[Language]*regexp.Regexp),
		keywords:     make(map[Language][]string),
	}

	d.initializeExtensions()
	d.initializeShebangs()
	d.initializePatterns()
	d.initializeKeywords()

	return d
}

// DetectFromFilename detects language from filename/extension
func (d *Detector) DetectFromFilename(filename string) []DetectionResult {
	var results []DetectionResult

	ext := strings.ToLower(filepath.Ext(filename))
	if languages, exists := d.extensionMap[ext]; exists {
		for i, lang := range languages {
			confidence := 1.0 - (float64(i) * 0.1) // First match gets highest confidence
			if confidence < 0.1 {
				confidence = 0.1
			}
			results = append(results, DetectionResult{
				Language:   lang,
				Confidence: confidence,
				Reason:     "file_extension",
			})
		}
	}

	return results
}

// DetectFromShebang detects language from shebang line
func (d *Detector) DetectFromShebang(code string) *DetectionResult {
	lines := strings.Split(code, "\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := strings.TrimSpace(lines[0])
	if !strings.HasPrefix(firstLine, "#!") {
		return nil
	}

	shebang := strings.ToLower(firstLine)

	// Check exact matches first
	for pattern, lang := range d.shebangMap {
		if strings.Contains(shebang, pattern) {
			return &DetectionResult{
				Language:   lang,
				Confidence: 0.9,
				Reason:     "shebang",
			}
		}
	}

	return nil
}

// DetectFromContent analyzes code content for language hints
func (d *Detector) DetectFromContent(code string) []DetectionResult {
	var results []DetectionResult
	scores := make(map[Language]float64)

	// Check for language-specific patterns
	for lang, pattern := range d.patterns {
		matches := pattern.FindAllString(code, -1)
		if len(matches) > 0 {
			scores[lang] += float64(len(matches)) * 0.1
		}
	}

	// Check for keywords
	for lang, keywords := range d.keywords {
		keywordCount := 0
		for _, keyword := range keywords {
			keywordCount += strings.Count(strings.ToLower(code), keyword)
		}
		if keywordCount > 0 {
			scores[lang] += float64(keywordCount) * 0.05
		}
	}

	// Convert scores to results
	for lang, score := range scores {
		if score > 0.05 { // Minimum threshold
			confidence := score
			if confidence > 1.0 {
				confidence = 1.0
			}
			results = append(results, DetectionResult{
				Language:   lang,
				Confidence: confidence,
				Reason:     "content_analysis",
			})
		}
	}

	return results
}

// DetectLanguage performs comprehensive language detection
func (d *Detector) DetectLanguage(code string, filename string) []DetectionResult {
	var allResults []DetectionResult

	// Try filename detection first
	if filename != "" {
		filenameResults := d.DetectFromFilename(filename)
		allResults = append(allResults, filenameResults...)
	}

	// Try shebang detection
	if shebangResult := d.DetectFromShebang(code); shebangResult != nil {
		allResults = append(allResults, *shebangResult)
	}

	// Try content analysis
	contentResults := d.DetectFromContent(code)
	allResults = append(allResults, contentResults...)

	// Merge and sort results
	return d.mergeAndSort(allResults)
}

// GetBestMatch returns the most confident language detection
func (d *Detector) GetBestMatch(code string, filename string) *DetectionResult {
	results := d.DetectLanguage(code, filename)
	if len(results) == 0 {
		// Return a default fallback
		return &DetectionResult{
			Language:   LanguageShell,
			Confidence: 0.1,
			Reason:     "fallback",
		}
	}
	return &results[0]
}

// mergeAndSort combines detection results and sorts by confidence
func (d *Detector) mergeAndSort(results []DetectionResult) []DetectionResult {
	if len(results) == 0 {
		return results
	}

	// Merge results by language, keeping highest confidence
	merged := make(map[Language]DetectionResult)
	for _, result := range results {
		if existing, exists := merged[result.Language]; exists {
			if result.Confidence > existing.Confidence {
				merged[result.Language] = result
			}
		} else {
			merged[result.Language] = result
		}
	}

	// Convert back to slice and sort
	var sortedResults []DetectionResult
	for _, result := range merged {
		sortedResults = append(sortedResults, result)
	}

	// Sort by confidence (highest first)
	for i := 0; i < len(sortedResults)-1; i++ {
		for j := i + 1; j < len(sortedResults); j++ {
			if sortedResults[i].Confidence < sortedResults[j].Confidence {
				sortedResults[i], sortedResults[j] = sortedResults[j], sortedResults[i]
			}
		}
	}

	return sortedResults
}

// initializeExtensions sets up file extension mappings
func (d *Detector) initializeExtensions() {
	extensions := map[string][]Language{
		".py":   {LanguagePython},
		".pyw":  {LanguagePython},
		".js":   {LanguageJavaScript},
		".mjs":  {LanguageJavaScript},
		".cjs":  {LanguageJavaScript},
		".ts":   {LanguageTypeScript},
		".tsx":  {LanguageTypeScript},
		".go":   {LanguageGo},
		".rs":   {LanguageRust},
		".java": {LanguageJava},
		".c":    {LanguageC},
		".h":    {LanguageC},
		".cpp":  {LanguageCPP},
		".cxx":  {LanguageCPP},
		".cc":   {LanguageCPP},
		".hpp":  {LanguageCPP},
		".hxx":  {LanguageCPP},
		".cs":   {LanguageCSharp},
		".csx":  {LanguageCSharp},
		".rb":   {LanguageRuby},
		".php":  {LanguagePHP},
		".sh":   {LanguageShell},
		".bash": {LanguageShell},
		".zsh":  {LanguageShell},
		".fish": {LanguageShell},
		".r":    {LanguageR},
		".R":    {LanguageR},
		".lua":  {LanguageLua},
		".pl":   {LanguagePerl},
		".pm":   {LanguagePerl},
	}

	d.extensionMap = extensions
}

// initializeShebangs sets up shebang mappings
func (d *Detector) initializeShebangs() {
	shebangs := map[string]Language{
		"python":  LanguagePython,
		"python3": LanguagePython,
		"node":    LanguageJavaScript,
		"bash":    LanguageShell,
		"/bin/sh": LanguageShell,
		"zsh":     LanguageShell,
		"fish":    LanguageShell,
		"ruby":    LanguageRuby,
		"php":     LanguagePHP,
		"rscript": LanguageR,
		"lua":     LanguageLua,
		"perl":    LanguagePerl,
	}

	d.shebangMap = shebangs
}

// initializePatterns sets up regex patterns for language detection
func (d *Detector) initializePatterns() {
	patterns := map[Language]string{
		LanguagePython:     `(?i)(import\s+\w+|from\s+\w+\s+import|def\s+\w+|class\s+\w+|if\s+__name__\s*==\s*['"']__main__['"])`,
		LanguageJavaScript: `(?i)(function\s+\w+|const\s+\w+|let\s+\w+|var\s+\w+|console\.log|require\s*\(|module\.exports)`,
		LanguageTypeScript: `(?i)(interface\s+\w+|type\s+\w+\s*=|implements\s+\w+|export\s+type|import\s+type)`,
		LanguageGo:         `(?i)(package\s+main|func\s+main|import\s*\(|fmt\.Print)`,
		LanguageRust:       `(?i)(fn\s+main|use\s+std::|println!|pub\s+fn|impl\s+\w+)`,
		LanguageJava:       `(?i)(public\s+class|public\s+static\s+void\s+main|import\s+java\.)`,
		LanguageC:          `(?i)(#include\s*<|int\s+main|printf\s*\(|malloc\s*\()`,
		LanguageCPP:        `(?i)(#include\s*<iostream>|std::|cout\s*<<|cin\s*>>|namespace\s+std)`,
		LanguageCSharp:     `(?i)(using\s+\w+(\.\w+)*;|namespace\s+\w+|public\s+class\s+\w+|static\s+void\s+Main|Console\.(WriteLine|Write))`,
		LanguageRuby:       `(?i)(def\s+\w+|class\s+\w+|puts\s+|require\s+|gem\s+)`,
		LanguagePHP:        `(?i)(<\?php|echo\s+|\$\w+\s*=|function\s+\w+)`,
		LanguageShell:      `(?i)(echo\s+|ls\s+|cd\s+|mkdir\s+|chmod\s+|grep\s+)`,
		LanguageR:          `(?i)(library\s*\(|install\.packages|data\.frame|<-\s*function)`,
		LanguageLua:        `(?i)(function\s+\w+|local\s+\w+|print\s*\(|require\s*\()`,
		LanguagePerl:       `(?i)(use\s+strict|use\s+warnings|sub\s+\w+|print\s+|my\s+\$)`,
	}

	for lang, pattern := range patterns {
		d.patterns[lang] = regexp.MustCompile(pattern)
	}
}

// initializeKeywords sets up keyword lists for content analysis
func (d *Detector) initializeKeywords() {
	keywords := map[Language][]string{
		LanguagePython:     {"import", "def", "class", "if", "else", "elif", "for", "while", "try", "except", "with", "as", "lambda", "yield"},
		LanguageJavaScript: {"function", "const", "let", "var", "if", "else", "for", "while", "return", "async", "await", "promise"},
		LanguageTypeScript: {"interface", "type", "extends", "implements", "generic", "namespace", "declare", "abstract"},
		LanguageGo:         {"package", "import", "func", "type", "struct", "interface", "map", "chan", "select", "go", "defer"},
		LanguageRust:       {"fn", "let", "mut", "struct", "enum", "impl", "trait", "match", "if", "else", "loop", "while"},
		LanguageJava:       {"public", "private", "protected", "class", "interface", "extends", "implements", "abstract", "static", "final"},
		LanguageC:          {"#include", "int", "char", "float", "double", "void", "struct", "union", "enum", "typedef", "sizeof"},
		LanguageCPP:        {"class", "public:", "private:", "protected:", "virtual", "override", "namespace", "template", "typename"},
		LanguageCSharp:     {"using", "namespace", "public", "private", "protected", "class", "interface", "static", "void", "string", "int", "bool", "var"},
		LanguageRuby:       {"def", "class", "module", "require", "include", "attr_accessor", "attr_reader", "attr_writer", "begin", "rescue"},
		LanguagePHP:        {"<?php", "function", "class", "public", "private", "protected", "namespace", "use", "trait", "interface"},
		LanguageShell:      {"echo", "ls", "cd", "mkdir", "chmod", "grep", "sed", "awk", "sort", "uniq", "wc", "find"},
		LanguageR:          {"library", "data.frame", "vector", "matrix", "list", "factor", "summary", "plot", "lm", "glm"},
		LanguageLua:        {"function", "local", "end", "if", "then", "else", "elseif", "for", "while", "repeat", "until"},
		LanguagePerl:       {"use", "strict", "warnings", "sub", "my", "our", "local", "package", "bless", "ref"},
	}

	d.keywords = keywords
}
