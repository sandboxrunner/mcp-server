package python

import (
	"math"
	"regexp"
	"strings"
	"time"
)

// ComplexityCalculator calculates various code complexity metrics
type ComplexityCalculator struct {
	config *ComplexityConfig
}

// ComplexityConfig configures complexity calculation
type ComplexityConfig struct {
	IncludeCyclomaticComplexity bool    `json:"include_cyclomatic_complexity"`
	IncludeCognitiveComplexity  bool    `json:"include_cognitive_complexity"`
	IncludeHalsteadMetrics      bool    `json:"include_halstead_metrics"`
	IncludeMaintainabilityIndex bool    `json:"include_maintainability_index"`
	ComplexityThreshold         int     `json:"complexity_threshold"`
	MaintainabilityThreshold    float64 `json:"maintainability_threshold"`
}

// NewComplexityCalculator creates a new complexity calculator
func NewComplexityCalculator() *ComplexityCalculator {
	return &ComplexityCalculator{
		config: &ComplexityConfig{
			IncludeCyclomaticComplexity: true,
			IncludeCognitiveComplexity:  true,
			IncludeHalsteadMetrics:      true,
			IncludeMaintainabilityIndex: true,
			ComplexityThreshold:         10,
			MaintainabilityThreshold:    85.0,
		},
	}
}

// HalsteadMetrics contains Halstead complexity metrics
type HalsteadMetrics struct {
	DistinctOperators    int     `json:"distinct_operators"`
	DistinctOperands     int     `json:"distinct_operands"`
	TotalOperators       int     `json:"total_operators"`
	TotalOperands        int     `json:"total_operands"`
	Vocabulary           int     `json:"vocabulary"`
	Length               int     `json:"length"`
	Volume               float64 `json:"volume"`
	Difficulty           float64 `json:"difficulty"`
	Effort               float64 `json:"effort"`
	TimeToProgram        float64 `json:"time_to_program"`
	BugsDelivered        float64 `json:"bugs_delivered"`
}

// CognitiveComplexityMetrics contains cognitive complexity information
type CognitiveComplexityMetrics struct {
	Score          int                   `json:"score"`
	Functions      map[string]int        `json:"functions"`
	Classes        map[string]int        `json:"classes"`
	NestingLevels  []int                 `json:"nesting_levels"`
	ComplexStructs []ComplexStructure    `json:"complex_structures"`
}

// ComplexStructure represents a complex code structure
type ComplexStructure struct {
	Type       string `json:"type"`
	LineNumber int    `json:"line_number"`
	Complexity int    `json:"complexity"`
	Nesting    int    `json:"nesting"`
}

// Calculate calculates comprehensive complexity metrics for Python code
func (cc *ComplexityCalculator) Calculate(code string) *ComplexityMetrics {
	metrics := &ComplexityMetrics{
		Metadata: make(map[string]interface{}),
	}
	
	lines := strings.Split(code, "\n")
	
	// Basic line counting
	metrics.PhysicalLines = len(lines)
	metrics.BlankLines = cc.countBlankLines(lines)
	metrics.CommentLines = cc.countCommentLines(lines)
	metrics.LogicalLines = metrics.PhysicalLines - metrics.BlankLines - metrics.CommentLines
	metrics.LinesOfCode = metrics.LogicalLines
	
	// Count functions and classes
	metrics.FunctionCount = cc.countFunctions(lines)
	metrics.ClassCount = cc.countClasses(lines)
	metrics.MethodCount = cc.countMethods(lines)
	
	// Calculate cyclomatic complexity
	if cc.config.IncludeCyclomaticComplexity {
		metrics.CyclomaticComplexity = cc.calculateCyclomaticComplexity(lines)
	}
	
	// Calculate maintainability index
	if cc.config.IncludeMaintainabilityIndex {
		halstead := cc.calculateHalsteadMetrics(code)
		metrics.Maintainability = cc.calculateMaintainabilityIndex(metrics, halstead)
	}
	
	// Estimate technical debt
	metrics.TechnicalDebt = cc.estimateTechnicalDebt(metrics)
	
	return metrics
}

// countBlankLines counts blank lines in the code
func (cc *ComplexityCalculator) countBlankLines(lines []string) int {
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			count++
		}
	}
	return count
}

// countCommentLines counts comment lines in the code
func (cc *ComplexityCalculator) countCommentLines(lines []string) int {
	count := 0
	inMultiLineComment := false
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Multi-line comments (docstrings)
		if strings.HasPrefix(trimmed, `"""`) || strings.HasPrefix(trimmed, "'''") {
			if !inMultiLineComment {
				inMultiLineComment = true
				count++
				// Check if it's a single-line docstring
				quote := trimmed[:3]
				if strings.Count(trimmed, quote) >= 2 {
					inMultiLineComment = false
				}
				continue
			} else {
				inMultiLineComment = false
				count++
				continue
			}
		}
		
		if inMultiLineComment {
			count++
			continue
		}
		
		// Single-line comments
		if strings.HasPrefix(trimmed, "#") {
			count++
		}
	}
	
	return count
}

// countFunctions counts function definitions
func (cc *ComplexityCalculator) countFunctions(lines []string) int {
	count := 0
	funcRegex := regexp.MustCompile(`^\s*def\s+[a-zA-Z_][a-zA-Z0-9_]*\s*\(`)
	
	for _, line := range lines {
		if funcRegex.MatchString(line) {
			count++
		}
	}
	
	return count
}

// countClasses counts class definitions
func (cc *ComplexityCalculator) countClasses(lines []string) int {
	count := 0
	classRegex := regexp.MustCompile(`^\s*class\s+[a-zA-Z_][a-zA-Z0-9_]*`)
	
	for _, line := range lines {
		if classRegex.MatchString(line) {
			count++
		}
	}
	
	return count
}

// countMethods counts method definitions (functions within classes)
func (cc *ComplexityCalculator) countMethods(lines []string) int {
	methodCount := 0
	inClass := false
	classIndent := 0
	
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		
		// Check for class definition
		if strings.Contains(line, "class ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			inClass = true
			classIndent = indent
			continue
		}
		
		// Reset if we're out of class scope
		if inClass && indent <= classIndent && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			inClass = false
		}
		
		// Count methods within classes
		if inClass && strings.Contains(line, "def ") && indent > classIndent {
			methodCount++
		}
	}
	
	return methodCount
}

// calculateCyclomaticComplexity calculates cyclomatic complexity
func (cc *ComplexityCalculator) calculateCyclomaticComplexity(lines []string) int {
	complexity := 1 // Base complexity
	
	// Patterns that increase complexity
	complexityPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\bif\b`),
		regexp.MustCompile(`\belif\b`),
		regexp.MustCompile(`\belse\b`),
		regexp.MustCompile(`\bfor\b`),
		regexp.MustCompile(`\bwhile\b`),
		regexp.MustCompile(`\btry\b`),
		regexp.MustCompile(`\bexcept\b`),
		regexp.MustCompile(`\bfinally\b`),
		regexp.MustCompile(`\band\b`),
		regexp.MustCompile(`\bor\b`),
		regexp.MustCompile(`\bbreak\b`),
		regexp.MustCompile(`\bcontinue\b`),
		regexp.MustCompile(`\breturn\b`),
		regexp.MustCompile(`\byield\b`),
		regexp.MustCompile(`\braise\b`),
		regexp.MustCompile(`\bassert\b`),
		regexp.MustCompile(`\bwith\b`),
		regexp.MustCompile(`\basync\s+for\b`),
		regexp.MustCompile(`\basync\s+with\b`),
	}
	
	for _, line := range lines {
		// Skip comment lines
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "" {
			continue
		}
		
		// Simple string detection to avoid counting keywords in strings
		processedLine := cc.removeStrings(line)
		
		// Check each complexity pattern
		for _, pattern := range complexityPatterns {
			matches := pattern.FindAllString(processedLine, -1)
			complexity += len(matches)
		}
		
		// Additional complexity for comprehensions
		if cc.hasListComprehension(processedLine) {
			complexity++
		}
	}
	
	return complexity
}

// removeStrings removes string literals from a line to avoid false positives
func (cc *ComplexityCalculator) removeStrings(line string) string {
	var result strings.Builder
	inString := false
	stringChar := byte(0)
	escaped := false
	
	for i := 0; i < len(line); i++ {
		char := line[i]
		
		if escaped {
			escaped = false
			if !inString {
				result.WriteByte(char)
			}
			continue
		}
		
		if char == '\\' {
			escaped = true
			if !inString {
				result.WriteByte(char)
			}
			continue
		}
		
		if char == '"' || char == '\'' {
			if !inString {
				inString = true
				stringChar = char
				result.WriteByte(' ') // Replace with space
			} else if char == stringChar {
				inString = false
				result.WriteByte(' ') // Replace with space
			}
			continue
		}
		
		if !inString {
			result.WriteByte(char)
		} else {
			result.WriteByte(' ') // Replace string content with spaces
		}
	}
	
	return result.String()
}

// hasListComprehension checks if a line contains list/dict/set comprehensions
func (cc *ComplexityCalculator) hasListComprehension(line string) bool {
	// Simple detection of comprehensions
	comprehensionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\[[^\]]*\bfor\b[^\]]*\]`), // List comprehension
		regexp.MustCompile(`\{[^}]*\bfor\b[^}]*\}`),   // Dict/Set comprehension
		regexp.MustCompile(`\([^)]*\bfor\b[^)]*\)`),   // Generator expression
	}
	
	for _, pattern := range comprehensionPatterns {
		if pattern.MatchString(line) {
			return true
		}
	}
	
	return false
}

// calculateHalsteadMetrics calculates Halstead complexity metrics
func (cc *ComplexityCalculator) calculateHalsteadMetrics(code string) *HalsteadMetrics {
	operators := make(map[string]int)
	operands := make(map[string]int)
	
	// Python operators
	operatorPatterns := []string{
		`\+`, `-`, `\*`, `/`, `//`, `%`, `\*\*`,
		`==`, `!=`, `<`, `>`, `<=`, `>=`,
		`and`, `or`, `not`, `is`, `in`,
		`=`, `\+=`, `-=`, `\*=`, `/=`, `//=`, `%=`, `\*\*=`,
		`&`, `\|`, `\^`, `~`, `<<`, `>>`,
		`&=`, `\|=`, `\^=`, `<<=`, `>>=`,
		`\.`, `\[`, `\]`, `\(`, `\)`, `\{`, `\}`,
		`:`, `;`, `,`,
	}
	
	// Remove strings and comments first
	cleanCode := cc.removeStringsAndComments(code)
	
	// Count operators
	for _, pattern := range operatorPatterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllString(cleanCode, -1)
		if len(matches) > 0 {
			operators[pattern] = len(matches)
		}
	}
	
	// Count operands (identifiers, literals)
	operandRegex := regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]*\b|\b\d+(?:\.\d+)?\b`)
	operandMatches := operandRegex.FindAllString(cleanCode, -1)
	
	// Filter out keywords
	keywords := map[string]bool{
		"and": true, "as": true, "assert": true, "break": true, "class": true,
		"continue": true, "def": true, "del": true, "elif": true, "else": true,
		"except": true, "exec": true, "finally": true, "for": true, "from": true,
		"global": true, "if": true, "import": true, "in": true, "is": true,
		"lambda": true, "not": true, "or": true, "pass": true, "print": true,
		"raise": true, "return": true, "try": true, "while": true, "with": true,
		"yield": true, "async": true, "await": true, "nonlocal": true,
	}
	
	for _, operand := range operandMatches {
		if !keywords[operand] {
			operands[operand]++
		}
	}
	
	// Calculate Halstead metrics
	n1 := len(operators)  // distinct operators
	n2 := len(operands)   // distinct operands
	N1 := 0               // total operators
	N2 := 0               // total operands
	
	for _, count := range operators {
		N1 += count
	}
	for _, count := range operands {
		N2 += count
	}
	
	vocabulary := n1 + n2
	length := N1 + N2
	volume := float64(length) * math.Log2(float64(vocabulary))
	
	var difficulty, effort, timeToProgram, bugsDelivered float64
	if n2 > 0 {
		difficulty = (float64(n1) / 2.0) * (float64(N2) / float64(n2))
		effort = difficulty * volume
		timeToProgram = effort / 18.0 // Stroud number
		bugsDelivered = volume / 3000.0
	}
	
	return &HalsteadMetrics{
		DistinctOperators: n1,
		DistinctOperands:  n2,
		TotalOperators:    N1,
		TotalOperands:     N2,
		Vocabulary:        vocabulary,
		Length:            length,
		Volume:            volume,
		Difficulty:        difficulty,
		Effort:            effort,
		TimeToProgram:     timeToProgram,
		BugsDelivered:     bugsDelivered,
	}
}

// removeStringsAndComments removes strings and comments from code
func (cc *ComplexityCalculator) removeStringsAndComments(code string) string {
	lines := strings.Split(code, "\n")
	var result []string
	
	for _, line := range lines {
		processedLine := cc.removeStrings(line)
		
		// Remove single-line comments
		if commentPos := strings.Index(processedLine, "#"); commentPos != -1 {
			processedLine = processedLine[:commentPos]
		}
		
		result = append(result, processedLine)
	}
	
	return strings.Join(result, "\n")
}

// calculateMaintainabilityIndex calculates the maintainability index
func (cc *ComplexityCalculator) calculateMaintainabilityIndex(metrics *ComplexityMetrics, halstead *HalsteadMetrics) float64 {
	// Maintainability Index formula:
	// MI = 171 - 5.2 * ln(Halstead Volume) - 0.23 * (Cyclomatic Complexity) - 16.2 * ln(Lines of Code)
	
	if metrics.LinesOfCode == 0 || halstead.Volume == 0 {
		return 100.0 // Perfect score for empty code
	}
	
	mi := 171.0 - 5.2*math.Log(halstead.Volume) - 0.23*float64(metrics.CyclomaticComplexity) - 16.2*math.Log(float64(metrics.LinesOfCode))
	
	// Normalize to 0-100 scale
	if mi < 0 {
		mi = 0
	} else if mi > 100 {
		mi = 100
	}
	
	return mi
}

// estimateTechnicalDebt estimates technical debt based on complexity metrics
func (cc *ComplexityCalculator) estimateTechnicalDebt(metrics *ComplexityMetrics) time.Duration {
	// Simple heuristic for technical debt estimation
	// Based on complexity thresholds and maintainability
	
	debtMinutes := 0.0
	
	// Add debt for high cyclomatic complexity
	if metrics.CyclomaticComplexity > cc.config.ComplexityThreshold {
		excess := metrics.CyclomaticComplexity - cc.config.ComplexityThreshold
		debtMinutes += float64(excess) * 15.0 // 15 minutes per excess point
	}
	
	// Add debt for low maintainability
	if metrics.Maintainability < cc.config.MaintainabilityThreshold {
		deficit := cc.config.MaintainabilityThreshold - metrics.Maintainability
		debtMinutes += deficit * 2.0 // 2 minutes per maintainability point below threshold
	}
	
	// Add debt based on function count (too many functions may indicate poor organization)
	if metrics.FunctionCount > 50 {
		excess := metrics.FunctionCount - 50
		debtMinutes += float64(excess) * 5.0 // 5 minutes per excess function
	}
	
	// Add debt for large files
	if metrics.LinesOfCode > 500 {
		excess := metrics.LinesOfCode - 500
		debtMinutes += float64(excess) * 0.1 // 0.1 minutes per excess line
	}
	
	return time.Duration(debtMinutes) * time.Minute
}

// CalculateCognitiveComplexity calculates cognitive complexity
func (cc *ComplexityCalculator) CalculateCognitiveComplexity(code string) *CognitiveComplexityMetrics {
	metrics := &CognitiveComplexityMetrics{
		Functions: make(map[string]int),
		Classes:   make(map[string]int),
	}
	
	lines := strings.Split(code, "\n")
	currentFunction := ""
	nestingLevel := 0
	complexity := 0
	
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		
		// Track nesting level
		if strings.HasSuffix(trimmed, ":") {
			nestingLevel++
			metrics.NestingLevels = append(metrics.NestingLevels, nestingLevel)
		}
		
		// Check for function/class definitions
		if funcMatch := regexp.MustCompile(`def\s+([a-zA-Z_][a-zA-Z0-9_]*)`).FindStringSubmatch(trimmed); funcMatch != nil {
			if currentFunction != "" {
				metrics.Functions[currentFunction] = complexity
			}
			currentFunction = funcMatch[1]
			complexity = 0
		}
		
		if regexp.MustCompile(`class\s+([a-zA-Z_][a-zA-Z0-9_]*)`).MatchString(trimmed) {
			// Class definition found - could be used for future enhancements
		}
		
		// Calculate cognitive complexity increments
		increment := cc.calculateCognitiveIncrement(trimmed, nestingLevel)
		complexity += increment
		
		if increment > 0 {
			structType := cc.identifyStructureType(trimmed)
			metrics.ComplexStructs = append(metrics.ComplexStructs, ComplexStructure{
				Type:       structType,
				LineNumber: lineNum + 1,
				Complexity: increment,
				Nesting:    nestingLevel,
			})
		}
	}
	
	// Add final function
	if currentFunction != "" {
		metrics.Functions[currentFunction] = complexity
	}
	
	// Calculate total score
	for _, score := range metrics.Functions {
		metrics.Score += score
	}
	
	return metrics
}

// calculateCognitiveIncrement calculates the cognitive complexity increment for a line
func (cc *ComplexityCalculator) calculateCognitiveIncrement(line string, nestingLevel int) int {
	increment := 0
	
	// Increment for control flow statements
	controlFlowPatterns := []string{
		`\bif\b`, `\belif\b`, `\bfor\b`, `\bwhile\b`,
		`\btry\b`, `\bexcept\b`, `\bfinally\b`,
	}
	
	for _, pattern := range controlFlowPatterns {
		if matched, _ := regexp.MatchString(pattern, line); matched {
			increment++
			break // Only count once per line
		}
	}
	
	// Increment for logical operators (and, or)
	logicalPatterns := []string{`\band\b`, `\bor\b`}
	for _, pattern := range logicalPatterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllString(line, -1)
		increment += len(matches)
	}
	
	// Additional increment for nesting
	if increment > 0 && nestingLevel > 1 {
		increment += nestingLevel - 1
	}
	
	return increment
}

// identifyStructureType identifies the type of complex structure
func (cc *ComplexityCalculator) identifyStructureType(line string) string {
	if matched, _ := regexp.MatchString(`\bif\b`, line); matched {
		return "if_statement"
	}
	if matched, _ := regexp.MatchString(`\bfor\b`, line); matched {
		return "for_loop"
	}
	if matched, _ := regexp.MatchString(`\bwhile\b`, line); matched {
		return "while_loop"
	}
	if matched, _ := regexp.MatchString(`\btry\b`, line); matched {
		return "try_block"
	}
	if matched, _ := regexp.MatchString(`\bexcept\b`, line); matched {
		return "except_block"
	}
	if matched, _ := regexp.MatchString(`\band\b|\bor\b`, line); matched {
		return "logical_operator"
	}
	
	return "unknown"
}

// GetComplexityReport generates a comprehensive complexity report
func (cc *ComplexityCalculator) GetComplexityReport(metrics *ComplexityMetrics) *ComplexityReport {
	report := &ComplexityReport{
		OverallScore: cc.calculateOverallScore(metrics),
		Recommendations: cc.generateRecommendations(metrics),
	}
	
	// Determine complexity level
	if metrics.CyclomaticComplexity <= 5 {
		report.ComplexityLevel = "Low"
	} else if metrics.CyclomaticComplexity <= 10 {
		report.ComplexityLevel = "Moderate"
	} else if metrics.CyclomaticComplexity <= 20 {
		report.ComplexityLevel = "High"
	} else {
		report.ComplexityLevel = "Very High"
	}
	
	return report
}

// ComplexityReport provides a summary of complexity analysis
type ComplexityReport struct {
	OverallScore      float64  `json:"overall_score"`
	ComplexityLevel   string   `json:"complexity_level"`
	Recommendations   []string `json:"recommendations"`
	TechnicalDebtDays float64  `json:"technical_debt_days"`
}

// calculateOverallScore calculates an overall complexity score
func (cc *ComplexityCalculator) calculateOverallScore(metrics *ComplexityMetrics) float64 {
	// Weighted score based on multiple factors
	cyclomaticWeight := 0.4
	maintainabilityWeight := 0.3
	sizeWeight := 0.2
	structureWeight := 0.1
	
	// Normalize cyclomatic complexity (0-100 scale, inverted)
	cyclomaticScore := math.Max(0, 100-float64(metrics.CyclomaticComplexity)*5)
	
	// Maintainability is already 0-100
	maintainabilityScore := metrics.Maintainability
	
	// Size score based on lines of code
	sizeScore := math.Max(0, 100-float64(metrics.LinesOfCode)/10)
	
	// Structure score based on function/class organization
	avgFunctionsPerClass := float64(metrics.FunctionCount) / math.Max(1, float64(metrics.ClassCount))
	structureScore := math.Max(0, 100-avgFunctionsPerClass*5)
	
	overallScore := cyclomaticWeight*cyclomaticScore +
		maintainabilityWeight*maintainabilityScore +
		sizeWeight*sizeScore +
		structureWeight*structureScore
	
	return overallScore
}

// generateRecommendations generates recommendations based on complexity metrics
func (cc *ComplexityCalculator) generateRecommendations(metrics *ComplexityMetrics) []string {
	var recommendations []string
	
	if metrics.CyclomaticComplexity > 15 {
		recommendations = append(recommendations, "Consider breaking down complex functions into smaller, more focused functions")
	}
	
	if metrics.Maintainability < 70 {
		recommendations = append(recommendations, "Improve code maintainability by adding comments and refactoring complex sections")
	}
	
	if metrics.LinesOfCode > 500 {
		recommendations = append(recommendations, "Consider splitting large files into smaller modules")
	}
	
	if metrics.FunctionCount > 30 && metrics.ClassCount == 0 {
		recommendations = append(recommendations, "Consider organizing functions into classes for better structure")
	}
	
	if float64(metrics.CommentLines)/float64(metrics.LinesOfCode) < 0.1 {
		recommendations = append(recommendations, "Add more comments to improve code documentation")
	}
	
	return recommendations
}