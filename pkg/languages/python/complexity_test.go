package python

import (
	"testing"
	"time"
)

func TestNewComplexityCalculator(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	if calculator == nil {
		t.Error("Calculator should not be nil")
	}
	
	if calculator.config == nil {
		t.Error("Config should not be nil")
	}
	
	// Test default config values
	if !calculator.config.IncludeCyclomaticComplexity {
		t.Error("Cyclomatic complexity should be enabled by default")
	}
	
	if !calculator.config.IncludeHalsteadMetrics {
		t.Error("Halstead metrics should be enabled by default")
	}
	
	if calculator.config.ComplexityThreshold != 10 {
		t.Errorf("Expected complexity threshold 10, got %d", calculator.config.ComplexityThreshold)
	}
	
	if calculator.config.MaintainabilityThreshold != 85.0 {
		t.Errorf("Expected maintainability threshold 85.0, got %f", calculator.config.MaintainabilityThreshold)
	}
}

func TestComplexityCalculator_countBlankLines(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	tests := []struct {
		name     string
		lines    []string
		expected int
	}{
		{
			name:     "No blank lines",
			lines:    []string{"def function():", "    pass"},
			expected: 0,
		},
		{
			name:     "Some blank lines",
			lines:    []string{"def function():", "", "    pass", "", ""},
			expected: 3,
		},
		{
			name:     "All blank lines",
			lines:    []string{"", "   ", "\t", ""},
			expected: 4,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculator.countBlankLines(tt.lines)
			if result != tt.expected {
				t.Errorf("Expected %d blank lines, got %d", tt.expected, result)
			}
		})
	}
}

func TestComplexityCalculator_countCommentLines(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	tests := []struct {
		name     string
		lines    []string
		expected int
	}{
		{
			name:     "No comments",
			lines:    []string{"def function():", "    pass"},
			expected: 0,
		},
		{
			name: "Single line comments",
			lines: []string{
				"# This is a comment",
				"def function():",
				"    # Another comment",
				"    pass",
			},
			expected: 2,
		},
		{
			name: "Multi-line docstring",
			lines: []string{
				"def function():",
				`    """`,
				`    This is a docstring`,
				`    with multiple lines`,
				`    """`,
				"    pass",
			},
			expected: 3,
		},
		{
			name: "Single line docstring",
			lines: []string{
				"def function():",
				`    """Single line docstring"""`,
				"    pass",
			},
			expected: 1,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculator.countCommentLines(tt.lines)
			if result != tt.expected {
				t.Errorf("Expected %d comment lines, got %d", tt.expected, result)
			}
		})
	}
}

func TestComplexityCalculator_countFunctions(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	code := []string{
		"def function1():",
		"    pass",
		"",
		"def function2(arg1, arg2):",
		"    return arg1 + arg2",
		"",
		"class MyClass:",
		"    def method1(self):",
		"        pass",
		"    ",
		"    def method2(self, arg):",
		"        return arg",
		"",
		"async def async_function():",
		"    await something()",
	}
	
	result := calculator.countFunctions(code)
	expected := 5 // function1, function2, method1, method2, async_function
	
	if result != expected {
		t.Errorf("Expected %d functions, got %d", expected, result)
	}
}

func TestComplexityCalculator_countClasses(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	code := []string{
		"class Class1:",
		"    pass",
		"",
		"class Class2(BaseClass):",
		"    def method(self):",
		"        pass",
		"",
		"def function():",
		"    pass",
		"",
		"class Class3(Base1, Base2):",
		"    pass",
	}
	
	result := calculator.countClasses(code)
	expected := 3
	
	if result != expected {
		t.Errorf("Expected %d classes, got %d", expected, result)
	}
}

func TestComplexityCalculator_countMethods(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	code := []string{
		"def function():",
		"    pass",
		"",
		"class MyClass:",
		"    def method1(self):",
		"        pass",
		"    ",
		"    def method2(self, arg):",
		"        return arg",
		"",
		"def another_function():",
		"    pass",
		"",
		"class AnotherClass:",
		"    def method3(self):",
		"        pass",
	}
	
	result := calculator.countMethods(code)
	expected := 3 // method1, method2, method3
	
	if result != expected {
		t.Errorf("Expected %d methods, got %d", expected, result)
	}
}

func TestComplexityCalculator_calculateCyclomaticComplexity(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	tests := []struct {
		name     string
		code     []string
		expected int
	}{
		{
			name: "Simple function",
			code: []string{
				"def simple_function():",
				"    return True",
			},
			expected: 1, // Base complexity
		},
		{
			name: "Function with if statement",
			code: []string{
				"def function_with_if(x):",
				"    if x > 0:",
				"        return True",
				"    return False",
			},
			expected: 2, // Base + if
		},
		{
			name: "Function with if-elif-else",
			code: []string{
				"def function_with_conditions(x):",
				"    if x > 10:",
				"        return 'high'",
				"    elif x > 5:",
				"        return 'medium'",
				"    else:",
				"        return 'low'",
			},
			expected: 4, // Base + if + elif + else
		},
		{
			name: "Function with loops",
			code: []string{
				"def function_with_loops():",
				"    for i in range(10):",
				"        if i % 2 == 0:",
				"            continue",
				"    while True:",
				"        break",
			},
			expected: 6, // Base + for + if + continue + while + break
		},
		{
			name: "Function with exception handling",
			code: []string{
				"def function_with_exceptions():",
				"    try:",
				"        risky_operation()",
				"    except ValueError:",
				"        handle_value_error()",
				"    except Exception:",
				"        handle_generic_error()",
				"    finally:",
				"        cleanup()",
			},
			expected: 5, // Base + try + except + except + finally
		},
		{
			name: "Function with logical operators",
			code: []string{
				"def function_with_logic(a, b, c):",
				"    if a and b or c:",
				"        return True",
				"    return False",
			},
			expected: 4, // Base + if + and + or
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculator.calculateCyclomaticComplexity(tt.code)
			if result != tt.expected {
				t.Errorf("Expected complexity %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestComplexityCalculator_removeStrings(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    `print("Hello, World!")`,
			expected: `print( )`,
		},
		{
			input:    `value = 'test string'`,
			expected: `value =  `,
		},
		{
			input:    `path = "C:\\Users\\test"`,
			expected: `path =  `,
		},
		{
			input:    `if condition and "test" in string:`,
			expected: `if condition and   in string:`,
		},
		{
			input:    `no_strings_here = 42`,
			expected: `no_strings_here = 42`,
		},
	}
	
	for _, tt := range tests {
		result := calculator.removeStrings(tt.input)
		if result != tt.expected {
			t.Errorf("Expected %q, got %q", tt.expected, result)
		}
	}
}

func TestComplexityCalculator_hasListComprehension(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	tests := []struct {
		line     string
		expected bool
	}{
		{
			line:     "result = [x for x in items]",
			expected: true,
		},
		{
			line:     "squares = [x**2 for x in range(10)]",
			expected: true,
		},
		{
			line:     "dict_comp = {k: v for k, v in items.items()}",
			expected: true,
		},
		{
			line:     "gen_exp = (x for x in items)",
			expected: true,
		},
		{
			line:     "regular_list = [1, 2, 3, 4]",
			expected: false,
		},
		{
			line:     "function_call()",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		result := calculator.hasListComprehension(tt.line)
		if result != tt.expected {
			t.Errorf("For line %q, expected %v, got %v", tt.line, tt.expected, result)
		}
	}
}

func TestComplexityCalculator_calculateHalsteadMetrics(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	code := `
def simple_function(x, y):
    result = x + y
    if result > 10:
        return result * 2
    return result
`
	
	metrics := calculator.calculateHalsteadMetrics(code)
	
	if metrics.DistinctOperators == 0 {
		t.Error("Should detect distinct operators")
	}
	
	if metrics.DistinctOperands == 0 {
		t.Error("Should detect distinct operands")
	}
	
	if metrics.TotalOperators == 0 {
		t.Error("Should count total operators")
	}
	
	if metrics.TotalOperands == 0 {
		t.Error("Should count total operands")
	}
	
	if metrics.Vocabulary == 0 {
		t.Error("Vocabulary should be calculated")
	}
	
	if metrics.Length == 0 {
		t.Error("Length should be calculated")
	}
	
	if metrics.Volume == 0 {
		t.Error("Volume should be calculated")
	}
	
	// Test that vocabulary equals distinct operators + distinct operands
	expectedVocabulary := metrics.DistinctOperators + metrics.DistinctOperands
	if metrics.Vocabulary != expectedVocabulary {
		t.Errorf("Expected vocabulary %d, got %d", expectedVocabulary, metrics.Vocabulary)
	}
	
	// Test that length equals total operators + total operands
	expectedLength := metrics.TotalOperators + metrics.TotalOperands
	if metrics.Length != expectedLength {
		t.Errorf("Expected length %d, got %d", expectedLength, metrics.Length)
	}
}

func TestComplexityCalculator_calculateMaintainabilityIndex(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	metrics := &ComplexityMetrics{
		CyclomaticComplexity: 5,
		LinesOfCode:         50,
	}
	
	halstead := &HalsteadMetrics{
		Volume: 100.0,
	}
	
	mi := calculator.calculateMaintainabilityIndex(metrics, halstead)
	
	if mi < 0 || mi > 100 {
		t.Errorf("Maintainability index should be between 0 and 100, got %f", mi)
	}
	
	// Test edge case with zero values
	emptyMetrics := &ComplexityMetrics{
		LinesOfCode: 0,
	}
	
	emptyHalstead := &HalsteadMetrics{
		Volume: 0,
	}
	
	mi = calculator.calculateMaintainabilityIndex(emptyMetrics, emptyHalstead)
	if mi != 100.0 {
		t.Errorf("Empty code should have perfect maintainability index of 100, got %f", mi)
	}
}

func TestComplexityCalculator_estimateTechnicalDebt(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	tests := []struct {
		name     string
		metrics  *ComplexityMetrics
		expected bool // Whether debt should be > 0
	}{
		{
			name: "Simple code",
			metrics: &ComplexityMetrics{
				CyclomaticComplexity: 5,
				Maintainability:     90,
				FunctionCount:       10,
				LinesOfCode:        100,
			},
			expected: false, // Should have minimal debt
		},
		{
			name: "Complex code",
			metrics: &ComplexityMetrics{
				CyclomaticComplexity: 25,
				Maintainability:     60,
				FunctionCount:       80,
				LinesOfCode:        1000,
			},
			expected: true, // Should have significant debt
		},
		{
			name: "High complexity",
			metrics: &ComplexityMetrics{
				CyclomaticComplexity: 30,
				Maintainability:     85,
				FunctionCount:       20,
				LinesOfCode:        200,
			},
			expected: true, // High complexity should create debt
		},
		{
			name: "Low maintainability",
			metrics: &ComplexityMetrics{
				CyclomaticComplexity: 8,
				Maintainability:     40,
				FunctionCount:       15,
				LinesOfCode:        150,
			},
			expected: true, // Low maintainability should create debt
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			debt := calculator.estimateTechnicalDebt(tt.metrics)
			
			if tt.expected && debt == 0 {
				t.Error("Expected technical debt but got none")
			}
			
			if !tt.expected && debt > 30*time.Minute {
				t.Errorf("Expected minimal debt but got %v", debt)
			}
			
			if debt < 0 {
				t.Error("Technical debt should not be negative")
			}
		})
	}
}

func TestComplexityCalculator_Calculate(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	code := `
def factorial(n):
    """Calculate factorial of n."""
    if n <= 1:
        return 1
    else:
        return n * factorial(n - 1)

def fibonacci(n):
    """Calculate nth Fibonacci number."""
    if n <= 1:
        return n
    
    a, b = 0, 1
    for i in range(2, n + 1):
        a, b = b, a + b
    
    return b

class Calculator:
    """Simple calculator class."""
    
    def __init__(self):
        self.value = 0
    
    def add(self, x):
        """Add x to current value."""
        self.value += x
        return self
    
    def multiply(self, x):
        """Multiply current value by x."""
        if x == 0:
            self.value = 0
        else:
            self.value *= x
        return self
    
    def get_value(self):
        """Get current value."""
        return self.value

# Test the calculator
calc = Calculator()
result = calc.add(5).multiply(2).get_value()
print(f"Result: {result}")
`
	
	metrics := calculator.Calculate(code)
	
	if metrics.PhysicalLines == 0 {
		t.Error("Should count physical lines")
	}
	
	if metrics.LogicalLines == 0 {
		t.Error("Should count logical lines")
	}
	
	if metrics.BlankLines == 0 {
		t.Error("Should count blank lines")
	}
	
	if metrics.CommentLines == 0 {
		t.Error("Should count comment lines (docstrings)")
	}
	
	if metrics.FunctionCount != 5 {
		t.Errorf("Expected 5 functions, got %d", metrics.FunctionCount)
	}
	
	if metrics.ClassCount != 1 {
		t.Errorf("Expected 1 class, got %d", metrics.ClassCount)
	}
	
	if metrics.MethodCount != 4 {
		t.Errorf("Expected 4 methods, got %d", metrics.MethodCount)
	}
	
	if metrics.CyclomaticComplexity == 0 {
		t.Error("Should calculate cyclomatic complexity")
	}
	
	if metrics.Maintainability == 0 {
		t.Error("Should calculate maintainability index")
	}
	
	if metrics.TechnicalDebt == 0 {
		t.Log("Technical debt is zero (acceptable for simple code)")
	}
	
	// Test that logical lines + blank lines + comment lines roughly equals physical lines
	totalCounted := metrics.LogicalLines + metrics.BlankLines + metrics.CommentLines
	if totalCounted > metrics.PhysicalLines {
		t.Errorf("Counted lines (%d) should not exceed physical lines (%d)", totalCounted, metrics.PhysicalLines)
	}
}

func TestComplexityCalculator_CalculateCognitiveComplexity(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	code := `
def simple_function(x):
    return x * 2

def complex_function(items):
    total = 0
    for item in items:  # +1
        if item.is_valid():  # +2 (nested)
            if item.value > 10:  # +3 (nested deeper)
                total += item.value * 2
            elif item.value > 5:  # +1 (elif at same level as if)
                total += item.value
        else:  # +1 (else at same level as if)
            if item.can_repair():  # +3 (nested)
                item.repair()
                total += 1
    return total
`
	
	cognitiveMetrics := calculator.CalculateCognitiveComplexity(code)
	
	if cognitiveMetrics.Score == 0 {
		t.Error("Should calculate cognitive complexity score")
	}
	
	if len(cognitiveMetrics.Functions) == 0 {
		t.Error("Should track function complexities")
	}
	
	// Check that complex_function has higher complexity than simple_function
	simpleComplexity, hasSimple := cognitiveMetrics.Functions["simple_function"]
	complexComplexity, hasComplex := cognitiveMetrics.Functions["complex_function"]
	
	if !hasSimple {
		t.Error("Should find simple_function")
	}
	
	if !hasComplex {
		t.Error("Should find complex_function")
	}
	
	if hasSimple && hasComplex && complexComplexity <= simpleComplexity {
		t.Errorf("complex_function (%d) should have higher complexity than simple_function (%d)", 
			complexComplexity, simpleComplexity)
	}
	
	if len(cognitiveMetrics.ComplexStructs) == 0 {
		t.Error("Should identify complex structures")
	}
}

func TestComplexityCalculator_GetComplexityReport(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	metrics := &ComplexityMetrics{
		CyclomaticComplexity: 15,
		Maintainability:     75,
		FunctionCount:       25,
		ClassCount:         3,
		LinesOfCode:        300,
	}
	
	report := calculator.GetComplexityReport(metrics)
	
	if report.OverallScore == 0 {
		t.Error("Should calculate overall score")
	}
	
	if report.ComplexityLevel == "" {
		t.Error("Should determine complexity level")
	}
	
	if len(report.Recommendations) == 0 {
		t.Error("Should generate recommendations")
	}
	
	// Test complexity level determination
	expectedLevel := "Moderate" // For complexity of 15
	if report.ComplexityLevel != expectedLevel {
		t.Errorf("Expected complexity level %s, got %s", expectedLevel, report.ComplexityLevel)
	}
}

func TestComplexityCalculator_generateRecommendations(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	tests := []struct {
		name     string
		metrics  *ComplexityMetrics
		minRecs  int
	}{
		{
			name: "High complexity code",
			metrics: &ComplexityMetrics{
				CyclomaticComplexity: 25,
				Maintainability:     60,
				FunctionCount:       50,
				ClassCount:         0,
				LinesOfCode:        800,
				CommentLines:       10,
			},
			minRecs: 3,
		},
		{
			name: "Well-structured code",
			metrics: &ComplexityMetrics{
				CyclomaticComplexity: 8,
				Maintainability:     90,
				FunctionCount:       15,
				ClassCount:         3,
				LinesOfCode:        200,
				CommentLines:       40,
			},
			minRecs: 0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recommendations := calculator.generateRecommendations(tt.metrics)
			
			if len(recommendations) < tt.minRecs {
				t.Errorf("Expected at least %d recommendations, got %d", tt.minRecs, len(recommendations))
			}
			
			// Check that recommendations are not empty
			for _, rec := range recommendations {
				if rec == "" {
					t.Error("Recommendation should not be empty")
				}
			}
		})
	}
}

func TestComplexityCalculator_calculateOverallScore(t *testing.T) {
	calculator := NewComplexityCalculator()
	
	tests := []struct {
		name     string
		metrics  *ComplexityMetrics
		expected float64 // Range expectation
		min      bool    // Whether to test minimum
	}{
		{
			name: "Perfect code",
			metrics: &ComplexityMetrics{
				CyclomaticComplexity: 1,
				Maintainability:     100,
				FunctionCount:       1,
				ClassCount:         1,
				LinesOfCode:        10,
			},
			expected: 85,
			min:      true,
		},
		{
			name: "Poor code",
			metrics: &ComplexityMetrics{
				CyclomaticComplexity: 50,
				Maintainability:     20,
				FunctionCount:       100,
				ClassCount:         1,
				LinesOfCode:        2000,
			},
			expected: 30,
			min:      false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := calculator.calculateOverallScore(tt.metrics)
			
			if score < 0 || score > 100 {
				t.Errorf("Score should be between 0-100, got %f", score)
			}
			
			if tt.min && score < tt.expected {
				t.Errorf("Expected score >= %f, got %f", tt.expected, score)
			} else if !tt.min && score > tt.expected {
				t.Errorf("Expected score <= %f, got %f", tt.expected, score)
			}
		})
	}
}

// Benchmark tests

func BenchmarkComplexityCalculator_Calculate(b *testing.B) {
	calculator := NewComplexityCalculator()
	
	code := `
def complex_function(data):
    result = []
    for item in data:
        if item.is_valid():
            try:
                processed = item.process()
                if processed.quality > 0.8:
                    result.append(processed)
                elif processed.quality > 0.5:
                    if processed.can_improve():
                        improved = processed.improve()
                        result.append(improved)
                    else:
                        result.append(processed)
                else:
                    logger.warning("Low quality item")
            except ProcessingError:
                logger.error("Failed to process item")
                continue
            except Exception as e:
                logger.critical(f"Unexpected error: {e}")
                raise
            finally:
                item.cleanup()
    return result

class DataProcessor:
    def __init__(self, config):
        self.config = config
        self.stats = {'processed': 0, 'failed': 0}
    
    def process_batch(self, batch):
        results = []
        for item in batch:
            try:
                if self.should_process(item):
                    result = self.process_item(item)
                    results.append(result)
                    self.stats['processed'] += 1
                else:
                    self.stats['failed'] += 1
            except Exception:
                self.stats['failed'] += 1
        return results
`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculator.Calculate(code)
	}
}

func BenchmarkComplexityCalculator_calculateCyclomaticComplexity(b *testing.B) {
	calculator := NewComplexityCalculator()
	
	lines := []string{
		"def complex_function(x, y, z):",
		"    if x > 0:",
		"        if y > 0:",
		"            if z > 0:",
		"                return x * y * z",
		"            elif z < 0:",
		"                return x * y / z",
		"            else:",
		"                return x * y",
		"        elif y < 0:",
		"            return x / y",
		"        else:",
		"            return x",
		"    elif x < 0:",
		"        for i in range(abs(x)):",
		"            if i % 2 == 0:",
		"                continue",
		"            try:",
		"                result = process(i)",
		"            except ValueError:",
		"                result = 0",
		"            except Exception:",
		"                break",
		"            finally:",
		"                cleanup()",
		"        return result",
		"    else:",
		"        while True:",
		"            if should_continue():",
		"                continue",
		"            else:",
		"                break",
		"        return 0",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculator.calculateCyclomaticComplexity(lines)
	}
}

func BenchmarkComplexityCalculator_calculateHalsteadMetrics(b *testing.B) {
	calculator := NewComplexityCalculator()
	
	code := `
def fibonacci(n):
    if n <= 1:
        return n
    else:
        return fibonacci(n-1) + fibonacci(n-2)

def factorial(n):
    if n == 0 or n == 1:
        return 1
    else:
        return n * factorial(n-1)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

class MathUtils:
    @staticmethod
    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n**0.5) + 1):
            if n % i == 0:
                return False
        return True
    
    @staticmethod
    def lcm(a, b):
        return abs(a * b) // gcd(a, b)
`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculator.calculateHalsteadMetrics(code)
	}
}

func BenchmarkComplexityCalculator_removeStrings(b *testing.B) {
	calculator := NewComplexityCalculator()
	
	testLine := `print(f"Processing item {i}: '{item.name}' with value \"{item.value}\" and status '{item.status}'")`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculator.removeStrings(testLine)
	}
}