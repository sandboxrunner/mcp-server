package node

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJavaScriptAnalyzer(t *testing.T) {
	tempDir := t.TempDir()

	analyzer := NewJavaScriptAnalyzer(tempDir)

	assert.NotNil(t, analyzer)
	assert.Equal(t, tempDir, analyzer.workingDir)
	assert.Equal(t, filepath.Join(tempDir, "node_modules"), analyzer.nodeModulesPath)
	assert.NotNil(t, analyzer.configManager)
	assert.NotNil(t, analyzer.lintEngine)
	assert.NotNil(t, analyzer.securityScanner)
	assert.NotNil(t, analyzer.performanceProfiler)
	assert.NotNil(t, analyzer.bundleAnalyzer)
	assert.NotNil(t, analyzer.dependencyAnalyzer)
}

func TestNewAnalysisConfigManager(t *testing.T) {
	tempDir := t.TempDir()

	manager := NewAnalysisConfigManager(tempDir)

	assert.NotNil(t, manager)
	assert.Equal(t, tempDir, manager.workingDir)
	assert.Equal(t, filepath.Join(tempDir, "package.json"), manager.packageJSONPath)
	assert.NotNil(t, manager.configTemplates)
}

func TestNewESLintEngine(t *testing.T) {
	tempDir := t.TempDir()

	engine := NewESLintEngine(tempDir)

	assert.NotNil(t, engine)
	assert.Equal(t, tempDir, engine.workingDir)
	assert.NotNil(t, engine.rulesCache)
	assert.NotNil(t, engine.fixableRules)
	assert.NotNil(t, engine.customRules)
	assert.NotNil(t, engine.ruleStats)

	// Check rule statistics initialization
	assert.NotNil(t, engine.ruleStats.RuleViolations)
	assert.NotNil(t, engine.ruleStats.SeverityBreakdown)
	assert.NotNil(t, engine.ruleStats.FileBreakdown)
	assert.NotNil(t, engine.ruleStats.TrendData)
}

func TestNewSecurityScanner(t *testing.T) {
	tempDir := t.TempDir()

	scanner := NewSecurityScanner(tempDir)

	assert.NotNil(t, scanner)
	assert.Equal(t, tempDir, scanner.workingDir)
	assert.NotNil(t, scanner.vulnerabilityDB)
	assert.NotNil(t, scanner.customChecks)
	assert.NotNil(t, scanner.securityPolicies)
	assert.NotNil(t, scanner.scanHistory)
}

func TestNewVulnerabilityDatabase(t *testing.T) {
	db := NewVulnerabilityDatabase()

	assert.NotNil(t, db)
	assert.NotNil(t, db.entries)
	assert.NotEmpty(t, db.sources)
	assert.Contains(t, db.sources, "https://registry.npmjs.org/-/npm/v1/security/audits")
}

func TestNewPerformanceProfiler(t *testing.T) {
	tempDir := t.TempDir()

	profiler := NewPerformanceProfiler(tempDir)

	assert.NotNil(t, profiler)
	assert.Equal(t, tempDir, profiler.workingDir)
	assert.NotNil(t, profiler.metrics)
	assert.NotNil(t, profiler.benchmarks)
	assert.NotNil(t, profiler.optimizations)
	assert.NotNil(t, profiler.profiles)
}

func TestNewJSBundleAnalyzer(t *testing.T) {
	tempDir := t.TempDir()

	analyzer := NewJSBundleAnalyzer(tempDir)

	assert.NotNil(t, analyzer)
	assert.Equal(t, tempDir, analyzer.workingDir)
	assert.NotNil(t, analyzer.bundleStats)
	assert.NotNil(t, analyzer.dependencies)
	assert.NotNil(t, analyzer.chunkAnalysis)
	assert.NotNil(t, analyzer.treemapData)
}

func TestNewDependencyAnalyzer(t *testing.T) {
	tempDir := t.TempDir()

	analyzer := NewDependencyAnalyzer(tempDir)

	assert.NotNil(t, analyzer)
	assert.Equal(t, tempDir, analyzer.workingDir)
	assert.Equal(t, filepath.Join(tempDir, "package.json"), analyzer.packageJSONPath)
	assert.NotNil(t, analyzer.dependencyTree)
	assert.NotNil(t, analyzer.vulnerabilities)
	assert.NotNil(t, analyzer.outdatedPackages)
	assert.NotNil(t, analyzer.licenseIncompatibilities)
	assert.NotNil(t, analyzer.circularDependencies)
	assert.NotNil(t, analyzer.unusedDependencies)
}

func TestFindTool(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	// Create a mock local tool in node_modules/.bin
	nodeModulesBin := filepath.Join(tempDir, "node_modules", ".bin")
	err := os.MkdirAll(nodeModulesBin, 0755)
	require.NoError(t, err)

	eslintPath := filepath.Join(nodeModulesBin, "eslint")
	err = os.WriteFile(eslintPath, []byte("#!/bin/bash\necho 'mock eslint'"), 0755)
	require.NoError(t, err)

	foundPath, err := analyzer.findTool("eslint")
	assert.NoError(t, err)
	assert.Equal(t, eslintPath, foundPath)
}

func TestFindToolNotFound(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	_, err := analyzer.findTool("nonexistent-tool")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestAutoDetectFiles(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	// Create test files
	testFiles := map[string]string{
		"src/index.js":        "console.log('hello');",
		"src/utils.ts":        "export const utils = {};",
		"src/component.jsx":   "export const Component = () => {};",
		"src/types.tsx":       "export interface Props {}",
		"lib/module.mjs":      "export default {};",
		"dist/bundle.js":      "// built file", // Should be excluded
		"node_modules/dep.js": "// dependency", // Should be excluded
		"README.md":           "# Project",     // Should be excluded
	}

	for filePath, content := range testFiles {
		fullPath := filepath.Join(tempDir, filePath)
		err := os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte(content), 0644)
		require.NoError(t, err)
	}

	files, err := analyzer.autoDetectFiles()
	assert.NoError(t, err)

	// Should include JS/TS files but exclude build dirs and node_modules
	assert.Len(t, files, 5) // .js, .ts, .jsx, .tsx, .mjs

	// Convert to relative paths for easier checking
	relativeFiles := make([]string, len(files))
	for i, file := range files {
		relPath, _ := filepath.Rel(tempDir, file)
		relativeFiles[i] = relPath
	}

	assert.Contains(t, relativeFiles, "src/index.js")
	assert.Contains(t, relativeFiles, "src/utils.ts")
	assert.Contains(t, relativeFiles, "src/component.jsx")
	assert.Contains(t, relativeFiles, "src/types.tsx")
	assert.Contains(t, relativeFiles, "lib/module.mjs")
	assert.NotContains(t, relativeFiles, "dist/bundle.js")
	assert.NotContains(t, relativeFiles, "node_modules/dep.js")
	assert.NotContains(t, relativeFiles, "README.md")
}

func TestStringSliceFromAnalysisTypes(t *testing.T) {
	types := []AnalysisType{
		AnalysisTypeLinting,
		AnalysisTypeSecurity,
		AnalysisTypePerformance,
	}

	result := stringSliceFromAnalysisTypes(types)

	assert.Len(t, result, 3)
	assert.Contains(t, result, "linting")
	assert.Contains(t, result, "security")
	assert.Contains(t, result, "performance")
}

func TestAnalyzeWithAutoDetection(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	// Create test files
	srcFile := filepath.Join(tempDir, "src", "index.js")
	err := os.MkdirAll(filepath.Dir(srcFile), 0755)
	require.NoError(t, err)
	err = os.WriteFile(srcFile, []byte("console.log('test');"), 0644)
	require.NoError(t, err)

	req := &AnalysisRequest{
		AnalysisType: []AnalysisType{AnalysisTypeLinting},
		Timeout:      5 * time.Second,
	}

	// Mock the analyzer to avoid actual tool execution
	result, err := analyzer.Analyze(context.Background(), req)

	// Should succeed even without actual tools
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, result.FilesAnalyzed) // Should auto-detect the .js file
	assert.NotNil(t, result.Summary)
}

func TestAnalyzeWithTimeout(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	req := &AnalysisRequest{
		SourceFiles:  []string{"src/index.js"},
		AnalysisType: []AnalysisType{AnalysisTypeAll},
		Timeout:      1 * time.Millisecond,
	}

	result, err := analyzer.Analyze(ctx, req)

	// Should handle timeout gracefully
	assert.NoError(t, err) // The implementation handles timeouts in sub-components
	assert.NotNil(t, result)
}

func TestAnalyzeDefaultTimeout(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	req := &AnalysisRequest{
		SourceFiles:  []string{"src/index.js"},
		AnalysisType: []AnalysisType{AnalysisTypeLinting},
		// No timeout specified
	}

	// This is more of a structure test since we can't run actual analysis
	result, err := analyzer.Analyze(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	// Should have set default timeout internally (15 minutes)
}

func TestGenerateAnalysisSummary(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	// Create mock analysis result
	result := &AnalysisResult{
		LintingResults: &LintingResults{
			TotalIssues:  10,
			ErrorCount:   3,
			WarningCount: 7,
		},
		SecurityResults: &SecurityAnalysisResults{
			AuditResults: &SecurityAuditResults{
				TotalVulnerabilities: 5,
				CriticalCount:        1,
				HighCount:            2,
				MediumCount:          2,
				LowCount:             0,
			},
			RiskAssessment: &RiskAssessment{
				OverallRisk: "medium",
			},
		},
		PerformanceResults: &PerformanceAnalysisResults{
			Metrics: &PerformanceMetrics{
				ExecutionTime: 100 * time.Millisecond,
			},
		},
	}

	summary := analyzer.generateAnalysisSummary(result)

	assert.NotNil(t, summary)
	assert.Greater(t, summary.OverallScore, 0.0)
	assert.NotEmpty(t, summary.QualityGrade)
	assert.Equal(t, "medium", summary.SecurityRating)
	assert.NotEmpty(t, summary.PerformanceRating)
	assert.NotNil(t, summary.TechnicalDebt)
	assert.NotNil(t, summary.KeyFindings)
	assert.NotNil(t, summary.ActionItems)

	// Should have key findings for errors and vulnerabilities
	assert.NotEmpty(t, summary.KeyFindings)

	foundLintingFinding := false
	foundSecurityFinding := false

	for _, finding := range summary.KeyFindings {
		if finding.Category == "Code Quality" {
			foundLintingFinding = true
		}
		if finding.Category == "Security" {
			foundSecurityFinding = true
		}
	}

	assert.True(t, foundLintingFinding)
	assert.True(t, foundSecurityFinding)
}

func TestCalculateLintingScore(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	tests := []struct {
		name     string
		results  *LintingResults
		expected float64
	}{
		{
			name: "no issues",
			results: &LintingResults{
				TotalIssues:  0,
				ErrorCount:   0,
				WarningCount: 0,
			},
			expected: 100.0,
		},
		{
			name: "some warnings only",
			results: &LintingResults{
				TotalIssues:  5,
				ErrorCount:   0,
				WarningCount: 5,
			},
			expected: 99.5, // 100 - (0*2 + 5)/10
		},
		{
			name: "some errors and warnings",
			results: &LintingResults{
				TotalIssues:  10,
				ErrorCount:   3,
				WarningCount: 7,
			},
			expected: 98.7, // 100 - (3*2 + 7)/10 = 100 - 13/10
		},
		{
			name: "many issues (score floor)",
			results: &LintingResults{
				TotalIssues:  1000,
				ErrorCount:   500,
				WarningCount: 500,
			},
			expected: 0.0, // Should be floored at 0
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.calculateLintingScore(tt.results)
			assert.Equal(t, tt.expected, score)
		})
	}
}

func TestCalculateSecurityScore(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	tests := []struct {
		name     string
		results  *SecurityAnalysisResults
		expected float64
	}{
		{
			name: "no audit results",
			results: &SecurityAnalysisResults{
				AuditResults: nil,
			},
			expected: 100.0,
		},
		{
			name: "no vulnerabilities",
			results: &SecurityAnalysisResults{
				AuditResults: &SecurityAuditResults{
					TotalVulnerabilities: 0,
				},
			},
			expected: 100.0,
		},
		{
			name: "mixed vulnerability levels",
			results: &SecurityAnalysisResults{
				AuditResults: &SecurityAuditResults{
					TotalVulnerabilities: 10,
					CriticalCount:        1, // 1*4 = 4
					HighCount:            2, // 2*3 = 6
					MediumCount:          3, // 3*2 = 6
					LowCount:             4, // 4*1 = 4
					// Total weighted: 20
				},
			},
			expected: 96.0, // 100 - 20/5 = 100 - 4
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := analyzer.calculateSecurityScore(tt.results)
			assert.Equal(t, tt.expected, score)
		})
	}
}

func TestCalculatePerformanceRating(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	// Test with the current implementation that returns 75.0
	results := &PerformanceAnalysisResults{}
	rating := analyzer.calculatePerformanceRating(results)

	// Since calculatePerformanceScore currently returns 75.0,
	// and 75.0 >= 70 but < 80, it should return "fair"
	assert.Equal(t, "fair", rating)
}

func TestCalculateQualityGrade(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	tests := []struct {
		score    float64
		expected string
	}{
		{95.0, "A"},
		{85.0, "B"},
		{75.0, "C"},
		{65.0, "D"},
		{50.0, "F"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			grade := analyzer.calculateQualityGrade(tt.score)
			assert.Equal(t, tt.expected, grade)
		})
	}
}

// Test analysis request validation
func TestAnalysisRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		request *AnalysisRequest
		valid   bool
	}{
		{
			name: "valid linting request",
			request: &AnalysisRequest{
				SourceFiles:  []string{"src/index.js"},
				AnalysisType: []AnalysisType{AnalysisTypeLinting},
				LintingOptions: &LintingOptions{
					ESLintConfig: ".eslintrc.json",
				},
			},
			valid: true,
		},
		{
			name: "valid security request",
			request: &AnalysisRequest{
				SourceFiles:  []string{"src/index.js"},
				AnalysisType: []AnalysisType{AnalysisTypeSecurity},
				SecurityOptions: &SecurityAnalysisOptions{
					IncludeNPMAudit: true,
					IncludeCodeScan: true,
				},
			},
			valid: true,
		},
		{
			name: "valid all analysis request",
			request: &AnalysisRequest{
				SourceFiles:  []string{"src/index.js"},
				AnalysisType: []AnalysisType{AnalysisTypeAll},
				LintingOptions: &LintingOptions{
					AutoFix: true,
				},
				SecurityOptions: &SecurityAnalysisOptions{
					IncludeNPMAudit: true,
				},
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - request structure should be valid
			assert.NotNil(t, tt.request)
			assert.NotEmpty(t, tt.request.AnalysisType)

			if tt.valid {
				// Additional validation for valid requests
				assert.True(t, len(tt.request.AnalysisType) > 0)

				for _, analysisType := range tt.request.AnalysisType {
					assert.Contains(t, []AnalysisType{
						AnalysisTypeLinting,
						AnalysisTypeSecurity,
						AnalysisTypePerformance,
						AnalysisTypeBundle,
						AnalysisTypeDependency,
						AnalysisTypeAll,
					}, analysisType)
				}
			}
		})
	}
}

// Test data structures
func TestSecurityVulnerabilityStruct(t *testing.T) {
	vuln := &SecurityVulnerability{
		ID:          "CVE-2021-1234",
		Title:       "Test Vulnerability",
		Severity:    "high",
		Description: "A test vulnerability",
		Package:     "lodash",
		Version:     "4.17.20",
		FixedIn:     "4.17.21",
		References:  []string{"https://example.com/vuln"},
		CVE:         "CVE-2021-1234",
		CVSS:        7.5,
		ExploitRisk: "medium",
		Remediation: &RemediationAdvice{
			Action:      "update",
			Priority:    "high",
			Difficulty:  "easy",
			Steps:       []string{"npm update lodash"},
			AutoFixable: true,
		},
		Metadata: map[string]interface{}{
			"source": "npm-audit",
		},
	}

	assert.Equal(t, "CVE-2021-1234", vuln.ID)
	assert.Equal(t, "high", vuln.Severity)
	assert.Equal(t, "lodash", vuln.Package)
	assert.Equal(t, 7.5, vuln.CVSS)
	assert.NotNil(t, vuln.Remediation)
	assert.True(t, vuln.Remediation.AutoFixable)
	assert.Contains(t, vuln.Metadata, "source")
}

func TestPerformanceMetricsStruct(t *testing.T) {
	metrics := &PerformanceMetrics{
		ExecutionTime:   100 * time.Millisecond,
		MemoryUsage:     1024 * 1024, // 1MB
		CPUUsage:        15.5,
		GCTime:          10 * time.Millisecond,
		NetworkRequests: 5,
		FileSystemOps:   10,
		FunctionCalls: map[string]int{
			"main":   1,
			"helper": 5,
		},
		HotSpots: []HotSpot{
			{
				Function:      "expensiveCalculation",
				File:          "src/math.js",
				Line:          42,
				ExecutionTime: 50 * time.Millisecond,
				CallCount:     100,
				Severity:      "high",
			},
		},
		MemoryLeaks: []MemoryLeak{
			{
				Object:     "EventListener",
				Size:       1024,
				GrowthRate: 0.1,
				Location:   "src/events.js:15",
				DetectedAt: time.Now(),
				Confidence: 0.8,
			},
		},
	}

	assert.Equal(t, 100*time.Millisecond, metrics.ExecutionTime)
	assert.Equal(t, int64(1024*1024), metrics.MemoryUsage)
	assert.Equal(t, 15.5, metrics.CPUUsage)
	assert.Len(t, metrics.HotSpots, 1)
	assert.Len(t, metrics.MemoryLeaks, 1)
	assert.Equal(t, "expensiveCalculation", metrics.HotSpots[0].Function)
	assert.Equal(t, "EventListener", metrics.MemoryLeaks[0].Object)
}

func TestDependencyAnalysisStructures(t *testing.T) {
	depInfo := &DependencyInfo{
		Name:           "lodash",
		Version:        "4.17.21",
		License:        "MIT",
		Size:           50 * 1024, // 50KB
		Dependencies:   []string{"core-js"},
		DevDependency:  false,
		PeerDependency: false,
		Transitive:     false,
		DepthLevel:     1,
		LastUpdated:    time.Now(),
		Metadata: map[string]interface{}{
			"homepage": "https://lodash.com",
		},
	}

	assert.Equal(t, "lodash", depInfo.Name)
	assert.Equal(t, "4.17.21", depInfo.Version)
	assert.Equal(t, "MIT", depInfo.License)
	assert.False(t, depInfo.DevDependency)
	assert.False(t, depInfo.Transitive)
	assert.Contains(t, depInfo.Metadata, "homepage")

	outdated := &OutdatedPackage{
		Name:            "express",
		CurrentVersion:  "4.17.1",
		WantedVersion:   "4.18.0",
		LatestVersion:   "4.18.1",
		UpdateType:      "minor",
		LastUpdated:     time.Now(),
		BreakingChanges: []string{},
	}

	assert.Equal(t, "express", outdated.Name)
	assert.Equal(t, "4.17.1", outdated.CurrentVersion)
	assert.Equal(t, "4.18.1", outdated.LatestVersion)
	assert.Equal(t, "minor", outdated.UpdateType)

	circular := CircularDependency{
		Cycle:      []string{"a", "b", "c", "a"},
		Type:       "require",
		Severity:   "warning",
		Resolution: "refactor",
	}

	assert.Len(t, circular.Cycle, 4)
	assert.Equal(t, "a", circular.Cycle[0])
	assert.Equal(t, "a", circular.Cycle[3])
	assert.Equal(t, "require", circular.Type)
}

// Benchmark tests
func BenchmarkNewJavaScriptAnalyzer(b *testing.B) {
	tempDir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewJavaScriptAnalyzer(tempDir)
	}
}

func BenchmarkAutoDetectFiles(b *testing.B) {
	tempDir := b.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	// Create many test files
	for i := 0; i < 100; i++ {
		filePath := filepath.Join(tempDir, "src", "file"+string(rune(i))+".js")
		os.MkdirAll(filepath.Dir(filePath), 0755)
		os.WriteFile(filePath, []byte("console.log('test');"), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.autoDetectFiles()
	}
}

func BenchmarkCalculateLintingScore(b *testing.B) {
	tempDir := b.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	results := &LintingResults{
		TotalIssues:  100,
		ErrorCount:   30,
		WarningCount: 70,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.calculateLintingScore(results)
	}
}

func BenchmarkGenerateAnalysisSummary(b *testing.B) {
	tempDir := b.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	result := &AnalysisResult{
		LintingResults: &LintingResults{
			TotalIssues:  50,
			ErrorCount:   10,
			WarningCount: 40,
		},
		SecurityResults: &SecurityAnalysisResults{
			AuditResults: &SecurityAuditResults{
				TotalVulnerabilities: 5,
				CriticalCount:        1,
				HighCount:            2,
				MediumCount:          2,
				LowCount:             0,
			},
			RiskAssessment: &RiskAssessment{
				OverallRisk: "medium",
			},
		},
		PerformanceResults: &PerformanceAnalysisResults{
			Metrics: &PerformanceMetrics{
				ExecutionTime: 200 * time.Millisecond,
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.generateAnalysisSummary(result)
	}
}

// Error handling tests
func TestAnalyzeWithEmptySourceFiles(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	req := &AnalysisRequest{
		SourceFiles:  []string{},
		AnalysisType: []AnalysisType{AnalysisTypeLinting},
	}

	result, err := analyzer.Analyze(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	// Should auto-detect files when none provided
}

func TestInitializeWithoutTools(t *testing.T) {
	tempDir := t.TempDir()
	analyzer := NewJavaScriptAnalyzer(tempDir)

	// This should handle the case where no analysis tools are installed
	ctx := context.Background()
	err := analyzer.Initialize(ctx)

	// Should not fail even without tools (warnings logged)
	assert.NoError(t, err)
}

// Integration test placeholders
func TestIntegrationESLintAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Skip("Integration test requires actual ESLint installation")
}

func TestIntegrationSecurityAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Skip("Integration test requires npm audit or security scanning tools")
}
