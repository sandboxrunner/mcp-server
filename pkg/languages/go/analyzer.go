package go_lang

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// AnalysisConfig represents analysis configuration
type AnalysisConfig struct {
	Packages        []string          `json:"packages"`           // Packages to analyze
	Tags            []string          `json:"tags"`               // Build tags
	EnableVet       bool              `json:"enable_vet"`         // Enable go vet
	EnableRace      bool              `json:"enable_race"`        // Enable race detection
	EnableEscape    bool              `json:"enable_escape"`      // Enable escape analysis
	EnableInlining  bool              `json:"enable_inlining"`    // Enable inlining analysis
	EnableCPUProf   bool              `json:"enable_cpu_prof"`    // Enable CPU profiling
	EnableMemProf   bool              `json:"enable_mem_prof"`    // Enable memory profiling
	EnableBlockProf bool              `json:"enable_block_prof"`  // Enable block profiling
	EnableMutexProf bool              `json:"enable_mutex_prof"`  // Enable mutex profiling
	EnableTrace     bool              `json:"enable_trace"`       // Enable execution tracing
	StaticCheck     StaticCheckConfig `json:"static_check"`       // Staticcheck configuration
	GolangCILint    GolangCIConfig    `json:"golangci_lint"`      // GolangCI-lint configuration
	ImportAnalysis  ImportConfig      `json:"import_analysis"`    // Import analysis configuration
	CodeGen         CodeGenConfig     `json:"code_gen"`           // Code generation configuration
	WorkDir         string            `json:"work_dir"`           // Working directory
	Environment     map[string]string `json:"environment"`        // Additional environment variables
	Timeout         time.Duration     `json:"timeout"`            // Analysis timeout
	Parallel        int               `json:"parallel"`           // Number of parallel analyses
	Verbose         bool              `json:"verbose"`            // Verbose output
}

// StaticCheckConfig represents staticcheck configuration
type StaticCheckConfig struct {
	Enabled     bool     `json:"enabled"`
	Checks      []string `json:"checks"`       // Specific checks to enable (e.g., "SA1019")
	ConfigFile  string   `json:"config_file"`  // Path to staticcheck.conf
	FailOnNoise bool     `json:"fail_on_noise"` // Fail on noise (unactionable reports)
	GoVersion   string   `json:"go_version"`   // Target Go version
	Unused      bool     `json:"unused"`       // Enable unused analysis
	Explains    []string `json:"explains"`     // Explain specific checks
}

// GolangCIConfig represents golangci-lint configuration
type GolangCIConfig struct {
	Enabled        bool     `json:"enabled"`
	ConfigFile     string   `json:"config_file"`     // Path to .golangci.yml
	EnableAll      bool     `json:"enable_all"`      // Enable all linters
	DisableAll     bool     `json:"disable_all"`     // Disable all linters
	EnabledLinters []string `json:"enabled_linters"` // Specific linters to enable
	DisabledLinters []string `json:"disabled_linters"` // Specific linters to disable
	SkipDirs       []string `json:"skip_dirs"`       // Directories to skip
	SkipFiles      []string `json:"skip_files"`      // Files to skip
	Timeout        string   `json:"timeout"`         // Timeout for golangci-lint
	IssuesExitCode int      `json:"issues_exit_code"` // Exit code when issues are found
	Fast           bool     `json:"fast"`            // Fast mode
}

// ImportConfig represents import analysis configuration
type ImportConfig struct {
	Enabled         bool     `json:"enabled"`
	UnusedImports   bool     `json:"unused_imports"`   // Find unused imports
	CircularImports bool     `json:"circular_imports"` // Find circular imports
	StdlibOnly      bool     `json:"stdlib_only"`      // Analyze only stdlib imports
	ExternalOnly    bool     `json:"external_only"`    // Analyze only external imports
	DepthLimit      int      `json:"depth_limit"`      // Maximum import depth
	ExcludePatterns []string `json:"exclude_patterns"` // Patterns to exclude
}

// CodeGenConfig represents code generation configuration
type CodeGenConfig struct {
	Enabled      bool     `json:"enabled"`
	GoGenerate   bool     `json:"go_generate"`   // Run go generate
	Protobuf     bool     `json:"protobuf"`      // Generate protobuf code
	Swagger      bool     `json:"swagger"`       // Generate swagger docs
	Mockery      bool     `json:"mockery"`       // Generate mocks
	Stringer     bool     `json:"stringer"`      // Generate string methods
	JSONEnums    bool     `json:"json_enums"`    // Generate JSON enum methods
	GoStruct     bool     `json:"go_struct"`     // Generate struct tags
	Templates    []string `json:"templates"`     // Custom template files
	OutputDir    string   `json:"output_dir"`    // Output directory for generated code
}

// AnalysisResult represents analysis results
type AnalysisResult struct {
	Success       bool                   `json:"success"`
	Duration      time.Duration          `json:"duration"`
	VetResults    []VetIssue             `json:"vet_results,omitempty"`
	StaticResults []StaticCheckIssue     `json:"static_results,omitempty"`
	LintResults   []LintIssue            `json:"lint_results,omitempty"`
	ImportResults []ImportIssue          `json:"import_results,omitempty"`
	ProfileResults map[string]string     `json:"profile_results,omitempty"`
	CodeGenResults []CodeGenResult       `json:"codegen_results,omitempty"`
	Summary       AnalysisSummary        `json:"summary"`
	Errors        []string               `json:"errors"`
	Warnings      []string               `json:"warnings"`
	RawOutput     map[string]string      `json:"raw_output,omitempty"`
}

// VetIssue represents a go vet issue
type VetIssue struct {
	Package  string `json:"package"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Analyzer string `json:"analyzer"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// StaticCheckIssue represents a staticcheck issue
type StaticCheckIssue struct {
	Package  string   `json:"package"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	Check    string   `json:"check"`
	Message  string   `json:"message"`
	Severity string   `json:"severity"`
	Related  []string `json:"related,omitempty"`
}

// LintIssue represents a linter issue
type LintIssue struct {
	Package     string `json:"package"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Linter      string `json:"linter"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	Rule        string `json:"rule,omitempty"`
	Replacement string `json:"replacement,omitempty"`
}

// ImportIssue represents an import analysis issue
type ImportIssue struct {
	Package     string   `json:"package"`
	File        string   `json:"file"`
	Import      string   `json:"import"`
	Type        string   `json:"type"` // unused, circular, depth, etc.
	Message     string   `json:"message"`
	Suggestions []string `json:"suggestions,omitempty"`
	Chain       []string `json:"chain,omitempty"` // For circular imports
}

// CodeGenResult represents code generation results
type CodeGenResult struct {
	Tool      string   `json:"tool"`
	Success   bool     `json:"success"`
	Files     []string `json:"files"`     // Generated files
	Message   string   `json:"message"`
	Error     string   `json:"error,omitempty"`
	Duration  time.Duration `json:"duration"`
}

// AnalysisSummary represents overall analysis summary
type AnalysisSummary struct {
	TotalIssues    int `json:"total_issues"`
	VetIssues      int `json:"vet_issues"`
	StaticIssues   int `json:"static_issues"`
	LintIssues     int `json:"lint_issues"`
	ImportIssues   int `json:"import_issues"`
	CriticalIssues int `json:"critical_issues"`
	WarningIssues  int `json:"warning_issues"`
	InfoIssues     int `json:"info_issues"`
	FilesAnalyzed  int `json:"files_analyzed"`
	PackagesAnalyzed int `json:"packages_analyzed"`
}

// Analyzer handles Go code analysis
type Analyzer struct {
	workingDir string
	config     *AnalysisConfig
	verbose    bool
}

// NewAnalyzer creates a new Go analyzer
func NewAnalyzer(workingDir string) *Analyzer {
	return &Analyzer{
		workingDir: workingDir,
		config:     NewDefaultAnalysisConfig(),
		verbose:    false,
	}
}

// NewDefaultAnalysisConfig creates a default analysis configuration
func NewDefaultAnalysisConfig() *AnalysisConfig {
	return &AnalysisConfig{
		Packages:        []string{"./..."},
		EnableVet:       true,
		EnableRace:      false,
		EnableEscape:    false,
		EnableInlining:  false,
		EnableCPUProf:   false,
		EnableMemProf:   false,
		EnableBlockProf: false,
		EnableMutexProf: false,
		EnableTrace:     false,
		StaticCheck: StaticCheckConfig{
			Enabled: false,
			Checks:  []string{},
		},
		GolangCILint: GolangCIConfig{
			Enabled: false,
		},
		ImportAnalysis: ImportConfig{
			Enabled:         false,
			UnusedImports:   true,
			CircularImports: true,
			DepthLimit:      10,
		},
		CodeGen: CodeGenConfig{
			Enabled:    false,
			GoGenerate: true,
		},
		Environment: make(map[string]string),
		Timeout:     10 * time.Minute,
		Parallel:    runtime.NumCPU(),
		Verbose:     false,
	}
}

// SetConfig sets the analysis configuration
func (a *Analyzer) SetConfig(config *AnalysisConfig) {
	a.config = config
}

// SetVerbose enables verbose output
func (a *Analyzer) SetVerbose(verbose bool) {
	a.verbose = verbose
}

// Analyze performs comprehensive code analysis
func (a *Analyzer) Analyze(ctx context.Context) (*AnalysisResult, error) {
	startTime := time.Now()

	log.Debug().
		Str("working_dir", a.workingDir).
		Strs("packages", a.config.Packages).
		Msg("Starting Go analysis")

	result := &AnalysisResult{
		VetResults:     []VetIssue{},
		StaticResults:  []StaticCheckIssue{},
		LintResults:    []LintIssue{},
		ImportResults:  []ImportIssue{},
		ProfileResults: make(map[string]string),
		CodeGenResults: []CodeGenResult{},
		Errors:         []string{},
		Warnings:       []string{},
		RawOutput:      make(map[string]string),
		Summary:        AnalysisSummary{},
	}

	// Run go vet analysis
	if a.config.EnableVet {
		if err := a.runVetAnalysis(ctx, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Vet analysis failed: %v", err))
		}
	}

	// Run staticcheck analysis
	if a.config.StaticCheck.Enabled {
		if err := a.runStaticCheckAnalysis(ctx, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Staticcheck analysis failed: %v", err))
		}
	}

	// Run golangci-lint analysis
	if a.config.GolangCILint.Enabled {
		if err := a.runGolangCILintAnalysis(ctx, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("GolangCI-lint analysis failed: %v", err))
		}
	}

	// Run import analysis
	if a.config.ImportAnalysis.Enabled {
		if err := a.runImportAnalysis(ctx, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Import analysis failed: %v", err))
		}
	}

	// Run profiling analysis
	if a.config.EnableCPUProf || a.config.EnableMemProf || a.config.EnableBlockProf ||
		a.config.EnableMutexProf || a.config.EnableTrace {
		if err := a.runProfilingAnalysis(ctx, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Profiling analysis failed: %v", err))
		}
	}

	// Run code generation
	if a.config.CodeGen.Enabled {
		if err := a.runCodeGeneration(ctx, result); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Code generation failed: %v", err))
		}
	}

	// Calculate summary
	a.calculateSummary(result)

	result.Duration = time.Since(startTime)
	result.Success = len(result.Errors) == 0

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Int("total_issues", result.Summary.TotalIssues).
		Msg("Analysis completed")

	return result, nil
}

// RunVetOnly runs only go vet analysis
func (a *Analyzer) RunVetOnly(ctx context.Context) (*AnalysisResult, error) {
	oldConfig := a.config
	defer func() { a.config = oldConfig }()

	// Temporarily disable other analyses
	a.config.StaticCheck.Enabled = false
	a.config.GolangCILint.Enabled = false
	a.config.ImportAnalysis.Enabled = false
	a.config.CodeGen.Enabled = false

	return a.Analyze(ctx)
}

// RunRaceDetection runs race detection analysis
func (a *Analyzer) RunRaceDetection(ctx context.Context) (*AnalysisResult, error) {
	log.Debug().Msg("Running race detection analysis")

	cmd := exec.CommandContext(ctx, "go", "test", "-race", "./...")
	cmd.Dir = a.workingDir
	cmd.Env = a.buildEnvironment()

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	result := &AnalysisResult{
		RawOutput: map[string]string{"race": outputStr},
		Summary:   AnalysisSummary{},
	}

	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("Race detection failed: %v", err))
		// Parse race detection output for issues
		a.parseRaceDetectionOutput(outputStr, result)
	} else {
		result.Success = true
	}

	return result, nil
}

// runVetAnalysis runs go vet analysis
func (a *Analyzer) runVetAnalysis(ctx context.Context, result *AnalysisResult) error {
	log.Debug().Msg("Running go vet analysis")

	args := []string{"vet"}
	if len(a.config.Tags) > 0 {
		args = append(args, "-tags", strings.Join(a.config.Tags, ","))
	}
	args = append(args, a.config.Packages...)

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = a.workingDir
	cmd.Env = a.buildEnvironment()

	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	result.RawOutput["vet"] = outputStr

	// Parse vet output
	a.parseVetOutput(outputStr, result)

	if err != nil && len(result.VetResults) == 0 {
		return fmt.Errorf("vet execution failed: %w", err)
	}

	return nil
}

// runStaticCheckAnalysis runs staticcheck analysis
func (a *Analyzer) runStaticCheckAnalysis(ctx context.Context, result *AnalysisResult) error {
	log.Debug().Msg("Running staticcheck analysis")

	// Check if staticcheck is available
	if _, err := exec.LookPath("staticcheck"); err != nil {
		return fmt.Errorf("staticcheck not found: %w", err)
	}

	args := []string{}
	
	if len(a.config.StaticCheck.Checks) > 0 {
		args = append(args, "-checks", strings.Join(a.config.StaticCheck.Checks, ","))
	}
	
	if a.config.StaticCheck.ConfigFile != "" {
		args = append(args, "-config", a.config.StaticCheck.ConfigFile)
	}
	
	if a.config.StaticCheck.FailOnNoise {
		args = append(args, "-fail", "noise")
	}
	
	if a.config.StaticCheck.GoVersion != "" {
		args = append(args, "-go", a.config.StaticCheck.GoVersion)
	}
	
	if len(a.config.Tags) > 0 {
		args = append(args, "-tags", strings.Join(a.config.Tags, ","))
	}

	args = append(args, a.config.Packages...)

	cmd := exec.CommandContext(ctx, "staticcheck", args...)
	cmd.Dir = a.workingDir
	cmd.Env = a.buildEnvironment()

	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	result.RawOutput["staticcheck"] = outputStr

	// Parse staticcheck output
	a.parseStaticCheckOutput(outputStr, result)

	if err != nil && len(result.StaticResults) == 0 {
		return fmt.Errorf("staticcheck execution failed: %w", err)
	}

	return nil
}

// runGolangCILintAnalysis runs golangci-lint analysis
func (a *Analyzer) runGolangCILintAnalysis(ctx context.Context, result *AnalysisResult) error {
	log.Debug().Msg("Running golangci-lint analysis")

	// Check if golangci-lint is available
	if _, err := exec.LookPath("golangci-lint"); err != nil {
		return fmt.Errorf("golangci-lint not found: %w", err)
	}

	args := []string{"run"}
	
	if a.config.GolangCILint.ConfigFile != "" {
		args = append(args, "-c", a.config.GolangCILint.ConfigFile)
	}
	
	if a.config.GolangCILint.EnableAll {
		args = append(args, "--enable-all")
	}
	
	if a.config.GolangCILint.DisableAll {
		args = append(args, "--disable-all")
	}
	
	if len(a.config.GolangCILint.EnabledLinters) > 0 {
		args = append(args, "--enable", strings.Join(a.config.GolangCILint.EnabledLinters, ","))
	}
	
	if len(a.config.GolangCILint.DisabledLinters) > 0 {
		args = append(args, "--disable", strings.Join(a.config.GolangCILint.DisabledLinters, ","))
	}
	
	if len(a.config.GolangCILint.SkipDirs) > 0 {
		args = append(args, "--skip-dirs", strings.Join(a.config.GolangCILint.SkipDirs, ","))
	}
	
	if len(a.config.GolangCILint.SkipFiles) > 0 {
		args = append(args, "--skip-files", strings.Join(a.config.GolangCILint.SkipFiles, ","))
	}
	
	if a.config.GolangCILint.Timeout != "" {
		args = append(args, "--timeout", a.config.GolangCILint.Timeout)
	}
	
	if a.config.GolangCILint.Fast {
		args = append(args, "--fast")
	}
	
	if len(a.config.Tags) > 0 {
		args = append(args, "--build-tags", strings.Join(a.config.Tags, ","))
	}

	args = append(args, "--out-format", "json")
	args = append(args, a.config.Packages...)

	cmd := exec.CommandContext(ctx, "golangci-lint", args...)
	cmd.Dir = a.workingDir
	cmd.Env = a.buildEnvironment()

	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	result.RawOutput["golangci-lint"] = outputStr

	// Parse golangci-lint output
	a.parseGolangCILintOutput(outputStr, result)

	if err != nil && len(result.LintResults) == 0 {
		// golangci-lint returns non-zero exit code when issues are found
		if a.config.GolangCILint.IssuesExitCode > 0 {
			return nil // Expected behavior
		}
		return fmt.Errorf("golangci-lint execution failed: %w", err)
	}

	return nil
}

// runImportAnalysis runs import analysis
func (a *Analyzer) runImportAnalysis(ctx context.Context, result *AnalysisResult) error {
	log.Debug().Msg("Running import analysis")

	// Analyze unused imports
	if a.config.ImportAnalysis.UnusedImports {
		if err := a.analyzeUnusedImports(ctx, result); err != nil {
			log.Warn().Err(err).Msg("Failed to analyze unused imports")
		}
	}

	// Analyze circular imports
	if a.config.ImportAnalysis.CircularImports {
		if err := a.analyzeCircularImports(ctx, result); err != nil {
			log.Warn().Err(err).Msg("Failed to analyze circular imports")
		}
	}

	return nil
}

// runProfilingAnalysis runs profiling analysis
func (a *Analyzer) runProfilingAnalysis(ctx context.Context, result *AnalysisResult) error {
	log.Debug().Msg("Running profiling analysis")

	// This would typically involve running tests with profiling enabled
	// and then analyzing the resulting profiles
	args := []string{"test", "-bench", ".", "-run", "^$"}

	if a.config.EnableCPUProf {
		cpuProfile := filepath.Join(a.workingDir, "cpu.prof")
		args = append(args, "-cpuprofile", cpuProfile)
		result.ProfileResults["cpu"] = cpuProfile
	}

	if a.config.EnableMemProf {
		memProfile := filepath.Join(a.workingDir, "mem.prof")
		args = append(args, "-memprofile", memProfile)
		result.ProfileResults["memory"] = memProfile
	}

	if a.config.EnableBlockProf {
		blockProfile := filepath.Join(a.workingDir, "block.prof")
		args = append(args, "-blockprofile", blockProfile)
		result.ProfileResults["block"] = blockProfile
	}

	if a.config.EnableMutexProf {
		mutexProfile := filepath.Join(a.workingDir, "mutex.prof")
		args = append(args, "-mutexprofile", mutexProfile)
		result.ProfileResults["mutex"] = mutexProfile
	}

	if a.config.EnableTrace {
		traceFile := filepath.Join(a.workingDir, "trace.out")
		args = append(args, "-trace", traceFile)
		result.ProfileResults["trace"] = traceFile
	}

	args = append(args, a.config.Packages...)

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = a.workingDir
	cmd.Env = a.buildEnvironment()

	output, err := cmd.CombinedOutput()
	result.RawOutput["profiling"] = string(output)

	if err != nil {
		return fmt.Errorf("profiling failed: %w", err)
	}

	return nil
}

// runCodeGeneration runs code generation
func (a *Analyzer) runCodeGeneration(ctx context.Context, result *AnalysisResult) error {
	log.Debug().Msg("Running code generation")

	if a.config.CodeGen.GoGenerate {
		if err := a.runGoGenerate(ctx, result); err != nil {
			log.Warn().Err(err).Msg("go generate failed")
		}
	}

	return nil
}

// runGoGenerate runs go generate
func (a *Analyzer) runGoGenerate(ctx context.Context, result *AnalysisResult) error {
	startTime := time.Now()

	cmd := exec.CommandContext(ctx, "go", "generate", "./...")
	cmd.Dir = a.workingDir
	cmd.Env = a.buildEnvironment()

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	genResult := CodeGenResult{
		Tool:     "go generate",
		Success:  err == nil,
		Message:  outputStr,
		Duration: time.Since(startTime),
	}

	if err != nil {
		genResult.Error = err.Error()
	}

	result.CodeGenResults = append(result.CodeGenResults, genResult)
	return err
}

// parseVetOutput parses go vet output
func (a *Analyzer) parseVetOutput(output string, result *AnalysisResult) {
	lines := strings.Split(output, "\n")
	vetRegex := regexp.MustCompile(`^([^:]+):(\d+):(\d+):\s*(.+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := vetRegex.FindStringSubmatch(line)
		if len(matches) == 5 {
			lineNum, _ := strconv.Atoi(matches[2])
			colNum, _ := strconv.Atoi(matches[3])

			issue := VetIssue{
				File:     matches[1],
				Line:     lineNum,
				Column:   colNum,
				Message:  matches[4],
				Analyzer: "vet",
				Severity: "warning",
			}

			result.VetResults = append(result.VetResults, issue)
		}
	}
}

// parseStaticCheckOutput parses staticcheck output
func (a *Analyzer) parseStaticCheckOutput(output string, result *AnalysisResult) {
	lines := strings.Split(output, "\n")
	staticRegex := regexp.MustCompile(`^([^:]+):(\d+):(\d+):\s*([A-Z]+\d+):\s*(.+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := staticRegex.FindStringSubmatch(line)
		if len(matches) == 6 {
			lineNum, _ := strconv.Atoi(matches[2])
			colNum, _ := strconv.Atoi(matches[3])

			issue := StaticCheckIssue{
				File:     matches[1],
				Line:     lineNum,
				Column:   colNum,
				Check:    matches[4],
				Message:  matches[5],
				Severity: "warning",
			}

			result.StaticResults = append(result.StaticResults, issue)
		}
	}
}

// parseGolangCILintOutput parses golangci-lint JSON output
func (a *Analyzer) parseGolangCILintOutput(output string, result *AnalysisResult) {
	if output == "" {
		return
	}

	// Try to parse as JSON first
	var lintResult struct {
		Issues []struct {
			FromLinter  string `json:"FromLinter"`
			Text        string `json:"Text"`
			Severity    string `json:"Severity"`
			SourceLines []string `json:"SourceLines"`
			Replacement *struct {
				NewLines []string `json:"NewLines"`
			} `json:"Replacement"`
			Pos struct {
				Filename string `json:"Filename"`
				Offset   int    `json:"Offset"`
				Line     int    `json:"Line"`
				Column   int    `json:"Column"`
			} `json:"Pos"`
		} `json:"Issues"`
	}

	if err := json.Unmarshal([]byte(output), &lintResult); err == nil {
		for _, issue := range lintResult.Issues {
			lintIssue := LintIssue{
				File:     issue.Pos.Filename,
				Line:     issue.Pos.Line,
				Column:   issue.Pos.Column,
				Linter:   issue.FromLinter,
				Message:  issue.Text,
				Severity: issue.Severity,
			}

			if issue.Replacement != nil && len(issue.Replacement.NewLines) > 0 {
				lintIssue.Replacement = strings.Join(issue.Replacement.NewLines, "\n")
			}

			result.LintResults = append(result.LintResults, lintIssue)
		}
	}
}

// parseRaceDetectionOutput parses race detection output
func (a *Analyzer) parseRaceDetectionOutput(output string, result *AnalysisResult) {
	if strings.Contains(output, "WARNING: DATA RACE") {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "WARNING: DATA RACE") ||
				strings.Contains(line, "Write at") ||
				strings.Contains(line, "Read at") {
				result.Warnings = append(result.Warnings, line)
			}
		}
	}
}

// analyzeUnusedImports analyzes unused imports
func (a *Analyzer) analyzeUnusedImports(ctx context.Context, result *AnalysisResult) error {
	// This would typically use tools like goimports or custom analysis
	cmd := exec.CommandContext(ctx, "goimports", "-l", ".")
	cmd.Dir = a.workingDir

	output, err := cmd.Output()
	if err != nil {
		return err
	}

	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, file := range files {
		if file != "" {
			issue := ImportIssue{
				File:    file,
				Type:    "unused",
				Message: "File has unused imports",
			}
			result.ImportResults = append(result.ImportResults, issue)
		}
	}

	return nil
}

// analyzeCircularImports analyzes circular imports
func (a *Analyzer) analyzeCircularImports(ctx context.Context, result *AnalysisResult) error {
	// This would implement circular import detection logic
	// For now, we'll use a simple approach with go list
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "./...")
	cmd.Dir = a.workingDir

	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// Simple circular import detection would go here
	// This is a placeholder implementation
	_ = output

	return nil
}

// calculateSummary calculates analysis summary
func (a *Analyzer) calculateSummary(result *AnalysisResult) {
	result.Summary.VetIssues = len(result.VetResults)
	result.Summary.StaticIssues = len(result.StaticResults)
	result.Summary.LintIssues = len(result.LintResults)
	result.Summary.ImportIssues = len(result.ImportResults)

	result.Summary.TotalIssues = result.Summary.VetIssues +
		result.Summary.StaticIssues +
		result.Summary.LintIssues +
		result.Summary.ImportIssues

	// Count severity levels
	for _, issue := range result.VetResults {
		a.countSeverity(issue.Severity, &result.Summary)
	}
	for _, issue := range result.StaticResults {
		a.countSeverity(issue.Severity, &result.Summary)
	}
	for _, issue := range result.LintResults {
		a.countSeverity(issue.Severity, &result.Summary)
	}
}

// countSeverity counts issues by severity
func (a *Analyzer) countSeverity(severity string, summary *AnalysisSummary) {
	switch strings.ToLower(severity) {
	case "error", "critical":
		summary.CriticalIssues++
	case "warning", "warn":
		summary.WarningIssues++
	case "info", "note":
		summary.InfoIssues++
	}
}

// buildEnvironment builds environment variables for analysis
func (a *Analyzer) buildEnvironment() []string {
	env := os.Environ()

	// Go module settings
	env = append(env, "GO111MODULE=on")

	// Additional environment variables from config
	for key, value := range a.config.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}

// ValidateConfig validates the analysis configuration
func (a *Analyzer) ValidateConfig() error {
	if a.config == nil {
		return fmt.Errorf("analysis configuration is nil")
	}

	if len(a.config.Packages) == 0 {
		return fmt.Errorf("no packages specified for analysis")
	}

	return nil
}