package go_lang

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// TestConfig represents test configuration
type TestConfig struct {
	Packages       []string          `json:"packages"`          // Packages to test ("./..." for all)
	Tags           []string          `json:"tags"`              // Build tags
	Timeout        time.Duration     `json:"timeout"`           // Test timeout
	Short          bool              `json:"short"`             // Run only short tests
	Verbose        bool              `json:"verbose"`           // Verbose output
	Race           bool              `json:"race"`              // Enable race detection
	Cover          bool              `json:"cover"`             // Enable coverage
	CoverMode      string            `json:"cover_mode"`        // Coverage mode: set, count, atomic
	CoverProfile   string            `json:"cover_profile"`     // Coverage profile file
	CoverPkg       []string          `json:"cover_pkg"`         // Packages to include in coverage
	CPUProfile     string            `json:"cpu_profile"`       // CPU profile file
	MemProfile     string            `json:"mem_profile"`       // Memory profile file
	BlockProfile   string            `json:"block_profile"`     // Block profile file
	MutexProfile   string            `json:"mutex_profile"`     // Mutex profile file
	TraceProfile   string            `json:"trace_profile"`     // Trace profile file
	Parallel       int               `json:"parallel"`          // Number of parallel tests
	Count          int               `json:"count"`             // Number of times to run tests
	FailFast       bool              `json:"fail_fast"`         // Stop on first failure
	JSON           bool              `json:"json"`              // Output in JSON format
	Benchmarks     bool              `json:"benchmarks"`        // Run benchmarks
	BenchTime      string            `json:"bench_time"`        // Benchmark time (e.g., "10s", "100x")
	BenchMem       bool              `json:"bench_mem"`         // Show memory allocation stats
	CPUCount       int               `json:"cpu_count"`         // GOMAXPROCS for tests
	Environment    map[string]string `json:"environment"`       // Additional environment variables
	Args           []string          `json:"args"`              // Additional test arguments
	TestFlags      []string          `json:"test_flags"`        // Additional test flags
	RunFilter      string            `json:"run_filter"`        // Run only tests matching pattern
	SkipFilter     string            `json:"skip_filter"`       // Skip tests matching pattern
	CacheDisable   bool              `json:"cache_disable"`     // Disable test caching
	ModReadonly    bool              `json:"mod_readonly"`      // Module readonly mode
	WorkDir        string            `json:"work_dir"`          // Working directory
}

// TestResult represents test execution results
type TestResult struct {
	Success        bool                   `json:"success"`
	Duration       time.Duration          `json:"duration"`
	PackageResults []PackageTestResult    `json:"package_results"`
	Coverage       *CoverageReport        `json:"coverage,omitempty"`
	Benchmarks     []BenchmarkResult      `json:"benchmarks,omitempty"`
	Output         string                 `json:"output"`
	ErrorOutput    string                 `json:"error_output"`
	FailedTests    []TestFailure          `json:"failed_tests"`
	SkippedTests   []string               `json:"skipped_tests"`
	ProfileFiles   map[string]string      `json:"profile_files,omitempty"`
	Summary        TestSummary            `json:"summary"`
}

// PackageTestResult represents results for a single package
type PackageTestResult struct {
	Package     string        `json:"package"`
	Success     bool          `json:"success"`
	Duration    time.Duration `json:"duration"`
	Tests       []TestCase    `json:"tests"`
	Coverage    float64       `json:"coverage"`
	OutputLines []string      `json:"output_lines"`
}

// TestCase represents a single test case
type TestCase struct {
	Name     string        `json:"name"`
	Status   TestStatus    `json:"status"`
	Duration time.Duration `json:"duration"`
	Output   []string      `json:"output"`
	Error    string        `json:"error,omitempty"`
}

// TestStatus represents test status
type TestStatus string

const (
	TestStatusPass TestStatus = "PASS"
	TestStatusFail TestStatus = "FAIL"
	TestStatusSkip TestStatus = "SKIP"
)

// TestFailure represents a test failure
type TestFailure struct {
	Package  string `json:"package"`
	Test     string `json:"test"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

// CoverageReport represents coverage information
type CoverageReport struct {
	Mode        string            `json:"mode"`
	Packages    []PackageCoverage `json:"packages"`
	TotalLines  int               `json:"total_lines"`
	CoveredLines int              `json:"covered_lines"`
	Percentage  float64           `json:"percentage"`
	ProfileFile string            `json:"profile_file,omitempty"`
}

// PackageCoverage represents coverage for a package
type PackageCoverage struct {
	Package      string         `json:"package"`
	Files        []FileCoverage `json:"files"`
	Lines        int            `json:"lines"`
	CoveredLines int            `json:"covered_lines"`
	Percentage   float64        `json:"percentage"`
}

// FileCoverage represents coverage for a file
type FileCoverage struct {
	File         string    `json:"file"`
	Lines        int       `json:"lines"`
	CoveredLines int       `json:"covered_lines"`
	Percentage   float64   `json:"percentage"`
	Blocks       []Block   `json:"blocks"`
}

// Block represents a coverage block
type Block struct {
	StartLine int `json:"start_line"`
	StartCol  int `json:"start_col"`
	EndLine   int `json:"end_line"`
	EndCol    int `json:"end_col"`
	Count     int `json:"count"`
}

// BenchmarkResult represents benchmark results
type BenchmarkResult struct {
	Name         string  `json:"name"`
	Iterations   int     `json:"iterations"`
	NsPerOp      float64 `json:"ns_per_op"`
	MBPerSec     float64 `json:"mb_per_sec,omitempty"`
	BytesPerOp   int     `json:"bytes_per_op,omitempty"`
	AllocsPerOp  int     `json:"allocs_per_op,omitempty"`
	Package      string  `json:"package"`
}

// TestSummary represents overall test summary
type TestSummary struct {
	TotalPackages int `json:"total_packages"`
	PassedPackages int `json:"passed_packages"`
	FailedPackages int `json:"failed_packages"`
	TotalTests    int `json:"total_tests"`
	PassedTests   int `json:"passed_tests"`
	FailedTests   int `json:"failed_tests"`
	SkippedTests  int `json:"skipped_tests"`
	TotalBenchmarks int `json:"total_benchmarks"`
}

// TestRunner handles Go test execution
type TestRunner struct {
	workingDir string
	config     *TestConfig
	verbose    bool
}

// NewTestRunner creates a new test runner
func NewTestRunner(workingDir string) *TestRunner {
	return &TestRunner{
		workingDir: workingDir,
		config:     NewDefaultTestConfig(),
		verbose:    false,
	}
}

// NewDefaultTestConfig creates a default test configuration
func NewDefaultTestConfig() *TestConfig {
	return &TestConfig{
		Packages:     []string{"./..."},
		Timeout:      10 * time.Minute,
		Short:        false,
		Verbose:      false,
		Race:         false,
		Cover:        false,
		CoverMode:    "set",
		Parallel:     4,
		Count:        1,
		FailFast:     false,
		JSON:         false,
		Benchmarks:   false,
		BenchTime:    "1s",
		BenchMem:     false,
		CacheDisable: false,
		ModReadonly:  false,
		Environment:  make(map[string]string),
	}
}

// SetConfig sets the test configuration
func (tr *TestRunner) SetConfig(config *TestConfig) {
	tr.config = config
}

// SetVerbose enables verbose output
func (tr *TestRunner) SetVerbose(verbose bool) {
	tr.verbose = verbose
}

// RunTests executes tests with the configured settings
func (tr *TestRunner) RunTests(ctx context.Context) (*TestResult, error) {
	startTime := time.Now()

	log.Debug().
		Str("working_dir", tr.workingDir).
		Strs("packages", tr.config.Packages).
		Msg("Starting Go tests")

	result := &TestResult{
		PackageResults: []PackageTestResult{},
		FailedTests:    []TestFailure{},
		SkippedTests:   []string{},
		ProfileFiles:   make(map[string]string),
		Summary:        TestSummary{},
	}

	// Build test command
	args, err := tr.buildTestArgs()
	if err != nil {
		return nil, fmt.Errorf("failed to build test arguments: %w", err)
	}

	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = tr.workingDir
	cmd.Env = tr.buildEnvironment()

	log.Debug().Strs("args", args).Msg("Executing go test")

	// Execute tests
	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	result.Duration = time.Since(startTime)
	result.Output = outputStr

	if err != nil {
		result.Success = false
		result.ErrorOutput = outputStr
	} else {
		result.Success = true
	}

	// Parse test output
	if err := tr.parseTestOutput(outputStr, result); err != nil {
		log.Warn().Err(err).Msg("Failed to parse test output")
	}

	// Generate coverage report if enabled
	if tr.config.Cover && tr.config.CoverProfile != "" {
		if coverage, err := tr.generateCoverageReport(ctx); err == nil {
			result.Coverage = coverage
		} else {
			log.Warn().Err(err).Msg("Failed to generate coverage report")
		}
	}

	// Collect profile files
	tr.collectProfileFiles(result)

	log.Debug().
		Bool("success", result.Success).
		Dur("duration", result.Duration).
		Int("total_tests", result.Summary.TotalTests).
		Msg("Tests completed")

	return result, nil
}

// RunBenchmarks executes benchmarks
func (tr *TestRunner) RunBenchmarks(ctx context.Context, pattern string) (*TestResult, error) {
	oldBenchmarks := tr.config.Benchmarks
	oldRunFilter := tr.config.RunFilter

	tr.config.Benchmarks = true
	if pattern != "" {
		tr.config.RunFilter = pattern
	}

	result, err := tr.RunTests(ctx)

	tr.config.Benchmarks = oldBenchmarks
	tr.config.RunFilter = oldRunFilter

	return result, err
}

// DiscoverTests discovers available tests in the project
func (tr *TestRunner) DiscoverTests(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-list", ".*")
	cmd.Dir = tr.workingDir
	cmd.Env = tr.buildEnvironment()

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to discover tests: %w", err)
	}

	var tests []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Test") || strings.HasPrefix(line, "Benchmark") ||
			strings.HasPrefix(line, "Example") {
			tests = append(tests, line)
		}
	}

	return tests, nil
}

// RunSingleTest runs a specific test
func (tr *TestRunner) RunSingleTest(ctx context.Context, pkg, testName string) (*TestResult, error) {
	oldPackages := tr.config.Packages
	oldRunFilter := tr.config.RunFilter

	if pkg != "" {
		tr.config.Packages = []string{pkg}
	}
	tr.config.RunFilter = fmt.Sprintf("^%s$", testName)

	result, err := tr.RunTests(ctx)

	tr.config.Packages = oldPackages
	tr.config.RunFilter = oldRunFilter

	return result, err
}

// ValidateConfig validates the test configuration
func (tr *TestRunner) ValidateConfig() error {
	if tr.config == nil {
		return fmt.Errorf("test configuration is nil")
	}

	if len(tr.config.Packages) == 0 {
		return fmt.Errorf("no packages specified for testing")
	}

	// Validate coverage mode
	if tr.config.Cover {
		validModes := []string{"set", "count", "atomic"}
		valid := false
		for _, mode := range validModes {
			if tr.config.CoverMode == mode {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid coverage mode: %s", tr.config.CoverMode)
		}
	}

	return nil
}

// EnableCoverage enables coverage with specified mode
func (tr *TestRunner) EnableCoverage(mode string, profileFile string) {
	tr.config.Cover = true
	tr.config.CoverMode = mode
	tr.config.CoverProfile = profileFile
}

// EnableProfiling enables various profiling options
func (tr *TestRunner) EnableProfiling(cpu, mem, block, mutex, trace string) {
	if cpu != "" {
		tr.config.CPUProfile = cpu
	}
	if mem != "" {
		tr.config.MemProfile = mem
	}
	if block != "" {
		tr.config.BlockProfile = block
	}
	if mutex != "" {
		tr.config.MutexProfile = mutex
	}
	if trace != "" {
		tr.config.TraceProfile = trace
	}
}

// buildTestArgs builds the command line arguments for go test
func (tr *TestRunner) buildTestArgs() ([]string, error) {
	args := []string{"test"}

	// Add packages
	args = append(args, tr.config.Packages...)

	// Basic flags
	if tr.config.Verbose || tr.verbose {
		args = append(args, "-v")
	}

	if tr.config.Short {
		args = append(args, "-short")
	}

	if tr.config.Race {
		args = append(args, "-race")
	}

	if tr.config.FailFast {
		args = append(args, "-failfast")
	}

	if tr.config.JSON {
		args = append(args, "-json")
	}

	if tr.config.CacheDisable {
		args = append(args, "-cache=false")
	}

	// Timeout
	if tr.config.Timeout > 0 {
		args = append(args, "-timeout", tr.config.Timeout.String())
	}

	// Parallel execution
	if tr.config.Parallel > 0 {
		args = append(args, "-parallel", strconv.Itoa(tr.config.Parallel))
	}

	// Count
	if tr.config.Count > 1 {
		args = append(args, "-count", strconv.Itoa(tr.config.Count))
	}

	// CPU count
	if tr.config.CPUCount > 0 {
		args = append(args, "-cpu", strconv.Itoa(tr.config.CPUCount))
	}

	// Build tags
	if len(tr.config.Tags) > 0 {
		args = append(args, "-tags", strings.Join(tr.config.Tags, ","))
	}

	// Coverage
	if tr.config.Cover {
		args = append(args, "-cover")
		
		if tr.config.CoverMode != "" {
			args = append(args, "-covermode", tr.config.CoverMode)
		}
		
		if tr.config.CoverProfile != "" {
			profilePath := filepath.Join(tr.workingDir, tr.config.CoverProfile)
			args = append(args, "-coverprofile", profilePath)
		}
		
		if len(tr.config.CoverPkg) > 0 {
			args = append(args, "-coverpkg", strings.Join(tr.config.CoverPkg, ","))
		}
	}

	// Profiling
	if tr.config.CPUProfile != "" {
		args = append(args, "-cpuprofile", filepath.Join(tr.workingDir, tr.config.CPUProfile))
	}
	
	if tr.config.MemProfile != "" {
		args = append(args, "-memprofile", filepath.Join(tr.workingDir, tr.config.MemProfile))
	}
	
	if tr.config.BlockProfile != "" {
		args = append(args, "-blockprofile", filepath.Join(tr.workingDir, tr.config.BlockProfile))
	}
	
	if tr.config.MutexProfile != "" {
		args = append(args, "-mutexprofile", filepath.Join(tr.workingDir, tr.config.MutexProfile))
	}
	
	if tr.config.TraceProfile != "" {
		args = append(args, "-trace", filepath.Join(tr.workingDir, tr.config.TraceProfile))
	}

	// Test filters
	if tr.config.RunFilter != "" {
		args = append(args, "-run", tr.config.RunFilter)
	}
	
	if tr.config.SkipFilter != "" {
		args = append(args, "-skip", tr.config.SkipFilter)
	}

	// Benchmarks
	if tr.config.Benchmarks {
		args = append(args, "-bench", ".")
		
		if tr.config.BenchTime != "" {
			args = append(args, "-benchtime", tr.config.BenchTime)
		}
		
		if tr.config.BenchMem {
			args = append(args, "-benchmem")
		}
	}

	// Module flags
	if tr.config.ModReadonly {
		args = append(args, "-mod=readonly")
	}

	// Additional test flags
	args = append(args, tr.config.TestFlags...)

	// Additional arguments
	if len(tr.config.Args) > 0 {
		args = append(args, "--")
		args = append(args, tr.config.Args...)
	}

	return args, nil
}

// buildEnvironment builds environment variables for test execution
func (tr *TestRunner) buildEnvironment() []string {
	env := os.Environ()

	// Go module settings
	env = append(env, "GO111MODULE=on")

	// Additional environment variables from config
	for key, value := range tr.config.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	return env
}

// parseTestOutput parses the test output and extracts results
func (tr *TestRunner) parseTestOutput(output string, result *TestResult) error {
	lines := strings.Split(output, "\n")
	currentPackage := ""
	var currentPackageResult *PackageTestResult

	// Regular expressions for parsing
	passRegex := regexp.MustCompile(`^--- PASS:\s+(\w+)\s+\(([0-9.]+)s\)`)
	failRegex := regexp.MustCompile(`^--- FAIL:\s+(\w+)\s+\(([0-9.]+)s\)`)
	skipRegex := regexp.MustCompile(`^--- SKIP:\s+(\w+)\s+\(([0-9.]+)s\)`)
	packageRegex := regexp.MustCompile(`^(ok|FAIL)\s+([^\s]+)\s+([0-9.]+)s(?:\s+coverage:\s+([0-9.]+)%)?`)
	benchmarkRegex := regexp.MustCompile(`^Benchmark(\w+)-(\d+)\s+(\d+)\s+([0-9.]+)\s+ns/op(?:\s+([0-9.]+)\s+B/op)?\s*(?:\s+([0-9.]+)\s+allocs/op)?`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Package result
		if matches := packageRegex.FindStringSubmatch(line); len(matches) >= 4 {
			if currentPackageResult != nil {
				result.PackageResults = append(result.PackageResults, *currentPackageResult)
			}

			duration, _ := time.ParseDuration(matches[3] + "s")
			coverage := 0.0
			if len(matches) > 4 && matches[4] != "" {
				coverage, _ = strconv.ParseFloat(matches[4], 64)
			}

			currentPackageResult = &PackageTestResult{
				Package:  matches[2],
				Success:  matches[1] == "ok",
				Duration: duration,
				Coverage: coverage,
				Tests:    []TestCase{},
			}
			currentPackage = matches[2]
			continue
		}

		// Test case results
		if matches := passRegex.FindStringSubmatch(line); len(matches) >= 3 {
			duration, _ := time.ParseDuration(matches[2] + "s")
			if currentPackageResult != nil {
				currentPackageResult.Tests = append(currentPackageResult.Tests, TestCase{
					Name:     matches[1],
					Status:   TestStatusPass,
					Duration: duration,
				})
			}
			result.Summary.PassedTests++
		} else if matches := failRegex.FindStringSubmatch(line); len(matches) >= 3 {
			duration, _ := time.ParseDuration(matches[2] + "s")
			if currentPackageResult != nil {
				currentPackageResult.Tests = append(currentPackageResult.Tests, TestCase{
					Name:     matches[1],
					Status:   TestStatusFail,
					Duration: duration,
				})
			}
			result.FailedTests = append(result.FailedTests, TestFailure{
				Package: currentPackage,
				Test:    matches[1],
				Message: line,
			})
			result.Summary.FailedTests++
		} else if matches := skipRegex.FindStringSubmatch(line); len(matches) >= 3 {
			duration, _ := time.ParseDuration(matches[2] + "s")
			if currentPackageResult != nil {
				currentPackageResult.Tests = append(currentPackageResult.Tests, TestCase{
					Name:     matches[1],
					Status:   TestStatusSkip,
					Duration: duration,
				})
			}
			result.SkippedTests = append(result.SkippedTests, matches[1])
			result.Summary.SkippedTests++
		}

		// Benchmark results
		if matches := benchmarkRegex.FindStringSubmatch(line); len(matches) >= 5 {
			iterations, _ := strconv.Atoi(matches[3])
			nsPerOp, _ := strconv.ParseFloat(matches[4], 64)
			
			benchmark := BenchmarkResult{
				Name:       "Benchmark" + matches[1],
				Iterations: iterations,
				NsPerOp:    nsPerOp,
				Package:    currentPackage,
			}

			if len(matches) > 5 && matches[5] != "" {
				benchmark.BytesPerOp, _ = strconv.Atoi(matches[5])
			}
			if len(matches) > 6 && matches[6] != "" {
				benchmark.AllocsPerOp, _ = strconv.Atoi(matches[6])
			}

			result.Benchmarks = append(result.Benchmarks, benchmark)
			result.Summary.TotalBenchmarks++
		}
	}

	// Add final package result
	if currentPackageResult != nil {
		result.PackageResults = append(result.PackageResults, *currentPackageResult)
	}

	// Calculate summary
	result.Summary.TotalPackages = len(result.PackageResults)
	for _, pkg := range result.PackageResults {
		if pkg.Success {
			result.Summary.PassedPackages++
		} else {
			result.Summary.FailedPackages++
		}
		result.Summary.TotalTests += len(pkg.Tests)
	}

	return nil
}

// generateCoverageReport generates a detailed coverage report
func (tr *TestRunner) generateCoverageReport(ctx context.Context) (*CoverageReport, error) {
	if tr.config.CoverProfile == "" {
		return nil, fmt.Errorf("no coverage profile specified")
	}

	profilePath := filepath.Join(tr.workingDir, tr.config.CoverProfile)
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("coverage profile not found: %s", profilePath)
	}

	// Parse coverage profile
	content, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read coverage profile: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty coverage profile")
	}

	// Parse mode from first line
	mode := "set"
	if strings.HasPrefix(lines[0], "mode:") {
		mode = strings.TrimSpace(strings.TrimPrefix(lines[0], "mode:"))
	}

	report := &CoverageReport{
		Mode:        mode,
		Packages:    []PackageCoverage{},
		ProfileFile: profilePath,
	}

	// Parse coverage blocks
	packageMap := make(map[string]*PackageCoverage)
	fileMap := make(map[string]*FileCoverage)

	blockRegex := regexp.MustCompile(`^([^:]+):(\d+)\.(\d+),(\d+)\.(\d+)\s+(\d+)\s+(\d+)$`)

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		matches := blockRegex.FindStringSubmatch(line)
		if len(matches) != 8 {
			continue
		}

		filename := matches[1]
		startLine, _ := strconv.Atoi(matches[2])
		startCol, _ := strconv.Atoi(matches[3])
		endLine, _ := strconv.Atoi(matches[4])
		endCol, _ := strconv.Atoi(matches[5])
		numStmt, _ := strconv.Atoi(matches[6])
		count, _ := strconv.Atoi(matches[7])

		// Extract package name from filename
		packageName := filepath.Dir(filename)
		if packageName == "." {
			packageName = "main"
		}

		// Initialize package if not exists
		if packageMap[packageName] == nil {
			packageMap[packageName] = &PackageCoverage{
				Package: packageName,
				Files:   []FileCoverage{},
			}
		}

		// Initialize file if not exists
		if fileMap[filename] == nil {
			fileMap[filename] = &FileCoverage{
				File:   filename,
				Blocks: []Block{},
			}
		}

		// Add block
		block := Block{
			StartLine: startLine,
			StartCol:  startCol,
			EndLine:   endLine,
			EndCol:    endCol,
			Count:     count,
		}

		fileMap[filename].Blocks = append(fileMap[filename].Blocks, block)
		fileMap[filename].Lines += numStmt

		if count > 0 {
			fileMap[filename].CoveredLines += numStmt
		}

		packageMap[packageName].Lines += numStmt
		if count > 0 {
			packageMap[packageName].CoveredLines += numStmt
		}

		report.TotalLines += numStmt
		if count > 0 {
			report.CoveredLines += numStmt
		}
	}

	// Calculate percentages and build final report
	if report.TotalLines > 0 {
		report.Percentage = float64(report.CoveredLines) / float64(report.TotalLines) * 100
	}

	for _, pkg := range packageMap {
		if pkg.Lines > 0 {
			pkg.Percentage = float64(pkg.CoveredLines) / float64(pkg.Lines) * 100
		}

		// Add files to package
		for _, file := range fileMap {
			if strings.HasPrefix(file.File, pkg.Package) {
				if file.Lines > 0 {
					file.Percentage = float64(file.CoveredLines) / float64(file.Lines) * 100
				}
				pkg.Files = append(pkg.Files, *file)
			}
		}

		report.Packages = append(report.Packages, *pkg)
	}

	return report, nil
}

// collectProfileFiles collects generated profile files
func (tr *TestRunner) collectProfileFiles(result *TestResult) {
	profiles := map[string]string{
		"cpu":   tr.config.CPUProfile,
		"mem":   tr.config.MemProfile,
		"block": tr.config.BlockProfile,
		"mutex": tr.config.MutexProfile,
		"trace": tr.config.TraceProfile,
	}

	for profileType, filename := range profiles {
		if filename != "" {
			profilePath := filepath.Join(tr.workingDir, filename)
			if _, err := os.Stat(profilePath); err == nil {
				result.ProfileFiles[profileType] = profilePath
			}
		}
	}
}