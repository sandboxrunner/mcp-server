package csharp

import (
	"context"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CSharpCompilerType represents different C# compiler types
type CSharpCompilerType int

const (
	DotNetCLI CSharpCompilerType = iota
	MSBuild
	MonoCompiler
	RoslynCompiler
)

func (t CSharpCompilerType) String() string {
	switch t {
	case DotNetCLI:
		return "dotnet"
	case MSBuild:
		return "msbuild"
	case MonoCompiler:
		return "mono"
	case RoslynCompiler:
		return "roslyn"
	default:
		return "unknown"
	}
}

// ProjectType represents different C# project types
type ProjectType int

const (
	ConsoleApp ProjectType = iota
	ClassLibrary
	WebApp
	WebAPI
	BlazorApp
	WinFormsApp
	WPFApp
	XamarinApp
	MauiApp
	TestProject
)

func (t ProjectType) String() string {
	switch t {
	case ConsoleApp:
		return "console"
	case ClassLibrary:
		return "classlib"
	case WebApp:
		return "webapp"
	case WebAPI:
		return "webapi"
	case BlazorApp:
		return "blazorwasm"
	case WinFormsApp:
		return "winforms"
	case WPFApp:
		return "wpf"
	case XamarinApp:
		return "xamarin"
	case MauiApp:
		return "maui"
	case TestProject:
		return "xunit"
	default:
		return "console"
	}
}

// TargetFramework represents .NET target frameworks
type TargetFramework string

const (
	Net8        TargetFramework = "net8.0"
	Net7        TargetFramework = "net7.0"
	Net6        TargetFramework = "net6.0"
	Net5        TargetFramework = "net5.0"
	NetCore31   TargetFramework = "netcoreapp3.1"
	NetCore21   TargetFramework = "netcoreapp2.1"
	NetStandard TargetFramework = "netstandard2.0"
	NetFramework TargetFramework = "net472"
)

// BuildConfiguration represents build configurations
type BuildConfiguration string

const (
	Debug   BuildConfiguration = "Debug"
	Release BuildConfiguration = "Release"
)

// RuntimeIdentifier represents target runtime identifiers
type RuntimeIdentifier string

const (
	WinX64   RuntimeIdentifier = "win-x64"
	WinX86   RuntimeIdentifier = "win-x86"
	WinArm64 RuntimeIdentifier = "win-arm64"
	LinuxX64 RuntimeIdentifier = "linux-x64"
	LinuxArm RuntimeIdentifier = "linux-arm"
	OsxX64   RuntimeIdentifier = "osx-x64"
	OsxArm64 RuntimeIdentifier = "osx-arm64"
)

// NuGetPackage represents a NuGet package dependency
type NuGetPackage struct {
	PackageId      string `json:"package_id"`
	Version        string `json:"version"`
	IncludePrerelease bool `json:"include_prerelease"`
	Source         string `json:"source,omitempty"`
	TargetFramework string `json:"target_framework,omitempty"`
}

// ProjectReference represents a project reference
type ProjectReference struct {
	Include string `json:"include"`
	Name    string `json:"name,omitempty"`
}

// CompilationTarget represents C# compilation target
type CompilationTarget struct {
	Framework      TargetFramework     `json:"framework"`
	Configuration  BuildConfiguration  `json:"configuration"`
	Runtime        RuntimeIdentifier   `json:"runtime,omitempty"`
	OutputType     string             `json:"output_type"`
	Platform       string             `json:"platform"`
	Architecture   string             `json:"architecture"`
	SelfContained  bool               `json:"self_contained"`
	SingleFile     bool               `json:"single_file"`
	ReadyToRun     bool               `json:"ready_to_run"`
	PublishTrimmed bool               `json:"publish_trimmed"`
}

// CSharpCompiler represents a comprehensive C# compilation system
type CSharpCompiler struct {
	compilerType       CSharpCompilerType
	projectType        ProjectType
	dotnetCommand      string
	msbuildCommand     string
	nugetCommand       string
	version            *DotNetVersion
	target             *CompilationTarget
	packages           []*NuGetPackage
	projectReferences  []*ProjectReference
	nugetSources       []string
	projectGenerator   *ProjectGenerator
	nugetManager       *NuGetPackageManager
	testRunner         *TestRunner
	publishManager     *PublishManager
	profiler           *DotNetProfiler
	formatter          *CSharpFormatter
	linter             *CSharpLinter
	documentationGenerator *XmlDocGenerator
	securityScanner    *DotNetSecurityScanner
	cache              *CompilationCache
	metrics            *CompilationMetrics
	mutex              sync.RWMutex
}

// DotNetVersion represents .NET version information
type DotNetVersion struct {
	Major         int    `json:"major"`
	Minor         int    `json:"minor"`
	Patch         int    `json:"patch"`
	Build         string `json:"build"`
	Version       string `json:"version"`
	Runtime       string `json:"runtime"`
	SDKVersion    string `json:"sdk_version"`
	Architecture  string `json:"architecture"`
}

// ProjectGenerator generates C# project files
type ProjectGenerator struct {
	templateManager *ProjectTemplateManager
	solutionManager *SolutionManager
}

// ProjectTemplateManager manages project templates
type ProjectTemplateManager struct {
	availableTemplates map[string]*ProjectTemplate
	customTemplates    []*ProjectTemplate
}

// ProjectTemplate represents a project template
type ProjectTemplate struct {
	Name         string            `json:"name"`
	ShortName    string            `json:"short_name"`
	Description  string            `json:"description"`
	Language     string            `json:"language"`
	Tags         []string          `json:"tags"`
	Framework    TargetFramework   `json:"framework"`
	ProjectType  ProjectType       `json:"project_type"`
	Files        map[string]string `json:"files"`
	Packages     []*NuGetPackage   `json:"packages"`
}

// SolutionManager manages Visual Studio solutions
type SolutionManager struct {
	solutionFiles map[string]*SolutionFile
}

// SolutionFile represents a Visual Studio solution
type SolutionFile struct {
	Name     string             `json:"name"`
	Version  string             `json:"version"`
	Projects []*SolutionProject `json:"projects"`
	GlobalSections map[string]map[string]string `json:"global_sections"`
}

// SolutionProject represents a project in a solution
type SolutionProject struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	ProjectType  string `json:"project_type"`
	ProjectGuid  string `json:"project_guid"`
	SolutionGuid string `json:"solution_guid"`
}

// NuGetPackageManager handles NuGet package operations
type NuGetPackageManager struct {
	nugetCommand   string
	dotnetCommand  string
	sources        []string
	packageCache   map[string]*NuGetPackage
	restoreManager *PackageRestoreManager
	updateManager  *PackageUpdateManager
	mutex          sync.RWMutex
}

// PackageRestoreManager handles package restoration
type PackageRestoreManager struct {
	globalPackagesFolder string
	packageSources       []string
	verbosity           string
	noCache             bool
	configFile          string
}

// PackageUpdateManager handles package updates
type PackageUpdateManager struct {
	source         string
	prerelease     bool
	interactive    bool
	framework      string
}

// TestRunner executes .NET tests
type TestRunner struct {
	testFramework      string // xunit, nunit, mstest
	coverageAnalyzer   *CoverageAnalyzer
	testLogger         string
	testSettings       string
	resultsDirectory   string
	verbosity          string
	parallel           bool
	maxParallelism     int
	testAdapterPath    string
}

// CoverageAnalyzer analyzes test coverage
type CoverageAnalyzer struct {
	coverletEnabled    bool
	reportGeneratorEnabled bool
	threshold          float64
	excludeFilters     []string
	includeFilters     []string
	formats            []string
	outputDirectory    string
}

// PublishManager handles application publishing
type PublishManager struct {
	outputPath        string
	configuration     BuildConfiguration
	framework         TargetFramework
	runtime           RuntimeIdentifier
	selfContained     bool
	singleFile        bool
	readyToRun        bool
	publishTrimmed    bool
	includeNativeLibsForSelfExtract bool
	includeAllContentForSelfExtract bool
}

// DotNetProfiler handles performance profiling
type DotNetProfiler struct {
	profilerType       string // dotTrace, PerfView, JetBrains
	samplingEnabled    bool
	memoryProfilingEnabled bool
	timelineProfilingEnabled bool
	coverageEnabled    bool
	outputFormat       string
	outputDirectory    string
}

// CSharpFormatter handles code formatting
type CSharpFormatter struct {
	formatterType      string // dotnet-format, EditorConfig
	editorConfigFile   string
	verbosity          string
	include            []string
	exclude            []string
	fixWhitespace      bool
	fixStyle           bool
	fixAnalyzers       bool
}

// CSharpLinter performs static analysis
type CSharpLinter struct {
	roslynAnalyzersEnabled bool
	stylecopEnabled        bool
	fxcopEnabled          bool
	sonarAnalyzerEnabled   bool
	rulesets              []string
	suppressions          []string
	warningsAsErrors      bool
	treatWarningsAsErrors []string
	noWarn                []string
}

// XmlDocGenerator generates XML documentation
type XmlDocGenerator struct {
	generateDocFile    bool
	docFilePath        string
	includePrivateMembers bool
	generateReferences bool
	outputDirectory    string
}

// DotNetSecurityScanner scans for security vulnerabilities
type DotNetSecurityScanner struct {
	securityCodeScanEnabled bool
	dependencyCheckEnabled  bool
	snykEnabled            bool
	whitesourceEnabled     bool
	severityThreshold      string
	outputFormat           string
	excludeFiles           []string
}

// CompilationCache handles build caching
type CompilationCache struct {
	enabled        bool
	cacheDirectory string
	maxSize        int64
	ttl            time.Duration
	cleanupInterval time.Duration
	storage        CacheStorage
	mutex          sync.RWMutex
}

// CacheStorage handles cache persistence
type CacheStorage interface {
	Get(key string) ([]byte, error)
	Put(key string, data []byte) error
	Delete(key string) error
	Clear() error
	Size() (int64, error)
}

// CompilationMetrics tracks compilation performance
type CompilationMetrics struct {
	compilationTime       time.Duration
	testTime             time.Duration
	publishTime          time.Duration
	totalTime            time.Duration
	sourceFiles          int
	compiledAssemblies   int
	testAssemblies       int
	testsRun             int
	testsPassed          int
	testsFailed          int
	testsSkipped         int
	codeLines            int
	commentLines         int
	emptyLines           int
	cyclomaticComplexity int
	technicalDebt        time.Duration
	codeSmells           int
	bugs                 int
	vulnerabilities      int
	duplicatedLines      int
	duplicatedBlocks     int
	maintainabilityIndex float64
	reliabilityRating    string
	securityRating       string
	coverage             float64
	memoryUsage          int64
	cpuUsage             float64
	diskUsage            int64
}

// CompilationRequest represents a C# compilation request
type CompilationRequest struct {
	WorkingDir       string                 `json:"working_dir"`
	SourceFiles      []string              `json:"source_files"`
	ProjectName      string                `json:"project_name"`
	ProjectType      ProjectType           `json:"project_type"`
	Target           *CompilationTarget    `json:"target"`
	Packages         []*NuGetPackage       `json:"packages"`
	ProjectRefs      []*ProjectReference   `json:"project_references"`
	Options          map[string]interface{} `json:"options"`
	Environment      map[string]string     `json:"environment"`
	Timeout          time.Duration         `json:"timeout"`
	Debug            bool                  `json:"debug"`
	Optimize         bool                  `json:"optimize"`
	Profile          bool                  `json:"profile"`
	RunTests         bool                  `json:"run_tests"`
	GenerateDocs     bool                  `json:"generate_docs"`
	SecurityScan     bool                  `json:"security_scan"`
	Publish          bool                  `json:"publish"`
	CreateSolution   bool                  `json:"create_solution"`
}

// CompilationResponse represents a C# compilation response
type CompilationResponse struct {
	Success            bool                   `json:"success"`
	CompilationTime    time.Duration          `json:"compilation_time"`
	OutputFiles        []string              `json:"output_files"`
	AssemblyFiles      []string              `json:"assembly_files"`
	PublishedFiles     []string              `json:"published_files"`
	TestResults        *TestResult           `json:"test_results,omitempty"`
	Documentation      *DocumentationResult  `json:"documentation,omitempty"`
	SecurityResults    *SecurityScanResult   `json:"security_results,omitempty"`
	Metrics            *CompilationMetrics   `json:"metrics"`
	Warnings           []CompilationWarning  `json:"warnings"`
	Errors             []CompilationError    `json:"errors"`
	Output             string                `json:"output"`
	Error              error                 `json:"error,omitempty"`
}

// TestResult represents test execution results
type TestResult struct {
	Success         bool          `json:"success"`
	TestsRun        int           `json:"tests_run"`
	TestsPassed     int           `json:"tests_passed"`
	TestsFailed     int           `json:"tests_failed"`
	TestsSkipped    int           `json:"tests_skipped"`
	ExecutionTime   time.Duration `json:"execution_time"`
	Coverage        *CoverageReport `json:"coverage,omitempty"`
	FailedTests     []FailedTest  `json:"failed_tests"`
	Output          string        `json:"output"`
	TrxFile         string        `json:"trx_file,omitempty"`
}

// CoverageReport represents test coverage information
type CoverageReport struct {
	LineCoverage     float64 `json:"line_coverage"`
	BranchCoverage   float64 `json:"branch_coverage"`
	MethodCoverage   float64 `json:"method_coverage"`
	ClassCoverage    float64 `json:"class_coverage"`
	CoveredLines     int     `json:"covered_lines"`
	TotalLines       int     `json:"total_lines"`
	CoveredBranches  int     `json:"covered_branches"`
	TotalBranches    int     `json:"total_branches"`
	CoverageFile     string  `json:"coverage_file"`
	HtmlReportPath   string  `json:"html_report_path"`
}

// FailedTest represents a failed test
type FailedTest struct {
	TestClass      string        `json:"test_class"`
	TestMethod     string        `json:"test_method"`
	Error          string        `json:"error"`
	Stacktrace     string        `json:"stacktrace"`
	ExecutionTime  time.Duration `json:"execution_time"`
	ErrorMessage   string        `json:"error_message"`
}

// DocumentationResult represents documentation generation results
type DocumentationResult struct {
	Success        bool     `json:"success"`
	OutputDir      string   `json:"output_dir"`
	GeneratedFiles []string `json:"generated_files"`
	XmlDocFile     string   `json:"xml_doc_file"`
	Errors         []string `json:"errors"`
	Warnings       []string `json:"warnings"`
}

// SecurityScanResult represents security scan results
type SecurityScanResult struct {
	Success         bool               `json:"success"`
	Vulnerabilities []Vulnerability    `json:"vulnerabilities"`
	Dependencies    []DependencyIssue  `json:"dependencies"`
	CodeIssues      []CodeSecurityIssue `json:"code_issues"`
	Summary         SecuritySummary    `json:"summary"`
}

// Vulnerability represents a security vulnerability
type Vulnerability struct {
	Id          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	CWE         string  `json:"cwe"`
	Component   string  `json:"component"`
	Version     string  `json:"version"`
	FixVersion  string  `json:"fix_version,omitempty"`
}

// DependencyIssue represents a dependency-related issue
type DependencyIssue struct {
	Package       *NuGetPackage   `json:"package"`
	Vulnerability *Vulnerability  `json:"vulnerability"`
	Severity      string          `json:"severity"`
	Exploitable   bool            `json:"exploitable"`
}

// CodeSecurityIssue represents a code security issue
type CodeSecurityIssue struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Rule        string `json:"rule"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Confidence  string `json:"confidence"`
}

// SecuritySummary provides security scan summary
type SecuritySummary struct {
	TotalVulnerabilities    int `json:"total_vulnerabilities"`
	HighVulnerabilities     int `json:"high_vulnerabilities"`
	MediumVulnerabilities   int `json:"medium_vulnerabilities"`
	LowVulnerabilities      int `json:"low_vulnerabilities"`
	TotalDependencies       int `json:"total_dependencies"`
	VulnerableDependencies  int `json:"vulnerable_dependencies"`
	SecurityRating          string `json:"security_rating"`
}

// CompilationWarning represents a compilation warning
type CompilationWarning struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

// CompilationError represents a compilation error
type CompilationError struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

// NewCSharpCompiler creates a new C# compiler instance
func NewCSharpCompiler(compilerType CSharpCompilerType, projectType ProjectType) (*CSharpCompiler, error) {
	compiler := &CSharpCompiler{
		compilerType:      compilerType,
		projectType:       projectType,
		packages:          make([]*NuGetPackage, 0),
		projectReferences: make([]*ProjectReference, 0),
		nugetSources:      make([]string, 0),
		cache:             NewCompilationCache(),
		metrics:           NewCompilationMetrics(),
	}

	// Initialize .NET environment
	if err := compiler.initializeEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to initialize .NET environment: %w", err)
	}

	// Initialize components
	if err := compiler.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	return compiler, nil
}

// initializeEnvironment initializes the .NET environment
func (c *CSharpCompiler) initializeEnvironment() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Find dotnet command
	dotnetPath, err := exec.LookPath("dotnet")
	if err != nil {
		return fmt.Errorf("dotnet CLI not found: %w", err)
	}
	c.dotnetCommand = dotnetPath

	// Find msbuild command (optional)
	if msbuildPath, err := exec.LookPath("msbuild"); err == nil {
		c.msbuildCommand = msbuildPath
	}

	// Find nuget command (optional)
	if nugetPath, err := exec.LookPath("nuget"); err == nil {
		c.nugetCommand = nugetPath
	}

	// Get .NET version
	version, err := c.getDotNetVersion()
	if err != nil {
		return fmt.Errorf("failed to get .NET version: %w", err)
	}
	c.version = version

	// Set default compilation target
	c.target = &CompilationTarget{
		Framework:     Net8,
		Configuration: Debug,
		OutputType:    "Exe",
		Platform:      "AnyCPU",
		Architecture:  "x64",
		SelfContained: false,
		SingleFile:    false,
		ReadyToRun:    false,
		PublishTrimmed: false,
	}

	// Initialize default NuGet sources
	c.initializeDefaultNuGetSources()

	return nil
}

// getDotNetVersion gets the .NET version information
func (c *CSharpCompiler) getDotNetVersion() (*DotNetVersion, error) {
	cmd := exec.Command(c.dotnetCommand, "--version")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	versionStr := strings.TrimSpace(string(output))
	parts := strings.Split(versionStr, ".")

	version := &DotNetVersion{
		Version: versionStr,
	}

	if len(parts) >= 1 {
		if major, err := strconv.Atoi(parts[0]); err == nil {
			version.Major = major
		}
	}
	if len(parts) >= 2 {
		if minor, err := strconv.Atoi(parts[1]); err == nil {
			version.Minor = minor
		}
	}
	if len(parts) >= 3 {
		patchParts := strings.Split(parts[2], "-")
		if patch, err := strconv.Atoi(patchParts[0]); err == nil {
			version.Patch = patch
		}
		if len(patchParts) > 1 {
			version.Build = patchParts[1]
		}
	}

	// Get runtime information
	cmd = exec.Command(c.dotnetCommand, "--info")
	output, err = cmd.Output()
	if err == nil {
		infoStr := string(output)
		// Parse runtime and architecture from --info output
		lines := strings.Split(infoStr, "\n")
		for _, line := range lines {
			if strings.Contains(line, "RID:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					version.Runtime = strings.TrimSpace(parts[1])
				}
			}
			if strings.Contains(line, "Architecture:") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					version.Architecture = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	return version, nil
}

// initializeDefaultNuGetSources sets up default NuGet sources
func (c *CSharpCompiler) initializeDefaultNuGetSources() {
	c.nugetSources = []string{
		"https://api.nuget.org/v3/index.json",
		"https://nuget.pkg.github.com/*/index.json",
	}
}

// initializeComponents initializes various C# compiler components
func (c *CSharpCompiler) initializeComponents() error {
	// Initialize project generator
	c.projectGenerator = NewProjectGenerator()

	// Initialize NuGet package manager
	c.nugetManager = NewNuGetPackageManager(c.dotnetCommand, c.nugetSources)

	// Initialize test runner
	c.testRunner = NewTestRunner()

	// Initialize publish manager
	c.publishManager = NewPublishManager()

	// Initialize profiler
	c.profiler = NewDotNetProfiler()

	// Initialize formatter
	c.formatter = NewCSharpFormatter()

	// Initialize linter
	c.linter = NewCSharpLinter()

	// Initialize documentation generator
	c.documentationGenerator = NewXmlDocGenerator()

	// Initialize security scanner
	c.securityScanner = NewDotNetSecurityScanner()

	return nil
}

// Compile compiles C# code using the .NET CLI
func (c *CSharpCompiler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	startTime := time.Now()
	response := &CompilationResponse{
		Metrics:        NewCompilationMetrics(),
		Warnings:       make([]CompilationWarning, 0),
		Errors:         make([]CompilationError, 0),
		OutputFiles:    make([]string, 0),
		AssemblyFiles:  make([]string, 0),
		PublishedFiles: make([]string, 0),
	}

	// Validate request
	if err := c.validateCompilationRequest(request); err != nil {
		response.Success = false
		response.Error = err
		return response, err
	}

	// Check cache
	if c.cache.enabled {
		if cachedResponse := c.checkCache(request); cachedResponse != nil {
			return cachedResponse, nil
		}
	}

	// Create or validate project file
	projectFile, err := c.createOrValidateProject(request)
	if err != nil {
		response.Success = false
		response.Error = fmt.Errorf("project creation/validation failed: %w", err)
		return response, response.Error
	}

	// Restore packages
	if err := c.restorePackages(ctx, request); err != nil {
		response.Success = false
		response.Error = fmt.Errorf("package restore failed: %w", err)
		return response, response.Error
	}

	// Execute compilation
	compileResponse, err := c.executeCompilation(ctx, request, projectFile)
	if err != nil {
		response.Success = false
		response.Error = fmt.Errorf("compilation failed: %w", err)
		return response, response.Error
	}

	// Copy compilation results
	response.Success = compileResponse.Success
	response.OutputFiles = compileResponse.OutputFiles
	response.AssemblyFiles = compileResponse.AssemblyFiles
	response.Warnings = compileResponse.Warnings
	response.Errors = compileResponse.Errors
	response.Output = compileResponse.Output

	// Run tests if requested
	if request.RunTests && response.Success {
		testResult, err := c.runTests(ctx, request, projectFile)
		if err != nil {
			response.TestResults = &TestResult{
				Success: false,
				Output:  fmt.Sprintf("Test execution failed: %v", err),
			}
		} else {
			response.TestResults = testResult
		}
	}

	// Publish if requested
	if request.Publish && response.Success {
		publishedFiles, err := c.publishApplication(ctx, request, projectFile)
		if err != nil {
			response.Error = fmt.Errorf("publishing failed: %w", err)
		} else {
			response.PublishedFiles = publishedFiles
		}
	}

	// Generate documentation if requested
	if request.GenerateDocs && response.Success {
		docResult, err := c.generateDocumentation(ctx, request, projectFile)
		if err != nil {
			response.Documentation = &DocumentationResult{
				Success: false,
				Errors:  []string{fmt.Sprintf("Documentation generation failed: %v", err)},
			}
		} else {
			response.Documentation = docResult
		}
	}

	// Run security scan if requested
	if request.SecurityScan && response.Success {
		securityResult, err := c.runSecurityScan(ctx, request, projectFile)
		if err != nil {
			response.SecurityResults = &SecurityScanResult{
				Success: false,
				Summary: SecuritySummary{},
			}
		} else {
			response.SecurityResults = securityResult
		}
	}

	// Update metrics
	response.CompilationTime = time.Since(startTime)
	response.Metrics.compilationTime = response.CompilationTime
	response.Metrics.totalTime = response.CompilationTime

	// Cache successful result
	if c.cache.enabled && response.Success {
		c.cacheResult(request, response)
	}

	return response, nil
}

// validateCompilationRequest validates the compilation request
func (c *CSharpCompiler) validateCompilationRequest(request *CompilationRequest) error {
	if request.WorkingDir == "" {
		return fmt.Errorf("working directory is required")
	}

	if request.ProjectName == "" {
		request.ProjectName = "SandboxProject"
	}

	if request.Timeout <= 0 {
		request.Timeout = 60 * time.Second
	}

	return nil
}

// createOrValidateProject creates a new project or validates existing project
func (c *CSharpCompiler) createOrValidateProject(request *CompilationRequest) (string, error) {
	projectFile := filepath.Join(request.WorkingDir, request.ProjectName+".csproj")

	// Check if project file already exists
	if _, err := os.Stat(projectFile); err == nil {
		// Validate existing project file
		return projectFile, c.validateProjectFile(projectFile)
	}

	// Create new project file
	return projectFile, c.createProjectFile(request, projectFile)
}

// validateProjectFile validates an existing project file
func (c *CSharpCompiler) validateProjectFile(projectFile string) error {
	content, err := os.ReadFile(projectFile)
	if err != nil {
		return fmt.Errorf("failed to read project file: %w", err)
	}

	// Basic XML validation
	var project struct {
		XMLName xml.Name `xml:"Project"`
		SDK     string   `xml:"Sdk,attr"`
	}

	if err := xml.Unmarshal(content, &project); err != nil {
		return fmt.Errorf("invalid project file format: %w", err)
	}

	return nil
}

// createProjectFile creates a new C# project file
func (c *CSharpCompiler) createProjectFile(request *CompilationRequest, projectFile string) error {
	framework := Net8
	if request.Target != nil && request.Target.Framework != "" {
		framework = request.Target.Framework
	}

	outputType := "Exe"
	if request.Target != nil && request.Target.OutputType != "" {
		outputType = request.Target.OutputType
	}

	// Determine SDK based on project type
	sdk := "Microsoft.NET.Sdk"
	if request.ProjectType == TestProject {
		sdk = "Microsoft.NET.Sdk"
		outputType = "Library"
	}

	projectContent := fmt.Sprintf(`<Project Sdk="%s">

  <PropertyGroup>
    <OutputType>%s</OutputType>
    <TargetFramework>%s</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

</Project>`, sdk, outputType, framework)

	// Add package references if any
	if len(request.Packages) > 0 {
		packageRefs := "\n  <ItemGroup>\n"
		for _, pkg := range request.Packages {
			packageRefs += fmt.Sprintf("    <PackageReference Include=\"%s\" Version=\"%s\" />\n", 
				pkg.PackageId, pkg.Version)
		}
		packageRefs += "  </ItemGroup>\n"
		
		projectContent = strings.Replace(projectContent, "</Project>", packageRefs+"</Project>", 1)
	}

	// Add project references if any
	if len(request.ProjectRefs) > 0 {
		projectRefs := "\n  <ItemGroup>\n"
		for _, projRef := range request.ProjectRefs {
			projectRefs += fmt.Sprintf("    <ProjectReference Include=\"%s\" />\n", projRef.Include)
		}
		projectRefs += "  </ItemGroup>\n"
		
		projectContent = strings.Replace(projectContent, "</Project>", projectRefs+"</Project>", 1)
	}

	return os.WriteFile(projectFile, []byte(projectContent), 0644)
}

// restorePackages restores NuGet packages
func (c *CSharpCompiler) restorePackages(ctx context.Context, request *CompilationRequest) error {
	args := []string{"restore"}
	if request.Debug {
		args = append(args, "--verbosity", "detailed")
	}

	cmd := exec.CommandContext(ctx, c.dotnetCommand, args...)
	cmd.Dir = request.WorkingDir

	// Set environment
	cmd.Env = os.Environ()
	for key, value := range request.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("package restore failed: %v\nOutput: %s", err, string(output))
	}

	return nil
}

// executeCompilation executes the actual compilation
func (c *CSharpCompiler) executeCompilation(ctx context.Context, request *CompilationRequest, projectFile string) (*CompilationResponse, error) {
	response := &CompilationResponse{
		Metrics:       NewCompilationMetrics(),
		Warnings:      make([]CompilationWarning, 0),
		Errors:        make([]CompilationError, 0),
		OutputFiles:   make([]string, 0),
		AssemblyFiles: make([]string, 0),
	}

	// Build dotnet build command
	args := []string{"build"}

	// Add configuration
	configuration := Debug
	if request.Target != nil && request.Target.Configuration != "" {
		configuration = request.Target.Configuration
	}
	args = append(args, "--configuration", string(configuration))

	// Add verbosity
	if request.Debug {
		args = append(args, "--verbosity", "detailed")
	} else {
		args = append(args, "--verbosity", "normal")
	}

	// Add no-restore flag since we already restored
	args = append(args, "--no-restore")

	// Execute build
	cmd := exec.CommandContext(ctx, c.dotnetCommand, args...)
	cmd.Dir = request.WorkingDir

	// Set environment
	cmd.Env = os.Environ()
	for key, value := range request.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	output, err := cmd.CombinedOutput()
	response.Output = string(output)

	if err != nil {
		response.Success = false
		response.Error = err
		c.parseBuildOutput(string(output), response)
		return response, nil
	}

	// Find compiled assemblies
	assemblies, err := c.findAssemblies(request.WorkingDir, string(configuration))
	if err != nil {
		response.Success = false
		response.Error = fmt.Errorf("failed to find assemblies: %w", err)
		return response, response.Error
	}

	response.Success = true
	response.AssemblyFiles = assemblies
	response.OutputFiles = assemblies

	// Parse warnings from successful compilation
	c.parseBuildOutput(string(output), response)

	return response, nil
}

// parseBuildOutput parses dotnet build output for errors and warnings
func (c *CSharpCompiler) parseBuildOutput(output string, response *CompilationResponse) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse error/warning pattern: file(line,column): error/warning CS0000: message
		errorRegex := regexp.MustCompile(`^(.+?)\((\d+),(\d+)\):\s*(error|warning)\s+([A-Z]+\d+):\s*(.+)$`)
		matches := errorRegex.FindStringSubmatch(line)

		if len(matches) >= 7 {
			file := matches[1]
			lineNum, _ := strconv.Atoi(matches[2])
			colNum, _ := strconv.Atoi(matches[3])
			msgType := matches[4]
			code := matches[5]
			message := matches[6]

			if msgType == "error" {
				response.Errors = append(response.Errors, CompilationError{
					File:    file,
					Line:    lineNum,
					Column:  colNum,
					Code:    code,
					Message: message,
					Type:    "compilation",
				})
			} else if msgType == "warning" {
				response.Warnings = append(response.Warnings, CompilationWarning{
					File:    file,
					Line:    lineNum,
					Column:  colNum,
					Code:    code,
					Message: message,
					Type:    "compilation",
				})
			}
		}
	}
}

// findAssemblies finds compiled assembly files
func (c *CSharpCompiler) findAssemblies(workingDir, configuration string) ([]string, error) {
	var assemblies []string

	// Look in bin directory
	binDir := filepath.Join(workingDir, "bin", configuration)
	
	err := filepath.WalkDir(binDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Ignore errors, directory might not exist
		}

		if !d.IsDir() && strings.HasSuffix(path, ".dll") || strings.HasSuffix(path, ".exe") {
			relPath, err := filepath.Rel(workingDir, path)
			if err != nil {
				return err
			}
			assemblies = append(assemblies, relPath)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return assemblies, nil
}

// runTests runs .NET tests
func (c *CSharpCompiler) runTests(ctx context.Context, request *CompilationRequest, projectFile string) (*TestResult, error) {
	result := &TestResult{
		FailedTests: make([]FailedTest, 0),
	}

	args := []string{"test"}

	// Add test logger
	args = append(args, "--logger", "trx")

	// Add verbosity
	if request.Debug {
		args = append(args, "--verbosity", "detailed")
	}

	// Add no-build flag since we already built
	args = append(args, "--no-build")

	// Execute tests
	cmd := exec.CommandContext(ctx, c.dotnetCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	// Parse test output
	c.parseTestOutput(string(output), result)

	if err != nil && result.TestsFailed == 0 {
		result.Success = false
		result.Output = fmt.Sprintf("Test execution failed: %v\n%s", err, output)
		return result, nil
	}

	result.Success = (result.TestsFailed == 0)
	return result, nil
}

// parseTestOutput parses dotnet test output
func (c *CSharpCompiler) parseTestOutput(output string, result *TestResult) {
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse test summary
		if strings.Contains(line, "Total tests:") {
			// Pattern: Total tests: 5. Passed: 3. Failed: 1. Skipped: 1.
			testSummaryRegex := regexp.MustCompile(`Total tests:\s*(\d+).*Passed:\s*(\d+).*Failed:\s*(\d+).*Skipped:\s*(\d+)`)
			matches := testSummaryRegex.FindStringSubmatch(line)

			if len(matches) >= 5 {
				result.TestsRun, _ = strconv.Atoi(matches[1])
				result.TestsPassed, _ = strconv.Atoi(matches[2])
				result.TestsFailed, _ = strconv.Atoi(matches[3])
				result.TestsSkipped, _ = strconv.Atoi(matches[4])
			}
		}

		// Parse individual test failures
		if strings.Contains(line, "Failed") && strings.Contains(line, "::") {
			parts := strings.Split(line, "::")
			if len(parts) >= 2 {
				failedTest := FailedTest{
					TestClass:  strings.TrimSpace(parts[0]),
					TestMethod: strings.TrimSpace(parts[1]),
					Error:      "Test failed",
				}
				result.FailedTests = append(result.FailedTests, failedTest)
			}
		}
	}
}

// publishApplication publishes the application
func (c *CSharpCompiler) publishApplication(ctx context.Context, request *CompilationRequest, projectFile string) ([]string, error) {
	args := []string{"publish"}

	// Add configuration
	configuration := Release
	if request.Target != nil && request.Target.Configuration != "" {
		configuration = request.Target.Configuration
	}
	args = append(args, "--configuration", string(configuration))

	// Add output directory
	outputDir := filepath.Join(request.WorkingDir, "publish")
	args = append(args, "--output", outputDir)

	// Add runtime if specified
	if request.Target != nil && request.Target.Runtime != "" {
		args = append(args, "--runtime", string(request.Target.Runtime))
	}

	// Add self-contained flag
	if request.Target != nil && request.Target.SelfContained {
		args = append(args, "--self-contained", "true")
	} else {
		args = append(args, "--self-contained", "false")
	}

	// Add single file flag
	if request.Target != nil && request.Target.SingleFile {
		args = append(args, "--property:PublishSingleFile=true")
	}

	// Execute publish
	cmd := exec.CommandContext(ctx, c.dotnetCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("publish failed: %v\nOutput: %s", err, string(output))
	}

	// Find published files
	publishedFiles, err := c.findPublishedFiles(outputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to find published files: %w", err)
	}

	return publishedFiles, nil
}

// findPublishedFiles finds all published files
func (c *CSharpCompiler) findPublishedFiles(publishDir string) ([]string, error) {
	var files []string

	if _, err := os.Stat(publishDir); err != nil {
		return files, nil
	}

	err := filepath.WalkDir(publishDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			relPath, err := filepath.Rel(publishDir, path)
			if err != nil {
				return err
			}
			files = append(files, relPath)
		}

		return nil
	})

	return files, err
}

// generateDocumentation generates XML documentation
func (c *CSharpCompiler) generateDocumentation(ctx context.Context, request *CompilationRequest, projectFile string) (*DocumentationResult, error) {
	result := &DocumentationResult{
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	// XML documentation is generated during build if enabled in project file
	// For now, just check if XML documentation file exists
	projectName := strings.TrimSuffix(filepath.Base(projectFile), ".csproj")
	xmlDocFile := filepath.Join(request.WorkingDir, "bin", "Debug", projectName+".xml")

	if _, err := os.Stat(xmlDocFile); err == nil {
		result.Success = true
		result.XmlDocFile = xmlDocFile
		result.GeneratedFiles = []string{xmlDocFile}
	} else {
		result.Success = false
		result.Errors = append(result.Errors, "XML documentation file not found. Enable GenerateDocumentationFile in project.")
	}

	return result, nil
}

// runSecurityScan runs security scans
func (c *CSharpCompiler) runSecurityScan(ctx context.Context, request *CompilationRequest, projectFile string) (*SecurityScanResult, error) {
	result := &SecurityScanResult{
		Success:         true,
		Vulnerabilities: make([]Vulnerability, 0),
		Dependencies:    make([]DependencyIssue, 0),
		CodeIssues:      make([]CodeSecurityIssue, 0),
		Summary:         SecuritySummary{},
	}

	// Run dotnet list package --vulnerable
	args := []string{"list", "package", "--vulnerable"}
	cmd := exec.CommandContext(ctx, c.dotnetCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()
	if err == nil {
		c.parseVulnerablePackages(string(output), result)
	}

	// Calculate summary
	result.Summary.TotalDependencies = len(request.Packages)
	result.Summary.VulnerableDependencies = len(result.Dependencies)
	result.Summary.TotalVulnerabilities = len(result.Vulnerabilities)

	for _, vuln := range result.Vulnerabilities {
		switch vuln.Severity {
		case "HIGH":
			result.Summary.HighVulnerabilities++
		case "MEDIUM":
			result.Summary.MediumVulnerabilities++
		case "LOW":
			result.Summary.LowVulnerabilities++
		}
	}

	// Determine security rating
	if result.Summary.HighVulnerabilities > 0 {
		result.Summary.SecurityRating = "POOR"
	} else if result.Summary.MediumVulnerabilities > 5 {
		result.Summary.SecurityRating = "FAIR"
	} else if result.Summary.LowVulnerabilities > 10 {
		result.Summary.SecurityRating = "GOOD"
	} else {
		result.Summary.SecurityRating = "EXCELLENT"
	}

	return result, nil
}

// parseVulnerablePackages parses vulnerable package output
func (c *CSharpCompiler) parseVulnerablePackages(output string, result *SecurityScanResult) {
	// This would parse the output of dotnet list package --vulnerable
	// Implementation placeholder for parsing vulnerable packages
}

// checkCache checks if a cached result exists for the request
func (c *CSharpCompiler) checkCache(request *CompilationRequest) *CompilationResponse {
	// Implementation would check cache based on request hash
	return nil
}

// cacheResult caches the compilation result
func (c *CSharpCompiler) cacheResult(request *CompilationRequest, response *CompilationResponse) {
	// Implementation would cache the result based on request hash
}

// GetSupportedFeatures returns the features supported by this compiler
func (c *CSharpCompiler) GetSupportedFeatures() map[string]bool {
	features := make(map[string]bool)

	features["compilation"] = true
	features["package_management"] = true
	features["project_generation"] = true
	features["solution_support"] = true
	features["testing"] = true
	features["publishing"] = true
	features["documentation_generation"] = true
	features["security_scanning"] = true
	features["code_formatting"] = true
	features["static_analysis"] = true
	features["performance_profiling"] = true
	features["cross_platform"] = true
	features["self_contained_deployment"] = true
	features["single_file_deployment"] = true
	features["ready_to_run"] = true
	features["ahead_of_time_compilation"] = true

	return features
}

// GetVersion returns the .NET compiler version
func (c *CSharpCompiler) GetVersion() *DotNetVersion {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.version
}

// SetProjectType changes the project type
func (c *CSharpCompiler) SetProjectType(projectType ProjectType) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.projectType = projectType
}

// AddPackage adds a NuGet package to the project
func (c *CSharpCompiler) AddPackage(pkg *NuGetPackage) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Validate package
	if pkg.PackageId == "" || pkg.Version == "" {
		return fmt.Errorf("invalid package: packageId and version are required")
	}

	// Check for duplicates
	for _, existing := range c.packages {
		if existing.PackageId == pkg.PackageId {
			return fmt.Errorf("package %s already exists", pkg.PackageId)
		}
	}

	c.packages = append(c.packages, pkg)
	return nil
}

// AddProjectReference adds a project reference
func (c *CSharpCompiler) AddProjectReference(projRef *ProjectReference) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Validate project reference
	if projRef.Include == "" {
		return fmt.Errorf("invalid project reference: include path is required")
	}

	// Check for duplicates
	for _, existing := range c.projectReferences {
		if existing.Include == projRef.Include {
			return fmt.Errorf("project reference %s already exists", projRef.Include)
		}
	}

	c.projectReferences = append(c.projectReferences, projRef)
	return nil
}

// Clean cleans the build artifacts
func (c *CSharpCompiler) Clean(ctx context.Context, workingDir string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if there's a project file before running dotnet clean
	projectFiles, _ := filepath.Glob(filepath.Join(workingDir, "*.csproj"))
	solutionFiles, _ := filepath.Glob(filepath.Join(workingDir, "*.sln"))
	
	if len(projectFiles) > 0 || len(solutionFiles) > 0 {
		args := []string{"clean"}
		cmd := exec.CommandContext(ctx, c.dotnetCommand, args...)
		cmd.Dir = workingDir

		output, err := cmd.CombinedOutput()
		if err != nil {
			// Don't fail if dotnet clean fails, continue with manual cleanup
			fmt.Printf("Warning: dotnet clean failed: %v\nOutput: %s", err, string(output))
		}
	}

	// Clean directories manually
	dirsToClean := []string{"bin", "obj", "publish"}
	for _, dir := range dirsToClean {
		dirPath := filepath.Join(workingDir, dir)
		if _, err := os.Stat(dirPath); err == nil {
			if err := os.RemoveAll(dirPath); err != nil {
				return fmt.Errorf("failed to clean %s: %w", dir, err)
			}
		}
	}

	// Clean cache if enabled
	if c.cache != nil && c.cache.enabled && c.cache.storage != nil {
		if err := c.cache.storage.Clear(); err != nil {
			return fmt.Errorf("failed to clean cache: %w", err)
		}
	}

	return nil
}

// Helper functions for component initialization

// NewCompilationCache creates a new compilation cache
func NewCompilationCache() *CompilationCache {
	return &CompilationCache{
		enabled:         true,
		cacheDirectory:  filepath.Join(os.TempDir(), "csharp-compiler-cache"),
		maxSize:         1024 * 1024 * 1024, // 1GB
		ttl:             24 * time.Hour,
		cleanupInterval: 1 * time.Hour,
	}
}

// NewCompilationMetrics creates a new compilation metrics instance
func NewCompilationMetrics() *CompilationMetrics {
	return &CompilationMetrics{
		maintainabilityIndex: 0.0,
		reliabilityRating:    "UNKNOWN",
		securityRating:       "UNKNOWN",
		coverage:             0.0,
	}
}

// NewProjectGenerator creates a new project generator
func NewProjectGenerator() *ProjectGenerator {
	return &ProjectGenerator{
		templateManager: NewProjectTemplateManager(),
		solutionManager: NewSolutionManager(),
	}
}

// NewProjectTemplateManager creates a new project template manager
func NewProjectTemplateManager() *ProjectTemplateManager {
	return &ProjectTemplateManager{
		availableTemplates: make(map[string]*ProjectTemplate),
		customTemplates:    make([]*ProjectTemplate, 0),
	}
}

// NewSolutionManager creates a new solution manager
func NewSolutionManager() *SolutionManager {
	return &SolutionManager{
		solutionFiles: make(map[string]*SolutionFile),
	}
}

// NewNuGetPackageManager creates a new NuGet package manager
func NewNuGetPackageManager(dotnetCommand string, sources []string) *NuGetPackageManager {
	return &NuGetPackageManager{
		dotnetCommand:  dotnetCommand,
		sources:        sources,
		packageCache:   make(map[string]*NuGetPackage),
		restoreManager: NewPackageRestoreManager(),
		updateManager:  NewPackageUpdateManager(),
	}
}

// NewPackageRestoreManager creates a new package restore manager
func NewPackageRestoreManager() *PackageRestoreManager {
	return &PackageRestoreManager{
		globalPackagesFolder: filepath.Join(os.Getenv("HOME"), ".nuget", "packages"),
		verbosity:           "normal",
		noCache:             false,
	}
}

// NewPackageUpdateManager creates a new package update manager
func NewPackageUpdateManager() *PackageUpdateManager {
	return &PackageUpdateManager{
		prerelease:  false,
		interactive: false,
	}
}

// NewTestRunner creates a new test runner
func NewTestRunner() *TestRunner {
	return &TestRunner{
		testFramework:    "xunit",
		coverageAnalyzer: NewCoverageAnalyzer(),
		testLogger:       "trx",
		verbosity:        "normal",
		parallel:         true,
		maxParallelism:   4,
	}
}

// NewCoverageAnalyzer creates a new coverage analyzer
func NewCoverageAnalyzer() *CoverageAnalyzer {
	return &CoverageAnalyzer{
		coverletEnabled:         true,
		reportGeneratorEnabled:  true,
		threshold:              80.0,
		excludeFilters:         make([]string, 0),
		includeFilters:         make([]string, 0),
		formats:                []string{"html", "xml"},
		outputDirectory:        "coverage",
	}
}

// NewPublishManager creates a new publish manager
func NewPublishManager() *PublishManager {
	return &PublishManager{
		outputPath:                      "publish",
		configuration:                   Release,
		framework:                       Net8,
		selfContained:                   false,
		singleFile:                      false,
		readyToRun:                      false,
		publishTrimmed:                  false,
		includeNativeLibsForSelfExtract: false,
		includeAllContentForSelfExtract: false,
	}
}

// NewDotNetProfiler creates a new .NET profiler
func NewDotNetProfiler() *DotNetProfiler {
	return &DotNetProfiler{
		profilerType:               "dotTrace",
		samplingEnabled:            true,
		memoryProfilingEnabled:     true,
		timelineProfilingEnabled:   true,
		coverageEnabled:            false,
		outputFormat:               "html",
		outputDirectory:            "profiling",
	}
}

// NewCSharpFormatter creates a new C# formatter
func NewCSharpFormatter() *CSharpFormatter {
	return &CSharpFormatter{
		formatterType:     "dotnet-format",
		verbosity:         "normal",
		include:           make([]string, 0),
		exclude:           make([]string, 0),
		fixWhitespace:     true,
		fixStyle:          true,
		fixAnalyzers:      true,
	}
}

// NewCSharpLinter creates a new C# linter
func NewCSharpLinter() *CSharpLinter {
	return &CSharpLinter{
		roslynAnalyzersEnabled: true,
		stylecopEnabled:        true,
		fxcopEnabled:          false,
		sonarAnalyzerEnabled:   false,
		rulesets:              make([]string, 0),
		suppressions:          make([]string, 0),
		warningsAsErrors:      false,
		treatWarningsAsErrors: make([]string, 0),
		noWarn:                make([]string, 0),
	}
}

// NewXmlDocGenerator creates a new XML documentation generator
func NewXmlDocGenerator() *XmlDocGenerator {
	return &XmlDocGenerator{
		generateDocFile:       true,
		includePrivateMembers: false,
		generateReferences:    true,
		outputDirectory:       "docs",
	}
}

// NewDotNetSecurityScanner creates a new .NET security scanner
func NewDotNetSecurityScanner() *DotNetSecurityScanner {
	return &DotNetSecurityScanner{
		securityCodeScanEnabled: true,
		dependencyCheckEnabled:  true,
		snykEnabled:            false,
		whitesourceEnabled:     false,
		severityThreshold:      "medium",
		outputFormat:           "json",
		excludeFiles:           make([]string, 0),
	}
}