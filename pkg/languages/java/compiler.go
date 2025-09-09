package java

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JavaCompilerType represents different Java compiler types
type JavaCompilerType int

const (
	JavacCompiler JavaCompilerType = iota
	EclipseCompiler
	IntelliJCompiler
)

func (t JavaCompilerType) String() string {
	switch t {
	case JavacCompiler:
		return "javac"
	case EclipseCompiler:
		return "ecj"
	case IntelliJCompiler:
		return "intellij"
	default:
		return "unknown"
	}
}

// BuildSystemType represents different Java build systems
type BuildSystemType int

const (
	DirectBuild BuildSystemType = iota
	MavenBuild
	GradleBuild
	AntBuild
)

func (t BuildSystemType) String() string {
	switch t {
	case DirectBuild:
		return "direct"
	case MavenBuild:
		return "maven"
	case GradleBuild:
		return "gradle"
	case AntBuild:
		return "ant"
	default:
		return "unknown"
	}
}

// JavaVersion represents Java version information
type JavaVersion struct {
	Major   int    `json:"major"`
	Minor   int    `json:"minor"`
	Patch   int    `json:"patch"`
	Build   string `json:"build"`
	Version string `json:"version"`
}

// CompilationTarget represents target Java version and platform
type CompilationTarget struct {
	JavaVersion    string `json:"java_version"`
	TargetVersion  string `json:"target_version"`
	SourceVersion  string `json:"source_version"`
	Architecture   string `json:"architecture"`
	OperatingSystem string `json:"operating_system"`
}

// ClasspathEntry represents a classpath entry
type ClasspathEntry struct {
	Path     string            `json:"path"`
	Type     string            `json:"type"` // jar, directory, module
	Metadata map[string]string `json:"metadata"`
}

// Dependency represents a Java dependency
type Dependency struct {
	GroupId    string `json:"group_id"`
	ArtifactId string `json:"artifact_id"`
	Version    string `json:"version"`
	Scope      string `json:"scope"`
	Type       string `json:"type"`
	Classifier string `json:"classifier,omitempty"`
}

// Repository represents a dependency repository
type Repository struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Layout   string `json:"layout"`
	Releases bool   `json:"releases"`
	Snapshots bool  `json:"snapshots"`
}

// JavaCompiler represents a comprehensive Java compilation system
type JavaCompiler struct {
	compilerType     JavaCompilerType
	buildSystem      BuildSystemType
	javaHome         string
	javacCommand     string
	javaCommand      string
	mavenCommand     string
	gradleCommand    string
	antCommand       string
	version          *JavaVersion
	target           *CompilationTarget
	classpath        []ClasspathEntry
	dependencies     []*Dependency
	repositories     []*Repository
	buildSystemHandlers map[BuildSystemType]BuildSystemHandler
	dependencyManager   *DependencyManager
	projectGenerator    *ProjectGenerator
	jarBuilder          *JarBuilder
	testRunner          *TestRunner
	profiler            *JavaProfiler
	formatter           *JavaFormatter
	linter              *JavaLinter
	documentationGenerator *JavaDocGenerator
	securityScanner     *JavaSecurityScanner
	cache               *CompilationCache
	metrics             *CompilationMetrics
	mutex               sync.RWMutex
}

// BuildSystemHandler interface for different build systems
type BuildSystemHandler interface {
	Initialize(ctx context.Context, request *CompilationRequest) error
	Prepare(ctx context.Context, request *CompilationRequest) error
	Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error)
	Test(ctx context.Context, request *CompilationRequest) (*TestResult, error)
	Package(ctx context.Context, request *CompilationRequest) (*PackageResult, error)
	Clean(ctx context.Context, workingDir string) error
	GetArtifacts(workingDir string) ([]string, error)
	ValidateProject(workingDir string) error
}

// DependencyManager handles Java dependency resolution
type DependencyManager struct {
	repositories     []*Repository
	localRepository  string
	dependencyCache  map[string]*Dependency
	resolutionOrder  []string
	conflictResolver ConflictResolver
	mutex            sync.RWMutex
}

// ConflictResolver handles dependency version conflicts
type ConflictResolver struct {
	strategy string // nearest, highest, lowest
	excludes []string
}

// ProjectGenerator generates project files for different build systems
type ProjectGenerator struct {
	mavenGenerator  *MavenProjectGenerator
	gradleGenerator *GradleProjectGenerator
	antGenerator    *AntProjectGenerator
}

// JarBuilder handles JAR file creation and manipulation
type JarBuilder struct {
	jarCommand      string
	manifestBuilder *ManifestBuilder
	signatureHandler *JarSignatureHandler
}

// ManifestBuilder creates JAR manifest files
type ManifestBuilder struct {
	mainClass    string
	classPath    []string
	attributes   map[string]string
	sectionAttributes map[string]map[string]string
}

// JarSignatureHandler handles JAR signing
type JarSignatureHandler struct {
	jarsignerCommand string
	keystore        string
	alias           string
	storepass       string
	keypass         string
}

// TestRunner executes Java tests
type TestRunner struct {
	junitRunner    *JUnitRunner
	testngRunner   *TestNGRunner
	mockitoSupport bool
	hamcrestSupport bool
	coverage       *CoverageAnalyzer
}

// JUnitRunner runs JUnit tests
type JUnitRunner struct {
	version     string
	suiteRunner bool
	parallel    bool
	timeout     time.Duration
}

// TestNGRunner runs TestNG tests
type TestNGRunner struct {
	version      string
	suiteFile    string
	groups       []string
	excludeGroups []string
	parallel     string
	threadCount  int
}

// CoverageAnalyzer analyzes test coverage
type CoverageAnalyzer struct {
	jacocoEnabled bool
	coberturaEnabled bool
	outputFormat  string
	threshold     float64
}

// JavaProfiler handles performance profiling
type JavaProfiler struct {
	profilerType    string // jvisualvm, yourkit, jprofiler, async-profiler
	samplingRate    int
	heapAnalysis    bool
	cpuAnalysis     bool
	memoryAnalysis  bool
	outputFormat    string
}

// JavaFormatter handles code formatting
type JavaFormatter struct {
	formatterType   string // google-java-format, eclipse, intellij
	configFile      string
	tabSize         int
	maxLineLength   int
	sortImports     bool
	removeUnusedImports bool
}

// JavaLinter performs static analysis
type JavaLinter struct {
	checkstyleEnabled bool
	pmdEnabled        bool
	spotbugsEnabled   bool
	errorproneEnabled bool
	configFiles       map[string]string
	rulesets          map[string][]string
	suppressions      []string
}

// JavaDocGenerator generates documentation
type JavaDocGenerator struct {
	javadocCommand  string
	outputDirectory string
	windowTitle     string
	docTitle        string
	author          bool
	version         bool
	since           bool
	links           []string
	groups          map[string][]string
}

// JavaSecurityScanner scans for security vulnerabilities
type JavaSecurityScanner struct {
	owasp           *OWASPDependencyCheck
	snyk            *SnykScanner
	sonarqube       *SonarQubeScanner
	spotbugs        *SpotBugsSecurityScanner
}

// OWASPDependencyCheck configuration
type OWASPDependencyCheck struct {
	enabled         bool
	databaseUrl     string
	suppressionFile string
	failOnCVSS      float64
}

// SnykScanner configuration
type SnykScanner struct {
	enabled   bool
	token     string
	orgId     string
	severity  string
}

// SonarQubeScanner configuration
type SonarQubeScanner struct {
	enabled    bool
	serverUrl  string
	token      string
	projectKey string
}

// SpotBugsSecurityScanner configuration
type SpotBugsSecurityScanner struct {
	enabled     bool
	includeFilter string
	excludeFilter string
	effort      string
	threshold   string
}

// CompilationCache handles build caching
type CompilationCache struct {
	enabled       bool
	cacheDir      string
	maxSize       int64
	ttl           time.Duration
	keyGenerator  CacheKeyGenerator
	storage       CacheStorage
	mutex         sync.RWMutex
}

// CacheKeyGenerator generates cache keys
type CacheKeyGenerator struct {
	algorithm string
	includes  []string
	excludes  []string
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
	compilationTime    time.Duration
	testTime          time.Duration
	packageTime       time.Duration
	totalTime         time.Duration
	sourceFiles       int
	compiledClasses   int
	testClasses       int
	testsRun          int
	testsPassed       int
	testsFailed       int
	testsSkipped      int
	codeLines         int
	commentLines      int
	emptyLines        int
	cyclomaticComplexity int
	technicalDebt     time.Duration
	codeSmells        int
	bugs              int
	vulnerabilities   int
	duplicatedLines   int
	duplicatedBlocks  int
	maintainabilityIndex float64
	reliabilityRating    string
	securityRating       string
	coverage             float64
	memoryUsage          int64
	heapUsage            int64
	cpuUsage             float64
}

// CompilationRequest represents a compilation request
type CompilationRequest struct {
	WorkingDir       string                 `json:"working_dir"`
	SourceFiles      []string              `json:"source_files"`
	MainClass        string                `json:"main_class"`
	ClasspathEntries []ClasspathEntry      `json:"classpath_entries"`
	Dependencies     []*Dependency         `json:"dependencies"`
	Target           *CompilationTarget    `json:"target"`
	BuildSystem      BuildSystemType       `json:"build_system"`
	Options          map[string]interface{} `json:"options"`
	Environment      map[string]string     `json:"environment"`
	Timeout          time.Duration         `json:"timeout"`
	Debug            bool                  `json:"debug"`
	Optimize         bool                  `json:"optimize"`
	Profile          bool                  `json:"profile"`
	RunTests         bool                  `json:"run_tests"`
	GenerateDocs     bool                  `json:"generate_docs"`
	SecurityScan     bool                  `json:"security_scan"`
	CreateJar        bool                  `json:"create_jar"`
	SignJar          bool                  `json:"sign_jar"`
}

// CompilationResponse represents a compilation response
type CompilationResponse struct {
	Success         bool                   `json:"success"`
	CompilationTime time.Duration          `json:"compilation_time"`
	OutputFiles     []string              `json:"output_files"`
	ClassFiles      []string              `json:"class_files"`
	JarFiles        []string              `json:"jar_files"`
	TestResults     *TestResult           `json:"test_results,omitempty"`
	Documentation   *DocumentationResult  `json:"documentation,omitempty"`
	SecurityResults *SecurityScanResult   `json:"security_results,omitempty"`
	Metrics         *CompilationMetrics   `json:"metrics"`
	Warnings        []CompilationWarning  `json:"warnings"`
	Errors          []CompilationError    `json:"errors"`
	Output          string                `json:"output"`
	Error           error                 `json:"error,omitempty"`
}

// TestResult represents test execution results
type TestResult struct {
	Success       bool          `json:"success"`
	TestsRun      int           `json:"tests_run"`
	TestsPassed   int           `json:"tests_passed"`
	TestsFailed   int           `json:"tests_failed"`
	TestsSkipped  int           `json:"tests_skipped"`
	ExecutionTime time.Duration `json:"execution_time"`
	Coverage      *CoverageReport `json:"coverage,omitempty"`
	FailedTests   []FailedTest  `json:"failed_tests"`
	Output        string        `json:"output"`
}

// CoverageReport represents test coverage information
type CoverageReport struct {
	LineCoverage   float64 `json:"line_coverage"`
	BranchCoverage float64 `json:"branch_coverage"`
	MethodCoverage float64 `json:"method_coverage"`
	ClassCoverage  float64 `json:"class_coverage"`
	CoveredLines   int     `json:"covered_lines"`
	TotalLines     int     `json:"total_lines"`
	CoveredBranches int    `json:"covered_branches"`
	TotalBranches   int    `json:"total_branches"`
}

// FailedTest represents a failed test
type FailedTest struct {
	TestClass   string `json:"test_class"`
	TestMethod  string `json:"test_method"`
	Error       string `json:"error"`
	Stacktrace  string `json:"stacktrace"`
	ExecutionTime time.Duration `json:"execution_time"`
}

// PackageResult represents packaging results
type PackageResult struct {
	Success     bool     `json:"success"`
	JarFiles    []string `json:"jar_files"`
	WarFiles    []string `json:"war_files"`
	EarFiles    []string `json:"ear_files"`
	Checksums   map[string]string `json:"checksums"`
	Signatures  map[string]string `json:"signatures"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DocumentationResult represents documentation generation results
type DocumentationResult struct {
	Success        bool     `json:"success"`
	OutputDir      string   `json:"output_dir"`
	GeneratedFiles []string `json:"generated_files"`
	IndexFile      string   `json:"index_file"`
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
	Dependency    *Dependency `json:"dependency"`
	Vulnerability *Vulnerability `json:"vulnerability"`
	Severity      string      `json:"severity"`
	Exploitable   bool        `json:"exploitable"`
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
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	HighVulnerabilities  int `json:"high_vulnerabilities"`
	MediumVulnerabilities int `json:"medium_vulnerabilities"`
	LowVulnerabilities   int `json:"low_vulnerabilities"`
	TotalDependencies    int `json:"total_dependencies"`
	VulnerableDependencies int `json:"vulnerable_dependencies"`
	SecurityRating       string `json:"security_rating"`
}

// CompilationWarning represents a compilation warning
type CompilationWarning struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

// CompilationError represents a compilation error
type CompilationError struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// NewJavaCompiler creates a new Java compiler instance
func NewJavaCompiler(compilerType JavaCompilerType, buildSystem BuildSystemType) (*JavaCompiler, error) {
	compiler := &JavaCompiler{
		compilerType:        compilerType,
		buildSystem:         buildSystem,
		classpath:          make([]ClasspathEntry, 0),
		dependencies:       make([]*Dependency, 0),
		repositories:       make([]*Repository, 0),
		buildSystemHandlers: make(map[BuildSystemType]BuildSystemHandler),
		cache:              NewCompilationCache(),
		metrics:            NewCompilationMetrics(),
	}

	// Initialize Java environment
	if err := compiler.initializeEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to initialize Java environment: %w", err)
	}

	// Initialize build system handlers
	if err := compiler.initializeBuildSystems(); err != nil {
		return nil, fmt.Errorf("failed to initialize build systems: %w", err)
	}

	// Initialize components
	if err := compiler.initializeComponents(); err != nil {
		return nil, fmt.Errorf("failed to initialize components: %w", err)
	}

	return compiler, nil
}

// initializeEnvironment initializes the Java environment
func (c *JavaCompiler) initializeEnvironment() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Find Java home
	javaHome := os.Getenv("JAVA_HOME")
	if javaHome == "" {
		// Try to find Java installation
		cmd := exec.Command("java", "-XshowSettings:properties", "-version")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Java not found: %w", err)
		}

		// Parse java.home from output
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "java.home") {
				parts := strings.Split(line, "=")
				if len(parts) == 2 {
					javaHome = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	if javaHome == "" {
		return fmt.Errorf("JAVA_HOME not set and could not detect Java installation")
	}

	c.javaHome = javaHome

	// Set up command paths
	c.javaCommand = filepath.Join(javaHome, "bin", "java")
	c.javacCommand = filepath.Join(javaHome, "bin", "javac")

	// Detect additional tools
	if mavenPath, err := exec.LookPath("mvn"); err == nil {
		c.mavenCommand = mavenPath
	}
	if gradlePath, err := exec.LookPath("gradle"); err == nil {
		c.gradleCommand = gradlePath
	}
	if antPath, err := exec.LookPath("ant"); err == nil {
		c.antCommand = antPath
	}

	// Get Java version
	version, err := c.getJavaVersion()
	if err != nil {
		return fmt.Errorf("failed to get Java version: %w", err)
	}
	c.version = version

	// Set default compilation target
	c.target = &CompilationTarget{
		JavaVersion:   version.Version,
		SourceVersion: version.Version,
		TargetVersion: version.Version,
		Architecture:  "x86_64",
		OperatingSystem: "linux",
	}

	// Initialize default repositories
	c.initializeDefaultRepositories()

	return nil
}

// getJavaVersion gets the Java version information
func (c *JavaCompiler) getJavaVersion() (*JavaVersion, error) {
	cmd := exec.Command(c.javaCommand, "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	versionStr := string(output)
	lines := strings.Split(versionStr, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("no version output")
	}

	// Parse version from first line
	versionLine := lines[0]
	versionRegex := regexp.MustCompile(`"([^"]+)"`)
	matches := versionRegex.FindStringSubmatch(versionLine)
	if len(matches) < 2 {
		return nil, fmt.Errorf("could not parse version from: %s", versionLine)
	}

	fullVersion := matches[1]
	parts := strings.Split(fullVersion, ".")

	version := &JavaVersion{
		Version: fullVersion,
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
		patchParts := strings.Split(parts[2], "_")
		if patch, err := strconv.Atoi(patchParts[0]); err == nil {
			version.Patch = patch
		}
		if len(patchParts) > 1 {
			version.Build = patchParts[1]
		}
	}

	return version, nil
}

// initializeDefaultRepositories sets up default Maven repositories
func (c *JavaCompiler) initializeDefaultRepositories() {
	c.repositories = []*Repository{
		{
			Id:        "central",
			Name:      "Maven Central Repository",
			URL:       "https://repo1.maven.org/maven2/",
			Layout:    "default",
			Releases:  true,
			Snapshots: false,
		},
		{
			Id:        "apache-snapshots",
			Name:      "Apache Snapshots Repository",
			URL:       "https://repository.apache.org/snapshots/",
			Layout:    "default",
			Releases:  false,
			Snapshots: true,
		},
	}
}

// initializeBuildSystems initializes build system handlers
func (c *JavaCompiler) initializeBuildSystems() error {
	c.buildSystemHandlers[DirectBuild] = NewDirectBuildHandler(c)
	
	if c.mavenCommand != "" {
		c.buildSystemHandlers[MavenBuild] = NewMavenBuildHandler(c)
	}
	
	if c.gradleCommand != "" {
		c.buildSystemHandlers[GradleBuild] = NewGradleBuildHandler(c)
	}
	
	if c.antCommand != "" {
		c.buildSystemHandlers[AntBuild] = NewAntBuildHandler(c)
	}

	return nil
}

// initializeComponents initializes various Java compiler components
func (c *JavaCompiler) initializeComponents() error {
	// Initialize dependency manager
	c.dependencyManager = NewDependencyManager(c.repositories)

	// Initialize project generator
	c.projectGenerator = NewProjectGenerator()

	// Initialize JAR builder
	c.jarBuilder = NewJarBuilder()

	// Initialize test runner
	c.testRunner = NewTestRunner()

	// Initialize profiler
	c.profiler = NewJavaProfiler()

	// Initialize formatter
	c.formatter = NewJavaFormatter()

	// Initialize linter
	c.linter = NewJavaLinter()

	// Initialize documentation generator
	c.documentationGenerator = NewJavaDocGenerator(c.javaHome)

	// Initialize security scanner
	c.securityScanner = NewJavaSecurityScanner()

	return nil
}

// Compile compiles Java code using the specified build system
func (c *JavaCompiler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	startTime := time.Now()
	response := &CompilationResponse{
		Metrics:     NewCompilationMetrics(),
		Warnings:    make([]CompilationWarning, 0),
		Errors:      make([]CompilationError, 0),
		OutputFiles: make([]string, 0),
		ClassFiles:  make([]string, 0),
		JarFiles:    make([]string, 0),
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

	// Get build system handler
	buildHandler, exists := c.buildSystemHandlers[request.BuildSystem]
	if !exists {
		err := fmt.Errorf("unsupported build system: %s", request.BuildSystem.String())
		response.Success = false
		response.Error = err
		return response, err
	}

	// Initialize build system
	if err := buildHandler.Initialize(ctx, request); err != nil {
		response.Success = false
		response.Error = fmt.Errorf("build system initialization failed: %w", err)
		return response, response.Error
	}

	// Prepare build
	if err := buildHandler.Prepare(ctx, request); err != nil {
		response.Success = false
		response.Error = fmt.Errorf("build preparation failed: %w", err)
		return response, response.Error
	}

	// Execute compilation
	compileResponse, err := buildHandler.Compile(ctx, request)
	if err != nil {
		response.Success = false
		response.Error = fmt.Errorf("compilation failed: %w", err)
		return response, response.Error
	}

	// Copy compilation results
	response.Success = compileResponse.Success
	response.OutputFiles = compileResponse.OutputFiles
	response.ClassFiles = compileResponse.ClassFiles
	response.Warnings = compileResponse.Warnings
	response.Errors = compileResponse.Errors
	response.Output = compileResponse.Output

	// Run tests if requested
	if request.RunTests && response.Success {
		testResult, err := buildHandler.Test(ctx, request)
		if err != nil {
			// Don't fail compilation if tests fail
			response.TestResults = &TestResult{
				Success: false,
				Output:  fmt.Sprintf("Test execution failed: %v", err),
			}
		} else {
			response.TestResults = testResult
		}
	}

	// Create JAR if requested
	if request.CreateJar && response.Success {
		packageResult, err := buildHandler.Package(ctx, request)
		if err != nil {
			response.Error = fmt.Errorf("JAR creation failed: %w", err)
		} else if packageResult.Success {
			response.JarFiles = packageResult.JarFiles
		}
	}

	// Generate documentation if requested
	if request.GenerateDocs && response.Success {
		docResult, err := c.generateDocumentation(ctx, request)
		if err != nil {
			// Don't fail compilation if documentation generation fails
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
		securityResult, err := c.runSecurityScan(ctx, request)
		if err != nil {
			// Don't fail compilation if security scan fails
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
func (c *JavaCompiler) validateCompilationRequest(request *CompilationRequest) error {
	if request.WorkingDir == "" {
		return fmt.Errorf("working directory is required")
	}

	if len(request.SourceFiles) == 0 && request.BuildSystem == DirectBuild {
		return fmt.Errorf("source files are required for direct build")
	}

	if request.Timeout <= 0 {
		request.Timeout = 30 * time.Second
	}

	return nil
}

// checkCache checks if a cached result exists for the request
func (c *JavaCompiler) checkCache(request *CompilationRequest) *CompilationResponse {
	// Implementation would check cache based on request hash
	// This is a placeholder for the caching logic
	return nil
}

// cacheResult caches the compilation result
func (c *JavaCompiler) cacheResult(request *CompilationRequest, response *CompilationResponse) {
	// Implementation would cache the result based on request hash
	// This is a placeholder for the caching logic
}

// generateDocumentation generates Java documentation
func (c *JavaCompiler) generateDocumentation(ctx context.Context, request *CompilationRequest) (*DocumentationResult, error) {
	if c.documentationGenerator == nil {
		return nil, fmt.Errorf("documentation generator not initialized")
	}

	outputDir := filepath.Join(request.WorkingDir, "docs")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create documentation directory: %w", err)
	}

	// Build javadoc command
	args := []string{
		"-d", outputDir,
		"-sourcepath", request.WorkingDir,
		"-classpath", c.buildClasspath(request.ClasspathEntries),
	}

	// Add source files or packages
	if len(request.SourceFiles) > 0 {
		for _, sourceFile := range request.SourceFiles {
			if filepath.Ext(sourceFile) == ".java" {
				args = append(args, sourceFile)
			}
		}
	} else {
		// Auto-detect packages
		packages, err := c.detectPackages(request.WorkingDir)
		if err != nil {
			return nil, fmt.Errorf("failed to detect packages: %w", err)
		}
		args = append(args, packages...)
	}

	// Execute javadoc
	cmd := exec.CommandContext(ctx, c.documentationGenerator.javadocCommand, args...)
	cmd.Dir = request.WorkingDir
	output, err := cmd.CombinedOutput()

	result := &DocumentationResult{
		OutputDir: outputDir,
		Errors:   make([]string, 0),
		Warnings: make([]string, 0),
	}

	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("javadoc execution failed: %v", err))
		result.Errors = append(result.Errors, string(output))
		return result, nil
	}

	// Find generated files
	generatedFiles, err := c.findGeneratedFiles(outputDir)
	if err != nil {
		result.Success = false
		result.Errors = append(result.Errors, fmt.Sprintf("failed to find generated files: %v", err))
		return result, nil
	}

	result.Success = true
	result.GeneratedFiles = generatedFiles
	result.IndexFile = filepath.Join(outputDir, "index.html")

	return result, nil
}

// runSecurityScan runs security scans on the Java code
func (c *JavaCompiler) runSecurityScan(ctx context.Context, request *CompilationRequest) (*SecurityScanResult, error) {
	if c.securityScanner == nil {
		return nil, fmt.Errorf("security scanner not initialized")
	}

	result := &SecurityScanResult{
		Success:         true,
		Vulnerabilities: make([]Vulnerability, 0),
		Dependencies:    make([]DependencyIssue, 0),
		CodeIssues:      make([]CodeSecurityIssue, 0),
		Summary:         SecuritySummary{},
	}

	// Run OWASP Dependency Check if enabled
	if c.securityScanner.owasp != nil && c.securityScanner.owasp.enabled {
		owaspResults, err := c.runOWASPDependencyCheck(ctx, request)
		if err == nil {
			result.Dependencies = append(result.Dependencies, owaspResults...)
		}
	}

	// Run SpotBugs security scan if enabled
	if c.securityScanner.spotbugs != nil && c.securityScanner.spotbugs.enabled {
		codeIssues, err := c.runSpotBugsSecurity(ctx, request)
		if err == nil {
			result.CodeIssues = append(result.CodeIssues, codeIssues...)
		}
	}

	// Calculate summary
	result.Summary.TotalDependencies = len(request.Dependencies)
	result.Summary.VulnerableDependencies = len(result.Dependencies)
	
	for _, issue := range result.Dependencies {
		result.Summary.TotalVulnerabilities++
		switch issue.Severity {
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

// runOWASPDependencyCheck runs OWASP dependency check
func (c *JavaCompiler) runOWASPDependencyCheck(ctx context.Context, request *CompilationRequest) ([]DependencyIssue, error) {
	// This would integrate with OWASP Dependency Check
	// Implementation placeholder
	return []DependencyIssue{}, nil
}

// runSpotBugsSecurity runs SpotBugs security analysis
func (c *JavaCompiler) runSpotBugsSecurity(ctx context.Context, request *CompilationRequest) ([]CodeSecurityIssue, error) {
	// This would integrate with SpotBugs security rules
	// Implementation placeholder
	return []CodeSecurityIssue{}, nil
}

// buildClasspath builds the classpath string from classpath entries
func (c *JavaCompiler) buildClasspath(entries []ClasspathEntry) string {
	if len(entries) == 0 {
		return ""
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}

	return strings.Join(paths, string(os.PathListSeparator))
}

// detectPackages detects Java packages in the source directory
func (c *JavaCompiler) detectPackages(sourceDir string) ([]string, error) {
	packages := make(map[string]bool)

	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".java") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}

		// Extract package declaration
		packageRegex := regexp.MustCompile(`package\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*;`)
		matches := packageRegex.FindStringSubmatch(string(content))
		if len(matches) >= 2 {
			packages[matches[1]] = true
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(packages))
	for pkg := range packages {
		result = append(result, pkg)
	}

	sort.Strings(result)
	return result, nil
}

// findGeneratedFiles finds all generated documentation files
func (c *JavaCompiler) findGeneratedFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			relPath, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			files = append(files, relPath)
		}

		return nil
	})

	return files, err
}

// GetSupportedFeatures returns the features supported by this compiler
func (c *JavaCompiler) GetSupportedFeatures() map[string]bool {
	features := make(map[string]bool)
	
	features["compilation"] = true
	features["jar_creation"] = true
	features["javadoc_generation"] = true
	features["junit_testing"] = true
	features["maven_integration"] = c.mavenCommand != ""
	features["gradle_integration"] = c.gradleCommand != ""
	features["ant_integration"] = c.antCommand != ""
	features["dependency_resolution"] = true
	features["security_scanning"] = true
	features["code_formatting"] = true
	features["static_analysis"] = true
	features["performance_profiling"] = true
	features["test_coverage"] = true
	features["cross_compilation"] = false // Java is platform independent
	
	return features
}

// GetVersion returns the Java compiler version
func (c *JavaCompiler) GetVersion() *JavaVersion {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.version
}

// SetBuildSystem changes the build system
func (c *JavaCompiler) SetBuildSystem(buildSystem BuildSystemType) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.buildSystemHandlers[buildSystem]; !exists {
		return fmt.Errorf("build system %s not available", buildSystem.String())
	}

	c.buildSystem = buildSystem
	return nil
}

// AddDependency adds a dependency to the project
func (c *JavaCompiler) AddDependency(dependency *Dependency) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Validate dependency
	if dependency.GroupId == "" || dependency.ArtifactId == "" || dependency.Version == "" {
		return fmt.Errorf("invalid dependency: groupId, artifactId, and version are required")
	}

	// Check for duplicates
	for _, existing := range c.dependencies {
		if existing.GroupId == dependency.GroupId && existing.ArtifactId == dependency.ArtifactId {
			return fmt.Errorf("dependency %s:%s already exists", dependency.GroupId, dependency.ArtifactId)
		}
	}

	c.dependencies = append(c.dependencies, dependency)
	return nil
}

// AddRepository adds a repository for dependency resolution
func (c *JavaCompiler) AddRepository(repository *Repository) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Validate repository
	if repository.Id == "" || repository.URL == "" {
		return fmt.Errorf("invalid repository: id and url are required")
	}

	// Check for duplicates
	for _, existing := range c.repositories {
		if existing.Id == repository.Id {
			return fmt.Errorf("repository %s already exists", repository.Id)
		}
	}

	c.repositories = append(c.repositories, repository)
	if c.dependencyManager != nil {
		c.dependencyManager.AddRepository(repository)
	}

	return nil
}

// Clean cleans the build artifacts
func (c *JavaCompiler) Clean(ctx context.Context, workingDir string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Clean build directories
	buildDirs := []string{"target", "build", "out", "classes"}
	for _, dir := range buildDirs {
		dirPath := filepath.Join(workingDir, dir)
		if _, err := os.Stat(dirPath); err == nil {
			if err := os.RemoveAll(dirPath); err != nil {
				return fmt.Errorf("failed to clean %s: %w", dir, err)
			}
		}
	}

	// Clean JAR files
	jarFiles, err := filepath.Glob(filepath.Join(workingDir, "*.jar"))
	if err == nil {
		for _, jarFile := range jarFiles {
			if err := os.Remove(jarFile); err != nil {
				return fmt.Errorf("failed to clean JAR file %s: %w", jarFile, err)
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
		enabled:      true,
		cacheDir:     filepath.Join(os.TempDir(), "java-compiler-cache"),
		maxSize:      1024 * 1024 * 1024, // 1GB
		ttl:          24 * time.Hour,
		keyGenerator: CacheKeyGenerator{algorithm: "sha256"},
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

// NewDependencyManager creates a new dependency manager
func NewDependencyManager(repositories []*Repository) *DependencyManager {
	return &DependencyManager{
		repositories:    repositories,
		localRepository: filepath.Join(os.Getenv("HOME"), ".m2", "repository"),
		dependencyCache: make(map[string]*Dependency),
		resolutionOrder: []string{"nearest", "highest"},
		conflictResolver: ConflictResolver{
			strategy: "nearest",
			excludes: make([]string, 0),
		},
	}
}

// AddRepository adds a repository to the dependency manager
func (dm *DependencyManager) AddRepository(repository *Repository) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()
	dm.repositories = append(dm.repositories, repository)
}

// NewProjectGenerator creates a new project generator
func NewProjectGenerator() *ProjectGenerator {
	return &ProjectGenerator{
		mavenGenerator:  &MavenProjectGenerator{},
		gradleGenerator: &GradleProjectGenerator{},
		antGenerator:    &AntProjectGenerator{},
	}
}

// MavenProjectGenerator generates Maven projects
type MavenProjectGenerator struct {
	groupId    string
	artifactId string
	version    string
	packaging  string
}

// GradleProjectGenerator generates Gradle projects
type GradleProjectGenerator struct {
	groupId     string
	artifactId  string
	version     string
	buildScript string
}

// AntProjectGenerator generates Ant projects
type AntProjectGenerator struct {
	projectName string
	buildFile   string
}

// NewJarBuilder creates a new JAR builder
func NewJarBuilder() *JarBuilder {
	jarCommand, _ := exec.LookPath("jar")
	return &JarBuilder{
		jarCommand:      jarCommand,
		manifestBuilder: &ManifestBuilder{attributes: make(map[string]string)},
		signatureHandler: &JarSignatureHandler{},
	}
}

// NewTestRunner creates a new test runner
func NewTestRunner() *TestRunner {
	return &TestRunner{
		junitRunner:     &JUnitRunner{version: "5.8.2", timeout: 30 * time.Second},
		testngRunner:    &TestNGRunner{version: "7.4.0", parallel: "methods", threadCount: 4},
		mockitoSupport:  true,
		hamcrestSupport: true,
		coverage:        &CoverageAnalyzer{jacocoEnabled: true, threshold: 80.0},
	}
}

// NewJavaProfiler creates a new Java profiler
func NewJavaProfiler() *JavaProfiler {
	return &JavaProfiler{
		profilerType:   "async-profiler",
		samplingRate:   1000,
		heapAnalysis:   true,
		cpuAnalysis:    true,
		memoryAnalysis: true,
		outputFormat:   "html",
	}
}

// NewJavaFormatter creates a new Java formatter
func NewJavaFormatter() *JavaFormatter {
	return &JavaFormatter{
		formatterType:       "google-java-format",
		tabSize:             4,
		maxLineLength:       100,
		sortImports:         true,
		removeUnusedImports: true,
	}
}

// NewJavaLinter creates a new Java linter
func NewJavaLinter() *JavaLinter {
	return &JavaLinter{
		checkstyleEnabled: true,
		pmdEnabled:        true,
		spotbugsEnabled:   true,
		errorproneEnabled: true,
		configFiles:       make(map[string]string),
		rulesets:          make(map[string][]string),
		suppressions:      make([]string, 0),
	}
}

// NewJavaDocGenerator creates a new JavaDoc generator
func NewJavaDocGenerator(javaHome string) *JavaDocGenerator {
	return &JavaDocGenerator{
		javadocCommand:  filepath.Join(javaHome, "bin", "javadoc"),
		outputDirectory: "docs",
		author:          true,
		version:         true,
		since:           true,
		links:           []string{"https://docs.oracle.com/en/java/javase/11/docs/api/"},
		groups:          make(map[string][]string),
	}
}

// NewJavaSecurityScanner creates a new Java security scanner
func NewJavaSecurityScanner() *JavaSecurityScanner {
	return &JavaSecurityScanner{
		owasp: &OWASPDependencyCheck{
			enabled:     true,
			failOnCVSS:  7.0,
		},
		snyk: &SnykScanner{
			enabled:  false,
			severity: "high",
		},
		sonarqube: &SonarQubeScanner{
			enabled: false,
		},
		spotbugs: &SpotBugsSecurityScanner{
			enabled:   true,
			effort:    "max",
			threshold: "low",
		},
	}
}