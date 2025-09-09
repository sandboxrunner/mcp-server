package executors

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/types"
)

// MavenPOM represents a Maven pom.xml file structure
type MavenPOM struct {
	XMLName      xml.Name           `xml:"project"`
	ModelVersion string             `xml:"modelVersion"`
	GroupID      string             `xml:"groupId"`
	ArtifactID   string             `xml:"artifactId"`
	Version      string             `xml:"version"`
	Packaging    string             `xml:"packaging,omitempty"`
	Name         string             `xml:"name,omitempty"`
	Description  string             `xml:"description,omitempty"`
	Properties   *MavenProperties   `xml:"properties,omitempty"`
	Dependencies *MavenDependencies `xml:"dependencies,omitempty"`
	Build        *MavenBuild        `xml:"build,omitempty"`
}

// MavenProperties represents Maven properties
type MavenProperties struct {
	MavenCompilerSource string `xml:"maven.compiler.source,omitempty"`
	MavenCompilerTarget string `xml:"maven.compiler.target,omitempty"`
	JavaVersion         string `xml:"java.version,omitempty"`
	ProjectBuildSourceEncoding string `xml:"project.build.sourceEncoding,omitempty"`
}

// MavenDependencies represents Maven dependencies
type MavenDependencies struct {
	Dependency []MavenDependency `xml:"dependency"`
}

// MavenDependency represents a single Maven dependency
type MavenDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope,omitempty"`
}

// MavenBuild represents Maven build configuration
type MavenBuild struct {
	Plugins *MavenPlugins `xml:"plugins,omitempty"`
}

// MavenPlugins represents Maven plugins
type MavenPlugins struct {
	Plugin []MavenPlugin `xml:"plugin"`
}

// MavenPlugin represents a Maven plugin
type MavenPlugin struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// JavaExecutor handles Java code execution with classpath and Maven support
type JavaExecutor struct {
	*BaseExecutor
	javacCmd     string
	javaCmd      string
	mavenCmd     string
	buildTool    string // "maven" or "gradle"
	javaVersion  string
	mainClass    string
	classpath    []string
	mavenPOM     *MavenPOM
}

// NewJavaExecutor creates a new Java executor
func NewJavaExecutor() *JavaExecutor {
	base := NewBaseExecutor(
		types.LanguageJava,
		60*time.Second,
		[]string{"maven", "gradle"},
		true,
	)

	return &JavaExecutor{
		BaseExecutor: base,
		javacCmd:     "javac",
		javaCmd:      "java",
		mavenCmd:     "mvn",
		buildTool:    "maven",
		javaVersion:  "17",
		mainClass:    "Main",
		classpath:    []string{},
	}
}

// GetVersion returns the Java version
func (e *JavaExecutor) GetVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, e.javaCmd, "-version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to get Java version: %w", err)
	}

	version := strings.TrimSpace(string(output))
	// Extract version from output like "openjdk version "17.0.2" 2022-01-18"
	re := regexp.MustCompile(`version\s+"([^"]+)"`)
	matches := re.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1], nil
	}
	return version, nil
}

// SetupEnvironment prepares the Java execution environment
func (e *JavaExecutor) SetupEnvironment(ctx context.Context, options *ExecutionOptions) (*EnvironmentInfo, error) {
	// Set Java commands from options if specified
	if javacCmd, exists := options.CustomConfig["javac_cmd"]; exists {
		e.javacCmd = javacCmd
	}
	if javaCmd, exists := options.CustomConfig["java_cmd"]; exists {
		e.javaCmd = javaCmd
	}

	// Set build tool from options
	if buildTool, exists := options.CustomConfig["build_tool"]; exists {
		e.buildTool = buildTool
		if buildTool == "gradle" {
			e.mavenCmd = "gradle"
		}
	}

	// Set main class from options
	if mainClass, exists := options.CustomConfig["main_class"]; exists {
		e.mainClass = mainClass
	}

	// Set Java version from options
	if javaVersion, exists := options.CustomConfig["java_version"]; exists {
		e.javaVersion = javaVersion
	}

	// Create working directory
	if err := os.MkdirAll(options.WorkingDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create working directory: %w", err)
	}

	// Initialize project structure based on build tool
	if err := e.initializeJavaProject(ctx, options); err != nil {
		return nil, fmt.Errorf("failed to initialize Java project: %w", err)
	}

	// Get version info
	version, err := e.GetVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Java version: %w", err)
	}

	// Create environment info
	envInfo := &EnvironmentInfo{
		Language:       e.GetLanguage(),
		Version:        version,
		Interpreter:    e.javaCmd,
		PackageManager: e.mavenCmd,
		WorkingDir:     options.WorkingDir,
		ConfigFiles:    []string{},
		SystemInfo: map[string]string{
			"javac_executable": e.javacCmd,
			"java_executable":  e.javaCmd,
			"build_tool":       e.buildTool,
			"main_class":       e.mainClass,
			"java_version":     e.javaVersion,
		},
	}

	// Add configuration files based on build tool
	if e.buildTool == "maven" {
		pomPath := filepath.Join(options.WorkingDir, "pom.xml")
		if _, err := os.Stat(pomPath); err == nil {
			envInfo.ConfigFiles = append(envInfo.ConfigFiles, "pom.xml")
		}
	} else if e.buildTool == "gradle" {
		buildGradlePath := filepath.Join(options.WorkingDir, "build.gradle")
		if _, err := os.Stat(buildGradlePath); err == nil {
			envInfo.ConfigFiles = append(envInfo.ConfigFiles, "build.gradle")
		}
	}

	e.UpdateMetrics("setup_completed", time.Now())
	e.UpdateMetrics("build_tool", e.buildTool)
	e.UpdateMetrics("java_version", version)
	e.UpdateMetrics("main_class", e.mainClass)

	return envInfo, nil
}

// InstallPackages installs Java dependencies using Maven or Gradle
func (e *JavaExecutor) InstallPackages(ctx context.Context, packages []string, options *ExecutionOptions) (*PackageInstallResult, error) {
	if len(packages) == 0 {
		return &PackageInstallResult{Success: true}, nil
	}

	startTime := time.Now()
	result := &PackageInstallResult{
		InstalledPackages: []PackageInfo{},
		FailedPackages:    []string{},
	}

	// Ensure project is initialized
	if err := e.initializeJavaProject(ctx, options); err != nil {
		result.Error = fmt.Errorf("failed to initialize Java project: %w", err)
		return result, nil
	}

	// Update build configuration with dependencies
	if e.buildTool == "maven" {
		if err := e.updatePomDependencies(packages, options); err != nil {
			result.Error = fmt.Errorf("failed to update pom.xml: %w", err)
			return result, nil
		}
	} else {
		result.Error = fmt.Errorf("gradle dependency management not fully implemented")
		return result, nil
	}

	// Download dependencies
	var cmd *exec.Cmd
	if e.buildTool == "maven" {
		cmd = exec.CommandContext(ctx, e.mavenCmd, "dependency:resolve")
	}

	cmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		result.Error = fmt.Errorf("dependency resolution failed: %w", err)
		result.FailedPackages = packages
		return result, nil
	}

	// Parse successful installations
	result.Success = true
	for _, pkg := range packages {
		// Extract artifact info from Maven coordinates
		parts := strings.Split(pkg, ":")
		var name string
		if len(parts) >= 2 {
			name = parts[1] // artifactId
		} else {
			name = pkg
		}

		result.InstalledPackages = append(result.InstalledPackages, PackageInfo{
			Name: name,
		})
	}

	result.Duration = time.Since(startTime)

	e.UpdateMetrics("packages_installed", len(result.InstalledPackages))
	e.UpdateMetrics("package_install_duration", result.Duration)

	return result, nil
}

// ValidateCode performs Java syntax validation
func (e *JavaExecutor) ValidateCode(ctx context.Context, code string, options *ExecutionOptions) error {
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("empty code provided")
	}

	// Create temporary file for syntax checking
	tmpFile := filepath.Join(options.WorkingDir, "SyntaxCheck.java")
	
	// Ensure code has a class declaration
	if !strings.Contains(code, "class ") {
		code = fmt.Sprintf("public class SyntaxCheck {\n%s\n}", code)
	}
	
	if err := os.WriteFile(tmpFile, []byte(code), 0644); err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tmpFile)

	// Check syntax using javac
	cmd := exec.CommandContext(ctx, e.javacCmd, tmpFile)
	cmd.Dir = options.WorkingDir

	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("syntax error: %s", string(output))
	}

	// Remove compiled class file
	classFile := filepath.Join(options.WorkingDir, "SyntaxCheck.class")
	os.Remove(classFile)

	e.UpdateMetrics("syntax_validation_completed", time.Now())
	return nil
}

// PrepareFiles creates necessary files for Java execution
func (e *JavaExecutor) PrepareFiles(ctx context.Context, code string, options *ExecutionOptions) (map[string]string, error) {
	files := make(map[string]string)

	// Create source directory structure
	srcDir := "src"
	if e.buildTool == "maven" {
		srcDir = "src/main/java"
	}

	mainFile := filepath.Join(srcDir, fmt.Sprintf("%s.java", e.mainClass))

	// Ensure code has proper class structure
	if !strings.Contains(code, fmt.Sprintf("class %s", e.mainClass)) {
		if strings.Contains(code, "public static void main") {
			code = fmt.Sprintf("public class %s {\n%s\n}", e.mainClass, code)
		} else {
			code = fmt.Sprintf("public class %s {\n    public static void main(String[] args) {\n%s\n    }\n}", e.mainClass, code)
		}
	}

	files[mainFile] = code

	// Add user-specified files
	for filename, content := range options.Files {
		files[filename] = content
	}

	// Create build configuration
	if e.buildTool == "maven" {
		pomXML := e.createPomXML(options)
		files["pom.xml"] = pomXML
	}

	// Write all files to working directory
	for filename, content := range files {
		fullPath := filepath.Join(options.WorkingDir, filename)

		// Create directories if needed
		if dir := filepath.Dir(fullPath); dir != options.WorkingDir {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}

		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("failed to write file %s: %w", filename, err)
		}
	}

	e.UpdateMetrics("files_prepared", len(files))
	return files, nil
}

// Compile compiles Java code
func (e *JavaExecutor) Compile(ctx context.Context, code string, options *ExecutionOptions) (*CompilationResult, error) {
	startTime := time.Now()

	result := &CompilationResult{
		Success:  false,
		CacheKey: e.generateCacheKey(code, options),
		CacheHit: false,
	}

	var cmd *exec.Cmd
	var outputDir string

	if e.buildTool == "maven" {
		// Use Maven to compile
		cmd = exec.CommandContext(ctx, e.mavenCmd, "compile")
		outputDir = "target/classes"
	} else {
		// Use javac directly
		sourceFile := fmt.Sprintf("src/%s.java", e.mainClass)
		outputDir = "classes"
		
		// Create output directory
		if err := os.MkdirAll(filepath.Join(options.WorkingDir, outputDir), 0755); err != nil {
			result.Error = fmt.Errorf("failed to create output directory: %w", err)
			return result, nil
		}

		args := []string{"-d", outputDir}
		
		// Add classpath if specified
		if len(e.classpath) > 0 {
			args = append(args, "-cp", strings.Join(e.classpath, ":"))
		}
		
		// Add compile flags
		if len(options.CompileFlags) > 0 {
			args = append(args, options.CompileFlags...)
		}
		
		args = append(args, sourceFile)
		cmd = exec.CommandContext(ctx, e.javacCmd, args...)
	}

	cmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Error = fmt.Errorf("compilation failed: %w", err)
		return result, nil
	}

	// Check if class file was created
	classFile := filepath.Join(options.WorkingDir, outputDir, fmt.Sprintf("%s.class", e.mainClass))
	if _, err := os.Stat(classFile); err != nil {
		result.Error = fmt.Errorf("class file not found after compilation: %w", err)
		return result, nil
	}

	result.Success = true
	result.ArtifactPaths = []string{classFile}

	e.UpdateMetrics("compilation_completed", time.Now())
	e.UpdateMetrics("compilation_duration", result.Duration)

	return result, nil
}

// Execute runs Java code and returns the result
func (e *JavaExecutor) Execute(ctx context.Context, code string, options *ExecutionOptions) (*ExecutionResult, error) {
	startTime := time.Now()

	// Prepare files
	files, err := e.PrepareFiles(ctx, code, options)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare files: %w", err)
	}

	// Install packages if specified
	if len(options.Packages) > 0 {
		if _, err := e.InstallPackages(ctx, options.Packages, options); err != nil {
			return &ExecutionResult{
				ExitCode: 1,
				Stderr:   fmt.Sprintf("Package installation failed: %v", err),
				Duration: time.Since(startTime),
				Language: e.GetLanguage(),
				Error:    err,
			}, nil
		}
	}

	// Compile the code
	compileResult, err := e.Compile(ctx, code, options)
	if err != nil {
		return &ExecutionResult{
			ExitCode: 1,
			Stderr:   fmt.Sprintf("Compilation failed: %v", err),
			Duration: time.Since(startTime),
			Language: e.GetLanguage(),
			Error:    err,
		}, nil
	}

	if !compileResult.Success {
		return &ExecutionResult{
			ExitCode:        1,
			Stderr:          compileResult.Output,
			Duration:        time.Since(startTime),
			Language:        e.GetLanguage(),
			CompilationTime: compileResult.Duration,
			Error:           compileResult.Error,
		}, nil
	}

	// Execute the compiled class
	executionStart := time.Now()
	var cmd *exec.Cmd

	if e.buildTool == "maven" {
		// Use Maven to run
		args := []string{"exec:java", fmt.Sprintf("-Dexec.mainClass=%s", e.mainClass)}
		if len(options.RuntimeFlags) > 0 {
			args = append(args, fmt.Sprintf("-Dexec.args=%s", strings.Join(options.RuntimeFlags, " ")))
		}
		cmd = exec.CommandContext(ctx, e.mavenCmd, args...)
	} else {
		// Use java directly
		args := []string{"-cp", "classes"}
		
		// Add runtime flags
		if len(options.RuntimeFlags) > 0 {
			args = append(args, options.RuntimeFlags...)
		}
		
		args = append(args, e.mainClass)
		cmd = exec.CommandContext(ctx, e.javaCmd, args...)
	}

	cmd.Dir = options.WorkingDir

	// Set environment variables
	env := os.Environ()
	for k, v := range options.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = env

	// Setup stdin if provided
	if options.Stdin != "" {
		cmd.Stdin = strings.NewReader(options.Stdin)
	}

	// Execute command
	stdout, stderr, exitCode := e.executeCommand(ctx, cmd, options.Timeout)
	executionTime := time.Since(executionStart)
	totalDuration := time.Since(startTime)

	// Collect created files
	createdFiles := make([]string, 0, len(files))
	for filename := range files {
		createdFiles = append(createdFiles, filename)
	}

	// Add compiled artifacts
	if e.buildTool == "maven" {
		targetDir := filepath.Join(options.WorkingDir, "target")
		if _, err := os.Stat(targetDir); err == nil {
			createdFiles = append(createdFiles, "target/")
		}
	} else {
		classesDir := filepath.Join(options.WorkingDir, "classes")
		if _, err := os.Stat(classesDir); err == nil {
			createdFiles = append(createdFiles, "classes/")
		}
	}

	var commands []string
	if e.buildTool == "maven" {
		commands = []string{"mvn compile", fmt.Sprintf("mvn exec:java -Dexec.mainClass=%s", e.mainClass)}
	} else {
		commands = []string{
			fmt.Sprintf("javac -d classes src/%s.java", e.mainClass),
			fmt.Sprintf("java -cp classes %s", e.mainClass),
		}
	}

	result := &ExecutionResult{
		ExitCode:        exitCode,
		Stdout:          stdout,
		Stderr:          stderr,
		Duration:        totalDuration,
		Language:        e.GetLanguage(),
		Commands:        commands,
		CreatedFiles:    createdFiles,
		CompilationTime: compileResult.Duration,
		ExecutionTime:   executionTime,
		Metadata: map[string]string{
			"java_executable":  e.javaCmd,
			"working_dir":      options.WorkingDir,
			"build_tool":       e.buildTool,
			"main_class":       e.mainClass,
			"packages_count":   fmt.Sprintf("%d", len(options.Packages)),
		},
	}

	e.UpdateMetrics("execution_completed", time.Now())
	e.UpdateMetrics("execution_duration", totalDuration)
	e.UpdateMetrics("exit_code", exitCode)

	return result, nil
}

// initializeJavaProject initializes a Java project structure
func (e *JavaExecutor) initializeJavaProject(ctx context.Context, options *ExecutionOptions) error {
	// Create source directory structure
	srcDir := "src"
	if e.buildTool == "maven" {
		srcDir = "src/main/java"
	}

	if err := os.MkdirAll(filepath.Join(options.WorkingDir, srcDir), 0755); err != nil {
		return fmt.Errorf("failed to create source directory: %w", err)
	}

	// Create test directory for Maven
	if e.buildTool == "maven" {
		testDir := "src/test/java"
		if err := os.MkdirAll(filepath.Join(options.WorkingDir, testDir), 0755); err != nil {
			return fmt.Errorf("failed to create test directory: %w", err)
		}
	}

	return nil
}

// createPomXML creates a Maven pom.xml file
func (e *JavaExecutor) createPomXML(options *ExecutionOptions) string {
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.sandbox</groupId>
    <artifactId>sandbox-project</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    
    <name>Sandbox Java Project</name>
    <description>Generated project for code execution</description>
    
    <properties>
        <maven.compiler.source>` + e.javaVersion + `</maven.compiler.source>
        <maven.compiler.target>` + e.javaVersion + `</maven.compiler.target>
        <java.version>` + e.javaVersion + `</java.version>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>`

	if len(options.Packages) > 0 {
		pom += "\n    <dependencies>"
		for _, pkg := range options.Packages {
			// Parse Maven coordinates: groupId:artifactId:version
			parts := strings.Split(pkg, ":")
			if len(parts) >= 3 {
				pom += fmt.Sprintf(`
        <dependency>
            <groupId>%s</groupId>
            <artifactId>%s</artifactId>
            <version>%s</version>
        </dependency>`, parts[0], parts[1], parts[2])
			}
		}
		pom += "\n    </dependencies>"
	}

	pom += `
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.11.0</version>
                <configuration>
                    <source>` + e.javaVersion + `</source>
                    <target>` + e.javaVersion + `</target>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.codehaus.mojo</groupId>
                <artifactId>exec-maven-plugin</artifactId>
                <version>3.1.0</version>
                <configuration>
                    <mainClass>` + e.mainClass + `</mainClass>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>`

	return pom
}

// updatePomDependencies updates pom.xml with new dependencies
func (e *JavaExecutor) updatePomDependencies(packages []string, options *ExecutionOptions) error {
	pomPath := filepath.Join(options.WorkingDir, "pom.xml")

	// Create or update pom.xml
	pomContent := e.createPomXML(options)
	if err := os.WriteFile(pomPath, []byte(pomContent), 0644); err != nil {
		return fmt.Errorf("failed to write pom.xml: %w", err)
	}

	return nil
}

// executeCommand executes a command with timeout and returns stdout, stderr, and exit code
func (e *JavaExecutor) executeCommand(ctx context.Context, cmd *exec.Cmd, timeout time.Duration) (string, string, int) {
	// Create context with timeout
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd.Cancel = func() error {
			return cmd.Process.Kill()
		}
	}

	// Capture stdout and stderr separately
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Sprintf("Failed to create stdout pipe: %v", err), 1
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Sprintf("Failed to create stderr pipe: %v", err), 1
	}

	// Start command
	if err := cmd.Start(); err != nil {
		return "", fmt.Sprintf("Failed to start command: %v", err), 1
	}

	// Read output
	stdoutBytes, _ := readAll(stdout)
	stderrBytes, _ := readAll(stderr)

	// Wait for command to finish
	err = cmd.Wait()

	// Determine exit code
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return string(stdoutBytes), string(stderrBytes), exitCode
}

// generateCacheKey generates a cache key for compilation
func (e *JavaExecutor) generateCacheKey(code string, options *ExecutionOptions) string {
	// Simple hash-like key based on code and options
	key := fmt.Sprintf("java-%s-%s-%s-%v", code[:min(len(code), 100)], e.javaVersion, e.mainClass, options.CompileFlags)
	return fmt.Sprintf("%x", []byte(key))
}

// extractJavaImports extracts import statements from Java code
func (e *JavaExecutor) extractJavaImports(code string) []string {
	var imports []string

	// Regular expression for Java imports
	importPattern := regexp.MustCompile(`^\s*import\s+(?:static\s+)?([a-zA-Z_][a-zA-Z0-9_.]*(?:\.\*)?)\s*;`)

	lines := strings.Split(code, "\n")
	for _, line := range lines {
		matches := importPattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			importName := matches[1]
			// Skip java.lang.* imports (automatically available)
			if !strings.HasPrefix(importName, "java.lang.") {
				imports = append(imports, importName)
			}
		}
	}

	return removeDuplicates(imports)
}