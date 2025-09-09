package java

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// DirectBuildHandler handles direct javac compilation
type DirectBuildHandler struct {
	compiler *JavaCompiler
}

// NewDirectBuildHandler creates a new direct build handler
func NewDirectBuildHandler(compiler *JavaCompiler) *DirectBuildHandler {
	return &DirectBuildHandler{
		compiler: compiler,
	}
}

// Initialize initializes the direct build system
func (d *DirectBuildHandler) Initialize(ctx context.Context, request *CompilationRequest) error {
	// Create output directory
	outputDir := filepath.Join(request.WorkingDir, "classes")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	return nil
}

// Prepare prepares the direct build
func (d *DirectBuildHandler) Prepare(ctx context.Context, request *CompilationRequest) error {
	// Validate source files exist
	for _, sourceFile := range request.SourceFiles {
		fullPath := filepath.Join(request.WorkingDir, sourceFile)
		if _, err := os.Stat(fullPath); err != nil {
			return fmt.Errorf("source file not found: %s", sourceFile)
		}
	}
	return nil
}

// Compile compiles Java source files directly with javac
func (d *DirectBuildHandler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	response := &CompilationResponse{
		Metrics:     NewCompilationMetrics(),
		Warnings:    make([]CompilationWarning, 0),
		Errors:      make([]CompilationError, 0),
		OutputFiles: make([]string, 0),
		ClassFiles:  make([]string, 0),
	}

	// Build javac command
	args := []string{}

	// Add classpath
	if len(request.ClasspathEntries) > 0 {
		classpath := d.compiler.buildClasspath(request.ClasspathEntries)
		args = append(args, "-cp", classpath)
	}

	// Add compilation target
	if request.Target != nil {
		if request.Target.SourceVersion != "" {
			args = append(args, "-source", request.Target.SourceVersion)
		}
		if request.Target.TargetVersion != "" {
			args = append(args, "-target", request.Target.TargetVersion)
		}
	}

	// Add output directory
	outputDir := filepath.Join(request.WorkingDir, "classes")
	args = append(args, "-d", outputDir)

	// Add debug information if requested
	if request.Debug {
		args = append(args, "-g")
	}

	// Add optimization if requested
	if request.Optimize {
		args = append(args, "-O")
	}

	// Add verbose output for detailed compilation info
	args = append(args, "-verbose")

	// Add deprecation warnings
	args = append(args, "-deprecation")

	// Add unchecked warnings
	args = append(args, "-Xlint:unchecked")

	// Add source files
	for _, sourceFile := range request.SourceFiles {
		args = append(args, filepath.Join(request.WorkingDir, sourceFile))
	}

	// Execute javac
	cmd := exec.CommandContext(ctx, d.compiler.javacCommand, args...)
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

		// Parse compilation errors and warnings
		d.parseJavacOutput(string(output), response)
		return response, nil
	}

	// Find compiled class files
	classFiles, err := d.findClassFiles(outputDir)
	if err != nil {
		response.Success = false
		response.Error = fmt.Errorf("failed to find class files: %w", err)
		return response, response.Error
	}

	response.Success = true
	response.ClassFiles = classFiles
	response.OutputFiles = classFiles

	// Parse warnings from successful compilation
	d.parseJavacOutput(string(output), response)

	return response, nil
}

// Test runs tests for direct build (limited support)
func (d *DirectBuildHandler) Test(ctx context.Context, request *CompilationRequest) (*TestResult, error) {
	// Direct build has limited test support
	// Look for test classes and run them with java command
	testResult := &TestResult{
		Success:     true,
		TestsRun:    0,
		TestsPassed: 0,
		TestsFailed: 0,
		TestsSkipped: 0,
	}

	// Find test classes
	classesDir := filepath.Join(request.WorkingDir, "classes")
	testClasses, err := d.findTestClasses(classesDir)
	if err != nil {
		testResult.Success = false
		testResult.Output = fmt.Sprintf("Failed to find test classes: %v", err)
		return testResult, nil
	}

	if len(testClasses) == 0 {
		testResult.Output = "No test classes found"
		return testResult, nil
	}

	// Run each test class
	for _, testClass := range testClasses {
		result := d.runTestClass(ctx, request, testClass)
		testResult.TestsRun += result.TestsRun
		testResult.TestsPassed += result.TestsPassed
		testResult.TestsFailed += result.TestsFailed
		testResult.TestsSkipped += result.TestsSkipped
		
		if !result.Success {
			testResult.Success = false
			testResult.FailedTests = append(testResult.FailedTests, result.FailedTests...)
		}
	}

	return testResult, nil
}

// Package creates JAR files for direct build
func (d *DirectBuildHandler) Package(ctx context.Context, request *CompilationRequest) (*PackageResult, error) {
	result := &PackageResult{
		Success:    true,
		JarFiles:   make([]string, 0),
		Checksums:  make(map[string]string),
		Signatures: make(map[string]string),
		Metadata:   make(map[string]interface{}),
	}

	classesDir := filepath.Join(request.WorkingDir, "classes")
	jarFile := filepath.Join(request.WorkingDir, "application.jar")

	// Build jar command
	args := []string{"cf", jarFile}

	// Add manifest if main class is specified
	if request.MainClass != "" {
		manifestFile := filepath.Join(request.WorkingDir, "MANIFEST.MF")
		manifestContent := fmt.Sprintf("Manifest-Version: 1.0\nMain-Class: %s\n", request.MainClass)
		
		if err := os.WriteFile(manifestFile, []byte(manifestContent), 0644); err != nil {
			result.Success = false
			result.Metadata["error"] = fmt.Sprintf("Failed to create manifest: %v", err)
			return result, nil
		}
		
		args = []string{"cfm", jarFile, manifestFile}
	}

	// Add all class files
	args = append(args, "-C", classesDir, ".")

	// Execute jar command
	cmd := exec.CommandContext(ctx, d.compiler.jarBuilder.jarCommand, args...)
	cmd.Dir = request.WorkingDir
	output, err := cmd.CombinedOutput()

	if err != nil {
		result.Success = false
		result.Metadata["error"] = fmt.Sprintf("JAR creation failed: %v", err)
		result.Metadata["output"] = string(output)
		return result, nil
	}

	result.JarFiles = append(result.JarFiles, jarFile)
	result.Metadata["output"] = string(output)

	return result, nil
}

// Clean cleans direct build artifacts
func (d *DirectBuildHandler) Clean(ctx context.Context, workingDir string) error {
	dirsToClean := []string{"classes", "*.jar", "MANIFEST.MF"}
	
	for _, pattern := range dirsToClean {
		if strings.Contains(pattern, "*") {
			// Handle glob patterns
			matches, err := filepath.Glob(filepath.Join(workingDir, pattern))
			if err != nil {
				continue
			}
			for _, match := range matches {
				os.Remove(match)
			}
		} else {
			// Handle directories
			dirPath := filepath.Join(workingDir, pattern)
			os.RemoveAll(dirPath)
		}
	}

	return nil
}

// GetArtifacts returns build artifacts for direct build
func (d *DirectBuildHandler) GetArtifacts(workingDir string) ([]string, error) {
	artifacts := make([]string, 0)

	// Find class files
	classesDir := filepath.Join(workingDir, "classes")
	if _, err := os.Stat(classesDir); err == nil {
		classFiles, err := d.findClassFiles(classesDir)
		if err == nil {
			artifacts = append(artifacts, classFiles...)
		}
	}

	// Find JAR files
	jarFiles, err := filepath.Glob(filepath.Join(workingDir, "*.jar"))
	if err == nil {
		artifacts = append(artifacts, jarFiles...)
	}

	return artifacts, nil
}

// ValidateProject validates a direct build project
func (d *DirectBuildHandler) ValidateProject(workingDir string) error {
	// Check for Java source files
	javaFiles, err := filepath.Glob(filepath.Join(workingDir, "*.java"))
	if err != nil {
		return fmt.Errorf("failed to search for Java files: %w", err)
	}

	if len(javaFiles) == 0 {
		return fmt.Errorf("no Java source files found in %s", workingDir)
	}

	return nil
}

// parseJavacOutput parses javac output for errors and warnings
func (d *DirectBuildHandler) parseJavacOutput(output string, response *CompilationResponse) {
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse error/warning pattern: filename:line: error/warning: message
		errorRegex := regexp.MustCompile(`^(.+?):(\d+):\s*(error|warning):\s*(.+)$`)
		matches := errorRegex.FindStringSubmatch(line)
		
		if len(matches) >= 5 {
			file := matches[1]
			lineNum, _ := strconv.Atoi(matches[2])
			msgType := matches[3]
			message := matches[4]

			if msgType == "error" {
				response.Errors = append(response.Errors, CompilationError{
					File:    file,
					Line:    lineNum,
					Message: message,
					Type:    "compilation",
				})
			} else if msgType == "warning" {
				response.Warnings = append(response.Warnings, CompilationWarning{
					File:    file,
					Line:    lineNum,
					Message: message,
					Type:    "compilation",
				})
			}
		}
	}
}

// findClassFiles finds all compiled class files
func (d *DirectBuildHandler) findClassFiles(classesDir string) ([]string, error) {
	var classFiles []string

	err := filepath.Walk(classesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".class") {
			relPath, err := filepath.Rel(classesDir, path)
			if err != nil {
				return err
			}
			classFiles = append(classFiles, relPath)
		}

		return nil
	})

	return classFiles, err
}

// findTestClasses finds test classes (classes with Test suffix or main method)
func (d *DirectBuildHandler) findTestClasses(classesDir string) ([]string, error) {
	var testClasses []string

	err := filepath.Walk(classesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".class") {
			className := strings.TrimSuffix(filepath.Base(path), ".class")
			if strings.HasSuffix(className, "Test") || strings.Contains(className, "Test") {
				// Convert file path to class name
				relPath, err := filepath.Rel(classesDir, path)
				if err != nil {
					return err
				}
				className := strings.ReplaceAll(strings.TrimSuffix(relPath, ".class"), string(os.PathSeparator), ".")
				testClasses = append(testClasses, className)
			}
		}

		return nil
	})

	return testClasses, err
}

// runTestClass runs a single test class
func (d *DirectBuildHandler) runTestClass(ctx context.Context, request *CompilationRequest, testClass string) *TestResult {
	result := &TestResult{
		Success:     true,
		TestsRun:    1,
		TestsPassed: 0,
		TestsFailed: 0,
		TestsSkipped: 0,
		FailedTests: make([]FailedTest, 0),
	}

	// Build classpath
	classpath := filepath.Join(request.WorkingDir, "classes")
	if len(request.ClasspathEntries) > 0 {
		classpath += string(os.PathListSeparator) + d.compiler.buildClasspath(request.ClasspathEntries)
	}

	// Run the test class
	args := []string{"-cp", classpath, testClass}
	cmd := exec.CommandContext(ctx, d.compiler.javaCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		result.Success = false
		result.TestsFailed = 1
		result.FailedTests = append(result.FailedTests, FailedTest{
			TestClass:  testClass,
			TestMethod: "main",
			Error:      err.Error(),
			Stacktrace: string(output),
		})
	} else {
		result.TestsPassed = 1
	}

	return result
}

// MavenBuildHandler handles Maven-based builds
type MavenBuildHandler struct {
	compiler *JavaCompiler
}

// NewMavenBuildHandler creates a new Maven build handler
func NewMavenBuildHandler(compiler *JavaCompiler) *MavenBuildHandler {
	return &MavenBuildHandler{
		compiler: compiler,
	}
}

// Initialize initializes the Maven build system
func (m *MavenBuildHandler) Initialize(ctx context.Context, request *CompilationRequest) error {
	// Check if pom.xml exists, create if it doesn't
	pomPath := filepath.Join(request.WorkingDir, "pom.xml")
	if _, err := os.Stat(pomPath); os.IsNotExist(err) {
		return m.generatePomXml(request)
	}
	return nil
}

// Prepare prepares the Maven build
func (m *MavenBuildHandler) Prepare(ctx context.Context, request *CompilationRequest) error {
	// Create standard Maven directory structure
	dirs := []string{
		"src/main/java",
		"src/main/resources",
		"src/test/java",
		"src/test/resources",
		"target",
	}

	for _, dir := range dirs {
		dirPath := filepath.Join(request.WorkingDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create Maven directory %s: %w", dir, err)
		}
	}

	// Move source files to proper Maven structure if needed
	return m.organizeMavenSources(request)
}

// Compile compiles using Maven
func (m *MavenBuildHandler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	response := &CompilationResponse{
		Metrics:     NewCompilationMetrics(),
		Warnings:    make([]CompilationWarning, 0),
		Errors:      make([]CompilationError, 0),
		OutputFiles: make([]string, 0),
		ClassFiles:  make([]string, 0),
	}

	// Run Maven compile
	args := []string{"compile"}
	
	// Add debug flag if requested
	if request.Debug {
		args = append(args, "-X")
	}

	// Add offline mode if no internet access
	args = append(args, "-o")

	cmd := exec.CommandContext(ctx, m.compiler.mavenCommand, args...)
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
		m.parseMavenOutput(string(output), response)
		return response, nil
	}

	// Find compiled class files
	targetDir := filepath.Join(request.WorkingDir, "target", "classes")
	classFiles, err := m.findClassFiles(targetDir)
	if err != nil {
		response.Success = false
		response.Error = fmt.Errorf("failed to find class files: %w", err)
		return response, response.Error
	}

	response.Success = true
	response.ClassFiles = classFiles
	response.OutputFiles = classFiles

	// Parse warnings from successful compilation
	m.parseMavenOutput(string(output), response)

	return response, nil
}

// Test runs Maven tests
func (m *MavenBuildHandler) Test(ctx context.Context, request *CompilationRequest) (*TestResult, error) {
	args := []string{"test"}
	
	cmd := exec.CommandContext(ctx, m.compiler.mavenCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()

	testResult := &TestResult{
		Output:      string(output),
		FailedTests: make([]FailedTest, 0),
	}

	// Parse Maven test output
	m.parseMavenTestOutput(string(output), testResult)

	if err != nil && testResult.TestsFailed == 0 {
		// If Maven failed but we didn't detect test failures, it's a build error
		testResult.Success = false
		testResult.Output = fmt.Sprintf("Maven test execution failed: %v\n%s", err, output)
		return testResult, nil
	}

	testResult.Success = (testResult.TestsFailed == 0)
	return testResult, nil
}

// Package creates packages using Maven
func (m *MavenBuildHandler) Package(ctx context.Context, request *CompilationRequest) (*PackageResult, error) {
	result := &PackageResult{
		Success:    true,
		JarFiles:   make([]string, 0),
		Checksums:  make(map[string]string),
		Signatures: make(map[string]string),
		Metadata:   make(map[string]interface{}),
	}

	args := []string{"package"}
	
	cmd := exec.CommandContext(ctx, m.compiler.mavenCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()
	result.Metadata["output"] = string(output)

	if err != nil {
		result.Success = false
		result.Metadata["error"] = fmt.Sprintf("Maven package failed: %v", err)
		return result, nil
	}

	// Find generated JAR files
	targetDir := filepath.Join(request.WorkingDir, "target")
	jarFiles, err := filepath.Glob(filepath.Join(targetDir, "*.jar"))
	if err == nil {
		result.JarFiles = jarFiles
	}

	return result, nil
}

// Clean cleans Maven build artifacts
func (m *MavenBuildHandler) Clean(ctx context.Context, workingDir string) error {
	cmd := exec.CommandContext(ctx, m.compiler.mavenCommand, "clean")
	cmd.Dir = workingDir
	_, err := cmd.CombinedOutput()
	return err
}

// GetArtifacts returns Maven build artifacts
func (m *MavenBuildHandler) GetArtifacts(workingDir string) ([]string, error) {
	artifacts := make([]string, 0)

	targetDir := filepath.Join(workingDir, "target")
	if _, err := os.Stat(targetDir); err != nil {
		return artifacts, nil
	}

	// Find class files
	classesDir := filepath.Join(targetDir, "classes")
	if classFiles, err := m.findClassFiles(classesDir); err == nil {
		artifacts = append(artifacts, classFiles...)
	}

	// Find JAR files
	if jarFiles, err := filepath.Glob(filepath.Join(targetDir, "*.jar")); err == nil {
		artifacts = append(artifacts, jarFiles...)
	}

	return artifacts, nil
}

// ValidateProject validates a Maven project
func (m *MavenBuildHandler) ValidateProject(workingDir string) error {
	pomPath := filepath.Join(workingDir, "pom.xml")
	if _, err := os.Stat(pomPath); err != nil {
		return fmt.Errorf("pom.xml not found in %s", workingDir)
	}

	// Validate pom.xml structure
	content, err := os.ReadFile(pomPath)
	if err != nil {
		return fmt.Errorf("failed to read pom.xml: %w", err)
	}

	var pom struct {
		XMLName xml.Name `xml:"project"`
	}

	if err := xml.Unmarshal(content, &pom); err != nil {
		return fmt.Errorf("invalid pom.xml format: %w", err)
	}

	return nil
}

// generatePomXml generates a basic pom.xml file
func (m *MavenBuildHandler) generatePomXml(request *CompilationRequest) error {
	pomContent := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.example</groupId>
    <artifactId>sandbox-project</artifactId>
    <version>1.0-SNAPSHOT</version>
    <packaging>jar</packaging>
    
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
    
    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.8.1</version>
                <configuration>
                    <source>11</source>
                    <target>11</target>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.0.0-M5</version>
            </plugin>
        </plugins>
    </build>
</project>`

	// Update versions based on target
	if request.Target != nil && request.Target.SourceVersion != "" {
		pomContent = strings.ReplaceAll(pomContent, "<source>11</source>", fmt.Sprintf("<source>%s</source>", request.Target.SourceVersion))
		pomContent = strings.ReplaceAll(pomContent, "<target>11</target>", fmt.Sprintf("<target>%s</target>", request.Target.TargetVersion))
		pomContent = strings.ReplaceAll(pomContent, "<maven.compiler.source>11</maven.compiler.source>", fmt.Sprintf("<maven.compiler.source>%s</maven.compiler.source>", request.Target.SourceVersion))
		pomContent = strings.ReplaceAll(pomContent, "<maven.compiler.target>11</maven.compiler.target>", fmt.Sprintf("<maven.compiler.target>%s</maven.compiler.target>", request.Target.TargetVersion))
	}

	pomPath := filepath.Join(request.WorkingDir, "pom.xml")
	return os.WriteFile(pomPath, []byte(pomContent), 0644)
}

// organizeMavenSources moves source files to Maven directory structure
func (m *MavenBuildHandler) organizeMavenSources(request *CompilationRequest) error {
	mainJavaDir := filepath.Join(request.WorkingDir, "src", "main", "java")
	
	for _, sourceFile := range request.SourceFiles {
		sourcePath := filepath.Join(request.WorkingDir, sourceFile)
		
		// Skip if already in Maven structure
		if strings.HasPrefix(sourcePath, filepath.Join(request.WorkingDir, "src")) {
			continue
		}
		
		// Determine package structure from file
		packagePath, err := m.extractPackagePath(sourcePath)
		if err != nil {
			continue // Skip files we can't process
		}
		
		// Create target directory
		targetDir := filepath.Join(mainJavaDir, packagePath)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create package directory: %w", err)
		}
		
		// Move file
		targetPath := filepath.Join(targetDir, filepath.Base(sourceFile))
		if err := os.Rename(sourcePath, targetPath); err != nil {
			// If rename fails, try copy and delete
			if content, err := os.ReadFile(sourcePath); err == nil {
				if err := os.WriteFile(targetPath, content, 0644); err == nil {
					os.Remove(sourcePath)
				}
			}
		}
	}
	
	return nil
}

// extractPackagePath extracts package path from Java source file
func (m *MavenBuildHandler) extractPackagePath(sourceFile string) (string, error) {
	content, err := os.ReadFile(sourceFile)
	if err != nil {
		return "", err
	}

	// Extract package declaration
	packageRegex := regexp.MustCompile(`package\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*;`)
	matches := packageRegex.FindStringSubmatch(string(content))
	if len(matches) >= 2 {
		return strings.ReplaceAll(matches[1], ".", string(os.PathSeparator)), nil
	}

	return "", nil // Default package
}

// parseMavenOutput parses Maven compilation output
func (m *MavenBuildHandler) parseMavenOutput(output string, response *CompilationResponse) {
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse Maven error/warning pattern
		if strings.Contains(line, "[ERROR]") && strings.Contains(line, ".java:") {
			parts := strings.Split(line, ".java:")
			if len(parts) >= 2 {
				file := parts[0]
				if idx := strings.LastIndex(file, "[ERROR]"); idx != -1 {
					file = strings.TrimSpace(file[idx+7:]) + ".java"
				}
				
				messagePart := parts[1]
				lineColRegex := regexp.MustCompile(`^\[(\d+),(\d+)\]\s*(.+)$`)
				matches := lineColRegex.FindStringSubmatch(messagePart)
				
				if len(matches) >= 4 {
					lineNum, _ := strconv.Atoi(matches[1])
					colNum, _ := strconv.Atoi(matches[2])
					message := matches[3]
					
					response.Errors = append(response.Errors, CompilationError{
						File:    file,
						Line:    lineNum,
						Column:  colNum,
						Message: message,
						Type:    "compilation",
					})
				}
			}
		}

		if strings.Contains(line, "[WARNING]") && strings.Contains(line, ".java:") {
			// Similar parsing for warnings
			parts := strings.Split(line, ".java:")
			if len(parts) >= 2 {
				file := parts[0]
				if idx := strings.LastIndex(file, "[WARNING]"); idx != -1 {
					file = strings.TrimSpace(file[idx+9:]) + ".java"
				}
				
				messagePart := parts[1]
				lineColRegex := regexp.MustCompile(`^\[(\d+),(\d+)\]\s*(.+)$`)
				matches := lineColRegex.FindStringSubmatch(messagePart)
				
				if len(matches) >= 4 {
					lineNum, _ := strconv.Atoi(matches[1])
					colNum, _ := strconv.Atoi(matches[2])
					message := matches[3]
					
					response.Warnings = append(response.Warnings, CompilationWarning{
						File:    file,
						Line:    lineNum,
						Column:  colNum,
						Message: message,
						Type:    "compilation",
					})
				}
			}
		}
	}
}

// parseMavenTestOutput parses Maven test output
func (m *MavenBuildHandler) parseMavenTestOutput(output string, result *TestResult) {
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Parse test summary line
		if strings.Contains(line, "Tests run:") {
			// Pattern: Tests run: 5, Failures: 1, Errors: 0, Skipped: 2
			testSummaryRegex := regexp.MustCompile(`Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)`)
			matches := testSummaryRegex.FindStringSubmatch(line)
			
			if len(matches) >= 5 {
				result.TestsRun, _ = strconv.Atoi(matches[1])
				failures, _ := strconv.Atoi(matches[2])
				errors, _ := strconv.Atoi(matches[3])
				result.TestsSkipped, _ = strconv.Atoi(matches[4])
				
				result.TestsFailed = failures + errors
				result.TestsPassed = result.TestsRun - result.TestsFailed - result.TestsSkipped
			}
		}
		
		// Parse individual test failures
		if strings.Contains(line, "FAILURE") || strings.Contains(line, "ERROR") {
			// Extract test method and class information
			testFailureRegex := regexp.MustCompile(`(\w+)\(([^)]+)\)`)
			matches := testFailureRegex.FindStringSubmatch(line)
			
			if len(matches) >= 3 {
				failedTest := FailedTest{
					TestMethod: matches[1],
					TestClass:  matches[2],
					Error:      "Test failed",
				}
				result.FailedTests = append(result.FailedTests, failedTest)
			}
		}
	}
}

// findClassFiles finds all compiled class files in target directory
func (m *MavenBuildHandler) findClassFiles(targetDir string) ([]string, error) {
	var classFiles []string

	if _, err := os.Stat(targetDir); err != nil {
		return classFiles, nil
	}

	err := filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".class") {
			relPath, err := filepath.Rel(targetDir, path)
			if err != nil {
				return err
			}
			classFiles = append(classFiles, relPath)
		}

		return nil
	})

	return classFiles, err
}

// GradleBuildHandler handles Gradle-based builds
type GradleBuildHandler struct {
	compiler *JavaCompiler
}

// NewGradleBuildHandler creates a new Gradle build handler
func NewGradleBuildHandler(compiler *JavaCompiler) *GradleBuildHandler {
	return &GradleBuildHandler{
		compiler: compiler,
	}
}

// Initialize initializes the Gradle build system
func (g *GradleBuildHandler) Initialize(ctx context.Context, request *CompilationRequest) error {
	// Check if build.gradle exists, create if it doesn't
	buildGradlePath := filepath.Join(request.WorkingDir, "build.gradle")
	if _, err := os.Stat(buildGradlePath); os.IsNotExist(err) {
		return g.generateBuildGradle(request)
	}
	return nil
}

// Prepare prepares the Gradle build
func (g *GradleBuildHandler) Prepare(ctx context.Context, request *CompilationRequest) error {
	// Create standard Gradle directory structure
	dirs := []string{
		"src/main/java",
		"src/main/resources",
		"src/test/java",
		"src/test/resources",
		"build",
	}

	for _, dir := range dirs {
		dirPath := filepath.Join(request.WorkingDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create Gradle directory %s: %w", dir, err)
		}
	}

	// Move source files to proper Gradle structure if needed
	return g.organizeGradleSources(request)
}

// Compile compiles using Gradle
func (g *GradleBuildHandler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	response := &CompilationResponse{
		Metrics:     NewCompilationMetrics(),
		Warnings:    make([]CompilationWarning, 0),
		Errors:      make([]CompilationError, 0),
		OutputFiles: make([]string, 0),
		ClassFiles:  make([]string, 0),
	}

	// Run Gradle compile
	args := []string{"compileJava"}
	
	// Add debug flag if requested
	if request.Debug {
		args = append(args, "--debug")
	}

	// Add offline mode if no internet access
	args = append(args, "--offline")

	cmd := exec.CommandContext(ctx, g.compiler.gradleCommand, args...)
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
		g.parseGradleOutput(string(output), response)
		return response, nil
	}

	// Find compiled class files
	buildDir := filepath.Join(request.WorkingDir, "build", "classes", "java", "main")
	classFiles, err := g.findClassFiles(buildDir)
	if err != nil {
		response.Success = false
		response.Error = fmt.Errorf("failed to find class files: %w", err)
		return response, response.Error
	}

	response.Success = true
	response.ClassFiles = classFiles
	response.OutputFiles = classFiles

	// Parse warnings from successful compilation
	g.parseGradleOutput(string(output), response)

	return response, nil
}

// Test runs Gradle tests
func (g *GradleBuildHandler) Test(ctx context.Context, request *CompilationRequest) (*TestResult, error) {
	args := []string{"test"}
	
	cmd := exec.CommandContext(ctx, g.compiler.gradleCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()

	testResult := &TestResult{
		Output:      string(output),
		FailedTests: make([]FailedTest, 0),
	}

	// Parse Gradle test output
	g.parseGradleTestOutput(string(output), testResult)

	if err != nil && testResult.TestsFailed == 0 {
		testResult.Success = false
		testResult.Output = fmt.Sprintf("Gradle test execution failed: %v\n%s", err, output)
		return testResult, nil
	}

	testResult.Success = (testResult.TestsFailed == 0)
	return testResult, nil
}

// Package creates packages using Gradle
func (g *GradleBuildHandler) Package(ctx context.Context, request *CompilationRequest) (*PackageResult, error) {
	result := &PackageResult{
		Success:    true,
		JarFiles:   make([]string, 0),
		Checksums:  make(map[string]string),
		Signatures: make(map[string]string),
		Metadata:   make(map[string]interface{}),
	}

	args := []string{"jar"}
	
	cmd := exec.CommandContext(ctx, g.compiler.gradleCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()
	result.Metadata["output"] = string(output)

	if err != nil {
		result.Success = false
		result.Metadata["error"] = fmt.Sprintf("Gradle jar task failed: %v", err)
		return result, nil
	}

	// Find generated JAR files
	buildDir := filepath.Join(request.WorkingDir, "build", "libs")
	jarFiles, err := filepath.Glob(filepath.Join(buildDir, "*.jar"))
	if err == nil {
		result.JarFiles = jarFiles
	}

	return result, nil
}

// Clean cleans Gradle build artifacts
func (g *GradleBuildHandler) Clean(ctx context.Context, workingDir string) error {
	cmd := exec.CommandContext(ctx, g.compiler.gradleCommand, "clean")
	cmd.Dir = workingDir
	_, err := cmd.CombinedOutput()
	return err
}

// GetArtifacts returns Gradle build artifacts
func (g *GradleBuildHandler) GetArtifacts(workingDir string) ([]string, error) {
	artifacts := make([]string, 0)

	buildDir := filepath.Join(workingDir, "build")
	if _, err := os.Stat(buildDir); err != nil {
		return artifacts, nil
	}

	// Find class files
	classesDir := filepath.Join(buildDir, "classes", "java", "main")
	if classFiles, err := g.findClassFiles(classesDir); err == nil {
		artifacts = append(artifacts, classFiles...)
	}

	// Find JAR files
	libsDir := filepath.Join(buildDir, "libs")
	if jarFiles, err := filepath.Glob(filepath.Join(libsDir, "*.jar")); err == nil {
		artifacts = append(artifacts, jarFiles...)
	}

	return artifacts, nil
}

// ValidateProject validates a Gradle project
func (g *GradleBuildHandler) ValidateProject(workingDir string) error {
	buildGradlePath := filepath.Join(workingDir, "build.gradle")
	if _, err := os.Stat(buildGradlePath); err != nil {
		return fmt.Errorf("build.gradle not found in %s", workingDir)
	}

	return nil
}

// generateBuildGradle generates a basic build.gradle file
func (g *GradleBuildHandler) generateBuildGradle(request *CompilationRequest) error {
	javaVersion := "11"
	if request.Target != nil && request.Target.SourceVersion != "" {
		javaVersion = request.Target.SourceVersion
	}

	buildGradleContent := fmt.Sprintf(`plugins {
    id 'java'
    id 'application'
}

group = 'com.example'
version = '1.0-SNAPSHOT'

java {
    sourceCompatibility = JavaVersion.VERSION_%s
    targetCompatibility = JavaVersion.VERSION_%s
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation 'junit:junit:4.13.2'
}

application {
    mainClass = '%s'
}

test {
    useJUnit()
}`, javaVersion, javaVersion, request.MainClass)

	buildGradlePath := filepath.Join(request.WorkingDir, "build.gradle")
	return os.WriteFile(buildGradlePath, []byte(buildGradleContent), 0644)
}

// organizeGradleSources moves source files to Gradle directory structure
func (g *GradleBuildHandler) organizeGradleSources(request *CompilationRequest) error {
	mainJavaDir := filepath.Join(request.WorkingDir, "src", "main", "java")
	
	for _, sourceFile := range request.SourceFiles {
		sourcePath := filepath.Join(request.WorkingDir, sourceFile)
		
		// Skip if already in Gradle structure
		if strings.HasPrefix(sourcePath, filepath.Join(request.WorkingDir, "src")) {
			continue
		}
		
		// Determine package structure from file
		packagePath, err := g.extractPackagePath(sourcePath)
		if err != nil {
			continue // Skip files we can't process
		}
		
		// Create target directory
		targetDir := filepath.Join(mainJavaDir, packagePath)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("failed to create package directory: %w", err)
		}
		
		// Move file
		targetPath := filepath.Join(targetDir, filepath.Base(sourceFile))
		if err := os.Rename(sourcePath, targetPath); err != nil {
			// If rename fails, try copy and delete
			if content, err := os.ReadFile(sourcePath); err == nil {
				if err := os.WriteFile(targetPath, content, 0644); err == nil {
					os.Remove(sourcePath)
				}
			}
		}
	}
	
	return nil
}

// extractPackagePath extracts package path from Java source file
func (g *GradleBuildHandler) extractPackagePath(sourceFile string) (string, error) {
	content, err := os.ReadFile(sourceFile)
	if err != nil {
		return "", err
	}

	packageRegex := regexp.MustCompile(`package\s+([a-zA-Z_][a-zA-Z0-9_.]*)\s*;`)
	matches := packageRegex.FindStringSubmatch(string(content))
	if len(matches) >= 2 {
		return strings.ReplaceAll(matches[1], ".", string(os.PathSeparator)), nil
	}

	return "", nil
}

// parseGradleOutput parses Gradle compilation output
func (g *GradleBuildHandler) parseGradleOutput(output string, response *CompilationResponse) {
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse Gradle error/warning pattern
		if strings.Contains(line, "error:") || strings.Contains(line, "warning:") {
			errorRegex := regexp.MustCompile(`(.+?):(\d+):\s*(error|warning):\s*(.+)`)
			matches := errorRegex.FindStringSubmatch(line)
			
			if len(matches) >= 5 {
				file := matches[1]
				lineNum, _ := strconv.Atoi(matches[2])
				msgType := matches[3]
				message := matches[4]

				if msgType == "error" {
					response.Errors = append(response.Errors, CompilationError{
						File:    file,
						Line:    lineNum,
						Message: message,
						Type:    "compilation",
					})
				} else if msgType == "warning" {
					response.Warnings = append(response.Warnings, CompilationWarning{
						File:    file,
						Line:    lineNum,
						Message: message,
						Type:    "compilation",
					})
				}
			}
		}
	}
}

// parseGradleTestOutput parses Gradle test output
func (g *GradleBuildHandler) parseGradleTestOutput(output string, result *TestResult) {
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Parse test summary
		if strings.Contains(line, "tests completed") {
			testSummaryRegex := regexp.MustCompile(`(\d+)\s+tests?\s+completed(?:,\s+(\d+)\s+failed)?(?:,\s+(\d+)\s+skipped)?`)
			matches := testSummaryRegex.FindStringSubmatch(line)
			
			if len(matches) >= 2 {
				result.TestsRun, _ = strconv.Atoi(matches[1])
				if len(matches) >= 3 && matches[2] != "" {
					result.TestsFailed, _ = strconv.Atoi(matches[2])
				}
				if len(matches) >= 4 && matches[3] != "" {
					result.TestsSkipped, _ = strconv.Atoi(matches[3])
				}
				result.TestsPassed = result.TestsRun - result.TestsFailed - result.TestsSkipped
			}
		}
	}
}

// findClassFiles finds all compiled class files
func (g *GradleBuildHandler) findClassFiles(classesDir string) ([]string, error) {
	var classFiles []string

	if _, err := os.Stat(classesDir); err != nil {
		return classFiles, nil
	}

	err := filepath.Walk(classesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".class") {
			relPath, err := filepath.Rel(classesDir, path)
			if err != nil {
				return err
			}
			classFiles = append(classFiles, relPath)
		}

		return nil
	})

	return classFiles, err
}

// AntBuildHandler handles Ant-based builds
type AntBuildHandler struct {
	compiler *JavaCompiler
}

// NewAntBuildHandler creates a new Ant build handler
func NewAntBuildHandler(compiler *JavaCompiler) *AntBuildHandler {
	return &AntBuildHandler{
		compiler: compiler,
	}
}

// Initialize initializes the Ant build system
func (a *AntBuildHandler) Initialize(ctx context.Context, request *CompilationRequest) error {
	buildXmlPath := filepath.Join(request.WorkingDir, "build.xml")
	if _, err := os.Stat(buildXmlPath); os.IsNotExist(err) {
		return a.generateBuildXml(request)
	}
	return nil
}

// Prepare prepares the Ant build
func (a *AntBuildHandler) Prepare(ctx context.Context, request *CompilationRequest) error {
	dirs := []string{"src", "build", "lib"}
	
	for _, dir := range dirs {
		dirPath := filepath.Join(request.WorkingDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create Ant directory %s: %w", dir, err)
		}
	}

	return nil
}

// Compile compiles using Ant
func (a *AntBuildHandler) Compile(ctx context.Context, request *CompilationRequest) (*CompilationResponse, error) {
	response := &CompilationResponse{
		Metrics:     NewCompilationMetrics(),
		Warnings:    make([]CompilationWarning, 0),
		Errors:      make([]CompilationError, 0),
		OutputFiles: make([]string, 0),
		ClassFiles:  make([]string, 0),
	}

	args := []string{"compile"}
	
	cmd := exec.CommandContext(ctx, a.compiler.antCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()
	response.Output = string(output)

	if err != nil {
		response.Success = false
		response.Error = err
		return response, nil
	}

	// Find compiled class files
	buildDir := filepath.Join(request.WorkingDir, "build")
	classFiles, err := a.findClassFiles(buildDir)
	if err != nil {
		response.Success = false
		response.Error = fmt.Errorf("failed to find class files: %w", err)
		return response, response.Error
	}

	response.Success = true
	response.ClassFiles = classFiles
	response.OutputFiles = classFiles

	return response, nil
}

// Test runs Ant tests
func (a *AntBuildHandler) Test(ctx context.Context, request *CompilationRequest) (*TestResult, error) {
	args := []string{"test"}
	
	cmd := exec.CommandContext(ctx, a.compiler.antCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()

	testResult := &TestResult{
		Output:      string(output),
		Success:     err == nil,
		FailedTests: make([]FailedTest, 0),
	}

	return testResult, nil
}

// Package creates packages using Ant
func (a *AntBuildHandler) Package(ctx context.Context, request *CompilationRequest) (*PackageResult, error) {
	result := &PackageResult{
		Success:  true,
		JarFiles: make([]string, 0),
		Metadata: make(map[string]interface{}),
	}

	args := []string{"jar"}
	
	cmd := exec.CommandContext(ctx, a.compiler.antCommand, args...)
	cmd.Dir = request.WorkingDir

	output, err := cmd.CombinedOutput()
	result.Metadata["output"] = string(output)

	if err != nil {
		result.Success = false
		result.Metadata["error"] = fmt.Sprintf("Ant jar task failed: %v", err)
		return result, nil
	}

	return result, nil
}

// Clean cleans Ant build artifacts
func (a *AntBuildHandler) Clean(ctx context.Context, workingDir string) error {
	cmd := exec.CommandContext(ctx, a.compiler.antCommand, "clean")
	cmd.Dir = workingDir
	_, err := cmd.CombinedOutput()
	return err
}

// GetArtifacts returns Ant build artifacts
func (a *AntBuildHandler) GetArtifacts(workingDir string) ([]string, error) {
	artifacts := make([]string, 0)
	
	buildDir := filepath.Join(workingDir, "build")
	if classFiles, err := a.findClassFiles(buildDir); err == nil {
		artifacts = append(artifacts, classFiles...)
	}

	return artifacts, nil
}

// ValidateProject validates an Ant project
func (a *AntBuildHandler) ValidateProject(workingDir string) error {
	buildXmlPath := filepath.Join(workingDir, "build.xml")
	if _, err := os.Stat(buildXmlPath); err != nil {
		return fmt.Errorf("build.xml not found in %s", workingDir)
	}
	return nil
}

// generateBuildXml generates a basic build.xml file
func (a *AntBuildHandler) generateBuildXml(request *CompilationRequest) error {
	buildXmlContent := `<?xml version="1.0" encoding="UTF-8"?>
<project name="sandbox-project" default="compile" basedir=".">
    <property name="src.dir" value="src"/>
    <property name="build.dir" value="build"/>
    <property name="lib.dir" value="lib"/>
    
    <path id="classpath">
        <fileset dir="${lib.dir}" includes="**/*.jar"/>
    </path>
    
    <target name="init">
        <mkdir dir="${build.dir}"/>
    </target>
    
    <target name="compile" depends="init">
        <javac srcdir="${src.dir}" destdir="${build.dir}" classpathref="classpath" includeantruntime="false"/>
    </target>
    
    <target name="jar" depends="compile">
        <jar destfile="${build.dir}/application.jar" basedir="${build.dir}"/>
    </target>
    
    <target name="clean">
        <delete dir="${build.dir}"/>
    </target>
    
    <target name="test" depends="compile">
        <java classname="TestRunner" classpathref="classpath">
            <classpath>
                <pathelement location="${build.dir}"/>
            </classpath>
        </java>
    </target>
</project>`

	buildXmlPath := filepath.Join(request.WorkingDir, "build.xml")
	return os.WriteFile(buildXmlPath, []byte(buildXmlContent), 0644)
}

// findClassFiles finds all compiled class files for Ant
func (a *AntBuildHandler) findClassFiles(buildDir string) ([]string, error) {
	var classFiles []string

	if _, err := os.Stat(buildDir); err != nil {
		return classFiles, nil
	}

	err := filepath.Walk(buildDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".class") {
			relPath, err := filepath.Rel(buildDir, path)
			if err != nil {
				return err
			}
			classFiles = append(classFiles, relPath)
		}

		return nil
	})

	return classFiles, err
}