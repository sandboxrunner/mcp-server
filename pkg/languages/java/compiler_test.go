package java

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewJavaCompiler(t *testing.T) {
	// Test creating a new Java compiler
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Verify compiler was created successfully
	if compiler == nil {
		t.Fatal("Expected compiler to be created, got nil")
	}

	// Verify compiler type
	if compiler.compilerType != JavacCompiler {
		t.Errorf("Expected compiler type %v, got %v", JavacCompiler, compiler.compilerType)
	}

	// Verify build system
	if compiler.buildSystem != DirectBuild {
		t.Errorf("Expected build system %v, got %v", DirectBuild, compiler.buildSystem)
	}

	// Verify components are initialized
	if compiler.dependencyManager == nil {
		t.Error("Expected dependency manager to be initialized")
	}
	if compiler.projectGenerator == nil {
		t.Error("Expected project generator to be initialized")
	}
	if compiler.jarBuilder == nil {
		t.Error("Expected JAR builder to be initialized")
	}
	if compiler.testRunner == nil {
		t.Error("Expected test runner to be initialized")
	}
}

func TestJavaCompilerInitialization(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Test Java version detection
	version := compiler.GetVersion()
	if version == nil {
		t.Error("Expected Java version to be detected")
	}

	// Test supported features
	features := compiler.GetSupportedFeatures()
	expectedFeatures := []string{
		"compilation",
		"jar_creation",
		"javadoc_generation",
		"junit_testing",
		"dependency_resolution",
	}

	for _, feature := range expectedFeatures {
		if !features[feature] {
			t.Errorf("Expected feature %s to be supported", feature)
		}
	}
}

func TestSimpleJavaCompilation(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Create temporary directory
	tempDir := t.TempDir()

	// Create a simple Java source file
	javaCode := `public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}`

	sourceFile := filepath.Join(tempDir, "HelloWorld.java")
	if err := os.WriteFile(sourceFile, []byte(javaCode), 0644); err != nil {
		t.Fatalf("Failed to write source file: %v", err)
	}

	// Create compilation request
	request := &CompilationRequest{
		WorkingDir:   tempDir,
		SourceFiles:  []string{"HelloWorld.java"},
		MainClass:    "HelloWorld",
		BuildSystem:  DirectBuild,
		Timeout:      30 * time.Second,
		Environment:  make(map[string]string),
		ClasspathEntries: make([]ClasspathEntry, 0),
		Dependencies: make([]*Dependency, 0),
	}

	// Compile the code
	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected compilation to succeed, but it failed: %v", response.Error)
		t.Logf("Compilation output: %s", response.Output)
		for _, error := range response.Errors {
			t.Logf("Error: %s:%d - %s", error.File, error.Line, error.Message)
		}
	}

	// Verify class files were created
	if len(response.ClassFiles) == 0 {
		t.Error("Expected class files to be created")
	}

	// Verify HelloWorld.class exists
	classFile := filepath.Join(tempDir, "classes", "HelloWorld.class")
	if _, err := os.Stat(classFile); err != nil {
		t.Errorf("Expected class file to exist: %v", err)
	}
}

func TestJavaCompilationWithPackages(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	tempDir := t.TempDir()

	// Create Java source file with package
	javaCode := `package com.example.test;

public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
    
    public int subtract(int a, int b) {
        return a - b;
    }
}`

	// Create package directory
	packageDir := filepath.Join(tempDir, "com", "example", "test")
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		t.Fatalf("Failed to create package directory: %v", err)
	}

	sourceFile := filepath.Join(packageDir, "Calculator.java")
	if err := os.WriteFile(sourceFile, []byte(javaCode), 0644); err != nil {
		t.Fatalf("Failed to write source file: %v", err)
	}

	request := &CompilationRequest{
		WorkingDir:   tempDir,
		SourceFiles:  []string{filepath.Join("com", "example", "test", "Calculator.java")},
		BuildSystem:  DirectBuild,
		Timeout:      30 * time.Second,
		Environment:  make(map[string]string),
		ClasspathEntries: make([]ClasspathEntry, 0),
		Dependencies: make([]*Dependency, 0),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected compilation to succeed: %v", response.Error)
		t.Logf("Output: %s", response.Output)
	}

	// Verify class file was created in correct package structure
	classFile := filepath.Join(tempDir, "classes", "com", "example", "test", "Calculator.class")
	if _, err := os.Stat(classFile); err != nil {
		t.Errorf("Expected class file to exist at %s: %v", classFile, err)
	}
}

func TestJavaCompilationWithErrors(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	tempDir := t.TempDir()

	// Create Java source file with syntax errors
	javaCode := `public class BrokenCode {
    public static void main(String[] args) {
        // Missing semicolon
        System.out.println("This will fail")
        
        // Undefined variable
        System.out.println(undefinedVariable);
    }
}`

	sourceFile := filepath.Join(tempDir, "BrokenCode.java")
	if err := os.WriteFile(sourceFile, []byte(javaCode), 0644); err != nil {
		t.Fatalf("Failed to write source file: %v", err)
	}

	request := &CompilationRequest{
		WorkingDir:   tempDir,
		SourceFiles:  []string{"BrokenCode.java"},
		BuildSystem:  DirectBuild,
		Timeout:      30 * time.Second,
		Environment:  make(map[string]string),
		ClasspathEntries: make([]ClasspathEntry, 0),
		Dependencies: make([]*Dependency, 0),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	
	if err != nil {
		t.Fatalf("Compilation execution failed: %v", err)
	}

	// Compilation should fail
	if response.Success {
		t.Error("Expected compilation to fail due to syntax errors")
	}

	// Should have compilation errors
	if len(response.Errors) == 0 {
		t.Error("Expected compilation errors to be reported")
	}

	// Verify error details
	hasExpectedError := false
	for _, compErr := range response.Errors {
		if strings.Contains(compErr.Message, "';' expected") || 
		   strings.Contains(compErr.Message, "cannot find symbol") {
			hasExpectedError = true
			break
		}
	}
	
	if !hasExpectedError {
		t.Errorf("Expected specific compilation errors, got: %v", response.Errors)
	}
}

func TestJavaCompilationWithMultipleFiles(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	tempDir := t.TempDir()

	// Create main class
	mainCode := `public class Main {
    public static void main(String[] args) {
        Calculator calc = new Calculator();
        int result = calc.add(5, 3);
        System.out.println("Result: " + result);
    }
}`

	// Create calculator class
	calcCode := `public class Calculator {
    public int add(int a, int b) {
        return a + b;
    }
    
    public int multiply(int a, int b) {
        return a * b;
    }
}`

	mainFile := filepath.Join(tempDir, "Main.java")
	calcFile := filepath.Join(tempDir, "Calculator.java")

	if err := os.WriteFile(mainFile, []byte(mainCode), 0644); err != nil {
		t.Fatalf("Failed to write main file: %v", err)
	}

	if err := os.WriteFile(calcFile, []byte(calcCode), 0644); err != nil {
		t.Fatalf("Failed to write calculator file: %v", err)
	}

	request := &CompilationRequest{
		WorkingDir:   tempDir,
		SourceFiles:  []string{"Main.java", "Calculator.java"},
		MainClass:    "Main",
		BuildSystem:  DirectBuild,
		Timeout:      30 * time.Second,
		Environment:  make(map[string]string),
		ClasspathEntries: make([]ClasspathEntry, 0),
		Dependencies: make([]*Dependency, 0),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected compilation to succeed: %v", response.Error)
		t.Logf("Output: %s", response.Output)
	}

	// Verify both class files were created
	expectedClasses := []string{"Main.class", "Calculator.class"}
	classesDir := filepath.Join(tempDir, "classes")

	for _, className := range expectedClasses {
		classFile := filepath.Join(classesDir, className)
		if _, err := os.Stat(classFile); err != nil {
			t.Errorf("Expected class file %s to exist: %v", className, err)
		}
	}
}

func TestJavaCompilationWithJarCreation(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	tempDir := t.TempDir()

	javaCode := `public class Application {
    public static void main(String[] args) {
        System.out.println("Application running...");
    }
}`

	sourceFile := filepath.Join(tempDir, "Application.java")
	if err := os.WriteFile(sourceFile, []byte(javaCode), 0644); err != nil {
		t.Fatalf("Failed to write source file: %v", err)
	}

	request := &CompilationRequest{
		WorkingDir:   tempDir,
		SourceFiles:  []string{"Application.java"},
		MainClass:    "Application",
		BuildSystem:  DirectBuild,
		CreateJar:    true,
		Timeout:      30 * time.Second,
		Environment:  make(map[string]string),
		ClasspathEntries: make([]ClasspathEntry, 0),
		Dependencies: make([]*Dependency, 0),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)
	
	if err != nil {
		t.Fatalf("Compilation failed: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected compilation to succeed: %v", response.Error)
		t.Logf("Output: %s", response.Output)
	}

	// Verify JAR file was created
	if len(response.JarFiles) == 0 {
		t.Error("Expected JAR file to be created")
	} else {
		jarFile := response.JarFiles[0]
		if _, err := os.Stat(jarFile); err != nil {
			t.Errorf("Expected JAR file to exist: %v", err)
		}
	}
}

func TestMavenProjectGeneration(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, MavenBuild)
	if err != nil {
		t.Skipf("Skipping test - Java/Maven not available: %v", err)
	}

	tempDir := t.TempDir()

	request := &CompilationRequest{
		WorkingDir:   tempDir,
		SourceFiles:  []string{},
		BuildSystem:  MavenBuild,
		Timeout:      30 * time.Second,
		Environment:  make(map[string]string),
		Target: &CompilationTarget{
			SourceVersion: "11",
			TargetVersion: "11",
		},
	}

	// Initialize Maven build system
	if buildHandler, exists := compiler.buildSystemHandlers[MavenBuild]; exists {
		ctx := context.Background()
		err := buildHandler.Initialize(ctx, request)
		if err != nil {
			t.Fatalf("Failed to initialize Maven build system: %v", err)
		}

		// Verify pom.xml was created
		pomPath := filepath.Join(tempDir, "pom.xml")
		if _, err := os.Stat(pomPath); err != nil {
			t.Errorf("Expected pom.xml to be created: %v", err)
		}

		// Verify pom.xml content
		content, err := os.ReadFile(pomPath)
		if err != nil {
			t.Fatalf("Failed to read pom.xml: %v", err)
		}

		pomContent := string(content)
		if !strings.Contains(pomContent, "<source>11</source>") {
			t.Error("Expected pom.xml to contain Java 11 source version")
		}
		if !strings.Contains(pomContent, "<target>11</target>") {
			t.Error("Expected pom.xml to contain Java 11 target version")
		}
	} else {
		t.Skip("Maven build handler not available")
	}
}

func TestGradleProjectGeneration(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, GradleBuild)
	if err != nil {
		t.Skipf("Skipping test - Java/Gradle not available: %v", err)
	}

	tempDir := t.TempDir()

	request := &CompilationRequest{
		WorkingDir:   tempDir,
		SourceFiles:  []string{},
		MainClass:    "com.example.Main",
		BuildSystem:  GradleBuild,
		Timeout:      30 * time.Second,
		Environment:  make(map[string]string),
		Target: &CompilationTarget{
			SourceVersion: "11",
			TargetVersion: "11",
		},
	}

	// Initialize Gradle build system
	if buildHandler, exists := compiler.buildSystemHandlers[GradleBuild]; exists {
		ctx := context.Background()
		err := buildHandler.Initialize(ctx, request)
		if err != nil {
			t.Fatalf("Failed to initialize Gradle build system: %v", err)
		}

		// Verify build.gradle was created
		buildGradlePath := filepath.Join(tempDir, "build.gradle")
		if _, err := os.Stat(buildGradlePath); err != nil {
			t.Errorf("Expected build.gradle to be created: %v", err)
		}

		// Verify build.gradle content
		content, err := os.ReadFile(buildGradlePath)
		if err != nil {
			t.Fatalf("Failed to read build.gradle: %v", err)
		}

		buildContent := string(content)
		if !strings.Contains(buildContent, "mainClass = 'com.example.Main'") {
			t.Error("Expected build.gradle to contain main class")
		}
		if !strings.Contains(buildContent, "VERSION_11") {
			t.Error("Expected build.gradle to contain Java 11 version")
		}
	} else {
		t.Skip("Gradle build handler not available")
	}
}

func TestDependencyManagement(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Test adding dependencies
	dependency := &Dependency{
		GroupId:    "junit",
		ArtifactId: "junit",
		Version:    "4.13.2",
		Scope:      "test",
		Type:       "jar",
	}

	err = compiler.AddDependency(dependency)
	if err != nil {
		t.Errorf("Failed to add dependency: %v", err)
	}

	// Verify dependency was added
	found := false
	for _, dep := range compiler.dependencies {
		if dep.GroupId == "junit" && dep.ArtifactId == "junit" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected dependency to be added to compiler")
	}

	// Test adding duplicate dependency
	err = compiler.AddDependency(dependency)
	if err == nil {
		t.Error("Expected error when adding duplicate dependency")
	}

	// Test adding repository
	repository := &Repository{
		Id:        "custom-repo",
		Name:      "Custom Repository",
		URL:       "https://repo.example.com/maven2/",
		Layout:    "default",
		Releases:  true,
		Snapshots: false,
	}

	err = compiler.AddRepository(repository)
	if err != nil {
		t.Errorf("Failed to add repository: %v", err)
	}

	// Verify repository was added
	foundRepo := false
	for _, repo := range compiler.repositories {
		if repo.Id == "custom-repo" {
			foundRepo = true
			break
		}
	}

	if !foundRepo {
		t.Error("Expected repository to be added to compiler")
	}
}

func TestBuildSystemSwitching(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Test switching to Maven (if available)
	if compiler.mavenCommand != "" {
		err = compiler.SetBuildSystem(MavenBuild)
		if err != nil {
			t.Errorf("Failed to switch to Maven build system: %v", err)
		}

		if compiler.buildSystem != MavenBuild {
			t.Errorf("Expected build system to be Maven, got %v", compiler.buildSystem)
		}
	}

	// Test switching to Gradle (if available)
	if compiler.gradleCommand != "" {
		err = compiler.SetBuildSystem(GradleBuild)
		if err != nil {
			t.Errorf("Failed to switch to Gradle build system: %v", err)
		}

		if compiler.buildSystem != GradleBuild {
			t.Errorf("Expected build system to be Gradle, got %v", compiler.buildSystem)
		}
	}

	// Test switching to unsupported build system
	compiler.buildSystemHandlers = make(map[BuildSystemType]BuildSystemHandler)
	err = compiler.SetBuildSystem(MavenBuild)
	if err == nil {
		t.Error("Expected error when switching to unsupported build system")
	}
}

func TestJavaCompilationValidation(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Test validation with missing working directory
	request := &CompilationRequest{
		WorkingDir:  "",
		SourceFiles: []string{"Test.java"},
		BuildSystem: DirectBuild,
	}

	ctx := context.Background()
	_, err = compiler.Compile(ctx, request)
	if err == nil {
		t.Error("Expected error for missing working directory")
	}

	// Test validation with missing source files for direct build
	request = &CompilationRequest{
		WorkingDir:  t.TempDir(),
		SourceFiles: []string{},
		BuildSystem: DirectBuild,
	}

	_, err = compiler.Compile(ctx, request)
	if err == nil {
		t.Error("Expected error for missing source files in direct build")
	}

	// Test validation with invalid timeout (should be auto-corrected)
	request = &CompilationRequest{
		WorkingDir:  t.TempDir(),
		SourceFiles: []string{"Test.java"},
		BuildSystem: DirectBuild,
		Timeout:     0,
	}

	// Create a dummy source file
	sourceFile := filepath.Join(request.WorkingDir, "Test.java")
	os.WriteFile(sourceFile, []byte("public class Test {}"), 0644)

	response, err := compiler.Compile(ctx, request)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Timeout should have been set to default
	if response.Metrics.compilationTime == 0 {
		// This is expected for a quick compilation
	}
}

func TestJavaCompilerCleanup(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	tempDir := t.TempDir()

	// Create some files to clean up
	classesDir := filepath.Join(tempDir, "classes")
	targetDir := filepath.Join(tempDir, "target")
	buildDir := filepath.Join(tempDir, "build")

	os.MkdirAll(classesDir, 0755)
	os.MkdirAll(targetDir, 0755)
	os.MkdirAll(buildDir, 0755)

	// Create some files
	os.WriteFile(filepath.Join(classesDir, "Test.class"), []byte("dummy"), 0644)
	os.WriteFile(filepath.Join(tempDir, "test.jar"), []byte("dummy"), 0644)

	// Clean up
	ctx := context.Background()
	err = compiler.Clean(ctx, tempDir)
	if err != nil {
		t.Errorf("Failed to clean: %v", err)
	}

	// Verify directories were cleaned
	if _, err := os.Stat(classesDir); err == nil {
		t.Error("Expected classes directory to be removed")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "test.jar")); err == nil {
		t.Error("Expected JAR file to be removed")
	}
}

func TestJavaCompilerStringMethods(t *testing.T) {
	// Test JavaCompilerType.String()
	tests := []struct {
		compilerType JavaCompilerType
		expected     string
	}{
		{JavacCompiler, "javac"},
		{EclipseCompiler, "ecj"},
		{IntelliJCompiler, "intellij"},
		{JavaCompilerType(999), "unknown"},
	}

	for _, test := range tests {
		result := test.compilerType.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}

	// Test BuildSystemType.String()
	buildTests := []struct {
		buildSystem BuildSystemType
		expected    string
	}{
		{DirectBuild, "direct"},
		{MavenBuild, "maven"},
		{GradleBuild, "gradle"},
		{AntBuild, "ant"},
		{BuildSystemType(999), "unknown"},
	}

	for _, test := range buildTests {
		result := test.buildSystem.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

func TestJavaCompilerComponents(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Test that all components are properly initialized
	components := map[string]interface{}{
		"dependencyManager":        compiler.dependencyManager,
		"projectGenerator":         compiler.projectGenerator,
		"jarBuilder":              compiler.jarBuilder,
		"testRunner":              compiler.testRunner,
		"profiler":                compiler.profiler,
		"formatter":               compiler.formatter,
		"linter":                  compiler.linter,
		"documentationGenerator":  compiler.documentationGenerator,
		"securityScanner":         compiler.securityScanner,
		"cache":                   compiler.cache,
		"metrics":                 compiler.metrics,
	}

	for name, component := range components {
		if component == nil {
			t.Errorf("Expected %s to be initialized", name)
		}
	}

	// Test dependency manager functionality
	if compiler.dependencyManager != nil {
		// Test adding repository to dependency manager
		repo := &Repository{
			Id:   "test-repo",
			Name: "Test Repository",
			URL:  "https://test.example.com/repo/",
		}
		compiler.dependencyManager.AddRepository(repo)

		// Verify repository was added
		found := false
		for _, r := range compiler.dependencyManager.repositories {
			if r.Id == "test-repo" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected repository to be added to dependency manager")
		}
	}
}

func TestJavaVersionParsing(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	version := compiler.GetVersion()
	if version == nil {
		t.Fatal("Expected Java version to be parsed")
	}

	// Version should have a valid version string
	if version.Version == "" {
		t.Error("Expected version string to be non-empty")
	}

	// Major version should be reasonable (8, 11, 17, etc.)
	if version.Major < 8 || version.Major > 25 {
		t.Errorf("Expected major version to be between 8 and 25, got %d", version.Major)
	}

	t.Logf("Detected Java version: %s (Major: %d, Minor: %d, Patch: %d)",
		version.Version, version.Major, version.Minor, version.Patch)
}

func TestClasspathBuilding(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Test building classpath with multiple entries
	entries := []ClasspathEntry{
		{Path: "/path/to/lib1.jar", Type: "jar"},
		{Path: "/path/to/lib2.jar", Type: "jar"},
		{Path: "/path/to/classes", Type: "directory"},
	}

	classpath := compiler.buildClasspath(entries)
	
	// Verify all paths are included
	expectedPaths := []string{"/path/to/lib1.jar", "/path/to/lib2.jar", "/path/to/classes"}
	for _, path := range expectedPaths {
		if !strings.Contains(classpath, path) {
			t.Errorf("Expected classpath to contain %s, got: %s", path, classpath)
		}
	}

	// Test with empty entries
	emptyClasspath := compiler.buildClasspath([]ClasspathEntry{})
	if emptyClasspath != "" {
		t.Errorf("Expected empty classpath for no entries, got: %s", emptyClasspath)
	}
}

func TestJavaCompilerConcurrency(t *testing.T) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	// Test concurrent access to compiler methods
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Test concurrent access to version
			version := compiler.GetVersion()
			if version == nil {
				t.Errorf("Goroutine %d: Expected version to be available", id)
				return
			}

			// Test concurrent access to features
			features := compiler.GetSupportedFeatures()
			if len(features) == 0 {
				t.Errorf("Goroutine %d: Expected features to be available", id)
				return
			}

			// Test concurrent dependency addition
			dep := &Dependency{
				GroupId:    "test",
				ArtifactId: fmt.Sprintf("artifact-%d", id),
				Version:    "1.0.0",
			}

			err := compiler.AddDependency(dep)
			if err != nil {
				t.Errorf("Goroutine %d: Failed to add dependency: %v", id, err)
				return
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all dependencies were added
	if len(compiler.dependencies) != numGoroutines {
		t.Errorf("Expected %d dependencies, got %d", numGoroutines, len(compiler.dependencies))
	}
}

func TestJavaCompilerErrorHandling(t *testing.T) {
	// Test creating compiler with invalid configuration
	// This test ensures error handling works correctly

	// Create a compiler instance
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		t.Skipf("Skipping test - Java not available: %v", err)
	}

	tempDir := t.TempDir()

	// Test compilation with non-existent source file
	request := &CompilationRequest{
		WorkingDir:   tempDir,
		SourceFiles:  []string{"NonExistent.java"},
		BuildSystem:  DirectBuild,
		Timeout:      30 * time.Second,
		Environment:  make(map[string]string),
		ClasspathEntries: make([]ClasspathEntry, 0),
		Dependencies: make([]*Dependency, 0),
	}

	ctx := context.Background()
	response, err := compiler.Compile(ctx, request)

	// Should handle the error gracefully
	if err == nil {
		t.Error("Expected error for non-existent source file")
	}

	if response != nil && response.Success {
		t.Error("Expected compilation to fail for non-existent source file")
	}

	// Test invalid dependency
	invalidDep := &Dependency{
		GroupId:    "", // Invalid - empty groupId
		ArtifactId: "test",
		Version:    "1.0.0",
	}

	err = compiler.AddDependency(invalidDep)
	if err == nil {
		t.Error("Expected error for invalid dependency")
	}

	// Test invalid repository
	invalidRepo := &Repository{
		Id:  "", // Invalid - empty id
		URL: "https://example.com",
	}

	err = compiler.AddRepository(invalidRepo)
	if err == nil {
		t.Error("Expected error for invalid repository")
	}
}

// Benchmark tests
func BenchmarkJavaCompilerCreation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
		if err != nil {
			b.Skipf("Skipping benchmark - Java not available: %v", err)
		}
		_ = compiler
	}
}

func BenchmarkSimpleJavaCompilation(b *testing.B) {
	compiler, err := NewJavaCompiler(JavacCompiler, DirectBuild)
	if err != nil {
		b.Skipf("Skipping benchmark - Java not available: %v", err)
	}

	javaCode := `public class BenchmarkTest {
    public static void main(String[] args) {
        System.out.println("Benchmark test");
    }
}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tempDir := b.TempDir()
		
		sourceFile := filepath.Join(tempDir, "BenchmarkTest.java")
		os.WriteFile(sourceFile, []byte(javaCode), 0644)

		request := &CompilationRequest{
			WorkingDir:   tempDir,
			SourceFiles:  []string{"BenchmarkTest.java"},
			BuildSystem:  DirectBuild,
			Timeout:      30 * time.Second,
			Environment:  make(map[string]string),
			ClasspathEntries: make([]ClasspathEntry, 0),
			Dependencies: make([]*Dependency, 0),
		}

		ctx := context.Background()
		_, err := compiler.Compile(ctx, request)
		if err != nil {
			b.Fatalf("Compilation failed: %v", err)
		}
	}
}