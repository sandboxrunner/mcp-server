package languages

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sandboxrunner/mcp-server/pkg/languages/node"
	"github.com/sandboxrunner/mcp-server/pkg/languages/typescript"
)

// TypeScriptHandler handles TypeScript code execution
type TypeScriptHandler struct {
	*BaseHandler
	npmInstaller      *node.NPMInstaller
	environmentManager *node.NodeEnvironmentManager
	analyzer          *node.JavaScriptAnalyzer
	compiler          *typescript.TypeScriptCompiler
}

// NewTypeScriptHandler creates a new TypeScript handler
func NewTypeScriptHandler() *TypeScriptHandler {
	handler := &TypeScriptHandler{
		BaseHandler: NewBaseHandler(
			LanguageTypeScript,
			[]string{".ts", ".tsx"},
			"node:20-alpine",
			[]string{"20-alpine", "18-alpine", "16-alpine", "latest"},
			"npm",
			45*time.Second, // TypeScript compilation takes time
			true,           // Compiled language
		),
	}
	
	return handler
}

// initializeTypeScriptComponents initializes TypeScript components for the handler
func (h *TypeScriptHandler) initializeTypeScriptComponents(workingDir string) {
	if h.npmInstaller == nil {
		// Auto-detect package manager
		envManager := node.NewNodeEnvironmentManager(workingDir)
		packageManager := envManager.DetectPackageManager()
		h.npmInstaller = node.NewNPMInstaller(workingDir, "node", packageManager)
	}
	if h.environmentManager == nil {
		h.environmentManager = node.NewNodeEnvironmentManager(workingDir)
	}
	if h.analyzer == nil {
		h.analyzer = node.NewJavaScriptAnalyzer(workingDir)
	}
	if h.compiler == nil {
		h.compiler = typescript.NewTypeScriptCompiler(workingDir)
	}
}

// DetectLanguage checks if the code is TypeScript
func (h *TypeScriptHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	// Check file extension
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == ".ts" || ext == ".tsx" {
		confidence += 0.9 // Strong indicator
	}

	// Check for TypeScript-specific patterns
	tsPatterns := []string{
		`interface\s+\w+\s*{`,          // interface declarations
		`type\s+\w+\s*=`,               // type aliases
		`:\s*\w+(\[\])?(\s*\|\s*\w+)*`, // type annotations
		`<\w+>`,                        // generic type parameters
		`implements\s+\w+`,             // class implements interface
		`extends\s+\w+<`,               // generic inheritance
		`export\s+type\s+\w+`,          // type exports
		`import\s+type\s+`,             // type imports
		`enum\s+\w+\s*{`,               // enum declarations
		`namespace\s+\w+\s*{`,          // namespace declarations
		`declare\s+(var|let|const|function|class|module)`, // ambient declarations
		`abstract\s+class`, // abstract classes
		`readonly\s+\w+`,   // readonly properties
		`public\s+\w+`,     // public access modifier
		`private\s+\w+`,    // private access modifier
		`protected\s+\w+`,  // protected access modifier
		`as\s+\w+`,         // type assertions
		`keyof\s+\w+`,      // keyof operator
		`typeof\s+\w+`,     // typeof type operator
		`Record<`,          // Record utility type
		`Partial<`,         // Partial utility type
		`Required<`,        // Required utility type
		`Pick<`,            // Pick utility type
		`Omit<`,            // Omit utility type
	}

	for _, pattern := range tsPatterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.15
		}
	}

	// Check for TypeScript-specific keywords and features
	tsKeywords := []string{
		"interface", "type", "enum", "namespace", "declare", "abstract",
		"implements", "extends", "public", "private", "protected", "readonly",
		"override", "static", "async", "keyof", "typeof", "infer", "never",
		"unknown", "any", "void", "undefined", "null", "boolean", "number",
		"string", "symbol", "bigint", "object",
	}

	for _, keyword := range tsKeywords {
		// Use word boundaries to avoid partial matches
		pattern := fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(keyword))
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.08
		}
	}

	// Check for JSX syntax (for .tsx files)
	if ext == ".tsx" {
		jsxPatterns := []string{
			`<\w+.*?>`,    // JSX opening tags
			`<\/\w+>`,     // JSX closing tags
			`<\w+.*?\/>`,  // Self-closing JSX tags
			`React\.`,     // React namespace
			`useState\(`,  // React hooks
			`useEffect\(`, // React hooks
			`props\.\w+`,  // Props usage
		}

		for _, pattern := range jsxPatterns {
			if matched, _ := regexp.MatchString(pattern, code); matched {
				confidence += 0.1
			}
		}
	}

	// Reduce confidence if it looks more like plain JavaScript
	if !strings.Contains(code, ":") && !strings.Contains(code, "interface") &&
		!strings.Contains(code, "type ") && !strings.Contains(code, "enum ") {
		confidence *= 0.3
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares TypeScript code for execution
func (h *TypeScriptHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	// Create workspace if it doesn't exist
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return NewEnvironmentError(
			fmt.Sprintf("failed to create working directory: %v", err),
			LanguageTypeScript,
			err.Error(),
		)
	}

	// Initialize TypeScript components
	h.initializeTypeScriptComponents(req.WorkingDir)

	// Setup Node.js environment
	if h.environmentManager != nil {
		setupReq := &node.NodeEnvironmentSetupRequest{
			Environment: req.Environment,
		}
		
		_, err := h.environmentManager.SetupEnvironment(ctx, setupReq)
		if err != nil {
			fmt.Printf("Warning: Node.js environment setup failed: %v\n", err)
		}
	}

	// Install TypeScript and packages if specified
	packages := append(req.Packages, "typescript", "@types/node")
	if len(packages) > 0 && h.npmInstaller != nil {
		installReq := &node.NodeInstallRequest{
			Packages:       packages,
			PackageManager: h.environmentManager.DetectPackageManager(),
			Environment:    req.Environment,
			Timeout:        req.Timeout,
		}
		
		result, err := h.npmInstaller.Install(ctx, installReq)
		if err != nil || !result.Success {
			return NewEnvironmentError(
				fmt.Sprintf("TypeScript package installation failed: %v", err),
				LanguageTypeScript,
				result.Output,
			)
		}
	}

	// Initialize TypeScript compiler
	if h.compiler != nil {
		if err := h.compiler.Initialize(ctx); err != nil {
			fmt.Printf("Warning: TypeScript compiler initialization failed: %v\n", err)
		}
	}

	// Create additional files if specified
	for filename, content := range req.Files {
		filePath := filepath.Join(req.WorkingDir, filename)

		// Create directory for file if needed
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return NewEnvironmentError(
				fmt.Sprintf("failed to create directory for file %s: %v", filename, err),
				LanguageTypeScript,
				err.Error(),
			)
		}

		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return NewEnvironmentError(
				fmt.Sprintf("failed to create file %s: %v", filename, err),
				LanguageTypeScript,
				err.Error(),
			)
		}
	}

	// Legacy fallback - Create package.json if it doesn't exist
	if err := h.createPackageJson(req.WorkingDir, req.Packages); err != nil {
		return err
	}

	// Legacy fallback - Create tsconfig.json if it doesn't exist  
	if err := h.createTsConfig(req.WorkingDir, req); err != nil {
		return err
	}

	// Legacy fallback - Install TypeScript and dependencies if needed
	if err := h.ensureTypeScriptInstalled(ctx, req.WorkingDir); err != nil {
		return err
	}

	return nil
}

// Execute runs TypeScript code (compiles first, then executes)
func (h *TypeScriptHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguageTypeScript,
		Metadata: make(map[string]string),
	}

	// Create temporary TypeScript file
	var tsFile string
	if mainFile, exists := req.Options["main_file"]; exists {
		tsFile = filepath.Join(req.WorkingDir, mainFile)
	} else {
		ext := ".ts"
		if strings.Contains(req.Code, "React") || strings.Contains(req.Code, "JSX") {
			ext = ".tsx"
		}
		tsFile = filepath.Join(req.WorkingDir, "temp_script"+ext)
	}

	if err := os.WriteFile(tsFile, []byte(req.Code), 0644); err != nil {
		result.Error = NewEnvironmentError(
			fmt.Sprintf("failed to create TypeScript file: %v", err),
			LanguageTypeScript,
			err.Error(),
		)
		return result, result.Error
	}

	// Compile TypeScript to JavaScript
	var jsFile string
	var err error
	
	if h.compiler != nil {
		// Use comprehensive TypeScript compiler
		compileReq := &typescript.CompilationRequest{
			SourceFiles:  []string{tsFile},
			Target:       typescript.TargetES2020,
			Module:       typescript.ModuleCommonJS,
			SourceMap:    false,
			Declaration:  false,
			Strict:       false,
			Incremental:  false,
			OutputDir:    req.WorkingDir,
			Environment:  req.Environment,
			Timeout:      req.Timeout,
		}
		
		compileResult, compileErr := h.compiler.Compile(ctx, compileReq)
		if compileErr != nil || !compileResult.Success {
			errorMsg := fmt.Sprintf("TypeScript compilation failed: %v", compileErr)
			if compileResult != nil {
				errorMsg = fmt.Sprintf("TypeScript compilation failed: %s", compileResult.Output)
				// Add diagnostics to result metadata
				if len(compileResult.Diagnostics) > 0 {
					var diagnostics []string
					for _, diag := range compileResult.Diagnostics {
						diagnostics = append(diagnostics, fmt.Sprintf("%s:%d:%d - %s", diag.File, diag.Line, diag.Column, diag.Message))
					}
					result.Metadata["ts_diagnostics"] = strings.Join(diagnostics, "\n")
				}
			}
			
			result.Error = NewCompilationError(errorMsg, LanguageTypeScript, compileResult.Output)
			result.Duration = time.Since(startTime)
			return result, result.Error
		}
		
		// Find generated JS file
		if len(compileResult.OutputFiles) > 0 {
			jsFile = compileResult.OutputFiles[0]
		} else {
			// Fallback to expected location
			jsFile = strings.TrimSuffix(tsFile, filepath.Ext(tsFile)) + ".js"
		}
		
		// Add compilation info to metadata
		result.Metadata["compilation_duration"] = compileResult.Duration.String()
		result.Metadata["output_files"] = fmt.Sprintf("%d", len(compileResult.OutputFiles))
		if len(compileResult.Diagnostics) > 0 {
			result.Metadata["diagnostics_count"] = fmt.Sprintf("%d", len(compileResult.Diagnostics))
		}
	} else {
		// Fallback to legacy compilation
		jsFile, err = h.compileTypeScript(ctx, req, tsFile)
		if err != nil {
			result.Error = err
			result.Duration = time.Since(startTime)
			return result, result.Error
		}
	}

	result.Command = fmt.Sprintf("tsc %s && node %s", filepath.Base(tsFile), filepath.Base(jsFile))

	// Execute the compiled JavaScript
	nodeResult, err := h.executeCompiledJS(ctx, req, jsFile, startTime)
	if err != nil {
		result.Error = err
	}

	// Copy results from JavaScript execution
	result.ExitCode = nodeResult.ExitCode
	result.Stdout = nodeResult.Stdout
	result.Stderr = nodeResult.Stderr
	result.Duration = nodeResult.Duration
	result.Metadata = nodeResult.Metadata

	// Clean up temporary files
	if !strings.Contains(tsFile, req.Options["main_file"]) {
		os.Remove(tsFile)
		os.Remove(jsFile)
	}

	return result, nil
}

// InstallPackages installs TypeScript packages using npm
func (h *TypeScriptHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	result := &PackageInstallResult{
		InstalledPackages: make([]string, 0),
		FailedPackages:    make([]string, 0),
	}

	startTime := time.Now()

	// Ensure TypeScript packages are included
	packages := make([]string, len(req.Packages))
	copy(packages, req.Packages)

	// Add TypeScript if not already present
	hasTypeScript := false
	for _, pkg := range packages {
		if strings.HasPrefix(pkg, "typescript") {
			hasTypeScript = true
			break
		}
	}

	if !hasTypeScript {
		packages = append(packages, "typescript")
	}

	// Add @types packages for TypeScript
	for i, pkg := range packages {
		if !strings.HasPrefix(pkg, "@types/") && !strings.HasPrefix(pkg, "typescript") {
			// Check if it's a common package that needs types
			if h.needsTypeDefinitions(pkg) {
				packages = append(packages, "@types/"+pkg)
			}
		}
		packages[i] = pkg
	}

	// Build npm install command
	cmd := []string{"npm", "install"}

	// Add options
	if saveDev, exists := req.Options["save-dev"]; exists && saveDev == "true" {
		cmd = append(cmd, "--save-dev")
	}

	cmd = append(cmd, packages...)

	// Execute install command
	execCmd := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	execCmd.Dir = req.WorkingDir

	// Set environment
	execCmd.Env = os.Environ()
	for key, value := range req.Environment {
		execCmd.Env = append(execCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	output, err := execCmd.CombinedOutput()
	result.Output = string(output)
	result.Duration = time.Since(startTime)

	if err != nil {
		result.Success = false
		result.FailedPackages = packages
		result.Error = err
	} else {
		result.Success = true
		result.InstalledPackages = packages
	}

	return result, nil
}

// SetupEnvironment sets up TypeScript environment
func (h *TypeScriptHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	result := &EnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	// Check Node.js version first
	nodeCmd := exec.CommandContext(ctx, "node", "--version")
	nodeCmd.Dir = req.WorkingDir

	nodeOutput, err := nodeCmd.Output()
	if err != nil {
		result.Success = false
		result.Error = NewEnvironmentError(
			"Node.js not found or not executable",
			LanguageTypeScript,
			err.Error(),
		)
		return result, result.Error
	}

	nodeVersion := strings.TrimSpace(string(nodeOutput))

	// Check TypeScript version
	tsCmd := exec.CommandContext(ctx, "npx", "tsc", "--version")
	tsCmd.Dir = req.WorkingDir

	tsOutput, tsErr := tsCmd.Output()
	var tsVersion string
	if tsErr != nil {
		// TypeScript not installed, install it
		if installErr := h.ensureTypeScriptInstalled(ctx, req.WorkingDir); installErr != nil {
			result.Success = false
			result.Error = installErr
			return result, result.Error
		}

		// Try again after installation
		tsCmd2 := exec.CommandContext(ctx, "npx", "tsc", "--version")
		tsCmd2.Dir = req.WorkingDir
		if tsOutput2, err2 := tsCmd2.Output(); err2 == nil {
			tsVersion = strings.TrimSpace(string(tsOutput2))
		} else {
			tsVersion = "unknown"
		}
	} else {
		tsVersion = strings.TrimSpace(string(tsOutput))
	}

	result.Version = fmt.Sprintf("TypeScript %s (Node.js %s)", tsVersion, nodeVersion)
	result.Path = "npx tsc"

	// Set up environment variables
	result.Environment["NODE_ENV"] = "development"
	result.Environment["TS_NODE_COMPILER_OPTIONS"] = `{"module":"commonjs"}`

	// Create package.json and tsconfig.json if they don't exist
	packageJsonPath := filepath.Join(req.WorkingDir, "package.json")
	if _, err := os.Stat(packageJsonPath); os.IsNotExist(err) {
		if createErr := h.createPackageJson(req.WorkingDir, nil); createErr != nil {
			result.Success = false
			result.Error = createErr
			return result, result.Error
		}
	}

	tsconfigPath := filepath.Join(req.WorkingDir, "tsconfig.json")
	if _, err := os.Stat(tsconfigPath); os.IsNotExist(err) {
		dummyReq := &ExecutionRequest{WorkingDir: req.WorkingDir}
		if createErr := h.createTsConfig(req.WorkingDir, dummyReq); createErr != nil {
			result.Success = false
			result.Error = createErr
			return result, result.Error
		}
	}

	result.Success = true
	result.Output = fmt.Sprintf("TypeScript environment set up successfully. %s", result.Version)

	return result, nil
}

// GetRequiredFiles returns files needed for TypeScript execution
func (h *TypeScriptHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)

	// Add main script
	if mainFile, exists := req.Options["main_file"]; exists {
		files[mainFile] = req.Code
	} else {
		ext := ".ts"
		if strings.Contains(req.Code, "React") || strings.Contains(req.Code, "JSX") {
			ext = ".tsx"
		}
		files["index"+ext] = req.Code
	}

	// Add package.json
	files["package.json"] = h.generatePackageJson(req.Packages)

	// Add tsconfig.json
	files["tsconfig.json"] = h.generateTsConfig()

	return files
}

// GetCompileCommand returns the TypeScript compile command
func (h *TypeScriptHandler) GetCompileCommand(req *ExecutionRequest) string {
	if mainFile, exists := req.Options["main_file"]; exists {
		return fmt.Sprintf("npx tsc %s", mainFile)
	}

	return "npx tsc"
}

// GetRunCommand returns the run command for compiled JavaScript
func (h *TypeScriptHandler) GetRunCommand(req *ExecutionRequest) string {
	jsFile := "index.js"
	if mainFile, exists := req.Options["main_file"]; exists {
		jsFile = strings.TrimSuffix(mainFile, filepath.Ext(mainFile)) + ".js"
	}

	return fmt.Sprintf("node %s", jsFile)
}

// ValidateCode performs TypeScript syntax validation
func (h *TypeScriptHandler) ValidateCode(code string) error {
	if err := h.BaseHandler.ValidateCode(code); err != nil {
		return err
	}

	// Check for balanced delimiters
	if err := h.checkBalancedDelimiters(code); err != nil {
		return err
	}

	return nil
}

// Helper methods

func (h *TypeScriptHandler) compileTypeScript(ctx context.Context, req *ExecutionRequest, tsFile string) (string, error) {
	// Determine output file name
	jsFile := strings.TrimSuffix(tsFile, filepath.Ext(tsFile)) + ".js"

	// Build TypeScript compile command
	cmd := exec.CommandContext(ctx, "npx", "tsc", "--outFile", jsFile, tsFile)
	cmd.Dir = req.WorkingDir

	// Set environment
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", NewCompilationError(
			fmt.Sprintf("TypeScript compilation failed: %s", string(output)),
			LanguageTypeScript,
			string(output),
		)
	}

	return jsFile, nil
}

func (h *TypeScriptHandler) executeCompiledJS(ctx context.Context, req *ExecutionRequest, jsFile string, startTime time.Time) (*ExecutionResult, error) {
	// Create a JavaScript execution context
	execCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "node", jsFile)
	cmd.Dir = req.WorkingDir

	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Handle stdin
	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	// Execute
	output, err := cmd.CombinedOutput()

	result := &ExecutionResult{
		Language: LanguageTypeScript,
		Duration: time.Since(startTime),
		Metadata: make(map[string]string),
	}

	// Parse output
	outputStr := string(output)
	result.Stdout, result.Stderr = h.parseOutput(outputStr)

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}

		return result, NewRuntimeError(
			fmt.Sprintf("execution failed: %v", err),
			LanguageTypeScript,
			result.Stderr,
		)
	}

	result.ExitCode = 0
	return result, nil
}

func (h *TypeScriptHandler) ensureTypeScriptInstalled(ctx context.Context, workingDir string) error {
	// Check if TypeScript is already available
	cmd := exec.CommandContext(ctx, "npx", "tsc", "--version")
	cmd.Dir = workingDir

	if err := cmd.Run(); err == nil {
		return nil // Already installed
	}

	// Install TypeScript
	installCmd := exec.CommandContext(ctx, "npm", "install", "typescript", "@types/node")
	installCmd.Dir = workingDir

	if err := installCmd.Run(); err != nil {
		return NewEnvironmentError(
			fmt.Sprintf("failed to install TypeScript: %v", err),
			LanguageTypeScript,
			err.Error(),
		)
	}

	return nil
}

func (h *TypeScriptHandler) createPackageJson(workingDir string, packages []string) error {
	packageJsonPath := filepath.Join(workingDir, "package.json")

	// Check if package.json already exists
	if _, err := os.Stat(packageJsonPath); err == nil {
		return nil
	}

	packageJson := h.generatePackageJson(packages)

	return os.WriteFile(packageJsonPath, []byte(packageJson), 0644)
}

func (h *TypeScriptHandler) generatePackageJson(packages []string) string {
	pkg := map[string]interface{}{
		"name":        "typescript-sandbox",
		"version":     "1.0.0",
		"description": "TypeScript sandbox project",
		"main":        "index.js",
		"scripts": map[string]string{
			"build": "tsc",
			"start": "node index.js",
			"dev":   "ts-node index.ts",
		},
		"dependencies": map[string]string{
			"typescript":  "latest",
			"@types/node": "latest",
		},
	}

	// Add specified packages
	dependencies := pkg["dependencies"].(map[string]string)
	for _, packageName := range packages {
		if strings.Contains(packageName, "@") && !strings.HasPrefix(packageName, "@") {
			parts := strings.SplitN(packageName, "@", 2)
			dependencies[parts[0]] = parts[1]
		} else {
			dependencies[packageName] = "*"
		}
	}

	jsonBytes, _ := json.MarshalIndent(pkg, "", "  ")
	return string(jsonBytes)
}

func (h *TypeScriptHandler) createTsConfig(workingDir string, req *ExecutionRequest) error {
	tsconfigPath := filepath.Join(workingDir, "tsconfig.json")

	// Check if tsconfig.json already exists
	if _, err := os.Stat(tsconfigPath); err == nil {
		return nil
	}

	tsconfig := h.generateTsConfig()

	return os.WriteFile(tsconfigPath, []byte(tsconfig), 0644)
}

func (h *TypeScriptHandler) generateTsConfig() string {
	config := map[string]interface{}{
		"compilerOptions": map[string]interface{}{
			"target":                           "ES2020",
			"module":                           "commonjs",
			"lib":                              []string{"ES2020"},
			"outDir":                           "./dist",
			"rootDir":                          "./",
			"strict":                           true,
			"esModuleInterop":                  true,
			"skipLibCheck":                     true,
			"forceConsistentCasingInFileNames": true,
			"resolveJsonModule":                true,
			"declaration":                      true,
			"declarationMap":                   true,
			"sourceMap":                        true,
		},
		"include": []string{"**/*"},
		"exclude": []string{"node_modules", "**/*.spec.ts", "**/*.test.ts"},
	}

	jsonBytes, _ := json.MarshalIndent(config, "", "  ")
	return string(jsonBytes)
}

func (h *TypeScriptHandler) needsTypeDefinitions(packageName string) bool {
	commonPackages := []string{
		"express", "lodash", "moment", "axios", "react", "react-dom",
		"jquery", "fs-extra", "commander", "chalk", "inquirer",
	}

	for _, pkg := range commonPackages {
		if pkg == packageName {
			return true
		}
	}

	return false
}

func (h *TypeScriptHandler) parseOutput(output string) (stdout, stderr string) {
	lines := strings.Split(output, "\n")

	var stdoutLines, stderrLines []string

	for _, line := range lines {
		if h.isErrorLine(line) {
			stderrLines = append(stderrLines, line)
		} else {
			stdoutLines = append(stdoutLines, line)
		}
	}

	return strings.Join(stdoutLines, "\n"), strings.Join(stderrLines, "\n")
}

func (h *TypeScriptHandler) isErrorLine(line string) bool {
	errorPatterns := []string{
		"Error:",
		"TypeError:",
		"ReferenceError:",
		"SyntaxError:",
		"RangeError:",
		"CompilerError:",
		"TSError:",
		"at ",     // Stack trace lines
		"    at ", // Indented stack trace lines
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}

	return false
}

func (h *TypeScriptHandler) checkBalancedDelimiters(code string) error {
	stack := make([]rune, 0)
	pairs := map[rune]rune{
		')': '(',
		']': '[',
		'}': '{',
		'>': '<', // For generic types
	}

	inString := false
	inComment := false
	var stringChar rune

	for i, char := range code {
		// Handle string literals
		if char == '"' || char == '\'' || char == '`' {
			if !inComment {
				if !inString {
					inString = true
					stringChar = char
				} else if char == stringChar {
					inString = false
				}
			}
			continue
		}

		if inString {
			continue
		}

		// Handle comments
		if i < len(code)-1 {
			next := rune(code[i+1])
			if char == '/' && next == '/' {
				inComment = true
				continue
			}
			if char == '/' && next == '*' {
				inComment = true
				continue
			}
		}

		if char == '\n' {
			inComment = false
			continue
		}

		if inComment {
			continue
		}

		switch char {
		case '(', '[', '{':
			stack = append(stack, char)
		case '<':
			// Only treat as opening delimiter in type contexts
			if h.isInTypeContext(code, i) {
				stack = append(stack, char)
			}
		case ')', ']', '}', '>':
			if len(stack) == 0 {
				return NewCompilationError(
					fmt.Sprintf("Unmatched closing delimiter '%c' at position %d", char, i),
					LanguageTypeScript,
					code,
				)
			}

			expected := pairs[char]
			if stack[len(stack)-1] != expected {
				return NewCompilationError(
					fmt.Sprintf("Mismatched delimiter: expected '%c' but found '%c' at position %d", expected, char, i),
					LanguageTypeScript,
					code,
				)
			}

			stack = stack[:len(stack)-1]
		}
	}

	if len(stack) > 0 {
		return NewCompilationError(
			fmt.Sprintf("Unclosed delimiter '%c'", stack[len(stack)-1]),
			LanguageTypeScript,
			code,
		)
	}

	return nil
}

func (h *TypeScriptHandler) isInTypeContext(code string, position int) bool {
	// Simple heuristic to determine if < is used for generics
	// Look backwards for type-related keywords
	if position < 10 {
		return false
	}

	beforeContext := code[max(0, position-20):position]
	typeKeywords := []string{"interface", "type", "class", "function", "Array", "Promise", "Map", "Set"}

	for _, keyword := range typeKeywords {
		if strings.Contains(beforeContext, keyword) {
			return true
		}
	}

	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
