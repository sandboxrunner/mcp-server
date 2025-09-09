package languages

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// GoHandler handles Go code execution
type GoHandler struct {
	*BaseHandler
}

// NewGoHandler creates a new Go handler
func NewGoHandler() *GoHandler {
	return &GoHandler{
		BaseHandler: NewBaseHandler(
			LanguageGo,
			[]string{".go"},
			"golang:1.21-alpine",
			[]string{"1.21-alpine", "1.20-alpine", "1.19-alpine", "latest"},
			"go",
			45*time.Second, // Go compilation can take time
			true,           // Compiled language
		),
	}
}

// DetectLanguage checks if the code is Go
func (h *GoHandler) DetectLanguage(code string, filename string) float64 {
	confidence := 0.0

	// Check file extension
	if strings.HasSuffix(strings.ToLower(filename), ".go") {
		confidence += 0.9
	}

	// Check for package declaration (required in Go)
	if matched, _ := regexp.MatchString(`^package\s+\w+`, code); matched {
		confidence += 0.8
	}

	// Check for Go-specific patterns
	goPatterns := []string{
		`package\s+main`,                  // main package
		`func\s+main\s*\(\s*\)`,           // main function
		`import\s*\(`,                     // import block
		`import\s+"[^"]+?"`,               // import statement
		`func\s+\w+\s*\([^)]*\)`,          // function declaration
		`type\s+\w+\s+(struct|interface)`, // type declaration
		`var\s+\w+\s+\w+`,                 // variable declaration with type
		`\w+\s*:=\s*`,                     // short variable declaration
		`fmt\.Print(ln|f)?\(`,             // fmt package usage
		`make\s*\(\s*\w+`,                 // make function
		`append\s*\(`,                     // append function
		`range\s+\w+`,                     // range keyword
		`chan\s+\w+`,                      // channel declaration
		`go\s+\w+\s*\(`,                   // goroutine
		`defer\s+\w+`,                     // defer statement
		`select\s*{`,                      // select statement
		`interface\{\}`,                   // empty interface
		`nil\b`,                           // nil keyword
		`\berror\b`,                       // error interface
	}

	for _, pattern := range goPatterns {
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.12
		}
	}

	// Check for Go keywords
	goKeywords := []string{
		"package", "import", "func", "var", "const", "type", "struct",
		"interface", "map", "chan", "select", "go", "defer", "range",
		"fallthrough", "break", "continue", "goto", "return", "if",
		"else", "switch", "case", "default", "for", "nil", "true", "false",
	}

	for _, keyword := range goKeywords {
		pattern := fmt.Sprintf(`\b%s\b`, regexp.QuoteMeta(keyword))
		if matched, _ := regexp.MatchString(pattern, code); matched {
			confidence += 0.06
		}
	}

	// Check for Go standard library usage
	stdLibPatterns := []string{
		`fmt\.`, `os\.`, `io\.`, `strings\.`, `strconv\.`, `time\.`,
		`context\.`, `sync\.`, `net\/http\.`, `encoding\/json\.`,
		`log\.`, `errors\.`, `math\.`, `sort\.`, `bufio\.`,
	}

	for _, pattern := range stdLibPatterns {
		if strings.Contains(code, pattern) {
			confidence += 0.08
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// PrepareExecution prepares Go code for execution
func (h *GoHandler) PrepareExecution(ctx context.Context, req *ExecutionRequest) error {
	// Create workspace if it doesn't exist
	if err := os.MkdirAll(req.WorkingDir, 0755); err != nil {
		return NewEnvironmentError(
			fmt.Sprintf("failed to create working directory: %v", err),
			LanguageGo,
			err.Error(),
		)
	}

	// Initialize Go module if not present
	if err := h.initializeGoModule(ctx, req.WorkingDir); err != nil {
		return err
	}

	// Create additional files if specified
	for filename, content := range req.Files {
		filePath := filepath.Join(req.WorkingDir, filename)

		// Create directory for file if needed
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			return NewEnvironmentError(
				fmt.Sprintf("failed to create directory for file %s: %v", filename, err),
				LanguageGo,
				err.Error(),
			)
		}

		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return NewEnvironmentError(
				fmt.Sprintf("failed to create file %s: %v", filename, err),
				LanguageGo,
				err.Error(),
			)
		}
	}

	// Install dependencies if specified
	if len(req.Packages) > 0 {
		if err := h.installDependencies(ctx, req.WorkingDir, req.Packages); err != nil {
			return err
		}
	}

	return nil
}

// Execute runs Go code (compiles and runs)
func (h *GoHandler) Execute(ctx context.Context, req *ExecutionRequest) (*ExecutionResult, error) {
	startTime := time.Now()

	result := &ExecutionResult{
		Language: LanguageGo,
		Metadata: make(map[string]string),
	}

	// Create temporary Go file or use specified main file
	var goFile string
	if mainFile, exists := req.Options["main_file"]; exists {
		goFile = filepath.Join(req.WorkingDir, mainFile)
	} else {
		goFile = filepath.Join(req.WorkingDir, "main.go")
	}

	// Ensure the code has proper package declaration
	code := req.Code
	if !strings.Contains(code, "package ") {
		code = "package main\n\n" + code
	}

	// Add import for fmt if not present and code uses Print functions
	if !strings.Contains(code, "import") &&
		(strings.Contains(code, "Print") || strings.Contains(code, "fmt.")) {
		lines := strings.Split(code, "\n")
		packageLine := ""
		otherLines := []string{}

		for i, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "package ") {
				packageLine = line
				otherLines = lines[i+1:]
				break
			}
		}

		if packageLine != "" {
			code = packageLine + "\n\nimport \"fmt\"\n\n" + strings.Join(otherLines, "\n")
		}
	}

	if err := os.WriteFile(goFile, []byte(code), 0644); err != nil {
		result.Error = NewEnvironmentError(
			fmt.Sprintf("failed to create Go file: %v", err),
			LanguageGo,
			err.Error(),
		)
		return result, result.Error
	}

	// Determine execution method (run vs build + run)
	if runDirectly, exists := req.Options["run_directly"]; exists && runDirectly == "true" {
		// Use go run for simple scripts
		result.Command = fmt.Sprintf("go run %s", filepath.Base(goFile))
		return h.executeGoRun(ctx, req, goFile, startTime)
	} else {
		// Build and then execute binary
		result.Command = fmt.Sprintf("go build %s && ./%s", filepath.Base(goFile), "main")
		return h.executeBuildAndRun(ctx, req, goFile, startTime)
	}
}

// InstallPackages installs Go dependencies
func (h *GoHandler) InstallPackages(ctx context.Context, req *PackageInstallRequest) (*PackageInstallResult, error) {
	result := &PackageInstallResult{
		InstalledPackages: make([]string, 0),
		FailedPackages:    make([]string, 0),
	}

	startTime := time.Now()

	// Initialize Go module if not present
	if err := h.initializeGoModule(ctx, req.WorkingDir); err != nil {
		result.Success = false
		result.Error = err
		return result, nil
	}

	// Install each package using go get
	var outputs []string

	for _, pkg := range req.Packages {
		cmd := exec.CommandContext(ctx, "go", "get", pkg)
		cmd.Dir = req.WorkingDir

		// Set environment
		cmd.Env = os.Environ()
		for key, value := range req.Environment {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
		}

		output, err := cmd.CombinedOutput()
		outputs = append(outputs, string(output))

		if err != nil {
			result.FailedPackages = append(result.FailedPackages, pkg)
		} else {
			result.InstalledPackages = append(result.InstalledPackages, pkg)
		}
	}

	result.Output = strings.Join(outputs, "\n")
	result.Duration = time.Since(startTime)
	result.Success = len(result.FailedPackages) == 0

	if !result.Success && len(result.FailedPackages) == len(req.Packages) {
		result.Error = fmt.Errorf("failed to install all packages")
	}

	return result, nil
}

// SetupEnvironment sets up Go environment
func (h *GoHandler) SetupEnvironment(ctx context.Context, req *EnvironmentSetupRequest) (*EnvironmentSetupResult, error) {
	result := &EnvironmentSetupResult{
		Environment: make(map[string]string),
	}

	// Check Go version
	cmd := exec.CommandContext(ctx, "go", "version")
	cmd.Dir = req.WorkingDir

	output, err := cmd.Output()
	if err != nil {
		result.Success = false
		result.Error = NewEnvironmentError(
			"Go not found or not executable",
			LanguageGo,
			err.Error(),
		)
		return result, result.Error
	}

	versionStr := strings.TrimSpace(string(output))
	result.Version = versionStr
	result.Path = "go"

	// Set up Go environment variables
	goEnvCmd := exec.CommandContext(ctx, "go", "env", "GOPATH", "GOROOT", "GOOS", "GOARCH")
	goEnvCmd.Dir = req.WorkingDir

	envOutput, envErr := goEnvCmd.Output()
	if envErr == nil {
		envLines := strings.Split(strings.TrimSpace(string(envOutput)), "\n")
		if len(envLines) >= 4 {
			result.Environment["GOPATH"] = envLines[0]
			result.Environment["GOROOT"] = envLines[1]
			result.Environment["GOOS"] = envLines[2]
			result.Environment["GOARCH"] = envLines[3]
		}
	}

	// Additional Go environment variables
	result.Environment["GO111MODULE"] = "on"
	result.Environment["CGO_ENABLED"] = "1"

	// Initialize Go module if not present
	if err := h.initializeGoModule(ctx, req.WorkingDir); err != nil {
		result.Success = false
		result.Error = err
		return result, result.Error
	}

	result.Success = true
	result.Output = fmt.Sprintf("Go environment set up successfully. %s", result.Version)

	return result, nil
}

// GetRequiredFiles returns files needed for Go execution
func (h *GoHandler) GetRequiredFiles(req *ExecutionRequest) map[string]string {
	files := make(map[string]string)

	// Ensure code has package declaration
	code := req.Code
	if !strings.Contains(code, "package ") {
		code = "package main\n\n" + code
	}

	// Add main file
	if mainFile, exists := req.Options["main_file"]; exists {
		files[mainFile] = code
	} else {
		files["main.go"] = code
	}

	// Add go.mod file
	files["go.mod"] = h.generateGoMod()

	return files
}

// GetCompileCommand returns the Go compile command
func (h *GoHandler) GetCompileCommand(req *ExecutionRequest) string {
	if mainFile, exists := req.Options["main_file"]; exists {
		return fmt.Sprintf("go build %s", mainFile)
	}

	return "go build main.go"
}

// GetRunCommand returns the run command
func (h *GoHandler) GetRunCommand(req *ExecutionRequest) string {
	if runDirectly, exists := req.Options["run_directly"]; exists && runDirectly == "true" {
		if mainFile, exists := req.Options["main_file"]; exists {
			return fmt.Sprintf("go run %s", mainFile)
		}
		return "go run main.go"
	}

	// Determine binary name
	binaryName := "main"
	if mainFile, exists := req.Options["main_file"]; exists {
		binaryName = strings.TrimSuffix(mainFile, ".go")
	}

	return fmt.Sprintf("./%s", binaryName)
}

// ValidateCode performs basic Go syntax validation
func (h *GoHandler) ValidateCode(code string) error {
	if err := h.BaseHandler.ValidateCode(code); err != nil {
		return err
	}

	// Check for package declaration
	if !strings.Contains(code, "package ") {
		return NewCompilationError(
			"Go code must have a package declaration",
			LanguageGo,
			"Missing package declaration",
		)
	}

	// Check for balanced braces (important for Go)
	if err := h.checkBalancedBraces(code); err != nil {
		return err
	}

	return nil
}

// Helper methods

func (h *GoHandler) initializeGoModule(ctx context.Context, workingDir string) error {
	// Check if go.mod already exists
	goModPath := filepath.Join(workingDir, "go.mod")
	if _, err := os.Stat(goModPath); err == nil {
		return nil // Already exists
	}

	// Initialize Go module
	cmd := exec.CommandContext(ctx, "go", "mod", "init", "sandbox-project")
	cmd.Dir = workingDir

	if err := cmd.Run(); err != nil {
		return NewEnvironmentError(
			fmt.Sprintf("failed to initialize Go module: %v", err),
			LanguageGo,
			err.Error(),
		)
	}

	return nil
}

func (h *GoHandler) installDependencies(ctx context.Context, workingDir string, packages []string) error {
	for _, pkg := range packages {
		cmd := exec.CommandContext(ctx, "go", "get", pkg)
		cmd.Dir = workingDir

		if err := cmd.Run(); err != nil {
			return NewPackageError(
				fmt.Sprintf("failed to install package %s: %v", pkg, err),
				LanguageGo,
				err.Error(),
			)
		}
	}

	return nil
}

func (h *GoHandler) executeGoRun(ctx context.Context, req *ExecutionRequest, goFile string, startTime time.Time) (*ExecutionResult, error) {
	result := &ExecutionResult{
		Language: LanguageGo,
		Metadata: make(map[string]string),
	}

	// Create execution context with timeout
	execCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	// Execute go run
	cmd := exec.CommandContext(execCtx, "go", "run", goFile)
	cmd.Dir = req.WorkingDir

	// Set environment variables
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Go-specific environment variables
	cmd.Env = append(cmd.Env, "GO111MODULE=on")

	// Handle stdin
	if req.Stdin != "" {
		cmd.Stdin = strings.NewReader(req.Stdin)
	}

	// Execute
	output, err := cmd.CombinedOutput()
	result.Duration = time.Since(startTime)

	// Parse output
	outputStr := string(output)
	result.Stdout, result.Stderr = h.parseOutput(outputStr)

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}

		// Check for compilation errors
		if strings.Contains(result.Stderr, "syntax error") ||
			strings.Contains(result.Stderr, "cannot find package") {
			result.Error = NewCompilationError(
				"Go compilation error",
				LanguageGo,
				result.Stderr,
			)
		} else {
			result.Error = NewRuntimeError(
				fmt.Sprintf("execution failed: %v", err),
				LanguageGo,
				result.Stderr,
			)
		}
	} else {
		result.ExitCode = 0
	}

	return result, nil
}

func (h *GoHandler) executeBuildAndRun(ctx context.Context, req *ExecutionRequest, goFile string, startTime time.Time) (*ExecutionResult, error) {
	result := &ExecutionResult{
		Language: LanguageGo,
		Metadata: make(map[string]string),
	}

	// Determine binary name
	binaryName := strings.TrimSuffix(filepath.Base(goFile), ".go")
	binaryPath := filepath.Join(req.WorkingDir, binaryName)

	// First, build the Go program
	buildCtx, buildCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer buildCancel()

	buildCmd := exec.CommandContext(buildCtx, "go", "build", "-o", binaryName, goFile)
	buildCmd.Dir = req.WorkingDir

	// Set environment variables
	buildCmd.Env = os.Environ()
	for key, value := range req.Environment {
		buildCmd.Env = append(buildCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	buildCmd.Env = append(buildCmd.Env, "GO111MODULE=on")

	buildOutput, buildErr := buildCmd.CombinedOutput()
	if buildErr != nil {
		result.Duration = time.Since(startTime)
		result.Stderr = string(buildOutput)
		result.Error = NewCompilationError(
			"Go build failed",
			LanguageGo,
			result.Stderr,
		)
		return result, result.Error
	}

	// Now execute the binary
	execCtx, execCancel := context.WithTimeout(ctx, req.Timeout/2)
	defer execCancel()

	execCmd := exec.CommandContext(execCtx, binaryPath)
	execCmd.Dir = req.WorkingDir

	// Set environment variables for execution
	execCmd.Env = os.Environ()
	for key, value := range req.Environment {
		execCmd.Env = append(execCmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Handle stdin
	if req.Stdin != "" {
		execCmd.Stdin = strings.NewReader(req.Stdin)
	}

	// Execute
	execOutput, execErr := execCmd.CombinedOutput()
	result.Duration = time.Since(startTime)

	// Parse output
	outputStr := string(execOutput)
	result.Stdout, result.Stderr = h.parseOutput(outputStr)

	if execErr != nil {
		if exitError, ok := execErr.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = -1
		}

		result.Error = NewRuntimeError(
			fmt.Sprintf("execution failed: %v", execErr),
			LanguageGo,
			result.Stderr,
		)
	} else {
		result.ExitCode = 0
	}

	// Clean up binary
	os.Remove(binaryPath)

	return result, nil
}

func (h *GoHandler) generateGoMod() string {
	return `module sandbox-project

go 1.21
`
}

func (h *GoHandler) parseOutput(output string) (stdout, stderr string) {
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

func (h *GoHandler) isErrorLine(line string) bool {
	errorPatterns := []string{
		"error:",
		"panic:",
		"fatal error:",
		"syntax error",
		"undefined:",
		"cannot find package",
		"build failed",
		"compilation error",
		"\t", // Typically error context lines are indented
	}

	lowercaseLine := strings.ToLower(line)
	for _, pattern := range errorPatterns {
		if strings.Contains(lowercaseLine, pattern) {
			return true
		}
	}

	return false
}

func (h *GoHandler) checkBalancedBraces(code string) error {
	stack := make([]rune, 0)
	pairs := map[rune]rune{
		')': '(',
		']': '[',
		'}': '{',
	}

	inString := false
	inComment := false
	inMultiComment := false
	var stringChar rune

	runes := []rune(code)
	for i, char := range runes {
		// Handle string literals
		if char == '"' || char == '\'' || char == '`' {
			if !inComment && !inMultiComment {
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
		if i < len(runes)-1 {
			next := runes[i+1]
			if char == '/' && next == '/' && !inMultiComment {
				inComment = true
				continue
			}
			if char == '/' && next == '*' && !inComment {
				inMultiComment = true
				continue
			}
			if char == '*' && next == '/' && inMultiComment {
				inMultiComment = false
				i++ // Skip the '/'
				continue
			}
		}

		if char == '\n' {
			inComment = false
			continue
		}

		if inComment || inMultiComment {
			continue
		}

		switch char {
		case '(', '[', '{':
			stack = append(stack, char)
		case ')', ']', '}':
			if len(stack) == 0 {
				return NewCompilationError(
					fmt.Sprintf("Unmatched closing delimiter '%c' at position %d", char, i),
					LanguageGo,
					code,
				)
			}

			expected := pairs[char]
			if stack[len(stack)-1] != expected {
				return NewCompilationError(
					fmt.Sprintf("Mismatched delimiter: expected '%c' but found '%c' at position %d", expected, char, i),
					LanguageGo,
					code,
				)
			}

			stack = stack[:len(stack)-1]
		}
	}

	if len(stack) > 0 {
		return NewCompilationError(
			fmt.Sprintf("Unclosed delimiter '%c'", stack[len(stack)-1]),
			LanguageGo,
			code,
		)
	}

	return nil
}
