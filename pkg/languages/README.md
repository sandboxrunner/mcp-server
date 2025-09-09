# Multi-Language Code Execution System

This package provides a comprehensive, production-ready multi-language code execution system for the SandboxRunner MCP server. It supports automatic language detection, package management, compilation, and execution for 12+ programming languages.

## Architecture Overview

The system is built with a modular architecture consisting of several key components:

### Core Components

1. **Language Detection System** (`detector.go`)
   - File extension-based detection
   - Shebang line parsing  
   - Content analysis using regex patterns and keywords
   - Confidence scoring for multiple language matches
   - Fallback mechanisms for ambiguous code

2. **Base Language Interface** (`interface.go`)
   - Common interface for all language handlers
   - Standardized execution parameters and results
   - Package installation interface
   - Environment setup interface
   - Error handling with language-specific error types

3. **Container Images Configuration** (`images.go`)
   - Pre-defined container images for each language
   - Image versioning and management
   - Multi-language polyglot images (Jupyter, VS Code Server)
   - Image metadata including packages and environment setup

4. **Package Management System** (`packages.go`)
   - Universal package installation interface
   - Language-specific package managers (pip, npm, cargo, etc.)
   - Dependency resolution and installation
   - Package validation and error handling

5. **Language Manager** (`manager.go`)
   - Central coordinator for all language operations
   - Language handler registry management
   - Execution workflow orchestration
   - Multi-file project support
   - Environment isolation and cleanup

## Supported Languages

### Fully Implemented Handlers

- **Python** (`handlers/python.go`)
  - pip package management
  - Virtual environment support
  - Jupyter notebook compatibility
  - Syntax validation
  - Error categorization (syntax, runtime, import errors)

- **JavaScript/Node.js** (`handlers/javascript.go`)
  - npm/yarn package management
  - ES6+ syntax support
  - Package.json generation
  - Multiple Node.js versions
  - CommonJS and ES modules support

- **TypeScript** (`handlers/typescript.go`)
  - Automatic compilation to JavaScript
  - Type definition packages (@types/*)
  - tsconfig.json generation
  - JSX/TSX support for React
  - TypeScript-specific error handling

- **Go** (`handlers/golang.go`)
  - Go modules support
  - Cross-compilation capabilities
  - Package installation with `go get`
  - Both `go run` and build+execute modes
  - Proper package declaration handling

- **Rust** (`handlers/rust.go`)
  - Cargo package management
  - Cargo.toml generation
  - Release build optimization
  - Crate dependency management
  - Comprehensive error reporting

- **Java** (`handlers/java.go`)
  - Javac compilation
  - Automatic class name extraction
  - Main method wrapping for simple code
  - Classpath management
  - JVM execution

- **C++** (`handlers/cpp.go`)
  - GCC/G++ compilation
  - Standard library includes
  - Main function wrapping
  - Binary generation and cleanup
  - Compilation error reporting

- **Shell** (`handlers/shell.go`)
  - Bash, Zsh, Fish support
  - Script file vs direct execution
  - Environment variable handling
  - Security validation (dangerous command detection)
  - Shebang interpretation

### Stub Implementations

- **C**, **Ruby**, **PHP**, **R**, **Lua**, **Perl** - Basic framework in place, ready for full implementation

## Key Features

### 1. Automatic Language Detection

```go
detector := languages.NewDetector()
results := detector.DetectLanguage(code, filename)
bestMatch := detector.GetBestMatch(code, filename)
```

- Multiple detection strategies combined
- Confidence scoring system
- Fallback to shell for simple commands
- Extensible pattern matching

### 2. Comprehensive Package Management

```go
// Install packages for any supported language
err := manager.InstallPackages(ctx, languages.LanguagePython, 
    []string{"numpy", "pandas"}, workingDir, options)
```

- Language-specific package managers
- Automatic dependency resolution
- Package validation
- Installation result tracking

### 3. Flexible Execution Options

```go
req := &languages.ExecutionRequest{
    Code:        "print('Hello, World!')",
    Language:    languages.LanguagePython,
    Packages:    []string{"requests"},
    Environment: map[string]string{"DEBUG": "true"},
    Timeout:     30 * time.Second,
    Files:       additionalFiles,
}

result, err := manager.ExecuteCode(ctx, req)
```

- Timeout handling
- Environment variable support
- Multi-file project support
- Stdin/stdout/stderr handling
- Detailed execution results

### 4. Production-Ready Error Handling

- Language-specific error types (compilation, runtime, package errors)
- Detailed error messages and context
- Exit code tracking
- Comprehensive logging

### 5. Container Integration

- Pre-configured container images for each language
- Version management
- Multi-language environments
- Resource constraint support

## Usage Examples

### Basic Code Execution

```go
// Create a code executor
executor := languages.NewCodeExecutor("/workspace")

// Execute Python code
response := executor.Execute(ctx, &languages.ExecuteCodeRequest{
    Code: `
import math
print(f"The square root of 16 is {math.sqrt(16)}")
    `,
    Language: "python",
    Timeout:  30,
})

fmt.Printf("Output: %s\n", response.Stdout)
fmt.Printf("Success: %t\n", response.Success)
```

### Multi-File Project

```go
files := map[string]string{
    "main.go": `package main
import "./utils"
func main() {
    utils.PrintGreeting()
}`,
    "utils/utils.go": `package utils
import "fmt"
func PrintGreeting() {
    fmt.Println("Hello from utils!")
}`,
}

response := executor.Execute(ctx, &languages.ExecuteCodeRequest{
    Code:     files["main.go"],
    Language: "go",
    Files:    files,
})
```

### Package Installation

```go
response := executor.InstallPackages(ctx, "python", 
    []string{"numpy", "pandas", "matplotlib"}, "/workspace")

if response.Success {
    fmt.Printf("Installed: %v\n", response.InstalledPackages)
}
```

## Integration with SandboxRunner

The language system integrates seamlessly with the existing SandboxRunner MCP server:

1. **Enhanced RunCodeTool** - The existing `RunCodeTool` can be updated to use this system for more robust language detection and execution.

2. **Container Management** - Works with the existing sandbox manager to create appropriate container environments.

3. **Resource Management** - Integrates with sandbox resource limits and cleanup mechanisms.

4. **MCP Protocol** - Provides rich execution results that can be serialized for MCP responses.

## Extensibility

The system is designed for easy extension:

### Adding New Languages

1. Implement the `LanguageHandler` interface
2. Register with the handler registry
3. Add detection patterns to the detector
4. Configure container images

### Adding New Package Managers

1. Implement the `PackageManager` interface
2. Register with the package manager registry
3. Add language-specific installation logic

### Custom Execution Environments

- Override container images
- Customize compilation flags
- Add language-specific optimizations

## Security Considerations

- Command injection prevention
- Dangerous command detection (especially in shell)
- Resource limit enforcement
- Sandboxed execution environments
- Input validation and sanitization

## Performance Optimizations

- Compilation caching for compiled languages
- Container image layer optimization
- Parallel package installation
- Efficient cleanup mechanisms
- Streaming output for long-running processes

This multi-language execution system provides a robust foundation for code execution in the SandboxRunner MCP server, supporting a wide variety of programming languages with comprehensive error handling, package management, and production-ready features.