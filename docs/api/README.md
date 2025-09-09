# SandboxRunner API Documentation

Welcome to the SandboxRunner MCP Server API documentation. This comprehensive guide covers all aspects of using SandboxRunner for secure, multi-language code execution in isolated sandbox environments.

## Table of Contents

- [Overview](#overview)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Language Support](#language-support)
- [Examples](#examples)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Overview

SandboxRunner is a Model Context Protocol (MCP) server that provides secure, isolated execution environments for multiple programming languages. It uses runC containers for security and isolation, offering:

- **Multi-language Support**: Python, JavaScript, TypeScript, Go, Rust, Java, C++, C#, Shell scripts
- **Package Management**: Automatic installation of language-specific packages
- **Resource Management**: CPU, memory, and disk limits
- **File Operations**: Complete file system management
- **Security**: Container isolation with configurable network policies

### Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   MCP Client    │◄──►│  SandboxRunner   │◄──►│  runC Container │
│  (Claude, etc.) │    │     Server       │    │   Environment   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Getting Started

### Installation

1. **Download the binary** from the releases page or build from source:
   ```bash
   make build
   ```

2. **Create configuration** file:
   ```bash
   make config
   ```

3. **Run the server**:
   ```bash
   ./build/bin/mcp-sandboxd --config config/mcp-sandboxd.yaml
   ```

### Claude Desktop Integration

Add to your Claude Desktop configuration (`~/.claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sandboxrunner": {
      "command": "/path/to/mcp-sandboxd",
      "args": ["--config", "/path/to/config/mcp-sandboxd.yaml"],
      "env": {
        "SANDBOXRUNNER_LOGGING_LEVEL": "info"
      }
    }
  }
}
```

## API Reference

### Core Tools

#### Sandbox Management
- [`create_sandbox`](./tools/create_sandbox.md) - Create new sandbox environments
- [`list_sandboxes`](./tools/list_sandboxes.md) - List all sandbox environments
- [`terminate_sandbox`](./tools/terminate_sandbox.md) - Terminate sandbox environments

#### Code Execution
- [`run_code`](./tools/run_code.md) - Execute code with auto-detection
- [`exec_command`](./tools/exec_command.md) - Execute shell commands

#### Language-Specific Tools
- [`run_python`](./tools/run_python.md) - Python code execution with pip
- [`run_javascript`](./tools/run_javascript.md) - JavaScript/Node.js with npm
- [`run_typescript`](./tools/run_typescript.md) - TypeScript with compilation
- [`run_go`](./tools/run_go.md) - Go code with modules
- [`run_rust`](./tools/run_rust.md) - Rust code with Cargo
- [`run_java`](./tools/run_java.md) - Java with Maven/Gradle
- [`run_cpp`](./tools/run_cpp.md) - C++ with compilation
- [`run_csharp`](./tools/run_csharp.md) - C# with .NET
- [`run_shell`](./tools/run_shell.md) - Shell scripts
- [`run_generic`](./tools/run_generic.md) - Generic execution

#### File Operations
- [`upload_file`](./tools/upload_file.md) - Upload files to sandbox
- [`download_file`](./tools/download_file.md) - Download files from sandbox
- [`read_file`](./tools/read_file.md) - Read file contents
- [`write_file`](./tools/write_file.md) - Write file contents
- [`list_files`](./tools/list_files.md) - List directory contents

## Language Support

### Python
- **Versions**: 3.7+
- **Package Manager**: pip
- **Virtual Environments**: Supported
- **Special Features**: Jupyter notebook support, scientific computing libraries

```python
# Example with packages
import numpy as np
import pandas as pd

data = np.random.randn(100, 4)
df = pd.DataFrame(data)
print(df.describe())
```

### JavaScript/Node.js
- **Versions**: 16+
- **Package Manager**: npm
- **Frameworks**: Express, React, etc.
- **Special Features**: ES modules, async/await

```javascript
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.json({ message: 'Hello World!' });
});
```

### TypeScript
- **Versions**: 4.5+
- **Compilation**: Automatic
- **Targets**: ES2020, ES2021, etc.
- **Special Features**: Type checking, modern syntax

```typescript
interface User {
  name: string;
  age: number;
}

const user: User = { name: 'Alice', age: 30 };
console.log(user);
```

### Go
- **Versions**: 1.18+
- **Modules**: Full support
- **Build Tools**: go build, go mod
- **Special Features**: Fast compilation, concurrency

```go
package main

import (
    "fmt"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()
    r.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello"})
    })
}
```

### Rust
- **Versions**: 1.60+
- **Package Manager**: Cargo
- **Editions**: 2018, 2021
- **Special Features**: Memory safety, performance

```rust
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Person {
    name: String,
    age: u32,
}

fn main() {
    let person = Person {
        name: "Alice".to_string(),
        age: 30,
    };
    println!("{:?}", person);
}
```

### Java
- **Versions**: 11+
- **Build Tools**: Maven, Gradle
- **Frameworks**: Spring, etc.
- **Special Features**: JVM optimization, enterprise features

```java
import java.util.stream.IntStream;

public class Main {
    public static void main(String[] args) {
        int sum = IntStream.range(1, 101).sum();
        System.out.println("Sum: " + sum);
    }
}
```

### C++
- **Standards**: C++11, C++14, C++17, C++20
- **Compilers**: GCC, Clang
- **Libraries**: STL, Boost, etc.
- **Special Features**: Template metaprogramming, RAII

```cpp
#include <iostream>
#include <vector>
#include <algorithm>

int main() {
    std::vector<int> nums = {3, 1, 4, 1, 5, 9, 2, 6};
    std::sort(nums.begin(), nums.end());
    
    for (const auto& n : nums) {
        std::cout << n << " ";
    }
    return 0;
}
```

### C#
- **Versions**: .NET 6+
- **Package Manager**: NuGet
- **Frameworks**: ASP.NET Core, etc.
- **Special Features**: LINQ, async/await, nullable references

```csharp
using System;
using System.Linq;

class Program {
    static void Main() {
        var numbers = Enumerable.Range(1, 10);
        var sum = numbers.Where(n => n % 2 == 0).Sum();
        Console.WriteLine($"Sum of even numbers: {sum}");
    }
}
```

## Examples

### Basic Workflow

1. **Create a sandbox**:
   ```json
   {
     "tool": "create_sandbox",
     "parameters": {
       "image": "python:3.11",
       "memory_limit": "1G"
     }
   }
   ```

2. **Execute code**:
   ```json
   {
     "tool": "run_python",
     "parameters": {
       "sandbox_id": "12345678-1234-1234-1234-123456789abc",
       "code": "print('Hello World!')",
       "packages": ["numpy", "pandas"]
     }
   }
   ```

3. **Manage files**:
   ```json
   {
     "tool": "write_file",
     "parameters": {
       "sandbox_id": "12345678-1234-1234-1234-123456789abc",
       "path": "/workspace/data.txt",
       "content": "Hello, World!"
     }
   }
   ```

4. **Clean up**:
   ```json
   {
     "tool": "terminate_sandbox",
     "parameters": {
       "sandbox_id": "12345678-1234-1234-1234-123456789abc"
     }
   }
   ```

### Advanced Examples

See the [examples directory](../examples/) for comprehensive examples including:
- Multi-language projects
- Web application deployment
- Data science workflows
- Microservice development
- CI/CD pipeline integration

## Error Handling

### Common Error Codes

- `SANDBOX_NOT_FOUND` - Sandbox doesn't exist
- `INVALID_PARAMETERS` - Invalid request parameters
- `EXECUTION_TIMEOUT` - Code execution timed out
- `PACKAGE_INSTALL_FAILED` - Package installation failed
- `COMPILATION_ERROR` - Code compilation failed
- `RESOURCE_LIMIT_EXCEEDED` - Resource limits exceeded

### Error Response Format

```json
{
  "text": "Error message for user",
  "is_error": true,
  "metadata": {
    "code": "SANDBOX_NOT_FOUND",
    "message": "Sandbox not found",
    "details": "No sandbox found with ID 12345678-1234-1234-1234-123456789abc",
    "context": {
      "sandbox_id": "12345678-1234-1234-1234-123456789abc",
      "timestamp": "2024-01-15T10:30:00Z"
    }
  }
}
```

### Retry Strategies

1. **Transient Errors**: Retry with exponential backoff
2. **Resource Limits**: Increase limits or optimize code
3. **Package Errors**: Check package names and versions
4. **Timeout Errors**: Increase timeout or optimize code

## Best Practices

### Security
- Use minimal container images
- Set appropriate resource limits
- Avoid hardcoding credentials
- Validate all inputs
- Use network isolation by default

### Performance
- Reuse sandboxes when possible
- Choose appropriate timeout values
- Use compiled languages for CPU-intensive tasks
- Monitor resource usage
- Cache package installations

### Development
- Test with simple examples first
- Use version pinning for packages
- Handle errors gracefully
- Log execution details
- Implement proper cleanup

### Resource Management
```json
{
  "cpu_limit": "2.0",
  "memory_limit": "2G",
  "disk_limit": "10G",
  "timeout": 120
}
```

### Package Management
```json
{
  "packages": [
    "numpy==1.21.0",
    "pandas>=1.3.0,<2.0.0",
    "requests"
  ]
}
```

## Support

For support, please:
1. Check the [FAQ](./faq.md)
2. Review [troubleshooting guide](./troubleshooting.md)
3. Search [GitHub issues](https://github.com/sandboxrunner/mcp-server/issues)
4. Create a new issue with detailed information

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines on contributing to SandboxRunner.

## License

SandboxRunner is licensed under the MIT License. See [LICENSE](../../LICENSE) for details.