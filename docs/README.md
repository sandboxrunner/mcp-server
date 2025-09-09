# SandboxRunner Documentation Hub

Welcome to the comprehensive documentation for SandboxRunner - the secure, multi-language code execution platform built on MCP (Model Context Protocol).

## 📚 Documentation Overview

SandboxRunner provides secure, isolated execution environments for multiple programming languages using container technology. This documentation covers everything from quick setup to advanced deployment scenarios.

## 🚀 Quick Start

- **[Quick Start Guide](./guides/quick-start.md)** - Get running in 5 minutes
- **[API Reference](./api/README.md)** - Complete API documentation
- **[Interactive Swagger UI](./api/swagger-ui.html)** - Test APIs directly in your browser

## 📖 Main Documentation Sections

### 🎯 API Documentation
Comprehensive API reference with interactive tools:
- **[API Overview](./api/README.md)** - Complete API documentation
- **[OpenAPI Specification](./api/openapi.yaml)** - Machine-readable API spec
- **[Interactive Documentation](./api/swagger-ui.html)** - Swagger UI with testing capabilities
- **[Tool Reference](./api/tools/)** - Detailed documentation for each MCP tool

### 📋 Developer Guides
Step-by-step guides for developers:
- **[Quick Start](./guides/quick-start.md)** - 5-minute setup guide
- **[Installation Guide](./guides/installation.md)** - Detailed installation instructions
- **[MCP Integration](./guides/mcp-integration.md)** - Integrate with MCP clients
- **[Language Guides](./guides/languages/)** - Language-specific documentation
- **[Security Best Practices](./guides/security.md)** - Security guidelines
- **[Performance Optimization](./guides/performance.md)** - Performance tuning

### 🛠 SDK & Integration
Client libraries and integration tools:
- **[Python SDK](./sdk/python/)** - Comprehensive Python client library
- **[Postman Collection](./examples/postman_collection.json)** - Ready-to-use API collection
- **[Code Examples](./examples/)** - Practical usage examples
- **[SDK Development Guide](./guides/sdk-development.md)** - Build custom SDKs

### 🏗 Deployment & Operations
Production deployment guidance:
- **[Production Deployment](./guides/deployment/production.md)** - Production setup
- **[Docker Deployment](./guides/deployment/docker.md)** - Container deployment
- **[Kubernetes Guide](./guides/deployment/kubernetes.md)** - Kubernetes orchestration
- **[Monitoring & Logging](./guides/monitoring.md)** - Observability setup

## 🎨 Interactive Features

### 🌐 Swagger UI
**[Access Interactive API Documentation](./api/swagger-ui.html)**
- Test all API endpoints directly
- Generate SDKs for multiple languages
- Download OpenAPI specification
- Export Postman collections

### 🧪 Example Collections
- **[Postman Collection](./examples/postman_collection.json)** - Complete API test suite
- **[Language Examples](./examples/)** - Multi-language code samples
- **[Use Case Demos](./guides/use-cases/)** - Real-world implementation examples

## 🔧 Language Support

SandboxRunner supports multiple programming languages with specialized tools:

| Language | Tool | Package Manager | Features |
|----------|------|-----------------|----------|
| **Python** | `run_python` | pip | Virtual environments, Jupyter support |
| **JavaScript** | `run_javascript` | npm | Node.js, ES modules, async/await |
| **TypeScript** | `run_typescript` | npm | Automatic compilation, type checking |
| **Go** | `run_go` | go mod | Module support, fast compilation |
| **Rust** | `run_rust` | Cargo | Memory safety, performance |
| **Java** | `run_java` | Maven/Gradle | JVM optimization, enterprise features |
| **C++** | `run_cpp` | System packages | Multiple standards, optimization levels |
| **C#** | `run_csharp` | NuGet | .NET support, LINQ, async/await |
| **Shell** | `run_shell` | apt/yum | Multiple shells, system tools |

## 📋 Core Features

### 🛡 Security & Isolation
- **Container Isolation**: runC containers for secure execution
- **Resource Limits**: CPU, memory, and disk constraints
- **Network Policies**: Configurable network access control
- **Input Validation**: Comprehensive parameter validation
- **Audit Logging**: Complete execution audit trail

### ⚡ Performance & Scalability
- **Resource Management**: Efficient resource utilization
- **Concurrent Execution**: Multiple sandbox support
- **Package Caching**: Optimized dependency installation
- **Fast Startup**: Minimal container overhead
- **Auto Cleanup**: Automatic resource management

### 🔌 Integration Options
- **MCP Protocol**: Native Model Context Protocol support
- **HTTP REST API**: RESTful API for any language
- **WebSocket Streaming**: Real-time execution monitoring
- **Claude Desktop**: Direct integration with Claude
- **Custom SDKs**: Multi-language client libraries

## 🎯 Common Use Cases

### 📊 Data Science & Analytics
```python
# Python data analysis example
import pandas as pd
import numpy as np

data = pd.read_csv('/workspace/data.csv')
analysis_result = data.describe()
print(analysis_result)
```

### 🌐 Web Development
```javascript
// Express.js web server
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.json({ message: 'Hello World!' });
});
```

### 🔬 Algorithm Development
```rust
// Rust performance example
fn quicksort(arr: &mut [i32]) {
    if arr.len() <= 1 { return; }
    // ... sorting logic
}
```

### 🎓 Educational Platforms
- Interactive coding environments
- Automated code evaluation
- Multi-language support
- Safe execution sandboxing

## 🚦 Getting Started Paths

### 👨‍💻 Developer
1. **[Quick Start](./guides/quick-start.md)** - Basic setup
2. **[API Reference](./api/README.md)** - Learn the API
3. **[Python SDK](./sdk/python/)** - Use the SDK
4. **[Examples](./examples/)** - See it in action

### 🏢 Enterprise
1. **[Security Guide](./guides/security.md)** - Security assessment
2. **[Production Deployment](./guides/deployment/production.md)** - Deploy at scale
3. **[Monitoring](./guides/monitoring.md)** - Set up observability
4. **[High Availability](./guides/deployment/high-availability.md)** - HA setup

### 🎓 Educator
1. **[Educational Use Cases](./guides/use-cases/education.md)** - Teaching scenarios
2. **[Code Evaluation](./guides/use-cases/code-evaluation.md)** - Automated assessment
3. **[Multi-Language Support](./guides/languages/)** - Language features
4. **[Safety Features](./guides/security.md)** - Student safety

### 🔬 Data Scientist
1. **[Data Science Guide](./guides/use-cases/data-science.md)** - Scientific computing
2. **[Python Features](./guides/languages/python.md)** - Python-specific tools
3. **[Jupyter Integration](./guides/languages/python.md#jupyter-support)** - Notebook support
4. **[Package Management](./guides/languages/python.md#packages)** - Scientific libraries

## 🔗 Quick Links

### 📚 Documentation
- [Complete API Reference](./api/README.md)
- [Tool Documentation](./api/tools/)
- [Configuration Guide](./guides/configuration.md)
- [Troubleshooting](./guides/troubleshooting/)

### 🧰 Development Tools
- [Interactive Swagger UI](./api/swagger-ui.html)
- [Postman Collection](./examples/postman_collection.json)
- [Python SDK](./sdk/python/sandboxrunner.py)
- [Example Code](./examples/)

### 🌍 Community & Support
- [GitHub Repository](https://github.com/sandboxrunner/mcp-server)
- [Issue Tracker](https://github.com/sandboxrunner/mcp-server/issues)
- [Discord Community](https://discord.gg/sandboxrunner)
- [Discussions](https://github.com/sandboxrunner/mcp-server/discussions)

## 📄 Reference Documentation

### 🔧 Configuration
- [Complete Configuration Reference](./guides/reference/configuration.md)
- [Environment Variables](./guides/reference/environment.md)
- [Security Settings](./guides/reference/security.md)
- [Performance Tuning](./guides/reference/performance.md)

### 📊 Monitoring & Metrics
- [Metrics Reference](./guides/reference/metrics.md)
- [Health Checks](./guides/reference/health.md)
- [Logging Configuration](./guides/reference/logging.md)
- [Alerting Setup](./guides/reference/alerting.md)

### 🐛 Troubleshooting
- [Common Issues](./guides/troubleshooting/common-issues.md)
- [Error Code Reference](./guides/troubleshooting/error-codes.md)
- [Performance Issues](./guides/troubleshooting/performance.md)
- [Debug Mode](./guides/troubleshooting/debug-mode.md)

## 🆕 What's New

### Version 5.2.0
- **Enhanced API Documentation**: Complete OpenAPI 3.0 specification
- **Interactive Swagger UI**: Test APIs directly in your browser
- **Python SDK**: Comprehensive Python client library
- **Postman Integration**: Ready-to-use API collections
- **Improved Performance**: Faster container startup and execution
- **Enhanced Security**: Additional isolation and validation features

### Recent Updates
- **Multi-language Support**: Added C#, Rust, and improved TypeScript support
- **Package Management**: Enhanced dependency installation for all languages
- **Resource Management**: Better CPU, memory, and disk limit enforcement
- **Monitoring**: Improved logging and metrics collection
- **Documentation**: Comprehensive guides and examples

## 🤝 Contributing

We welcome contributions! See our guides:
- [Development Setup](./guides/contributing/development-setup.md)
- [Code Style Guide](./guides/contributing/code-style.md)
- [Testing Guidelines](./guides/contributing/testing.md)
- [Documentation Guidelines](./guides/contributing/documentation.md)

## 📞 Support & Community

### Getting Help
1. **Documentation**: Check the relevant guide above
2. **FAQ**: Review [Frequently Asked Questions](./guides/faq.md)
3. **Search Issues**: Look through [GitHub Issues](https://github.com/sandboxrunner/mcp-server/issues)
4. **Community**: Join our [Discord Server](https://discord.gg/sandboxrunner)
5. **Enterprise Support**: Contact [enterprise@sandboxrunner.dev](mailto:enterprise@sandboxrunner.dev)

### Reporting Issues
When reporting issues, please include:
- SandboxRunner version
- Operating system and version
- Container runtime information
- Complete error messages
- Steps to reproduce
- Expected vs actual behavior

## 📜 License

SandboxRunner is licensed under the MIT License. See [LICENSE](../LICENSE) for details.

---

**Start your journey**: Begin with our [Quick Start Guide](./guides/quick-start.md) and have SandboxRunner running in minutes!

**Need help?** Join our [community](https://discord.gg/sandboxrunner) or check the [troubleshooting guide](./guides/troubleshooting/common-issues.md).