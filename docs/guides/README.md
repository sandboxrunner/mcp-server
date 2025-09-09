# Developer Guides

Welcome to the SandboxRunner developer guides. These comprehensive guides will help you integrate SandboxRunner into your applications, understand best practices, and troubleshoot common issues.

## Getting Started

- [Quick Start Guide](./quick-start.md) - Get up and running in 5 minutes
- [Installation Guide](./installation.md) - Detailed installation instructions
- [Configuration Guide](./configuration.md) - Complete configuration reference
- [First Sandbox](./first-sandbox.md) - Create and use your first sandbox

## Integration Guides

- [MCP Client Integration](./mcp-integration.md) - Integrate with MCP clients
- [Claude Desktop Setup](./claude-desktop.md) - Setup with Claude Desktop
- [REST API Usage](./rest-api.md) - HTTP API integration
- [WebSocket Integration](./websocket.md) - Real-time communication
- [SDK Development](./sdk-development.md) - Build language-specific SDKs

## Language Guides

- [Python Development](./languages/python.md) - Python-specific features and best practices
- [JavaScript/Node.js](./languages/javascript.md) - JavaScript and Node.js development
- [TypeScript](./languages/typescript.md) - TypeScript compilation and execution
- [Go Programming](./languages/go.md) - Go modules and build tools
- [Rust Development](./languages/rust.md) - Cargo and Rust ecosystem
- [Java Development](./languages/java.md) - Maven, Gradle, and JVM
- [C++ Programming](./languages/cpp.md) - Compilation and libraries
- [C# Development](./languages/csharp.md) - .NET and NuGet packages
- [Shell Scripting](./languages/shell.md) - Shell scripts and system tools

## Advanced Topics

- [Security Best Practices](./security.md) - Container security and isolation
- [Performance Optimization](./performance.md) - Resource management and optimization
- [Monitoring and Logging](./monitoring.md) - Observability and debugging
- [Custom Images](./custom-images.md) - Building and using custom container images
- [Network Configuration](./networking.md) - Network policies and connectivity
- [Storage Management](./storage.md) - Persistent storage and file systems

## Deployment Guides

- [Production Deployment](./deployment/production.md) - Production-ready deployment
- [Docker Deployment](./deployment/docker.md) - Containerized deployment
- [Kubernetes Deployment](./deployment/kubernetes.md) - Kubernetes orchestration
- [Cloud Deployment](./deployment/cloud.md) - AWS, GCP, Azure deployment
- [High Availability](./deployment/high-availability.md) - HA configuration
- [Load Balancing](./deployment/load-balancing.md) - Scaling and load distribution

## Use Cases

- [Data Science Workflows](./use-cases/data-science.md) - Scientific computing and analysis
- [Web Development](./use-cases/web-development.md) - Full-stack development
- [API Development](./use-cases/api-development.md) - RESTful and GraphQL APIs
- [Microservices](./use-cases/microservices.md) - Microservice architecture
- [Educational Platforms](./use-cases/education.md) - Online coding platforms
- [CI/CD Pipelines](./use-cases/cicd.md) - Continuous integration and deployment
- [Code Evaluation](./use-cases/code-evaluation.md) - Automated code assessment

## Troubleshooting

- [Common Issues](./troubleshooting/common-issues.md) - Frequently encountered problems
- [Error Codes Reference](./troubleshooting/error-codes.md) - Complete error code documentation
- [Performance Issues](./troubleshooting/performance.md) - Performance debugging
- [Network Problems](./troubleshooting/network.md) - Network-related issues
- [Container Issues](./troubleshooting/containers.md) - Container runtime problems
- [Debug Mode](./troubleshooting/debug-mode.md) - Enhanced debugging and logging

## Migration Guides

- [Version Upgrade Guide](./migration/version-upgrade.md) - Upgrading between versions
- [Configuration Migration](./migration/config-migration.md) - Migrating configurations
- [API Changes](./migration/api-changes.md) - Breaking changes and migration paths

## Contributing

- [Development Setup](./contributing/development-setup.md) - Set up development environment
- [Code Style Guide](./contributing/code-style.md) - Coding standards and conventions
- [Testing Guide](./contributing/testing.md) - Writing and running tests
- [Documentation Guide](./contributing/documentation.md) - Contributing to documentation
- [Release Process](./contributing/release-process.md) - Release and versioning process

## Examples and Tutorials

- [Tutorial: Building a Code Playground](./tutorials/code-playground.md)
- [Tutorial: Data Processing Pipeline](./tutorials/data-pipeline.md)
- [Tutorial: Multi-Language Testing](./tutorials/multi-language-testing.md)
- [Tutorial: Interactive Learning Platform](./tutorials/learning-platform.md)
- [Tutorial: Serverless Functions](./tutorials/serverless-functions.md)

## Reference

- [API Reference](../api/README.md) - Complete API documentation
- [Configuration Reference](./reference/configuration.md) - All configuration options
- [Error Codes](./reference/error-codes.md) - Error code definitions
- [Performance Metrics](./reference/metrics.md) - Monitoring and metrics
- [Security Model](./reference/security.md) - Security architecture
- [Architecture Overview](./reference/architecture.md) - System architecture

## Community

- [Community Guidelines](./community/guidelines.md) - Community participation guidelines
- [Support Channels](./community/support.md) - Getting help and support
- [Contributing](./community/contributing.md) - How to contribute
- [Roadmap](./community/roadmap.md) - Project roadmap and future plans

## FAQ

### General Questions

**Q: What is SandboxRunner?**
A: SandboxRunner is an MCP server that provides secure, isolated execution environments for multiple programming languages using container technology.

**Q: Which languages are supported?**
A: Python, JavaScript, TypeScript, Go, Rust, Java, C++, C#, and Shell scripts with automatic language detection.

**Q: Is it secure?**
A: Yes, SandboxRunner uses runC containers with resource limits, network isolation, and security profiles for safe code execution.

**Q: Can I use it in production?**
A: Yes, SandboxRunner is designed for production use with proper configuration, monitoring, and security measures.

### Technical Questions

**Q: How do I install packages?**
A: Each language tool supports automatic package installation (pip for Python, npm for JavaScript, etc.) through the `packages` parameter.

**Q: Can I persist data between executions?**
A: Yes, use the file operations tools or mount persistent volumes to the sandbox environment.

**Q: How do I handle long-running processes?**
A: Set appropriate timeout values and consider using async execution patterns for long-running operations.

**Q: Can I access external services?**
A: Yes, configure network access with `network_mode: "bridge"` to enable internet connectivity.

### Integration Questions

**Q: How do I integrate with Claude Desktop?**
A: Add SandboxRunner to your Claude Desktop MCP configuration. See the [Claude Desktop Setup](./claude-desktop.md) guide.

**Q: Can I use it as a REST API?**
A: Yes, SandboxRunner supports both MCP protocol and HTTP REST API endpoints.

**Q: How do I build custom SDKs?**
A: Follow the [SDK Development](./sdk-development.md) guide for creating language-specific client libraries.

## Support

If you need help:

1. Check the relevant guide or FAQ above
2. Search [GitHub Issues](https://github.com/sandboxrunner/mcp-server/issues)
3. Join our [Discord community](https://discord.gg/sandboxrunner)
4. Create a detailed issue with reproduction steps

## License

SandboxRunner is licensed under the MIT License. See [LICENSE](../../LICENSE) for details.