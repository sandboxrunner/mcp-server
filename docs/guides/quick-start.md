# Quick Start Guide

Get up and running with SandboxRunner in under 5 minutes! This guide will walk you through installation, basic configuration, and your first code execution.

## Prerequisites

- Linux, macOS, or Windows with WSL2
- Docker installed and running
- runC container runtime
- 2GB+ available RAM
- 10GB+ available disk space

## Step 1: Installation

### Option A: Download Binary (Recommended)

```bash
# Download the latest release
curl -L https://github.com/sandboxrunner/mcp-server/releases/latest/download/mcp-sandboxd-linux-amd64 -o mcp-sandboxd
chmod +x mcp-sandboxd

# Move to PATH (optional)
sudo mv mcp-sandboxd /usr/local/bin/
```

### Option B: Build from Source

```bash
# Clone repository
git clone https://github.com/sandboxrunner/mcp-server.git
cd mcp-server

# Build
make build

# Binary will be in build/bin/mcp-sandboxd
```

## Step 2: Basic Configuration

Create a basic configuration file:

```bash
# Generate default configuration
./mcp-sandboxd --generate-config > config.yaml
```

Or create a minimal config manually:

```yaml
# config.yaml
server:
  protocol: "stdio"
  logging:
    level: "info"

sandboxes:
  default_image: "ubuntu:22.04"
  workspace_dir: "/workspace"
  max_sandboxes: 10
  resource_limits:
    cpu: "2.0"
    memory: "1G"
    disk: "10G"

tools:
  enabled: true
  timeout: 300
```

## Step 3: Start the Server

```bash
# Start SandboxRunner
./mcp-sandboxd --config config.yaml
```

The server will start and wait for MCP protocol messages on stdin/stdout.

## Step 4: Test with curl (HTTP Mode)

If you prefer HTTP API testing, modify your config:

```yaml
server:
  protocol: "http"
  port: 8080
```

Then test with curl:

```bash
# Start server in background
./mcp-sandboxd --config config.yaml &

# Create a sandbox
curl -X POST http://localhost:8080/mcp/tools/create_sandbox \
  -H "Content-Type: application/json" \
  -d '{
    "image": "python:3.11",
    "memory_limit": "1G"
  }'

# Response will include sandbox_id
# {"text": "Sandbox created...", "metadata": {"sandbox_id": "12345..."}}
```

## Step 5: Execute Your First Code

### Python Example

```bash
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "print(\"Hello from SandboxRunner!\")\nprint(f\"2 + 2 = {2 + 2}\")",
    "packages": ["numpy"]
  }'
```

### JavaScript Example

```bash
curl -X POST http://localhost:8080/mcp/tools/run_javascript \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "console.log(\"Hello from Node.js!\");\nconsole.log(\"Current time:\", new Date().toISOString());",
    "packages": ["lodash"]
  }'
```

## Step 6: Claude Desktop Integration

To use with Claude Desktop, add to your configuration file (`~/.claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sandboxrunner": {
      "command": "/path/to/mcp-sandboxd",
      "args": ["--config", "/path/to/config.yaml"]
    }
  }
}
```

Restart Claude Desktop and SandboxRunner tools will be available!

## Example Workflow

Here's a complete workflow using the MCP protocol (JSON-RPC over stdio):

```bash
# Input (to stdin)
{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "create_sandbox", "arguments": {"image": "python:3.11"}}}

# Output (from stdout)
{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "Sandbox created successfully\nID: abc123..."}]}}

# Run Python code
{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "run_python", "arguments": {"sandbox_id": "abc123...", "code": "import numpy as np\nprint('NumPy version:', np.__version__)", "packages": ["numpy"]}}}

# Clean up
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "terminate_sandbox", "arguments": {"sandbox_id": "abc123..."}}}
```

## Next Steps

Now that you have SandboxRunner running, explore these topics:

### Learn the Tools
- [API Reference](../api/README.md) - Complete tool documentation
- [Language Guides](./languages/) - Language-specific features
- [Examples](../examples/) - Code examples and use cases

### Advanced Configuration
- [Security Guide](./security.md) - Security best practices
- [Performance Guide](./performance.md) - Optimization tips
- [Custom Images](./custom-images.md) - Build custom container images

### Integration
- [MCP Integration](./mcp-integration.md) - Integrate with MCP clients
- [REST API Usage](./rest-api.md) - HTTP API integration
- [SDK Development](./sdk-development.md) - Build client libraries

### Production Deployment
- [Production Deployment](./deployment/production.md) - Production setup
- [Monitoring](./monitoring.md) - Observability and logging
- [High Availability](./deployment/high-availability.md) - HA configuration

## Troubleshooting

### Common Issues

**Server won't start:**
```bash
# Check configuration
./mcp-sandboxd --config config.yaml --validate

# Check logs
./mcp-sandboxd --config config.yaml --log-level debug
```

**Container errors:**
```bash
# Verify Docker is running
docker ps

# Test container runtime
docker run --rm ubuntu:22.04 echo "Hello World"

# Check runC installation
runc --version
```

**Permission errors:**
```bash
# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Or run with sudo (not recommended for production)
sudo ./mcp-sandboxd --config config.yaml
```

**Network issues:**
```bash
# Check port availability
netstat -ln | grep 8080

# Test local connectivity
curl http://localhost:8080/health
```

### Getting Help

If you encounter issues:

1. Check the [Troubleshooting Guide](./troubleshooting/common-issues.md)
2. Review [Error Codes](./troubleshooting/error-codes.md)
3. Search [GitHub Issues](https://github.com/sandboxrunner/mcp-server/issues)
4. Join our [Discord community](https://discord.gg/sandboxrunner)

## What's Next?

- **Try Different Languages**: Experiment with Go, Rust, TypeScript, etc.
- **Build a Project**: Create a multi-language application
- **Integrate with Your App**: Use the HTTP API or MCP protocol
- **Customize**: Build custom container images for your use case
- **Scale**: Deploy in production with monitoring and HA

Welcome to SandboxRunner! 🚀