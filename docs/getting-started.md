# Getting Started with SandboxRunner

**Get up and running with SandboxRunner in under 5 minutes!**

SandboxRunner is a powerful MCP (Model Context Protocol) server that provides secure, isolated execution environments for multiple programming languages. This guide will walk you through installation, configuration, and your first code execution.

## Prerequisites

Before you begin, ensure you have:

- **Operating System**: Linux, macOS, or Windows with WSL2
- **Container Runtime**: Docker installed and running
- **runC**: Container runtime (usually included with Docker)
- **System Resources**: 
  - 2GB+ available RAM
  - 10GB+ available disk space
  - Internet connection for package downloads

### Verify Prerequisites

```bash
# Check Docker
docker --version
docker ps

# Check runC
runc --version

# Check system resources
df -h  # Disk space
free -h  # Memory (Linux)
```

## Installation Options

### Option 1: Pre-built Binary (Recommended)

Download the latest release for your platform:

```bash
# Linux (x86_64)
curl -L https://github.com/sandboxrunner/mcp-server/releases/latest/download/mcp-sandboxd-linux-amd64 -o mcp-sandboxd
chmod +x mcp-sandboxd

# macOS (Intel)
curl -L https://github.com/sandboxrunner/mcp-server/releases/latest/download/mcp-sandboxd-darwin-amd64 -o mcp-sandboxd
chmod +x mcp-sandboxd

# macOS (Apple Silicon)
curl -L https://github.com/sandboxrunner/mcp-server/releases/latest/download/mcp-sandboxd-darwin-arm64 -o mcp-sandboxd
chmod +x mcp-sandboxd

# Windows (WSL2)
curl -L https://github.com/sandboxrunner/mcp-server/releases/latest/download/mcp-sandboxd-linux-amd64 -o mcp-sandboxd
chmod +x mcp-sandboxd

# Optional: Move to PATH
sudo mv mcp-sandboxd /usr/local/bin/
```

### Option 2: Docker Container

```bash
# Pull the image
docker pull sandboxrunner/mcp-server:latest

# Run with Docker
docker run -it --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config:/config \
  sandboxrunner/mcp-server:latest \
  --config /config/mcp-sandboxd.yaml
```

### Option 3: Build from Source

```bash
# Clone repository
git clone https://github.com/sandboxrunner/mcp-server.git
cd mcp-server

# Install dependencies
make deps

# Build binary
make build

# Binary will be in build/bin/mcp-sandboxd
```

## Quick Configuration

### Generate Default Configuration

```bash
# Create configuration directory
mkdir -p ~/.config/sandboxrunner

# Generate default configuration
./mcp-sandboxd --generate-config > ~/.config/sandboxrunner/config.yaml
```

### Minimal Configuration

For a quick start, create a minimal configuration file:

```yaml
# ~/.config/sandboxrunner/config.yaml
server:
  protocol: "stdio"  # Use "http" for REST API
  logging:
    level: "info"

sandbox:
  workspace_dir: "/tmp/sandboxrunner/workspaces"
  default_image: "ubuntu:22.04"
  max_sandboxes: 10
  default_resources:
    cpu_limit: "2.0"
    memory_limit: "1G" 
    disk_limit: "10G"
  network_mode: "none"  # "bridge" for internet access

tools:
  enabled_tools: ["create_sandbox", "run_python", "run_javascript", 
                  "run_go", "upload_file", "download_file", "exec_command"]
  default_timeout: "30s"
  validation_level: "strict"
```

## First Execution

### Test 1: Verify Installation

```bash
# Check version
./mcp-sandboxd --version

# Validate configuration
./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml --validate

# Expected output: "Configuration is valid"
```

### Test 2: Start the Server

```bash
# Start in foreground (for testing)
./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml --log-level debug

# Server should start and display:
# {"level":"info","msg":"SandboxRunner MCP Server starting..."}
# {"level":"info","msg":"Server ready for MCP protocol communication"}
```

### Test 3: MCP Protocol Test

Open a new terminal and test the MCP protocol:

```bash
# Test with JSON-RPC over stdin/stdout
echo '{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}' | ./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml
```

Expected response showing available tools:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {"name": "create_sandbox", "description": "Create isolated sandbox environment"},
      {"name": "run_python", "description": "Execute Python code"},
      {"name": "run_javascript", "description": "Execute JavaScript/Node.js code"},
      // ... more tools
    ]
  }
}
```

### Test 4: HTTP API Test (Optional)

If using HTTP mode, update your config:

```yaml
server:
  protocol: "http"
  port: 8080
```

Then test the HTTP API:

```bash
# Start server in background
./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml &

# Test health endpoint
curl http://localhost:8080/health

# Test tools list
curl http://localhost:8080/mcp/tools
```

## Your First Code Execution

### Step 1: Create a Sandbox

Using MCP protocol:
```bash
echo '{
  "jsonrpc": "2.0", 
  "id": 1, 
  "method": "tools/call", 
  "params": {
    "name": "create_sandbox",
    "arguments": {
      "image": "python:3.11-slim",
      "memory_limit": "1G"
    }
  }
}' | ./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml
```

Using HTTP API:
```bash
curl -X POST http://localhost:8080/mcp/tools/create_sandbox \
  -H "Content-Type: application/json" \
  -d '{
    "image": "python:3.11-slim",
    "memory_limit": "1G"
  }'
```

**Save the sandbox ID from the response!** You'll need it for the next steps.

### Step 2: Execute Python Code

```bash
# Replace YOUR_SANDBOX_ID with the ID from step 1
echo '{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "run_python",
    "arguments": {
      "sandbox_id": "YOUR_SANDBOX_ID",
      "code": "print(\"Hello from SandboxRunner!\")\nimport sys\nprint(f\"Python version: {sys.version}\")\nprint(f\"2 + 2 = {2 + 2}\")",
      "packages": ["numpy"]
    }
  }
}' | ./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml
```

Expected output:
```
Hello from SandboxRunner!
Python version: 3.11.x
2 + 2 = 4
NumPy version: 1.24.x
```

### Step 3: Try JavaScript

```bash
echo '{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "run_javascript",
    "arguments": {
      "sandbox_id": "YOUR_SANDBOX_ID",
      "code": "console.log(\"Hello from Node.js!\");\nconsole.log(\"Node version:\", process.version);\nconsole.log(\"Platform:\", process.platform);",
      "packages": ["lodash"]
    }
  }
}' | ./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml
```

### Step 4: File Operations

```bash
# Write a file
echo '{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "write_file",
    "arguments": {
      "sandbox_id": "YOUR_SANDBOX_ID",
      "path": "/workspace/hello.txt",
      "content": "Hello, World from SandboxRunner!"
    }
  }
}' | ./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml

# Read the file back
echo '{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "sandbox_id": "YOUR_SANDBOX_ID",
      "path": "/workspace/hello.txt"
    }
  }
}' | ./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml
```

### Step 5: Clean Up

```bash
# Terminate the sandbox
echo '{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "terminate_sandbox",
    "arguments": {
      "sandbox_id": "YOUR_SANDBOX_ID"
    }
  }
}' | ./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml
```

## Claude Desktop Integration

### Step 1: Configure Claude Desktop

Add to your Claude Desktop configuration file (`~/.claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sandboxrunner": {
      "command": "/usr/local/bin/mcp-sandboxd",
      "args": [
        "--config", 
        "/home/USERNAME/.config/sandboxrunner/config.yaml"
      ],
      "env": {
        "SANDBOXRUNNER_LOGGING_LEVEL": "info"
      }
    }
  }
}
```

### Step 2: Restart Claude Desktop

Close and restart Claude Desktop. SandboxRunner tools should now be available in Claude conversations.

### Step 3: Test with Claude

Start a conversation with Claude and try:

```
Can you create a Python sandbox and run some code to calculate the factorial of 10?
```

Claude should automatically use SandboxRunner to:
1. Create a sandbox
2. Execute Python code  
3. Return the results
4. Clean up the sandbox

## Troubleshooting

### Common Issues

**Server won't start:**
```bash
# Check configuration syntax
./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml --validate

# Check permissions
ls -la ~/.config/sandboxrunner/
sudo chown -R $USER ~/.config/sandboxrunner/

# Check logs
./mcp-sandboxd --config ~/.config/sandboxrunner/config.yaml --log-level debug
```

**Docker/Container errors:**
```bash
# Verify Docker is running
docker ps

# Test container creation
docker run --rm ubuntu:22.04 echo "Hello"

# Check Docker permissions
sudo usermod -aG docker $USER
newgrp docker
```

**Claude Desktop integration issues:**
```bash
# Verify configuration file syntax
cat ~/.claude_desktop_config.json | python -m json.tool

# Check executable path
which mcp-sandboxd
ls -la /usr/local/bin/mcp-sandboxd

# Check Claude Desktop logs (macOS)
tail -f ~/Library/Logs/Claude/claude_desktop.log
```

**Network connectivity issues:**
```bash
# Test with network access enabled
# Update config.yaml:
sandbox:
  network_mode: "bridge"  # Enable internet access

# Test external connectivity
curl -X POST http://localhost:8080/mcp/tools/run_python \
  -H "Content-Type: application/json" \
  -d '{
    "sandbox_id": "YOUR_SANDBOX_ID",
    "code": "import urllib.request\nresponse = urllib.request.urlopen(\"http://httpbin.org/get\")\nprint(response.status)",
    "timeout": 10
  }'
```

### Getting Help

1. **Check logs**: Enable debug logging for detailed information
2. **Verify setup**: Use the validation commands above
3. **Community**: Join our [Discord](https://discord.gg/sandboxrunner)
4. **Issues**: Report bugs on [GitHub](https://github.com/sandboxrunner/mcp-server/issues)

## Next Steps

🎉 **Congratulations!** You now have SandboxRunner up and running.

### Learn More
- **[API Documentation](./api/README.md)** - Complete API reference
- **[Language Guides](./guides/languages/)** - Language-specific features
- **[Configuration Guide](./configuration-guide.md)** - Advanced configuration
- **[Tutorials](./tutorials/)** - Step-by-step tutorials

### Advanced Features
- **[Custom Images](./guides/custom-images.md)** - Build custom container environments
- **[Security Guide](./guides/security.md)** - Production security best practices
- **[Performance Tuning](./performance-guide.md)** - Optimize for your use case
- **[Production Deployment](./guides/deployment/production.md)** - Deploy at scale

### Use Cases
- **[Data Science](./tutorials/data-science-workflow.md)** - Scientific computing workflows
- **[Web Development](./tutorials/web-development.md)** - Full-stack development
- **[Multi-language Projects](./tutorials/multi-language-project.md)** - Polyglot development

Happy coding with SandboxRunner! 🚀