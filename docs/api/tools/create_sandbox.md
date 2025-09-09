# create_sandbox

Creates a new isolated sandbox environment with specified configuration.

## Description

The `create_sandbox` tool creates a new secure, isolated environment using runC containers. Each sandbox is completely isolated with its own filesystem, network, and resource limits. This is typically the first step in any SandboxRunner workflow.

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `image` | string | No | `ubuntu:22.04` | Container image to use for the sandbox |
| `workspace_dir` | string | No | `/workspace` | Working directory inside the sandbox |
| `environment` | object | No | `{}` | Environment variables for the sandbox |
| `cpu_limit` | string | No | None | CPU limit (e.g., '1.0' for 1 CPU, '2.5' for 2.5 CPUs) |
| `memory_limit` | string | No | None | Memory limit (e.g., '1G', '512M', '2GB') |
| `disk_limit` | string | No | None | Disk limit (e.g., '10G', '1TB') |
| `network_mode` | string | No | `none` | Network mode: `none`, `bridge`, or `host` |

### Parameter Details

#### `image`
Container image to use as the base for the sandbox. Common options:
- `ubuntu:22.04` - Latest Ubuntu LTS (default)
- `python:3.11` - Python 3.11 environment
- `node:18` - Node.js 18 environment
- `golang:1.21` - Go 1.21 environment
- `rust:1.70` - Rust 1.70 environment
- Custom images from Docker Hub or private registries

#### `cpu_limit`
CPU resources allocated to the sandbox:
- Format: Decimal number representing CPU cores
- Examples: `"1.0"` (1 full CPU), `"0.5"` (half CPU), `"2.5"` (2.5 CPUs)
- Pattern: `^\\d+(\\.\\d+)?$`

#### `memory_limit`
Memory resources allocated to the sandbox:
- Format: Number followed by unit (K, M, G, T)
- Examples: `"512M"`, `"1G"`, `"2GB"`, `"1024MB"`
- Pattern: `^\\d+[KMGT]?B?$`

#### `disk_limit`
Disk space available in the sandbox:
- Format: Number followed by unit (K, M, G, T)
- Examples: `"5G"`, `"10GB"`, `"1TB"`, `"500M"`
- Pattern: `^\\d+[KMGT]?B?$`

#### `network_mode`
Network configuration for the sandbox:
- `none` - No network access (most secure, default)
- `bridge` - Bridge network with internet access
- `host` - Host network (least secure, use cautiously)

#### `environment`
Environment variables to set in the sandbox:
```json
{
  "PATH": "/usr/local/bin:/usr/bin:/bin",
  "PYTHONPATH": "/workspace",
  "NODE_ENV": "development",
  "DATABASE_URL": "sqlite:///workspace/app.db"
}
```

## Response

### Success Response
```json
{
  "text": "Sandbox created successfully\nID: 12345678-1234-1234-1234-123456789abc\nImage: ubuntu:22.04\nStatus: running\nWorking Directory: /workspace",
  "is_error": false,
  "metadata": {
    "sandbox_id": "12345678-1234-1234-1234-123456789abc",
    "container_id": "container-abc123",
    "status": "running",
    "image": "ubuntu:22.04",
    "workspace_dir": "/workspace",
    "created_at": "2024-01-15T10:30:00Z",
    "config": {
      "cpu_limit": "2.0",
      "memory_limit": "1G",
      "disk_limit": "10G",
      "network_mode": "none",
      "environment": {
        "PATH": "/usr/local/bin:/usr/bin:/bin"
      }
    }
  }
}
```

### Error Response
```json
{
  "text": "Failed to create sandbox: image not found",
  "is_error": true,
  "metadata": {
    "code": "IMAGE_NOT_FOUND",
    "message": "Container image 'invalid:latest' not found",
    "details": "The specified container image could not be pulled",
    "context": {
      "image": "invalid:latest",
      "registry": "docker.io"
    }
  }
}
```

## Examples

### Basic Ubuntu Sandbox
```json
{
  "tool": "create_sandbox",
  "parameters": {
    "image": "ubuntu:22.04",
    "workspace_dir": "/workspace"
  }
}
```

### Python Development Environment
```json
{
  "tool": "create_sandbox",
  "parameters": {
    "image": "python:3.11",
    "workspace_dir": "/app",
    "cpu_limit": "2.0",
    "memory_limit": "2G",
    "disk_limit": "5G",
    "environment": {
      "PYTHONPATH": "/app",
      "PYTHONUNBUFFERED": "1",
      "PIP_NO_CACHE_DIR": "1"
    }
  }
}
```

### Node.js with Network Access
```json
{
  "tool": "create_sandbox",
  "parameters": {
    "image": "node:18",
    "cpu_limit": "1.5",
    "memory_limit": "1G",
    "network_mode": "bridge",
    "environment": {
      "NODE_ENV": "development",
      "NPM_CONFIG_CACHE": "/tmp/.npm"
    }
  }
}
```

### High-Performance Computing Environment
```json
{
  "tool": "create_sandbox",
  "parameters": {
    "image": "ubuntu:22.04",
    "cpu_limit": "8.0",
    "memory_limit": "16G",
    "disk_limit": "100G",
    "environment": {
      "OMP_NUM_THREADS": "8",
      "MALLOC_ARENA_MAX": "2"
    }
  }
}
```

### Minimal Secure Environment
```json
{
  "tool": "create_sandbox",
  "parameters": {
    "image": "alpine:3.18",
    "cpu_limit": "0.5",
    "memory_limit": "256M",
    "disk_limit": "1G",
    "network_mode": "none"
  }
}
```

## Error Codes

| Code | Description | Solution |
|------|-------------|----------|
| `IMAGE_NOT_FOUND` | Container image not found | Check image name and availability |
| `INVALID_LIMITS` | Resource limits invalid | Verify limit format and values |
| `INSUFFICIENT_RESOURCES` | Not enough system resources | Reduce limits or free up resources |
| `NETWORK_CONFIGURATION_ERROR` | Network setup failed | Check network configuration |
| `CONTAINER_START_FAILED` | Container failed to start | Check image compatibility |

## Best Practices

### Security
- Use `network_mode: "none"` by default
- Set reasonable resource limits
- Use minimal base images (Alpine Linux)
- Avoid running as root when possible

### Performance
- Choose appropriate resource limits
- Use specific image tags (avoid `latest`)
- Consider image size and startup time
- Pre-pull frequently used images

### Resource Management
```json
{
  "cpu_limit": "2.0",    // Match to workload requirements
  "memory_limit": "1G",  // Allow headroom for language runtimes
  "disk_limit": "5G"     // Account for dependencies and temporary files
}
```

### Environment Configuration
```json
{
  "environment": {
    "TZ": "UTC",                    // Set consistent timezone
    "LANG": "C.UTF-8",             // Set locale
    "TMPDIR": "/tmp",              // Temporary directory
    "HOME": "/workspace"           // User home directory
  }
}
```

## Related Tools

- [`list_sandboxes`](./list_sandboxes.md) - List all sandbox environments
- [`terminate_sandbox`](./terminate_sandbox.md) - Terminate sandbox environments
- [`run_code`](./run_code.md) - Execute code in sandbox
- [`exec_command`](./exec_command.md) - Execute shell commands

## Troubleshooting

### Image Pull Issues
```bash
# Verify image exists
docker pull ubuntu:22.04

# Check registry access
docker info
```

### Resource Limit Issues
- Verify system has sufficient resources
- Check for other running containers
- Consider reducing limits for testing

### Network Issues
- Test network connectivity: `ping google.com`
- Check firewall rules
- Verify bridge network configuration

### Container Startup Issues
- Check container logs
- Verify image architecture matches host
- Test image manually: `docker run -it <image> /bin/bash`