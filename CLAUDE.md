# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SandboxRunner is a multi-language MCP (Model Context Protocol) server that provides isolated sandbox environments for executing code in multiple programming languages. It's designed for AI assistants and developers who need secure, containerized code execution with runc/OCI containers.

## Development Commands

### Build and Test
- `make build` - Build the main binary (output: `build/bin/mcp-sandboxd`)
- `make test` - Run all tests with race detection and coverage
- `make test-coverage` - Generate HTML coverage report
- `make lint` - Run golangci-lint (requires: `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`)
- `make fmt` - Format all Go code
- `make vet` - Run go vet static analysis

### Running the Server
- `make run` - Build and run server with default config
- `make run-config` - Run server with `config/mcp-sandboxd.yaml`
- `make dev` - Development server with live reload (requires: `go install github.com/cosmtrek/air@latest`)

### Configuration
- `make config` - Generate default config at `config/mcp-sandboxd.yaml`
- `make validate-config` - Validate existing configuration file
- `make init` - Initialize project (deps + config generation)

### Single Test Execution
- `go test -v ./pkg/sandbox/` - Run tests for specific package
- `go test -run TestFunctionName ./pkg/sandbox/` - Run specific test function

## Architecture Overview

The codebase follows a layered architecture organized into several key packages:

### Core Components

**MCP Server (`pkg/mcp/`)**: Implements the Model Context Protocol for communication with AI clients. Handles JSON-RPC messaging over stdio or HTTP/WebSocket. Manages client capabilities negotiation and tool execution routing.

**Sandbox Management (`pkg/sandbox/`)**: Core sandbox lifecycle management including creation, state tracking, resource allocation, and cleanup. Uses a state machine pattern for sandbox transitions and includes health checking and recovery mechanisms.

**Runtime Layer (`pkg/runtime/`)**: Low-level container execution using runc/OCI containers. Handles process management, filesystem operations, network isolation, security policies (seccomp, capabilities), and resource monitoring (CPU, memory, disk).

**Language Support (`pkg/languages/`)**: Multi-language execution handlers for Python, JavaScript/TypeScript, Go, Rust, Java, C++, C#, and Shell. Each language has specialized compilation, dependency management, and execution logic. Includes package managers (pip, npm, cargo, maven) and build systems.

**Tool Registry (`pkg/tools/`)**: Implements MCP tools for sandbox operations (create, list, terminate), code execution, and file management. Tools are registered dynamically based on configuration and provide the interface between MCP requests and sandbox operations.

**Storage (`pkg/storage/`)**: SQLite-based persistence for sandbox metadata, state tracking, and metrics collection. Handles database migrations and provides query interfaces for sandbox management.

### Supporting Infrastructure

**Configuration (`pkg/config/`)**: YAML-based configuration management with validation, defaults, and environment variable override support.

**Security (`pkg/runtime/security/`)**: Container security policies, audit logging, MAC (Mandatory Access Control) support, and compliance checking.

**Monitoring (`pkg/monitoring/`)**: Metrics collection, health checks, distributed tracing with OpenTelemetry, and performance monitoring.

**Resilience (`pkg/resilience/`)**: Circuit breaker patterns, retry logic, timeout management, and graceful degradation for high availability.

## Key Design Patterns

- **Registry Pattern**: Tools and language handlers are registered dynamically
- **State Machine**: Sandboxes follow strict state transitions (creating → ready → running → terminated)
- **Resource Pooling**: Efficient sandbox reuse and resource management
- **Event-Driven**: Async event processing for sandbox lifecycle and monitoring
- **Factory Pattern**: Language-specific executors and compilers
- **Command Pattern**: All operations are encapsulated as tools/commands

## Configuration

Server configuration is in `config/mcp-sandboxd.yaml` with sections for:
- Server settings (protocol: stdio/http, ports, timeouts)
- Sandbox defaults (images, resource limits, network mode)
- Enabled tools list and validation levels
- Logging configuration (level, format, rotation)
- Resource limits (file sizes, temp directories)

## Database and Storage

Uses SQLite for persistence with the following schema:
- Sandboxes table: metadata, state, resources, timestamps
- Files table: workspace file tracking and metadata
- Metrics table: performance and usage statistics

Database path configurable via `sandbox.database_path` in config.

## Container Runtime Integration

Integrates with runc (OCI runtime) for container management:
- Creates isolated namespaces (PID, mount, network, IPC, UTS)
- Applies security profiles (seccomp, capabilities, cgroups)
- Manages container lifecycle through runc CLI interface
- Supports multiple base images per language
- Network isolation configurable (none/bridge/host)

The system is designed for secure multi-tenant code execution with comprehensive resource monitoring and isolation.