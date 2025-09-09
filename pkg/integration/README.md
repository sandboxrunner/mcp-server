# SandboxRunner Integration Testing Framework

This package provides a comprehensive integration testing framework for SandboxRunner Phase 5.1.2, designed to test the complete system under realistic conditions including multi-container orchestration, failure scenarios, and security boundaries.

## Framework Components

### Core Framework (`framework.go`)
- **TestFramework**: Main orchestration class providing complete test infrastructure
- **TestEnvironment**: Configurable test environment settings
- **ResourceMonitor**: Real-time resource usage monitoring and alerting
- **TestDataGenerator**: Utilities for generating test data and code samples
- **IntegrationAsserts**: Specialized assertion helpers for integration scenarios

### Test Categories

#### 1. Multi-Container Orchestration (`container_tests.go`)
- **Concurrent Container Creation**: Tests creating multiple containers simultaneously
- **Cross-Container Communication**: Validates container isolation and communication patterns
- **Load Balancing**: Tests distributing work across multiple containers
- **Resource Isolation**: Verifies containers respect individual resource limits
- **Performance Testing**: Measures container startup times, high concurrency (100+ containers)
- **Scaling Behavior**: Tests scale-up and scale-down scenarios

#### 2. End-to-End User Journeys (`e2e_tests.go`)
- **Data Science Workflow**: Complete ML pipeline with data upload, analysis, and results
- **Web Development Workflow**: Full-stack development with package management and testing
- **Machine Learning Training**: Model training, validation, and artifact management
- **Cross-Language Development**: Multi-language projects with shared resources
- **CI/CD Pipeline Simulation**: Automated build, test, and deployment workflows

#### 3. Failure Injection & Chaos Testing (`failure_tests.go`)
- **FailureInjector**: Systematic failure injection system supporting multiple failure types:
  - CPU stress testing
  - Memory pressure simulation
  - Disk I/O stress
  - Process termination
  - Resource limit enforcement
- **Chaos Engineering**: Implementation of chaos monkey patterns
- **Recovery Testing**: Validates system recovery from failures
- **Concurrent Failure Handling**: Tests behavior under multiple simultaneous failures

#### 4. Security Boundary Testing (`security_tests.go`)
- **Container Isolation**: Verifies complete isolation between containers
- **Filesystem Isolation**: Tests file system boundaries and access controls
- **Network Isolation**: Validates network security and isolation
- **Process Isolation**: Tests process namespace isolation
- **Resource Limit Enforcement**: Verifies resource limits are properly enforced
- **Privilege Escalation Prevention**: Tests against common attack vectors
- **Malicious Code Protection**: Tests against fork bombs, memory exhaustion, infinite loops
- **Data Leakage Prevention**: Validates data cannot leak between containers

## Usage Examples

### Basic Integration Test
```go
func TestMyIntegration(t *testing.T) {
    framework := SetupTestFramework(t, DefaultTestEnvironment())
    defer framework.Cleanup(t)
    
    ctx := context.Background()
    container := framework.CreateTestSandbox(ctx, t, nil)
    framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
    
    // Your test logic here
}
```

### Custom Environment Configuration
```go
func TestWithCustomConfig(t *testing.T) {
    env := DefaultTestEnvironment()
    env.MaxConcurrentSandboxes = 50
    env.DefaultTimeout = 60 * time.Second
    env.ResourceLimits = sandbox.ResourceLimits{
        CPULimit:    "2.0",
        MemoryLimit: "1G",
        DiskLimit:   "2G",
    }
    
    framework := SetupTestFramework(t, env)
    defer framework.Cleanup(t)
    
    // Your test logic here
}
```

### Failure Injection Testing
```go
func TestWithFailureInjection(t *testing.T) {
    framework := SetupTestFramework(t, DefaultTestEnvironment())
    injector := NewFailureInjector(framework)
    defer injector.StopAllFailures()
    
    ctx := context.Background()
    container := framework.CreateTestSandbox(ctx, t, nil)
    
    // Inject CPU stress for 30 seconds
    err := injector.InjectFailure(ctx, FailureTypeCPUStress, container.ID, 30*time.Second)
    require.NoError(t, err)
    
    // Test system behavior under stress
}
```

### Resource Monitoring
```go
func TestWithResourceMonitoring(t *testing.T) {
    framework := SetupTestFramework(t, DefaultTestEnvironment())
    
    // Take baseline snapshot
    baseline := framework.ResourceMonitor.TakeSnapshot()
    
    // Perform operations
    // ...
    
    // Compare resource usage
    final := framework.ResourceMonitor.TakeSnapshot()
    delta := framework.ResourceMonitor.CompareSnapshots(baseline, final)
    
    assert.Less(t, delta.Delta.MemoryUsedMB, 100.0, "Memory usage should be bounded")
}
```

## Running Integration Tests

### Individual Test Categories
```bash
# Run container orchestration tests
go test -v ./pkg/integration -run TestMultiContainerOrchestration

# Run end-to-end workflow tests  
go test -v ./pkg/integration -run TestEndToEndUserJourneys

# Run failure injection tests
go test -v ./pkg/integration -run TestFailureInjectionAndRecovery

# Run security boundary tests
go test -v ./pkg/integration -run TestSecurityBoundaries
```

### Complete Integration Test Suite
```bash
# Run the complete suite
go test -v ./pkg/integration -run TestIntegration

# Run with extended timeout for long-running tests
go test -v ./pkg/integration -run TestIntegration -timeout 30m

# Quick smoke test
go test -v ./pkg/integration -run TestQuickIntegration
```

### Performance Benchmarks
```bash
# Benchmark sandbox creation performance
go test -bench=BenchmarkSandboxCreation ./pkg/integration

# Benchmark concurrent sandbox handling
go test -bench=BenchmarkConcurrentSandboxes ./pkg/integration
```

## Configuration Options

### TestEnvironment Settings
- `MaxConcurrentSandboxes`: Maximum number of simultaneous sandboxes (default: 10)
- `DefaultTimeout`: Default timeout for operations (default: 30s)
- `ResourceLimits`: Default resource limits for test containers
- `EnableLogging`: Enable detailed logging (default: true)
- `LogLevel`: Logging level (default: "info")
- `EnableMetrics`: Enable resource monitoring (default: true)
- `CleanupOnFailure`: Clean up resources when tests fail (default: true)

### Framework Features
- **Automatic Cleanup**: All resources are automatically cleaned up after tests
- **Parallel Execution**: Tests can run in parallel where appropriate
- **Resource Monitoring**: Real-time monitoring of CPU, memory, and disk usage
- **Failure Recovery**: Automatic recovery from transient failures
- **CI/CD Integration**: Designed to run in continuous integration environments

## Performance Targets

The integration testing framework validates the following performance characteristics:

### Container Operations
- Container startup time: <500ms average
- Concurrent container creation: 100+ containers
- Container termination: <2s for graceful shutdown
- Resource cleanup: <5s after container termination

### System Resilience
- Recovery from single container failure: <10s
- System stability during chaos testing: >95% uptime
- Memory leak detection: <10MB growth per 1000 operations
- Resource limit enforcement: 100% compliance

### Security Validation
- Container isolation: 100% verified isolation
- Privilege escalation: 0 successful attempts
- Data leakage: 0 cross-container data access
- Resource exhaustion: Proper containment of malicious code

## CI/CD Integration

### Environment Variables
- `INTEGRATION_TEST_TIMEOUT`: Override default test timeout
- `MAX_CONCURRENT_SANDBOXES`: Override concurrent sandbox limit
- `SKIP_LONG_RUNNING_TESTS`: Skip tests that take >5 minutes
- `ENABLE_CHAOS_TESTING`: Enable/disable chaos engineering tests

### Docker Integration
```dockerfile
# Example Dockerfile for CI integration testing
FROM golang:1.24-alpine
RUN apk add --no-cache docker-cli
WORKDIR /app
COPY . .
RUN go test -v ./pkg/integration -timeout 30m
```

### GitHub Actions Example
```yaml
name: Integration Tests
on: [push, pull_request]
jobs:
  integration:
    runs-on: ubuntu-latest
    services:
      docker:
        image: docker:dind
        options: --privileged
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
        with:
          go-version: 1.24
      - name: Run Integration Tests
        run: go test -v ./pkg/integration -timeout 30m
        env:
          MAX_CONCURRENT_SANDBOXES: 20
          SKIP_LONG_RUNNING_TESTS: true
```

## Troubleshooting

### Common Issues

1. **Resource Exhaustion**
   - Reduce `MaxConcurrentSandboxes` in test environment
   - Increase system memory/CPU allocation
   - Enable resource monitoring to identify bottlenecks

2. **Test Timeouts**
   - Increase `DefaultTimeout` in test environment
   - Use `-timeout` flag when running go test
   - Check for container startup delays

3. **Container Creation Failures**
   - Verify Docker/container runtime is running
   - Check container image availability
   - Validate filesystem permissions

4. **Security Test Failures**
   - Ensure container runtime supports security features
   - Verify proper container isolation configuration
   - Check for privileged container execution

### Debug Mode
```bash
# Run with verbose logging
INTEGRATION_LOG_LEVEL=debug go test -v ./pkg/integration

# Run with resource monitoring
ENABLE_RESOURCE_MONITORING=true go test -v ./pkg/integration

# Run single test with full output
go test -v ./pkg/integration -run TestSpecificFunction -timeout 10m
```

## Contributing

When adding new integration tests:

1. Follow the existing test patterns and naming conventions
2. Use the provided framework utilities (TestFramework, ResourceMonitor, etc.)
3. Include proper cleanup using `defer framework.Cleanup(t)`
4. Add appropriate assertions using IntegrationAsserts helpers
5. Document any new failure types or test scenarios
6. Consider performance implications and resource usage
7. Add both positive and negative test cases

### Test Structure Template
```go
func TestNewIntegrationScenario(t *testing.T) {
    framework := SetupTestFramework(t, DefaultTestEnvironment())
    asserts := NewIntegrationAsserts(t)
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    defer cancel()
    
    t.Run("SpecificTestCase", func(t *testing.T) {
        // Setup
        container := framework.CreateTestSandbox(ctx, t, nil)
        framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)
        
        // Execute test logic
        // ...
        
        // Assertions
        asserts.AssertSandboxExists(framework.SandboxManager, container.ID, sandbox.SandboxStatusRunning)
        
        // Cleanup is automatic via framework.Cleanup()
    })
}
```

This integration testing framework provides comprehensive coverage of SandboxRunner's functionality, ensuring reliability, security, and performance under realistic operating conditions.