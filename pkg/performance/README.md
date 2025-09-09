# Performance Testing Package

This package provides comprehensive performance testing and benchmarking capabilities for SandboxRunner, implementing the requirements from Phase 5.1.3 of the development roadmap.

## Overview

The performance testing suite validates that SandboxRunner meets the following targets:

- **Container startup**: < 500ms
- **Command execution**: < 100ms overhead
- **Memory usage**: < 50MB per sandbox
- **Concurrent sandboxes**: 100+
- **API response time**: < 200ms p99

## Package Structure

```
pkg/performance/
├── README.md              # This file
├── benchmark_test.go      # Core performance benchmarks
├── load_test.go          # Load testing and concurrency tests
├── memory_test.go        # Memory usage and leak testing
├── profiling_test.go     # CPU/memory profiling integration
├── config.go            # Configuration management
└── helpers.go           # Test utilities and helpers
```

## Test Categories

### 1. Benchmarks (`benchmark_test.go`)

Performance benchmarks using Go's built-in benchmarking framework:

- **Container Lifecycle**: Creation, startup, and termination performance
- **Tool Execution**: MCP tool execution overhead and throughput
- **Language Execution**: Language-specific code execution performance
- **File Operations**: File I/O performance across different data sizes
- **Concurrent Operations**: Performance under concurrent load
- **API Response Times**: End-to-end API response time measurements

### 2. Load Tests (`load_test.go`)

Sustained load and stress testing scenarios:

- **Sustained High Load**: Long-running high concurrency tests
- **Burst Traffic**: Spike traffic pattern handling
- **Memory Pressure**: System behavior under memory constraints
- **Resource Exhaustion**: Recovery from resource limits
- **Long-Running Operations**: System stability over time

### 3. Memory Tests (`memory_test.go`)

Memory usage analysis and leak detection:

- **Memory Usage per Sandbox**: Validate memory footprint targets
- **Memory Leak Detection**: Detect memory leaks during operations
- **Goroutine Leak Detection**: Monitor goroutine lifecycle
- **Concurrent Memory Usage**: Memory behavior under concurrency
- **Large Data Handling**: Memory efficiency with large payloads

### 4. Profiling Tests (`profiling_test.go`)

Performance profiling integration:

- **CPU Profiling**: CPU usage patterns and hotspots
- **Memory Profiling**: Memory allocation patterns
- **Concurrency Profiling**: Goroutine and blocking analysis
- **Benchmark Profiling**: Profile generation during benchmarks

## Configuration

Performance tests are configured via YAML configuration files. See `config/performance.yaml` for a complete example.

### Key Configuration Sections

```yaml
# Performance targets
targets:
  container_startup_ms: 500
  command_overhead_ms: 100
  memory_per_sandbox_mb: 50.0
  max_concurrent_sandboxes: 100
  api_response_p99_ms: 200

# Benchmark settings
benchmarks:
  enabled: true
  iterations: 100
  test_container_lifecycle: true
  test_tool_execution: true

# Load test settings
load_tests:
  enabled: true
  sustained_duration: 2m
  sustained_concurrency: 50

# Memory test settings
memory:
  enabled: true
  leak_detection: true
  profile_interval: 500ms
```

## Running Tests

### Using Make Targets

```bash
# Run all performance benchmarks
make perf-bench

# Run quick benchmarks (CI-friendly)
make perf-bench-quick

# Run specific benchmark categories
make perf-bench-container    # Container lifecycle
make perf-bench-tools        # Tool execution
make perf-bench-language     # Language execution
make perf-bench-memory       # Memory efficiency
make perf-bench-concurrent   # Concurrent operations

# Run load tests
make perf-load               # Sustained load tests
make perf-load-burst         # Burst traffic tests
make perf-load-memory        # Memory pressure tests
make perf-load-recovery      # Resource exhaustion tests
make perf-load-longrunning   # Long-running operations

# Run memory tests
make perf-memory             # Memory usage tests
make perf-memory-leak        # Memory leak detection
make perf-memory-goroutine   # Goroutine leak detection
make perf-memory-concurrent  # Concurrent memory tests
make perf-memory-large       # Large data handling

# Run profiling tests
make perf-profile-cpu        # CPU profiling
make perf-profile-memory     # Memory profiling
make perf-profile-concurrency # Concurrency profiling
make perf-profile-benchmark  # Benchmark profiling

# Run comprehensive test suite
make perf-all               # All performance tests (2-3 hours)
make perf-validation        # Quick validation (CI-friendly)
make perf-regression        # Regression tests against targets

# Configuration management
make perf-config            # Generate performance config
make perf-config-validate   # Validate config file
make perf-clean             # Clean artifacts
```

### Using Go Test Directly

```bash
# Run all performance benchmarks
go test -bench=. -benchmem -timeout 30m ./pkg/performance

# Run specific benchmarks
go test -bench=BenchmarkContainerLifecycle -benchmem ./pkg/performance
go test -bench=BenchmarkToolExecution -benchmem ./pkg/performance

# Run load tests
go test -v -timeout 60m ./pkg/performance -run TestSustainedHighLoad
go test -v -timeout 30m ./pkg/performance -run TestBurstTrafficPatterns

# Run memory tests
go test -v -timeout 30m ./pkg/performance -run TestSandboxMemoryUsage
go test -v -timeout 60m ./pkg/performance -run TestMemoryLeakDetection

# Run profiling tests
go test -v -timeout 30m ./pkg/performance -run TestCPUProfiling

# Run with custom configuration
PERF_CONFIG_FILE=./config/performance.yaml go test -v ./pkg/performance
```

### Test Flags and Environment Variables

- `testing.Short()`: Skip long-running tests when `-short` flag is used
- `CI=true`: Automatically detected CI environments with adapted timeouts
- `PERF_CONFIG_FILE`: Path to custom performance configuration file
- `PERF_OUTPUT_DIR`: Override output directory for test artifacts

## Output and Artifacts

### Benchmark Results

Benchmarks generate detailed performance metrics:

```
BenchmarkContainerLifecycle-8         100    5234567 ns/op     startup_ms:523.46
BenchmarkToolExecution/exec_command-8  1000   1234567 ns/op    execution_ms:123.46
BenchmarkAPIResponseTime/list_sandboxes-8  500  567890 ns/op  p99_ms:156.78
```

### Load Test Results

Load tests provide comprehensive metrics:

```
Load Test Results for high_load:
  total_requests: 10000
  successful_ops: 9850
  failed_ops: 150
  error_rate_percent: 1.50
  avg_response_time: 45ms
  p99_response_time: 187ms
  throughput_rps: 166.67
```

### Memory Test Results

Memory tests track usage patterns and detect leaks:

```
Memory usage:
  Initial: 12.34 MB
  Final: 45.67 MB
  Used: 33.33 MB
  Per sandbox: 1.67 MB
  Goroutines: 15 -> 23

Memory leak analysis:
  measurements: 120
  duration_seconds: 60.5
  memory_leak: false
  growth_rate_bytes: 512.34
```

### Profile Data

Profiling tests generate pprof-compatible profile files:

```
build/profiles/
├── cpu.prof         # CPU profiling data
├── mem.prof         # Memory profiling data  
├── block.prof       # Blocking profiling data
├── mutex.prof       # Mutex profiling data
├── goroutine.prof   # Goroutine profiling data
└── trace.out        # Execution trace data
```

## Analyzing Results

### Using pprof

```bash
# Analyze CPU profile
go tool pprof build/profiles/cpu.prof
(pprof) top10
(pprof) web
(pprof) list functionName

# Analyze memory profile
go tool pprof build/profiles/mem.prof
(pprof) top10 -cum
(pprof) png > memory_profile.png

# Analyze execution trace
go tool trace build/profiles/trace.out
```

### Performance Assertions

Tests automatically validate against configured targets:

```go
// Container startup time validation
if duration > 500*time.Millisecond {
    t.Errorf("Container startup took %v, target is < 500ms", duration)
}

// Memory usage validation
if memoryMB > 50.0 {
    t.Errorf("Memory usage %.2f MB exceeds target 50 MB", memoryMB)
}

// API response time validation (P99)
if p99 > 200*time.Millisecond {
    t.Errorf("P99 response time %v exceeds target 200ms", p99)
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Performance Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  performance:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Go
      uses: actions/setup-go@v3
      with:
        go-version: 1.21
    
    - name: Install Dependencies
      run: make deps
    
    - name: Run Performance Validation
      run: make perf-validation
      
    - name: Run Performance Regression Tests
      run: make perf-regression
      
    - name: Upload Performance Results
      uses: actions/upload-artifact@v3
      with:
        name: performance-results
        path: build/perf-reports/
```

### Performance Regression Detection

The test suite includes regression detection:

```bash
# Compare current performance against baseline
make perf-regression

# Generate performance baseline
make perf-bench > baseline_results.txt

# Compare against baseline in CI
make perf-bench | diff baseline_results.txt -
```

## Best Practices

### Test Design

1. **Isolation**: Each test should be independent and clean up after itself
2. **Repeatability**: Tests should produce consistent results across runs
3. **Realistic Workloads**: Use scenarios that mirror production usage
4. **Baseline Measurements**: Establish performance baselines for comparison
5. **Resource Cleanup**: Always clean up test resources to prevent interference

### Configuration Management

1. **Environment-Specific**: Use different configs for dev/CI/production
2. **Version Control**: Track configuration changes alongside code
3. **Documentation**: Document performance requirements and targets
4. **Validation**: Validate configuration files before running tests

### Continuous Monitoring

1. **Regular Execution**: Run performance tests on every significant change
2. **Trend Analysis**: Track performance metrics over time
3. **Alerting**: Set up alerts for performance regressions
4. **Baseline Updates**: Update baselines when architectural changes occur

## Troubleshooting

### Common Issues

**Tests Taking Too Long**
- Use `-short` flag for quick validation
- Reduce iteration counts in configuration
- Run specific test categories instead of full suite

**Memory Leak False Positives**
- Increase GC frequency in tests
- Allow for reasonable memory growth patterns
- Consider background operations in analysis

**Inconsistent Results**
- Ensure adequate warmup periods
- Account for system load variations
- Use multiple iterations and statistical analysis

**Resource Exhaustion**
- Monitor system resources during tests
- Adjust concurrency levels for test environment
- Implement proper cleanup and resource limits

### Debugging Performance Issues

1. **Enable Profiling**: Use profiling tests to identify bottlenecks
2. **Trace Analysis**: Use execution tracing for detailed analysis
3. **Metric Collection**: Collect detailed metrics during test runs
4. **Incremental Testing**: Test individual components in isolation
5. **Environment Analysis**: Consider system resources and constraints

## Contributing

When adding new performance tests:

1. Follow existing patterns and naming conventions
2. Include comprehensive documentation and comments
3. Add appropriate configuration options
4. Implement proper cleanup and error handling
5. Update this README with new test descriptions

### Adding New Benchmarks

```go
func BenchmarkNewFeature(b *testing.B) {
    config := setupBenchmark(b)
    manager := createTestManager(b, config)
    defer manager.Stop()
    
    b.ResetTimer()
    
    for i := 0; i < b.N; i++ {
        // Your benchmark code here
        start := time.Now()
        result, err := performOperation()
        duration := time.Since(start)
        
        if err != nil {
            b.Errorf("Operation failed: %v", err)
        }
        
        // Report custom metrics
        b.ReportMetric(float64(duration.Nanoseconds())/1e6, "operation_ms")
    }
}
```

### Adding New Load Tests

```go
func TestNewLoadScenario(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping load test in short mode")
    }
    
    config := setupBenchmark(&testing.B{})
    manager := createTestManager(&testing.B{}, config)
    defer manager.Stop()
    
    // Implement load test logic
    metrics := &LoadTestMetrics{}
    // ... test implementation
    
    // Validate results
    stats := metrics.GetStats()
    // ... assertions
}
```

## License

This performance testing package is part of the SandboxRunner project and follows the same licensing terms.