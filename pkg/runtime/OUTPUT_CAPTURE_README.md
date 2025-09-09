# Process Output Capture System

This document describes the comprehensive process output capture system implemented in `pkg/runtime/process.go`.

## Overview

The output capture system provides robust, scalable, and feature-rich process output management with advanced capabilities including:

- **Ring Buffer Management**: Fixed-size circular buffers with overflow handling
- **Concurrent Capture**: Goroutine-based concurrent stdout/stderr capture
- **Stream Processing**: Real-time streaming with configurable flush intervals
- **Compression**: Automatic gzip compression for large outputs
- **ANSI Processing**: Optional ANSI escape code removal
- **Resource Management**: Proper cleanup and resource management
- **Performance Metrics**: Detailed capture statistics and timing

## Core Components

### ProcessOutput Structure

```go
type ProcessOutput struct {
    // Output data
    Stdout   []byte        `json:"stdout,omitempty"`
    Stderr   []byte        `json:"stderr,omitempty"`
    ExitCode int32         `json:"exitCode"`
    Duration time.Duration `json:"duration"`

    // Metadata
    StdoutSize     int64     `json:"stdoutSize"`
    StderrSize     int64     `json:"stderrSize"`
    Truncated      bool      `json:"truncated"`
    Compressed     bool      `json:"compressed"`
    CaptureStarted time.Time `json:"captureStarted"`
    CaptureEnded   time.Time `json:"captureEnded"`

    // Streaming support
    Streaming     bool   `json:"streaming"`
    StreamChannel string `json:"streamChannel,omitempty"`
}
```

### RingBuffer Implementation

High-performance ring buffer with:
- Thread-safe concurrent access
- Wraparound behavior for fixed memory usage
- Atomic counters for total writes tracking
- Zero-allocation reads when possible

### OutputCapture Manager

Advanced output capture with:
- Configurable buffer sizes (default: 10MB)
- Optional streaming mode with channels
- Compression threshold configuration
- ANSI code processing
- Context-aware cancellation

## Configuration

### OutputCaptureConfig

```go
type OutputCaptureConfig struct {
    MaxBufferSize        int64         // Buffer size limit (default: 10MB)
    StreamingEnabled     bool          // Enable real-time streaming
    FlushInterval        time.Duration // Streaming flush interval
    CompressionEnabled   bool          // Enable compression
    CompressionThreshold int64         // Compression trigger size
    ProcessANSI          bool          // Strip ANSI codes
}
```

### Default Configuration

```go
config := DefaultOutputCaptureConfig()
// Returns:
// MaxBufferSize: 10MB
// StreamingEnabled: false
// FlushInterval: 100ms
// CompressionEnabled: true
// CompressionThreshold: 1MB
// ProcessANSI: true
```

## Usage Examples

### Basic Output Capture

```go
config := DefaultOutputCaptureConfig()
capture := NewOutputCapture(config)
defer capture.Close()

// Create output streams
stdoutReader, stdoutWriter := io.Pipe()
stderrReader, stderrWriter := io.Pipe()

// Start capture
ctx := context.Background()
capture.CaptureStreams(ctx, stdoutReader, stderrReader)

// Write data to streams
// ... process execution ...

// Get results
capture.Wait()
output := capture.GetOutput()

fmt.Printf("Captured %d bytes stdout, %d bytes stderr\n",
    output.StdoutSize, output.StderrSize)
fmt.Printf("Duration: %v, Truncated: %v\n",
    output.Duration, output.Truncated)
```

### Streaming Mode

```go
config := DefaultOutputCaptureConfig()
config.StreamingEnabled = true
config.FlushInterval = 50 * time.Millisecond

capture := NewOutputCapture(config)
defer capture.Close()

// Start capture
capture.CaptureStreams(ctx, stdoutReader, stderrReader)

// Consume streaming output
stdoutChan := capture.GetStdoutChannel()
go func() {
    for chunk := range stdoutChan {
        fmt.Printf("Stream: %s", chunk)
    }
}()
```

### Integration with ExecProcess

The system is integrated into the existing `ExecProcess` method:

```go
// Enhanced with advanced output capture
result, err := client.ExecProcess(ctx, containerID, processSpec)
if err != nil {
    return err
}

// Access enhanced output information
fmt.Printf("Process completed in %v\n", result.Output.Duration)
fmt.Printf("Output truncated: %v\n", result.Output.Truncated)
fmt.Printf("Output compressed: %v\n", result.Output.Compressed)

// Decompress if needed
stdout, err := result.GetStdout()
stderr, err := result.GetStderr()
```

## Performance Characteristics

### Benchmark Results

- **RingBuffer Write**: ~3,300 ns/op, 0 allocations
- **RingBuffer Read**: ~186,000 ns/op, 1 allocation
- **Output Capture**: ~1.3ms/op for small outputs
- **Concurrent Access**: Safe with minimal contention

### Memory Management

- Fixed-size buffers prevent unbounded memory growth
- Ring buffer overwrites old data when full
- Compression reduces memory usage for large outputs
- Streaming mode allows real-time processing without buffering

### Scalability Features

- Configurable buffer sizes based on requirements
- Optional compression for large outputs
- Context cancellation for proper cleanup
- Concurrent safe for multiple processes

## Error Handling

- Graceful handling of stream read errors
- Context cancellation support
- Resource cleanup on errors
- Timeout handling for long-running captures

## Thread Safety

- All operations are thread-safe
- Atomic counters for statistics
- Proper mutex protection for shared state
- Channel-based communication for streaming

## Testing

The implementation includes comprehensive tests:

- **Unit Tests**: >80% coverage of core functionality
- **Integration Tests**: Real process execution scenarios  
- **Concurrency Tests**: Multi-threaded access patterns
- **Performance Benchmarks**: Throughput and memory usage
- **Edge Cases**: Error conditions, resource exhaustion

### Running Tests

```bash
# Run all output capture tests
go test ./pkg/runtime/ -run="TestOutput|TestRingBuffer"

# Run benchmarks
go test ./pkg/runtime/ -bench=BenchmarkOutputCapture

# Generate coverage report
go test ./pkg/runtime/ -cover -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Future Enhancements

Potential improvements for future versions:

1. **Structured Logging**: JSON/structured output parsing
2. **Output Filtering**: Pattern-based filtering
3. **Metrics Export**: Prometheus metrics integration
4. **Persistence**: Optional output persistence to disk
5. **Rate Limiting**: Bandwidth limiting for streaming
6. **Encryption**: Optional output encryption for sensitive data

## Migration from Legacy System

The new system maintains backward compatibility:

- Legacy `ProcessResult` fields still available
- Existing code continues to work unchanged
- New features accessed via `result.Output` field
- Progressive migration path available

## Best Practices

1. **Configure Buffer Sizes**: Set appropriate limits for your use case
2. **Enable Streaming**: For long-running processes with real-time output needs
3. **Use Compression**: For processes with large output volumes
4. **Handle Context Cancellation**: Always use context for proper cleanup
5. **Monitor Truncation**: Check `Truncated` flag for buffer overflows
6. **Resource Cleanup**: Always call `Close()` on OutputCapture instances

This implementation provides a robust, scalable foundation for process output capture that can handle diverse requirements from simple command execution to complex streaming scenarios.