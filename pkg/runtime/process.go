package runtime

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/rs/zerolog/log"
)

// ProcessSpec holds configuration for process execution
type ProcessSpec struct {
	// Cmd is the command to execute (first argument)
	Cmd string `json:"cmd"`
	// Args are the command arguments (including the command itself)
	Args []string `json:"args"`
	// Env are the environment variables in key=value format
	Env []string `json:"env"`
	// WorkingDir is the working directory for the process
	WorkingDir string `json:"workingDir"`
	// User specifies the user to run the process as
	User string `json:"user"`
	// Terminal specifies if a terminal should be allocated
	Terminal bool `json:"terminal"`
	// Timeout specifies the maximum execution time
	Timeout time.Duration `json:"timeout"`
}

// Process represents a running process in a container
type Process struct {
	// ID is the unique process identifier
	ID string `json:"id"`
	// PID is the process ID from the system
	PID int32 `json:"pid"`
	// Status represents the current status of the process
	Status string `json:"status"`
	// StartTime is when the process was started
	StartTime time.Time `json:"startTime"`
	// ExitCode is the exit code of the process (if finished)
	ExitCode *int32 `json:"exitCode,omitempty"`
	// ContainerID is the ID of the container the process is running in
	ContainerID string `json:"containerId"`
}

// ProcessOutput holds comprehensive process output information
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

// ProcessResult holds the result of a process execution
type ProcessResult struct {
	Process *Process      `json:"process"`
	Output  ProcessOutput `json:"output"`
	Error   error         `json:"error,omitempty"`

	// Legacy compatibility
	ExitCode int32  `json:"exitCode"`
	Stdout   []byte `json:"stdout,omitempty"`
	Stderr   []byte `json:"stderr,omitempty"`
}

// NewProcessResult creates a ProcessResult with legacy compatibility
func NewProcessResult(process *Process, output ProcessOutput, err error) *ProcessResult {
	return &ProcessResult{
		Process:  process,
		Output:   output,
		Error:    err,
		// Legacy compatibility
		ExitCode: output.ExitCode,
		Stdout:   output.Stdout,
		Stderr:   output.Stderr,
	}
}

// GetStdout returns stdout data, decompressing if needed
func (pr *ProcessResult) GetStdout() ([]byte, error) {
	if !pr.Output.Compressed {
		return pr.Output.Stdout, nil
	}
	return pr.decompressData(pr.Output.Stdout)
}

// GetStderr returns stderr data, decompressing if needed
func (pr *ProcessResult) GetStderr() ([]byte, error) {
	if !pr.Output.Compressed {
		return pr.Output.Stderr, nil
	}
	return pr.decompressData(pr.Output.Stderr)
}

// decompressData decompresses gzipped data
func (pr *ProcessResult) decompressData(data []byte) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	return io.ReadAll(gzr)
}

// ToOCIProcessSpec converts ProcessSpec to OCI Process specification
func (ps *ProcessSpec) ToOCIProcessSpec() *specs.Process {
	process := &specs.Process{
		Terminal: ps.Terminal,
		Args:     ps.Args,
		Env:      ps.Env,
		Cwd:      ps.WorkingDir,
		User:     parseUser(ps.User),
	}

	// Set default working directory if not specified
	if process.Cwd == "" {
		process.Cwd = "/"
	}

	// Ensure Args includes the command if not already present
	if len(process.Args) == 0 && ps.Cmd != "" {
		process.Args = []string{ps.Cmd}
	} else if len(process.Args) > 0 && ps.Cmd != "" && process.Args[0] != ps.Cmd {
		// Prepend the command if Args doesn't start with it
		process.Args = append([]string{ps.Cmd}, process.Args...)
	}

	return process
}

// parseUser parses a user specification string into OCI User format
// Supports formats: "username", "uid", "uid:gid", "username:groupname"
func parseUser(userSpec string) specs.User {
	user := specs.User{
		UID: 0,
		GID: 0,
	}

	if userSpec == "" {
		return user
	}

	// Handle uid:gid format
	if strings.Contains(userSpec, ":") {
		parts := strings.SplitN(userSpec, ":", 2)
		if uid, err := strconv.ParseUint(parts[0], 10, 32); err == nil {
			user.UID = uint32(uid)
		} else {
			user.Username = parts[0]
		}
		
		if len(parts) > 1 {
			if gid, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
				user.GID = uint32(gid)
			}
		}
	} else {
		// Handle single user specification
		if uid, err := strconv.ParseUint(userSpec, 10, 32); err == nil {
			user.UID = uint32(uid)
		} else {
			user.Username = userSpec
		}
	}

	return user
}

// NewProcessSpec creates a new ProcessSpec with default values
func NewProcessSpec(cmd string, args []string) *ProcessSpec {
	// Ensure args includes the command
	if len(args) == 0 || args[0] != cmd {
		args = append([]string{cmd}, args...)
	}

	return &ProcessSpec{
		Cmd:        cmd,
		Args:       args,
		Env:        []string{},
		WorkingDir: "/",
		User:       "0:0", // root by default
		Terminal:   false,
		Timeout:    30 * time.Second, // 30 second default timeout
	}
}

// WithEnv adds environment variables to the process spec
func (ps *ProcessSpec) WithEnv(env map[string]string) *ProcessSpec {
	for k, v := range env {
		ps.Env = append(ps.Env, k+"="+v)
	}
	return ps
}

// WithEnvSlice adds environment variables from a slice of key=value strings
func (ps *ProcessSpec) WithEnvSlice(env []string) *ProcessSpec {
	ps.Env = append(ps.Env, env...)
	return ps
}

// WithWorkingDir sets the working directory for the process
func (ps *ProcessSpec) WithWorkingDir(dir string) *ProcessSpec {
	ps.WorkingDir = dir
	return ps
}

// WithUser sets the user for the process
func (ps *ProcessSpec) WithUser(user string) *ProcessSpec {
	ps.User = user
	return ps
}

// WithTerminal enables or disables terminal allocation
func (ps *ProcessSpec) WithTerminal(terminal bool) *ProcessSpec {
	ps.Terminal = terminal
	return ps
}

// WithTimeout sets the execution timeout
func (ps *ProcessSpec) WithTimeout(timeout time.Duration) *ProcessSpec {
	ps.Timeout = timeout
	return ps
}

// OutputCaptureConfig holds configuration for output capture
type OutputCaptureConfig struct {
	// Buffer size limit in bytes (default: 10MB)
	MaxBufferSize int64
	// Enable streaming mode for real-time output
	StreamingEnabled bool
	// Flush interval for streaming
	FlushInterval time.Duration
	// Enable compression for large outputs
	CompressionEnabled bool
	// Compression threshold in bytes
	CompressionThreshold int64
	// Enable ANSI color code processing
	ProcessANSI bool
}

// DefaultOutputCaptureConfig returns default configuration
func DefaultOutputCaptureConfig() *OutputCaptureConfig {
	return &OutputCaptureConfig{
		MaxBufferSize:        10 * 1024 * 1024, // 10MB
		StreamingEnabled:     false,
		FlushInterval:        100 * time.Millisecond,
		CompressionEnabled:   true,
		CompressionThreshold: 1024 * 1024, // 1MB
		ProcessANSI:          true,
	}
}

// RingBuffer implements a fixed-size ring buffer for output capture
type RingBuffer struct {
	mu       sync.RWMutex
	buf      []byte
	size     int64
	maxSize  int64
	start    int64
	end      int64
	wrapped  bool
	totalWrites int64
}

// NewRingBuffer creates a new ring buffer with the specified size
func NewRingBuffer(maxSize int64) *RingBuffer {
	return &RingBuffer{
		buf:     make([]byte, maxSize),
		maxSize: maxSize,
	}
}

// Write writes data to the ring buffer
func (rb *RingBuffer) Write(p []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	atomic.AddInt64(&rb.totalWrites, int64(len(p)))

	for _, b := range p {
		rb.buf[rb.end] = b
		
		if rb.size < rb.maxSize {
			// Buffer is not yet full
			rb.size++
		} else {
			// Buffer is full, we need to wrap around
			rb.wrapped = true
			rb.start = (rb.start + 1) % rb.maxSize
		}
		
		rb.end = (rb.end + 1) % rb.maxSize
	}

	return len(p), nil
}

// Read reads all available data from the ring buffer
func (rb *RingBuffer) Read() []byte {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 {
		return nil
	}

	result := make([]byte, rb.size)
	if rb.wrapped {
		// Data wraps around - start from rb.start to end of buffer, then from beginning to rb.end
		firstPart := copy(result, rb.buf[rb.start:])
		copy(result[firstPart:], rb.buf[:rb.end])
	} else {
		// Data is contiguous from start
		copy(result, rb.buf[rb.start:rb.start+rb.size])
	}

	return result
}

// Size returns the current size of data in the buffer
func (rb *RingBuffer) Size() int64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size
}

// TotalWrites returns the total number of bytes written (including overwritten)
func (rb *RingBuffer) TotalWrites() int64 {
	return atomic.LoadInt64(&rb.totalWrites)
}

// IsWrapped returns true if the buffer has wrapped around
func (rb *RingBuffer) IsWrapped() bool {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.wrapped
}

// OutputCapture manages process output capture with advanced features
type OutputCapture struct {
	mu     sync.RWMutex
	config *OutputCaptureConfig

	// Buffers for stdout and stderr
	stdoutBuffer *RingBuffer
	stderrBuffer *RingBuffer

	// Streaming support
	stdoutChan chan []byte
	stderrChan chan []byte
	done       chan struct{}

	// Metrics
	startTime    time.Time
	endTime      time.Time
	stdoutBytes  int64
	stderrBytes  int64

	// State
	closed bool
	cancel context.CancelFunc
}

// NewOutputCapture creates a new output capture instance
func NewOutputCapture(config *OutputCaptureConfig) *OutputCapture {
	if config == nil {
		config = DefaultOutputCaptureConfig()
	}

	oc := &OutputCapture{
		config:       config,
		stdoutBuffer: NewRingBuffer(config.MaxBufferSize),
		stderrBuffer: NewRingBuffer(config.MaxBufferSize),
		done:         make(chan struct{}),
		startTime:    time.Now(),
	}

	if config.StreamingEnabled {
		oc.stdoutChan = make(chan []byte, 100)
		oc.stderrChan = make(chan []byte, 100)
	}

	return oc
}

// CaptureStreams starts capturing from the provided readers
func (oc *OutputCapture) CaptureStreams(ctx context.Context, stdout, stderr io.Reader) {
	ctx, cancel := context.WithCancel(ctx)
	oc.cancel = cancel

	var wg sync.WaitGroup

	// Capture stdout
	if stdout != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.captureStream(ctx, stdout, oc.stdoutBuffer, oc.stdoutChan, &oc.stdoutBytes, "stdout")
		}()
	}

	// Capture stderr
	if stderr != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			oc.captureStream(ctx, stderr, oc.stderrBuffer, oc.stderrChan, &oc.stderrBytes, "stderr")
		}()
	}

	// Wait for completion in a separate goroutine
	go func() {
		wg.Wait()
		oc.mu.Lock()
		oc.endTime = time.Now()
		oc.mu.Unlock()
		close(oc.done)
	}()
}

// captureStream captures data from a single stream
func (oc *OutputCapture) captureStream(ctx context.Context, reader io.Reader, buffer *RingBuffer, streamChan chan []byte, byteCounter *int64, streamName string) {
	buf := make([]byte, 4096)
	var lastFlush time.Time

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Set read deadline to prevent blocking indefinitely
			n, err := reader.Read(buf)
			if n > 0 {
				data := buf[:n]
				
				// Process ANSI codes if enabled
				if oc.config.ProcessANSI {
					data = oc.processANSICodes(data)
				}

				// Write to ring buffer
				if _, writeErr := buffer.Write(data); writeErr != nil {
					log.Error().Err(writeErr).Str("stream", streamName).Msg("Failed to write to buffer")
				}

				// Update byte counter
				atomic.AddInt64(byteCounter, int64(n))

				// Stream if enabled
				if streamChan != nil {
					select {
					case streamChan <- append([]byte(nil), data...):
					default:
						// Channel full, skip this chunk to prevent blocking
						log.Warn().Str("stream", streamName).Msg("Stream channel full, dropping data")
					}
				}

				// Periodic flush for streaming
				if oc.config.StreamingEnabled && time.Since(lastFlush) > oc.config.FlushInterval {
					oc.flushStream(streamChan, streamName)
					lastFlush = time.Now()
				}
			}

			if err != nil {
				if err != io.EOF {
					log.Debug().Err(err).Str("stream", streamName).Msg("Stream read error")
				}
				return
			}
		}
	}
}

// processANSICodes removes or processes ANSI escape codes
func (oc *OutputCapture) processANSICodes(data []byte) []byte {
	// Simple ANSI escape sequence regex
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return ansiRegex.ReplaceAll(data, []byte{})
}

// flushStream sends any pending data to the stream channel
func (oc *OutputCapture) flushStream(streamChan chan []byte, streamName string) {
	if streamChan == nil {
		return
	}

	select {
	case streamChan <- []byte{}: // Empty flush marker
	default:
		log.Debug().Str("stream", streamName).Msg("Unable to flush stream - channel full")
	}
}

// GetOutput returns the captured output
func (oc *OutputCapture) GetOutput() ProcessOutput {
	oc.mu.RLock()
	defer oc.mu.RUnlock()

	stdoutData := oc.stdoutBuffer.Read()
	stderrData := oc.stderrBuffer.Read()

	output := ProcessOutput{
		Stdout:         stdoutData,
		Stderr:         stderrData,
		StdoutSize:     atomic.LoadInt64(&oc.stdoutBytes),
		StderrSize:     atomic.LoadInt64(&oc.stderrBytes),
		Truncated:      oc.stdoutBuffer.IsWrapped() || oc.stderrBuffer.IsWrapped(),
		CaptureStarted: oc.startTime,
		Streaming:      oc.config.StreamingEnabled,
	}

	if !oc.endTime.IsZero() {
		output.CaptureEnded = oc.endTime
		output.Duration = oc.endTime.Sub(oc.startTime)
	} else {
		output.Duration = time.Since(oc.startTime)
	}

	// Apply compression if enabled and data is large enough
	if oc.config.CompressionEnabled {
		if output.StdoutSize > oc.config.CompressionThreshold {
			if compressed, err := oc.compressData(stdoutData); err == nil {
				output.Stdout = compressed
				output.Compressed = true
			}
		}
		if output.StderrSize > oc.config.CompressionThreshold {
			if compressed, err := oc.compressData(stderrData); err == nil {
				output.Stderr = compressed
				output.Compressed = true
			}
		}
	}

	return output
}

// compressData compresses data using gzip
func (oc *OutputCapture) compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	
	if _, err := gzw.Write(data); err != nil {
		return nil, err
	}
	
	if err := gzw.Close(); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// GetStdoutChannel returns the stdout streaming channel
func (oc *OutputCapture) GetStdoutChannel() <-chan []byte {
	return oc.stdoutChan
}

// GetStderrChannel returns the stderr streaming channel
func (oc *OutputCapture) GetStderrChannel() <-chan []byte {
	return oc.stderrChan
}

// Wait waits for capture to complete
func (oc *OutputCapture) Wait() {
	<-oc.done
}

// Close closes the output capture and releases resources
func (oc *OutputCapture) Close() error {
	oc.mu.Lock()
	defer oc.mu.Unlock()

	if oc.closed {
		return nil
	}

	oc.closed = true

	if oc.cancel != nil {
		oc.cancel()
	}

	if oc.stdoutChan != nil {
		close(oc.stdoutChan)
	}
	if oc.stderrChan != nil {
		close(oc.stderrChan)
	}

	return nil
}

// FormatOutput provides utilities for output formatting
type FormatOutput struct{}

// StripANSI removes ANSI escape codes from text
func (fo *FormatOutput) StripANSI(data []byte) []byte {
	ansiRegex := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return ansiRegex.ReplaceAll(data, []byte{})
}

// TruncateOutput truncates output to a maximum size with ellipsis
func (fo *FormatOutput) TruncateOutput(data []byte, maxSize int) []byte {
	if len(data) <= maxSize {
		return data
	}

	truncated := make([]byte, maxSize)
	copy(truncated, data[:maxSize-3])
	copy(truncated[maxSize-3:], []byte("..."))
	return truncated
}

// SplitLines splits output into lines while preserving line endings
func (fo *FormatOutput) SplitLines(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}

	var lines [][]byte
	start := 0

	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i+1])
			start = i + 1
		}
	}

	// Add remaining data if any
	if start < len(data) {
		lines = append(lines, data[start:])
	}

	return lines
}