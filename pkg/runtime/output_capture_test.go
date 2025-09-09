package runtime

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

func TestRingBuffer_BasicOperations(t *testing.T) {
	rb := NewRingBuffer(10)

	// Test empty buffer
	if rb.Size() != 0 {
		t.Errorf("Expected empty buffer size 0, got %d", rb.Size())
	}

	// Test writing within capacity
	data := []byte("hello")
	n, err := rb.Write(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}
	if rb.Size() != int64(len(data)) {
		t.Errorf("Expected buffer size %d, got %d", len(data), rb.Size())
	}

	// Test reading
	result := rb.Read()
	if !bytes.Equal(result, data) {
		t.Errorf("Expected %s, got %s", string(data), string(result))
	}
}

func TestRingBuffer_Wraparound(t *testing.T) {
	rb := NewRingBuffer(5)

	// Write data that exceeds buffer capacity
	data := []byte("hello world")
	n, err := rb.Write(data)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	// Buffer should be wrapped and contain only the last 5 bytes
	if !rb.IsWrapped() {
		t.Error("Expected buffer to be wrapped")
	}

	if rb.Size() != 5 {
		t.Errorf("Expected buffer size 5, got %d", rb.Size())
	}

	result := rb.Read()
	expected := []byte("world")
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %s, got %s", string(expected), string(result))
	}

	// Total writes should track all written data
	if rb.TotalWrites() != int64(len(data)) {
		t.Errorf("Expected total writes %d, got %d", len(data), rb.TotalWrites())
	}
}

func TestRingBuffer_ConcurrentAccess(t *testing.T) {
	rb := NewRingBuffer(1000)
	done := make(chan struct{})
	
	// Start multiple writers
	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			data := []byte(strings.Repeat("x", 50))
			for j := 0; j < 10; j++ {
				rb.Write(data)
			}
		}(i)
	}

	// Start reader
	go func() {
		defer func() { done <- struct{}{} }()
		for i := 0; i < 100; i++ {
			rb.Read()
			time.Sleep(time.Microsecond)
		}
	}()

	// Wait for all goroutines
	for i := 0; i < 11; i++ {
		<-done
	}

	// Verify buffer integrity
	if rb.Size() < 0 || rb.Size() > 1000 {
		t.Errorf("Invalid buffer size after concurrent access: %d", rb.Size())
	}
}

func TestOutputCaptureConfig_Defaults(t *testing.T) {
	config := DefaultOutputCaptureConfig()

	expected := &OutputCaptureConfig{
		MaxBufferSize:        10 * 1024 * 1024,
		StreamingEnabled:     false,
		FlushInterval:        100 * time.Millisecond,
		CompressionEnabled:   true,
		CompressionThreshold: 1024 * 1024,
		ProcessANSI:          true,
	}

	if *config != *expected {
		t.Errorf("Default config mismatch. Got %+v, want %+v", config, expected)
	}
}

func TestOutputCapture_BasicCapture(t *testing.T) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = false
	oc := NewOutputCapture(config)
	defer oc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create test data
	stdoutData := []byte("stdout output\n")
	stderrData := []byte("stderr output\n")

	stdoutReader := strings.NewReader(string(stdoutData))
	stderrReader := strings.NewReader(string(stderrData))

	// Start capture
	oc.CaptureStreams(ctx, stdoutReader, stderrReader)
	
	// Wait for capture to complete
	oc.Wait()

	// Get output
	output := oc.GetOutput()

	// Verify stdout
	if !bytes.Equal(output.Stdout, stdoutData) {
		t.Errorf("Expected stdout %q, got %q", string(stdoutData), string(output.Stdout))
	}

	// Verify stderr
	if !bytes.Equal(output.Stderr, stderrData) {
		t.Errorf("Expected stderr %q, got %q", string(stderrData), string(output.Stderr))
	}

	// Verify metrics
	if output.StdoutSize != int64(len(stdoutData)) {
		t.Errorf("Expected stdout size %d, got %d", len(stdoutData), output.StdoutSize)
	}

	if output.StderrSize != int64(len(stderrData)) {
		t.Errorf("Expected stderr size %d, got %d", len(stderrData), output.StderrSize)
	}

	if output.Duration <= 0 {
		t.Error("Expected positive duration")
	}

	if output.Truncated {
		t.Error("Expected output not to be truncated for small data")
	}
}

func TestOutputCapture_LargeOutput(t *testing.T) {
	config := DefaultOutputCaptureConfig()
	config.MaxBufferSize = 1024 // Small buffer to test truncation
	config.CompressionEnabled = false // Disable for easier testing
	oc := NewOutputCapture(config)
	defer oc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create large data that exceeds buffer
	largeData := bytes.Repeat([]byte("x"), 2048)
	stdoutReader := bytes.NewReader(largeData)

	// Start capture
	oc.CaptureStreams(ctx, stdoutReader, nil)
	
	// Wait for capture to complete
	oc.Wait()

	// Get output
	output := oc.GetOutput()

	// Should be truncated
	if !output.Truncated {
		t.Error("Expected output to be truncated for large data")
	}

	// Output should be limited to buffer size
	if int64(len(output.Stdout)) > config.MaxBufferSize {
		t.Errorf("Output size %d exceeds buffer limit %d", len(output.Stdout), config.MaxBufferSize)
	}

	// Total size should reflect all data written
	if output.StdoutSize != int64(len(largeData)) {
		t.Errorf("Expected total stdout size %d, got %d", len(largeData), output.StdoutSize)
	}
}

func TestOutputCapture_Streaming(t *testing.T) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = true
	config.FlushInterval = 10 * time.Millisecond
	oc := NewOutputCapture(config)
	defer oc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create test data with multiple chunks
	testData := []string{"chunk1\n", "chunk2\n", "chunk3\n"}
	stdoutReader, stdoutWriter := io.Pipe()

	// Start capture
	oc.CaptureStreams(ctx, stdoutReader, nil)

	// Get streaming channel
	stdoutChan := oc.GetStdoutChannel()
	if stdoutChan == nil {
		t.Fatal("Expected stdout channel to be available")
	}

	// Write data in chunks
	go func() {
		defer stdoutWriter.Close()
		for _, chunk := range testData {
			stdoutWriter.Write([]byte(chunk))
			time.Sleep(20 * time.Millisecond) // Allow time for streaming
		}
	}()

	// Read from streaming channel
	receivedChunks := make([]string, 0)
	timeout := time.After(500 * time.Millisecond)

	for len(receivedChunks) < len(testData) {
		select {
		case chunk := <-stdoutChan:
			if len(chunk) > 0 { // Skip empty flush markers
				receivedChunks = append(receivedChunks, string(chunk))
			}
		case <-timeout:
			break
		}
	}

	// Verify streaming worked
	if len(receivedChunks) == 0 {
		t.Error("Expected to receive streaming chunks")
	}
}

func TestOutputCapture_ANSIProcessing(t *testing.T) {
	config := DefaultOutputCaptureConfig()
	config.ProcessANSI = true
	oc := NewOutputCapture(config)
	defer oc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create data with ANSI escape codes
	dataWithANSI := []byte("\x1b[31mRed text\x1b[0m normal text")
	stdoutReader := bytes.NewReader(dataWithANSI)

	// Start capture
	oc.CaptureStreams(ctx, stdoutReader, nil)
	
	// Wait for capture to complete
	oc.Wait()

	// Get output
	output := oc.GetOutput()

	// ANSI codes should be stripped
	expected := []byte("Red text normal text")
	if !bytes.Equal(output.Stdout, expected) {
		t.Errorf("Expected ANSI-stripped output %q, got %q", string(expected), string(output.Stdout))
	}
}

func TestOutputCapture_Compression(t *testing.T) {
	config := DefaultOutputCaptureConfig()
	config.CompressionEnabled = true
	config.CompressionThreshold = 100 // Low threshold for testing
	oc := NewOutputCapture(config)
	defer oc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// Create compressible data that exceeds threshold
	largeData := bytes.Repeat([]byte("compressible data "), 20)
	stdoutReader := bytes.NewReader(largeData)

	// Start capture
	oc.CaptureStreams(ctx, stdoutReader, nil)
	
	// Wait for capture to complete
	oc.Wait()

	// Get output
	output := oc.GetOutput()

	// Should be compressed
	if !output.Compressed {
		t.Error("Expected output to be compressed for large data")
	}

	// Compressed data should be smaller
	if len(output.Stdout) >= len(largeData) {
		t.Error("Expected compressed data to be smaller than original")
	}
}

func TestProcessResult_LegacyCompatibility(t *testing.T) {
	process := &Process{
		ID:          "test-process",
		PID:         123,
		Status:      "completed",
		StartTime:   time.Now(),
		ContainerID: "test-container",
	}

	output := ProcessOutput{
		Stdout:   []byte("stdout data"),
		Stderr:   []byte("stderr data"),
		ExitCode: 0,
		Duration: time.Second,
	}

	result := NewProcessResult(process, output, nil)

	// Test legacy compatibility fields
	if result.ExitCode != output.ExitCode {
		t.Errorf("Expected legacy ExitCode %d, got %d", output.ExitCode, result.ExitCode)
	}

	if !bytes.Equal(result.Stdout, output.Stdout) {
		t.Errorf("Expected legacy Stdout %q, got %q", string(output.Stdout), string(result.Stdout))
	}

	if !bytes.Equal(result.Stderr, output.Stderr) {
		t.Errorf("Expected legacy Stderr %q, got %q", string(output.Stderr), string(result.Stderr))
	}
}

func TestProcessResult_Decompression(t *testing.T) {
	process := &Process{
		ID:          "test-process",
		PID:         123,
		Status:      "completed",
		StartTime:   time.Now(),
		ContainerID: "test-container",
	}

	// Create compressed output
	originalData := []byte("original data for compression test")
	config := DefaultOutputCaptureConfig()
	oc := NewOutputCapture(config)
	
	compressedData, err := oc.compressData(originalData)
	if err != nil {
		t.Fatalf("Failed to compress test data: %v", err)
	}

	output := ProcessOutput{
		Stdout:     compressedData,
		Stderr:     []byte{},
		ExitCode:   0,
		Duration:   time.Second,
		Compressed: true,
	}

	result := NewProcessResult(process, output, nil)

	// Test decompression
	decompressed, err := result.GetStdout()
	if err != nil {
		t.Errorf("Failed to decompress stdout: %v", err)
	}

	if !bytes.Equal(decompressed, originalData) {
		t.Errorf("Expected decompressed data %q, got %q", string(originalData), string(decompressed))
	}
}

func TestFormatOutput_Utilities(t *testing.T) {
	fo := &FormatOutput{}

	t.Run("StripANSI", func(t *testing.T) {
		input := []byte("\x1b[31mRed\x1b[0m normal \x1b[1mbold\x1b[0m")
		expected := []byte("Red normal bold")
		result := fo.StripANSI(input)
		
		if !bytes.Equal(result, expected) {
			t.Errorf("Expected %q, got %q", string(expected), string(result))
		}
	})

	t.Run("TruncateOutput", func(t *testing.T) {
		input := []byte("this is a long string that should be truncated")
		result := fo.TruncateOutput(input, 20)
		
		if len(result) != 20 {
			t.Errorf("Expected truncated length 20, got %d", len(result))
		}
		
		if !bytes.HasSuffix(result, []byte("...")) {
			t.Error("Expected truncated output to end with '...'")
		}
	})

	t.Run("SplitLines", func(t *testing.T) {
		input := []byte("line1\nline2\nline3")
		result := fo.SplitLines(input)
		
		expected := [][]byte{
			[]byte("line1\n"),
			[]byte("line2\n"),
			[]byte("line3"),
		}
		
		if len(result) != len(expected) {
			t.Errorf("Expected %d lines, got %d", len(expected), len(result))
		}
		
		for i, line := range result {
			if !bytes.Equal(line, expected[i]) {
				t.Errorf("Line %d: expected %q, got %q", i, string(expected[i]), string(line))
			}
		}
	})

	t.Run("SplitLines_Empty", func(t *testing.T) {
		result := fo.SplitLines([]byte{})
		if result != nil {
			t.Error("Expected nil for empty input")
		}
	})
}

func TestOutputCapture_ContextCancellation(t *testing.T) {
	config := DefaultOutputCaptureConfig()
	oc := NewOutputCapture(config)
	defer oc.Close()

	ctx, cancel := context.WithCancel(context.Background())

	// Create a blocking reader
	stdoutReader, stdoutWriter := io.Pipe()

	// Start capture
	oc.CaptureStreams(ctx, stdoutReader, nil)

	// Cancel context immediately
	cancel()

	// Write some data (should not block due to cancellation)
	go func() {
		time.Sleep(10 * time.Millisecond)
		stdoutWriter.Write([]byte("test data"))
		stdoutWriter.Close()
	}()

	// Wait for completion (should happen quickly due to cancellation)
	done := make(chan struct{})
	go func() {
		oc.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Expected - capture should stop quickly
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected capture to stop quickly after context cancellation")
	}
}

func TestOutputCapture_CloseCleanup(t *testing.T) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = true
	oc := NewOutputCapture(config)

	ctx := context.Background()
	stdoutReader := strings.NewReader("test data")
	
	// Start capture
	oc.CaptureStreams(ctx, stdoutReader, nil)

	// Get channels before closing
	stdoutChan := oc.GetStdoutChannel()
	
	// Close should clean up resources
	err := oc.Close()
	if err != nil {
		t.Errorf("Unexpected error closing: %v", err)
	}

	// Channels should be closed
	select {
	case _, ok := <-stdoutChan:
		if ok {
			t.Error("Expected stdout channel to be closed")
		}
	case <-time.After(10 * time.Millisecond):
		t.Error("Expected stdout channel to be closed immediately")
	}

	// Double close should not error
	err = oc.Close()
	if err != nil {
		t.Errorf("Unexpected error on double close: %v", err)
	}
}