package tools

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBufferedOutputStreamer_Basic(t *testing.T) {
	config := DefaultOutputStreamConfig()
	config.BufferSize = 1024
	config.FlushInterval = 50 * time.Millisecond

	streamer := NewBufferedOutputStreamer(config)
	defer streamer.Stop()

	// Create test readers
	stdout := strings.NewReader("Hello, World!\nThis is stdout\n")
	stderr := strings.NewReader("This is stderr\nError message\n")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start streaming
	err := streamer.StartStreaming(ctx, stdout, stderr)
	if err != nil {
		t.Fatalf("StartStreaming() error: %v", err)
	}

	// Collect outputs
	var outputs []StreamOutput
	outputChan := streamer.GetChannel()

	done := make(chan bool)
	go func() {
		defer close(done)
		for output := range outputChan {
			outputs = append(outputs, output)
			if output.Type == StreamTypeComplete {
				break
			}
		}
	}()

	// Wait for completion or timeout
	select {
	case <-done:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("Streaming did not complete within timeout")
	}

	// Verify outputs
	if len(outputs) == 0 {
		t.Fatal("No outputs received")
	}

	// Check that we received data from both stdout and stderr
	hasStdout := false
	hasStderr := false
	hasComplete := false

	for _, output := range outputs {
		switch output.Source {
		case StreamSourceStdout:
			hasStdout = true
			if !strings.Contains(output.Content, "Hello, World!") && !strings.Contains(output.Content, "This is stdout") {
				t.Errorf("Stdout output doesn't contain expected content: %s", output.Content)
			}
		case StreamSourceStderr:
			hasStderr = true
			if !strings.Contains(output.Content, "This is stderr") && !strings.Contains(output.Content, "Error message") {
				t.Errorf("Stderr output doesn't contain expected content: %s", output.Content)
			}
		case StreamSourceSystem:
			if output.Type == StreamTypeComplete {
				hasComplete = true
			}
		}
	}

	if !hasStdout {
		t.Error("No stdout outputs received")
	}
	if !hasStderr {
		t.Error("No stderr outputs received")
	}
	if !hasComplete {
		t.Error("No completion signal received")
	}

	// Check metrics
	metrics := streamer.GetMetrics()
	if metrics.LinesRead == 0 {
		t.Error("Expected lines read to be > 0")
	}
	if metrics.BytesRead == 0 {
		t.Error("Expected bytes read to be > 0")
	}
}

func TestBufferedOutputStreamer_ANSIFiltering(t *testing.T) {
	config := DefaultOutputStreamConfig()
	config.FilterANSI = true

	streamer := NewBufferedOutputStreamer(config)
	defer streamer.Stop()

	// Create test input with ANSI codes
	ansiText := "\x1b[31mRed text\x1b[0m\nNormal text\n\x1b[1;32mBold green\x1b[0m"
	stdout := strings.NewReader(ansiText)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := streamer.StartStreaming(ctx, stdout, nil)
	if err != nil {
		t.Fatalf("StartStreaming() error: %v", err)
	}

	// Collect outputs
	var outputs []StreamOutput
	outputChan := streamer.GetChannel()

	for output := range outputChan {
		outputs = append(outputs, output)
		if output.Type == StreamTypeComplete {
			break
		}
	}

	// Check that ANSI codes were filtered
	foundFiltered := false
	for _, output := range outputs {
		if output.Type == StreamTypeData && output.Source == StreamSourceStdout {
			if strings.Contains(output.Content, "\x1b[") {
				t.Errorf("ANSI codes not filtered: %s", output.Content)
			}
			if strings.Contains(output.Content, "Red text") || strings.Contains(output.Content, "Normal text") {
				foundFiltered = true
			}
		}
	}

	if !foundFiltered {
		t.Error("Expected filtered text not found")
	}

	// Check metrics for ANSI filtering
	metrics := streamer.GetMetrics()
	if metrics.ANSIFiltered == 0 {
		t.Error("Expected ANSI filtering count > 0")
	}
}

func TestBufferedOutputStreamer_ProgressDetection(t *testing.T) {
	config := DefaultOutputStreamConfig()
	config.DetectProgress = true

	streamer := NewBufferedOutputStreamer(config)
	defer streamer.Stop()

	// Create test input with progress indicators
	progressText := "Downloading file... 50%\nProgress: [####    ] 50%\nInstalling packages...\nLoading... 100%\n"
	stdout := strings.NewReader(progressText)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := streamer.StartStreaming(ctx, stdout, nil)
	if err != nil {
		t.Fatalf("StartStreaming() error: %v", err)
	}

	// Collect outputs
	var outputs []StreamOutput
	outputChan := streamer.GetChannel()

	for output := range outputChan {
		outputs = append(outputs, output)
		if output.Type == StreamTypeComplete {
			break
		}
	}

	// Check for progress detection
	foundProgress := false
	for _, output := range outputs {
		if output.Type == StreamTypeProgress {
			foundProgress = true
			if output.Metadata == nil || output.Metadata["detected"] != "progress_indicator" {
				t.Error("Progress output missing expected metadata")
			}
		}
	}

	if !foundProgress {
		t.Error("No progress indicators detected")
	}

	// Check metrics for progress detection
	metrics := streamer.GetMetrics()
	if metrics.ProgressDetected == 0 {
		t.Error("Expected progress detection count > 0")
	}
}

func TestBufferedOutputStreamer_JSONDetection(t *testing.T) {
	config := DefaultOutputStreamConfig()
	config.EnableJSON = true

	streamer := NewBufferedOutputStreamer(config)
	defer streamer.Stop()

	// Create test input with JSON
	jsonText := `{"message": "Hello", "status": "ok"}
Not JSON line
{"error": "Something went wrong", "code": 500}
`
	stdout := strings.NewReader(jsonText)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := streamer.StartStreaming(ctx, stdout, nil)
	if err != nil {
		t.Fatalf("StartStreaming() error: %v", err)
	}

	// Collect outputs
	var outputs []StreamOutput
	outputChan := streamer.GetChannel()

	for output := range outputChan {
		outputs = append(outputs, output)
		if output.Type == StreamTypeComplete {
			break
		}
	}

	// Check for JSON detection
	jsonCount := 0
	for _, output := range outputs {
		if output.Type == StreamTypeJSON {
			jsonCount++
			if output.Metadata == nil || output.Metadata["format"] != "json" {
				t.Error("JSON output missing expected metadata")
			}
		}
	}

	if jsonCount == 0 {
		t.Error("No JSON detected")
	}
}

func TestSimpleOutputStreamer(t *testing.T) {
	streamer := NewSimpleOutputStreamer()
	defer streamer.Stop()

	stdout := strings.NewReader("Line 1\nLine 2\nLine 3\n")
	stderr := strings.NewReader("Error 1\nError 2\n")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := streamer.StartStreaming(ctx, stdout, stderr)
	if err != nil {
		t.Fatalf("StartStreaming() error: %v", err)
	}

	// Collect outputs
	var outputs []StreamOutput
	outputChan := streamer.GetChannel()

	// Give time for streaming to complete
	time.Sleep(100 * time.Millisecond)
	streamer.Stop()

	for output := range outputChan {
		outputs = append(outputs, output)
	}

	if len(outputs) == 0 {
		t.Error("No outputs received from simple streamer")
	}

	// Check that we got outputs from both sources
	hasStdout := false
	hasStderr := false

	for _, output := range outputs {
		if output.Source == StreamSourceStdout {
			hasStdout = true
		}
		if output.Source == StreamSourceStderr {
			hasStderr = true
		}
		if output.Type != StreamTypeData {
			t.Errorf("Simple streamer should only produce data types, got %s", output.Type)
		}
	}

	if !hasStdout {
		t.Error("No stdout from simple streamer")
	}
	if !hasStderr {
		t.Error("No stderr from simple streamer")
	}
}

func TestStreamCollector(t *testing.T) {
	streamer := NewSimpleOutputStreamer()
	collector := NewStreamCollector()

	stdout := strings.NewReader("Stdout line 1\nStdout line 2\n")
	stderr := strings.NewReader("Stderr line 1\n")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := streamer.StartStreaming(ctx, stdout, stderr)
	if err != nil {
		t.Fatalf("StartStreaming() error: %v", err)
	}

	// Start collecting
	collectCtx, collectCancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(100 * time.Millisecond) // Give time for streaming
		streamer.Stop()
		collectCancel()
	}()

	err = collector.Collect(collectCtx, streamer)
	if err != nil && err != context.Canceled {
		t.Errorf("Collect() unexpected error: %v", err)
	}

	// Check collected outputs
	outputs := collector.GetOutputs()
	if len(outputs) == 0 {
		t.Error("No outputs collected")
	}

	// Test filtering by type
	dataOutputs := collector.GetOutputsByType(StreamTypeData)
	if len(dataOutputs) == 0 {
		t.Error("No data outputs found")
	}

	// Test combined content
	stdoutContent := collector.GetCombinedContent(StreamSourceStdout)
	if !strings.Contains(stdoutContent, "Stdout line 1") {
		t.Errorf("Combined stdout content missing expected text: %s", stdoutContent)
	}

	stderrContent := collector.GetCombinedContent(StreamSourceStderr)
	if !strings.Contains(stderrContent, "Stderr line 1") {
		t.Errorf("Combined stderr content missing expected text: %s", stderrContent)
	}

	allContent := collector.GetCombinedContent("")
	if len(allContent) == 0 {
		t.Error("Combined all content is empty")
	}

	// Test clear
	collector.Clear()
	outputs = collector.GetOutputs()
	if len(outputs) != 0 {
		t.Errorf("Expected 0 outputs after clear, got %d", len(outputs))
	}
}

func TestOutputStreamerMetrics(t *testing.T) {
	config := DefaultOutputStreamConfig()
	streamer := NewBufferedOutputStreamer(config)
	defer streamer.Stop()

	// Initial metrics should be initialized
	initialMetrics := streamer.GetMetrics()
	if initialMetrics.StartTime.IsZero() {
		t.Error("Start time should be set")
	}

	// Test with some data
	testData := strings.Repeat("Test line\n", 100)
	stdout := strings.NewReader(testData)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := streamer.StartStreaming(ctx, stdout, nil)
	if err != nil {
		t.Fatalf("StartStreaming() error: %v", err)
	}

	// Consume outputs
	outputChan := streamer.GetChannel()
	for range outputChan {
		// Just consume outputs
	}

	// Check final metrics
	finalMetrics := streamer.GetMetrics()
	if finalMetrics.LinesRead == 0 {
		t.Error("Expected lines read > 0")
	}
	if finalMetrics.BytesRead == 0 {
		t.Error("Expected bytes read > 0")
	}
	if finalMetrics.ChunksStreamed == 0 {
		t.Error("Expected chunks streamed > 0")
	}
}

func TestOutputStreamConfig(t *testing.T) {
	config := DefaultOutputStreamConfig()

	// Test default values
	if config.BufferSize <= 0 {
		t.Error("Default buffer size should be > 0")
	}
	if config.FlushInterval <= 0 {
		t.Error("Default flush interval should be > 0")
	}
	if config.MaxChunkSize <= 0 {
		t.Error("Default max chunk size should be > 0")
	}

	// Test creating streamer with custom config
	customConfig := OutputStreamConfig{
		BufferSize:     1024,
		FlushInterval:  10 * time.Millisecond,
		MaxChunkSize:   512,
		EnableANSI:     false,
		FilterANSI:     true,
		DetectProgress: false,
		EnableJSON:     false,
		Compress:       false,
		CompressionMin: 2048,
	}

	streamer := NewBufferedOutputStreamer(customConfig)
	defer streamer.Stop()

	if streamer.config.BufferSize != customConfig.BufferSize {
		t.Errorf("Expected buffer size %d, got %d", customConfig.BufferSize, streamer.config.BufferSize)
	}
}

func TestStreamOutputTypes(t *testing.T) {
	// Test StreamOutput struct
	output := StreamOutput{
		Type:      StreamTypeData,
		Content:   "test content",
		Source:    StreamSourceStdout,
		Timestamp: time.Now(),
		Metadata:  map[string]interface{}{"test": "value"},
	}

	if output.Type != StreamTypeData {
		t.Errorf("Expected type %s, got %s", StreamTypeData, output.Type)
	}

	if output.Source != StreamSourceStdout {
		t.Errorf("Expected source %s, got %s", StreamSourceStdout, output.Source)
	}

	if output.Content != "test content" {
		t.Errorf("Expected content 'test content', got '%s'", output.Content)
	}

	if output.Metadata["test"] != "value" {
		t.Errorf("Expected metadata test='value', got '%v'", output.Metadata["test"])
	}
}

// Benchmark tests
func BenchmarkBufferedOutputStreamer(b *testing.B) {
	config := DefaultOutputStreamConfig()
	testData := strings.Repeat("Benchmark test line\n", 1000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		streamer := NewBufferedOutputStreamer(config)
		stdout := strings.NewReader(testData)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

		streamer.StartStreaming(ctx, stdout, nil)

		// Consume all outputs
		outputChan := streamer.GetChannel()
		for range outputChan {
			// Just consume
		}

		streamer.Stop()
		cancel()
	}
}

func BenchmarkSimpleOutputStreamer(b *testing.B) {
	testData := strings.Repeat("Benchmark test line\n", 1000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		streamer := NewSimpleOutputStreamer()
		stdout := strings.NewReader(testData)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

		streamer.StartStreaming(ctx, stdout, nil)

		// Consume all outputs
		outputChan := streamer.GetChannel()
		for range outputChan {
			// Just consume
		}

		streamer.Stop()
		cancel()
	}
}

func BenchmarkStreamCollector(b *testing.B) {
	testData := strings.Repeat("Benchmark test line\n", 100)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		streamer := NewSimpleOutputStreamer()
		collector := NewStreamCollector()
		stdout := strings.NewReader(testData)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

		streamer.StartStreaming(ctx, stdout, nil)

		collectCtx, collectCancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(50 * time.Millisecond)
			streamer.Stop()
			collectCancel()
		}()

		collector.Collect(collectCtx, streamer)

		cancel()
	}
}
