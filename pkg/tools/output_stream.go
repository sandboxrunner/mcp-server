package tools

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// OutputStreamer provides real-time streaming of command output
type OutputStreamer interface {
	// StartStreaming begins streaming output from readers
	StartStreaming(ctx context.Context, stdout, stderr io.Reader) error

	// GetChannel returns the channel for streaming results
	GetChannel() <-chan StreamOutput

	// Stop stops the streaming process
	Stop()

	// GetMetrics returns streaming performance metrics
	GetMetrics() StreamMetrics
}

// StreamOutput represents a single output chunk from streaming
type StreamOutput struct {
	Type      StreamType             `json:"type"`
	Content   string                 `json:"content"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
	Source    StreamSource           `json:"source"`
}

// StreamType represents the type of stream output
type StreamType string

const (
	StreamTypeData     StreamType = "data"
	StreamTypeProgress StreamType = "progress"
	StreamTypeError    StreamType = "error"
	StreamTypeComplete StreamType = "complete"
	StreamTypeJSON     StreamType = "json"
)

// StreamSource indicates the source of the output
type StreamSource string

const (
	StreamSourceStdout StreamSource = "stdout"
	StreamSourceStderr StreamSource = "stderr"
	StreamSourceSystem StreamSource = "system"
)

// StreamMetrics tracks performance metrics for streaming
type StreamMetrics struct {
	StartTime        time.Time     `json:"start_time"`
	EndTime          time.Time     `json:"end_time"`
	Duration         time.Duration `json:"duration"`
	BytesRead        int64         `json:"bytes_read"`
	LinesRead        int64         `json:"lines_read"`
	ChunksStreamed   int64         `json:"chunks_streamed"`
	FlushCount       int64         `json:"flush_count"`
	CompressionSaved int64         `json:"compression_saved"`
	BufferOverflows  int64         `json:"buffer_overflows"`
	ANSIFiltered     int64         `json:"ansi_filtered"`
	ProgressDetected int64         `json:"progress_detected"`
}

// OutputStreamConfig configures the output streaming behavior
type OutputStreamConfig struct {
	BufferSize     int           `json:"buffer_size"`
	FlushInterval  time.Duration `json:"flush_interval"`
	MaxChunkSize   int           `json:"max_chunk_size"`
	EnableANSI     bool          `json:"enable_ansi"`
	FilterANSI     bool          `json:"filter_ansi"`
	DetectProgress bool          `json:"detect_progress"`
	EnableJSON     bool          `json:"enable_json"`
	Compress       bool          `json:"compress"`
	CompressionMin int           `json:"compression_min"`
}

// DefaultOutputStreamConfig returns default streaming configuration
func DefaultOutputStreamConfig() OutputStreamConfig {
	return OutputStreamConfig{
		BufferSize:     64 * 1024, // 64KB buffer
		FlushInterval:  100 * time.Millisecond,
		MaxChunkSize:   32 * 1024, // 32KB max chunk
		EnableANSI:     true,
		FilterANSI:     false,
		DetectProgress: true,
		EnableJSON:     true,
		Compress:       true,
		CompressionMin: 1024, // Compress if > 1KB
	}
}

// BufferedOutputStreamer implements OutputStreamer with buffering and streaming features
type BufferedOutputStreamer struct {
	config     OutputStreamConfig
	outputChan chan StreamOutput
	stopChan   chan struct{}
	wg         sync.WaitGroup
	metrics    StreamMetrics
	mutex      sync.RWMutex

	// Internal state
	buffer    *bytes.Buffer
	lastFlush time.Time
	stopped   bool

	// Patterns for detection
	ansiPattern     *regexp.Regexp
	progressPattern *regexp.Regexp
	jsonPattern     *regexp.Regexp
}

// NewBufferedOutputStreamer creates a new buffered output streamer
func NewBufferedOutputStreamer(config OutputStreamConfig) *BufferedOutputStreamer {
	streamer := &BufferedOutputStreamer{
		config:     config,
		outputChan: make(chan StreamOutput, 100), // Buffered channel
		stopChan:   make(chan struct{}),
		buffer:     &bytes.Buffer{},
		metrics:    StreamMetrics{StartTime: time.Now()},
	}

	// Compile regex patterns
	streamer.ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	streamer.progressPattern = regexp.MustCompile(`(?i)(progress|loading|downloading|installing|building).*?(\d+%|\d+/\d+|\[\#+\s*\])`)
	streamer.jsonPattern = regexp.MustCompile(`^\s*[\{\[].*[\}\]]\s*$`)

	return streamer
}

// StartStreaming begins streaming output from readers
func (s *BufferedOutputStreamer) StartStreaming(ctx context.Context, stdout, stderr io.Reader) error {
	s.mutex.Lock()
	if s.stopped {
		s.mutex.Unlock()
		return fmt.Errorf("streamer is already stopped")
	}
	s.metrics.StartTime = time.Now()
	s.mutex.Unlock()

	// Start flush timer
	s.wg.Add(1)
	go s.flushWorker(ctx)

	// Start streaming goroutines
	if stdout != nil {
		s.wg.Add(1)
		go s.streamReader(ctx, stdout, StreamSourceStdout)
	}

	if stderr != nil {
		s.wg.Add(1)
		go s.streamReader(ctx, stderr, StreamSourceStderr)
	}

	// Start completion monitor
	go s.completionMonitor()

	return nil
}

// GetChannel returns the channel for streaming results
func (s *BufferedOutputStreamer) GetChannel() <-chan StreamOutput {
	return s.outputChan
}

// Stop stops the streaming process
func (s *BufferedOutputStreamer) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.stopped {
		return
	}

	s.stopped = true
	s.metrics.EndTime = time.Now()
	s.metrics.Duration = s.metrics.EndTime.Sub(s.metrics.StartTime)

	close(s.stopChan)
}

// GetMetrics returns streaming performance metrics
func (s *BufferedOutputStreamer) GetMetrics() StreamMetrics {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	metrics := s.metrics
	if !s.stopped && !metrics.StartTime.IsZero() {
		metrics.Duration = time.Since(metrics.StartTime)
	}

	return metrics
}

// streamReader reads from a reader and streams output
func (s *BufferedOutputStreamer) streamReader(ctx context.Context, reader io.Reader, source StreamSource) {
	defer s.wg.Done()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, s.config.BufferSize), s.config.MaxChunkSize)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		line := scanner.Text()
		s.processLine(line, source)
	}

	if err := scanner.Err(); err != nil {
		s.sendOutput(StreamOutput{
			Type:      StreamTypeError,
			Content:   fmt.Sprintf("Scanner error: %v", err),
			Source:    source,
			Timestamp: time.Now(),
			Metadata:  map[string]interface{}{"error": err.Error()},
		})
	}
}

// processLine processes a single line of output
func (s *BufferedOutputStreamer) processLine(line string, source StreamSource) {
	s.mutex.Lock()
	s.metrics.LinesRead++
	s.metrics.BytesRead += int64(len(line))
	s.mutex.Unlock()

	// Filter ANSI codes if requested
	originalLine := line
	if s.config.FilterANSI {
		line = s.ansiPattern.ReplaceAllString(line, "")
		if len(line) != len(originalLine) {
			s.mutex.Lock()
			s.metrics.ANSIFiltered++
			s.mutex.Unlock()
		}
	}

	// Detect different types of content
	outputs := s.analyzeAndTransformLine(line, source)

	// Send all outputs
	for _, output := range outputs {
		s.sendOutput(output)
	}
}

// analyzeAndTransformLine analyzes a line and creates appropriate stream outputs
func (s *BufferedOutputStreamer) analyzeAndTransformLine(line string, source StreamSource) []StreamOutput {
	var outputs []StreamOutput
	timestamp := time.Now()

	// Check for progress indicators
	if s.config.DetectProgress && s.progressPattern.MatchString(line) {
		s.mutex.Lock()
		s.metrics.ProgressDetected++
		s.mutex.Unlock()

		outputs = append(outputs, StreamOutput{
			Type:      StreamTypeProgress,
			Content:   line,
			Source:    source,
			Timestamp: timestamp,
			Metadata: map[string]interface{}{
				"detected": "progress_indicator",
			},
		})
	}

	// Check for JSON content
	if s.config.EnableJSON && s.jsonPattern.MatchString(line) {
		if s.isValidJSON(line) {
			outputs = append(outputs, StreamOutput{
				Type:      StreamTypeJSON,
				Content:   line,
				Source:    source,
				Timestamp: timestamp,
				Metadata: map[string]interface{}{
					"format": "json",
				},
			})
		}
	}

	// Always send as regular data output
	content := line
	metadata := map[string]interface{}{
		"raw_length": len(line),
	}

	// Apply compression if enabled and content is large enough
	if s.config.Compress && len(content) >= s.config.CompressionMin {
		if compressed, err := s.compressContent(content); err == nil {
			compressionRatio := float64(len(compressed)) / float64(len(content))
			if compressionRatio < 0.8 { // Only use if significant compression
				metadata["compressed"] = true
				metadata["compression_ratio"] = compressionRatio
				metadata["original_size"] = len(content)
				content = compressed

				s.mutex.Lock()
				s.metrics.CompressionSaved += int64(len(line) - len(compressed))
				s.mutex.Unlock()
			}
		}
	}

	outputs = append(outputs, StreamOutput{
		Type:      StreamTypeData,
		Content:   content,
		Source:    source,
		Timestamp: timestamp,
		Metadata:  metadata,
	})

	return outputs
}

// sendOutput sends an output to the channel
func (s *BufferedOutputStreamer) sendOutput(output StreamOutput) {
	select {
	case s.outputChan <- output:
		s.mutex.Lock()
		s.metrics.ChunksStreamed++
		s.mutex.Unlock()
	case <-s.stopChan:
		return
	default:
		// Channel is full, increment overflow counter
		s.mutex.Lock()
		s.metrics.BufferOverflows++
		s.mutex.Unlock()

		log.Warn().Msg("Output channel is full, dropping output")
	}
}

// flushWorker periodically flushes buffered content
func (s *BufferedOutputStreamer) flushWorker(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.flushBuffer()
			return
		case <-s.stopChan:
			s.flushBuffer()
			return
		case <-ticker.C:
			s.flushBuffer()
		}
	}
}

// flushBuffer flushes any buffered content
func (s *BufferedOutputStreamer) flushBuffer() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.buffer.Len() == 0 {
		return
	}

	content := s.buffer.String()
	s.buffer.Reset()
	s.lastFlush = time.Now()
	s.metrics.FlushCount++

	// Send buffered content
	select {
	case s.outputChan <- StreamOutput{
		Type:      StreamTypeData,
		Content:   content,
		Source:    StreamSourceSystem,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"source": "buffer_flush",
			"size":   len(content),
		},
	}:
		s.metrics.ChunksStreamed++
	case <-s.stopChan:
		return
	default:
		s.metrics.BufferOverflows++
	}
}

// completionMonitor monitors for completion and sends final message
func (s *BufferedOutputStreamer) completionMonitor() {
	s.wg.Wait() // Wait for all streaming goroutines to complete

	// Send completion signal
	s.sendOutput(StreamOutput{
		Type:      StreamTypeComplete,
		Content:   "Streaming completed",
		Source:    StreamSourceSystem,
		Timestamp: time.Now(),
		Metadata: map[string]interface{}{
			"metrics": s.GetMetrics(),
		},
	})

	// Close output channel
	close(s.outputChan)
}

// compressContent compresses content using gzip
func (s *BufferedOutputStreamer) compressContent(content string) (string, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)

	if _, err := writer.Write([]byte(content)); err != nil {
		return "", err
	}

	if err := writer.Close(); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// isValidJSON checks if a string is valid JSON
func (s *BufferedOutputStreamer) isValidJSON(str string) bool {
	var js interface{}
	return json.Unmarshal([]byte(str), &js) == nil
}

// SimpleOutputStreamer is a basic implementation for simple use cases
type SimpleOutputStreamer struct {
	outputChan chan StreamOutput
	stopChan   chan struct{}
	metrics    StreamMetrics
	mutex      sync.RWMutex
	stopped    bool
}

// NewSimpleOutputStreamer creates a new simple output streamer
func NewSimpleOutputStreamer() *SimpleOutputStreamer {
	return &SimpleOutputStreamer{
		outputChan: make(chan StreamOutput, 50),
		stopChan:   make(chan struct{}),
		metrics:    StreamMetrics{StartTime: time.Now()},
	}
}

// StartStreaming begins streaming output from readers
func (s *SimpleOutputStreamer) StartStreaming(ctx context.Context, stdout, stderr io.Reader) error {
	s.mutex.Lock()
	if s.stopped {
		s.mutex.Unlock()
		return fmt.Errorf("streamer is already stopped")
	}
	s.metrics.StartTime = time.Now()
	s.mutex.Unlock()

	// Simple line-by-line streaming
	if stdout != nil {
		go s.simpleStream(ctx, stdout, StreamSourceStdout)
	}

	if stderr != nil {
		go s.simpleStream(ctx, stderr, StreamSourceStderr)
	}

	return nil
}

// GetChannel returns the channel for streaming results
func (s *SimpleOutputStreamer) GetChannel() <-chan StreamOutput {
	return s.outputChan
}

// Stop stops the streaming process
func (s *SimpleOutputStreamer) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.stopped {
		return
	}

	s.stopped = true
	s.metrics.EndTime = time.Now()
	s.metrics.Duration = s.metrics.EndTime.Sub(s.metrics.StartTime)

	close(s.stopChan)
	close(s.outputChan)
}

// GetMetrics returns streaming performance metrics
func (s *SimpleOutputStreamer) GetMetrics() StreamMetrics {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	metrics := s.metrics
	if !s.stopped && !metrics.StartTime.IsZero() {
		metrics.Duration = time.Since(metrics.StartTime)
	}

	return metrics
}

// simpleStream performs simple line-by-line streaming
func (s *SimpleOutputStreamer) simpleStream(ctx context.Context, reader io.Reader, source StreamSource) {
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		default:
		}

		line := scanner.Text()

		s.mutex.Lock()
		s.metrics.LinesRead++
		s.metrics.BytesRead += int64(len(line))
		s.mutex.Unlock()

		select {
		case s.outputChan <- StreamOutput{
			Type:      StreamTypeData,
			Content:   line,
			Source:    source,
			Timestamp: time.Now(),
			Metadata:  map[string]interface{}{"simple": true},
		}:
			s.mutex.Lock()
			s.metrics.ChunksStreamed++
			s.mutex.Unlock()
		case <-s.stopChan:
			return
		default:
			s.mutex.Lock()
			s.metrics.BufferOverflows++
			s.mutex.Unlock()
		}
	}

	if err := scanner.Err(); err != nil {
		select {
		case s.outputChan <- StreamOutput{
			Type:      StreamTypeError,
			Content:   fmt.Sprintf("Scanner error: %v", err),
			Source:    source,
			Timestamp: time.Now(),
			Metadata:  map[string]interface{}{"error": err.Error()},
		}:
		case <-s.stopChan:
		default:
		}
	}
}

// StreamCollector collects streaming output for later analysis
type StreamCollector struct {
	outputs []StreamOutput
	mutex   sync.RWMutex
}

// NewStreamCollector creates a new stream collector
func NewStreamCollector() *StreamCollector {
	return &StreamCollector{
		outputs: make([]StreamOutput, 0),
	}
}

// Collect collects output from a streamer
func (sc *StreamCollector) Collect(ctx context.Context, streamer OutputStreamer) error {
	outputChan := streamer.GetChannel()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case output, ok := <-outputChan:
			if !ok {
				return nil // Channel closed
			}

			sc.mutex.Lock()
			sc.outputs = append(sc.outputs, output)
			sc.mutex.Unlock()
		}
	}
}

// GetOutputs returns all collected outputs
func (sc *StreamCollector) GetOutputs() []StreamOutput {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	// Return a copy to prevent modification
	outputs := make([]StreamOutput, len(sc.outputs))
	copy(outputs, sc.outputs)
	return outputs
}

// GetOutputsByType returns outputs filtered by type
func (sc *StreamCollector) GetOutputsByType(streamType StreamType) []StreamOutput {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	var filtered []StreamOutput
	for _, output := range sc.outputs {
		if output.Type == streamType {
			filtered = append(filtered, output)
		}
	}

	return filtered
}

// GetCombinedContent returns all content combined as a single string
func (sc *StreamCollector) GetCombinedContent(source StreamSource) string {
	sc.mutex.RLock()
	defer sc.mutex.RUnlock()

	var builder strings.Builder
	for _, output := range sc.outputs {
		if source == "" || output.Source == source {
			if output.Type == StreamTypeData || output.Type == StreamTypeJSON {
				builder.WriteString(output.Content)
				if !strings.HasSuffix(output.Content, "\n") {
					builder.WriteString("\n")
				}
			}
		}
	}

	return builder.String()
}

// Clear clears all collected outputs
func (sc *StreamCollector) Clear() {
	sc.mutex.Lock()
	defer sc.mutex.Unlock()

	sc.outputs = sc.outputs[:0] // Keep allocated capacity
}
