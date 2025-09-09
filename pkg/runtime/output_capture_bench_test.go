package runtime

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func BenchmarkRingBuffer_Write(b *testing.B) {
	rb := NewRingBuffer(1024 * 1024) // 1MB buffer
	data := bytes.Repeat([]byte("x"), 1024) // 1KB chunks

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rb.Write(data)
	}
}

func BenchmarkRingBuffer_Read(b *testing.B) {
	rb := NewRingBuffer(1024 * 1024) // 1MB buffer
	data := bytes.Repeat([]byte("x"), 1024) // 1KB chunks

	// Fill the buffer
	for i := 0; i < 1000; i++ {
		rb.Write(data)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rb.Read()
	}
}

func BenchmarkRingBuffer_ConcurrentWriteRead(b *testing.B) {
	rb := NewRingBuffer(1024 * 1024) // 1MB buffer
	data := bytes.Repeat([]byte("x"), 100) // 100 byte chunks

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Alternate between write and read
			if rb.Size() < rb.maxSize/2 {
				rb.Write(data)
			} else {
				rb.Read()
			}
		}
	})
}

func BenchmarkOutputCapture_SmallOutput(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = false
	config.CompressionEnabled = false

	data := []byte("small output data\n")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		stdoutReader := bytes.NewReader(data)
		oc.CaptureStreams(ctx, stdoutReader, nil)
		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

func BenchmarkOutputCapture_LargeOutput(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = false
	config.CompressionEnabled = false

	// 100KB of data
	data := bytes.Repeat([]byte("large output data line\n"), 4347)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		stdoutReader := bytes.NewReader(data)
		oc.CaptureStreams(ctx, stdoutReader, nil)
		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

func BenchmarkOutputCapture_Streaming(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = true
	config.FlushInterval = time.Millisecond

	data := []byte("streaming data chunk\n")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)

		stdoutReader := bytes.NewReader(data)
		oc.CaptureStreams(ctx, stdoutReader, nil)
		
		// Consume streaming data
		stdoutChan := oc.GetStdoutChannel()
		go func() {
			for range stdoutChan {
				// Consume all data
			}
		}()

		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

func BenchmarkOutputCapture_Compression(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.CompressionEnabled = true
	config.CompressionThreshold = 1024 // 1KB threshold

	// Create compressible data (10KB)
	data := bytes.Repeat([]byte("this is compressible data that repeats many times\n"), 204)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		stdoutReader := bytes.NewReader(data)
		oc.CaptureStreams(ctx, stdoutReader, nil)
		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

func BenchmarkOutputCapture_ANSIProcessing(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.ProcessANSI = true
	config.CompressionEnabled = false

	// Create data with ANSI codes
	data := []byte("\x1b[31mRed text\x1b[0m \x1b[32mGreen text\x1b[0m \x1b[1mBold text\x1b[0m\n")
	largeData := bytes.Repeat(data, 1000) // Repeat 1000 times

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		stdoutReader := bytes.NewReader(largeData)
		oc.CaptureStreams(ctx, stdoutReader, nil)
		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

func BenchmarkOutputCapture_MultiStream(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = false
	config.CompressionEnabled = false

	stdoutData := bytes.Repeat([]byte("stdout line\n"), 1000)
	stderrData := bytes.Repeat([]byte("stderr line\n"), 1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		stdoutReader := bytes.NewReader(stdoutData)
		stderrReader := bytes.NewReader(stderrData)
		oc.CaptureStreams(ctx, stdoutReader, stderrReader)
		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

func BenchmarkFormatOutput_StripANSI(b *testing.B) {
	fo := &FormatOutput{}
	
	// Create data with many ANSI codes
	data := bytes.Repeat([]byte("\x1b[31mRed\x1b[0m \x1b[32mGreen\x1b[0m \x1b[1mBold\x1b[0m text "), 1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		fo.StripANSI(data)
	}
}

func BenchmarkFormatOutput_TruncateOutput(b *testing.B) {
	fo := &FormatOutput{}
	
	data := bytes.Repeat([]byte("this is a long line of text that needs truncation "), 1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		fo.TruncateOutput(data, 1000)
	}
}

func BenchmarkFormatOutput_SplitLines(b *testing.B) {
	fo := &FormatOutput{}
	
	// Create data with many lines
	data := bytes.Repeat([]byte("line of text\n"), 1000)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		fo.SplitLines(data)
	}
}

// Memory usage benchmarks

func BenchmarkOutputCapture_MemoryUsage_SmallBuffer(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.MaxBufferSize = 1024 // 1KB buffer
	config.CompressionEnabled = false

	// Create 10KB data to test memory usage with small buffer
	data := bytes.Repeat([]byte("test data line\n"), 666)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		stdoutReader := bytes.NewReader(data)
		oc.CaptureStreams(ctx, stdoutReader, nil)
		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

func BenchmarkOutputCapture_MemoryUsage_LargeBuffer(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.MaxBufferSize = 10 * 1024 * 1024 // 10MB buffer
	config.CompressionEnabled = false

	// Create 1MB data
	data := bytes.Repeat([]byte("test data line\n"), 66666)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		stdoutReader := bytes.NewReader(data)
		oc.CaptureStreams(ctx, stdoutReader, nil)
		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

// Throughput benchmarks

func BenchmarkOutputCapture_Throughput_1KB(b *testing.B) {
	benchmarkThroughput(b, 1024) // 1KB
}

func BenchmarkOutputCapture_Throughput_10KB(b *testing.B) {
	benchmarkThroughput(b, 10*1024) // 10KB
}

func BenchmarkOutputCapture_Throughput_100KB(b *testing.B) {
	benchmarkThroughput(b, 100*1024) // 100KB
}

func BenchmarkOutputCapture_Throughput_1MB(b *testing.B) {
	benchmarkThroughput(b, 1024*1024) // 1MB
}

func benchmarkThroughput(b *testing.B, dataSize int) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = false
	config.CompressionEnabled = false

	data := bytes.Repeat([]byte("x"), dataSize)

	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		stdoutReader := bytes.NewReader(data)
		oc.CaptureStreams(ctx, stdoutReader, nil)
		oc.Wait()
		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

// Concurrent benchmarks

func BenchmarkOutputCapture_Concurrent_SmallData(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = false
	config.CompressionEnabled = false

	data := []byte("concurrent test data\n")

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			oc := NewOutputCapture(config)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)

			stdoutReader := bytes.NewReader(data)
			oc.CaptureStreams(ctx, stdoutReader, nil)
			oc.Wait()
			_ = oc.GetOutput()

			oc.Close()
			cancel()
		}
	})
}

func BenchmarkOutputCapture_Concurrent_LargeData(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = false
	config.CompressionEnabled = false

	// 10KB data
	data := bytes.Repeat([]byte("concurrent test data line\n"), 400)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			oc := NewOutputCapture(config)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)

			stdoutReader := bytes.NewReader(data)
			oc.CaptureStreams(ctx, stdoutReader, nil)
			oc.Wait()
			_ = oc.GetOutput()

			oc.Close()
			cancel()
		}
	})
}

// Streaming performance benchmarks

func BenchmarkOutputCapture_StreamingThroughput(b *testing.B) {
	config := DefaultOutputCaptureConfig()
	config.StreamingEnabled = true
	config.FlushInterval = time.Microsecond // Very frequent flushing

	data := bytes.Repeat([]byte("streaming test data\n"), 100)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		oc := NewOutputCapture(config)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)

		// Use a pipe to simulate real-time data
		stdoutReader, stdoutWriter := io.Pipe()

		oc.CaptureStreams(ctx, stdoutReader, nil)

		// Get streaming channel and consume data
		stdoutChan := oc.GetStdoutChannel()
		consumeComplete := make(chan struct{})

		go func() {
			for range stdoutChan {
				// Consume all streamed data
			}
			close(consumeComplete)
		}()

		// Write data and close
		go func() {
			stdoutWriter.Write(data)
			stdoutWriter.Close()
		}()

		oc.Wait()
		<-consumeComplete

		_ = oc.GetOutput()

		oc.Close()
		cancel()
	}
}

// BenchmarkResults shows how to interpret benchmark results:
//
// Example output:
// BenchmarkRingBuffer_Write-8         	10000000	       150 ns/op	       0 B/op	       0 allocs/op
// This means:
// - Function: BenchmarkRingBuffer_Write
// - CPU cores: 8
// - Iterations: 10,000,000
// - Time per operation: 150 nanoseconds
// - Memory allocated per operation: 0 bytes
// - Allocations per operation: 0
//
// For throughput benchmarks, you'll see additional MB/s metric:
// BenchmarkOutputCapture_Throughput_1MB-8   	100	  10000000 ns/op	 104.86 MB/s
//
// Good performance indicators:
// - Low ns/op (nanoseconds per operation)
// - Low B/op (bytes per operation) - indicates minimal memory allocation
// - Low allocs/op - indicates minimal garbage collection pressure
// - High MB/s for throughput benchmarks