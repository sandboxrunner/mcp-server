package tools

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Benchmark comprehensive integration tests
func BenchmarkEnhancedExecCommand_Integration(b *testing.B) {
	// This would require a full sandbox setup, so we'll benchmark individual components
	b.Skip("Integration benchmark requires full sandbox environment")
}

// Benchmark CommandEnvironment operations
func BenchmarkCommandEnvironment_PrepareEnvironment(b *testing.B) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		BaseEnvironment: map[string]string{
			"PATH":  "/usr/local/bin:/usr/bin:/bin",
			"HOME":  "/root",
			"USER":  "root",
			"SHELL": "/bin/bash",
		},
		ExpandVariables: true,
		FilterSensitive: true,
	})
	if err != nil {
		b.Fatalf("Failed to create environment: %v", err)
	}

	languages := []string{"python", "javascript", "go", "rust", "java", "c", "cpp", "ruby"}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		lang := languages[i%len(languages)]
		_, err := env.PrepareEnvironmentForLanguage(lang)
		if err != nil {
			b.Errorf("PrepareEnvironmentForLanguage() error: %v", err)
		}
	}
}

func BenchmarkCommandEnvironment_VariableExpansion(b *testing.B) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		BaseEnvironment: map[string]string{
			"BASE_PATH":  "/usr/local/bin",
			"HOME":       "/root",
			"USER":       "root",
			"WORKSPACE":  "/workspace",
			"PROJECT":    "/workspace/project",
			"BUILD_DIR":  "${PROJECT}/build",
			"OUTPUT_DIR": "${BUILD_DIR}/output",
		},
		ExpandVariables: true,
	})
	if err != nil {
		b.Fatalf("Failed to create environment: %v", err)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := env.PrepareEnvironmentForLanguage("")
		if err != nil {
			b.Errorf("PrepareEnvironmentForLanguage() error: %v", err)
		}
	}
}

// Benchmark OutputStreamer performance
func BenchmarkBufferedOutputStreamer_LargeOutput(b *testing.B) {
	// Create large test data
	lineData := strings.Repeat("This is a benchmark test line with some decent length to test performance\n", 1000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		config := DefaultOutputStreamConfig()
		streamer := NewBufferedOutputStreamer(config)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stdout := strings.NewReader(lineData)

		streamer.StartStreaming(ctx, stdout, nil)

		// Consume all output
		outputChan := streamer.GetChannel()
		for range outputChan {
			// Just consume
		}

		streamer.Stop()
		cancel()
	}
}

func BenchmarkBufferedOutputStreamer_ANSIFiltering(b *testing.B) {
	// Create test data with ANSI codes
	ansiData := "\x1b[31mRed text\x1b[0m\n\x1b[1;32mBold green\x1b[0m\n\x1b[33mYellow\x1b[0m\n"
	testData := strings.Repeat(ansiData, 500)

	config := DefaultOutputStreamConfig()
	config.FilterANSI = true

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		streamer := NewBufferedOutputStreamer(config)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stdout := strings.NewReader(testData)

		streamer.StartStreaming(ctx, stdout, nil)

		// Consume all output
		outputChan := streamer.GetChannel()
		for range outputChan {
			// Just consume
		}

		streamer.Stop()
		cancel()
	}
}

func BenchmarkBufferedOutputStreamer_ProgressDetection(b *testing.B) {
	// Create test data with progress indicators
	progressData := "Downloading file... 10%\nProgress: [##        ] 20%\nInstalling... 50%\nBuilding project 75%\nComplete 100%\n"
	testData := strings.Repeat(progressData, 200)

	config := DefaultOutputStreamConfig()
	config.DetectProgress = true

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		streamer := NewBufferedOutputStreamer(config)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stdout := strings.NewReader(testData)

		streamer.StartStreaming(ctx, stdout, nil)

		// Consume all output
		outputChan := streamer.GetChannel()
		for range outputChan {
			// Just consume
		}

		streamer.Stop()
		cancel()
	}
}

func BenchmarkBufferedOutputStreamer_JSONDetection(b *testing.B) {
	// Create test data with JSON
	jsonData := `{"message": "Processing item", "progress": 25, "status": "in_progress"}
{"message": "Item processed", "progress": 50, "status": "success"}
{"message": "Processing batch", "progress": 75, "status": "in_progress"}
{"message": "Batch complete", "progress": 100, "status": "success"}
`
	testData := strings.Repeat(jsonData, 250)

	config := DefaultOutputStreamConfig()
	config.EnableJSON = true

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		streamer := NewBufferedOutputStreamer(config)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stdout := strings.NewReader(testData)

		streamer.StartStreaming(ctx, stdout, nil)

		// Consume all output
		outputChan := streamer.GetChannel()
		for range outputChan {
			// Just consume
		}

		streamer.Stop()
		cancel()
	}
}

// Benchmark StreamCollector performance
func BenchmarkStreamCollector_LargeCollection(b *testing.B) {
	testData := strings.Repeat("Benchmark line for collection testing\n", 1000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		streamer := NewSimpleOutputStreamer()
		collector := NewStreamCollector()

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		stdout := strings.NewReader(testData)

		streamer.StartStreaming(ctx, stdout, nil)

		collectCtx, collectCancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(100 * time.Millisecond)
			streamer.Stop()
			collectCancel()
		}()

		collector.Collect(collectCtx, streamer)
		cancel()

		// Measure collection operations
		_ = collector.GetOutputs()
		_ = collector.GetCombinedContent(StreamSourceStdout)
		_ = collector.GetOutputsByType(StreamTypeData)
	}
}

// Performance comparison tests
func BenchmarkOutputStreamer_Comparison(b *testing.B) {
	testData := strings.Repeat("Performance comparison test line\n", 500)

	b.Run("BufferedStreamer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			config := DefaultOutputStreamConfig()
			streamer := NewBufferedOutputStreamer(config)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			stdout := strings.NewReader(testData)

			streamer.StartStreaming(ctx, stdout, nil)
			for range streamer.GetChannel() {
				// Consume
			}
			streamer.Stop()
			cancel()
		}
	})

	b.Run("SimpleStreamer", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			streamer := NewSimpleOutputStreamer()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			stdout := strings.NewReader(testData)

			streamer.StartStreaming(ctx, stdout, nil)
			time.Sleep(50 * time.Millisecond) // Give time for streaming
			streamer.Stop()

			for range streamer.GetChannel() {
				// Consume
			}
			cancel()
		}
	})
}

// Memory usage benchmarks
func BenchmarkCommandEnvironment_MemoryUsage(b *testing.B) {
	b.Run("BasicEnvironment", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			env, err := NewCommandEnvironment(EnvironmentOptions{
				BaseEnvironment: map[string]string{
					"PATH": "/usr/bin:/bin",
					"HOME": "/root",
				},
			})
			if err != nil {
				b.Fatalf("Failed to create environment: %v", err)
			}
			_ = env
		}
	})

	b.Run("LargeEnvironment", func(b *testing.B) {
		b.ReportAllocs()
		largeEnv := make(map[string]string, 100)
		for i := 0; i < 100; i++ {
			largeEnv[fmt.Sprintf("VAR_%d", i)] = fmt.Sprintf("value_%d", i)
		}

		for i := 0; i < b.N; i++ {
			env, err := NewCommandEnvironment(EnvironmentOptions{
				BaseEnvironment: largeEnv,
			})
			if err != nil {
				b.Fatalf("Failed to create environment: %v", err)
			}
			_ = env
		}
	})
}

func BenchmarkOutputStreamer_MemoryUsage(b *testing.B) {
	testData := strings.Repeat("Memory usage test line\n", 1000)

	b.Run("BufferedStreamer", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			config := DefaultOutputStreamConfig()
			streamer := NewBufferedOutputStreamer(config)

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			stdout := strings.NewReader(testData)

			streamer.StartStreaming(ctx, stdout, nil)
			for range streamer.GetChannel() {
				// Consume
			}
			streamer.Stop()
			cancel()
		}
	})
}

// Concurrent performance tests
func BenchmarkCommandEnvironment_Concurrent(b *testing.B) {
	env, err := NewCommandEnvironment(EnvironmentOptions{
		BaseEnvironment: map[string]string{
			"PATH": "/usr/bin:/bin",
			"HOME": "/root",
		},
	})
	if err != nil {
		b.Fatalf("Failed to create environment: %v", err)
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		languages := []string{"python", "javascript", "go", "rust"}
		i := 0
		for pb.Next() {
			lang := languages[i%len(languages)]
			_, err := env.PrepareEnvironmentForLanguage(lang)
			if err != nil {
				b.Errorf("PrepareEnvironmentForLanguage() error: %v", err)
			}
			i++
		}
	})
}

func BenchmarkOutputStreamer_Concurrent(b *testing.B) {
	testData := strings.Repeat("Concurrent test line\n", 100)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			streamer := NewSimpleOutputStreamer()

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			stdout := strings.NewReader(testData)

			streamer.StartStreaming(ctx, stdout, nil)
			time.Sleep(10 * time.Millisecond)
			streamer.Stop()

			for range streamer.GetChannel() {
				// Consume
			}
			cancel()
		}
	})
}

// Throughput benchmarks
func BenchmarkOutputStreamer_Throughput(b *testing.B) {
	sizes := []int{100, 1000, 10000, 100000}

	for _, size := range sizes {
		testData := strings.Repeat("Throughput test line\n", size)

		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			b.SetBytes(int64(len(testData)))

			for i := 0; i < b.N; i++ {
				config := DefaultOutputStreamConfig()
				streamer := NewBufferedOutputStreamer(config)

				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				stdout := strings.NewReader(testData)

				start := time.Now()
				streamer.StartStreaming(ctx, stdout, nil)

				lineCount := 0
				for output := range streamer.GetChannel() {
					if output.Type == StreamTypeData {
						lineCount++
					}
					if output.Type == StreamTypeComplete {
						break
					}
				}

				duration := time.Since(start)
				b.ReportMetric(float64(lineCount)/duration.Seconds(), "lines/sec")

				streamer.Stop()
				cancel()
			}
		})
	}
}

// Configuration impact benchmarks
func BenchmarkOutputStreamer_ConfigImpact(b *testing.B) {
	testData := strings.Repeat("Config impact test line with ANSI \x1b[31mcolors\x1b[0m\n", 500)

	configs := map[string]OutputStreamConfig{
		"Minimal": {
			BufferSize:     1024,
			FlushInterval:  100 * time.Millisecond,
			MaxChunkSize:   512,
			EnableANSI:     false,
			FilterANSI:     false,
			DetectProgress: false,
			EnableJSON:     false,
			Compress:       false,
		},
		"Full": {
			BufferSize:     64 * 1024,
			FlushInterval:  50 * time.Millisecond,
			MaxChunkSize:   32 * 1024,
			EnableANSI:     true,
			FilterANSI:     true,
			DetectProgress: true,
			EnableJSON:     true,
			Compress:       true,
			CompressionMin: 1024,
		},
	}

	for name, config := range configs {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				streamer := NewBufferedOutputStreamer(config)

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				stdout := strings.NewReader(testData)

				streamer.StartStreaming(ctx, stdout, nil)
				for range streamer.GetChannel() {
					// Consume
				}
				streamer.Stop()
				cancel()
			}
		})
	}
}

// Stress tests
func BenchmarkSystem_StressTest(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping stress test in short mode")
	}

	// Test with very large data and concurrent operations
	b.Run("LargeDataConcurrent", func(b *testing.B) {
		largeData := strings.Repeat("Stress test line with various content and patterns\n", 10000)

		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				// Create environment
				env, err := NewCommandEnvironment(EnvironmentOptions{
					BaseEnvironment: map[string]string{
						"PATH": "/usr/local/bin:/usr/bin:/bin",
						"HOME": "/root",
						"USER": "root",
					},
					ExpandVariables: true,
				})
				if err != nil {
					b.Errorf("Failed to create environment: %v", err)
					continue
				}

				// Prepare environment for random language
				languages := []string{"python", "javascript", "go", "rust"}
				lang := languages[b.N%len(languages)]
				_, err = env.PrepareEnvironmentForLanguage(lang)
				if err != nil {
					b.Errorf("Failed to prepare environment: %v", err)
				}

				// Stream large data
				config := DefaultOutputStreamConfig()
				streamer := NewBufferedOutputStreamer(config)

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				stdout := strings.NewReader(largeData)

				streamer.StartStreaming(ctx, stdout, nil)

				// Collect with timeout
				collector := NewStreamCollector()
				collectCtx, collectCancel := context.WithTimeout(ctx, 5*time.Second)

				go func() {
					collector.Collect(collectCtx, streamer)
					collectCancel()
				}()

				// Wait for completion or timeout
				select {
				case <-collectCtx.Done():
				case <-time.After(5 * time.Second):
				}

				streamer.Stop()
				cancel()

				// Verify we got some data
				outputs := collector.GetOutputs()
				if len(outputs) == 0 {
					b.Error("No outputs collected in stress test")
				}
			}
		})
	})
}
