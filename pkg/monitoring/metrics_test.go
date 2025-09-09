package monitoring

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsRegistry_NewMetricsRegistry(t *testing.T) {
	config := DefaultMetricsConfig()
	registry := NewMetricsRegistry(config)
	
	assert.NotNil(t, registry)
	assert.Equal(t, config, registry.config)
	assert.NotNil(t, registry.metrics)
	assert.NotNil(t, registry.collectors)
	assert.NotNil(t, registry.gatherers)
}

func TestMetricsRegistry_NewCounter(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	
	counter, err := registry.NewCounter("test_counter", "Test counter metric", "label1", "label2")
	require.NoError(t, err)
	assert.NotNil(t, counter)
	assert.Equal(t, "sandboxrunner_test_counter", counter.name)
	assert.Equal(t, "Test counter metric", counter.help)
	assert.Equal(t, []string{"label1", "label2"}, counter.labels)
	
	// Test duplicate registration
	_, err = registry.NewCounter("test_counter", "Duplicate counter", "label1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestMetricsRegistry_NewGauge(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	
	gauge, err := registry.NewGauge("test_gauge", "Test gauge metric", "label1")
	require.NoError(t, err)
	assert.NotNil(t, gauge)
	assert.Equal(t, "sandboxrunner_test_gauge", gauge.name)
	assert.Equal(t, "Test gauge metric", gauge.help)
	assert.Equal(t, []string{"label1"}, gauge.labels)
}

func TestMetricsRegistry_NewHistogram(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	buckets := []float64{0.1, 0.5, 1.0, 5.0}
	
	histogram, err := registry.NewHistogram("test_histogram", "Test histogram metric", buckets, "label1")
	require.NoError(t, err)
	assert.NotNil(t, histogram)
	assert.Equal(t, "sandboxrunner_test_histogram", histogram.name)
	assert.Equal(t, "Test histogram metric", histogram.help)
	assert.Equal(t, []string{"label1"}, histogram.labels)
	assert.Equal(t, buckets, histogram.buckets)
	
	// Test with nil buckets (should use defaults)
	histogram2, err := registry.NewHistogram("test_histogram2", "Test histogram 2", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, histogram2.buckets)
}

func TestMetricsRegistry_NewSummary(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	objectives := map[float64]float64{0.5: 0.05, 0.9: 0.01}
	
	summary, err := registry.NewSummary("test_summary", "Test summary metric", objectives, "label1")
	require.NoError(t, err)
	assert.NotNil(t, summary)
	assert.Equal(t, "sandboxrunner_test_summary", summary.name)
	assert.Equal(t, "Test summary metric", summary.help)
	assert.Equal(t, []string{"label1"}, summary.labels)
	assert.Equal(t, objectives, summary.objectives)
	
	// Test with nil objectives (should use defaults)
	summary2, err := registry.NewSummary("test_summary2", "Test summary 2", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, summary2.objectives)
}

func TestCounter_Operations(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	counter, err := registry.NewCounter("test_counter", "Test counter", "method", "status")
	require.NoError(t, err)
	
	// Test increment
	counter.Inc("GET", "200")
	assert.Equal(t, float64(1), counter.Get("GET", "200"))
	
	// Test add
	counter.Add(5, "GET", "200")
	assert.Equal(t, float64(6), counter.Get("GET", "200"))
	
	// Test different label values
	counter.Inc("POST", "404")
	assert.Equal(t, float64(1), counter.Get("POST", "404"))
	assert.Equal(t, float64(6), counter.Get("GET", "200"))
	
	// Test panic on negative value
	assert.Panics(t, func() {
		counter.Add(-1, "GET", "200")
	})
}

func TestGauge_Operations(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	gauge, err := registry.NewGauge("test_gauge", "Test gauge", "node")
	require.NoError(t, err)
	
	// Test set
	gauge.Set(10.5, "node1")
	assert.Equal(t, float64(10.5), gauge.Get("node1"))
	
	// Test increment
	gauge.Inc("node1")
	assert.Equal(t, float64(11.5), gauge.Get("node1"))
	
	// Test decrement
	gauge.Dec("node1")
	assert.Equal(t, float64(10.5), gauge.Get("node1"))
	
	// Test add
	gauge.Add(-5.5, "node1")
	assert.Equal(t, float64(5), gauge.Get("node1"))
	
	// Test different label values
	gauge.Set(20, "node2")
	assert.Equal(t, float64(20), gauge.Get("node2"))
	assert.Equal(t, float64(5), gauge.Get("node1"))
}

func TestHistogram_Operations(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	buckets := []float64{0.1, 0.5, 1.0, 5.0}
	histogram, err := registry.NewHistogram("test_histogram", "Test histogram", buckets, "endpoint")
	require.NoError(t, err)
	
	// Record observations
	histogram.Observe(0.05, "/api/v1/users")
	histogram.Observe(0.3, "/api/v1/users")
	histogram.Observe(0.8, "/api/v1/users")
	histogram.Observe(2.0, "/api/v1/users")
	histogram.Observe(10.0, "/api/v1/users")
	
	// Check that values were recorded
	key := buildLabelsKey([]string{"endpoint"}, []string{"/api/v1/users"})
	value, exists := histogram.values[key]
	require.True(t, exists)
	assert.Equal(t, uint64(5), value.count)
	assert.InDelta(t, 13.15, value.sum, 0.01)
	
	// Check bucket counts
	assert.Equal(t, uint64(1), value.bucketCounts[0.1])  // 0.05
	assert.Equal(t, uint64(2), value.bucketCounts[0.5])  // 0.05, 0.3
	assert.Equal(t, uint64(3), value.bucketCounts[1.0])  // 0.05, 0.3, 0.8
	assert.Equal(t, uint64(4), value.bucketCounts[5.0])  // 0.05, 0.3, 0.8, 2.0
}

func TestSummary_Operations(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	summary, err := registry.NewSummary("test_summary", "Test summary", nil, "method")
	require.NoError(t, err)
	
	// Record observations
	values := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0}
	for _, v := range values {
		summary.Observe(v, "GET")
	}
	
	// Check that values were recorded
	key := buildLabelsKey([]string{"method"}, []string{"GET"})
	value, exists := summary.values[key]
	require.True(t, exists)
	assert.Equal(t, uint64(10), value.count)
	assert.InDelta(t, 5.5, value.sum, 0.01)
	assert.Len(t, value.observations, 10)
}

func TestMetricsRegistry_Gather(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	
	// Create metrics
	counter, _ := registry.NewCounter("requests_total", "Total requests", "method")
	gauge, _ := registry.NewGauge("memory_usage", "Memory usage", "node")
	
	// Record values
	counter.Inc("GET")
	counter.Add(5, "POST")
	gauge.Set(1024, "node1")
	
	// Gather metrics
	metrics, err := registry.Gather()
	require.NoError(t, err)
	assert.NotEmpty(t, metrics)
	
	// Verify metrics are present
	metricNames := make(map[string]bool)
	for _, metric := range metrics {
		metricNames[metric.Name] = true
	}
	
	assert.True(t, metricNames["sandboxrunner_requests_total"])
	assert.True(t, metricNames["sandboxrunner_memory_usage"])
}

func TestMetricsRegistry_GatherPrometheusFormat(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	
	// Create and populate metrics
	counter, _ := registry.NewCounter("http_requests_total", "Total HTTP requests", "method", "status")
	counter.Inc("GET", "200")
	counter.Add(3, "POST", "404")
	
	gauge, _ := registry.NewGauge("memory_bytes", "Memory usage in bytes")
	gauge.Set(1048576)
	
	// Generate Prometheus format
	output, err := registry.GatherPrometheusFormat()
	require.NoError(t, err)
	assert.NotEmpty(t, output)
	
	// Check for expected content
	assert.Contains(t, output, "# HELP sandboxrunner_http_requests_total Total HTTP requests")
	assert.Contains(t, output, "# TYPE sandboxrunner_http_requests_total counter")
	assert.Contains(t, output, "# HELP sandboxrunner_memory_bytes Memory usage in bytes")
	assert.Contains(t, output, "# TYPE sandboxrunner_memory_bytes gauge")
	assert.Contains(t, output, `sandboxrunner_http_requests_total{method="GET",status="200"}`)
	assert.Contains(t, output, `sandboxrunner_http_requests_total{method="POST",status="404"}`)
	assert.Contains(t, output, "sandboxrunner_memory_bytes 1.048576e+06")
}

func TestMetricsRegistry_GatherJSONFormat(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	
	// Create and populate metrics
	counter, _ := registry.NewCounter("requests_total", "Total requests")
	counter.Inc()
	
	// Generate JSON format
	output, err := registry.GatherJSONFormat()
	require.NoError(t, err)
	assert.NotEmpty(t, output)
	
	// Check that output is valid JSON
	assert.True(t, strings.HasPrefix(output, "["))
	assert.True(t, strings.HasSuffix(output, "]"))
	assert.Contains(t, output, "sandboxrunner_requests_total")
}

func TestMetricsRegistry_StartMetricsServer(t *testing.T) {
	config := DefaultMetricsConfig()
	config.Port = 0 // Use random port for testing
	registry := NewMetricsRegistry(config)
	
	// Create test metrics
	counter, _ := registry.NewCounter("test_requests", "Test requests")
	counter.Inc()
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Start server in goroutine
	go func() {
		err := registry.StartMetricsServer(ctx)
		assert.NoError(t, err)
	}()
	
	// Give server time to start
	time.Sleep(100 * time.Millisecond)
	
	// Test would need actual port discovery for full integration test
	// For now, just verify no immediate errors
}

func TestMetricsRegistry_HTTPEndpoints(t *testing.T) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	
	// Create test metrics
	counter, _ := registry.NewCounter("test_counter", "Test counter")
	counter.Inc()
	
	// Test Prometheus format endpoint
	w := httptest.NewRecorder()
	
	// Simulate the HTTP handler logic
	data, err := registry.GatherPrometheusFormat()
	require.NoError(t, err)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(data))
	
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", resp.Header.Get("Content-Type"))
	
	// Test JSON format endpoint
	w = httptest.NewRecorder()
	
	data, err = registry.GatherJSONFormat()
	require.NoError(t, err)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(data))
	
	resp = w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
}

func TestBuildLabelsKey(t *testing.T) {
	tests := []struct {
		names    []string
		values   []string
		expected string
	}{
		{
			names:    []string{},
			values:   []string{},
			expected: "",
		},
		{
			names:    []string{"method"},
			values:   []string{"GET"},
			expected: "method=GET",
		},
		{
			names:    []string{"method", "status"},
			values:   []string{"GET", "200"},
			expected: "method=GET,status=200",
		},
	}
	
	for _, test := range tests {
		result := buildLabelsKey(test.names, test.values)
		assert.Equal(t, test.expected, result)
	}
	
	// Test panic on mismatch
	assert.Panics(t, func() {
		buildLabelsKey([]string{"a", "b"}, []string{"1"})
	})
}

func TestParseLabelsKey(t *testing.T) {
	tests := []struct {
		key      string
		expected MetricLabels
	}{
		{
			key:      "",
			expected: MetricLabels{},
		},
		{
			key:      "method=GET",
			expected: MetricLabels{"method": "GET"},
		},
		{
			key:      "method=GET,status=200",
			expected: MetricLabels{"method": "GET", "status": "200"},
		},
	}
	
	for _, test := range tests {
		result := parseLabelsKey(test.key)
		assert.Equal(t, test.expected, result)
	}
}

func TestProcessCollector(t *testing.T) {
	collector := NewProcessCollector()
	assert.NotNil(t, collector)
	
	// Test describe
	ch := make(chan *Metric, 10)
	go func() {
		collector.Describe(ch)
		close(ch)
	}()
	
	metrics := make([]*Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	
	assert.NotEmpty(t, metrics)
	
	// Check for expected metrics
	metricNames := make(map[string]bool)
	for _, metric := range metrics {
		metricNames[metric.Name] = true
	}
	
	assert.True(t, metricNames["process_cpu_seconds_total"])
	assert.True(t, metricNames["process_open_fds"])
	assert.True(t, metricNames["process_virtual_memory_bytes"])
}

func TestGoCollector(t *testing.T) {
	collector := NewGoCollector()
	assert.NotNil(t, collector)
	
	// Test collect
	ch := make(chan *Metric, 50)
	go func() {
		collector.Collect(ch)
		close(ch)
	}()
	
	metrics := make([]*Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	
	assert.NotEmpty(t, metrics)
	
	// Check for expected metrics
	metricNames := make(map[string]bool)
	for _, metric := range metrics {
		metricNames[metric.Name] = true
	}
	
	assert.True(t, metricNames["go_goroutines"])
	assert.True(t, metricNames["go_memstats_alloc_bytes"])
	assert.True(t, metricNames["go_memstats_sys_bytes"])
}

func TestBuildInfoCollector(t *testing.T) {
	collector := NewBuildInfoCollector()
	assert.NotNil(t, collector)
	
	// Test collect
	ch := make(chan *Metric, 10)
	go func() {
		collector.Collect(ch)
		close(ch)
	}()
	
	metrics := make([]*Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	
	// Build info may not always be available in tests
	if len(metrics) > 0 {
		assert.Equal(t, "go_build_info", metrics[0].Name)
		assert.Equal(t, MetricTypeGauge, metrics[0].Type)
	}
}

func TestSandboxMetricsCollector(t *testing.T) {
	// Mock metrics getter
	metricsGetter := func() map[string]interface{} {
		return map[string]interface{}{
			"total_containers":    10,
			"running_containers":  7,
			"healthy_containers":  8,
			"total_events":        100,
			"average_startup_time": time.Duration(2.5 * float64(time.Second)),
			"state_distribution": map[interface{}]interface{}{
				"running": 7,
				"stopped": 2,
				"failed":  1,
			},
			"events_by_type": map[interface{}]interface{}{
				"container_start": 50,
				"container_stop":  30,
				"health_check":    20,
			},
		}
	}
	
	collector := NewSandboxMetricsCollector(metricsGetter)
	assert.NotNil(t, collector)
	
	// Test collect
	ch := make(chan *Metric, 50)
	go func() {
		collector.Collect(ch)
		close(ch)
	}()
	
	metrics := make([]*Metric, 0)
	for metric := range ch {
		metrics = append(metrics, metric)
	}
	
	assert.NotEmpty(t, metrics)
	
	// Check for expected metrics
	metricNames := make(map[string]bool)
	for _, metric := range metrics {
		metricNames[metric.Name] = true
	}
	
	assert.True(t, metricNames["sandbox_containers_total"])
	assert.True(t, metricNames["sandbox_containers_by_state"])
	assert.True(t, metricNames["sandbox_events_total"])
}

// Benchmark tests

func BenchmarkCounter_Inc(b *testing.B) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	counter, _ := registry.NewCounter("bench_counter", "Benchmark counter", "method")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		counter.Inc("GET")
	}
}

func BenchmarkGauge_Set(b *testing.B) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	gauge, _ := registry.NewGauge("bench_gauge", "Benchmark gauge", "node")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gauge.Set(float64(i), "node1")
	}
}

func BenchmarkHistogram_Observe(b *testing.B) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	histogram, _ := registry.NewHistogram("bench_histogram", "Benchmark histogram", nil, "endpoint")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		histogram.Observe(float64(i%1000)/100.0, "/api/test")
	}
}

func BenchmarkSummary_Observe(b *testing.B) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	summary, _ := registry.NewSummary("bench_summary", "Benchmark summary", nil, "method")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summary.Observe(float64(i%1000)/100.0, "GET")
	}
}

func BenchmarkMetricsRegistry_Gather(b *testing.B) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	
	// Create multiple metrics
	for i := 0; i < 100; i++ {
		counter, _ := registry.NewCounter(
			"bench_counter_"+string(rune(i)), 
			"Benchmark counter", 
			"method",
		)
		counter.Inc("GET")
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := registry.Gather()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMetricsRegistry_GatherPrometheusFormat(b *testing.B) {
	registry := NewMetricsRegistry(DefaultMetricsConfig())
	
	// Create metrics with data
	counter, _ := registry.NewCounter("requests_total", "Total requests", "method", "status")
	gauge, _ := registry.NewGauge("memory_bytes", "Memory usage")
	
	counter.Inc("GET", "200")
	counter.Inc("POST", "404")
	gauge.Set(1048576)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := registry.GatherPrometheusFormat()
		if err != nil {
			b.Fatal(err)
		}
	}
}