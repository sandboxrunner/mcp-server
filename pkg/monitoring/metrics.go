package monitoring

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// MetricType represents the type of metric
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeSummary   MetricType = "summary"
)

// MetricLabels represents labels for a metric
type MetricLabels map[string]string

// MetricValue represents a metric value with timestamp
type MetricValue struct {
	Value     float64           `json:"value"`
	Timestamp time.Time         `json:"timestamp"`
	Labels    MetricLabels      `json:"labels"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Metric represents a metric with its metadata and values
type Metric struct {
	Name        string         `json:"name"`
	Type        MetricType     `json:"type"`
	Help        string         `json:"help"`
	Labels      []string       `json:"labels"`
	Values      []MetricValue  `json:"values"`
	Unit        string         `json:"unit,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// Counter represents a counter metric
type Counter struct {
	name   string
	help   string
	labels []string
	values map[string]*counterValue
	mu     sync.RWMutex
}

type counterValue struct {
	value     float64
	timestamp time.Time
}

// Gauge represents a gauge metric
type Gauge struct {
	name   string
	help   string
	labels []string
	values map[string]*gaugeValue
	mu     sync.RWMutex
}

type gaugeValue struct {
	value     float64
	timestamp time.Time
}

// Histogram represents a histogram metric
type Histogram struct {
	name    string
	help    string
	labels  []string
	buckets []float64
	values  map[string]*histogramValue
	mu      sync.RWMutex
}

type histogramValue struct {
	bucketCounts map[float64]uint64
	count        uint64
	sum          float64
	timestamp    time.Time
}

// Summary represents a summary metric
type Summary struct {
	name       string
	help       string
	labels     []string
	objectives map[float64]float64 // quantile -> error
	values     map[string]*summaryValue
	mu         sync.RWMutex
}

type summaryValue struct {
	observations []float64
	count        uint64
	sum          float64
	timestamp    time.Time
}

// MetricsRegistry manages all metrics
type MetricsRegistry struct {
	metrics   map[string]interface{} // name -> metric (Counter, Gauge, Histogram, Summary)
	collectors []Collector
	gatherers []Gatherer
	mu        sync.RWMutex
	config    *MetricsConfig
}

// MetricsConfig configuration for metrics system
type MetricsConfig struct {
	Enabled               bool                   `json:"enabled"`
	Port                  int                    `json:"port"`
	Path                  string                 `json:"path"`
	Namespace             string                 `json:"namespace"`
	EnableBuildInfo       bool                   `json:"enable_build_info"`
	EnableProcessMetrics  bool                   `json:"enable_process_metrics"`
	EnableGoMetrics       bool                   `json:"enable_go_metrics"`
	GatherInterval        time.Duration          `json:"gather_interval"`
	RetentionDuration     time.Duration          `json:"retention_duration"`
	MaxMetricsInMemory    int                    `json:"max_metrics_in_memory"`
	CompressionEnabled    bool                   `json:"compression_enabled"`
	ExportFormats         []string               `json:"export_formats"`
	CustomLabels          map[string]string      `json:"custom_labels"`
	ScrapeConfigs         []ScrapeConfig         `json:"scrape_configs"`
	AlertingRules         []AlertingRule         `json:"alerting_rules"`
	RecordingRules        []RecordingRule        `json:"recording_rules"`
}

// ScrapeConfig defines a scrape target
type ScrapeConfig struct {
	JobName       string            `json:"job_name"`
	ScrapeInterval time.Duration    `json:"scrape_interval"`
	ScrapeTimeout  time.Duration    `json:"scrape_timeout"`
	MetricsPath    string           `json:"metrics_path"`
	Scheme         string           `json:"scheme"`
	StaticConfigs  []StaticConfig   `json:"static_configs"`
	RelabelConfigs []RelabelConfig  `json:"relabel_configs"`
}

// StaticConfig defines static targets
type StaticConfig struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// RelabelConfig defines relabeling rules
type RelabelConfig struct {
	SourceLabels []string `json:"source_labels"`
	Separator    string   `json:"separator"`
	TargetLabel  string   `json:"target_label"`
	Regex        string   `json:"regex"`
	Replacement  string   `json:"replacement"`
	Action       string   `json:"action"`
}

// AlertingRule defines an alerting rule
type AlertingRule struct {
	Alert       string            `json:"alert"`
	Expr        string            `json:"expr"`
	For         time.Duration     `json:"for"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// RecordingRule defines a recording rule
type RecordingRule struct {
	Record string            `json:"record"`
	Expr   string            `json:"expr"`
	Labels map[string]string `json:"labels"`
}

// Collector interface for custom metrics collection
type Collector interface {
	Describe(ch chan<- *Metric)
	Collect(ch chan<- *Metric)
}

// Gatherer interface for metrics gathering
type Gatherer interface {
	Gather() ([]*Metric, error)
}

// DefaultMetricsConfig returns default metrics configuration
func DefaultMetricsConfig() *MetricsConfig {
	return &MetricsConfig{
		Enabled:               true,
		Port:                  9090,
		Path:                  "/metrics",
		Namespace:             "sandboxrunner",
		EnableBuildInfo:       true,
		EnableProcessMetrics:  true,
		EnableGoMetrics:       true,
		GatherInterval:        15 * time.Second,
		RetentionDuration:     24 * time.Hour,
		MaxMetricsInMemory:    100000,
		CompressionEnabled:    true,
		ExportFormats:         []string{"prometheus", "json"},
		CustomLabels:          make(map[string]string),
		ScrapeConfigs:         []ScrapeConfig{},
		AlertingRules:         []AlertingRule{},
		RecordingRules:        []RecordingRule{},
	}
}

// NewMetricsRegistry creates a new metrics registry
func NewMetricsRegistry(config *MetricsConfig) *MetricsRegistry {
	if config == nil {
		config = DefaultMetricsConfig()
	}

	registry := &MetricsRegistry{
		metrics:    make(map[string]interface{}),
		collectors: make([]Collector, 0),
		gatherers:  make([]Gatherer, 0),
		config:     config,
	}

	// Add default collectors
	if config.EnableProcessMetrics {
		registry.RegisterCollector(NewProcessCollector())
	}
	if config.EnableGoMetrics {
		registry.RegisterCollector(NewGoCollector())
	}
	if config.EnableBuildInfo {
		registry.RegisterCollector(NewBuildInfoCollector())
	}

	return registry
}

// NewCounter creates a new counter metric
func (r *MetricsRegistry) NewCounter(name, help string, labelNames ...string) (*Counter, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.buildMetricName(name)
	if _, exists := r.metrics[fullName]; exists {
		return nil, fmt.Errorf("metric %s already exists", fullName)
	}

	counter := &Counter{
		name:   fullName,
		help:   help,
		labels: labelNames,
		values: make(map[string]*counterValue),
	}

	r.metrics[fullName] = counter
	log.Debug().Str("metric", fullName).Str("type", "counter").Msg("Counter metric registered")
	return counter, nil
}

// NewGauge creates a new gauge metric
func (r *MetricsRegistry) NewGauge(name, help string, labelNames ...string) (*Gauge, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.buildMetricName(name)
	if _, exists := r.metrics[fullName]; exists {
		return nil, fmt.Errorf("metric %s already exists", fullName)
	}

	gauge := &Gauge{
		name:   fullName,
		help:   help,
		labels: labelNames,
		values: make(map[string]*gaugeValue),
	}

	r.metrics[fullName] = gauge
	log.Debug().Str("metric", fullName).Str("type", "gauge").Msg("Gauge metric registered")
	return gauge, nil
}

// NewHistogram creates a new histogram metric
func (r *MetricsRegistry) NewHistogram(name, help string, buckets []float64, labelNames ...string) (*Histogram, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.buildMetricName(name)
	if _, exists := r.metrics[fullName]; exists {
		return nil, fmt.Errorf("metric %s already exists", fullName)
	}

	if buckets == nil {
		buckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
	}

	histogram := &Histogram{
		name:    fullName,
		help:    help,
		labels:  labelNames,
		buckets: buckets,
		values:  make(map[string]*histogramValue),
	}

	r.metrics[fullName] = histogram
	log.Debug().Str("metric", fullName).Str("type", "histogram").Msg("Histogram metric registered")
	return histogram, nil
}

// NewSummary creates a new summary metric
func (r *MetricsRegistry) NewSummary(name, help string, objectives map[float64]float64, labelNames ...string) (*Summary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fullName := r.buildMetricName(name)
	if _, exists := r.metrics[fullName]; exists {
		return nil, fmt.Errorf("metric %s already exists", fullName)
	}

	if objectives == nil {
		objectives = map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001}
	}

	summary := &Summary{
		name:       fullName,
		help:       help,
		labels:     labelNames,
		objectives: objectives,
		values:     make(map[string]*summaryValue),
	}

	r.metrics[fullName] = summary
	log.Debug().Str("metric", fullName).Str("type", "summary").Msg("Summary metric registered")
	return summary, nil
}

// RegisterCollector registers a custom collector
func (r *MetricsRegistry) RegisterCollector(collector Collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.collectors = append(r.collectors, collector)
	log.Debug().Msg("Custom collector registered")
}

// RegisterGatherer registers a custom gatherer
func (r *MetricsRegistry) RegisterGatherer(gatherer Gatherer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gatherers = append(r.gatherers, gatherer)
	log.Debug().Msg("Custom gatherer registered")
}

// Gather collects all metrics
func (r *MetricsRegistry) Gather() ([]*Metric, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var allMetrics []*Metric

	// Collect from registered metrics
	for _, metric := range r.metrics {
		switch m := metric.(type) {
		case *Counter:
			allMetrics = append(allMetrics, r.gatherCounter(m))
		case *Gauge:
			allMetrics = append(allMetrics, r.gatherGauge(m))
		case *Histogram:
			allMetrics = append(allMetrics, r.gatherHistogram(m))
		case *Summary:
			allMetrics = append(allMetrics, r.gatherSummary(m))
		}
	}

	// Collect from custom collectors
	for _, collector := range r.collectors {
		ch := make(chan *Metric, 100)
		go func(c Collector) {
			defer close(ch)
			c.Collect(ch)
		}(collector)

		for metric := range ch {
			allMetrics = append(allMetrics, metric)
		}
	}

	// Collect from gatherers
	for _, gatherer := range r.gatherers {
		if metrics, err := gatherer.Gather(); err == nil {
			allMetrics = append(allMetrics, metrics...)
		} else {
			log.Warn().Err(err).Msg("Failed to gather metrics from gatherer")
		}
	}

	return allMetrics, nil
}

// GatherPrometheusFormat exports metrics in Prometheus format
func (r *MetricsRegistry) GatherPrometheusFormat() (string, error) {
	metrics, err := r.Gather()
	if err != nil {
		return "", fmt.Errorf("failed to gather metrics: %w", err)
	}

	var output strings.Builder

	for _, metric := range metrics {
		// Write help
		if metric.Help != "" {
			output.WriteString(fmt.Sprintf("# HELP %s %s\n", metric.Name, metric.Help))
		}

		// Write type
		output.WriteString(fmt.Sprintf("# TYPE %s %s\n", metric.Name, metric.Type))

		// Write values
		for _, value := range metric.Values {
			labelPairs := r.formatLabels(value.Labels)
			if labelPairs != "" {
				output.WriteString(fmt.Sprintf("%s{%s} %g %d\n", 
					metric.Name, labelPairs, value.Value, value.Timestamp.Unix()*1000))
			} else {
				output.WriteString(fmt.Sprintf("%s %g %d\n", 
					metric.Name, value.Value, value.Timestamp.Unix()*1000))
			}
		}
		output.WriteString("\n")
	}

	return output.String(), nil
}

// GatherJSONFormat exports metrics in JSON format
func (r *MetricsRegistry) GatherJSONFormat() (string, error) {
	metrics, err := r.Gather()
	if err != nil {
		return "", fmt.Errorf("failed to gather metrics: %w", err)
	}

	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal metrics to JSON: %w", err)
	}

	return string(data), nil
}

// StartMetricsServer starts the HTTP metrics server
func (r *MetricsRegistry) StartMetricsServer(ctx context.Context) error {
	if !r.config.Enabled {
		log.Info().Msg("Metrics server disabled")
		return nil
	}

	mux := http.NewServeMux()
	
	// Prometheus format endpoint
	mux.HandleFunc(r.config.Path, func(w http.ResponseWriter, req *http.Request) {
		format := req.URL.Query().Get("format")
		
		switch format {
		case "json":
			data, err := r.GatherJSONFormat()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(data))
		default:
			data, err := r.GatherPrometheusFormat()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			w.Write([]byte(data))
		}
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Metrics metadata endpoint
	mux.HandleFunc("/metrics/metadata", func(w http.ResponseWriter, req *http.Request) {
		r.mu.RLock()
		metadata := make(map[string]interface{})
		for name, metric := range r.metrics {
			switch m := metric.(type) {
			case *Counter:
				metadata[name] = map[string]interface{}{
					"type": "counter",
					"help": m.help,
					"labels": m.labels,
				}
			case *Gauge:
				metadata[name] = map[string]interface{}{
					"type": "gauge",
					"help": m.help,
					"labels": m.labels,
				}
			case *Histogram:
				metadata[name] = map[string]interface{}{
					"type": "histogram",
					"help": m.help,
					"labels": m.labels,
					"buckets": m.buckets,
				}
			case *Summary:
				metadata[name] = map[string]interface{}{
					"type": "summary",
					"help": m.help,
					"labels": m.labels,
					"objectives": m.objectives,
				}
			}
		}
		r.mu.RUnlock()

		data, err := json.MarshalIndent(metadata, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", r.config.Port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		log.Info().Msg("Shutting down metrics server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	log.Info().
		Int("port", r.config.Port).
		Str("path", r.config.Path).
		Msg("Starting metrics server")

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start metrics server: %w", err)
	}

	return nil
}

// Helper methods

func (r *MetricsRegistry) buildMetricName(name string) string {
	if r.config.Namespace != "" {
		return fmt.Sprintf("%s_%s", r.config.Namespace, name)
	}
	return name
}

func (r *MetricsRegistry) formatLabels(labels MetricLabels) string {
	if len(labels) == 0 {
		return ""
	}

	// Add custom labels
	allLabels := make(MetricLabels)
	for k, v := range r.config.CustomLabels {
		allLabels[k] = v
	}
	for k, v := range labels {
		allLabels[k] = v
	}

	var pairs []string
	for key, value := range allLabels {
		pairs = append(pairs, fmt.Sprintf(`%s="%s"`, key, value))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

func (r *MetricsRegistry) gatherCounter(counter *Counter) *Metric {
	counter.mu.RLock()
	defer counter.mu.RUnlock()

	metric := &Metric{
		Name:      counter.name,
		Type:      MetricTypeCounter,
		Help:      counter.help,
		Labels:    counter.labels,
		Values:    make([]MetricValue, 0, len(counter.values)),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	for labelsKey, value := range counter.values {
		labels := parseLabelsKey(labelsKey)
		metric.Values = append(metric.Values, MetricValue{
			Value:     value.value,
			Timestamp: value.timestamp,
			Labels:    labels,
		})
	}

	return metric
}

func (r *MetricsRegistry) gatherGauge(gauge *Gauge) *Metric {
	gauge.mu.RLock()
	defer gauge.mu.RUnlock()

	metric := &Metric{
		Name:      gauge.name,
		Type:      MetricTypeGauge,
		Help:      gauge.help,
		Labels:    gauge.labels,
		Values:    make([]MetricValue, 0, len(gauge.values)),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	for labelsKey, value := range gauge.values {
		labels := parseLabelsKey(labelsKey)
		metric.Values = append(metric.Values, MetricValue{
			Value:     value.value,
			Timestamp: value.timestamp,
			Labels:    labels,
		})
	}

	return metric
}

func (r *MetricsRegistry) gatherHistogram(histogram *Histogram) *Metric {
	histogram.mu.RLock()
	defer histogram.mu.RUnlock()

	metric := &Metric{
		Name:      histogram.name,
		Type:      MetricTypeHistogram,
		Help:      histogram.help,
		Labels:    histogram.labels,
		Values:    make([]MetricValue, 0),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	for labelsKey, value := range histogram.values {
		labels := parseLabelsKey(labelsKey)
		
		// Add bucket counts
		for _, bucket := range histogram.buckets {
			bucketLabels := make(MetricLabels)
			for k, v := range labels {
				bucketLabels[k] = v
			}
			bucketLabels["le"] = fmt.Sprintf("%g", bucket)
			
			bucketCount := uint64(0)
			for b, count := range value.bucketCounts {
				if b <= bucket {
					bucketCount += count
				}
			}
			
			metric.Values = append(metric.Values, MetricValue{
				Value:     float64(bucketCount),
				Timestamp: value.timestamp,
				Labels:    bucketLabels,
			})
		}

		// Add +Inf bucket
		infLabels := make(MetricLabels)
		for k, v := range labels {
			infLabels[k] = v
		}
		infLabels["le"] = "+Inf"
		metric.Values = append(metric.Values, MetricValue{
			Value:     float64(value.count),
			Timestamp: value.timestamp,
			Labels:    infLabels,
		})

		// Add _count and _sum
		countLabels := make(MetricLabels)
		for k, v := range labels {
			countLabels[k] = v
		}
		metric.Values = append(metric.Values, MetricValue{
			Value:     float64(value.count),
			Timestamp: value.timestamp,
			Labels:    countLabels,
			Metadata:  map[string]interface{}{"suffix": "_count"},
		})

		sumLabels := make(MetricLabels)
		for k, v := range labels {
			sumLabels[k] = v
		}
		metric.Values = append(metric.Values, MetricValue{
			Value:     value.sum,
			Timestamp: value.timestamp,
			Labels:    sumLabels,
			Metadata:  map[string]interface{}{"suffix": "_sum"},
		})
	}

	return metric
}

func (r *MetricsRegistry) gatherSummary(summary *Summary) *Metric {
	summary.mu.RLock()
	defer summary.mu.RUnlock()

	metric := &Metric{
		Name:      summary.name,
		Type:      MetricTypeSummary,
		Help:      summary.help,
		Labels:    summary.labels,
		Values:    make([]MetricValue, 0),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	for labelsKey, value := range summary.values {
		labels := parseLabelsKey(labelsKey)
		
		// Calculate quantiles
		for quantile := range summary.objectives {
			quantileLabels := make(MetricLabels)
			for k, v := range labels {
				quantileLabels[k] = v
			}
			quantileLabels["quantile"] = fmt.Sprintf("%g", quantile)
			
			quantileValue := r.calculateQuantile(value.observations, quantile)
			metric.Values = append(metric.Values, MetricValue{
				Value:     quantileValue,
				Timestamp: value.timestamp,
				Labels:    quantileLabels,
			})
		}

		// Add _count and _sum
		countLabels := make(MetricLabels)
		for k, v := range labels {
			countLabels[k] = v
		}
		metric.Values = append(metric.Values, MetricValue{
			Value:     float64(value.count),
			Timestamp: value.timestamp,
			Labels:    countLabels,
			Metadata:  map[string]interface{}{"suffix": "_count"},
		})

		sumLabels := make(MetricLabels)
		for k, v := range labels {
			sumLabels[k] = v
		}
		metric.Values = append(metric.Values, MetricValue{
			Value:     value.sum,
			Timestamp: value.timestamp,
			Labels:    sumLabels,
			Metadata:  map[string]interface{}{"suffix": "_sum"},
		})
	}

	return metric
}

// Counter methods

// Inc increments the counter by 1
func (c *Counter) Inc(labelValues ...string) {
	c.Add(1, labelValues...)
}

// Add adds the given value to the counter
func (c *Counter) Add(value float64, labelValues ...string) {
	if value < 0 {
		panic("counter value cannot be negative")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	key := buildLabelsKey(c.labels, labelValues)
	if current, exists := c.values[key]; exists {
		current.value += value
		current.timestamp = time.Now()
	} else {
		c.values[key] = &counterValue{
			value:     value,
			timestamp: time.Now(),
		}
	}
}

// Get returns the current value of the counter
func (c *Counter) Get(labelValues ...string) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := buildLabelsKey(c.labels, labelValues)
	if value, exists := c.values[key]; exists {
		return value.value
	}
	return 0
}

// Gauge methods

// Set sets the gauge to the given value
func (g *Gauge) Set(value float64, labelValues ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	key := buildLabelsKey(g.labels, labelValues)
	g.values[key] = &gaugeValue{
		value:     value,
		timestamp: time.Now(),
	}
}

// Inc increments the gauge by 1
func (g *Gauge) Inc(labelValues ...string) {
	g.Add(1, labelValues...)
}

// Dec decrements the gauge by 1
func (g *Gauge) Dec(labelValues ...string) {
	g.Add(-1, labelValues...)
}

// Add adds the given value to the gauge
func (g *Gauge) Add(value float64, labelValues ...string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	key := buildLabelsKey(g.labels, labelValues)
	if current, exists := g.values[key]; exists {
		current.value += value
		current.timestamp = time.Now()
	} else {
		g.values[key] = &gaugeValue{
			value:     value,
			timestamp: time.Now(),
		}
	}
}

// Get returns the current value of the gauge
func (g *Gauge) Get(labelValues ...string) float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	key := buildLabelsKey(g.labels, labelValues)
	if value, exists := g.values[key]; exists {
		return value.value
	}
	return 0
}

// Histogram methods

// Observe records an observation
func (h *Histogram) Observe(value float64, labelValues ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	key := buildLabelsKey(h.labels, labelValues)
	if current, exists := h.values[key]; exists {
		current.count++
		current.sum += value
		current.timestamp = time.Now()
		
		// Update bucket counts
		for _, bucket := range h.buckets {
			if value <= bucket {
				current.bucketCounts[bucket]++
			}
		}
	} else {
		bucketCounts := make(map[float64]uint64)
		for _, bucket := range h.buckets {
			if value <= bucket {
				bucketCounts[bucket] = 1
			} else {
				bucketCounts[bucket] = 0
			}
		}
		
		h.values[key] = &histogramValue{
			bucketCounts: bucketCounts,
			count:        1,
			sum:          value,
			timestamp:    time.Now(),
		}
	}
}

// Summary methods

// Observe records an observation
func (s *Summary) Observe(value float64, labelValues ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := buildLabelsKey(s.labels, labelValues)
	if current, exists := s.values[key]; exists {
		current.observations = append(current.observations, value)
		current.count++
		current.sum += value
		current.timestamp = time.Now()
		
		// Limit observations to prevent memory leaks
		maxObservations := 10000
		if len(current.observations) > maxObservations {
			// Keep only recent observations
			start := len(current.observations) - maxObservations
			current.observations = current.observations[start:]
		}
	} else {
		s.values[key] = &summaryValue{
			observations: []float64{value},
			count:        1,
			sum:          value,
			timestamp:    time.Now(),
		}
	}
}

// Helper functions

func buildLabelsKey(labelNames []string, labelValues []string) string {
	if len(labelNames) != len(labelValues) {
		panic("label names and values length mismatch")
	}
	
	if len(labelNames) == 0 {
		return ""
	}
	
	pairs := make([]string, len(labelNames))
	for i, name := range labelNames {
		pairs[i] = fmt.Sprintf("%s=%s", name, labelValues[i])
	}
	return strings.Join(pairs, ",")
}

func parseLabelsKey(key string) MetricLabels {
	if key == "" {
		return make(MetricLabels)
	}
	
	labels := make(MetricLabels)
	pairs := strings.Split(key, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			labels[parts[0]] = parts[1]
		}
	}
	return labels
}

func (r *MetricsRegistry) calculateQuantile(observations []float64, quantile float64) float64 {
	if len(observations) == 0 {
		return 0
	}
	
	// Copy and sort observations
	sorted := make([]float64, len(observations))
	copy(sorted, observations)
	sort.Float64s(sorted)
	
	index := quantile * float64(len(sorted)-1)
	
	if index == float64(int(index)) {
		return sorted[int(index)]
	}
	
	lower := int(index)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	
	// Linear interpolation
	weight := index - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}