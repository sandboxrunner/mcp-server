package monitoring

import (
	"encoding/json"
	"fmt"
)

// GrafanaDashboard represents a Grafana dashboard configuration
type GrafanaDashboard struct {
	ID            int64                  `json:"id,omitempty"`
	UID           string                 `json:"uid,omitempty"`
	Title         string                 `json:"title"`
	Tags          []string               `json:"tags"`
	Style         string                 `json:"style"`
	Timezone      string                 `json:"timezone"`
	Editable      bool                   `json:"editable"`
	HideControls  bool                   `json:"hideControls"`
	SharedCrosshair bool                 `json:"sharedCrosshair"`
	Panels        []GrafanaPanel         `json:"panels"`
	Time          GrafanaTimeRange       `json:"time"`
	Timepicker    GrafanaTimepicker      `json:"timepicker"`
	Templating    GrafanaTemplating      `json:"templating"`
	Annotations   GrafanaAnnotations     `json:"annotations"`
	Refresh       string                 `json:"refresh"`
	SchemaVersion int                    `json:"schemaVersion"`
	Version       int                    `json:"version"`
}

// GrafanaPanel represents a dashboard panel
type GrafanaPanel struct {
	ID            int64                  `json:"id"`
	Title         string                 `json:"title"`
	Type          string                 `json:"type"`
	DataSource    string                 `json:"datasource"`
	Targets       []GrafanaTarget        `json:"targets"`
	GridPos       GrafanaGridPos         `json:"gridPos"`
	Options       map[string]interface{} `json:"options,omitempty"`
	FieldConfig   GrafanaFieldConfig     `json:"fieldConfig,omitempty"`
	Transformations []GrafanaTransformation `json:"transformations,omitempty"`
	Alert         *GrafanaAlert          `json:"alert,omitempty"`
}

// GrafanaTarget represents a query target
type GrafanaTarget struct {
	Expr         string `json:"expr"`
	Interval     string `json:"interval,omitempty"`
	LegendFormat string `json:"legendFormat,omitempty"`
	RefID        string `json:"refId"`
}

// GrafanaGridPos represents panel position
type GrafanaGridPos struct {
	H int `json:"h"`
	W int `json:"w"`
	X int `json:"x"`
	Y int `json:"y"`
}

// GrafanaFieldConfig represents field configuration
type GrafanaFieldConfig struct {
	Defaults  GrafanaFieldDefaults `json:"defaults"`
	Overrides []interface{}        `json:"overrides"`
}

// GrafanaFieldDefaults represents default field settings
type GrafanaFieldDefaults struct {
	Unit        string                 `json:"unit,omitempty"`
	Min         *float64               `json:"min,omitempty"`
	Max         *float64               `json:"max,omitempty"`
	Decimals    *int                   `json:"decimals,omitempty"`
	Color       map[string]interface{} `json:"color,omitempty"`
	Thresholds  map[string]interface{} `json:"thresholds,omitempty"`
}

// GrafanaTransformation represents data transformation
type GrafanaTransformation struct {
	ID      string                 `json:"id"`
	Options map[string]interface{} `json:"options"`
}

// GrafanaAlert represents panel alert configuration
type GrafanaAlert struct {
	Name        string                   `json:"name"`
	Message     string                   `json:"message"`
	Frequency   string                   `json:"frequency"`
	Conditions  []GrafanaAlertCondition  `json:"conditions"`
	ExecutionErrorState string           `json:"executionErrorState"`
	NoDataState string                   `json:"noDataState"`
	For         string                   `json:"for"`
}

// GrafanaAlertCondition represents alert condition
type GrafanaAlertCondition struct {
	Query        GrafanaAlertQuery      `json:"query"`
	Reducer      GrafanaAlertReducer    `json:"reducer"`
	Evaluator    GrafanaAlertEvaluator  `json:"evaluator"`
}

// GrafanaAlertQuery represents alert query
type GrafanaAlertQuery struct {
	QueryType string `json:"queryType"`
	RefID     string `json:"refId"`
}

// GrafanaAlertReducer represents alert reducer
type GrafanaAlertReducer struct {
	Type   string        `json:"type"`
	Params []interface{} `json:"params"`
}

// GrafanaAlertEvaluator represents alert evaluator
type GrafanaAlertEvaluator struct {
	Type   string        `json:"type"`
	Params []interface{} `json:"params"`
}

// GrafanaTimeRange represents time range
type GrafanaTimeRange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// GrafanaTimepicker represents timepicker configuration
type GrafanaTimepicker struct {
	RefreshIntervals []string `json:"refresh_intervals"`
	TimeOptions      []string `json:"time_options"`
}

// GrafanaTemplating represents dashboard templating
type GrafanaTemplating struct {
	List []GrafanaTemplate `json:"list"`
}

// GrafanaTemplate represents a template variable
type GrafanaTemplate struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	DataSource  string      `json:"datasource,omitempty"`
	Query       string      `json:"query,omitempty"`
	Refresh     int         `json:"refresh"`
	Options     []interface{} `json:"options,omitempty"`
	Current     interface{} `json:"current,omitempty"`
	Hide        int         `json:"hide"`
	IncludeAll  bool        `json:"includeAll"`
	Multi       bool        `json:"multi"`
	AllValue    string      `json:"allValue,omitempty"`
}

// GrafanaAnnotations represents dashboard annotations
type GrafanaAnnotations struct {
	List []GrafanaAnnotation `json:"list"`
}

// GrafanaAnnotation represents an annotation
type GrafanaAnnotation struct {
	Name       string `json:"name"`
	DataSource string `json:"datasource"`
	Enable     bool   `json:"enable"`
	Hide       bool   `json:"hide"`
	IconColor  string `json:"iconColor"`
	Query      string `json:"query"`
	Type       string `json:"type"`
}

// DashboardGenerator generates Grafana dashboards
type DashboardGenerator struct {
	namespace string
}

// NewDashboardGenerator creates a new dashboard generator
func NewDashboardGenerator(namespace string) *DashboardGenerator {
	return &DashboardGenerator{
		namespace: namespace,
	}
}

// GenerateSandboxOverviewDashboard generates the main sandbox overview dashboard
func (dg *DashboardGenerator) GenerateSandboxOverviewDashboard() (*GrafanaDashboard, error) {
	dashboard := &GrafanaDashboard{
		UID:           "sandbox-overview",
		Title:         "SandboxRunner Overview",
		Tags:          []string{"sandboxrunner", "overview"},
		Style:         "dark",
		Timezone:      "browser",
		Editable:      true,
		HideControls:  false,
		SharedCrosshair: true,
		Time: GrafanaTimeRange{
			From: "now-1h",
			To:   "now",
		},
		Refresh: "30s",
		SchemaVersion: 27,
		Version: 1,
		Timepicker: GrafanaTimepicker{
			RefreshIntervals: []string{"5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"},
			TimeOptions:      []string{"5m", "15m", "1h", "6h", "12h", "24h", "2d", "7d", "30d"},
		},
		Templating: GrafanaTemplating{
			List: []GrafanaTemplate{
				{
					Name:       "instance",
					Type:       "query",
					DataSource: "Prometheus",
					Query:      "label_values(up, instance)",
					Refresh:    1,
					Hide:       0,
					IncludeAll: true,
					Multi:      true,
					AllValue:   ".*",
				},
			},
		},
		Annotations: GrafanaAnnotations{
			List: []GrafanaAnnotation{
				{
					Name:       "Deployments",
					DataSource: "Prometheus",
					Enable:     true,
					Hide:       false,
					IconColor:  "rgba(0, 211, 255, 1)",
					Query:      "ALERTS{alertname=\"DeploymentStarted\"}",
					Type:       "tags",
				},
			},
		},
	}

	// Panel 1: Container Stats
	containerStatsPanel := GrafanaPanel{
		ID:         1,
		Title:      "Container Statistics",
		Type:       "stat",
		DataSource: "Prometheus",
		GridPos:    GrafanaGridPos{H: 8, W: 12, X: 0, Y: 0},
		Targets: []GrafanaTarget{
			{
				Expr:         fmt.Sprintf("%s_sandbox_containers_total", dg.namespace),
				RefID:        "A",
				LegendFormat: "Total Containers",
			},
			{
				Expr:         fmt.Sprintf("sum(%s_sandbox_containers_by_state{state=\"running\"})", dg.namespace),
				RefID:        "B",
				LegendFormat: "Running",
			},
			{
				Expr:         fmt.Sprintf("sum(%s_sandbox_containers_by_state{state=\"failed\"})", dg.namespace),
				RefID:        "C",
				LegendFormat: "Failed",
			},
		},
		FieldConfig: GrafanaFieldConfig{
			Defaults: GrafanaFieldDefaults{
				Unit: "short",
				Color: map[string]interface{}{
					"mode": "palette-classic",
				},
			},
		},
	}

	// Panel 2: Container States Over Time
	containerStatesPanel := GrafanaPanel{
		ID:         2,
		Title:      "Container States Over Time",
		Type:       "timeseries",
		DataSource: "Prometheus",
		GridPos:    GrafanaGridPos{H: 8, W: 12, X: 12, Y: 0},
		Targets: []GrafanaTarget{
			{
				Expr:         fmt.Sprintf("%s_sandbox_containers_by_state", dg.namespace),
				RefID:        "A",
				LegendFormat: "{{state}}",
			},
		},
		FieldConfig: GrafanaFieldConfig{
			Defaults: GrafanaFieldDefaults{
				Unit: "short",
			},
		},
	}

	// Panel 3: Health Status
	healthStatusPanel := GrafanaPanel{
		ID:         3,
		Title:      "Health Status",
		Type:       "piechart",
		DataSource: "Prometheus",
		GridPos:    GrafanaGridPos{H: 8, W: 12, X: 0, Y: 8},
		Targets: []GrafanaTarget{
			{
				Expr:         fmt.Sprintf("%s_sandbox_containers_by_health", dg.namespace),
				RefID:        "A",
				LegendFormat: "{{health}}",
			},
		},
	}

	// Panel 4: Resource Usage
	resourceUsagePanel := GrafanaPanel{
		ID:         4,
		Title:      "Resource Usage",
		Type:       "timeseries",
		DataSource: "Prometheus",
		GridPos:    GrafanaGridPos{H: 8, W: 12, X: 12, Y: 8},
		Targets: []GrafanaTarget{
			{
				Expr:         fmt.Sprintf("%s_sandbox_resource_usage_ratio{resource=\"cpu\"} * 100", dg.namespace),
				RefID:        "A",
				LegendFormat: "CPU %",
			},
			{
				Expr:         fmt.Sprintf("%s_sandbox_resource_usage_ratio{resource=\"memory\"} * 100", dg.namespace),
				RefID:        "B",
				LegendFormat: "Memory %",
			},
			{
				Expr:         fmt.Sprintf("%s_sandbox_resource_usage_ratio{resource=\"disk\"} * 100", dg.namespace),
				RefID:        "C",
				LegendFormat: "Disk %",
			},
		},
		FieldConfig: GrafanaFieldConfig{
			Defaults: GrafanaFieldDefaults{
				Unit: "percent",
				Min:  &[]float64{0}[0],
				Max:  &[]float64{100}[0],
			},
		},
	}

	// Panel 5: Event Rate
	eventRatePanel := GrafanaPanel{
		ID:         5,
		Title:      "Event Rate",
		Type:       "timeseries",
		DataSource: "Prometheus",
		GridPos:    GrafanaGridPos{H: 8, W: 24, X: 0, Y: 16},
		Targets: []GrafanaTarget{
			{
				Expr:         fmt.Sprintf("rate(%s_sandbox_events_total[5m])", dg.namespace),
				RefID:        "A",
				LegendFormat: "Events/sec",
			},
		},
		FieldConfig: GrafanaFieldConfig{
			Defaults: GrafanaFieldDefaults{
				Unit: "reqps",
			},
		},
	}

	// Panel 6: Performance Metrics
	performancePanel := GrafanaPanel{
		ID:         6,
		Title:      "Performance Metrics",
		Type:       "timeseries",
		DataSource: "Prometheus",
		GridPos:    GrafanaGridPos{H: 8, W: 12, X: 0, Y: 24},
		Targets: []GrafanaTarget{
			{
				Expr:         fmt.Sprintf("%s_sandbox_startup_duration_seconds", dg.namespace),
				RefID:        "A",
				LegendFormat: "Startup Duration",
			},
			{
				Expr:         fmt.Sprintf("%s_sandbox_health_check_duration_seconds", dg.namespace),
				RefID:        "B",
				LegendFormat: "Health Check Duration",
			},
		},
		FieldConfig: GrafanaFieldConfig{
			Defaults: GrafanaFieldDefaults{
				Unit: "s",
			},
		},
	}

	// Panel 7: System Metrics
	systemMetricsPanel := GrafanaPanel{
		ID:         7,
		Title:      "System Metrics",
		Type:       "timeseries",
		DataSource: "Prometheus",
		GridPos:    GrafanaGridPos{H: 8, W: 12, X: 12, Y: 24},
		Targets: []GrafanaTarget{
			{
				Expr:         "go_goroutines",
				RefID:        "A",
				LegendFormat: "Goroutines",
			},
			{
				Expr:         "process_open_fds",
				RefID:        "B",
				LegendFormat: "Open FDs",
			},
			{
				Expr:         "go_memstats_alloc_bytes / 1024 / 1024",
				RefID:        "C",
				LegendFormat: "Memory Alloc (MB)",
			},
		},
		FieldConfig: GrafanaFieldConfig{
			Defaults: GrafanaFieldDefaults{
				Unit: "short",
			},
		},
	}

	dashboard.Panels = []GrafanaPanel{
		containerStatsPanel,
		containerStatesPanel,
		healthStatusPanel,
		resourceUsagePanel,
		eventRatePanel,
		performancePanel,
		systemMetricsPanel,
	}

	return dashboard, nil
}

// GenerateDetailedDashboard generates a detailed metrics dashboard
func (dg *DashboardGenerator) GenerateDetailedDashboard() (*GrafanaDashboard, error) {
	dashboard := &GrafanaDashboard{
		UID:           "sandbox-detailed",
		Title:         "SandboxRunner Detailed Metrics",
		Tags:          []string{"sandboxrunner", "detailed"},
		Style:         "dark",
		Timezone:      "browser",
		Editable:      true,
		Time: GrafanaTimeRange{
			From: "now-6h",
			To:   "now",
		},
		Refresh: "1m",
		SchemaVersion: 27,
		Version: 1,
	}

	// Add detailed panels for in-depth analysis
	panels := []GrafanaPanel{
		{
			ID:         1,
			Title:      "Go Runtime - Memory Usage",
			Type:       "timeseries",
			DataSource: "Prometheus",
			GridPos:    GrafanaGridPos{H: 8, W: 12, X: 0, Y: 0},
			Targets: []GrafanaTarget{
				{
					Expr:         "go_memstats_heap_alloc_bytes",
					RefID:        "A",
					LegendFormat: "Heap Allocated",
				},
				{
					Expr:         "go_memstats_heap_sys_bytes",
					RefID:        "B",
					LegendFormat: "Heap System",
				},
				{
					Expr:         "go_memstats_heap_inuse_bytes",
					RefID:        "C",
					LegendFormat: "Heap In Use",
				},
			},
			FieldConfig: GrafanaFieldConfig{
				Defaults: GrafanaFieldDefaults{
					Unit: "bytes",
				},
			},
		},
		{
			ID:         2,
			Title:      "Go Runtime - GC Performance",
			Type:       "timeseries",
			DataSource: "Prometheus",
			GridPos:    GrafanaGridPos{H: 8, W: 12, X: 12, Y: 0},
			Targets: []GrafanaTarget{
				{
					Expr:         "rate(go_gc_duration_seconds_count[5m])",
					RefID:        "A",
					LegendFormat: "GC Rate",
				},
				{
					Expr:         "go_gc_duration_seconds{quantile=\"0.5\"}",
					RefID:        "B",
					LegendFormat: "GC Duration P50",
				},
				{
					Expr:         "go_gc_duration_seconds{quantile=\"0.9\"}",
					RefID:        "C",
					LegendFormat: "GC Duration P90",
				},
			},
		},
		{
			ID:         3,
			Title:      "Process Resource Usage",
			Type:       "timeseries",
			DataSource: "Prometheus",
			GridPos:    GrafanaGridPos{H: 8, W: 24, X: 0, Y: 8},
			Targets: []GrafanaTarget{
				{
					Expr:         "process_cpu_seconds_total",
					RefID:        "A",
					LegendFormat: "CPU Time",
				},
				{
					Expr:         "process_resident_memory_bytes",
					RefID:        "B",
					LegendFormat: "RSS Memory",
				},
				{
					Expr:         "process_virtual_memory_bytes",
					RefID:        "C",
					LegendFormat: "Virtual Memory",
				},
			},
		},
		{
			ID:         4,
			Title:      "Event Distribution by Type",
			Type:       "barchart",
			DataSource: "Prometheus",
			GridPos:    GrafanaGridPos{H: 8, W: 12, X: 0, Y: 16},
			Targets: []GrafanaTarget{
				{
					Expr:         fmt.Sprintf("%s_sandbox_events_by_type", dg.namespace),
					RefID:        "A",
					LegendFormat: "{{type}}",
				},
			},
		},
		{
			ID:         5,
			Title:      "Event Distribution by Severity",
			Type:       "barchart",
			DataSource: "Prometheus",
			GridPos:    GrafanaGridPos{H: 8, W: 12, X: 12, Y: 16},
			Targets: []GrafanaTarget{
				{
					Expr:         fmt.Sprintf("%s_sandbox_events_by_severity", dg.namespace),
					RefID:        "A",
					LegendFormat: "{{severity}}",
				},
			},
		},
	}

	dashboard.Panels = panels
	return dashboard, nil
}

// GenerateAlertingRules generates Prometheus alerting rules
func (dg *DashboardGenerator) GenerateAlertingRules() (string, error) {
	rules := fmt.Sprintf(`groups:
- name: sandboxrunner.rules
  rules:
  - alert: HighContainerFailureRate
    expr: |
      (
        %s_sandbox_containers_by_state{state="failed"} / 
        %s_sandbox_containers_total
      ) > 0.2
    for: 5m
    labels:
      severity: critical
      component: sandbox
    annotations:
      summary: "High container failure rate"
      description: "More than 20%% of containers are in failed state (current: {{ $value }})"

  - alert: TooManyUnhealthyContainers
    expr: %s_sandbox_containers_by_health{health="unhealthy"} > 3
    for: 2m
    labels:
      severity: warning
      component: sandbox
    annotations:
      summary: "Too many unhealthy containers"
      description: "{{ $value }} containers are unhealthy"

  - alert: HighCPUUsage
    expr: %s_sandbox_resource_usage_ratio{resource="cpu"} > 0.8
    for: 10m
    labels:
      severity: warning
      component: sandbox
    annotations:
      summary: "High CPU usage"
      description: "CPU usage is above 80%% (current: {{ $value | humanizePercentage }})"

  - alert: HighMemoryUsage
    expr: %s_sandbox_resource_usage_ratio{resource="memory"} > 0.9
    for: 5m
    labels:
      severity: critical
      component: sandbox
    annotations:
      summary: "High memory usage"
      description: "Memory usage is above 90%% (current: {{ $value | humanizePercentage }})"

  - alert: SlowContainerStartup
    expr: %s_sandbox_startup_duration_seconds > 30
    for: 5m
    labels:
      severity: warning
      component: sandbox
    annotations:
      summary: "Slow container startup"
      description: "Average container startup time is {{ $value }}s"

  - alert: HighEventRate
    expr: rate(%s_sandbox_events_total[5m]) > 10
    for: 10m
    labels:
      severity: warning
      component: sandbox
    annotations:
      summary: "High event rate"
      description: "Event rate is {{ $value }} events/second"

  - alert: GoMemoryLeak
    expr: increase(go_memstats_alloc_bytes[1h]) > 100*1024*1024
    for: 30m
    labels:
      severity: warning
      component: runtime
    annotations:
      summary: "Potential memory leak"
      description: "Memory allocation increased by {{ $value | humanizeBytes }} in the last hour"

  - alert: TooManyGoroutines
    expr: go_goroutines > 1000
    for: 15m
    labels:
      severity: warning
      component: runtime
    annotations:
      summary: "Too many goroutines"
      description: "Number of goroutines: {{ $value }}"

  - alert: HighGCTime
    expr: go_gc_duration_seconds{quantile="0.9"} > 0.1
    for: 5m
    labels:
      severity: warning
      component: runtime
    annotations:
      summary: "High GC duration"
      description: "90th percentile GC duration: {{ $value }}s"

  - alert: ProcessHighCPU
    expr: rate(process_cpu_seconds_total[5m]) > 0.8
    for: 10m
    labels:
      severity: warning
      component: process
    annotations:
      summary: "High process CPU usage"
      description: "Process CPU usage: {{ $value | humanizePercentage }}"

  - alert: TooManyOpenFiles
    expr: |
      (process_open_fds / process_max_fds) > 0.8
    for: 5m
    labels:
      severity: warning
      component: process
    annotations:
      summary: "Too many open file descriptors"
      description: "Open FDs: {{ $value | humanizePercentage }} of maximum"

  - alert: SandboxRunnerDown
    expr: up{job="sandboxrunner"} == 0
    for: 1m
    labels:
      severity: critical
      component: sandbox
    annotations:
      summary: "SandboxRunner instance down"
      description: "SandboxRunner instance {{ $labels.instance }} is down"
`, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace)

	return rules, nil
}

// GenerateRecordingRules generates Prometheus recording rules
func (dg *DashboardGenerator) GenerateRecordingRules() (string, error) {
	rules := fmt.Sprintf(`groups:
- name: sandboxrunner.recording.rules
  interval: 30s
  rules:
  - record: %s:container_failure_rate
    expr: |
      (
        %s_sandbox_containers_by_state{state="failed"} / 
        %s_sandbox_containers_total
      )

  - record: %s:container_health_ratio
    expr: |
      (
        %s_sandbox_containers_by_health{health="healthy"} / 
        %s_sandbox_containers_total
      )

  - record: %s:resource_usage_max
    expr: |
      max(%s_sandbox_resource_usage_ratio) by (resource)

  - record: %s:event_rate_5m
    expr: |
      rate(%s_sandbox_events_total[5m])

  - record: %s:startup_time_p95
    expr: |
      histogram_quantile(0.95, %s_sandbox_startup_duration_seconds)

  - record: instance:go_memory_usage_bytes
    expr: |
      go_memstats_heap_alloc_bytes

  - record: instance:go_gc_rate
    expr: |
      rate(go_gc_duration_seconds_count[5m])

  - record: instance:process_cpu_usage
    expr: |
      rate(process_cpu_seconds_total[5m])

  - record: instance:file_descriptor_usage_ratio
    expr: |
      process_open_fds / process_max_fds
`, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace, dg.namespace)

	return rules, nil
}

// ExportDashboardJSON exports a dashboard as JSON
func (dg *DashboardGenerator) ExportDashboardJSON(dashboard *GrafanaDashboard) (string, error) {
	data, err := json.MarshalIndent(dashboard, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal dashboard: %w", err)
	}
	return string(data), nil
}

// GeneratePrometheusConfig generates Prometheus configuration
func (dg *DashboardGenerator) GeneratePrometheusConfig(metricsPort int) (string, error) {
	config := fmt.Sprintf(`global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    monitor: 'sandboxrunner'

rule_files:
  - "sandboxrunner-alerts.yml"
  - "sandboxrunner-recording.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'sandboxrunner'
    static_configs:
      - targets: ['localhost:%d']
    scrape_interval: 15s
    scrape_timeout: 10s
    metrics_path: /metrics
    scheme: http

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 15s

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 15s
`, metricsPort)

	return config, nil
}

// GenerateAlertManagerConfig generates AlertManager configuration
func (dg *DashboardGenerator) GenerateAlertManagerConfig() (string, error) {
	config := `global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alertmanager@sandboxrunner.local'

route:
  group_by: ['alertname', 'component']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'
  routes:
  - match:
      severity: critical
    receiver: 'critical-alerts'
    group_wait: 5s
    repeat_interval: 5m

receivers:
- name: 'web.hook'
  webhook_configs:
  - url: 'http://localhost:5001/webhook'

- name: 'critical-alerts'
  webhook_configs:
  - url: 'http://localhost:5001/webhook'
  email_configs:
  - to: 'admin@sandboxrunner.local'
    subject: 'SandboxRunner Critical Alert'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      {{ end }}

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'component']
`

	return config, nil
}

// GenerateComposeFile generates Docker Compose file for monitoring stack
func (dg *DashboardGenerator) GenerateComposeFile(sandboxRunnerPort int) (string, error) {
	compose := fmt.Sprintf(`version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./sandboxrunner-alerts.yml:/etc/prometheus/sandboxrunner-alerts.yml
      - ./sandboxrunner-recording.yml:/etc/prometheus/sandboxrunner-recording.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
      - '--web.enable-admin-api'
    restart: unless-stopped

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
      - alertmanager_data:/alertmanager
    command:
      - '--config.file=/etc/alertmanager/alertmanager.yml'
      - '--storage.path=/alertmanager'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    restart: unless-stopped

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    ports:
      - "8080:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
      - /dev/disk/:/dev/disk:ro
    privileged: true
    restart: unless-stopped

volumes:
  prometheus_data:
  alertmanager_data:
  grafana_data:

networks:
  default:
    external:
      name: monitoring
`)

	return compose, nil
}

// DashboardConfig represents dashboard configuration
type DashboardConfig struct {
	Generator   *DashboardGenerator
	OutputDir   string
	MetricsPort int
}

// NewDashboardConfig creates new dashboard configuration
func NewDashboardConfig(namespace string, outputDir string, metricsPort int) *DashboardConfig {
	return &DashboardConfig{
		Generator:   NewDashboardGenerator(namespace),
		OutputDir:   outputDir,
		MetricsPort: metricsPort,
	}
}

// GenerateAll generates all monitoring configuration files
func (dc *DashboardConfig) GenerateAll() error {
	// Generate overview dashboard
	overviewDashboard, err := dc.Generator.GenerateSandboxOverviewDashboard()
	if err != nil {
		return fmt.Errorf("failed to generate overview dashboard: %w", err)
	}

	overviewJSON, err := dc.Generator.ExportDashboardJSON(overviewDashboard)
	if err != nil {
		return fmt.Errorf("failed to export overview dashboard: %w", err)
	}

	// Generate detailed dashboard
	detailedDashboard, err := dc.Generator.GenerateDetailedDashboard()
	if err != nil {
		return fmt.Errorf("failed to generate detailed dashboard: %w", err)
	}

	detailedJSON, err := dc.Generator.ExportDashboardJSON(detailedDashboard)
	if err != nil {
		return fmt.Errorf("failed to export detailed dashboard: %w", err)
	}

	// Generate alerting rules
	alertingRules, err := dc.Generator.GenerateAlertingRules()
	if err != nil {
		return fmt.Errorf("failed to generate alerting rules: %w", err)
	}

	// Generate recording rules
	recordingRules, err := dc.Generator.GenerateRecordingRules()
	if err != nil {
		return fmt.Errorf("failed to generate recording rules: %w", err)
	}

	// Generate Prometheus config
	prometheusConfig, err := dc.Generator.GeneratePrometheusConfig(dc.MetricsPort)
	if err != nil {
		return fmt.Errorf("failed to generate Prometheus config: %w", err)
	}

	// Generate AlertManager config
	alertManagerConfig, err := dc.Generator.GenerateAlertManagerConfig()
	if err != nil {
		return fmt.Errorf("failed to generate AlertManager config: %w", err)
	}

	// Generate Docker Compose
	composeFile, err := dc.Generator.GenerateComposeFile(dc.MetricsPort)
	if err != nil {
		return fmt.Errorf("failed to generate Docker Compose file: %w", err)
	}

	// Store all configurations in a map for easy access
	configs := map[string]string{
		"overview-dashboard.json":      overviewJSON,
		"detailed-dashboard.json":      detailedJSON,
		"sandboxrunner-alerts.yml":     alertingRules,
		"sandboxrunner-recording.yml":  recordingRules,
		"prometheus.yml":               prometheusConfig,
		"alertmanager.yml":             alertManagerConfig,
		"docker-compose.yml":           composeFile,
	}

	// Note: In a real implementation, you would write these files to disk
	// For now, we'll just log that they were generated
	for filename, content := range configs {
		fmt.Printf("Generated %s (%d bytes)\n", filename, len(content))
	}

	return nil
}