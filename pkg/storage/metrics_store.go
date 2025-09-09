package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
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

// AggregationPeriod represents the time period for metric aggregation
type AggregationPeriod string

const (
	AggregationRaw AggregationPeriod = "raw"
	Aggregation1m  AggregationPeriod = "1m"
	Aggregation5m  AggregationPeriod = "5m"
	Aggregation15m AggregationPeriod = "15m"
	Aggregation1h  AggregationPeriod = "1h"
	Aggregation6h  AggregationPeriod = "6h"
	Aggregation1d  AggregationPeriod = "1d"
	Aggregation7d  AggregationPeriod = "7d"
)

// Metric represents a single metric data point
type Metric struct {
	ID                int64             `json:"id"`
	MetricName        string            `json:"metric_name"`
	MetricType        MetricType        `json:"metric_type"`
	Labels            map[string]string `json:"labels"`
	Value             float64           `json:"value"`
	Timestamp         time.Time         `json:"timestamp"`
	SandboxID         string            `json:"sandbox_id,omitempty"`
	AggregationPeriod AggregationPeriod `json:"aggregation_period"`
}

// TimeSeriesQuery represents a query for time series data
type TimeSeriesQuery struct {
	MetricName     string
	SandboxID      string
	Labels         map[string]string
	StartTime      time.Time
	EndTime        time.Time
	Aggregation    AggregationPeriod
	GroupBy        []string
	Limit          int
}

// AggregatedMetric represents an aggregated metric value
type AggregatedMetric struct {
	MetricName        string                 `json:"metric_name"`
	Labels            map[string]string      `json:"labels"`
	Timestamp         time.Time              `json:"timestamp"`
	AggregationPeriod AggregationPeriod      `json:"aggregation_period"`
	Count             int64                  `json:"count"`
	Sum               float64                `json:"sum"`
	Min               float64                `json:"min"`
	Max               float64                `json:"max"`
	Avg               float64                `json:"avg"`
	Percentiles       map[string]float64     `json:"percentiles,omitempty"`
	Values            []float64              `json:"values,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// MetricFilter provides filtering options for metric queries
type MetricFilter struct {
	MetricNames       []string
	MetricTypes       []MetricType
	SandboxIDs        []string
	Labels            map[string]string
	StartTime         time.Time
	EndTime           time.Time
	AggregationPeriod AggregationPeriod
	Limit             int
	Offset            int
}

// RetentionPolicy defines how long to keep metrics at different aggregation levels
type RetentionPolicy struct {
	Period    AggregationPeriod `json:"period"`
	Duration  time.Duration     `json:"duration"`
	Enabled   bool              `json:"enabled"`
}

// MetricsStore provides time-series metric storage and aggregation
type MetricsStore struct {
	store            *SQLiteStore
	retentionPolicies []RetentionPolicy
	compressionLevel  int
	enableCompression bool
}

// NewMetricsStore creates a new metrics store
func NewMetricsStore(store *SQLiteStore) *MetricsStore {
	return &MetricsStore{
		store: store,
		retentionPolicies: []RetentionPolicy{
			{Period: AggregationRaw, Duration: time.Hour * 24, Enabled: true},      // 1 day raw data
			{Period: Aggregation1m, Duration: time.Hour * 24 * 7, Enabled: true},  // 7 days 1-minute data
			{Period: Aggregation5m, Duration: time.Hour * 24 * 30, Enabled: true}, // 30 days 5-minute data
			{Period: Aggregation1h, Duration: time.Hour * 24 * 90, Enabled: true}, // 90 days 1-hour data
			{Period: Aggregation1d, Duration: time.Hour * 24 * 365, Enabled: true}, // 1 year daily data
		},
		compressionLevel:  6,
		enableCompression: true,
	}
}

// Record stores a metric data point
func (m *MetricsStore) Record(ctx context.Context, metric *Metric) error {
	if metric.MetricName == "" {
		return fmt.Errorf("metric name cannot be empty")
	}

	if metric.Timestamp.IsZero() {
		metric.Timestamp = time.Now()
	}

	if metric.AggregationPeriod == "" {
		metric.AggregationPeriod = AggregationRaw
	}

	// Serialize labels
	labelsJSON, err := json.Marshal(metric.Labels)
	if err != nil {
		return fmt.Errorf("failed to marshal labels: %w", err)
	}

	// Insert metric
	query := `
		INSERT INTO metrics (
			metric_name, metric_type, labels, value, timestamp, 
			sandbox_id, aggregation_period
		) VALUES (?, ?, ?, ?, ?, ?, ?)`

	result, err := m.store.Exec(ctx, query,
		metric.MetricName, string(metric.MetricType), string(labelsJSON),
		metric.Value, metric.Timestamp, metric.SandboxID, string(metric.AggregationPeriod))
	if err != nil {
		return fmt.Errorf("failed to insert metric: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get insert ID: %w", err)
	}

	metric.ID = id

	log.Debug().
		Str("metric_name", metric.MetricName).
		Str("metric_type", string(metric.MetricType)).
		Float64("value", metric.Value).
		Time("timestamp", metric.Timestamp).
		Msg("Metric recorded successfully")

	return nil
}

// RecordBatch stores multiple metrics in a single transaction
func (m *MetricsStore) RecordBatch(ctx context.Context, metrics []*Metric) error {
	if len(metrics) == 0 {
		return nil
	}

	tx, err := m.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO metrics (
			metric_name, metric_type, labels, value, timestamp, 
			sandbox_id, aggregation_period
		) VALUES (?, ?, ?, ?, ?, ?, ?)`

	for _, metric := range metrics {
		if metric.MetricName == "" {
			continue // Skip invalid metrics
		}

		if metric.Timestamp.IsZero() {
			metric.Timestamp = time.Now()
		}

		if metric.AggregationPeriod == "" {
			metric.AggregationPeriod = AggregationRaw
		}

		// Serialize labels
		labelsJSON, err := json.Marshal(metric.Labels)
		if err != nil {
			log.Warn().Err(err).Str("metric_name", metric.MetricName).Msg("Failed to marshal labels")
			continue
		}

		result, err := tx.Exec(query,
			metric.MetricName, string(metric.MetricType), string(labelsJSON),
			metric.Value, metric.Timestamp, metric.SandboxID, string(metric.AggregationPeriod))
		if err != nil {
			log.Warn().Err(err).Str("metric_name", metric.MetricName).Msg("Failed to insert metric in batch")
			continue
		}

		id, err := result.LastInsertId()
		if err == nil {
			metric.ID = id
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit batch: %w", err)
	}

	log.Info().
		Int("batch_size", len(metrics)).
		Msg("Metric batch recorded successfully")

	return nil
}

// Query retrieves metrics based on the provided filter
func (m *MetricsStore) Query(ctx context.Context, filter *MetricFilter) ([]*Metric, error) {
	query := `
		SELECT id, metric_name, metric_type, labels, value, timestamp, 
		       sandbox_id, aggregation_period
		FROM metrics WHERE 1=1`

	args := []interface{}{}

	if len(filter.MetricNames) > 0 {
		placeholders := make([]string, len(filter.MetricNames))
		for i, name := range filter.MetricNames {
			placeholders[i] = "?"
			args = append(args, name)
		}
		query += " AND metric_name IN (" + strings.Join(placeholders, ",") + ")"
	}

	if len(filter.MetricTypes) > 0 {
		placeholders := make([]string, len(filter.MetricTypes))
		for i, mType := range filter.MetricTypes {
			placeholders[i] = "?"
			args = append(args, string(mType))
		}
		query += " AND metric_type IN (" + strings.Join(placeholders, ",") + ")"
	}

	if len(filter.SandboxIDs) > 0 {
		placeholders := make([]string, len(filter.SandboxIDs))
		for i, id := range filter.SandboxIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		query += " AND sandbox_id IN (" + strings.Join(placeholders, ",") + ")"
	}

	if !filter.StartTime.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, filter.StartTime)
	}

	if !filter.EndTime.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, filter.EndTime)
	}

	if filter.AggregationPeriod != "" {
		query += " AND aggregation_period = ?"
		args = append(args, string(filter.AggregationPeriod))
	}

	// Label filtering (simple contains check)
	for key, value := range filter.Labels {
		query += " AND labels LIKE ?"
		args = append(args, fmt.Sprintf(`%%"%s":"%s"%%`, key, value))
	}

	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)

		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := m.store.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query metrics: %w", err)
	}
	defer rows.Close()

	var metrics []*Metric
	for rows.Next() {
		var metric Metric
		var labelsJSON string
		var metricType, aggregationPeriod string

		err := rows.Scan(
			&metric.ID, &metric.MetricName, &metricType, &labelsJSON,
			&metric.Value, &metric.Timestamp, &metric.SandboxID, &aggregationPeriod,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan metric: %w", err)
		}

		metric.MetricType = MetricType(metricType)
		metric.AggregationPeriod = AggregationPeriod(aggregationPeriod)

		// Deserialize labels
		if labelsJSON != "" {
			if err := json.Unmarshal([]byte(labelsJSON), &metric.Labels); err != nil {
				return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
			}
		}

		metrics = append(metrics, &metric)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	return metrics, nil
}

// Aggregate performs time-based aggregation of metrics
func (m *MetricsStore) Aggregate(ctx context.Context, query *TimeSeriesQuery) ([]*AggregatedMetric, error) {
	if query.MetricName == "" {
		return nil, fmt.Errorf("metric name cannot be empty")
	}

	if query.StartTime.IsZero() || query.EndTime.IsZero() {
		return nil, fmt.Errorf("start and end times must be specified")
	}

	if query.Aggregation == "" {
		query.Aggregation = Aggregation1m
	}

	// Calculate time buckets based on aggregation period
	bucketSize := m.getAggregationInterval(query.Aggregation)
	if bucketSize == 0 {
		return nil, fmt.Errorf("invalid aggregation period: %s", query.Aggregation)
	}

	// Build SQL query for aggregation
	sqlQuery := `
		WITH time_buckets AS (
			SELECT 
				metric_name,
				labels,
				sandbox_id,
				datetime(
					(strftime('%s', timestamp) / ?) * ?, 
					'unixepoch'
				) as bucket_time,
				value
			FROM metrics
			WHERE metric_name = ?
				AND timestamp >= ?
				AND timestamp <= ?`

	args := []interface{}{
		int64(bucketSize.Seconds()),
		int64(bucketSize.Seconds()),
		query.MetricName,
		query.StartTime,
		query.EndTime,
	}

	if query.SandboxID != "" {
		sqlQuery += " AND sandbox_id = ?"
		args = append(args, query.SandboxID)
	}

	sqlQuery += `
		)
		SELECT 
			metric_name,
			labels,
			sandbox_id,
			bucket_time,
			COUNT(*) as count,
			SUM(value) as sum,
			MIN(value) as min,
			MAX(value) as max,
			AVG(value) as avg,
			GROUP_CONCAT(value) as values
		FROM time_buckets`

	// Add GROUP BY clause
	groupByFields := []string{"metric_name", "labels", "bucket_time"}
	if query.SandboxID == "" {
		groupByFields = append(groupByFields, "sandbox_id")
	}
	for _, field := range query.GroupBy {
		if !contains(groupByFields, field) {
			groupByFields = append(groupByFields, field)
		}
	}

	sqlQuery += " GROUP BY " + strings.Join(groupByFields, ", ")
	sqlQuery += " ORDER BY bucket_time ASC"

	if query.Limit > 0 {
		sqlQuery += " LIMIT ?"
		args = append(args, query.Limit)
	}

	rows, err := m.store.Query(ctx, sqlQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute aggregation query: %w", err)
	}
	defer rows.Close()

	var results []*AggregatedMetric
	for rows.Next() {
		var result AggregatedMetric
		var labelsJSON, sandboxID, bucketTime, valuesStr string

		err := rows.Scan(
			&result.MetricName, &labelsJSON, &sandboxID, &bucketTime,
			&result.Count, &result.Sum, &result.Min, &result.Max, &result.Avg, &valuesStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan aggregation result: %w", err)
		}

		// Parse timestamp
		result.Timestamp, err = time.Parse("2006-01-02 15:04:05", bucketTime)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bucket time: %w", err)
		}

		result.AggregationPeriod = query.Aggregation

		// Deserialize labels
		if labelsJSON != "" {
			if err := json.Unmarshal([]byte(labelsJSON), &result.Labels); err != nil {
				return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
			}
		}

		// Add sandbox_id to labels if it's not the queried one
		if query.SandboxID == "" && sandboxID != "" {
			if result.Labels == nil {
				result.Labels = make(map[string]string)
			}
			result.Labels["sandbox_id"] = sandboxID
		}

		// Parse individual values for percentile calculation
		if valuesStr != "" {
			valueStrs := strings.Split(valuesStr, ",")
			result.Values = make([]float64, 0, len(valueStrs))
			for _, valueStr := range valueStrs {
				if value, err := parseFloat(strings.TrimSpace(valueStr)); err == nil {
					result.Values = append(result.Values, value)
				}
			}

			// Calculate percentiles
			if len(result.Values) > 0 {
				result.Percentiles = m.calculatePercentiles(result.Values)
			}
		}

		results = append(results, &result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	log.Info().
		Str("metric_name", query.MetricName).
		Str("aggregation", string(query.Aggregation)).
		Time("start_time", query.StartTime).
		Time("end_time", query.EndTime).
		Int("result_count", len(results)).
		Msg("Metric aggregation completed")

	return results, nil
}

// CreateAggregations pre-computes aggregations for faster queries
func (m *MetricsStore) CreateAggregations(ctx context.Context, period AggregationPeriod) error {
	log.Info().Str("period", string(period)).Msg("Starting metric aggregation")

	bucketSize := m.getAggregationInterval(period)
	if bucketSize == 0 {
		return fmt.Errorf("invalid aggregation period: %s", period)
	}

	// Calculate time range for aggregation (last period only)
	endTime := time.Now().Truncate(bucketSize)
	startTime := endTime.Add(-bucketSize)

	tx, err := m.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing aggregations for this period
	deleteQuery := `
		DELETE FROM metrics 
		WHERE aggregation_period = ? 
			AND timestamp >= ? 
			AND timestamp < ?`
	_, err = tx.Exec(deleteQuery, string(period), startTime, endTime)
	if err != nil {
		return fmt.Errorf("failed to delete existing aggregations: %w", err)
	}

	// Create new aggregations
	insertQuery := `
		INSERT INTO metrics (
			metric_name, metric_type, labels, value, timestamp, 
			sandbox_id, aggregation_period
		)
		SELECT 
			metric_name,
			metric_type,
			labels,
			AVG(value) as value,
			datetime(
				(strftime('%s', timestamp) / ?) * ?, 
				'unixepoch'
			) as bucket_time,
			sandbox_id,
			?
		FROM metrics
		WHERE aggregation_period = 'raw'
			AND timestamp >= ?
			AND timestamp < ?
		GROUP BY metric_name, metric_type, labels, sandbox_id, bucket_time`

	_, err = tx.Exec(insertQuery,
		int64(bucketSize.Seconds()),
		int64(bucketSize.Seconds()),
		string(period),
		startTime,
		endTime)
	if err != nil {
		return fmt.Errorf("failed to create aggregations: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit aggregations: %w", err)
	}

	log.Info().
		Str("period", string(period)).
		Time("start_time", startTime).
		Time("end_time", endTime).
		Msg("Metric aggregations created successfully")

	return nil
}

// ApplyRetentionPolicies removes old metrics based on retention policies
func (m *MetricsStore) ApplyRetentionPolicies(ctx context.Context) error {
	log.Info().Msg("Applying metric retention policies")

	tx, err := m.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	totalDeleted := int64(0)

	for _, policy := range m.retentionPolicies {
		if !policy.Enabled {
			continue
		}

		cutoffTime := time.Now().Add(-policy.Duration)
		
		deleteQuery := "DELETE FROM metrics WHERE aggregation_period = ? AND timestamp < ?"
		result, err := tx.Exec(deleteQuery, string(policy.Period), cutoffTime)
		if err != nil {
			log.Error().
				Err(err).
				Str("period", string(policy.Period)).
				Msg("Failed to apply retention policy")
			continue
		}

		deleted, err := result.RowsAffected()
		if err == nil {
			totalDeleted += deleted
			log.Info().
				Str("period", string(policy.Period)).
				Time("cutoff_time", cutoffTime).
				Int64("deleted_count", deleted).
				Msg("Applied retention policy")
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit retention policy application: %w", err)
	}

	log.Info().
		Int64("total_deleted", totalDeleted).
		Msg("Retention policies applied successfully")

	return nil
}

// GetMetricsStats returns statistics about stored metrics
func (m *MetricsStore) GetMetricsStats(ctx context.Context) (*MetricsStats, error) {
	var stats MetricsStats

	// Get overall stats
	overallQuery := `
		SELECT 
			COUNT(*) as total_count,
			COUNT(DISTINCT metric_name) as unique_metrics,
			COUNT(DISTINCT sandbox_id) as unique_sandboxes,
			MIN(timestamp) as oldest_timestamp,
			MAX(timestamp) as newest_timestamp
		FROM metrics`

	row := m.store.QueryRow(ctx, overallQuery)
	err := row.Scan(
		&stats.TotalCount, &stats.UniqueMetrics, &stats.UniqueSandboxes,
		&stats.OldestTimestamp, &stats.NewestTimestamp)
	if err != nil {
		return nil, fmt.Errorf("failed to get overall stats: %w", err)
	}

	// Get stats by aggregation period
	periodQuery := `
		SELECT 
			aggregation_period,
			COUNT(*) as count,
			MIN(timestamp) as oldest,
			MAX(timestamp) as newest
		FROM metrics
		GROUP BY aggregation_period`

	rows, err := m.store.Query(ctx, periodQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get period stats: %w", err)
	}
	defer rows.Close()

	stats.ByPeriod = make(map[string]PeriodStats)
	for rows.Next() {
		var period string
		var periodStat PeriodStats

		err := rows.Scan(&period, &periodStat.Count, &periodStat.OldestTimestamp, &periodStat.NewestTimestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to scan period stats: %w", err)
		}

		stats.ByPeriod[period] = periodStat
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	// Get top metrics by count
	topMetricsQuery := `
		SELECT metric_name, COUNT(*) as count
		FROM metrics
		GROUP BY metric_name
		ORDER BY count DESC
		LIMIT 10`

	topRows, err := m.store.Query(ctx, topMetricsQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get top metrics: %w", err)
	}
	defer topRows.Close()

	for topRows.Next() {
		var metric TopMetric
		err := topRows.Scan(&metric.Name, &metric.Count)
		if err != nil {
			return nil, fmt.Errorf("failed to scan top metric: %w", err)
		}
		stats.TopMetrics = append(stats.TopMetrics, metric)
	}

	if err := topRows.Err(); err != nil {
		return nil, fmt.Errorf("top metrics row iteration error: %w", err)
	}

	return &stats, nil
}

// ExportMetrics exports metrics to a structured format for backup or analysis
func (m *MetricsStore) ExportMetrics(ctx context.Context, filter *MetricFilter, format string) (interface{}, error) {
	metrics, err := m.Query(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query metrics for export: %w", err)
	}

	switch format {
	case "json":
		return metrics, nil
	case "csv":
		return m.exportToCSV(metrics), nil
	case "prometheus":
		return m.exportToPrometheus(metrics), nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// MetricsStats represents statistics about stored metrics
type MetricsStats struct {
	TotalCount       int64                 `json:"total_count"`
	UniqueMetrics    int64                 `json:"unique_metrics"`
	UniqueSandboxes  int64                 `json:"unique_sandboxes"`
	OldestTimestamp  time.Time             `json:"oldest_timestamp"`
	NewestTimestamp  time.Time             `json:"newest_timestamp"`
	ByPeriod         map[string]PeriodStats `json:"by_period"`
	TopMetrics       []TopMetric           `json:"top_metrics"`
}

// PeriodStats represents statistics for a specific aggregation period
type PeriodStats struct {
	Count           int64     `json:"count"`
	OldestTimestamp time.Time `json:"oldest_timestamp"`
	NewestTimestamp time.Time `json:"newest_timestamp"`
}

// TopMetric represents a metric with its count
type TopMetric struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// getAggregationInterval returns the time interval for an aggregation period
func (m *MetricsStore) getAggregationInterval(period AggregationPeriod) time.Duration {
	switch period {
	case AggregationRaw:
		return 0
	case Aggregation1m:
		return time.Minute
	case Aggregation5m:
		return time.Minute * 5
	case Aggregation15m:
		return time.Minute * 15
	case Aggregation1h:
		return time.Hour
	case Aggregation6h:
		return time.Hour * 6
	case Aggregation1d:
		return time.Hour * 24
	case Aggregation7d:
		return time.Hour * 24 * 7
	default:
		return 0
	}
}

// calculatePercentiles calculates percentiles for a slice of values
func (m *MetricsStore) calculatePercentiles(values []float64) map[string]float64 {
	if len(values) == 0 {
		return nil
	}

	// Sort values
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	percentiles := map[string]float64{
		"p50":  m.percentile(sorted, 0.50),
		"p90":  m.percentile(sorted, 0.90),
		"p95":  m.percentile(sorted, 0.95),
		"p99":  m.percentile(sorted, 0.99),
		"p999": m.percentile(sorted, 0.999),
	}

	return percentiles
}

// percentile calculates the percentile value for sorted data
func (m *MetricsStore) percentile(sortedValues []float64, p float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}

	if p <= 0 {
		return sortedValues[0]
	}
	if p >= 1 {
		return sortedValues[len(sortedValues)-1]
	}

	index := p * float64(len(sortedValues)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sortedValues[lower]
	}

	// Linear interpolation
	weight := index - float64(lower)
	return sortedValues[lower]*(1-weight) + sortedValues[upper]*weight
}

// exportToCSV converts metrics to CSV format
func (m *MetricsStore) exportToCSV(metrics []*Metric) string {
	var csv strings.Builder
	csv.WriteString("timestamp,metric_name,metric_type,value,sandbox_id,labels\n")

	for _, metric := range metrics {
		labelsJSON, _ := json.Marshal(metric.Labels)
		csv.WriteString(fmt.Sprintf("%s,%s,%s,%f,%s,\"%s\"\n",
			metric.Timestamp.Format(time.RFC3339),
			metric.MetricName,
			string(metric.MetricType),
			metric.Value,
			metric.SandboxID,
			string(labelsJSON)))
	}

	return csv.String()
}

// exportToPrometheus converts metrics to Prometheus format
func (m *MetricsStore) exportToPrometheus(metrics []*Metric) string {
	var prom strings.Builder

	for _, metric := range metrics {
		// Build labels
		var labelParts []string
		for key, value := range metric.Labels {
			labelParts = append(labelParts, fmt.Sprintf(`%s="%s"`, key, value))
		}
		if metric.SandboxID != "" {
			labelParts = append(labelParts, fmt.Sprintf(`sandbox_id="%s"`, metric.SandboxID))
		}

		labelsStr := ""
		if len(labelParts) > 0 {
			labelsStr = "{" + strings.Join(labelParts, ",") + "}"
		}

		prom.WriteString(fmt.Sprintf("%s%s %f %d\n",
			metric.MetricName,
			labelsStr,
			metric.Value,
			metric.Timestamp.Unix()*1000))
	}

	return prom.String()
}

// parseFloat safely parses a string to float64
func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// CompressOldMetrics compresses old metric data to save space
func (m *MetricsStore) CompressOldMetrics(ctx context.Context, olderThan time.Duration) error {
	if !m.enableCompression {
		return nil
	}

	log.Info().Dur("older_than", olderThan).Msg("Starting metric compression")

	cutoffTime := time.Now().Add(-olderThan)

	// This is a placeholder for compression logic
	// In a real implementation, you might want to:
	// 1. Group similar metrics together
	// 2. Apply lossy compression for old data
	// 3. Store compressed data in separate tables
	// 4. Update queries to handle compressed data

	// For now, we'll just aggregate very old raw data into larger time buckets
	tx, err := m.store.BeginTransaction(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin compression transaction: %w", err)
	}
	defer tx.Rollback()

	// Create 1-day aggregations for raw data older than cutoff
	compressQuery := `
		INSERT OR REPLACE INTO metrics (
			metric_name, metric_type, labels, value, timestamp,
			sandbox_id, aggregation_period
		)
		SELECT 
			metric_name,
			metric_type,
			labels,
			AVG(value),
			datetime(date(timestamp)) as day_timestamp,
			sandbox_id,
			'1d'
		FROM metrics
		WHERE aggregation_period = 'raw' AND timestamp < ?
		GROUP BY metric_name, metric_type, labels, sandbox_id, date(timestamp)`

	_, err = tx.Exec(compressQuery, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to create compressed aggregations: %w", err)
	}

	// Delete the original raw data
	deleteQuery := "DELETE FROM metrics WHERE aggregation_period = 'raw' AND timestamp < ?"
	result, err := tx.Exec(deleteQuery, cutoffTime)
	if err != nil {
		return fmt.Errorf("failed to delete raw data: %w", err)
	}

	deletedCount, _ := result.RowsAffected()

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit compression: %w", err)
	}

	log.Info().
		Time("cutoff_time", cutoffTime).
		Int64("compressed_count", deletedCount).
		Msg("Metric compression completed")

	return nil
}