package sandbox

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// MetricsCollector collects and aggregates metrics from various sources
type MetricsCollector struct {
	manager       *Manager
	mu            sync.RWMutex
	metrics       *SystemMetrics
	alertRules    []AlertRule
	ctx           context.Context
	cancel        context.CancelFunc
	stopOnce      sync.Once
	collectionInterval time.Duration
}

// SystemMetrics contains comprehensive system metrics
type SystemMetrics struct {
	// Container metrics
	TotalContainers    int                            `json:"total_containers"`
	RunningContainers  int                            `json:"running_containers"`
	StoppedContainers  int                            `json:"stopped_containers"`
	FailedContainers   int                            `json:"failed_containers"`
	PausedContainers   int                            `json:"paused_containers"`
	CreatingContainers int                            `json:"creating_containers"`
	StateDistribution  map[ContainerState]int         `json:"state_distribution"`
	
	// Health metrics
	HealthyContainers   int                           `json:"healthy_containers"`
	UnhealthyContainers int                           `json:"unhealthy_containers"`
	WarningContainers   int                           `json:"warning_containers"`
	UnknownHealthContainers int                       `json:"unknown_health_containers"`
	HealthDistribution  map[HealthStatus]int          `json:"health_distribution"`
	
	// Event metrics
	TotalEvents        int                            `json:"total_events"`
	EventsByType       map[EventType]int              `json:"events_by_type"`
	EventsBySeverity   map[EventSeverity]int          `json:"events_by_severity"`
	RecentEventCount   int                            `json:"recent_event_count"`
	
	// Performance metrics
	AverageStartupTime    time.Duration                `json:"average_startup_time"`
	AverageHealthCheckTime time.Duration               `json:"average_health_check_time"`
	StateTransitionCount  int                          `json:"state_transition_count"`
	HealthCheckCount      int                          `json:"health_check_count"`
	
	// Resource metrics
	TotalCPUUsage    float64                          `json:"total_cpu_usage"`
	TotalMemoryUsage float64                          `json:"total_memory_usage"`
	TotalDiskUsage   float64                          `json:"total_disk_usage"`
	
	// Metadata
	Timestamp        time.Time                        `json:"timestamp"`
	CollectionTime   time.Duration                    `json:"collection_time"`
	Uptime          time.Duration                     `json:"uptime"`
	LastUpdate      time.Time                         `json:"last_update"`
}

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Condition   AlertCondition `json:"condition"`
	Severity    EventSeverity  `json:"severity"`
	Threshold   float64       `json:"threshold"`
	Duration    time.Duration  `json:"duration"`
	Enabled     bool          `json:"enabled"`
	LastFired   *time.Time    `json:"last_fired,omitempty"`
	FireCount   int64         `json:"fire_count"`
}

// AlertCondition represents different types of alert conditions
type AlertCondition string

const (
	// AlertConditionContainerFailureRate triggers when container failure rate exceeds threshold
	AlertConditionContainerFailureRate AlertCondition = "container_failure_rate"
	// AlertConditionUnhealthyContainers triggers when unhealthy container count exceeds threshold
	AlertConditionUnhealthyContainers AlertCondition = "unhealthy_containers"
	// AlertConditionHighResourceUsage triggers when resource usage exceeds threshold
	AlertConditionHighResourceUsage AlertCondition = "high_resource_usage"
	// AlertConditionEventRate triggers when event rate exceeds threshold
	AlertConditionEventRate AlertCondition = "event_rate"
	// AlertConditionSlowStartup triggers when average startup time exceeds threshold
	AlertConditionSlowStartup AlertCondition = "slow_startup"
)

// AlertEvaluationResult represents the result of evaluating an alert rule
type AlertEvaluationResult struct {
	RuleID    string        `json:"rule_id"`
	Triggered bool          `json:"triggered"`
	Value     float64       `json:"value"`
	Threshold float64       `json:"threshold"`
	Message   string        `json:"message"`
	Timestamp time.Time     `json:"timestamp"`
}

// DefaultAlertRules returns default alert rules for common scenarios
func DefaultAlertRules() []AlertRule {
	return []AlertRule{
		{
			ID:          "high-failure-rate",
			Name:        "High Container Failure Rate",
			Description: "Triggers when more than 20% of containers are in failed state",
			Condition:   AlertConditionContainerFailureRate,
			Severity:    EventSeverityCritical,
			Threshold:   0.2, // 20%
			Duration:    5 * time.Minute,
			Enabled:     true,
		},
		{
			ID:          "unhealthy-containers",
			Name:        "Unhealthy Containers",
			Description: "Triggers when more than 3 containers are unhealthy",
			Condition:   AlertConditionUnhealthyContainers,
			Severity:    EventSeverityWarning,
			Threshold:   3,
			Duration:    2 * time.Minute,
			Enabled:     true,
		},
		{
			ID:          "high-cpu-usage",
			Name:        "High CPU Usage",
			Description: "Triggers when average CPU usage exceeds 80%",
			Condition:   AlertConditionHighResourceUsage,
			Severity:    EventSeverityWarning,
			Threshold:   0.8, // 80%
			Duration:    10 * time.Minute,
			Enabled:     true,
		},
		{
			ID:          "slow-startup",
			Name:        "Slow Container Startup",
			Description: "Triggers when average startup time exceeds 30 seconds",
			Condition:   AlertConditionSlowStartup,
			Severity:    EventSeverityWarning,
			Threshold:   30, // seconds
			Duration:    5 * time.Minute,
			Enabled:     true,
		},
	}
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(manager *Manager, collectionInterval time.Duration) *MetricsCollector {
	ctx, cancel := context.WithCancel(context.Background())
	
	mc := &MetricsCollector{
		manager:            manager,
		metrics:            &SystemMetrics{},
		alertRules:         DefaultAlertRules(),
		ctx:                ctx,
		cancel:             cancel,
		collectionInterval: collectionInterval,
	}

	// Start metrics collection
	go mc.collectMetrics()

	// Start alert evaluation
	go mc.evaluateAlerts()

	log.Info().
		Dur("collection_interval", collectionInterval).
		Int("alert_rules", len(mc.alertRules)).
		Msg("Metrics collector initialized")

	return mc
}

// GetMetrics returns the current system metrics
func (mc *MetricsCollector) GetMetrics() *SystemMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	
	// Return a copy to prevent race conditions
	metricsCopy := *mc.metrics
	return &metricsCopy
}

// GetAlertRules returns all configured alert rules
func (mc *MetricsCollector) GetAlertRules() []AlertRule {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	
	rules := make([]AlertRule, len(mc.alertRules))
	copy(rules, mc.alertRules)
	return rules
}

// AddAlertRule adds a new alert rule
func (mc *MetricsCollector) AddAlertRule(rule AlertRule) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	mc.alertRules = append(mc.alertRules, rule)
	
	log.Info().
		Str("rule_id", rule.ID).
		Str("rule_name", rule.Name).
		Msg("Alert rule added")
}

// UpdateAlertRule updates an existing alert rule
func (mc *MetricsCollector) UpdateAlertRule(ruleID string, rule AlertRule) bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	for i, r := range mc.alertRules {
		if r.ID == ruleID {
			rule.ID = ruleID // Preserve ID
			mc.alertRules[i] = rule
			log.Info().
				Str("rule_id", ruleID).
				Str("rule_name", rule.Name).
				Msg("Alert rule updated")
			return true
		}
	}
	return false
}

// RemoveAlertRule removes an alert rule
func (mc *MetricsCollector) RemoveAlertRule(ruleID string) bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	for i, rule := range mc.alertRules {
		if rule.ID == ruleID {
			mc.alertRules = append(mc.alertRules[:i], mc.alertRules[i+1:]...)
			log.Info().
				Str("rule_id", ruleID).
				Str("rule_name", rule.Name).
				Msg("Alert rule removed")
			return true
		}
	}
	return false
}

// Stop stops the metrics collector
func (mc *MetricsCollector) Stop() {
	mc.stopOnce.Do(func() {
		log.Info().Msg("Stopping metrics collector")
		mc.cancel()
	})
}

// collectMetrics periodically collects and updates system metrics
func (mc *MetricsCollector) collectMetrics() {
	ticker := time.NewTicker(mc.collectionInterval)
	defer ticker.Stop()

	// Collect initial metrics
	mc.updateMetrics()

	for {
		select {
		case <-mc.ctx.Done():
			log.Info().Msg("Metrics collection stopped")
			return
		case <-ticker.C:
			mc.updateMetrics()
		}
	}
}

// updateMetrics collects and updates all system metrics
func (mc *MetricsCollector) updateMetrics() {
	startTime := time.Now()
	
	// Collect state statistics
	stateStats := mc.manager.GetStateStatistics()
	
	// Collect health statistics
	healthStats := mc.manager.GetHealthStatistics()
	
	// Collect event history for recent analysis
	recentEvents := mc.manager.GetEvents(100)
	
	// Calculate metrics
	metrics := &SystemMetrics{
		// Container state metrics
		StateDistribution:  stateStats,
		TotalContainers:    mc.sumStateDistribution(stateStats),
		RunningContainers:  stateStats[ContainerStateRunning],
		StoppedContainers:  stateStats[ContainerStateStopped],
		FailedContainers:   stateStats[ContainerStateFailed],
		PausedContainers:   stateStats[ContainerStatePaused],
		CreatingContainers: stateStats[ContainerStateCreating],
		
		// Health metrics from health checker
		HealthyContainers:       mc.getIntFromStats(healthStats, "healthy_containers"),
		UnhealthyContainers:     mc.getIntFromStats(healthStats, "unhealthy_containers"),
		WarningContainers:       mc.getIntFromStats(healthStats, "warning_containers"),
		UnknownHealthContainers: mc.getIntFromStats(healthStats, "unknown_containers"),
		
		// Event metrics
		TotalEvents:      len(recentEvents),
		EventsByType:     mc.countEventsByType(recentEvents),
		EventsBySeverity: mc.countEventsBySeverity(recentEvents),
		RecentEventCount: mc.countRecentEvents(recentEvents, time.Hour),
		
		// Performance metrics
		AverageStartupTime:     mc.calculateAverageStartupTime(recentEvents),
		AverageHealthCheckTime: mc.calculateAverageHealthCheckTime(),
		StateTransitionCount:   mc.countStateTransitions(recentEvents),
		HealthCheckCount:       mc.countHealthChecks(recentEvents),
		
		// Resource metrics (simplified - would integrate with actual monitoring)
		TotalCPUUsage:    mc.calculateTotalCPUUsage(),
		TotalMemoryUsage: mc.calculateTotalMemoryUsage(),
		TotalDiskUsage:   mc.calculateTotalDiskUsage(),
		
		// Metadata
		Timestamp:      time.Now(),
		CollectionTime: time.Since(startTime),
		LastUpdate:     time.Now(),
	}

	// Calculate health distribution
	metrics.HealthDistribution = map[HealthStatus]int{
		HealthStatusHealthy:   metrics.HealthyContainers,
		HealthStatusUnhealthy: metrics.UnhealthyContainers,
		HealthStatusWarning:   metrics.WarningContainers,
		HealthStatusUnknown:   metrics.UnknownHealthContainers,
	}

	// Update stored metrics
	mc.mu.Lock()
	mc.metrics = metrics
	mc.mu.Unlock()

	// Publish metrics update event
	metricsMap := map[string]interface{}{
		"total_containers":    metrics.TotalContainers,
		"running_containers":  metrics.RunningContainers,
		"healthy_containers":  metrics.HealthyContainers,
		"unhealthy_containers": metrics.UnhealthyContainers,
		"collection_time":     metrics.CollectionTime.Milliseconds(),
	}
	
	event := NewMetricsUpdateEvent("metrics-collector", metricsMap)
	mc.manager.eventBus.Publish(event)

	log.Debug().
		Int("total_containers", metrics.TotalContainers).
		Int("running_containers", metrics.RunningContainers).
		Int("healthy_containers", metrics.HealthyContainers).
		Dur("collection_time", metrics.CollectionTime).
		Msg("Metrics updated")
}

// evaluateAlerts periodically evaluates alert rules
func (mc *MetricsCollector) evaluateAlerts() {
	ticker := time.NewTicker(1 * time.Minute) // Evaluate alerts every minute
	defer ticker.Stop()

	for {
		select {
		case <-mc.ctx.Done():
			log.Info().Msg("Alert evaluation stopped")
			return
		case <-ticker.C:
			mc.evaluateAllAlerts()
		}
	}
}

// evaluateAllAlerts evaluates all enabled alert rules
func (mc *MetricsCollector) evaluateAllAlerts() {
	mc.mu.RLock()
	rules := make([]AlertRule, len(mc.alertRules))
	copy(rules, mc.alertRules)
	metrics := *mc.metrics
	mc.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		result := mc.evaluateAlertRule(rule, &metrics)
		if result.Triggered {
			mc.fireAlert(rule, result)
		}
	}
}

// evaluateAlertRule evaluates a single alert rule
func (mc *MetricsCollector) evaluateAlertRule(rule AlertRule, metrics *SystemMetrics) AlertEvaluationResult {
	result := AlertEvaluationResult{
		RuleID:    rule.ID,
		Threshold: rule.Threshold,
		Timestamp: time.Now(),
	}

	switch rule.Condition {
	case AlertConditionContainerFailureRate:
		if metrics.TotalContainers > 0 {
			result.Value = float64(metrics.FailedContainers) / float64(metrics.TotalContainers)
		}
		result.Triggered = result.Value > rule.Threshold
		result.Message = fmt.Sprintf("Container failure rate: %.2f%% (threshold: %.2f%%)", 
			result.Value*100, rule.Threshold*100)

	case AlertConditionUnhealthyContainers:
		result.Value = float64(metrics.UnhealthyContainers)
		result.Triggered = result.Value > rule.Threshold
		result.Message = fmt.Sprintf("Unhealthy containers: %.0f (threshold: %.0f)", 
			result.Value, rule.Threshold)

	case AlertConditionHighResourceUsage:
		result.Value = metrics.TotalCPUUsage
		result.Triggered = result.Value > rule.Threshold
		result.Message = fmt.Sprintf("CPU usage: %.2f%% (threshold: %.2f%%)", 
			result.Value*100, rule.Threshold*100)

	case AlertConditionSlowStartup:
		result.Value = metrics.AverageStartupTime.Seconds()
		result.Triggered = result.Value > rule.Threshold
		result.Message = fmt.Sprintf("Average startup time: %.2fs (threshold: %.2fs)", 
			result.Value, rule.Threshold)

	case AlertConditionEventRate:
		result.Value = float64(metrics.RecentEventCount)
		result.Triggered = result.Value > rule.Threshold
		result.Message = fmt.Sprintf("Recent event count: %.0f (threshold: %.0f)", 
			result.Value, rule.Threshold)
	}

	return result
}

// fireAlert triggers an alert
func (mc *MetricsCollector) fireAlert(rule AlertRule, result AlertEvaluationResult) {
	mc.mu.Lock()
	// Update rule fire statistics
	for i, r := range mc.alertRules {
		if r.ID == rule.ID {
			now := time.Now()
			mc.alertRules[i].LastFired = &now
			mc.alertRules[i].FireCount++
			break
		}
	}
	mc.mu.Unlock()

	// Create and publish alert event
	event := NewSystemAlertEvent("metrics-collector", rule.Name, result.Message, rule.Severity)
	event.Metadata = map[string]interface{}{
		"rule_id":     rule.ID,
		"condition":   rule.Condition,
		"value":       result.Value,
		"threshold":   rule.Threshold,
		"fire_count":  rule.FireCount,
	}
	event.Tags = append(event.Tags, "alert", string(rule.Condition))

	mc.manager.eventBus.Publish(event)

	log.Warn().
		Str("rule_id", rule.ID).
		Str("rule_name", rule.Name).
		Str("condition", string(rule.Condition)).
		Float64("value", result.Value).
		Float64("threshold", rule.Threshold).
		Msg("Alert triggered")
}

// Helper methods for metrics calculation

func (mc *MetricsCollector) sumStateDistribution(states map[ContainerState]int) int {
	total := 0
	for _, count := range states {
		total += count
	}
	return total
}

func (mc *MetricsCollector) getIntFromStats(stats map[string]interface{}, key string) int {
	if val, ok := stats[key]; ok {
		if intVal, ok := val.(int); ok {
			return intVal
		}
	}
	return 0
}

func (mc *MetricsCollector) countEventsByType(events []Event) map[EventType]int {
	counts := make(map[EventType]int)
	for _, event := range events {
		counts[event.Type]++
	}
	return counts
}

func (mc *MetricsCollector) countEventsBySeverity(events []Event) map[EventSeverity]int {
	counts := make(map[EventSeverity]int)
	for _, event := range events {
		counts[event.Severity]++
	}
	return counts
}

func (mc *MetricsCollector) countRecentEvents(events []Event, window time.Duration) int {
	cutoff := time.Now().Add(-window)
	count := 0
	for _, event := range events {
		if event.Timestamp.After(cutoff) {
			count++
		}
	}
	return count
}

func (mc *MetricsCollector) calculateAverageStartupTime(events []Event) time.Duration {
	var totalTime time.Duration
	count := 0
	
	for _, event := range events {
		if event.Type == EventTypeStateChange {
			if transition, ok := event.Metadata["transition"].(StateTransition); ok {
				if transition.To == ContainerStateRunning && transition.From == ContainerStateCreating {
					// Assume startup took some time - in real implementation, track this properly
					totalTime += 2 * time.Second
					count++
				}
			}
		}
	}
	
	if count == 0 {
		return 0
	}
	return totalTime / time.Duration(count)
}

func (mc *MetricsCollector) calculateAverageHealthCheckTime() time.Duration {
	// Simplified - in real implementation, would track actual health check times
	return 50 * time.Millisecond
}

func (mc *MetricsCollector) countStateTransitions(events []Event) int {
	count := 0
	for _, event := range events {
		if event.Type == EventTypeStateChange {
			count++
		}
	}
	return count
}

func (mc *MetricsCollector) countHealthChecks(events []Event) int {
	count := 0
	for _, event := range events {
		if event.Type == EventTypeHealthAlert {
			count++
		}
	}
	return count
}

func (mc *MetricsCollector) calculateTotalCPUUsage() float64 {
	// Simplified - would integrate with actual system monitoring
	return 0.15 // 15% average
}

func (mc *MetricsCollector) calculateTotalMemoryUsage() float64 {
	// Simplified - would integrate with actual system monitoring
	return 0.45 // 45% average
}

func (mc *MetricsCollector) calculateTotalDiskUsage() float64 {
	// Simplified - would integrate with actual system monitoring
	return 0.30 // 30% average
}