package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// AuditEventType represents different types of security audit events
type AuditEventType string

const (
	AuditEventSecuritySetup     AuditEventType = "security_setup"
	AuditEventSecurityViolation AuditEventType = "security_violation"
	AuditEventCapabilityUsage   AuditEventType = "capability_usage"
	AuditEventSyscallDenied     AuditEventType = "syscall_denied"
	AuditEventNamespaceAccess   AuditEventType = "namespace_access"
	AuditEventMACViolation      AuditEventType = "mac_violation"
	AuditEventProfileLoaded     AuditEventType = "profile_loaded"
	AuditEventProfileUpdated    AuditEventType = "profile_updated"
	AuditEventPolicyViolation   AuditEventType = "policy_violation"
	AuditEventAccessDenied      AuditEventType = "access_denied"
	AuditEventPrivilegeEscalation AuditEventType = "privilege_escalation"
	AuditEventSecurityAlert     AuditEventType = "security_alert"
)

// AuditSeverity represents the severity levels for audit events
type AuditSeverity string

const (
	SeverityInfo     AuditSeverity = "info"
	SeverityWarning  AuditSeverity = "warning"
	SeverityError    AuditSeverity = "error"
	SeverityCritical AuditSeverity = "critical"
)

// ViolationType represents different types of security violations
type ViolationType string

const (
	ViolationCapability    ViolationType = "capability"
	ViolationSyscall       ViolationType = "syscall"
	ViolationNamespace     ViolationType = "namespace"
	ViolationMAC           ViolationType = "mac"
	ViolationNetwork       ViolationType = "network"
	ViolationFileSystem    ViolationType = "filesystem"
	ViolationResource      ViolationType = "resource"
	ViolationProcess       ViolationType = "process"
	ViolationPolicy        ViolationType = "policy"
)

// AuditEvent represents a security audit event
type AuditEvent struct {
	ID            string                 `json:"id"`
	Timestamp     time.Time              `json:"timestamp"`
	ContainerID   string                 `json:"containerId"`
	Type          AuditEventType         `json:"type"`
	Severity      AuditSeverity          `json:"severity"`
	Source        string                 `json:"source"`
	Subject       string                 `json:"subject,omitempty"`
	Object        string                 `json:"object,omitempty"`
	Action        string                 `json:"action"`
	Result        string                 `json:"result"`
	Message       string                 `json:"message"`
	Details       map[string]interface{} `json:"details,omitempty"`
	ProcessInfo   *ProcessInfo           `json:"processInfo,omitempty"`
	SecurityContext *SecurityContextInfo `json:"securityContext,omitempty"`
	RiskScore     float64                `json:"riskScore,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Remediation   string                 `json:"remediation,omitempty"`
}

// SecurityViolation represents a security policy violation
type SecurityViolation struct {
	ID              string                 `json:"id"`
	Timestamp       time.Time              `json:"timestamp"`
	ContainerID     string                 `json:"containerId"`
	Type            ViolationType          `json:"type"`
	Severity        AuditSeverity          `json:"severity"`
	PolicyName      string                 `json:"policyName"`
	ProfileName     string                 `json:"profileName"`
	ViolatedRule    string                 `json:"violatedRule"`
	Subject         string                 `json:"subject"`
	Object          string                 `json:"object"`
	Action          string                 `json:"action"`
	Expected        string                 `json:"expected"`
	Actual          string                 `json:"actual"`
	Description     string                 `json:"description"`
	Impact          string                 `json:"impact"`
	ProcessInfo     *ProcessInfo           `json:"processInfo,omitempty"`
	SecurityContext *SecurityContextInfo   `json:"securityContext,omitempty"`
	Details         map[string]interface{} `json:"details,omitempty"`
	RiskScore       float64                `json:"riskScore"`
	Mitigation      string                 `json:"mitigation,omitempty"`
	Remediation     []string               `json:"remediation,omitempty"`
	Status          string                 `json:"status"` // "open", "investigating", "resolved", "false_positive"
	Resolution      string                 `json:"resolution,omitempty"`
	ResolvedAt      *time.Time             `json:"resolvedAt,omitempty"`
}

// ProcessInfo represents process information for audit events
type ProcessInfo struct {
	PID         int    `json:"pid"`
	PPID        int    `json:"ppid,omitempty"`
	Command     string `json:"command"`
	Arguments   []string `json:"arguments,omitempty"`
	User        string `json:"user"`
	Group       string `json:"group"`
	Executable  string `json:"executable,omitempty"`
	WorkingDir  string `json:"workingDir,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// SecurityContextInfo represents security context information
type SecurityContextInfo struct {
	Profile       string            `json:"profile,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	Namespaces    map[string]string `json:"namespaces,omitempty"`
	MACContext    string            `json:"macContext,omitempty"`
	SeccompMode   string            `json:"seccompMode,omitempty"`
	UserID        int               `json:"userId,omitempty"`
	GroupID       int               `json:"groupId,omitempty"`
	Privileged    bool              `json:"privileged,omitempty"`
	NoNewPrivs    bool              `json:"noNewPrivs,omitempty"`
}

// AuditConfig defines audit system configuration
type AuditConfig struct {
	Enabled                bool              `json:"enabled" yaml:"enabled"`
	LogLevel               AuditSeverity     `json:"logLevel" yaml:"logLevel"`
	LogPath                string            `json:"logPath" yaml:"logPath"`
	MaxLogSize             int64             `json:"maxLogSize" yaml:"maxLogSize"`
	MaxLogFiles            int               `json:"maxLogFiles" yaml:"maxLogFiles"`
	RetentionDays          int               `json:"retentionDays" yaml:"retentionDays"`
	BufferSize             int               `json:"bufferSize" yaml:"bufferSize"`
	FlushInterval          time.Duration     `json:"flushInterval" yaml:"flushInterval"`
	
	// Event filtering
	EventTypes             []AuditEventType  `json:"eventTypes,omitempty" yaml:"eventTypes,omitempty"`
	ExcludedEventTypes     []AuditEventType  `json:"excludedEventTypes,omitempty" yaml:"excludedEventTypes,omitempty"`
	MinimumSeverity        AuditSeverity     `json:"minimumSeverity" yaml:"minimumSeverity"`
	
	// Alerting
	AlertConfig            *AlertConfig      `json:"alertConfig,omitempty" yaml:"alertConfig,omitempty"`
	
	// Storage and export
	StorageConfig          *StorageConfig    `json:"storageConfig,omitempty" yaml:"storageConfig,omitempty"`
	ExportConfig           *ExportConfig     `json:"exportConfig,omitempty" yaml:"exportConfig,omitempty"`
	
	// Real-time monitoring
	RealTimeMonitoring     bool              `json:"realTimeMonitoring" yaml:"realTimeMonitoring"`
	WebhookURL             string            `json:"webhookUrl,omitempty" yaml:"webhookUrl,omitempty"`
}

// AlertConfig defines alerting configuration
type AlertConfig struct {
	Enabled              bool              `json:"enabled" yaml:"enabled"`
	WebhookURL           string            `json:"webhookUrl,omitempty" yaml:"webhookUrl,omitempty"`
	EmailRecipients      []string          `json:"emailRecipients,omitempty" yaml:"emailRecipients,omitempty"`
	SlackWebhook         string            `json:"slackWebhook,omitempty" yaml:"slackWebhook,omitempty"`
	AlertThresholds      map[string]int    `json:"alertThresholds,omitempty" yaml:"alertThresholds,omitempty"`
	CooldownPeriod       time.Duration     `json:"cooldownPeriod" yaml:"cooldownPeriod"`
	EscalationPolicy     []EscalationRule  `json:"escalationPolicy,omitempty" yaml:"escalationPolicy,omitempty"`
}

// EscalationRule defines alert escalation rules
type EscalationRule struct {
	Condition      string        `json:"condition" yaml:"condition"`
	Delay          time.Duration `json:"delay" yaml:"delay"`
	Recipients     []string      `json:"recipients" yaml:"recipients"`
	Actions        []string      `json:"actions,omitempty" yaml:"actions,omitempty"`
}

// StorageConfig defines audit log storage configuration
type StorageConfig struct {
	Type               string            `json:"type" yaml:"type"` // "file", "database", "s3", "elasticsearch"
	ConnectionString   string            `json:"connectionString,omitempty" yaml:"connectionString,omitempty"`
	TableName          string            `json:"tableName,omitempty" yaml:"tableName,omitempty"`
	IndexName          string            `json:"indexName,omitempty" yaml:"indexName,omitempty"`
	Compression        bool              `json:"compression" yaml:"compression"`
	Encryption         bool              `json:"encryption" yaml:"encryption"`
	EncryptionKey      string            `json:"encryptionKey,omitempty" yaml:"encryptionKey,omitempty"`
	RetentionPolicy    *RetentionPolicy  `json:"retentionPolicy,omitempty" yaml:"retentionPolicy,omitempty"`
}

// RetentionPolicy defines data retention policies
type RetentionPolicy struct {
	DefaultRetention     time.Duration     `json:"defaultRetention" yaml:"defaultRetention"`
	SeverityRetention    map[AuditSeverity]time.Duration `json:"severityRetention,omitempty" yaml:"severityRetention,omitempty"`
	TypeRetention        map[AuditEventType]time.Duration `json:"typeRetention,omitempty" yaml:"typeRetention,omitempty"`
	ArchiveAfter         time.Duration     `json:"archiveAfter,omitempty" yaml:"archiveAfter,omitempty"`
	DeleteAfter          time.Duration     `json:"deleteAfter,omitempty" yaml:"deleteAfter,omitempty"`
}

// ExportConfig defines audit log export configuration
type ExportConfig struct {
	Enabled            bool              `json:"enabled" yaml:"enabled"`
	Format             string            `json:"format" yaml:"format"` // "json", "csv", "xml", "syslog"
	Destination        string            `json:"destination" yaml:"destination"`
	Schedule           string            `json:"schedule,omitempty" yaml:"schedule,omitempty"` // cron format
	Compression        bool              `json:"compression" yaml:"compression"`
	Encryption         bool              `json:"encryption" yaml:"encryption"`
	IncludeMetadata    bool              `json:"includeMetadata" yaml:"includeMetadata"`
	FilterCriteria     map[string]interface{} `json:"filterCriteria,omitempty" yaml:"filterCriteria,omitempty"`
}

// AuditQuery defines query parameters for searching audit events
type AuditQuery struct {
	ContainerID     string                 `json:"containerId,omitempty"`
	Type            AuditEventType         `json:"type,omitempty"`
	Severity        AuditSeverity          `json:"severity,omitempty"`
	Source          string                 `json:"source,omitempty"`
	Subject         string                 `json:"subject,omitempty"`
	Action          string                 `json:"action,omitempty"`
	StartTime       time.Time              `json:"startTime,omitempty"`
	EndTime         time.Time              `json:"endTime,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	MinRiskScore    float64                `json:"minRiskScore,omitempty"`
	MaxRiskScore    float64                `json:"maxRiskScore,omitempty"`
	Details         map[string]interface{} `json:"details,omitempty"`
	Limit           int                    `json:"limit,omitempty"`
	Offset          int                    `json:"offset,omitempty"`
	SortBy          string                 `json:"sortBy,omitempty"`
	SortOrder       string                 `json:"sortOrder,omitempty"` // "asc", "desc"
}

// SecurityAuditor manages security audit logging and violation tracking
type SecurityAuditor struct {
	mu                sync.RWMutex
	config            *AuditConfig
	
	// Event storage
	events            []AuditEvent
	violations        []SecurityViolation
	eventBuffer       chan AuditEvent
	violationBuffer   chan SecurityViolation
	
	// Statistics and metrics
	statistics        *AuditStatistics
	
	// Storage backends
	logFile           *os.File
	storageBackend    StorageBackend
	
	// Alert management
	alertManager      *AlertManager
	
	// Cleanup and rotation
	cleanupTicker     *time.Ticker
	rotationTicker    *time.Ticker
	
	// Event filtering
	eventFilters      []EventFilter
	
	// Real-time monitoring
	realtimeListeners []RealtimeListener
	
	// Shutdown control
	shutdown          chan struct{}
	wg                sync.WaitGroup
}

// AuditStatistics provides audit system statistics
type AuditStatistics struct {
	TotalEvents         int64                          `json:"totalEvents"`
	ViolationCount      int64                          `json:"violationCount"`
	EventsByType        map[AuditEventType]int64       `json:"eventsByType"`
	ViolationsByType    map[ViolationType]int64        `json:"violationsByType"`
	EventsBySeverity    map[AuditSeverity]int64        `json:"eventsBySeverity"`
	ViolationsBySeverity map[AuditSeverity]int64       `json:"violationsBySeverity"`
	TopContainers       []ContainerStats               `json:"topContainers"`
	RecentTrends        map[string][]TimeSeriesPoint   `json:"recentTrends"`
	LastUpdated         time.Time                      `json:"lastUpdated"`
}

// ContainerStats provides per-container statistics
type ContainerStats struct {
	ContainerID      string `json:"containerId"`
	EventCount       int64  `json:"eventCount"`
	ViolationCount   int64  `json:"violationCount"`
	LastActivity     time.Time `json:"lastActivity"`
	RiskScore        float64 `json:"riskScore"`
}

// TimeSeriesPoint represents a time series data point
type TimeSeriesPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     int64     `json:"value"`
}

// StorageBackend defines interface for audit log storage backends
type StorageBackend interface {
	Store(event AuditEvent) error
	StoreViolation(violation SecurityViolation) error
	Query(query AuditQuery) ([]AuditEvent, error)
	QueryViolations(query ViolationQuery) ([]SecurityViolation, error)
	Close() error
}

// EventFilter defines interface for filtering audit events
type EventFilter interface {
	ShouldInclude(event AuditEvent) bool
}

// RealtimeListener defines interface for real-time event monitoring
type RealtimeListener interface {
	OnEvent(event AuditEvent)
	OnViolation(violation SecurityViolation)
}

// AlertManager manages security alerts
type AlertManager struct {
	config           *AlertConfig
	alertCounts      map[string]int
	lastAlertTime    map[string]time.Time
	escalationState  map[string]int
}

// ViolationQuery defines query parameters for searching violations
type ViolationQuery struct {
	ContainerID     string                 `json:"containerId,omitempty"`
	Type            ViolationType          `json:"type,omitempty"`
	Severity        AuditSeverity          `json:"severity,omitempty"`
	PolicyName      string                 `json:"policyName,omitempty"`
	ProfileName     string                 `json:"profileName,omitempty"`
	Status          string                 `json:"status,omitempty"`
	StartTime       time.Time              `json:"startTime,omitempty"`
	EndTime         time.Time              `json:"endTime,omitempty"`
	MinRiskScore    float64                `json:"minRiskScore,omitempty"`
	MaxRiskScore    float64                `json:"maxRiskScore,omitempty"`
	Limit           int                    `json:"limit,omitempty"`
	Offset          int                    `json:"offset,omitempty"`
	SortBy          string                 `json:"sortBy,omitempty"`
	SortOrder       string                 `json:"sortOrder,omitempty"`
}

// NewSecurityAuditor creates a new security auditor
func NewSecurityAuditor(config *AuditConfig) (*SecurityAuditor, error) {
	if config == nil {
		config = &AuditConfig{
			Enabled:         true,
			LogLevel:        SeverityInfo,
			LogPath:         "/var/log/sandboxrunner/audit.log",
			MaxLogSize:      100 * 1024 * 1024, // 100MB
			MaxLogFiles:     10,
			RetentionDays:   30,
			BufferSize:      1000,
			FlushInterval:   5 * time.Second,
			MinimumSeverity: SeverityInfo,
		}
	}

	auditor := &SecurityAuditor{
		config:            config,
		events:            make([]AuditEvent, 0),
		violations:        make([]SecurityViolation, 0),
		eventBuffer:       make(chan AuditEvent, config.BufferSize),
		violationBuffer:   make(chan SecurityViolation, config.BufferSize),
		statistics:        &AuditStatistics{
			EventsByType:         make(map[AuditEventType]int64),
			ViolationsByType:     make(map[ViolationType]int64),
			EventsBySeverity:     make(map[AuditSeverity]int64),
			ViolationsBySeverity: make(map[AuditSeverity]int64),
			TopContainers:        make([]ContainerStats, 0),
			RecentTrends:         make(map[string][]TimeSeriesPoint),
		},
		shutdown:          make(chan struct{}),
	}

	// Initialize log file
	if err := auditor.initializeLogFile(); err != nil {
		return nil, fmt.Errorf("failed to initialize log file: %w", err)
	}

	// Initialize storage backend
	if config.StorageConfig != nil {
		backend, err := auditor.initializeStorageBackend()
		if err != nil {
			log.Warn().Err(err).Msg("Failed to initialize storage backend, using file logging only")
		} else {
			auditor.storageBackend = backend
		}
	}

	// Initialize alert manager
	if config.AlertConfig != nil && config.AlertConfig.Enabled {
		auditor.alertManager = &AlertManager{
			config:          config.AlertConfig,
			alertCounts:     make(map[string]int),
			lastAlertTime:   make(map[string]time.Time),
			escalationState: make(map[string]int),
		}
	}

	// Start background workers
	auditor.startWorkers()

	log.Info().
		Str("log_path", config.LogPath).
		Str("log_level", string(config.LogLevel)).
		Bool("real_time_monitoring", config.RealTimeMonitoring).
		Msg("Security auditor initialized")

	return auditor, nil
}

// LogEvent logs a security audit event
func (sa *SecurityAuditor) LogEvent(event AuditEvent) {
	if !sa.config.Enabled {
		return
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Generate ID if not provided
	if event.ID == "" {
		event.ID = fmt.Sprintf("evt_%d_%s", event.Timestamp.Unix(), event.ContainerID)
	}

	// Apply event filters
	if !sa.shouldIncludeEvent(event) {
		return
	}

	// Calculate risk score if not provided
	if event.RiskScore == 0 {
		event.RiskScore = sa.calculateRiskScore(event)
	}

	// Send to buffer (non-blocking)
	select {
	case sa.eventBuffer <- event:
	default:
		log.Warn().Str("event_id", event.ID).Msg("Event buffer full, dropping event")
	}
}

// LogViolation logs a security violation
func (sa *SecurityAuditor) LogViolation(violation SecurityViolation) {
	if !sa.config.Enabled {
		return
	}

	// Set timestamp if not provided
	if violation.Timestamp.IsZero() {
		violation.Timestamp = time.Now()
	}

	// Generate ID if not provided
	if violation.ID == "" {
		violation.ID = fmt.Sprintf("viol_%d_%s", violation.Timestamp.Unix(), violation.ContainerID)
	}

	// Set default status
	if violation.Status == "" {
		violation.Status = "open"
	}

	// Calculate risk score if not provided
	if violation.RiskScore == 0 {
		violation.RiskScore = sa.calculateViolationRiskScore(violation)
	}

	// Send to buffer (non-blocking)
	select {
	case sa.violationBuffer <- violation:
	default:
		log.Warn().Str("violation_id", violation.ID).Msg("Violation buffer full, dropping violation")
	}
}

// QueryEvents queries audit events based on criteria
func (sa *SecurityAuditor) QueryEvents(query AuditQuery) ([]AuditEvent, error) {
	if sa.storageBackend != nil {
		return sa.storageBackend.Query(query)
	}

	// Fallback to in-memory search
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	var results []AuditEvent
	for _, event := range sa.events {
		if sa.matchesEventQuery(event, query) {
			results = append(results, event)
		}
	}

	// Sort results
	sort.Slice(results, func(i, j int) bool {
		if query.SortOrder == "asc" {
			return results[i].Timestamp.Before(results[j].Timestamp)
		}
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	// Apply pagination
	if query.Offset > 0 && query.Offset < len(results) {
		results = results[query.Offset:]
	}
	if query.Limit > 0 && query.Limit < len(results) {
		results = results[:query.Limit]
	}

	return results, nil
}

// QueryViolations queries security violations based on criteria
func (sa *SecurityAuditor) QueryViolations(query ViolationQuery) ([]SecurityViolation, error) {
	if sa.storageBackend != nil {
		return sa.storageBackend.QueryViolations(query)
	}

	// Fallback to in-memory search
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	var results []SecurityViolation
	for _, violation := range sa.violations {
		if sa.matchesViolationQuery(violation, query) {
			results = append(results, violation)
		}
	}

	// Sort results
	sort.Slice(results, func(i, j int) bool {
		if query.SortOrder == "asc" {
			return results[i].Timestamp.Before(results[j].Timestamp)
		}
		return results[i].Timestamp.After(results[j].Timestamp)
	})

	// Apply pagination
	if query.Offset > 0 && query.Offset < len(results) {
		results = results[query.Offset:]
	}
	if query.Limit > 0 && query.Limit < len(results) {
		results = results[:query.Limit]
	}

	return results, nil
}

// GetStatistics returns audit system statistics
func (sa *SecurityAuditor) GetStatistics() *AuditStatistics {
	sa.mu.RLock()
	defer sa.mu.RUnlock()

	// Update statistics
	sa.updateStatistics()

	// Return a copy
	stats := *sa.statistics
	return &stats
}

// ResolveViolation marks a violation as resolved
func (sa *SecurityAuditor) ResolveViolation(violationID, resolution string) error {
	sa.mu.Lock()
	defer sa.mu.Unlock()

	for i, violation := range sa.violations {
		if violation.ID == violationID {
			now := time.Now()
			sa.violations[i].Status = "resolved"
			sa.violations[i].Resolution = resolution
			sa.violations[i].ResolvedAt = &now

			log.Info().
				Str("violation_id", violationID).
				Str("resolution", resolution).
				Msg("Security violation resolved")

			return nil
		}
	}

	return fmt.Errorf("violation %s not found", violationID)
}

// AddEventFilter adds an event filter
func (sa *SecurityAuditor) AddEventFilter(filter EventFilter) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	
	sa.eventFilters = append(sa.eventFilters, filter)
}

// AddRealtimeListener adds a real-time event listener
func (sa *SecurityAuditor) AddRealtimeListener(listener RealtimeListener) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	
	sa.realtimeListeners = append(sa.realtimeListeners, listener)
}

// Shutdown gracefully shuts down the auditor
func (sa *SecurityAuditor) Shutdown() {
	log.Info().Msg("Shutting down security auditor")
	
	close(sa.shutdown)
	sa.wg.Wait()
	
	if sa.logFile != nil {
		sa.logFile.Close()
	}
	
	if sa.storageBackend != nil {
		sa.storageBackend.Close()
	}
	
	if sa.cleanupTicker != nil {
		sa.cleanupTicker.Stop()
	}
	
	if sa.rotationTicker != nil {
		sa.rotationTicker.Stop()
	}
	
	log.Info().Msg("Security auditor shutdown completed")
}

// Private helper methods

func (sa *SecurityAuditor) initializeLogFile() error {
	if sa.config.LogPath == "" {
		return nil
	}

	// Ensure log directory exists
	logDir := filepath.Dir(sa.config.LogPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// Open log file
	file, err := os.OpenFile(sa.config.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	sa.logFile = file
	return nil
}

func (sa *SecurityAuditor) initializeStorageBackend() (StorageBackend, error) {
	// In a real implementation, this would initialize the configured storage backend
	// (database, Elasticsearch, S3, etc.)
	return nil, fmt.Errorf("storage backend not implemented")
}

func (sa *SecurityAuditor) startWorkers() {
	// Event processing worker
	sa.wg.Add(1)
	go sa.eventWorker()
	
	// Violation processing worker
	sa.wg.Add(1)
	go sa.violationWorker()
	
	// Statistics update worker
	sa.wg.Add(1)
	go sa.statisticsWorker()
	
	// Cleanup worker
	if sa.config.RetentionDays > 0 {
		sa.cleanupTicker = time.NewTicker(24 * time.Hour)
		sa.wg.Add(1)
		go sa.cleanupWorker()
	}
	
	// Log rotation worker
	if sa.config.MaxLogSize > 0 {
		sa.rotationTicker = time.NewTicker(time.Hour)
		sa.wg.Add(1)
		go sa.rotationWorker()
	}
}

func (sa *SecurityAuditor) eventWorker() {
	defer sa.wg.Done()
	
	ticker := time.NewTicker(sa.config.FlushInterval)
	defer ticker.Stop()
	
	var eventBatch []AuditEvent
	
	for {
		select {
		case event := <-sa.eventBuffer:
			eventBatch = append(eventBatch, event)
			
			// Process immediately if it's a critical event
			if event.Severity == SeverityCritical {
				sa.processEventBatch(eventBatch)
				eventBatch = nil
			}
			
		case <-ticker.C:
			if len(eventBatch) > 0 {
				sa.processEventBatch(eventBatch)
				eventBatch = nil
			}
			
		case <-sa.shutdown:
			// Process remaining events
			if len(eventBatch) > 0 {
				sa.processEventBatch(eventBatch)
			}
			return
		}
	}
}

func (sa *SecurityAuditor) violationWorker() {
	defer sa.wg.Done()
	
	for {
		select {
		case violation := <-sa.violationBuffer:
			sa.processViolation(violation)
			
		case <-sa.shutdown:
			return
		}
	}
}

func (sa *SecurityAuditor) statisticsWorker() {
	defer sa.wg.Done()
	
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			sa.updateStatistics()
			
		case <-sa.shutdown:
			return
		}
	}
}

func (sa *SecurityAuditor) cleanupWorker() {
	defer sa.wg.Done()
	
	for {
		select {
		case <-sa.cleanupTicker.C:
			sa.performCleanup()
			
		case <-sa.shutdown:
			return
		}
	}
}

func (sa *SecurityAuditor) rotationWorker() {
	defer sa.wg.Done()
	
	for {
		select {
		case <-sa.rotationTicker.C:
			sa.performLogRotation()
			
		case <-sa.shutdown:
			return
		}
	}
}

func (sa *SecurityAuditor) processEventBatch(events []AuditEvent) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	
	for _, event := range events {
		// Store in memory
		sa.events = append(sa.events, event)
		
		// Write to log file
		if sa.logFile != nil {
			sa.writeEventToLog(event)
		}
		
		// Store in backend
		if sa.storageBackend != nil {
			if err := sa.storageBackend.Store(event); err != nil {
				log.Warn().Err(err).Str("event_id", event.ID).Msg("Failed to store event in backend")
			}
		}
		
		// Send to real-time listeners
		for _, listener := range sa.realtimeListeners {
			listener.OnEvent(event)
		}
		
		// Check for alerts
		if sa.alertManager != nil {
			sa.alertManager.CheckAlert(event)
		}
	}
}

func (sa *SecurityAuditor) processViolation(violation SecurityViolation) {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	
	// Store in memory
	sa.violations = append(sa.violations, violation)
	
	// Write to log file
	if sa.logFile != nil {
		sa.writeViolationToLog(violation)
	}
	
	// Store in backend
	if sa.storageBackend != nil {
		if err := sa.storageBackend.StoreViolation(violation); err != nil {
			log.Warn().Err(err).Str("violation_id", violation.ID).Msg("Failed to store violation in backend")
		}
	}
	
	// Send to real-time listeners
	for _, listener := range sa.realtimeListeners {
		listener.OnViolation(violation)
	}
	
	// Handle critical violations
	if violation.Severity == SeverityCritical {
		sa.handleCriticalViolation(violation)
	}
}

func (sa *SecurityAuditor) writeEventToLog(event AuditEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		log.Warn().Err(err).Str("event_id", event.ID).Msg("Failed to marshal event")
		return
	}
	
	sa.logFile.WriteString(string(data) + "\n")
}

func (sa *SecurityAuditor) writeViolationToLog(violation SecurityViolation) {
	data, err := json.Marshal(violation)
	if err != nil {
		log.Warn().Err(err).Str("violation_id", violation.ID).Msg("Failed to marshal violation")
		return
	}
	
	sa.logFile.WriteString(string(data) + "\n")
}

func (sa *SecurityAuditor) shouldIncludeEvent(event AuditEvent) bool {
	// Check minimum severity
	if sa.getSeverityLevel(event.Severity) < sa.getSeverityLevel(sa.config.MinimumSeverity) {
		return false
	}
	
	// Check event type filters
	if len(sa.config.EventTypes) > 0 {
		found := false
		for _, eventType := range sa.config.EventTypes {
			if event.Type == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check excluded event types
	for _, excludedType := range sa.config.ExcludedEventTypes {
		if event.Type == excludedType {
			return false
		}
	}
	
	// Apply custom filters
	for _, filter := range sa.eventFilters {
		if !filter.ShouldInclude(event) {
			return false
		}
	}
	
	return true
}

func (sa *SecurityAuditor) getSeverityLevel(severity AuditSeverity) int {
	switch severity {
	case SeverityInfo:
		return 0
	case SeverityWarning:
		return 1
	case SeverityError:
		return 2
	case SeverityCritical:
		return 3
	default:
		return 0
	}
}

func (sa *SecurityAuditor) calculateRiskScore(event AuditEvent) float64 {
	score := 0.0
	
	// Base score by severity
	switch event.Severity {
	case SeverityInfo:
		score += 0.1
	case SeverityWarning:
		score += 0.3
	case SeverityError:
		score += 0.6
	case SeverityCritical:
		score += 1.0
	}
	
	// Adjust by event type
	switch event.Type {
	case AuditEventSecurityViolation, AuditEventPrivilegeEscalation:
		score += 0.5
	case AuditEventCapabilityUsage, AuditEventSyscallDenied:
		score += 0.3
	case AuditEventMACViolation, AuditEventPolicyViolation:
		score += 0.4
	}
	
	// Ensure score is between 0 and 1
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

func (sa *SecurityAuditor) calculateViolationRiskScore(violation SecurityViolation) float64 {
	score := 0.0
	
	// Base score by severity
	switch violation.Severity {
	case SeverityInfo:
		score += 0.2
	case SeverityWarning:
		score += 0.4
	case SeverityError:
		score += 0.7
	case SeverityCritical:
		score += 1.0
	}
	
	// Adjust by violation type
	switch violation.Type {
	case ViolationCapability, ViolationSyscall:
		score += 0.3
	case ViolationMAC, ViolationPolicy:
		score += 0.4
	case ViolationNamespace, ViolationProcess:
		score += 0.5
	}
	
	// Ensure score is between 0 and 1
	if score > 1.0 {
		score = 1.0
	}
	
	return score
}

func (sa *SecurityAuditor) matchesEventQuery(event AuditEvent, query AuditQuery) bool {
	if query.ContainerID != "" && event.ContainerID != query.ContainerID {
		return false
	}
	
	if query.Type != "" && event.Type != query.Type {
		return false
	}
	
	if query.Severity != "" && event.Severity != query.Severity {
		return false
	}
	
	if query.Source != "" && !strings.Contains(strings.ToLower(event.Source), strings.ToLower(query.Source)) {
		return false
	}
	
	if query.Subject != "" && !strings.Contains(strings.ToLower(event.Subject), strings.ToLower(query.Subject)) {
		return false
	}
	
	if query.Action != "" && !strings.Contains(strings.ToLower(event.Action), strings.ToLower(query.Action)) {
		return false
	}
	
	if !query.StartTime.IsZero() && event.Timestamp.Before(query.StartTime) {
		return false
	}
	
	if !query.EndTime.IsZero() && event.Timestamp.After(query.EndTime) {
		return false
	}
	
	if query.MinRiskScore > 0 && event.RiskScore < query.MinRiskScore {
		return false
	}
	
	if query.MaxRiskScore > 0 && event.RiskScore > query.MaxRiskScore {
		return false
	}
	
	// Check tags
	if len(query.Tags) > 0 {
		hasMatchingTag := false
		for _, queryTag := range query.Tags {
			for _, eventTag := range event.Tags {
				if strings.EqualFold(queryTag, eventTag) {
					hasMatchingTag = true
					break
				}
			}
			if hasMatchingTag {
				break
			}
		}
		if !hasMatchingTag {
			return false
		}
	}
	
	return true
}

func (sa *SecurityAuditor) matchesViolationQuery(violation SecurityViolation, query ViolationQuery) bool {
	if query.ContainerID != "" && violation.ContainerID != query.ContainerID {
		return false
	}
	
	if query.Type != "" && violation.Type != query.Type {
		return false
	}
	
	if query.Severity != "" && violation.Severity != query.Severity {
		return false
	}
	
	if query.PolicyName != "" && !strings.Contains(strings.ToLower(violation.PolicyName), strings.ToLower(query.PolicyName)) {
		return false
	}
	
	if query.ProfileName != "" && !strings.Contains(strings.ToLower(violation.ProfileName), strings.ToLower(query.ProfileName)) {
		return false
	}
	
	if query.Status != "" && violation.Status != query.Status {
		return false
	}
	
	if !query.StartTime.IsZero() && violation.Timestamp.Before(query.StartTime) {
		return false
	}
	
	if !query.EndTime.IsZero() && violation.Timestamp.After(query.EndTime) {
		return false
	}
	
	if query.MinRiskScore > 0 && violation.RiskScore < query.MinRiskScore {
		return false
	}
	
	if query.MaxRiskScore > 0 && violation.RiskScore > query.MaxRiskScore {
		return false
	}
	
	return true
}

func (sa *SecurityAuditor) updateStatistics() {
	now := time.Now()
	
	// Reset counters
	sa.statistics.EventsByType = make(map[AuditEventType]int64)
	sa.statistics.ViolationsByType = make(map[ViolationType]int64)
	sa.statistics.EventsBySeverity = make(map[AuditSeverity]int64)
	sa.statistics.ViolationsBySeverity = make(map[AuditSeverity]int64)
	
	// Count events
	sa.statistics.TotalEvents = int64(len(sa.events))
	for _, event := range sa.events {
		sa.statistics.EventsByType[event.Type]++
		sa.statistics.EventsBySeverity[event.Severity]++
	}
	
	// Count violations
	sa.statistics.ViolationCount = int64(len(sa.violations))
	for _, violation := range sa.violations {
		sa.statistics.ViolationsByType[violation.Type]++
		sa.statistics.ViolationsBySeverity[violation.Severity]++
	}
	
	// Update container statistics
	containerStats := make(map[string]*ContainerStats)
	for _, event := range sa.events {
		if stats, exists := containerStats[event.ContainerID]; exists {
			stats.EventCount++
			if event.Timestamp.After(stats.LastActivity) {
				stats.LastActivity = event.Timestamp
			}
		} else {
			containerStats[event.ContainerID] = &ContainerStats{
				ContainerID:  event.ContainerID,
				EventCount:   1,
				LastActivity: event.Timestamp,
			}
		}
	}
	
	for _, violation := range sa.violations {
		if stats, exists := containerStats[violation.ContainerID]; exists {
			stats.ViolationCount++
			if violation.Timestamp.After(stats.LastActivity) {
				stats.LastActivity = violation.Timestamp
			}
		} else {
			containerStats[violation.ContainerID] = &ContainerStats{
				ContainerID:    violation.ContainerID,
				ViolationCount: 1,
				LastActivity:   violation.Timestamp,
			}
		}
	}
	
	// Convert to slice and sort
	sa.statistics.TopContainers = nil
	for _, stats := range containerStats {
		stats.RiskScore = float64(stats.ViolationCount) / float64(stats.EventCount+1)
		sa.statistics.TopContainers = append(sa.statistics.TopContainers, *stats)
	}
	
	sort.Slice(sa.statistics.TopContainers, func(i, j int) bool {
		return sa.statistics.TopContainers[i].EventCount > sa.statistics.TopContainers[j].EventCount
	})
	
	// Limit to top 10
	if len(sa.statistics.TopContainers) > 10 {
		sa.statistics.TopContainers = sa.statistics.TopContainers[:10]
	}
	
	sa.statistics.LastUpdated = now
}

func (sa *SecurityAuditor) performCleanup() {
	cutoffTime := time.Now().AddDate(0, 0, -sa.config.RetentionDays)
	
	sa.mu.Lock()
	defer sa.mu.Unlock()
	
	// Clean up old events
	filteredEvents := make([]AuditEvent, 0)
	for _, event := range sa.events {
		if event.Timestamp.After(cutoffTime) {
			filteredEvents = append(filteredEvents, event)
		}
	}
	removed := len(sa.events) - len(filteredEvents)
	sa.events = filteredEvents
	
	// Clean up old violations
	filteredViolations := make([]SecurityViolation, 0)
	for _, violation := range sa.violations {
		if violation.Timestamp.After(cutoffTime) {
			filteredViolations = append(filteredViolations, violation)
		}
	}
	removedViolations := len(sa.violations) - len(filteredViolations)
	sa.violations = filteredViolations
	
	if removed > 0 || removedViolations > 0 {
		log.Info().
			Int("removed_events", removed).
			Int("removed_violations", removedViolations).
			Msg("Audit log cleanup completed")
	}
}

func (sa *SecurityAuditor) performLogRotation() {
	if sa.logFile == nil {
		return
	}
	
	// Check file size
	info, err := sa.logFile.Stat()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get log file info")
		return
	}
	
	if info.Size() < sa.config.MaxLogSize {
		return
	}
	
	// Rotate log file
	sa.logFile.Close()
	
	// Rename current log file
	timestamp := time.Now().Format("20060102-150405")
	oldPath := sa.config.LogPath
	newPath := fmt.Sprintf("%s.%s", oldPath, timestamp)
	
	if err := os.Rename(oldPath, newPath); err != nil {
		log.Warn().Err(err).Msg("Failed to rotate log file")
		return
	}
	
	// Create new log file
	if err := sa.initializeLogFile(); err != nil {
		log.Error().Err(err).Msg("Failed to create new log file after rotation")
	}
	
	log.Info().
		Str("old_file", newPath).
		Str("new_file", oldPath).
		Msg("Log file rotated")
}

func (sa *SecurityAuditor) handleCriticalViolation(violation SecurityViolation) {
	log.Error().
		Str("violation_id", violation.ID).
		Str("container_id", violation.ContainerID).
		Str("type", string(violation.Type)).
		Str("description", violation.Description).
		Msg("Critical security violation detected")
	
	// In a real implementation, this might trigger immediate containment actions
}

// CheckAlert checks if an event should trigger an alert
func (am *AlertManager) CheckAlert(event AuditEvent) {
	if am == nil || !am.config.Enabled {
		return
	}
	
	// Check alert thresholds and trigger alerts as needed
	// This is a simplified implementation
	if event.Severity == SeverityCritical {
		am.sendAlert(event)
	}
}

func (am *AlertManager) sendAlert(event AuditEvent) {
	// Send alert via configured channels (webhook, email, Slack, etc.)
	log.Warn().
		Str("event_id", event.ID).
		Str("container_id", event.ContainerID).
		Str("type", string(event.Type)).
		Msg("Security alert triggered")
}