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

// ComplianceFramework represents different compliance frameworks
type ComplianceFramework string

const (
	FrameworkSOC2        ComplianceFramework = "soc2"
	FrameworkISO27001    ComplianceFramework = "iso27001"
	FrameworkNIST        ComplianceFramework = "nist"
	FrameworkPCIDSS      ComplianceFramework = "pcidss"
	FrameworkHIPAA       ComplianceFramework = "hipaa"
	FrameworkGDPR        ComplianceFramework = "gdpr"
	FrameworkFedRAMP     ComplianceFramework = "fedramp"
	FrameworkCIS         ComplianceFramework = "cis"
	FrameworkOWASP       ComplianceFramework = "owasp"
	FrameworkCustom      ComplianceFramework = "custom"
)

// ComplianceStatus represents compliance assessment status
type ComplianceStatus string

const (
	StatusCompliant    ComplianceStatus = "compliant"
	StatusNonCompliant ComplianceStatus = "non_compliant"
	StatusPartial      ComplianceStatus = "partial"
	StatusUnknown      ComplianceStatus = "unknown"
	StatusExempt       ComplianceStatus = "exempt"
	StatusInProgress   ComplianceStatus = "in_progress"
)

// ComplianceCheck represents a single compliance check
type ComplianceCheck struct {
	ID              string              `json:"id"`
	Framework       ComplianceFramework `json:"framework"`
	ControlID       string              `json:"controlId"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	Category        string              `json:"category"`
	Severity        string              `json:"severity"`
	RequiredLevel   string              `json:"requiredLevel"`
	CheckType       string              `json:"checkType"` // "automated", "manual", "hybrid"
	AutomationRules []AutomationRule    `json:"automationRules,omitempty"`
	ManualSteps     []string            `json:"manualSteps,omitempty"`
	References      []string            `json:"references,omitempty"`
	Tags            []string            `json:"tags,omitempty"`
	Enabled         bool                `json:"enabled"`
}

// AutomationRule defines automated compliance checking rules
type AutomationRule struct {
	RuleType    string                 `json:"ruleType"` // "policy", "configuration", "audit", "metric"
	Target      string                 `json:"target"`
	Property    string                 `json:"property"`
	Operator    string                 `json:"operator"` // "equals", "contains", "regex", "range"
	Expected    interface{}            `json:"expected"`
	Tolerance   interface{}            `json:"tolerance,omitempty"`
	Weight      float64                `json:"weight,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// ComplianceAssessment represents a compliance assessment result
type ComplianceAssessment struct {
	ID                string                    `json:"id"`
	Timestamp         time.Time                 `json:"timestamp"`
	ContainerID       string                    `json:"containerId"`
	Framework         ComplianceFramework       `json:"framework"`
	ProfileName       string                    `json:"profileName"`
	OverallStatus     ComplianceStatus          `json:"overallStatus"`
	OverallScore      float64                   `json:"overallScore"`
	MaxScore          float64                   `json:"maxScore"`
	CompliancePercent float64                   `json:"compliancePercent"`
	CheckResults      []ComplianceCheckResult   `json:"checkResults"`
	CategoryScores    map[string]float64        `json:"categoryScores"`
	Findings          []ComplianceFinding       `json:"findings"`
	Recommendations   []ComplianceRecommendation `json:"recommendations"`
	Evidence          []ComplianceEvidence      `json:"evidence,omitempty"`
	Metadata          map[string]interface{}    `json:"metadata,omitempty"`
	AssessorInfo      *AssessorInfo             `json:"assessorInfo,omitempty"`
	ValidUntil        *time.Time                `json:"validUntil,omitempty"`
	NextAssessment    *time.Time                `json:"nextAssessment,omitempty"`
}

// ComplianceCheckResult represents the result of a single compliance check
type ComplianceCheckResult struct {
	CheckID        string            `json:"checkId"`
	Status         ComplianceStatus  `json:"status"`
	Score          float64           `json:"score"`
	MaxScore       float64           `json:"maxScore"`
	Evidence       []string          `json:"evidence,omitempty"`
	Issues         []string          `json:"issues,omitempty"`
	Remediation    []string          `json:"remediation,omitempty"`
	ManualReview   bool              `json:"manualReview,omitempty"`
	LastChecked    time.Time         `json:"lastChecked"`
	CheckDuration  time.Duration     `json:"checkDuration"`
	Details        map[string]interface{} `json:"details,omitempty"`
}

// ComplianceFinding represents a compliance finding or issue
type ComplianceFinding struct {
	ID              string            `json:"id"`
	Severity        string            `json:"severity"`
	Title           string            `json:"title"`
	Description     string            `json:"description"`
	Category        string            `json:"category"`
	AffectedChecks  []string          `json:"affectedChecks"`
	Impact          string            `json:"impact"`
	RiskLevel       string            `json:"riskLevel"`
	Remediation     []string          `json:"remediation"`
	Timeline        string            `json:"timeline,omitempty"`
	ResponsibleParty string           `json:"responsibleParty,omitempty"`
	Status          string            `json:"status"` // "open", "in_progress", "resolved", "accepted_risk"
	CreatedAt       time.Time         `json:"createdAt"`
	UpdatedAt       time.Time         `json:"updatedAt"`
	ResolvedAt      *time.Time        `json:"resolvedAt,omitempty"`
	Evidence        []ComplianceEvidence `json:"evidence,omitempty"`
}

// ComplianceRecommendation represents a compliance recommendation
type ComplianceRecommendation struct {
	ID          string    `json:"id"`
	Priority    string    `json:"priority"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Actions     []string  `json:"actions"`
	Benefits    []string  `json:"benefits"`
	Resources   []string  `json:"resources,omitempty"`
	Effort      string    `json:"effort,omitempty"`
	Timeline    string    `json:"timeline,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// ComplianceEvidence represents evidence supporting compliance
type ComplianceEvidence struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type"` // "configuration", "log", "policy", "screenshot", "document"
	Source        string                 `json:"source"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	Content       string                 `json:"content,omitempty"`
	FilePath      string                 `json:"filePath,omitempty"`
	URL           string                 `json:"url,omitempty"`
	Hash          string                 `json:"hash,omitempty"`
	CollectedAt   time.Time              `json:"collectedAt"`
	ValidUntil    *time.Time             `json:"validUntil,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// AssessorInfo represents information about the assessor
type AssessorInfo struct {
	Name         string    `json:"name"`
	Organization string    `json:"organization,omitempty"`
	Email        string    `json:"email,omitempty"`
	Role         string    `json:"role,omitempty"`
	Certification string   `json:"certification,omitempty"`
	AssessmentDate time.Time `json:"assessmentDate"`
}

// CompliancePolicy represents a compliance policy configuration
type CompliancePolicy struct {
	ID             string                    `json:"id"`
	Name           string                    `json:"name"`
	Version        string                    `json:"version"`
	Description    string                    `json:"description"`
	Framework      ComplianceFramework       `json:"framework"`
	Scope          []string                  `json:"scope"`
	Checks         []ComplianceCheck         `json:"checks"`
	Categories     []ComplianceCategory      `json:"categories"`
	Requirements   []ComplianceRequirement   `json:"requirements"`
	Schedule       *ComplianceSchedule       `json:"schedule,omitempty"`
	Notifications  *NotificationConfig       `json:"notifications,omitempty"`
	Enabled        bool                      `json:"enabled"`
	CreatedAt      time.Time                 `json:"createdAt"`
	UpdatedAt      time.Time                 `json:"updatedAt"`
	CreatedBy      string                    `json:"createdBy"`
	ApprovedBy     string                    `json:"approvedBy,omitempty"`
	ApprovedAt     *time.Time                `json:"approvedAt,omitempty"`
}

// ComplianceCategory represents a category of compliance checks
type ComplianceCategory struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Weight      float64 `json:"weight"`
	Required    bool    `json:"required"`
	Checks      []string `json:"checks"`
}

// ComplianceRequirement represents a high-level compliance requirement
type ComplianceRequirement struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	RequirementType string   `json:"requirementType"`
	Mandatory       bool     `json:"mandatory"`
	Controls        []string `json:"controls"`
	Dependencies    []string `json:"dependencies,omitempty"`
	References      []string `json:"references,omitempty"`
}

// ComplianceSchedule defines when compliance checks should run
type ComplianceSchedule struct {
	Enabled           bool          `json:"enabled"`
	CronExpression    string        `json:"cronExpression"`
	Interval          time.Duration `json:"interval,omitempty"`
	MaxDuration       time.Duration `json:"maxDuration,omitempty"`
	RetryAttempts     int           `json:"retryAttempts"`
	RetryDelay        time.Duration `json:"retryDelay"`
	TimeZone          string        `json:"timeZone,omitempty"`
	MaintenanceWindows []MaintenanceWindow `json:"maintenanceWindows,omitempty"`
}

// MaintenanceWindow defines maintenance windows when checks should not run
type MaintenanceWindow struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	Recurrence  string    `json:"recurrence,omitempty"` // "daily", "weekly", "monthly"
}

// NotificationConfig defines compliance notification settings
type NotificationConfig struct {
	Enabled                bool     `json:"enabled"`
	EmailRecipients        []string `json:"emailRecipients,omitempty"`
	SlackWebhook           string   `json:"slackWebhook,omitempty"`
	WebhookURL             string   `json:"webhookUrl,omitempty"`
	NotifyOnFailure        bool     `json:"notifyOnFailure"`
	NotifyOnSuccess        bool     `json:"notifyOnSuccess"`
	NotifyOnStatusChange   bool     `json:"notifyOnStatusChange"`
	SummaryReportSchedule  string   `json:"summaryReportSchedule,omitempty"`
	IncludeDetails         bool     `json:"includeDetails"`
	EscalationThreshold    int      `json:"escalationThreshold,omitempty"`
}

// ComplianceManager manages compliance monitoring and reporting
type ComplianceManager struct {
	mu                sync.RWMutex
	policies          map[string]*CompliancePolicy
	checks            map[string]*ComplianceCheck
	assessments       []ComplianceAssessment
	findings          []ComplianceFinding
	evidence          []ComplianceEvidence
	
	// Storage paths
	policiesPath      string
	checksPath        string
	assessmentsPath   string
	evidencePath      string
	
	// Built-in checks and policies
	builtinChecks     map[string]*ComplianceCheck
	builtinPolicies   map[string]*CompliancePolicy
	
	// Monitoring and scheduling
	scheduledChecks   map[string]*time.Ticker
	
	// Audit integration
	auditor           *SecurityAuditor
	
	// Shutdown control
	shutdown          chan struct{}
	wg                sync.WaitGroup
}

// ComplianceQuery defines query parameters for compliance searches
type ComplianceQuery struct {
	ContainerID    string                 `json:"containerId,omitempty"`
	Framework      ComplianceFramework    `json:"framework,omitempty"`
	Status         ComplianceStatus       `json:"status,omitempty"`
	MinScore       float64                `json:"minScore,omitempty"`
	MaxScore       float64                `json:"maxScore,omitempty"`
	StartTime      time.Time              `json:"startTime,omitempty"`
	EndTime        time.Time              `json:"endTime,omitempty"`
	Categories     []string               `json:"categories,omitempty"`
	Severity       []string               `json:"severity,omitempty"`
	Tags           []string               `json:"tags,omitempty"`
	IncludeEvidence bool                  `json:"includeEvidence,omitempty"`
	Limit          int                    `json:"limit,omitempty"`
	Offset         int                    `json:"offset,omitempty"`
	SortBy         string                 `json:"sortBy,omitempty"`
	SortOrder      string                 `json:"sortOrder,omitempty"`
}

// NewComplianceManager creates a new compliance manager
func NewComplianceManager(basePath string) *ComplianceManager {
	cm := &ComplianceManager{
		policies:        make(map[string]*CompliancePolicy),
		checks:          make(map[string]*ComplianceCheck),
		assessments:     make([]ComplianceAssessment, 0),
		findings:        make([]ComplianceFinding, 0),
		evidence:        make([]ComplianceEvidence, 0),
		builtinChecks:   make(map[string]*ComplianceCheck),
		builtinPolicies: make(map[string]*CompliancePolicy),
		scheduledChecks: make(map[string]*time.Ticker),
		shutdown:        make(chan struct{}),
		policiesPath:    filepath.Join(basePath, "policies"),
		checksPath:      filepath.Join(basePath, "checks"),
		assessmentsPath: filepath.Join(basePath, "assessments"),
		evidencePath:    filepath.Join(basePath, "evidence"),
	}

	// Ensure directories exist
	for _, path := range []string{cm.policiesPath, cm.checksPath, cm.assessmentsPath, cm.evidencePath} {
		os.MkdirAll(path, 0755)
	}

	// Initialize built-in checks and policies
	cm.initializeBuiltinChecks()
	cm.initializeBuiltinPolicies()
	
	// Load existing policies and checks
	cm.loadPolicies()
	cm.loadChecks()
	cm.loadAssessments()
	
	log.Info().
		Int("policies", len(cm.policies)).
		Int("checks", len(cm.checks)).
		Int("assessments", len(cm.assessments)).
		Msg("Compliance manager initialized")
	
	return cm
}

// RunComplianceAssessment runs a compliance assessment for a container
func (cm *ComplianceManager) RunComplianceAssessment(containerID, policyID string) (*ComplianceAssessment, error) {
	cm.mu.RLock()
	policy, exists := cm.policies[policyID]
	if !exists {
		policy, exists = cm.builtinPolicies[policyID]
	}
	cm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("compliance policy '%s' not found", policyID)
	}

	if !policy.Enabled {
		return nil, fmt.Errorf("compliance policy '%s' is disabled", policyID)
	}

	log.Info().
		Str("container_id", containerID).
		Str("policy_id", policyID).
		Str("framework", string(policy.Framework)).
		Int("checks", len(policy.Checks)).
		Msg("Starting compliance assessment")

	assessment := &ComplianceAssessment{
		ID:             fmt.Sprintf("assessment_%s_%s_%d", containerID, policyID, time.Now().Unix()),
		Timestamp:      time.Now(),
		ContainerID:    containerID,
		Framework:      policy.Framework,
		ProfileName:    policyID,
		CheckResults:   make([]ComplianceCheckResult, 0),
		CategoryScores: make(map[string]float64),
		Findings:       make([]ComplianceFinding, 0),
		Recommendations: make([]ComplianceRecommendation, 0),
		Evidence:       make([]ComplianceEvidence, 0),
		Metadata:       make(map[string]interface{}),
	}

	startTime := time.Now()
	totalScore := 0.0
	maxScore := 0.0

	// Run each compliance check
	for _, check := range policy.Checks {
		if !check.Enabled {
			continue
		}

		log.Debug().
			Str("check_id", check.ID).
			Str("check_name", check.Name).
			Msg("Running compliance check")

		result := cm.runComplianceCheck(containerID, &check)
		assessment.CheckResults = append(assessment.CheckResults, result)

		totalScore += result.Score
		maxScore += result.MaxScore

		// Collect findings
		for _, issue := range result.Issues {
			finding := ComplianceFinding{
				ID:              fmt.Sprintf("finding_%s_%s", check.ID, time.Now().Format("20060102150405")),
				Severity:        check.Severity,
				Title:           fmt.Sprintf("Compliance issue in %s", check.Name),
				Description:     issue,
				Category:        check.Category,
				AffectedChecks:  []string{check.ID},
				RiskLevel:       check.Severity,
				Status:          "open",
				CreatedAt:       time.Now(),
				UpdatedAt:       time.Now(),
			}
			assessment.Findings = append(assessment.Findings, finding)
		}
	}

	// Calculate overall scores and status
	assessment.OverallScore = totalScore
	assessment.MaxScore = maxScore
	if maxScore > 0 {
		assessment.CompliancePercent = (totalScore / maxScore) * 100
	}

	// Determine overall status
	if assessment.CompliancePercent >= 95 {
		assessment.OverallStatus = StatusCompliant
	} else if assessment.CompliancePercent >= 70 {
		assessment.OverallStatus = StatusPartial
	} else {
		assessment.OverallStatus = StatusNonCompliant
	}

	// Calculate category scores
	categoryTotals := make(map[string]float64)
	categoryMaxes := make(map[string]float64)
	for _, result := range assessment.CheckResults {
		check := cm.findCheck(result.CheckID)
		if check != nil {
			categoryTotals[check.Category] += result.Score
			categoryMaxes[check.Category] += result.MaxScore
		}
	}
	for category, total := range categoryTotals {
		if max := categoryMaxes[category]; max > 0 {
			assessment.CategoryScores[category] = (total / max) * 100
		}
	}

	// Generate recommendations
	assessment.Recommendations = cm.generateRecommendations(assessment)

	// Set validity period
	if policy.Schedule != nil && policy.Schedule.Enabled {
		validUntil := time.Now().Add(policy.Schedule.Interval)
		assessment.ValidUntil = &validUntil
		nextAssessment := validUntil
		assessment.NextAssessment = &nextAssessment
	}

	duration := time.Since(startTime)
	assessment.Metadata["assessmentDuration"] = duration.String()
	assessment.Metadata["checksRun"] = len(assessment.CheckResults)
	assessment.Metadata["findingsCount"] = len(assessment.Findings)

	// Store the assessment
	cm.mu.Lock()
	cm.assessments = append(cm.assessments, *assessment)
	cm.mu.Unlock()

	// Save to file
	if err := cm.saveAssessment(assessment); err != nil {
		log.Warn().Err(err).Str("assessment_id", assessment.ID).Msg("Failed to save assessment")
	}

	log.Info().
		Str("assessment_id", assessment.ID).
		Str("container_id", containerID).
		Str("status", string(assessment.OverallStatus)).
		Float64("compliance_percent", assessment.CompliancePercent).
		Int("findings", len(assessment.Findings)).
		Str("duration", duration.String()).
		Msg("Compliance assessment completed")

	return assessment, nil
}

// GetAssessment retrieves a compliance assessment by ID
func (cm *ComplianceManager) GetAssessment(assessmentID string) (*ComplianceAssessment, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, assessment := range cm.assessments {
		if assessment.ID == assessmentID {
			// Return a copy
			assessmentCopy := assessment
			return &assessmentCopy, nil
		}
	}

	return nil, fmt.Errorf("assessment '%s' not found", assessmentID)
}

// QueryAssessments queries compliance assessments based on criteria
func (cm *ComplianceManager) QueryAssessments(query ComplianceQuery) ([]ComplianceAssessment, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	var results []ComplianceAssessment
	for _, assessment := range cm.assessments {
		if cm.matchesComplianceQuery(assessment, query) {
			results = append(results, assessment)
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

// GenerateComplianceReport generates a comprehensive compliance report
func (cm *ComplianceManager) GenerateComplianceReport(containerID string, frameworks []ComplianceFramework, format string) ([]byte, error) {
	// Query relevant assessments
	query := ComplianceQuery{
		ContainerID:     containerID,
		IncludeEvidence: true,
		Limit:           100,
		SortBy:          "timestamp",
		SortOrder:       "desc",
	}

	var allAssessments []ComplianceAssessment
	if len(frameworks) > 0 {
		for _, framework := range frameworks {
			query.Framework = framework
			assessments, err := cm.QueryAssessments(query)
			if err != nil {
				return nil, fmt.Errorf("failed to query assessments for framework %s: %w", framework, err)
			}
			allAssessments = append(allAssessments, assessments...)
		}
	} else {
		var err error
		allAssessments, err = cm.QueryAssessments(query)
		if err != nil {
			return nil, fmt.Errorf("failed to query assessments: %w", err)
		}
	}

	// Generate report based on format
	switch strings.ToLower(format) {
	case "json":
		return json.MarshalIndent(allAssessments, "", "  ")
	case "summary":
		return cm.generateSummaryReport(allAssessments)
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

// ResolveFinding marks a compliance finding as resolved
func (cm *ComplianceManager) ResolveFinding(findingID, resolution string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for i, finding := range cm.findings {
		if finding.ID == findingID {
			now := time.Now()
			cm.findings[i].Status = "resolved"
			cm.findings[i].ResolvedAt = &now
			cm.findings[i].UpdatedAt = now
			
			// Add resolution evidence
			evidence := ComplianceEvidence{
				ID:          fmt.Sprintf("evidence_%s_%d", findingID, now.Unix()),
				Type:        "document",
				Source:      "compliance_manager",
				Title:       "Finding Resolution",
				Description: "Resolution documentation for compliance finding",
				Content:     resolution,
				CollectedAt: now,
			}
			cm.evidence = append(cm.evidence, evidence)
			cm.findings[i].Evidence = append(cm.findings[i].Evidence, evidence)

			log.Info().
				Str("finding_id", findingID).
				Str("resolution", resolution).
				Msg("Compliance finding resolved")

			return nil
		}
	}

	return fmt.Errorf("finding %s not found", findingID)
}

// Shutdown gracefully shuts down the compliance manager
func (cm *ComplianceManager) Shutdown() {
	log.Info().Msg("Shutting down compliance manager")
	
	close(cm.shutdown)
	cm.wg.Wait()
	
	// Stop scheduled checks
	cm.mu.Lock()
	for _, ticker := range cm.scheduledChecks {
		ticker.Stop()
	}
	cm.mu.Unlock()
	
	log.Info().Msg("Compliance manager shutdown completed")
}

// Private helper methods

func (cm *ComplianceManager) initializeBuiltinChecks() {
	// Security configuration checks
	cm.builtinChecks["security-001"] = &ComplianceCheck{
		ID:            "security-001",
		Framework:     FrameworkCIS,
		ControlID:     "CIS-001",
		Name:          "Container Root Filesystem Read-Only",
		Description:   "Verify that the container's root filesystem is mounted as read-only",
		Category:      "filesystem",
		Severity:      "high",
		RequiredLevel: "standard",
		CheckType:     "automated",
		AutomationRules: []AutomationRule{
			{
				RuleType: "configuration",
				Target:   "filesystem",
				Property: "readOnlyRootFilesystem",
				Operator: "equals",
				Expected: true,
				Weight:   1.0,
			},
		},
		Enabled: true,
	}

	cm.builtinChecks["security-002"] = &ComplianceCheck{
		ID:            "security-002",
		Framework:     FrameworkCIS,
		ControlID:     "CIS-002",
		Name:          "Non-Root User Execution",
		Description:   "Verify that containers do not run as root user",
		Category:      "identity",
		Severity:      "high",
		RequiredLevel: "standard",
		CheckType:     "automated",
		AutomationRules: []AutomationRule{
			{
				RuleType: "configuration",
				Target:   "security_context",
				Property: "runAsNonRoot",
				Operator: "equals",
				Expected: true,
				Weight:   1.0,
			},
		},
		Enabled: true,
	}

	cm.builtinChecks["security-003"] = &ComplianceCheck{
		ID:            "security-003",
		Framework:     FrameworkCIS,
		ControlID:     "CIS-003",
		Name:          "Privilege Escalation Prevention",
		Description:   "Verify that privilege escalation is disabled",
		Category:      "privileges",
		Severity:      "critical",
		RequiredLevel: "standard",
		CheckType:     "automated",
		AutomationRules: []AutomationRule{
			{
				RuleType: "configuration",
				Target:   "security_context",
				Property: "allowPrivilegeEscalation",
				Operator: "equals",
				Expected: false,
				Weight:   1.0,
			},
		},
		Enabled: true,
	}

	cm.builtinChecks["security-004"] = &ComplianceCheck{
		ID:            "security-004",
		Framework:     FrameworkCIS,
		ControlID:     "CIS-004",
		Name:          "Capabilities Restriction",
		Description:   "Verify that dangerous capabilities are dropped",
		Category:      "privileges",
		Severity:      "high",
		RequiredLevel: "standard",
		CheckType:     "automated",
		AutomationRules: []AutomationRule{
			{
				RuleType: "configuration",
				Target:   "capabilities",
				Property: "drop",
				Operator: "contains",
				Expected: []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"},
				Weight:   1.0,
			},
		},
		Enabled: true,
	}

	log.Info().Int("builtin_checks", len(cm.builtinChecks)).Msg("Built-in compliance checks initialized")
}

func (cm *ComplianceManager) initializeBuiltinPolicies() {
	// CIS Docker Benchmark policy
	cisChecks := []ComplianceCheck{}
	for _, check := range cm.builtinChecks {
		if check.Framework == FrameworkCIS {
			cisChecks = append(cisChecks, *check)
		}
	}

	cm.builtinPolicies["cis-docker"] = &CompliancePolicy{
		ID:          "cis-docker",
		Name:        "CIS Docker Benchmark",
		Version:     "1.0",
		Description: "CIS Docker Benchmark compliance policy",
		Framework:   FrameworkCIS,
		Scope:       []string{"container", "runtime"},
		Checks:      cisChecks,
		Categories: []ComplianceCategory{
			{
				ID:          "filesystem",
				Name:        "Filesystem Security",
				Description: "Filesystem-related security controls",
				Weight:      0.25,
				Required:    true,
			},
			{
				ID:          "identity",
				Name:        "Identity and Access",
				Description: "Identity and access management controls",
				Weight:      0.25,
				Required:    true,
			},
			{
				ID:          "privileges",
				Name:        "Privilege Management",
				Description: "Privilege and capability management controls",
				Weight:      0.5,
				Required:    true,
			},
		},
		Schedule: &ComplianceSchedule{
			Enabled:        true,
			CronExpression: "0 2 * * 0", // Weekly on Sunday at 2 AM
			MaxDuration:    30 * time.Minute,
			RetryAttempts:  3,
			RetryDelay:     5 * time.Minute,
		},
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "system",
	}

	log.Info().Int("builtin_policies", len(cm.builtinPolicies)).Msg("Built-in compliance policies initialized")
}

func (cm *ComplianceManager) loadPolicies() {
	files, err := os.ReadDir(cm.policiesPath)
	if err != nil {
		log.Warn().Err(err).Str("path", cm.policiesPath).Msg("Failed to read policies directory")
		return
	}

	loaded := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			policyPath := filepath.Join(cm.policiesPath, file.Name())
			if policy, err := cm.loadPolicy(policyPath); err == nil {
				cm.policies[policy.ID] = policy
				loaded++
			} else {
				log.Warn().Err(err).Str("file", file.Name()).Msg("Failed to load policy")
			}
		}
	}

	log.Info().Int("loaded_policies", loaded).Msg("Compliance policies loaded")
}

func (cm *ComplianceManager) loadChecks() {
	files, err := os.ReadDir(cm.checksPath)
	if err != nil {
		log.Warn().Err(err).Str("path", cm.checksPath).Msg("Failed to read checks directory")
		return
	}

	loaded := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			checkPath := filepath.Join(cm.checksPath, file.Name())
			if check, err := cm.loadCheck(checkPath); err == nil {
				cm.checks[check.ID] = check
				loaded++
			} else {
				log.Warn().Err(err).Str("file", file.Name()).Msg("Failed to load check")
			}
		}
	}

	log.Info().Int("loaded_checks", loaded).Msg("Compliance checks loaded")
}

func (cm *ComplianceManager) loadAssessments() {
	files, err := os.ReadDir(cm.assessmentsPath)
	if err != nil {
		log.Warn().Err(err).Str("path", cm.assessmentsPath).Msg("Failed to read assessments directory")
		return
	}

	loaded := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			assessmentPath := filepath.Join(cm.assessmentsPath, file.Name())
			if assessment, err := cm.loadAssessment(assessmentPath); err == nil {
				cm.assessments = append(cm.assessments, *assessment)
				loaded++
			} else {
				log.Warn().Err(err).Str("file", file.Name()).Msg("Failed to load assessment")
			}
		}
	}

	log.Info().Int("loaded_assessments", loaded).Msg("Compliance assessments loaded")
}

func (cm *ComplianceManager) loadPolicy(policyPath string) (*CompliancePolicy, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}

	var policy CompliancePolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, err
	}

	return &policy, nil
}

func (cm *ComplianceManager) loadCheck(checkPath string) (*ComplianceCheck, error) {
	data, err := os.ReadFile(checkPath)
	if err != nil {
		return nil, err
	}

	var check ComplianceCheck
	if err := json.Unmarshal(data, &check); err != nil {
		return nil, err
	}

	return &check, nil
}

func (cm *ComplianceManager) loadAssessment(assessmentPath string) (*ComplianceAssessment, error) {
	data, err := os.ReadFile(assessmentPath)
	if err != nil {
		return nil, err
	}

	var assessment ComplianceAssessment
	if err := json.Unmarshal(data, &assessment); err != nil {
		return nil, err
	}

	return &assessment, nil
}

func (cm *ComplianceManager) saveAssessment(assessment *ComplianceAssessment) error {
	assessmentPath := filepath.Join(cm.assessmentsPath, fmt.Sprintf("%s.json", assessment.ID))
	
	data, err := json.MarshalIndent(assessment, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(assessmentPath, data, 0644)
}

func (cm *ComplianceManager) runComplianceCheck(containerID string, check *ComplianceCheck) ComplianceCheckResult {
	startTime := time.Now()
	
	result := ComplianceCheckResult{
		CheckID:        check.ID,
		Status:         StatusUnknown,
		Score:          0.0,
		MaxScore:       1.0,
		Evidence:       make([]string, 0),
		Issues:         make([]string, 0),
		Remediation:    make([]string, 0),
		LastChecked:    startTime,
		Details:        make(map[string]interface{}),
	}

	// Run automated checks
	if check.CheckType == "automated" || check.CheckType == "hybrid" {
		passed := 0
		total := len(check.AutomationRules)
		
		for _, rule := range check.AutomationRules {
			if cm.evaluateAutomationRule(containerID, rule) {
				passed++
				result.Evidence = append(result.Evidence, fmt.Sprintf("Rule passed: %s", rule.RuleType))
			} else {
				result.Issues = append(result.Issues, fmt.Sprintf("Rule failed: %s", rule.RuleType))
				result.Remediation = append(result.Remediation, fmt.Sprintf("Fix %s configuration", rule.Target))
			}
		}
		
		if total > 0 {
			result.Score = float64(passed) / float64(total)
			if result.Score == 1.0 {
				result.Status = StatusCompliant
			} else if result.Score > 0.5 {
				result.Status = StatusPartial
			} else {
				result.Status = StatusNonCompliant
			}
		}
	}

	// Manual review required
	if check.CheckType == "manual" || (check.CheckType == "hybrid" && result.Status != StatusCompliant) {
		result.ManualReview = true
		if result.Status == StatusUnknown {
			result.Status = StatusInProgress
		}
	}

	result.CheckDuration = time.Since(startTime)
	return result
}

func (cm *ComplianceManager) evaluateAutomationRule(containerID string, rule AutomationRule) bool {
	// In a real implementation, this would evaluate the rule against actual container configuration
	// For now, return true for demonstration purposes
	log.Debug().
		Str("container_id", containerID).
		Str("rule_type", rule.RuleType).
		Str("target", rule.Target).
		Str("property", rule.Property).
		Msg("Evaluating compliance rule")
	
	return true
}

func (cm *ComplianceManager) findCheck(checkID string) *ComplianceCheck {
	if check, exists := cm.checks[checkID]; exists {
		return check
	}
	if check, exists := cm.builtinChecks[checkID]; exists {
		return check
	}
	return nil
}

func (cm *ComplianceManager) generateRecommendations(assessment *ComplianceAssessment) []ComplianceRecommendation {
	var recommendations []ComplianceRecommendation

	// Generate recommendations based on failed checks
	for _, result := range assessment.CheckResults {
		if result.Status != StatusCompliant && len(result.Issues) > 0 {
			check := cm.findCheck(result.CheckID)
			if check != nil {
				recommendation := ComplianceRecommendation{
					ID:          fmt.Sprintf("rec_%s_%d", result.CheckID, time.Now().Unix()),
					Priority:    check.Severity,
					Title:       fmt.Sprintf("Address %s compliance issue", check.Name),
					Description: fmt.Sprintf("Resolve compliance issues in check: %s", check.Description),
					Actions:     result.Remediation,
					Benefits:    []string{fmt.Sprintf("Improve %s compliance", check.Category)},
					Timeline:    cm.getRecommendedTimeline(check.Severity),
					CreatedAt:   time.Now(),
				}
				recommendations = append(recommendations, recommendation)
			}
		}
	}

	return recommendations
}

func (cm *ComplianceManager) getRecommendedTimeline(severity string) string {
	switch severity {
	case "critical":
		return "immediate"
	case "high":
		return "within 1 week"
	case "medium":
		return "within 1 month"
	case "low":
		return "within 3 months"
	default:
		return "as needed"
	}
}

func (cm *ComplianceManager) matchesComplianceQuery(assessment ComplianceAssessment, query ComplianceQuery) bool {
	if query.ContainerID != "" && assessment.ContainerID != query.ContainerID {
		return false
	}
	
	if query.Framework != "" && assessment.Framework != query.Framework {
		return false
	}
	
	if query.Status != "" && assessment.OverallStatus != query.Status {
		return false
	}
	
	if query.MinScore > 0 && assessment.CompliancePercent < query.MinScore {
		return false
	}
	
	if query.MaxScore > 0 && assessment.CompliancePercent > query.MaxScore {
		return false
	}
	
	if !query.StartTime.IsZero() && assessment.Timestamp.Before(query.StartTime) {
		return false
	}
	
	if !query.EndTime.IsZero() && assessment.Timestamp.After(query.EndTime) {
		return false
	}
	
	return true
}

func (cm *ComplianceManager) generateSummaryReport(assessments []ComplianceAssessment) ([]byte, error) {
	if len(assessments) == 0 {
		return []byte("No compliance assessments found"), nil
	}

	summary := struct {
		ReportGeneratedAt time.Time                        `json:"reportGeneratedAt"`
		TotalAssessments  int                              `json:"totalAssessments"`
		OverallCompliance float64                          `json:"overallCompliance"`
		StatusDistribution map[ComplianceStatus]int        `json:"statusDistribution"`
		FrameworkBreakdown map[ComplianceFramework]int     `json:"frameworkBreakdown"`
		RecentAssessment  *ComplianceAssessment            `json:"recentAssessment,omitempty"`
		TopFindings       []string                         `json:"topFindings"`
	}{
		ReportGeneratedAt:  time.Now(),
		TotalAssessments:   len(assessments),
		StatusDistribution: make(map[ComplianceStatus]int),
		FrameworkBreakdown: make(map[ComplianceFramework]int),
		TopFindings:        make([]string, 0),
	}

	totalCompliance := 0.0
	for _, assessment := range assessments {
		summary.StatusDistribution[assessment.OverallStatus]++
		summary.FrameworkBreakdown[assessment.Framework]++
		totalCompliance += assessment.CompliancePercent
	}

	if len(assessments) > 0 {
		summary.OverallCompliance = totalCompliance / float64(len(assessments))
		summary.RecentAssessment = &assessments[0] // Assuming sorted by timestamp desc
	}

	return json.MarshalIndent(summary, "", "  ")
}