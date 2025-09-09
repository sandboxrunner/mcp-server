package python

import (
	"regexp"
	"strings"
)

// SecurityScanner performs security analysis on Python code
type SecurityScanner struct {
	rules []SecurityRule
}

// SecurityRule defines a security scanning rule
type SecurityRule struct {
	ID          string            `json:"id"`
	Type        SecurityIssueType `json:"type"`
	Severity    SeverityLevel     `json:"severity"`
	Pattern     *regexp.Regexp    `json:"pattern"`
	Message     string            `json:"message"`
	Suggestion  string            `json:"suggestion"`
	CWE         string            `json:"cwe"`
	Description string            `json:"description"`
}

// NewSecurityScanner creates a new security scanner with predefined rules
func NewSecurityScanner() *SecurityScanner {
	scanner := &SecurityScanner{}
	scanner.initializeRules()
	return scanner
}

// initializeRules initializes security scanning rules
func (ss *SecurityScanner) initializeRules() {
	ss.rules = []SecurityRule{
		// SQL Injection patterns
		{
			ID:       "sql_injection_1",
			Type:     SecurityIssueTypeInjection,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`execute\s*\(\s*["|'].*%.*["|']\s*%`),
			Message:  "Potential SQL injection vulnerability",
			Suggestion: "Use parameterized queries instead of string formatting",
			CWE:      "CWE-89",
			Description: "String formatting in SQL queries can lead to SQL injection",
		},
		{
			ID:       "sql_injection_2",
			Type:     SecurityIssueTypeInjection,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`\.format\s*\([^)]*\).*execute`),
			Message:  "Potential SQL injection via .format()",
			Suggestion: "Use parameterized queries with execute(query, params)",
			CWE:      "CWE-89",
			Description: "Using .format() with SQL execute can lead to injection",
		},
		{
			ID:       "sql_injection_3",
			Type:     SecurityIssueTypeInjection,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`f["'].*\{.*\}.*["'].*execute`),
			Message:  "Potential SQL injection via f-string",
			Suggestion: "Use parameterized queries instead of f-strings",
			CWE:      "CWE-89",
			Description: "F-strings in SQL queries can lead to injection vulnerabilities",
		},
		
		// Command injection patterns
		{
			ID:       "command_injection_1",
			Type:     SecurityIssueTypeInjection,
			Severity: SeverityLevelCritical,
			Pattern:  regexp.MustCompile(`os\.system\s*\(\s*["|'].*\+.*["|']\s*\)`),
			Message:  "Command injection vulnerability in os.system()",
			Suggestion: "Use subprocess.run() with a list of arguments",
			CWE:      "CWE-78",
			Description: "String concatenation in os.system() can lead to command injection",
		},
		{
			ID:       "command_injection_2",
			Type:     SecurityIssueTypeInjection,
			Severity: SeverityLevelCritical,
			Pattern:  regexp.MustCompile(`subprocess\.(call|run|Popen)\s*\(["|'].*\+.*["|']`),
			Message:  "Command injection vulnerability in subprocess",
			Suggestion: "Pass arguments as a list instead of concatenated string",
			CWE:      "CWE-78",
			Description: "String concatenation in subprocess calls can lead to command injection",
		},
		
		// Hardcoded secrets
		{
			ID:       "hardcoded_password",
			Type:     SecurityIssueTypeHardcodedSecret,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*["|'][^"|']{8,}["|']`),
			Message:  "Hardcoded password detected",
			Suggestion: "Use environment variables or configuration files for passwords",
			CWE:      "CWE-798",
			Description: "Hardcoded passwords in source code are a security risk",
		},
		{
			ID:       "hardcoded_api_key",
			Type:     SecurityIssueTypeHardcodedSecret,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`(?i)(api_key|apikey|access_key|secret_key)\s*=\s*["|'][A-Za-z0-9+/=]{20,}["|']`),
			Message:  "Hardcoded API key detected",
			Suggestion: "Use environment variables for API keys",
			CWE:      "CWE-798",
			Description: "Hardcoded API keys should not be stored in source code",
		},
		{
			ID:       "hardcoded_token",
			Type:     SecurityIssueTypeHardcodedSecret,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`(?i)(token|bearer|jwt)\s*=\s*["|'][A-Za-z0-9+/=.-]{30,}["|']`),
			Message:  "Hardcoded token detected",
			Suggestion: "Use secure token storage mechanisms",
			CWE:      "CWE-798",
			Description: "Hardcoded tokens pose security risks",
		},
		
		// Insecure random number generation
		{
			ID:       "insecure_random",
			Type:     SecurityIssueTypeInsecureRandom,
			Severity: SeverityLevelMedium,
			Pattern:  regexp.MustCompile(`random\.(random|randint|choice|sample)\(`),
			Message:  "Insecure random number generation",
			Suggestion: "Use secrets module for cryptographic purposes",
			CWE:      "CWE-338",
			Description: "random module is not cryptographically secure",
		},
		
		// Path traversal vulnerabilities
		{
			ID:       "path_traversal_1",
			Type:     SecurityIssueTypePathTraversal,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`open\s*\(\s*["|'].*\.\./.*["|']`),
			Message:  "Path traversal vulnerability",
			Suggestion: "Validate and sanitize file paths",
			CWE:      "CWE-22",
			Description: "Directory traversal sequences in file paths",
		},
		{
			ID:       "path_traversal_2",
			Type:     SecurityIssueTypePathTraversal,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`os\.path\.join\s*\([^)]*\.\./`),
			Message:  "Potential path traversal in os.path.join",
			Suggestion: "Use os.path.abspath() and validate paths",
			CWE:      "CWE-22",
			Description: "Path traversal sequences in path joining",
		},
		
		// XSS vulnerabilities (web frameworks)
		{
			ID:       "xss_flask",
			Type:     SecurityIssueTypeXSS,
			Severity: SeverityLevelMedium,
			Pattern:  regexp.MustCompile(`return\s+["|'].*\+.*["|']`),
			Message:  "Potential XSS vulnerability in template",
			Suggestion: "Use template escaping or safe string handling",
			CWE:      "CWE-79",
			Description: "String concatenation in templates can lead to XSS",
		},
		
		// Insecure deserialization
		{
			ID:       "insecure_pickle",
			Type:     SecurityIssueTypeDeserialization,
			Severity: SeverityLevelCritical,
			Pattern:  regexp.MustCompile(`pickle\.loads?\s*\(`),
			Message:  "Insecure deserialization with pickle",
			Suggestion: "Avoid pickle for untrusted data; use JSON instead",
			CWE:      "CWE-502",
			Description: "pickle.load can execute arbitrary code",
		},
		{
			ID:       "insecure_eval",
			Type:     SecurityIssueTypeDangerous,
			Severity: SeverityLevelCritical,
			Pattern:  regexp.MustCompile(`\beval\s*\(`),
			Message:  "Dangerous use of eval()",
			Suggestion: "Avoid eval(); use ast.literal_eval() for safe evaluation",
			CWE:      "CWE-95",
			Description: "eval() can execute arbitrary code",
		},
		{
			ID:       "insecure_exec",
			Type:     SecurityIssueTypeDangerous,
			Severity: SeverityLevelCritical,
			Pattern:  regexp.MustCompile(`\bexec\s*\(`),
			Message:  "Dangerous use of exec()",
			Suggestion: "Avoid exec(); consider safer alternatives",
			CWE:      "CWE-95",
			Description: "exec() can execute arbitrary code",
		},
		
		// Dangerous imports
		{
			ID:       "dangerous_subprocess_shell",
			Type:     SecurityIssueTypeDangerous,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`subprocess\.(call|run|Popen).*shell\s*=\s*True`),
			Message:  "Subprocess with shell=True is dangerous",
			Suggestion: "Use shell=False and pass command as list",
			CWE:      "CWE-78",
			Description: "shell=True can lead to command injection vulnerabilities",
		},
		
		// Insecure HTTP
		{
			ID:       "insecure_http",
			Type:     SecurityIssueTypeDangerous,
			Severity: SeverityLevelMedium,
			Pattern:  regexp.MustCompile(`requests\.get\s*\(\s*["|']http://`),
			Message:  "Insecure HTTP connection",
			Suggestion: "Use HTTPS instead of HTTP",
			CWE:      "CWE-319",
			Description: "HTTP connections are not encrypted",
		},
		
		// Weak cryptography
		{
			ID:       "weak_crypto_md5",
			Type:     SecurityIssueTypeDangerous,
			Severity: SeverityLevelMedium,
			Pattern:  regexp.MustCompile(`hashlib\.md5\(`),
			Message:  "MD5 is cryptographically weak",
			Suggestion: "Use SHA-256 or better for security purposes",
			CWE:      "CWE-327",
			Description: "MD5 hash function is cryptographically broken",
		},
		{
			ID:       "weak_crypto_sha1",
			Type:     SecurityIssueTypeDangerous,
			Severity: SeverityLevelMedium,
			Pattern:  regexp.MustCompile(`hashlib\.sha1\(`),
			Message:  "SHA-1 is cryptographically weak",
			Suggestion: "Use SHA-256 or better for security purposes",
			CWE:      "CWE-327",
			Description: "SHA-1 hash function is cryptographically weak",
		},
		
		// Unsafe YAML loading
		{
			ID:       "unsafe_yaml",
			Type:     SecurityIssueTypeDeserialization,
			Severity: SeverityLevelHigh,
			Pattern:  regexp.MustCompile(`yaml\.load\s*\(`),
			Message:  "Unsafe YAML loading",
			Suggestion: "Use yaml.safe_load() instead of yaml.load()",
			CWE:      "CWE-502",
			Description: "yaml.load() can execute arbitrary Python code",
		},
		
		// Debug mode in production
		{
			ID:       "debug_mode",
			Type:     SecurityIssueTypeDangerous,
			Severity: SeverityLevelMedium,
			Pattern:  regexp.MustCompile(`(?i)debug\s*=\s*True`),
			Message:  "Debug mode enabled",
			Suggestion: "Disable debug mode in production",
			CWE:      "CWE-489",
			Description: "Debug mode can expose sensitive information",
		},
		
		// Temporary file vulnerabilities
		{
			ID:       "insecure_temp_file",
			Type:     SecurityIssueTypeDangerous,
			Severity: SeverityLevelMedium,
			Pattern:  regexp.MustCompile(`tempfile\.mktemp\(`),
			Message:  "Insecure temporary file creation",
			Suggestion: "Use tempfile.mkstemp() or NamedTemporaryFile()",
			CWE:      "CWE-377",
			Description: "mktemp() creates predictable temporary file names",
		},
	}
}

// Scan performs security analysis on Python code
func (ss *SecurityScanner) Scan(code string) []*SecurityIssue {
	var issues []*SecurityIssue
	
	lines := strings.Split(code, "\n")
	
	for lineNum, line := range lines {
		// Skip comments and empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		
		// Check each security rule
		for _, rule := range ss.rules {
			matches := rule.Pattern.FindAllStringSubmatchIndex(line, -1)
			for _, match := range matches {
				issue := &SecurityIssue{
					Type:       rule.Type,
					Severity:   rule.Severity,
					Message:    rule.Message,
					LineNumber: lineNum + 1,
					Column:     match[0] + 1,
					Rule:       rule.ID,
					Suggestion: rule.Suggestion,
					CWE:        rule.CWE,
				}
				issues = append(issues, issue)
			}
		}
		
		// Additional context-sensitive checks
		issues = append(issues, ss.performContextualChecks(line, lineNum+1)...)
	}
	
	return issues
}

// performContextualChecks performs additional security checks that require context
func (ss *SecurityScanner) performContextualChecks(line string, lineNum int) []*SecurityIssue {
	var issues []*SecurityIssue
	
	// Check for potential LDAP injection
	if strings.Contains(line, "ldap") && (strings.Contains(line, "+") || strings.Contains(line, "%")) {
		issues = append(issues, &SecurityIssue{
			Type:       SecurityIssueTypeInjection,
			Severity:   SeverityLevelHigh,
			Message:    "Potential LDAP injection vulnerability",
			LineNumber: lineNum,
			Rule:       "ldap_injection",
			Suggestion: "Properly escape LDAP filter characters",
			CWE:        "CWE-90",
		})
	}
	
	// Check for potential NoSQL injection
	if (strings.Contains(line, "mongo") || strings.Contains(line, "pymongo")) && 
	   (strings.Contains(line, "$where") || strings.Contains(line, "eval")) {
		issues = append(issues, &SecurityIssue{
			Type:       SecurityIssueTypeInjection,
			Severity:   SeverityLevelHigh,
			Message:    "Potential NoSQL injection vulnerability",
			LineNumber: lineNum,
			Rule:       "nosql_injection",
			Suggestion: "Avoid using $where operator with dynamic content",
			CWE:        "CWE-943",
		})
	}
	
	// Check for XML vulnerabilities
	if strings.Contains(line, "xml.etree.ElementTree") && strings.Contains(line, "parse") {
		issues = append(issues, &SecurityIssue{
			Type:       SecurityIssueTypeDangerous,
			Severity:   SeverityLevelMedium,
			Message:    "XML parsing vulnerability (XXE)",
			LineNumber: lineNum,
			Rule:       "xml_xxe",
			Suggestion: "Use defusedxml library for safe XML parsing",
			CWE:        "CWE-611",
		})
	}
	
	// Check for unsafe SSL/TLS configuration
	if strings.Contains(line, "ssl") && (strings.Contains(line, "CERT_NONE") || strings.Contains(line, "verify=False")) {
		issues = append(issues, &SecurityIssue{
			Type:       SecurityIssueTypeDangerous,
			Severity:   SeverityLevelHigh,
			Message:    "Disabled SSL certificate verification",
			LineNumber: lineNum,
			Rule:       "ssl_verification_disabled",
			Suggestion: "Enable SSL certificate verification",
			CWE:        "CWE-295",
		})
	}
	
	// Check for race condition in file operations
	if strings.Contains(line, "os.access") && strings.Contains(line, "open") {
		issues = append(issues, &SecurityIssue{
			Type:       SecurityIssueTypeDangerous,
			Severity:   SeverityLevelMedium,
			Message:    "Potential race condition (TOCTOU)",
			LineNumber: lineNum,
			Rule:       "race_condition_toctou",
			Suggestion: "Use try-except blocks instead of checking before accessing",
			CWE:        "CWE-367",
		})
	}
	
	return issues
}

// AddCustomRule adds a custom security rule
func (ss *SecurityScanner) AddCustomRule(rule SecurityRule) {
	ss.rules = append(ss.rules, rule)
}

// RemoveRule removes a security rule by ID
func (ss *SecurityScanner) RemoveRule(ruleID string) {
	for i, rule := range ss.rules {
		if rule.ID == ruleID {
			ss.rules = append(ss.rules[:i], ss.rules[i+1:]...)
			break
		}
	}
}

// GetRules returns all security rules
func (ss *SecurityScanner) GetRules() []SecurityRule {
	return ss.rules
}

// FilterIssuesBySeverity filters security issues by severity level
func (ss *SecurityScanner) FilterIssuesBySeverity(issues []*SecurityIssue, minSeverity SeverityLevel) []*SecurityIssue {
	severityOrder := map[SeverityLevel]int{
		SeverityLevelInfo:     1,
		SeverityLevelLow:      2,
		SeverityLevelMedium:   3,
		SeverityLevelHigh:     4,
		SeverityLevelCritical: 5,
	}
	
	minLevel := severityOrder[minSeverity]
	var filteredIssues []*SecurityIssue
	
	for _, issue := range issues {
		if severityOrder[issue.Severity] >= minLevel {
			filteredIssues = append(filteredIssues, issue)
		}
	}
	
	return filteredIssues
}

// GetSecurityReport generates a comprehensive security report
func (ss *SecurityScanner) GetSecurityReport(issues []*SecurityIssue) *SecurityReport {
	report := &SecurityReport{
		TotalIssues: len(issues),
		IssuesByType: make(map[SecurityIssueType]int),
		IssuesBySeverity: make(map[SeverityLevel]int),
		RiskScore: 0,
	}
	
	// Count issues by type and severity
	for _, issue := range issues {
		report.IssuesByType[issue.Type]++
		report.IssuesBySeverity[issue.Severity]++
		
		// Calculate risk score
		switch issue.Severity {
		case SeverityLevelCritical:
			report.RiskScore += 10
		case SeverityLevelHigh:
			report.RiskScore += 7
		case SeverityLevelMedium:
			report.RiskScore += 4
		case SeverityLevelLow:
			report.RiskScore += 2
		case SeverityLevelInfo:
			report.RiskScore += 1
		}
	}
	
	// Determine overall risk level
	if report.RiskScore >= 50 {
		report.RiskLevel = SeverityLevelCritical
	} else if report.RiskScore >= 30 {
		report.RiskLevel = SeverityLevelHigh
	} else if report.RiskScore >= 15 {
		report.RiskLevel = SeverityLevelMedium
	} else if report.RiskScore >= 5 {
		report.RiskLevel = SeverityLevelLow
	} else {
		report.RiskLevel = SeverityLevelInfo
	}
	
	return report
}

// SecurityReport provides a summary of security analysis
type SecurityReport struct {
	TotalIssues      int                           `json:"total_issues"`
	IssuesByType     map[SecurityIssueType]int     `json:"issues_by_type"`
	IssuesBySeverity map[SeverityLevel]int         `json:"issues_by_severity"`
	RiskScore        int                           `json:"risk_score"`
	RiskLevel        SeverityLevel                 `json:"risk_level"`
	Recommendations  []string                      `json:"recommendations"`
}

// GetRecommendations generates security recommendations based on found issues
func (ss *SecurityScanner) GetRecommendations(issues []*SecurityIssue) []string {
	var recommendations []string
	seenTypes := make(map[SecurityIssueType]bool)
	
	for _, issue := range issues {
		if !seenTypes[issue.Type] {
			switch issue.Type {
			case SecurityIssueTypeInjection:
				recommendations = append(recommendations, "Implement input validation and use parameterized queries")
			case SecurityIssueTypeHardcodedSecret:
				recommendations = append(recommendations, "Use environment variables or secure vaults for secrets")
			case SecurityIssueTypeInsecureRandom:
				recommendations = append(recommendations, "Use cryptographically secure random number generators")
			case SecurityIssueTypePathTraversal:
				recommendations = append(recommendations, "Validate and sanitize all file paths")
			case SecurityIssueTypeXSS:
				recommendations = append(recommendations, "Implement proper output encoding and validation")
			case SecurityIssueTypeDeserialization:
				recommendations = append(recommendations, "Avoid deserializing untrusted data")
			case SecurityIssueTypeDangerous:
				recommendations = append(recommendations, "Review and replace dangerous function calls")
			}
			seenTypes[issue.Type] = true
		}
	}
	
	return recommendations
}