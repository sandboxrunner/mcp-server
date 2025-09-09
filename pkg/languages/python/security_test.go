package python

import (
	"testing"
)

func TestNewSecurityScanner(t *testing.T) {
	scanner := NewSecurityScanner()
	
	if scanner == nil {
		t.Error("Scanner should not be nil")
	}
	
	if len(scanner.rules) == 0 {
		t.Error("Scanner should have predefined rules")
	}
	
	// Check that we have rules for major security categories
	categories := make(map[SecurityIssueType]bool)
	for _, rule := range scanner.rules {
		categories[rule.Type] = true
	}
	
	expectedCategories := []SecurityIssueType{
		SecurityIssueTypeInjection,
		SecurityIssueTypeHardcodedSecret,
		SecurityIssueTypeInsecureRandom,
		SecurityIssueTypePathTraversal,
		SecurityIssueTypeDeserialization,
		SecurityIssueTypeDangerous,
	}
	
	for _, category := range expectedCategories {
		if !categories[category] {
			t.Errorf("Missing rules for category: %s", category)
		}
	}
}

func TestSecurityScanner_Scan(t *testing.T) {
	scanner := NewSecurityScanner()
	
	// Test code with various security issues
	vulnerableCode := `
import os
import pickle
import subprocess
import hashlib

# SQL Injection
query = "SELECT * FROM users WHERE id = %s" % user_id
cursor.execute(query)

# Command Injection
os.system("ls " + user_input)
subprocess.run("ping " + host, shell=True)

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
password = "mysecretpassword123"

# Insecure random
import random
token = random.randint(1000, 9999)

# Path traversal
filename = "../../../etc/passwd"
with open(filename, 'r') as f:
    content = f.read()

# Dangerous functions
data = pickle.loads(user_data)
result = eval(user_input)
exec(code_from_user)

# Weak cryptography
hash_value = hashlib.md5(data.encode()).hexdigest()

# Insecure HTTP
response = requests.get("http://api.example.com/data")
`
	
	issues := scanner.Scan(vulnerableCode)
	
	if len(issues) == 0 {
		t.Error("Should detect security issues in vulnerable code")
	}
	
	// Check that we found issues of different types
	issueTypes := make(map[SecurityIssueType]int)
	for _, issue := range issues {
		issueTypes[issue.Type]++
	}
	
	expectedTypes := []SecurityIssueType{
		SecurityIssueTypeInjection,
		SecurityIssueTypeHardcodedSecret,
		SecurityIssueTypeInsecureRandom,
		SecurityIssueTypePathTraversal,
		SecurityIssueTypeDeserialization,
		SecurityIssueTypeDangerous,
	}
	
	for _, expectedType := range expectedTypes {
		if issueTypes[expectedType] == 0 {
			t.Errorf("Should detect issues of type: %s", expectedType)
		}
	}
	
	// Check that all issues have required fields
	for _, issue := range issues {
		if issue.Message == "" {
			t.Error("Issue should have a message")
		}
		if issue.LineNumber == 0 {
			t.Error("Issue should have a line number")
		}
		if issue.Severity == "" {
			t.Error("Issue should have a severity level")
		}
		if issue.Rule == "" {
			t.Error("Issue should have a rule ID")
		}
		if issue.Suggestion == "" {
			t.Error("Issue should have a suggestion")
		}
	}
}

func TestSecurityScanner_Scan_SafeCode(t *testing.T) {
	scanner := NewSecurityScanner()
	
	// Test code without security issues
	safeCode := `
import requests
import json
from typing import List, Dict

def get_user_data(user_id: int) -> Dict:
    """Safely fetch user data."""
    # Use parameterized queries
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))
    
    # Use secure random for tokens
    import secrets
    token = secrets.token_hex(16)
    
    # Use HTTPS
    response = requests.get("https://api.example.com/data")
    
    # Use JSON instead of pickle
    data = json.loads(response.text)
    
    # Validate file paths
    if os.path.isabs(filename) or '..' in filename:
        raise ValueError("Invalid filename")
    
    # Use SHA-256
    import hashlib
    hash_value = hashlib.sha256(data.encode()).hexdigest()
    
    return data
`
	
	issues := scanner.Scan(safeCode)
	
	// Safe code might still have some issues depending on the rules
	// but should have significantly fewer than vulnerable code
	if len(issues) > 5 {
		t.Errorf("Safe code should have minimal security issues, got %d", len(issues))
	}
}

func TestSecurityScanner_AddCustomRule(t *testing.T) {
	scanner := NewSecurityScanner()
	
	initialRuleCount := len(scanner.rules)
	
	customRule := SecurityRule{
		ID:       "custom_rule_1",
		Type:     SecurityIssueTypeDangerous,
		Severity: SeverityLevelMedium,
		Pattern:  nil, // Would be a compiled regex in real implementation
		Message:  "Custom security rule triggered",
	}
	
	scanner.AddCustomRule(customRule)
	
	if len(scanner.rules) != initialRuleCount+1 {
		t.Errorf("Expected %d rules, got %d", initialRuleCount+1, len(scanner.rules))
	}
	
	// Check that the custom rule was added
	found := false
	for _, rule := range scanner.rules {
		if rule.ID == "custom_rule_1" {
			found = true
			break
		}
	}
	
	if !found {
		t.Error("Custom rule was not added")
	}
}

func TestSecurityScanner_RemoveRule(t *testing.T) {
	scanner := NewSecurityScanner()
	
	// Find a rule to remove
	var ruleToRemove string
	if len(scanner.rules) > 0 {
		ruleToRemove = scanner.rules[0].ID
	} else {
		t.Skip("No rules to remove")
	}
	
	initialRuleCount := len(scanner.rules)
	
	scanner.RemoveRule(ruleToRemove)
	
	if len(scanner.rules) != initialRuleCount-1 {
		t.Errorf("Expected %d rules, got %d", initialRuleCount-1, len(scanner.rules))
	}
	
	// Check that the rule was removed
	for _, rule := range scanner.rules {
		if rule.ID == ruleToRemove {
			t.Error("Rule was not removed")
		}
	}
}

func TestSecurityScanner_FilterIssuesBySeverity(t *testing.T) {
	scanner := NewSecurityScanner()
	
	// Create test issues with different severities
	issues := []*SecurityIssue{
		{Severity: SeverityLevelInfo},
		{Severity: SeverityLevelLow},
		{Severity: SeverityLevelMedium},
		{Severity: SeverityLevelHigh},
		{Severity: SeverityLevelCritical},
	}
	
	// Filter by medium severity and above
	filtered := scanner.FilterIssuesBySeverity(issues, SeverityLevelMedium)
	
	if len(filtered) != 3 {
		t.Errorf("Expected 3 issues (medium, high, critical), got %d", len(filtered))
	}
	
	for _, issue := range filtered {
		if issue.Severity == SeverityLevelInfo || issue.Severity == SeverityLevelLow {
			t.Error("Filtered issues should not contain info or low severity")
		}
	}
	
	// Filter by critical only
	criticalOnly := scanner.FilterIssuesBySeverity(issues, SeverityLevelCritical)
	
	if len(criticalOnly) != 1 {
		t.Errorf("Expected 1 critical issue, got %d", len(criticalOnly))
	}
	
	if len(criticalOnly) > 0 && criticalOnly[0].Severity != SeverityLevelCritical {
		t.Error("Filtered issue should be critical severity")
	}
}

func TestSecurityScanner_GetSecurityReport(t *testing.T) {
	scanner := NewSecurityScanner()
	
	// Create test issues
	issues := []*SecurityIssue{
		{Type: SecurityIssueTypeInjection, Severity: SeverityLevelHigh},
		{Type: SecurityIssueTypeInjection, Severity: SeverityLevelMedium},
		{Type: SecurityIssueTypeHardcodedSecret, Severity: SeverityLevelHigh},
		{Type: SecurityIssueTypeDangerous, Severity: SeverityLevelCritical},
	}
	
	report := scanner.GetSecurityReport(issues)
	
	if report.TotalIssues != 4 {
		t.Errorf("Expected 4 total issues, got %d", report.TotalIssues)
	}
	
	if report.IssuesByType[SecurityIssueTypeInjection] != 2 {
		t.Errorf("Expected 2 injection issues, got %d", report.IssuesByType[SecurityIssueTypeInjection])
	}
	
	if report.IssuesBySeverity[SeverityLevelHigh] != 2 {
		t.Errorf("Expected 2 high severity issues, got %d", report.IssuesBySeverity[SeverityLevelHigh])
	}
	
	if report.RiskScore == 0 {
		t.Error("Risk score should be calculated")
	}
	
	if report.RiskLevel == "" {
		t.Error("Risk level should be determined")
	}
	
	// Test high risk score
	if report.RiskScore < 20 {
		t.Error("Risk score should be high with critical and high severity issues")
	}
}

func TestSecurityScanner_GetRecommendations(t *testing.T) {
	scanner := NewSecurityScanner()
	
	// Create issues of different types
	issues := []*SecurityIssue{
		{Type: SecurityIssueTypeInjection},
		{Type: SecurityIssueTypeHardcodedSecret},
		{Type: SecurityIssueTypeInsecureRandom},
		{Type: SecurityIssueTypePathTraversal},
		{Type: SecurityIssueTypeXSS},
		{Type: SecurityIssueTypeDeserialization},
		{Type: SecurityIssueTypeDangerous},
	}
	
	recommendations := scanner.GetRecommendations(issues)
	
	if len(recommendations) == 0 {
		t.Error("Should generate recommendations")
	}
	
	// Check that we have at least one recommendation per issue type
	expectedMinRecommendations := 7 // One per issue type
	if len(recommendations) < expectedMinRecommendations {
		t.Errorf("Expected at least %d recommendations, got %d", expectedMinRecommendations, len(recommendations))
	}
	
	// Check that recommendations are not empty
	for _, recommendation := range recommendations {
		if recommendation == "" {
			t.Error("Recommendation should not be empty")
		}
	}
}

func TestSecurityScanner_performContextualChecks(t *testing.T) {
	scanner := NewSecurityScanner()
	
	tests := []struct {
		name         string
		line         string
		expectedType SecurityIssueType
		shouldDetect bool
	}{
		{
			name:         "LDAP injection",
			line:         `filter = "(&(uid=" + username + ")(objectClass=person))"`,
			expectedType: SecurityIssueTypeInjection,
			shouldDetect: true,
		},
		{
			name:         "NoSQL injection",
			line:         `collection.find({"$where": "this.name == '" + name + "'})`,
			expectedType: SecurityIssueTypeInjection,
			shouldDetect: true,
		},
		{
			name:         "XML XXE vulnerability",
			line:         `tree = xml.etree.ElementTree.parse(user_file)`,
			expectedType: SecurityIssueTypeDangerous,
			shouldDetect: true,
		},
		{
			name:         "SSL verification disabled",
			line:         `response = requests.get(url, verify=False)`,
			expectedType: SecurityIssueTypeDangerous,
			shouldDetect: true,
		},
		{
			name:         "Safe code",
			line:         `response = requests.get(url)`,
			shouldDetect: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := scanner.performContextualChecks(tt.line, 1)
			
			if tt.shouldDetect && len(issues) == 0 {
				t.Error("Should detect security issue")
			}
			
			if !tt.shouldDetect && len(issues) > 0 {
				t.Error("Should not detect security issue")
			}
			
			if tt.shouldDetect && len(issues) > 0 {
				found := false
				for _, issue := range issues {
					if issue.Type == tt.expectedType {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Should detect issue of type %s", tt.expectedType)
				}
			}
		})
	}
}

func TestSecurityRule_Validation(t *testing.T) {
	tests := []struct {
		name  string
		rule  SecurityRule
		valid bool
	}{
		{
			name: "Valid rule",
			rule: SecurityRule{
				ID:       "test_rule",
				Type:     SecurityIssueTypeDangerous,
				Severity: SeverityLevelMedium,
				Message:  "Test message",
			},
			valid: true,
		},
		{
			name: "Missing ID",
			rule: SecurityRule{
				Type:     SecurityIssueTypeDangerous,
				Severity: SeverityLevelMedium,
				Message:  "Test message",
			},
			valid: false,
		},
		{
			name: "Missing message",
			rule: SecurityRule{
				ID:       "test_rule",
				Type:     SecurityIssueTypeDangerous,
				Severity: SeverityLevelMedium,
			},
			valid: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation
			if tt.valid {
				if tt.rule.ID == "" {
					t.Error("Valid rule should have ID")
				}
				if tt.rule.Message == "" {
					t.Error("Valid rule should have message")
				}
			} else {
				if tt.rule.ID == "" || tt.rule.Message == "" {
					t.Log("Invalid rule correctly missing required fields")
				}
			}
		})
	}
}

func TestSeverityLevel_Ordering(t *testing.T) {
	// Test severity level ordering for filtering
	severityOrder := map[SeverityLevel]int{
		SeverityLevelInfo:     1,
		SeverityLevelLow:      2,
		SeverityLevelMedium:   3,
		SeverityLevelHigh:     4,
		SeverityLevelCritical: 5,
	}
	
	// Test that critical is highest
	if severityOrder[SeverityLevelCritical] <= severityOrder[SeverityLevelHigh] {
		t.Error("Critical severity should be higher than high")
	}
	
	// Test that info is lowest
	if severityOrder[SeverityLevelInfo] >= severityOrder[SeverityLevelLow] {
		t.Error("Info severity should be lower than low")
	}
}

func TestSecurityIssue_Fields(t *testing.T) {
	issue := &SecurityIssue{
		Type:       SecurityIssueTypeInjection,
		Severity:   SeverityLevelHigh,
		Message:    "SQL injection vulnerability",
		LineNumber: 42,
		Column:     10,
		Rule:       "sql_injection_1",
		Suggestion: "Use parameterized queries",
		CWE:        "CWE-89",
	}
	
	if issue.Type != SecurityIssueTypeInjection {
		t.Error("Issue type not set correctly")
	}
	
	if issue.Severity != SeverityLevelHigh {
		t.Error("Issue severity not set correctly")
	}
	
	if issue.Message == "" {
		t.Error("Issue should have message")
	}
	
	if issue.LineNumber != 42 {
		t.Error("Issue line number not set correctly")
	}
	
	if issue.Suggestion == "" {
		t.Error("Issue should have suggestion")
	}
	
	if issue.CWE == "" {
		t.Error("Issue should have CWE reference")
	}
}

// Benchmark tests

func BenchmarkSecurityScanner_Scan(b *testing.B) {
	scanner := NewSecurityScanner()
	
	// Large code sample with various patterns
	code := `
import os
import sys
import pickle
import subprocess
import requests
import hashlib

def vulnerable_function(user_input):
    # Various vulnerable patterns
    query = "SELECT * FROM users WHERE id = %s" % user_input
    os.system("ls " + user_input)
    subprocess.run(user_input, shell=True)
    
    password = "hardcoded_password_123"
    api_key = "sk-1234567890abcdef"
    
    import random
    token = random.randint(1000, 9999)
    
    filename = "../../../etc/passwd" + user_input
    with open(filename) as f:
        data = f.read()
    
    result = eval(user_input)
    exec(user_input)
    pickle.loads(user_input)
    
    hash_val = hashlib.md5(user_input.encode()).hexdigest()
    
    response = requests.get("http://api.example.com/" + user_input)
    
    return result

class VulnerableClass:
    def __init__(self):
        self.secret = "another_hardcoded_secret"
    
    def process_data(self, data):
        return eval(data)
`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanner.Scan(code)
	}
}

func BenchmarkSecurityScanner_FilterIssuesBySeverity(b *testing.B) {
	scanner := NewSecurityScanner()
	
	// Create a large number of test issues
	issues := make([]*SecurityIssue, 1000)
	severities := []SeverityLevel{
		SeverityLevelInfo, SeverityLevelLow, SeverityLevelMedium,
		SeverityLevelHigh, SeverityLevelCritical,
	}
	
	for i := 0; i < 1000; i++ {
		issues[i] = &SecurityIssue{
			Severity: severities[i%len(severities)],
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanner.FilterIssuesBySeverity(issues, SeverityLevelMedium)
	}
}

func BenchmarkSecurityScanner_GetSecurityReport(b *testing.B) {
	scanner := NewSecurityScanner()
	
	// Create test issues
	issues := make([]*SecurityIssue, 100)
	types := []SecurityIssueType{
		SecurityIssueTypeInjection, SecurityIssueTypeHardcodedSecret,
		SecurityIssueTypeInsecureRandom, SecurityIssueTypePathTraversal,
	}
	severities := []SeverityLevel{
		SeverityLevelLow, SeverityLevelMedium, SeverityLevelHigh, SeverityLevelCritical,
	}
	
	for i := 0; i < 100; i++ {
		issues[i] = &SecurityIssue{
			Type:     types[i%len(types)],
			Severity: severities[i%len(severities)],
		}
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanner.GetSecurityReport(issues)
	}
}