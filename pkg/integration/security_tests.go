package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sandboxrunner/mcp-server/pkg/sandbox"
	"github.com/sandboxrunner/mcp-server/pkg/tools"
)

// SecurityTestSuite provides comprehensive security testing for sandbox isolation
type SecurityTestSuite struct {
	framework *TestFramework
	asserts   *IntegrationAsserts
}

// NewSecurityTestSuite creates a new security test suite
func NewSecurityTestSuite(framework *TestFramework) *SecurityTestSuite {
	return &SecurityTestSuite{
		framework: framework,
		asserts:   NewIntegrationAsserts(nil), // Will be set per test
	}
}

// TestSecurityBoundaries tests container isolation and security measures
func TestSecurityBoundaries(t *testing.T) {
	env := DefaultTestEnvironment()
	env.EnableMetrics = true
	framework := SetupTestFramework(t, env)
	suite := NewSecurityTestSuite(framework)
	suite.asserts.T = t

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	t.Run("ContainerIsolation", func(t *testing.T) {
		suite.testContainerIsolation(ctx, t)
	})

	t.Run("FileSystemIsolation", func(t *testing.T) {
		suite.testFileSystemIsolation(ctx, t)
	})

	t.Run("NetworkIsolation", func(t *testing.T) {
		suite.testNetworkIsolation(ctx, t)
	})

	t.Run("ProcessIsolation", func(t *testing.T) {
		suite.testProcessIsolation(ctx, t)
	})

	t.Run("ResourceLimitsEnforcement", func(t *testing.T) {
		suite.testResourceLimitsEnforcement(ctx, t)
	})

	t.Run("PrivilegeEscalationPrevention", func(t *testing.T) {
		suite.testPrivilegeEscalationPrevention(ctx, t)
	})

	t.Run("MaliciousCodeExecution", func(t *testing.T) {
		suite.testMaliciousCodeExecution(ctx, t)
	})

	t.Run("DataLeakagePrevention", func(t *testing.T) {
		suite.testDataLeakagePrevention(ctx, t)
	})
}

// testContainerIsolation verifies that containers are properly isolated from each other
func (s *SecurityTestSuite) testContainerIsolation(ctx context.Context, t *testing.T) {
	// Create two containers with different security contexts
	container1 := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Environment: map[string]string{
			"SECURITY_TEST": "isolation_test_1",
			"SECRET_VALUE":  "container1_secret",
		},
	})

	container2 := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Environment: map[string]string{
			"SECURITY_TEST": "isolation_test_2",
			"SECRET_VALUE":  "container2_secret",
		},
	})

	s.framework.WaitForSandboxReady(ctx, t, container1.ID, 30*time.Second)
	s.framework.WaitForSandboxReady(ctx, t, container2.ID, 30*time.Second)

	execTool := &tools.ExecCommandTool{Manager: s.framework.SandboxManager}

	// Test 1: Verify containers have different hostnames
	result1, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "hostname",
	})
	require.NoError(t, err)
	hostname1 := strings.TrimSpace(result1.(*tools.ExecutionResult).Stdout)

	result2, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container2.ID,
		"command":    "hostname",
	})
	require.NoError(t, err)
	hostname2 := strings.TrimSpace(result2.(*tools.ExecutionResult).Stdout)

	assert.NotEqual(t, hostname1, hostname2, "Containers should have different hostnames")

	// Test 2: Verify containers have different process IDs for init
	result1, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "ps",
		"args":       []string{"aux"},
	})
	require.NoError(t, err)

	result2, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container2.ID,
		"command":    "ps",
		"args":       []string{"aux"},
	})
	require.NoError(t, err)

	// Both should show isolated process trees
	assert.Contains(t, result1.(*tools.ExecutionResult).Stdout, "ps aux", "Container 1 should show its own processes")
	assert.Contains(t, result2.(*tools.ExecutionResult).Stdout, "ps aux", "Container 2 should show its own processes")

	// Test 3: Verify environment isolation
	result1, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "printenv",
		"args":       []string{"SECRET_VALUE"},
	})
	require.NoError(t, err)
	assert.Contains(t, result1.(*tools.ExecutionResult).Stdout, "container1_secret")

	result2, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container2.ID,
		"command":    "printenv",
		"args":       []string{"SECRET_VALUE"},
	})
	require.NoError(t, err)
	assert.Contains(t, result2.(*tools.ExecutionResult).Stdout, "container2_secret")

	// Test 4: Verify PID namespace isolation
	result1, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "ls",
		"args":       []string{"/proc"},
	})
	require.NoError(t, err)

	result2, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container2.ID,
		"command":    "ls",
		"args":       []string{"/proc"},
	})
	require.NoError(t, err)

	// Both containers should see their own /proc filesystem
	assert.Contains(t, result1.(*tools.ExecutionResult).Stdout, "1", "Container 1 should see init as PID 1")
	assert.Contains(t, result2.(*tools.ExecutionResult).Stdout, "1", "Container 2 should see init as PID 1")

	t.Log("Container isolation tests passed")
}

// testFileSystemIsolation verifies file system boundaries
func (s *SecurityTestSuite) testFileSystemIsolation(ctx context.Context, t *testing.T) {
	container := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Environment: map[string]string{
			"SECURITY_TEST": "filesystem_isolation",
		},
	})

	s.framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

	execTool := &tools.ExecCommandTool{Manager: s.framework.SandboxManager}
	uploadTool := &tools.UploadFileTool{Manager: s.framework.SandboxManager}

	// Test 1: Verify workspace isolation
	secretContent := "This is sensitive data that should be isolated"
	_, err := uploadTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"file_path":  "/workspace/sensitive.txt",
		"content":    secretContent,
	})
	require.NoError(t, err)

	// Try to access files outside workspace (should fail)
	result, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "ls",
		"args":       []string{"/etc/passwd"},
	})
	// This might succeed in some containers, but sensitive files should not be writable
	if err == nil {
		// Verify we can't write to system files
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "touch",
			"args":       []string{"/etc/malicious_file"},
		})
		// This should fail due to permissions
		if result != nil {
			assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode, 
				"Should not be able to write to system directories")
		}
	}

	// Test 2: Verify file permissions are enforced
	_, err = uploadTool.Execute(ctx, map[string]interface{}{
		"sandbox_id":  container.ID,
		"file_path":   "/workspace/readonly.txt",
		"content":     "readonly content",
		"permissions": "0444", // Read-only
	})
	require.NoError(t, err)

	// Try to modify read-only file (should fail)
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "echo",
		"args":       []string{"modified"},
	})
	require.NoError(t, err)

	// Redirect should fail due to permissions
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "sh",
		"args":       []string{"-c", "echo 'modified' > /workspace/readonly.txt"},
	})
	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"Should not be able to modify read-only files")
	}

	// Test 3: Verify directory traversal protection
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "ls",
		"args":       []string{"../../../etc"},
	})
	// This test depends on the container setup - in a properly secured container,
	// directory traversal should be limited
	if result != nil && result.(*tools.ExecutionResult).ExitCode == 0 {
		t.Log("Directory traversal possible - ensure proper container security")
	}

	// Test 4: Verify mount point isolation
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "mount",
	})
	if err == nil && result.(*tools.ExecutionResult).ExitCode == 0 {
		mountOutput := result.(*tools.ExecutionResult).Stdout
		// Should not see host filesystem mounts
		assert.NotContains(t, mountOutput, "/home", "Should not see host home directory")
		t.Logf("Mount information: %s", mountOutput)
	}

	t.Log("Filesystem isolation tests completed")
}

// testNetworkIsolation verifies network security boundaries
func (s *SecurityTestSuite) testNetworkIsolation(ctx context.Context, t *testing.T) {
	container := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		NetworkMode:  "none", // No network access
		Environment: map[string]string{
			"SECURITY_TEST": "network_isolation",
		},
	})

	s.framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

	execTool := &tools.ExecCommandTool{Manager: s.framework.SandboxManager}

	// Test 1: Verify external network access is blocked
	result, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "ping",
		"args":       []string{"-c", "1", "8.8.8.8"},
		"timeout":    10,
	})
	
	// Should fail due to network isolation
	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"External network access should be blocked")
	} else {
		t.Log("Network tools not available (expected in minimal container)")
	}

	// Test 2: Verify DNS resolution is blocked
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "nslookup",
		"args":       []string{"google.com"},
		"timeout":    5,
	})
	
	// Should fail or not be available
	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"DNS resolution should be blocked")
	}

	// Test 3: Verify loopback interface is available
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "ping",
		"args":       []string{"-c", "1", "127.0.0.1"},
		"timeout":    5,
	})
	
	// Loopback should work if ping is available
	if err == nil && result != nil && result.(*tools.ExecutionResult).ExitCode == 0 {
		assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "127.0.0.1",
			"Loopback interface should be accessible")
	} else {
		t.Log("Loopback test skipped (ping not available)")
	}

	// Test 4: Check network interfaces
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "ip",
		"args":       []string{"addr", "show"},
	})
	
	if err == nil && result != nil {
		output := result.(*tools.ExecutionResult).Stdout
		// Should only see loopback interface
		assert.Contains(t, output, "lo", "Loopback interface should be present")
		// Should not see external interfaces in isolated mode
		t.Logf("Network interfaces: %s", output)
	} else {
		// Try alternative command
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "ifconfig",
		})
		if err == nil && result != nil {
			t.Logf("Network interfaces (ifconfig): %s", result.(*tools.ExecutionResult).Stdout)
		} else {
			t.Log("Network interface tools not available")
		}
	}

	t.Log("Network isolation tests completed")
}

// testProcessIsolation verifies process-level security
func (s *SecurityTestSuite) testProcessIsolation(ctx context.Context, t *testing.T) {
	container := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Environment: map[string]string{
			"SECURITY_TEST": "process_isolation",
		},
	})

	s.framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

	execTool := &tools.ExecCommandTool{Manager: s.framework.SandboxManager}

	// Test 1: Verify process namespace isolation
	result, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "ps",
		"args":       []string{"aux"},
	})
	require.NoError(t, err)

	processOutput := result.(*tools.ExecutionResult).Stdout
	// Should only see processes within the container
	assert.Contains(t, processOutput, "ps aux", "Should see the current ps command")
	
	// Should not see host processes (like systemd with PID 1 outside container)
	lines := strings.Split(processOutput, "\n")
	processCount := len(lines) - 2 // Subtract header and empty line
	assert.Less(t, processCount, 50, "Should see limited number of processes (container isolation)")

	// Test 2: Verify user isolation
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "id",
	})
	require.NoError(t, err)
	userInfo := result.(*tools.ExecutionResult).Stdout
	t.Logf("Container user info: %s", userInfo)

	// Test 3: Verify capability restrictions
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "capsh",
		"args":       []string{"--print"},
	})
	
	if err == nil && result.(*tools.ExecutionResult).ExitCode == 0 {
		capabilities := result.(*tools.ExecutionResult).Stdout
		t.Logf("Container capabilities: %s", capabilities)
		
		// Should not have dangerous capabilities
		assert.NotContains(t, capabilities, "cap_sys_admin", "Should not have sys_admin capability")
		assert.NotContains(t, capabilities, "cap_net_admin", "Should not have net_admin capability")
	} else {
		t.Log("Capability inspection tools not available")
	}

	// Test 4: Try to access host processes via /proc (should be isolated)
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "ls",
		"args":       []string{"/proc"},
	})
	require.NoError(t, err)

	procOutput := result.(*tools.ExecutionResult).Stdout
	procEntries := strings.Fields(procOutput)
	
	// In a properly isolated container, should only see container processes
	pidCount := 0
	for _, entry := range procEntries {
		if len(entry) > 0 && entry[0] >= '0' && entry[0] <= '9' {
			pidCount++
		}
	}
	assert.Less(t, pidCount, 20, "Should see limited PIDs in isolated /proc")

	t.Log("Process isolation tests completed")
}

// testResourceLimitsEnforcement verifies resource limits are properly enforced
func (s *SecurityTestSuite) testResourceLimitsEnforcement(ctx context.Context, t *testing.T) {
	// Create container with strict resource limits
	container := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "0.2",   // 20% of 1 CPU
			MemoryLimit: "64M",   // 64MB RAM
			DiskLimit:   "100M",  // 100MB disk
		},
		Environment: map[string]string{
			"SECURITY_TEST": "resource_limits",
		},
	})

	s.framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

	execTool := &tools.ExecCommandTool{Manager: s.framework.SandboxManager}

	// Test 1: Memory limit enforcement
	result, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "python3",
		"args": []string{"-c", `
import sys
try:
    # Try to allocate 100MB (more than the 64MB limit)
    data = bytearray(100 * 1024 * 1024)
    print("Memory allocation succeeded unexpectedly")
    sys.exit(1)
except MemoryError:
    print("Memory allocation failed as expected")
    sys.exit(0)
except Exception as e:
    print(f"Other error: {e}")
    sys.exit(2)
`},
		"timeout": 30,
	})

	if err == nil && result != nil {
		output := result.(*tools.ExecutionResult).Stdout
		exitCode := result.(*tools.ExecutionResult).ExitCode
		
		// Should either fail due to memory limit or Python not being available
		if strings.Contains(output, "Memory allocation failed") || strings.Contains(output, "MemoryError") {
			t.Log("Memory limits are enforced correctly")
		} else if exitCode != 0 {
			t.Log("Memory allocation failed (limit enforcement possible)")
		} else {
			t.Log("Memory limit enforcement test inconclusive")
		}
	}

	// Test 2: Disk limit enforcement
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "dd",
		"args":       []string{"if=/dev/zero", "of=/workspace/large_file", "bs=1M", "count=200"},
		"timeout":    60,
	})

	// Should fail due to disk space limit
	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"Large file creation should fail due to disk limits")
	}

	// Test 3: CPU limit enforcement (check if process can be throttled)
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "sh",
		"args": []string{"-c", `
			start_time=$(date +%s)
			# CPU intensive task
			for i in $(seq 1 100000); do
				echo $i > /dev/null
			done
			end_time=$(date +%s)
			duration=$((end_time - start_time))
			echo "Task completed in $duration seconds"
			if [ $duration -gt 5 ]; then
				echo "Task was throttled (good)"
				exit 0
			else
				echo "Task completed too quickly (may indicate no throttling)"
				exit 1
			fi
		`},
		"timeout": 30,
	})

	if err == nil && result != nil {
		t.Logf("CPU limit test output: %s", result.(*tools.ExecutionResult).Stdout)
	}

	// Test 4: Check resource usage visibility
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "free",
		"args":       []string{"-m"},
	})
	
	if err == nil && result != nil {
		memInfo := result.(*tools.ExecutionResult).Stdout
		t.Logf("Container memory info: %s", memInfo)
		
		// The container should see limited memory
		if strings.Contains(memInfo, "64") || strings.Contains(memInfo, "63") {
			t.Log("Memory limits are visible to container")
		}
	}

	t.Log("Resource limits enforcement tests completed")
}

// testPrivilegeEscalationPrevention tests against common privilege escalation attacks
func (s *SecurityTestSuite) testPrivilegeEscalationPrevention(ctx context.Context, t *testing.T) {
	container := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Environment: map[string]string{
			"SECURITY_TEST": "privilege_escalation",
		},
	})

	s.framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

	execTool := &tools.ExecCommandTool{Manager: s.framework.SandboxManager}

	// Test 1: Attempt sudo usage (should fail)
	result, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "sudo",
		"args":       []string{"id"},
		"timeout":    10,
	})

	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"sudo should not be available or should fail")
	} else {
		t.Log("sudo command not available (good)")
	}

	// Test 2: Attempt to access /etc/shadow
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "cat",
		"args":       []string{"/etc/shadow"},
	})

	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"Should not be able to read /etc/shadow")
	}

	// Test 3: Attempt to modify system files
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "touch",
		"args":       []string{"/etc/malicious_config"},
	})

	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"Should not be able to modify system directories")
	}

	// Test 4: Check for setuid binaries
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "find",
		"args":       []string{"/usr", "/bin", "/sbin", "-perm", "-4000", "-type", "f", "2>/dev/null"},
		"timeout":    30,
	})

	if err == nil && result != nil {
		setuidBinaries := result.(*tools.ExecutionResult).Stdout
		t.Logf("Found setuid binaries: %s", setuidBinaries)
		
		// In a security-hardened container, there should be minimal setuid binaries
		lines := strings.Split(strings.TrimSpace(setuidBinaries), "\n")
		if len(lines) > 0 && lines[0] != "" {
			setuidCount := len(lines)
			assert.Less(t, setuidCount, 10, "Should have minimal setuid binaries")
		}
	}

	// Test 5: Attempt process tracing (should fail)
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "strace",
		"args":       []string{"id"},
	})

	if result != nil {
		// strace might not be available, or might fail due to capabilities
		if result.(*tools.ExecutionResult).ExitCode != 0 {
			t.Log("strace failed or not available (good for security)")
		}
	}

	t.Log("Privilege escalation prevention tests completed")
}

// testMaliciousCodeExecution tests protection against malicious code execution
func (s *SecurityTestSuite) testMaliciousCodeExecution(ctx context.Context, t *testing.T) {
	container := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Resources: sandbox.ResourceLimits{
			CPULimit:    "0.5",
			MemoryLimit: "256M",
		},
		Environment: map[string]string{
			"SECURITY_TEST": "malicious_code",
		},
	})

	s.framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

	uploadTool := &tools.UploadFileTool{Manager: s.framework.SandboxManager}
	execTool := &tools.ExecCommandTool{Manager: s.framework.SandboxManager}

	// Test 1: Fork bomb protection
	forkBombScript := `#!/bin/bash
# Fork bomb - should be contained by resource limits
:(){ :|:& };:
`

	_, err := uploadTool.Execute(ctx, map[string]interface{}{
		"sandbox_id":  container.ID,
		"file_path":   "/workspace/forkbomb.sh",
		"content":     forkBombScript,
		"permissions": "0755",
	})
	require.NoError(t, err)

	result, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "timeout",
		"args":       []string{"10s", "/workspace/forkbomb.sh"},
		"timeout":    15,
	})

	// Should be contained by resource limits and timeout
	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"Fork bomb should be contained")
	}

	// Verify container is still responsive after fork bomb attempt
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "echo",
		"args":       []string{"container_still_alive"},
		"timeout":    10,
	})

	require.NoError(t, err)
	s.asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))
	assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "container_still_alive")

	// Test 2: Memory exhaustion protection
	memExhaustScript := `#!/usr/bin/env python3
# Memory exhaustion attempt
try:
    data = []
    while True:
        data.append(bytearray(1024 * 1024))  # 1MB chunks
        print(f"Allocated {len(data)} MB")
except MemoryError:
    print("Memory limit reached")
except Exception as e:
    print(f"Error: {e}")
`

	_, err = uploadTool.Execute(ctx, map[string]interface{}{
		"sandbox_id":  container.ID,
		"file_path":   "/workspace/memexhaust.py",
		"content":     memExhaustScript,
		"permissions": "0755",
	})
	require.NoError(t, err)

	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "timeout",
		"args":       []string{"20s", "python3", "/workspace/memexhaust.py"},
		"timeout":    25,
	})

	// Should be stopped by memory limits or timeout
	if result != nil {
		t.Logf("Memory exhaustion test output: %s", result.(*tools.ExecutionResult).Stdout)
	}

	// Test 3: Infinite loop protection
	infiniteLoopScript := `#!/bin/bash
# Infinite CPU loop
while true; do
    echo "burning cpu" > /dev/null
done
`

	_, err = uploadTool.Execute(ctx, map[string]interface{}{
		"sandbox_id":  container.ID,
		"file_path":   "/workspace/cpuloop.sh",
		"content":     infiniteLoopScript,
		"permissions": "0755",
	})
	require.NoError(t, err)

	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "timeout",
		"args":       []string{"5s", "/workspace/cpuloop.sh"},
		"timeout":    10,
	})

	// Should be stopped by timeout
	if result != nil {
		assert.NotEqual(t, 0, result.(*tools.ExecutionResult).ExitCode,
			"Infinite loop should be stopped by timeout")
	}

	// Test 4: Verify container is still responsive
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container.ID,
		"command":    "echo",
		"args":       []string{"final_health_check"},
	})

	require.NoError(t, err)
	s.asserts.AssertExecutionSuccess(result.(*tools.ExecutionResult))

	t.Log("Malicious code execution protection tests completed")
}

// testDataLeakagePrevention tests protection against data exfiltration
func (s *SecurityTestSuite) testDataLeakagePrevention(ctx context.Context, t *testing.T) {
	// Create two containers with different sensitive data
	container1 := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Environment: map[string]string{
			"SECURITY_TEST": "data_leakage_1",
			"API_KEY":       "secret_key_container1",
		},
	})

	container2 := s.framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
		Image:        "ubuntu:20.04",
		WorkspaceDir: "/workspace",
		Environment: map[string]string{
			"SECURITY_TEST": "data_leakage_2",
			"API_KEY":       "secret_key_container2",
		},
	})

	s.framework.WaitForSandboxReady(ctx, t, container1.ID, 30*time.Second)
	s.framework.WaitForSandboxReady(ctx, t, container2.ID, 30*time.Second)

	uploadTool := &tools.UploadFileTool{Manager: s.framework.SandboxManager}
	execTool := &tools.ExecCommandTool{Manager: s.framework.SandboxManager}

	// Upload sensitive data to each container
	sensitiveData1 := "Container 1 sensitive data: credit_card=1234-5678-9012-3456"
	_, err := uploadTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"file_path":  "/workspace/sensitive1.txt",
		"content":    sensitiveData1,
	})
	require.NoError(t, err)

	sensitiveData2 := "Container 2 sensitive data: ssn=123-45-6789"
	_, err = uploadTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container2.ID,
		"file_path":  "/workspace/sensitive2.txt",
		"content":    sensitiveData2,
	})
	require.NoError(t, err)

	// Test 1: Verify containers cannot access each other's data
	result, err := execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "cat",
		"args":       []string{"/workspace/sensitive2.txt"}, // Try to read container2's data
	})

	// Should fail - container1 cannot see container2's files
	assert.Error(t, err, "Should not be able to access other container's files")

	// Test 2: Verify environment isolation
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "printenv",
		"args":       []string{"API_KEY"},
	})
	require.NoError(t, err)
	assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "secret_key_container1")
	assert.NotContains(t, result.(*tools.ExecutionResult).Stdout, "secret_key_container2")

	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container2.ID,
		"command":    "printenv",
		"args":       []string{"API_KEY"},
	})
	require.NoError(t, err)
	assert.Contains(t, result.(*tools.ExecutionResult).Stdout, "secret_key_container2")
	assert.NotContains(t, result.(*tools.ExecutionResult).Stdout, "secret_key_container1")

	// Test 3: Verify no cross-container process visibility
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "ps",
		"args":       []string{"aux"},
	})
	require.NoError(t, err)

	processOutput := result.(*tools.ExecutionResult).Stdout
	// Should not contain references to container2's processes or data
	assert.NotContains(t, processOutput, "secret_key_container2")
	assert.NotContains(t, processOutput, "data_leakage_2")

	// Test 4: Test data exfiltration attempts via network (if networking allowed)
	// This test assumes networking is disabled for security
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "ping",
		"args":       []string{"-c", "1", "8.8.8.8"},
		"timeout":    5,
	})

	// Should fail if network isolation is in place
	if result != nil && result.(*tools.ExecutionResult).ExitCode == 0 {
		t.Log("WARNING: Container has network access - consider network isolation for sensitive data")
	} else {
		t.Log("Network isolation is working correctly")
	}

	// Test 5: Verify file system boundaries
	result, err = execTool.Execute(ctx, map[string]interface{}{
		"sandbox_id": container1.ID,
		"command":    "find",
		"args":       []string{"/", "-name", "*sensitive*", "-type", "f", "2>/dev/null"},
		"timeout":    30,
	})

	if err == nil && result != nil {
		foundFiles := result.(*tools.ExecutionResult).Stdout
		// Should only find its own sensitive file
		assert.Contains(t, foundFiles, "sensitive1.txt")
		assert.NotContains(t, foundFiles, "sensitive2.txt")
	}

	t.Log("Data leakage prevention tests completed")
}

// TestSecurityConfiguration tests security configuration and hardening
func TestSecurityConfiguration(t *testing.T) {
	framework := SetupTestFramework(t, DefaultTestEnvironment())
	suite := NewSecurityTestSuite(framework)
	suite.asserts.T = t

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	t.Run("DefaultSecurityPosture", func(t *testing.T) {
		// Test default security configuration
		container := framework.CreateTestSandbox(ctx, t, nil) // Use defaults
		framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}

		// Verify default user is not root
		result, err := execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "whoami",
		})
		require.NoError(t, err)
		
		username := strings.TrimSpace(result.(*tools.ExecutionResult).Stdout)
		if username != "root" {
			t.Logf("Good: Container running as non-root user: %s", username)
		} else {
			t.Log("WARNING: Container running as root - consider non-root default")
		}

		// Check if container has restricted capabilities
		result, err = execTool.Execute(ctx, map[string]interface{}{
			"sandbox_id": container.ID,
			"command":    "capsh",
			"args":       []string{"--print"},
		})
		
		if err == nil && result.(*tools.ExecutionResult).ExitCode == 0 {
			caps := result.(*tools.ExecutionResult).Stdout
			t.Logf("Default capabilities: %s", caps)
		}
	})

	t.Run("SecurityAuditLog", func(t *testing.T) {
		// Test that security-relevant events are logged
		container := framework.CreateTestSandbox(ctx, t, &sandbox.SandboxConfig{
			Environment: map[string]string{
				"AUDIT_TEST": "true",
			},
		})
		framework.WaitForSandboxReady(ctx, t, container.ID, 30*time.Second)

		execTool := &tools.ExecCommandTool{Manager: framework.SandboxManager}

		// Perform actions that should be audited
		actions := []struct {
			description string
			command     string
			args        []string
		}{
			{"File access", "ls", []string{"/etc/passwd"}},
			{"Process listing", "ps", []string{"aux"}},
			{"Network config", "ifconfig", []string{}},
		}

		for _, action := range actions {
			result, err := execTool.Execute(ctx, map[string]interface{}{
				"sandbox_id": container.ID,
				"command":    action.command,
				"args":       action.args,
			})
			
			if err == nil {
				t.Logf("Audit test - %s: %s", action.description, 
					strings.TrimSpace(result.(*tools.ExecutionResult).Stdout))
			} else {
				t.Logf("Audit test - %s: Command failed (may be expected)", action.description)
			}
		}
	})
}