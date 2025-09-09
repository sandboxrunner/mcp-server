package python

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewPythonDebugger(t *testing.T) {
	// Test with nil config (should use defaults)
	debugger := NewPythonDebugger(nil)
	
	if debugger == nil {
		t.Error("Debugger should not be nil")
	}
	
	if debugger.config == nil {
		t.Error("Config should not be nil")
	}
	
	// Check default config values
	if debugger.config.DebuggerType != DebuggerTypePDB {
		t.Errorf("Expected debugger type %s, got %s", DebuggerTypePDB, debugger.config.DebuggerType)
	}
	
	if debugger.config.RemoteHost != "localhost" {
		t.Errorf("Expected remote host 'localhost', got %s", debugger.config.RemoteHost)
	}
	
	if debugger.config.RemotePort != 5678 {
		t.Errorf("Expected remote port 5678, got %d", debugger.config.RemotePort)
	}
	
	if !debugger.config.AutoBreakOnError {
		t.Error("Auto break on error should be enabled by default")
	}
	
	if debugger.config.MaxStackDepth != 10 {
		t.Errorf("Expected max stack depth 10, got %d", debugger.config.MaxStackDepth)
	}
	
	if debugger.breakpoints == nil {
		t.Error("Breakpoints map should be initialized")
	}
	
	// Test with custom config
	customConfig := &DebugConfig{
		DebuggerType:      DebuggerTypeIPDB,
		EnableRemoteDebug: true,
		RemotePort:       8080,
		MaxStackDepth:    20,
	}
	
	debugger = NewPythonDebugger(customConfig)
	
	if debugger.config.DebuggerType != DebuggerTypeIPDB {
		t.Errorf("Expected debugger type %s, got %s", DebuggerTypeIPDB, debugger.config.DebuggerType)
	}
	
	if debugger.config.RemotePort != 8080 {
		t.Errorf("Expected remote port 8080, got %d", debugger.config.RemotePort)
	}
}

func TestPythonDebugger_SetBreakpoint(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	breakpoint := &Breakpoint{
		File:      "test.py",
		Line:      10,
		Condition: "x > 5",
	}
	
	debugger.SetBreakpoint(breakpoint)
	
	// Check that breakpoint was added
	breakpoints, exists := debugger.breakpoints["test.py"]
	if !exists {
		t.Error("Breakpoints should exist for test.py")
	}
	
	if len(breakpoints) != 1 {
		t.Errorf("Expected 1 breakpoint, got %d", len(breakpoints))
	}
	
	bp := breakpoints[0]
	if bp.Line != 10 {
		t.Errorf("Expected line 10, got %d", bp.Line)
	}
	
	if bp.Condition != "x > 5" {
		t.Errorf("Expected condition 'x > 5', got %s", bp.Condition)
	}
	
	if !bp.Enabled {
		t.Error("Breakpoint should be enabled")
	}
	
	if bp.ID == "" {
		t.Error("Breakpoint should have an ID")
	}
	
	// Test adding another breakpoint to the same file
	breakpoint2 := &Breakpoint{
		File: "test.py",
		Line: 20,
	}
	
	debugger.SetBreakpoint(breakpoint2)
	
	breakpoints = debugger.breakpoints["test.py"]
	if len(breakpoints) != 2 {
		t.Errorf("Expected 2 breakpoints, got %d", len(breakpoints))
	}
}

func TestPythonDebugger_RemoveBreakpoint(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	breakpoint := &Breakpoint{
		File: "test.py",
		Line: 10,
	}
	
	debugger.SetBreakpoint(breakpoint)
	breakpointID := breakpoint.ID
	
	// Remove the breakpoint
	removed := debugger.RemoveBreakpoint(breakpointID)
	if !removed {
		t.Error("Should successfully remove breakpoint")
	}
	
	// Check that breakpoint was removed
	breakpoints := debugger.breakpoints["test.py"]
	if len(breakpoints) != 0 {
		t.Errorf("Expected 0 breakpoints, got %d", len(breakpoints))
	}
	
	// Try to remove non-existent breakpoint
	removed = debugger.RemoveBreakpoint("non-existent")
	if removed {
		t.Error("Should not remove non-existent breakpoint")
	}
}

func TestPythonDebugger_prepareDebugScript(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	originalCode := `
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

print(factorial(5))
`
	
	// Set a breakpoint
	breakpoint := &Breakpoint{
		File:      "test.py",
		Line:      3,
		Condition: "n > 1",
	}
	debugger.SetBreakpoint(breakpoint)
	
	debugScript, err := debugger.prepareDebugScript(originalCode, "test.py")
	if err != nil {
		t.Fatalf("Failed to prepare debug script: %v", err)
	}
	
	if debugScript == "" {
		t.Error("Debug script should not be empty")
	}
	
	// Check that debug script contains imports
	if !strings.Contains(debugScript, "import pdb") {
		t.Error("Debug script should import pdb")
	}
	
	// Check that helper functions are included
	if !strings.Contains(debugScript, "__debug_breakpoint") {
		t.Error("Debug script should include helper functions")
	}
	
	// Check that original code is included
	if !strings.Contains(debugScript, "factorial") {
		t.Error("Debug script should include original code")
	}
}

func TestPythonDebugger_insertBreakpoints(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	code := `def test_function():
    x = 1
    y = 2
    return x + y`
	
	// Set breakpoints
	bp1 := &Breakpoint{File: "test.py", Line: 2, Enabled: true}
	bp2 := &Breakpoint{File: "test.py", Line: 4, Enabled: true, Condition: "x > 0"}
	bp3 := &Breakpoint{File: "test.py", Line: 3, Enabled: false} // Disabled
	
	debugger.SetBreakpoint(bp1)
	debugger.SetBreakpoint(bp2)
	debugger.SetBreakpoint(bp3)
	
	instrumented := debugger.insertBreakpoints(code, "test.py")
	
	if instrumented == code {
		t.Error("Code should be modified with breakpoints")
	}
	
	// Check that enabled breakpoints were inserted
	if !strings.Contains(instrumented, "__debug_breakpoint(2") {
		t.Error("Should insert breakpoint at line 2")
	}
	
	if !strings.Contains(instrumented, "__debug_breakpoint(4") {
		t.Error("Should insert breakpoint at line 4")
	}
	
	// Check that condition is included
	if !strings.Contains(instrumented, `"x > 0"`) {
		t.Error("Should include breakpoint condition")
	}
	
	// Check that disabled breakpoint is not inserted
	if strings.Contains(instrumented, "__debug_breakpoint(3") {
		t.Error("Should not insert disabled breakpoint")
	}
}

func TestPythonDebugger_getLineIndentation(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	tests := []struct {
		line     string
		expected string
	}{
		{"def function():", ""},
		{"    x = 1", "    "},
		{"\t\ty = 2", "\t\t"},
		{"", ""},
		{"    # comment", "    "},
		{"\t    mixed = 'indent'", "\t    "},
	}
	
	for _, tt := range tests {
		result := debugger.getLineIndentation(tt.line)
		if result != tt.expected {
			t.Errorf("For line %q, expected %q, got %q", tt.line, tt.expected, result)
		}
	}
}

func TestPythonDebugger_parseFrameInfo(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	session := &DebugSession{}
	
	frameInfo := "DEBUG_FRAME:/path/to/file.py:42:my_function"
	
	debugger.parseFrameInfo(session, frameInfo)
	
	if session.CurrentFrame == nil {
		t.Error("Current frame should be set")
	}
	
	frame := session.CurrentFrame
	if frame.File != "/path/to/file.py" {
		t.Errorf("Expected file '/path/to/file.py', got %s", frame.File)
	}
	
	if frame.Line != 42 {
		t.Errorf("Expected line 42, got %d", frame.Line)
	}
	
	if frame.Name != "my_function" {
		t.Errorf("Expected function name 'my_function', got %s", frame.Name)
	}
	
	if frame.ID != 0 {
		t.Errorf("Expected frame ID 0, got %d", frame.ID)
	}
}

func TestPythonDebugger_handleBreakpointHit(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	session := &DebugSession{
		State: DebugStateRunning,
	}
	
	// Set up a breakpoint
	bp := &Breakpoint{
		File: "test.py",
		Line: 15,
	}
	debugger.SetBreakpoint(bp)
	
	breakpointInfo := "DEBUG_BREAKPOINT:15"
	
	debugger.handleBreakpointHit(session, breakpointInfo)
	
	if session.State != DebugStateBreakpoint {
		t.Errorf("Expected state %s, got %s", DebugStateBreakpoint, session.State)
	}
	
	// Check that hit count was incremented
	breakpoints := debugger.breakpoints["test.py"]
	if len(breakpoints) > 0 && breakpoints[0].HitCount != 1 {
		t.Errorf("Expected hit count 1, got %d", breakpoints[0].HitCount)
	}
}

func TestPythonDebugger_generateSessionID(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	id1 := debugger.generateSessionID()
	id2 := debugger.generateSessionID()
	
	if id1 == "" {
		t.Error("Session ID should not be empty")
	}
	
	if !strings.HasPrefix(id1, "debug_") {
		t.Error("Session ID should start with 'debug_'")
	}
	
	// IDs should be different (time-based)
	time.Sleep(1 * time.Millisecond)
	if id1 == id2 {
		t.Error("Session IDs should be unique")
	}
}

func TestPythonDebugger_generateBreakpointID(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	id1 := debugger.generateBreakpointID()
	id2 := debugger.generateBreakpointID()
	
	if id1 == "" {
		t.Error("Breakpoint ID should not be empty")
	}
	
	if !strings.HasPrefix(id1, "bp_") {
		t.Error("Breakpoint ID should start with 'bp_'")
	}
	
	// IDs should be different
	if id1 == id2 {
		t.Error("Breakpoint IDs should be unique")
	}
}

func TestPythonDebugger_GetSessionInfo(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	// No active session
	info := debugger.GetSessionInfo()
	if info != nil {
		t.Error("Should return nil when no active session")
	}
	
	// With active session
	session := &DebugSession{
		ID:    "test_session",
		State: DebugStateRunning,
	}
	
	debugger.session = session
	
	info = debugger.GetSessionInfo()
	if info == nil {
		t.Error("Should return session info")
	}
	
	if info.ID != "test_session" {
		t.Errorf("Expected session ID 'test_session', got %s", info.ID)
	}
}

func TestPythonDebugger_FormatDebugOutput(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	
	output := []string{
		"DEBUG_FRAME:/path/to/file.py:10:function",
		"Hello, World!",
		"DEBUG_LOCALS:{\"x\": {\"value\": \"5\", \"type\": \"int\"}}",
		"Processing item 1",
		"DEBUG_BREAKPOINT:10",
		"Done",
	}
	
	formatted := debugger.FormatDebugOutput(output)
	
	// Debug prefixes should be removed
	if strings.Contains(formatted, "DEBUG_") {
		t.Error("Formatted output should not contain DEBUG_ prefixes")
	}
	
	// Regular output should be preserved
	if !strings.Contains(formatted, "Hello, World!") {
		t.Error("Regular output should be preserved")
	}
	
	if !strings.Contains(formatted, "Processing item 1") {
		t.Error("Regular output should be preserved")
	}
	
	if !strings.Contains(formatted, "Done") {
		t.Error("Regular output should be preserved")
	}
}

func TestDebugSession_DefaultValues(t *testing.T) {
	session := &DebugSession{
		ID:         "test",
		State:      DebugStateIdle,
		Variables:  make(map[string]*Variable),
		StartTime:  time.Now(),
		LastUpdate: time.Now(),
	}
	
	if session.ID != "test" {
		t.Error("Session ID not set correctly")
	}
	
	if session.State != DebugStateIdle {
		t.Error("Session state should be idle")
	}
	
	if session.Variables == nil {
		t.Error("Variables map should be initialized")
	}
	
	if session.StartTime.IsZero() {
		t.Error("Start time should be set")
	}
}

func TestBreakpoint_DefaultValues(t *testing.T) {
	bp := &Breakpoint{
		File:      "test.py",
		Line:      10,
		Condition: "x > 5",
		Enabled:   true,
		Temporary: false,
	}
	
	if bp.File != "test.py" {
		t.Error("File not set correctly")
	}
	
	if bp.Line != 10 {
		t.Error("Line not set correctly")
	}
	
	if bp.Condition != "x > 5" {
		t.Error("Condition not set correctly")
	}
	
	if !bp.Enabled {
		t.Error("Breakpoint should be enabled")
	}
	
	if bp.Temporary {
		t.Error("Breakpoint should not be temporary by default")
	}
	
	if bp.HitCount != 0 {
		t.Error("Hit count should start at 0")
	}
}

func TestStackFrame_DefaultValues(t *testing.T) {
	frame := &StackFrame{
		ID:      0,
		Name:    "test_function",
		File:    "/path/to/file.py",
		Line:    42,
		Code:    "return x + y",
		Locals:  make(map[string]*Variable),
		Globals: make(map[string]*Variable),
	}
	
	if frame.Name != "test_function" {
		t.Error("Function name not set correctly")
	}
	
	if frame.File != "/path/to/file.py" {
		t.Error("File not set correctly")
	}
	
	if frame.Line != 42 {
		t.Error("Line not set correctly")
	}
	
	if frame.Locals == nil {
		t.Error("Locals map should be initialized")
	}
	
	if frame.Globals == nil {
		t.Error("Globals map should be initialized")
	}
}

func TestVariable_DefaultValues(t *testing.T) {
	variable := &Variable{
		Name:       "test_var",
		Value:      "42",
		Type:       "int",
		Size:       2,
		Expandable: false,
		Children:   make(map[string]*Variable),
		Metadata:   make(map[string]interface{}),
	}
	
	if variable.Name != "test_var" {
		t.Error("Variable name not set correctly")
	}
	
	if variable.Value != "42" {
		t.Error("Variable value not set correctly")
	}
	
	if variable.Type != "int" {
		t.Error("Variable type not set correctly")
	}
	
	if variable.Size != 2 {
		t.Error("Variable size not set correctly")
	}
	
	if variable.Expandable {
		t.Error("Variable should not be expandable by default")
	}
	
	if variable.Children == nil {
		t.Error("Children map should be initialized")
	}
	
	if variable.Metadata == nil {
		t.Error("Metadata map should be initialized")
	}
}

func TestNewRemoteDebugger(t *testing.T) {
	host := "192.168.1.100"
	port := 9999
	
	remoteDebugger := NewRemoteDebugger(host, port)
	
	if remoteDebugger == nil {
		t.Error("Remote debugger should not be nil")
	}
	
	if remoteDebugger.host != host {
		t.Errorf("Expected host %s, got %s", host, remoteDebugger.host)
	}
	
	if remoteDebugger.port != port {
		t.Errorf("Expected port %d, got %d", port, remoteDebugger.port)
	}
	
	if remoteDebugger.PythonDebugger == nil {
		t.Error("Python debugger should not be nil")
	}
	
	// Check config
	config := remoteDebugger.PythonDebugger.config
	if config.DebuggerType != DebuggerTypeRemotePDB {
		t.Errorf("Expected debugger type %s, got %s", DebuggerTypeRemotePDB, config.DebuggerType)
	}
	
	if !config.EnableRemoteDebug {
		t.Error("Remote debug should be enabled")
	}
	
	if config.RemoteHost != host {
		t.Errorf("Expected remote host %s, got %s", host, config.RemoteHost)
	}
	
	if config.RemotePort != port {
		t.Errorf("Expected remote port %d, got %d", port, config.RemotePort)
	}
}

func TestNewDebugProfiler(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	profilerConfig := &ProfilerConfig{
		EnableCProfile:       true,
		EnableLineProfiler:   false,
		EnableMemoryProfiler: true,
		SortBy:              "cumulative",
	}
	
	profiler := NewDebugProfiler(debugger, profilerConfig)
	
	if profiler == nil {
		t.Error("Debug profiler should not be nil")
	}
	
	if profiler.debugger != debugger {
		t.Error("Debugger reference not set correctly")
	}
	
	if profiler.profiler != profilerConfig {
		t.Error("Profiler config not set correctly")
	}
}

func TestDebugProfiler_generateProfilingSetup(t *testing.T) {
	debugger := NewPythonDebugger(nil)
	profilerConfig := &ProfilerConfig{
		EnableCProfile:       true,
		EnableLineProfiler:   true,
		EnableMemoryProfiler: true,
	}
	
	profiler := NewDebugProfiler(debugger, profilerConfig)
	
	setup := profiler.generateProfilingSetup()
	
	if setup == "" {
		t.Error("Profiling setup should not be empty")
	}
	
	// Check for cProfile setup
	if !strings.Contains(setup, "import cProfile") {
		t.Error("Should import cProfile")
	}
	
	if !strings.Contains(setup, "profiler.enable()") {
		t.Error("Should enable profiler")
	}
	
	// Check for line profiler setup
	if !strings.Contains(setup, "import line_profiler") {
		t.Error("Should import line_profiler")
	}
	
	// Check for memory profiler setup
	if !strings.Contains(setup, "import memory_profiler") {
		t.Error("Should import memory_profiler")
	}
	
	if !strings.Contains(setup, "import psutil") {
		t.Error("Should import psutil")
	}
}

// Integration test (would require actual Python process)
func TestPythonDebugger_Integration_StartDebugSession(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	debugger := NewPythonDebugger(nil)
	
	req := &DebugRequest{
		Code: `
def test_function(x, y):
    result = x + y
    return result

print(test_function(5, 3))
`,
		PythonPath: "python3",
		WorkingDir: "/tmp",
		Arguments:  []string{},
		Environment: map[string]string{},
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	result, err := debugger.StartDebugSession(ctx, req)
	if err != nil {
		if strings.Contains(err.Error(), "python3") || strings.Contains(err.Error(), "executable file not found") {
			t.Skip("Python3 not available, skipping integration test")
		}
		t.Fatalf("Failed to start debug session: %v", err)
	}
	
	if !result.Success {
		t.Errorf("Debug session should be successful: %v", result.Error)
	}
	
	if result.SessionID == "" {
		t.Error("Session ID should not be empty")
	}
	
	if result.State != DebugStateRunning {
		t.Errorf("Expected state %s, got %s", DebugStateRunning, result.State)
	}
	
	// Clean up
	debugger.StopDebugSession()
}

// Benchmark tests

func BenchmarkPythonDebugger_SetBreakpoint(b *testing.B) {
	debugger := NewPythonDebugger(nil)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bp := &Breakpoint{
			File: "test.py",
			Line: i + 1,
		}
		debugger.SetBreakpoint(bp)
	}
}

func BenchmarkPythonDebugger_insertBreakpoints(b *testing.B) {
	debugger := NewPythonDebugger(nil)
	
	// Set up some breakpoints
	for i := 1; i <= 10; i++ {
		bp := &Breakpoint{
			File:    "test.py",
			Line:    i,
			Enabled: true,
		}
		debugger.SetBreakpoint(bp)
	}
	
	code := `def test_function():
    x = 1
    y = 2
    z = 3
    a = 4
    b = 5
    c = 6
    d = 7
    e = 8
    return x + y + z + a + b + c + d + e`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = debugger.insertBreakpoints(code, "test.py")
	}
}

func BenchmarkPythonDebugger_prepareDebugScript(b *testing.B) {
	debugger := NewPythonDebugger(nil)
	
	// Set up some breakpoints
	for i := 1; i <= 5; i++ {
		bp := &Breakpoint{
			File:    "test.py",
			Line:    i,
			Enabled: true,
		}
		debugger.SetBreakpoint(bp)
	}
	
	code := `
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

def fibonacci(n):
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)

print("Factorial of 5:", factorial(5))
print("Fibonacci of 10:", fibonacci(10))
`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := debugger.prepareDebugScript(code, "test.py")
		if err != nil {
			b.Fatalf("Failed to prepare debug script: %v", err)
		}
	}
}

func BenchmarkPythonDebugger_FormatDebugOutput(b *testing.B) {
	debugger := NewPythonDebugger(nil)
	
	output := []string{
		"DEBUG_FRAME:/path/to/file.py:10:function",
		"Hello, World!",
		"DEBUG_LOCALS:{\"x\": {\"value\": \"5\", \"type\": \"int\"}}",
		"Processing item 1",
		"DEBUG_BREAKPOINT:10",
		"Processing item 2",
		"DEBUG_STACK:[{\"file\": \"/test.py\", \"line\": 5}]",
		"Done processing",
		"DEBUG_FRAME:/path/to/file.py:15:another_function",
		"Final result: 42",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = debugger.FormatDebugOutput(output)
	}
}