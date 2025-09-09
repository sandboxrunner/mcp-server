package python

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// PythonDebugger provides debugging capabilities for Python code
type PythonDebugger struct {
	config         *DebugConfig
	session        *DebugSession
	breakpoints    map[string][]*Breakpoint
	outputHandlers []DebugOutputHandler
	mutex          sync.RWMutex
}

// DebugConfig configures debugging behavior
type DebugConfig struct {
	DebuggerType        DebuggerType `json:"debugger_type"`
	EnableRemoteDebug   bool         `json:"enable_remote_debug"`
	RemoteHost          string       `json:"remote_host"`
	RemotePort          int          `json:"remote_port"`
	AutoBreakOnError    bool         `json:"auto_break_on_error"`
	MaxStackDepth       int          `json:"max_stack_depth"`
	VariableDisplayMode DisplayMode  `json:"variable_display_mode"`
	OutputBufferSize    int          `json:"output_buffer_size"`
	TimeoutSeconds      int          `json:"timeout_seconds"`
}

// DebuggerType represents the type of debugger to use
type DebuggerType string

const (
	DebuggerTypePDB      DebuggerType = "pdb"
	DebuggerTypeIPDB     DebuggerType = "ipdb"
	DebuggerTypePuDB     DebuggerType = "pudb"
	DebuggerTypeRemotePDB DebuggerType = "remote_pdb"
	DebuggerTypeDAP      DebuggerType = "dap" // Debug Adapter Protocol
)

// DisplayMode represents how variables should be displayed
type DisplayMode string

const (
	DisplayModeCompact DisplayMode = "compact"
	DisplayModeVerbose DisplayMode = "verbose"
	DisplayModeJSON    DisplayMode = "json"
)

// NewPythonDebugger creates a new Python debugger instance
func NewPythonDebugger(config *DebugConfig) *PythonDebugger {
	if config == nil {
		config = &DebugConfig{
			DebuggerType:        DebuggerTypePDB,
			EnableRemoteDebug:   false,
			RemoteHost:          "localhost",
			RemotePort:          5678,
			AutoBreakOnError:    true,
			MaxStackDepth:       10,
			VariableDisplayMode: DisplayModeCompact,
			OutputBufferSize:    1024,
			TimeoutSeconds:      30,
		}
	}
	
	return &PythonDebugger{
		config:      config,
		breakpoints: make(map[string][]*Breakpoint),
	}
}

// DebugSession represents an active debugging session
type DebugSession struct {
	ID             string                 `json:"id"`
	PythonPath     string                 `json:"python_path"`
	WorkingDir     string                 `json:"working_dir"`
	ScriptPath     string                 `json:"script_path"`
	Process        *os.Process            `json:"process"`
	State          DebugState             `json:"state"`
	CurrentFrame   *StackFrame            `json:"current_frame"`
	StackTrace     []*StackFrame          `json:"stack_trace"`
	Variables      map[string]*Variable   `json:"variables"`
	Output         []string               `json:"output"`
	StartTime      time.Time              `json:"start_time"`
	LastUpdate     time.Time              `json:"last_update"`
	DebuggerPipe   io.WriteCloser         `json:"debugger_pipe"`
	OutputPipe     io.ReadCloser          `json:"output_pipe"`
	InputPipe      io.WriteCloser         `json:"input_pipe"`
	ErrorPipe      io.ReadCloser          `json:"error_pipe"`
}

// DebugState represents the current state of the debugging session
type DebugState string

const (
	DebugStateIdle       DebugState = "idle"
	DebugStateRunning    DebugState = "running"
	DebugStatePaused     DebugState = "paused"
	DebugStateBreakpoint DebugState = "breakpoint"
	DebugStateError      DebugState = "error"
	DebugStateFinished   DebugState = "finished"
)

// Breakpoint represents a debugging breakpoint
type Breakpoint struct {
	ID         string            `json:"id"`
	File       string            `json:"file"`
	Line       int               `json:"line"`
	Column     int               `json:"column"`
	Condition  string            `json:"condition"`
	HitCount   int               `json:"hit_count"`
	Enabled    bool              `json:"enabled"`
	Temporary  bool              `json:"temporary"`
	Properties map[string]string `json:"properties"`
}

// StackFrame represents a stack frame in the call stack
type StackFrame struct {
	ID         int               `json:"id"`
	Name       string            `json:"name"`
	File       string            `json:"file"`
	Line       int               `json:"line"`
	Column     int               `json:"column"`
	Code       string            `json:"code"`
	Locals     map[string]*Variable `json:"locals"`
	Globals    map[string]*Variable `json:"globals"`
	Arguments  map[string]*Variable `json:"arguments"`
}

// Variable represents a variable in the debugging context
type Variable struct {
	Name        string                 `json:"name"`
	Value       string                 `json:"value"`
	Type        string                 `json:"type"`
	Size        int                    `json:"size"`
	Children    map[string]*Variable   `json:"children"`
	Expandable  bool                   `json:"expandable"`
	Reference   string                 `json:"reference"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// DebugRequest contains parameters for starting a debug session
type DebugRequest struct {
	Code        string            `json:"code"`
	ScriptPath  string            `json:"script_path"`
	PythonPath  string            `json:"python_path"`
	WorkingDir  string            `json:"working_dir"`
	Arguments   []string          `json:"arguments"`
	Environment map[string]string `json:"environment"`
	Breakpoints []*Breakpoint     `json:"breakpoints"`
	Options     map[string]string `json:"options"`
}

// DebugResult contains the result of debug operations
type DebugResult struct {
	Success    bool              `json:"success"`
	SessionID  string            `json:"session_id"`
	State      DebugState        `json:"state"`
	Output     []string          `json:"output"`
	Error      error             `json:"error"`
	StackTrace []*StackFrame     `json:"stack_trace"`
	Variables  map[string]*Variable `json:"variables"`
	Duration   time.Duration     `json:"duration"`
}

// DebugOutputHandler handles debug output
type DebugOutputHandler func(output string, outputType DebugOutputType)

// DebugOutputType represents the type of debug output
type DebugOutputType string

const (
	DebugOutputStdout     DebugOutputType = "stdout"
	DebugOutputStderr     DebugOutputType = "stderr"
	DebugOutputDebugger   DebugOutputType = "debugger"
	DebugOutputBreakpoint DebugOutputType = "breakpoint"
	DebugOutputError      DebugOutputType = "error"
)

// StartDebugSession starts a new debugging session
func (pd *PythonDebugger) StartDebugSession(ctx context.Context, req *DebugRequest) (*DebugResult, error) {
	startTime := time.Now()
	
	result := &DebugResult{
		Variables: make(map[string]*Variable),
	}
	
	// Create debug session
	session := &DebugSession{
		ID:         pd.generateSessionID(),
		PythonPath: req.PythonPath,
		WorkingDir: req.WorkingDir,
		ScriptPath: req.ScriptPath,
		State:      DebugStateIdle,
		Variables:  make(map[string]*Variable),
		StartTime:  startTime,
		LastUpdate: startTime,
	}
	
	if session.PythonPath == "" {
		session.PythonPath = "python3"
	}
	
	if session.WorkingDir == "" {
		session.WorkingDir = "."
	}
	
	// Prepare script for debugging
	debugScript, err := pd.prepareDebugScript(req.Code, req.ScriptPath)
	if err != nil {
		result.Error = fmt.Errorf("failed to prepare debug script: %w", err)
		return result, result.Error
	}
	
	// Set initial breakpoints
	for _, bp := range req.Breakpoints {
		pd.SetBreakpoint(bp)
	}
	
	// Start debugging process
	err = pd.startDebugProcess(ctx, session, debugScript, req)
	if err != nil {
		result.Error = fmt.Errorf("failed to start debug process: %w", err)
		return result, result.Error
	}
	
	pd.mutex.Lock()
	pd.session = session
	pd.mutex.Unlock()
	
	result.Success = true
	result.SessionID = session.ID
	result.State = session.State
	result.Duration = time.Since(startTime)
	
	return result, nil
}

// prepareDebugScript prepares the Python script for debugging
func (pd *PythonDebugger) prepareDebugScript(code, scriptPath string) (string, error) {
	var debugCode strings.Builder
	
	// Import debugger
	switch pd.config.DebuggerType {
	case DebuggerTypePDB:
		debugCode.WriteString("import pdb\n")
	case DebuggerTypeIPDB:
		debugCode.WriteString("import ipdb as pdb\n")
	case DebuggerTypePuDB:
		debugCode.WriteString("import pudb as pdb\n")
	case DebuggerTypeRemotePDB:
		debugCode.WriteString("import pdb\n")
		debugCode.WriteString("import sys\n")
		debugCode.WriteString("import socket\n")
	}
	
	// Add debugging setup
	debugCode.WriteString("import sys\n")
	debugCode.WriteString("import traceback\n")
	debugCode.WriteString("import json\n")
	debugCode.WriteString("\n")
	
	// Add custom debugging functions
	debugCode.WriteString(pd.getDebugHelperFunctions())
	
	// Add breakpoint insertion
	instrumentedCode := pd.insertBreakpoints(code, scriptPath)
	debugCode.WriteString(instrumentedCode)
	
	return debugCode.String(), nil
}

// getDebugHelperFunctions returns helper functions for debugging
func (pd *PythonDebugger) getDebugHelperFunctions() string {
	return `
# Debug helper functions
def __debug_print_frame_info():
    frame = sys._getframe(1)
    print(f"DEBUG_FRAME:{frame.f_code.co_filename}:{frame.f_lineno}:{frame.f_code.co_name}")
    
def __debug_print_variables(frame):
    locals_info = {}
    for name, value in frame.f_locals.items():
        try:
            locals_info[name] = {
                'value': str(value),
                'type': type(value).__name__,
                'size': len(str(value)) if hasattr(value, '__len__') else 0
            }
        except:
            locals_info[name] = {'value': '<error>', 'type': 'unknown', 'size': 0}
    
    print(f"DEBUG_LOCALS:{json.dumps(locals_info)}")

def __debug_print_stack():
    stack = traceback.extract_stack()[:-1]
    stack_info = []
    for frame in stack:
        stack_info.append({
            'file': frame.filename,
            'line': frame.lineno,
            'name': frame.name,
            'code': frame.line or ''
        })
    print(f"DEBUG_STACK:{json.dumps(stack_info)}")

def __debug_breakpoint(line_no, condition=None):
    if condition:
        frame = sys._getframe(1)
        try:
            if not eval(condition, frame.f_globals, frame.f_locals):
                return
        except:
            pass
    
    print(f"DEBUG_BREAKPOINT:{line_no}")
    __debug_print_frame_info()
    __debug_print_variables(sys._getframe(1))
    __debug_print_stack()
    pdb.set_trace()

`
}

// insertBreakpoints inserts breakpoints into the Python code
func (pd *PythonDebugger) insertBreakpoints(code, scriptPath string) string {
	lines := strings.Split(code, "\n")
	result := make([]string, 0, len(lines))
	
	for lineNum, line := range lines {
		result = append(result, line)
		
		// Check if there's a breakpoint on this line
		if breakpoints, exists := pd.breakpoints[scriptPath]; exists {
			for _, bp := range breakpoints {
				if bp.Line == lineNum+1 && bp.Enabled {
					indent := pd.getLineIndentation(line)
					breakpointCode := fmt.Sprintf("%s__debug_breakpoint(%d", indent, bp.Line)
					if bp.Condition != "" {
						breakpointCode += fmt.Sprintf(", %q", bp.Condition)
					}
					breakpointCode += ")"
					result = append(result, breakpointCode)
				}
			}
		}
	}
	
	return strings.Join(result, "\n")
}

// getLineIndentation extracts the indentation of a line
func (pd *PythonDebugger) getLineIndentation(line string) string {
	for i, char := range line {
		if char != ' ' && char != '\t' {
			return line[:i]
		}
	}
	return line
}

// startDebugProcess starts the debugging process
func (pd *PythonDebugger) startDebugProcess(ctx context.Context, session *DebugSession, debugScript string, req *DebugRequest) error {
	// Write debug script to temporary file
	tempFile := filepath.Join(session.WorkingDir, fmt.Sprintf("debug_script_%s.py", session.ID))
	if err := os.WriteFile(tempFile, []byte(debugScript), 0644); err != nil {
		return fmt.Errorf("failed to write debug script: %w", err)
	}
	
	// Prepare command
	args := []string{tempFile}
	args = append(args, req.Arguments...)
	
	cmd := exec.CommandContext(ctx, session.PythonPath, args...)
	cmd.Dir = session.WorkingDir
	
	// Set environment
	cmd.Env = os.Environ()
	for key, value := range req.Environment {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}
	
	// Setup pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	session.OutputPipe = stdout
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	session.ErrorPipe = stderr
	
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	session.InputPipe = stdin
	
	// Start process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start debug process: %w", err)
	}
	
	session.Process = cmd.Process
	session.State = DebugStateRunning
	
	// Start output monitoring
	go pd.monitorOutput(session)
	
	return nil
}

// monitorOutput monitors the debug process output
func (pd *PythonDebugger) monitorOutput(session *DebugSession) {
	// Monitor stdout
	go func() {
		scanner := bufio.NewScanner(session.OutputPipe)
		for scanner.Scan() {
			line := scanner.Text()
			session.Output = append(session.Output, line)
			pd.processDebugOutput(session, line, DebugOutputStdout)
		}
	}()
	
	// Monitor stderr
	go func() {
		scanner := bufio.NewScanner(session.ErrorPipe)
		for scanner.Scan() {
			line := scanner.Text()
			session.Output = append(session.Output, "ERROR: "+line)
			pd.processDebugOutput(session, line, DebugOutputStderr)
		}
	}()
}

// processDebugOutput processes debug output and extracts debugging information
func (pd *PythonDebugger) processDebugOutput(session *DebugSession, line string, outputType DebugOutputType) {
	session.LastUpdate = time.Now()
	
	// Parse special debug output
	if strings.HasPrefix(line, "DEBUG_FRAME:") {
		pd.parseFrameInfo(session, line)
	} else if strings.HasPrefix(line, "DEBUG_LOCALS:") {
		pd.parseVariables(session, line)
	} else if strings.HasPrefix(line, "DEBUG_STACK:") {
		pd.parseStackTrace(session, line)
	} else if strings.HasPrefix(line, "DEBUG_BREAKPOINT:") {
		pd.handleBreakpointHit(session, line)
	}
	
	// Call output handlers
	for _, handler := range pd.outputHandlers {
		handler(line, outputType)
	}
}

// parseFrameInfo parses frame information from debug output
func (pd *PythonDebugger) parseFrameInfo(session *DebugSession, line string) {
	// Format: DEBUG_FRAME:filename:lineno:function_name
	parts := strings.Split(line, ":")
	if len(parts) >= 4 {
		filename := parts[1]
		lineNo, _ := strconv.Atoi(parts[2])
		funcName := parts[3]
		
		session.CurrentFrame = &StackFrame{
			ID:   0,
			Name: funcName,
			File: filename,
			Line: lineNo,
		}
	}
}

// parseVariables parses variable information from debug output
func (pd *PythonDebugger) parseVariables(session *DebugSession, line string) {
	// Extract JSON data after DEBUG_LOCALS:
	jsonData := strings.TrimPrefix(line, "DEBUG_LOCALS:")
	
	var localsInfo map[string]interface{}
	if err := parseJSONSafely(jsonData, &localsInfo); err == nil {
		for name, info := range localsInfo {
			if infoMap, ok := info.(map[string]interface{}); ok {
				variable := &Variable{
					Name: name,
					Type: getString(infoMap, "type"),
					Value: getString(infoMap, "value"),
					Size: getInt(infoMap, "size"),
				}
				session.Variables[name] = variable
				
				if session.CurrentFrame != nil {
					if session.CurrentFrame.Locals == nil {
						session.CurrentFrame.Locals = make(map[string]*Variable)
					}
					session.CurrentFrame.Locals[name] = variable
				}
			}
		}
	}
}

// parseStackTrace parses stack trace information from debug output
func (pd *PythonDebugger) parseStackTrace(session *DebugSession, line string) {
	// Extract JSON data after DEBUG_STACK:
	jsonData := strings.TrimPrefix(line, "DEBUG_STACK:")
	
	var stackInfo []interface{}
	if err := parseJSONSafely(jsonData, &stackInfo); err == nil {
		session.StackTrace = make([]*StackFrame, 0, len(stackInfo))
		
		for i, frameInfo := range stackInfo {
			if frameMap, ok := frameInfo.(map[string]interface{}); ok {
				frame := &StackFrame{
					ID:   i,
					Name: getString(frameMap, "name"),
					File: getString(frameMap, "file"),
					Line: getInt(frameMap, "line"),
					Code: getString(frameMap, "code"),
				}
				session.StackTrace = append(session.StackTrace, frame)
			}
		}
	}
}

// handleBreakpointHit handles when a breakpoint is hit
func (pd *PythonDebugger) handleBreakpointHit(session *DebugSession, line string) {
	// Extract line number from DEBUG_BREAKPOINT:line_no
	parts := strings.Split(line, ":")
	if len(parts) >= 2 {
		lineNo, _ := strconv.Atoi(parts[1])
		
		// Update breakpoint hit count
		for _, breakpoints := range pd.breakpoints {
			for _, bp := range breakpoints {
				if bp.Line == lineNo {
					bp.HitCount++
					break
				}
			}
		}
		
		session.State = DebugStateBreakpoint
		log.Info().Int("line", lineNo).Msg("Breakpoint hit")
	}
}

// SetBreakpoint sets a breakpoint
func (pd *PythonDebugger) SetBreakpoint(bp *Breakpoint) {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()
	
	if bp.ID == "" {
		bp.ID = pd.generateBreakpointID()
	}
	
	if bp.File == "" {
		bp.File = "main.py"
	}
	
	bp.Enabled = true
	
	if pd.breakpoints[bp.File] == nil {
		pd.breakpoints[bp.File] = make([]*Breakpoint, 0)
	}
	
	pd.breakpoints[bp.File] = append(pd.breakpoints[bp.File], bp)
}

// RemoveBreakpoint removes a breakpoint
func (pd *PythonDebugger) RemoveBreakpoint(breakpointID string) bool {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()
	
	for filename, breakpoints := range pd.breakpoints {
		for i, bp := range breakpoints {
			if bp.ID == breakpointID {
				pd.breakpoints[filename] = append(breakpoints[:i], breakpoints[i+1:]...)
				return true
			}
		}
	}
	
	return false
}

// StepInto performs a step into operation
func (pd *PythonDebugger) StepInto() error {
	return pd.sendDebugCommand("step")
}

// StepOver performs a step over operation
func (pd *PythonDebugger) StepOver() error {
	return pd.sendDebugCommand("next")
}

// StepOut performs a step out operation
func (pd *PythonDebugger) StepOut() error {
	return pd.sendDebugCommand("return")
}

// Continue continues execution
func (pd *PythonDebugger) Continue() error {
	return pd.sendDebugCommand("continue")
}

// sendDebugCommand sends a command to the debugger
func (pd *PythonDebugger) sendDebugCommand(command string) error {
	pd.mutex.RLock()
	session := pd.session
	pd.mutex.RUnlock()
	
	if session == nil || session.InputPipe == nil {
		return fmt.Errorf("no active debug session")
	}
	
	_, err := session.InputPipe.Write([]byte(command + "\n"))
	if err != nil {
		return fmt.Errorf("failed to send debug command: %w", err)
	}
	
	if session.State == DebugStateBreakpoint {
		session.State = DebugStateRunning
	}
	
	return nil
}

// EvaluateExpression evaluates an expression in the current debug context
func (pd *PythonDebugger) EvaluateExpression(expression string) (*Variable, error) {
	// Send evaluation command to debugger
	evalCommand := fmt.Sprintf("p %s", expression)
	if err := pd.sendDebugCommand(evalCommand); err != nil {
		return nil, err
	}
	
	// This is a simplified implementation
	// In a real implementation, you would capture the output and parse it
	return &Variable{
		Name:  expression,
		Value: "<evaluation result>",
		Type:  "unknown",
	}, nil
}

// GetVariables returns variables in the current scope
func (pd *PythonDebugger) GetVariables(scope string) (map[string]*Variable, error) {
	pd.mutex.RLock()
	session := pd.session
	pd.mutex.RUnlock()
	
	if session == nil {
		return nil, fmt.Errorf("no active debug session")
	}
	
	switch scope {
	case "local":
		if session.CurrentFrame != nil {
			return session.CurrentFrame.Locals, nil
		}
	case "global":
		if session.CurrentFrame != nil {
			return session.CurrentFrame.Globals, nil
		}
	default:
		return session.Variables, nil
	}
	
	return make(map[string]*Variable), nil
}

// GetStackTrace returns the current stack trace
func (pd *PythonDebugger) GetStackTrace() ([]*StackFrame, error) {
	pd.mutex.RLock()
	session := pd.session
	pd.mutex.RUnlock()
	
	if session == nil {
		return nil, fmt.Errorf("no active debug session")
	}
	
	return session.StackTrace, nil
}

// StopDebugSession stops the current debugging session
func (pd *PythonDebugger) StopDebugSession() error {
	pd.mutex.Lock()
	defer pd.mutex.Unlock()
	
	if pd.session == nil {
		return fmt.Errorf("no active debug session")
	}
	
	// Send quit command
	if pd.session.InputPipe != nil {
		pd.session.InputPipe.Write([]byte("quit\n"))
		pd.session.InputPipe.Close()
	}
	
	// Kill process if still running
	if pd.session.Process != nil {
		pd.session.Process.Kill()
	}
	
	// Close pipes
	if pd.session.OutputPipe != nil {
		pd.session.OutputPipe.Close()
	}
	if pd.session.ErrorPipe != nil {
		pd.session.ErrorPipe.Close()
	}
	
	pd.session.State = DebugStateFinished
	pd.session = nil
	
	return nil
}

// AddOutputHandler adds an output handler
func (pd *PythonDebugger) AddOutputHandler(handler DebugOutputHandler) {
	pd.outputHandlers = append(pd.outputHandlers, handler)
}

// GetSessionInfo returns information about the current session
func (pd *PythonDebugger) GetSessionInfo() *DebugSession {
	pd.mutex.RLock()
	defer pd.mutex.RUnlock()
	
	return pd.session
}

// FormatDebugOutput formats debug output for display
func (pd *PythonDebugger) FormatDebugOutput(output []string) string {
	var formatted strings.Builder
	
	for _, line := range output {
		// Remove debug prefixes for cleaner output
		if strings.HasPrefix(line, "DEBUG_") {
			continue
		}
		
		formatted.WriteString(line)
		formatted.WriteString("\n")
	}
	
	return formatted.String()
}

// Helper functions

func (pd *PythonDebugger) generateSessionID() string {
	return fmt.Sprintf("debug_%d", time.Now().Unix())
}

func (pd *PythonDebugger) generateBreakpointID() string {
	return fmt.Sprintf("bp_%d", time.Now().UnixNano())
}

func parseJSONSafely(data string, v interface{}) error {
	// This would use a proper JSON parser
	// For now, just return an error for simplicity
	return fmt.Errorf("JSON parsing not implemented")
}

func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		if num, ok := val.(float64); ok {
			return int(num)
		}
		if num, ok := val.(int); ok {
			return num
		}
	}
	return 0
}

// RemoteDebugger provides remote debugging capabilities
type RemoteDebugger struct {
	*PythonDebugger
	host string
	port int
}

// NewRemoteDebugger creates a new remote debugger
func NewRemoteDebugger(host string, port int) *RemoteDebugger {
	config := &DebugConfig{
		DebuggerType:      DebuggerTypeRemotePDB,
		EnableRemoteDebug: true,
		RemoteHost:        host,
		RemotePort:        port,
	}
	
	return &RemoteDebugger{
		PythonDebugger: NewPythonDebugger(config),
		host:           host,
		port:           port,
	}
}

// StartRemoteSession starts a remote debugging session
func (rd *RemoteDebugger) StartRemoteSession(ctx context.Context, req *DebugRequest) (*DebugResult, error) {
	// Modify the debug script to include remote debugging setup
	remoteSetup := fmt.Sprintf(`
import socket
import pdb

class RemotePdb(pdb.Pdb):
    def __init__(self, host='%s', port=%d):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.handle = self.sock.makefile('rw')
        super(RemotePdb, self).__init__(completekey='tab', stdin=self.handle, stdout=self.handle)

    def cmdloop(self, intro=None):
        super(RemotePdb, self).cmdloop(intro)
        
    def close(self):
        self.handle.close()
        self.sock.close()

# Replace pdb.set_trace with remote version
_remote_pdb = RemotePdb()
pdb.set_trace = _remote_pdb.set_trace
`, rd.host, rd.port)
	
	// Prepend remote setup to the code
	req.Code = remoteSetup + "\n" + req.Code
	
	return rd.PythonDebugger.StartDebugSession(ctx, req)
}

// DebugProfiler provides profiling capabilities alongside debugging
type DebugProfiler struct {
	debugger *PythonDebugger
	profiler *ProfilerConfig
}

// ProfilerConfig configures profiling behavior
type ProfilerConfig struct {
	EnableCProfile    bool   `json:"enable_cprofile"`
	EnableLineProfiler bool   `json:"enable_line_profiler"`
	EnableMemoryProfiler bool `json:"enable_memory_profiler"`
	OutputFile        string `json:"output_file"`
	SortBy            string `json:"sort_by"`
}

// NewDebugProfiler creates a new debug profiler
func NewDebugProfiler(debugger *PythonDebugger, profilerConfig *ProfilerConfig) *DebugProfiler {
	return &DebugProfiler{
		debugger: debugger,
		profiler: profilerConfig,
	}
}

// StartProfilingSession starts a debugging session with profiling
func (dp *DebugProfiler) StartProfilingSession(ctx context.Context, req *DebugRequest) (*DebugResult, error) {
	// Add profiling imports and setup to the code
	profilingSetup := dp.generateProfilingSetup()
	req.Code = profilingSetup + "\n" + req.Code
	
	return dp.debugger.StartDebugSession(ctx, req)
}

// generateProfilingSetup generates profiling setup code
func (dp *DebugProfiler) generateProfilingSetup() string {
	var setup strings.Builder
	
	if dp.profiler.EnableCProfile {
		setup.WriteString("import cProfile\n")
		setup.WriteString("import pstats\n")
		setup.WriteString("profiler = cProfile.Profile()\n")
		setup.WriteString("profiler.enable()\n")
	}
	
	if dp.profiler.EnableLineProfiler {
		setup.WriteString("import line_profiler\n")
		setup.WriteString("line_prof = line_profiler.LineProfiler()\n")
	}
	
	if dp.profiler.EnableMemoryProfiler {
		setup.WriteString("import memory_profiler\n")
		setup.WriteString("import psutil\n")
	}
	
	return setup.String()
}