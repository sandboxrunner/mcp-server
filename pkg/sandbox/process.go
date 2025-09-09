package sandbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"github.com/sandboxrunner/mcp-server/pkg/runtime"
)

// ProcessStatus represents the status of a process
type ProcessStatus string

const (
	ProcessStatusStarting ProcessStatus = "starting"
	ProcessStatusRunning  ProcessStatus = "running"
	ProcessStatusExited   ProcessStatus = "exited"
	ProcessStatusError    ProcessStatus = "error"
	ProcessStatusKilled   ProcessStatus = "killed"
)

// Process represents a running process in a sandbox
type Process struct {
	ID          string                 `json:"id"`
	SandboxID   string                 `json:"sandbox_id"`
	PID         int32                  `json:"pid"`
	Command     []string               `json:"command"`
	Environment map[string]string      `json:"environment"`
	WorkingDir  string                 `json:"working_dir"`
	Status      ProcessStatus          `json:"status"`
	ExitCode    *int32                 `json:"exit_code"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     *time.Time             `json:"end_time"`
	StdoutPath  string                 `json:"stdout_path"`
	StderrPath  string                 `json:"stderr_path"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ProcessExecutor handles process execution within sandboxes
type ProcessExecutor struct {
	db        *sql.DB
	manager   *Manager
	processes map[string]*Process
	mu        sync.RWMutex
}

// ProcessExecRequest represents a process execution request
type ProcessExecRequest struct {
	SandboxID   string            `json:"sandbox_id"`
	Command     []string          `json:"command"`
	Environment map[string]string `json:"environment"`
	WorkingDir  string            `json:"working_dir"`
	Timeout     *time.Duration    `json:"timeout"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// ProcessExecResponse represents the result of process execution
type ProcessExecResponse struct {
	Process  *Process `json:"process"`
	Stdout   string   `json:"stdout"`
	Stderr   string   `json:"stderr"`
	ExitCode int32    `json:"exit_code"`
	Success  bool     `json:"success"`
	Error    string   `json:"error"`
}

// NewProcessExecutor creates a new process executor
func NewProcessExecutor(db *sql.DB, manager *Manager) (*ProcessExecutor, error) {
	executor := &ProcessExecutor{
		db:        db,
		manager:   manager,
		processes: make(map[string]*Process),
	}

	// Create processes table
	if err := executor.createProcessTable(); err != nil {
		return nil, fmt.Errorf("failed to create process table: %w", err)
	}

	// Load existing processes
	if err := executor.loadProcesses(); err != nil {
		log.Warn().Err(err).Msg("Failed to load existing processes")
	}

	return executor, nil
}

// ExecuteProcess executes a process in the specified sandbox
func (pe *ProcessExecutor) ExecuteProcess(ctx context.Context, req ProcessExecRequest) (*ProcessExecResponse, error) {
	// Validate sandbox exists
	sandbox, err := pe.manager.GetSandbox(req.SandboxID)
	if err != nil {
		return nil, fmt.Errorf("sandbox not found: %w", err)
	}

	if sandbox.Status != SandboxStatusRunning {
		return nil, fmt.Errorf("sandbox is not running: %s", sandbox.Status)
	}

	processID := uuid.New().String()
	
	process := &Process{
		ID:          processID,
		SandboxID:   req.SandboxID,
		Command:     req.Command,
		Environment: req.Environment,
		WorkingDir:  req.WorkingDir,
		Status:      ProcessStatusStarting,
		StartTime:   time.Now(),
		StdoutPath:  fmt.Sprintf("/tmp/sandbox-process-%s.stdout", processID),
		StderrPath:  fmt.Sprintf("/tmp/sandbox-process-%s.stderr", processID),
		Metadata:    req.Metadata,
	}

	if process.Metadata == nil {
		process.Metadata = make(map[string]interface{})
	}

	// Set default working directory if not provided
	if process.WorkingDir == "" {
		process.WorkingDir = "/workspace"
	}

	// Merge environment variables
	env := make(map[string]string)
	for k, v := range sandbox.Environment {
		env[k] = v
	}
	for k, v := range req.Environment {
		env[k] = v
	}
	process.Environment = env

	pe.mu.Lock()
	pe.processes[processID] = process
	pe.mu.Unlock()

	// Save process to database
	if err := pe.saveProcess(process); err != nil {
		log.Warn().Err(err).Str("process_id", processID).Msg("Failed to save process to database")
	}

	// Execute the process with timeout if specified
	var execCtx context.Context
	var cancel context.CancelFunc
	
	if req.Timeout != nil {
		execCtx, cancel = context.WithTimeout(ctx, *req.Timeout)
		defer cancel()
	} else {
		execCtx = ctx
	}

	response, err := pe.executeWithCapture(execCtx, process, sandbox)
	if err != nil {
		process.Status = ProcessStatusError
		process.Metadata["error"] = err.Error()
		
		endTime := time.Now()
		process.EndTime = &endTime

		pe.saveProcess(process)
		
		return &ProcessExecResponse{
			Process: process,
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	return response, nil
}

// GetProcess retrieves a process by ID
func (pe *ProcessExecutor) GetProcess(processID string) (*Process, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	process, exists := pe.processes[processID]
	if !exists {
		return nil, fmt.Errorf("process not found: %s", processID)
	}

	return process, nil
}

// ListProcesses lists all processes for a sandbox
func (pe *ProcessExecutor) ListProcesses(sandboxID string) ([]*Process, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	var processes []*Process
	for _, process := range pe.processes {
		if process.SandboxID == sandboxID {
			processes = append(processes, process)
		}
	}

	return processes, nil
}

// KillProcess terminates a running process
func (pe *ProcessExecutor) KillProcess(ctx context.Context, processID string) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	process, exists := pe.processes[processID]
	if !exists {
		return fmt.Errorf("process not found: %s", processID)
	}

	if process.Status != ProcessStatusRunning {
		return fmt.Errorf("process is not running: %s", process.Status)
	}

	// Get sandbox
	sandbox, err := pe.manager.GetSandbox(process.SandboxID)
	if err != nil {
		return fmt.Errorf("failed to get sandbox: %w", err)
	}

	// Kill the process
	if err := pe.manager.runcClient.KillProcess(ctx, sandbox.ContainerID, process.PID); err != nil {
		return fmt.Errorf("failed to kill process: %w", err)
	}

	process.Status = ProcessStatusKilled
	endTime := time.Now()
	process.EndTime = &endTime

	// Update database
	if err := pe.saveProcess(process); err != nil {
		log.Warn().Err(err).Str("process_id", processID).Msg("Failed to update process in database")
	}

	log.Info().Str("process_id", processID).Int32("pid", process.PID).Msg("Process killed")
	return nil
}

// GetProcessOutput retrieves stdout and stderr for a process
func (pe *ProcessExecutor) GetProcessOutput(processID string) (string, string, error) {
	process, err := pe.GetProcess(processID)
	if err != nil {
		return "", "", err
	}

	stdout, err := pe.readOutputFile(process.StdoutPath)
	if err != nil {
		log.Warn().Err(err).Str("process_id", processID).Msg("Failed to read stdout")
	}

	stderr, err := pe.readOutputFile(process.StderrPath)
	if err != nil {
		log.Warn().Err(err).Str("process_id", processID).Msg("Failed to read stderr")
	}

	return stdout, stderr, nil
}

// StreamProcessOutput streams real-time output from a process
func (pe *ProcessExecutor) StreamProcessOutput(ctx context.Context, processID string) (<-chan string, error) {
	process, err := pe.GetProcess(processID)
	if err != nil {
		return nil, err
	}

	outputChan := make(chan string, 100)

	go func() {
		defer close(outputChan)
		
		// For simplicity, we'll poll the output files
		// In a production system, you might want to use inotify or similar
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		var lastStdoutSize, lastStderrSize int64

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check stdout
				if newContent, err := pe.readOutputFileFromOffset(process.StdoutPath, lastStdoutSize); err == nil && newContent != "" {
					outputChan <- newContent
					lastStdoutSize += int64(len(newContent))
				}

				// Check stderr
				if newContent, err := pe.readOutputFileFromOffset(process.StderrPath, lastStderrSize); err == nil && newContent != "" {
					outputChan <- newContent
					lastStderrSize += int64(len(newContent))
				}

				// Stop if process is no longer running
				if process.Status == ProcessStatusExited || process.Status == ProcessStatusError || process.Status == ProcessStatusKilled {
					return
				}
			}
		}
	}()

	return outputChan, nil
}

// executeWithCapture executes a process and captures its output
func (pe *ProcessExecutor) executeWithCapture(ctx context.Context, process *Process, sandbox *Sandbox) (*ProcessExecResponse, error) {
	// Create stdout and stderr files
	stdoutFile, err := os.Create(process.StdoutPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout file: %w", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.Create(process.StderrPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr file: %w", err)
	}
	defer stderrFile.Close()

	// Execute process in container using the new ProcessSpec
	processSpec := runtime.NewProcessSpec(process.Command[0], process.Command[1:])
	
	// Convert environment map to slice
	env := make([]string, 0, len(process.Environment))
	for k, v := range process.Environment {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	
	processSpec.WithEnvSlice(env).WithWorkingDir(process.WorkingDir)

	result, err := pe.manager.runcClient.ExecProcess(ctx, sandbox.ContainerID, processSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to execute process: %w", err)
	}

	process.PID = result.Process.PID
	process.Status = ProcessStatusRunning

	// Save updated process
	pe.saveProcess(process)

	// Wait for process completion
	// This is simplified - in a real implementation, you'd want better process monitoring
	go pe.monitorProcess(ctx, process, sandbox)

	// Read output (for immediate response)
	time.Sleep(100 * time.Millisecond) // Brief wait to capture initial output
	
	stdout, _ := pe.readOutputFile(process.StdoutPath)
	stderr, _ := pe.readOutputFile(process.StderrPath)

	return &ProcessExecResponse{
		Process:  process,
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: 0, // Will be updated when process completes
		Success:  true,
	}, nil
}

// monitorProcess monitors a process until completion
func (pe *ProcessExecutor) monitorProcess(ctx context.Context, process *Process, sandbox *Sandbox) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check process status
			status, err := pe.manager.runcClient.GetProcessStatus(ctx, sandbox.ContainerID, fmt.Sprintf("proc-%s", process.ID))
			if err != nil {
				log.Debug().Err(err).Str("process_id", process.ID).Msg("Failed to get process status")
				continue
			}

			if !status.Running {
				process.Status = ProcessStatusExited
				process.ExitCode = &status.ExitCode
				endTime := time.Now()
				process.EndTime = &endTime

				pe.saveProcess(process)
				
				log.Info().
					Str("process_id", process.ID).
					Int32("exit_code", status.ExitCode).
					Msg("Process completed")
				return
			}
		}
	}
}

// readOutputFile reads the entire content of an output file
func (pe *ProcessExecutor) readOutputFile(filepath string) (string, error) {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return "", nil
	}

	content, err := os.ReadFile(filepath)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

// readOutputFileFromOffset reads file content starting from a specific offset
func (pe *ProcessExecutor) readOutputFileFromOffset(filepath string, offset int64) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Seek to offset
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return "", err
	}

	// Read remaining content
	content, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

// saveProcess saves a process to the database
func (pe *ProcessExecutor) saveProcess(process *Process) error {
	metadataJSON, _ := json.Marshal(process.Metadata)
	envJSON, _ := json.Marshal(process.Environment)
	commandJSON, _ := json.Marshal(process.Command)

	query := `INSERT OR REPLACE INTO processes 
		(id, sandbox_id, pid, command, environment, working_dir, status, exit_code, 
		 start_time, end_time, stdout_path, stderr_path, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var endTime interface{}
	if process.EndTime != nil {
		endTime = *process.EndTime
	}

	var exitCode interface{}
	if process.ExitCode != nil {
		exitCode = *process.ExitCode
	}

	_, err := pe.db.Exec(query,
		process.ID, process.SandboxID, process.PID,
		string(commandJSON), string(envJSON), process.WorkingDir,
		string(process.Status), exitCode, process.StartTime, endTime,
		process.StdoutPath, process.StderrPath, string(metadataJSON))

	return err
}

// loadProcesses loads existing processes from database
func (pe *ProcessExecutor) loadProcesses() error {
	query := `SELECT id, sandbox_id, pid, command, environment, working_dir, status, exit_code,
		start_time, end_time, stdout_path, stderr_path, metadata FROM processes`
	
	rows, err := pe.db.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var process Process
		var statusStr, commandJSON, envJSON, metadataJSON string
		var exitCode *int32
		var endTime *time.Time

		err := rows.Scan(
			&process.ID, &process.SandboxID, &process.PID,
			&commandJSON, &envJSON, &process.WorkingDir,
			&statusStr, &exitCode, &process.StartTime, &endTime,
			&process.StdoutPath, &process.StderrPath, &metadataJSON)
		if err != nil {
			continue
		}

		process.Status = ProcessStatus(statusStr)
		process.ExitCode = exitCode
		process.EndTime = endTime
		
		json.Unmarshal([]byte(commandJSON), &process.Command)
		json.Unmarshal([]byte(envJSON), &process.Environment)
		json.Unmarshal([]byte(metadataJSON), &process.Metadata)

		pe.processes[process.ID] = &process
	}

	return nil
}

// createProcessTable creates the processes table
func (pe *ProcessExecutor) createProcessTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS processes (
		id TEXT PRIMARY KEY,
		sandbox_id TEXT NOT NULL,
		pid INTEGER,
		command TEXT NOT NULL,
		environment TEXT,
		working_dir TEXT,
		status TEXT NOT NULL,
		exit_code INTEGER,
		start_time DATETIME NOT NULL,
		end_time DATETIME,
		stdout_path TEXT,
		stderr_path TEXT,
		metadata TEXT,
		FOREIGN KEY (sandbox_id) REFERENCES sandboxes(id)
	);

	CREATE INDEX IF NOT EXISTS idx_processes_sandbox_id ON processes(sandbox_id);
	CREATE INDEX IF NOT EXISTS idx_processes_status ON processes(status);
	CREATE INDEX IF NOT EXISTS idx_processes_start_time ON processes(start_time);
	`

	_, err := pe.db.Exec(query)
	return err
}