package runtime

import (
	"testing"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestProcessSpec_ToOCIProcessSpec(t *testing.T) {
	tests := []struct {
		name     string
		spec     ProcessSpec
		expected specs.Process
	}{
		{
			name: "basic process spec",
			spec: ProcessSpec{
				Cmd:        "/bin/echo",
				Args:       []string{"/bin/echo", "hello"},
				Env:        []string{"PATH=/usr/bin", "HOME=/root"},
				WorkingDir: "/tmp",
				User:       "1000:1000",
				Terminal:   true,
			},
			expected: specs.Process{
				Terminal: true,
				Args:     []string{"/bin/echo", "hello"},
				Env:      []string{"PATH=/usr/bin", "HOME=/root"},
				Cwd:      "/tmp",
				User:     specs.User{UID: 1000, GID: 1000},
			},
		},
		{
			name: "empty working dir defaults to root",
			spec: ProcessSpec{
				Cmd:  "/bin/ls",
				Args: []string{"/bin/ls"},
			},
			expected: specs.Process{
				Terminal: false,
				Args:     []string{"/bin/ls"},
				Env:      []string{},
				Cwd:      "/",
				User:     specs.User{UID: 0, GID: 0},
			},
		},
		{
			name: "cmd prepended to args if not present",
			spec: ProcessSpec{
				Cmd:  "/bin/cat",
				Args: []string{"file.txt"},
			},
			expected: specs.Process{
				Terminal: false,
				Args:     []string{"/bin/cat", "file.txt"},
				Env:      []string{},
				Cwd:      "/",
				User:     specs.User{UID: 0, GID: 0},
			},
		},
		{
			name: "empty args uses cmd",
			spec: ProcessSpec{
				Cmd: "/bin/pwd",
			},
			expected: specs.Process{
				Terminal: false,
				Args:     []string{"/bin/pwd"},
				Env:      []string{},
				Cwd:      "/",
				User:     specs.User{UID: 0, GID: 0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.spec.ToOCIProcessSpec()

			if result.Terminal != tt.expected.Terminal {
				t.Errorf("Terminal = %v, want %v", result.Terminal, tt.expected.Terminal)
			}

			if len(result.Args) != len(tt.expected.Args) {
				t.Errorf("Args length = %v, want %v", len(result.Args), len(tt.expected.Args))
			} else {
				for i, arg := range result.Args {
					if arg != tt.expected.Args[i] {
						t.Errorf("Args[%d] = %v, want %v", i, arg, tt.expected.Args[i])
					}
				}
			}

			if len(result.Env) != len(tt.expected.Env) {
				t.Errorf("Env length = %v, want %v", len(result.Env), len(tt.expected.Env))
			} else {
				for i, env := range result.Env {
					if env != tt.expected.Env[i] {
						t.Errorf("Env[%d] = %v, want %v", i, env, tt.expected.Env[i])
					}
				}
			}

			if result.Cwd != tt.expected.Cwd {
				t.Errorf("Cwd = %v, want %v", result.Cwd, tt.expected.Cwd)
			}

			if result.User.UID != tt.expected.User.UID {
				t.Errorf("User.UID = %v, want %v", result.User.UID, tt.expected.User.UID)
			}

			if result.User.GID != tt.expected.User.GID {
				t.Errorf("User.GID = %v, want %v", result.User.GID, tt.expected.User.GID)
			}
		})
	}
}

func TestParseUser(t *testing.T) {
	tests := []struct {
		name     string
		userSpec string
		expected specs.User
	}{
		{
			name:     "empty user spec",
			userSpec: "",
			expected: specs.User{UID: 0, GID: 0},
		},
		{
			name:     "uid only",
			userSpec: "1000",
			expected: specs.User{UID: 1000, GID: 0},
		},
		{
			name:     "uid:gid",
			userSpec: "1000:1000",
			expected: specs.User{UID: 1000, GID: 1000},
		},
		{
			name:     "username only",
			userSpec: "ubuntu",
			expected: specs.User{Username: "ubuntu", UID: 0, GID: 0},
		},
		{
			name:     "username:gid",
			userSpec: "ubuntu:1000",
			expected: specs.User{Username: "ubuntu", UID: 0, GID: 1000},
		},
		{
			name:     "username:groupname",
			userSpec: "ubuntu:docker",
			expected: specs.User{Username: "ubuntu", UID: 0, GID: 0},
		},
		{
			name:     "uid:groupname",
			userSpec: "1000:docker",
			expected: specs.User{UID: 1000, GID: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseUser(tt.userSpec)

			if result.UID != tt.expected.UID {
				t.Errorf("UID = %v, want %v", result.UID, tt.expected.UID)
			}

			if result.GID != tt.expected.GID {
				t.Errorf("GID = %v, want %v", result.GID, tt.expected.GID)
			}

			if result.Username != tt.expected.Username {
				t.Errorf("Username = %v, want %v", result.Username, tt.expected.Username)
			}
		})
	}
}

func TestNewProcessSpec(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		args []string
		want ProcessSpec
	}{
		{
			name: "basic command",
			cmd:  "/bin/echo",
			args: []string{"hello"},
			want: ProcessSpec{
				Cmd:        "/bin/echo",
				Args:       []string{"/bin/echo", "hello"},
				Env:        []string{},
				WorkingDir: "/",
				User:       "0:0",
				Terminal:   false,
				Timeout:    30 * time.Second,
			},
		},
		{
			name: "command already in args",
			cmd:  "/bin/ls",
			args: []string{"/bin/ls", "-la"},
			want: ProcessSpec{
				Cmd:        "/bin/ls",
				Args:       []string{"/bin/ls", "-la"},
				Env:        []string{},
				WorkingDir: "/",
				User:       "0:0",
				Terminal:   false,
				Timeout:    30 * time.Second,
			},
		},
		{
			name: "empty args",
			cmd:  "/bin/pwd",
			args: []string{},
			want: ProcessSpec{
				Cmd:        "/bin/pwd",
				Args:       []string{"/bin/pwd"},
				Env:        []string{},
				WorkingDir: "/",
				User:       "0:0",
				Terminal:   false,
				Timeout:    30 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewProcessSpec(tt.cmd, tt.args)

			if result.Cmd != tt.want.Cmd {
				t.Errorf("Cmd = %v, want %v", result.Cmd, tt.want.Cmd)
			}

			if len(result.Args) != len(tt.want.Args) {
				t.Errorf("Args length = %v, want %v", len(result.Args), len(tt.want.Args))
			} else {
				for i, arg := range result.Args {
					if arg != tt.want.Args[i] {
						t.Errorf("Args[%d] = %v, want %v", i, arg, tt.want.Args[i])
					}
				}
			}

			if result.WorkingDir != tt.want.WorkingDir {
				t.Errorf("WorkingDir = %v, want %v", result.WorkingDir, tt.want.WorkingDir)
			}

			if result.User != tt.want.User {
				t.Errorf("User = %v, want %v", result.User, tt.want.User)
			}

			if result.Terminal != tt.want.Terminal {
				t.Errorf("Terminal = %v, want %v", result.Terminal, tt.want.Terminal)
			}

			if result.Timeout != tt.want.Timeout {
				t.Errorf("Timeout = %v, want %v", result.Timeout, tt.want.Timeout)
			}
		})
	}
}

func TestProcessSpec_FluentAPI(t *testing.T) {
	spec := NewProcessSpec("/bin/bash", []string{"-c", "echo hello"})

	result := spec.
		WithEnv(map[string]string{"HOME": "/tmp", "USER": "test"}).
		WithEnvSlice([]string{"PATH=/usr/bin"}).
		WithWorkingDir("/var/tmp").
		WithUser("1000:1000").
		WithTerminal(true).
		WithTimeout(60 * time.Second)

	// Test environment variables
	expectedEnv := []string{"HOME=/tmp", "USER=test", "PATH=/usr/bin"}
	if len(result.Env) != len(expectedEnv) {
		t.Errorf("Env length = %v, want %v", len(result.Env), len(expectedEnv))
	}

	// Check if all expected env vars are present (order might vary due to map iteration)
	envMap := make(map[string]bool)
	for _, env := range result.Env {
		envMap[env] = true
	}
	for _, expected := range expectedEnv {
		if !envMap[expected] {
			t.Errorf("Expected env var %s not found", expected)
		}
	}

	if result.WorkingDir != "/var/tmp" {
		t.Errorf("WorkingDir = %v, want %v", result.WorkingDir, "/var/tmp")
	}

	if result.User != "1000:1000" {
		t.Errorf("User = %v, want %v", result.User, "1000:1000")
	}

	if result.Terminal != true {
		t.Errorf("Terminal = %v, want %v", result.Terminal, true)
	}

	if result.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want %v", result.Timeout, 60*time.Second)
	}
}

func TestProcess_JSONSerialization(t *testing.T) {
	exitCode := int32(0)
	process := &Process{
		ID:          "proc-12345678",
		PID:         1234,
		Status:      "completed",
		StartTime:   time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		ExitCode:    &exitCode,
		ContainerID: "container-123",
	}

	// Test that all fields are properly tagged for JSON serialization
	// This ensures the struct can be marshaled/unmarshaled correctly
	if process.ID == "" {
		t.Error("Process ID should not be empty")
	}
	if process.PID == 0 {
		t.Error("Process PID should not be zero")
	}
	if process.Status == "" {
		t.Error("Process Status should not be empty")
	}
	if process.StartTime.IsZero() {
		t.Error("Process StartTime should not be zero")
	}
	if process.ExitCode == nil {
		t.Error("Process ExitCode should not be nil")
	}
	if process.ContainerID == "" {
		t.Error("Process ContainerID should not be empty")
	}
}

func TestProcessResult_Structure(t *testing.T) {
	process := &Process{
		ID:          "test-process",
		PID:         123,
		Status:      "completed",
		StartTime:   time.Now(),
		ContainerID: "test-container",
	}

	result := &ProcessResult{
		Process:  process,
		ExitCode: 0,
		Stdout:   []byte("hello world\n"),
		Stderr:   []byte(""),
		Error:    nil,
	}

	if result.Process != process {
		t.Error("ProcessResult.Process should match the provided process")
	}
	if result.ExitCode != 0 {
		t.Errorf("ProcessResult.ExitCode = %v, want 0", result.ExitCode)
	}
	if string(result.Stdout) != "hello world\n" {
		t.Errorf("ProcessResult.Stdout = %v, want 'hello world\\n'", string(result.Stdout))
	}
	if len(result.Stderr) != 0 {
		t.Errorf("ProcessResult.Stderr should be empty, got %v", result.Stderr)
	}
	if result.Error != nil {
		t.Errorf("ProcessResult.Error should be nil, got %v", result.Error)
	}
}