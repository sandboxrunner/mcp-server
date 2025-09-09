package security

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// SeccompAction represents seccomp filter actions
type SeccompAction string

const (
	SeccompActionAllow    SeccompAction = "SCMP_ACT_ALLOW"
	SeccompActionErrno    SeccompAction = "SCMP_ACT_ERRNO"
	SeccompActionKill     SeccompAction = "SCMP_ACT_KILL"
	SeccompActionKillProcess SeccompAction = "SCMP_ACT_KILL_PROCESS"
	SeccompActionTrap     SeccompAction = "SCMP_ACT_TRAP"
	SeccompActionTrace    SeccompAction = "SCMP_ACT_TRACE"
	SeccompActionLog      SeccompAction = "SCMP_ACT_LOG"
	SeccompActionNotify   SeccompAction = "SCMP_ACT_NOTIFY"
)

// SeccompOperator represents comparison operators for seccomp args
type SeccompOperator string

const (
	SeccompOpNotEqual     SeccompOperator = "SCMP_CMP_NE"
	SeccompOpLess         SeccompOperator = "SCMP_CMP_LT"
	SeccompOpLessOrEqual  SeccompOperator = "SCMP_CMP_LE"
	SeccompOpEqual        SeccompOperator = "SCMP_CMP_EQ"
	SeccompOpGreaterEqual SeccompOperator = "SCMP_CMP_GE"
	SeccompOpGreater      SeccompOperator = "SCMP_CMP_GT"
	SeccompOpMaskedEqual  SeccompOperator = "SCMP_CMP_MASKED_EQ"
)

// SeccompArch represents supported architectures
type SeccompArch string

const (
	SeccompArchNative SeccompArch = "SCMP_ARCH_NATIVE"
	SeccompArchX86    SeccompArch = "SCMP_ARCH_X86"
	SeccompArchX86_64 SeccompArch = "SCMP_ARCH_X86_64"
	SeccompArchX32    SeccompArch = "SCMP_ARCH_X32"
	SeccompArchARM    SeccompArch = "SCMP_ARCH_ARM"
	SeccompArchAARCH64 SeccompArch = "SCMP_ARCH_AARCH64"
	SeccompArchMIPS   SeccompArch = "SCMP_ARCH_MIPS"
	SeccompArchMIPS64 SeccompArch = "SCMP_ARCH_MIPS64"
	SeccompArchPPC64  SeccompArch = "SCMP_ARCH_PPC64"
	SeccompArchPPC64LE SeccompArch = "SCMP_ARCH_PPC64LE"
	SeccompArchS390   SeccompArch = "SCMP_ARCH_S390"
	SeccompArchS390X  SeccompArch = "SCMP_ARCH_S390X"
)

// SeccompProfile represents a complete seccomp profile
type SeccompProfile struct {
	DefaultAction    SeccompAction   `json:"defaultAction" yaml:"defaultAction"`
	Architecture     []SeccompArch   `json:"architectures,omitempty" yaml:"architectures,omitempty"`
	Syscalls         []SeccompSyscall `json:"syscalls,omitempty" yaml:"syscalls,omitempty"`
	ListenerPath     string          `json:"listenerPath,omitempty" yaml:"listenerPath,omitempty"`
	ListenerMetadata string          `json:"listenerMetadata,omitempty" yaml:"listenerMetadata,omitempty"`
	Flags            []string        `json:"flags,omitempty" yaml:"flags,omitempty"`
}

// SeccompSyscall defines seccomp syscall rules
type SeccompSyscall struct {
	Names    []string      `json:"names" yaml:"names"`
	Action   SeccompAction `json:"action" yaml:"action"`
	Args     []SeccompArg  `json:"args,omitempty" yaml:"args,omitempty"`
	Comment  string        `json:"comment,omitempty" yaml:"comment,omitempty"`
	Includes *SeccompFilter `json:"includes,omitempty" yaml:"includes,omitempty"`
	Excludes *SeccompFilter `json:"excludes,omitempty" yaml:"excludes,omitempty"`
	ErrnoRet *uint         `json:"errnoRet,omitempty" yaml:"errnoRet,omitempty"`
}

// SeccompArg defines syscall argument restrictions
type SeccompArg struct {
	Index    uint            `json:"index" yaml:"index"`
	Value    uint64          `json:"value" yaml:"value"`
	ValueTwo uint64          `json:"valueTwo,omitempty" yaml:"valueTwo,omitempty"`
	Op       SeccompOperator `json:"op" yaml:"op"`
}

// SeccompFilter defines conditional filters
type SeccompFilter struct {
	MinKernel string   `json:"minKernel,omitempty" yaml:"minKernel,omitempty"`
	Arches    []string `json:"arches,omitempty" yaml:"arches,omitempty"`
	Caps      []string `json:"caps,omitempty" yaml:"caps,omitempty"`
}

// SeccompProfileType represents predefined profile types
type SeccompProfileType string

const (
	ProfileTypeDefault     SeccompProfileType = "default"
	ProfileTypeRestricted  SeccompProfileType = "restricted"
	ProfileTypeNetworking  SeccompProfileType = "networking"
	ProfileTypeFilesystem  SeccompProfileType = "filesystem"
	ProfileTypeCompute     SeccompProfileType = "compute"
	ProfileTypePrivileged  SeccompProfileType = "privileged"
	ProfileTypeCustom      SeccompProfileType = "custom"
)

// SeccompConfig defines seccomp filtering configuration
type SeccompConfig struct {
	// Profile configuration
	ProfileType      SeccompProfileType `json:"profileType" yaml:"profileType"`
	CustomProfile    *SeccompProfile    `json:"customProfile,omitempty" yaml:"customProfile,omitempty"`
	ProfilePath      string             `json:"profilePath,omitempty" yaml:"profilePath,omitempty"`
	
	// Runtime configuration
	NoNewPrivs       bool               `json:"noNewPrivs" yaml:"noNewPrivs"`
	DefaultAction    SeccompAction      `json:"defaultAction,omitempty" yaml:"defaultAction,omitempty"`
	
	// Audit and monitoring
	AuditConfig      *SeccompAuditConfig `json:"auditConfig,omitempty" yaml:"auditConfig,omitempty"`
	ViolationAction  SeccompAction      `json:"violationAction,omitempty" yaml:"violationAction,omitempty"`
	
	// Advanced options
	ListenerConfig   *SeccompListenerConfig `json:"listenerConfig,omitempty" yaml:"listenerConfig,omitempty"`
	TemplateVars     map[string]string  `json:"templateVars,omitempty" yaml:"templateVars,omitempty"`
}

// SeccompAuditConfig defines seccomp auditing configuration
type SeccompAuditConfig struct {
	Enabled          bool     `json:"enabled" yaml:"enabled"`
	LogViolations    bool     `json:"logViolations" yaml:"logViolations"`
	LogAllowed       bool     `json:"logAllowed" yaml:"logAllowed"`
	LogSyscalls      []string `json:"logSyscalls,omitempty" yaml:"logSyscalls,omitempty"`
	MaxLogEntries    int      `json:"maxLogEntries" yaml:"maxLogEntries"`
}

// SeccompListenerConfig defines seccomp listener configuration for SCMP_ACT_NOTIFY
type SeccompListenerConfig struct {
	Enabled          bool   `json:"enabled" yaml:"enabled"`
	SocketPath       string `json:"socketPath" yaml:"socketPath"`
	ProcessorType    string `json:"processorType" yaml:"processorType"` // "allow", "deny", "custom"
	CustomHandler    string `json:"customHandler,omitempty" yaml:"customHandler,omitempty"`
}

// SeccompManager manages seccomp filtering for containers
type SeccompManager struct {
	mu               sync.RWMutex
	containerConfigs map[string]*SeccompConfig
	containerProfiles map[string]*SeccompProfile
	activeFilters    map[string]string // containerID -> profile path
	
	// Profile templates
	profileTemplates map[SeccompProfileType]*SeccompProfile
	
	// System support
	systemSupport    bool
	supportedActions map[SeccompAction]bool
	
	// Audit and monitoring
	auditLog         []SeccompAuditEntry
	maxAuditEntries  int
	
	// Profile storage
	profilesPath     string
}

// SeccompAuditEntry represents a seccomp audit log entry
type SeccompAuditEntry struct {
	Timestamp    int64         `json:"timestamp"`
	ContainerID  string        `json:"containerId"`
	PID          int           `json:"pid"`
	Syscall      string        `json:"syscall"`
	Action       SeccompAction `json:"action"`
	Args         []uint64      `json:"args,omitempty"`
	Result       string        `json:"result"`
	ProcessInfo  string        `json:"processInfo,omitempty"`
}

// SeccompValidationResult holds seccomp validation results
type SeccompValidationResult struct {
	Valid        bool     `json:"valid"`
	Errors       []string `json:"errors,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
	ProfileStats *SeccompProfileStats `json:"profileStats,omitempty"`
}

// SeccompProfileStats provides statistics about a seccomp profile
type SeccompProfileStats struct {
	TotalSyscalls    int                        `json:"totalSyscalls"`
	AllowedSyscalls  int                        `json:"allowedSyscalls"`
	BlockedSyscalls  int                        `json:"blockedSyscalls"`
	ActionCounts     map[SeccompAction]int      `json:"actionCounts"`
	RiskAssessment   string                     `json:"riskAssessment"`
	Coverage         float64                    `json:"coverage"` // Percentage of common syscalls covered
}

// NewSeccompManager creates a new seccomp manager
func NewSeccompManager(profilesPath string) *SeccompManager {
	sm := &SeccompManager{
		containerConfigs:  make(map[string]*SeccompConfig),
		containerProfiles: make(map[string]*SeccompProfile),
		activeFilters:     make(map[string]string),
		profileTemplates:  make(map[SeccompProfileType]*SeccompProfile),
		supportedActions:  make(map[SeccompAction]bool),
		auditLog:          make([]SeccompAuditEntry, 0),
		maxAuditEntries:   10000,
		profilesPath:      profilesPath,
	}

	// Detect seccomp support
	sm.detectSeccompSupport()
	
	// Initialize profile templates
	sm.initializeProfileTemplates()
	
	// Ensure profiles directory exists
	if err := os.MkdirAll(profilesPath, 0755); err != nil {
		log.Warn().Err(err).Str("path", profilesPath).Msg("Failed to create profiles directory")
	}
	
	return sm
}

// SetupSeccompFilter configures seccomp filtering for a container
func (sm *SeccompManager) SetupSeccompFilter(containerID string, config *SeccompConfig) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()

	logger.Debug().Msg("Setting up seccomp filtering")

	if !sm.systemSupport {
		logger.Warn().Msg("Seccomp is not supported on this system")
		return nil
	}

	// Validate seccomp configuration
	if validation := sm.validateSeccompConfig(config); !validation.Valid {
		logger.Error().
			Strs("errors", validation.Errors).
			Msg("Seccomp configuration validation failed")
		return fmt.Errorf("seccomp validation failed: %s", strings.Join(validation.Errors, "; "))
	}

	// Generate or load seccomp profile
	profile, err := sm.generateSeccompProfile(containerID, config)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to generate seccomp profile")
		return fmt.Errorf("failed to generate seccomp profile: %w", err)
	}

	// Write profile to file
	profilePath, err := sm.writeSeccompProfile(containerID, profile)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to write seccomp profile")
		return fmt.Errorf("failed to write seccomp profile: %w", err)
	}

	// Setup seccomp listener if configured
	if config.ListenerConfig != nil && config.ListenerConfig.Enabled {
		if err := sm.setupSeccompListener(containerID, config.ListenerConfig); err != nil {
			logger.Error().Err(err).Msg("Failed to setup seccomp listener")
			return fmt.Errorf("failed to setup seccomp listener: %w", err)
		}
	}

	// Setup seccomp auditing if enabled
	if config.AuditConfig != nil && config.AuditConfig.Enabled {
		if err := sm.setupSeccompAuditing(containerID, config.AuditConfig); err != nil {
			logger.Warn().Err(err).Msg("Failed to setup seccomp auditing")
		}
	}

	// Store configuration and profile
	sm.mu.Lock()
	sm.containerConfigs[containerID] = config
	sm.containerProfiles[containerID] = profile
	sm.activeFilters[containerID] = profilePath
	sm.mu.Unlock()

	logger.Info().
		Str("profile_type", string(config.ProfileType)).
		Str("profile_path", profilePath).
		Str("default_action", string(profile.DefaultAction)).
		Int("syscall_rules", len(profile.Syscalls)).
		Msg("Seccomp filtering configured successfully")

	// Audit the setup
	sm.auditSeccompAction(containerID, 0, "setup", string(profile.DefaultAction), 
		fmt.Sprintf("Profile: %s, Rules: %d", config.ProfileType, len(profile.Syscalls)))

	return nil
}

// ValidateSeccompFilter validates seccomp configuration for a container
func (sm *SeccompManager) ValidateSeccompFilter(containerID string) (*SeccompValidationResult, error) {
	sm.mu.RLock()
	config, exists := sm.containerConfigs[containerID]
	profile, hasProfile := sm.containerProfiles[containerID]
	sm.mu.RUnlock()

	if !exists || !hasProfile {
		return &SeccompValidationResult{
			Valid: false,
			Errors: []string{fmt.Sprintf("no seccomp configuration found for container %s", containerID)},
		}, nil
	}

	result := sm.validateSeccompConfig(config)
	
	// Additional runtime validation
	if err := sm.validateSeccompProfile(profile); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("seccomp profile validation failed: %s", err))
		result.Valid = false
	}

	// Generate profile statistics
	if result.Valid {
		result.ProfileStats = sm.generateProfileStats(profile)
	}

	return result, nil
}

// GetSeccompProfile returns the seccomp profile for a container
func (sm *SeccompManager) GetSeccompProfile(containerID string) (*SeccompProfile, error) {
	sm.mu.RLock()
	profile, exists := sm.containerProfiles[containerID]
	sm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no seccomp profile found for container %s", containerID)
	}

	// Return a deep copy to prevent modification
	return sm.deepCopyProfile(profile), nil
}

// AuditSyscall audits syscall execution for seccomp filtering
func (sm *SeccompManager) AuditSyscall(containerID string, pid int, syscall string, action SeccompAction, args []uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	entry := SeccompAuditEntry{
		Timestamp:   0, // In real implementation, use time.Now().Unix()
		ContainerID: containerID,
		PID:         pid,
		Syscall:     syscall,
		Action:      action,
		Args:        args,
		Result:      string(action),
	}

	sm.auditLog = append(sm.auditLog, entry)

	// Trim audit log if it exceeds maximum entries
	if len(sm.auditLog) > sm.maxAuditEntries {
		sm.auditLog = sm.auditLog[len(sm.auditLog)-sm.maxAuditEntries:]
	}

	// Log violations and important actions
	if action == SeccompActionKill || action == SeccompActionKillProcess || action == SeccompActionErrno {
		log.Warn().
			Str("container_id", containerID).
			Int("pid", pid).
			Str("syscall", syscall).
			Str("action", string(action)).
			Msg("Seccomp violation detected")
	}
}

// GetAuditLog returns seccomp audit log entries
func (sm *SeccompManager) GetAuditLog(containerID string, limit int) []SeccompAuditEntry {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var entries []SeccompAuditEntry
	for i := len(sm.auditLog) - 1; i >= 0 && len(entries) < limit; i-- {
		entry := sm.auditLog[i]
		if containerID == "" || entry.ContainerID == containerID {
			entries = append(entries, entry)
		}
	}

	return entries
}

// CleanupSeccompFilter cleans up seccomp filtering for a container
func (sm *SeccompManager) CleanupSeccompFilter(containerID string) error {
	logger := log.With().
		Str("container_id", containerID).
		Logger()

	logger.Debug().Msg("Cleaning up seccomp filtering")

	sm.mu.Lock()
	profilePath, hasPath := sm.activeFilters[containerID]
	delete(sm.containerConfigs, containerID)
	delete(sm.containerProfiles, containerID)
	delete(sm.activeFilters, containerID)
	sm.mu.Unlock()

	// Clean up profile file
	if hasPath {
		if err := os.Remove(profilePath); err != nil && !os.IsNotExist(err) {
			logger.Warn().Err(err).Str("profile_path", profilePath).Msg("Failed to remove seccomp profile file")
		}
	}

	// Clean up listener if it exists
	sm.cleanupSeccompListener(containerID)

	// Audit the cleanup
	sm.auditSeccompAction(containerID, 0, "cleanup", "", "Seccomp filtering cleaned up")

	logger.Debug().Msg("Seccomp filtering cleanup completed")
	return nil
}

// Private helper methods

func (sm *SeccompManager) detectSeccompSupport() {
	// Check for seccomp support
	if _, err := os.Stat("/proc/sys/kernel/seccomp"); err == nil {
		sm.systemSupport = true
		log.Debug().Msg("Seccomp support detected")

		// Detect supported actions (simplified)
		sm.supportedActions = map[SeccompAction]bool{
			SeccompActionAllow:       true,
			SeccompActionErrno:       true,
			SeccompActionKill:        true,
			SeccompActionKillProcess: true,
			SeccompActionTrap:        true,
			SeccompActionLog:         true,
		}

		// Check for SCMP_ACT_NOTIFY support (kernel 5.0+)
		if sm.checkNotifySupport() {
			sm.supportedActions[SeccompActionNotify] = true
			log.Debug().Msg("Seccomp notify support detected")
		}
	} else {
		sm.systemSupport = false
		log.Warn().Msg("Seccomp is not supported on this system")
	}
}

func (sm *SeccompManager) checkNotifySupport() bool {
	// In a real implementation, this would check for SCMP_ACT_NOTIFY support
	// For now, return true as a placeholder
	return true
}

func (sm *SeccompManager) initializeProfileTemplates() {
	// Default profile - balanced security and functionality
	sm.profileTemplates[ProfileTypeDefault] = &SeccompProfile{
		DefaultAction: SeccompActionErrno,
		Architecture:  []SeccompArch{SeccompArchNative},
		Syscalls: []SeccompSyscall{
			{
				Names:   []string{"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64"},
				Action:  SeccompActionAllow,
				Comment: "Common syscalls required for most applications",
			},
			{
				Names:   []string{"ptrace", "process_vm_readv", "process_vm_writev", "perf_event_open"},
				Action:  SeccompActionKill,
				Comment: "Dangerous syscalls for debugging and profiling",
			},
		},
	}

	// Restricted profile - maximum security
	sm.profileTemplates[ProfileTypeRestricted] = &SeccompProfile{
		DefaultAction: SeccompActionKill,
		Architecture:  []SeccompArch{SeccompArchNative},
		Syscalls: []SeccompSyscall{
			{
				Names:   []string{"read", "write", "close", "stat", "fstat", "mmap", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "readv", "writev", "access", "pipe", "select", "sched_yield", "dup", "dup2", "nanosleep", "getpid", "exit", "uname", "fcntl", "getdents", "getcwd", "getuid", "getgid", "geteuid", "getegid", "getrlimit", "getrusage", "sysinfo", "times", "getgroups", "rt_sigpending", "sigaltstack", "statfs", "fstatfs", "getpriority", "sched_getscheduler", "prctl", "gettimeofday", "time", "futex", "set_thread_area", "get_thread_area", "set_tid_address", "restart_syscall", "exit_group", "clock_gettime", "clock_getres", "gettid"},
				Action:  SeccompActionAllow,
				Comment: "Minimal syscalls for basic operation",
			},
		},
	}

	// Networking profile - network-focused applications
	sm.profileTemplates[ProfileTypeNetworking] = &SeccompProfile{
		DefaultAction: SeccompActionErrno,
		Architecture:  []SeccompArch{SeccompArchNative},
		Syscalls: []SeccompSyscall{
			{
				Names:   []string{"socket", "bind", "listen", "accept", "accept4", "connect", "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "setsockopt", "getsockopt", "socketpair"},
				Action:  SeccompActionAllow,
				Comment: "Network operations",
			},
			{
				Names:   []string{"read", "write", "open", "close", "stat", "fstat", "mmap", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "readv", "writev", "access", "pipe", "select", "poll", "epoll_create", "epoll_ctl", "epoll_wait", "sched_yield", "dup", "dup2", "nanosleep", "getpid", "exit", "uname", "fcntl", "getdents", "getcwd", "getuid", "getgid", "geteuid", "getegid", "getrlimit", "getrusage", "sysinfo", "times", "getgroups", "rt_sigpending", "sigaltstack", "statfs", "fstatfs", "getpriority", "sched_getscheduler", "prctl", "gettimeofday", "time", "futex", "set_thread_area", "get_thread_area", "set_tid_address", "restart_syscall", "exit_group", "clock_gettime", "clock_getres", "gettid"},
				Action:  SeccompActionAllow,
				Comment: "Basic syscalls",
			},
		},
	}

	// Filesystem profile - filesystem-intensive applications
	sm.profileTemplates[ProfileTypeFilesystem] = &SeccompProfile{
		DefaultAction: SeccompActionErrno,
		Architecture:  []SeccompArch{SeccompArchNative},
		Syscalls: []SeccompSyscall{
			{
				Names:   []string{"open", "close", "read", "write", "stat", "fstat", "lstat", "access", "readlink", "getcwd", "chdir", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "rename", "chmod", "fchmod", "chown", "fchown", "lchown", "truncate", "ftruncate", "flock", "fsync", "fdatasync", "sync", "openat", "mkdirat", "unlinkat", "renameat", "fchownat", "fchmodat", "faccessat", "utimensat"},
				Action:  SeccompActionAllow,
				Comment: "Filesystem operations",
			},
			{
				Names:   []string{"mmap", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "readv", "writev", "pipe", "select", "sched_yield", "dup", "dup2", "nanosleep", "getpid", "exit", "uname", "fcntl", "getdents", "getuid", "getgid", "geteuid", "getegid", "getrlimit", "getrusage", "sysinfo", "times", "getgroups", "rt_sigpending", "sigaltstack", "statfs", "fstatfs", "getpriority", "sched_getscheduler", "prctl", "gettimeofday", "time", "futex", "set_thread_area", "get_thread_area", "set_tid_address", "restart_syscall", "exit_group", "clock_gettime", "clock_getres", "gettid"},
				Action:  SeccompActionAllow,
				Comment: "Basic syscalls",
			},
		},
	}

	// Compute profile - CPU-intensive applications
	sm.profileTemplates[ProfileTypeCompute] = &SeccompProfile{
		DefaultAction: SeccompActionErrno,
		Architecture:  []SeccompArch{SeccompArchNative},
		Syscalls: []SeccompSyscall{
			{
				Names:   []string{"sched_setaffinity", "sched_getaffinity", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_yield", "clone", "fork", "vfork", "execve", "wait4", "waitid"},
				Action:  SeccompActionAllow,
				Comment: "Process and scheduling operations",
			},
			{
				Names:   []string{"read", "write", "open", "close", "stat", "fstat", "mmap", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "readv", "writev", "access", "pipe", "select", "dup", "dup2", "nanosleep", "getpid", "exit", "uname", "fcntl", "getdents", "getcwd", "getuid", "getgid", "geteuid", "getegid", "getrlimit", "setrlimit", "getrusage", "sysinfo", "times", "getgroups", "rt_sigpending", "sigaltstack", "statfs", "fstatfs", "getpriority", "setpriority", "prctl", "gettimeofday", "time", "futex", "set_thread_area", "get_thread_area", "set_tid_address", "restart_syscall", "exit_group", "clock_gettime", "clock_getres", "gettid"},
				Action:  SeccompActionAllow,
				Comment: "Basic syscalls",
			},
		},
	}

	// Privileged profile - minimal restrictions
	sm.profileTemplates[ProfileTypePrivileged] = &SeccompProfile{
		DefaultAction: SeccompActionAllow,
		Architecture:  []SeccompArch{SeccompArchNative},
		Syscalls: []SeccompSyscall{
			{
				Names:   []string{"reboot", "swapon", "swapoff", "mount", "umount", "umount2", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module"},
				Action:  SeccompActionKill,
				Comment: "Extremely dangerous system calls",
			},
		},
	}

	log.Info().Int("profile_templates", len(sm.profileTemplates)).Msg("Seccomp profile templates initialized")
}

func (sm *SeccompManager) validateSeccompConfig(config *SeccompConfig) *SeccompValidationResult {
	result := &SeccompValidationResult{
		Valid: true,
	}

	// Validate profile type
	if config.ProfileType == "" {
		result.Errors = append(result.Errors, "profile type is required")
		result.Valid = false
		return result
	}

	// Validate profile type exists
	if config.ProfileType != ProfileTypeCustom {
		if _, exists := sm.profileTemplates[config.ProfileType]; !exists {
			result.Errors = append(result.Errors, fmt.Sprintf("unknown profile type: %s", config.ProfileType))
			result.Valid = false
		}
	}

	// Validate custom profile if specified
	if config.ProfileType == ProfileTypeCustom {
		if config.CustomProfile == nil && config.ProfilePath == "" {
			result.Errors = append(result.Errors, "custom profile or profile path is required for custom profile type")
			result.Valid = false
		}
		
		if config.CustomProfile != nil {
			if err := sm.validateSeccompProfile(config.CustomProfile); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("custom profile validation failed: %s", err))
				result.Valid = false
			}
		}
	}

	// Validate default action if specified
	if config.DefaultAction != "" {
		if !sm.supportedActions[config.DefaultAction] {
			result.Errors = append(result.Errors, fmt.Sprintf("unsupported default action: %s", config.DefaultAction))
			result.Valid = false
		}
	}

	// Validate violation action if specified
	if config.ViolationAction != "" {
		if !sm.supportedActions[config.ViolationAction] {
			result.Errors = append(result.Errors, fmt.Sprintf("unsupported violation action: %s", config.ViolationAction))
			result.Valid = false
		}
	}

	// Validate listener configuration
	if config.ListenerConfig != nil && config.ListenerConfig.Enabled {
		if !sm.supportedActions[SeccompActionNotify] {
			result.Warnings = append(result.Warnings, "seccomp notify action is not supported on this system")
		}
		
		if config.ListenerConfig.SocketPath == "" {
			result.Errors = append(result.Errors, "listener socket path is required when listener is enabled")
			result.Valid = false
		}
	}

	return result
}

func (sm *SeccompManager) validateSeccompProfile(profile *SeccompProfile) error {
	// Validate default action
	if !sm.supportedActions[profile.DefaultAction] {
		return fmt.Errorf("unsupported default action: %s", profile.DefaultAction)
	}

	// Validate syscall rules
	for i, syscall := range profile.Syscalls {
		if len(syscall.Names) == 0 {
			return fmt.Errorf("syscall rule %d has no syscall names", i)
		}
		
		if !sm.supportedActions[syscall.Action] {
			return fmt.Errorf("syscall rule %d has unsupported action: %s", i, syscall.Action)
		}

		// Validate syscall arguments
		for j, arg := range syscall.Args {
			if arg.Index > 5 { // Linux syscalls have max 6 arguments (0-5)
				return fmt.Errorf("syscall rule %d, arg %d has invalid index %d (max 5)", i, j, arg.Index)
			}
		}
	}

	return nil
}

func (sm *SeccompManager) generateSeccompProfile(containerID string, config *SeccompConfig) (*SeccompProfile, error) {
	var profile *SeccompProfile

	switch config.ProfileType {
	case ProfileTypeCustom:
		if config.CustomProfile != nil {
			profile = config.CustomProfile
		} else if config.ProfilePath != "" {
			// Load profile from file
			loadedProfile, err := sm.loadSeccompProfile(config.ProfilePath)
			if err != nil {
				return nil, fmt.Errorf("failed to load profile from %s: %w", config.ProfilePath, err)
			}
			profile = loadedProfile
		} else {
			return nil, fmt.Errorf("custom profile type requires either CustomProfile or ProfilePath")
		}
	default:
		template, exists := sm.profileTemplates[config.ProfileType]
		if !exists {
			return nil, fmt.Errorf("unknown profile type: %s", config.ProfileType)
		}
		profile = sm.deepCopyProfile(template)
	}

	// Apply template variables if any
	if len(config.TemplateVars) > 0 {
		profile = sm.applyTemplateVars(profile, config.TemplateVars)
	}

	// Override default action if specified
	if config.DefaultAction != "" {
		profile.DefaultAction = config.DefaultAction
	}

	return profile, nil
}

func (sm *SeccompManager) loadSeccompProfile(profilePath string) (*SeccompProfile, error) {
	file, err := os.Open(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open profile file: %w", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file: %w", err)
	}

	var profile SeccompProfile
	if err := json.Unmarshal(content, &profile); err != nil {
		return nil, fmt.Errorf("failed to parse profile JSON: %w", err)
	}

	return &profile, nil
}

func (sm *SeccompManager) writeSeccompProfile(containerID string, profile *SeccompProfile) (string, error) {
	profileData, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal profile: %w", err)
	}

	profilePath := filepath.Join(sm.profilesPath, fmt.Sprintf("seccomp-%s.json", containerID))
	
	if err := os.WriteFile(profilePath, profileData, 0644); err != nil {
		return "", fmt.Errorf("failed to write profile file: %w", err)
	}

	return profilePath, nil
}

func (sm *SeccompManager) setupSeccompListener(containerID string, config *SeccompListenerConfig) error {
	log.Debug().Str("container_id", containerID).Str("socket_path", config.SocketPath).Msg("Setting up seccomp listener")
	
	// In a real implementation, this would:
	// 1. Create Unix domain socket at SocketPath
	// 2. Set up listener for SCMP_ACT_NOTIFY events
	// 3. Configure custom handler or default processor
	
	return nil
}

func (sm *SeccompManager) setupSeccompAuditing(containerID string, config *SeccompAuditConfig) error {
	log.Debug().Str("container_id", containerID).Msg("Setting up seccomp auditing")
	
	// In a real implementation, this would:
	// 1. Configure audit rules for seccomp events
	// 2. Set up log rotation and limits
	// 3. Configure syscall-specific logging
	
	return nil
}

func (sm *SeccompManager) cleanupSeccompListener(containerID string) {
	// Clean up seccomp listener resources
	log.Debug().Str("container_id", containerID).Msg("Cleaning up seccomp listener")
}

func (sm *SeccompManager) auditSeccompAction(containerID string, pid int, action, result, details string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	entry := SeccompAuditEntry{
		Timestamp:   0, // In real implementation, use time.Now().Unix()
		ContainerID: containerID,
		PID:         pid,
		Syscall:     action,
		Action:      SeccompAction(result),
		Result:      result,
		ProcessInfo: details,
	}

	sm.auditLog = append(sm.auditLog, entry)

	if len(sm.auditLog) > sm.maxAuditEntries {
		sm.auditLog = sm.auditLog[len(sm.auditLog)-sm.maxAuditEntries:]
	}
}

func (sm *SeccompManager) generateProfileStats(profile *SeccompProfile) *SeccompProfileStats {
	stats := &SeccompProfileStats{
		ActionCounts: make(map[SeccompAction]int),
	}

	// Count syscalls and actions
	for _, syscall := range profile.Syscalls {
		stats.TotalSyscalls += len(syscall.Names)
		stats.ActionCounts[syscall.Action] += len(syscall.Names)
		
		if syscall.Action == SeccompActionAllow {
			stats.AllowedSyscalls += len(syscall.Names)
		} else {
			stats.BlockedSyscalls += len(syscall.Names)
		}
	}

	// Assess risk based on default action and allowed syscalls
	switch profile.DefaultAction {
	case SeccompActionAllow:
		stats.RiskAssessment = "high"
	case SeccompActionKill, SeccompActionKillProcess:
		stats.RiskAssessment = "low"
	default:
		stats.RiskAssessment = "medium"
	}

	// Calculate coverage (simplified)
	commonSyscalls := 200 // Approximate number of commonly used syscalls
	if stats.AllowedSyscalls > 0 {
		stats.Coverage = float64(min(stats.AllowedSyscalls, commonSyscalls)) / float64(commonSyscalls) * 100
	}

	return stats
}

func (sm *SeccompManager) deepCopyProfile(profile *SeccompProfile) *SeccompProfile {
	copy := &SeccompProfile{
		DefaultAction:    profile.DefaultAction,
		Architecture:     append([]SeccompArch{}, profile.Architecture...),
		ListenerPath:     profile.ListenerPath,
		ListenerMetadata: profile.ListenerMetadata,
		Flags:            append([]string{}, profile.Flags...),
	}

	for _, syscall := range profile.Syscalls {
		syscallCopy := SeccompSyscall{
			Names:    append([]string{}, syscall.Names...),
			Action:   syscall.Action,
			Comment:  syscall.Comment,
			ErrnoRet: syscall.ErrnoRet,
		}
		
		for _, arg := range syscall.Args {
			syscallCopy.Args = append(syscallCopy.Args, arg)
		}
		
		copy.Syscalls = append(copy.Syscalls, syscallCopy)
	}

	return copy
}

func (sm *SeccompManager) applyTemplateVars(profile *SeccompProfile, vars map[string]string) *SeccompProfile {
	// Apply template variable substitution
	// This is a simplified implementation - in practice, you'd use a template engine
	
	profileData, err := json.Marshal(profile)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to marshal profile for template substitution")
		return profile
	}

	profileStr := string(profileData)
	for key, value := range vars {
		// Support both {{key}} and {{.key}} formats
		placeholder1 := fmt.Sprintf("{{%s}}", key)
		placeholder2 := fmt.Sprintf("{{.%s}}", key)
		profileStr = strings.ReplaceAll(profileStr, placeholder1, value)
		profileStr = strings.ReplaceAll(profileStr, placeholder2, value)
	}

	var newProfile SeccompProfile
	if err := json.Unmarshal([]byte(profileStr), &newProfile); err != nil {
		log.Warn().Err(err).Msg("Failed to unmarshal profile after template substitution")
		return profile
	}

	return &newProfile
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}