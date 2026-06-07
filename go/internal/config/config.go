// Package config defines the JSON contract between the Node.js wrapper and
// the Go sandbox engine. It represents the execution policy the JS layer
// resolves (hosts → IPs, paths, env) before handing off to the OS engine.
package config

// ExecConfig is the canonical JSON structure the Go binary reads from stdin.
// The Node.js wrapper populates this after DNS resolution and path expansion.
type ExecConfig struct {
	// Cmd is the command to execute (e.g., "npm", "pip", "java").
	Cmd string `json:"cmd"`

	// Args are the command-line arguments passed to Cmd.
	Args []string `json:"args"`

	// Env is a flat key→value map of environment variables to set inside
	// the sandbox. If empty, the full parent environment is inherited.
	Env map[string]string `json:"env"`

	// ReadPaths are filesystem paths the sandboxed process is allowed to
	// read from. On Linux these become read-only bind mounts; on macOS
	// they become (allow file-read*) rules.
	ReadPaths []string `json:"readPaths"`

	// WritePaths are filesystem paths the sandboxed process is allowed to
	// write to. On Linux these become read-write bind mounts; on macOS
	// they become (allow file-read* and allow file-write*) rules.
	WritePaths []string `json:"writePaths"`

	// AllowHosts are hostname strings to resolve before execution.
	// The Node.js layer resolves these to IPs and populates AllowIPs,
	// but this field is kept for debugging and macOS Seatbelt profiles
	// that support hostname matching.
	AllowHosts []string `json:"allowHosts"`

	// AllowIPs are resolved IP addresses the sandboxed process can reach.
	// On macOS these become (allow network-outbound) rules. On Linux
	// they're used when network filtering is enabled.
	AllowIPs []string `json:"allowIPs"`

	// AllowPorts are TCP ports the sandboxed process can connect to.
	// 0 means any port. Used by Landlock network rules on Linux and
	// Seatbelt rules on macOS. Default: [80, 443].
	AllowPorts []int `json:"allowPorts"`

	// DisableNetwork, when true, cuts all network access. On Linux this
	// adds CLONE_NEWNET; on macOS it adds (allow network-outbound) rules
	// only for resolved IPs.
	DisableNetwork bool `json:"disableNetwork"`

	// MaxMemoryMB caps the sandboxed process memory in megabytes.
	// 0 means no limit. Applied via cgroup v2 memory.max on Linux;
	// RLIMIT_AS on macOS.
	MaxMemoryMB int `json:"maxMemoryMB"`

	// MaxCPUCores limits CPU consumption as a fractional core count.
	// E.g. 0.5 = half a core, 2.0 = two full cores. 0 means no limit.
	// Applied via cgroup v2 cpu.max on Linux; RLIMIT_CPU on macOS.
	MaxCPUCores float64 `json:"maxCPUCores"`

	// MaxProcesses limits the number of child processes (anti-fork bomb).
	// 0 means no limit. Applied via cgroup v2 pids.max on Linux;
	// RLIMIT_NPROC on macOS.
	MaxProcesses int `json:"maxProcesses"`

	// TimeoutMs is a hard kill switch in milliseconds. The parent process
	// kills the sandboxed command and all descendants after this duration.
	// 0 means no timeout. Enforced by the JS wrapper layer; also applied
	// as RLIMIT_CPU on macOS and a cgroup-based deadline on Linux.
	TimeoutMs int `json:"timeoutMs"`

	// WorkingDir is the directory the sandboxed process runs in.
	// Defaults to the current working directory if empty.
	WorkingDir string `json:"workingDir"`

	// EnableAudit, when true, captures sandbox violations (file reads,
	// network connections, etc.) and returns them as auditLog entries.
	// On Linux this uses SECCOMP_RET_TRAP via SIGSYS; on macOS it uses
	// Seatbelt (trace ...) rules.
	EnableAudit bool `json:"enableAudit"`

	// EnableDiff, when true, tracks filesystem mutations during execution
	// and returns an fsDiff report (added, modified, deleted files).
	// On Linux this uses OverlayFS; on macOS/Windows it uses a shadow
	// directory snapshot-diff approach.
	EnableDiff bool `json:"enableDiff"`

	// EnableLearn, when true, runs the command in permissive mode and
	// records all filesystem and network accesses to generate a strict
	// policy file (Behavioral Bill of Materials).
	EnableLearn bool `json:"enableLearn"`

	// AllowExec lists executable names the sandboxed process is allowed
	// to exec. Empty means any executable. On macOS this becomes
	// (allow process-exec (file ...)) rules. On Linux this is enforced
	// via seccomp-bpf execve tracing.
	AllowExec []string `json:"allowExec"`

	// BlockExec lists executable names to prevent execution. Takes
	// precedence over AllowExec. On macOS this becomes (deny process-exec)
	// rules. On Linux this is enforced via seccomp-bpf.
	BlockExec []string `json:"blockExec"`

	// BlockFork, when true, prevents the sandboxed process from forking
	// new processes. On macOS this becomes (allow process-fork). On Linux
	// this blocks clone/fork/vfork syscalls via seccomp.
	BlockFork bool `json:"blockFork"`

	// TraceExec, when true, allows all exec/fork but logs every child
	// process spawned with the command line and parent PID. Works on
	// both macOS (Seatbelt trace) and Linux (seccomp SIGSYS trap).
	TraceExec bool `json:"traceExec"`

	// DumpProfile, when true, outputs the generated Seatbelt profile
	// to stdout as "PROFILE:<profile content>" and exits without
	// running the command. Used for testing profile generation.
	DumpProfile bool `json:"dumpProfile"`

	// Strict, when true, treats sandbox initialization warnings as errors
	// (e.g. cgroup, landlock, or seccomp errors) instead of bypassing them.
	Strict bool `json:"strict"`
}

// AuditEntry represents a single sandbox violation or event.
type AuditEntry struct {
	// Type is the event type: "file-read", "file-write", "network-connect",
	// "network-bind", "process-exec", "syscall".
	Type string `json:"type"`

	// Target is the resource that was accessed (file path, IP, port, syscall name).
	Target string `json:"target"`

	// Detail is an optional human-readable description.
	Detail string `json:"detail,omitempty"`
}

// AuditResult is written to stderr as JSON when EnableAudit is true.
// The JS runner parses these lines from stderr.
type AuditResult struct {
	AuditLog []AuditEntry `json:"auditLog"`
}

// FSDiffEntry describes a single filesystem mutation.
type FSDiffEntry struct {
	// Path is the absolute filesystem path.
	Path string `json:"path"`

	// Mode is the file permission bits (e.g., 0644).
	Mode uint32 `json:"mode,omitempty"`

	// Size is the file size in bytes (0 for directories).
	Size int64 `json:"size,omitempty"`

	// IsDir is true if the entry is a directory.
	IsDir bool `json:"isDir,omitempty"`
}

// FSDiff is the mutation report returned when EnableDiff is true.
// It contains lists of added, modified, and deleted files/directories.
type FSDiff struct {
	// Added lists files/dirs that did not exist before execution.
	Added []FSDiffEntry `json:"added,omitempty"`

	// Modified lists files/dirs that existed before but changed.
	Modified []FSDiffEntry `json:"modified,omitempty"`

	// Deleted lists files/dirs that existed before but are gone.
	Deleted []FSDiffEntry `json:"deleted,omitempty"`
}

// LearnedPolicy is the auto-generated policy from learning mode.
// It represents a strict, minimal policy based on observed behavior.
type LearnedPolicy struct {
	// ReadPaths are filesystem paths the process actually read.
	ReadPaths []string `json:"readPaths"`

	// WritePaths are filesystem paths the process actually wrote.
	WritePaths []string `json:"writePaths"`

	// AllowHosts are hostnames the process connected to.
	AllowHosts []string `json:"allowHosts"`

	// AllowIPs are IP addresses the process connected to.
	AllowIPs []string `json:"allowIPs"`

	// AllowPorts are TCP ports the process connected to.
	AllowPorts []int `json:"allowPorts"`

	// EnvVars are environment variables the process accessed.
	EnvVars []string `json:"envVars,omitempty"`

	// Cmd is the command that was learned.
	Cmd string `json:"cmd"`

	// Args are the arguments used during learning.
	Args []string `json:"args"`
}

// ExecResult is the output returned to the JS runner after execution.
// It contains stdout, stderr, exit code, and optional additional data.
type ExecResult struct {
	Stdout   string       `json:"stdout"`
	Stderr   string       `json:"stderr"`
	ExitCode int          `json:"exitCode"`
	AuditLog []AuditEntry `json:"auditLog,omitempty"`
	// TimedOut is true if the process was killed due to a timeout.
	TimedOut bool `json:"timedOut,omitempty"`
	// FSDiff is the filesystem mutation report (when EnableDiff is true).
	FSDiff *FSDiff `json:"fsDiff,omitempty"`
	// LearnedPolicy is the auto-generated policy (when EnableLearn is true).
	LearnedPolicy *LearnedPolicy `json:"learnedPolicy,omitempty"`
}
