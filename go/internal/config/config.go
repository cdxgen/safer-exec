// Package config defines the JSON contract between the Node.js wrapper and
// the Go sandbox engine. It represents the execution policy the JS layer
// resolves (hosts → IPs, paths, env) before handing off to the OS engine.
package config

// AllowURLRule specifies a fine-grained URL access rule for outbound HTTP/HTTPS
// requests observed via eBPF TLS uprobes (TraceHTTPURLs). Rules are matched
// against captured HTTP requests in real-time and violations are emitted as
// "url-violation" audit entries.
//
// This feature is Linux-only and requires TraceHTTPURLs to be enabled.
//
// Host matching supports three formats:
//
//	"registry.npmjs.org"     — exact hostname match
//	"*.npmjs.org"            — wildcard: matches any single subdomain label
//	"~^registry\.npmjs\.org" — Go regexp (prefix "~"): full-featured regex
//
// PathPrefix matching:
//
//	"/npm/v1/"   — plain string prefix match
//	"~^/npm/v[0-9]/" — regexp (prefix "~")
//
// An empty string for any field means "match anything" for that dimension.
type AllowURLRule struct {
	// Protocol is the URL scheme to match: "http", "https", or "" (any).
	Protocol string `json:"protocol,omitempty"`

	// Host is the hostname or pattern to match (see package doc for syntax).
	// Required — an empty host matches every host.
	Host string `json:"host"`

	// Port is the TCP port to match. 0 matches any port.
	Port int `json:"port,omitempty"`

	// PathPrefix is the URL path prefix or pattern to match.
	// "" or "/" matches all paths.
	PathPrefix string `json:"pathPrefix,omitempty"`

	// Methods lists the allowed HTTP verbs (e.g. ["GET","POST"]).
	// An empty or nil slice allows any method.
	Methods []string `json:"methods,omitempty"`
}

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

	// AllowURLRules are fine-grained URL access rules matched against HTTP
	// requests captured by the eBPF TLS uprobe (TraceHTTPURLs).
	// Linux-only. Each rule can restrict by protocol, host (wildcard/regex),
	// port, path prefix (wildcard/regex), and HTTP method.
	// Violations are emitted as "url-violation" audit entries.
	AllowURLRules []AllowURLRule `json:"allowURLRules,omitempty"`

	// DisableNetwork, when true, cuts all network access. On Linux this
	// adds CLONE_NEWNET; on macOS it adds (allow network-outbound) rules
	// only for resolved IPs.
	DisableNetwork bool `json:"disableNetwork"`

	// AllowLoopback, when true, permits localhost/loopback connections.
	AllowLoopback bool `json:"allowLoopback"`

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

	// PolicyFilePath is the path to a policy file on disk. When both
	// EnableLearn and PolicyFilePath are set, the learner merges newly
	// observed behavior into the existing file and writes it back atomically.
	PolicyFilePath string `json:"policyFilePath,omitempty"`

	// AllowCrypto, when true, allows system cryptographic library and device access.
	// Defaults to true (unrestricted). If false, access to common cryptographic paths
	// (OpenSSL, TLS certs, entropy devices) is restricted.
	AllowCrypto bool `json:"allowCrypto"`

	// BlockCrypto, when true, explicitly prevents loading system cryptographic libraries.
	BlockCrypto bool `json:"blockCrypto"`

	// BlockCryptoEntropy, when true, blocks access to entropy/random devices (/dev/random, /dev/urandom).
	BlockCryptoEntropy bool `json:"blockCryptoEntropy"`

	// DetectFIPS, when true, watches for FIPS-compliant operational lookups (checking fips_enabled or loading fips provider modules).
	DetectFIPS bool `json:"detectFIPS"`

	// StrictFIPS, when true, requires FIPS compliance. If the runtime fails to utilize FIPS mode or fails validation, a sandbox error is triggered.
	StrictFIPS bool `json:"strictFIPS"`

	// AllowGPU, when true, permits processes to utilize host GPU nodes (/dev/nvidia*, /dev/dri/*). Defaults to true.
	AllowGPU bool `json:"allowGPU"`

	// BlockTPM, when true, restricts hardware access to the Trusted Platform Module (/dev/tpm0, /dev/tpmrm0).
	BlockTPM bool `json:"blockTPM"`

	// SpoofAntiVM, when true, intercepts virtualization and debugger detection paths (/sys/class/dmi/id/product_name, TracerPid in /proc) to conceal sandboxing.
	SpoofAntiVM bool `json:"spoofAntiVM"`

	// TraceLibraries, when true, tracks dynamic library loading using LD_AUDIT (Linux) / DYLD_INSERT_LIBRARIES (macOS).
	TraceLibraries bool `json:"traceLibraries"`

	// TraceTempDir, when non-empty, specifies the directory where the dynamic library tracker (LD_AUDIT helper) is extracted.
	TraceTempDir string `json:"traceTempDir,omitempty"`

	// TraceHTTPURLs, when true, attaches eBPF uprobes to TLS write functions
	// (SSL_write, gnutls_record_send, Go crypto/tls.(*Conn).Write) to capture
	// plaintext HTTP/1.x and HTTP/2 requests before encryption. HTTP/2 HEADERS
	// frames are decoded via per-connection HPACK decoders; the dynamic
	// compression table is maintained across successive TLS writes on the same
	// connection. Requires Linux kernel >= 5.8 and CAP_BPF + CAP_PERFMON in the
	// init user namespace.
	// Captured requests are emitted as "http-request" audit entries when
	// EnableAudit is true, and as httpAccess entries in --learn mode output.
	TraceHTTPURLs bool `json:"traceHTTPURLs"`

	// StructuredOutputPath, when non-empty, redirects all structured output
	// (FSDIFF, LEARNED, PROFILE markers) to the specified file path instead
	// of writing them to stdout. The file is written as newline-delimited
	// JSON lines, one marker per line. When this field is set, the binary's
	// stdout carries only the raw command output with no marker pollution.
	StructuredOutputPath string `json:"structuredOutputPath,omitempty"`
}

// HTTPAccessEntry records a single HTTP request observed during eBPF tracing.
// It is emitted in audit logs as type "http-request" and stored in PolicyFile.HTTPAccess
// when --learn mode is active with --trace-http-urls.
type HTTPAccessEntry struct {
	// Method is the HTTP verb (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS).
	Method string `json:"method"`
	// Host is the value of the HTTP Host header (e.g. "registry.npmjs.org").
	Host string `json:"host"`
	// Path is the request path (e.g. "/-/npm/v1/security/advisories/bulk").
	Path string `json:"path,omitempty"`
	// Protocol is the protocol used ("http" or "https").
	Protocol string `json:"protocol"`
	// Port is the TCP port of the request (e.g. 443).
	Port int `json:"port"`
	// Blocked is true when AllowURLRules are set and this request matched no rule.
	Blocked bool `json:"blocked,omitempty"`
	// Query is the request query parameters.
	Query string `json:"query,omitempty"`
	// Body is the request body payload.
	Body string `json:"body,omitempty"`
	// Source identifies the TLS library that was intercepted.
	// One of: "ssl_write_uprobe", "go_tls_uprobe", "gnutls_uprobe".
	Source string `json:"source"`
	// PID is the host PID of the process that made the request.
	PID uint32 `json:"pid,omitempty"`
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

// PolicyFile is the portable, round-trippable sandbox policy format.
// It is both the output of --learn (written to --learn-output) and
// the input to --policy-file. All fields are optional; zero values mean
// "no restriction" or "inherit from other config".
//
// Schema version "1" is the current format. Future breaking changes
// increment the version string.
type PolicyFile struct {
	// Metadata (informational only, preserved during merges)
	Name        string `json:"name,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`

	// Filesystem
	ReadPaths  []string `json:"readPaths,omitempty"`
	WritePaths []string `json:"writePaths,omitempty"`

	// Network
	DisableNetwork bool     `json:"disableNetwork,omitempty"`
	AllowLoopback  bool     `json:"allowLoopback,omitempty"`
	AllowHosts     []string `json:"allowHosts,omitempty"`
	AllowIPs       []string `json:"allowIPs,omitempty"`
	AllowPorts     []int    `json:"allowPorts,omitempty"`

	// Environment — prefer Env map; EnvVars is legacy (list of names only)
	Env     map[string]string `json:"env,omitempty"`
	EnvVars []string          `json:"envVars,omitempty"`

	// Exec / fork controls
	AllowExec []string `json:"allowExec,omitempty"`
	BlockExec []string `json:"blockExec,omitempty"`
	BlockFork bool     `json:"blockFork,omitempty"`

	// Resource limits (0 = no limit)
	MaxMemoryMB  int     `json:"maxMemoryMB,omitempty"`
	MaxCPUCores  float64 `json:"maxCPUCores,omitempty"`
	MaxProcesses int     `json:"maxProcesses,omitempty"`
	TimeoutMs    int     `json:"timeoutMs,omitempty"`

	// Observability
	TraceExec   bool `json:"traceExec,omitempty"`
	EnableAudit bool `json:"enableAudit,omitempty"`

	// Cryptographic Controls
	AllowCrypto        bool `json:"allowCrypto,omitempty"`
	BlockCrypto        bool `json:"blockCrypto,omitempty"`
	BlockCryptoEntropy bool `json:"blockCryptoEntropy,omitempty"`
	DetectFIPS         bool `json:"detectFIPS,omitempty"`
	StrictFIPS         bool `json:"strictFIPS,omitempty"`
	FIPSDetected       bool `json:"fipsDetected,omitempty"`

	// Advanced Controls
	AllowGPU       bool `json:"allowGPU,omitempty"`
	BlockTPM       bool `json:"blockTPM,omitempty"`
	SpoofAntiVM    bool `json:"spoofAntiVM,omitempty"`
	TraceLibraries bool `json:"traceLibraries,omitempty"`
	GPUUsed        bool `json:"gpuUsed,omitempty"`
	TPMUsed        bool `json:"tpmUsed,omitempty"`
	AntiVMActive   bool `json:"antiVMActive,omitempty"`

	// HTTP access log — populated when --trace-http-urls is used with --learn
	// or --audit. Records observed HTTP requests with method, host, and path.
	HTTPAccess []HTTPAccessEntry `json:"httpAccess,omitempty"`

	// AllowURLRules are fine-grained URL access rules for HTTP requests.
	// Linux-only. Populated by learn mode from HTTPAccess observations,
	// and applied during enforcement when TraceHTTPURLs is active.
	AllowURLRules []AllowURLRule `json:"allowURLRules,omitempty"`

	// Informational — set by learner, ignored when loading as policy-file
	Cmd  string   `json:"cmd,omitempty"`
	Args []string `json:"args,omitempty"`
}

// LearnedPolicy is a type alias for backward compatibility.
// New code should use PolicyFile directly.
// Deprecated: use PolicyFile instead.
type LearnedPolicy = PolicyFile

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
