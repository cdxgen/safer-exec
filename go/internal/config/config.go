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

// BindFdSpec describes a file descriptor to bind-mount into the sandbox.
// The FD must be opened by the parent process before sandbox entry.
// This enables privilege-separated FD handoff from a privileged parent to
// the sandbox for pre-opened sockets, device nodes, and special files.
// Linux-only.
type BindFdSpec struct {
	Fd       int    `json:"fd"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly,omitempty"`
}

// LockFileSpec describes a file lock to acquire before sandbox entry.
// Path is the file path, Exclusive controls whether to use LOCK_EX (exclusive)
// or LOCK_SH (shared, default).
type LockFileSpec struct {
	Path      string `json:"path"`
	Exclusive bool   `json:"exclusive,omitempty"`
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

	// MaxReadIOPS limits read IO operations per second. 0 means no limit.
	// Applied via cgroup v2 io.max on Linux. Not enforced on macOS.
	MaxReadIOPS int `json:"maxReadIOPS"`

	// MaxWriteIOPS limits write IO operations per second. 0 means no limit.
	// Applied via cgroup v2 io.max on Linux. Not enforced on macOS.
	MaxWriteIOPS int `json:"maxWriteIOPS"`

	// MaxReadBps limits read bandwidth in bytes per second. 0 means no limit.
	// Applied via cgroup v2 io.max on Linux. Not enforced on macOS.
	MaxReadBps int64 `json:"maxReadBps"`

	// MaxWriteBps limits write bandwidth in bytes per second. 0 means no limit.
	// Applied via cgroup v2 io.max on Linux. Not enforced on macOS.
	MaxWriteBps int64 `json:"maxWriteBps"`

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

	// EnableDryRun, when true, runs the command with all operations denied
	// and returns a complete audit of everything the command attempted.
	// No filesystem or network side effects occur. The exit code is
	// overridden to 0. When set, EnableAudit is implicitly enabled.
	EnableDryRun bool `json:"enableDryRun"`

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

	// ValidateProfile, when true, uses sandbox-exec -n to syntax-check the
	// generated Seatbelt profile without executing the command. On macOS,
	// this validates the profile is well-formed before attempting to run.
	// Returns any syntax errors in stderr and exits with a non-zero code on failure.
	ValidateProfile bool `json:"validateProfile"`

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

	// TraceCrypto, when true, attaches eBPF uprobes to TLS cipher negotiation
	// functions (SSL_get_current_cipher, SSL_CIPHER_get_name for OpenSSL/BoringSSL;
	// gnutls_cipher_suite_get_name for GnuTLS) and crypto operation functions
	// (EVP_DigestInit, EVP_EncryptInit_ex, EVP_PKEY_sign for OpenSSL) to capture
	// the negotiated TLS cipher suite per connection and crypto algorithm usage.
	// Requires Linux kernel >= 5.8, CAP_BPF + CAP_PERFMON. Automatically enables
	// TraceHTTPURLs if not already set.
	// Captured cipher info is included in HTTPAccess entries, audit logs, and
	// the learned policy.
	TraceCrypto bool `json:"traceCrypto,omitempty"`

	// AllowCiphers lists the allowed TLS cipher suite names (e.g. ["ECDHE-RSA-AES256-GCM-SHA384", "TLS_AES_256_GCM_SHA384"]).
	// If TraceCrypto is active, any observed TLS negotiation using a cipher suite not in this list
	// will trigger a cipher-violation audit entry. Empty or nil allows any cipher.
	AllowCiphers []string `json:"allowCiphers,omitempty"`

	// CBOMOutputPath, when set, writes a CycloneDX CBOM (Cryptography Bill of Materials)
	// document to the specified file path. The document includes cryptographic-asset
	// components for detected TLS ciphers, libraries, and crypto operations.
	CBOMOutputPath string `json:"cbomOutputPath,omitempty"`

	// CryptoProbeMode controls the depth of crypto tracing.
	// "tls-only" (default) — capture only TLS cipher suites
	// "operations" — also capture digest, encrypt, sign operations (higher overhead)
	CryptoProbeMode string `json:"cryptoProbeMode,omitempty"`

	// StructuredOutputPath, when non-empty, redirects all structured output
	// (FSDIFF, LEARNED, PROFILE markers) to the specified file path instead
	// of writing them to stdout. The file is written as newline-delimited
	// JSON lines, one marker per line. When this field is set, the binary's
	// stdout carries only the raw command output with no marker pollution.
	StructuredOutputPath string `json:"structuredOutputPath,omitempty"`

	// ConfigFilePath, when set, tells the --init process to read config
	// from this file instead of the SAFER_EXEC_CONFIG environment variable.
	// The file is created with 0600 permissions and deleted after reading.
	ConfigFilePath string `json:"configFilePath,omitempty"`

	// AllowEnvs is a list of environment variables allowed to pass through.
	// This is the single opt-in for both credential-bearing variables and
	// loader-control variables (DYLD_*, LD_*, NODE_OPTIONS, DEVELOPER_DIR,
	// ...); the latter are stripped unless their exact name is listed here.
	AllowEnvs []string `json:"allowEnvs"`

	// BlockInterpreters, when true, denies execution of preinstalled
	// Apple-signed scripting engines and sampling tools that carry
	// unsigned-executable-memory, library-validation, or task-port
	// exemptions (tclsh, wish, perl, system python, ruby, expect, and the
	// com.apple.SamplingTools binaries) and starves them of the FFI
	// frameworks (Tcl/Tk/Ffidl) used to load in-memory shellcode. macOS-only;
	// ignored on other platforms. The command itself is never blocked.
	BlockInterpreters bool `json:"blockInterpreters,omitempty"`

	// DenyPersistenceWrites, when true, denies writes to well-known
	// auto-execution and persistence locations (LaunchAgents/LaunchDaemons,
	// plugin loader directories, preference stores, /usr/local/bin) that a
	// build or package install never legitimately needs to write to. A path
	// explicitly named in WritePaths is exempt. Enforced via Seatbelt on
	// macOS, where these trees are otherwise reachable through the broad
	// default read/write allows. On Linux the namespace + Landlock model is
	// already deny-by-default for any path not granted via WritePaths, so the
	// flag is informational there.
	DenyPersistenceWrites bool `json:"denyPersistenceWrites,omitempty"`

	// AllowWritableDylibLoad, when true, disables the (otherwise default
	// under BlockInterpreters) deny on reading .dylib files from writable or
	// temporary directories. Enable it for native-addon builds that compile
	// and immediately dlopen a dynamic library from the build tree. macOS-only.
	AllowWritableDylibLoad bool `json:"allowWritableDylibLoad,omitempty"`

	// BlockJIT, when true, blocks the syscalls that turn writable memory into
	// executable memory or execute anonymous files: mprotect/pkey_mprotect
	// with PROT_EXEC on a writable mapping, mmap with PROT_WRITE|PROT_EXEC or
	// MAP_JIT, and memfd_create. This stops in-memory shellcode loaders at the
	// syscall level. It breaks legitimate JITs (V8/node, the JVM, LuaJIT) and
	// is therefore opt-in. Enforced via seccomp on Linux; on macOS, where
	// Seatbelt cannot filter syscalls, it strengthens the interpreter denies
	// and emits a warning that in-process JIT cannot be prevented.
	BlockJIT bool `json:"blockJIT,omitempty"`

	// AllowHidden, when true, permits read/write to hidden files and directories
	AllowHidden bool `json:"allowHidden"`

	// AllowListen is a list of IP addresses or ip:port strings allowed to bind/listen to.
	AllowListen []string `json:"allowListen"`

	// SetUpDev, when true (default for full isolation), creates a minimal /dev
	// inside the sandbox with essential device nodes (null, zero, full, random,
	// urandom, tty), /dev/pts, /dev/shm, and stdio symlinks. When false, the
	// sandbox inherits whatever /dev exists in the mount namespace.
	// Linux-only. Defaults to true when using full isolation.
	SetUpDev bool `json:"setUpDev,omitempty"`

	// UseReaper, when true, enables the PID 1 reaper process for correct
	// zombie reaping and exit code propagation within PID namespaces.
	// When false (default), the target command runs as PID 1 directly.
	// The reaper is incompatible with blockFork — when blockFork is
	// active, seccomp kills the reaper's own fork syscall. Enable this
	// only when you need correct zombie handling and are not using
	// blockFork.
	UseReaper bool `json:"useReaper,omitempty"`

	// ProcHardening, when true, covers dangerous /proc entries (sys,
	// sysrq-trigger, irq, bus) with read-only bind mounts after the
	// fresh proc mount. Linux-only.
	ProcHardening bool `json:"procHardening,omitempty"`

	// SubmountEnforce, when true, parses /proc/self/mountinfo after all
	// bind mounts to individually remount submounts as read-only. Closes
	// the MS_REC loophole. Linux-only.
	SubmountEnforce bool `json:"submountEnforce,omitempty"`

	// DieWithParent, when true, ensures the sandboxed process receives SIGKILL
	// when its parent process dies (PR_SET_PDEATHSIG). Prevents orphaned sandbox
	// processes in CI/CD environments. Linux-only.
	DieWithParent bool `json:"dieWithParent,omitempty"`

	// NewSession, when true, calls setsid() to disconnect the sandboxed process
	// from the controlling terminal. Prevents terminal-based signal injection
	// (SIGHUP, SIGINT) and TTY-based attacks. Linux-only.
	NewSession bool `json:"newSession,omitempty"`

	// TmpOverlayPaths lists directories that should appear writable inside the
	// sandbox but whose writes are ephemeral. Each path gets an overlay mount
	// with a tmpfs upper layer that is discarded when the sandbox exits.
	// Useful for cache directories (e.g., ~/.npm/_cacache) or scratch dirs.
	// Linux-only. Requires kernel overlay + userxattr support.
	TmpOverlayPaths []string `json:"tmpOverlayPaths,omitempty"`

	// LockFiles lists file lock specifications to acquire before sandbox entry.
	// Each entry specifies a file path and whether the lock should be exclusive
	// (LOCK_EX) or shared (LOCK_SH, default). These locks are held for the
	// duration of the sandbox, enabling concurrent sandbox coordination.
	// Linux+macOS.
	LockFiles []LockFileSpec `json:"lockFiles,omitempty"`

	// JsonStatusFd is a writable file descriptor number for lifecycle
	// notifications. The engine writes JSON-lines on sandbox start
	// ({"child-pid":N,"type":"sandbox-start"}) and exit
	// ({"exit-code":N,"type":"sandbox-exit"}). Set by the Node.js runner.
	// 0 means disabled. Linux-only in the reaper process.
	JsonStatusFd int `json:"jsonStatusFd,omitempty"`

	// BindUseFd, when true (default), uses fd-based bind mounting to protect
	// against TOCTTOU races between path resolution and the mount call.
	// The source is opened first, mounted via /proc/self/fd/N, and then
	// stat(fd) is compared against lstat(target) to detect swaps.
	// Linux-only. Disable if /proc/self/fd is not available.
	BindUseFd bool `json:"bindUseFd,omitempty"`

	// SeccompFilters lists additional seccomp-bpf programs to stack after
	// the base filter. Each entry specifies either a base64-encoded BPF
	// program or a path to a pre-compiled BPF file. Filters are loaded
	// in LIFO order (last in list = evaluated first by kernel).
	// This enables policy composition across organizational boundaries.
	// Linux-only.
	SeccompFilters []SeccompFilterSpec `json:"seccompFilters,omitempty"`

	// ProtectSystem controls automatic read-only protection of system
	// directories. "strict" makes /usr, /boot, /etc, /lib, /lib64 read-only.
	// "full" is the same as "strict" but also includes /. "off" (default)
	// preserves the current behavior. Linux-only.
	ProtectSystem string `json:"protectSystem,omitempty"`

	// ProtectHome controls $HOME directory isolation inside the sandbox.
	// "read-only" makes the home directory read-only. "tmpfs" replaces the
	// home directory with a fresh tmpfs mount (ephemeral). "off" (default)
	// preserves the current behavior. Linux-only.
	ProtectHome string `json:"protectHome,omitempty"`

	// PrivateTmp, when true, mounts a fresh tmpfs on /tmp and /var/tmp
	// inside the sandbox so temporary files are not shared with the host
	// or other sandbox instances. Linux-only.
	PrivateTmp bool `json:"privateTmp,omitempty"`

	// BindFds lists file descriptors to bind-mount into the sandbox from
	// the parent process. Each entry specifies a source FD (opened by the
	// parent) and a target mount path inside the sandbox. This enables
	// privilege-separated FD handoff for pre-opened sockets, device nodes,
	// and special files. Linux-only.
	BindFds []BindFdSpec `json:"bindFds,omitempty"`

	// MapToTargetUid, when true, maps UID 0 inside the user namespace to
	// the caller's real UID so the sandboxed process runs with the caller's
	// identity rather than appearing as root. Linux-only.
	MapToTargetUid bool `json:"mapToTargetUid,omitempty"`

	// AllowUserns, when true, permits the sandboxed process to create nested
	// user and mount namespaces via clone()/clone3() (CLONE_NEWUSER/CLONE_NEWNS).
	// Defaults to false: nested namespaces are blocked by seccomp because they
	// are the entry point for many unprivileged-userns kernel privilege-escalation
	// bugs and are not needed by normal package/build tooling. Set to true only
	// for workloads that legitimately sandbox themselves. Linux-only.
	AllowUserns bool `json:"allowUserns,omitempty"`

	// AllowChrootFallback, when true, permits the engine to fall back to chroot()
	// when pivot_root() fails. Defaults to false: a chroot-based root is escapable
	// (e.g. via an fd to a directory outside the new root, or fchdir/.. when
	// combined with namespace tricks), so silently degrading to it would weaken
	// filesystem isolation. With the default, a pivot_root failure is fatal even
	// outside --strict. Linux-only.
	AllowChrootFallback bool `json:"allowChrootFallback,omitempty"`
}

// SeccompFilterSpec describes an additional seccomp-bpf filter to stack.
type SeccompFilterSpec struct {
	// Program is a base64-encoded BPF program (SockFilter array).
	// Mutually exclusive with Path and Policy.
	Program string `json:"program,omitempty"`

	// Path is a filesystem path to a file containing raw BPF bytecode
	// (struct sock_filter array). Mutually exclusive with Program and Policy.
	Path string `json:"path,omitempty"`

	// Policy is a Kafel-style policy string (e.g. "ALLOW openat, read; DEFAULT KILL").
	// Compiles to BPF at runtime. Mutually exclusive with Program and Path.
	Policy string `json:"policy,omitempty"`
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
	// Cipher is the negotiated TLS cipher suite name (e.g. "ECDHE-RSA-AES256-GCM-SHA384").
	// Populated when TraceCrypto is enabled.
	Cipher string `json:"cipher,omitempty"`
	// CipherIANAName is the IANA standard cipher suite name.
	CipherIANAName string `json:"cipherIanaName,omitempty"`
	// CipherIANAID is the IANA cipher suite ID.
	CipherIANAID uint16 `json:"cipherIanaId,omitempty"`
	// TLSVersion is the negotiated TLS protocol version.
	TLSVersion string `json:"tlsVersion,omitempty"`
	// CipherBits is the number of secret bits in the cipher.
	CipherBits int `json:"cipherBits,omitempty"`
	// CryptoLibrary is the name and version of the detected crypto library.
	CryptoLibrary string `json:"cryptoLibrary,omitempty"`
	// CryptoLibraryVersion is the detected version of the crypto library.
	CryptoLibraryVersion string `json:"cryptoLibraryVersion,omitempty"`
}

// CipherInfo describes a single negotiated TLS cipher suite observed during
// eBPF crypto tracing. Captured via uretprobes on SSL_get_current_cipher
// and related functions.
type CipherInfo struct {
	// ConnID is the TLS connection identifier (SSL* pointer) — same value
	// used in HTTPAccessEntry for cross-referencing HTTP requests to ciphers.
	ConnID uint64 `json:"connId,omitempty"`
	// Name is the human-readable cipher suite name (e.g. "ECDHE-RSA-AES256-GCM-SHA384").
	Name string `json:"name"`
	// IANAName is the IANA standard cipher suite name (e.g. "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").
	IANAName string `json:"ianaName,omitempty"`
	// IANAID is the IANA cipher suite ID (e.g. 0xC02C).
	IANAID uint16 `json:"ianaId,omitempty"`
	// Protocol is the TLS protocol version (e.g. "TLSv1.2", "TLSv1.3").
	Protocol string `json:"protocol,omitempty"`
	// Bits is the number of secret bits in the cipher.
	Bits int `json:"bits,omitempty"`
	// KeyExchange is the key exchange algorithm (e.g. "ECDHE", "RSA").
	KeyExchange string `json:"keyExchange,omitempty"`
	// Authentication is the authentication algorithm (e.g. "RSA", "ECDSA").
	Authentication string `json:"authentication,omitempty"`
	// Encryption is the symmetric encryption algorithm (e.g. "AES", "CHACHA20").
	Encryption string `json:"encryption,omitempty"`
	// EncryptionBits is the symmetric cipher key size in bits.
	EncryptionBits int `json:"encryptionBits,omitempty"`
	// Hash is the hash/MAC algorithm (e.g. "SHA384", "SHA256").
	Hash string `json:"hash,omitempty"`
	// Mode is the cipher mode (e.g. "GCM", "POLY1305").
	Mode string `json:"mode,omitempty"`
	// Library is the crypto library that established this connection.
	Library string `json:"library,omitempty"`
	// LibraryVersion is the detected version of the crypto library.
	LibraryVersion string `json:"libraryVersion,omitempty"`
	// PID is the host PID of the process that negotiated this cipher.
	PID uint32 `json:"pid,omitempty"`
}

// CryptoOperation describes a single cryptographic operation observed via
// eBPF uprobes on OpenSSL/GnuTLS/Go crypto functions.
type CryptoOperation struct {
	// Type is the operation type: "digest", "encrypt", "decrypt", "sign", "verify", "keygen".
	Type string `json:"type"`
	// Algorithm is the algorithm name (e.g. "SHA-256", "AES-256-CBC", "RSA-2048").
	Algorithm string `json:"algorithm"`
	// Library is the crypto library that performed this operation.
	Library string `json:"library,omitempty"`
	// LibraryVersion is the detected version of the crypto library.
	LibraryVersion string `json:"libraryVersion,omitempty"`
	// PID is the host PID of the process that performed this operation.
	PID uint32 `json:"pid,omitempty"`
	// Count is the number of times this operation was observed (deduplicated).
	Count uint64 `json:"count,omitempty"`
}

// CryptoLibrary describes a detected cryptographic library.
type CryptoLibrary struct {
	// Name is the library name (e.g. "OpenSSL", "GnuTLS", "Go crypto/tls").
	Name string `json:"name"`
	// Version is the detected version string (e.g. "3.0.8").
	Version string `json:"version,omitempty"`
	// Path is the absolute path to the shared library (e.g. "/usr/lib/x86_64-linux-gnu/libssl.so.3").
	Path string `json:"path,omitempty"`
	// Source indicates how the library was detected: "ebpf_uprobe", "proc_maps", "buildinfo", "symbol_table".
	Source string `json:"source,omitempty"`
}

// CryptoResult is the structured output written as CRYPTO: marker.
// It collects all cryptographic observations from a single execution.
type CryptoResult struct {
	// Ciphers is the list of negotiated TLS cipher suites observed.
	Ciphers []CipherInfo `json:"ciphers,omitempty"`
	// Libraries is the list of detected cryptographic libraries.
	Libraries []CryptoLibrary `json:"libraries,omitempty"`
	// Operations is the list of detected cryptographic operations (opt-in deep tracing).
	Operations []CryptoOperation `json:"operations,omitempty"`
	// Platform is the OS platform where observations were made.
	Platform string `json:"platform,omitempty"`
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
	AllowListen    []string `json:"allowListen,omitempty"`

	// Filesystem isolation
	ProtectSystem  string         `json:"protectSystem,omitempty"`
	ProtectHome    string         `json:"protectHome,omitempty"`
	PrivateTmp     bool           `json:"privateTmp,omitempty"`
	MapToTargetUid bool           `json:"mapToTargetUid,omitempty"`
	LockFiles      []LockFileSpec `json:"lockFiles,omitempty"`

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
	MaxReadIOPS  int     `json:"maxReadIOPS,omitempty"`
	MaxWriteIOPS int     `json:"maxWriteIOPS,omitempty"`
	MaxReadBps   int64   `json:"maxReadBps,omitempty"`
	MaxWriteBps  int64   `json:"maxWriteBps,omitempty"`
	TimeoutMs    int     `json:"timeoutMs,omitempty"`

	// Extends specifies the name of a built-in policy to extend.
	// The base policy is loaded first, then this policy's fields are overlaid.
	// This enables structured policy composition without duplication.
	Extends string `json:"extends,omitempty"`

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

	// Hardening controls (mirror of the ExecConfig fields)
	BlockInterpreters      bool `json:"blockInterpreters,omitempty"`
	DenyPersistenceWrites  bool `json:"denyPersistenceWrites,omitempty"`
	AllowWritableDylibLoad bool `json:"allowWritableDylibLoad,omitempty"`
	BlockJIT               bool `json:"blockJIT,omitempty"`
	GPUUsed                bool `json:"gpuUsed,omitempty"`
	TPMUsed                bool `json:"tpmUsed,omitempty"`
	AntiVMActive           bool `json:"antiVMActive,omitempty"`

	// HTTP access log — populated when --trace-http-urls is used with --learn
	// or --audit. Records observed HTTP requests with method, host, and path.
	HTTPAccess []HTTPAccessEntry `json:"httpAccess,omitempty"`

	// AllowURLRules are fine-grained URL access rules for HTTP requests.
	// Linux-only. Populated by learn mode from HTTPAccess observations,
	// and applied during enforcement when TraceHTTPURLs is active.
	AllowURLRules []AllowURLRule `json:"allowURLRules,omitempty"`

	// Crypto ciphers, libraries, and operations — populated when --trace-crypto
	// is used with --learn or --audit.
	CryptoCiphers    []CipherInfo      `json:"cryptoCiphers,omitempty"`
	CryptoLibraries  []CryptoLibrary   `json:"cryptoLibraries,omitempty"`
	CryptoOperations []CryptoOperation `json:"cryptoOperations,omitempty"`

	// AllowCiphers lists the allowed TLS cipher suite names.
	AllowCiphers []string `json:"allowCiphers,omitempty"`

	// Informational — set by learner, ignored when loading as policy-file
	Cmd  string   `json:"cmd,omitempty"`
	Args []string `json:"args,omitempty"`
}

// LearnedPolicy is a type alias for backward compatibility.
// New code should use PolicyFile directly.
// Deprecated: use PolicyFile instead.
type LearnedPolicy = PolicyFile

// DiagnosticsResult is the output of the --diagnostics command.
// It reports OS-level capabilities and safer-exec feature support.
type DiagnosticsResult struct {
	// Platform is the operating system (e.g. "darwin", "linux").
	Platform string `json:"platform"`
	// Arch is the CPU architecture (e.g. "arm64", "amd64").
	Arch string `json:"arch"`
	// Kernel is the full kernel version string (e.g. "24.0.0").
	Kernel string `json:"kernel"`
	// Release is the OS release name/version (e.g. "24.0.0" on Darwin, "6.8.0-arch" on Linux).
	Release string `json:"release"`
	// Capabilities is a map of feature name to CapabilityInfo.
	Capabilities map[string]CapabilityInfo `json:"capabilities"`
	// Features maps safer-exec feature names to their support status.
	Features map[string]bool `json:"features"`
}

// CapabilityInfo describes a single OS capability.
type CapabilityInfo struct {
	// Available indicates whether the capability is present.
	Available bool `json:"available"`
	// Detail is an optional human-readable description or version info.
	Detail string `json:"detail,omitempty"`
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
	// Crypto is the cryptographic observation report (when TraceCrypto is true).
	Crypto *CryptoResult `json:"crypto,omitempty"`
	// DryRun is the dry-run audit report (when EnableDryRun is true).
	DryRun *DryRunResult `json:"dryRun,omitempty"`
}

// DryRunResult is the complete dry-run audit report.
type DryRunResult struct {
	ExitCode int           `json:"exitCode"`
	Events   []DryRunEvent `json:"events"`
	Summary  DryRunSummary `json:"summary"`
}

// DryRunEvent describes a single blocked operation during dry-run.
type DryRunEvent struct {
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	Target string `json:"target,omitempty"`
	Port   int    `json:"port,omitempty"`
}

// DryRunSummary provides counts by event type.
type DryRunSummary struct {
	TotalEvents     int `json:"totalEvents"`
	FileReads       int `json:"fileReads"`
	FileWrites      int `json:"fileWrites"`
	FileMetadata    int `json:"fileMetadata"`
	NetworkOutbound int `json:"networkOutbound"`
	NetworkBind     int `json:"networkBind"`
	ExecAttempts    int `json:"execAttempts"`
	ForkAttempts    int `json:"forkAttempts"`
}

// ProfileValidationResult is the output of --validate-profile mode.
// It reports whether the generated Seatbelt profile passes syntax validation.
type ProfileValidationResult struct {
	// Valid is true if the profile passes syntax check.
	Valid bool `json:"valid"`
	// Profile is the generated Seatbelt profile text.
	Profile string `json:"profile,omitempty"`
	// Errors is a list of validation error messages.
	Errors []string `json:"errors,omitempty"`
	// Warning is an informational message (e.g., sandbox-exec not found).
	Warning string `json:"warning,omitempty"`
}
