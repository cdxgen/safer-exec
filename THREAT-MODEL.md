# Threat Model: @cdxgen/safer-exec

## Scope

This document covers the sandboxing guarantees, attack surfaces, and failure modes of the `@cdxgen/safer-exec` library. The library enforces OS-level isolation around process execution through a Go binary that uses native mechanisms on macOS and Linux, and on Windows the Microsoft eXecution Container (MXC) ProcessContainer backend.

## 1. System Overview

### Components

- **Node.js wrapper** (`npm/src/`) resolves policies, performs DNS lookups, serializes the execution config, and spawns the Go binary.
- **Go engine** (`go/cmd/safer-exec/`) reads JSON config from stdin and applies platform-specific isolation.
- **macOS engine** generates Seatbelt profiles, applies RLIMIT quotas, and runs commands through `sandbox-exec`.
- **Linux engine** uses namespace isolation, bind mounts, `pivot_root`, seccomp-bpf filters, Landlock network confinement, and cgroup v2 resource quotas.
- **Windows engine** translates the config into an MXC request (`go/internal/mxc/`) and runs the command through the MXC executor `wxc-exec.exe` inside a job object (`go/internal/winjob/`).
- **Learner** (`go/internal/learner/`) traces process behavior via strace (Linux) or Seatbelt trace rules (macOS) to generate policies. On Windows a learning run stays contained and the policy is built from MXC's denial capture and the recording egress proxy (`go/internal/mxc/denials.go`).
- **Filesystem diff** (`go/internal/fsdiff/`) compares snapshots of the write paths taken before and after the run, with SHA-256 hashes for regular files, on every platform.

### Execution Flow

```
Node.js (policy + DNS) --[JSON on stdin]--> Go binary --[sandbox]--> target command
                                                              |
                                                    stdout/stderr back to Node.js
```

### Config Contract

The Node.js layer serializes an `ExecConfig` object to JSON. The Go struct expects the following fields:

| Field                    | Type     | Description                             |
| ------------------------ | -------- | --------------------------------------- |
| `cmd`                    | string   | Command to execute                      |
| `args`                   | string[] | Command arguments                       |
| `env`                    | object   | Environment variables                   |
| `readPaths`              | string[] | Filesystem read paths                   |
| `writePaths`             | string[] | Filesystem write paths                  |
| `allowHosts`             | string[] | Hostnames to allow                      |
| `allowIPs`               | string[] | Resolved IP addresses                   |
| `allowPorts`             | number[] | TCP ports to allow                      |
| `disableNetwork`         | boolean  | Cut all network access                  |
| `maxMemoryMB`            | number   | Memory limit in megabytes               |
| `maxCPUCores`            | number   | CPU limit as fractional cores           |
| `maxProcesses`           | number   | Max child processes                     |
| `timeoutMs`              | number   | Hard kill timeout in milliseconds       |
| `workingDir`             | string   | Working directory                       |
| `enableAudit`            | boolean  | Enable violation auditing               |
| `enableDiff`             | boolean  | Enable filesystem diffing               |
| `enableLearn`            | boolean  | Enable learning mode                    |
| `allowExec`              | string[] | Executables to allow                    |
| `blockExec`              | string[] | Executables to block                    |
| `blockFork`              | boolean  | Prevent forking                         |
| `blockInterpreters`      | boolean  | Deny entitled scripting engines (macOS) |
| `denyPersistenceWrites`  | boolean  | Deny persistence-location writes        |
| `allowWritableDylibLoad` | boolean  | Relax writable-`.dylib` deny (macOS)    |
| `blockJIT`               | boolean  | Block W^X / JIT syscalls (Linux)        |
| `traceExec`              | boolean  | Log child processes                     |
| `strict`                 | boolean  | Treat warnings as hard errors           |
| `allowEnvs`              | string[] | Allowed host env vars                   |
| `allowHidden`            | boolean  | Allow hidden paths read/write           |
| `traceCrypto`            | boolean  | Capture TLS & non-TLS operations        |
| `cbomOutputPath`         | string   | Write CycloneDX CBOM JSON file          |
| `cryptoProbeMode`        | string   | Depth of crypto probe (operations)      |

## 1.5 Default Configuration and Opt-in Hardening

Several isolation mechanisms are **opt-in** and are not active unless explicitly
enabled. Operators must not assume an out-of-the-box configuration enables every
control described in this document. The table below reflects the actual defaults
applied by the Node.js layer (`npm/src/index.js`) and the Go engine.

| Control                                                            | Default                   | Notes                                                                                                                            |
| ------------------------------------------------------------------ | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Seccomp architecture pinning                                       | **on** (always)           | Rejects foreign-arch (i386 compat gate) and x32 syscalls; not configurable off.                                                  |
| Block nested user/mount namespaces (`CLONE_NEWUSER`/`CLONE_NEWNS`) | **on**                    | Disable with `allowUserns`. clone3 is forced to ENOSYS so the clone() flag check cannot be evaded.                               |
| Seccomp default hardening blocklist                                | **on**                    | ptrace, mount, unshare, bpf, keyctl, setuid/setgid, module loading, io_uring, etc.                                               |
| `pivot_root` failure handling                                      | **fatal**                 | Does not silently degrade to an escapable chroot. Opt in to the weaker fallback with `allowChrootFallback`.                      |
| Environment sanitization                                           | **on**                    | Sensitive-looking and loader-control keys (`DYLD_*`/`LD_*`/`NODE_OPTIONS`/...) stripped unless `allowEnvs` lists them. See §3.5. |
| `setUpDev` (minimal `/dev`)                                        | **on** for full isolation |                                                                                                                                  |
| `blockFork`                                                        | **off**                   | Enable to prevent the target from creating any child process.                                                                    |
| `blockInterpreters`                                                | **off** (on in policies)  | macOS. Denies entitled scripting engines / sampling tools (§3.8.1). Built-in non-interpreter policies enable it.                 |
| `denyPersistenceWrites`                                            | **off** (on in policies)  | Denies writes to LaunchAgents/plugin loaders/`/usr/local/bin` (§3.8.2). All built-in policies enable it.                         |
| `blockJIT`                                                         | **off**                   | Linux. Seccomp W^X (§3.8.1). Breaks V8/JVM/LuaJIT; never enabled by default.                                                     |
| `bindUseFd` (TOCTTOU-safe bind mounts)                             | **off**                   | Enable for the O_PATH + re-stat protection described in §3.16.                                                                   |
| `submountEnforce` (read-only submount closure)                     | **off**                   | Enable for the protection described in §3.12.                                                                                    |
| `procHardening` (read-only `/proc/sys`, etc.)                      | **off**                   |                                                                                                                                  |
| `protectSystem` / `protectHome`                                    | **off**                   |                                                                                                                                  |
| `mapToTargetUid`                                                   | **off**                   |                                                                                                                                  |
| `useReaper` (PID 1 reaper)                                         | **off**                   | Incompatible with `blockFork`.                                                                                                   |

For production use, enable `strict` so that initialization warnings (cgroup,
landlock, seccomp, pivot_root) become hard errors rather than silent
degradations, and explicitly turn on the opt-in controls relevant to your
workload.

## 2. Sandbox Mechanisms

### macOS (Seatbelt + RLIMIT)

| Mechanism        | What it enforces                                | How                                              |
| ---------------- | ----------------------------------------------- | ------------------------------------------------ |
| Seatbelt profile | File read/write, network outbound, process exec | Generated `.sb` profile passed to `sandbox-exec` |
| RLIMIT_AS        | Virtual memory cap                              | `syscall.Setrlimit(2)`                           |
| RLIMIT_CPU       | CPU time limit                                  | `syscall.Setrlimit(5)`                           |
| RLIMIT_NPROC     | Child process count                             | `syscall.Setrlimit(6)`                           |

Seatbelt profiles start with `(deny default)` then add allow rules. The profile imports `system.sb` which includes base system rules.

### Linux (Namespaces + Seccomp + Landlock + cgroup v2 + eBPF LSM)

| Mechanism         | What it enforces          | How                                                                        |
| ----------------- | ------------------------- | -------------------------------------------------------------------------- |
| User namespace    | UID isolation             | `CLONE_NEWUSER` + `/proc/self` UID/GID mapping                             |
| Mount namespace   | Filesystem isolation      | `CLONE_NEWNS` + tmpfs root + bind mounts (fd-based with TOCTTOU check)     |
| PID namespace     | Process tree isolation    | `CLONE_NEWPID` + PID 1 reaper process                                      |
| UTS namespace     | Hostname isolation        | `CLONE_NEWUTS`                                                             |
| Network namespace | Network isolation         | `CLONE_NEWNET` (when `disableNetwork` is true)                             |
| pivot_root        | Root filesystem swap      | Mounts tmpfs, bind-mounts paths, pivots with MS_PRIVATE old-root cleanup   |
| Seccomp-bpf       | Syscall filtering         | Blocks ptrace, kcmp, unshare, mount, pivot_root + stackable custom filters |
| Landlock v2       | Network port filtering    | Ruleset version 5 (kernel 6.2+) for TCP connect/bind                       |
| Landlock v3+      | Filesystem confinement    | `path_beneath` rules for read/write/execute/truncate/refer access          |
| cgroup v2         | Resource quotas           | `cpu.max`, `memory.max`, `pids.max`, `io.max`                              |
| LSM BPF           | Kernel-level audits       | Attaches BPF hooks to `bprm_check_security` / `file_open`                  |
| MS_SLAVE          | Mount propagation control | Prevents sandbox mounts from leaking to host                               |
| Submount remount  | Read-only enforcement     | Parses `/proc/self/mountinfo`, remounts each submount as read-only         |
| /proc hardening   | Dangerous entry blockage  | Covers `sys`, `sysrq-trigger`, `irq`, `bus` with read-only bind mounts     |
| /dev isolation    | Minimal device exposure   | Fresh tmpfs with only essential device nodes + stdio symlinks              |

### Windows (MXC ProcessContainer + job objects)

| Mechanism                           | What it enforces                                                 | How                                                                                                      |
| ----------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| BaseContainer filesystem grants     | File read/write                                                  | `CreateProcessSecurityEnvironment` grants; ungranted paths are inaccessible, `%SystemRoot%` is read-only |
| Denied paths                        | Persistence locations under broad write grants                   | Native deny grants (`PSE_SUPPORT_FS_DENY`)                                                               |
| Per-container WFP filters           | Egress by destination CIDR, protocol and port; proxy-only egress | Applied and owned by the OS for the container's lifetime                                                 |
| Job UI limits                       | Clipboard, input injection, desktop, handles, atoms              | `JOB_OBJECT_UILIMIT_*` on MXC's job                                                                      |
| Win32k system-call disable (opt-in) | GUI subsystem kernel attack surface                              | `windowsBlockWin32k`                                                                                     |
| Outer job object                    | Committed memory, CPU rate, active processes; tree teardown      | Limits on safer-exec's job; MXC's job nests under it; `KILL_ON_JOB_CLOSE`                                |
| Explicit environment block          | No inherited profile environment                                 | `process.env` is always supplied, `inheritDefaultEnv` false                                              |
| ETW session (opt-in)                | Observability only: DLLs the workload loads (`traceLibraries`)   | Microsoft-Windows-Kernel-Process image-load events, recorded by the engine outside the container         |

## 3. Threats and Attack Vectors

### 3.1 DNS Resolution

**Threat:** Hostnames are resolved at execution time. If a target host changes its IP address between resolution and connection (DNS spoofing, cache poisoning), the sandbox may connect to the wrong IP.

**Impact:** The command reaches an unintended host. The Seatbelt and Landlock rules only filter by IP, not by hostname.

**Mitigation:** The Node.js layer resolves all `allowHosts` to IPs before spawning the Go binary. On Linux and macOS the sandbox cannot enforce a remote-IP allowlist (§3.3); there, host resolution derives the set of allowed ports and drives eBPF URL observability on Linux. On Windows the engine resolves `allowHosts` itself and installs per-container WFP rules for exactly those addresses (§3.18), so a spoofed answer at start-up decides which addresses are reachable for the whole run.

**Residual risk:** On Linux and macOS, because egress is filtered by port rather than by IP (§3.3), DNS spoofing or rebinding does not change the effective exposure: any host is already reachable on an allowed port. On Windows a poisoned resolution opens the poisoned address instead of the real one. For strict egress control, use `disableNetwork`, `proxyEgress` (hostnames checked at CONNECT time), or an external firewall/eBPF egress policy.

### 3.2 Filesystem Escapes

**Threat:** The target command reads files outside the specified paths, writes to unexpected locations, or follows symlinks to discover information.

**Impact:**

- Reading files outside allowed paths may leak environment configuration or credentials.
- Writing to files outside allowed paths may modify project state or overwrite data.

**How isolation works:**

- **Linux:** A tmpfs root is mounted. Read paths are bind-mounted read-only. Write paths are bind-mounted read-write. The process only sees mounted paths plus `/proc` and `/sys`.
- **macOS:** The Seatbelt profile allows file reads and writes for all paths by default, then adds explicit subpath rules for the specified paths. The base `system.sb` profile is imported.
- **Windows:** The BaseContainer sees only granted paths plus the read-only `%SystemRoot%`; everything else, including Program Files and the user profile, is invisible. See §3.18.

**Mitigation:** By default, `safer-exec` avoids blanket allows and instead restricts macOS file operations to a standard minimal set. When no custom paths are specified, the sandbox profile generates rules allowing reading of standard system directories and the working directory, and restricts write access exclusively to temporary directories (e.g. `/tmp`, `/private/tmp`). If explicit read/write paths are supplied, only those paths (plus system directories) are permitted.

### 3.3 Network Escapes

**Threat:** The target command connects to hosts or ports outside the allow list.

**Impact:** Data exfiltration, calling APIs that trigger side effects, or connecting to local services for information gathering.

**How isolation works:**

- **Linux:** A new network namespace is created when `disableNetwork` is true — this is the only mechanism that fully severs egress. When the network is not disabled, Landlock restricts TCP connections to the configured ports. Landlock filters by port, **not** by IP.
- **macOS:** Seatbelt port filtering uses `remote ip "*:PORT"` patterns.
- **Windows:** Per-container WFP rules allow only the `/32` and `/128` addresses the allowed hosts resolved to, on the allowed TCP ports (default 80 and 443). In `proxyEgress` mode only the loopback proxy is reachable.

**On Linux and macOS, egress is filtered by port, not by host/IP (important).** Neither Landlock
(Linux) nor Seatbelt (macOS) can pin outbound connections to a specific remote IP
address: Landlock has no IP-level rule type, and Seatbelt's `(remote ip ...)`
filter only accepts `*` or `localhost` as the host. Consequently `allowHosts` /
`allowIPs` constrain only the _ports_ that may be used (and, on macOS, prevent a
fall-through to fully-unrestricted egress). They do **not** prevent the sandboxed
process from reaching an arbitrary host on an allowed port (e.g. exfiltration to
an attacker server over 443). When host-pinning is requested:

- **macOS** emits a warning that IP pinning is not enforceable and confines egress
  to the requested ports only.
- **Linux** can fully sever egress with `disableNetwork`; for observability of the
  specific hosts/URLs reached, use `allowURLRules` with eBPF HTTP tracing
  (`traceHTTPURLs`), which records and flags per-URL violations.

**Residual risk:**

- On Linux and macOS, any remote host is reachable on an allowed port. True
  per-IP egress confinement there requires `disableNetwork` (full cut) or a
  host-level firewall/eBPF egress policy outside `safer-exec`.
- On Windows, other sites served from an allowed address (CDNs, shared cloud
  front ends) are reachable too; use `proxyEgress` when the hostname itself
  must be enforced.

### 3.4 Resource Exhaustion

**Threat:** The target command consumes unbounded memory, CPU, or spawns excessive child processes.

**Impact:** Slows down the host system, causes OOM kills of sibling processes, or triggers fork bombs.

**How isolation works:**

- **Linux:** cgroup v2 enforces `memory.max`, `cpu.max`, and `pids.max`.
- **macOS:** RLIMIT quotas enforce `RLIMIT_AS` (address space), `RLIMIT_CPU` (CPU seconds), and `RLIMIT_NPROC` (process count).
- **Windows:** A job object around the launcher enforces job-wide committed memory, a CPU-rate hard cap and the active-process count; see §3.18.

**Residual risk:**

- Memory, CPU, and process limits default to 0 (unlimited). The timeout defaults to 60 seconds. Users should explicitly set `maxMemory`, `maxCPUCores`, and `maxProcesses` for production use. Sensible recommendations: 512 MB memory, 1.0 CPU core, 100 processes.
- RLIMIT_CPU on macOS limits total CPU time, not wall clock time. A single-threaded process gets the full allocation.
- The process count limit on macOS adds 10 to the configured value to account for internal processes. On Linux it adds 2.

### 3.5 Environment Inheritance

**Threat:** The target command inherits environment variables that affect its behavior.

**Impact:** The command may use different configuration, connect to different hosts, or behave differently than expected.

**How isolation works:** By default, the sandbox does not inherit host environment variables other than safe defaults (such as PATH, HOME, TERM, LANG, and LC\_\*). Custom environment variables can be set via `env()`, and host environment variables can be allowed via `allowEnvs()`. Environment variables are sanitized by default along two axes:

- **Credential-bearing keys** — any key containing TOKEN, PASSWORD, SECRET, API_KEY, CLIENT_SECRET, SESSION, COOKIE, AUTH, or KEY is stripped.
- **Loader-control keys** — variables that steer the dynamic loader or a language runtime and so enable code injection: `DYLD_*` and `LD_*` (any member, e.g. `DYLD_INSERT_LIBRARIES`, `LD_PRELOAD`, `LD_AUDIT`), plus `DEVELOPER_DIR` (CoreSymbolication external-dylib path), `NODE_OPTIONS`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `RUBYOPT`, `PERL5LIB`, `GCONV_PATH`, `GIT_SSH_COMMAND`, and similar. These are stripped even though they do not match a credential pattern.

A key listed in `allowEnvs()` bypasses **both** filters — it is the single, deliberate opt-in for passing either a credential or a loader-control variable through. The Go engine repeats this filtering as a backstop, so a policy or caller that sets a loader-control variable directly in `env` cannot smuggle it past the strip without also allow-listing it.

**Windows:** Names are compared case-insensitively, the inherited baseline adds the variables Windows programs need to start (`SystemRoot`, `PATHEXT`, the profile folders), and the engine additionally strips variables that load code into .NET or PowerShell processes. See §3.18.

**Residual risk:** PATH, HOME, and other safe defaults are inherited even when a custom environment is set. The filter inspects key names, not values. Allow-listing a loader-control variable (e.g. for an instrumentation harness) re-enables its injection capability by design; this is an explicit operator decision. macOS additionally strips `DYLD_*` for SIP-protected/restricted target binaries at the kernel level regardless of this layer.

### 3.6 Seatbelt Profile Construction (macOS)

**Threat:** The Seatbelt profile is constructed programmatically. Incorrect or overlapping rules may weaken isolation.

**Impact:** The command runs with broader permissions than intended.

**How it works:** The profile is built by concatenating Seatbelt rule strings. The order is:

1. Version declaration and default deny
2. Import system.sb
3. Base allows (signal, process-exec, process-fork, file-read*, file-write*, user-preference-read, file-read-metadata)
4. Per-path read rules
5. Per-path write rules
6. Network rules
7. Fork/exec restrictions (when configured)

**Residual risk:** The base allow rules grant broad file access. The per-path rules are additive. This is functionally correct but means the Seatbelt profile is permissive by design. The Linux path provides stronger isolation through the tmpfs + bind mount approach.

### 3.7 Seccomp Filter (Linux)

**Threat:** The seccomp-bpf filter only blocks a small set of syscalls. Other syscalls are allowed.

**Impact:** The target can perform syscalls not typically needed but does not affect isolation quality.

**Architecture pinning:** The filter loads `seccomp_data.arch` and kills the
process (SECCOMP_RET_KILL_PROCESS) for any syscall that does not arrive under the
native architecture. On x86_64 it additionally rejects x32-ABI syscall numbers
(those carrying `__X32_SYSCALL_BIT`). Without this, a process could bypass the
entire number-based blocklist via the i386 compat gate (`int 0x80`, where syscall
numbers differ) or the x32 ABI. The architecture guard runs before the syscall
number is inspected.

**Blocked syscalls:** ptrace, kcmp, unshare, mount, pivot_root, syscall
(meta-syscall), personality, the setuid/setgid family, capset, the
setxattr/removexattr family, bpf, perf_event_open, userfaultfd, keyctl,
request_key, fanotify/inotify, io_uring (setup/enter/register), process_vm_readv/writev,
module loading (init/finit/delete_module), quotactl, swapon/swapoff, time
manipulation (settimeofday/clock_settime/adjtimex), syslog, ioperm/iopl, acct,
reboot, kexec_load, and chroot.

**Namespace creation:** `clone()` flags are inspected; `CLONE_NEWUSER` and
`CLONE_NEWNS` are denied (EPERM) by default so the sandboxed process cannot
create nested namespaces (a common precondition for unprivileged-userns kernel
LPEs). Because BPF cannot dereference the `clone3` arguments struct, `clone3` is
forced to ENOSYS, causing libc to fall back to the inspectable `clone()` path.
This is disabled by `allowUserns`.

**Fork blocking:** When `blockFork` is set, `clone` without `CLONE_THREAD`,
`fork`, and `vfork` are blocked while thread creation (`CLONE_THREAD`) is
preserved. `clone3` is already forced to ENOSYS (see above), so it cannot evade
the fork block.

**What is not blocked:** All other syscalls including read, write, openat, stat, fstat, lstat, access, connect, socket, recvfrom, sendto, etc.

### 3.8 Fork and Exec Control

**Threat:** The target command spawns unexpected child processes to run postinstall scripts, call external tools, or perform side-channel operations.

**Impact:**

- Postinstall scripts may download additional dependencies or run build steps.
- Child processes inherit the sandbox profile but may access different resources than the parent.
- Forking allows the command to run parallel operations that consume additional resources.

**How isolation works:**

- **macOS:** Seatbelt rules restrict `process-exec` to specified binaries. The `blockFork` flag removes the `process-fork` allow rule. The `traceExec` flag adds `(trace process-exec "*")` to log all child processes.
- **Linux:** Seccomp-bpf filters `fork`, `vfork`, and `clone` (flag-checked to allow `CLONE_THREAD`), and forces `clone3` to ENOSYS, when `blockFork` is set. The `allowExec`/`blockExec` flags filter exec by executable name.

**Exec-control limitation (important):** Stateless seccomp cannot allow the
target's own initial `exec` while blocking every descendant — the launcher and
any child share the same two exec syscalls (`execve`/`execveat`), so exactly one
must remain open and a child can use whichever that is. The engine therefore
makes the guarantee precise rather than absolute:

- `blockExec: ['*']` **with** `blockFork`: no child process can be created at all,
  so the only exec is the target's own launch (an in-place self-replacement stays
  inside the same sandbox and cannot escalate). The `execveat` evasion vector is
  blocked; `execve` stays open solely for the launcher. **This is the recommended
  configuration for fully preventing subprocess execution.**
- `blockExec: ['*']` **without** `blockFork`: children can exist and inherit the
  filter. `execve` (the libc exec path used by `sh`/`system`/`posix_spawn`) is
  blocked, but a child invoking the `execveat` syscall directly is an irreducible
  residual; the engine emits a warning recommending `blockFork`.
- `traceExec`: tracing observes rather than blocks, so no exec syscall is filtered
  at the seccomp layer; exec events are surfaced by the eBPF/audit layer.

For a hard guarantee against arbitrary subprocess execution that does not depend
on this asymmetry, combine `blockExec: ['*']` with `blockFork`.

**Residual risk:**

- Wildcard blocking (`blockExec: ['*']`) without `blockFork` leaves the `execveat`
  syscall reachable by descendants, as described above.
- The `traceExec` flag on Linux uses seccomp `SIGSYS` trapping on `execve`. This adds overhead to every child process spawn.
- Fork blocking on macOS uses Seatbelt rules. The command may still fork but the child inherits the same Seatbelt profile.

### 3.8.1 Living-off-the-land interpreters and in-memory code execution (`blockInterpreters`, `blockJIT`)

**Threat:** A confined process re-execs a preinstalled, Apple-signed binary that
carries a code-signing exemption — `com.apple.security.cs.allow-unsigned-executable-memory`
or `com.apple.security.cs.disable-library-validation` — and uses it to run code
the sandbox never sees on disk. `tclsh` is the canonical example: it ships the
Ffidl libffi binding plus `http`/`tls`, so a script can `mmap`/`mprotect` raw
shellcode or `load` an unsigned dylib, fetched from a remote URL, entirely in
memory. The same exemptions cover `wish`, system `perl`/`python3`/`ruby`,
`expect`, and the `com.apple.SamplingTools` binaries (`symbols`, `vmmap`,
`atos`, ...), which additionally hold `com.apple.system-task-ports` (arbitrary
`task_for_pid`). This bypasses both filesystem confinement (nothing is written)
and `process-exec` denials (the interpreter itself is the allowed binary).

**Impact:** Arbitrary native code execution inside the sandbox, invisible to
`--diff` and to write-path confinement; potential dylib hijack via a writable
path; egress over an allowed port (which macOS Seatbelt cannot pin to a host).

**How isolation works:**

- `blockInterpreters` (macOS) emits last-match-wins `process-exec` denies for the
  entitled interpreters and sampling tools, using framework-root `subpath` rules
  so direct-framework invocation (e.g. the versioned `tclsh8.5`) is covered, not
  just the `/usr/bin` shims. It also denies `file-read*` on the Tcl/Tk frameworks
  and `/System/Library/Tcl` (where Ffidl lives), starving the FFI bridge even if
  an interpreter is reachable. A self-command guard (symlink-resolved) exempts the
  binary the caller deliberately asked to run and warns instead of breaking it.
  Under `blockInterpreters`, reads of `.dylib` files from writable/temp trees are
  also denied (the `load bad.dylib` vector), with `allowWritableDylibLoad` as the
  escape hatch for native-addon builds.
- `blockJIT` (Linux) closes the primitive at the syscall level — the only place it
  can truly be stopped — via seccomp: `mprotect`/`pkey_mprotect` adding `PROT_EXEC`,
  `mmap` with `PROT_WRITE|PROT_EXEC`, and `memfd_create` (anonymous-file exec) all
  return EPERM.

**Residual risk:** The unsigned-executable-memory primitive is a syscall-level
capability that **Seatbelt cannot filter**, so on macOS in-process JIT inside an
_allowed_ binary (including the target command itself) cannot be prevented — only
detected, via EndpointSecurity `es_event_mmap`/`es_event_mprotect` telemetry and
the Tcl/Ffidl framework reads surfaced by `traceLibraries`. `blockJIT` is opt-in
because it breaks legitimate JITs (V8/Node, the JVM, LuaJIT). `blockInterpreters`
is macOS-specific; on Linux the entitlement model does not apply, and arbitrary
interpreters are governed by `allowExec`/`blockExec` and `blockJIT` instead.

### 3.8.2 Persistence and privilege-escalation staging (`denyPersistenceWrites`)

**Threat:** A confined build writes a payload to a well-known auto-execution
location so it survives the sandbox or is later picked up by a privileged system
service: `~/Library/LaunchAgents` (login persistence), the plugin trees scanned by
root daemons (`/Library/DirectoryServices/PlugIns`, MIDI drivers, QuickLook),
preference stores that can be poisoned into launching code, or the
world-writable `/usr/local/bin` that macOS diagnostic tools resolve helpers from.
None of these are legitimate build/install write targets.

**Impact:** Persistence across the sandbox boundary; in some chains, code executed
later by a privileged service (local privilege escalation).

**How isolation works:** `denyPersistenceWrites` emits `file-write*` denies for
these locations after the temp/write allows so they win under last-match-wins. A
path explicitly granted via `writePaths` is exempt. All built-in policies enable
it. On Linux the namespace + Landlock allowlist is already deny-by-default for any
path not granted, so the flag is informational there rather than additive.

**Residual risk:** The deny list enumerates known locations; a novel persistence
vector outside it is not covered. The flag removes only the in-sandbox _staging_
step — it does not patch the privileged service that would consume the payload.
safer-exec also never authenticates an IPC/helper peer by bare PID (the
`audit_token`-vs-`processIdentifier` PID-reuse bug class), and applies the
sandbox profile at process start rather than after the process has warmed up
privileged caches.

### 3.9 Learning Mode

**Threat:** On Linux and macOS, learning mode runs the command without sandbox restrictions, then generates a policy from observed behavior. On Windows the run stays contained. On every platform the command decides what it touches, so it can try to steer the learned policy toward broader grants.

**Impact:** The learned policy may be incomplete if the command behaves differently under observation (Heisenberg effect) or if the strace/trace parser misses certain syscalls.

**How it works:**

- **Linux with strace:** Traces openat, open, readlink, connect, sendto, recvfrom, stat variants, and access. Parses the output to extract file paths and network connections.
- **Linux without strace:** Takes pre/post filesystem snapshots and scans /proc/net/tcp for network connections.
- **macOS:** Uses Seatbelt trace rules to log file reads, file writes, network outbound, and process exec to a trace file.
- **Windows:** Runs contained with MXC denial capture and a recording egress proxy. The proxy refuses loopback, link-local (cloud metadata) and multicast destinations. The learned policy drops paths spelled through aliases (UNC, 8.3 names, trailing dots, streams), drive roots, the profile and its AppData roots, Program Files, ProgramData, `%SystemRoot%`, the engine's own directories, and write access to persistence locations. One-off consent such as `windowsAllowDaclMutation` is never copied into the learned policy.

**Residual risk:** Review learned policies before enforcing them; they record what the command attempted, not what it needs. The strace-based learner may miss indirect file accesses (e.g., files accessed through memory-mapped I/O). The basic learner only captures network connections active at the moment of the /proc/net/tcp scan, missing transient connections.

### 3.10 Filesystem Diff

**Threat:** The diff mechanism misses file changes or reports false positives.

**Impact:** Incorrect understanding of what files the command modified.

**How it works:** On every platform the engine snapshots the write paths before and after the run and compares SHA-256 hashes (regular files up to 64 MiB), sizes, modification times and permission modes. Directories count as modified only when their mode changes. The engine takes the post-run snapshot with the user's full privileges after the sandboxed command, which could write inside the roots, has finished. The snapshotter is therefore built not to be steered by it:

- Each root is resolved once, before the command starts. A root that the command later replaces with a symlink, or whose parent directory it replaces, is recorded as a single changed entry and never walked, so the diff cannot be pointed at `$HOME`, `/` or a device.
- Symlinks inside a root are recorded, not followed, and only regular files are opened for hashing, without following a final symlink and without blocking on a FIFO.
- A tree reachable through more than one root is recorded once.

**Residual risk:** The diff only covers configured write paths. Changes to files outside those paths are not captured. A command still running when the post-run snapshot starts (a detached child on macOS) can swap a directory during the walk; the root check repeated after the walk discards such a root, but the engine may already have read files it reached.

### 3.11 Process Escape

**Threat:** The target command escapes the sandbox entirely.

**Impact:** The command runs with full host privileges.

**Linux escape paths:**

1. Unshare additional namespaces to create nested isolation (blocked by seccomp).
2. Create nested user/mount namespaces via `clone`/`clone3` to obtain namespaced capabilities for kernel LPEs (blocked by default: `CLONE_NEWUSER`/`CLONE_NEWNS` denied and `clone3` forced to ENOSYS; opt out with `allowUserns`).
3. Mount new filesystems to discover host state (blocked by seccomp).
4. Trace sibling processes (blocked by seccomp ptrace rule).
5. Pivot root again (blocked by seccomp pivot_root rule; a failed initial pivot_root is fatal by default rather than degrading to chroot).
6. Issue blocklisted syscalls via the i386 compat gate or x32 ABI (blocked by architecture pinning; see §3.7).
7. Use clone3 to bypass fork/clone blocking (clone3 is forced to ENOSYS, so it falls back to the flag-checked clone path).
8. Use execveat to bypass execve blocking — see the exec-control limitation in §3.8; closed when `blockExec: ['*']` is combined with `blockFork`.

**Network namespace:**

A new network namespace is created when `disableNetwork` is true. This prevents the sandboxed process from observing host network interfaces, listening sockets, or network connection state. When a new network namespace is active, explicit `allowHosts` / `allowPorts` configuration is required for outbound connectivity.

**Network Port Listening Restriction:**
By default, the sandboxed process is prevented from listening on any network port (including local loopback `lo`) on macOS, Linux and Windows. Listening or binding to specific IP addresses or ports must be explicitly permitted using `allowListen` / `--allow-listen`.

**macOS escape paths:**

1. Fork child processes that read files (allowed, children inherit the Seatbelt profile).
2. Read environment variables from parent processes (allowed through system.sb).

### 3.12 Submount Read-Only Bypass

**Threat:** A bind-mounted directory tree is remounted read-only, but existing submounts within it remain writable because the kernel's `MS_REC` remount does not propagate flags to all submounts reliably (known kernel behavior especially on systemd hosts with layered mounts).

**Impact:** Writable submounts leak through apparently read-only bind mounts. For example, bind-mounting `/usr` as read-only but `/usr/local` (a separate mount) remaining writable.

**How isolation works:** When `submountEnforce` is enabled (**opt-in; off by default**), after each read-only bind mount the engine parses `/proc/self/mountinfo` to discover all submounts under the target, then individually remounts each with `MS_REMOUNT | MS_BIND | MS_RDONLY`. This closes the `MS_REC` propagation loophole regardless of kernel version or host configuration. Mountinfo fields are octal-unescaped (e.g. `\040` → space) before comparison so submounts whose paths contain whitespace are matched correctly.

**Residual risk:** With `submountEnforce` off (the default), writable submounts under a read-only bind mount remain writable. When enabled, a race remains between the initial mount and the submount scan in which a process could rapidly create new submounts.

### 3.13 PID Namespace Zombie Accumulation

**Threat:** In a PID namespace, orphaned child processes are reparented to PID 1. If PID 1 does not call `waitpid()`, zombies accumulate indefinitely, consuming process table slots and preventing correct exit code propagation.

**Impact:** Resource exhaustion (zombie processes), incorrect exit codes reported to the parent, and potential sandbox leaks (processes that outlive the sandbox).

**How isolation works:** The engine forks a dedicated PID 1 reaper process that runs a `wait4()` loop, reaping orphaned zombies and propagating the target command's exit code. The reaper exits with the target's exit code, ensuring the parent process receives the correct status.

**Residual risk:** If the reaper process is killed (e.g., by `SIGKILL`), remaining children become zombies in the namespace. The kernel cleans up when the PID namespace is destroyed.

### 3.14 File Descriptor Leak

**Threat:** File descriptors opened during sandbox setup (config file, audit pipe, cgroup fds) are inherited by the target command, exposing internal state and enabling sandbox escapes via `/proc/self/fd/N`.

**Impact:** The target command can read sandbox configuration, write to audit channels, or access files through leaked fds that bypass filesystem isolation.

**How isolation works:** Before exec, the engine iterates `/proc/self/fd` and closes every fd above stderr (fd 2). This is done in the post-fork child process using raw syscalls for fork-safety.

**Residual risk:** Fds created between the close loop and the execve may still leak. The close-loop-exec window is minimized to a few instructions.

### 3.15 Mount Propagation Leakage

**Threat:** On hosts with shared mount propagation (default on systemd), mounts created inside the sandbox namespace propagate back to the host mount namespace, allowing bidirectional mount visibility.

**Impact:** The sandboxed process can observe host mount events or create mounts visible outside the sandbox.

**How isolation works:** `MS_SLAVE | MS_REC` is set on the root mount immediately after entering the mount namespace, ensuring sandbox mounts do not propagate to the host. Before unmounting the old root, `MS_PRIVATE | MS_REC` is set to break the propagation tree and ensure clean unmount.

**Residual risk:** Host mount events still propagate into the sandbox (slave receives, does not send). This is intentional for compatibility.

### 3.16 TOCTTOU Race in Bind Mounts

**Threat:** Between symlink resolution and the `mount()` syscall, a concurrent process replaces the resolved path with a symlink to a sensitive location, bypassing path-based restrictions.

**Impact:** The mount operation binds an unintended target path, potentially exposing host files inside the sandbox.

**How isolation works:** When `bindUseFd` is enabled (**opt-in; off by default**), the source path is opened via `O_PATH` before mounting, mounted through `/proc/self/fd/N`, and then `fstat(fd)` is compared against `lstat(target)` to detect swaps. If the inode or device number differ, the mount is rolled back with `MNT_DETACH` and an error is returned.

**Residual risk:** With `bindUseFd` enabled the race window is reduced to the interval between `fstat` and `mount` (microseconds). With the default (`bindUseFd` off), the plain `mount(source, target)` path is used and the full symlink-swap race window is present — enable `bindUseFd` for workloads where the bind-mount sources are attacker-influenced.

### 3.17 Pre-Sandbox Helper Resolution (Linux)

**Threat:** Before the sandbox namespaces exist, the Linux engine runs the system
helpers `unshare` (to create the namespaces) and `ip` (to bring up loopback).
These run with the launching user's privileges. If they were resolved via the
inherited `PATH`, a caller that prepends an attacker-controlled directory (a
common CI pattern, e.g. `./node_modules/.bin` or `.` on `PATH`) could substitute
a malicious `unshare`/`ip` and achieve code execution before any confinement is
applied.

**How isolation works:** Both helpers are resolved with `lookTrustedTool`, which
searches only a fixed set of standard absolute directories (`/usr/bin`, `/bin`,
`/usr/sbin`, `/sbin`), ignores `$PATH`, and requires the resolved file to be a
regular file that is not group- or world-writable. `ip` is skipped entirely when
no trusted binary is found; `unshare` falls back to the bare name only on exotic
systems where it is absent from every standard directory (no worse than the
historical behavior, while the common case is fully pinned).

### 3.18 Windows Engine (MXC)

**Containment tier.** The guarantees in this section hold on the BaseContainer tier (Windows 11 24H2, 25H2 or 26H1 with the August 2026 servicing update, or later; Windows Server is not on MXC's supported list). On older builds MXC falls back to an AppContainer tier that grants access by adding entries to the access control lists of the granted paths on the host. The engine probes the host on every run and refuses that tier unless the caller sets `windowsAllowDaclMutation`. On that tier a grant applies to the whole tree below it, so the engine also refuses drive-root grants there. MXC restores the original ACLs at the end of a run and, if it was killed first, replays its saved backups on the next start. The shipped executor does not include MXC's bind-filter tier.

**Executor integrity.** `wxc-exec.exe` runs with the caller's privileges and creates the container, so it is trusted like the engine itself. It ships next to `safer-exec-rt.exe` in the platform package and is built from a pinned MXC commit. The engine looks for it only there or at the absolute path in `SAFER_EXEC_MXC_EXEC`, never on `PATH`, and the Node layer never resolves the engine by bare name (Windows would search the current directory first). MXC's elevating helpers (`winhttp-proxy-shim.exe`, `plm.exe`, `wxc-host-prep.exe`) are not shipped, so no run can trigger a UAC prompt. MXC's debug and override variables (`MXC_*`, `WXC_*`, for example `MXC_FORCE_TIER`) are removed from the executor's environment so they cannot select a tier other than the one the probe vetted.

**Engine-owned files.** Each run keeps its MXC request (which carries the workload's environment) and the denial report in a directory under `%TEMP%\safer-exec-mxc`. MXC replays ACL backups from `%LOCALAPPDATA%\Microsoft\MXC` on every start. The engine creates both directories and every request denies them to the container whenever a grant would reach them, so neither this sandbox nor a concurrent one with a broad `TEMP` or `LOCALAPPDATA` grant can read another run's request, rewrite a request or report, or plant ACL backups.

**Shared stderr.** The workload writes to the same stderr handle as `wxc-exec.exe`, so it can print lines that look like MXC's protocol. The engine therefore ignores MXC's denial-report pointer and reads the report only from its own run directory. It accepts an error envelope only with MXC's two error codes and a non-zero exit, and a timeout only when its own clock agrees. A workload that leaves a marker unterminated cannot hide MXC's real envelope. Audit and diff output are produced on every enforce-mode exit path, so a forged failure cannot suppress them. A non-zero exit before any workload process existed is reported as an MXC failure, not as the workload's status.

**Command-line injection.** MXC passes `process.commandLine` to `CreateProcessW`. The engine resolves the executable itself (absolute `PATH` entries only, quoted entries honored, no current-directory search, only `.com/.exe/.bat/.cmd`), always quotes the program path, and escapes arguments for `CommandLineToArgvW`. Batch files run through an explicit `%SystemRoot%\System32\cmd.exe /d /e:ON /v:OFF /c` taken from the host environment (a caller-supplied `SYSTEMROOT` cannot redirect it), with cmd-specific quoting, `%` neutralized and CR/LF rejected: the CVE-2024-24576 class. A batch script that expands its own arguments unquoted (`%~1`) can still be injected by its arguments; that is a property of the script. When the command is `cmd.exe` itself, the arguments after `/c`, `/k` or `/r` form one shell command string (`cmd /d /s /c "..."`), so they are shell syntax, not data. The workload environment sets `NoDefaultCurrentDirectoryInExePath=1`, so batch shims and child processes do not pick up programs planted in the working directory.

**Environment.** Besides the cross-platform loader-control filtering (§3.5), the engine removes variables that load code into .NET or PowerShell processes unless they are named in `allowEnvs`: CLR and CoreCLR profilers, `DOTNET_STARTUP_HOOKS`, `DOTNET_ADDITIONAL_DEPS`, `DOTNET_SHARED_STORE`, `DOTNET_DiagnosticPorts`, every `COMPlus_*` setting, `__COMPAT_LAYER` and `PSModulePath`.

**Network.** Direct-egress rules allow only the addresses the hosts resolved to at start. Other hostnames served from those addresses (CDN or shared cloud front ends) stay reachable; use `proxyEgress` when the hostname itself must be enforced. In proxy mode the container may reach only the proxy endpoint. safer-exec's proxy has no package or AppContainer identity, so MXC's identity-less mode is used. MXC documents that mode as weaker because host loopback is allowed and the bidirectional private-network capability is granted, but the engine test `TestWindowsEngineConfinesHostAndProxyBypass` verifies on Windows 11 25H2 that WFP still keeps other loopback listeners, the host's LAN address and allowed hosts dialed directly out of reach. `allowListen`, private-network destinations and `allowLoopback` need capabilities Windows cannot scope as narrowly as requested; the engine reports them as broader than requested, and `strict` refuses them. The learning proxy refuses loopback, link-local and multicast destinations.

**Persistence locations.** `denyPersistenceWrites` denies existing Startup folders, PowerShell profile directories (including a redirected Documents folder), per-user `PATH` directories and shell, git, npm and SSH configuration under broader write grants. A Windows container cannot deny a path that does not exist (the container API rejects the policy), so a missing location stays creatable; the engine reports it as not enforced and `strict` refuses the run.

**Home and temp isolation.** `protectHome` and `privateTmp` have no Windows mechanism of their own. The container already hides the user profile and the host's temp directory, so they hold until a grant reaches into those directories. Linux drops or covers such grants, but Windows keeps them. The engine therefore reports `protectHome` as not enforced for a write grant inside the profile (`read-only`) or any grant inside it (`tmpfs`), and `privateTmp` for any grant inside or above `%TEMP%` or `%TMP%`; `strict` refuses those runs. `blockInterpreters` stays silent, as on Linux: the interpreters it denies carry exemptions only macOS grants.

**Resource limits.** Job limits apply to the launcher too, so 32 MB is added to the memory limit for it; a workload that fills the job can still starve the launcher. Windows fails allocations past a job memory limit instead of killing the process, so the engine terminates the workload (exit 137) on the first limit notification. Job notifications are queued in the engine rather than dropped, but Windows does not guarantee their delivery; dropped notifications are reported. Processes are killed only after the engine confirms they are still members of the job, so a reused process id cannot point it at an unrelated process. I/O rate limits are not enforced.

**Exec control.** There is no per-executable exec filter. An absolute-path `blockExec` entry is enforced when that path is unreachable inside the container. A bare name means "the program `PATH` finds" and is enforced when no `PATH` directory readable in the container contains it; a copy stored elsewhere under a grant can still be started by its full path, as on macOS. `blockFork` on an executable is enforced by the active-process limit, which then enforces every exec rule. A `.bat` or `.cmd` command needs two extra process slots for its `cmd.exe` interpreters, and any program the script starts can use them, so `blockFork` and exec rules on a batch command are reported as not enforced.

**Win32k.** MXC disables Win32k system calls by default, but common runtimes (Node.js, Java) cannot start without `user32.dll`, so safer-exec turns the block off unless the caller sets `windowsBlockWin32k`. By default the workload can therefore reach the Win32k kernel attack surface. Enable the block for console-only workloads. Clipboard and input injection stay blocked either way.

**Observability gaps.** On BaseContainer hosts MXC's denial capture does not report accesses to paths outside every grant and is best-effort even for grant conflicts, so audit, learning and dry-run reports are partial and must not be treated as a complete record. Learning runs stay contained instead of using MXC's permissive mode, which lifts enforcement while recording nothing on these hosts.

**Session 0.** Containers started from session 0 (services, SSH logons) cannot open the session's window station, so programs that load `user32.dll` fail to start. This fails closed.

**Library tracing.** `traceLibraries` runs a real-time ETW session on the Microsoft-Windows-Kernel-Process provider in the engine, outside the container. The kernel logs the process and image-load events, so the workload cannot hide a load from the engine's record, and `TestWindowsEngineWorkloadCannotStopTraceSession` verifies that a contained process is denied when it tries to stop the session. The entries travel over the report channel (§3.19), which the workload cannot write to. It can load many images, though: the engine keeps at most about a million events per run and reports at most 10,000 distinct images, and it reports anything past those bounds, and any events Windows drops, as a warning. Loads are attributed by following process starts down from `wxc-exec.exe` and matching each event to one process lifetime, so a process id that Windows reuses after a workload process exits does not pull an unrelated process into the report. Only section mappings are seen; a workload that maps a DLL's bytes by hand is not reported, so treat the list as an inventory, not a control. `traceCrypto` uses the same session to name the crypto DLLs among the loads; a DLL is recognized by file name, so a renamed copy is missed and a look-alike name is reported.

Starting the session needs administrator rights or the Performance Log Users group. Running the engine elevated for this does not elevate the workload: on Windows 11 25H2 (build 26200) the contained process runs with a low-integrity AppContainer token in which the Administrators group is not enabled and only `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege` remain. Windows keeps a session running until it is stopped, even after the process that started it dies, so each session is named after the engine's process id and creation time, and every start first stops sessions whose engine no longer runs.

### 3.19 Engine Report Channel

The workload writes to the same stdout and stderr as the engine. Audit entries used to be JSON lines on stderr and results (`FSDIFF:`, `LEARNED:`, `CRYPTO:`, `DRYRUN:`, `PROFILE:`) marker lines on stdout, so a workload could print look-alikes: fake `lib-load` entries that a BOM generator would turn into components, a fake filesystem diff, or a fake learned policy that a later run would enforce.

The Node runner now passes a dedicated pipe (stdio[3], `reportFd`) and reads audit entries and results only from it; stdout and stderr are passed through as plain output. The workload never holds the pipe:

- **macOS and the BSDs:** the engine marks it close-on-exec at startup, so `sandbox-exec` and the target do not inherit it.
- **Linux:** close-on-exec as well. The inner `--init` processes, which exec the target in their own place, write their audit entries to an internal pipe that they also mark close-on-exec. The engine makes itself non-dumpable, so a process of the same user cannot open `/proc/<engine>/fd/3`; in reduced isolation, the one mode where the workload sees the engine's PID, the sandbox already denies that open (the security test tries it).
- **Windows:** libuv hands the pipe over in the C runtime's descriptor table (`STARTUPINFO.lpReserved2`); the engine reads the handle from there and makes it non-inheritable, and Go passes only explicit handles to `wxc-exec.exe` anyway.

**Residual risk:** on Linux the `LD_AUDIT` helper that reports `lib-load` events runs inside the workload's processes, so the workload can write to the descriptor the helper uses. That descriptor is a separate pipe whose lines the engine re-validates and re-encodes as `lib-load` entries only, so a workload can add library entries of its own but no other audit type and no result. The macOS (Seatbelt log) and Windows (ETW) sources are outside the workload's reach. An engine run by hand without `reportFd` keeps the old stdout/stderr protocol and its exposure.

### 3.20 TLS Handshake Observation

With `traceCrypto`, the egress proxy reads the cleartext start of each CONNECT tunnel: the ClientHello and ServerHello, and up to TLS 1.2 the server certificate and key exchange. It never terminates, decrypts or alters the connection, and it stops reading once the cleartext part is over (at most 64 KiB from the client and 256 KiB from the server), after which the tunnel is copied directly. The bytes come from the workload and from a server it chose, so a workload talking to a server it controls can make the recorded parameters say anything; the record shows what each connection's handshake claimed, which is what an inventory needs, not proof of what was negotiated. Malformed or non-TLS streams end observation without affecting the tunnel. At most 1,024 distinct parameter sets are recorded per run.

## 4. Platform-Aware Policies

Policies are resolved at runtime based on the operating system. The following platform differences affect policy behavior:

| Policy   | macOS-specific                                              | Linux-specific                                                |
| -------- | ----------------------------------------------------------- | ------------------------------------------------------------- |
| npm      | SSL certs: `/usr/local/etc/openssl@3/certs`                 | SSL certs: `/etc/pki/tls/certs`, `/usr/share/ca-certificates` |
| pnpm     | Inherits npm macOS paths                                    | Inherits npm Linux paths                                      |
| yarn     | Inherits npm macOS paths                                    | Inherits npm Linux paths                                      |
| pypi     | Python: `/usr/bin/python3`, lib: `/usr/local/lib/python3.*` | Python: `/usr/bin/python3`, lib: `/usr/lib/python3`           |
| maven    | JDK: `/Library/Java/JavaVirtualMachines`                    | JDK: `/usr/lib/jvm`                                           |
| cargo    | Rustup: `~/.rustup`, cargo: `~/.cargo`                      | Same paths (cross-platform)                                   |
| rubygems | Ruby: `/usr/bin/ruby`, lib: `/usr/lib/ruby`                 | Ruby: `/usr/bin/ruby`, lib: `/usr/lib/ruby`                   |
| composer | PHP: `/usr/bin/php`, lib: `/usr/local/lib/php`              | PHP: `/usr/bin/php`, lib: `/usr/lib/php`                      |
| deno     | Deno: `/usr/local/bin/deno`                                 | Deno: `/usr/bin/deno`                                         |
| gomod    | Go: `/usr/local/go`                                         | Go: `/usr/local/go`                                           |
| bun      | Bun: `/usr/local/bin/bun`                                   | Bun: `/usr/bin/bun`                                           |

**Residual risk:** If the target binary lives in a non-standard location, the policy may not include the correct read path. For example, Homebrew-installed tools on macOS live in `/opt/homebrew/bin` on Apple Silicon, which is not covered by the default policies.

## 4.5 Advanced Sandbox Escape Vector Analysis

This section analyzes advanced threat vectors, escape techniques, and how `safer-exec` counters them.

| Escape Vector                      | Technical Mechanism                                                                                                                                                                      | `safer-exec` Mitigation Status                                                                                                                                                                                                                                                                                                                                       |
| :--------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Kernel Exploits via Namespaces** | Attackers use unprivileged user namespaces (`CLONE_NEWUSER`) to gain local capabilities (e.g., `CAP_NET_ADMIN`) and exploit bugs in kernel subsystems (like `netfilter` or `OverlayFS`). | **Mitigated**: Seccomp blocks `unshare`, denies `CLONE_NEWUSER`/`CLONE_NEWNS` in the `clone()` flag check, and forces `clone3` to ENOSYS so it cannot evade the check. `PR_SET_NO_NEW_PRIVS` prevents privilege transitions. Opt out with `allowUserns`.                                                                                                             |
| **Seccomp Compat-ABI Bypass**      | On x86_64 an attacker issues blocklisted syscalls through the i386 compat gate (`int 0x80`, different syscall numbers) or the x32 ABI to evade a number-only filter.                     | **Mitigated**: The filter pins `seccomp_data.arch` to the native architecture and rejects x32 syscall numbers before inspecting the number, killing any cross-ABI syscall.                                                                                                                                                                                           |
| **Mach Port IPC Exploits (macOS)** | Sandboxed processes target system daemons over Mach IPC to run code in a privileged context.                                                                                             | **Mitigated**: Seatbelt profiles restrict Mach port service lookups to the absolute minimum required bootstrap components.                                                                                                                                                                                                                                           |
| **eBPF/LSM/Perf Monitoring**       | Attackers load eBPF probes, performance monitors (`perf_event_open`), or uprobes to spy on memory, environment variables, or other processes.                                            | **Mitigated**: Seccomp blocks `bpf`, `perf_event_open`, `userfaultfd`, and `keyctl` system calls by default.                                                                                                                                                                                                                                                         |
| **Privilege Escalation**           | Processes use `setuid`, `setgid`, or `setcap` to gain elevated access or modify attributes.                                                                                              | **Mitigated**: Seccomp blocks all `setuid`, `setgid`, `capset`, and `setxattr` / extended attribute manipulation syscalls by default.                                                                                                                                                                                                                                |
| **UDP Socket Evasion**             | Landlock limits network rules to TCP. Attackers use UDP or RAW sockets to bypass restrictions.                                                                                           | **Mitigated**: Active network namespace unsharing (`CLONE_NEWNET`) cuts off all socket families (UDP, Netlink, RAW) entirely.                                                                                                                                                                                                                                        |
| **Sandbox Tool Reuse**             | Attackers execute `safer-exec` or `safer-exec-rt` to spawn secondary escaped tasks.                                                                                                      | **Mitigated**: On Linux and macOS, default `BlockExec` rules automatically register and forbid the execution of the sandbox binary itself. On Windows, a container cannot create another one: `CreateProcessSecurityEnvironment` fails from inside a BaseContainer (verified by `TestWindowsEngineNestedEngineGainsNothing`), so no self-blocking entries are added. |

## 5. Assumptions

1. The Go binary itself is not tampered with. It is statically compiled and shipped with the npm package.
2. The host OS provides working namespace, mount, and cgroup v2 support on Linux.
3. The host OS provides `sandbox-exec` on macOS.
4. On Windows, the host provides the BaseContainer API and the MXC executor shipped with the platform package is not tampered with. A caller who consents to MXC's ACL-modifying fallback tier (`windowsAllowDaclMutation`) accepts that host ACLs change for the duration of each run.
5. DNS resolution returns correct results during the execution window.
6. The target command is a standard executable, not a shell script that modifies its own environment before running.

## 6. Recommendations

1. **Set resource limits for production use.** Resource limits (memory, CPU, process count) default to 0 (unlimited). Configure `maxMemory`, `maxCPUCores`, and `maxProcesses` explicitly. Sensible defaults for most workloads: 512 MB memory, 1.0 CPU core, 100 processes. The timeout defaults to 60 seconds.
2. **Strengthen macOS Seatbelt rules.** Remove the blanket `(allow file-read*)` and `(allow file-write*)` rules. Use only the per-path subpath rules for actual confinement.
3. **Landlock port ranges are now narrowed.** Only explicitly configured ports (defaults: 80, 443) are allowed — the 1-1024 wildcard has been removed.
4. **Include IPv6 in Landlock rules.** The current implementation adds both IPv4 and IPv6 rules, but DNS resolution may return IPv6 addresses that are not included in the allow list.
5. **Add a policy validation step.** Before execution, verify that read paths exist and write paths do not overlap with read paths.
6. **Support policy composition.** Allow combining multiple policies with explicit merge semantics rather than the current additive approach.
7. **Add Homebrew path detection.** On macOS, detect `/opt/homebrew/bin` and `/opt/homebrew/lib` for Apple Silicon installations.
8. **Document fork/exec overhead.** The `traceExec` flag adds seccomp `SIGSYS` trapping on every `execve` call. This adds latency to child process spawns. Document the expected overhead.
9. **Sanitized Environment by Default.** Environment sanitization is enabled by default to strip sensitive environment variables (API keys, tokens, secrets) before sandboxed execution. Use `allowEnvs` to explicitly allow specific host variables when necessary.
10. **Keep `pivot_root` failures as hard errors.** Relying on degraded mode without `pivot_root` weakens filesystem isolation. Use `--strict` to enforce this in production.
