# Threat Model: @cdxgen/safer-exec

## Scope

This document covers the sandboxing guarantees, attack surfaces, and failure modes of the `@cdxgen/safer-exec` library. The library enforces OS-level isolation around process execution through a Go binary that uses native mechanisms on macOS and Linux.

## 1. System Overview

### Components

- **Node.js wrapper** (`npm/src/`) resolves policies, performs DNS lookups, serializes the execution config, and spawns the Go binary.
- **Go engine** (`go/cmd/safer-exec/`) reads JSON config from stdin and applies platform-specific isolation.
- **macOS engine** generates Seatbelt profiles, applies RLIMIT quotas, and runs commands through `sandbox-exec`.
- **Linux engine** uses namespace isolation, bind mounts, `pivot_root`, seccomp-bpf filters, Landlock network confinement, and cgroup v2 resource quotas.
- **Learner** (`go/internal/learner/`) traces process behavior via strace (Linux) or Seatbelt trace rules (macOS) to generate policies.
- **Filesystem diff** (`go/internal/fsdiff/`) captures file mutations via OverlayFS (Linux) or pre/post snapshots with SHA-256 hashes (macOS).

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

## 3. Threats and Attack Vectors

### 3.1 DNS Resolution

**Threat:** Hostnames are resolved at execution time. If a target host changes its IP address between resolution and connection (DNS spoofing, cache poisoning), the sandbox may connect to the wrong IP.

**Impact:** The command reaches an unintended host. The Seatbelt and Landlock rules only filter by IP, not by hostname.

**Mitigation:** The Node.js layer resolves all `allowHosts` to IPs before spawning the Go binary. Note, however, that neither platform enforces a remote-IP allowlist at the sandbox layer — see §3.3. Host resolution is used to derive the set of allowed ports and to drive eBPF URL observability on Linux, not to pin connections to specific IPs.

**Residual risk:** Because egress is filtered by port rather than by IP (§3.3), DNS spoofing/rebinding does not change the effective exposure: any host is already reachable on an allowed port. For strict egress control, use `disableNetwork` or an external firewall/eBPF egress policy.

### 3.2 Filesystem Escapes

**Threat:** The target command reads files outside the specified paths, writes to unexpected locations, or follows symlinks to discover information.

**Impact:**

- Reading files outside allowed paths may leak environment configuration or credentials.
- Writing to files outside allowed paths may modify project state or overwrite data.

**How isolation works:**

- **Linux:** A tmpfs root is mounted. Read paths are bind-mounted read-only. Write paths are bind-mounted read-write. The process only sees mounted paths plus `/proc` and `/sys`.
- **macOS:** The Seatbelt profile allows file reads and writes for all paths by default, then adds explicit subpath rules for the specified paths. The base `system.sb` profile is imported.

**Mitigation:** By default, `safer-exec` avoids blanket allows and instead restricts macOS file operations to a standard minimal set. When no custom paths are specified, the sandbox profile generates rules allowing reading of standard system directories and the working directory, and restricts write access exclusively to temporary directories (e.g. `/tmp`, `/private/tmp`). If explicit read/write paths are supplied, only those paths (plus system directories) are permitted.

### 3.3 Network Escapes

**Threat:** The target command connects to hosts or ports outside the allow list.

**Impact:** Data exfiltration, calling APIs that trigger side effects, or connecting to local services for information gathering.

**How isolation works:**

- **Linux:** A new network namespace is created when `disableNetwork` is true — this is the only mechanism that fully severs egress. When the network is not disabled, Landlock restricts TCP connections to the configured ports. Landlock filters by port, **not** by IP.
- **macOS:** Seatbelt port filtering uses `remote ip "*:PORT"` patterns.

**Egress is filtered by port, not by host/IP (important).** Neither Landlock
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

- Within an allowed port, any remote host is reachable on both platforms. True
  per-IP egress confinement requires `disableNetwork` (full cut) or a
  host-level firewall/eBPF egress policy outside `safer-exec`.

### 3.4 Resource Exhaustion

**Threat:** The target command consumes unbounded memory, CPU, or spawns excessive child processes.

**Impact:** Slows down the host system, causes OOM kills of sibling processes, or triggers fork bombs.

**How isolation works:**

- **Linux:** cgroup v2 enforces `memory.max`, `cpu.max`, and `pids.max`.
- **macOS:** RLIMIT quotas enforce `RLIMIT_AS` (address space), `RLIMIT_CPU` (CPU seconds), and `RLIMIT_NPROC` (process count).

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

**Threat:** Learning mode runs the command without sandbox restrictions, then generates a policy from observed behavior.

**Impact:** The learned policy may be incomplete if the command behaves differently under observation (Heisenberg effect) or if the strace/trace parser misses certain syscalls.

**How it works:**

- **Linux with strace:** Traces openat, open, readlink, connect, sendto, recvfrom, stat variants, and access. Parses the output to extract file paths and network connections.
- **Linux without strace:** Takes pre/post filesystem snapshots and scans /proc/net/tcp for network connections.
- **macOS:** Uses Seatbelt trace rules to log file reads, file writes, network outbound, and process exec to a trace file.

**Residual risk:** The strace-based learner may miss indirect file accesses (e.g., files accessed through memory-mapped I/O). The basic learner only captures network connections active at the moment of the /proc/net/tcp scan, missing transient connections.

### 3.10 Filesystem Diff

**Threat:** The diff mechanism misses file changes or reports false positives.

**Impact:** Incorrect understanding of what files the command modified.

**How it works:**

- **Linux:** OverlayFS captures writes in an upper directory. The diff compares pre/post snapshots.
- **macOS:** Pre/post snapshots walk the write paths and compare SHA-256 hashes, file sizes, and permission modes.

**Residual risk:** The diff only covers configured write paths. Changes to files outside those paths are not captured. The snapshot walks skip symlinks and special files.

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
By default, the sandboxed process is prevented from listening on any network port (including local loopback `lo`) on both macOS and Linux. Listening or binding to specific IP addresses or ports must be explicitly permitted using `allowListen` / `--allow-listen`.

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

| Escape Vector                      | Technical Mechanism                                                                                                                                                                      | `safer-exec` Mitigation Status                                                                                                                                                                                                                           |
| :--------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Kernel Exploits via Namespaces** | Attackers use unprivileged user namespaces (`CLONE_NEWUSER`) to gain local capabilities (e.g., `CAP_NET_ADMIN`) and exploit bugs in kernel subsystems (like `netfilter` or `OverlayFS`). | **Mitigated**: Seccomp blocks `unshare`, denies `CLONE_NEWUSER`/`CLONE_NEWNS` in the `clone()` flag check, and forces `clone3` to ENOSYS so it cannot evade the check. `PR_SET_NO_NEW_PRIVS` prevents privilege transitions. Opt out with `allowUserns`. |
| **Seccomp Compat-ABI Bypass**      | On x86_64 an attacker issues blocklisted syscalls through the i386 compat gate (`int 0x80`, different syscall numbers) or the x32 ABI to evade a number-only filter.                     | **Mitigated**: The filter pins `seccomp_data.arch` to the native architecture and rejects x32 syscall numbers before inspecting the number, killing any cross-ABI syscall.                                                                               |
| **Mach Port IPC Exploits (macOS)** | Sandboxed processes target system daemons over Mach IPC to run code in a privileged context.                                                                                             | **Mitigated**: Seatbelt profiles restrict Mach port service lookups to the absolute minimum required bootstrap components.                                                                                                                               |
| **eBPF/LSM/Perf Monitoring**       | Attackers load eBPF probes, performance monitors (`perf_event_open`), or uprobes to spy on memory, environment variables, or other processes.                                            | **Mitigated**: Seccomp blocks `bpf`, `perf_event_open`, `userfaultfd`, and `keyctl` system calls by default.                                                                                                                                             |
| **Privilege Escalation**           | Processes use `setuid`, `setgid`, or `setcap` to gain elevated access or modify attributes.                                                                                              | **Mitigated**: Seccomp blocks all `setuid`, `setgid`, `capset`, and `setxattr` / extended attribute manipulation syscalls by default.                                                                                                                    |
| **UDP Socket Evasion**             | Landlock limits network rules to TCP. Attackers use UDP or RAW sockets to bypass restrictions.                                                                                           | **Mitigated**: Active network namespace unsharing (`CLONE_NEWNET`) cuts off all socket families (UDP, Netlink, RAW) entirely.                                                                                                                            |
| **Sandbox Tool Reuse**             | Attackers execute `safer-exec` or `safer-exec-rt` to spawn secondary escaped tasks.                                                                                                      | **Mitigated**: Default `BlockExec` rules automatically register and forbid the execution of the sandbox binary itself.                                                                                                                                   |

## 5. Assumptions

1. The Go binary itself is not tampered with. It is statically compiled and shipped with the npm package.
2. The host OS provides working namespace, mount, and cgroup v2 support on Linux.
3. The host OS provides `sandbox-exec` on macOS.
4. DNS resolution returns correct results during the execution window.
5. The target command is a standard executable, not a shell script that modifies its own environment before running.

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
