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

| Field            | Type     | Description                       |
| ---------------- | -------- | --------------------------------- |
| `cmd`            | string   | Command to execute                |
| `args`           | string[] | Command arguments                 |
| `env`            | object   | Environment variables             |
| `readPaths`      | string[] | Filesystem read paths             |
| `writePaths`     | string[] | Filesystem write paths            |
| `allowHosts`     | string[] | Hostnames to allow                |
| `allowIPs`       | string[] | Resolved IP addresses             |
| `allowPorts`     | number[] | TCP ports to allow                |
| `disableNetwork` | boolean  | Cut all network access            |
| `maxMemoryMB`    | number   | Memory limit in megabytes         |
| `maxCPUCores`    | number   | CPU limit as fractional cores     |
| `maxProcesses`   | number   | Max child processes               |
| `timeoutMs`      | number   | Hard kill timeout in milliseconds |
| `workingDir`     | string   | Working directory                 |
| `enableAudit`    | boolean  | Enable violation auditing         |
| `enableDiff`     | boolean  | Enable filesystem diffing         |
| `enableLearn`    | boolean  | Enable learning mode              |
| `allowExec`      | string[] | Executables to allow              |
| `blockExec`      | string[] | Executables to block              |
| `blockFork`      | boolean  | Prevent forking                   |
| `traceExec`      | boolean  | Log child processes               |
| `strict`         | boolean  | Treat warnings as hard errors     |
| `sanitizeEnv`    | boolean  | Strip sensitive env vars          |

## 2. Sandbox Mechanisms

### macOS (Seatbelt + RLIMIT)

| Mechanism        | What it enforces                                | How                                              |
| ---------------- | ----------------------------------------------- | ------------------------------------------------ |
| Seatbelt profile | File read/write, network outbound, process exec | Generated `.sb` profile passed to `sandbox-exec` |
| RLIMIT_AS        | Virtual memory cap                              | `syscall.Setrlimit(2)`                           |
| RLIMIT_CPU       | CPU time limit                                  | `syscall.Setrlimit(5)`                           |
| RLIMIT_NPROC     | Child process count                             | `syscall.Setrlimit(6)`                           |

Seatbelt profiles start with `(deny default)` then add allow rules. The profile imports `system.sb` which includes base system rules.

### Linux (Namespaces + Seccomp + Landlock + cgroup v2)

| Mechanism         | What it enforces       | How                                                                                                                    |
| ----------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| User namespace    | UID isolation          | `CLONE_NEWUSER` + `/proc/self` UID/GID mapping                                                                         |
| Mount namespace   | Filesystem isolation   | `CLONE_NEWNS` + tmpfs root + bind mounts                                                                               |
| PID namespace     | Process tree isolation | `CLONE_NEWPID`                                                                                                         |
| UTS namespace     | Hostname isolation     | `CLONE_NEWUTS`                                                                                                         |
| Network namespace | Network isolation      | `CLONE_NEWNET` (when `disableNetwork` is true)                                                                         |
| pivot_root        | Root filesystem swap   | Mounts tmpfs, bind-mounts paths, pivots                                                                                |
| Seccomp-bpf       | Syscall filtering      | Blocks ptrace, kcmp, unshare, mount, pivot_root, syscall, execveat (when TraceExec/BlockExec), clone3 (when BlockFork) |
| Landlock v2       | Network port filtering | Ruleset version 5 (kernel 6.2+) for TCP connect/bind                                                                   |
| cgroup v2         | Resource quotas        | `cpu.max`, `memory.max`, `pids.max`                                                                                    |

## 3. Threats and Attack Vectors

### 3.1 DNS Resolution

**Threat:** Hostnames are resolved at execution time. If a target host changes its IP address between resolution and connection (DNS spoofing, cache poisoning), the sandbox may connect to the wrong IP.

**Impact:** The command reaches an unintended host. The Seatbelt and Landlock rules only filter by IP, not by hostname.

**Mitigation:** The Node.js layer resolves all `allowHosts` to IPs before spawning the Go binary. The Go binary also performs its own resolution on the platform side. Both sets of IPs are included in the rules.

**Residual risk:** DNS changes between resolution and execution window. IPv6 addresses are resolved but Landlock rules on Linux only cover IPv4 by default for the basic path.

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

- **Linux:** A new network namespace is created when `disableNetwork` is true. Landlock v2 rules restrict TCP connections to explicitly configured ports (defaults: 80, 443). No wildcard range for privileged ports.
- **macOS:** Seatbelt rules allow outbound connections. Port filtering uses `remote ip "*:PORT"` patterns.

**Residual risk:**

- macOS Seatbelt port rules use wildcard IP patterns that match any source IP on the target port.

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

**How isolation works:** When `env()` is called, the sandbox sets only PATH, HOME, and the specified variables. When no env is set, the full parent environment is inherited. The `sanitizeEnv` flag strips keys containing TOKEN, PASSWORD, SECRET, API_KEY, CLIENT_SECRET, SESSION, COOKIE, AUTH, or KEY before execution.

**Residual risk:** PATH and HOME are always inherited even when a custom environment is set. This means the command uses the same executable search path and home directory as the parent process. The `sanitizeEnv` check is case-insensitive but does not inspect environment variable values, only key names.

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

**Blocked syscalls:** ptrace, kcmp, unshare, mount, pivot_root, syscall (meta-syscall). When `blockFork` is set: clone, fork, vfork, clone3. When `traceExec` or blockExec wildcard is set: execve, execveat.

**What is not blocked:** All other syscalls including read, write, openat, stat, fstat, lstat, access, connect, socket, recvfrom, sendto, etc.

### 3.8 Fork and Exec Control

**Threat:** The target command spawns unexpected child processes to run postinstall scripts, call external tools, or perform side-channel operations.

**Impact:**

- Postinstall scripts may download additional dependencies or run build steps.
- Child processes inherit the sandbox profile but may access different resources than the parent.
- Forking allows the command to run parallel operations that consume additional resources.

**How isolation works:**

- **macOS:** Seatbelt rules restrict `process-exec` to specified binaries. The `blockFork` flag removes the `process-fork` allow rule. The `traceExec` flag adds `(trace process-exec "*")` to log all child processes.
- **Linux:** Seccomp-bpf filters block `clone` (0/3), `fork` (0/1), `vfork` (0/5), and `execve` (0/32) syscalls for x86_64. The `allowExec` flag filters by executable name. The `blockExec` flag blocks specific binaries.

**Residual risk:**

- Wildcard blocking (`blockExec: ['*']`) blocks all exec calls. This may cause the command to fail if it needs to spawn subprocesses.
- The `traceExec` flag on Linux uses seccomp `SIGSYS` trapping on `execve`. This adds overhead to every child process spawn.
- Fork blocking on macOS uses Seatbelt rules. The command may still fork but the child inherits the same Seatbelt profile.

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
2. Mount new filesystems to discover host state (blocked by seccomp).
3. Trace sibling processes (blocked by seccomp ptrace rule).
4. Pivot root again (blocked by seccomp pivot_root rule, and failure is a hard error).
5. Use clone3 to bypass fork/clone blocking (blocked when BlockFork is enabled).
6. Use execveat to bypass execve blocking (blocked when TraceExec or BlockExec wildcard is enabled).

**Network namespace:**

A new network namespace is created when `disableNetwork` is true. This prevents the sandboxed process from observing host network interfaces, listening sockets, or network connection state. When a new network namespace is active, explicit `allowHosts` / `allowPorts` configuration is required for outbound connectivity.

**macOS escape paths:**

1. Fork child processes that read files (allowed, children inherit the Seatbelt profile).
2. Read environment variables from parent processes (allowed through system.sb).

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
9. **Use `--sanitize-env` in CI/CD environments.** Enable sanitize-env to strip sensitive environment variables (API keys, tokens, secrets) before sandboxed execution.
10. **Keep `pivot_root` failures as hard errors.** Relying on degraded mode without `pivot_root` weakens filesystem isolation. Use `--strict` to enforce this in production.
