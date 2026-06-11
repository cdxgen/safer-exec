# @cdxgen/safer-exec

OS-level sandboxing with tracing, auditing, and learning mode for arbitrary binaries.

On macOS the Go binary generates Seatbelt profiles and runs commands through `sandbox-exec`. On Linux it uses namespace isolation, bind mounts, `pivot_root`, seccomp-bpf filters, Landlock network confinement, and cgroup v2 resource quotas.

## Install

```bash
npm install @cdxgen/safer-exec
```

## CLI

The CLI provides terminal access to all sandbox features.

```bash
# Run with a built-in policy
safer-exec --policy=npm -- npm install

# Resource limits
safer-exec --max-memory=512 --max-cpu=1.0 -- npm run build

# Disable network, enable auditing
safer-exec --disable-network --audit -- cat package.json

# Filesystem diffing
safer-exec --diff --write-path=/tmp -- sh -c "echo hello > /tmp/out.txt"

# Learning mode
safer-exec --learn --learn-output=policy.json -- npm install

# Fork and exec control
safer-exec --allow-exec=node --allow-exec=npx -- npm run build
safer-exec --block-exec=sh -- npm install
safer-exec --block-fork -- npm install
safer-exec --trace-exec -- npm install

# Strip sensitive environment variables
safer-exec --sanitize-env -- npm install
```

Full help: `safer-exec --help`.

## Fluent API

```js
import { SaferExec } from "@cdxgen/safer-exec";

const result = await new SaferExec()
  .allowHosts("registry.npmjs.org", "api.github.com")
  .readPaths("/usr", "/etc/ssl/certs")
  .writePaths(process.cwd() + "/node_modules")
  .env("NODE_ENV", "production")
  .maxMemory(512)
  .disableNetwork()
  .run("npm", ["install"]);

console.log(result.exitCode, result.stdout);
```

Every configuration method returns `this` for chaining. The `.run()` method returns a promise that resolves to an `ExecResult` object containing `stdout`, `stderr`, `exitCode`, and optional `auditLog`, `fsDiff`, or `learnedPolicy` fields depending on which features are enabled.

## API Reference

### Constructor

`new SaferExec(options?)`

| Option               | Type       | Default         | Description                                                                                          |
| -------------------- | ---------- | --------------- | ---------------------------------------------------------------------------------------------------- |
| `allowHosts`         | `string[]` | `[]`            | Hostnames to allow network access to                                                                 |
| `allowURLRules`      | `Object[]` | `[]`            | Fine-grained URL rules — exact, wildcard, regex, path, method (Linux only, requires `traceHTTPURLs`) |
| `readPaths`          | `string[]` | `[]`            | Filesystem paths to read from                                                                        |
| `writePaths`         | `string[]` | `[]`            | Filesystem paths to write to                                                                         |
| `env`                | `Object`   | `{}`            | Environment variables to set                                                                         |
| `disableNetwork`     | `boolean`  | `false`         | Cut all network access                                                                               |
| `maxMemoryMB`        | `number`   | `512`           | Memory limit in megabytes (default: 512)                                                             |
| `maxCPUCores`        | `number`   | `1.0`           | CPU limit as fractional cores (default: 1.0)                                                         |
| `maxProcesses`       | `number`   | `100`           | Max child processes — anti-fork bomb (default: 100)                                                  |
| `timeoutMs`          | `number`   | `60000`         | Hard kill timeout in milliseconds (default: 60000)                                                   |
| `workingDir`         | `string`   | `process.cwd()` | Working directory                                                                                    |
| `binaryPath`         | `string`   | auto-resolved   | Override Go binary path                                                                              |
| `enableAudit`        | `boolean`  | `false`         | Enable violation auditing                                                                            |
| `allowPorts`         | `number[]` | `[]`            | TCP ports to allow                                                                                   |
| `enableDiff`         | `boolean`  | `false`         | Enable filesystem mutation diffing                                                                   |
| `enableLearn`        | `boolean`  | `false`         | Enable behavioral auto-profiling                                                                     |
| `allowExec`          | `string[]` | `[]`            | Executables the command is allowed to run                                                            |
| `blockExec`          | `string[]` | `[]`            | Executables to block from running                                                                    |
| `blockFork`          | `boolean`  | `false`         | Prevent forking new processes                                                                        |
| `traceExec`          | `boolean`  | `false`         | Log every child process spawned                                                                      |
| `strict`             | `boolean`  | `false`         | Treat sandbox setup warnings as errors                                                               |
| `allowCrypto`        | `boolean`  | `true`          | Permit cryptographic library/device access                                                           |
| `blockCrypto`        | `boolean`  | `false`         | Block system crypto libraries access                                                                 |
| `blockCryptoEntropy` | `boolean`  | `false`         | Block entropy (/dev/random) device access                                                            |
| `detectFIPS`         | `boolean`  | `false`         | Enable FIPS compliance checks/logging                                                                |
| `strictFIPS`         | `boolean`  | `false`         | Force strict FIPS validation                                                                         |
| `allowGPU`           | `boolean`  | `false`         | Permit process to utilize host GPU nodes                                                             |
| `blockTPM`           | `boolean`  | `false`         | Restrict hardware access to TPM device                                                               |
| `spoofAntiVM`        | `boolean`  | `false`         | Intercept debugger & virtualization checks                                                           |
| `traceLibraries`     | `boolean`  | `false`         | Track dynamic library loading (opt-in)                                                               |
| `traceHTTPURLs`      | `boolean`  | `false`         | Capture HTTPS request URLs via eBPF uprobes (Linux only, requires CAP_BPF)                           |
| `sanitizeEnv`        | `boolean`  | `false`         | Strip sensitive env vars (TOKEN, SECRET, etc.) before passing to sandbox                             |

### Instance Methods

All methods return `this` for chaining except `.run()`.

| Method                  | Description                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| `.applyPolicy(name)`    | Apply a pre-defined policy. Throws if unknown.                                                   |
| `.allowHosts(...hosts)` | Add hostnames to the network allow list                                                          |
| `.allowUrls(...urls)`   | Add fine-grained URL rules — strings or `{host,protocol,path,methods,port}` objects (Linux only) |
| `.readPaths(...paths)`  | Add filesystem read paths                                                                        |
| `.writePaths(...paths)` | Add filesystem write paths                                                                       |
| `.env(key, value)`      | Set an environment variable                                                                      |
| `.disableNetwork()`     | Disable all network access                                                                       |
| `.maxMemory(mb)`        | Set memory limit in megabytes                                                                    |
| `.maxCPUCores(cores)`   | Set CPU limit as fractional cores (e.g. 0.5)                                                     |
| `.maxProcesses(count)`  | Set maximum child process count                                                                  |
| `.timeout(ms)`          | Set hard kill timeout in milliseconds                                                            |
| `.binaryPath(path)`     | Override the Go binary path                                                                      |
| `.workingDir(dir)`      | Set the working directory                                                                        |
| `.enableAudit()`        | Enable sandbox violation auditing                                                                |
| `.allowPorts(...ports)` | Set allowed TCP ports                                                                            |
| `.enableDiff()`         | Enable filesystem mutation diffing                                                               |
| `.enableLearn()`        | Enable behavioral auto-profiling                                                                 |
| `.allowExec(...cmds)`   | Restrict which executables can run                                                               |
| `.blockExec(...cmds)`   | Block specific executables from running                                                          |
| `.blockFork()`          | Prevent the command from forking new processes                                                   |
| `.traceExec()`          | Log every child process spawned                                                                  |
| `.strict()`             | Treat sandbox setup warnings as hard errors                                                      |
| `.resolveSymlinks()`    | Resolve target command symlink in PATH                                                           |
| `.allowCrypto(allow)`   | Allow/disallow cryptographic operations                                                          |
| `.blockCrypto()`        | Restrict system cryptographic libraries                                                          |
| `.blockCryptoEntropy()` | Restrict entropy devices (/dev/random)                                                           |
| `.detectFIPS()`         | Log and watch for FIPS lookups                                                                   |
| `.strictFIPS()`         | Restrict runtime to strict FIPS compliant mode                                                   |
| `.allowGPU(allow)`      | Allow/disallow access to host GPU nodes                                                          |
| `.blockTPM()`           | Restrict hardware access to TPM device                                                           |
| `.spoofAntiVM()`        | Intercept debugger & virtualization checks                                                       |
| `.traceLibraries()`     | Track dynamic library loading (LD_AUDIT on Linux, audit events on macOS)                         |
| `.traceHTTPURLs()`      | Capture HTTPS request URLs/methods via eBPF TLS uprobes (Linux only)                             |
| `.sanitizeEnv(val)`     | Strip sensitive env vars (TOKEN, SECRET, AUTH, etc.) before passing to sandbox                   |

### `.run(cmd, args?)`

Execute the sandboxed command. Returns `Promise<ExecResult>`:

```ts
interface Entry {
  path: string;
  size: number;
}

interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut?: boolean;
  auditLog?: Array<{ type: string; target: string; detail?: string }>;
  fsDiff?: { added: Entry[]; modified: Entry[]; deleted: Entry[] };
  learnedPolicy?: {
    readPaths: string[];
    writePaths: string[];
    allowIPs: string[];
    allowPorts: number[];
    envVars: string[];
    allowCrypto?: boolean;
    blockCrypto?: boolean;
    blockCryptoEntropy?: boolean;
    detectFIPS?: boolean;
    strictFIPS?: boolean;
    fipsDetected?: boolean;
    cmd: string;
    args: string[];
  };
}
```

### `.runPipe(cmd, args?, options?)`

Execute the sandboxed command, streaming stdout and stderr directly in real-time as the command runs. This is the recommended execution method for long-running or interactive commands (like build scripts, test runners, or command-line wrappers) where buffering output is undesirable.

```ts
interface PipeOptions {
  stdout?: NodeJS.WritableStream | null; // Stream to pipe stdout to (defaults to process.stdout, null to suppress)
  stderr?: NodeJS.WritableStream | null; // Stream to pipe stderr to (defaults to process.stderr, null to suppress)
}
```

Returns `Promise<Omit<ExecResult, 'stdout' | 'stderr'>>`. Captured structured output (filesystem diffs, learned policies, profile logs) is written to a temporary file instead of stdout and parsed after exit.

## Architecture

The Node.js layer handles policy resolution, DNS lookups, and config serialization. It pipes a JSON `ExecConfig` to the Go binary over stdin. The Go binary reads the config and delegates to a platform-specific engine.

**macOS path:**

1. Generate a Seatbelt profile from the config
2. Apply RLIMIT quotas (memory via `RLIMIT_AS`, CPU via `RLIMIT_CPU`, process count via `RLIMIT_NPROC`)
3. Execute `sandbox-exec -f <profile> <cmd> <args...>`

**Linux path (full isolation):**

1. Probe for user namespace availability; fall back to reduced mode if restricted
2. Fork self with `--init` flag and config in `SAFER_EXEC_CONFIG` env var
3. Unshare namespaces (user, mount, PID, UTS, network)
4. Map UID/GID to root inside the user namespace for mount privileges
5. Create cgroup v2 hierarchy for resource quotas
6. Mount tmpfs root, bind-mount read/write paths, mount proc and sysfs
7. Apply Landlock v2 network confinement rules (only explicitly configured ports, no 1-1024 wildcard)
8. Apply seccomp-bpf filter blocking ptrace, kcmp, unshare, mount, pivot_root, execveat (when TraceExec), clone3 (when BlockFork)
9. `pivot_root` to the new filesystem tree (failure is a hard error)
10. `execve` the target command

**Linux path (reduced isolation — user namespaces unavailable):**

1. Fork self with `--init-reduced` flag (no unshare)
2. Create cgroup v2 hierarchy for resource quotas
3. Apply Landlock v2 network confinement rules
4. Apply seccomp-bpf syscall filter
5. `execve` the target command (host filesystem fully visible)

Communication between layers uses marker-prefixed JSON on stdout:

- `FSDIFF:` prefix for filesystem diff reports
- `LEARNED:` prefix for learned policy output
- Audit entries are written as JSON lines to stderr

## Standalone SEA Binaries

For environments without Node.js, or when you want to execute sandboxed commands directly using a standalone binary, pre-built Single Executable Application (SEA) binaries are published to GitHub Releases.

These binaries are fully self-contained, wrapping Node.js and the statically compiled Go engine into a single executable.

### Supported Platforms and Architectures

- **macOS Intel (`darwin-amd64`)**
- **macOS Apple Silicon (`darwin-arm64`)**
- **Linux GNU (`linux-amd64`, `linux-arm64`)**
- **Linux Musl (`linux-amd64-musl`, `linux-arm64-musl`)**

### Download and Verification

You can download and verify the integrity of the standalone binaries using `curl` and `sha256`:

```bash
# Set parameters
OS="linux" # or "darwin"
ARCH="amd64" # or "arm64"
LIBC="" # or "-musl" for alpine/musl distributions
VERSION="0.5.0"

# Download binary and checksum files
curl -L -O "https://github.com/cdxgen/safer-exec/releases/download/v${VERSION}/safer-exec-${OS}-${ARCH}${LIBC}"
curl -L -O "https://github.com/cdxgen/safer-exec/releases/download/v${VERSION}/safer-exec-${OS}-${ARCH}${LIBC}.sha256"

# Verify checksum
if [[ "$OS" == "darwin" ]]; then
  shasum -a 256 -c "safer-exec-${OS}-${ARCH}${LIBC}.sha256"
else
  sha256sum -c "safer-exec-${OS}-${ARCH}${LIBC}.sha256"
fi

# Make binary executable and run
chmod +x "safer-exec-${OS}-${ARCH}${LIBC}"
./safer-exec-${OS}-${ARCH}${LIBC} --version
```

## Prerequisites

**macOS:** Works out of the box using the built-in `sandbox-exec`.

**Linux:**

- **Learning Mode** requires `strace` to be installed (`sudo apt install strace`).
- On most distributions (Debian, Fedora, Arch, Alpine/Musl, Ubuntu ≤ 23.10) safer-exec works out of the box with full namespace isolation.
- On **Ubuntu 24.04+** user namespace creation is restricted by AppArmor by default. safer-exec automatically detects this and falls back to **reduced isolation mode** (seccomp-bpf + Landlock only; no filesystem, PID, or network namespace isolation). A warning is printed. See [Full Isolation on Ubuntu 24.04+](#full-isolation-on-ubuntu-2404) below to restore full isolation with an AppArmor profile.

**Linux Resource Limits (Cgroup v2):**
By default, `systemd`-based distributions do not allow unprivileged users to apply CPU, Memory, or PID limits. If you want to use `.maxMemory()`, `.maxCPUCores()`, or `.maxProcesses()` on systemd distributions without running as `root`, you must enable `systemd` user delegation on your machine:

```bash
# Enable CPU, Memory, and PID delegation for user sessions
sudo mkdir -p /etc/systemd/system/user@.service.d
sudo sh -c 'echo -e "[Service]\nDelegate=cpu memory pids" > /etc/systemd/system/user@.service.d/delegate.conf'
sudo systemctl daemon-reload

# You may need to log out and log back in for changes to take effect.
```

_Note on Alpine Linux (OpenRC):_ Alpine Linux uses OpenRC as the init system instead of systemd. OpenRC mounts cgroup v2 automatically at `/sys/fs/cgroup`. The systemd user delegation configuration above is not required; resource limits will be applied directly to the cgroup hierarchy.

_Note: If cgroup v2 delegation is not configured or available (e.g. inside restricted Docker containers), `safer-exec` will gracefully skip the resource limits and print a warning, but will still enforce all other sandbox constraints (filesystem, network, syscalls)._

## Linux Isolation Modes

safer-exec runs in one of two modes on Linux, chosen automatically at startup:

| Mode                   | Filesystem isolation      | PID namespace | Network namespace          | Seccomp | Landlock | Cgroup limits |
| ---------------------- | ------------------------- | ------------- | -------------------------- | ------- | -------- | ------------- |
| **Full** (default)     | ✓ bind-mount + pivot_root | ✓             | ✓ (if `--disable-network`) | ✓       | ✓        | ✓             |
| **Reduced** (fallback) | ✗                         | ✗             | ✗                          | ✓       | ✓        | ✓             |

Full mode requires the ability to create unprivileged user namespaces (`unshare -U`). Reduced mode is used automatically when this is unavailable, and a warning is printed to stderr:

```
safer-exec: warning: user namespaces unavailable — running with reduced isolation (seccomp + landlock only; no filesystem, PID, or network namespace isolation). Install the safer-exec AppArmor profile for full isolation.
```

In reduced mode, seccomp-bpf syscall filtering and Landlock network confinement still apply, so fork/exec blocking, syscall restrictions, and per-host network allow-lists remain effective. Filesystem isolation (restricting visible paths via bind mounts) and `--diff` are not available.

## Full Isolation on Ubuntu 24.04+

Ubuntu 24.04 (and later) restricts unprivileged user namespace creation by default via AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`). The restriction is per-binary: you can grant safer-exec permission without changing the system-wide setting.

### Install the AppArmor profile

```bash
sudo tee /etc/apparmor.d/safer-exec > /dev/null << 'EOF'
# AppArmor profile for safer-exec — grants permission to create
# unprivileged user namespaces required for full sandbox isolation.
abi <abi/4.0>,
include <tunables/global>

profile safer-exec /usr/local/bin/safer-exec flags=(unconfined) {
  userns,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/safer-exec
```

Adjust the path (`/usr/local/bin/safer-exec`) to wherever the binary is installed. When using the npm package, the binary lives inside `node_modules/@cdxgen/safer-exec-linux-*/bin/safer-exec` — you can use a glob pattern:

```bash
sudo tee /etc/apparmor.d/safer-exec > /dev/null << 'EOF'
abi <abi/4.0>,
include <tunables/global>

profile safer-exec /** {
  userns,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/safer-exec
```

The profile takes effect immediately (no reboot required). Verify with:

```bash
# Should show the profile loaded
sudo aa-status | grep safer-exec
```

### Alternative 1: Elevate ONLY the SEA binary

```
sudo setcap 'cap_bpf,cap_perfmon,cap_sys_ptrace,cap_sys_admin+eip' /usr/local/bin/safer-exec
```

### Alternativ 2: system-wide sysctl (not recommended)

If installing an AppArmor profile is not an option (e.g., in ephemeral CI environments), you can disable the restriction globally:

```bash
# Temporary (lost on reboot)
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

# Permanent
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl -p /etc/sysctl.d/99-userns.conf
```

This weakens a system-wide security policy. Prefer the AppArmor profile for production systems.

## Pre-built Policies

Apply a hardened profile for common package managers. User-defined settings take precedence over policy defaults when both are present.

```js
const result = await new SaferExec().applyPolicy("npm").run("npm", ["install"]);
```

Available policies: `npm`, `pnpm`, `yarn`, `pypi`, `maven`, `cargo`, `rubygems`, `composer`, `deno`, `gomod`, `bun`.

Each policy is platform-aware. Paths are resolved at runtime based on the operating system. For example, the npm policy detects the Node binary directory, resolves SSL certificate paths for macOS versus Linux, and sets registry host allow lists for npm, Yarn, and JS CDN endpoints.

Policies that cover JavaScript package managers include `blockFork: true` and `blockExec: ['*']` by default to prevent postinstall scripts from spawning subprocesses.

## Fork and Exec Control

Restrict which executables the sandboxed process can run, block specific binaries, prevent forking, or trace all child processes.

```js
// Allow only specific executables
const result = await new SaferExec()
  .allowExec("node", "npx", "corepack")
  .run("npm", ["install"]);

// Block specific executables (takes precedence over allow list)
const result = await new SaferExec()
  .blockExec("sh", "bash")
  .run("npm", ["install"]);

// Prevent all forking
const result = await new SaferExec().blockFork().run("npm", ["install"]);

// Log every child process spawned
const result = await new SaferExec().traceExec().run("npm", ["install"]);

console.log(result.auditLog); // process-exec entries with command lines and PIDs
```

On macOS these map to Seatbelt `process-exec` and `process-fork` rules. On Linux they add seccomp-bpf filters for `clone`, `fork`, `vfork`, and `execve` syscalls.

## Filesystem Diffing

Track exactly which files a command creates, modifies, or deletes.

```js
const result = await new SaferExec()
  .writePaths(process.cwd())
  .enableDiff()
  .run("npm", ["install"]);

console.log(result.fsDiff.added); // newly created files
console.log(result.fsDiff.modified); // changed files
console.log(result.fsDiff.deleted); // removed files
```

On Linux this uses OverlayFS to capture writes in a temporary upper directory. On macOS it compares pre and post execution snapshots of the write paths using SHA-256 content hashes.

## Learning Mode

Run a command in permissive mode and get back a strict minimal policy based on observed behavior.

```js
const result = await new SaferExec().enableLearn().run("npm", ["install"]);

console.log(result.learnedPolicy);
// { readPaths: ["/usr", "/etc"], writePaths: ["./node_modules"],
//   allowIPs: ["93.184.216.34"], allowPorts: [443] }
```

On Linux the learner uses strace to capture file opens, stat calls, and network connects. If strace is not available it falls back to pre/post filesystem snapshots and `/proc/net/tcp` scanning. On macOS it uses Seatbelt trace rules.

## Audit Mode

Capture sandbox violations and resource accesses as structured log entries.

```js
const result = await new SaferExec()
  .allowHosts("api.github.com")
  .readPaths("/usr", "/etc/ssl/certs")
  .writePaths("/tmp/output")
  .maxMemory(256)
  .enableAudit()
  .run("curl", ["https://api.github.com"]);

console.log(result.auditLog);
```

Each audit entry contains a type (`file-read`, `file-write`, `network-connect`, `syscall`, `process-exec`), the target resource, and optional details.

## Library Tracing (Dynamic Link Observability)

Enable opt-in dynamic library load tracking to observe which shared libraries a sandboxed process loads at runtime.

```js
const result = await new SaferExec()
  .traceLibraries()
  .enableAudit()
  .run("node", ["myapp.js"]);

// On Linux: auditLog contains {"type":"lib-load","target":"/lib/x86_64-linux-gnu/libc.so.6"} entries
// On macOS: stderr contains trace-libraries diagnostic; .dylib loads appear as file-read audit events
console.log(result.auditLog.filter((e) => e.type === "lib-load"));
```

**Platform behavior:**

| Platform  | Mechanism                                                           | Scope                                                                                                     |
| --------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **Linux** | `LD_AUDIT` (glibc) or `/proc/<pid>/maps` monitor fallback (musl)    | All ELF shared libraries loaded, including transitive dependencies and `dlopen` calls                     |
| **macOS** | Seatbelt audit (file-read events for `.dylib` / `.framework` paths) | Library paths as captured by Seatbelt trace; `DYLD_INSERT_LIBRARIES` is blocked by macOS hardened runtime |

On Linux (glibc), `safer-exec` ships with a precompiled C audit helper embedded inside the binary and injects it via `LD_AUDIT`. On Linux systems running `musl` libc (like Alpine Linux) where `LD_AUDIT` is not supported, it automatically falls back to a high-precision recursive `/proc/<pid>/maps` scanner. Each loaded library emits a `{"type":"lib-load","target":"<path>"}` JSON entry to stderr, which `runner.js` parses into `result.auditLog`.

**CLI:**

```bash
# Trace library loads on Linux (works out-of-the-box on both glibc and musl)
safer-exec --trace-libraries -- node myapp.js

# Output dynamic library list directly to a JSON file (automatically enables trace-libraries)
safer-exec --trace-output-file=libs.json -- node myapp.js

# Extract the helper library to a specific directory (implies trace-libraries)
safer-exec --trace-temp-dir=/tmp/custom-temp-dir -- node myapp.js

# Combine with audit output
safer-exec --trace-libraries --audit -- python3 script.py
```

> [!NOTE]
> `--trace-libraries` and `--trace-output-file` work out-of-the-box on Linux (using the embedded precompiled helper library or proc maps fallback) and macOS (using the existing Seatbelt audit infrastructure). On Linux, the precompiled LD_AUDIT helper is extracted to a temporary folder before execution. The path is automatically negotiated checking common CI temp variables (`RUNNER_TEMP`, `WORKSPACE_TMP`, `CI_PROJECT_DIR`, etc.) or working directories, but you can explicitly specify it via `--trace-temp-dir` (CLI) or `.traceTempDir(dir)` (JS API). No external compiler is required.

## HTTPS URL Tracing (`--trace-http-urls`)

Enable opt-in capture of outbound HTTPS request URLs and methods by attaching eBPF uprobes to TLS write functions. Because the uprobes fire _before_ encryption, the plaintext request headers are captured without needing a CA certificate or man-in-the-middle proxy.

Both **HTTP/1.x** and **HTTP/2** are supported:

- HTTP/1.x: request line and `Host` header are parsed directly from the plaintext write buffer.
- HTTP/2: HEADERS frames are decoded using HPACK (RFC 7541). The tracer maintains a per-connection dynamic compression table (keyed by the `SSL*` pointer) so headers compressed with dynamic table references are correctly decoded across successive writes on the same connection.

**Platform requirements:**

- Linux kernel ≥ 5.8 (BPF ring buffer support), `amd64` or `arm64`
- `CAP_BPF` + `CAP_PERFMON` in the init user namespace (typically requires running as root or with those capabilities granted)
- Supported TLS libraries: OpenSSL/BoringSSL (`libssl.so`), GnuTLS (`libgnutls.so`), Go's built-in `crypto/tls`

When requirements are not met the flag is silently ignored; execution continues without HTTP tracing.

```bash
# Capture HTTPS URLs during audit mode
safer-exec --trace-http-urls --audit -- node index.js

# Capture HTTPS URLs during learn mode (records into policy file's httpAccess section)
safer-exec --learn --learn-output=policy.json --trace-http-urls -- npm install
```

```js
// JavaScript API
const result = await new SaferExec()
  .traceHTTPURLs()
  .enableAudit()
  .run("node", ["index.js"]);

// result.auditLog entries with type "http-request":
// { type: "http-request", method: "GET", host: "registry.npmjs.org", path: "/-/npm/v1/security/advisories/bulk", protocol: "https", port: 443, query: "version=18", body: "payload", source: "ssl_write_uprobe", pid: 12345 }

// Real-Time Event-Driven Auditing (e.g. for long-running HTTP servers)
const exec = new SaferExec()
  .traceHTTPURLs()
  .enableAudit()
  .suppressLibLoadStderr(); // Suppresses raw logs from printing to process.stderr

exec.on("audit", (entry) => {
  if (entry.type === "http-request") {
    console.log(
      `[Real-time] HTTP ${entry.method} ${entry.protocol}://${entry.host}:${entry.port}${entry.path}${entry.query ? "?" + entry.query : ""}`,
    );
  } else {
    console.log(`[Real-time] ${entry.type}: ${entry.target}`);
  }
});

await exec.run("node", ["index.js"]);
```

Each captured request emits a `{"type":"http-request","method":"...","host":"...","path":"...","protocol":"...","port":...,"query":"...","body":"...","source":"...","pid":...}` JSON line to stderr (audit log). In `--learn` mode, deduplicated entries are also written to the `httpAccess` array in the generated policy file.

| Source value       | TLS library intercepted                |
| ------------------ | -------------------------------------- |
| `ssl_write_uprobe` | OpenSSL / BoringSSL (`libssl.so`)      |
| `go_tls_uprobe`    | Go built-in `crypto/tls` (Go binaries) |
| `gnutls_uprobe`    | GnuTLS (`libgnutls.so`)                |

## URL Access-Control Rules (`allowUrls` / `--allow-url`)

When `traceHTTPURLs()` is enabled on Linux, you can layer **URL-level allow rules** on top of the coarser `allowHosts` list. Rules are matched against every HTTPS request captured by the eBPF tracer. Requests that match _at least one_ rule are allowed; anything else is logged as a `url-violation` audit entry.

Ports declared inside URL rules are **automatically added** to the Landlock network allow-list, so you do not need to call `.allowPorts()` separately.

> [!NOTE]
> `allowUrls` is a **Linux-only observational enforcement** feature. On macOS a warning is emitted and the rules are ignored. Enforcement currently surfaces violations as audit log entries; network-level blocking still depends on `allowHosts` / `allowPorts` / `disableNetwork()`.

### Pattern types

Each rule can be a URL **string** (parsed automatically) or a **plain object**. All fields are optional — omitting a field means "match anything".

```ts
interface AllowURLRule {
  host?: string; // hostname pattern (see matching modes below)
  protocol?: string; // "https" | "http"  (default: any)
  port?: number; // TCP port           (default: any)
  path?: string; // path pattern        (default: any)
  methods?: string[]; // HTTP verbs          (default: any)
}
```

#### 1. Exact match

Plain strings match the full hostname or path exactly (case-insensitive).

```js
.allowUrls({ host: 'registry.npmjs.org', protocol: 'https' })
// matches: https://registry.npmjs.org/...
// rejects: https://api.npmjs.org/...
```

#### 2. Wildcard (`*`)

A single `*` matches one label in a hostname (cannot span dots) or any sequence of characters in a path.

```js
// Hostname wildcard — single subdomain level only
.allowUrls({ host: '*.npmjs.org' })
// matches: registry.npmjs.org
// rejects: a.b.npmjs.org        ← * does not span dots

// Path glob
.allowUrls({ host: 'registry.npmjs.org', path: '/-/npm/v1/*' })
// matches: /-/npm/v1/security/advisories/bulk
// rejects: /express              ← wrong prefix
```

You can also pass a full URL string and it will be parsed automatically:

```js
.allowUrls('https://*.npmjs.org/')
.allowUrls('https://registry.npmjs.org/-/npm/v1/*')
```

#### 3. Regex (prefix `~`)

Patterns that start with `~` are treated as regular expressions. The `~` is stripped before compilation.

```js
// Regex hostname
.allowUrls({ host: '~^registry\.npmjs\.org$', protocol: 'https' })

// Regex path
.allowUrls({ host: 'registry.npmjs.org', path: '~^/-/npm/v[0-9]+/' })

// Combined — regex host + regex path
.allowUrls({ host: '~^(registry|api)\.npmjs\.org$', path: '~^/[a-z]' })
```

#### 4. Method-restricted rules

```js
.allowUrls({ host: 'api.github.com', methods: ['GET', 'POST'] })
// allows GET and POST; rejects PUT, DELETE, PATCH ...
```

#### 5. Multiple rules — any match wins

```js
const result = await new SaferExec()
  .traceHTTPURLs()
  .allowHosts("registry.npmjs.org", "api.github.com")
  .allowUrls(
    // exact host + path prefix
    { host: "registry.npmjs.org", protocol: "https", path: "/-/npm/v1/" },
    // wildcard subdomain
    "*.npmjs.org",
    // regex host, GET only
    { host: "~^api\.github\.com$", protocol: "https", methods: ["GET"] },
  )
  .enableAudit()
  .run("npm", ["install"]);

// Violations surface in the audit log:
const violations = result.auditLog.filter((e) => e.type === "url-violation");
console.log(violations);
// [{type:'url-violation', target:'https://telemetry.example.com/', details:'violation detected at ...'}]
```

### CLI equivalent

```bash
# String form — parsed as URL
sudo safer-exec --trace-http-urls \
  --allow-url="https://registry.npmjs.org/-/npm/v1/" \
  --allow-url="https://*.npmjs.org" \
  --allow-url="https://~^api\.github\.com$" \
  --audit -- npm install
```

### Real-time violation streaming

```js
const exec = new SaferExec()
  .traceHTTPURLs()
  .allowUrls({ host: "*.npmjs.org" })
  .enableAudit();

exec.on("audit", (entry) => {
  if (entry.type === "url-violation") {
    console.error("[BLOCKED]", entry.target);
  }
});

await exec.run("npm", ["install"]);
```

### Platform notes

| Platform                      | Behaviour                                                                          |
| ----------------------------- | ---------------------------------------------------------------------------------- |
| **Linux ≥ 5.8, root/CAP_BPF** | Full enforcement — violations logged, ports auto-allowed in Landlock               |
| **Linux — eBPF unavailable**  | Warning printed (`http-trace: eBPF HTTP tracing not supported`); URL rules ignored |
| **macOS**                     | Warning printed (`http-trace: ... will be ignored on macOS`); URL rules ignored    |

## Environment Variables

### Injected Environment Variables

The sandbox automatically injects the following environment variable into the sandboxed process environment:

- `RUNNING_IN_SAFER_EXEC_SANDBOX=true`: Indication that the command is running inside a secure sandbox (useful for downstream tools to detect the sandboxed environment and suppress warnings or adjust path lookups).

### Sensitive Environment Variable Warning

Prior to executing a command, `safer-exec` scans the environment variables mapping (`env`) case-insensitively for keys containing potentially sensitive strings (such as `TOKEN`, `PASSWORD`, `SECRET`, `API_KEY`, `CLIENT_SECRET`, `SESSION`, `COOKIE`, `AUTH`, and `KEY`).

If any sensitive keys are detected, a consolidated warning is logged to standard error (`stderr`):

```
safer-exec: warning: sensitive environment variables detected: GITHUB_TOKEN, MY_SECRET
```

### FIPS Compliance Confinement

`safer-exec` supports auditing and enforcing FIPS (Federal Information Processing Standards) compliance:

- **Linux**: When `detectFIPS` or `strictFIPS` is enabled, the sandbox checks the host state `/proc/sys/crypto/fips_enabled` and mirrors this virtualized file inside the container. If `strictFIPS` is configured and the host lacks FIPS compliance, execution is blocked and a `fips-violation` is audited.
- **macOS**: On macOS, FIPS state is verified by reading Apple's security preference plist (`FIPSMode`). If `strictFIPS` is active and FIPSMode is disabled on the host, a validation failure is triggered.
- **Auto-Discovery**: During learn mode, if a process attempts to query the FIPS status or dynamic FIPS module providers (e.g. `fips.so` or `fips.dylib`), the generated policy automatically sets `fipsDetected: true`.

## Development

### Build

```bash
cd go
go build -o bin/safer-exec ./cmd/safer-exec/
```

### Tests

```bash
npm run test:unit         # Unit tests
npm run test:integration  # Integration tests
npm run test:security     # Security boundary tests
npm run test:benchmark    # Performance benchmarks
```

## License

MIT
