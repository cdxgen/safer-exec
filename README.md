# @cdxgen/safer-exec

OS-level sandboxing with tracing, auditing, and learning mode for arbitrary binaries.

On macOS the Go binary generates Seatbelt profiles and runs commands through `sandbox-exec`. On Linux it uses namespace isolation, bind mounts, `pivot_root`, seccomp-bpf filters, Landlock network and filesystem confinement, and cgroup v2 resource quotas (memory, CPU, PID, IO). OpenBSD support is available via `unveil(2)` and `pledge(2)`.

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
safer-exec --max-read-iops=1000 --max-write-bps=104857600 -- npm install

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

# Block Apple-signed scripting engines / sampling tools that can load in-memory
# shellcode or unsigned dylibs (tclsh, wish, perl, system python, ruby, vmmap, ...)
safer-exec --block-interpreters -- npm install

# Deny writes to persistence locations (LaunchAgents, plugin loaders, /usr/local/bin, ...)
safer-exec --deny-persistence-writes -- npm install

# Block W^X / JIT syscalls at the syscall level (Linux; breaks V8/JVM/LuaJIT)
safer-exec --block-jit -- ./run-untrusted-binary

# Pass through specific environment variables from the host (environment is sanitized by default).
# Loader-control vars (DYLD_*, LD_*, NODE_OPTIONS, DEVELOPER_DIR, ...) are stripped unless named here.
safer-exec --allow-envs=VAR1,VAR2 -- npm install

# Process lifecycle control (Linux only)
safer-exec --die-with-parent -- npm install
safer-exec --new-session -- npm install

# Ephemeral writable overlays (Linux only)
safer-exec --tmp-overlay=/tmp/cache -- npm install

# Concurrent sandbox coordination
safer-exec --lock-file=/var/run/build.lock -- npm run build

# Stack additional seccomp filters (Linux only)
safer-exec --seccomp-filter=/etc/safer-exec/custom.bpf -- npm install

# Disable fd-based bind mounts
safer-exec --no-bind-fd -- npm install

# Disable default /dev setup
safer-exec --no-set-up-dev -- npm install

# Validate Seatbelt profile syntax (macOS)
safer-exec --validate-profile -- cat /etc/hosts

# Policy composition — extend a built-in policy
echo '{"extends":"npm","allowHosts":["custom.registry.com"]}' > custom.json
safer-exec --policy-file=custom.json -- npm install

# Diagnostics mode — probe OS capabilities and feature support
safer-exec diagnostics

# Isolate home directory with tmpfs
safer-exec --protect-home=tmpfs -- npm test

# Enable private /tmp
safer-exec --private-tmp --write-path=/tmp -- sh -c "echo test > /tmp/out.txt"

# Use exclusive file locks for serialized installs
safer-exec --lock-file-exclusive=/var/lock/npm-install -- npm install

# Stack a Kafel seccomp policy (opt-in)
safer-exec --seccomp-policy="ALLOW openat, read, write; DEFAULT KILL" -- cat /etc/hostname

# Bind a pre-opened FD into the sandbox
safer-exec --bind-fd=3:/dev/host-tty:ro -- tty
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

| Option                   | Type       | Default         | Description                                                                                                                                                                        |
| ------------------------ | ---------- | --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allowHosts`             | `string[]` | `[]`            | Hostnames to allow network access to                                                                                                                                               |
| `allowURLRules`          | `Object[]` | `[]`            | Fine-grained URL rules — exact, wildcard, regex, path, method (Linux only, requires `traceHTTPURLs`)                                                                               |
| `readPaths`              | `string[]` | `[]`            | Filesystem paths to read from                                                                                                                                                      |
| `writePaths`             | `string[]` | `[]`            | Filesystem paths to write to                                                                                                                                                       |
| `env`                    | `Object`   | `{}`            | Environment variables to set                                                                                                                                                       |
| `disableNetwork`         | `boolean`  | `false`         | Cut all network access                                                                                                                                                             |
| `maxMemoryMB`            | `number`   | `512`           | Memory limit in megabytes (default: 512)                                                                                                                                           |
| `maxCPUCores`            | `number`   | `1.0`           | CPU limit as fractional cores (default: 1.0)                                                                                                                                       |
| `maxProcesses`           | `number`   | `100`           | Max child processes — anti-fork bomb (default: 100)                                                                                                                                |
| `maxReadIOPS`            | `number`   | `0`             | Max read IO operations per second — I/O bomb prevention (Linux only)                                                                                                               |
| `maxWriteIOPS`           | `number`   | `0`             | Max write IO operations per second — I/O bomb prevention (Linux only)                                                                                                              |
| `maxReadBps`             | `number`   | `0`             | Max read bandwidth in bytes per second (Linux only)                                                                                                                                |
| `maxWriteBps`            | `number`   | `0`             | Max write bandwidth in bytes per second (Linux only)                                                                                                                               |
| `timeoutMs`              | `number`   | `60000`         | Hard kill timeout in milliseconds (default: 60000)                                                                                                                                 |
| `workingDir`             | `string`   | `process.cwd()` | Working directory                                                                                                                                                                  |
| `binaryPath`             | `string`   | auto-resolved   | Override Go binary path                                                                                                                                                            |
| `enableAudit`            | `boolean`  | `false`         | Enable violation auditing                                                                                                                                                          |
| `allowPorts`             | `number[]` | `[]`            | TCP ports to allow                                                                                                                                                                 |
| `enableDiff`             | `boolean`  | `false`         | Enable filesystem mutation diffing                                                                                                                                                 |
| `enableLearn`            | `boolean`  | `false`         | Enable behavioral auto-profiling                                                                                                                                                   |
| `validateProfile`        | `boolean`  | `false`         | Validate Seatbelt profile syntax without executing (macOS only)                                                                                                                    |
| `allowExec`              | `string[]` | `[]`            | Executables the command is allowed to run                                                                                                                                          |
| `blockExec`              | `string[]` | `[]`            | Executables to block from running                                                                                                                                                  |
| `blockFork`              | `boolean`  | `false`         | Prevent forking new processes                                                                                                                                                      |
| `blockInterpreters`      | `boolean`  | `false`         | Deny Apple-signed scripting engines / sampling tools that can load in-memory shellcode or unsigned dylibs (macOS only)                                                             |
| `denyPersistenceWrites`  | `boolean`  | `false`         | Deny writes to LaunchAgents, plugin loaders, `/usr/local/bin`, preference stores and other persistence locations (enforced on macOS)                                               |
| `allowWritableDylibLoad` | `boolean`  | `false`         | Permit loading `.dylib` from writable/temp dirs under `blockInterpreters` — for native-addon builds (macOS only)                                                                   |
| `blockJIT`               | `boolean`  | `false`         | Block W^X / JIT syscalls (mprotect PROT_EXEC, mmap W+X, memfd_create). Breaks V8/JVM/LuaJIT; opt-in (Linux only)                                                                   |
| `traceExec`              | `boolean`  | `false`         | Log every child process spawned                                                                                                                                                    |
| `strict`                 | `boolean`  | `false`         | Treat sandbox setup warnings as errors                                                                                                                                             |
| `allowCrypto`            | `boolean`  | `true`          | Permit cryptographic library/device access                                                                                                                                         |
| `blockCrypto`            | `boolean`  | `false`         | Block system crypto libraries access                                                                                                                                               |
| `blockCryptoEntropy`     | `boolean`  | `false`         | Block entropy (/dev/random) device access                                                                                                                                          |
| `detectFIPS`             | `boolean`  | `false`         | Enable FIPS compliance checks/logging                                                                                                                                              |
| `strictFIPS`             | `boolean`  | `false`         | Force strict FIPS validation                                                                                                                                                       |
| `allowGPU`               | `boolean`  | `false`         | Permit process to utilize host GPU nodes                                                                                                                                           |
| `blockTPM`               | `boolean`  | `false`         | Restrict hardware access to TPM device                                                                                                                                             |
| `spoofAntiVM`            | `boolean`  | `false`         | Intercept debugger & virtualization checks                                                                                                                                         |
| `traceLibraries`         | `boolean`  | `false`         | Track dynamic library loading (opt-in)                                                                                                                                             |
| `traceHTTPURLs`          | `boolean`  | `false`         | Capture HTTPS request URLs via eBPF uprobes (Linux only, requires CAP_BPF)                                                                                                         |
| `allowEnvs`              | `string[]` | `[]`            | Host env vars to pass through (sanitized by default; also the opt-in for loader-control vars like `DYLD_*`, `LD_*`, `NODE_OPTIONS`, `DEVELOPER_DIR`, which are stripped otherwise) |
| `allowHidden`            | `boolean`  | `false`         | Allow read/write access to hidden files and directories (dotfiles)                                                                                                                 |
| `allowListen`            | `string[]` | `[]`            | IP addresses or ip:port strings to allow listening on (blocked by default, even on loopback)                                                                                       |
| `traceCrypto`            | `boolean`  | `false`         | Enable cryptographic tracing — cipher suites and library detection (Linux only, requires CAP_BPF). Auto-enables `traceHTTPURLs`.                                                   |
| `cbomOutputPath`         | `string`   | `""`            | Write a CycloneDX CBOM JSON document to this path when `traceCrypto` is active                                                                                                     |
| `cryptoProbeMode`        | `string`   | `"tls-only"`    | Crypto probe depth: `"tls-only"` (default) captures TLS ciphers; `"operations"` also captures digest, encrypt, sign operations (higher overhead)                                   |

### Instance Methods

All methods return `this` for chaining except `.run()`.

| Method                      | Description                                                                                                                                                                          |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `.applyPolicy(name)`        | Apply a pre-defined policy. Throws if unknown.                                                                                                                                       |
| `.allowHosts(...hosts)`     | Add hostnames to the network allow list                                                                                                                                              |
| `.allowUrls(...urls)`       | Add fine-grained URL rules — strings or `{host,protocol,path,methods,port}` objects (Linux only)                                                                                     |
| `.readPaths(...paths)`      | Add filesystem read paths                                                                                                                                                            |
| `.writePaths(...paths)`     | Add filesystem write paths                                                                                                                                                           |
| `.env(key, value)`          | Set an environment variable                                                                                                                                                          |
| `.disableNetwork()`         | Disable all network access                                                                                                                                                           |
| `.maxMemory(mb)`            | Set memory limit in megabytes                                                                                                                                                        |
| `.maxCPUCores(cores)`       | Set CPU limit as fractional cores (e.g. 0.5)                                                                                                                                         |
| `.maxProcesses(count)`      | Set maximum child process count                                                                                                                                                      |
| `.maxReadIOPS(iops)`        | Set max read IO operations per second (Linux only)                                                                                                                                   |
| `.maxWriteIOPS(iops)`       | Set max write IO operations per second (Linux only)                                                                                                                                  |
| `.maxReadBps(bps)`          | Set max read bytes per second (Linux only)                                                                                                                                           |
| `.maxWriteBps(bps)`         | Set max write bytes per second (Linux only)                                                                                                                                          |
| `.timeout(ms)`              | Set hard kill timeout in milliseconds                                                                                                                                                |
| `.binaryPath(path)`         | Override the Go binary path                                                                                                                                                          |
| `.workingDir(dir)`          | Set the working directory                                                                                                                                                            |
| `.enableAudit()`            | Enable sandbox violation auditing                                                                                                                                                    |
| `.allowPorts(...ports)`     | Set allowed TCP ports                                                                                                                                                                |
| `.enableDiff()`             | Enable filesystem mutation diffing                                                                                                                                                   |
| `.enableLearn()`            | Enable behavioral auto-profiling                                                                                                                                                     |
| `.validateProfile()`        | Validate Seatbelt profile syntax without executing (macOS)                                                                                                                           |
| `.allowExec(...cmds)`       | Restrict which executables can run                                                                                                                                                   |
| `.blockExec(...cmds)`       | Block specific executables from running                                                                                                                                              |
| `.blockFork()`              | Prevent the command from forking new processes                                                                                                                                       |
| `.blockInterpreters()`      | Deny Apple-signed scripting engines / sampling tools that can load in-memory shellcode or unsigned dylibs (macOS)                                                                    |
| `.denyPersistenceWrites()`  | Deny writes to LaunchAgents, plugin loaders, `/usr/local/bin` and other persistence locations (enforced on macOS)                                                                    |
| `.allowWritableDylibLoad()` | Permit loading `.dylib` from writable/temp dirs under `.blockInterpreters()` — for native-addon builds (macOS)                                                                       |
| `.blockJIT()`               | Block W^X / JIT syscalls (mprotect PROT_EXEC, mmap W+X, memfd_create). Breaks V8/JVM/LuaJIT; opt-in (Linux)                                                                          |
| `.traceExec()`              | Log every child process spawned                                                                                                                                                      |
| `.strict()`                 | Treat sandbox setup warnings as hard errors                                                                                                                                          |
| `.resolveSymlinks()`        | Resolve target command symlink in PATH                                                                                                                                               |
| `.allowCrypto(allow)`       | Allow/disallow cryptographic operations                                                                                                                                              |
| `.blockCrypto()`            | Restrict system cryptographic libraries                                                                                                                                              |
| `.blockCryptoEntropy()`     | Restrict entropy devices (/dev/random)                                                                                                                                               |
| `.detectFIPS()`             | Log and watch for FIPS lookups                                                                                                                                                       |
| `.strictFIPS()`             | Restrict runtime to strict FIPS compliant mode                                                                                                                                       |
| `.allowGPU(allow)`          | Allow/disallow access to host GPU nodes                                                                                                                                              |
| `.blockTPM()`               | Restrict hardware access to TPM device                                                                                                                                               |
| `.spoofAntiVM()`            | Intercept debugger & virtualization checks                                                                                                                                           |
| `.traceLibraries()`         | Track dynamic library loading (LD_AUDIT on Linux, audit events on macOS)                                                                                                             |
| `.traceHTTPURLs()`          | Capture HTTPS request URLs/methods via eBPF TLS uprobes (Linux only)                                                                                                                 |
| `.allowEnvs(...keys)`       | Allow specific host environment variables to pass through. Also the opt-in for loader-control vars (`DYLD_*`, `LD_*`, `NODE_OPTIONS`, `DEVELOPER_DIR`), which are stripped otherwise |
| `.allowHidden(allow)`       | Allow/disallow access to hidden files and directories (dotfiles)                                                                                                                     |
| `.allowListen(list)`        | Allow listening/binding on specific IP addresses or ip:port strings (blocked by default, even loopback)                                                                              |
| `.traceCrypto()`            | Enable TLS cipher suite and crypto library detection via eBPF uprobes (Linux only). Auto-enables `.traceHTTPURLs()`.                                                                 |
| `.cbom(path)`               | Set the output path for the CycloneDX CBOM JSON document (requires `.traceCrypto()`)                                                                                                 |
| `.cryptoProbeMode(mode)`    | Set crypto probe depth: `"tls-only"` (default) or `"operations"` (also captures digest/sign ops)                                                                                     |
| `.setUpDev(enable)`         | Enabled by default. Pass `false` to disable minimal `/dev` setup inside sandbox. Linux-only.                                                                                         |
| `.dieWithParent()`          | Enabled by default. Kill sandboxed process with SIGKILL when parent dies (PR_SET_PDEATHSIG). Linux-only. Pass `false` to disable.                                                    |
| `.newSession()`             | Enabled by default. Disconnect from controlling terminal via setsid(). Linux-only. Pass `false` to disable.                                                                          |
| `.tmpOverlayPaths(...)`     | Create ephemeral writable overlays at paths (overlayfs, Linux only)                                                                                                                  |
| `.bindUseFd(use)`           | Opt-in. Use fd-based bind mounting for TOCTTOU safety. Linux-only.                                                                                                                   |
| `.seccompFilters(filters)`  | Stack additional seccomp-bpf filters (base64 encoded or file path, Linux only)                                                                                                       |
| `.protectSystem(mode)`      | Opt-in (default `"off"`). Make system directories read-only automatically. Modes: `"strict"`, `"full"`, `"off"`. Linux-only.                                                         |
| `.protectHome(mode)`        | Opt-in. Isolate the user's home directory. Modes: `"read-only"`, `"tmpfs"`, `"off"` (default). Linux-only.                                                                           |
| `.privateTmp(enable)`       | Replace `/tmp` and `/var/tmp` with fresh tmpfs. Linux-only.                                                                                                                          |
| `.bindFds(...specs)`        | Bind-mount pre-opened file descriptors into the sandbox. Each spec: `{ fd: number, target: string, readOnly?: boolean }` — Linux-only.                                               |
| `.lockFilesExclusive(...)`  | Acquire exclusive (write) advisory locks. Convenience for serialized coordination.                                                                                                   |
| `.seccompPolicy(policy)`    | Stack a Kafel-style seccomp policy using simple syntax. Example: `"ALLOW openat, read, write; DEFAULT KILL"`                                                                         |
| `.mapToTargetUid(enable)`   | Map UID 0 inside namespace to the caller's real UID. Linux-only.                                                                                                                     |
| `.lockFiles(...specs)`      | accepts `{ path: string, exclusive?: boolean }` objects in addition to plain strings.                                                                                                |

### OS & Capability Support Matrix

| API Method                             | macOS | Linux | Windows / BSD | Required Capabilities / Permissions                    | Notes                                                                                                                                                  |
| :------------------------------------- | :---: | :---: | :-----------: | :----------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.allowHosts(...)`                     |  Yes  |  Yes  |      No       | None                                                   | On Linux: DNS resolution to IP. On macOS: Seatbelt rules.                                                                                              |
| `.allowListen(...)`                    |  Yes  |  Yes  |      No       | None (macOS), Unprivileged User Namespaces (Linux)     | Blocks loopback port binding by default unless explicitly permitted.                                                                                   |
| `.allowPorts(...)`                     |  Yes  |  Yes  |      No       | None                                                   | Restricts outbound ports. macOS uses Seatbelt; Linux uses Landlock.                                                                                    |
| `.allowUrls(...)`                      |  No   |  Yes  |      No       | `CAP_BPF`, `CAP_PERFMON`                               | Requires eBPF tracing engine.                                                                                                                          |
| `.readPaths(...)` / `.writePaths(...)` |  Yes  |  Yes  |      No       | None (macOS), Unprivileged User Namespaces (Linux)     | Restricts filesystem access. macOS uses Seatbelt; Linux uses Mount Namespaces.                                                                         |
| `.disableNetwork()`                    |  Yes  |  Yes  |      No       | None (macOS), Unprivileged User Namespaces (Linux)     | macOS blocks outbound; Linux unshares Net Namespace.                                                                                                   |
| `.maxMemory(...)`                      |  Yes  |  Yes  |      No       | None (macOS), Cgroups write permission (Linux)         | macOS: `RLIMIT_AS`. Linux: cgroups v2 `memory.max`.                                                                                                    |
| `.maxCPUCores(...)`                    |  Yes  |  Yes  |      No       | None (macOS), Cgroups write permission (Linux)         | macOS: `RLIMIT_CPU`. Linux: cgroups v2 `cpu.max`.                                                                                                      |
| `.maxProcesses(...)`                   |  Yes  |  Yes  |      No       | None (macOS), Cgroups write permission (Linux)         | macOS: `RLIMIT_NPROC`. Linux: cgroups v2 `pids.max`.                                                                                                   |
| `.maxReadIOPS(...)` etc.               |  No   |  Yes  |      No       | Cgroups write permission                               | Linux cgroups v2 `io.max` throttling.                                                                                                                  |
| `.enableAudit()`                       |  Yes  |  Yes  |      No       | None                                                   | macOS uses Seatbelt trace; Linux uses Seccomp-BPF trap.                                                                                                |
| `.enableDiff()`                        |  Yes  |  Yes  |      No       | None (macOS), Unprivileged User Namespaces (Linux)     | macOS: Shadow dir snapshot. Linux: OverlayFS mount.                                                                                                    |
| `.enableLearn()`                       |  Yes  |  Yes  |      No       | None (macOS), `SYS_PTRACE` or `ptrace_scope=0` (Linux) | macOS parses Seatbelt trace logs. Linux uses `strace` or fallback.                                                                                     |
| `.allowExec(...)` / `.blockExec(...)`  |  Yes  |  Yes  |      No       | None                                                   | Restricts process execution. macOS uses Seatbelt; Linux uses Seccomp.                                                                                  |
| `.blockFork()`                         |  Yes  |  Yes  |      No       | None                                                   | macOS uses Seatbelt; Linux uses Seccomp.                                                                                                               |
| `.blockInterpreters()`                 |  Yes  |  n/a  |      No       | None                                                   | macOS-only. Denies tclsh/wish/perl/python/ruby/SamplingTools exec + starves Tcl/Tk/Ffidl reads. No-op elsewhere.                                       |
| `.denyPersistenceWrites()`             |  Yes  |  Yes  |      No       | None (macOS), Unprivileged User Namespaces (Linux)     | macOS: Seatbelt write denies on LaunchAgents/plugins/`/usr/local/bin`. Linux: already deny-by-default via Landlock allowlist.                          |
| `.allowWritableDylibLoad()`            |  Yes  |  n/a  |      No       | None                                                   | macOS-only. Relaxes the `.blockInterpreters()` writable-`.dylib` read deny.                                                                            |
| `.blockJIT()`                          |  No   |  Yes  |      No       | None                                                   | Linux-only (Seccomp W^X). Denies mprotect PROT_EXEC, mmap W+X, memfd_create. Breaks V8/JVM/LuaJIT — opt-in. On macOS, Seatbelt cannot filter syscalls. |
| `.traceExec()`                         |  Yes  |  Yes  |      No       | None                                                   | Logs child spawns. macOS: Seatbelt trace. Linux: Seccomp trap.                                                                                         |
| `.allowGPU(...)`                       |  No   |  Yes  |      No       | Unprivileged User Namespaces                           | Linux-only. Bind mounts device nodes to sandbox.                                                                                                       |
| `.blockTPM()`                          |  No   |  Yes  |      No       | Unprivileged User Namespaces                           | Linux-only. Restricts access to `/dev/tpm*`.                                                                                                           |
| `.spoofAntiVM()`                       |  No   |  Yes  |      No       | Unprivileged User Namespaces                           | Linux-only. Conceals sandbox execution details.                                                                                                        |
| `.traceLibraries()`                    |  Yes  |  Yes  |      No       | None                                                   | macOS: `DYLD_INSERT_LIBRARIES`. Linux: `LD_AUDIT`.                                                                                                     |
| `.traceHTTPURLs()` / `.traceCrypto()`  |  No   |  Yes  |      No       | `CAP_BPF`, `CAP_PERFMON`                               | Linux eBPF TLS uprobes.                                                                                                                                |

### Static Methods

| Method                    | Description                                                                                                                               |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `SaferExec.diagnostics()` | Probe OS capabilities and safer-exec feature support. Returns a promise of `{ platform, arch, kernel, release, capabilities, features }`. |

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
2. Fork self with `--init` flag and config via temp file path (`SAFER_EXEC_CONFIG_PATH`) or env var (`SAFER_EXEC_CONFIG`)
3. Unshare namespaces (user, mount, PID, UTS, network)
4. Map UID/GID to root inside the user namespace for mount privileges
5. Create cgroup v2 hierarchy for resource quotas
6. Mount tmpfs root, bind-mount read/write paths, mount proc and sysfs
7. Apply Landlock v2 network confinement rules (well-known ports 1-1024 auto-allowed)
8. Apply seccomp-bpf filter blocking ptrace, kcmp, unshare, mount, pivot_root
9. `pivot_root` to the new filesystem tree (hard error with `--strict`; chroot fallback otherwise)
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

profile safer-exec /usr/local/bin/safer-exec-rt flags=(unconfined) {
  userns,
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/safer-exec
```

Adjust the path (`/usr/local/bin/safer-exec-rt`) to wherever the binary is installed. When using the npm package, the binary lives inside `node_modules/@cdxgen/safer-exec-linux-*/bin/safer-exec-rt` — you can use a glob pattern:

```bash
sudo tee /etc/apparmor.d/safer-exec > /dev/null << 'EOF'
abi <abi/4.0>,
include <tunables/global>

profile safer-exec <path to>/node_modules/@cdxgen/safer-exec-linux-*/bin/safer-exec-rt {
  # Allow user namespaces
  userns,
  # Add other necessary rules (ix/px for child processes, file r/w, etc.)
}
EOF

sudo apparmor_parser -r /etc/apparmor.d/safer-exec
```

The profile takes effect immediately (no reboot required). Verify with:

```bash
# Should show the profile loaded
sudo aa-status | grep safer-exec
```

### Alternative 1: Elevate ONLY the Go Runtime binary

```
sudo setcap 'cap_sys_resource,cap_bpf,cap_perfmon,cap_sys_ptrace,cap_sys_admin+eip' /usr/local/bin/safer-exec-rt
```

> [!NOTE]
> **Automatic Bootstrapping (CI/Root execution):**
> If the Go runtime binary is missing from `/usr/local/bin/safer-exec-rt` and the process runs under root permissions (UID 0), the npm wrapper automatically copies/bootstraps the binary to `/usr/local/bin/safer-exec-rt` and executes `setcap` internally during the initial run to enable capability-sensitive tracing out of the box.

### Alternative 2: system-wide sysctl (not recommended)

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

All built-in policies set `denyPersistenceWrites: true`, so an install can never stage a LaunchAgent, a loader plugin, or a binary in `/usr/local/bin` (enforced on macOS; Linux is already deny-by-default for ungranted paths). The non-interpreter ecosystems (`npm`, `pnpm`, `yarn`, `bun`, `deno`, `maven`, `cargo`, `gomod`, `composer`) additionally set `blockInterpreters: true`, blocking the Apple-signed scripting engines and sampling tools that can load in-memory shellcode. The interpreter-driven ecosystems (`pypi`, `uv`, `rubygems`) deliberately leave `blockInterpreters` off, since their own runtime is one of those engines. `blockJIT` is never enabled by default — every ecosystem runs or can invoke a JIT (V8/Node, the JVM), so enable it only for workloads you know do not JIT.

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

## Diagnostics

Probe the host machine for OS-level sandboxing capabilities and safer-exec feature support.

```bash
safer-exec diagnostics
```

Sample output on macOS:

```
safer-exec v0.9.0 — Diagnostics
========================================================

  Platform:    darwin (arm64)
  Kernel:      25.5.0
  Release:     macOS 26.5.1
  Node.js:     v24.16.0

OS Capabilities
────────────────────────────────────────────────────────
  ✓ Sandbox Exec              sandbox-exec is in PATH
  ✓ Seatbelt Profile          Seatbelt (Sandbox) profile generation via sandbox-exec
  ✓ Rlimit As                 max address space: 9223372036854775807 bytes
  ✓ Rlimit Cpu                max CPU time: 9223372036854775807 seconds
  ✓ Rlimit Nproc              max processes: 9223372036854775807
  ✓ Dyld Insert Libraries     DYLD_INSERT_LIBRARIES supported (SIP-restricted)
  ✓ Fips Detection            defaults read available

SaferExec Features
────────────────────────────────────────────────────────
  ✓ Network Isolation         ✓ Exec Control               ✓ Audit Tracing
  ✓ File Read Restriction     ✓ Fork Control               ✓ Filesystem Diff
  ✓ File Write Restriction    ✓ Memory Limit               ✓ Learning Mode
  ✓ CPU Limit                 ✓ Process Limit              ✓ Strict Mode
  ✓ Crypto Control            ✓ FIPS Detection             ✓ GPU Control
  ✓ TPM Control               ✓ Anti-VM Spoofing           ✓ Library Tracing
  ✗ HTTP URL Tracing          ✗ Allow URL Rules

  Summary: 18/20 features supported
```

Use the API to get structured data:

```js
const diag = await SaferExec.diagnostics();
console.log(diag.platform); // 'darwin'
console.log(diag.capabilities.sandbox_exec.available); // true
console.log(diag.features.network_isolation); // true
```

Capabilities are OS-level primitives (sandbox-exec, namespaces, cgroups, seccomp, etc.). Features are safer-exec capabilities built on top of those primitives (network isolation, file restriction, memory limits, etc.). When a feature shows ✗, its underlying primitive is unavailable on the current platform — for example, `trace_http_urls` and `allow_url_rules` require Linux with eBPF (kernel ≥ 5.8 + CAP_BPF).

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

Enable opt-in capture of TLS cipher suites and cryptographic library identities using eBPF uretprobes on OpenSSL/GnuTLS cipher negotiation functions. This is a superset of `--trace-http-urls` — enabling crypto tracing automatically enables URL tracing as well.

### Unified Socket-Level Handshake & SNI Fallback Tracing

To ensure robustness, `safer-exec` intercepts TCP socket handshakes at the socket level using kernel tracepoints (`sys_enter_connect`, `sys_enter_write`, `sys_enter_sendto`, etc.). It automatically parses TLS `ClientHello` (SNI) and `ServerHello` records from socket buffers to resolve hostnames and negotiated ciphers for statically-compiled languages (such as Go or Rust) that bypass dynamic library wrappers.

### Cryptographic Operations Auditing (beyond TLS)

When `cryptoProbeMode` is set to `"operations"`, `safer-exec` attaches uprobes to common system cryptography functions (such as OpenSSL `MD5_Init`, `SHA1_Init`, `SHA224_Init`, `SHA256_Init`, `SHA384_Init`, `SHA512_Init`, `AES_set_encrypt_key` and `AES_set_decrypt_key` or Go internal crypto routines `crypto/sha256.block`, `crypto/aes.encryptBlock`). This captures local, non-network cryptographic operations (hashing, symmetric encryption/decryption) and exports them in the CycloneDX Cryptography Bill of Materials (CBOM).

### File and Execution Auditing via LSM BPF

On kernels supporting Linux Security Modules (LSM) BPF (kernel ≥ 5.7), `safer-exec` attaches to LSM hooks (`bprm_check_security` and `file_open`). Using the kernel `bpf_d_path` helper, it dynamically audits process context, absolute files, and executions, providing kernel-level runtime observability and policy verification.

**Platform requirements:** identical to `--trace-http-urls` (Linux ≥ 5.8, `CAP_BPF` + `CAP_PERFMON`, `amd64` or `arm64`).

### CLI

```bash
# Capture cipher suites and emit a CycloneDX CBOM
safer-exec --trace-crypto --cbom-output=cbom.json -- node index.js

# Also capture digest, encrypt, sign operations (higher overhead)
safer-exec --trace-crypto --crypto-probe-mode=operations --cbom-output=cbom.json -- node index.js

# Combine with learn mode to record ciphers in the policy file
safer-exec --learn --learn-output=policy.json --trace-crypto -- npm install
```

### JavaScript API

```js
import { SaferExec } from "@cdxgen/safer-exec";

const result = await new SaferExec()
  .traceCrypto() // enable cipher + library tracing
  .cbom("./cbom.json") // write CycloneDX CBOM on exit
  .cryptoProbeMode("operations") // also capture digest/sign ops
  .run("node", ["index.js"]);

// result.crypto — cryptographic observations
// {
//   ciphers: [
//     {
//       name: "ECDHE-RSA-AES256-GCM-SHA384",
//       ianaName: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
//       ianaId: 49200,
//       protocol: "TLSv1.2",
//       keyExchange: "ECDHE",
//       authentication: "RSA",
//       encryption: "AES",
//       encryptionBits: 256,
//       hash: "SHA384",
//       mode: "GCM",
//       library: "OpenSSL",
//       libraryVersion: "3.0.8",
//       pid: 12345
//     }
//   ],
//   libraries: [
//     { name: "OpenSSL", version: "3.0.8", path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", source: "ebpf_uprobe" }
//   ],
//   operations: [],   // populated when cryptoProbeMode is "operations"
//   platform: "linux"
// }
```

### Real-Time Event-Driven Crypto Auditing

When both `.enableAudit()` and `.traceCrypto()` are enabled, cryptographic events are parsed and emitted in real-time as `audit` events on the `SaferExec` instance:

```js
const exec = new SaferExec().traceCrypto().enableAudit();

exec.on("audit", (entry) => {
  if (entry.type === "crypto-cipher") {
    console.log(`Negotiated cipher ${entry.name} via ${entry.library}`);
  } else if (entry.type === "crypto-library") {
    console.log(
      `Loaded crypto library: ${entry.name} version ${entry.version} at ${entry.path}`,
    );
  } else if (entry.type === "crypto-operation") {
    console.log(
      `Crypto operation observed: ${entry.operation} (${entry.algorithm})`,
    );
  }
});

await exec.run("node", ["index.js"]);
```

Additionally, standard `"http-request"` audit events are enriched with cipher, protocol, and cryptographic library details if captured:

```json
{
  "type": "http-request",
  "method": "GET",
  "host": "registry.npmjs.org",
  "path": "/",
  "protocol": "https",
  "port": 443,
  "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
  "cipherIanaName": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "cipherIanaId": 49200,
  "tlsVersion": "TLSv1.2",
  "cipherBits": 256,
  "cryptoLibrary": "OpenSSL",
  "cryptoLibraryVersion": "3"
}
```

### Cipher Allowlisting

When `--trace-crypto` / `.traceCrypto()` is active, you can restrict the allowed TLS cipher suites. If a sandboxed command negotiates a TLS connection using a cipher suite not explicitly in the allowlist, a `cipher-violation` audit event is emitted.

To ensure high reliability across stripped libraries and older or unprivileged kernels (e.g., GitHub Actions runner environments), `safer-exec` employs a dual-mechanism fallback architecture:

1. **Map-Based Entry Tracing:** Function parameters (such as the `SSL*` or `cipher*` pointers) are captured at the function entry `uprobes` and stored in BPF maps indexed by thread IDs. Exit `uretprobes` look up the connection context from these maps rather than trying to read parameters directly from registers at return, avoiding verifier rejections.
2. **TLS Handshake Record Parsing Fallback:** A fallback packet decoder hooks standard read/recv library calls or intercept socket connection state (`sys_enter_connect` tracepoint / socket-level events) to parse unencrypted ClientHello and ServerHello records directly from raw TCP buffers, extracting negotiated cipher suites and destination hostnames (SNI) even if target libraries lack symbol tables. The SNI parsing (`parseSNI` function) tracks the standard TLS Handshake Record (record type `0x16` and Handshake type `0x01` ClientHello), navigating through the TLS header, ClientHello session parameters, cipher suite list, compression formats, and extension blocks to pinpoint the Server Name Indication list (type `0x0000` per RFC 6066) and extract the exact HostName.

**CLI:**

```bash
# Allow only modern TLS v1.3 ciphers, trigger violations for any older negotiations
safer-exec --trace-crypto --allow-cipher=TLS_AES_256_GCM_SHA384 --allow-cipher=TLS_CHACHA20_POLY1305_SHA256 --audit -- curl https://registry.npmjs.org
```

**JavaScript API:**

```js
const result = await new SaferExec()
  .traceCrypto()
  .allowCiphers("TLS_AES_256_GCM_SHA384", "ECDHE-RSA-AES256-GCM-SHA384")
  .enableAudit()
  .run("curl", ["https://registry.npmjs.org"]);
```

### CBOM Output

When `--cbom-output` / `.cbom(path)` is set, a [CycloneDX 1.7](https://cyclonedx.org/specification/overview/) JSON document is written containing `cryptographic-asset` components for each detected cipher suite and library:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "version": 1,
  "metadata": { "timestamp": "...", "tools": [...] },
  "components": [
    {
      "type": "cryptographic-asset",
      "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
      "cryptoProperties": {
        "assetType": "protocol",
        "protocolProperties": {
          "type": "tls",
          "version": "1.2",
          "cipherSuites": [
            {
              "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
              "algorithms": ["ECDHE", "RSA", "AES-256-GCM", "SHA384"]
            }
          ]
        }
      }
    }
  ]
}
```

### `result.crypto` fields

| Field        | Type                | Description                                                                       |
| ------------ | ------------------- | --------------------------------------------------------------------------------- |
| `ciphers`    | `CipherInfo[]`      | Negotiated TLS cipher suites observed during execution                            |
| `libraries`  | `CryptoLibrary[]`   | Detected cryptographic libraries (OpenSSL, GnuTLS, Go crypto/tls, etc.)           |
| `operations` | `CryptoOperation[]` | Crypto operations (digest, encrypt, sign, verify) — only with `"operations"` mode |
| `platform`   | `string`            | OS platform where observations were made                                          |

**`CipherInfo` fields:**

| Field            | Type     | Description                                                         |
| ---------------- | -------- | ------------------------------------------------------------------- |
| `name`           | `string` | OpenSSL-style name (e.g. `"ECDHE-RSA-AES256-GCM-SHA384"`)           |
| `ianaName`       | `string` | IANA standard name (e.g. `"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"`) |
| `ianaId`         | `number` | IANA cipher suite ID (e.g. `0xC030`)                                |
| `protocol`       | `string` | TLS protocol version (`"TLSv1.2"`, `"TLSv1.3"`)                     |
| `keyExchange`    | `string` | Key exchange algorithm (`"ECDHE"`, `"DHE"`, `"RSA"`)                |
| `authentication` | `string` | Authentication algorithm (`"RSA"`, `"ECDSA"`)                       |
| `encryption`     | `string` | Symmetric cipher name (`"AES"`, `"CHACHA20"`)                       |
| `encryptionBits` | `number` | Cipher key size in bits                                             |
| `hash`           | `string` | Hash/MAC algorithm (`"SHA256"`, `"SHA384"`)                         |
| `mode`           | `string` | Cipher mode (`"GCM"`, `"POLY1305"`, `"CBC"`)                        |
| `library`        | `string` | Crypto library that established the connection                      |
| `libraryVersion` | `string` | Detected library version                                            |
| `pid`            | `number` | Host PID of the process that negotiated this cipher                 |

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

### New since v0.12.0: Hardened Defaults

Three defense-in-depth features are now **enabled by default** (Linux-only, fall back gracefully):

- **Minimal /dev** — Essential device nodes from a fresh tmpfs (safer than inheriting host /dev)
- **Die-with-parent** — Sandbox killed when parent exits (PR_SET_PDEATHSIG, prevents orphaned processes)
- **New session** — Terminal disconnected via setsid() to block SIGHUP/SIGINT injection

Additional opt-in hardening features:

- **ProtectSystem** — `--protect-system=strict|full` auto-makes system dirs read-only
- **ProtectHome** — `--protect-home=read-only|tmpfs` isolates $HOME
- **PrivateTmp** — `--private-tmp` replaces /tmp and /var/tmp with fresh tmpfs
- **Bind-use-fd** — `--bind-use-fd` enables TOCTTOU-safe fd-based bind mounting
- **Protect system** — Simply use `--protect-system=strict` to proactively harden further

## Linux-Specific Features

### AppArmor Profile

On Ubuntu 24.04+ and other distributions that restrict unprivileged user namespaces, `safer-exec` falls back to reduced isolation mode (seccomp + Landlock only, no filesystem isolation). To enable full sandbox isolation, install the bundled AppArmor profile:

```bash
sudo cp apparmor/safer-exec /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/safer-exec
```

Verify the profile is loaded with `safer-exec diagnostics` — look for "AppArmor Profile" under SaferExec Features.

### Landlock Filesystem Rules

In addition to Landlock network confinement, Landlock filesystem access rules is used as a defense-in-depth layer. Read and write paths declared in the policy are enforced at the kernel level, catching symlink escapes and missed bind-mount paths. Requires Landlock ABI v3+ (Linux kernel >= 5.13).

### Cgroup v2 IO Limiting

Prevent I/O bomb scenarios by limiting read/write IOPS and bandwidth:

```bash
safer-exec --max-read-iops=1000 --max-write-iops=1000 \
           --max-read-bps=104857600 --max-write-bps=104857600 \
           -- npm install
```

### Policy Composition

Policy files can extend built-in policies using the `extends` field. The base policy is loaded first, then the file's rules are overlaid on top:

```json
{
  "extends": "npm",
  "allowHosts": ["custom.internal.registry.com"],
  "readPaths": ["/usr/local/custom-certs"],
  "maxMemoryMB": 2048
}
```

## Platform Support

| Platform | Sandbox Mechanism                        | Status       |
| -------- | ---------------------------------------- | ------------ |
| macOS    | Seatbelt profiles + `sandbox-exec`       | Production   |
| Linux    | Namespaces + seccomp + Landlock + cgroup | Production   |
| OpenBSD  | `unveil(2)` + `pledge(2)`                | Experimental |

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
