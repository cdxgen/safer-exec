# @cdxgen/safer-exec

OS-level sandboxing for process execution. A zero-dependency Node.js library backed by a statically compiled Go binary.

On macOS the Go binary generates Seatbelt profiles and runs commands through `sandbox-exec`. On Linux it uses namespace isolation, bind mounts, `pivot_root`, seccomp-bpf filters, Landlock network confinement, and cgroup v2 resource quotas.

## Install

```bash
npm install @cdxgen/safer-exec
```

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
```

Full help: `safer-exec --help`.

## API Reference

### Constructor

`new SaferExec(options?)`

| Option           | Type       | Default         | Description                               |
| ---------------- | ---------- | --------------- | ----------------------------------------- |
| `allowHosts`     | `string[]` | `[]`            | Hostnames to allow network access to      |
| `readPaths`      | `string[]` | `[]`            | Filesystem paths to read from             |
| `writePaths`     | `string[]` | `[]`            | Filesystem paths to write to              |
| `env`            | `Object`   | `{}`            | Environment variables to set              |
| `disableNetwork` | `boolean`  | `false`         | Cut all network access                    |
| `maxMemoryMB`    | `number`   | `0`             | Memory limit in megabytes                 |
| `maxCPUCores`    | `number`   | `0`             | CPU limit as fractional cores             |
| `maxProcesses`   | `number`   | `0`             | Max child processes (anti-fork bomb)      |
| `timeoutMs`      | `number`   | `0`             | Hard kill timeout in milliseconds         |
| `workingDir`     | `string`   | `process.cwd()` | Working directory                         |
| `binaryPath`     | `string`   | auto-resolved   | Override Go binary path                   |
| `enableAudit`    | `boolean`  | `false`         | Enable violation auditing                 |
| `allowPorts`     | `number[]` | `[]`            | TCP ports to allow                        |
| `enableDiff`     | `boolean`  | `false`         | Enable filesystem mutation diffing        |
| `enableLearn`    | `boolean`  | `false`         | Enable behavioral auto-profiling          |
| `allowExec`      | `string[]` | `[]`            | Executables the command is allowed to run |
| `blockExec`      | `string[]` | `[]`            | Executables to block from running         |
| `blockFork`      | `boolean`  | `false`         | Prevent forking new processes             |
| `traceExec`      | `boolean`  | `false`         | Log every child process spawned           |

### Instance Methods

All methods return `this` for chaining except `.run()`.

| Method                  | Description                                    |
| ----------------------- | ---------------------------------------------- |
| `.applyPolicy(name)`    | Apply a pre-defined policy. Throws if unknown. |
| `.allowHosts(...hosts)` | Add hostnames to the network allow list        |
| `.readPaths(...paths)`  | Add filesystem read paths                      |
| `.writePaths(...paths)` | Add filesystem write paths                     |
| `.env(key, value)`      | Set an environment variable                    |
| `.disableNetwork()`     | Disable all network access                     |
| `.maxMemory(mb)`        | Set memory limit in megabytes                  |
| `.maxCPUCores(cores)`   | Set CPU limit as fractional cores (e.g. 0.5)   |
| `.maxProcesses(count)`  | Set maximum child process count                |
| `.timeout(ms)`          | Set hard kill timeout in milliseconds          |
| `.binaryPath(path)`     | Override the Go binary path                    |
| `.workingDir(dir)`      | Set the working directory                      |
| `.enableAudit()`        | Enable sandbox violation auditing              |
| `.allowPorts(...ports)` | Set allowed TCP ports                          |
| `.enableDiff()`         | Enable filesystem mutation diffing             |
| `.enableLearn()`        | Enable behavioral auto-profiling               |
| `.allowExec(...cmds)`   | Restrict which executables can run             |
| `.blockExec(...cmds)`   | Block specific executables from running        |
| `.blockFork()`          | Prevent the command from forking new processes |
| `.traceExec()`          | Log every child process spawned                |

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
    cmd: string;
    args: string[];
  };
}
```

## Architecture

The Node.js layer handles policy resolution, DNS lookups, and config serialization. It pipes a JSON `ExecConfig` to the Go binary over stdin. The Go binary reads the config and delegates to a platform-specific engine.

**macOS path:**

1. Generate a Seatbelt profile from the config
2. Apply RLIMIT quotas (memory via `RLIMIT_AS`, CPU via `RLIMIT_CPU`, process count via `RLIMIT_NPROC`)
3. Execute `sandbox-exec -f <profile> <cmd> <args...>`

**Linux path:**

1. Fork self with `--init` flag and config in `SAFER_EXEC_CONFIG` env var
2. Unshare namespaces (user, mount, PID, UTS, network)
3. Map UID/GID to root inside the user namespace for mount privileges
4. Create cgroup v2 hierarchy for resource quotas
5. Mount tmpfs root, bind-mount read/write paths, mount proc and sysfs
6. Apply Landlock v2 network confinement rules
7. Apply seccomp-bpf filter blocking ptrace, kcmp, unshare, mount, pivot_root
8. `pivot_root` to the new filesystem tree
9. `execve` the target command

Communication between layers uses marker-prefixed JSON on stdout:

- `FSDIFF:` prefix for filesystem diff reports
- `LEARNED:` prefix for learned policy output
- Audit entries are written as JSON lines to stderr

## Performance

| Metric                          | Time    |
| ------------------------------- | ------- |
| Baseline (`child_process.exec`) | ~2.6ms  |
| SaferExec warm start            | ~13ms   |
| Overhead                        | ~10.5ms |
| With policy + DNS resolution    | ~113ms  |

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
