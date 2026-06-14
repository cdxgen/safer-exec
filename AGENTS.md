# AGENTS.md — Guidelines for AI agents working on @cdxgen/safer-exec

## Project Overview

`@cdxgen/safer-exec` is a zero-dependency Node.js library that provides OS-level sandboxing for process execution. It consists of:

- **Go engine** (`go/`) — a statically compiled binary that enforces native sandboxing
- **Node.js wrapper** (`npm/src/`) — resolves policies, performs DNS lookups, and orchestrates the Go binary
- **CLI** (`npm/src/cli.js`) — terminal interface to all sandbox features
- **Tests** (`tests/` and `npm/src/*.test.js`) — unit, integration, security, and exhaustion tests

### Architecture at a Glance

```
Node.js (policy + DNS) --[JSON on stdin]--> Go binary --[sandbox]--> target command
                                                              |
                                                    stdout/stderr back to Node.js
```

The Go engine binary is named **`safer-exec-rt`** (runtime). The name `safer-exec` (without `-rt`) is reserved for the standalone caxa-bundled executable distributed on GitHub Releases.

**macOS**: Generates Seatbelt profiles → applies RLIMIT quotas → runs via `sandbox-exec`

**Linux**: Forks self with `--init` → unshares namespaces → sets MS_SLAVE on root → mounts tmpfs → creates cgroup v2 → bind-mounts paths (fd-based with TOCTTOU check) → enforces submount read-only flags → double pivot_root → sets up /proc (hidepid=2 + dangerous entry hardening) → sets up minimal /dev → applies Landlock network rules → applies Landlock filesystem rules → applies seccomp-bpf (base + stackable filters) → acquires file locks → forks PID 1 reaper → child closes leaked fds → child sets PR_SET_PDEATHSIG / setsid → child execves target

---

## Directory Structure

```
go/                           — Go engine (platform-specific sandboxing)
  cmd/safer-exec/             — Entry point + platform engines
    main.go                   — Reads JSON config from stdin, dispatches
    engine_darwin.go          — macOS: Seatbelt + RLIMIT engine
    engine_linux.go           — Linux: namespaces + seccomp + Landlock (net + fs) + cgroup
    engine_openbsd.go         — OpenBSD: unveil(2) + pledge(2) engine
    engine_linux_amd64.go     — x86_64 syscall numbers
    engine_linux_arm64.go     — arm64 syscall numbers
    engine_linux_*_syscall.go — Architecture-specific syscall constants
    engine_darwin_test.go     — macOS engine tests
    engine_linux_test.go      — Linux engine tests
   internal/
    config/                   — ExecConfig JSON contract (shared by all layers)
    learner/                  — Linux strace-based behavioral learner
    learnermac/               — macOS Seatbelt trace parser (learning mode)
    fsdiff/                   — Filesystem snapshot + SHA-256 diff utilities
    httptrace/                — eBPF HTTP URL + crypto tracing (Linux-only)
      bpf/                    — BPF C source + pre-compiled objects
      cipher.go               — Cipher name parser + IANA registry mapping
      cipher_test.go          — Cipher decomposition tests
apparmor/                     — AppArmor profile for unprivileged user namespace creation
  safer-exec                  — Bundled AppArmor profile
npm/
  package.json                — npm package definition (@cdxgen/safer-exec)
  src/
    index.js                  — SaferExec class (fluent API, public interface)
    cli.js                    — CLI entry point (shebang, argument parsing)
    runner.js                 — Go binary spawner, I/O piping, output parsing
    net.js                    — DNS resolution (hostname → IP)
    policies/                 — Pre-built hardened policies per ecosystem
      npm.js, pnpm.js, yarn.js, pypi.js, maven.js, cargo.js,
      rubygems.js, composer.js, deno.js, gomod.js, bun.js
      sslhelper.js            — Platform-specific SSL cert paths
tests/
  integration.test.js         — Full pipeline tests (policy → DNS → Go → sandbox)
  security.test.js            — Boundary tests (isolation, env leakage, limits)
  exhaustion.test.js          — Resource exhaustion tests (memory bombs, fork bombs)
  benchmark.js                — Performance benchmarks vs child_process.exec
```

---

## Build and Run

### Prerequisites

- **Go 1.22+** (for building the engine)
- **Node.js 20+** (for running the wrapper and tests)

### Build the Go Binary

```bash
cd go
go build -trimpath -ldflags="-s -w" -o bin/safer-exec-rt ./cmd/safer-exec/
```

Cross-compile for other platforms:

```bash
GOOS=darwin GOARCH=arm64 go build -o bin/safer-exec-rt-darwin-arm64 ./cmd/safer-exec/
GOOS=linux GOARCH=amd64 go build -o bin/safer-exec-rt-linux-amd64 ./cmd/safer-exec/
```

### Run Tests

```bash
# From the npm/ directory (requires Go binary built first)
npm run test:unit         # Node.js unit tests (npm/src/*.test.js)
npm run test:integration  # Integration tests (tests/integration.test.js)
npm run test:security     # Security boundary tests (tests/security.test.js)
npm run test:exhaustion   # Resource exhaustion tests (tests/exhaustion.test.js)
npm run test:benchmark    # Performance benchmarks (tests/benchmark.js)
npm run test:all          # All tests

# Go tests (run from go/)
cd go
go test -v -race ./...
```

### Use the CLI

```bash
node npm/src/cli.js --help
node npm/src/cli.js --policy=npm -- npm install
node npm/src/cli.js --max-memory=512 -- npm run build
node npm/src/cli.js --diff --write-path=/tmp -- npm install
node npm/src/cli.js --learn -- npm install
node npm/src/cli.js --trace-crypto --cbom-output=cbom.json -- npm install
node npm/src/cli.js diagnostics
```

---

## Key Design Decisions

### Config Contract (`go/internal/config/config.go`)

The `ExecConfig` struct is the canonical JSON contract between Node.js and Go. All configuration flows through this struct. When adding a new feature:

1. Add the field to `ExecConfig` in `config.go`
2. Update the Node.js `SaferExec` class in `index.js`
3. Update both platform engines (`engine_darwin.go` and `engine_linux.go`)
4. Update the CLI argument parser in `cli.js`
5. Add tests for both platforms
6. **Update documentation** (update README.md to describe the new configuration settings, CLI flags, and API methods)

### Platform-Specific Engines

- **macOS** uses Go build tags (`//go:build darwin`) — Seatbelt profiles + RLIMIT
- **Linux** uses Go build tags (`//go:build linux`) — namespaces + seccomp + Landlock (net + fs) + cgroup v2
- **OpenBSD** uses Go build tags (`//go:build openbsd`) — unveil(2) + pledge(2)
- Architecture-specific syscall numbers use build tags (`linux && amd64`, `linux && arm64`)
- The `run()` function signature is the same across platforms — the implementation differs

### Linux Engine: Enhanced Isolation Flow

The Linux engine has been hardened with multiple layered defenses:

1. **Mount propagation control**: `MS_SLAVE` is set on root to prevent sandbox mounts from propagating to the host.
2. **FD-based bind mounting**: Source paths are opened via `O_PATH` and mounted through `/proc/self/fd/N`. Post-mount, `fstat(fd)` is compared against `lstat(target)` to detect TOCTTOU races.
3. **Submount read-only enforcement**: After each read-only bind mount, `/proc/self/mountinfo` is parsed to discover submounts, which are individually remounted read-only. Closes the kernel `MS_REC` loophole.
4. **`/proc` hardening**: Dangerous writable entries (`/proc/sys`, `/proc/sysrq-trigger`, `/proc/irq`, `/proc/bus`) are covered with read-only bind mounts.
5. **Minimal `/dev` setup**: A fresh tmpfs is mounted on `/dev` with only essential device nodes (`null`, `zero`, `full`, `random`, `urandom`, `tty`), stdio symlinks, and `/dev/shm`.
6. **PID 1 reaper**: A guardian process runs as PID 1 in the PID namespace, reaping orphaned zombies and correctly propagating exit codes.
7. **Exit code propagation**: `initMain()` and `initReducedMain()` now check for `ExitError` and use its code instead of always exiting with `1`.

### Structured Output Protocol

The Go binary communicates structured data back to Node.js via marker-prefixed JSON on stdout:

- `FSDIFF:` prefix — filesystem diff report
- `LEARNED:` prefix — learned policy output
- `CRYPTO:` prefix — cryptographic observations (ciphers, libraries)
- Audit entries — JSON lines on stderr

The Node.js `runner.js` parses these markers and separates them from regular stdout.

### JSON Status Protocol

A JSON-lines status protocol is available for external lifecycle monitoring. When `JsonStatusFd` is configured (set by the Node.js runner via an O_CLOEXEC pipe fd), the engine writes:

```json
{"child-pid": 12345, "type": "sandbox-start"}
{"exit-code": 0, "type": "sandbox-exit"}
```

### Policy System

Policies are plain JavaScript functions that return config objects. They are platform-aware (detecting OS for SSL paths, Node binary paths, etc.). When adding a new policy:

1. Create `npm/src/policies/<name>.js`
2. Export a function that returns `{ allowHosts, readPaths, writePaths, env }`
3. Register in `POLICIES` map in `index.js`
4. Add test in `npm/src/policies.test.js`

---

## Coding Conventions

### Go Code

- Use `//go:build` tags for platform-specific files
- Engine functions follow the pattern: `run(cfg)`, `runInit(cfg)`, `runLearn(cfg)`
- Syscall numbers should be defined in architecture-specific files, not in the main engine
- Use `fmt.Fprintf(os.Stderr, "safer-exec: ...")` for error messages
- Tests use Go's `testing` package with `t.TempDir()` for temp directories
- Post-fork child processes must only use raw syscalls — no Go runtime functions

### JavaScript Code

- ES modules only (`"type": "module"` in package.json)
- JSDoc annotations on all exported functions and classes
- Use `node:test` and `node:assert/strict` for testing (no external test frameworks)
- Fluent API: all config methods return `this` for chaining (except `.run()` which returns `Promise<ExecResult>`)
- Error messages prefixed with `safer-exec:` for identification

### Binary Resolution

The `resolveBinaryPath()` function in `runner.js` locates the Go engine binary. It searches in this priority order:
1. `go/bin/safer-exec-rt-{platform}-{arch}` (platform-specific local build)
2. `go/bin/safer-exec-rt` (generic local build)
3. Platform-specific npm optional dependencies in `node_modules`
4. `/usr/local/bin/safer-exec-rt` (system-wide install; auto-bootstraps from node_modules if running as root)
5. Bare string `'safer-exec-rt'` (PATH resolution fallback)

### Testing

- Unit tests live alongside source files (`src/*.test.js`)
- Integration and security tests live in `tests/`
- Go tests live alongside engine files (`engine_*_test.go`)
- Tests should verify actual sandbox behavior, not just config serialization
- Exhaustion tests should use `.timeout()` to prevent hanging
- **NEVER use `sudo` to run tests or execute command verification.** If a test requires special capabilities, configure appropriate setcap or file permissions instead of using superuser privileges.

---

## Common Tasks

### Adding a New Sandbox Feature

1. Add field to `ExecConfig` in `go/internal/config/config.go`
2. Implement in `engine_darwin.go` (Seatbelt rule or RLIMIT)
3. Implement in `engine_linux.go` (namespace, seccomp, Landlock, or cgroup)
4. Add method to `SaferExec` class in `npm/src/index.js`
5. If the feature has user-facing config, add the field to `PolicyFile` in `config.go` and the `applyPolicyFile` method in `index.js`
6. Add CLI flag in `npm/src/cli.js`
7. Add tests to both platform test files and Node.js tests
8. **Update documentation** (update README.md to describe the new configuration settings, CLI flags, and API methods)

### Adding a New Ecosystem Policy

1. Create `npm/src/policies/<ecosystem>.js`
2. Export `<ecosystem>Policy()` function returning policy config
3. Import and register in `POLICIES` map in `npm/src/index.js`
4. Add test in `npm/src/policies.test.js`

### Crypto Tracing & CBOM Generation

The `--trace-crypto` feature captures TLS cipher suites and cryptographic library
identities using eBPF uretprobes on OpenSSL/GnuTLS cipher negotiation functions.

**How it works:**

1. **Library detection**: `attachLibraryProbes()` in `httptrace_linux.go` parses
   library paths (`libssl.so.3` → OpenSSL 3.x) and extracts versions. Detected
   libraries are returned via `Tracer.DetectedLibraries()`.

2. **Cipher detection**: eBPF uretprobes on `SSL_get_current_cipher`,
   `SSL_CIPHER_get_name`, `SSL_CIPHER_get_bits`, `SSL_get_version` (OpenSSL),
   and `gnutls_cipher_suite_get_name` (GnuTLS) capture negotiated cipher suites
   per TLS connection. Cipher info is correlated with HTTP requests via the
   SSL\* pointer (`ConnID`).

3. **CBOM output**: `writeCBOMFile()` in `engine_linux.go` produces a minimal
   CycloneDX JSON document with `cryptographic-asset` components for each
   detected library and cipher suite. The document uses CycloneDX 1.7
   specification.

4. **Cipher name parsing**: `DecomposeCipherName()` in `cipher.go` parses
   OpenSSL-style names into constituent algorithms (key exchange,
   authentication, encryption, hash, mode) for CBOM metadata.

**Adding or maintaining a BPF probe:**

1. Modify/add probes in `go/internal/httptrace/bpf/ssl_trace.c`. When capturing parameters, avoid reading registers directly in exit `uretprobe` return handlers (which is blocked by the verifier on stripped/older runner kernels). Instead, implement a dual hook:
   - Save function parameters in a BPF hash map keyed by `tgid_tid` (`bpf_get_current_pid_tgid()`) during the entry `uprobe`.
   - Retrieve the arguments from the map and read the return value (`PT_REGS_RC(ctx)`) during the exit `uretprobe`.
2. Add the corresponding `*ebpf.Program` field to `bpfObjects` in `httptrace_linux.go`.
3. Register the program loading and attach it under `EnableCryptoTracing()` or `AttachStaticOpenSSL()`.
4. Handle the events correctly in `readCipherLoop()`.
5. Rebuild BPF objects: Run `cd go/internal/httptrace/bpf && bash compile.sh` to compile BPF bytecode targeting multiple architectures inside Docker containers. Because the Docker mount points to the host directory, make sure you compile BPF changes locally without container virtualization directory translation issues, and stage the updated `.o` binary objects (`ssl_trace_linux_amd64.o` and `ssl_trace_linux_arm64.o`) into git.

### Debugging Sandbox Issues

- Run with `--audit` to see resource accesses
- Run with `--learn` to discover what a command actually needs
- Check stderr for `safer-exec:` prefixed messages
- On macOS, inspect generated Seatbelt profiles (temp `.sb` files)
- On Linux, check `/proc/self/ns/` for namespace state
- Run `safer-exec diagnostics` or `SaferExec.diagnostics()` to verify platform readiness and detect sandbox configuration issues
- On Ubuntu 24.04+, the binary at `/usr/local/bin/safer-exec-rt` may need an AppArmor profile to create user namespaces; use `safer-exec bootstrap-apparmor`

### Policy Files in Agentic Workflows

AI agents working with `safer-exec` can leverage policy files (`--policy-file`) to dynamically build and refine permissions:

1. **Discover**: Execute commands with `--learn` and `--learn-output=policy.json` to observe necessary file and network access paths.
2. **Refine**: Inspect the output policy JSON. Prune unnecessary paths or narrow broad directories to specific sub-paths (avoid blanket rules).
3. **Iterate**: Run subsequent workflow steps with `--learn --policy-file=policy.json` to merge new operations into the existing policy.
4. **Deploy**: Enforce the generated policy in production using `--policy-file=policy.json` (CLI) or `applyPolicyFile(path)` (Node.js API).

---

## Threat Model

See `THREAT-MODEL.md` for the complete threat model covering sandbox guarantees, attack surfaces, and failure modes.

Key guarantees:

- **macOS**: Seatbelt `(deny default)` + `system.sb` import
- **Linux**: User namespace + mount namespace (MS_SLAVE propagation control) + seccomp-bpf blocking escape syscalls + Landlock network/filesystem confinement + submount read-only enforcement + `/proc` dangerous entry hardening + minimal `/dev` setup + fd-based TOCTTOU-safe bind mounts + PID 1 reaper with zombie reaping
- Both platforms enforce resource quotas (memory, CPU, process count, I/O)
