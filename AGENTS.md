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

**macOS**: Generates Seatbelt profiles → applies RLIMIT quotas → runs via `sandbox-exec`

**Linux**: Forks self with `--init` → unshares namespaces → creates cgroup v2 → mounts tmpfs + bind mounts → applies Landlock network rules → applies seccomp-bpf → `pivot_root` → `execve`

---

## Directory Structure

```
go/                           — Go engine (platform-specific sandboxing)
  cmd/safer-exec/             — Entry point + platform engines
    main.go                   — Reads JSON config from stdin, dispatches
    engine_darwin.go          — macOS: Seatbelt + RLIMIT engine
    engine_linux.go           — Linux: namespaces + seccomp + Landlock + cgroup
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
go build -ldflags="-s -w" -o bin/safer-exec ./cmd/safer-exec/
```

Cross-compile for other platforms:

```bash
GOOS=darwin GOARCH=arm64 go build -o bin/safer-exec-darwin-arm64 ./cmd/safer-exec/
GOOS=linux GOARCH=amd64 go build -o bin/safer-exec-linux-amd64 ./cmd/safer-exec/
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

### Platform-Specific Engines

- **macOS** uses Go build tags (`//go:build darwin`) — Seatbelt profiles + RLIMIT
- **Linux** uses Go build tags (`//go:build linux`) — namespaces + seccomp + Landlock + cgroup v2
- Architecture-specific syscall numbers use build tags (`linux && amd64`, `linux && arm64`)
- The `run()` function signature is the same across platforms — the implementation differs

### Structured Output Protocol

The Go binary communicates structured data back to Node.js via marker-prefixed JSON on stdout:

- `FSDIFF:` prefix — filesystem diff report
- `LEARNED:` prefix — learned policy output
- Audit entries — JSON lines on stderr

The Node.js `runner.js` parses these markers and separates them from regular stdout.

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

### JavaScript Code

- ES modules only (`"type": "module"` in package.json)
- JSDoc annotations on all exported functions and classes
- Use `node:test` and `node:assert/strict` for testing (no external test frameworks)
- Fluent API: all config methods return `this` for chaining (except `.run()` which returns `Promise<ExecResult>`)
- Error messages prefixed with `safer-exec:` for identification

### Testing

- Unit tests live alongside source files (`src/*.test.js`)
- Integration and security tests live in `tests/`
- Go tests live alongside engine files (`engine_*_test.go`)
- Tests should verify actual sandbox behavior, not just config serialization
- Exhaustion tests should use `.timeout()` to prevent hanging

---

## Common Tasks

### Adding a New Sandbox Feature

1. Add field to `ExecConfig` in `go/internal/config/config.go`
2. Implement in `engine_darwin.go` (Seatbelt rule or RLIMIT)
3. Implement in `engine_linux.go` (namespace, seccomp, Landlock, or cgroup)
4. Add method to `SaferExec` class in `npm/src/index.js`
5. Add CLI flag in `npm/src/cli.js`
6. Add tests to both platform test files and Node.js tests
7. **Update documentation** (update README.md to describe the new configuration settings, CLI flags, and API methods)

### Adding a New Ecosystem Policy

1. Create `npm/src/policies/<ecosystem>.js`
2. Export `<ecosystem>Policy()` function returning policy config
3. Import and register in `POLICIES` map in `npm/src/index.js`
4. Add test in `npm/src/policies.test.js`

### Debugging Sandbox Issues

- Run with `--audit` to see resource accesses
- Run with `--learn` to discover what a command actually needs
- Check stderr for `safer-exec:` prefixed messages
- On macOS, inspect generated Seatbelt profiles (temp `.sb` files)
- On Linux, check `/proc/self/ns/` for namespace state

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
- **Linux**: User namespace + mount namespace + seccomp-bpf blocking escape syscalls
- Both platforms enforce resource quotas (memory, CPU, process count)
