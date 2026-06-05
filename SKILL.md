# Safer-Exec CLI Skill

This skill guides AI agents on using the `safer-exec` CLI tool and Node.js API for sandboxed command execution.

## Overview

`safer-exec` runs commands inside an OS-level sandbox with configurable policies, resource limits, filesystem diffing, and behavioral auto-profiling. It uses Seatbelt on macOS and namespace/seccomp/Landlock isolation on Linux.

## CLI Quick Reference

```
safer-exec [OPTIONS] -- COMMAND [ARGS...]
```

### Core Options

| Flag                  | Short | Description                               |
| --------------------- | ----- | ----------------------------------------- |
| `--policy=<name>`     | `-p`  | Apply a built-in policy preset            |
| `--max-memory=<mb>`   | `-m`  | Memory limit in megabytes                 |
| `--max-cpu=<cores>`   | `-c`  | CPU limit as fractional cores             |
| `--max-processes=<n>` |       | Max child processes                       |
| `--timeout=<ms>`      | `-t`  | Hard kill timeout                         |
| `--disable-network`   | `-n`  | Disable all network access                |
| `--allow-host=<host>` | `-H`  | Allow network access to host (repeatable) |
| `--port=<port>`       |       | Allow specific TCP port (repeatable)      |
| `--read-path=<path>`  | `-r`  | Allow reading from path (repeatable)      |
| `--write-path=<path>` | `-w`  | Allow writing to path (repeatable)        |
| `--env=<KEY=VALUE>`   | `-e`  | Set environment variable (repeatable)     |
| `--cwd=<dir>`         | `-C`  | Set working directory                     |

### Feature Flags

| Flag                    | Short | Description                                  |
| ----------------------- | ----- | -------------------------------------------- |
| `--diff`                | `-d`  | Enable filesystem mutation diffing           |
| `--learn`               | `-l`  | Enable behavioral auto-profiling             |
| `--learn-output=<file>` |       | Write learned policy to file                 |
| `--audit`               | `-a`  | Enable sandbox violation auditing            |
| `--allow-exec=<cmd>`    |       | Allow only specific executables (repeatable) |
| `--block-exec=<cmd>`    |       | Block specific executables (repeatable)      |
| `--block-fork`          |       | Prevent forking new processes                |
| `--trace-exec`          |       | Log every child process spawned              |
| `--json`                | `-j`  | Output results as JSON                       |
| `--help`                | `-h`  | Show help                                    |
| `--version`             | `-v`  | Show version                                 |

### Built-in Policies

Available: `npm`, `pnpm`, `yarn`, `pypi`, `maven`, `cargo`, `rubygems`, `composer`, `deno`, `gomod`, `bun`

Each policy is platform-aware and configures registry hosts, SSL cert paths, cache directories, and build directories for the ecosystem.

## Use Cases

### 1. Run with a Hardened Policy

Run npm install with the NPM policy (restricts network to npm registries, limits file reads/writes):

```bash
safer-exec --policy=npm -- npm install
```

Other ecosystems:

```bash
safer-exec --policy=pypi -- pip install -r requirements.txt
safer-exec --policy=maven -- mvn compile
safer-exec --policy=cargo -- cargo build
```

### 2. Resource Limits

Prevent runaway processes from consuming host resources:

```bash
# Limit to 512MB RAM and 1 CPU core
safer-exec --max-memory=512 --max-cpu=1.0 -- npm run build

# Limit child process count (anti-fork bomb)
safer-exec --max-memory=256 --max-processes=50 -- npm test

# Set a hard timeout
safer-exec --timeout=30000 -- npm run lint
```

### 3. Network Isolation

Disable all network or restrict to specific hosts:

```bash
# No network at all
safer-exec --disable-network -- cat package.json

# Allow specific hosts and ports
safer-exec --allow-host=api.github.com --port=443 -- curl https://api.github.com

# Combine with policy (user settings override policy defaults)
safer-exec --policy=npm --allow-host=custom.registry.com -- npm install
```

### 4. Filesystem Diffing

Track exactly which files a command creates, modifies, or deletes:

```bash
safer-exec --diff --write-path=. -- npm install
```

This outputs a summary like:

```
[safer-exec] Filesystem diff: +42 added, ~3 modified, -0 deleted
```

### 5. Learning Mode

Discover what a command actually needs by running it in permissive mode:

```bash
safer-exec --learn -- npm install
```

Save the learned policy for reuse:

```bash
safer-exec --learn --learn-output=policy.json -- npm install
```

The learned policy contains the minimal set of read paths, write paths, IPs, and ports the command actually accessed.

### 6. Audit Mode

Capture sandbox violations and resource accesses as structured log entries:

```bash
safer-exec --audit -- npm install
```

### 7. Exec and Fork Control

Restrict which executables can run or prevent forking:

```bash
# Only allow node and npx
safer-exec --allow-exec=node --allow-exec=npx -- npm run build

# Block shells
safer-exec --block-exec=sh --block-exec=bash -- npm install

# Prevent all forking
safer-exec --block-fork -- npm install

# Log every child process
safer-exec --trace-exec -- npm install
```

### 8. JSON Output

Get machine-parseable results for automation:

```bash
safer-exec --json --diff -- npm install
```

Returns:

```json
{
  "stdout": "...",
  "stderr": "...",
  "exitCode": 0,
  "fsDiff": {
    "added": [{ "path": "./node_modules/chalk/index.js", "size": 1234 }],
    "modified": [],
    "deleted": []
  }
}
```

## Node.js API

```js
import { SaferExec } from "@cdxgen/safer-exec";

const result = await new SaferExec()
  .applyPolicy("npm")
  .allowHosts("custom.registry.com")
  .maxMemory(512)
  .maxCPUCores(1.0)
  .enableDiff()
  .enableAudit()
  .run("npm", ["install"]);

console.log(result.exitCode, result.stdout);
console.log(result.fsDiff?.added); // new files
console.log(result.auditLog); // violations
```

### Learning Mode via API

```js
const result = await new SaferExec().enableLearn().run("npm", ["install"]);

console.log(result.learnedPolicy);
// { readPaths: ["/usr", "/etc"], writePaths: ["./node_modules"],
//   allowIPs: ["93.184.216.34"], allowPorts: [443] }
```

### Convenience Function

```js
import { saferExec } from "@cdxgen/safer-exec";

const result = await saferExec("npm", ["install"], {
  allowHosts: ["registry.npmjs.org"],
  readPaths: ["/usr", "/etc/ssl/certs"],
  writePaths: [process.cwd() + "/node_modules"],
});
```

## When to Use

- **Package installation**: Run `npm install`, `pip install`, `cargo build` with hardened policies
- **Build verification**: Run builds with resource limits to catch memory leaks
- **Change detection**: Use `--diff` to see exactly what files a command modifies
- **Policy discovery**: Use `--learn` to generate minimal policies for new commands
- **Security auditing**: Use `--audit` to track resource accesses
- **Fork bomb prevention**: Use `--max-processes` and `--max-memory` for untrusted code
- **Network isolation**: Use `--disable-network` or `--allow-host` for offline builds

## Implementation Notes

- The CLI is a Node.js script (`npm/src/cli.js`) that uses the `SaferExec` class
- All CLI options map directly to `SaferExec` methods
- The Go binary is resolved at runtime: first checks `go/bin/safer-exec` (local build), then falls back to PATH
- Structured output markers (`FSDIFF:`, `LEARNED:`) are parsed from stdout by the runner
- Audit entries are JSON lines on stderr
- Exit code 124 means timeout
- Exit codes 132, 137, 153 are treated as successful OOM kills on macOS
