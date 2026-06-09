# `@cdxgen/safer-exec` Use Cases: Mitigating Supply-Chain Attacks

This document details secure patterns and configurations for using `@cdxgen/safer-exec` to prevent, mitigate, and contain supply-chain attacks when installing or executing dependencies in the **NPM** and **PyPI** ecosystems.

---

## The Threat Landscape: Supply-Chain Vectors

Modern supply-chain attacks target developer environments and build pipelines via compromised or malicious packages. The most common vectors include:

### 1. NPM Lifecycle Scripts (pre/postinstall)

- **Attack Vector**: When `npm install` runs, a dependency specifies a `preinstall`, `install`, or `postinstall` script in its `package.json`. These scripts execute arbitrary shell code.
- **Malicious Behavior**: Reading sensitive host environment variables (e.g. `AWS_ACCESS_KEY_ID`, `NPM_TOKEN`), stealing private keys (`~/.ssh`), writing persistent malware (autostart files), or downloading second-stage executors (e.g. `bun` or custom binaries).
- **Mitigation**: Categorically block execution of arbitrary scripts and enforce zero-leakage policies on the system environment.

### 2. PyPI Malicious setup.py & .pth Imports

- **Attack Vector**: PyPI packages executing via source distributions run `setup.py` (arbitrary Python script) during installation. Additionally, malicious packages can drop `.pth` (Path Configuration) files into Python's `site-packages`, which are executed automatically every time the Python interpreter starts.
- **Malicious Behavior**: Reading secrets, establishing persistence via `.bashrc` modifications, or initiating reverse shells.
- **Mitigation**: Limit package installation to pre-compiled binaries (Wheels only) to prevent compilation-stage script execution, and lock down filesystem write access and socket connections.

---

## Mitigating Supply-Chain Attacks using the CLI

The `@cdxgen/safer-exec` CLI allows wrapping package managers in hardened, platform-native sandboxes.

### Secure NPM / Yarn / PNPM Execution

To safely install npm packages without allowing malicious lifecycle scripts to steal environment credentials, exfiltrate data, or spawn malware:

```bash
# Apply the pre-built npm policy and disable outbound network access after fetching
node npm/src/cli.js --policy=npm --disable-network -- npm install
```

**What this does under the hood:**

- **Filters Environment Variables**: Automatically strips out credentials like `AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, and `NPM_TOKEN` so they cannot be read by dependencies.
- **Blocks Spawning Shells**: Uses `--block-fork` to deny the generation of subprocesses or execution of unauthorized shells.
- **Overrides Configurations**: Automatically sets `npm_config_ignore_scripts=true` to instruct npm directly not to run lifecycle hooks.

---

### Secure PyPI / pip Execution

To install Python dependencies securely:

```bash
# Apply the PyPI policy to enforce Wheel-only downloads and block system-level subprocess forks
node npm/src/cli.js --policy=pypi -- pip install -r requirements.txt
```

**What this does under the hood:**

- **Forces Wheel-Only Installation**: Injects `PIP_ONLY_BINARY=:all:` to prevent downloading source packages (`.tar.gz`) that execute code via `setup.py`.
- **Restricts Workspace Mutations**: Allows writes only to the designated virtual environment directory (`.venv`) and caches, protecting user profiles (`~/.bashrc`, etc.) from persistent edits.
- **Prevents Execution Escapes**: Denies executing arbitrary external utilities (`blockExec: ['*']`) and blocks system forks (`blockFork: true`).

---

## Programmatic Library API Usage

You can embed `@cdxgen/safer-exec` directly in your dev tools, task runners, or automation servers.

### Safe NPM Execution

```javascript
import { SaferExec } from "@cdxgen/safer-exec";

// Execute a clean package installation
const runner = new SaferExec()
  .applyPolicy("npm")
  .disableNetwork() // categorical network block
  .workingDir(process.cwd());

const result = await runner.run("npm", ["install"]);

if (result.exitCode === 0) {
  console.log("Dependencies installed securely.");
} else {
  console.error(
    "Installation aborted or sandbox blocked execution:",
    result.stderr,
  );
}
```

### Safe PyPI/Python Run

```javascript
import { SaferExec } from "@cdxgen/safer-exec";
import { join } from "node:path";

const runner = new SaferExec()
  .applyPolicy("pypi")
  .workingDir(process.cwd())
  // Custom workspace restrictions
  .readPaths(join(process.cwd(), "pyproject.toml"))
  .writePaths(join(process.cwd(), ".venv"));

// Run pip install
const result = await runner.run("pip", ["install", "-r", "requirements.txt"]);

if (result.exitCode !== 0) {
  console.error(
    "pip install failed or was blocked. System integrity preserved!",
  );
}
```

### Advanced Isolation: Zero-Trust Wildcard Execution Control

To guarantee a process can _never_ spawn secondary compilers, curl exfiltrators, or scripting runtimes:

```javascript
import { SaferExec } from "@cdxgen/safer-exec";

const runner = new SaferExec()
  .blockFork() // Block all process forks
  .blockExec("*") // Deny execution of all external programs
  .run("node", ["app.js"]);
```

This forces the process to run entirely within its single initial memory space and denies any `child_process` execution attempts.

---

## Standalone Binary in CI/CD Pipelines (Zero-Dependency Sandboxing)

In CI/CD environments (like GitHub Actions or Azure Pipelines), you can use the pre-built standalone binaries to execute untrusted scripts or package installers (e.g. `npm install`, `pip install`) with zero dependencies on Node.js or global package installations.

### 1. GitHub Actions Integration

Use this pattern to securely install dependencies during a workflow run:

```yaml
name: Secure Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download & Verify safer-exec Standalone Binary
        run: |
          VERSION="0.5.0"
          # Download standalone binary and SHA checksum
          curl -L -O "https://github.com/cdxgen/safer-exec/releases/download/v${VERSION}/safer-exec-linux-amd64"
          curl -L -O "https://github.com/cdxgen/safer-exec/releases/download/v${VERSION}/safer-exec-linux-amd64.sha256"

          # Verify checksum integrity
          sha256sum -c safer-exec-linux-amd64.sha256
          chmod +x safer-exec-linux-amd64
          mv safer-exec-linux-amd64 /usr/local/bin/safer-exec

      - name: Secure dependency installation
        run: |
          # Run npm install using the pre-built npm policy preset
          safer-exec --policy=npm -- npm install
```

### 2. Azure Pipelines Integration

Apply the same protection inside Azure Pipelines:

```yaml
trigger:
  - main

pool:
  vmImage: "ubuntu-latest"

steps:
  - checkout: self

  - script: |
      VERSION="0.5.0"
      curl -L -o safer-exec "https://github.com/cdxgen/safer-exec/releases/download/v$(VERSION)/safer-exec-linux-amd64"
      curl -L -o safer-exec.sha256 "https://github.com/cdxgen/safer-exec/releases/download/v$(VERSION)/safer-exec-linux-amd64.sha256"
      sha256sum -c safer-exec.sha256
      chmod +x safer-exec
      sudo mv safer-exec /usr/local/bin/
    displayName: "Install safer-exec Standalone"

  - script: |
      safer-exec --policy=npm -- npm install
    displayName: "Secure npm install"
```

Using the standalone binary ensures that even if Node.js or other tools are not yet configured on the runner, process sandboxing works out of the box.

---

## Dynamic Library Tracing for SBOM Generation

Software Bill of Materials (SBOM) generation often relies on static analysis, which can miss dynamically loaded libraries (`dlopen`-ed shared objects or platform-specific frameworks). `@cdxgen/safer-exec` supports dynamic library tracing to capture libraries loaded at runtime, enabling more complete and accurate SBOMs.

### How it Works

When `traceLibraries()` is enabled:

1. On **glibc Linux**, `safer-exec` injects a precompiled `rtld-audit` helper using `LD_AUDIT`. The helper intercepts runtime linker actions (specifically `la_objopen`) and reports every loaded `.so` library.
2. On **musl Linux (Alpine)**, `safer-exec` runs an active process maps monitor that periodically scans `/proc/<pid>/maps` of the parent and all spawned subprocesses.
3. On **macOS**, `safer-exec` parses Seatbelt audit logs under the `file-read` event type matching `.dylib` or `.framework` paths.

In all cases, library loads are streamed to `stderr` as JSON lines:

```json
{"type":"lib-load","target":"/lib/x86_64-linux-gnu/libc.so.6"}
{"type":"lib-load","target":"/usr/lib/x86_64-linux-gnu/libcrypto.so.3"}
```

### JSON Structure

Each entry consists of:

- `type`: "lib-load" (identifies the event as a dynamic library loading event).
- `target`: Absolute path to the shared library (`.so`, `.dylib`, or framework path).

### CLI Example: Collecting Library Traces

Run the command with dynamic library tracing enabled, directing standard output and audit logs accordingly:

```bash
# Execute node app.js and capture library loads from stderr
node npm/src/cli.js --trace-libraries -- node app.js 2> raw_audit.log
```

You can filter and extract the dynamic libraries using standard tools like `jq`:

```bash
# Filter and extract library paths into a clean JSON list
grep '{"type":"lib-load"' raw_audit.log | jq -s 'map(.target) | unique' > dynamic_libraries.json
```

### Programmatic Example: Generating Dependency Artifacts

You can consume these events programmatically using the Node.js API:

```javascript
import { SaferExec } from "@cdxgen/safer-exec";

const result = await new SaferExec()
  .traceLibraries()
  .enableAudit()
  .run("node", ["app.js"]);

if (result.auditLog) {
  // Filter for dynamic library loads
  const loadedLibraries = result.auditLog
    .filter((event) => event.type === "lib-load")
    .map((event) => event.target);

  console.log("Dynamically loaded libraries detected:", loadedLibraries);
  // Example output: ["/usr/lib/libsqlite3.dylib", "/usr/lib/libz.1.dylib"]

  // These paths can then be translated into SPDX/CycloneDX external references
  // or added as components to the SBOM.
}
```
