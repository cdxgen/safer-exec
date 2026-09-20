#!/usr/bin/env node

/**
 * safer-exec CLI — sandboxed command execution from the terminal.
 *
 * Run any command inside an OS-level sandbox with configurable policies,
 * resource limits, filesystem diffing, and behavioral auto-profiling.
 *
 * @module cli
 *
 * @example
 * # Run with a built-in policy
 * safer-exec --policy=npm -- npm install
 *
 * # Run with resource limits
 * safer-exec --max-memory=512 --max-cpu=1.0 -- npm run build
 *
 * # Disable network access
 * safer-exec --disable-network -- cat package.json
 *
 * # Enable filesystem diffing
 * safer-exec --diff --write-path=/tmp -- npm install
 *
 * # Learning mode — auto-generate a strict policy
 * safer-exec --learn -- npm install
 */

import { parseArgs } from 'node:util';
import { SaferExec } from './index.js';
import { runPipe, resolveBinaryPath } from './runner.js';
import { writeFileSync, readFileSync, appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Read the package version from package.json. Falls back to a placeholder
 * if the file cannot be read (e.g., during development without npm install).
 */
function readPackageVersion() {
  try {
    const pkgPath = join(__dirname, '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    return pkg.version || '0.0.0-dev';
  } catch {
    return '0.0.0-dev';
  }
}

const VERSION = readPackageVersion();

/**
 * Print help text to stdout.
 */
function printHelp() {
  const help = `
Usage:
  safer-exec [OPTIONS] -- COMMAND [ARGS...]
  safer-exec diagnostics
  safer-exec hook <pre|post|audit> [OPTIONS]
  safer-exec harness <list|install|uninstall|import> [OPTIONS]

Hook mode (agentic harness integration):
  safer-exec hook pre               Read a PreToolUse payload from stdin, audit it
                                    (JSONL trail), optionally enforce converted
                                    permission rules / wrap Bash in the sandbox
  safer-exec hook post              Audit a PostToolUse payload (file changes, results)
  safer-exec hook audit [--tail=N] [--json] [--last=N] [--follow]
                                    Show the audit trail (default ~/.safer-exec/hooks-audit.jsonl)
  Environment: SAFER_EXEC_HOOK_CONFIG, SAFER_EXEC_HOOK_MODE=enforce,
               SAFER_EXEC_HOOK_WRAP=1, SAFER_EXEC_HOOK_POLICY,
               SAFER_EXEC_HOOK_AUDIT_LOG, SAFER_EXEC_HOOK_HARNESS

Harness mode (install / convert permissions):
  safer-exec harness list                                   Detect harness configs
  safer-exec harness install <id> [--scope=project|user]
                              [--mode=audit|enforce] [--policy-file=<file>]
                              [--events=pre,post] [--wrap] [--timeout=<sec>]
                              [--no-import]
  safer-exec harness uninstall <id> [--scope=project|user]
  safer-exec harness import <id> [--path=<file>] [--out=<policy.json>] [--print]
  (the harness id may also be given as --harness=<id>)
  Harnesses: claude-code, zcode, codex, gemini, cursor, factory, copilot, opencode

Options:
  -p, --policy=<name>        Apply a built-in policy preset
                             Available: npm, pypi, maven, cargo, rubygems,
                                        composer, deno, gomod, bun, pnpm,
                                        pnpmInstall, poku, uv, nuget, cdxgen
  -m, --max-memory=<mb>      Memory limit in megabytes
  -c, --max-cpu=<cores>      CPU limit as fractional cores (e.g. 0.5)
      --max-processes=<n>    Max child processes (anti-fork bomb)
      --max-read-iops=<n>    Max read IOPS (Linux only)
      --max-write-iops=<n>   Max write IOPS (Linux only)
      --max-read-bps=<n>     Max read bandwidth in bytes/s (Linux only)
      --max-write-bps=<n>    Max write bandwidth in bytes/s (Linux only)
  -t, --timeout=<ms>         Hard kill timeout in milliseconds

  -n, --disable-network      Disable all network access
      --allow-loopback       Allow localhost/loopback connections
      --proxy-egress         Enforce hostname egress via local CONNECT proxy (HTTP_PROXY injection)
  -H, --allow-host=<host>    Allow network access to specific host (repeatable)
      --allow-url=<url>      Allow network access to specific URL/Pattern (Linux only, repeatable)
      --port=<port>          Allow network access to specific TCP port (repeatable)

  -r, --read-path=<path>     Allow reading from filesystem path (repeatable)
  -w, --write-path=<path>    Allow writing to filesystem path (repeatable)
  -e, --env=<KEY=VALUE>      Set environment variable in sandbox (repeatable)
  -C, --cwd=<dir>            Set working directory for command

  --allow-exec=<cmd>         Allow only specific executables to run (repeatable)
  --block-exec=<cmd>         Block specific executables from running (repeatable)
  --block-fork               Prevent the command from forking new processes
  --block-interpreters       Deny Apple-signed scripting engines / sampling tools that can load in-memory shellcode (macOS)
  --deny-persistence-writes  Deny writes to LaunchAgents, plugin loaders, /usr/local/bin and other persistence locations
  --allow-writable-dylib-load Permit loading .dylib from writable/temp dirs under --block-interpreters (macOS)
  --allow-security-services Permit mach-lookup to securityd + the user database (macOS; widens the sandbox to reach the keychain — .NET needs it, TLS validation does not)
  --block-jit                Block W^X / JIT syscalls (mprotect PROT_EXEC, memfd_create, MAP_JIT); breaks V8/JVM (Linux)
  --trace-exec               Log every child process spawned (fork + exec audit)
  --trace-libraries          Track dynamically loaded libraries at runtime
  --trace-output-file=<file> Write tracked libraries to file (implies trace-libraries)
  --trace-temp-dir=<dir>     Temporary directory to extract dynamic library helper to (implies trace-libraries)
  --trace-http-urls          Capture HTTPS request URLs/methods via eBPF TLS uprobes (Linux only, requires CAP_BPF)
  --trace-crypto             Enable cryptographic tracing: cipher suites, libraries (auto-enables --trace-http-urls)
  --cbom-output=<file>       Write CycloneDX CBOM JSON to file (requires --trace-crypto)
  --crypto-probe-mode=<mode> Crypto probe depth: "tls-only" (default) or "operations"

  -d, --diff                 Enable filesystem mutation diffing
  -l, --learn                Enable behavioral auto-profiling (learning mode)
      --learn-output=<file>  Write learned policy to file
      --dry-run              Run with all operations denied; report what the command attempted (no side effects)
      --validate-profile     Validate Seatbelt profile syntax (macOS only)
  -a, --audit                Enable sandbox violation auditing
      --audit-output-file=<f> Write audit log to file (implies audit)
  -s, --strict               Treat sandbox setup warnings as errors
      --allow-envs=<vars>     Comma-separated host env vars to pass through (sanitized by default; also the opt-in for loader-control vars like DYLD_*, LD_*, NODE_OPTIONS)
      --allow-hidden          Allow access to hidden files and directories (blocked by default)
      --allow-listen=<list>   Comma-separated list of IP addresses or ip:port strings to allow listening on (blocked by default)
      --no-set-up-dev         Disable minimal /dev setup (default: enabled, Linux only)
      --no-die-with-parent    Disable PR_SET_PDEATHSIG orphan prevention (default: enabled, Linux only)
      --no-new-session        Disable setsid() terminal disconnect (default: enabled, Linux only)
      --bind-use-fd           Enable fd-based bind mounting for TOCTTOU safety (Linux only)
      --tmp-overlay=<path>    Create an ephemeral writable overlay at path (repeatable, Linux only)
      --protect-system=<mode>   Auto-make system dirs read-only: strict, full, or off (Linux only)
      --protect-home=<mode>     Home dir isolation: read-only, tmpfs, or off (Linux only)
      --private-tmp             Replace /tmp and /var/tmp with fresh tmpfs (Linux only)
      --lock-file=<path>      Acquire shared advisory lock on file for sandbox duration (repeatable)
      --seccomp-filter=<spec> Stack additional seccomp-bpf filter (base64 encoded program or file path, repeatable, Linux only)
      --seccomp-policy=<policy> Kafel-style seccomp policy string (e.g. "ALLOW openat; DEFAULT KILL", Linux only)
      --bind-fd=<FD:DEST[:ro]>  Bind-mount pre-opened FD to destination path (repeatable, Linux only)
                                 Use ':ro' suffix for read-only mount
      --lock-file-exclusive=<p> Acquire exclusive (write) advisory lock on file (repeatable)
      --map-to-target-uid       Map UID 0 in namespace to caller's real UID (Linux only)

  -j, --json                 Output results as JSON
  -h, --help                 Show this help message
  -v, --version              Show version

Diagnostics:
  safer-exec diagnostics        Show OS capabilities and feature support
  safer-exec bootstrap-apparmor Load AppArmor profile for user namespaces (Linux, requires sudo)Examples:
  # Run npm install with the NPM policy
  safer-exec --policy=npm -- npm install

  # Run with resource limits
  safer-exec --max-memory=512 --max-cpu=1.0 -- npm run build

  # Disable network and enable auditing
  safer-exec --disable-network --audit -- cat package.json

  # Filesystem diffing — see what files a command creates/modifies
  safer-exec --diff --write-path=/tmp -- sh -c "echo hello > /tmp/out.txt"

  # Learning mode — auto-generate a strict policy from observed behavior
  safer-exec --learn --learn-output=policy.json -- npm install

  # Custom sandbox with specific hosts and ports
  safer-exec --allow-host=api.github.com --port=443 -- curl https://api.github.com

  # Restrict which executables the command can run
  safer-exec --allow-exec=node --allow-exec=npx -- npm run build

  # Log all child processes spawned
  safer-exec --trace-exec -- npm install
`.trimStart();

  process.stdout.write(help + '\n');
}

/**
 * Parse CLI arguments using Node.js built-in parseArgs.
 *
 * @returns {{ values: Object, positionals: string[] }}
 */
function parseCliArgs() {
  return parseArgs({
    options: {
      policy: {
        type: 'string',
        short: 'p',
      },
      'policy-file': {
        type: 'string',
      },
      'disable-network': {
        type: 'boolean',
        short: 'n',
      },
      'allow-loopback': {
        type: 'boolean',
      },
      'max-memory': {
        type: 'string',
        short: 'm',
      },
      'allow-crypto': {
        type: 'boolean',
      },
      'block-crypto': {
        type: 'boolean',
      },
      'block-crypto-entropy': {
        type: 'boolean',
      },
      'detect-fips': {
        type: 'boolean',
      },
      'strict-fips': {
        type: 'boolean',
      },
      'allow-gpu': {
        type: 'boolean',
      },
      'block-tpm': {
        type: 'boolean',
      },
      'spoof-antivm': {
        type: 'boolean',
      },
      'trace-libraries': {
        type: 'boolean',
      },
      'trace-http-urls': {
        type: 'boolean',
      },
      'trace-crypto': {
        type: 'boolean',
      },
      'cbom-output': {
        type: 'string',
      },
      'crypto-probe-mode': {
        type: 'string',
      },
      'trace-output-file': {
        type: 'string',
      },
      'trace-temp-dir': {
        type: 'string',
      },
      'max-cpu': {
        type: 'string',
        short: 'c',
      },
      'max-processes': {
        type: 'string',
      },
      'max-read-iops': {
        type: 'string',
      },
      'max-write-iops': {
        type: 'string',
      },
      'max-read-bps': {
        type: 'string',
      },
      'max-write-bps': {
        type: 'string',
      },
      timeout: {
        type: 'string',
        short: 't',
      },
      'allow-host': {
        type: 'string',
        multiple: true,
        short: 'H',
      },
      'allow-url': {
        type: 'string',
        multiple: true,
      },
      'allow-cipher': {
        type: 'string',
        multiple: true,
      },
      port: {
        type: 'string',
        multiple: true,
      },
      'read-path': {
        type: 'string',
        multiple: true,
        short: 'r',
      },
      'write-path': {
        type: 'string',
        multiple: true,
        short: 'w',
      },
      env: {
        type: 'string',
        multiple: true,
        short: 'e',
      },
      cwd: {
        type: 'string',
        short: 'C',
      },
      'allow-exec': {
        type: 'string',
        multiple: true,
      },
      'block-exec': {
        type: 'string',
        multiple: true,
      },
      'block-fork': {
        type: 'boolean',
      },
      'block-interpreters': {
        type: 'boolean',
      },
      'deny-persistence-writes': {
        type: 'boolean',
      },
      'allow-writable-dylib-load': {
        type: 'boolean',
      },
      'allow-security-services': {
        type: 'boolean',
      },
      'block-jit': {
        type: 'boolean',
      },
      'proxy-egress': {
        type: 'boolean',
      },
      'trace-exec': {
        type: 'boolean',
      },
      audit: {
        type: 'boolean',
        short: 'a',
      },
      'audit-output-file': {
        type: 'string',
      },
      diff: {
        type: 'boolean',
        short: 'd',
      },
      learn: {
        type: 'boolean',
        short: 'l',
      },
      'dry-run': {
        type: 'boolean',
      },
      'learn-output': {
        type: 'string',
      },
      'validate-profile': {
        type: 'boolean',
      },
      strict: {
        type: 'boolean',
        short: 's',
      },
      'allow-envs': {
        type: 'string',
        multiple: true,
      },
      'allow-hidden': {
        type: 'boolean',
      },
      'allow-listen': {
        type: 'string',
        multiple: true,
      },
      'no-set-up-dev': {
        type: 'boolean',
      },
      'no-die-with-parent': {
        type: 'boolean',
      },
      'no-new-session': {
        type: 'boolean',
      },
      'bind-use-fd': {
        type: 'boolean',
      },
      'tmp-overlay': {
        type: 'string',
        multiple: true,
      },
      'lock-file': {
        type: 'string',
        multiple: true,
      },
      'seccomp-filter': {
        type: 'string',
        multiple: true,
      },
      'protect-system': {
        type: 'string',
      },
      'protect-home': {
        type: 'string',
      },
      'private-tmp': {
        type: 'boolean',
      },
      'bind-fd': {
        type: 'string',
        multiple: true,
      },
      'seccomp-policy': {
        type: 'string',
      },
      'lock-file-exclusive': {
        type: 'string',
        multiple: true,
      },
      'map-to-target-uid': {
        type: 'boolean',
      },
      json: {
        type: 'boolean',
        short: 'j',
      },
      help: {
        type: 'boolean',
        short: 'h',
      },
      version: {
        type: 'boolean',
        short: 'v',
      },
    },
    withValue: [
      'policy',
      'policy-file',
      'max-memory',
      'max-cpu',
      'max-processes',
      'max-read-iops',
      'max-write-iops',
      'max-read-bps',
      'max-write-bps',
      'timeout',
      'allow-host',
      'port',
      'read-path',
      'write-path',
      'env',
      'cwd',
      'learn-output',
      'dry-run',
      'trace-output-file',
      'trace-temp-dir',
      'allow-exec',
      'block-exec',
      'tmp-overlay',
      'lock-file',
      'seccomp-filter',
      'bind-fd',
      'lock-file-exclusive',
      'protect-system',
      'protect-home',
      'seccomp-policy',
    ],
    allowPositionals: true,
  });
}

/**
 * Validate a numeric CLI option and return the parsed value.
 *
 * @param {string} value - The raw string value
 * @param {string} name - The option name for error messages
 * @param {boolean} integer - Whether to require an integer
 * @returns {number}
 */
function parseNumeric(value, name, integer = true) {
  const parsed = integer ? parseInt(value, 10) : parseFloat(value);
  if (isNaN(parsed) || parsed < 0) {
    process.stderr.write(
      `[safer-exec] Error: invalid --${name} value: "${value}". Must be a positive ${integer ? 'integer' : 'number'}.\n`
    );
    process.exit(1);
  }
  return parsed;
}

/**
 * Build a SaferExec instance from parsed CLI values.
 *
 * @param {Object} values - Parsed argument values
 * @param {string} cmd - The command to execute
 * @param {string[]} args - Command arguments
 * @returns {{ exec: SaferExec, options: Object }}
 */
function buildExec(values, cmd, args) {
  const exec = new SaferExec();

  // Apply built-in policy if specified
  if (values.policy) {
    try {
      exec.applyPolicy(values.policy);
    } catch (err) {
      process.stderr.write(`[safer-exec] Error: ${err.message}\n`);
      process.exit(1);
    }
  }

  // Apply policy file (after named preset; CLI flags still override)
  if (values['policy-file']) {
    try {
      exec.applyPolicyFile(values['policy-file']);
    } catch (err) {
      process.stderr.write(`[safer-exec] Error loading policy file: ${err.message}\n`);
      process.exit(1);
    }
  }

  // Resource limits
  if (values['max-memory']) {
    exec.maxMemory(parseNumeric(values['max-memory'], 'max-memory'));
  }
  if (values['max-cpu']) {
    exec.maxCPUCores(parseNumeric(values['max-cpu'], 'max-cpu', false));
  }
  if (values['max-processes']) {
    exec.maxProcesses(parseNumeric(values['max-processes'], 'max-processes'));
  }
  if (values['max-read-iops']) {
    exec.maxReadIOPS(parseNumeric(values['max-read-iops'], 'max-read-iops'));
  }
  if (values['max-write-iops']) {
    exec.maxWriteIOPS(parseNumeric(values['max-write-iops'], 'max-write-iops'));
  }
  if (values['max-read-bps']) {
    exec.maxReadBps(parseNumeric(values['max-read-bps'], 'max-read-bps'));
  }
  if (values['max-write-bps']) {
    exec.maxWriteBps(parseNumeric(values['max-write-bps'], 'max-write-bps'));
  }
  if (values.timeout) {
    exec.timeout(parseNumeric(values.timeout, 'timeout'));
  }

  // Network
  if (values['disable-network']) {
    exec.disableNetwork();
  }
  if (values['allow-loopback']) {
    exec.allowLoopback();
  }
  if (values['allow-host'] && values['allow-host'].length > 0) {
    exec.allowHosts(...values['allow-host']);
  }
  if (values['allow-url'] && values['allow-url'].length > 0) {
    exec.allowUrls(...values['allow-url']);
  }
  if (values.port && values.port.length > 0) {
    exec.allowPorts(...values.port.map((p) => parseNumeric(p, 'port')));
  }

  // Filesystem
  if (values['read-path'] && values['read-path'].length > 0) {
    exec.readPaths(...values['read-path']);
  }
  if (values['write-path'] && values['write-path'].length > 0) {
    exec.writePaths(...values['write-path']);
  }

  // Environment
  if (values.env) {
    for (const envStr of values.env) {
      const idx = envStr.indexOf('=');
      if (idx > 0) {
        exec.env(envStr.slice(0, idx), envStr.slice(idx + 1));
      }
    }
  }

  // Working directory
  if (values.cwd) {
    exec.workingDir(values.cwd);
  }

  // Exec/fork control
  if (values['allow-exec'] && values['allow-exec'].length > 0) {
    exec.allowExec(...values['allow-exec']);
  }
  if (values['block-exec'] && values['block-exec'].length > 0) {
    exec.blockExec(...values['block-exec']);
  }
  if (values['block-fork']) {
    exec.blockFork();
  }
  if (values['block-interpreters']) {
    exec.blockInterpreters();
  }
  if (values['deny-persistence-writes']) {
    exec.denyPersistenceWrites();
  }
  if (values['allow-writable-dylib-load']) {
    exec.allowWritableDylibLoad();
  }
  if (values['allow-security-services']) {
    exec.allowSecurityServices();
  }
  if (values['block-jit']) {
    exec.blockJIT();
  }
  if (values['proxy-egress']) {
    exec.proxyEgress();
  }
  if (values['trace-exec']) {
    exec.traceExec();
  }

  if (values['allow-envs'] && values['allow-envs'].length > 0) {
    const list = [];
    for (const item of values['allow-envs']) {
      list.push(...item.split(',').map(s => s.trim()).filter(Boolean));
    }
    exec.allowEnvs(...list);
  }
  if (values['allow-hidden']) {
    exec.allowHidden();
  }
  if (values['allow-listen'] && values['allow-listen'].length > 0) {
    const list = [];
    for (const item of values['allow-listen']) {
      list.push(...item.split(',').map(s => s.trim()).filter(Boolean));
    }
    exec.allowListen(list);
  }
  if (values['no-set-up-dev']) {
    exec.setUpDev(false);
  }
  if (values['no-die-with-parent']) {
    exec.dieWithParent(false);
  }
  if (values['no-new-session']) {
    exec.newSession(false);
  }
  if (values['bind-use-fd']) {
    exec.bindUseFd(true);
  }
  if (values['tmp-overlay'] && values['tmp-overlay'].length > 0) {
    exec.tmpOverlayPaths(...values['tmp-overlay']);
  }
  if (values['lock-file'] && values['lock-file'].length > 0) {
    exec.lockFiles(...values['lock-file']);
  }
  if (values['seccomp-filter'] && values['seccomp-filter'].length > 0) {
    const specs = [];
    for (const item of values['seccomp-filter']) {
      if (item.startsWith('/') || item.startsWith('./') || item.startsWith('../')) {
        specs.push({ path: item });
      } else {
        specs.push({ program: item });
      }
    }
    exec.seccompFilters(specs);
  }

  if (values['protect-system']) {
    exec.protectSystem(values['protect-system']);
  }
  if (values['protect-home']) {
    exec.protectHome(values['protect-home']);
  }
  if (values['private-tmp']) {
    exec.privateTmp();
  }
  if (values['bind-fd'] && values['bind-fd'].length > 0) {
    const specs = [];
    for (const item of values['bind-fd']) {
      const parts = item.split(':');
      if (parts.length >= 2) {
        const fd = parseInt(parts[0], 10);
        if (!isNaN(fd)) {
          const target = parts[1];
          const readOnly = parts.length >= 3 && parts[2] === 'ro';
          specs.push({ fd, target, readOnly });
        }
      }
    }
    if (specs.length > 0) {
      exec.bindFds(...specs);
    }
  }
  if (values['seccomp-policy']) {
    exec.seccompPolicy(values['seccomp-policy']);
  }
  if (values['lock-file-exclusive'] && values['lock-file-exclusive'].length > 0) {
    exec.lockFilesExclusive(...values['lock-file-exclusive']);
  }
  if (values['map-to-target-uid']) {
    exec.mapToTargetUid();
  }

  // Features
  if (values.audit || values['audit-output-file']) {
    exec.enableAudit();
    if (values['audit-output-file']) {
      exec.suppressLibLoadStderr();
    }
  }
  if (values.diff) {
    exec.enableDiff();
  }
  if (values.learn) {
    exec.enableLearn();
  }
  if (values['dry-run']) {
    exec.enableDryRun();
  }
  if (values['validate-profile']) {
    exec.validateProfile();
  }
  if (values.strict) {
    exec.strict();
  }
  if (values['allow-crypto'] !== undefined) {
    exec.allowCrypto(values['allow-crypto']);
  }
  if (values['block-crypto']) {
    exec.blockCrypto();
  }
  if (values['block-crypto-entropy']) {
    exec.blockCryptoEntropy();
  }
  if (values['detect-fips']) {
    exec.detectFIPS();
  }
  if (values['strict-fips']) {
    exec.strictFIPS();
  }
  if (values['allow-gpu']) {
    exec.allowGPU();
  }
  if (values['block-tpm']) {
    exec.blockTPM();
  }
  if (values['spoof-antivm']) {
    exec.spoofAntiVM();
  }
  if (values['trace-http-urls']) {
    exec.traceHTTPURLs();
  }
  if (values['trace-crypto']) {
    exec.traceCrypto();
  }
  if (values['cbom-output']) {
    exec.cbom(values['cbom-output']);
  }
  if (values['allow-cipher']) {
    exec.allowCiphers(values['allow-cipher']);
  }
  if (values['crypto-probe-mode']) {
    exec.cryptoProbeMode(values['crypto-probe-mode']);
  }
  if (values['trace-libraries'] || values['trace-output-file'] || values['trace-temp-dir']) {
    exec.traceLibraries();
    if (values['trace-output-file']) {
      exec.suppressLibLoadStderr();
    }
    if (values['trace-temp-dir']) {
      exec.traceTempDir(values['trace-temp-dir']);
    }
  }

  return { exec };
}

/**
 * Format a capability/feature row with a tick or cross.
 */
function formatCheck(available, label, detail) {
  const mark = available ? '\u2713' : '\u2717';
  const detailStr = detail ? '  ' + detail : '';
  return '  ' + mark + ' ' + label.padEnd(26) + detailStr;
}

/**
 * Run diagnostics and print a formatted report to stdout.
 */
async function runDiagnosticsAndPrint() {
  let data;
  try {
    data = await SaferExec.diagnostics();
  } catch (err) {
    process.stderr.write('[safer-exec] Diagnostics error: ' + err.message + '\n');
    process.exit(1);
  }

  const out = [];
  out.push('');
  out.push('safer-exec v' + readPackageVersion() + ' \u2014 Diagnostics');
  out.push('='.repeat(56));
  out.push('');
  out.push('  Platform:    ' + data.platform + ' (' + data.arch + ')');
  out.push('  Kernel:      ' + data.kernel);
  out.push('  Release:     ' + (data.release || 'N/A'));
  out.push('  Node.js:     ' + (data.nodeVersion || process.version));
  out.push('');

  // OS Capabilities
  out.push('OS Capabilities');
  out.push('\u2500'.repeat(56));
  for (const [key, cap] of Object.entries(data.capabilities || {})) {
    const label = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    out.push(formatCheck(cap.available, label, cap.detail || ''));
  }
  out.push('');

  // SaferExec Features
  out.push('SaferExec Features');
  out.push('\u2500'.repeat(56));
  const featureLabels = {
    network_isolation: 'Network Isolation',
    file_read_restriction: 'File Read Restriction',
    file_write_restriction: 'File Write Restriction',
    memory_limit: 'Memory Limit',
    cpu_limit: 'CPU Limit',
    process_limit: 'Process Limit',
    io_limit: 'IO Limit (Cgroup v2)',
    exec_control: 'Exec Control',
    fork_control: 'Fork Control',
    audit_tracing: 'Audit Tracing',
    filesystem_diff: 'Filesystem Diff',
    learning_mode: 'Learning Mode',
    strict_mode: 'Strict Mode',
    crypto_control: 'Crypto Control',
    fips_detection: 'FIPS Detection',
    gpu_control: 'GPU Control',
    tpm_control: 'TPM Control',
    antivm_spoofing: 'Anti-VM Spoofing',
    trace_libraries: 'Library Tracing',
    trace_http_urls: 'HTTP URL Tracing',
    allow_url_rules: 'Allow URL Rules',
    trace_crypto: 'Cryptographic Tracing',
    time_isolation: 'Time Namespace',
    ipc_isolation: 'IPC Namespace',
    landlock_filesystem: 'Landlock Filesystem',
    landlock_layers: 'Landlock Layer Info',
    apparmor_safer_exec: 'AppArmor Profile',
    proc_hidepid: 'Proc Hidepid',
    profile_validation: 'Profile Validation',
    dev_setup: 'Dev Setup',
    die_with_parent: 'Die With Parent',
    new_session: 'New Session',
    tmp_overlay: 'Tmp Overlay',
    file_locks: 'File Locks',
    json_status: 'JSON Status',
    bind_use_fd: 'Bind Use FD',
    seccomp_stacking: 'Seccomp Stacking',
    pid_reaper: 'PID Reaper',
    mount_propagation_control: 'Mount Propagation Control',
    submount_readonly_enforcement: 'Submount Read-Only Enforcement',
    proc_hardening: 'Proc Hardening',
    extra_fd_cleanup: 'Extra FD Cleanup',
    cgroup_v1_fallback: 'Cgroup v1 Fallback',
    protect_system: 'ProtectSystem',
    protect_home: 'ProtectHome',
    private_tmp: 'Private Tmp',
    cross_ns_fd_binding: 'Cross-NS FD Binding',
    exclusive_file_locks: 'Exclusive File Locks',
    map_to_target_uid: 'Map to Target UID',
    kafel_seccomp_policy: 'Kafel Seccomp Policy',
    landlock_ioctl_control: 'Landlock IOCTL Control',
    landlock_udp_control: 'Landlock UDP Control',
    landlock_scoped_rules: 'Landlock Scoped Rules',
  };
  for (const [key, label] of Object.entries(featureLabels)) {
    const available = data.features && data.features[key] === true;
    out.push(formatCheck(available, label, ''));
  }
  out.push('');

  // Summary
  const totalFeatures = Object.keys(featureLabels).length;
  const supported = Object.entries(data.features || {}).filter(([k, v]) => featureLabels[k] && v === true).length;
  out.push('  Summary: ' + supported + '/' + totalFeatures + ' features supported');
  out.push('');

  process.stdout.write(out.join('\n') + '\n');
}

/**
 * Dispatch the `hook` subcommand.
 *
 * @param {string[]} rest arguments after `hook`
 * @returns {Promise<number>} exit code
 */
async function runHookSubcommand(rest) {
  const sub = rest[0];
  const args = rest.slice(1);
  if (sub !== 'pre' && sub !== 'post' && sub !== 'audit') {
    process.stderr.write('[safer-exec] Usage: safer-exec hook <pre|post|audit> [--tail=N] [--json] [--last=N] [--follow]\n');
    return 1;
  }
  const { runHookCli, readAuditTrail, loadHookConfig } = await import('./hooks.js');
  if (sub === 'pre' || sub === 'post') {
    return runHookCli(sub);
  }
  // audit viewer
  const flags = parseSimpleFlags(args);
  const config = loadHookConfig();
  const file = flags['file'] || config.auditLog;
  const follow = Boolean(flags.follow || flags.f);
  const records = readAuditTrail(file, { last: Number(flags.tail || flags.last || (follow ? 10 : 0)) });
  if (flags.json) {
    process.stdout.write(JSON.stringify(records, null, 2) + '\n');
    return 0;
  }
  if (records.length === 0 && !follow) {
    process.stdout.write(`No audit records in ${file}\n`);
    return 0;
  }
  process.stdout.write(
    `safer-exec hook audit trail (${file}) — ${records.length} records${follow ? ', following (Ctrl-C to stop)' : ''}\n`
  );
  for (const r of records) process.stdout.write(formatAuditRecord(r));
  if (follow) return followAuditTrail(file, readAuditTrail(file, {}).length);
  return 0;
}

/**
 * Render one audit record as a trail line.
 *
 * @param {Object} r
 * @returns {string}
 */
function formatAuditRecord(r) {
  // Engine entries (from wrapped runs) carry type/target; hook records carry event/activity
  const isEngine = !r.event && r.type;
  const act = r.activity || {};
  const target = act.command || act.path || act.url || act.query || act.server ||
    r.target || r.details || '';
  const line = String(target).replace(/\s+/g, ' ').slice(0, 100);
  const decision = r.decision && r.decision !== 'passthrough' ? ` [${r.decision}]` : '';
  const when = (r.ts || '').slice(11, 19);
  if (isEngine) {
    const note = r.details && r.details !== r.target ? ` — ${String(r.details).slice(0, 40)}` : '';
    return `${when || '  (rt)  '} (safer-exec-rt) ${String(r.type).padEnd(18)} ${line}${note}\n`;
  }
  const warn = r.enforcementWarning ? `  !! ${r.enforcementWarning}` : '';
  return `${when} ${String(r.harness || '').padEnd(11)} ${(r.event || '').padEnd(12)} ` +
    `${String(r.tool || '').padEnd(12)} ${line}${decision}${r.wrapped ? ' (sandboxed)' : ''}${warn}\n`;
}

/**
 * Follow an audit trail like `tail -f`: poll for appended records and render
 * each new one. Runs until interrupted.
 *
 * Polling (not fs.watch) because the hook appends from a short-lived process
 * per tool call, and watch events for appends are unreliable across platforms
 * and network filesystems.
 *
 * @param {string} file audit trail path
 * @param {number} shown number of records already rendered
 * @returns {Promise<number>}
 */
async function followAuditTrail(file, shown) {
  const { readAuditTrail } = await import('./hooks.js');
  let seen = shown;
  await new Promise((resolve) => {
    const timer = setInterval(() => {
      let all;
      try {
        all = readAuditTrail(file, {});
      } catch {
        return; // trail not written yet, or momentarily unreadable
      }
      if (all.length < seen) seen = 0; // truncated or rotated — re-render
      for (const r of all.slice(seen)) process.stdout.write(formatAuditRecord(r));
      seen = all.length;
    }, 500);
    const stop = () => {
      clearInterval(timer);
      resolve(undefined);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  });
  return 0;
}

/**
 * Dispatch the `harness` subcommand (list / install / uninstall / import).
 *
 * @param {string[]} rest arguments after `harness`
 * @returns {Promise<number>} exit code
 */
async function runHarnessSubcommand(rest) {
  const sub = rest[0];
  const args = rest.slice(1);
  const flags = parseSimpleFlags(args);
  // The harness id may be given positionally (`harness install zcode`) or as
  // a flag (`--harness=zcode`); the flag wins when both are present.
  const positionalId = args.find((a) => !a.startsWith('-'));
  const harnessId = flags.harness || positionalId || '';
  const harnesses = await import('./harnesses/index.js');

  if (sub === 'list') {
    const found = harnesses.detectHarnesses();
    process.stdout.write('Detected agentic harness configurations:\n');
    for (const h of found) {
      const existing = h.configs.filter((c) => c.exists).map((c) => c.path);
      const mark = existing.length > 0 ? '\u2713' : ' ';
      process.stdout.write(` ${mark} ${h.id.padEnd(11)} ${h.label.padEnd(18)} ${existing.length ? existing.join(', ') : '(no config found)'}\n`);
    }
    process.stdout.write('\nInstall hooks:      safer-exec harness install --harness=<id>\n');
    process.stdout.write('Import permissions:  safer-exec harness import --harness=<id>\n');
    return 0;
  }

  if (sub === 'import') {
    const id = harnessId;
    if (!id) {
      process.stderr.write('[safer-exec] --harness=<id> is required. See: safer-exec harness list\n');
      return 1;
    }
    try {
      const { policy, sources } = harnesses.importHarnessPolicy(id, { path: flags.path });
      const out = flags.out;
      if (out) {
        writeFileSync(out, JSON.stringify(policy, null, 2) + '\n');
        process.stderr.write(`[safer-exec] Policy written to ${out} (from ${sources.join(', ')})\n`);
      }
      if (flags.print || !out) {
        process.stdout.write(JSON.stringify(policy, null, 2) + '\n');
      }
      return 0;
    } catch (err) {
      process.stderr.write(`[safer-exec] ${err.message}\n`);
      return 1;
    }
  }

  if (sub === 'install') {
    const id = harnessId;
    if (!id) {
      process.stderr.write('[safer-exec] --harness=<id> is required. See: safer-exec harness list\n');
      return 1;
    }
    const events = String(flags.events || 'pre,post').split(',').map((s) => s.trim()).filter((s) => s === 'pre' || s === 'post');
    try {
      const result = harnesses.installHarnessHooks(id, {
        scope: flags.scope || 'project',
        mode: flags.mode === 'enforce' ? 'enforce' : 'audit',
        events: events.length > 0 ? events : ['pre', 'post'],
        wrap: Boolean(flags.wrap),
        policyFile: flags['policy-file'] || '',
        auditLog: flags['audit-log'] || '',
        timeoutSec: flags.timeout ? parseInt(flags.timeout, 10) : 30,
        skipPolicyImport: Boolean(flags['no-import']),
      });
      process.stdout.write(`Installed safer-exec hooks for ${result.harness} (scope: ${result.scope})\n`);
      process.stdout.write(`  Hook config:    ${result.hookConfigFile}\n`);
      process.stdout.write(`  Audit trail:    ${result.auditLog}\n`);
      if (result.policyFile) {
        process.stdout.write(`  Policy:         ${result.policyFile}`);
        process.stdout.write(result.importedFrom.length ? ` (imported from ${result.importedFrom.join(', ')})\n` : '\n');
      } else {
        process.stdout.write('  Policy:         none (no harness permission config found — audit only)\n');
      }
      for (const f of result.hookSettingsFiles) {
        process.stdout.write(`  Harness hooks:  ${f}\n`);
      }
      if (result.mode === 'enforce') {
        process.stdout.write('  Mode:           enforce (deny rules block tools; allow rules auto-approve)\n');
      } else {
        process.stdout.write('  Mode:           audit (observes only). Switch with --mode=enforce\n');
      }
      if (result.wrap) {
        if (result.supportsWrap) {
          process.stdout.write('  Wrapping:       Bash commands rewritten to run inside the safer-exec sandbox\n');
        } else {
          process.stdout.write(
            `  Wrapping:       requested but ${result.harness} ignores hook "updatedInput" — commands run unwrapped\n`
          );
        }
      }
      if (result.warning) {
        process.stderr.write(`[safer-exec] WARNING: ${result.warning}\n`);
      }
      return 0;
    } catch (err) {
      process.stderr.write(`[safer-exec] ${err.message}\n`);
      return 1;
    }
  }

  if (sub === 'uninstall') {
    const id = harnessId;
    if (!id) {
      process.stderr.write('[safer-exec] --harness=<id> is required.\n');
      return 1;
    }
    try {
      const result = harnesses.uninstallHarnessHooks(id, { scope: flags.scope || 'project' });
      if (result.removed.length === 0) {
        process.stdout.write(`No safer-exec hooks found for ${id} (scope: ${flags.scope || 'project'})\n`);
        return 0;
      }
      for (const f of result.removed) {
        process.stdout.write(`Removed safer-exec hooks from ${f}\n`);
      }
      return 0;
    } catch (err) {
      process.stderr.write(`[safer-exec] ${err.message}\n`);
      return 1;
    }
  }

  process.stderr.write('[safer-exec] Usage: safer-exec harness <list|install|uninstall|import> [--harness=<id>] [options]\n');
  return 1;
}

/**
 * Minimal --key=value / --key flag parser for subcommands.
 *
 * @param {string[]} args
 * @returns {Record<string, string|boolean>}
 */
function parseSimpleFlags(args) {
  /** @type {Record<string, string|boolean>} */
  const flags = {};
  for (const arg of args) {
    if (!arg.startsWith('--')) continue;
    const eq = arg.indexOf('=');
    if (eq > 0) {
      flags[arg.slice(2, eq)] = arg.slice(eq + 1);
    } else {
      flags[arg.slice(2)] = true;
    }
  }
  return flags;
}

/**
 * Main CLI entry point.
 */
async function main() {
  const argv = process.argv.slice(2);

  // Subcommands with their own flag surface — dispatch before strict parsing
  if (argv[0] === 'hook') {
    process.exit(await runHookSubcommand(argv.slice(1)));
  }
  if (argv[0] === 'harness') {
    process.exit(await runHarnessSubcommand(argv.slice(1)));
  }

  const { values, positionals } = parseCliArgs();

  // Handle --version
  if (values.version) {
    process.stdout.write(`safer-exec v${VERSION}\n`);
    process.exit(0);
  }

  // Handle --help
  if (values.help) {
    printHelp();
    process.exit(0);
  }

  // Handle diagnostics command
  if (positionals.length === 1 && positionals[0] === 'diagnostics') {
    await runDiagnosticsAndPrint();
    process.exit(0);
  }

  // Handle bootstrap-apparmor command
  if (positionals.length === 1 && positionals[0] === 'bootstrap-apparmor') {
    const { execSync } = await import('node:child_process');
    const { writeFileSync, existsSync } = await import('node:fs');
    if (process.getuid?.() !== 0) {
      process.stderr.write('[safer-exec] Error: bootstrap-apparmor command requires root/sudo privileges.\n');
      process.exit(1);
    }
    const resolvedPath = resolveBinaryPath();
    const binaryPath = (resolvedPath && resolvedPath !== 'safer-exec-rt') ? resolvedPath : '/usr/local/bin/safer-exec-rt';
    if (!existsSync(binaryPath)) {
      process.stderr.write(`[safer-exec] Warning: The binary at ${binaryPath} does not exist. Skipping AppArmor profile creation.\n`);
      process.exit(0);
    }
    const profilePath = '/etc/apparmor.d/safer-exec';
    const profileContent = `
# AppArmor profile for safer-exec — grants permission to create
# unprivileged user namespaces required for full sandbox isolation.
abi <abi/4.0>,
include <tunables/global>

profile safer-exec ${binaryPath} flags=(unconfined) {
  userns,
}
`;
    try {
      process.stdout.write(`Writing AppArmor profile to ${profilePath}...\n`);
      writeFileSync(profilePath, profileContent.trim() + '\n');
      process.stdout.write('Parsing and loading AppArmor profile...\n');
      execSync(`apparmor_parser -r ${profilePath}`);
      process.stdout.write('AppArmor profile loaded successfully! Verify with: sudo aa-status | grep safer-exec\n');
      process.exit(0);
    } catch (err) {
      process.stderr.write(`[safer-exec] Error loading AppArmor profile: ${err.message}\n`);
      process.exit(1);
    }
  }

  // Extract command and args from positionals (after --)
  if (positionals.length === 0) {
    process.stderr.write('[safer-exec] Error: no command specified. Use --help for usage.\n');
    process.exit(1);
  }

  const cmd = positionals[0];
  const args = positionals.slice(1);

  // Build the SaferExec instance
  const { exec } = buildExec(values, cmd, args);

  // If audit-output-file is requested, set up a real-time event listener to append audit entries to the file
  if (values['audit-output-file']) {
    exec.on('audit', (entry) => {
      try {
        appendFileSync(values['audit-output-file'], JSON.stringify(entry) + '\n');
      } catch (err) {
        process.stderr.write(`[safer-exec] Warning: failed to write audit entry to file: ${err.message}\n`);
      }
    });
  }

  // Run the command
  try {
    // JSON mode: buffer all output so we can emit a single JSON object
    if (values.json) {
      const result = await exec.run(cmd, args);

      if (values.diff && result.fsDiff === undefined) {
        result.fsDiff = null;
      }
      if (values.learn && result.learnedPolicy === undefined) {
        result.learnedPolicy = null;
      }
      if (values['trace-output-file'] && result.auditLog) {
        const libLoads = result.auditLog
          .filter((e) => e.type === 'lib-load')
          .map((e) => e.target);
        writeFileSync(values['trace-output-file'], JSON.stringify(libLoads, null, 2));
      }
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      process.exit(result.exitCode);
    }

    // Normal mode: stream stdout/stderr in real-time as the command runs
    const result = await exec.runPipe(cmd, args);

    // Output trace-libraries to file if requested
    if (values['trace-output-file'] && result.auditLog) {
      const libLoads = result.auditLog
        .filter((e) => e.type === 'lib-load')
        .map((e) => e.target);
      writeFileSync(values['trace-output-file'], JSON.stringify(libLoads, null, 2));
      process.stderr.write(
        `[safer-exec] Trace libraries output written to ${values['trace-output-file']}\n`
      );
    }

    // Output learned policy to file if requested
    if (values.learn && values['learn-output'] && result.learnedPolicy) {
      writeFileSync(values['learn-output'], JSON.stringify(result.learnedPolicy, null, 2));
      process.stderr.write(
        `[safer-exec] Learned policy written to ${values['learn-output']}\n`
      );
    }

    // Output filesystem diff summary
    if (result.fsDiff) {
      const added = result.fsDiff.added?.length ?? 0;
      const modified = result.fsDiff.modified?.length ?? 0;
      const deleted = result.fsDiff.deleted?.length ?? 0;
      if (added > 0 || modified > 0 || deleted > 0) {
        process.stderr.write(
          `[safer-exec] Filesystem diff: +${added} added, ~${modified} modified, -${deleted} deleted\n`
        );
      }
    }

    // Output trace-exec summary
    if (values['trace-exec'] && result.auditLog) {
      const execEntries = result.auditLog.filter((e) => e.type === 'process-exec');
      if (execEntries.length > 0) {
        process.stderr.write(`[safer-exec] Child processes spawned: ${execEntries.length}\n`);
        for (const entry of execEntries) {
          process.stderr.write(`  - ${entry.target}\n`);
        }
      }
    }

    // Output dry-run report
    if (result.dryRun) {
      process.stderr.write('\n');
      formatDryRunReport(result.dryRun);
    }

    // Print success/failure message
    if (result.exitCode === 124 || result.timedOut) {
      process.stderr.write('[safer-exec] Command timed out\n');
      result.exitCode = 124; // Force standard timeout exit code
    } else if (result.exitCode !== 0) {
      process.stderr.write(
        `[safer-exec] Command exited with code ${result.exitCode}\n`
      );
    }

    process.exit(result.exitCode);
  } catch (err) {
    if (values.json) {
      process.stdout.write(JSON.stringify({ error: err.message }, null, 2) + '\n');
    } else {
      process.stderr.write(`[safer-exec] Error: ${err.message}\n`);
    }
    process.exit(1);
  }
}

/**
 * Format and write a dry-run report to stderr as a human-readable table.
 *
 * @param {object} dryRun - The dry-run result from the runner
 */
function formatDryRunReport(dryRun) {
  const { events = [], summary = {} } = dryRun;
  const out = process.stderr;

  out.write('\n╔══════════════════════════════════════════╗\n');
  out.write('║         DRY-RUN AUDIT REPORT             ║\n');
  out.write('╠══════════════════════════════════════════╣\n');

  const groups = {};
  for (const e of events) {
    if (!groups[e.type]) groups[e.type] = [];
    groups[e.type].push(e);
  }

  const groupConfig = {
    'file-read':      { label: 'FILE READS',        key: 'path' },
    'file-write':     { label: 'FILE WRITES',       key: 'path' },
    'file-metadata':  { label: 'FILE METADATA',     key: 'path' },
    'network-outbound': { label: 'NETWORK OUTBOUND',  key: 'target', fmt: (e) => e.port ? `${e.target}:${e.port}` : e.target },
    'network-bind':   { label: 'NETWORK BIND',      key: 'target', fmt: (e) => e.port ? `${e.target}:${e.port}` : e.target },
    'process-exec':   { label: 'PROCESS EXEC',      key: 'path' },
    'process-fork':   { label: 'PROCESS FORK',      key: 'path' },
    'signal':         { label: 'SIGNAL',            key: 'path' },
  };

  for (const [type, cfg] of Object.entries(groupConfig)) {
    const items = groups[type];
    if (!items || items.length === 0) continue;
    out.write(`║                                          ║\n`);
    out.write(`║  ${cfg.label} (${items.length} attempted)${' '.repeat(Math.max(0, 22 - cfg.label.length - String(items.length).length))}║\n`);
    out.write(`║──────────────────────────────────────────║\n`);

    const shown = items.slice(0, 25);
    for (const e of shown) {
      const val = cfg.fmt ? cfg.fmt(e) : (e[cfg.key] || '(unknown)');
      const truncated = val.length > 36 ? val.slice(0, 33) + '...' : val;
      out.write(`║  ${truncated}${' '.repeat(Math.max(0, 38 - truncated.length))}║\n`);
    }
    if (items.length > 25) {
      out.write(`║  ... and ${items.length - 25} more${' '.repeat(Math.max(0, 22 - String(items.length - 25).length))}║\n`);
    }
  }

  out.write('╠══════════════════════════════════════════╣\n');
  out.write(`║  Exit code: ${dryRun.exitCode} (synthetic)${' '.repeat(Math.max(0, 12 - String(dryRun.exitCode).length))}            ║\n`);
  out.write(`║  Total events: ${summary.totalEvents || events.length}${' '.repeat(Math.max(0, 20 - String(summary.totalEvents || events.length).length))}                     ║\n`);
  out.write('╚══════════════════════════════════════════╝\n\n');
}

main();
