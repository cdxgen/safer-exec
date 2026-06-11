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

Options:
  -p, --policy=<name>        Apply a built-in policy preset
                             Available: npm, pypi, maven, cargo, rubygems,
                                        composer, deno, gomod, bun
  -m, --max-memory=<mb>      Memory limit in megabytes
  -c, --max-cpu=<cores>      CPU limit as fractional cores (e.g. 0.5)
      --max-processes=<n>    Max child processes (anti-fork bomb)
  -t, --timeout=<ms>         Hard kill timeout in milliseconds

  -n, --disable-network      Disable all network access
      --allow-loopback       Allow localhost/loopback connections
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
  --trace-exec               Log every child process spawned (fork + exec audit)
  --trace-libraries          Track dynamically loaded libraries at runtime
  --trace-output-file=<file> Write tracked libraries to file (implies trace-libraries)
  --trace-temp-dir=<dir>     Temporary directory to extract dynamic library helper to (implies trace-libraries)
  --trace-http-urls          Capture HTTPS request URLs/methods via eBPF TLS uprobes (Linux only, requires CAP_BPF)

  -d, --diff                 Enable filesystem mutation diffing
  -l, --learn                Enable behavioral auto-profiling (learning mode)
      --learn-output=<file>  Write learned policy to file
  -a, --audit                Enable sandbox violation auditing
      --audit-output-file=<f> Write audit log to file (implies audit)
  -s, --strict               Treat sandbox setup warnings as errors
      --sanitize-env          Strip sensitive env vars (TOKEN, SECRET, etc.)

  -j, --json                 Output results as JSON
  -h, --help                 Show this help message
  -v, --version              Show version

Diagnostics:
  safer-exec diagnostics        Show OS capabilities and feature support

Examples:
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
      'learn-output': {
        type: 'string',
      },
      strict: {
        type: 'boolean',
        short: 's',
      },
      'sanitize-env': {
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
      'timeout',
      'allow-host',
      'port',
      'read-path',
      'write-path',
      'env',
      'cwd',
      'learn-output',
      'trace-output-file',
      'trace-temp-dir',
      'allow-exec',
      'block-exec',
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
  if (values['trace-exec']) {
    exec.traceExec();
  }

    if (values['sanitize-env']) {
    exec.sanitizeEnv();
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
 * Main CLI entry point.
 */
async function main() {
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

main();
