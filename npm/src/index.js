/**
 * SaferExec — zero-dependency Node.js sandboxing library.
 *
 * Internally orchestrates a statically compiled Go binary to enforce
 * native OS sandboxing (Namespaces/Seccomp on Linux; Seatbelt on macOS).
 *
 * @module index
 * @see https://github.com/cdxgen/safer-exec
 *
 * @example
 * import { SaferExec } from '@cdxgen/safer-exec';
 *
 * // Run npm install with the built-in NPM policy
 * const result = await new SaferExec()
 *   .applyPolicy('npm')
 *   .run('npm', ['install']);
 *
 * console.log(result.exitCode, result.stdout);
 *
 * @example
 * // Custom sandboxed execution with audit logging
 * const result = await new SaferExec()
 *   .allowHosts(['api.github.com'])
 *   .readPaths(['/usr', '/etc/ssl/certs'])
 *   .writePaths(['/tmp/output'])
 *   .maxMemory(256)
 *   .enableAudit()
 *   .run('curl', ['https://api.github.com']);
 *
 * console.log(result.exitCode, result.stdout, result.auditLog);
 *
 * @example
 * // Filesystem diffing — track what files a command creates/modifies
 * const result = await new SaferExec()
 *   .writePaths(process.cwd())
 *   .enableDiff()
 *   .run('npm', ['install']);
 *
 * console.log(result.fsDiff?.added);  // newly created files
 * console.log(result.fsDiff?.modified); // modified files
 * console.log(result.fsDiff?.deleted);  // deleted files
 *
 * @example
 * // Learning mode — auto-generate a strict policy from observed behavior
 * const result = await new SaferExec()
 *   .enableLearn()
 *   .run('npm', ['install']);
 *
 * console.log(result.learnedPolicy);
 * // { readPaths: ["/usr", "/etc"], writePaths: ["./node_modules"],
 * //   allowIPs: ["93.184.216.34"], allowPorts: [443] }
 */

import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { resolveHosts } from './net.js';
import { run as runBinary } from './runner.js';
import { npmPolicy } from './policies/npm.js';
import { pnpmPolicy } from './policies/pnpm.js';
import { yarnPolicy } from './policies/yarn.js';
import { pypiPolicy } from './policies/pypi.js';
import { mavenPolicy } from './policies/maven.js';
import { cargoPolicy } from './policies/cargo.js';
import { rubygemsPolicy } from './policies/rubygems.js';
import { composerPolicy } from './policies/composer.js';
import { denoPolicy } from './policies/deno.js';
import { gomodPolicy } from './policies/gomod.js';
import { bunPolicy } from './policies/bun.js';

// Resolve the path to the npm package root directory.
// This is used to resolve relative binary paths relative to the package,
// not the current working directory (which may differ when tests run).
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const __packageRoot = dirname(__dirname); // npm/src/index.js -> npm/ -> package root

// Registry of built-in policies
const POLICIES = {
  npm: npmPolicy,
  yarn: yarnPolicy,
  pnpm: pnpmPolicy,
  pypi: pypiPolicy,
  maven: mavenPolicy,
  cargo: cargoPolicy,
  rubygems: rubygemsPolicy,
  composer: composerPolicy,
  deno: denoPolicy,
  gomod: gomodPolicy,
  bun: bunPolicy,
};

/**
 * The SaferExec class provides a fluent API for configuring and
 * executing sandboxed commands.
 *
 * Each method returns `this` for chaining. Call `.run()` to execute
 * the sandboxed command.
 *
 * @example
 * const result = await new SaferExec()
 *   .applyPolicy('npm')
 *   .allowHosts(['custom.registry.com'])
 *   .env('CUSTOM_VAR', 'value')
 *   .run('npm', ['install']);
 */
export class SaferExec {
  /**
   * Create a new SaferExec instance with default configuration.
   *
   * @param {Object} [options] - Initial configuration
   * @param {string[]} [options.allowHosts] - Hostnames to allow network access to
   * @param {string[]} [options.readPaths] - Filesystem paths to read from
   * @param {string[]} [options.writePaths] - Filesystem paths to write to
   * @param {Object} [options.env] - Environment variables to set
   * @param {boolean} [options.disableNetwork] - Whether to disable all network access
   * @param {number} [options.maxMemoryMB] - Memory limit in megabytes
   * @param {number} [options.maxCPUCores] - CPU limit as fractional cores (e.g. 0.5)
   * @param {number} [options.maxProcesses] - Max child processes (anti-fork bomb)
   * @param {number} [options.timeoutMs] - Hard kill timeout in milliseconds
   * @param {string} [options.workingDir] - Working directory for the command
   * @param {string} [options.binaryPath] - Override the Go binary path
   * @param {boolean} [options.enableAudit] - Enable sandbox violation auditing
   * @param {number[]} [options.allowPorts] - TCP ports to allow (default: [80, 443])
   * @param {boolean} [options.enableDiff] - Enable filesystem mutation diffing
   * @param {boolean} [options.enableLearn] - Enable behavioral auto-profiling (learning mode)
   */
  constructor(options = {}) {
    /** @type {string[]} */
    this._allowHosts = options.allowHosts || [];

    /** @type {string[]} */
    this._readPaths = options.readPaths || [];

    /** @type {string[]} */
    this._writePaths = options.writePaths || [];

    /** @type {Object<string, string>} */
    this._env = options.env || {};

    /** @type {boolean} */
    this._disableNetwork = options.disableNetwork || false;

    /** @type {number} */
    this._maxMemoryMB = options.maxMemoryMB || 0;

    /** @type {number} */
    this._maxCPUCores = options.maxCPUCores || 0;

    /** @type {number} */
    this._maxProcesses = options.maxProcesses || 0;

    /** @type {number} */
    this._timeoutMs = options.timeoutMs || 0;

    /** @type {string} */
    this._workingDir = options.workingDir || process.cwd();

    /** @type {string|undefined} */
    this._binaryPath = options.binaryPath;

    /** @type {string[]} Resolved IPs (populated before run) */
    this._allowIPs = [];

    /** @type {boolean} */
    this._enableAudit = options.enableAudit || false;

    /** @type {number[]} */
    this._allowPorts = options.allowPorts || [];

    /** @type {boolean} */
    this._enableDiff = options.enableDiff || false;

    /** @type {boolean} */
    this._enableLearn = options.enableLearn || false;

    /** @type {string[]} Executables the command is allowed to exec */
    this._allowExec = options.allowExec || [];

    /** @type {string[]} Executables to block from execution */
    this._blockExec = options.blockExec || [];

    /** @type {boolean} Prevent forking new processes */
    this._blockFork = options.blockFork || false;

    /** @type {boolean} Log every child process spawned */
    this._traceExec = options.traceExec || false;

    /** @type {boolean} Output generated Seatbelt profile instead of running command */
    this._dumpProfile = options.dumpProfile || false;
  }

  /**
   * Apply a pre-defined ecosystem policy.
   *
   * Merges the policy's configuration with any existing user-defined
   * settings. User-defined settings take precedence over policy defaults.
   *
   * @param {'npm'|'pypi'|'maven'|'cargo'|'rubygems'|'composer'|'deno'|'gomod'|'bun'} name - The policy name
   * @returns {SaferExec} This instance for chaining
   * @throws {Error} If the policy name is not recognized
   *
   * @example
   * new SaferExec().applyPolicy('npm').run('npm', ['install']);
   */
  applyPolicy(name) {
    const policyFn = POLICIES[name];
    if (!policyFn) {
      const available = Object.keys(POLICIES).join(', ');
      throw new Error(
        `Unknown policy: "${name}". Available: ${available}`
      );
    }

    const policy = policyFn();

    // Merge policy with existing config (user settings take precedence)
    this._allowHosts = [...new Set([...(policy.allowHosts || []), ...this._allowHosts])];
    this._readPaths = [...new Set([...(policy.readPaths || []), ...this._readPaths])];
    this._writePaths = [...new Set([...(policy.writePaths || []), ...this._writePaths])];

    // Merge env (user env takes precedence)
    this._env = { ...(policy.env || {}), ...this._env };

    // Merge exec/fork restrictions (user settings take precedence)
    if (policy.allowExec && policy.allowExec.length > 0) {
      this._allowExec = [...new Set([...policy.allowExec, ...this._allowExec])];
    }
    if (policy.blockExec && policy.blockExec.length > 0) {
      this._blockExec = [...new Set([...policy.blockExec, ...this._blockExec])];
    }
    if (policy.blockFork) {
      this._blockFork = true;
    }
    if (policy.traceExec) {
      this._traceExec = true;
    }

    return this;
  }

  /**
   * Add hostnames to the allow list.
   *
   * These hostnames will be resolved to IP addresses before execution.
   *
   * @param {...string} hosts - Hostnames to allow
   * @returns {SaferExec} This instance for chaining
   */
  allowHosts(...hosts) {
    for (const host of hosts) {
      if (!this._allowHosts.includes(host)) {
        this._allowHosts.push(host);
      }
    }
    return this;
  }

  /**
   * Add filesystem paths to the read allow list.
   *
   * @param {...string} paths - Paths to allow reading from
   * @returns {SaferExec} This instance for chaining
   */
  readPaths(...paths) {
    for (const path of paths) {
      if (!this._readPaths.includes(path)) {
        this._readPaths.push(path);
      }
    }
    return this;
  }

  /**
   * Add filesystem paths to the write allow list.
   *
   * @param {...string} paths - Paths to allow writing to
   * @returns {SaferExec} This instance for chaining
   */
  writePaths(...paths) {
    for (const path of paths) {
      if (!this._writePaths.includes(path)) {
        this._writePaths.push(path);
      }
    }
    return this;
  }

  /**
   * Set an environment variable in the sandbox.
   *
   * @param {string} key - Variable name
   * @param {string} value - Variable value
   * @returns {SaferExec} This instance for chaining
   */
  env(key, value) {
    this._env[key] = value;
    return this;
  }

  /**
   * Disable all network access.
   *
   * On Linux this adds a new network namespace. On macOS this
   * restricts outbound connections to resolved IPs only.
   *
   * @returns {SaferExec} This instance for chaining
   */
  disableNetwork() {
    this._disableNetwork = true;
    return this;
  }

  /**
   * Set a memory limit for the sandboxed process.
   *
   * @param {number} mb - Memory limit in megabytes
   * @returns {SaferExec} This instance for chaining
   */
  maxMemory(mb) {
    this._maxMemoryMB = mb;
    return this;
  }

  /**
   * Set a CPU limit for the sandboxed process.
   *
   * The value is expressed as fractional cores. For example, 0.5 means
   * half a CPU core, and 2.0 means two full cores. On Linux this is
   * enforced via cgroup v2 cpu.max; on macOS via RLIMIT_CPU.
   *
   * @param {number} cores - CPU limit as fractional cores (e.g. 0.5, 1.0, 2.0)
   * @returns {SaferExec} This instance for chaining
   */
  maxCPUCores(cores) {
    this._maxCPUCores = cores;
    return this;
  }

  /**
   * Set a maximum number of child processes (anti-fork bomb).
   *
   * Prevents the sandboxed process from spawning more than the specified
   * number of child processes. On Linux this is enforced via cgroup v2
   * pids.max; on macOS via RLIMIT_NPROC.
   *
   * @param {number} count - Maximum number of child processes
   * @returns {SaferExec} This instance for chaining
   */
  maxProcesses(count) {
    this._maxProcesses = count;
    return this;
  }

  /**
   * Set a hard kill timeout for the sandboxed process.
   *
   * After the specified number of milliseconds, the sandboxed process
   * and all its descendants are forcefully terminated. This is enforced
   * by the JS wrapper layer (AbortController) and also passed to the Go
   * engine as RLIMIT_CPU on macOS.
   *
   * @param {number} ms - Timeout in milliseconds (0 = no timeout)
   * @returns {SaferExec} This instance for chaining
   */
  timeout(ms) {
    this._timeoutMs = ms;
    return this;
  }

  /**
   * Set the path to the Go binary.
   *
   * @param {string} path - Path to the Go binary
   * @returns {SaferExec} This instance for chaining
   */
  binaryPath(path) {
    this._binaryPath = path;
    return this;
  }

  /**
   * Set the working directory for the sandboxed command.
   *
   * @param {string} dir - Working directory path
   * @returns {SaferExec} This instance for chaining
   */
  workingDir(dir) {
    this._workingDir = dir;
    return this;
  }

  /**
   * Enable sandbox violation auditing.
   *
   * When enabled, the sandbox engine captures and returns information
   * about file reads, network connections, and other operations performed
   * by the sandboxed process.
   *
   * @returns {SaferExec} This instance for chaining
   */
  enableAudit() {
    this._enableAudit = true;
    return this;
  }

  /**
   * Set allowed TCP ports for network connections.
   *
   * @param {...number} ports - TCP ports to allow
   * @returns {SaferExec} This instance for chaining
   */
  allowPorts(...ports) {
    for (const port of ports) {
      if (!this._allowPorts.includes(port)) {
        this._allowPorts.push(port);
      }
    }
    return this;
  }

  /**
   * Enable filesystem mutation diffing.
   *
   * When enabled, the engine tracks all filesystem changes during
   * execution and returns a diff report with added, modified, and
   * deleted files. The result includes an `fsDiff` property:
   *
   * ```js
   * {
   *   added: [{ path: "./node_modules/.package-lock.json", size: 1024 }],
   *   modified: [{ path: "./package-lock.json", size: 4096 }],
   *   deleted: []
   * }
   * ```
   *
   * On Linux this uses OverlayFS to capture writes in a temporary
   * upper directory. On macOS it uses a pre/post snapshot comparison
   * of the write paths.
   *
   * @returns {SaferExec} This instance for chaining
   */
  enableDiff() {
    this._enableDiff = true;
    return this;
  }

  /**
   * Enable behavioral auto-profiling (learning mode).
   *
   * When enabled, the command runs in permissive mode and the engine
   * records all filesystem and network accesses. After execution, it
   * returns a strict, minimal policy file based on observed behavior.
   *
   * The result includes a `learnedPolicy` property:
   *
   * ```js
   * {
   *   readPaths: ["/usr", "/etc/ssl/certs"],
   *   writePaths: ["./node_modules"],
   *   allowIPs: ["93.184.216.34"],
   *   allowPorts: [443],
   *   cmd: "npm",
   *   args: ["install"]
   * }
   * ```
   *
   * On Linux this uses strace (if available) or /proc-based tracing.
   * On macOS it uses Seatbelt trace rules and parses the output.
   *
   * @returns {SaferExec} This instance for chaining
   */
  enableLearn() {
    this._enableLearn = true;
    return this;
  }

  /**
   * Restrict which executables the sandboxed process can run.
   *
   * When allowExec is set, the command can only exec the specified
   * binary names. This prevents npm from spawning unexpected tools.
   * Block list takes precedence: an executable in both allow and block
   * lists is blocked.
   *
   * On macOS this becomes (allow process-exec (file ...)) Seatbelt rules.
   * On Linux this is enforced via seccomp-bpf execve tracing.
   *
   * @param {...string} cmds - Executable names to allow (e.g. "node", "npx")
   * @returns {SaferExec} This instance for chaining
   *
   * @example
   * new SaferExec()
   *   .allowExec('node', 'npx', 'corepack')
   *   .run('npm', ['install']);
   */
  allowExec(...cmds) {
    for (const cmd of cmds) {
      if (!this._allowExec.includes(cmd)) {
        this._allowExec.push(cmd);
      }
    }
    return this;
  }

  /**
   * Block specific executables from running.
   *
   * Takes precedence over allowExec. An executable in the block list
   * cannot run even if it is in the allow list.
   *
   * @param {...string} cmds - Executable names to block (e.g. "sh", "bash")
   * @returns {SaferExec} This instance for chaining
   *
   * @example
   * new SaferExec()
   *   .blockExec('sh', 'bash')
   *   .run('npm', ['install']);
   */
  blockExec(...cmds) {
    for (const cmd of cmds) {
      if (!this._blockExec.includes(cmd)) {
        this._blockExec.push(cmd);
      }
    }
    return this;
  }

  /**
   * Prevent the sandboxed process from forking new processes.
   *
   * Forking is how processes create children. Blocking fork prevents
   * the command from spawning any subprocesses at all.
   *
   * On macOS this becomes (allow process-fork) Seatbelt rules.
   * On Linux this blocks clone/fork/vfork syscalls via seccomp.
   *
   * @returns {SaferExec} This instance for chaining
   */
  blockFork() {
    this._blockFork = true;
    return this;
  }

  /**
   * Log every child process spawned by the sandboxed command.
   *
   * Fork and exec are allowed, but every child process is logged with
   * the command line and parent PID. The result includes an `auditLog`
   * property with process-exec entries.
   *
   * On macOS this uses Seatbelt (trace process-exec) rules.
   * On Linux this uses seccomp SIGSYS trapping on execve.
   *
   * @returns {SaferExec} This instance for chaining
   */
  traceExec() {
    this._traceExec = true;
    return this;
  }

  /**
   * Output the generated Seatbelt profile instead of running the command.
   *
   * Returns the raw Seatbelt profile text in the result's `profile` property.
   * Useful for testing and debugging profile generation.
   *
   * @returns {SaferExec} This instance for chaining
   */
  dumpProfile() {
    this._dumpProfile = true;
    return this;
  }

  /**
   * Execute the sandboxed command.
   *
   * Before spawning the Go binary, this method:
   * 1. Resolves all allowed hostnames to IP addresses
   * 2. Builds the JSON config
   * 3. Spawns the Go binary and pipes the config via stdin
   *
   * @param {string} cmd - The command to execute
   * @param {string[]} [args=[]] - Command arguments
   * @returns {Promise<ExecResult>} The execution result
   * @returns {string} returns.stdout - Captured stdout
   * @returns {string} returns.stderr - Captured stderr
   * @returns {number} returns.exitCode - Process exit code
   * @returns {Array<Object>} [returns.auditLog] - Audit log entries (when enableAudit is true)
   * @returns {Object} [returns.fsDiff] - Filesystem mutation report (when enableDiff is true)
   * @returns {Object} [returns.learnedPolicy] - Auto-generated policy (when enableLearn is true)
   *
   * @example
   * const result = await new SaferExec()
   *   .applyPolicy('npm')
   *   .run('npm', ['install']);
   *
   * if (result.exitCode === 0) {
   *   console.log('Install succeeded');
   * }
   */
  async run(cmd, args = []) {
    // Resolve hostnames to IPs
    if (this._allowHosts.length > 0) {
      const { ips, failures } = await resolveHosts(this._allowHosts);
      this._allowIPs = ips;

      if (failures.length > 0) {
        const hostList = failures.map((f) => f.host).join(', ');
        console.warn(
          `safer-exec: could not resolve hosts: ${hostList}`
        );
      }
    }

    // Build the config object
    const config = {
      cmd,
      args,
      env: Object.keys(this._env).length > 0 ? this._env : undefined,
      readPaths: this._readPaths,
      writePaths: this._writePaths,
      allowHosts: this._allowHosts,
      allowIPs: this._allowIPs,
      allowPorts: this._allowPorts,
      disableNetwork: this._disableNetwork,
      maxMemoryMB: this._maxMemoryMB,
      maxCPUCores: this._maxCPUCores,
      maxProcesses: this._maxProcesses,
      timeoutMs: this._timeoutMs,
      workingDir: this._workingDir,
      enableAudit: this._enableAudit,
      enableDiff: this._enableDiff,
      enableLearn: this._enableLearn,
      allowExec: this._allowExec,
      blockExec: this._blockExec,
      blockFork: this._blockFork,
      traceExec: this._traceExec,
      dumpProfile: this._dumpProfile,
    };

    // Determine effective timeout: use explicit timeout or default to 60s
    const effectiveTimeout = this._timeoutMs > 0 ? this._timeoutMs : 60000;

    // Resolve binary path: if it's relative (starts with . or ..), resolve
    // it relative to the npm package root (not the current working directory,
    // which may differ when tests run from subdirectories).
    let binaryPath = this._binaryPath;
    if (binaryPath && (binaryPath.startsWith('.') || binaryPath.startsWith('..'))) {
      binaryPath = resolve(__packageRoot, binaryPath);
    }

    // Run the Go binary with a slightly longer timeout to let it finish cleanly
    const options = {
      binaryPath,
      timeout: effectiveTimeout + 2000,
      enableAudit: this._enableAudit,
    };
    return runBinary(config, options);
  }
}

/**
 * Convenience function for quick sandboxed execution.
 *
 * @param {string} cmd - The command to execute
 * @param {string[]} [args=[]] - Command arguments
 * @param {Object} [options] - SaferExec constructor options
 * @returns {Promise<ExecResult>} The execution result
 *
 * @example
 * const result = await saferExec('npm', ['install'], {
 *   allowHosts: ['registry.npmjs.org'],
 *   readPaths: ['/usr', '/etc/ssl/certs'],
 *   writePaths: [process.cwd() + '/node_modules'],
 * });
 */
export async function saferExec(cmd, args = [], options = {}) {
  const exec = new SaferExec(options);
  return exec.run(cmd, args);
}

export default SaferExec;
