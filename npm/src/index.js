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
import { dirname, resolve, join } from 'node:path';
import { existsSync, readFileSync, statSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { EventEmitter } from 'node:events';
import { resolveHosts } from './net.js';
import { stripDangerousEnv } from './env.js';
import { run as runBinary, runPipe as runBinaryPipe } from './runner.js';
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
import { pokuPolicy } from './policies/poku.js';
import { cdxgenPolicy } from './policies/cdxgen.js';
import { pnpmInstallPolicy } from './policies/pnpmInstall.js';
import { uvPolicy } from './policies/uv.js';
function findInPath(cmd) {
  if (cmd.includes('/') || cmd.includes('\\')) {
    return cmd;
  }
  const paths = (process.env.PATH || '').split(process.platform === 'win32' ? ';' : ':');
  for (const p of paths) {
    const fullPath = join(p, cmd);
    if (existsSync(fullPath)) {
      return fullPath;
    }
  }
  return cmd;
}

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
  poku: pokuPolicy,
  cdxgen: cdxgenPolicy,
  pnpmInstall: pnpmInstallPolicy,
  uv: uvPolicy,
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
function expandEnv(str) {
  if (typeof str !== 'string') return str;
  // Replace ~ at the start with HOME
  if (str.startsWith('~')) {
    const home = process.env.HOME || process.env.USERPROFILE || '';
    str = home + str.slice(1);
  }
  const home = process.env.HOME || process.env.USERPROFILE || '';
  // Replace $HOME with home directory
  str = str.replace(/\$HOME\b/g, home);
  // Replace $PWD or $CWD with process.cwd()
  str = str.replace(/\$(PWD|CWD)\b/g, () => process.cwd());
  // Replace $TMPDIR or $TEMP with os.tmpdir()
  return str.replace(/\$(TMPDIR|TEMP)\b/g, () => tmpdir());
}

/**
 * Parse a URL string or AllowURLRule object into a normalized AllowURLRule.
 *
 * String format: `[protocol://]host[:port][/path]`
 * Examples:
 *   - `"https://registry.npmjs.org/-/npm/v1/"` → { protocol:"https", host:"registry.npmjs.org", port:443, pathPrefix:"/-/npm/v1/" }
 *   - `"https://*.npmjs.org"` → { protocol:"https", host:"*.npmjs.org" }
 *   - `"~^registry\\.npmjs\\.org$"` → treated as object: { host: "~^registry\\.npmjs\\.org$" }
 *
 * Object format: `{ protocol?, host, port?, pathPrefix?, methods? }`
 *
 * Returns null if the input cannot be parsed.
 *
 * @param {string|Object} input - URL string or AllowURLRule object
 * @returns {{ protocol?: string, host: string, port?: number, pathPrefix?: string, methods?: string[] }|null}
 */
function _parseURLRule(input) {
  if (!input) return null;

  // Object form — pass through with validation
  if (typeof input === 'object' && !Array.isArray(input)) {
    if (typeof input.host !== 'string') return null;
    return {
      protocol: input.protocol || undefined,
      host: input.host,
      port: typeof input.port === 'number' ? input.port : undefined,
      pathPrefix: input.pathPrefix || input.path || undefined,
      methods: Array.isArray(input.methods) ? input.methods : undefined,
    };
  }

  if (typeof input !== 'string' || !input) return null;

  // Regex shorthand: if the string starts with "~", treat as a host regex rule
  if (input.startsWith('~')) {
    return { host: input };
  }

  // Ensure we have a scheme so new URL() can parse it
  let raw = input;
  if (!raw.includes('://')) {
    raw = 'https://' + raw;
  }

  try {
    const u = new URL(raw);
    const protocol = u.protocol.replace(/:$/, ''); // "https:" → "https"
    const host = u.hostname;                        // "registry.npmjs.org"
    const port = u.port
      ? parseInt(u.port, 10)
      : (protocol === 'https' ? 443 : protocol === 'http' ? 80 : undefined);
    const pathPrefix = u.pathname && u.pathname !== '/' ? u.pathname : undefined;

    if (!host) return null;
    return {
      protocol,
      host,
      port,
      pathPrefix,
      methods: undefined,
    };
  } catch {
    // Unparseable — treat entire string as a host pattern
    return { host: input };
  }
}


export class SaferExec extends EventEmitter {
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
   * @param {boolean} [options.resolveSymlinks] - Resolve target command symlink in PATH
   * @param {string[]} [options.allowEnvs] - Host environment variables allowed to pass through
   */
  constructor(options = {}) {
    super();
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

    /** @type {boolean} */
    this._allowLoopback = options.allowLoopback || false;

    /** @type {number} */
    this._maxMemoryMB = options.maxMemoryMB || 0;

    /** @type {number} */
    this._maxCPUCores = options.maxCPUCores || 0;

    /** @type {number} */
    this._maxProcesses = options.maxProcesses || 0;

    /** @type {number} Max read IO operations per second (Linux only) */
    this._maxReadIOPS = options.maxReadIOPS || 0;

    /** @type {number} Max write IO operations per second (Linux only) */
    this._maxWriteIOPS = options.maxWriteIOPS || 0;

    /** @type {number} Max read bandwidth in bytes per second (Linux only) */
    this._maxReadBps = options.maxReadBps || 0;

    /** @type {number} Max write bandwidth in bytes per second (Linux only) */
    this._maxWriteBps = options.maxWriteBps || 0;

    /** @type {number} */
    this._timeoutMs = options.timeoutMs || 60000;

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

    /** @type {boolean} Enable dry-run mode */
    this._enableDryRun = options.enableDryRun || false;

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

    /** @type {boolean} Validate the generated Seatbelt profile syntax */
    this._validateProfile = options.validateProfile || false;

    /** @type {boolean} Treat sandbox setup warnings as errors */
    this._strict = options.strict || false;

    /** @type {string} Path to the policy file if loaded or merging */
    this._policyFilePath = options.policyFilePath || '';

    /** @type {boolean} Opt-in to resolve target command symlink */
    this._resolveSymlinks = options.resolveSymlinks || false;

    /** @type {string[]} Environment variables allowed to pass through */
    this._allowEnvs = options.allowEnvs || [];

    /** @type {boolean} Deny execution of Apple-signed scripting engines / sampling tools (macOS) */
    this._blockInterpreters = options.blockInterpreters || false;

    /** @type {boolean} Deny writes to auto-execution / persistence locations */
    this._denyPersistenceWrites = options.denyPersistenceWrites || false;

    /** @type {boolean} Permit loading .dylib from writable/temp dirs under blockInterpreters (macOS) */
    this._allowWritableDylibLoad = options.allowWritableDylibLoad || false;

    /** @type {boolean} Block JIT / W^X syscalls (mprotect PROT_EXEC, memfd_create, MAP_JIT) */
    this._blockJIT = options.blockJIT || false;

    /** @type {boolean} Allow reading/writing hidden files and directories */
    this._allowHidden = options.allowHidden || false;

    /** @type {string[]} IP addresses or ip:port strings allowed to bind/listen to */
    this._allowListen = Array.isArray(options.allowListen) ? options.allowListen : [];

    /** @type {boolean} Allow cryptographic library and device access */
    this._allowCrypto = options.allowCrypto !== false;

    /** @type {boolean} Explicitly block cryptographic library access */
    this._blockCrypto = options.blockCrypto || false;

    /** @type {boolean} Block entropy device access (/dev/random, /dev/urandom) */
    this._blockCryptoEntropy = options.blockCryptoEntropy || false;

    /** @type {boolean} Detect FIPS compliant operations */
    this._detectFIPS = options.detectFIPS || false;

    /** @type {boolean} Enforce FIPS compliance strictly */
    this._strictFIPS = options.strictFIPS || false;

    /** @type {boolean} Allow processes to utilize host GPU nodes */
    this._allowGPU = options.allowGPU || false;

    /** @type {boolean} Restrict hardware access to TPM device */
    this._blockTPM = options.blockTPM || false;

    /** @type {boolean} Intercept VM and hypervisor properties */
    this._spoofAntiVM = options.spoofAntiVM || false;

    /** @type {boolean} Track dynamic library loading (opt-in) */
    this._traceLibraries = options.traceLibraries || false;

    /** @type {string} Temporary directory to extract dynamic library helper to */
    this._traceTempDir = options.traceTempDir || '';

    /** @type {boolean} Suppress printing lib-load JSON entries to stderr stream */
    this._suppressLibLoadStderr = options.suppressLibLoadStderr || false;

    /** @type {boolean} Attach eBPF uprobes to TLS write functions to capture HTTP URLs (Linux only, kernel >= 5.8) */
    this._traceHTTPURLs = options.traceHTTPURLs || false;

    /** @type {boolean} Enable cryptographic tracing (cipher suites, libraries). Auto-enables traceHTTPURLs. */
    this._traceCrypto = options.traceCrypto || false;

    /** @type {string} Path for CycloneDX CBOM JSON output */
    this._cbomOutputPath = options.cbomOutputPath || '';

    /** @type {string} Crypto probe mode: "tls-only" or "operations" */
    this._cryptoProbeMode = options.cryptoProbeMode || 'tls-only';

    /** @type {string[]} Allowed TLS cipher suites (Linux only) */
    this._allowCiphers = options.allowCiphers || [];

    /**
     * Fine-grained URL access rules (Linux-only, requires traceHTTPURLs).
     * Each entry: { protocol?, host, port?, pathPrefix?, methods? }
     * Host and pathPrefix accept exact strings, globs ("*.npmjs.org"), or
     * regexps prefixed with "~" ("~^registry\.npmjs\.org$").
     * @type {Array<{protocol?: string, host: string, port?: number, pathPrefix?: string, methods?: string[]}>}
     */
    this._allowURLRules = options.allowURLRules || [];

    /** @type {boolean} Set up minimal /dev inside sandbox (Linux only) */
    this._setUpDev = options.setUpDev !== undefined ? options.setUpDev : true;

    /** @type {boolean} Kill sandboxed process when parent dies (PR_SET_PDEATHSIG) */
    this._dieWithParent = options.dieWithParent !== undefined ? options.dieWithParent : true;

    /** @type {boolean} Disconnect from controlling terminal (setsid) */
    this._newSession = options.newSession !== undefined ? options.newSession : true;

    /** @type {string[]} Create ephemeral writable overlay at paths (Linux only) */
    this._tmpOverlayPaths = Array.isArray(options.tmpOverlayPaths) ? options.tmpOverlayPaths : [];

    /** @type {string[]} Advisory file locks during sandbox execution */
    this._lockFiles = Array.isArray(options.lockFiles) ? options.lockFiles : [];

    /** @type {boolean} Use fd-based bind mounting for TOCTTOU safety (opt-in, may break DNS on some kernels) */
    this._bindUseFd = options.bindUseFd !== undefined ? options.bindUseFd : false;

    /** @type {Array<{program?: string, path?: string}>} Stackable seccomp-bpf filters */
    this._seccompFilters = Array.isArray(options.seccompFilters) ? options.seccompFilters : [];

    /** @type {boolean} Use PID 1 reaper for zombie cleanup (default false, opt-in) */
    this._useReaper = options.useReaper || false;

    /** @type {boolean} Harden /proc with read-only bind mounts (default false, opt-in) */
    this._procHardening = options.procHardening || false;

    /** @type {boolean} Enforce submount read-only (default false, opt-in) */
    this._submountEnforce = options.submountEnforce || false;

    /** @type {string} Auto-make system directories read-only: "strict", "full", or "off" */
    this._protectSystem = options.protectSystem || 'off';

    /** @type {string} Home directory isolation: "read-only", "tmpfs", or "off" */
    this._protectHome = options.protectHome || 'off';

    /** @type {boolean} Mount fresh tmpfs on /tmp and /var/tmp (Linux only, opt-in) */
    this._privateTmp = options.privateTmp !== undefined ? options.privateTmp : false;

    /** @type {Array<{fd: number, target: string, readOnly?: boolean}>} Pre-opened FDs to bind-mount */
    this._bindFds = Array.isArray(options.bindFds) ? options.bindFds : [];

    /** @type {boolean} Map UID 0 inside namespace to caller's real UID (Linux only, opt-in) */
    this._mapToTargetUid = options.mapToTargetUid || false;

    /**
     * @type {boolean} Permit the sandboxed process to create nested user/mount
     * namespaces (CLONE_NEWUSER/CLONE_NEWNS). Defaults to false: nested
     * namespaces are blocked by seccomp because they are a common entry point
     * for unprivileged-userns kernel privilege-escalation bugs. Linux only.
     */
    this._allowUserns = options.allowUserns || false;

    /**
     * @type {boolean} Permit degrading to an escapable chroot when pivot_root
     * fails. Defaults to false: a pivot_root failure is fatal so filesystem
     * isolation is never silently weakened. Linux only.
     */
    this._allowChrootFallback = options.allowChrootFallback || false;
  }

  /**
   * Apply a pre-defined ecosystem policy.
   *
   * Merges the policy's configuration with any existing user-defined
   * settings. User-defined settings take precedence over policy defaults.
   *
   * @param {'npm'|'pypi'|'maven'|'cargo'|'rubygems'|'composer'|'deno'|'gomod'|'bun'|'uv'} name - The policy name
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
    if (policy.allowLoopback) {
      this._allowLoopback = true;
    }
    if (policy.resolveSymlinks) {
      this._resolveSymlinks = true;
    }

    return this;
  }

  /**
   * Load a policy file (JSON) and apply it to this instance.
   *
   * The policy file format matches the output of `--learn --learn-output`.
   * All fields are optional; zero values mean "no restriction".
   *
   * This method is applied AFTER `applyPolicy()` (named preset) and BEFORE
   * per-flag CLI overrides. A policy file augments a named preset, and
   * explicit CLI flags always win.
   *
   * When combined with `--learn`, the policy file is used as the base for
   * merging newly observed behavior. The merged result is written back
   * to the file atomically.
   *
   * @param {string} filePath - Path to the JSON policy file
   * @returns {SaferExec} This instance for chaining
   * @throws {Error} If the file cannot be read or parsed
   *
   * @example
   * // Load a saved policy file
   * const result = await new SaferExec()
   *   .applyPolicyFile('./my-policy.json')
   *   .run('npm', ['install']);
   *
   * @example
   * // Combine a named preset with a custom policy file
   * const result = await new SaferExec()
   *   .applyPolicy('npm')
   *   .applyPolicyFile('./extra-paths.json')
   *   .run('npm', ['install']);
   *
   * @example
   * // Load a policy file with variables
   * const result = await new SaferExec()
   *   .applyPolicyFile('./policy-with-vars.json')
   *   .run('echo', ['test']);
   */
  applyPolicyFile(filePath) {
    this._policyFilePath = filePath;
    const raw = JSON.parse(readFileSync(filePath, 'utf-8'));
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      throw new Error(`Invalid policy file: ${filePath}`);
    }

    // Handle policy composition: if a policy file has an "extends" field,
    // load the base policy first and overlay the current file's rules.
    if (raw.extends && typeof raw.extends === 'string') {
      const basePolicyFn = POLICIES[raw.extends];
      if (!basePolicyFn) {
        throw new Error(`Unknown extends policy: "${raw.extends}"`);
      }
      const basePolicy = basePolicyFn();
      // Apply base policy paths/hosts/env first
      if (Array.isArray(basePolicy.readPaths)) {
        this._readPaths = [...new Set([...basePolicy.readPaths.map(p => expandEnv(p)), ...this._readPaths])];
      }
      if (Array.isArray(basePolicy.writePaths)) {
        this._writePaths = [...new Set([...basePolicy.writePaths.map(p => expandEnv(p)), ...this._writePaths])];
      }
      if (Array.isArray(basePolicy.allowHosts)) {
        this._allowHosts = [...new Set([...basePolicy.allowHosts, ...this._allowHosts])];
      }
      if (basePolicy.env) {
        this._env = { ...basePolicy.env, ...this._env };
      }
      if (Array.isArray(basePolicy.allowListen)) {
        this._allowListen = [...new Set([...basePolicy.allowListen, ...this._allowListen])];
      }
    }

    // Filesystem paths
    if (Array.isArray(raw.readPaths) && raw.readPaths.length > 0) {
      this.readPaths(...raw.readPaths.map(p => expandEnv(p)));
    }
    if (Array.isArray(raw.writePaths) && raw.writePaths.length > 0) {
      this.writePaths(...raw.writePaths.map(p => expandEnv(p)));
    }

    // Network
    if (raw.disableNetwork) {
      this.disableNetwork();
    }
    if (raw.allowLoopback) {
      this.allowLoopback();
    }
    if (Array.isArray(raw.allowHosts) && raw.allowHosts.length > 0) {
      this.allowHosts(...raw.allowHosts);
    }
    if (Array.isArray(raw.allowIPs) && raw.allowIPs.length > 0) {
      this._allowIPs = [...new Set([...(this._allowIPs ?? []), ...raw.allowIPs])];
    }
    if (Array.isArray(raw.allowPorts) && raw.allowPorts.length > 0) {
      this.allowPorts(...raw.allowPorts);
    }
    if (Array.isArray(raw.allowListen) && raw.allowListen.length > 0) {
      this.allowListen(raw.allowListen);
    }

    // Environment — prefer env map; fall back to envVars list
    if (raw.env && typeof raw.env === 'object' && !Array.isArray(raw.env)) {
      for (const [k, v] of Object.entries(raw.env)) {
        this.env(k, v);
      }
    } else if (Array.isArray(raw.envVars)) {
      for (const name of raw.envVars) {
        if (typeof name === 'string' && process.env[name] !== undefined) {
          this.env(name, process.env[name]);
        }
      }
    }

    // Exec / fork controls
    if (Array.isArray(raw.allowExec) && raw.allowExec.length > 0) {
      this.allowExec(...raw.allowExec);
    }
    if (Array.isArray(raw.blockExec) && raw.blockExec.length > 0) {
      this.blockExec(...raw.blockExec);
    }
    if (raw.blockFork) {
      this.blockFork();
    }
    if (raw.blockInterpreters) {
      this.blockInterpreters();
    }
    if (raw.denyPersistenceWrites) {
      this.denyPersistenceWrites();
    }
    if (raw.allowWritableDylibLoad) {
      this.allowWritableDylibLoad();
    }
    if (raw.blockJIT) {
      this.blockJIT();
    }

    // Observability
    if (raw.traceExec) {
      this.traceExec();
    }
    if (raw.enableAudit) {
      this.enableAudit();
    }

    // Resource limits
    if (raw.maxMemoryMB) {
      this.maxMemory(raw.maxMemoryMB);
    }
    if (raw.maxCPUCores) {
      this.maxCPUCores(raw.maxCPUCores);
    }
    if (raw.maxProcesses) {
      this.maxProcesses(raw.maxProcesses);
    }
    if (raw.maxReadIOPS) {
      this.maxReadIOPS(raw.maxReadIOPS);
    }
    if (raw.maxWriteIOPS) {
      this.maxWriteIOPS(raw.maxWriteIOPS);
    }
    if (raw.maxReadBps) {
      this.maxReadBps(raw.maxReadBps);
    }
    if (raw.maxWriteBps) {
      this.maxWriteBps(raw.maxWriteBps);
    }
    if (raw.timeoutMs) {
      this.timeout(raw.timeoutMs);
    }
    if (raw.resolveSymlinks) {
      this.resolveSymlinks();
    }
    if (raw.allowCrypto !== undefined) {
      this._allowCrypto = raw.allowCrypto;
    }
    if (raw.blockCrypto) {
      this.blockCrypto();
    }
    if (raw.blockCryptoEntropy) {
      this.blockCryptoEntropy();
    }
    if (raw.detectFIPS) {
      this.detectFIPS();
    }
    if (raw.strictFIPS) {
      this.strictFIPS();
    }
    if (raw.allowGPU !== undefined) {
      this._allowGPU = raw.allowGPU;
    }
    if (raw.blockTPM) {
      this.blockTPM();
    }
    if (raw.spoofAntiVM) {
      this.spoofAntiVM();
    }
    if (raw.traceLibraries) {
      this.traceLibraries();
    }
    if (raw.traceTempDir) {
      this.traceTempDir(raw.traceTempDir);
    }
    if (raw.traceHTTPURLs) {
      this.traceHTTPURLs();
    }
    // AllowURLRules (Linux-only URL-level filtering)
    if (Array.isArray(raw.allowURLRules) && raw.allowURLRules.length > 0) {
      this.allowUrls(...raw.allowURLRules);
    }
    if (Array.isArray(raw.tmpOverlayPaths) && raw.tmpOverlayPaths.length > 0) {
      this.tmpOverlayPaths(...raw.tmpOverlayPaths);
    }
    if (Array.isArray(raw.lockFiles) && raw.lockFiles.length > 0) {
      for (const lock of raw.lockFiles) {
        if (typeof lock === 'string') {
          this._lockFiles.push({ path: lock, exclusive: false });
        } else if (lock && lock.path) {
          this._lockFiles.push({ path: lock.path, exclusive: lock.exclusive || false });
        }
      }
    }
    if (typeof raw.protectSystem === 'string') {
      this._protectSystem = raw.protectSystem;
    }
    if (typeof raw.protectHome === 'string') {
      this._protectHome = raw.protectHome;
    }
    if (typeof raw.privateTmp === 'boolean') {
      this._privateTmp = raw.privateTmp;
    }
    if (typeof raw.mapToTargetUid === 'boolean') {
      this._mapToTargetUid = raw.mapToTargetUid;
    }
    if (typeof raw.allowUserns === 'boolean') {
      this._allowUserns = raw.allowUserns;
    }
    if (typeof raw.allowChrootFallback === 'boolean') {
      this._allowChrootFallback = raw.allowChrootFallback;
    }
    if (raw.setUpDev !== undefined) {
      this.setUpDev(raw.setUpDev);
    }
    if (raw.dieWithParent) {
      this.dieWithParent();
    }
    if (raw.newSession) {
      this.newSession();
    }
    if (raw.bindUseFd !== undefined) {
      this.bindUseFd(raw.bindUseFd);
    }
    if (Array.isArray(raw.seccompFilters) && raw.seccompFilters.length > 0) {
      this.seccompFilters(raw.seccompFilters);
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
   * Add fine-grained URL access rules (Linux-only, requires TraceHTTPURLs).
   *
   * Requests observed by the eBPF TLS uprobe are validated against these rules.
   * Requests matching no rule are emitted as "url-violation" audit entries.
   * Ports declared in URL rules are automatically added to the Landlock allowlist.
   *
   * Each argument can be:
   * - A URL string: `"https://registry.npmjs.org/-/npm/v1/"` — parsed into a rule.
   * - An object with fields: `{ protocol, host, port, pathPrefix, methods }` (`path` is accepted as an alias for `pathPrefix`).
   *
   * Host and pathPrefix support three matching modes:
   * - Exact:    `"registry.npmjs.org"`
   * - Glob:     `"*.npmjs.org"`, `"/npm/v1/*"`
   * - Regex:    `"~^registry\\.npmjs\\.org$"` (prefix `~` triggers regexp)
   *
   * @param {...(string|Object)} urlsOrRules - URL strings or AllowURLRule objects
   * @returns {SaferExec} This instance for chaining
   *
   * @example
   * new SaferExec()
   *   .allowUrls(
   *     'https://registry.npmjs.org/-/npm/v1/',
   *     'https://*.npmjs.org',
   *     { protocol: 'https', host: 'api.github.com', port: 443, methods: ['GET'] }
   *   )
   *   .traceHTTPURLs()
   *   .run('npm', ['install']);
   */
  allowUrls(...urlsOrRules) {
    for (const input of urlsOrRules) {
      const rule = _parseURLRule(input);
      if (!rule) continue;
      // Auto-register the host for DNS resolution (skip wildcard/regex hosts)
      const host = rule.host;
      if (host && !host.startsWith('~') && !host.includes('*')) {
        if (!this._allowHosts.includes(host)) {
          this._allowHosts.push(host);
        }
      }
      this._allowURLRules.push(rule);
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
    const flatPaths = paths.flat(Infinity);
    for (const path of flatPaths) {
      if (typeof path === 'string' && !this._readPaths.includes(path)) {
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
    const flatPaths = paths.flat(Infinity);
    for (const path of flatPaths) {
      if (typeof path === 'string' && !this._writePaths.includes(path)) {
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
   * Allow loopback/localhost connections.
   *
   * @returns {SaferExec} This instance for chaining
   */
  allowLoopback() {
    this._allowLoopback = true;
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
   * Set maximum read IO operations per second (Linux only).
   *
   * @param {number} iops - Max read IOPS (0 = no limit)
   * @returns {SaferExec} This instance for chaining
   */
  maxReadIOPS(iops) {
    this._maxReadIOPS = iops;
    return this;
  }

  /**
   * Set maximum write IO operations per second (Linux only).
   *
   * @param {number} iops - Max write IOPS (0 = no limit)
   * @returns {SaferExec} This instance for chaining
   */
  maxWriteIOPS(iops) {
    this._maxWriteIOPS = iops;
    return this;
  }

  /**
   * Set maximum read bandwidth in bytes per second (Linux only).
   *
   * @param {number} bps - Max read bytes per second (0 = no limit)
   * @returns {SaferExec} This instance for chaining
   */
  maxReadBps(bps) {
    this._maxReadBps = bps;
    return this;
  }

  /**
   * Set maximum write bandwidth in bytes per second (Linux only).
   *
   * @param {number} bps - Max write bytes per second (0 = no limit)
   * @returns {SaferExec} This instance for chaining
   */
  maxWriteBps(bps) {
    this._maxWriteBps = bps;
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
   * Enable dry-run mode for supply chain audit and malware analysis.
   *
   * In dry-run mode, ALL filesystem and network operations are denied
   * (no side effects). Every attempted read/write/exec/network connection
   * is captured and returned as a structured audit report. The command
   * receives a synthetic exit code of 0.
   *
   * Dry-run mode implicitly enables audit logging.
   *
   * @returns {SaferExec} This instance for chaining
   */
  enableDryRun() {
    this._enableDryRun = true;
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
   * Deny execution of preinstalled Apple-signed scripting engines and
   * sampling tools that carry unsigned-executable-memory, library-validation,
   * or task-port exemptions (tclsh, wish, perl, system python, ruby, expect,
   * and the com.apple.SamplingTools binaries), and starve them of the FFI
   * frameworks (Tcl/Tk/Ffidl) used to load in-memory shellcode. macOS-only;
   * the sandboxed command itself is never blocked.
   *
   * @returns {SaferExec} This instance for chaining
   */
  blockInterpreters() {
    this._blockInterpreters = true;
    return this;
  }

  /**
   * Deny writes to well-known auto-execution and persistence locations
   * (LaunchAgents/LaunchDaemons, plugin loader directories, login shell rc
   * files, autostart/cron directories, /usr/local/bin) that a build or
   * package install never legitimately needs to write to. Paths explicitly
   * passed to {@link writePaths} remain writable.
   *
   * @returns {SaferExec} This instance for chaining
   */
  denyPersistenceWrites() {
    this._denyPersistenceWrites = true;
    return this;
  }

  /**
   * Permit loading .dylib files from writable or temporary directories even
   * when {@link blockInterpreters} is active. Enable this for native-addon
   * builds that compile and immediately load a dynamic library from the build
   * tree. macOS-only.
   *
   * @returns {SaferExec} This instance for chaining
   */
  allowWritableDylibLoad() {
    this._allowWritableDylibLoad = true;
    return this;
  }

  /**
   * Block the syscalls that turn writable memory into executable memory or
   * execute anonymous files (mprotect/pkey_mprotect PROT_EXEC on writable
   * mappings, mmap PROT_WRITE|PROT_EXEC or MAP_JIT, memfd_create). This stops
   * in-memory shellcode loaders at the syscall level on Linux. It breaks
   * legitimate JITs (V8/node, the JVM, LuaJIT) and is therefore opt-in.
   *
   * @returns {SaferExec} This instance for chaining
   */
  blockJIT() {
    this._blockJIT = true;
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
   * Validate the generated Seatbelt profile syntax without executing the command.
   *
   * Uses sandbox-exec -n to syntax-check the generated profile. Returns
   * a validation result with any errors detected. Available on macOS only.
   *
   * @returns {SaferExec} This instance for chaining
   */
  validateProfile() {
    this._validateProfile = true;
    return this;
  }

  /**
   * Enable symlink resolution of the target command.
   *
   * @param {boolean} [enable=true] - Whether to enable symlink resolution
   * @returns {SaferExec} This instance for chaining
   */
  resolveSymlinks(enable = true) {
    this._resolveSymlinks = enable;
    return this;
  }

  /**
   * Enable strict sandboxing mode.
   *
   * In strict mode, any sandbox initialization failures or degraded security
   * states (e.g. unavailable user namespaces, seccomp, or cgroups) will raise
   * hard errors instead of falling back to degraded protection.
   *
   * @returns {SaferExec} This instance for chaining
   */
  strict() {
    this._strict = true;
    return this;
  }

  /**
   * Allow specific environment variables to pass through from the host process.
   *
   * This is also the opt-in for loader-control variables (DYLD_*, LD_*,
   * NODE_OPTIONS, DEVELOPER_DIR, ...), which are stripped by default because
   * they can hijack library loading or inject startup code; name one here only
   * when you intend that.
   *
   * @param {...string} envs - Names of environment variables to allow
   * @returns {SaferExec} This instance for chaining
   */
  allowEnvs(...envs) {
    for (const env of envs) {
      if (typeof env === 'string' && env && !this._allowEnvs.includes(env)) {
        this._allowEnvs.push(env);
      }
    }
    return this;
  }


  /**
   * Allow/disallow reading and writing to hidden files and directories.
   *
   * @param {boolean} [allow=true] - Whether to allow hidden paths
   * @returns {SaferExec} This instance for chaining
   */
  allowHidden(allow = true) {
    this._allowHidden = allow;
    return this;
  }

  /**
   * Allow the sandboxed process to bind/listen to specific IP addresses or ip:port strings.
   *
   * @param {string|string[]} listenList - IP address or list of IP addresses / ip:port strings
   * @returns {SaferExec} This instance for chaining
   */
  allowListen(listenList) {
    if (Array.isArray(listenList)) {
      this._allowListen.push(...listenList);
    } else if (typeof listenList === 'string' && listenList) {
      this._allowListen.push(listenList);
    }
    return this;
  }

  /**
   * Enable or disable minimal /dev setup inside the sandbox.
   * Essential device nodes like /dev/null, /dev/zero, /dev/random, /dev/urandom,
   * /dev/tty are created from a fresh tmpfs. Enabled by default.
   *
   * @param {boolean} [enable=true] - Pass false to disable
   * @returns {SaferExec} This instance for chaining
   */
  setUpDev(enable = true) {
    this._setUpDev = enable;
    return this;
  }

  /**
   * Use the PID 1 reaper for zombie reaping and exit code propagation.
   * Incompatible with blockFork. Linux-only, opt-in.
   *
   * @param {boolean} [enable=true] - Whether to use the reaper
   * @returns {SaferExec} This instance for chaining
   */
  useReaper(enable = true) {
    this._useReaper = enable;
    return this;
  }

  /**
   * Harden /proc by covering dangerous writable entries (sys, sysrq-trigger,
   * irq, bus) with read-only bind mounts. Linux-only, opt-in.
   *
   * @param {boolean} [enable=true] - Whether to harden /proc
   * @returns {SaferExec} This instance for chaining
   */
  procHardening(enable = true) {
    this._procHardening = enable;
    return this;
  }

  /**
   * Enforce that submounts under read-only bind mounts are also read-only.
   * Scans /proc/self/mountinfo and remounts matching submounts.
   * Linux-only, opt-in.
   *
   * @param {boolean} [enable=true] - Whether to enforce submounts
   * @returns {SaferExec} This instance for chaining
   */
  submountEnforce(enable = true) {
    this._submountEnforce = enable;
    return this;
  }

  /**
   * Automatically make system directories read-only inside the sandbox.
   * Mirrors systemd's ProtectSystem directive for defense-in-depth.
   *
   * "strict" — Mount /usr, /boot, /etc, /lib, /lib64 as read-only.
   * "full"   — Same as strict plus /.
   * "off"    — No automatic read-only system paths (default).
   *
   * User-declared WritePaths take precedence over ProtectSystem.
   * Linux-only.
   *
   * @param {'strict'|'full'|'off'} [mode='strict'] - Protection mode
   * @returns {SaferExec} This instance for chaining
   */
  protectSystem(mode = 'strict') {
    this._protectSystem = mode;
    return this;
  }

  /**
   * Isolate the home directory ($HOME) inside the sandbox.
   *
   * "read-only" — Bind-mount $HOME as read-only.
   * "tmpfs"     — Replace $HOME with a blank tmpfs mount.
   * "off"       — Inherit host home directory (default).
   *
   * Linux-only.
   *
   * @param {'read-only'|'tmpfs'|'off'} [mode='read-only'] - Isolation mode
   * @returns {SaferExec} This instance for chaining
   */
  protectHome(mode = 'read-only') {
    this._protectHome = mode;
    return this;
  }

  /**
   * Replace /tmp and /var/tmp with fresh tmpfs mounts inside the sandbox.
   * Prevents temporary file leakage and cross-sandbox contamination.
   * Linux-only.
   *
   * @param {boolean} [enable=true] - Whether to enable private temp directories
   * @returns {SaferExec} This instance for chaining
   */
  privateTmp(enable = true) {
    this._privateTmp = enable;
    return this;
  }

  /**
   * Bind-mount pre-opened file descriptors into the sandbox.
   * Enables privileged parent to sandbox FD handoff for pre-connected
   * sockets, device nodes, and special files.
   * Linux-only.
   *
   * @param {...{fd: number, target: string, readOnly?: boolean}} specs - FD bind specs
   * @returns {SaferExec} This instance for chaining
   */
  bindFds(...specs) {
    for (const s of specs) {
      if (s && typeof s.fd === 'number' && s.target) {
        this._bindFds.push({ fd: s.fd, target: s.target, readOnly: s.readOnly || false });
      }
    }
    return this;
  }

  /**
   * Map UID 0 inside the user namespace to the caller's real UID.
   * This makes the sandboxed process run as the caller's UID (not root),
   * reducing the surface for kernel bugs triggered by root-in-namespace processes.
   * Linux-only. Requires newuidmap/newgidmap helpers.
   *
   * @param {boolean} [enable=true] - Whether to enable UID remapping
   * @returns {SaferExec} This instance for chaining
   */
  mapToTargetUid(enable = true) {
    this._mapToTargetUid = enable;
    return this;
  }

  /**
   * Permit the sandboxed process to create nested user and mount namespaces
   * (CLONE_NEWUSER / CLONE_NEWNS). Disabled by default: nested namespaces are
   * blocked by seccomp because they are a common entry point for
   * unprivileged-userns kernel privilege-escalation bugs and are not needed by
   * normal package or build tooling. Enable only for workloads that legitimately
   * sandbox themselves. Linux-only.
   *
   * @param {boolean} [enable=true] - Whether to allow nested namespace creation
   * @returns {SaferExec} This instance for chaining
   */
  allowUserns(enable = true) {
    this._allowUserns = enable;
    return this;
  }

  /**
   * Permit degrading to an escapable chroot when pivot_root fails. Disabled by
   * default: a pivot_root failure is treated as fatal so filesystem isolation is
   * never silently weakened to a chroot (which a sandboxed process can escape).
   * Enable only on hosts where pivot_root is unavailable and a weaker boundary
   * is acceptable. Linux-only.
   *
   * @param {boolean} [enable=true] - Whether to allow the chroot fallback
   * @returns {SaferExec} This instance for chaining
   */
  allowChrootFallback(enable = true) {
    this._allowChrootFallback = enable;
    return this;
  }

  /**
   * Kill the sandboxed process with SIGKILL when its parent process dies.
   * Uses PR_SET_PDEATHSIG to prevent orphaned sandbox processes.
   * Linux-only. Enabled by default.
   *
   * @param {boolean} [enable=true] - Pass false to disable
   * @returns {SaferExec} This instance for chaining
   */
  dieWithParent(enable = true) {
    this._dieWithParent = enable;
    return this;
  }

  /**
   * Disconnect the sandboxed process from the controlling terminal via setsid().
   * Prevents terminal-based signal injection (SIGHUP, SIGINT).
   * Linux-only. Enabled by default.
   *
   * @param {boolean} [enable=true] - Pass false to disable
   * @returns {SaferExec} This instance for chaining
   */
  newSession(enable = true) {
    this._newSession = enable;
    return this;
  }

  /**
   * Create ephemeral writable overlays at the given paths.
   * Writes to these paths are stored in a tmpfs upper layer that is discarded
   * when the sandbox exits. Uses overlayfs with userxattr (unprivileged).
   * Linux-only.
   *
   * @param {...string} paths - Directory paths to overlay
   * @returns {SaferExec} This instance for chaining
   */
  tmpOverlayPaths(...paths) {
    this._tmpOverlayPaths.push(...paths);
    return this;
  }

  /**
   * Acquire advisory file locks for the duration of the sandbox.
   * Accepts plain string paths (shared lock, default) or LockFileSpec objects
   * with an optional `exclusive` flag.
   *
   * @param {...(string|LockFileSpec)} specs - File paths or lock specs {path: string, exclusive?: boolean}
   * @returns {SaferExec} This instance for chaining
   *
   * @typedef {{path: string, exclusive?: boolean}} LockFileSpec
   */
  lockFiles(...specs) {
    for (const spec of specs) {
      if (typeof spec === 'string') {
        this._lockFiles.push({ path: spec, exclusive: false });
      } else if (spec && typeof spec === 'object' && spec.path) {
        this._lockFiles.push({ path: spec.path, exclusive: spec.exclusive || false });
      }
    }
    return this;
  }

  /**
   * Acquire exclusive (write) advisory locks on files for the sandbox duration.
   * Exclusive locks enable serialized coordination patterns
   * (e.g., hold exclusive lock during npm install, shared during npm test).
   *
   * @param {...string} paths - File paths to lock exclusively
   * @returns {SaferExec} This instance for chaining
   *
   * @example
   * new SaferExec().lockFilesExclusive('/var/lock/npm-install').run('npm', ['install']);
   */
  lockFilesExclusive(...paths) {
    for (const p of paths) {
      this._lockFiles.push({ path: p, exclusive: true });
    }
    return this;
  }

  /**
   * Enable or disable fd-based bind mounting (default: enabled).
   * When enabled, source paths are opened before mounting and mounted via
   * /proc/self/fd/N, with a TOCTTOU integrity check after the mount.
   * Linux-only.
   *
   * @param {boolean} [use=true] - Pass false to disable
   * @returns {SaferExec} This instance for chaining
   */
  bindUseFd(use = true) {
    this._bindUseFd = use;
    return this;
  }

  /**
   * Stack additional seccomp-bpf filters to compose policies.
   * Each filter is evaluated before the base filter (LIFO kernel order).
   * Linux-only.
   *
   * @param {Array<{program?: string, path?: string}>} filters - Filter specs
   * @returns {SaferExec} This instance for chaining
   */
  seccompFilters(filters) {
    if (Array.isArray(filters)) {
      this._seccompFilters.push(...filters);
    }
    return this;
  }

  /**
   * Stack a Kafel-style seccomp policy filter using a simple policy language.
   * Compiles at runtime to BPF bytecode. Linux-only.
   *
   * Supported syntax: "ALLOW syscall1, syscall2; DEFAULT KILL"
   * Valid actions: ALLOW, KILL, ERRNO(n)
   *
   * @param {string} policy - Kafel-style policy string
   * @returns {SaferExec} This instance for chaining
   *
   * @example
   * new SaferExec().seccompPolicy('ALLOW openat, read, write, close; DEFAULT KILL');
   */
  seccompPolicy(policy) {
    if (typeof policy === 'string' && policy.trim()) {
      this._seccompFilters.push({ policy: policy.trim() });
    }
    return this;
  }

  /**
   * Allow cryptographic library and entropy device access (default).
   *
   * @param {boolean} [allow=true] - Whether to allow crypto operations
   * @returns {SaferExec} This instance for chaining
   */
  allowCrypto(allow = true) {
    this._allowCrypto = allow;
    return this;
  }

  /**
   * Block loading of system cryptographic libraries.
   *
   * @returns {SaferExec} This instance for chaining
   */
  blockCrypto() {
    this._blockCrypto = true;
    return this;
  }

  /**
   * Block access to entropy devices (/dev/random and /dev/urandom).
   *
   * @returns {SaferExec} This instance for chaining
   */
  blockCryptoEntropy() {
    this._blockCryptoEntropy = true;
    return this;
  }

  /**
   * Detect FIPS-compliant operational lookups.
   *
   * @returns {SaferExec} This instance for chaining
   */
  detectFIPS() {
    this._detectFIPS = true;
    return this;
  }

  /**
   * Require FIPS compliance strictly.
   *
   * @returns {SaferExec} This instance for chaining
   */
  strictFIPS() {
    this._strictFIPS = true;
    return this;
  }

  /**
   * Allow/disallow GPU hardware node usage.
   *
   * @param {boolean} [allow=true] - Whether to allow GPU access
   * @returns {SaferExec} This instance for chaining
   */
  allowGPU(allow = true) {
    this._allowGPU = allow;
    return this;
  }

  /**
   * Block hardware access to the Trusted Platform Module (TPM).
   *
   * @returns {SaferExec} This instance for chaining
   */
  blockTPM() {
    this._blockTPM = true;
    return this;
  }

  /**
   * Conceal sandboxing by intercepting hypervisor and debugger checks.
   *
   * @returns {SaferExec} This instance for chaining
   */
  spoofAntiVM() {
    this._spoofAntiVM = true;
    return this;
  }

  /**
   * Track dynamic library loading via LD_AUDIT / DYLD_INSERT_LIBRARIES.
   *
   * @returns {SaferExec} This instance for chaining
   */
  traceLibraries() {
    this._traceLibraries = true;
    return this;
  }

  /**
   * Enable eBPF-based HTTP URL tracing via uprobes on TLS write functions.
   *
   * Attaches uprobes to SSL_write (OpenSSL/BoringSSL), gnutls_record_send (GnuTLS),
   * and Go's crypto/tls.(*Conn).Write to capture plaintext HTTP/1.x requests before
   * encryption. Observed requests are emitted as "http-request" audit entries and
   * included in the learned policy when combined with enableLearn().
   *
   * Requirements: Linux kernel >= 5.8, CAP_BPF + CAP_PERFMON (effectively root).
   * Gracefully falls back with a warning on unsupported platforms/kernels.
   *
   * @returns {SaferExec} This instance for chaining
   */
  traceHTTPURLs() {
    this._traceHTTPURLs = true;
    return this;
  }

  /**
   * Enable cryptographic tracing via eBPF uprobes on TLS cipher negotiation and
   * crypto operation functions. Automatically enables HTTP URL tracing.
   *
   * Captures:
   * - Negotiated TLS cipher suites per connection (name, IANA ID, protocol version, key size)
   * - Detected cryptographic library identities and versions (OpenSSL, GnuTLS, Go crypto/tls)
   * - Optionally: digest, encrypt, sign operations (when cryptoProbeMode is "operations")
   *
   * Cipher info is attached to HTTP access entries and included in audit logs,
   * learned policies, and CBOM output.
   *
   * Requirements: Linux kernel >= 5.8, CAP_BPF + CAP_PERFMON.
   * Falls back to library detection from /proc/pid/maps when eBPF probes fail.
   *
   * @returns {SaferExec} This instance for chaining
   */
  traceCrypto() {
    this._traceCrypto = true;
    this._traceHTTPURLs = true;
    return this;
  }

  /**
   * Set the path for CycloneDX CBOM (Cryptography Bill of Materials) output.
   *
   * When set, the Go binary writes a minimal CycloneDX JSON document with
   * cryptographic-asset components for detected libraries, cipher suites,
   * and crypto operations to this file path after execution completes.
   *
   * Requires traceCrypto() or --trace-crypto to be active.
   *
   * @param {string} path - File path for CBOM output (e.g. "./cbom.json")
   * @returns {SaferExec} This instance for chaining
   */
  cbom(path) {
    this._cbomOutputPath = path;
    return this;
  }

  /**
   * Set the crypto probe mode controlling the depth of crypto tracing.
   *
   * "tls-only" (default) — capture only TLS cipher suites after handshake.
   * "operations" — also capture digest, encrypt, and sign operations (higher overhead).
   *
   * @param {'tls-only'|'operations'} mode - The crypto probe depth
   * @returns {SaferExec} This instance for chaining
   */
  cryptoProbeMode(mode) {
    this._cryptoProbeMode = mode;
    return this;
  }

  /**
   * Restrict negotiation to specific TLS cipher suites.
   *
   * Observed cipher negotiations using any suite not in this list will trigger
   * a `cipher-violation` audit log entry.
   *
   * Supports standard cipher names (e.g. "ECDHE-RSA-AES256-GCM-SHA384")
   * and IANA standard names (e.g. "TLS_AES_256_GCM_SHA384").
   *
   * @param {...string|string[]} ciphers - Cipher suites to allow
   * @returns {SaferExec} This instance for chaining
   */
  allowCiphers(...ciphers) {
    const flat = ciphers.flat();
    for (const c of flat) {
      if (c && !this._allowCiphers.includes(c)) {
        this._allowCiphers.push(c);
      }
    }
    return this;
  }

  /**
   * Set the temporary directory where the dynamic library tracker (LD_AUDIT helper) is extracted.
   *
   * @param {string} dir - The path to the directory
   * @returns {SaferExec} This instance for chaining
   */
  traceTempDir(dir) {
    this._traceTempDir = dir;
    if (dir) {
      this._traceLibraries = true;
    }
    return this;
  }

  /**
   * Suppress dynamic library load warnings/entries from being printed to the stderr stream.
   *
   * @param {boolean} [val=true] - Whether to suppress the log lines from reaching process.stderr
   * @returns {SaferExec} This instance for chaining
   */
  suppressLibLoadStderr(val = true) {
    this._suppressLibLoadStderr = val;
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
  /**
   * Build the ExecConfig object and resolve all hostnames to IPs.
   *
   * This is the shared preparation step used by both `run()` and `runPipe()`.
   * It resolves symlinks, filters non-existent paths, and resolves hostnames.
   *
   * @param {string} cmd - The command to execute
   * @param {string[]} args - Command arguments
   * @returns {Promise<{ config: object, binaryPath: string, effectiveTimeout: number }>}
   */
  async _buildConfig(cmd, args) {
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
    let effectiveReadPaths = [...this._readPaths];
    if (this._workingDir && this._workingDir !== '/' && !effectiveReadPaths.includes(this._workingDir)) {
      effectiveReadPaths.push(this._workingDir);
    }
    if (process.platform === 'linux') {
      // Only allow safe, public system binary and library directories
      const essentialLinuxPaths = [
        '/bin', '/sbin', '/usr', '/lib', '/lib64'
      ];

      // Instead of mounting the entire '/etc' and '/dev', specify only
      // safe, non-sensitive system files and standard device nodes.
      const essentialLinuxFiles = [
        // Linker dynamic library configurations (required for binary execution)
        '/etc/ld.so.cache',
        '/etc/ld.so.conf',
        '/etc/ld.so.conf.d',

        // Public SSL/TLS root certificates (required for secure outgoing requests)
        '/etc/ssl',
        '/etc/pki',

        // System runtime configs and system release identifiers
        '/etc/alternatives',
        '/etc/os-release',
        '/etc/nsswitch.conf',

        // Standard safe device nodes (prevents raw host disk access while preserving standard piping)
        '/dev/null',
        '/dev/zero',
        '/dev/random',
        '/dev/urandom'
      ];

      // Only mount name resolution files if network access is actually active
      if (!this._disableNetwork) {
        essentialLinuxFiles.push('/etc/resolv.conf');
        essentialLinuxFiles.push('/etc/hosts');
      }

      for (const p of essentialLinuxPaths) {
        if (!effectiveReadPaths.includes(p)) {
          effectiveReadPaths.push(p);
        }
      }

      for (const f of essentialLinuxFiles) {
        if (!effectiveReadPaths.includes(f)) {
          effectiveReadPaths.push(f);
        }
      }
    }

    // Always ensure the Node.js runtime directories (raw and resolved realpath) are readable
    // to allow executing Node.js under the sandbox.
    try {
      const nodeBinDir = dirname(process.execPath);
      const nodeLibDir = nodeBinDir.replace(/bin$/, 'lib');
      if (!effectiveReadPaths.includes(nodeBinDir)) {
        effectiveReadPaths.push(nodeBinDir);
      }
      if (!effectiveReadPaths.includes(nodeLibDir)) {
        effectiveReadPaths.push(nodeLibDir);
      }
    } catch {}

    try {
      const nodeRealBinDir = dirname(realpathSync(process.execPath));
      const nodeRealLibDir = nodeRealBinDir.replace(/bin$/, 'lib');
      if (!effectiveReadPaths.includes(nodeRealBinDir)) {
        effectiveReadPaths.push(nodeRealBinDir);
      }
      if (!effectiveReadPaths.includes(nodeRealLibDir)) {
        effectiveReadPaths.push(nodeRealLibDir);
      }
    } catch {}

    // Filter non-existent paths to prevent Go bind mount warnings/errors
    effectiveReadPaths = effectiveReadPaths.filter(p => p && existsSync(p));
    let effectiveWritePaths = [...this._writePaths].filter(p => p && existsSync(p));

    if (!this._allowHidden) {
      const hiddenRegex = /(^|\/)\.[^\/]+/;
      const nodeDirs = new Set();
      try {
        const rawBin = dirname(process.execPath);
        nodeDirs.add(rawBin);
        nodeDirs.add(rawBin.replace(/bin$/, 'lib'));
      } catch {}
      try {
        const realBin = dirname(realpathSync(process.execPath));
        nodeDirs.add(realBin);
        nodeDirs.add(realBin.replace(/bin$/, 'lib'));
      } catch {}

      effectiveReadPaths = effectiveReadPaths.filter(p => {
        const isNodeDir = Array.from(nodeDirs).some(nd => p === nd || p.startsWith(nd + '/'));
        if (isNodeDir) {
          return true;
        }
        return !hiddenRegex.test(p);
      });
      effectiveWritePaths = effectiveWritePaths.filter(p => !hiddenRegex.test(p));
    }

    // Deduplicate
    effectiveReadPaths = Array.from(new Set(effectiveReadPaths));
    effectiveWritePaths = Array.from(new Set(effectiveWritePaths));

    const effectiveBlockExec = [...this._blockExec];
    try {
      const { resolveBinaryPath } = await import('./runner.js');
      const binPath = resolveBinaryPath();
      if (binPath && !effectiveBlockExec.includes(binPath)) {
        effectiveBlockExec.push(binPath);
      }
    } catch {}

    const pathEnv = process.env.PATH || '';
    const delimiter = process.platform === 'win32' ? ';' : ':';
    for (const p of pathEnv.split(delimiter)) {
      if (!p) continue;
      for (const name of ['safer-exec', 'safer-exec-rt']) {
        try {
          const fullPath = join(p, name);
          if (existsSync(fullPath) && !effectiveBlockExec.includes(fullPath)) {
            effectiveBlockExec.push(fullPath);
          }
        } catch {}
      }
    }
    for (const name of ['safer-exec', 'safer-exec-rt']) {
      if (!effectiveBlockExec.includes(name)) {
        effectiveBlockExec.push(name);
      }
    }

    let executionCmd = cmd;
    if (this._resolveSymlinks) {
      try {
        const located = findInPath(cmd);
        executionCmd = realpathSync(located);
      } catch {}
    }

    const finalEnv = {
      ...this._env,
    };
    for (const name of this._allowEnvs) {
      if (process.env[name] !== undefined && finalEnv[name] === undefined) {
        finalEnv[name] = process.env[name];
      }
    }
    // Strip loader-control variables (DYLD_*, LD_*, NODE_OPTIONS, ...) before
    // they reach the sandboxed process; naming one in allowEnvs is the
    // explicit opt-in. The Go engine repeats this filtering as a backstop.
    const sanitizedEnv = stripDangerousEnv(finalEnv, this._allowEnvs);
    for (const k of Object.keys(finalEnv)) {
      if (!(k in sanitizedEnv)) {
        delete finalEnv[k];
      }
    }
    finalEnv.RUNNING_IN_SAFER_EXEC_SANDBOX = 'true';

    // Build the config object
    const config = {
      cmd: executionCmd,
      args,
      env: finalEnv,
      readPaths: effectiveReadPaths,
      writePaths: effectiveWritePaths,
      allowHosts: this._allowHosts,
      allowIPs: this._allowIPs,
      allowPorts: this._allowPorts,
      disableNetwork: this._disableNetwork,
      allowLoopback: this._allowLoopback,
      maxMemoryMB: this._maxMemoryMB,
      maxCPUCores: this._maxCPUCores,
      maxProcesses: this._maxProcesses,
      maxReadIOPS: this._maxReadIOPS,
      maxWriteIOPS: this._maxWriteIOPS,
      maxReadBps: this._maxReadBps,
      maxWriteBps: this._maxWriteBps,
      timeoutMs: this._timeoutMs,
      workingDir: this._workingDir,
      enableAudit: this._enableAudit || this._traceLibraries || this._traceHTTPURLs,
      enableDiff: this._enableDiff,
      enableLearn: this._enableLearn,
      enableDryRun: this._enableDryRun,
      allowExec: this._allowExec,
      blockExec: effectiveBlockExec,
      blockFork: this._blockFork,
      traceExec: this._traceExec,
      dumpProfile: this._dumpProfile,
      validateProfile: this._validateProfile,
      strict: this._strict,
      policyFilePath: this._policyFilePath,
      allowCrypto: this._allowCrypto,
      blockCrypto: this._blockCrypto,
      blockCryptoEntropy: this._blockCryptoEntropy,
      detectFIPS: this._detectFIPS,
      strictFIPS: this._strictFIPS,
      allowGPU: this._allowGPU,
      blockTPM: this._blockTPM,
      spoofAntiVM: this._spoofAntiVM,
      traceLibraries: this._traceLibraries,
      traceTempDir: this._traceTempDir,
      traceHTTPURLs: this._traceHTTPURLs,
      traceCrypto: this._traceCrypto,
      allowCiphers: this._allowCiphers,
      cbomOutputPath: this._cbomOutputPath,
      cryptoProbeMode: this._cryptoProbeMode,
      allowURLRules: this._allowURLRules,
      allowEnvs: this._allowEnvs,
      blockInterpreters: this._blockInterpreters,
      denyPersistenceWrites: this._denyPersistenceWrites,
      allowWritableDylibLoad: this._allowWritableDylibLoad,
      blockJIT: this._blockJIT,
      allowHidden: this._allowHidden,
      allowListen: this._allowListen,
      setUpDev: this._setUpDev,
      dieWithParent: this._dieWithParent,
      newSession: this._newSession,
      tmpOverlayPaths: this._tmpOverlayPaths,
      lockFiles: this._lockFiles,
      bindUseFd: this._bindUseFd,
      seccompFilters: this._seccompFilters,
      useReaper: this._useReaper,
      procHardening: this._procHardening,
      submountEnforce: this._submountEnforce,
      protectSystem: this._protectSystem,
      protectHome: this._protectHome,
      privateTmp: this._privateTmp,
      bindFds: this._bindFds,
      mapToTargetUid: this._mapToTargetUid,
      allowUserns: this._allowUserns,
      allowChrootFallback: this._allowChrootFallback,
    };

    const effectiveTimeout = this._timeoutMs;

    // Resolve binary path: if it's relative (starts with . or ..), resolve
    // it relative to the npm package root (not the current working directory,
    // which may differ when tests run from subdirectories).
    let binaryPath = this._binaryPath;
    if (binaryPath && (binaryPath.startsWith('.') || binaryPath.startsWith('..'))) {
      binaryPath = resolve(__packageRoot, binaryPath);
    }

    return { config, binaryPath, effectiveTimeout };
  }

  /**
   * Execute the sandboxed command, buffering all output.
   *
   * Before spawning the Go binary, this method:
   * 1. Resolves all allowed hostnames to IP addresses
   * 2. Builds the JSON config
   * 3. Spawns the Go binary and pipes the config via stdin
   *
   * Output (stdout/stderr) is collected and returned in the result object.
   * For interactive or long-running commands where you want live output,
   * use {@link runPipe} instead.
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
    const { config, binaryPath, effectiveTimeout } = await this._buildConfig(cmd, args);

    // Run the Go binary with a slightly longer timeout to let it finish cleanly
    const options = {
      binaryPath,
      timeout: effectiveTimeout + 2000,
      enableAudit: this._enableAudit || this._traceLibraries || this._traceHTTPURLs,
      suppressLibLoadStderr: this._suppressLibLoadStderr,
      onAudit: (entry) => this.emit('audit', entry),
    };
    return runBinary(config, options);
  }

  /**
   * Execute the sandboxed command, streaming stdout/stderr in real-time.
   *
   * Identical to {@link run} but pipes stdout and stderr directly to the
   * parent process streams as data arrives, rather than buffering until
   * completion. This is the correct mode for long-running or interactive
   * commands (e.g. test runners, build tools) where live output is expected.
   *
   * Structured output markers (`FSDIFF:`, `LEARNED:`) are still intercepted
   * and returned in the result object. Only clean command output reaches
   * the streams.
   *
   * @param {string} cmd - The command to execute
   * @param {string[]} [args=[]] - Command arguments
   * @param {object} [pipeOptions={}] - Streaming options
   * @param {NodeJS.WritableStream|null} [pipeOptions.stdout=process.stdout] - Target stream for stdout (null = suppress)
   * @param {NodeJS.WritableStream|null} [pipeOptions.stderr=process.stderr] - Target stream for stderr (null = suppress)
   * @returns {Promise<{ exitCode: number, timedOut: boolean, fsDiff: object|null, learnedPolicy: object|null }>}
   *
   * @example
   * // Stream output live (e.g. from a CLI)
   * const result = await new SaferExec()
   *   .applyPolicy('poku')
   *   .timeout(240000)
   *   .runPipe('pnpm', ['test']);
   *
   * process.exit(result.exitCode);
   */
  async runPipe(cmd, args = [], pipeOptions = {}) {
    const { config, binaryPath, effectiveTimeout } = await this._buildConfig(cmd, args);

    const options = {
      binaryPath,
      timeout: effectiveTimeout + 2000,
      enableAudit: this._enableAudit || this._traceLibraries || this._traceHTTPURLs,
      stdout: pipeOptions.stdout !== undefined ? pipeOptions.stdout : process.stdout,
      stderr: pipeOptions.stderr !== undefined ? pipeOptions.stderr : process.stderr,
      suppressLibLoadStderr: this._suppressLibLoadStderr,
      onAudit: (entry) => this.emit('audit', entry),
    };
    return runBinaryPipe(config, options);
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

/**
 * Run diagnostics and return OS capabilities and safer-exec feature support.
 *
 * Spawns the Go binary with `--diagnostics` and parses the JSON output.
 * The result includes platform info, OS capabilities (with availability and
 * detail), and safer-exec feature flags.
 *
 * @returns {Promise<Object>} Diagnostics result with platform, capabilities, and features
 *
 * @example
 * const info = await SaferExec.diagnostics();
 * console.log(info.platform);              // 'darwin'
 * console.log(info.capabilities.sandbox_exec); // { available: true, detail: '...' }
 * console.log(info.features.network_isolation); // true
 */
SaferExec.diagnostics = async function () {
  const { resolveBinaryPath } = await import('./runner.js');
  const binaryPath = resolveBinaryPath();
  const { spawn } = await import('node:child_process');

  return new Promise((resolvePromise, reject) => {
    const proc = spawn(binaryPath, ['--diagnostics'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10000,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    proc.stderr.on('data', (chunk) => { stderr += chunk.toString(); });

    proc.on('error', (err) => {
      reject(new Error(`Failed to run diagnostics: ${err.message}`));
    });

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Diagnostics failed (exit ${code}): ${stderr.trim()}`));
        return;
      }
      try {
        const data = JSON.parse(stdout);
        data.nodeVersion = process.version;
        resolvePromise(data);
      } catch (err) {
        reject(new Error(`Failed to parse diagnostics output: ${err.message}. Raw: ${stdout}`));
      }
    });
  });
};

export default SaferExec;
