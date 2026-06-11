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
   * @param {boolean} [options.sanitizeEnv] - Strip sensitive env vars before passing to sandbox
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

    /** @type {boolean} Strip sensitive env vars before passing to sandbox */
    this._sanitizeEnv = options.sanitizeEnv || false;

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

    /**
     * Fine-grained URL access rules (Linux-only, requires traceHTTPURLs).
     * Each entry: { protocol?, host, port?, pathPrefix?, methods? }
     * Host and pathPrefix accept exact strings, globs ("*.npmjs.org"), or
     * regexps prefixed with "~" ("~^registry\.npmjs\.org$").
     * @type {Array<{protocol?: string, host: string, port?: number, pathPrefix?: string, methods?: string[]}>}
     */
    this._allowURLRules = options.allowURLRules || [];
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
   * Strip sensitive environment variables before passing to the sandbox.
   *
   * When enabled, environment variable keys containing substrings like
   * TOKEN, PASSWORD, SECRET, API_KEY, CLIENT_SECRET, SESSION, COOKIE,
   * AUTH, or KEY are removed from the environment before execution.
   *
   * @param {boolean} [val=true] - Whether to sanitize the environment
   * @returns {SaferExec} This instance for chaining
   */
  sanitizeEnv(val = true) {
    this._sanitizeEnv = val;
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
      // These paths are required for dynamically linked binaries, shells,
      // and basic system resolution to work inside an isolated tmpfs root.
      const essentialLinuxPaths = [
        '/bin', '/sbin', '/usr', '/lib', '/lib64', '/etc', '/dev', '/run',
        '/tmp', '/var/tmp', '/proc', '/sys'
      ];
      for (const p of essentialLinuxPaths) {
        if (!effectiveReadPaths.includes(p) && existsSync(p)) {
          effectiveReadPaths.push(p);
        }
      }
    }

    // Filter non-existent paths to prevent Go bind mount warnings/errors
    effectiveReadPaths = effectiveReadPaths.filter(p => existsSync(p));
    let effectiveWritePaths = [...this._writePaths].filter(p => existsSync(p));

    // Deduplicate
    effectiveReadPaths = Array.from(new Set(effectiveReadPaths));
    effectiveWritePaths = Array.from(new Set(effectiveWritePaths));

    let executionCmd = cmd;
    if (this._resolveSymlinks) {
      try {
        const located = findInPath(cmd);
        executionCmd = realpathSync(located);
      } catch {}
    }

    const finalEnv = {
      ...this._env,
      RUNNING_IN_SAFER_EXEC_SANDBOX: 'true',
    };

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
      allowExec: this._allowExec,
      blockExec: this._blockExec,
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
      allowURLRules: this._allowURLRules,
      sanitizeEnv: this._sanitizeEnv,
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
