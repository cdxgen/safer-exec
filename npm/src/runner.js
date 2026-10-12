/**
 * Go binary runner — spawns the Go binary, pipes JSON config via stdin,
 * and captures stdout/stderr/exitCode with timeout support, audit log parsing,
 * filesystem diff output, and learned policy output.
 *
 * ## Report channel
 *
 * The sandboxed command writes to the same stdout and stderr as the engine,
 * so nothing parsed from those streams can be trusted: a command could print
 * a line that looks like an audit entry or a `FSDIFF:` result. The engine
 * therefore sends its audit entries and structured results (fsDiff,
 * learnedPolicy, crypto, dryRun, profile) over a separate pipe, stdio[3],
 * named in `config.reportFd`, which the command never inherits. Each line on
 * it is one JSON object: `{"audit": {...}}` or `{"result": "FSDIFF", "data": ...}`.
 * stdout and stderr carry only the command's output and the engine's own
 * `safer-exec:` messages, and are passed through untouched.
 *
 * `parseStructuredOutput`, `readStructuredFile` and `parseAuditLog` read the
 * older stdout/stderr/file protocol, which the engine still uses when it is
 * run without a report channel (by hand, or from its own tests).
 *
 * @module runner
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { basename, dirname, join, win32 } from 'node:path';
import { readFileSync, existsSync, chmodSync, realpathSync } from 'node:fs';
import { platform, arch } from 'node:os';
import { createRequire } from 'node:module';

/**
 * Validate that an object looks like an audit log entry.
 * Supports standard violations/calls as well as crypto ciphers, libraries, and operations.
 *
 * @param {Object} entry - The parsed JSON entry
 * @returns {boolean} True if it is a valid audit entry
 */
export function isValidAuditEntry(entry) {
  return !!(entry && entry.type && (
    entry.target ||
    entry.host ||
    entry.name ||
    entry.algorithm ||
    entry.cipher ||
    entry.operation
  ));
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Resolve the path to the Go binary for the current platform/arch.
 *
 * Tries the following in order:
 * 1. A locally compiled binary in the go/bin directory
 * 2. Platform-specific optional dependency package
 * 3. The 'safer-exec' command in PATH
 *
 * @returns {string} The absolute path to the Go binary
 * @throws {Error} If no binary can be found for the current platform
 */
export function resolveBinaryPath() {
  const currentPlatform = platform();
  const currentArch = arch();
  const localArch = currentArch === 'x64' ? 'amd64' : currentArch;
  const isWindows = currentPlatform === 'win32';
  // Go names the platform "windows"; executables need the .exe suffix.
  const goPlatform = isWindows ? 'windows' : currentPlatform;
  const exeSuffix = isWindows ? '.exe' : '';

  // Try platform-arch specific locally compiled binary first
  const platformArchBinary = join(__dirname, '..', '..', 'go', 'bin', `safer-exec-rt-${goPlatform}-${localArch}${exeSuffix}`);
  if (existsSync(platformArchBinary)) {
    return platformArchBinary;
  }

  // Try standard locally compiled binary
  const localBinary = join(__dirname, '..', '..', 'go', 'bin', `safer-exec-rt${exeSuffix}`);
  if (existsSync(localBinary)) {
    return localBinary;
  }

  // Try to resolve from platform-specific optional dependencies
  let pkgName = "";

  if (currentPlatform === "darwin") {
    if (currentArch === "arm64") {
      pkgName = "@cdxgen/safer-exec-darwin-arm64";
    } else if (currentArch === "x64") {
      pkgName = "@cdxgen/safer-exec-darwin-amd64";
    }
  } else if (currentPlatform === "linux") {
    if (currentArch === "x64") {
      pkgName = "@cdxgen/safer-exec-linux-amd64";
    } else if (currentArch === "arm64") {
      pkgName = "@cdxgen/safer-exec-linux-arm64";
    }
  } else if (isWindows) {
    // The Windows packages also ship the MXC executor (wxc-exec.exe) next to
    // the engine, which is where the engine looks for it.
    if (currentArch === "x64") {
      pkgName = "@cdxgen/safer-exec-windows-amd64";
    } else if (currentArch === "arm64") {
      pkgName = "@cdxgen/safer-exec-windows-arm64";
    }
  }

  if (!pkgName) {
    return undefined;
  }

  try {
    const require = createRequire(import.meta.url);
    const mainPkgPath = require.resolve("@cdxgen/safer-exec");

    // Resolve standard pnpm, npm, and yarn physical locations of node_modules relative to resolved package file
    const searchDirs = [];
    let curDir = dirname(mainPkgPath);
    while (curDir && curDir !== dirname(curDir)) {
      if (basename(curDir) === "node_modules") {
        searchDirs.push(curDir);
      }
      const nodeModulesSub = join(curDir, "node_modules");
      if (existsSync(nodeModulesSub)) {
        searchDirs.push(nodeModulesSub);
      }
      curDir = dirname(curDir);
    }

    for (const modulesDir of searchDirs) {
      // Direct structure under node_modules
      const directPath = join(modulesDir, pkgName, "bin", `safer-exec-rt${exeSuffix}`);
      let realDirectPath;
      try {
        realDirectPath = realpathSync(directPath);
      } catch (_err) {
        realDirectPath = directPath;
      }
      if (existsSync(realDirectPath)) {
        if (!isWindows) {
          try {
            chmodSync(realDirectPath, 0o755);
          } catch (_err) {
            // ignore
          }
        }
        return realDirectPath;
      }
    }
  } catch (err) {
    console.log(
      "error resolving safer-exec package path:",
      err.message,
    );
  }
  if (isWindows) {
    // Never hand Windows a bare name: CreateProcess searches the current
    // directory before PATH, so a safer-exec-rt.exe planted in the project
    // being scanned would run unsandboxed. Search absolute PATH entries only.
    return findOnWindowsPath('safer-exec-rt.exe');
  }
  // Try PATH
  const defaultGlobalPath = '/usr/local/bin/safer-exec-rt';
  try {
    if (existsSync(defaultGlobalPath)) {
      return defaultGlobalPath;
    }
  } catch {}
  return 'safer-exec-rt';
}

/**
 * Finds an executable in the absolute directories of PATH (Windows spells the
 * variable in any case). Relative and empty entries are skipped because they
 * resolve against the current directory.
 *
 * @param {string} name - File name including its extension
 * @param {object} [env=process.env] - Environment to read PATH from
 * @returns {string|undefined} The absolute path, or undefined when not found
 */
export function findOnWindowsPath(name, env = process.env) {
  const key = Object.keys(env).find((k) => k.toUpperCase() === 'PATH');
  for (const dir of (key ? env[key] : '').split(';')) {
    const entry = dir.trim().replace(/^"(.*)"$/, '$1');
    if (!entry || !win32.isAbsolute(entry) || /^[\\/](?![\\/])/.test(entry)) {
      continue;
    }
    const candidate = win32.join(entry, name);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

/**
 * Resolves the engine binary or fails with an actionable message.
 *
 * @param {string} [override] - Explicit binary path from the caller
 * @returns {string} The engine path
 * @throws {Error} When no engine is available for this platform
 */
function requireBinaryPath(override) {
  const binaryPath = override || resolveBinaryPath();
  if (!binaryPath) {
    throw new Error(
      `safer-exec: no engine binary for ${platform()}-${arch()}. Install the matching ` +
        '@cdxgen/safer-exec-<platform>-<arch> package or put safer-exec-rt on PATH.',
    );
  }
  return binaryPath;
}

/**
 * Options for spawning the engine. On POSIX the engine leads its own process
 * group so a timeout can kill the whole tree. On Windows "detached" would
 * give it a separate console instead; the engine's job object already ties
 * the sandboxed tree to the engine's lifetime.
 *
 * @returns {import('node:child_process').SpawnOptions}
 */
export function engineSpawnOptions() {
  // stdio[3] is the report channel (see the module comment).
  const stdio = ['pipe', 'pipe', 'pipe', 'pipe'];
  if (platform() === 'win32') {
    return { stdio, windowsHide: true };
  }
  return { stdio, detached: true };
}

/** File descriptor of the report channel in the engine (stdio[3]). */
export const REPORT_FD = 3;

/**
 * Reads the engine's report channel: newline-delimited JSON objects that are
 * either an audit entry (`{"audit": {...}}`) or a structured result
 * (`{"result": "FSDIFF", "data": ...}`). Malformed lines are ignored; when a
 * result arrives more than once the last one wins.
 *
 * @param {(entry: object) => void} onAudit - Called for each audit entry
 * @returns {{ push: (chunk: Buffer|string) => void, end: () => void, results: { fsDiff: object|null, learnedPolicy: object|null, crypto: object|null, dryRun: object|null, profile: string|null } }}
 */
export function createReportParser(onAudit) {
  const results = { fsDiff: null, learnedPolicy: null, crypto: null, dryRun: null, profile: null };
  const state = { opened: false };
  const keys = { FSDIFF: 'fsDiff', LEARNED: 'learnedPolicy', CRYPTO: 'crypto', DRYRUN: 'dryRun' };
  let buffer = '';
  const handle = (line) => {
    if (!line.trim()) {
      return;
    }
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    if (!msg || typeof msg !== 'object') {
      return;
    }
    if (msg.report !== undefined) {
      state.opened = true;
    } else if (msg.audit !== undefined) {
      if (isValidAuditEntry(msg.audit)) {
        onAudit(msg.audit);
      }
    } else if (msg.result === 'PROFILE') {
      results.profile = typeof msg.data === 'string' ? msg.data : JSON.stringify(msg.data);
    } else if (keys[msg.result]) {
      results[keys[msg.result]] = msg.data ?? null;
    }
  };
  return {
    push(chunk) {
      buffer += chunk.toString('utf-8');
      const lines = buffer.split('\n');
      buffer = lines.pop();
      for (const line of lines) {
        handle(line);
      }
    },
    end() {
      handle(buffer);
      buffer = '';
    },
    results,
    /** Whether the engine opened the channel (its first line). */
    get opened() {
      return state.opened;
    },
  };
}

/**
 * The warning shown when the engine never opened the report channel: an
 * engine binary older than this package prints its results to stdout and
 * stderr, where they are no longer read.
 */
const REPORT_MISSING =
  'safer-exec: warning: the engine did not open its report channel, so audit entries and results are unavailable; ' +
  'is safer-exec-rt older than @cdxgen/safer-exec?\n';

/**
 * Resolves once the report channel has been read to its end, or right away
 * when the engine has none.
 *
 * @param {import('node:stream').Readable|undefined} stream
 * @param {ReturnType<typeof createReportParser>} parser
 * @returns {Promise<void>}
 */
function readReport(stream, parser) {
  if (!stream) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    stream.on('data', (chunk) => parser.push(chunk));
    stream.on('error', () => {});
    stream.on('close', () => {
      parser.end();
      resolve();
    });
  });
}

/**
 * Kill the engine after a timeout: the whole process group on POSIX, and on
 * Windows the engine itself, whose job object then terminates the sandbox.
 *
 * @param {import('node:child_process').ChildProcess} child
 */
export function killEngine(child) {
  if (platform() !== 'win32') {
    try {
      // Kill the entire process group, not just the unshare parent
      process.kill(-child.pid, 'SIGKILL');
      return;
    } catch {}
  }
  child.kill('SIGKILL');
}

/**
 * Run a command through the Go binary with the given config.
 *
 * @param {object} config - The exec config (ExecConfig)
 * @param {object} [options] - Runner options
 * @param {string} [options.binaryPath] - Override the default binary path
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {boolean} [options.enableAudit=false] - Collect audit entries from the report channel
 * @param {boolean} [options.pipeStdout=false] - Pipe stdout/stderr directly (for CLI)
 * @returns {Promise<ExecResult>} The execution result
 */
export async function run(config, options = {}) {
  const binaryPath = requireBinaryPath(options.binaryPath);
  const timeout = options.timeout || 60000;

  const child = spawn(binaryPath, [], engineSpawnOptions());

  const configJson = JSON.stringify({ ...config, reportFd: REPORT_FD });
  child.stdin.write(configJson);
  child.stdin.end();

  // Set up timeout
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    killEngine(child);
  }, timeout);

  const chunks = { stdout: [], stderr: [] };
  const auditLog = [];
  const report = createReportParser((entry) => {
    if (!options.enableAudit) {
      return;
    }
    auditLog.push(entry);
    if (options.onAudit) {
      options.onAudit(entry);
    }
    // Audit entries are shown among the stderr output, as the engine used to
    // print them there, unless the caller collects them on its own.
    if (!options.suppressLibLoadStderr) {
      chunks.stderr.push(Buffer.from(JSON.stringify(entry) + '\n'));
    }
  });
  const reportDone = readReport(child.stdio[REPORT_FD], report);

  const status = await new Promise((resolve, reject) => {
    child.stdout.on('data', (chunk) => chunks.stdout.push(chunk));
    child.stderr.on('data', (chunk) => chunks.stderr.push(chunk));
    child.on('error', (err) => {
      clearTimeout(timeoutId);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timeoutId);
      resolve(code);
    });
  });
  await reportDone;
  if (!report.opened) {
    chunks.stderr.push(Buffer.from(REPORT_MISSING));
  }

  const { fsDiff, learnedPolicy, crypto, dryRun, profile } = report.results;
  return {
    stdout: Buffer.concat(chunks.stdout).toString('utf-8'),
    stderr: Buffer.concat(chunks.stderr).toString('utf-8'),
    exitCode: status ?? 1,
    auditLog: options.enableAudit ? auditLog : null,
    timedOut,
    ...(fsDiff !== null && { fsDiff }),
    ...(learnedPolicy !== null && { learnedPolicy }),
    ...(crypto !== null && { crypto }),
    ...(dryRun !== null && { dryRun }),
    ...(profile !== null && { profile }),
  };
}

/**
 * Parse structured output lines (FSDIFF:..., LEARNED:..., CRYPTO:..., PROFILE:...) from stdout.
 *
 * The Go binary prefixes special output with markers:
 * - "FSDIFF:" followed by JSON for filesystem diff
 * - "LEARNED:" followed by JSON for learned policy
 * - "CRYPTO:" followed by JSON for cryptographic observations
 * - "PROFILE:" followed by the generated Seatbelt profile text
 *
 * @param {string} stdout - Raw stdout from the Go binary
 * @returns {{ fsDiff: object|null, learnedPolicy: object|null, crypto: object|null, dryRun: object|null, profile: string|null, cleanStdout: string }}
 */
export function parseStructuredOutput(stdout) {
  let fsDiff = null;
  let learnedPolicy = null;
  let crypto = null;
  let dryRun = null;
  let profile = null;
  const lines = stdout.split('\n');
  const cleanLines = [];

  for (const line of lines) {
    let foundMarker = false;
    for (const marker of ['FSDIFF:', 'LEARNED:', 'CRYPTO:', 'DRYRUN:', 'PROFILE:']) {
      const idx = line.indexOf(marker);
      if (idx !== -1) {
        foundMarker = true;
        const prefix = line.slice(0, idx);
        if (prefix) {
          cleanLines.push(prefix);
        }
        const value = line.slice(idx + marker.length);
        if (marker === 'FSDIFF:') {
          try {
            fsDiff = JSON.parse(value);
          } catch {
            cleanLines.push(line);
          }
        } else if (marker === 'LEARNED:') {
          try {
            learnedPolicy = JSON.parse(value);
          } catch {
            cleanLines.push(line);
          }
        } else if (marker === 'CRYPTO:') {
          try {
            crypto = JSON.parse(value);
          } catch {
            cleanLines.push(line);
          }
        } else if (marker === 'DRYRUN:') {
          try {
            dryRun = JSON.parse(value);
          } catch {
            cleanLines.push(line);
          }
        } else if (marker === 'PROFILE:') {
          profile = value;
        }
        break;
      }
    }
    if (!foundMarker) {
      if (profile !== null) {
        // Continue collecting profile lines after PROFILE: prefix
        profile = profile + '\n' + line;
      } else {
        cleanLines.push(line);
      }
    }
  }

  return {
    fsDiff,
    learnedPolicy,
    crypto,
    dryRun,
    profile,
    cleanStdout: cleanLines.join('\n'),
  };
}

/**
 * Parse audit log entries from stderr output.
 *
 * The Go binary writes audit entries as JSON lines to stderr when
 * audit mode is enabled. Each line is a JSON object with at least:
 * - type: "file_read" | "file_write" | "network" | "syscall"
 * - target: the resource being accessed
 * - timestamp: ISO 8601 timestamp
 * - details: additional context-specific fields
 *
 * @param {string} stderr - The stderr output from the Go binary
 * @returns {Array<Object>} Array of parsed audit log entries
 */
export function parseAuditLog(stderr) {
  const entries = [];
  const lines = stderr.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      const entry = JSON.parse(trimmed);

      // Validate it looks like an audit entry.
      // http-request entries use "host" instead of "target".
      if (isValidAuditEntry(entry)) {
        entries.push(entry);
      }
    } catch {
      // Not JSON, skip
    }
  }

  return entries;
}

/**
 * Read and parse structured output markers from a file.
 *
 * @param {string} filePath - Path to the structured output file
 * @returns {{ fsDiff: object|null, learnedPolicy: object|null, profile: string|null }}
 */
export function readStructuredFile(filePath) {
  let fsDiff = null;
  let learnedPolicy = null;
  let crypto = null;
  let dryRun = null;
  let profile = null;

  if (!existsSync(filePath)) {
    return { fsDiff, learnedPolicy, crypto, dryRun, profile };
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const lines = content.split('\n');

    for (const line of lines) {
      if (line.startsWith('FSDIFF:')) {
        try {
          fsDiff = JSON.parse(line.slice(7));
        } catch {}
      } else if (line.startsWith('LEARNED:')) {
        try {
          learnedPolicy = JSON.parse(line.slice(8));
        } catch {}
      } else if (line.startsWith('CRYPTO:')) {
        try {
          crypto = JSON.parse(line.slice(7));
        } catch {}
      } else if (line.startsWith('DRYRUN:')) {
        try {
          dryRun = JSON.parse(line.slice(7));
        } catch {}
      } else if (line.startsWith('PROFILE:')) {
        profile = line.slice(8);
      } else if (profile !== null && line) {
        profile = profile + '\n' + line;
      }
    }
  } catch (err) {
    // Silently ignore file read errors, return whatever we parsed
  }

  return { fsDiff, learnedPolicy, crypto, dryRun, profile };
}

/**
 * Run a command through the Go binary, piping stdout/stderr directly
 * to the parent process in real-time. Used by the CLI for live output.
 *
 * stdout and stderr are forwarded raw as they arrive. Audit entries and
 * structured results come over the report channel; audit entries are also
 * written to the stderr stream unless `suppressLibLoadStderr` is set.
 *
 * @param {object} config - The exec config (ExecConfig)
 * @param {object} [options] - Runner options
 * @param {string} [options.binaryPath] - Override the default binary path
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {NodeJS.WritableStream} [options.stdout=process.stdout] - Stream to pipe stdout to
 * @param {NodeJS.WritableStream} [options.stderr=process.stderr] - Stream to pipe stderr to
 * @param {boolean} [options.enableAudit=false] - Collect audit entries
 * @param {boolean} [options.suppressLibLoadStderr=false] - Keep audit entries out of the stderr stream
 * @param {(entry: object) => void} [options.onAudit] - Called for each audit entry as it arrives
 * @returns {Promise<{ exitCode: number, timedOut: boolean, fsDiff: object|null, learnedPolicy: object|null, crypto: object|null, dryRun: object|null, profile: string|null, auditLog: object[]|null }>}
 */
export async function runPipe(config, options = {}) {
  const binaryPath = requireBinaryPath(options.binaryPath);
  const timeout = options.timeout || 60000;
  const outStream = options.stdout === null ? null : (options.stdout ?? process.stdout);
  const errStream = options.stderr === null ? null : (options.stderr ?? process.stderr);

  const child = spawn(binaryPath, [], engineSpawnOptions());

  const configJson = JSON.stringify({ ...config, reportFd: REPORT_FD });
  child.stdin.write(configJson);
  child.stdin.end();

  // Forward stdout and stderr streams directly in real-time
  if (outStream) {
    if (typeof outStream.write === 'function' && typeof outStream.on !== 'function') {
      child.stdout.on('data', (chunk) => outStream.write(chunk));
    } else {
      child.stdout.pipe(outStream);
    }
  } else {
    child.stdout.resume();
  }
  if (errStream) {
    child.stderr.on('data', (chunk) => errStream.write(chunk));
  } else {
    child.stderr.resume();
  }

  const auditLog = [];
  const report = createReportParser((entry) => {
    if (!options.enableAudit) {
      return;
    }
    auditLog.push(entry);
    if (options.onAudit) {
      options.onAudit(entry);
    }
    if (!options.suppressLibLoadStderr && errStream) {
      errStream.write(JSON.stringify(entry) + '\n');
    }
  });
  const reportDone = readReport(child.stdio[REPORT_FD], report);

  // Set up timeout
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    killEngine(child);
  }, timeout);

  const code = await new Promise((resolve, reject) => {
    child.on('error', (err) => {
      clearTimeout(timeoutId);
      reject(err);
    });
    child.on('close', (exitCode) => {
      clearTimeout(timeoutId);
      resolve(exitCode);
    });
  });
  await reportDone;
  if (!report.opened && errStream) {
    errStream.write(REPORT_MISSING);
  }

  const { fsDiff, learnedPolicy, crypto, dryRun, profile } = report.results;
  return {
    exitCode: code ?? 1,
    timedOut,
    fsDiff,
    learnedPolicy,
    crypto,
    dryRun,
    profile,
    auditLog: options.enableAudit ? auditLog : null,
  };
}
