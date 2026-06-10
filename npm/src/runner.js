/**
 * Go binary runner — spawns the Go binary, pipes JSON config via stdin,
 * and captures stdout/stderr/exitCode with timeout support, audit log parsing,
 * filesystem diff output, and learned policy output.
 *
 * ## Structured output protocol
 *
 * The Go binary communicates structured data (fsDiff, learnedPolicy, profile)
 * back to Node.js via one of two mechanisms:
 *
 * - **Buffered mode** (`run`): markers are written to stdout alongside regular
 *   output, prefixed with `FSDIFF:`, `LEARNED:`, or `PROFILE:`. After the
 *   process exits, `parseStructuredOutput` separates markers from clean stdout.
 *
 * - **Streaming mode** (`runPipe`): a temporary file path is passed to the Go
 *   binary via `config.structuredOutputPath`. The binary writes markers to
 *   that file instead of stdout, leaving stdout clean for raw real-time piping.
 *   After the process exits, `readStructuredFile` parses the file and deletes it.
 *
 * @module runner
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir, platform, arch } from 'node:os';
import { createRequire } from 'node:module';

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

  // Try platform-arch specific locally compiled binary first
  const platformArchBinary = join(__dirname, '..', '..', 'go', 'bin', `safer-exec-${currentPlatform}-${localArch}`);
  try {
    readFileSync(platformArchBinary);
    return platformArchBinary;
  } catch {}

  // Try standard locally compiled binary
  const localBinary = join(__dirname, '..', '..', 'go', 'bin', 'safer-exec');
  try {
    readFileSync(localBinary);
    return localBinary;
  } catch {
    // Not compiled yet
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
      const directPath = join(modulesDir, pkgName, "bin", "safer-exec");
      let realDirectPath;
      try {
        realDirectPath = realpathSync(directPath);
      } catch (_err) {
        realDirectPath = directPath;
      }
      if (existsSync(realDirectPath)) {
        try {
          chmodSync(realDirectPath, 0o755);
        } catch (_err) {
          // ignore
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

  // Try PATH
  return 'safer-exec';
}

/**
 * Run a command through the Go binary with the given config.
 *
 * @param {object} config - The exec config (ExecConfig)
 * @param {object} [options] - Runner options
 * @param {string} [options.binaryPath] - Override the default binary path
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {boolean} [options.enableAudit=false] - Whether to parse audit logs from stderr
 * @param {boolean} [options.pipeStdout=false] - Pipe stdout/stderr directly (for CLI)
 * @returns {Promise<ExecResult>} The execution result
 */
export async function run(config, options = {}) {
  const binaryPath = options.binaryPath || resolveBinaryPath();
  const timeout = options.timeout || 60000;

  const child = spawn(binaryPath, [], {
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: true,
  });

  const configJson = JSON.stringify(config);

  // Write config to stdin
  child.stdin.write(configJson);
  child.stdin.end();

  // Set up timeout
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    try {
      // Kill the entire process group, not just the unshare parent
      process.kill(-child.pid, 'SIGKILL');
    } catch (e) {
      child.kill('SIGKILL');
    }
  }, timeout);

  const { stdout, stderr, status, realtimeAuditLog } = await new Promise((resolve, reject) => {
    const chunks = { stdout: [], stderr: [] };
    const realtimeAuditLog = [];
    let stderrLineBuffer = '';

    child.stdout.on('data', (chunk) => chunks.stdout.push(chunk));
    child.stderr.on('data', (chunk) => {
      if (options.enableAudit) {
        stderrLineBuffer += chunk.toString('utf-8');
        const lines = stderrLineBuffer.split('\n');
        stderrLineBuffer = lines.pop();

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) {
            chunks.stderr.push(Buffer.from('\n'));
            continue;
          }

          let parsed = null;
          try {
            const entry = JSON.parse(trimmed);
            if (entry.type && (entry.target || entry.host)) {
              parsed = entry;
            }
          } catch {}

          if (parsed) {
            realtimeAuditLog.push(parsed);
            if (options.onAudit) {
              options.onAudit(parsed);
            }
            if (!options.suppressLibLoadStderr) {
              chunks.stderr.push(Buffer.from(line + '\n'));
            }
          } else {
            chunks.stderr.push(Buffer.from(line + '\n'));
          }
        }
      } else {
        chunks.stderr.push(chunk);
      }
    });

    child.on('error', (err) => {
      clearTimeout(timeoutId);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timeoutId);
      if (options.enableAudit && stderrLineBuffer.trim()) {
        const line = stderrLineBuffer;
        const trimmed = line.trim();
        let parsed = null;
        try {
          const entry = JSON.parse(trimmed);
          if (entry.type && (entry.target || entry.host)) {
            parsed = entry;
          }
        } catch {}

        if (parsed) {
          realtimeAuditLog.push(parsed);
          if (options.onAudit) {
            options.onAudit(parsed);
          }
          if (!options.suppressLibLoadStderr) {
            chunks.stderr.push(Buffer.from(line + '\n'));
          }
        } else {
          chunks.stderr.push(Buffer.from(line + '\n'));
        }
      }
      resolve({
        stdout: Buffer.concat(chunks.stdout).toString('utf-8'),
        stderr: Buffer.concat(chunks.stderr).toString('utf-8'),
        status: code,
        realtimeAuditLog,
      });
    });
  });

  // Parse structured output from stdout
  const { fsDiff, learnedPolicy, profile, cleanStdout } = parseStructuredOutput(stdout);

  // Parse audit log entries from stderr when enabled
  let auditLog = null;
  if (options.enableAudit) {
    auditLog = realtimeAuditLog;
  }

  return {
    stdout: cleanStdout,
    stderr,
    exitCode: status ?? 1,
    auditLog,
    timedOut,
    ...(fsDiff !== null && { fsDiff }),
    ...(learnedPolicy !== null && { learnedPolicy }),
    ...(profile !== null && { profile }),
  };
}

/**
 * Parse structured output lines (FSDIFF:..., LEARNED:..., PROFILE:...) from stdout.
 *
 * The Go binary prefixes special output with markers:
 * - "FSDIFF:" followed by JSON for filesystem diff
 * - "LEARNED:" followed by JSON for learned policy
 * - "PROFILE:" followed by the generated Seatbelt profile text
 *
 * @param {string} stdout - Raw stdout from the Go binary
 * @returns {{ fsDiff: object|null, learnedPolicy: object|null, profile: string|null, cleanStdout: string }}
 */
export function parseStructuredOutput(stdout) {
  let fsDiff = null;
  let learnedPolicy = null;
  let profile = null;
  const lines = stdout.split('\n');
  const cleanLines = [];

  for (const line of lines) {
    if (line.startsWith('FSDIFF:')) {
      try {
        fsDiff = JSON.parse(line.slice(7));
      } catch {
        cleanLines.push(line);
      }
    } else if (line.startsWith('LEARNED:')) {
      try {
        learnedPolicy = JSON.parse(line.slice(8));
      } catch {
        cleanLines.push(line);
      }
    } else if (line.startsWith('PROFILE:')) {
      profile = line.slice(8);
    } else if (profile !== null) {
      // Continue collecting profile lines after PROFILE: prefix
      profile = profile + '\n' + line;
    } else {
      cleanLines.push(line);
    }
  }

  return {
    fsDiff,
    learnedPolicy,
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
      if (entry.type && (entry.target || entry.host)) {
        entries.push(entry);
      }
    } catch {
      // Not JSON, skip
    }
  }

  return entries;
}

/**
 * Run a command through the Go binary, piping stdout/stderr directly
 * to the parent process in real-time. Used by the CLI for live output.
 *
 * Structured output markers (FSDIFF:, LEARNED:, PROFILE:) are intercepted
 * and suppressed from the live stream; they are returned in the resolved
 * value as parsed objects. All other stdout/stderr data is forwarded as
 * soon as it arrives.
 *
 * @param {object} config - The exec config (ExecConfig)
 * @param {object} [options] - Runner options
 * @param {string} [options.binaryPath] - Override the default binary path
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {NodeJS.WritableStream} [options.stdout=process.stdout] - Stream to pipe stdout to
 * @param {NodeJS.WritableStream} [options.stderr=process.stderr] - Stream to pipe stderr to
 * @returns {Promise<{ exitCode: number, timedOut: boolean, fsDiff: object|null, learnedPolicy: object|null }>}
 */
/**
 * Read and parse structured output markers from a file.
 *
 * @param {string} filePath - Path to the structured output file
 * @returns {{ fsDiff: object|null, learnedPolicy: object|null, profile: string|null }}
 */
export function readStructuredFile(filePath) {
  let fsDiff = null;
  let learnedPolicy = null;
  let profile = null;

  if (!existsSync(filePath)) {
    return { fsDiff, learnedPolicy, profile };
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
      } else if (line.startsWith('PROFILE:')) {
        profile = line.slice(8);
      } else if (profile !== null && line) {
        profile = profile + '\n' + line;
      }
    }
  } catch (err) {
    // Silently ignore file read errors, return whatever we parsed
  }

  return { fsDiff, learnedPolicy, profile };
}

/**
 * Run a command through the Go binary, piping stdout/stderr directly
 * to the parent process in real-time. Used by the CLI for live output.
 *
 * Real-time stdout is piped completely raw and without filtering.
 * Structured output markers (FSDIFF:, LEARNED:, PROFILE:) are written
 * to a temporary file specified in config.structuredOutputPath and
 * read back after the process exits.
 *
 * @param {object} config - The exec config (ExecConfig)
 * @param {object} [options] - Runner options
 * @param {string} [options.binaryPath] - Override the default binary path
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {NodeJS.WritableStream} [options.stdout=process.stdout] - Stream to pipe stdout to
 * @param {NodeJS.WritableStream} [options.stderr=process.stderr] - Stream to pipe stderr to
 * @returns {Promise<{ exitCode: number, timedOut: boolean, fsDiff: object|null, learnedPolicy: object|null, profile: string|null }>}
 */
export async function runPipe(config, options = {}) {
  const binaryPath = options.binaryPath || resolveBinaryPath();
  const timeout = options.timeout || 60000;
  const outStream = options.stdout === null ? null : (options.stdout ?? process.stdout);
  const errStream = options.stderr === null ? null : (options.stderr ?? process.stderr);

  // Create temporary directory and file for structured output redirects
  let tempDir = null;
  let structuredPath = null;
  try {
    tempDir = mkdtempSync(join(tmpdir(), 'safer-exec-pipe-'));
    structuredPath = join(tempDir, 'structured.log');
    config.structuredOutputPath = structuredPath;
  } catch (err) {
    // Fail-safe: if temp file creation fails, proceed without StructuredOutputPath
    config.structuredOutputPath = '';
  }

  const child = spawn(binaryPath, [], {
    stdio: ['pipe', 'pipe', 'pipe'],
    detached: true,
  });

  const configJson = JSON.stringify(config);
  child.stdin.write(configJson);
  child.stdin.end();

  // Forward stdout and stderr streams directly in real-time
  if (outStream) {
    if (typeof outStream.write === 'function' && typeof outStream.on !== 'function') {
      child.stdout.on('data', (chunk) => outStream.write(chunk));
    } else {
      child.stdout.pipe(outStream);
    }
  }
  const realtimeAuditLog = [];
  let stderrLineBuffer = '';
  if (options.enableAudit || errStream) {
    child.stderr.on('data', (chunk) => {
      if (options.enableAudit) {
        stderrLineBuffer += chunk.toString('utf-8');
        const lines = stderrLineBuffer.split('\n');
        stderrLineBuffer = lines.pop();

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) {
            if (errStream) {
              errStream.write('\n');
            }
            continue;
          }

          let parsed = null;
          try {
            const entry = JSON.parse(trimmed);
            if (entry.type && (entry.target || entry.host)) {
              parsed = entry;
            }
          } catch {}

          if (parsed) {
            realtimeAuditLog.push(parsed);
            if (options.onAudit) {
              options.onAudit(parsed);
            }
            if (!options.suppressLibLoadStderr && errStream) {
              errStream.write(line + '\n');
            }
          } else {
            if (errStream) {
              errStream.write(line + '\n');
            }
          }
        }
      } else {
        if (errStream) {
          errStream.write(chunk);
        }
      }
    });
  }

  // Set up timeout
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch (e) {
      child.kill('SIGKILL');
    }
  }, timeout);

  return new Promise((resolve, reject) => {
    child.on('error', (err) => {
      clearTimeout(timeoutId);
      if (tempDir && existsSync(tempDir)) {
        try {
          rmSync(tempDir, { recursive: true, force: true });
        } catch {}
      }
      reject(err);
    });

    child.on('close', (code) => {
      clearTimeout(timeoutId);

      if (options.enableAudit && stderrLineBuffer.trim()) {
        const line = stderrLineBuffer;
        const trimmed = line.trim();
        let parsed = null;
        try {
          const entry = JSON.parse(trimmed);
          if (entry.type && (entry.target || entry.host)) {
            parsed = entry;
          }
        } catch {}

        if (parsed) {
          realtimeAuditLog.push(parsed);
          if (options.onAudit) {
            options.onAudit(parsed);
          }
          if (!options.suppressLibLoadStderr && errStream) {
            errStream.write(line + '\n');
          }
        } else {
          if (errStream) {
            errStream.write(line + '\n');
          }
        }
      }

      let fsDiff = null;
      let learnedPolicy = null;
      let profile = null;

      // Parse structured output from the temporary file if it was created
      if (structuredPath) {
        const parsed = readStructuredFile(structuredPath);
        fsDiff = parsed.fsDiff;
        learnedPolicy = parsed.learnedPolicy;
        profile = parsed.profile;
      }

      // Clean up the temporary directory/file
      if (tempDir && existsSync(tempDir)) {
        try {
          rmSync(tempDir, { recursive: true, force: true });
        } catch {}
      }

      let auditLog = null;
      if (options.enableAudit) {
        auditLog = realtimeAuditLog;
      }

      resolve({
        exitCode: code ?? 1,
        timedOut,
        fsDiff,
        learnedPolicy,
        profile,
        auditLog,
      });
    });
  });
}

