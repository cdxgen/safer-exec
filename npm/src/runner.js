/**
 * Go binary runner — spawns the Go binary, pipes JSON config via stdin,
 * and captures stdout/stderr/exitCode with timeout support, audit log parsing,
 * filesystem diff output, and learned policy output.
 *
 * @module runner
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFileSync } from 'node:fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Resolve the path to the Go binary for the current platform/arch.
 *
 * Tries the following in order:
 * 1. A locally compiled binary in the go/bin directory
 * 2. The 'safer-exec' command in PATH
 *
 * @returns {string} The absolute path to the Go binary
 * @throws {Error} If no binary can be found for the current platform
 */
export function resolveBinaryPath() {
  // Try locally compiled binary
  const localBinary = join(__dirname, '..', '..', 'go', 'bin', 'safer-exec');
  try {
    readFileSync(localBinary);
    return localBinary;
  } catch {
    // Not compiled yet
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
  });

  const configJson = JSON.stringify(config);

  // Write config to stdin
  child.stdin.write(configJson);
  child.stdin.end();

  // Set up timeout
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    child.kill('SIGKILL');
  }, timeout);

  const { stdout, stderr, status } = await new Promise((resolve, reject) => {
    const chunks = { stdout: [], stderr: [] };

    child.stdout.on('data', (chunk) => chunks.stdout.push(chunk));
    child.stderr.on('data', (chunk) => chunks.stderr.push(chunk));

    child.on('error', (err) => {
      clearTimeout(timeoutId);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timeoutId);
      resolve({
        stdout: Buffer.concat(chunks.stdout).toString('utf-8'),
        stderr: Buffer.concat(chunks.stderr).toString('utf-8'),
        status: code,
      });
    });
  });

  // Parse structured output from stdout
  const { fsDiff, learnedPolicy, profile, cleanStdout } = parseStructuredOutput(stdout);

  // Parse audit log entries from stderr when enabled
  let auditLog = null;
  if (options.enableAudit) {
    auditLog = parseAuditLog(stderr);
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

      // Validate it looks like an audit entry
      if (entry.type && entry.target) {
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
 * @param {object} config - The exec config (ExecConfig)
 * @param {object} [options] - Runner options
 * @param {string} [options.binaryPath] - Override the default binary path
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {NodeJS.WritableStream} [options.stdout=process.stdout] - Stream to pipe stdout to
 * @param {NodeJS.WritableStream} [options.stderr=process.stderr] - Stream to pipe stderr to
 * @returns {Promise<{ exitCode: number, timedOut: boolean, fsDiff: object|null, learnedPolicy: object|null }>}
 */
export async function runPipe(config, options = {}) {
  const binaryPath = options.binaryPath || resolveBinaryPath();
  const timeout = options.timeout || 60000;
  const outStream = options.stdout === null ? { write: () => {} } : (options.stdout ?? process.stdout);
  const errStream = options.stderr === null ? { write: () => {} } : (options.stderr ?? process.stderr);

  const child = spawn(binaryPath, [], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  const configJson = JSON.stringify(config);
  child.stdin.write(configJson);
  child.stdin.end();

  // Pipe stdout/stderr in real-time, but capture structured output
  const stdoutChunks = [];
  const stderrChunks = [];

  child.stdout.on('data', (chunk) => {
    stdoutChunks.push(chunk);
    outStream.write(chunk);
  });

  child.stderr.on('data', (chunk) => {
    stderrChunks.push(chunk);
    errStream.write(chunk);
  });

  // Set up timeout
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    child.kill('SIGKILL');
  }, timeout);

  return new Promise((resolve, reject) => {
    child.on('error', (err) => {
      clearTimeout(timeoutId);
      reject(err);
    });
    child.on('close', (code) => {
      clearTimeout(timeoutId);

      const rawStdout = Buffer.concat(stdoutChunks).toString('utf-8');
      const { fsDiff, learnedPolicy, cleanStdout } = parseStructuredOutput(rawStdout);

      resolve({
        stdout: cleanStdout,
        stderr: Buffer.concat(stderrChunks).toString('utf-8'),
        exitCode: code ?? 1,
        timedOut,
        fsDiff: fsDiff ?? null,
        learnedPolicy: learnedPolicy ?? null,
      });
    });
  });
}
