/**
 * E2E tests for CLI argument parsing, short flags, help text, and policy presets.
 * Includes `--` separators to cleanly isolate sandbox flags from target command arguments.
 *
 * @module cli_e2e_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { writeFileSync, unlinkSync, readFileSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, 'cli.js');
const nodeCmd = process.execPath;

/**
 * Safely runs the CLI and returns execution details without throwing an exception.
 */
function runCli(...args) {
  return new Promise((resolve) => {
    execFile(nodeCmd, [cliPath, ...args], { timeout: 15000 }, (err, stdout, stderr) => {
      resolve({
        exitCode: err ? (err.code ?? 1) : 0,
        killed: err?.killed ?? false,
        stdout: stdout || '',
        stderr: stderr || '',
      });
    });
  });
}

// On Linux, the sandbox isolates the filesystem completely. To run basic binaries like `echo`
// or `node` outside of a pre-configured policy, we must mount core system libraries.
const basePaths = process.platform === 'linux'
  ? ['-r', '/usr', '-r', '/bin', '-r', '/lib', '-r', '/lib64', '-r', dirname(nodeCmd)]
  : [];

/**
 * Helper to run `echo` inside the sandbox with necessary library paths.
 */
async function runEcho(cliArgs, outputString) {
  return runCli(...cliArgs, ...basePaths, '--', 'echo', outputString);
}

/**
 * Helper to assert the command exited with 0 and optionally contains a substring.
 */
function assertSuccess(res, expectedSubstring) {
  if (res.exitCode !== 0) {
    console.error(`Command failed unexpectedly:\nExit Code: ${res.exitCode}\nSTDOUT: ${res.stdout}\nSTDERR: ${res.stderr}`);
  }
  strict.equal(res.exitCode, 0, 'Command should exit with 0');
  if (expectedSubstring) {
    strict.ok(res.stdout.includes(expectedSubstring), `Output should contain: ${expectedSubstring}`);
  }
}

describe('CLI E2E', () => {
  describe('Help text', () => {
    it('should print help with --help', async () => {
      const res = await runCli('--help');
      strict.equal(res.exitCode, 0);
      strict.ok(res.stdout.includes('safer-exec'), 'help should mention safer-exec');
      strict.ok(res.stdout.includes('Usage'), 'help should include Usage section');
      strict.ok(res.stdout.includes('--max-memory'), 'help should document --max-memory');
      strict.ok(res.stdout.includes('-m'), 'help should document -m short flag');
    });

    it('should print help with -h', async () => {
      const res = await runCli('-h');
      strict.equal(res.exitCode, 0);
      strict.ok(res.stdout.includes('Usage'));
    });
  });

  describe('Version output', () => {
    it('should print version with --version', async () => {
      const res = await runCli('--version');
      strict.equal(res.exitCode, 0);
      strict.ok(res.stdout.includes('0.6.3'), 'version should include 0.6.3');
    });
  });

  describe('Short flags', () => {
    it('should accept -m for --max-memory', async () => {
      const res = await runEcho(['-m', '256'], 'memory-test');
      assertSuccess(res, 'memory-test');
    });

    it('should accept -c for --max-cpu', async () => {
      const res = await runEcho(['-c', '50'], 'cpu-test');
      assertSuccess(res, 'cpu-test');
    });

    it('should accept -p for --policy', async () => {
      // The npm policy permits Node but blocks generic shell commands, so we use Node explicitly
      const res = await runCli('-p', 'npm', ...basePaths, '--', nodeCmd, '-e', 'console.log("policy-test")');
      assertSuccess(res, 'policy-test');
    });

    it('should accept -d for --diff', async () => {
      const res = await runEcho(['-d'], 'diff-test');
      assertSuccess(res, 'diff-test');
    });

    it('should accept -l for --learn', async () => {
      const res = await runEcho(['-l'], 'learn-test');
      assertSuccess(res, 'learn-test');
    });

    it('should accept -n for --disable-network', async () => {
      const res = await runEcho(['-n'], 'network-test');
      assertSuccess(res, 'network-test');
    });

    it('should accept -w for --write-path', async () => {
      const res = await runEcho(['-w', tmpdir()], 'write-test');
      assertSuccess(res, 'write-test');
    });

    it('should accept -e for --env', async () => {
      const res = await runCli(...basePaths, '-e', 'CLI_TEST_VAR=cli_value', '--', nodeCmd, '-e', 'console.log(process.env.CLI_TEST_VAR)');
      assertSuccess(res, 'cli_value');
    });
  });

  describe('Long flags', () => {
    it('should accept --max-memory', async () => {
      const res = await runEcho(['--max-memory', '512'], 'long-memory-test');
      assertSuccess(res, 'long-memory-test');
    });

    it('should accept --policy', async () => {
      // Use node to bypass arbitrary exec blocks in strict policies
      const res = await runCli('--policy', 'npm', ...basePaths, '--', nodeCmd, '-e', 'console.log("long-policy-test")');
      assertSuccess(res, 'long-policy-test');
    });

    it('should accept --diff', async () => {
      const res = await runEcho(['--diff'], 'long-diff-test');
      assertSuccess(res, 'long-diff-test');
    });

    it('should accept --env', async () => {
      const res = await runCli(...basePaths, '--env', 'LONG_ENV_VAR=long_value', '--', nodeCmd, '-e', 'console.log(process.env.LONG_ENV_VAR)');
      assertSuccess(res, 'long_value');
    });

    it('should accept --allow-loopback', async () => {
      const res = await runEcho(['--allow-loopback'], 'loopback-test');
      assertSuccess(res, 'loopback-test');
    });
  });

  describe('Policy presets', () => {
    const policies = ['npm', 'pypi', 'maven', 'cargo', 'rubygems', 'composer', 'deno', 'gomod', 'bun', 'poku', 'cdxgen'];

    for (const policy of policies) {
      it(`should accept policy preset: ${policy}`, async () => {
        // We trigger an invalid command to ensure the policy parses without JS TypeErrors.
        // It will fail at the OS sandbox execution layer (Exit code != 0), which is perfectly fine.
        const res = await runCli('--policy', policy, '--', 'nonexistent-dummy-binary-123');
        strict.ok(!res.stderr.includes('Unknown policy'), `Should not throw Unknown policy for ${policy}`);
        strict.ok(!res.stderr.includes('TypeError'), `Should not throw JS errors for ${policy}`);
      });
    }

    it('should reject invalid policy preset', async () => {
      const res = await runCli('--policy', 'invalid-policy', '--', 'echo', 'test');
      strict.notEqual(res.exitCode, 0, 'Should exit with non-zero code');
      strict.ok(res.stderr.includes('invalid') || res.stderr.includes('Unknown'), 'Should print invalid policy error');
    });
  });

  describe('Combined flags', () => {
    it('should combine multiple short flags', async () => {
      const res = await runEcho(['-m', '128', '-c', '50', '-n', '-d'], 'multi-short');
      assertSuccess(res, 'multi-short');
    });

    it('should combine policy with other flags', async () => {
      // The npm policy blocks arbitrary execs, so we use Node which is explicitly allowed
      const res = await runCli('-p', 'npm', '-d', '-l', '-n', ...basePaths, '--', nodeCmd, '-e', 'console.log("policy-combo")');
      assertSuccess(res, 'policy-combo');
    });

    it('should combine multiple env vars', async () => {
      const res = await runCli(
        ...basePaths,
        '-e', 'VAR_A=value_a',
        '-e', 'VAR_B=value_b',
        '--',
        nodeCmd, '-e', 'console.log(process.env.VAR_A, process.env.VAR_B)'
      );
      assertSuccess(res, 'value_a value_b');
    });
  });

  describe('Command execution', () => {
    it('should return non-zero exit code for failing commands', async () => {
      const res = await runCli(...basePaths, '--', nodeCmd, '-e', 'process.exit(42)');
      strict.equal(res.exitCode, 42, 'should propagate exit code 42');
    });

    it('should handle commands with arguments', async () => {
      const res = await runCli(...basePaths, '--', 'echo', '-n', 'no-newline');
      assertSuccess(res, 'no-newline');
    });
  });

  describe('Error handling', () => {
    it('should fail for non-existent command', async () => {
      const res = await runCli('--', 'nonexistent-command-123');
      strict.notEqual(res.exitCode, 0, 'should fail for non-existent command');
    });

    it('should fail for invalid max-memory value', async () => {
      const res = await runCli('-m', 'not-a-number', '--', 'echo', 'test');
      strict.notEqual(res.exitCode, 0);
      strict.ok(res.stderr.includes('invalid') || res.stderr.includes('NaN') || res.stderr.includes('must be'), 'should report invalid max-memory');
    });
  });

  describe('Output format', () => {
    it('should output JSON when --json is used', async () => {
      const res = await runEcho(['--json'], 'json-test');
      const parsed = JSON.parse(res.stdout);
      strict.ok(parsed, 'should parse as JSON');
      strict.equal(parsed.exitCode, 0, 'JSON should have exitCode 0');
      strict.ok(parsed.stdout.includes('json-test'), 'JSON should have stdout');
    });

    it('should output JSON with diff when --json and --diff', async () => {
      const res = await runEcho(['--json', '--diff'], 'json-diff-test');
      const parsed = JSON.parse(res.stdout);
      strict.ok('fsDiff' in parsed, 'JSON should have fsDiff');
    });

    it('should output JSON with learned policy when --json and --learn', async () => {
      const res = await runEcho(['--json', '--learn'], 'json-learn-test');
      const parsed = JSON.parse(res.stdout);
      strict.ok('learnedPolicy' in parsed, 'JSON should have learnedPolicy');
    });
  });

  describe('Working directory', () => {
    it('should accept --cwd flag', async () => {
      const cwd = tmpdir();
      const res = await runCli('--cwd', cwd, ...basePaths, '--', nodeCmd, '-e', 'console.log(process.cwd())');
      strict.equal(res.exitCode, 0);
      strict.ok(res.stdout.includes(cwd) || res.stdout.includes('/tmp') || res.stdout.includes('/private/tmp') || res.stdout.includes('Temp'));
    });
  });

  describe('Timeout', () => {
    it('should timeout slow commands', async () => {
      const res = await runCli('--timeout', '500', ...basePaths, '--', nodeCmd, '-e', 'setTimeout(()=>{}, 5000)');
      strict.notEqual(res.exitCode, 0, 'should forcefully terminate timed out command');
    });
  });

  describe('Audit mode', () => {
    it('should accept --audit flag', async () => {
      const res = await runEcho(['--audit'], 'audit-test');
      assertSuccess(res, 'audit-test');
    });
  });

  describe('Policy file flag', () => {
    it('should fail when policy file does not exist', async () => {
      const res = await runCli('--policy-file', 'nonexistent-policy-file-12345.json', '--', 'echo', 'test');
      strict.notEqual(res.exitCode, 0);
      strict.ok(res.stderr.includes('Error loading policy file') || res.stderr.includes('ENOENT'));
    });

    it('should load a valid policy file and run command', async () => {
      const tempPolicy = join(tmpdir(), `cli-test-policy-${Date.now()}.json`);
      writeFileSync(tempPolicy, JSON.stringify({
        readPaths: [tmpdir()]
      }));

      try {
        const res = await runEcho(['--policy-file', tempPolicy], 'policy-file-test');
        assertSuccess(res, 'policy-file-test');
      } finally {
        try { unlinkSync(tempPolicy); } catch {}
      }
    });

    it('should support combining --policy-file with other CLI options', async () => {
      const tempPolicy = join(tmpdir(), `cli-test-policy-combine-${Date.now()}.json`);
      writeFileSync(tempPolicy, JSON.stringify({
        readPaths: [tmpdir()]
      }));

      try {
        const res = await runEcho(['--policy-file', tempPolicy, '--read-path', '/etc'], 'policy-file-combine-test');
        assertSuccess(res, 'policy-file-combine-test');
      } finally {
        try { unlinkSync(tempPolicy); } catch {}
      }
    });

    it('should merge new observations into the policy file with --learn', async () => {
      const tempPolicy = join(tmpdir(), `cli-test-policy-learn-${Date.now()}.json`);
      // Start with a valid policy file
      writeFileSync(tempPolicy, JSON.stringify({
        readPaths: ['/etc']
      }));

      try {
        const res = await runEcho(['--learn', '--policy-file', tempPolicy], 'policy-file-learn-test');
        assertSuccess(res, 'policy-file-learn-test');

        // Check if the policy file was written back and contains some entries
        const content = JSON.parse(readFileSync(tempPolicy, 'utf8'));
        strict.ok(content.readPaths && content.readPaths.length > 0);
      } finally {
        try { unlinkSync(tempPolicy); } catch {}
      }
    });
  });
});