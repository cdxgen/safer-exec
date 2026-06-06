/**
 * E2E tests for CLI argument parsing, short flags, help text, and policy presets.
 *
 * Covers:
 *   - Short flag aliases (-m, -p, -d, -l, -n, -w, -r, -h, -e, -c)
 *   - Help text output (--help, -?)
 *   - Version output (--version)
 *   - Policy preset application (npm, pypi, maven, cargo, rubygems, composer, deno, gomod, bun)
 *   - Argument validation and error handling
 *   - Combined flags and chaining
 *   - Real command execution through CLI
 *
 * @module cli_e2e_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { realpathSync } from 'node:fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cliPath = join(__dirname, 'cli.js');
const execFileP = promisify(execFile);

/**
 * Run the CLI with given args and return { stdout, stderr, exitCode }.
 */
function runCli(...args) {
  return execFileP('node', [cliPath, ...args], { timeout: 30_000 });
}

/**
 * Run the CLI with given args and allow it to fail.
 */
function runCliRaw(...args) {
  return new Promise((resolve) => {
    const child = execFile('node', [cliPath, ...args], { timeout: 30_000 }, (err, stdout, stderr) => {
      resolve({
        exitCode: err?.code ?? 0,
        stdout: stdout || '',
        stderr: stderr || '',
      });
    });
  });
}

describe('CLI E2E', () => {
  describe('Help text', () => {
    it('should print help with --help', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('safer-exec'), 'help should mention safer-exec');
      strict.ok(stdout.includes('Usage'), 'help should include Usage section');
      strict.ok(stdout.includes('--max-memory'), 'help should document --max-memory');
      strict.ok(stdout.includes('--policy'), 'help should document --policy');
      strict.ok(stdout.includes('--diff'), 'help should document --diff');
      strict.ok(stdout.includes('--learn'), 'help should document --learn');
      strict.ok(stdout.includes('--disable-network'), 'help should document --disable-network');
    });

    it('should print help with -h', async () => {
      const { stdout } = await runCli('-h');
      strict.ok(stdout.includes('safer-exec'), 'help should mention safer-exec');
      strict.ok(stdout.includes('Usage'), 'help should include Usage section');
    });

    it('should print help with --help and --max-memory', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-m'), 'help should document -m short flag');
    });

    it('should print help with --help and --policy', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-p'), 'help should document -p short flag');
    });

    it('should print help with --help and --diff', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-d'), 'help should document -d short flag');
    });

    it('should print help with --help and --learn', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-l'), 'help should document -l short flag');
    });

    it('should print help with --help and --disable-network', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-n'), 'help should document -n short flag');
    });

    it('should print help with --help and --write-path', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-w'), 'help should document -w short flag');
    });

    it('should print help with --help and --read-path', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-r'), 'help should document -r short flag');
    });

    it('should print help with --help and --allow-host', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-H'), 'help should document -H short flag');
    });

    it('should print help with --help and --env', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-e'), 'help should document -e short flag');
    });

    it('should print help with --help and --max-cpu', async () => {
      const { stdout } = await runCli('--help');
      strict.ok(stdout.includes('-c'), 'help should document -c short flag');
    });

    it('should exit with code 0 on help', async () => {
      const { exitCode } = await runCliRaw('--help');
      strict.equal(exitCode, 0, 'help should exit with code 0');
    });
  });

  describe('Version output', () => {
    it('should print version with --version', async () => {
      const { stdout } = await runCli('--version');
      strict.ok(stdout.includes('0.1.0'), 'version should include 0.1.0');
    });

    it('should exit with code 0 on version', async () => {
      const { exitCode } = await runCliRaw('--version');
      strict.equal(exitCode, 0, 'version should exit with code 0');
    });
  });

  describe('Short flags', () => {
    it('should accept -m for --max-memory', async () => {
      const { stdout } = await runCli('-m', '256', 'echo', 'memory-test');
      strict.ok(stdout.includes('memory-test'), 'should echo memory-test');
    });

    it('should accept -c for --max-cpu', async () => {
      const { stdout } = await runCli('-c', '50', 'echo', 'cpu-test');
      strict.ok(stdout.includes('cpu-test'), 'should echo cpu-test');
    });

    it('should accept -p for --policy', async () => {
      const { stdout } = await runCli('-p', 'npm', 'echo', 'policy-test');
      strict.ok(stdout.includes('policy-test'), 'should echo policy-test');
    });

    it('should accept -d for --diff', async () => {
      const { stdout } = await runCli('-d', 'echo', 'diff-test');
      strict.ok(stdout.includes('diff-test'), 'should echo diff-test');
    });

    it('should accept -l for --learn', async () => {
      const { stdout } = await runCli('-l', 'echo', 'learn-test');
      strict.ok(stdout.includes('learn-test'), 'should echo learn-test');
    });

    it('should accept -n for --disable-network', async () => {
      const { stdout } = await runCli('-n', 'echo', 'network-test');
      strict.ok(stdout.includes('network-test'), 'should echo network-test');
    });

    it('should accept -w for --write-path', async () => {
      const { stdout } = await runCli('-w', tmpdir(), 'echo', 'write-test');
      strict.ok(stdout.includes('write-test'), 'should echo write-test');
    });

    it('should accept -r for --read-path', async () => {
      const { stdout } = await runCli('-r', realpathSync('/etc'), 'echo', 'read-test');
      strict.ok(stdout.includes('read-test'), 'should echo read-test');
    });

    it('should accept -H for --allow-host', async () => {
      const { stdout } = await runCli('-H', 'registry.npmjs.org', 'echo', 'host-test');
      strict.ok(stdout.includes('host-test'), 'should echo host-test');
    });

    it('should accept -e for --env', async () => {
      const { stdout } = await runCli('-e', 'CLI_TEST_VAR=cli_value', '--', 'sh', '-c', 'echo $CLI_TEST_VAR');
      strict.ok(stdout.includes('cli_value'), 'should pass env variable');
    });
  });

  describe('Long flags', () => {
    it('should accept --max-memory', async () => {
      const { stdout } = await runCli('--max-memory', '512', 'echo', 'long-memory-test');
      strict.ok(stdout.includes('long-memory-test'), 'should echo long-memory-test');
    });

    it('should accept --policy', async () => {
      const { stdout } = await runCli('--policy', 'pypi', 'echo', 'long-policy-test');
      strict.ok(stdout.includes('long-policy-test'), 'should echo long-policy-test');
    });

    it('should accept --diff', async () => {
      const { stdout } = await runCli('--diff', 'echo', 'long-diff-test');
      strict.ok(stdout.includes('long-diff-test'), 'should echo long-diff-test');
    });

    it('should accept --learn', async () => {
      const { stdout } = await runCli('--learn', 'echo', 'long-learn-test');
      strict.ok(stdout.includes('long-learn-test'), 'should echo long-learn-test');
    });

    it('should accept --disable-network', async () => {
      const { stdout } = await runCli('--disable-network', 'echo', 'long-network-test');
      strict.ok(stdout.includes('long-network-test'), 'should echo long-network-test');
    });

    it('should accept --write-path', async () => {
      const { stdout } = await runCli('--write-path', tmpdir(), 'echo', 'long-write-test');
      strict.ok(stdout.includes('long-write-test'), 'should echo long-write-test');
    });

    it('should accept --read-path', async () => {
      const { stdout } = await runCli('--read-path', realpathSync('/etc'), 'echo', 'long-read-test');
      strict.ok(stdout.includes('long-read-test'), 'should echo long-read-test');
    });

    it('should accept --allow-host', async () => {
      const { stdout } = await runCli('--allow-host', 'registry.npmjs.org', 'echo', 'long-host-test');
      strict.ok(stdout.includes('long-host-test'), 'should echo long-host-test');
    });

    it('should accept --env', async () => {
      const { stdout } = await runCli('--env', 'LONG_ENV_VAR=long_value', '--', 'sh', '-c', 'echo $LONG_ENV_VAR');
      strict.ok(stdout.includes('long_value'), 'should pass env variable');
    });
  });

  describe('Policy presets', () => {
    const policies = ['npm', 'pypi', 'maven', 'cargo', 'rubygems', 'composer', 'deno', 'gomod', 'bun'];

    for (const policy of policies) {
      it(`should accept policy preset: ${policy}`, async () => {
        const { stdout } = await runCli('--policy', policy, 'echo', `preset-${policy}`);
        strict.ok(stdout.includes(`preset-${policy}`), `should echo preset-${policy}`);
      });
    }

    it('should reject invalid policy preset', async () => {
      const { exitCode, stderr } = await runCliRaw('--policy', 'invalid-policy', 'echo', 'test');
      strict.ok(exitCode !== 0 || stderr.includes('invalid'), 'should fail for invalid policy');
    });
  });

  describe('Combined flags', () => {
    it('should combine -m and -p', async () => {
      const { stdout } = await runCli('-m', '256', '-p', 'npm', 'echo', 'combined-mp');
      strict.ok(stdout.includes('combined-mp'), 'should echo combined-mp');
    });

    it('should combine -d and -l', async () => {
      const { stdout } = await runCli('-d', '-l', 'echo', 'combined-dl');
      strict.ok(stdout.includes('combined-dl'), 'should echo combined-dl');
    });

    it('should combine -n and -w', async () => {
      const { stdout } = await runCli('-n', '-w', tmpdir(), 'echo', 'combined-nw');
      strict.ok(stdout.includes('combined-nw'), 'should echo combined-nw');
    });

    it('should combine multiple short flags', async () => {
      const { stdout } = await runCli('-m', '128', '-c', '50', '-n', '-d', 'echo', 'multi-short');
      strict.ok(stdout.includes('multi-short'), 'should echo multi-short');
    });

    it('should combine short and long flags', async () => {
      const { stdout } = await runCli('-m', '256', '--diff', '--disable-network', 'echo', 'mixed');
      strict.ok(stdout.includes('mixed'), 'should echo mixed');
    });

    it('should combine policy with other flags', async () => {
      const { stdout } = await runCli('-p', 'npm', '-d', '-l', '-n', 'echo', 'policy-combo');
      strict.ok(stdout.includes('policy-combo'), 'should echo policy-combo');
    });

    it('should combine multiple env vars', async () => {
      const { stdout } = await runCli(
        '-e', 'VAR_A=value_a',
        '-e', 'VAR_B=value_b',
        '--', 'sh', '-c', 'echo $VAR_A $VAR_B'
      );
      strict.ok(stdout.includes('value_a'), 'should pass VAR_A');
      strict.ok(stdout.includes('value_b'), 'should pass VAR_B');
    });
  });

  describe('Command execution', () => {
    it('should run simple echo command', async () => {
      const { stdout } = await runCli('echo', 'hello world');
      strict.ok(stdout.includes('hello world'), 'should echo hello world');
    });

    it('should run shell commands', async () => {
      const { stdout } = await runCli('--', 'sh', '-c', 'echo "shell output"');
      strict.ok(stdout.includes('shell output'), 'should echo shell output');
    });

    it('should capture stdout from commands', async () => {
      const { stdout } = await runCli('printf', 'exact output');
      strict.ok(stdout.includes('exact output'), 'should capture exact output');
    });

    it('should return non-zero exit code for failing commands', async () => {
      const { exitCode } = await runCliRaw('--', 'sh', '-c', 'exit 42');
      strict.equal(exitCode, 42, 'should return exit code 42');
    });

    it('should handle commands with arguments', async () => {
      const { stdout } = await runCli('echo', '-n', 'no-newline');
      strict.ok(stdout.includes('no-newline'), 'should echo no-newline');
    });

    it('should handle commands with special characters', async () => {
      const { stdout } = await runCli('--', 'sh', '-c', "echo 'special $chars & here'");
      strict.ok(stdout.includes('special $chars & here'), 'should handle special characters');
    });
  });

  describe('Error handling', () => {
    it('should fail for non-existent command', async () => {
      const { exitCode, stderr } = await runCliRaw('nonexistent-command-123');
      strict.ok(exitCode !== 0, 'should fail for non-existent command');
    });

    it('should fail for invalid max-memory value', async () => {
      const { exitCode, stderr } = await runCliRaw('-m', 'not-a-number', 'echo', 'test');
      strict.ok(exitCode !== 0 || stderr.includes('invalid'), 'should fail for invalid max-memory');
    });

    it('should fail for invalid max-cpu value', async () => {
      const { exitCode, stderr } = await runCliRaw('-c', 'not-a-number', 'echo', 'test');
      strict.ok(exitCode !== 0 || stderr.includes('invalid'), 'should fail for invalid max-cpu');
    });

    it('should show usage when no command provided', async () => {
      const { exitCode, stdout, stderr } = await runCliRaw();
      strict.ok(exitCode !== 0 || stdout.includes('Usage') || stdout.includes('safer-exec'), 'should show usage or help');
    });
  });

  describe('Output format', () => {
    it('should output JSON when --json is used', async () => {
      const { stdout } = await runCli('--json', 'echo', 'json-test');
      const parsed = JSON.parse(stdout);
      strict.ok(parsed, 'should parse as JSON');
      strict.ok('exitCode' in parsed, 'JSON should have exitCode');
      strict.ok('stdout' in parsed, 'JSON should have stdout');
    });

    it('should output JSON with diff when --json and --diff', async () => {
      const { stdout } = await runCli('--json', '--diff', 'echo', 'json-diff-test');
      const parsed = JSON.parse(stdout);
      strict.ok(parsed, 'should parse as JSON');
      strict.ok('fsDiff' in parsed, 'JSON should have fsDiff');
    });

    it('should output JSON with learned policy when --json and --learn', async () => {
      const { stdout } = await runCli('--json', '--learn', 'echo', 'json-learn-test');
      const parsed = JSON.parse(stdout);
      strict.ok(parsed, 'should parse as JSON');
      strict.ok('learnedPolicy' in parsed, 'JSON should have learnedPolicy');
    });
  });

  describe('Working directory', () => {
    it('should accept --cwd flag', async () => {
      const cwd = tmpdir();
      const { stdout } = await runCli('--cwd', cwd, 'pwd');
      strict.ok(stdout.includes(cwd) || stdout.includes('/tmp') || stdout.includes('/private/tmp'), 'should show tmpdir as working directory');
    });

    it('should accept -C short flag for --cwd', async () => {
      const cwd = tmpdir();
      const { stdout } = await runCli('-C', cwd, 'pwd');
      strict.ok(stdout.includes(cwd) || stdout.includes('/tmp') || stdout.includes('/private/tmp'), 'should show tmpdir as working directory');
    });
  });

  describe('Timeout', () => {
    it('should accept --timeout flag', async () => {
      const { stdout } = await runCli('--timeout', '10000', 'echo', 'timeout-test');
      strict.ok(stdout.includes('timeout-test'), 'should echo timeout-test');
    });

    it('should timeout slow commands', async () => {
      const { exitCode, stderr } = await runCliRaw('--timeout', '500', '--', 'sh', '-c', 'sleep 10');
      strict.ok(exitCode !== 0, 'should fail for timed out command');
      strict.ok(
        stderr.includes('timeout') || stderr.includes('timed'),
        'should mention timeout in error'
      );
    });
  });

  describe('Audit mode', () => {
    it('should accept --audit flag', async () => {
      const { stdout } = await runCli('--audit', 'echo', 'audit-test');
      strict.ok(stdout.includes('audit-test'), 'should echo audit-test');
    });

    it('should accept -a short flag for --audit', async () => {
      const { stdout } = await runCli('-a', 'echo', 'audit-short-test');
      strict.ok(stdout.includes('audit-short-test'), 'should echo audit-short-test');
    });
  });

  describe('Real-world CLI workflows', () => {
    it('should run npm ls with policy preset', async () => {
      const { stdout } = await runCli('-p', 'npm', 'npm', '--version');
      strict.ok(stdout.length > 0, 'should have npm version output');
    });

    it('should run cat with diff enabled', async () => {
      const { stdout } = await runCli('-d', 'cat', realpathSync('/etc') + '/hosts');
      strict.ok(stdout.length > 0, 'should have /etc/hosts content');
    });

    it('should run with learn mode on file operations', async () => {
      const { stdout } = await runCli('-l', 'ls', '-la', tmpdir());
      strict.ok(stdout.length > 0, 'should have ls output');
    });

    it('should run with combined policy, diff, and learn', async () => {
      const { stdout } = await runCli('-p', 'npm', '-d', '-l', 'echo', 'full-workflow');
      strict.ok(stdout.includes('full-workflow'), 'should echo full-workflow');
    });
  });
});
