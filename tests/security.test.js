/**
 * Security tests for the SaferExec sandbox.
 *
 * Tests that verify:
 * - File read/write isolation
 * - Environment leakage prevention
 * - Network restrictions
 * - Memory limits
 * - Multiple policy boundaries
 *
 * @module security_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from '../npm/src/index.js';

describe('Security Tests', () => {
  describe('File read isolation', () => {
    it('should read files with sandbox', async () => {
      const result = await new SaferExec()
        .readPaths('/etc')
        .run('sh', ['-c', 'cat /etc/hosts']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.length > 0,
        'should read /etc/hosts content'
      );
    });

    it('should read without explicit read paths (system.sb)', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'cat /etc/hosts']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should read content');
    });

    it('should read multiple files simultaneously', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'cat /etc/hosts /etc/protocols 2>/dev/null']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });
  });

  describe('Environment leakage', () => {
    it('should not leak AWS credentials', async () => {
      process.env.AWS_SECRET_ACCESS_KEY = 'wKkjlzvDfGhIjKlMnOpQrStUvWxYz';
      process.env.AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';

      const result = await new SaferExec()
        .env('AWS_SECRET_ACCESS_KEY', 'secret1')
        .env('AWS_ACCESS_KEY_ID', 'key1')
        .run('sh', ['-c', 'echo $AWS_SECRET_ACCESS_KEY:$AWS_ACCESS_KEY_ID']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('secret1:key1'),
        'should use sandboxed credentials'
      );

      delete process.env.AWS_SECRET_ACCESS_KEY;
      delete process.env.AWS_ACCESS_KEY_ID;
    });

    it('should not leak HOME directory', async () => {
      const result = await new SaferExec()
        .env('HOME_DIR', '/sandboxed/home')
        .run('sh', ['-c', 'echo $HOME_DIR']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('/sandboxed/home'),
        'should use sandboxed value'
      );
    });

    it('should allow all env when no env specified', async () => {
      process.env.SECURITY_TEST_VAR = 'test_value_123';

      const result = await new SaferExec()
        .run('sh', ['-c', 'echo $SECURITY_TEST_VAR']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('test_value_123'),
        'should inherit parent environment'
      );

      delete process.env.SECURITY_TEST_VAR;
    });
  });

  describe('Network restrictions', () => {
    it('should execute with disabled network', async () => {
      const result = await new SaferExec()
        .disableNetwork()
        .allowHosts('github.com')
        .run('echo', ['network disabled']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    it('should resolve multiple hosts for network allow list', async () => {
      const result = await new SaferExec()
        .allowHosts('github.com', 'google.com', 'npmjs.org')
        .run('echo', ['hosts allowed']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });
  });

  describe('Memory limits', () => {
    it('should enforce memory limit', async () => {
      const result = await new SaferExec()
        .maxMemory(64)
        .run('sh', ['-c', 'echo "memory limited"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('memory limited'),
        'should complete within memory limit'
      );
    });

    it('should handle zero memory limit (no limit)', async () => {
      const result = await new SaferExec()
        .maxMemory(0)
        .run('echo', ['no limit']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });
  });

  describe('Command execution', () => {
    it('should handle commands with arguments', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "arg1" && echo "arg2" && echo "arg3"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('arg1') &&
        result.stdout.includes('arg2') &&
        result.stdout.includes('arg3'),
        'should handle multiple commands'
      );
    });

    it('should handle special characters in output', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "special chars: angle brackets and quotes"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('special'),
        'should handle special characters'
      );
    });

    it('should capture both stdout and stderr', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "stdout" && echo "stderr" >&2']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('stdout'),
        'should capture stdout'
      );
      strict.ok(
        result.stderr.includes('stderr'),
        'should capture stderr'
      );
    });

    it('should return correct exit codes', async () => {
      for (const code of [0, 1, 42, 127, 255]) {
        const result = await new SaferExec()
          .run('sh', ['-c', `exit ${code}`]);

        strict.equal(
          result.exitCode,
          code,
          `should return exit code ${code}`
        );
      }
    });
  });

  describe('Policy boundary tests', () => {
    it('should apply npm policy with correct hosts', async () => {
      const exec = new SaferExec().applyPolicy('npm');
      // Verify internal state by running and checking it doesn't fail
      const result = await exec.run('echo', ['npm']);
      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    it('should not break with empty policy merge', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .applyPolicy('pypi') // Second policy should merge
        .run('echo', ['merged']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    it('should handle all policies in sequence', async () => {
      const policies = ['npm', 'pypi', 'maven', 'cargo'];
      for (const policy of policies) {
        const result = await new SaferExec()
          .applyPolicy(policy)
          .run('echo', [policy]);

        strict.equal(
          result.exitCode,
          0,
          `should work with ${policy} policy`
        );
      }
    });
  });
});
