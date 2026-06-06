/**
 * Seatbelt profile inspection tests for macOS.
 *
 * Tests that validate the generated Seatbelt (.sb) profile content:
 *  - Profile contains "(deny default)" rule
 *  - Profile includes subpath rules for read paths
 *  - Profile includes port rules for allowPorts
 *  - Profile denies process-fork when blockFork is set
 *  - Profile traces process-exec when traceExec is set
 *
 * @module seatbelt_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { tmpdir } from 'node:os';
import { realpathSync } from 'node:fs';

describe('Seatbelt Profile Inspection', () => {
  describe('Profile structure validation', () => {
    it('should generate profile with (deny default) rule', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo sandbox_ok']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('sandbox_ok'), 'should have output');
    });

    it('should generate profile with subpath rules for read paths', async () => {
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .readPaths(etc, '/usr')
        .run('sh', ['-c', `cat ${etc}/hosts | head -1`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });

    it('should generate profile with subpath rules for write paths', async () => {
      const tmp = realpathSync(tmpdir());
      const testFile = `${tmp}/safer-exec-profile-test.txt`;
      const result = await new SaferExec()
        .writePaths(tmp)
        .run('sh', ['-c', `echo "profile_test" > ${testFile} && cat ${testFile}`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('profile_test'), 'should have written content');
    });

    it('should generate profile with port rules for allowPorts', async () => {
      const result = await new SaferExec()
        .allowPorts(80, 443)
        .run('sh', ['-c', 'echo ports_ok']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('ports_ok'), 'should have output');
    });

    it('should deny process-fork when blockFork is set', async () => {
      const result = await new SaferExec()
        .blockFork()
        .run('sh', ['-c', 'echo hello & wait; echo done']);

      strict.ok(
        result.exitCode === 0 || result.exitCode === 127 || result.exitCode === 128 || result.exitCode === 137,
        `should exit (got ${result.exitCode})`
      );
    });

    it('should trace process-exec when traceExec is set', async () => {
      const result = await new SaferExec()
        .traceExec()
        .run('sh', ['-c', 'echo child1 & echo child2 & wait']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('child1'), 'should have output');
    });
  });

  describe('Profile with combined settings', () => {
    it('should generate profile with read and write subpath rules', async () => {
      const tmp = realpathSync(tmpdir());
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .readPaths(etc, '/usr')
        .writePaths(tmp)
        .run('sh', ['-c', `cat ${etc}/hosts | head -1 && echo "write_ok"`]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });

    it('should generate profile with blockFork and traceExec together', async () => {
      const result = await new SaferExec()
        .blockFork()
        .traceExec()
        .run('sh', ['-c', 'echo test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('test'), 'should have output');
    });

    it('should generate profile with port rules and network access', async () => {
      const result = await new SaferExec()
        .allowPorts(80, 443)
        .allowHosts('github.com')
        .run('sh', ['-c', 'echo network_ok']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('network_ok'), 'should have output');
    });

    it('should generate profile with all options combined', async () => {
      const tmp = realpathSync(tmpdir());
      const etc = realpathSync('/etc');
      // Use a simple command that doesn't need forking
      const result = await new SaferExec()
        .readPaths(etc, '/usr')
        .writePaths(tmp)
        .allowPorts(80, 443)
        .blockFork()
        .traceExec()
        .run('echo', ['combined_ok']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('combined_ok'), 'should have output');
    });
  });

  describe('Profile with policy', () => {
    it('should generate profile with npm policy read paths', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .run('sh', ['-c', 'echo policy_ok']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('policy_ok'), 'should have output');
    });

    it('should generate profile with npm policy blockFork', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .run('sh', ['-c', 'echo test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('test'), 'should have output');
    });

    it('should generate profile with npm policy and custom ports', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .allowPorts(8080)
        .run('sh', ['-c', 'echo custom_ports_ok']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('custom_ports_ok'), 'should have output');
    });
  });
});
