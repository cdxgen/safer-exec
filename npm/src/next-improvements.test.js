/**
 * Unit tests for next-generation improvement APIs in the SaferExec class.
 *
 * Covers protectSystem, protectHome, privateTmp, bindFds, mapToTargetUid,
 * lockFiles (enhanced), lockFilesExclusive, seccompPolicy, and combined chaining.
 *
 * @module next_improvements_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { tmpdir } from 'node:os';
import { writeFileSync, unlinkSync, existsSync } from 'node:fs';

describe('Next Improvements API', () => {
  describe('protectSystem', () => {
    it('should default to "off"', () => {
      const s = new SaferExec();
      strict.equal(s._protectSystem, 'off');
    });
    it('should set mode to "strict"', () => {
      const s = new SaferExec();
      strict.equal(s.protectSystem('strict')._protectSystem, 'strict');
    });
    it('should set mode to "full"', () => {
      const s = new SaferExec();
      strict.equal(s.protectSystem('full')._protectSystem, 'full');
    });
    it('should return this for chaining', () => {
      const s = new SaferExec();
      strict.equal(s.protectSystem(), s);
    });
    it('should accept protectSystem in constructor options', () => {
      const s = new SaferExec({ protectSystem: 'strict' });
      strict.equal(s._protectSystem, 'strict');
    });
    it('should default mode to "strict" when called without argument', () => {
      const s = new SaferExec();
      s.protectSystem();
      strict.equal(s._protectSystem, 'strict');
    });
    it('should include protectSystem in _buildConfig', async () => {
      const s = new SaferExec().protectSystem('full');
      const { config } = await s._buildConfig('echo', ['hello']);
      strict.equal(config.protectSystem, 'full');
    });
  });

  describe('protectHome', () => {
    it('should default to "off"', () => {
      const s = new SaferExec();
      strict.equal(s._protectHome, 'off');
    });
    it('should set mode to "read-only" (default)', () => {
      const s = new SaferExec();
      strict.equal(s.protectHome()._protectHome, 'read-only');
    });
    it('should set mode to "tmpfs"', () => {
      const s = new SaferExec();
      strict.equal(s.protectHome('tmpfs')._protectHome, 'tmpfs');
    });
    it('should return this for chaining', () => {
      const s = new SaferExec();
      strict.equal(s.protectHome(), s);
    });
    it('should accept protectHome in constructor', () => {
      const s = new SaferExec({ protectHome: 'tmpfs' });
      strict.equal(s._protectHome, 'tmpfs');
    });
    it('should include protectHome in config', async () => {
      const s = new SaferExec().protectHome('read-only');
      const { config } = await s._buildConfig('echo', ['hello']);
      strict.equal(config.protectHome, 'read-only');
    });
  });

  describe('privateTmp', () => {
    it('should default to false', () => {
      const s = new SaferExec();
      strict.equal(s._privateTmp, false);
    });
    it('should enable with true', () => {
      const s = new SaferExec();
      s.privateTmp();
      strict.equal(s._privateTmp, true);
    });
    it('should accept explicit false', () => {
      const s = new SaferExec();
      s.privateTmp(true);
      s.privateTmp(false);
      strict.equal(s._privateTmp, false);
    });
    it('should return this for chaining', () => {
      const s = new SaferExec();
      strict.equal(s.privateTmp(), s);
    });
    it('should accept in constructor', () => {
      const s = new SaferExec({ privateTmp: true });
      strict.equal(s._privateTmp, true);
    });
    it('should include privateTmp in config', async () => {
      const s = new SaferExec().privateTmp();
      const { config } = await s._buildConfig('echo', ['hello']);
      strict.equal(config.privateTmp, true);
    });
  });

  describe('bindFds', () => {
    it('should default to empty array', () => {
      const s = new SaferExec();
      strict.deepEqual(s._bindFds, []);
    });
    it('should add FD bind specs', () => {
      const s = new SaferExec();
      s.bindFds({ fd: 3, target: '/dev/special' });
      strict.equal(s._bindFds.length, 1);
      strict.equal(s._bindFds[0].fd, 3);
      strict.equal(s._bindFds[0].target, '/dev/special');
      strict.equal(s._bindFds[0].readOnly, false);
    });
    it('should add read-only FD bind spec', () => {
      const s = new SaferExec();
      s.bindFds({ fd: 4, target: '/etc/secret', readOnly: true });
      strict.equal(s._bindFds[0].readOnly, true);
    });
    it('should accept multiple specs', () => {
      const s = new SaferExec();
      s.bindFds(
        { fd: 3, target: '/a' },
        { fd: 4, target: '/b', readOnly: true }
      );
      strict.equal(s._bindFds.length, 2);
    });
    it('should ignore invalid specs', () => {
      const s = new SaferExec();
      s.bindFds(null, undefined, {}, { fd: 3 }, { target: '/x' });
      strict.equal(s._bindFds.length, 0);
    });
    it('should return this for chaining', () => {
      const s = new SaferExec();
      strict.equal(s.bindFds({ fd: 3, target: '/a' }), s);
    });
    it('should accept in constructor', () => {
      const s = new SaferExec({ bindFds: [{ fd: 3, target: '/x' }] });
      strict.equal(s._bindFds.length, 1);
    });
    it('should include bindFds in config', async () => {
      const s = new SaferExec().bindFds({ fd: 5, target: '/dev/input' });
      const { config } = await s._buildConfig('echo', ['hello']);
      strict.equal(config.bindFds.length, 1);
      strict.equal(config.bindFds[0].fd, 5);
    });
  });

  describe('mapToTargetUid', () => {
    it('should default to false', () => {
      const s = new SaferExec();
      strict.equal(s._mapToTargetUid, false);
    });
    it('should enable with true', () => {
      const s = new SaferExec();
      s.mapToTargetUid();
      strict.equal(s._mapToTargetUid, true);
    });
    it('should return this for chaining', () => {
      const s = new SaferExec();
      strict.equal(s.mapToTargetUid(), s);
    });
    it('should accept in constructor', () => {
      const s = new SaferExec({ mapToTargetUid: true });
      strict.equal(s._mapToTargetUid, true);
    });
    it('should include mapToTargetUid in config', async () => {
      const s = new SaferExec().mapToTargetUid();
      const { config } = await s._buildConfig('echo', ['hello']);
      strict.equal(config.mapToTargetUid, true);
    });
  });

  describe('lockFiles (enhanced)', () => {
    it('should accept string paths (backward compat)', () => {
      const s = new SaferExec();
      s.lockFiles('/var/lock/npm');
      strict.equal(s._lockFiles.length, 1);
      strict.equal(s._lockFiles[0].path, '/var/lock/npm');
      strict.equal(s._lockFiles[0].exclusive, false);
    });
    it('should accept LockFileSpec objects', () => {
      const s = new SaferExec();
      s.lockFiles({ path: '/var/lock/a', exclusive: true });
      strict.equal(s._lockFiles[0].exclusive, true);
    });
    it('should accept mixed string and object specs', () => {
      const s = new SaferExec();
      s.lockFiles('/var/lock/shared', { path: '/var/lock/exclusive', exclusive: true });
      strict.equal(s._lockFiles.length, 2);
      strict.equal(s._lockFiles[0].exclusive, false);
      strict.equal(s._lockFiles[1].exclusive, true);
    });
    it('should default exclusive to false for object specs', () => {
      const s = new SaferExec();
      s.lockFiles({ path: '/var/lock/x' });
      strict.equal(s._lockFiles[0].exclusive, false);
    });
  });

  describe('lockFilesExclusive', () => {
    it('should create exclusive lock specs', () => {
      const s = new SaferExec();
      s.lockFilesExclusive('/var/lock/a', '/var/lock/b');
      strict.equal(s._lockFiles.length, 2);
      strict.equal(s._lockFiles[0].exclusive, true);
      strict.equal(s._lockFiles[1].exclusive, true);
      strict.equal(s._lockFiles[0].path, '/var/lock/a');
    });
    it('should return this for chaining', () => {
      const s = new SaferExec();
      strict.equal(s.lockFilesExclusive('/x'), s);
    });
    it('should work alongside shared lockFiles', () => {
      const s = new SaferExec();
      s.lockFiles('/var/lock/shared');
      s.lockFilesExclusive('/var/lock/exclusive');
      strict.equal(s._lockFiles.length, 2);
      strict.equal(s._lockFiles[0].exclusive, false);
      strict.equal(s._lockFiles[1].exclusive, true);
    });
  });

  describe('seccompPolicy', () => {
    it('should add policy string to seccomp filters', () => {
      const s = new SaferExec();
      s.seccompPolicy('ALLOW openat, read, write; DEFAULT KILL');
      strict.equal(s._seccompFilters.length, 1);
      strict.equal(s._seccompFilters[0].policy, 'ALLOW openat, read, write; DEFAULT KILL');
    });
    it('should ignore empty strings', () => {
      const s = new SaferExec();
      s.seccompPolicy('');
      s.seccompPolicy('   ');
      strict.equal(s._seccompFilters.length, 0);
    });
    it('should trim whitespace', () => {
      const s = new SaferExec();
      s.seccompPolicy('  ALLOW read; DEFAULT KILL  ');
      strict.equal(s._seccompFilters[0].policy, 'ALLOW read; DEFAULT KILL');
    });
    it('should return this for chaining', () => {
      const s = new SaferExec();
      strict.equal(s.seccompPolicy('ALLOW read; DEFAULT KILL'), s);
    });
    it('should coexist with other seccomp filter types', () => {
      const s = new SaferExec();
      s.seccompFilters([{ program: 'AAAA' }]);
      s.seccompPolicy('ALLOW read; DEFAULT KILL');
      strict.equal(s._seccompFilters.length, 2);
      strict.equal(s._seccompFilters[0].program, 'AAAA');
      strict.equal(s._seccompFilters[1].policy, 'ALLOW read; DEFAULT KILL');
    });
    it('should include policy in config', async () => {
      const s = new SaferExec().seccompPolicy('ALLOW read; DEFAULT KILL');
      const { config } = await s._buildConfig('echo', ['hello']);
      strict.equal(config.seccompFilters.length, 1);
      strict.equal(config.seccompFilters[0].policy, 'ALLOW read; DEFAULT KILL');
    });
  });

  describe('new default-enabled features', () => {
    it('should default setUpDev to true', () => {
      const s = new SaferExec();
      strict.equal(s._setUpDev, true);
    });
    it('should default dieWithParent to true', () => {
      const s = new SaferExec();
      strict.equal(s._dieWithParent, true);
    });
    it('should default newSession to true', () => {
      const s = new SaferExec();
      strict.equal(s._newSession, true);
    });
    it('should default bindUseFd to false', () => {
      const s = new SaferExec();
      strict.equal(s._bindUseFd, false);
    });
    it('should disable setUpDev when called with false', () => {
      const s = new SaferExec();
      s.setUpDev(false);
      strict.equal(s._setUpDev, false);
    });
    it('should disable dieWithParent when called with false', () => {
      const s = new SaferExec();
      s.dieWithParent(false);
      strict.equal(s._dieWithParent, false);
    });
    it('should disable newSession when called with false', () => {
      const s = new SaferExec();
      s.newSession(false);
      strict.equal(s._newSession, false);
    });
    it('should disable bindUseFd when called with false', () => {
      const s = new SaferExec();
      s.bindUseFd(false);
      strict.equal(s._bindUseFd, false);
    });
    it('should pass new defaults in config', async () => {
      const s = new SaferExec();
      const { config } = await s._buildConfig('echo', ['hello']);
      strict.equal(config.setUpDev, true);
      strict.equal(config.dieWithParent, true);
      strict.equal(config.newSession, true);
      strict.equal(config.bindUseFd, false);
    });
  });

  describe('combined chaining (new features)', () => {
    it('should chain multiple new methods', async () => {
      const s = new SaferExec();
      s
        .protectSystem('strict')
        .protectHome('read-only')
        .privateTmp()
        .mapToTargetUid()
        .seccompPolicy('ALLOW openat, read, write; DEFAULT KILL')
        .lockFilesExclusive('/var/lock/test')
        .bindFds({ fd: 3, target: '/dev/special' });

      const { config } = await s._buildConfig('echo', ['hello']);
      strict.equal(config.protectSystem, 'strict');
      strict.equal(config.protectHome, 'read-only');
      strict.equal(config.privateTmp, true);
      strict.equal(config.mapToTargetUid, true);
      strict.equal(config.seccompFilters[0].policy, 'ALLOW openat, read, write; DEFAULT KILL');
      strict.equal(config.lockFiles[0].path, '/var/lock/test');
      strict.equal(config.lockFiles[0].exclusive, true);
      strict.equal(config.bindFds[0].fd, 3);
    });
  });

  describe('run with new features (integration)', () => {
    it('should execute command with protectSystem set to off', async () => {
      const s = new SaferExec().protectSystem('off');
      const result = await s.run('echo', ['hello']);
      strict.equal(result.exitCode, 0);
      strict.ok(result.stdout.includes('hello'));
    });
    it('should execute command with protectHome set to off', async () => {
      const s = new SaferExec().protectHome('off');
      const result = await s.run('echo', ['test']);
      strict.equal(result.exitCode, 0);
      strict.ok(result.stdout.includes('test'));
    });
    it('should execute command with privateTmp enabled', async () => {
      const s = new SaferExec().writePaths('/tmp').privateTmp();
      const result = await s.run('sh', ['-c', 'echo works > /tmp/test.txt && cat /tmp/test.txt']);
      strict.equal(result.exitCode, 0);
      strict.ok(result.stdout.includes('works'));
    });
    it('should execute command with mapToTargetUid', async () => {
      const s = new SaferExec().mapToTargetUid();
      const result = await s.run('id', ['-u']);
      strict.equal(result.exitCode, 0);
    });
    it('should execute with exclusive lock file', async () => {
      const tmpDir = tmpdir();
      const lockPath = `${tmpDir}/test-lock-excl-${Date.now()}`;
      writeFileSync(lockPath, '');
      try {
        const s = new SaferExec().lockFilesExclusive(lockPath);
        const result = await s.run('echo', ['locked-exclusive']);
        strict.equal(result.exitCode, 0);
        strict.ok(result.stdout.includes('locked-exclusive'));
      } finally {
        try { unlinkSync(lockPath); } catch {}
      }
    });
    it('should execute with mixed shared and exclusive locks', async () => {
      const tmpDir = tmpdir();
      const sharedLockPath = `${tmpDir}/test-shared-${Date.now()}`;
      const exclLockPath = `${tmpDir}/test-excl-${Date.now()}`;
      writeFileSync(sharedLockPath, '');
      writeFileSync(exclLockPath, '');
      try {
        const s = new SaferExec()
          .lockFiles(sharedLockPath)
          .lockFilesExclusive(exclLockPath);
        const result = await s.run('echo', ['mixed-locks']);
        strict.equal(result.exitCode, 0);
        strict.ok(result.stdout.includes('mixed-locks'));
      } finally {
        try { unlinkSync(sharedLockPath); } catch {}
        try { unlinkSync(exclLockPath); } catch {}
      }
    });
    it('should seed policy in config when seccompPolicy is used', async () => {
      const s = new SaferExec().seccompPolicy('ALLOW read, write, openat; DEFAULT ERRNO(1)');
      const result = await s.run('echo', ['seccomp-policy-test']);
      strict.equal(result.exitCode, 0);
      strict.ok(result.stdout.includes('seccomp-policy-test'));
    });
    it('should pass combined new options through config', async () => {
      const s = new SaferExec({
        protectSystem: 'strict',
        protectHome: 'read-only',
        privateTmp: true,
        mapToTargetUid: true,
      });
      const { config } = await s._buildConfig('true', []);
      strict.equal(config.protectSystem, 'strict');
      strict.equal(config.protectHome, 'read-only');
      strict.equal(config.privateTmp, true);
      strict.equal(config.mapToTargetUid, true);
    });
  });
});
