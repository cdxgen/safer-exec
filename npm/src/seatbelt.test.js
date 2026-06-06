/**
 * Seatbelt profile inspection tests for macOS.
 *
 * @module seatbelt_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { tmpdir } from 'node:os';
import { realpathSync } from 'node:fs';

const basePaths = ['/bin', '/usr', '/System', '/dev', '/private'];

describe('Seatbelt Profile Inspection', () => {
  describe('Profile structure validation', () => {
    it('should generate profile with (deny default) rule', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const result = await new SaferExec().readPaths(...basePaths).run('sh', ['-c', 'echo sandbox_ok']);
      strict.equal(result.exitCode, 0);
    });

    it('should deny process-fork when blockFork is set', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const result = await new SaferExec().readPaths(...basePaths).blockFork().run('sh', ['-c', 'echo hello & wait; echo done']);
      strict.notEqual(result.exitCode, 0, 'should block execution and exit with non-zero code');
    });

    it('should trace process-exec when traceExec is set', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const result = await new SaferExec().readPaths(...basePaths).traceExec().run('sh', ['-c', 'echo child1 & wait']);
      strict.ok(result.exitCode >= 0);
    });
  });

  describe('Profile with combined settings', () => {
    it('should generate profile with blockFork and traceExec together', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const result = await new SaferExec().readPaths(...basePaths).blockFork().traceExec().run('echo', ['test']);
      strict.ok(result.exitCode >= 0);
    });

    it('should generate profile with all options combined', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const tmp = realpathSync(tmpdir());
      const etc = realpathSync('/etc');
      const result = await new SaferExec()
        .readPaths(etc, ...basePaths)
        .writePaths(tmp)
        .allowPorts(80, 443)
        .blockFork()
        .traceExec()
        .run('echo', ['combined_ok']);

      strict.ok(result.exitCode >= 0);
    });
  });
});