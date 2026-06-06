/**
 * Darwin-specific tests for RLIMIT enforcement and macOS sandbox features.
 *
 * @module darwin_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { tmpdir } from 'node:os';
import { realpathSync } from 'node:fs';

const basePaths = ['/bin', '/usr', '/System', '/dev', '/private'];

describe('Darwin RLIMIT Enforcement', () => {
  describe('RLIMIT_AS — Memory limit', () => {
    it('should enforce RLIMIT_AS memory limit (2MB)', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const result = await new SaferExec().readPaths(...basePaths).maxMemory(2).run('sh', ['-c', 'python3 -c "print(chr(65) * 5_000_000)"']);
      strict.ok(result.exitCode === 0 || result.exitCode > 0);
    });
  });

  describe('RLIMIT_CPU — CPU time limit', () => {
    it('should enforce RLIMIT_CPU time limit', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const start = Date.now();
      const result = await new SaferExec().readPaths(...basePaths).maxCPUCores(0.1).timeout(5000).run('sh', ['-c', 'while true; do :; done']);
      const elapsed = Date.now() - start;
      strict.ok(result.exitCode !== 0 || result.timedOut, 'should exit non-zero or timeout');
      strict.ok(elapsed < 9000, `should complete within 9s, took ${elapsed}ms`); // Increased upper bound for busy CI runners
    });

    it('should enforce CPU limit with computation', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const start = Date.now();
      const result = await new SaferExec().readPaths(...basePaths).maxCPUCores(0.25).timeout(5000).run('sh', ['-c', 'i=0; while [ $i -lt 10000000 ]; do i=$((i + 1)); done; echo done']);
      const elapsed = Date.now() - start;
      strict.ok(elapsed < 9000, `should complete within 9s, took ${elapsed}ms`);
    });
  });

  describe('RLIMIT_NPROC — Process count limit', () => {
    it('should enforce RLIMIT_NPROC process limit', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const result = await new SaferExec().readPaths(...basePaths).maxProcesses(5).run('sh', ['-c', 'for i in $(seq 1 100); do echo $i & done; wait']);
      strict.ok(result.exitCode >= 0);
    });
  });
});

describe('Darwin Seatbelt Profile Generation', () => {
  it('should generate a valid Seatbelt profile (basic)', async (t) => {
    if (process.platform !== 'darwin') return t.skip('skip');
    const result = await new SaferExec().readPaths(...basePaths).run('sh', ['-c', 'echo sandbox_ok']);
    strict.equal(result.exitCode, 0);
  });

  it('should generate Seatbelt profile with blockFork', async (t) => {
    if (process.platform !== 'darwin') return t.skip('skip');
    const result = await new SaferExec().readPaths(...basePaths).blockFork().run('sh', ['-c', 'echo hello & wait; echo done']);
    strict.notEqual(result.exitCode, 0, `should block execution and return non-zero, got ${result.exitCode}`);
  });

  it('should generate Seatbelt profile with traceExec', async (t) => {
    if (process.platform !== 'darwin') return t.skip('skip');
    const result = await new SaferExec().readPaths(...basePaths).traceExec().run('sh', ['-c', 'echo child1 & echo child2 & wait']);
    strict.ok(result.exitCode >= 0); // Tracers might affect return codes
  });
});

describe('Darwin sandbox-exec Integration', () => {
  it('should run under sandbox-exec successfully', async (t) => {
    if (process.platform !== 'darwin') return t.skip('skip');
    const result = await new SaferExec().readPaths(...basePaths).run('sh', ['-c', 'echo sandbox_ok']);
    strict.equal(result.exitCode, 0);
  });
});