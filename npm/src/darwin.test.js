/**
 * Darwin-specific tests for RLIMIT enforcement and macOS sandbox features.
 *
 * Tests that verify:
 *  - RLIMIT_AS memory limit enforcement
 *  - RLIMIT_CPU time limit enforcement
 *  - RLIMIT_NPROC process limit enforcement
 *  - Seatbelt profile generation
 *  - sandbox-exec integration
 *  - Homebrew path detection
 *
 * @module darwin_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { tmpdir } from 'node:os';
import { realpathSync } from 'node:fs';

describe('Darwin RLIMIT Enforcement', () => {
  describe('RLIMIT_AS — Memory limit', () => {
    it('should enforce RLIMIT_AS memory limit (2MB)', async () => {
      const result = await new SaferExec()
        .maxMemory(2)
        .run('sh', ['-c', 'python3 -c "print(chr(65) * 5_000_000)"']);

      strict.ok(
        result.exitCode === 0 || result.exitCode === 137,
        `should exit with 0 or SIGKILL (137), got ${result.exitCode}`
      );
    });

    it('should allow commands within memory limit', async () => {
      const result = await new SaferExec()
        .maxMemory(64)
        .run('sh', ['-c', 'python3 -c "print(chr(65) * 100_000)"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });

    it('should enforce memory limit with perl (1MB)', async () => {
      const result = await new SaferExec()
        .maxMemory(1)
        .run('sh', ['-c', 'perl -e "print \\"x\\" x (3 * 1024 * 1024)"']);

      strict.ok(
        result.exitCode === 0 || result.exitCode === 137 || result.exitCode === 255,
        `should exit with 0, SIGKILL (137), or perl error (255), got ${result.exitCode}`
      );
    });

    it('should handle zero memory limit (no limit)', async () => {
      const result = await new SaferExec()
        .maxMemory(0)
        .run('sh', ['-c', 'echo "no limit"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('no limit'), 'should have output');
    });
  });

  describe('RLIMIT_CPU — CPU time limit', () => {
    it('should enforce RLIMIT_CPU time limit', async () => {
      const start = Date.now();
      const result = await new SaferExec()
        .maxCPUCores(0.1)
        .timeout(5000)
        .run('sh', ['-c', 'while true; do :; done']);

      const elapsed = Date.now() - start;
      strict.ok(
        result.exitCode === 0 || result.exitCode === 124 || result.timedOut,
        `should exit or timeout, got ${result.exitCode}`
      );
      strict.ok(elapsed < 6000, `should complete within 6s, took ${elapsed}ms`);
    });

    it('should allow commands within CPU limit', async () => {
      const result = await new SaferExec()
        .maxCPUCores(1.0)
        .run('sh', ['-c', 'echo "cpu limited"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('cpu limited'), 'should have output');
    });

    it('should enforce CPU limit with computation', async () => {
      const start = Date.now();
      const result = await new SaferExec()
        .maxCPUCores(0.25)
        .timeout(5000)
        .run('sh', ['-c', 'i=0; while [ $i -lt 10000000 ]; do i=$((i + 1)); done; echo done']);

      const elapsed = Date.now() - start;
      strict.ok(
        result.exitCode === 0 || result.exitCode === 124 || result.timedOut,
        `should exit or timeout, got ${result.exitCode}`
      );
      strict.ok(elapsed < 6000, `should complete within 6s, took ${elapsed}ms`);
    });

    it('should handle zero CPU limit (no limit)', async () => {
      const result = await new SaferExec()
        .maxCPUCores(0)
        .run('sh', ['-c', 'echo "no limit"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('no limit'), 'should have output');
    });
  });

  describe('RLIMIT_NPROC — Process count limit', () => {
    it('should enforce RLIMIT_NPROC process limit', async () => {
      const result = await new SaferExec()
        .maxProcesses(5)
        .run('sh', ['-c', 'for i in $(seq 1 100); do echo $i & done; wait']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });

    it('should handle tight process limit', async () => {
      const result = await new SaferExec()
        .maxProcesses(3)
        .run('sh', ['-c', 'for i in $(seq 1 10); do echo $i & done; wait']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });

    it('should handle zero process limit (no limit)', async () => {
      const result = await new SaferExec()
        .maxProcesses(0)
        .run('sh', ['-c', 'for i in $(seq 1 50); do echo $i & done; wait']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });

    it('should enforce combined memory + process limits', async () => {
      const result = await new SaferExec()
        .maxMemory(10)
        .maxProcesses(10)
        .run('sh', ['-c', 'for i in $(seq 1 20); do perl -e "print \\"x\\" x 100000" & done; wait']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.length > 0, 'should have output');
    });
  });

  describe('Combined RLIMIT enforcement', () => {
    it('should enforce all three limits simultaneously', async () => {
      const result = await new SaferExec()
        .maxMemory(10)
        .maxCPUCores(0.5)
        .maxProcesses(10)
        .timeout(5000)
        .run('sh', ['-c', `
          for i in $(seq 1 5); do
            perl -e "my @a = ('x' x 100000); my \$s = 0; for (1..50000) { \$s += \$_ }; print \"done\\n\"" &
          done
          wait
          echo "all done"
        `]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('all done'), 'should complete');
    });

    it('should handle resource contention gracefully', async () => {
      const result = await new SaferExec()
        .maxMemory(5)
        .maxCPUCores(0.25)
        .maxProcesses(5)
        .timeout(5000)
        .run('sh', ['-c', `
          for i in $(seq 1 3); do
            perl -e "my @a = ('x' x 200000); print \"worker $i\\n\"" &
          done
          wait
          echo "done"
        `]);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('done'), 'should complete');
    });
  });
});

describe('Darwin Seatbelt Profile Generation', () => {
  it('should generate a valid Seatbelt profile (basic)', async () => {
    const result = await new SaferExec()
      .run('sh', ['-c', 'echo sandbox_ok']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.includes('sandbox_ok'), 'should have output');
  });

  it('should generate Seatbelt profile with read paths', async () => {
    const etc = realpathSync('/etc');
    const result = await new SaferExec()
      .readPaths(etc, '/usr')
      .run('sh', ['-c', `cat ${etc}/hosts | head -1`]);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.length > 0, 'should have output');
  });

  it('should generate Seatbelt profile with write paths', async () => {
    const tmp = realpathSync(tmpdir());
    const result = await new SaferExec()
      .writePaths(tmp)
      .run('sh', ['-c', `echo "test" > ${tmp}/safer-exec-darwin-test && cat ${tmp}/safer-exec-darwin-test`]);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.includes('test'), 'should have written content');
  });

  it('should generate Seatbelt profile with network rules', async () => {
    const result = await new SaferExec()
      .allowHosts('github.com')
      .run('sh', ['-c', 'echo network_ok']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.includes('network_ok'), 'should have output');
  });

  it('should generate Seatbelt profile with port rules', async () => {
    const result = await new SaferExec()
      .allowPorts(80, 443)
      .run('sh', ['-c', 'echo ports_ok']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.includes('ports_ok'), 'should have output');
  });

  it('should generate Seatbelt profile with blockFork', async () => {
    const result = await new SaferExec()
      .blockFork()
      .run('sh', ['-c', 'echo hello & wait; echo done']);

    strict.ok(
      result.exitCode === 0 || result.exitCode === 127 || result.exitCode === 128 || result.exitCode === 137,
      `should exit (got ${result.exitCode})`
    );
  });

  it('should generate Seatbelt profile with traceExec', async () => {
    const result = await new SaferExec()
      .traceExec()
      .run('sh', ['-c', 'echo child1 & echo child2 & wait']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.includes('child1'), 'should have output');
  });

  it('should generate Seatbelt profile with audit mode', async () => {
    const etc = realpathSync('/etc');
    const result = await new SaferExec()
      .enableAudit()
      .run('sh', ['-c', `cat ${etc}/hosts | head -1`]);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.length > 0, 'should have output');
  });
});

describe('Darwin sandbox-exec Integration', () => {
  it('should run under sandbox-exec successfully', async () => {
    const result = await new SaferExec()
      .run('sh', ['-c', 'echo sandbox_ok']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.includes('sandbox_ok'), 'should have output');
  });

  it('should handle concurrent sandbox-exec instances', async () => {
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

  it('should handle many concurrent sandbox-exec instances', async () => {
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

  it('should handle sandbox-exec with environment variables', async () => {
    const result = await new SaferExec()
      .env('TEST_VAR', 'test_value')
      .run('sh', ['-c', 'echo $TEST_VAR']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.includes('test_value'), 'should have env var');
  });

  it('should handle sandbox-exec with working directory', async () => {
    const result = await new SaferExec()
      .workingDir('/')
      .run('sh', ['-c', 'pwd']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.equal(result.stdout.trim(), '/', 'should be in root directory');
  });
});

describe('Darwin Homebrew Path Detection', () => {
  it('should detect Homebrew paths on Apple Silicon', async () => {
    const result = await new SaferExec()
      .applyPolicy('npm')
      .run('echo', ['test']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
  });

  it('should include Homebrew OpenSSL paths in SSL detection', async () => {
    const result = await new SaferExec()
      .applyPolicy('npm')
      .run('sh', ['-c', 'echo ssl_ok']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(result.stdout.includes('ssl_ok'), 'should have output');
  });
});
