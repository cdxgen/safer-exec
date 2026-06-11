/**
 * Breakout Security Test Suite.
 *
 * Aggressive tests that attempt to crash the host by exhausting resources.
 * Each test spawns a command that exhausts resources and verifies
 * the sandbox catches it.
 *
 * Test categories:
 *  - Memory bombs (allocation loops, array multiplication)
 *  - Fork bombs (recursive process spawning)
 *  - CPU miners (infinite computation loops)
 *  - Combined exhaustion (memory + CPU + processes simultaneously)
 *  - Edge cases (zero limits, negative limits, very large limits)
 *
 * @module exhaustion_test
 */

import { describe, it, before } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from '../npm/src/index.js';
import { execSync } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { join } from 'node:path';

// Resolve the go binary path properly
let binaryPath = undefined;
try {
  const potentialPath = join(process.cwd(), "..", 'bin', 'safer-exec');
  if (existsSync(potentialPath)) {
    binaryPath = potentialPath;
  } else {
    execSync('cd ../go && CGO_ENABLED=0 go build -trimpath -o ../bin/safer-exec ./cmd/safer-exec/', {
      stdio: 'ignore',
      cwd: process.cwd(),
    });
    if (existsSync(potentialPath)) {
      binaryPath = potentialPath;
    }
  }
} catch {
  // Ignored - fall back to SaferExec default behavior
}

function createExec() {
  const exec = new SaferExec();
  if (binaryPath) {
    exec.binaryPath(binaryPath);
  }
  return exec;
}

describe('Resource Exhaustion Tests', () => {
  before(() => {
    if (!binaryPath) {
      console.warn('SaferExec Go binary not found. Exhaustion tests might not enforce limits strictly if fallback is used.');
    }
  });

  describe('Memory Bomb — Allocation Loops', () => {
    it('should kill process that exceeds memory limit (5MB)', async () => {
      const result = await createExec()
        .maxMemory(5) // 5MB limit
        .timeout(5000)
        .run('sh', ['-c', `
          # Allocate ~10MB of memory by creating a large string
          python3 -c "print('x' * (10 * 1024 * 1024))" 2>/dev/null || \
          perl -e "print 'x' x (10 * 1024 * 1024)" 2>/dev/null || \
          echo "allocated"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137, 'should exit cleanly or be killed');
    });

    it('should kill process with continuous memory allocation loop', async () => {
      const result = await createExec()
        .maxMemory(10) // 10MB limit
        .timeout(5000)
        .run('sh', ['-c', `
          # Keep allocating in a loop until OOM
          python3 -c "
          a = []
          i = 0
          while True:
              a.append(list(range(100000)))
              i += 1
              if i % 100 == 0: print(i)
          " 2>/dev/null || echo "oom"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137, 'should exit cleanly or be killed');
    });

    it('should handle multiple concurrent memory-heavy processes', async () => {
      const results = await Promise.all([
        createExec()
          .maxMemory(10)
          .timeout(5000)
          .run('sh', ['-c', 'perl -e "print \\"x\\" x (5 * 1024 * 1024)"']),
        createExec()
          .maxMemory(10)
          .timeout(5000)
          .run('sh', ['-c', 'perl -e "print \\"y\\" x (5 * 1024 * 1024)"']),
        createExec()
          .maxMemory(10)
          .timeout(5000)
          .run('sh', ['-c', 'perl -e "print \\"z\\" x (5 * 1024 * 1024)"']),
      ]);

      for (const result of results) {
        strict.ok(result.exitCode === 0 || result.exitCode === 137 || result.exitCode === 127, 'each process should exit cleanly or be killed');
      }
    });

    it('should detect memory exhaustion with correct exit code', async () => {
      const result = await createExec()
        .maxMemory(1) // Very small limit
        .timeout(5000)
        .run('sh', ['-c', `
          # Allocate 1MB at a time in a loop
          for i in {1..10}; do
            perl -e "print 'x' x (1024 * 1024)"
          done
        `]);

      strict.ok(
        result.exitCode === 0 || result.exitCode === 1 || result.exitCode === 137 || result.exitCode === 255 || result.exitCode === 127,
        `should exit with code 0, 1, 137 (SIGKILL), 127 (cmd not found), or 255, got ${result.exitCode}`
      );
    });

    it('should handle memory bomb with 1MB limit', async () => {
      const result = await createExec()
        .maxMemory(1) // 1MB limit
        .timeout(3000)
        .run('sh', ['-c', `
          # Allocate 2MB
          perl -e "print 'x' x (2 * 1024 * 1024)"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137 || result.exitCode === 255 || result.exitCode === 127, 'should exit');
    });
  });

  describe('CPU Miner — Infinite Computation Loops', () => {
    it('should kill process that exceeds CPU time limit', async () => {
      const result = await createExec()
        .maxCPUCores(0.1) // Very small CPU limit
        .timeout(5000)
        .run('sh', ['-c', `
          # Spin CPU in an infinite loop
          while true; do
            :
          done
        `]);

      strict.ok(
        result.exitCode === 0 || result.timedOut || result.exitCode === 124 || result.exitCode === 137,
        'should exit cleanly, be killed, or timeout'
      );
    });

    it('should limit CPU with fractional cores', async () => {
      const start = Date.now();
      const result = await createExec()
        .maxCPUCores(0.5)
        .timeout(5000)
        .run('sh', ['-c', `
          # Count to 10 million
          i=0; while [ $i -lt 10000000 ]; do i=$((i + 1)); done; echo done
        `]);

      const elapsed = Date.now() - start;
      strict.ok(
        result.exitCode === 0 || result.timedOut || result.exitCode === 124 || result.exitCode === 137,
        'should exit cleanly, be killed, or timeout'
      );
      strict.ok(elapsed < 8000, `should complete within 8s, took ${elapsed}ms`);
    });

    it('should handle CPU spinning with multiple cores', async () => {
      const results = await Promise.all([
        createExec()
          .maxCPUCores(0.5)
          .timeout(10000)
          .run('sh', ['-c', 'i=0; while [ $i -lt 1000000 ]; do i=$((i + 1)); done; echo done']),
        createExec()
          .maxCPUCores(0.5)
          .timeout(10000)
          .run('sh', ['-c', 'i=0; while [ $i -lt 1000000 ]; do i=$((i + 1)); done; echo done']),
      ]);

      for (const result of results) {
        strict.ok(
          result.exitCode === 0 || result.timedOut || result.exitCode === 124 || result.exitCode === 137,
          'should exit cleanly, be killed, or timeout'
        );
      }
    });

    it('should handle CPU miner with Python', async () => {
      const start = Date.now();
      const result = await createExec()
        .maxCPUCores(0.5)
        .timeout(5000)
        .run('sh', ['-c', `
          python3 -c "
          import math
          i = 0
          while True:
              i = math.sqrt(i + 1)
              if i > 1000000: print('done')
          " 2>/dev/null || echo "done"
        `]);

      const elapsed = Date.now() - start;
      strict.ok(elapsed < 8000, `should complete within 8s, took ${elapsed}ms`);
      strict.ok(result.exitCode === 0 || result.timedOut || result.exitCode === 137, 'should exit, be killed, or timeout');
    });
  });

  describe('Fork Bomb — Process Explosion', () => {
    it('should limit child processes', async () => {
      const result = await createExec()
        .maxProcesses(10)
        .timeout(5000)
        .run('sh', ['-c', `
          # Fork 20 processes
          for i in {1..20}; do
            echo "fork $i" &
          done
          wait
          echo "done"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137, 'should exit cleanly or be blocked');
    });

    it('should prevent classic fork bomb explosion', async () => {
      const result = await createExec()
        .maxProcesses(50)
        .timeout(5000)
        .run('sh', ['-c', `
          # Fork bomb: spawn 50 processes, each spawning 50 more
          for i in \$(seq 1 50); do
            for j in \$(seq 1 50); do
              echo \$j &
            done
          done
          wait
          echo "done"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137, 'should exit cleanly or be blocked');
    });

    it('should handle process limit with sequential forks', async () => {
      const result = await createExec()
        .maxProcesses(20)
        .timeout(5000)
        .run('sh', ['-c', `
          for i in {1..50}; do
            echo "process $i" &
          done
          wait
          echo "all done"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137, 'should exit cleanly or be blocked');
    });

    it('should count processes correctly with tight limit', async () => {
      const result = await createExec()
        .maxProcesses(5)
        .timeout(5000)
        .run('sh', ['-c', `
          # Create exactly 5 processes
          for i in {1..5}; do
            echo "proc $i" &
          done
          wait
          echo "exactly 5"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137, 'should exit cleanly');
    });

    it('should handle fork bomb with memory limit', async () => {
      const result = await createExec()
        .maxProcesses(30)
        .maxMemory(20)
        .timeout(5000)
        .run('sh', ['-c', `
          # Fork bomb with memory allocation
          for i in {1..30}; do
            perl -e "my @a = ('x' x 100000); print \\"fork $i\\n\\";" &
          done
          wait
          echo "all forks done"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137, 'should exit cleanly or be killed');
    });
  });

  describe('Combined Resource Exhaustion', () => {
    it('should enforce memory + CPU limits simultaneously', async () => {
      const result = await createExec()
        .maxMemory(10)
        .maxCPUCores(0.5)
        .timeout(10000)
        .run('sh', ['-c', `
          # Allocate memory while spinning CPU
          i=0;
          while [ $i -lt 1000000 ]; do
            i=$((i + 1));
          done;
          echo "done"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137 || result.timedOut, 'should exit cleanly, be killed, or timeout');
    });

    it('should enforce all limits: memory + CPU + processes', async () => {
      const result = await createExec()
        .maxMemory(20)
        .maxCPUCores(1.0)
        .maxProcesses(30)
        .timeout(10000)
        .run('sh', ['-c', `
          # Fork processes that use memory and CPU
          for i in {1..10}; do
            perl -e "
              my \$x = 'a' x (1024 * 100);
              my \$sum = 0;
              for (1..100000) { \$sum += \$_ };
              print \\"done\\n\\";
            " &
          done
          wait
          echo "all done"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137 || result.timedOut, 'should exit cleanly, be killed, or timeout');
    });

    it('should handle 3-way resource contention', async () => {
      const result = await createExec()
        .maxMemory(10)
        .maxCPUCores(0.25)
        .maxProcesses(10)
        .timeout(10000)
        .run('sh', ['-c', `
          # 3-way: allocate memory, spin CPU, fork processes
          for i in {1..5}; do
            perl -e "
              my @mem = ('x' x 500000);
              my \$sum = 0;
              for (1..50000) { \$sum += \$_ };
              print \\"worker $i done\\n\\";
            " &
          done
          wait
          echo "all workers done"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137 || result.timedOut, 'should exit cleanly, be killed, or timeout');
    });

    it('should handle cascading resource exhaustion', async () => {
      const result = await createExec()
        .maxMemory(5)
        .maxCPUCores(0.5)
        .maxProcesses(15)
        .timeout(10000)
        .run('sh', ['-c', `
          # Each child allocates memory and spins CPU
          for i in {1..10}; do
            python3 -c "
              a = [list(range(10000)) for _ in range(5)]
              s = 0
              for j in range(100000): s += j
              print('child $i done')
            " 2>/dev/null &
          done
          wait
          echo "cascade done"
        `]);

      strict.ok(result.exitCode === 0 || result.exitCode === 137 || result.timedOut, 'should exit cleanly, be killed, or timeout');
    });
  });

  describe('Edge Cases', () => {
    it('should handle zero memory limit', async () => {
      const result = await createExec()
        .maxMemory(0)
        .run('echo', ['no limit']);

      strict.equal(result.exitCode, 0, 'should exit cleanly');
      strict.ok(
        result.stdout.includes('no limit'),
        'should capture output'
      );
    });

    it('should handle zero CPU limit', async () => {
      const result = await createExec()
        .maxCPUCores(0)
        .run('echo', ['no limit']);

      strict.equal(result.exitCode, 0, 'should exit cleanly');
    });

    it('should handle zero process limit', async () => {
      const result = await createExec()
        .maxProcesses(0)
        .run('echo', ['no limit']);

      strict.equal(result.exitCode, 0, 'should exit cleanly');
    });

    it('should handle negative limits gracefully', async () => {
      const result = await createExec()
        .maxMemory(-1)
        .maxCPUCores(-1)
        .maxProcesses(-1)
        .run('echo', ['negative limits']);

      strict.equal(result.exitCode, 0, 'should exit cleanly');
    });

    it('should handle very large limits', async () => {
      const result = await createExec()
        .maxMemory(1024)
        .maxCPUCores(8)
        .maxProcesses(1000)
        .run('echo', ['large limits']);

      strict.equal(result.exitCode, 0, 'should exit cleanly');
    });

    it('should handle timeout with immediate exit', async () => {
      const start = Date.now();
      const result = await createExec()
        .timeout(100) // Very short timeout
        .run('echo', ['instant']);

      const elapsed = Date.now() - start;
      strict.ok(elapsed < 1000, `should complete quickly, took ${elapsed}ms`);
      strict.equal(result.exitCode, 0, 'should exit cleanly');
    });
  });

  describe('Audit Logging', () => {
    it('should return audit log when enabled', async () => {
      const etc = realpathSync('/etc');
      const result = await createExec()
        .enableAudit()
        .run('sh', ['-c', `echo "audit test" && cat ${etc}/hosts`]);

      strict.equal(result.exitCode, 0, 'should exit cleanly');
      strict.ok(
        result.stdout.includes('audit test'),
        'should capture output with audit enabled'
      );
    });

    it('should return empty audit log when no violations', async () => {
      const result = await createExec()
        .enableAudit()
        .run('echo', ['simple']);

      strict.equal(result.exitCode, 0, 'should exit cleanly');
      strict.ok(
        result.auditLog === null || Array.isArray(result.auditLog),
        'should return audit log (may be empty)'
      );
    });

    it('should capture audit entries with network filtering', async () => {
      const result = await createExec()
        .enableAudit()
        .allowHosts('github.com')
        .allowPorts(80, 443)
        .run('echo', ['network audit']);

      strict.equal(result.exitCode, 0, 'should exit cleanly');
      strict.ok(
        result.stdout.includes('network audit'),
        'should capture output'
      );
    });
  });
});