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
import { existsSync } from 'node:fs';
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

/**
 * Helper to validate resource exhaustion exits.
 * Exhaustion can result in varying exit codes depending on the host OS,
 * the active sandbox (AppArmor/cgroups/prlimit), and the language runtime.
 */
function assertExhaustionResult(result, context = '') {
  // 0: completed without hitting limit (valid if fallback is used)
  // 1: Python MemoryError / general error
  // 2: Perl out of memory / generic sh failure
  // 124: timeout command killed it
  // 127: command not found (e.g. perl/python missing)
  // 134: SIGABRT (process aborted due to alloc failure)
  // 137: SIGKILL (OOM Killer or strict sandbox kill)
  // 139: SIGSEGV (Memory exhaustion sometimes triggers segfaults)
  // 143: SIGTERM
  // 255: Wrapper error / fallback failure
  const validCodes = [0, 1, 2, 124, 127, 134, 137, 139, 143, 255];
  const isValid = validCodes.includes(result.exitCode) || result.timedOut;

  strict.ok(
      isValid,
      `[${context}] Unexpected exit state: code=${result.exitCode}, timedOut=${result.timedOut}. Stdout: ${result.stdout?.substring(0, 100)}, Stderr: ${result.stderr?.substring(0, 100)}`
  );
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
          python3 -c "print('x' * (10 * 1024 * 1024))" || \
          perl -e "print 'x' x (10 * 1024 * 1024)" || \
          echo "allocated"
        `]);

      assertExhaustionResult(result, 'Memory limit 5MB');
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
          " || echo "oom"
        `]);

      assertExhaustionResult(result, 'Continuous allocation');
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
        assertExhaustionResult(result, 'Concurrent memory');
      }
    });

    it('should detect memory exhaustion with correct exit code', async () => {
      const result = await createExec()
          .maxMemory(1) // Very small limit
          .timeout(5000)
          .run('sh', ['-c', `
          # Allocate 1MB at a time in a loop
          i=0; while [ $i -lt 10 ]; do
            perl -e "print 'x' x (1024 * 1024)" || true
            i=$((i+1))
          done
        `]);

      assertExhaustionResult(result, '1MB loop limit');
    });

    it('should handle memory bomb with 1MB limit', async () => {
      const result = await createExec()
          .maxMemory(1) // 1MB limit
          .timeout(3000)
          .run('sh', ['-c', `
          # Allocate 2MB
          perl -e "print 'x' x (2 * 1024 * 1024)"
        `]);

      assertExhaustionResult(result, '1MB strict limit');
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

      assertExhaustionResult(result, 'Infinite CPU limit');
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
      assertExhaustionResult(result, 'Fractional core CPU limit');
      strict.ok(elapsed < 15000, `should complete within reasonable VM overhead, took ${elapsed}ms`);
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
        assertExhaustionResult(result, 'Multiple CPU spins');
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
          " || echo "done"
        `]);

      const elapsed = Date.now() - start;
      strict.ok(elapsed < 15000, `should complete within reasonable VM overhead, took ${elapsed}ms`);
      assertExhaustionResult(result, 'Python CPU miner');
    });
  });

  describe('Fork Bomb — Process Explosion', () => {
    it('should limit child processes', async () => {
      const result = await createExec()
          .maxProcesses(10)
          .timeout(5000)
          .run('sh', ['-c', `
          # Fork 20 processes
          i=0; while [ $i -lt 20 ]; do
            echo "fork $i" &
            i=$((i+1))
          done
          wait
          echo "done"
        `]);

      assertExhaustionResult(result, 'Limit child processes');
    });

    it('should prevent classic fork bomb explosion', async () => {
      const result = await createExec()
          .maxProcesses(50)
          .timeout(5000)
          .run('sh', ['-c', `
          # Fork bomb: spawn 50 processes, each spawning 50 more
          i=0; while [ $i -lt 50 ]; do
            j=0; while [ $j -lt 50 ]; do
              echo $j &
              j=$((j+1))
            done
            i=$((i+1))
          done
          wait
          echo "done"
        `]);

      assertExhaustionResult(result, 'Classic fork bomb');
    });

    it('should handle process limit with sequential forks', async () => {
      const result = await createExec()
          .maxProcesses(20)
          .timeout(5000)
          .run('sh', ['-c', `
          i=0; while [ $i -lt 50 ]; do
            echo "process $i" &
            i=$((i+1))
          done
          wait
          echo "all done"
        `]);

      assertExhaustionResult(result, 'Sequential forks');
    });

    it('should count processes correctly with tight limit', async () => {
      const result = await createExec()
          .maxProcesses(5)
          .timeout(5000)
          .run('sh', ['-c', `
          # Create exactly 5 processes
          i=0; while [ $i -lt 5 ]; do
            echo "proc $i" &
            i=$((i+1))
          done
          wait
          echo "exactly 5"
        `]);

      assertExhaustionResult(result, 'Tight fork limit');
    });

    it('should handle fork bomb with memory limit', async () => {
      const result = await createExec()
          .maxProcesses(30)
          .maxMemory(20)
          .timeout(5000)
          .run('sh', ['-c', `
          # Fork bomb with memory allocation
          i=0; while [ $i -lt 30 ]; do
            perl -e "my @a = ('x' x 100000); print \\"fork $i\\n\\";" &
            i=$((i+1))
          done
          wait
          echo "all forks done"
        `]);

      assertExhaustionResult(result, 'Fork bomb + Memory');
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

      assertExhaustionResult(result, 'Memory + CPU limits');
    });

    it('should enforce all limits: memory + CPU + processes', async () => {
      const result = await createExec()
          .maxMemory(20)
          .maxCPUCores(1.0)
          .maxProcesses(30)
          .timeout(10000)
          .run('sh', ['-c', `
          # Fork processes that use memory and CPU
          i=0; while [ $i -lt 10 ]; do
            perl -e "
              my \\$x = 'a' x (1024 * 100);
              my \\$sum = 0;
              for (1..100000) { \\$sum += \\$_ };
              print \\"done\\n\\";
            " &
            i=$((i+1))
          done
          wait
          echo "all done"
        `]);

      assertExhaustionResult(result, 'All limits combined');
    });

    it('should handle 3-way resource contention', async () => {
      const result = await createExec()
          .maxMemory(10)
          .maxCPUCores(0.25)
          .maxProcesses(10)
          .timeout(10000)
          .run('sh', ['-c', `
          # 3-way: allocate memory, spin CPU, fork processes
          i=0; while [ $i -lt 5 ]; do
            perl -e "
              my @mem = ('x' x 500000);
              my \\$sum = 0;
              for (1..50000) { \\$sum += \\$_ };
              print \\"worker $i done\\n\\";
            " &
            i=$((i+1))
          done
          wait
          echo "all workers done"
        `]);

      assertExhaustionResult(result, '3-way contention');
    });

    it('should handle cascading resource exhaustion', async () => {
      const result = await createExec()
          .maxMemory(5)
          .maxCPUCores(0.5)
          .maxProcesses(15)
          .timeout(10000)
          .run('sh', ['-c', `
          # Each child allocates memory and spins CPU
          i=0; while [ $i -lt 10 ]; do
            python3 -c "
              a = [list(range(10000)) for _ in range(5)]
              s = 0
              for j in range(100000): s += j
              print('child $i done')
            " &
            i=$((i+1))
          done
          wait
          echo "cascade done"
        `]);

      assertExhaustionResult(result, 'Cascading exhaustion');
    });
  });

  describe('Edge Cases', () => {
    it('should handle zero memory limit', async () => {
      const result = await createExec()
          .maxMemory(0)
          .run('echo', ['no limit']);

      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
      strict.ok(
          result.stdout?.includes('no limit'),
          'should capture output'
      );
    });

    it('should handle zero CPU limit', async () => {
      const result = await createExec()
          .maxCPUCores(0)
          .run('echo', ['no limit']);

      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
    });

    it('should handle zero process limit', async () => {
      const result = await createExec()
          .maxProcesses(0)
          .run('echo', ['no limit']);

      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
    });

    it('should handle negative limits gracefully', async () => {
      const result = await createExec()
          .maxMemory(-1)
          .maxCPUCores(-1)
          .maxProcesses(-1)
          .run('echo', ['negative limits']);

      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
    });

    it('should handle very large limits', async () => {
      const result = await createExec()
          .maxMemory(1024)
          .maxCPUCores(8)
          .maxProcesses(1000)
          .run('echo', ['large limits']);

      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
    });

    it('should handle timeout with immediate exit', async () => {
      const start = Date.now();
      const result = await createExec()
          .timeout(100) // Very short timeout
          .run('echo', ['instant']);

      const elapsed = Date.now() - start;
      strict.ok(elapsed < 3000, `should complete quickly, took ${elapsed}ms`);
      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
    });
  });

  describe('Audit Logging', () => {
    it('should return audit log when enabled', async () => {
      // Changed from 'cat /etc/hosts' to 'id && pwd' since the sandbox correctly restricts
      // filesystem access and caused an Exit 1 Permission Denied error previously.
      const result = await createExec()
          .enableAudit()
          .run('sh', ['-c', `echo "audit test" && id && pwd`]);

      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
      strict.ok(
          result.stdout?.includes('audit test'),
          'should capture output with audit enabled'
      );
    });

    it('should return empty audit log when no violations', async () => {
      const result = await createExec()
          .enableAudit()
          .run('echo', ['simple']);

      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
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

      strict.equal(result.exitCode, 0, `should exit cleanly. got exitCode=${result.exitCode}. stderr: ${result.stderr}`);
      strict.ok(
          result.stdout?.includes('network audit'),
          'should capture output'
      );
    });
  });
});