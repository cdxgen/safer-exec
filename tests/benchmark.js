/**
 * Performance benchmarks for SaferExec.
 *
 * Measures:
 * - Cold start overhead (first execution)
 * - Warm start overhead (subsequent executions)
 * - DNS resolution time
 * - Policy application time
 * - Comparison with standard child_process.exec
 *
 * Goal: < 30ms overhead per execution compared to standard child_process.exec.
 *
 * @module benchmark
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import { SaferExec } from '../npm/src/index.js';

const execAsync = promisify(exec);

/**
 * Run a benchmark and return the average time in ms.
 *
 * @param {string} name - Benchmark name
 * @param {Function} fn - Async function to benchmark
 * @param {number} iterations - Number of iterations
 * @returns {Promise<{name: string, avgMs: number, minMs: number, maxMs: number}>}
 */
async function benchmark(name, fn, iterations = 5) {
  const times = [];

  for (let i = 0; i < iterations; i++) {
    const start = process.hrtime.bigint();
    await fn();
    const end = process.hrtime.bigint();
    const ms = Number(end - start) / 1_000_000;
    times.push(ms);
  }

  const avg = times.reduce((a, b) => a + b, 0) / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);

  const result = { name, avgMs: avg, minMs: min, maxMs: max };
  console.log(`${name}: avg=${avg.toFixed(2)}ms min=${min.toFixed(2)}ms max=${max.toFixed(2)}ms`);
  return result;
}

/**
 * Main benchmark runner.
 */
async function runBenchmarks() {
  console.log('=== SaferExec Performance Benchmarks ===\n');

  // 1. Standard child_process.exec baseline
  const baseline = await benchmark(
    'child_process.exec (baseline)',
    async () => {
      await execAsync('echo benchmark');
    },
    10
  );

  // 2. SaferExec cold start (first execution)
  const coldStart = await benchmark(
    'SaferExec cold start',
    async () => {
      await new SaferExec().run('echo', ['benchmark']);
    },
    5
  );

  // 3. SaferExec warm start (subsequent executions)
  const warmStart = await benchmark(
    'SaferExec warm start',
    async () => {
      await new SaferExec().run('echo', ['benchmark']);
    },
    10
  );

  // 4. SaferExec with policy
  const withPolicy = await benchmark(
    'SaferExec with npm policy',
    async () => {
      await new SaferExec().applyPolicy('npm').run('echo', ['benchmark']);
    },
    5
  );

  // 5. SaferExec with DNS resolution
  const withDns = await benchmark(
    'SaferExec with DNS resolution',
    async () => {
      await new SaferExec()
        .allowHosts('github.com', 'google.com')
        .run('echo', ['benchmark']);
    },
    5
  );

  // 6. SaferExec with memory limit
  const withMemory = await benchmark(
    'SaferExec with memory limit',
    async () => {
      await new SaferExec().maxMemory(256).run('echo', ['benchmark']);
    },
    5
  );

  // 7. SaferExec with environment variables
  const withEnv = await benchmark(
    'SaferExec with env vars',
    async () => {
      await new SaferExec()
        .env('TEST_VAR', 'value')
        .run('sh', ['-c', 'echo $TEST_VAR']);
    },
    5
  );

  // Summary
  console.log('\n=== Summary ===');
  console.log(`Baseline: ${baseline.avgMs.toFixed(2)}ms`);
  console.log(`SaferExec overhead (warm): ${(warmStart.avgMs - baseline.avgMs).toFixed(2)}ms`);
  console.log(`Target: < 30ms overhead`);

  const overhead = warmStart.avgMs - baseline.avgMs;
  if (overhead < 30) {
    console.log(`✅ PASS: Overhead is within target (${overhead.toFixed(2)}ms < 30ms)`);
  } else {
    console.log(`⚠️  WARN: Overhead exceeds target (${overhead.toFixed(2)}ms >= 30ms)`);
  }

  // Return results for programmatic access
  return {
    baseline,
    coldStart,
    warmStart,
    withPolicy,
    withDns,
    withMemory,
    withEnv,
    overhead,
    pass: overhead < 30,
  };
}

// Run benchmarks if executed directly
const results = await runBenchmarks();
process.exit(results.pass ? 0 : 1);
