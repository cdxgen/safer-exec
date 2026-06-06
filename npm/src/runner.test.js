/**
 * Unit tests for the runner module (runner.js).
 *
 * @module runner_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { dirname } from 'node:path';
import { resolveBinaryPath, run } from './runner.js';

const baseReadPaths = process.platform === 'darwin'
  ? ['/bin', '/usr', '/System', '/dev', '/private', dirname(process.execPath)]
  : ['/bin', '/usr', '/lib', '/lib64', dirname(process.execPath)];

function createConfig(overrides) {
  return {
    env: {},
    readPaths: baseReadPaths,
    writePaths: [],
    allowHosts: [],
    allowIPs: [],
    disableNetwork: false,
    maxMemoryMB: 0,
    workingDir: '',
    ...overrides
  };
}

describe('run', () => {
  it('should execute a simple echo command', async () => {
    const result = await run(createConfig({ cmd: 'echo', args: ['hello from test'] }));
    strict.equal(result.exitCode, 0, `should exit with code 0. STDERR: ${result.stderr}`);
    strict.ok(result.stdout.includes('hello from test'));
  });

  it('should capture stderr', async () => {
    const result = await run(createConfig({ cmd: 'sh', args: ['-c', 'echo "stderr message" >&2'] }));
    strict.equal(result.exitCode, 0);
    strict.ok(result.stderr.includes('stderr message'));
  });

  it('should return non-zero exit code for failing command', async () => {
    const result = await run(createConfig({ cmd: 'sh', args: ['-c', 'exit 42'] }));
    strict.equal(result.exitCode, 42);
  });

  it('should pass environment variables', async () => {
    const result = await run(createConfig({ cmd: 'sh', args: ['-c', 'echo $TEST_VAR'], env: { TEST_VAR: 'sandboxed_value' } }));
    strict.equal(result.exitCode, 0);
    strict.ok(result.stdout.includes('sandboxed_value'));
  });
});