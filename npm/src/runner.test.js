/**
 * Unit tests for the runner module (runner.js).
 *
 * Tests binary path resolution and command execution.
 *
 * @module runner_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { resolveBinaryPath, run } from './runner.js';

describe('resolveBinaryPath', () => {
  it('should return a non-empty string', () => {
    const path = resolveBinaryPath();
    strict.ok(path.length > 0, 'should return a path');
  });

  it('should return a valid path format', () => {
    const path = resolveBinaryPath();
    // Should either be an absolute path or a command name
    strict.ok(
      path.startsWith('/') || /^[a-z0-9_-]+$/i.test(path),
      `path should be absolute or a command name: ${path}`
    );
  });
});

describe('run', () => {
  it('should execute a simple echo command', async () => {
    const result = await run({
      cmd: 'echo',
      args: ['hello from test'],
      env: {},
      readPaths: [],
      writePaths: [],
      allowHosts: [],
      allowIPs: [],
      disableNetwork: false,
      maxMemoryMB: 0,
      workingDir: '',
    });

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(
      result.stdout.includes('hello from test'),
      'stdout should contain the echo text'
    );
  });

  it('should capture stderr', async () => {
    const result = await run({
      cmd: 'sh',
      args: ['-c', 'echo "stderr message" >&2'],
      env: {},
      readPaths: [],
      writePaths: [],
      allowHosts: [],
      allowIPs: [],
      disableNetwork: false,
      maxMemoryMB: 0,
      workingDir: '',
    });

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(
      result.stderr.includes('stderr message'),
      'stderr should contain the error message'
    );
  });

  it('should return non-zero exit code for failing command', async () => {
    const result = await run({
      cmd: 'sh',
      args: ['-c', 'exit 42'],
      env: {},
      readPaths: [],
      writePaths: [],
      allowHosts: [],
      allowIPs: [],
      disableNetwork: false,
      maxMemoryMB: 0,
      workingDir: '',
    });

    strict.equal(result.exitCode, 42, 'should exit with code 42');
  });

  it('should pass environment variables', async () => {
    const result = await run({
      cmd: 'sh',
      args: ['-c', 'echo $TEST_VAR'],
      env: { TEST_VAR: 'sandboxed_value' },
      readPaths: [],
      writePaths: [],
      allowHosts: [],
      allowIPs: [],
      disableNetwork: false,
      maxMemoryMB: 0,
      workingDir: '',
    });

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(
      result.stdout.includes('sandboxed_value'),
      'should have access to environment variable'
    );
  });
});
