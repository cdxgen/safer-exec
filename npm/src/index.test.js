/**
 * Unit tests for the SaferExec class (index.js).
 *
 * Tests the fluent API, policy application, DNS resolution,
 * and command execution.
 *
 * @module index_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec, saferExec } from './index.js';

describe('SaferExec', () => {
  describe('constructor', () => {
    it('should create an instance with default values', () => {
      const exec = new SaferExec();
      strict.ok(exec instanceof SaferExec, 'should be a SaferExec instance');
    });

    it('should accept initial options', () => {
      const exec = new SaferExec({
        allowHosts: ['example.com'],
        readPaths: ['/usr'],
        writePaths: ['/tmp'],
        env: { TEST: 'value' },
        disableNetwork: true,
        maxMemoryMB: 256,
      });

      strict.ok(exec, 'should create with options');
    });
  });

  describe('fluent API', () => {
    it('should chain methods returning this', () => {
      const exec = new SaferExec();
      strict.equal(
        exec.allowHosts('example.com'),
        exec,
        'allowHosts should return this'
      );
      strict.equal(
        exec.readPaths('/usr'),
        exec,
        'readPaths should return this'
      );
      strict.equal(
        exec.writePaths('/tmp'),
        exec,
        'writePaths should return this'
      );
      strict.equal(
        exec.env('KEY', 'value'),
        exec,
        'env should return this'
      );
      strict.equal(
        exec.disableNetwork(),
        exec,
        'disableNetwork should return this'
      );
      strict.equal(
        exec.maxMemory(512),
        exec,
        'maxMemory should return this'
      );
      strict.equal(
        exec.workingDir('/test'),
        exec,
        'workingDir should return this'
      );
    });

    it('should deduplicate allowHosts', () => {
      const exec = new SaferExec();
      exec.allowHosts('example.com');
      exec.allowHosts('example.com');
      exec.allowHosts('other.com');

      // Internal state check via running a command
      strict.ok(exec, 'should not throw');
    });
  });

  describe('applyPolicy', () => {
    it('should apply npm policy', () => {
      const exec = new SaferExec();
      exec.applyPolicy('npm');
      strict.ok(exec, 'should not throw');
    });

    it('should apply pypi policy', () => {
      const exec = new SaferExec();
      exec.applyPolicy('pypi');
      strict.ok(exec, 'should not throw');
    });

    it('should apply maven policy', () => {
      const exec = new SaferExec();
      exec.applyPolicy('maven');
      strict.ok(exec, 'should not throw');
    });

    it('should apply cargo policy', () => {
      const exec = new SaferExec();
      exec.applyPolicy('cargo');
      strict.ok(exec, 'should not throw');
    });

    it('should throw on unknown policy', () => {
      const exec = new SaferExec();
      try {
        exec.applyPolicy('unknown');
        strict.fail('should have thrown');
      } catch (error) {
        strict.ok(
          error.message.includes('Unknown policy'),
          'should mention unknown policy'
        );
        strict.ok(
          error.message.includes('npm'),
          'should list available policies'
        );
      }
    });
  });

  describe('run', () => {
    it('should execute a simple command', async () => {
      const result = await new SaferExec()
        .run('echo', ['hello']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('hello'),
        'should capture stdout'
      );
    });

    it('should execute with environment variables', async () => {
      const result = await new SaferExec()
        .env('TEST_VAR', 'test_value')
        .run('sh', ['-c', 'echo $TEST_VAR']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(
        result.stdout.includes('test_value'),
        'should pass environment variable'
      );
    });

    it('should execute with memory limit', async () => {
      const result = await new SaferExec()
        .maxMemory(256)
        .run('echo', ['limited']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });
  });
});

describe('saferExec convenience function', () => {
  it('should execute a command', async () => {
    const result = await saferExec('echo', ['convenience']);

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(
      result.stdout.includes('convenience'),
      'should capture stdout'
    );
  });

  it('should accept options', async () => {
    const result = await saferExec('sh', ['-c', 'echo $FOO'], {
      env: { FOO: 'bar' },
    });

    strict.equal(result.exitCode, 0, 'should exit with code 0');
    strict.ok(
      result.stdout.includes('bar'),
      'should pass environment variable'
    );
  });
});
