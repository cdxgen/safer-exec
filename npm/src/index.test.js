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
import { tmpdir } from 'node:os';
import { realpathSync } from 'node:fs';

describe('SaferExec', () => {
  describe('constructor', () => {
    it('should create an instance with default values', () => {
      const exec = new SaferExec();
      strict.ok(exec instanceof SaferExec, 'should be a SaferExec instance');
    });

    it('should initialize all internal fields to defaults', () => {
      const exec = new SaferExec();
      strict.deepEqual(exec._allowHosts, [], 'allowHosts should be empty');
      strict.deepEqual(exec._readPaths, [], 'readPaths should be empty');
      strict.deepEqual(exec._writePaths, [], 'writePaths should be empty');
      strict.deepEqual(exec._env, {}, 'env should be empty object');
      strict.equal(exec._disableNetwork, false, 'disableNetwork should be false');
      strict.equal(exec._maxMemoryMB, 0, 'maxMemoryMB should be 0');
      strict.equal(exec._maxCPUCores, 0, 'maxCPUCores should be 0');
      strict.equal(exec._maxProcesses, 0, 'maxProcesses should be 0');
      strict.equal(exec._timeoutMs, 0, 'timeoutMs should be 0');
      strict.equal(exec._workingDir, process.cwd(), 'workingDir should be cwd');
      strict.equal(exec._binaryPath, undefined, 'binaryPath should be undefined');
      strict.deepEqual(exec._allowIPs, [], 'allowIPs should be empty');
      strict.equal(exec._enableAudit, false, 'enableAudit should be false');
      strict.deepEqual(exec._allowPorts, [], 'allowPorts should be empty');
      strict.equal(exec._enableDiff, false, 'enableDiff should be false');
      strict.equal(exec._enableLearn, false, 'enableLearn should be false');
      strict.deepEqual(exec._allowExec, [], 'allowExec should be empty');
      strict.deepEqual(exec._blockExec, [], 'blockExec should be empty');
      strict.equal(exec._blockFork, false, 'blockFork should be false');
      strict.equal(exec._traceExec, false, 'traceExec should be false');
    });

    it('should accept initial options', () => {
      const exec = new SaferExec({
        allowHosts: ['example.com'],
        readPaths: ['/usr'],
        writePaths: [tmpdir()],
        env: { TEST: 'value' },
        disableNetwork: true,
        maxMemoryMB: 256,
        maxCPUCores: 0.5,
        maxProcesses: 10,
        timeoutMs: 5000,
        enableAudit: true,
        allowPorts: [80, 443],
        enableDiff: true,
        enableLearn: true,
        allowExec: ['node'],
        blockExec: ['sh'],
        blockFork: true,
        traceExec: true,
      });

      strict.deepEqual(exec._allowHosts, ['example.com']);
      strict.deepEqual(exec._readPaths, ['/usr']);
      strict.deepEqual(exec._writePaths, [tmpdir()]);
      strict.deepEqual(exec._env, { TEST: 'value' });
      strict.equal(exec._disableNetwork, true);
      strict.equal(exec._maxMemoryMB, 256);
      strict.equal(exec._maxCPUCores, 0.5);
      strict.equal(exec._maxProcesses, 10);
      strict.equal(exec._timeoutMs, 5000);
      strict.equal(exec._enableAudit, true);
      strict.deepEqual(exec._allowPorts, [80, 443]);
      strict.equal(exec._enableDiff, true);
      strict.equal(exec._enableLearn, true);
      strict.deepEqual(exec._allowExec, ['node']);
      strict.deepEqual(exec._blockExec, ['sh']);
      strict.equal(exec._blockFork, true);
      strict.equal(exec._traceExec, true);
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
        exec.writePaths(tmpdir()),
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

    it('should chain all methods in a single expression', () => {
      const exec = new SaferExec();
      const result = exec
        .allowHosts('example.com')
        .readPaths('/usr')
        .writePaths(tmpdir())
        .env('KEY', 'value')
        .disableNetwork()
        .maxMemory(512)
        .maxCPUCores(1.0)
        .maxProcesses(10)
        .timeout(5000)
        .binaryPath('/usr/bin/test')
        .workingDir('/test')
        .enableAudit()
        .allowPorts(80, 443)
        .enableDiff()
        .enableLearn()
        .allowExec('node', 'npx')
        .blockExec('sh')
        .blockFork()
        .traceExec();

      strict.equal(result, exec, 'all methods should return the same instance');
    });

    it('should deduplicate allowHosts', () => {
      const exec = new SaferExec();
      exec.allowHosts('example.com');
      exec.allowHosts('example.com');
      exec.allowHosts('other.com');
      exec.allowHosts('example.com');

      strict.deepEqual(
        exec._allowHosts,
        ['example.com', 'other.com'],
        'should deduplicate hosts'
      );
      strict.equal(exec._allowHosts.length, 2, 'should have exactly 2 hosts');
    });

    it('should deduplicate readPaths', () => {
      const exec = new SaferExec();
      const etc = realpathSync('/etc');
      exec.readPaths('/usr', etc);
      exec.readPaths('/usr');
      exec.readPaths('/var');

      strict.deepEqual(
        exec._readPaths,
        ['/usr', etc, '/var'],
        'should deduplicate read paths'
      );
    });

    it('should deduplicate writePaths', () => {
      const exec = new SaferExec();
      const tmp = tmpdir();
      exec.writePaths(tmp, '/var');
      exec.writePaths(tmp);

      strict.deepEqual(
        exec._writePaths,
        [tmp, '/var'],
        'should deduplicate write paths'
      );
    });

    it('should deduplicate allowPorts', () => {
      const exec = new SaferExec();
      exec.allowPorts(80, 443);
      exec.allowPorts(80);

      strict.deepEqual(
        exec._allowPorts,
        [80, 443],
        'should deduplicate ports'
      );
    });

    it('should deduplicate allowExec', () => {
      const exec = new SaferExec();
      exec.allowExec('node', 'npx');
      exec.allowExec('node');

      strict.deepEqual(
        exec._allowExec,
        ['node', 'npx'],
        'should deduplicate allowExec'
      );
    });

    it('should deduplicate blockExec', () => {
      const exec = new SaferExec();
      exec.blockExec('sh', 'bash');
      exec.blockExec('sh');

      strict.deepEqual(
        exec._blockExec,
        ['sh', 'bash'],
        'should deduplicate blockExec'
      );
    });

    it('should accept multiple hosts in a single allowHosts call', () => {
      const exec = new SaferExec();
      exec.allowHosts('a.com', 'b.com', 'c.com');

      strict.deepEqual(
        exec._allowHosts,
        ['a.com', 'b.com', 'c.com'],
        'should accept multiple hosts'
      );
    });

    it('should accept multiple paths in a single readPaths call', () => {
      const exec = new SaferExec();
      const etc = realpathSync('/etc');
      exec.readPaths('/usr', etc, '/var');

      strict.deepEqual(
        exec._readPaths,
        ['/usr', etc, '/var'],
        'should accept multiple paths'
      );
    });

    it('should set env vars individually and accumulate', () => {
      const exec = new SaferExec();
      exec.env('A', '1');
      exec.env('B', '2');
      exec.env('A', '3'); // override

      strict.deepEqual(exec._env, { A: '3', B: '2' }, 'env should accumulate and override');
    });

    it('blockFork should be idempotent', () => {
      const exec = new SaferExec();
      exec.blockFork();
      exec.blockFork();
      strict.equal(exec._blockFork, true);
    });

    it('traceExec should be idempotent', () => {
      const exec = new SaferExec();
      exec.traceExec();
      exec.traceExec();
      strict.equal(exec._traceExec, true);
    });

    it('enableAudit should be idempotent', () => {
      const exec = new SaferExec();
      exec.enableAudit();
      exec.enableAudit();
      strict.equal(exec._enableAudit, true);
    });

    it('enableDiff should be idempotent', () => {
      const exec = new SaferExec();
      exec.enableDiff();
      exec.enableDiff();
      strict.equal(exec._enableDiff, true);
    });

    it('enableLearn should be idempotent', () => {
      const exec = new SaferExec();
      exec.enableLearn();
      exec.enableLearn();
      strict.equal(exec._enableLearn, true);
    });
  });

  describe('applyPolicy', () => {
    it('should apply npm policy', () => {
      const exec = new SaferExec();
      exec.applyPolicy('npm');
      strict.ok(exec._allowHosts.length > 0, 'should have hosts');
      strict.ok(exec._readPaths.length > 0, 'should have readPaths');
      strict.ok(exec._writePaths.length > 0, 'should have writePaths');
    });

    it('should apply npm policy and populate expected hosts', () => {
      const exec = new SaferExec();
      exec.applyPolicy('npm');

      strict.ok(
        exec._allowHosts.includes('registry.npmjs.org'),
        'should include npm registry'
      );
      strict.ok(
        exec._allowHosts.includes('registry.yarnpkg.com'),
        'should include yarn registry'
      );
    });

    it('should apply pypi policy', () => {
      const exec = new SaferExec();
      exec.applyPolicy('pypi');
      strict.ok(exec._allowHosts.length > 0, 'should have hosts');
      strict.ok(exec._readPaths.length > 0, 'should have readPaths');
    });

    it('should apply maven policy', () => {
      const exec = new SaferExec();
      exec.applyPolicy('maven');
      strict.ok(exec._allowHosts.length > 0, 'should have hosts');
      strict.ok(exec._readPaths.length > 0, 'should have readPaths');
    });

    it('should apply cargo policy', () => {
      const exec = new SaferExec();
      exec.applyPolicy('cargo');
      strict.ok(exec._allowHosts.length > 0, 'should have hosts');
      strict.ok(exec._readPaths.length > 0, 'should have readPaths');
    });

    it('should apply all 11 policies without error', () => {
      const policies = [
        'npm', 'yarn', 'pnpm', 'pypi', 'maven',
        'cargo', 'rubygems', 'composer', 'deno', 'gomod', 'bun'
      ];
      for (const policy of policies) {
        const exec = new SaferExec();
        exec.applyPolicy(policy);
        strict.ok(exec._allowHosts.length > 0, `${policy} should have hosts`);
      }
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

    it('should merge policy with existing user settings (user settings preserved)', () => {
      const exec = new SaferExec();
      exec.allowHosts('custom.registry.com');
      exec.readPaths('/custom/path');
      exec.applyPolicy('npm');

      strict.ok(
        exec._allowHosts.includes('custom.registry.com'),
        'should keep user-defined hosts'
      );
      strict.ok(
        exec._allowHosts.includes('registry.npmjs.org'),
        'should add policy hosts'
      );
      strict.ok(
        exec._readPaths.includes('/custom/path'),
        'should keep user-defined readPaths'
      );
    });

    it('should merge env vars with user env taking precedence', () => {
      const exec = new SaferExec();
      exec.env('npm_config_loglevel', 'debug');
      exec.applyPolicy('npm');

      strict.equal(
        exec._env.npm_config_loglevel,
        'debug',
        'user env should override policy env'
      );
    });

    it('should merge multiple policies cumulatively', () => {
      const exec = new SaferExec();
      exec.applyPolicy('npm');
      const npmHosts = exec._allowHosts.length;

      exec.applyPolicy('pypi');
      strict.ok(
        exec._allowHosts.length >= npmHosts,
        'should have at least as many hosts after second policy'
      );
      strict.ok(
        exec._allowHosts.includes('registry.npmjs.org'),
        'should still have npm hosts'
      );
      strict.ok(
        exec._allowHosts.includes('pypi.org'),
        'should have pypi hosts'
      );
    });

    it('should apply npm blockFork setting', () => {
      const exec = new SaferExec();
      exec.applyPolicy('npm');
      strict.equal(exec._blockFork, true, 'npm policy should set blockFork');
    });

    it('should apply npm blockExec setting', () => {
      const exec = new SaferExec();
      exec.applyPolicy('npm');
      strict.ok(exec._blockExec.length > 0, 'npm policy should set blockExec');
    });

    it('should return this for chaining after applyPolicy', () => {
      const exec = new SaferExec();
      const result = exec.applyPolicy('npm');
      strict.equal(result, exec, 'applyPolicy should return this');
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

    it('should resolve hostnames before execution', async () => {
      const exec = new SaferExec();
      exec.allowHosts('github.com', 'google.com');
      await exec.run('echo', ['test']);

      strict.ok(
        exec._allowIPs.length > 0,
        'should have resolved IPs'
      );
    });

    it('should handle unresolvable hosts gracefully', async () => {
      const result = await new SaferExec()
        .allowHosts('nonexistent-host-12345.local')
        .run('echo', ['test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
    });

    it('should respect working directory', async () => {
      const result = await new SaferExec()
        .workingDir('/')
        .run('sh', ['-c', 'pwd']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.equal(result.stdout.trim(), '/', 'should be in root directory');
    });

    it('should capture stderr separately from stdout', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "out" && echo "err" >&2']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('out'), 'should have stdout');
      strict.ok(result.stderr.includes('err'), 'should have stderr');
    });

    it('should return correct exit codes', async () => {
      for (const code of [0, 1, 42]) {
        const result = await new SaferExec()
          .run('sh', ['-c', `exit ${code}`]);

        strict.equal(
          result.exitCode,
          code,
          `should return exit code ${code}`
        );
      }
    });

    it('should handle commands with special characters', async () => {
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "hello world & more"']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('hello world'), 'should handle spaces');
    });

    it('should execute with timeout', async () => {
      const result = await new SaferExec()
        .timeout(5000)
        .run('echo', ['timed']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('timed'), 'should capture output');
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

  it('should return result with expected shape', async () => {
    const result = await saferExec('echo', ['test']);

    strict.equal(typeof result.exitCode, 'number', 'exitCode should be a number');
    strict.equal(typeof result.stdout, 'string', 'stdout should be a string');
    strict.equal(typeof result.stderr, 'string', 'stderr should be a string');
  });
});
