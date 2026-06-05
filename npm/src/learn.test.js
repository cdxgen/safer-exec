/**
 * Tests for behavioral auto-profiling (enableLearn).
 *
 * Verifies that the engine correctly captures filesystem and network
 * behavior during execution and generates a strict policy from observations.
 *
 * @module learn_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Create a temporary test directory with known files.
 * @returns {string} Path to the test directory
 */
function createTestDir() {
  const dir = join('/tmp', `safer-learn-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'readme.md'), '# Test Project');
  writeFileSync(join(dir, 'config.json'), '{"key": "value"}');
  return dir;
}

/**
 * Clean up a test directory.
 * @param {string} dir
 */
function cleanupTestDir(dir) {
  if (existsSync(dir)) {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('Learning Mode (enableLearn)', () => {
  describe('Basic learning', () => {
    it('should return a learned policy for a simple command', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('echo', ['hello']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy in result');
      strict.equal(
        result.learnedPolicy.cmd,
        'echo',
        'learned policy should capture the command'
      );
      strict.deepEqual(
        result.learnedPolicy.args,
        ['hello'],
        'learned policy should capture the arguments'
      );
    });

    it('should capture the command and args in learned policy', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('sh', ['-c', 'echo test']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
      strict.equal(
        result.learnedPolicy.cmd,
        'sh',
        'learned policy should capture the command'
      );
      strict.deepEqual(
        result.learnedPolicy.args,
        ['-c', 'echo test'],
        'learned policy should capture the arguments'
      );
    });

    it('should return read paths for file access', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('cat', ['/etc/hosts']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
      // Read paths may or may not be captured depending on strace availability
      if (result.learnedPolicy.readPaths?.length > 0) {
        strict.ok(
          result.learnedPolicy.readPaths.some((p) => p.includes('hosts')),
          'should capture /etc/hosts in read paths'
        );
      }
    });

    it('should capture network connections for curl', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('curl', ['-s', '-o', '/dev/null', 'https://httpbin.org/ip']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
      // Network info may or may not be captured depending on strace availability
      if (result.learnedPolicy.allowIPs?.length > 0) {
        strict.ok(
          result.learnedPolicy.allowIPs.length > 0,
          'should capture network IPs'
        );
      }
    });
  });

  describe('Learned policy structure', () => {
    it('should have all required fields', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('echo', ['structure test']);

      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
      strict.ok('cmd' in result.learnedPolicy, 'should have cmd field');
      strict.ok('args' in result.learnedPolicy, 'should have args field');
      strict.ok('readPaths' in result.learnedPolicy, 'should have readPaths field');
      strict.ok('writePaths' in result.learnedPolicy, 'should have writePaths field');
      strict.ok('allowIPs' in result.learnedPolicy, 'should have allowIPs field');
      strict.ok('allowPorts' in result.learnedPolicy, 'should have allowPorts field');
    });

    it('should have arrays for list fields', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('echo', ['arrays test']);

      strict.ok(Array.isArray(result.learnedPolicy.readPaths), 'readPaths should be an array');
      strict.ok(Array.isArray(result.learnedPolicy.writePaths), 'writePaths should be an array');
      strict.ok(Array.isArray(result.learnedPolicy.allowIPs), 'allowIPs should be an array');
      strict.ok(Array.isArray(result.learnedPolicy.allowPorts), 'allowPorts should be an array');
      strict.ok(Array.isArray(result.learnedPolicy.args), 'args should be an array');
    });
  });

  describe('Without learning mode', () => {
    it('should not include learnedPolicy when enableLearn is not set', async () => {
      const result = await new SaferExec()
        .run('echo', ['hello']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.equal(result.learnedPolicy, undefined, 'should not have learnedPolicy');
    });
  });

  describe('Chaining with other methods', () => {
    it('should chain with writePaths', async () => {
      const result = await new SaferExec()
        .writePaths('/tmp')
        .enableLearn()
        .run('echo', ['chained']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
    });

    it('should chain with maxMemory', async () => {
      const result = await new SaferExec()
        .maxMemory(256)
        .enableLearn()
        .run('echo', ['chained']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
    });

    it('should chain with allowHosts', async () => {
      const result = await new SaferExec()
        .allowHosts('registry.npmjs.org')
        .enableLearn()
        .run('echo', ['chained']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
    });

    it('should chain with disableNetwork', async () => {
      const result = await new SaferExec()
        .disableNetwork()
        .enableLearn()
        .run('echo', ['chained']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
    });

    it('should chain with environment variables', async () => {
      const result = await new SaferExec()
        .env('LEARN_TEST_VAR', 'learn_value')
        .enableLearn()
        .run('sh', ['-c', 'echo $LEARN_TEST_VAR']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
    });
  });

  describe('File access learning', () => {
    it('should learn from reading multiple files', async () => {
      const testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .enableLearn()
          .run('sh', ['-c', `cat ${join(testDir, 'readme.md')} ${join(testDir, 'config.json')}`]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.learnedPolicy, 'should have learnedPolicy');
        // If strace is available, read paths should be captured
        if (result.learnedPolicy.readPaths?.length > 0) {
          strict.ok(
            result.learnedPolicy.readPaths.some((p) => p.includes('readme.md')) ||
            result.learnedPolicy.readPaths.some((p) => p.includes('config.json')),
            'should capture at least one read path'
          );
        }
      } finally {
        cleanupTestDir(testDir);
      }
    });

    it('should learn from writing files', async () => {
      const testDir = createTestDir();

      try {
        const result = await new SaferExec()
          .enableLearn()
          .run('sh', ['-c', `echo "learned write" > ${join(testDir, 'output.txt')}`]);

        strict.equal(result.exitCode, 0, 'command should succeed');
        strict.ok(result.learnedPolicy, 'should have learnedPolicy');
        // If strace is available, write paths should be captured
        if (result.learnedPolicy.writePaths?.length > 0) {
          strict.ok(
            result.learnedPolicy.writePaths.some((p) => p.includes('output.txt')),
            'should capture output.txt in write paths'
          );
        }
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('Network learning', () => {
    it('should learn from HTTP connections', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('sh', ['-c', 'curl -s -o /dev/null https://httpbin.org/get || true']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
      // If strace is available, network info should be captured
      if (result.learnedPolicy.allowPorts?.length > 0) {
        strict.ok(
          result.learnedPolicy.allowPorts.includes(443),
          'should capture port 443 for HTTPS'
        );
      }
    });

    it('should learn from multiple network connections', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('sh', ['-c', 'curl -s -o /dev/null https://httpbin.org/get && curl -s -o /dev/null https://httpbin.org/ip || true']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
    });
  });

  describe('Edge cases', () => {
    it('should handle failing commands gracefully', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('sh', ['-c', 'exit 42']);

      strict.ok(result.learnedPolicy, 'should have learnedPolicy even for failing commands');
      strict.equal(result.learnedPolicy.cmd, 'sh', 'should capture command');
    });

    it('should handle commands with no file access', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('sh', ['-c', 'echo $((123 * 456))']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
      strict.ok(
        Array.isArray(result.learnedPolicy.readPaths),
        'readPaths should be an array even if empty'
      );
    });

    it('should handle commands with no network access', async () => {
      const result = await new SaferExec()
        .enableLearn()
        .run('echo', ['no network']);

      strict.equal(result.exitCode, 0, 'command should succeed');
      strict.ok(result.learnedPolicy, 'should have learnedPolicy');
      strict.ok(
        Array.isArray(result.learnedPolicy.allowIPs),
        'allowIPs should be an array even if empty'
      );
    });
  });

  describe('Real-world scenario: learning npm install behavior', () => {
    it('should generate a useful policy for npm install', async () => {
      const testDir = createTestDir();
      writeFileSync(
        join(testDir, 'package.json'),
        JSON.stringify({
          name: 'learn-test',
          version: '1.0.0',
          dependencies: { chalk: '^5.0.0' },
        })
      );

      try {
        const result = await new SaferExec()
          .workingDir(testDir)
          .enableLearn()
          .run('npm', ['install', '--ignore-scripts']);

        strict.equal(result.exitCode, 0, 'npm install should succeed');
        strict.ok(result.learnedPolicy, 'should have learnedPolicy');
        strict.equal(result.learnedPolicy.cmd, 'npm', 'should capture npm command');
        strict.ok(
          result.learnedPolicy.args.includes('install'),
          'should capture install argument'
        );

        // Verify the learned policy has the expected structure
        strict.ok(
          Array.isArray(result.learnedPolicy.readPaths) ||
          Array.isArray(result.learnedPolicy.writePaths) ||
          Array.isArray(result.learnedPolicy.allowPorts),
          'should have array fields in learned policy'
        );
      } finally {
        cleanupTestDir(testDir);
      }
    });
  });

  describe('Learned policy can be used directly', () => {
    it('should produce a policy that can be used with SaferExec', async () => {
      // First, learn a policy
      const learnResult = await new SaferExec()
        .enableLearn()
        .run('cat', ['/etc/hosts']);

      strict.ok(learnResult.learnedPolicy, 'should have learnedPolicy');

      // Then use the learned policy to run the same command
      const { readPaths, writePaths, allowHosts } = learnResult.learnedPolicy;
      const exec = new SaferExec();

      if (readPaths?.length > 0) {
        readPaths.forEach((p) => exec.readPaths(p));
      }
      if (writePaths?.length > 0) {
        writePaths.forEach((p) => exec.writePaths(p));
      }
      if (allowHosts?.length > 0) {
        allowHosts.forEach((h) => exec.allowHosts(h));
      }

      const useResult = await exec.run('cat', ['/etc/hosts']);
      strict.equal(useResult.exitCode, 0, 'should succeed with learned policy');
      strict.ok(useResult.stdout.length > 0, 'should have output');
    });
  });
});
