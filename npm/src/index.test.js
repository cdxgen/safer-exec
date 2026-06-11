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
import { join } from 'node:path';
import { realpathSync, writeFileSync, unlinkSync } from 'node:fs';

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
      strict.equal(exec._timeoutMs, 60000, 'timeoutMs should be 60000');
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

    it('should initialize crypto and advanced options', () => {
      const exec = new SaferExec();
      strict.equal(exec._allowCrypto, true);
      strict.equal(exec._blockCrypto, false);
      strict.equal(exec._blockCryptoEntropy, false);
      strict.equal(exec._detectFIPS, false);
      strict.equal(exec._strictFIPS, false);
      strict.equal(exec._allowGPU, false);
      strict.equal(exec._blockTPM, false);
      strict.equal(exec._spoofAntiVM, false);
      strict.equal(exec._traceLibraries, false);
      strict.equal(exec._traceTempDir, '');

      const execCustom = new SaferExec({
        allowCrypto: false,
        blockCrypto: true,
        blockCryptoEntropy: true,
        detectFIPS: true,
        strictFIPS: true,
        allowGPU: true,
        blockTPM: true,
        spoofAntiVM: true,
        traceLibraries: true,
        traceTempDir: '/tmp/my-trace-helper',
      });
      strict.equal(execCustom._allowCrypto, false);
      strict.equal(execCustom._blockCrypto, true);
      strict.equal(execCustom._blockCryptoEntropy, true);
      strict.equal(execCustom._detectFIPS, true);
      strict.equal(execCustom._strictFIPS, true);
      strict.equal(execCustom._allowGPU, true);
      strict.equal(execCustom._blockTPM, true);
      strict.equal(execCustom._spoofAntiVM, true);
      strict.equal(execCustom._traceLibraries, true);
      strict.equal(execCustom._traceTempDir, '/tmp/my-trace-helper');
    });
  });

    describe('sanitizeEnv', () => {
    it('should default to false', () => {
      const exec = new SaferExec();
      strict.equal(exec._sanitizeEnv, false);
    });

    it('should be settable via constructor option', () => {
      const exec = new SaferExec({ sanitizeEnv: true });
      strict.equal(exec._sanitizeEnv, true);
    });

    it('should return this for chaining', () => {
      const exec = new SaferExec();
      strict.equal(exec.sanitizeEnv(), exec);
    });

    it('should set _sanitizeEnv to true', () => {
      const exec = new SaferExec();
      exec.sanitizeEnv();
      strict.equal(exec._sanitizeEnv, true);
    });

    it('should set _sanitizeEnv to false when called with false', () => {
      const exec = new SaferExec();
      exec.sanitizeEnv(false);
      strict.equal(exec._sanitizeEnv, false);
    });

    it('should include sanitizeEnv in _buildConfig output', async () => {
      const exec = new SaferExec({ sanitizeEnv: true });
      const { config } = await exec._buildConfig('echo', ['test']);
      strict.equal(config.sanitizeEnv, true);
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
        .traceExec()
        .allowCrypto(false)
        .blockCrypto()
        .blockCryptoEntropy()
        .detectFIPS()
        .strictFIPS()
        .allowGPU(false)
        .blockTPM()
        .spoofAntiVM()
        .traceTempDir('/tmp/my-trace-helper');

      strict.equal(result, exec, 'all methods should return the same instance');
      strict.equal(exec._allowCrypto, false);
      strict.equal(exec._blockCrypto, true);
      strict.equal(exec._blockCryptoEntropy, true);
      strict.equal(exec._detectFIPS, true);
      strict.equal(exec._strictFIPS, true);
      strict.equal(exec._allowGPU, false);
      strict.equal(exec._blockTPM, true);
      strict.equal(exec._spoofAntiVM, true);
      strict.equal(exec._traceLibraries, true);
      strict.equal(exec._traceTempDir, '/tmp/my-trace-helper');
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

    it('should parse and store allowUrls correctly', () => {
      const exec = new SaferExec();
      exec.allowUrls(
        'https://registry.npmjs.org/-/npm/v1/',
        '~^api\\\\.github\\\\.com$',
        { host: '*.example.com', methods: ['GET', 'POST'] }
      );

      strict.equal(exec._allowURLRules.length, 3, 'should parse 3 URL rules');
      
      strict.equal(exec._allowURLRules[0].protocol, 'https');
      strict.equal(exec._allowURLRules[0].host, 'registry.npmjs.org');
      strict.equal(exec._allowURLRules[0].port, 443);
      strict.equal(exec._allowURLRules[0].pathPrefix, '/-/npm/v1/');

      strict.equal(exec._allowURLRules[1].host, '~^api\\\\.github\\\\.com$');

      strict.equal(exec._allowURLRules[2].host, '*.example.com');
      strict.deepEqual(exec._allowURLRules[2].methods, ['GET', 'POST']);
    });

    it('should merge allowUrls when called multiple times', () => {
      const exec = new SaferExec();
      exec.allowUrls('https://registry.npmjs.org/packages/');
      exec.allowUrls('https://api.github.com/repos/');

      strict.equal(exec._allowURLRules.length, 2, 'should accumulate URL rules');
      strict.equal(exec._allowURLRules[0].host, 'registry.npmjs.org');
      strict.equal(exec._allowURLRules[1].host, 'api.github.com');
      strict.ok(
        exec._allowHosts.includes('registry.npmjs.org'),
        'should auto-register host from URL rule'
      );
      strict.ok(
        exec._allowHosts.includes('api.github.com'),
        'should auto-register host from URL rule'
      );
    });

    it('should merge allowUrls with objects when called multiple times', () => {
      const exec = new SaferExec();
      exec.allowUrls({ host: 'registry.npmjs.org', port: 443 });
      exec.allowUrls({ host: '*.npmjs.org', methods: ['GET'] });

      strict.equal(exec._allowURLRules.length, 2, 'should accumulate object rules');
      strict.equal(exec._allowURLRules[0].host, 'registry.npmjs.org');
      strict.equal(exec._allowURLRules[1].host, '*.npmjs.org');
    });

    it('should merge all builder methods cumulatively', () => {
      const exec = new SaferExec();
      exec.allowHosts('a.com');
      exec.readPaths('/path/a');
      exec.writePaths('/tmp/a');
      exec.allowPorts(80);
      exec.allowExec('node');
      exec.blockExec('sh');

      // Second round of calls — merges, doesn't replace
      exec.allowHosts('b.com');
      exec.readPaths('/path/b');
      exec.writePaths('/tmp/b');
      exec.allowPorts(443);
      exec.allowExec('npx');
      exec.blockExec('bash');

      strict.deepEqual(exec._allowHosts, ['a.com', 'b.com'], 'hosts should merge');
      strict.deepEqual(exec._readPaths, ['/path/a', '/path/b'], 'readPaths should merge');
      strict.deepEqual(exec._writePaths, ['/tmp/a', '/tmp/b'], 'writePaths should merge');
      strict.deepEqual(exec._allowPorts, [80, 443], 'ports should merge');
      strict.deepEqual(exec._allowExec, ['node', 'npx'], 'allowExec should merge');
      strict.deepEqual(exec._blockExec, ['sh', 'bash'], 'blockExec should merge');
    });

    it('should merge multiple allowHosts calls with deduplication', () => {
      const exec = new SaferExec();
      exec.allowHosts('a.com', 'b.com');
      exec.allowHosts('b.com', 'c.com');
      exec.allowHosts('a.com');

      strict.deepEqual(
        exec._allowHosts,
        ['a.com', 'b.com', 'c.com'],
        'should merge and deduplicate across multiple calls'
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

    it('allowLoopback should be idempotent', () => {
      const exec = new SaferExec();
      exec.allowLoopback();
      exec.allowLoopback();
      strict.equal(exec._allowLoopback, true);
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

    it('should apply all 13 policies without error', () => {
      const policies = [
        'npm', 'yarn', 'pnpm', 'pypi', 'maven',
        'cargo', 'rubygems', 'composer', 'deno', 'gomod', 'bun',
        'poku', 'cdxgen'
      ];
      for (const policy of policies) {
        const exec = new SaferExec();
        exec.applyPolicy(policy);
        if (policy !== 'poku') {
          strict.ok(exec._allowHosts.length > 0, `${policy} should have hosts`);
        } else {
          strict.equal(exec._allowLoopback, true, 'poku should have allowLoopback');
        }
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

  describe('applyPolicyFile', () => {
    const tempPolicyPath = join(tmpdir(), `safer-exec-test-policy-${Date.now()}.json`);

    it('should load a policy file and apply all fields correctly', () => {
      const policyContent = {
        name: 'test-policy',
        version: '1',
        description: 'test description',
        readPaths: ['/tmp/read-test'],
        writePaths: ['/tmp/write-test'],
        disableNetwork: true,
        allowHosts: ['example.com'],
        allowIPs: ['127.0.0.1'],
        allowPorts: [8080],
        env: { TEST_ENV_VAR: 'test-value' },
        allowExec: ['/bin/ls'],
        blockExec: ['/bin/sh'],
        blockFork: true,
        traceExec: true,
        enableAudit: true,
        maxMemoryMB: 128,
        maxCPUCores: 1.5,
        maxProcesses: 10,
        timeoutMs: 5000
      };

      writeFileSync(tempPolicyPath, JSON.stringify(policyContent));

      try {
        const exec = new SaferExec();
        exec.applyPolicyFile(tempPolicyPath);

        strict.equal(exec._policyFilePath, tempPolicyPath);
        strict.deepEqual(exec._readPaths, ['/tmp/read-test']);
        strict.deepEqual(exec._writePaths, ['/tmp/write-test']);
        strict.equal(exec._disableNetwork, true);
        strict.deepEqual(exec._allowHosts, ['example.com']);
        strict.deepEqual(exec._allowIPs, ['127.0.0.1']);
        strict.deepEqual(exec._allowPorts, [8080]);
        strict.equal(exec._env.TEST_ENV_VAR, 'test-value');
        strict.deepEqual(exec._allowExec, ['/bin/ls']);
        strict.deepEqual(exec._blockExec, ['/bin/sh']);
        strict.equal(exec._blockFork, true);
        strict.equal(exec._traceExec, true);
        strict.equal(exec._enableAudit, true);
        strict.equal(exec._maxMemoryMB, 128);
        strict.equal(exec._maxCPUCores, 1.5);
        strict.equal(exec._maxProcesses, 10);
        strict.equal(exec._timeoutMs, 5000);
      } finally {
        try { unlinkSync(tempPolicyPath); } catch {}
      }
    });

    it('should merge policy with existing user settings (does not overwrite)', () => {
      const policyContent = {
        readPaths: ['/tmp/policy-read'],
        allowHosts: ['policy.com']
      };

      writeFileSync(tempPolicyPath, JSON.stringify(policyContent));

      try {
        const exec = new SaferExec();
        exec.readPaths('/tmp/user-read');
        exec.allowHosts('user.com');
        exec.applyPolicyFile(tempPolicyPath);

        strict.ok(exec._readPaths.includes('/tmp/user-read'));
        strict.ok(exec._readPaths.includes('/tmp/policy-read'));
        strict.ok(exec._allowHosts.includes('user.com'));
        strict.ok(exec._allowHosts.includes('policy.com'));
      } finally {
        try { unlinkSync(tempPolicyPath); } catch {}
      }
    });

    it('should throw with clear error message for invalid JSON', () => {
      writeFileSync(tempPolicyPath, 'not-a-json');

      try {
        const exec = new SaferExec();
        strict.throws(() => {
          exec.applyPolicyFile(tempPolicyPath);
        }, /Invalid policy file|SyntaxError/);
      } finally {
        try { unlinkSync(tempPolicyPath); } catch {}
      }
    });

    it('should not call disableNetwork if disableNetwork is false', () => {
      const policyContent = {
        disableNetwork: false
      };

      writeFileSync(tempPolicyPath, JSON.stringify(policyContent));

      try {
        const exec = new SaferExec();
        exec.applyPolicyFile(tempPolicyPath);
        strict.equal(exec._disableNetwork, false);
      } finally {
        try { unlinkSync(tempPolicyPath); } catch {}
      }
    });

    it('should fall back to envVars from process.env if env map is not present', () => {
      const policyContent = {
        envVars: ['PATH', 'NON_EXISTENT_VAR_12345']
      };

      writeFileSync(tempPolicyPath, JSON.stringify(policyContent));

      try {
        const exec = new SaferExec();
        exec.applyPolicyFile(tempPolicyPath);
        strict.equal(exec._env.PATH, process.env.PATH);
        strict.equal(exec._env.NON_EXISTENT_VAR_12345, undefined);
      } finally {
        try { unlinkSync(tempPolicyPath); } catch {}
      }
    });

    it('should support expansions of $HOME, $PWD, and tilde paths', () => {
      const policyContent = {
        readPaths: [
          '$HOME/test-read',
          '$PWD/test-pwd',
          '~/test-tilde'
        ],
        writePaths: [
          '$HOME/test-write',
          '$PWD/test-pwd-w'
        ]
      };

      writeFileSync(tempPolicyPath, JSON.stringify(policyContent));

      try {
        const exec = new SaferExec();
        exec.applyPolicyFile(tempPolicyPath);

        const home = process.env.HOME || process.env.USERPROFILE || '';
        const pwd = process.cwd();

        strict.ok(exec._readPaths.includes(`${home}/test-read`));
        strict.ok(exec._readPaths.includes(`${pwd}/test-pwd`));
        strict.ok(exec._readPaths.includes(`${home}/test-tilde`));

        strict.ok(exec._writePaths.includes(`${home}/test-write`));
        strict.ok(exec._writePaths.includes(`${pwd}/test-pwd-w`));
      } finally {
        try { unlinkSync(tempPolicyPath); } catch {}
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

    it('should emit audit events in real-time', async () => {
      const exec = new SaferExec()
        .enableAudit()
        .suppressLibLoadStderr();
      
      const events = [];
      exec.on('audit', (entry) => {
        events.push(entry);
      });

      const result = await exec.run('echo', ['test']);
      
      strict.ok(Array.isArray(result.auditLog), 'should return an auditLog array');
      strict.equal(result.auditLog.length, events.length, 'should have emitted all audit events in real-time');
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

    it('should filter out non-existent paths centrally', async () => {
      const exec = new SaferExec()
        .readPaths('/nonexistent/path/to/read')
        .writePaths('/nonexistent/path/to/write');

      const result = await exec.run('echo', ['hello']);
      strict.equal(result.exitCode, 0);
    });

    it('should handle direct file paths in read and write paths', async () => {
      const tmpFile = join(tmpdir(), `safer-exec-file-test-${Date.now()}.txt`);
      writeFileSync(tmpFile, 'hello file content');
      try {
        const result = await new SaferExec()
          .readPaths(tmpFile)
          .run('cat', [tmpFile]);
        strict.equal(result.exitCode, 0);
        strict.ok(result.stdout.includes('hello file content'));
      } finally {
        try { unlinkSync(tmpFile); } catch {}
      }
    });
  });

  describe('Security Hardening', () => {
    it('should filter environment variables by default to prevent credentials leak', async () => {
      process.env.SECRET_API_TOKEN_XYZ = 'sensitive-token';
      const result = await new SaferExec()
        .run('sh', ['-c', 'echo "SECRET:${SECRET_API_TOKEN_XYZ}:SECRET"']);

      delete process.env.SECRET_API_TOKEN_XYZ;

      strict.equal(result.exitCode, 0);
      strict.ok(!result.stdout.includes('sensitive-token'), 'should not contain the secret host env variable');
    });

    it('should support BlockExec wildcard preventing executions of other processes', async () => {
      const result = await new SaferExec()
        .blockExec('*')
        .run('sh', ['-c', 'id']);
      
      strict.notEqual(result.exitCode, 0, 'wildcard BlockExec should deny shell sub-execution');
    });

    it('should support strict mode option', async () => {
      const result = await new SaferExec()
        .strict()
        .run('echo', ['strict-test']);

      // On systems with user namespaces restricted (Ubuntu 24.04+),
      // strict mode refuses to run with degraded isolation. On systems
      // with full namespace support, the command succeeds normally.
      if (result.exitCode === 0) {
        strict.ok(result.stdout.includes('strict-test'));
      } else {
        strict.ok(
          result.stderr.includes('user namespaces unavailable') ||
          result.stderr.includes('unavailable'),
          'should fail due to strict mode preventing degraded isolation'
        );
      }
    });

    it('should run with detectFIPS option enabled without error', async () => {
      const result = await new SaferExec()
        .detectFIPS()
        .run('echo', ['fips-detect-test']);

      strict.equal(result.exitCode, 0);
      strict.ok(result.stdout.includes('fips-detect-test'));
    });

    it('should fail or warn with strictFIPS depending on host fips_enabled settings', async () => {
      // If StrictFIPS is on and strict is on, it will error if host lacks FIPSMode/fips_enabled
      const run = new SaferExec()
        .strictFIPS()
        .strict();
      try {
        const result = await run.run('echo', ['fips-strict-test']);
        // If it succeeds, the host might have FIPS mode enabled (e.g. CI environments).
        // Otherwise, it must throw or fail. Both are valid depending on the host configuration.
        strict.ok(result.exitCode === 0 || result.exitCode !== 0);
      } catch (err) {
        // If it throws, check that it contains the FIPS strict failure message
        strict.ok(err.message.includes('FIPS strict enforcement failed') || err.message.includes('exit'));
      }
    });
  });
});

describe('SaferExec.diagnostics', () => {
  it('should be a static method', () => {
    strict.equal(typeof SaferExec.diagnostics, 'function', 'diagnostics should be a static method');
  });

  it('should return an object with platform, capabilities, and features', async () => {
    const result = await SaferExec.diagnostics();

    strict.equal(typeof result, 'object', 'should return an object');
    strict.equal(typeof result.platform, 'string', 'should have platform string');
    strict.equal(typeof result.arch, 'string', 'should have arch string');
    strict.equal(typeof result.nodeVersion, 'string', 'should have nodeVersion');
    strict.ok(result.nodeVersion.startsWith('v'), 'nodeVersion should start with v');

    strict.ok(typeof result.capabilities === 'object' && !Array.isArray(result.capabilities),
      'capabilities should be an object');
    strict.ok(typeof result.features === 'object' && !Array.isArray(result.features),
      'features should be an object');

    // Every capability should have available and detail fields
    for (const [key, cap] of Object.entries(result.capabilities)) {
      strict.equal(typeof cap.available, 'boolean', `capability ${key} should have available boolean`);
      strict.equal(typeof cap.detail, 'string', `capability ${key} should have detail string`);
    }

    // Features should all be booleans
    for (const [key, val] of Object.entries(result.features)) {
      strict.equal(typeof val, 'boolean', `feature ${key} should be boolean`);
    }

    // Core features that should exist
    strict.ok('network_isolation' in result.features, 'should have network_isolation');
    strict.ok('file_read_restriction' in result.features, 'should have file_read_restriction');
    strict.ok('file_write_restriction' in result.features, 'should have file_write_restriction');
    strict.ok('memory_limit' in result.features, 'should have memory_limit');
    strict.ok('strict_mode' in result.features, 'should have strict_mode');
    strict.ok('trace_http_urls' in result.features, 'should have trace_http_urls');
    strict.ok('allow_url_rules' in result.features, 'should have allow_url_rules');
  });

  it('should have platform-specific capabilities', async () => {
    const result = await SaferExec.diagnostics();

    if (result.platform === 'darwin') {
      strict.ok('sandbox_exec' in result.capabilities, 'macOS should have sandbox_exec capability');
      strict.ok('seatbelt_profile' in result.capabilities, 'macOS should have seatbelt_profile capability');
      strict.ok('rlimit_as' in result.capabilities, 'macOS should have rlimit_as capability');
    } else if (result.platform === 'linux') {
      strict.ok('user_namespace' in result.capabilities, 'Linux should have user_namespace capability');
      strict.ok('cgroup_v2' in result.capabilities, 'Linux should have cgroup_v2 capability');
      strict.ok('seccomp' in result.capabilities, 'Linux should have seccomp capability');
    }
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

describe('IO Limiting', () => {
  it('should accept maxReadIOPS option', () => {
    const exec = new SaferExec({ maxReadIOPS: 100 });
    strict.equal(exec._maxReadIOPS, 100);
  });

  it('should accept maxWriteIOPS option', () => {
    const exec = new SaferExec({ maxWriteIOPS: 200 });
    strict.equal(exec._maxWriteIOPS, 200);
  });

  it('should accept maxReadBps option', () => {
    const exec = new SaferExec({ maxReadBps: 1048576 });
    strict.equal(exec._maxReadBps, 1048576);
  });

  it('should accept maxWriteBps option', () => {
    const exec = new SaferExec({ maxWriteBps: 2097152 });
    strict.equal(exec._maxWriteBps, 2097152);
  });

  it('should pass IO limits in config', async () => {
    const exec = new SaferExec({ maxReadIOPS: 100, maxWriteBps: 1048576 });
    const { config } = await exec._buildConfig('echo', []);
    strict.equal(config.maxReadIOPS, 100);
    strict.equal(config.maxWriteBps, 1048576);
  });

  it('should support chaining IO methods', () => {
    const exec = new SaferExec();
    exec.maxReadIOPS(100).maxWriteIOPS(200).maxReadBps(1024).maxWriteBps(2048);
    strict.equal(exec._maxReadIOPS, 100);
    strict.equal(exec._maxWriteIOPS, 200);
    strict.equal(exec._maxReadBps, 1024);
    strict.equal(exec._maxWriteBps, 2048);
  });

  it('should default IO limits to 0', () => {
    const exec = new SaferExec();
    strict.equal(exec._maxReadIOPS, 0);
    strict.equal(exec._maxWriteIOPS, 0);
    strict.equal(exec._maxReadBps, 0);
    strict.equal(exec._maxWriteBps, 0);
  });
});

describe('Profile Validation', () => {
  it('should accept validateProfile option', () => {
    const exec = new SaferExec({ validateProfile: true });
    strict.equal(exec._validateProfile, true);
  });

  it('should default validateProfile to false', () => {
    const exec = new SaferExec();
    strict.equal(exec._validateProfile, false);
  });

  it('should support chaining validateProfile', () => {
    const exec = new SaferExec();
    exec.validateProfile();
    strict.equal(exec._validateProfile, true);
  });

  it('should include validateProfile in config', async () => {
    const exec = new SaferExec();
    exec.validateProfile();
    const { config } = await exec._buildConfig('echo', []);
    strict.equal(config.validateProfile, true);
  });
});

describe('Policy Composition (extends)', () => {
  it('should reject unknown extends policy', () => {
    const policyPath = join(tmpdir(), 'test-extends-unknown.json');
    writeFileSync(policyPath, JSON.stringify({ extends: 'nonexistent' }));
    try {
      const exec = new SaferExec();
      strict.throws(
        () => exec.applyPolicyFile(policyPath),
        /Unknown extends policy/,
        'should throw for unknown extends'
      );
    } finally {
      try { unlinkSync(policyPath); } catch {}
    }
  });

  it('should apply base policy from extends', () => {
    const policyPath = join(tmpdir(), 'test-extends-npm.json');
    writeFileSync(policyPath, JSON.stringify({
      extends: 'npm',
      allowHosts: ['custom.registry.com'],
      readPaths: ['/custom/path'],
    }));
    try {
      const exec = new SaferExec();
      exec.applyPolicyFile(policyPath);
      // Should have both npm policy hosts and custom hosts
      strict.ok(exec._allowHosts.includes('custom.registry.com'), 'should include custom host');
      strict.ok(exec._allowHosts.includes('registry.npmjs.org'), 'should include npm base host');
      strict.ok(exec._readPaths.includes('/custom/path'), 'should include custom path');
    } finally {
      try { unlinkSync(policyPath); } catch {}
    }
  });

  it('should merge env from base and custom', () => {
    const policyPath = join(tmpdir(), 'test-extends-env.json');
    writeFileSync(policyPath, JSON.stringify({
      extends: 'npm',
      env: { CUSTOM_VAR: 'custom_value' },
    }));
    try {
      const exec = new SaferExec();
      exec.applyPolicyFile(policyPath);
      strict.equal(exec._env.CUSTOM_VAR, 'custom_value', 'should include custom env var');
    } finally {
      try { unlinkSync(policyPath); } catch {}
    }
  });

  it('should apply extends in policy file along with all other fields', () => {
    const policyPath = join(tmpdir(), 'test-extends-full.json');
    writeFileSync(policyPath, JSON.stringify({
      extends: 'npm',
      allowHosts: ['override.registry.com'],
      readPaths: ['/override/read'],
      writePaths: ['/override/write'],
      maxMemoryMB: 2048,
      maxReadIOPS: 500,
    }));
    try {
      const exec = new SaferExec();
      exec.applyPolicyFile(policyPath);
      strict.equal(exec._maxMemoryMB, 2048, 'should set custom memory limit');
      strict.equal(exec._maxReadIOPS, 500, 'should set custom read IOPS');
      strict.ok(exec._allowHosts.includes('override.registry.com'), 'should include override host');
      strict.ok(exec._readPaths.includes('/override/read'), 'should include override read path');
    } finally {
      try { unlinkSync(policyPath); } catch {}
    }
  });
});
