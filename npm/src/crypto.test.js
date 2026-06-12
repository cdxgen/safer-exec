/**
 * Unit tests for crypto tracing API (traceCrypto, cbom, cryptoProbeMode).
 *
 * Tests API surface and config serialization. End-to-end crypto tracing
 * requires Linux kernel >= 5.8 with CAP_BPF and is tested in integration tests.
 *
 * @module crypto_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';

describe('SaferExec crypto tracing API', () => {
  describe('traceCrypto()', () => {
    it('should set _traceCrypto to true', () => {
      const exec = new SaferExec();
      exec.traceCrypto();
      strict.equal(exec._traceCrypto, true);
    });

    it('should auto-enable _traceHTTPURLs', () => {
      const exec = new SaferExec();
      exec.traceCrypto();
      strict.equal(exec._traceHTTPURLs, true);
    });

    it('should return this for chaining', () => {
      const exec = new SaferExec();
      const result = exec.traceCrypto();
      strict.equal(result, exec);
    });
  });

  describe('cbom()', () => {
    it('should set _cbomOutputPath', () => {
      const exec = new SaferExec();
      exec.cbom('./cbom.json');
      strict.equal(exec._cbomOutputPath, './cbom.json');
    });

    it('should return this for chaining', () => {
      const exec = new SaferExec();
      const result = exec.cbom('/tmp/out.json');
      strict.equal(result, exec);
    });
  });

  describe('cryptoProbeMode()', () => {
    it('should set mode to "operations"', () => {
      const exec = new SaferExec();
      exec.cryptoProbeMode('operations');
      strict.equal(exec._cryptoProbeMode, 'operations');
    });

    it('should default to "tls-only"', () => {
      const exec = new SaferExec();
      strict.equal(exec._cryptoProbeMode, 'tls-only');
    });

    it('should return this for chaining', () => {
      const exec = new SaferExec();
      const result = exec.cryptoProbeMode('tls-only');
      strict.equal(result, exec);
    });
  });

  describe('traceHTTPURLs()', () => {
    it('should set _traceHTTPURLs to true', () => {
      const exec = new SaferExec();
      exec.traceHTTPURLs();
      strict.equal(exec._traceHTTPURLs, true);
    });

    it('should return this for chaining', () => {
      const exec = new SaferExec();
      const result = exec.traceHTTPURLs();
      strict.equal(result, exec);
    });
  });

  describe('allowUrls()', () => {
    it('should parse URL strings and auto-allow hostnames', () => {
      const exec = new SaferExec();
      exec.allowUrls('https://registry.npmjs.org/path/to/something');
      strict.equal(exec._allowURLRules.length, 1);
      strict.equal(exec._allowURLRules[0].host, 'registry.npmjs.org');
      strict.equal(exec._allowURLRules[0].protocol, 'https');
      strict.equal(exec._allowURLRules[0].port, 443);
      strict.equal(exec._allowURLRules[0].pathPrefix, '/path/to/something');
      strict.ok(exec._allowHosts.includes('registry.npmjs.org'));
    });

    it('should parse URL rules as objects and keep methods/port', () => {
      const exec = new SaferExec();
      exec.allowUrls({
        protocol: 'https',
        host: 'api.github.com',
        port: 8443,
        path: '/repos',
        methods: ['GET', 'POST']
      });
      strict.equal(exec._allowURLRules.length, 1);
      strict.equal(exec._allowURLRules[0].host, 'api.github.com');
      strict.equal(exec._allowURLRules[0].port, 8443);
      strict.equal(exec._allowURLRules[0].pathPrefix, '/repos');
      strict.deepEqual(exec._allowURLRules[0].methods, ['GET', 'POST']);
      strict.ok(exec._allowHosts.includes('api.github.com'));
    });

    it('should support regex shorthand prefix (~)', () => {
      const exec = new SaferExec();
      exec.allowUrls('~^.*\\.npmjs\\.org$');
      strict.equal(exec._allowURLRules.length, 1);
      strict.equal(exec._allowURLRules[0].host, '~^.*\\.npmjs\\.org$');
      // Wildcards/regex hosts should not be added to allowHosts automatically
      strict.ok(!exec._allowHosts.includes('~^.*\\.npmjs\\.org$'));
    });
  });

  describe('constructor options', () => {
    it('should accept traceCrypto option', () => {
      const exec = new SaferExec({ traceCrypto: true });
      strict.equal(exec._traceCrypto, true);
      strict.equal(exec._traceHTTPURLs, false);
    });

    it('should accept cbomOutputPath option', () => {
      const exec = new SaferExec({ cbomOutputPath: '/tmp/cbom.json' });
      strict.equal(exec._cbomOutputPath, '/tmp/cbom.json');
    });

    it('should accept cryptoProbeMode option', () => {
      const exec = new SaferExec({ cryptoProbeMode: 'operations' });
      strict.equal(exec._cryptoProbeMode, 'operations');
    });

    it('should accept traceHTTPURLs option', () => {
      const exec = new SaferExec({ traceHTTPURLs: true });
      strict.equal(exec._traceHTTPURLs, true);
    });
  });

  describe('_buildConfig crypto fields', () => {
    it('should include traceCrypto in config', async () => {
      const exec = new SaferExec();
      exec.traceCrypto();
      exec.cbom('./cbom.json');
      exec.cryptoProbeMode('operations');
      // _buildConfig requires resolving hosts but we have none
      const { config } = await exec._buildConfig('echo', ['hello']);
      strict.equal(config.traceCrypto, true);
      strict.equal(config.cbomOutputPath, './cbom.json');
      strict.equal(config.cryptoProbeMode, 'operations');
      strict.equal(config.traceHTTPURLs, true);
    });

    it('should include allowURLRules and traceHTTPURLs in config', async () => {
      const exec = new SaferExec();
      exec.traceHTTPURLs();
      exec.allowUrls('https://registry.npmjs.org/express');
      const { config } = await exec._buildConfig('echo', ['hello']);
      strict.equal(config.traceHTTPURLs, true);
      strict.equal(config.allowURLRules.length, 1);
      strict.equal(config.allowURLRules[0].host, 'registry.npmjs.org');
    });

    it('should omit crypto fields when not set', async () => {
      const exec = new SaferExec();
      const { config } = await exec._buildConfig('echo', ['hello']);
      strict.equal(config.traceCrypto, false);
      strict.equal(config.cbomOutputPath, '');
      strict.equal(config.cryptoProbeMode, 'tls-only');
    });

    it('should include allowCiphers in config', async () => {
      const exec = new SaferExec();
      exec.allowCiphers('ECDHE-RSA-AES256-GCM-SHA384', 'TLS_AES_256_GCM_SHA384');
      const { config } = await exec._buildConfig('echo', ['hello']);
      strict.deepEqual(config.allowCiphers, ['ECDHE-RSA-AES256-GCM-SHA384', 'TLS_AES_256_GCM_SHA384']);
    });
  });

  describe('allowCiphers()', () => {
    it('should add ciphers to _allowCiphers list', () => {
      const exec = new SaferExec();
      exec.allowCiphers('ECDHE-RSA-AES256-GCM-SHA384');
      strict.deepEqual(exec._allowCiphers, ['ECDHE-RSA-AES256-GCM-SHA384']);
    });

    it('should support array arguments and flat arrays', () => {
      const exec = new SaferExec();
      exec.allowCiphers(['A', 'B'], 'C');
      strict.deepEqual(exec._allowCiphers, ['A', 'B', 'C']);
    });

    it('should accept allowCiphers in constructor options', () => {
      const exec = new SaferExec({ allowCiphers: ['X'] });
      strict.deepEqual(exec._allowCiphers, ['X']);
    });
  });
});

import { isValidAuditEntry } from './runner.js';

describe('isValidAuditEntry', () => {
  it('should validate standard audit entries', () => {
    strict.ok(isValidAuditEntry({ type: 'file_read', target: '/etc/passwd' }));
    strict.ok(isValidAuditEntry({ type: 'network', host: 'google.com' }));
    strict.ok(!isValidAuditEntry({ type: 'file_read' })); // missing target
  });

  it('should validate crypto audit entries', () => {
    strict.ok(isValidAuditEntry({ type: 'crypto-cipher', cipher: 'ECDHE-RSA-AES256-GCM-SHA384' }));
    strict.ok(isValidAuditEntry({ type: 'crypto-library', name: 'OpenSSL' }));
    strict.ok(isValidAuditEntry({ type: 'crypto-operation', operation: 'digest' }));
    strict.ok(!isValidAuditEntry({ type: 'crypto-cipher' })); // missing cipher/name/etc
  });
});

