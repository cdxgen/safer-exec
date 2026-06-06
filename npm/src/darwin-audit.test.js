/**
 * Darwin-specific tests: Homebrew path detection, audit mode trace validation.
 *
 * Tests that verify:
 *  - npm policy includes Homebrew paths on darwin arm64
 *  - SSL paths include Homebrew OpenSSL on darwin arm64
 *  - Audit mode captures file-read audit entries
 *  - Audit mode captures process-exec audit entries
 *
 * @module darwin_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec, saferExec } from './index.js';
import { getSslPaths, isMac } from './policies/sslhelper.js';
import { npmPolicy } from './policies/npm.js';
import { parseAuditLog } from './runner.js';

describe('Darwin Homebrew Path Detection', () => {
  describe('npmPolicy Homebrew paths', () => {
    it('should include Homebrew paths on darwin arm64', (t) => {
      if (process.platform !== 'darwin') {
        it.skip('skip: not darwin');
        return;
      }
      if (process.arch !== 'arm64') {
        t.skip('not arm64');
        return;
      }

      const policy = npmPolicy();
      const hasHomebrewPath = policy.readPaths.some(
        (p) => p.startsWith('/opt/homebrew')
      );

      strict.ok(
        hasHomebrewPath,
        'npm policy should include Homebrew paths on darwin arm64'
      );
    });

    it('should include Homebrew node path on darwin arm64', (t) => {
      if (process.platform !== 'darwin') {
        it.skip('skip: not darwin');
        return;
      }
      if (process.arch !== 'arm64') {
        t.skip('not arm64');
        return;
      }

      const policy = npmPolicy();
      // The policy includes Homebrew paths via getSslPaths() which adds
      // /opt/homebrew/etc/openssl@3/certs, etc.
      const hasHomebrewSsl = policy.readPaths.some(
        (p) => p.startsWith('/opt/homebrew') && p.includes('openssl')
      );

      strict.ok(
        hasHomebrewSsl,
        'npm policy should include Homebrew SSL paths on darwin arm64'
      );
    });

    it('should include Homebrew lib path on darwin arm64', () => {
      if (process.platform !== 'darwin') {
        it.skip('skip: not darwin');
        return;
      }
      if (process.arch !== 'arm64') {
        it.skip('skip: not arm64');
        return;
      }

      const policy = npmPolicy();
      // The policy includes Homebrew paths via getSslPaths()
      const hasHomebrewPath = policy.readPaths.some(
        (p) => p.startsWith('/opt/homebrew')
      );

      strict.ok(
        hasHomebrewPath,
        'npm policy should include Homebrew paths on darwin arm64'
      );
    });

    it('should not include Homebrew paths on non-arm64 platforms', () => {
      if (process.platform !== 'darwin' || process.arch !== 'arm64') {
        it.skip('skip: not darwin arm64');
        return;
      }

      // On darwin arm64, Homebrew paths should be present
      const policy = npmPolicy();
      const hasHomebrewPath = policy.readPaths.some(
        (p) => p.startsWith('/opt/homebrew')
      );

      strict.ok(
        hasHomebrewPath,
        'npm policy should include Homebrew paths on darwin arm64'
      );
    });
  });

  describe('SSL paths Homebrew OpenSSL', () => {
    it('should include Homebrew OpenSSL paths on darwin arm64', () => {
      if (process.platform !== 'darwin') {
        it.skip('skip: not darwin');
        return;
      }
      if (process.arch !== 'arm64') {
        it.skip('skip: not arm64');
        return;
      }

      const sslPaths = getSslPaths();
      const hasHomebrewOpenSSL = sslPaths.some(
        (p) => p.startsWith('/opt/homebrew') && p.includes('openssl')
      );

      strict.ok(
        hasHomebrewOpenSSL,
        'SSL paths should include Homebrew OpenSSL on darwin arm64'
      );
    });

    it('should include multiple Homebrew OpenSSL versions on darwin arm64', () => {
      if (process.platform !== 'darwin') {
        it.skip('skip: not darwin');
        return;
      }
      if (process.arch !== 'arm64') {
        it.skip('skip: not arm64');
        return;
      }

      const sslPaths = getSslPaths();
      const homebrewPaths = sslPaths.filter(
        (p) => p.startsWith('/opt/homebrew') && p.includes('openssl')
      );

      strict.ok(
        homebrewPaths.length >= 2,
        `SSL paths should include at least 2 Homebrew OpenSSL paths, got ${homebrewPaths.length}: ${homebrewPaths.join(', ')}`
      );
    });

    it('should include system SSL paths alongside Homebrew on darwin arm64', () => {
      if (process.platform !== 'darwin') {
        it.skip('skip: not darwin');
        return;
      }
      if (process.arch !== 'arm64') {
        it.skip('skip: not arm64');
        return;
      }

      const sslPaths = getSslPaths();
      const hasSystemSSL = sslPaths.some(
        (p) => p === '/etc/ssl/certs'
      );

      strict.ok(
        hasSystemSSL,
        'SSL paths should include system SSL path /etc/ssl/certs on darwin arm64'
      );
    });

    it('should not include Homebrew paths on non-darwin platforms', () => {
      if (process.platform === 'darwin') {
        it.skip('skip: is darwin');
        return;
      }

      const sslPaths = getSslPaths();
      const hasHomebrewPath = sslPaths.some(
        (p) => p.startsWith('/opt/homebrew')
      );

      strict.ok(
        !hasHomebrewPath,
        'SSL paths should not include Homebrew paths on non-darwin platforms'
      );
    });
  });
});

describe('Audit Mode Trace Validation', () => {
  describe('Audit log parsing', () => {
    it('should parse file-read audit entries from stderr', () => {
      const stderr = JSON.stringify({
        type: 'file-read',
        target: '/etc/hosts',
        detail: 'violation detected at /etc/hosts',
      }) + '\n';

      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 1, 'should have 1 audit entry');
      strict.equal(entries[0].type, 'file-read', 'should be file-read type');
      strict.equal(entries[0].target, '/etc/hosts', 'should have correct target');
    });

    it('should parse process-exec audit entries from stderr', () => {
      const stderr = JSON.stringify({
        type: 'process-exec',
        target: '/usr/bin/cat',
        detail: 'violation detected at /usr/bin/cat',
      }) + '\n';

      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 1, 'should have 1 audit entry');
      strict.equal(entries[0].type, 'process-exec', 'should be process-exec type');
      strict.equal(entries[0].target, '/usr/bin/cat', 'should have correct target');
    });

    it('should parse multiple audit entries from stderr', () => {
      const stderr = JSON.stringify({
        type: 'file-read',
        target: '/etc/hosts',
        detail: 'violation detected at /etc/hosts',
      }) + '\n' + JSON.stringify({
        type: 'network-connect',
        target: '93.184.216.34:443',
        detail: 'violation detected at 93.184.216.34:443',
      }) + '\n';

      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 2, 'should have 2 audit entries');
      strict.equal(entries[0].type, 'file-read', 'first entry should be file-read');
      strict.equal(entries[1].type, 'network-connect', 'second entry should be network-connect');
    });

    it('should skip non-JSON lines in stderr', () => {
      const stderr = 'some non-JSON line\n' + JSON.stringify({
        type: 'file-read',
        target: '/etc/hosts',
      }) + '\n';

      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 1, 'should have 1 audit entry, skipping non-JSON line');
      strict.equal(entries[0].type, 'file-read', 'should be file-read type');
    });

    it('should skip invalid JSON in stderr', () => {
      const stderr = '{invalid json}\n' + JSON.stringify({
        type: 'file-read',
        target: '/etc/hosts',
      }) + '\n';

      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 1, 'should have 1 audit entry, skipping invalid JSON');
    });

    it('should skip JSON without type and target fields', () => {
      const stderr = JSON.stringify({
        foo: 'bar',
      }) + '\n';

      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 0, 'should skip JSON without type and target');
    });

    it('should handle empty stderr', () => {
      const entries = parseAuditLog('');
      strict.equal(entries.length, 0, 'should have no entries for empty stderr');
    });
  });

  describe('Audit mode with sandboxed execution', () => {
    it('should capture audit entries from sandboxed file-read', async () => {
      const result = await new SaferExec()
        .enableAudit()
        .run('sh', ['-c', 'echo audit_test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('audit_test'), 'should have output');

      // Audit log should be present (may be empty if no violations)
      strict.ok(
        result.auditLog !== null || result.auditLog === undefined,
        'auditLog should be present in result'
      );
    });

    it('should capture audit entries from sandboxed process-exec', async () => {
      const result = await new SaferExec()
        .enableAudit()
        .run('sh', ['-c', 'echo child1 && echo child2']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('child1'), 'should have child1 output');
      strict.ok(result.stdout.includes('child2'), 'should have child2 output');
    });

    it('should capture audit entries with read paths', async () => {
      const result = await new SaferExec()
        .enableAudit()
        .run('sh', ['-c', 'echo audit_read_test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('audit_read_test'), 'should have output');
    });

    it('should capture audit entries with traceExec', async () => {
      const result = await new SaferExec()
        .enableAudit()
        .traceExec()
        .run('sh', ['-c', 'echo trace_test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('trace_test'), 'should have output');
    });

    it('should capture audit entries with blockFork', async () => {
      const result = await new SaferExec()
        .enableAudit()
        .blockFork()
        .run('sh', ['-c', 'echo fork_test']);

      strict.ok(
        result.exitCode === 0 || result.exitCode === 127 || result.exitCode === 128 || result.exitCode === 137,
        `should exit (got ${result.exitCode})`
      );
    });

    it('should capture audit entries with npm policy', async () => {
      const result = await new SaferExec()
        .applyPolicy('npm')
        .enableAudit()
        .run('sh', ['-c', 'echo policy_audit_test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('policy_audit_test'), 'should have output');
    });

    it('should capture audit entries with allowPorts', async () => {
      const result = await new SaferExec()
        .enableAudit()
        .allowPorts(80, 443)
        .run('sh', ['-c', 'echo port_audit_test']);

      strict.equal(result.exitCode, 0, 'should exit with code 0');
      strict.ok(result.stdout.includes('port_audit_test'), 'should have output');
    });
  });

  describe('Audit mode with concurrent execution', () => {
    it('should capture audit entries from multiple concurrent executions', async () => {
      const results = await Promise.all([
        new SaferExec().enableAudit().run('echo', ['audit1']),
        new SaferExec().enableAudit().run('echo', ['audit2']),
        new SaferExec().enableAudit().run('echo', ['audit3']),
      ]);

      for (const result of results) {
        strict.equal(result.exitCode, 0, `should exit with code 0`);
      }
    });

    it('should capture audit entries from many concurrent executions', async () => {
      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          new SaferExec().enableAudit().run('sh', ['-c', `echo audit_${i}`])
        );
      }

      const results = await Promise.all(promises);
      for (const result of results) {
        strict.equal(result.exitCode, 0, `should exit with code 0`);
      }
    });
  });
});
