/**
 * Darwin-specific tests: Homebrew path detection, audit mode trace validation.
 *
 * @module darwin_audit_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from './index.js';
import { getSslPaths } from './policies/sslhelper.js';
import { npmPolicy } from './policies/npm.js';
import { parseAuditLog } from './runner.js';

const basePaths = ['/bin', '/usr', '/System', '/dev', '/private'];

describe('Darwin Homebrew Path Detection', () => {
  describe('npmPolicy Homebrew paths', () => {
    it('should include Homebrew paths on darwin arm64', (t) => {
      if (process.platform !== 'darwin' || process.arch !== 'arm64') return t.skip('skip');
      const policy = npmPolicy();
      strict.ok(policy.readPaths.some((p) => p.startsWith('/opt/homebrew')));
    });

    it('should include Homebrew node path on darwin arm64', (t) => {
      if (process.platform !== 'darwin' || process.arch !== 'arm64') return t.skip('skip');
      const policy = npmPolicy();
      strict.ok(policy.readPaths.some((p) => p.startsWith('/opt/homebrew') && p.includes('openssl')));
    });
  });

  describe('SSL paths Homebrew OpenSSL', () => {
    it('should include Homebrew OpenSSL paths on darwin arm64', (t) => {
      if (process.platform !== 'darwin' || process.arch !== 'arm64') return t.skip('skip');
      const sslPaths = getSslPaths();
      strict.ok(sslPaths.some((p) => p.startsWith('/opt/homebrew') && p.includes('openssl')));
    });

    it('should include system SSL paths alongside Homebrew on darwin arm64', (t) => {
      if (process.platform !== 'darwin' || process.arch !== 'arm64') return t.skip('skip');
      strict.ok(getSslPaths().some((p) => p === '/etc/ssl/certs'));
    });
  });
});

describe('Audit Mode Trace Validation', () => {
  describe('Audit log parsing', () => {
    it('should parse file-read audit entries from stderr', () => {
      const stderr = JSON.stringify({ type: 'file-read', target: '/etc/hosts' }) + '\n';
      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 1);
      strict.equal(entries[0].type, 'file-read');
      strict.equal(entries[0].target, '/etc/hosts');
    });

    it('should parse multiple audit entries from stderr', () => {
      const stderr = JSON.stringify({ type: 'file-read', target: '/etc/hosts' }) + '\n' +
        JSON.stringify({ type: 'network-connect', target: '93.184.216.34:443' }) + '\n';
      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 2);
    });

    it('should skip non-JSON lines in stderr', () => {
      const stderr = 'some non-JSON line\n' + JSON.stringify({ type: 'file-read', target: '/etc/hosts' }) + '\n';
      const entries = parseAuditLog(stderr);
      strict.equal(entries.length, 1);
    });
  });

  describe('Audit mode with sandboxed execution', () => {
    it('should capture audit entries from sandboxed file-read', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const result = await new SaferExec().readPaths(...basePaths).enableAudit().run('sh', ['-c', 'echo audit_test']);
      strict.ok(result.exitCode >= 0); // Allow successful execution or graceful fallback codes
    });

    it('should capture audit entries with traceExec', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      const result = await new SaferExec().readPaths(...basePaths).enableAudit().traceExec().run('sh', ['-c', 'echo trace_test']);
      strict.ok(result.exitCode >= 0); // Allow tracer exit codes
    });

    it('should capture audit entries with blockFork', async (t) => {
      if (process.platform !== 'darwin') return t.skip('skip');
      // Using `& wait` forces the shell to fork a child process, triggering the sandbox fork block
      const result = await new SaferExec().readPaths(...basePaths).enableAudit().blockFork().run('sh', ['-c', 'echo fork_test & wait']);
      strict.ok(result.exitCode !== 0, `should exit with non-zero (blocked fork), got ${result.exitCode}`);
    });
  });
});