import { describe, it, before } from 'node:test';
import strict from 'node:assert/strict';
import { writeFileSync, unlinkSync, copyFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SaferExec } from '../npm/src/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// This test requires Linux and root/CAP_BPF privileges.
const isLinux = process.platform === 'linux';
const isRoot = process.env.USER === 'root' || process.getuid?.() === 0;

describe('HTTP Tracing Integration Tests', { skip: !isLinux || !isRoot }, () => {
  before(() => {
    if (isLinux && isRoot) {
      try {
        // Resolve the compiled Go binary and install it to /usr/local/bin/safer-exec
        // to bypass AppArmor unshare execution restrictions on home directories.
        const localBinary = join(__dirname, '..', 'go', 'bin', 'safer-exec');
        if (existsSync(localBinary)) {
          copyFileSync(localBinary, '/usr/local/bin/safer-exec');
        } else {
          // Check other compiled targets if standard path is missing
          const platformArchBinary = join(__dirname, '..', 'go', 'bin', `safer-exec-linux-amd64`);
          if (existsSync(platformArchBinary)) {
            copyFileSync(platformArchBinary, '/usr/local/bin/safer-exec');
          }
        }
      } catch (err) {
        console.error('safer-exec test setup: failed to copy binary to /usr/local/bin:', err);
      }
    }
  });

  it('should trace HTTP request from Node.js script', async () => {
    const scriptPath = '/tmp/tmp_test_http.js';
    writeFileSync(scriptPath, `
      import https from 'node:https';
      https.get('https://registry.npmjs.org/', (res) => {
        res.resume();
      });
    `);

    try {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .traceHTTPURLs()
        .enableAudit();

      // Listen for audit events
      const events = [];
      exec.on('audit', (entry) => {
        if (entry.type === 'http-request') {
          events.push(entry);
        }
      });

      const result = await exec.run(process.execPath, [scriptPath]);
      strict.equal(
        result.exitCode,
        0,
        `Node script should exit successfully, got exitCode: ${result.exitCode}. Stderr: ${result.stderr}, Stdout: ${result.stdout}`
      );

      // Allow brief time for eBPF ring buffer to flush
      await new Promise(resolve => setTimeout(resolve, 250));

      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'Should find HTTP trace for registry.npmjs.org');
      strict.equal(trace.protocol, 'https', 'Protocol should be https');
      strict.equal(trace.port, 443, 'Port should be 443');
      strict.equal(trace.method, 'GET', 'Method should be GET');
    } finally {
      try { unlinkSync(scriptPath); } catch {}
    }
  });

  it('should trace HTTP request from Python script', async () => {
    const scriptPath = '/tmp/tmp_test_http.py';
    writeFileSync(scriptPath, `
import urllib.request
import ssl
import sys
try:
    context = ssl._create_unverified_context()
    urllib.request.urlopen('https://registry.npmjs.org/search?q=test', context=context)
except Exception as e:
    print("PYTHON_URL_ERROR:", e, file=sys.stderr)
`);

    try {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec')
        .allowHosts('registry.npmjs.org')
        .traceHTTPURLs()
        .enableAudit();

      const events = [];
      exec.on('audit', (entry) => {
        if (entry.type === 'http-request') {
          events.push(entry);
        }
      });

      const result = await exec.run('python3', [scriptPath]);
      console.log('PYTHON RUN RESULT:', { exitCode: result.exitCode, stderr: result.stderr, stdout: result.stdout });
      console.log('PYTHON CAPTURED EVENTS:', events);
      strict.equal(
        result.exitCode,
        0,
        `Python script should exit successfully, got exitCode: ${result.exitCode}. Stderr: ${result.stderr}, Stdout: ${result.stdout}`
      );

      // Allow brief time for eBPF ring buffer to flush
      await new Promise(resolve => setTimeout(resolve, 250));

      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'Should find HTTP trace for registry.npmjs.org');
      strict.equal(trace.protocol, 'https', 'Protocol should be https');
      strict.equal(trace.port, 443, 'Port should be 443');
      strict.equal(trace.method, 'GET', 'Method should be GET');
      strict.equal(trace.path, '/search', 'Path should be /search');
      strict.equal(trace.query, 'q=test', 'Query string should be q=test');
    } finally {
      try { unlinkSync(scriptPath); } catch {}
    }
  });
});
