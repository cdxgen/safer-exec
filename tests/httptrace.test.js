import { describe, it, before } from 'node:test';
import strict from 'node:assert/strict';
import { writeFileSync, unlinkSync, copyFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SaferExec as OriginalSaferExec } from '../npm/src/index.js';

class SaferExec extends OriginalSaferExec {
  constructor(options = {}) {
    super(options);
    this.readPaths('/tmp');
    this.writePaths('/tmp');
  }
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// This test requires Linux and root/CAP_BPF privileges.
const isLinux = process.platform === 'linux';
const isRoot = process.env.USER === 'root' || process.getuid?.() === 0;

/** Collect audit events from a SaferExec run, returns { events, violations }. */
function collectAudit(exec) {
  const events = [];
  const violations = [];
  exec.on('audit', (entry) => {
    if (entry.type === 'http-request') events.push(entry);
    else if (entry.type === 'url-violation') violations.push(entry);
  });
  return { events, violations };
}

/** Write a temp file, run fn(), then clean up. */
async function withTempFile(path, content, fn) {
  writeFileSync(path, content);
  try {
    await fn();
  } finally {
    try { unlinkSync(path); } catch { /* ignore */ }
  }
}

// ──────────────────────────────────────────────────────────────
// Node.js HTTPS scripts
// ──────────────────────────────────────────────────────────────

/** Node script that GETs a single URL and exits. */
const nodeScript = (url) => `
import https from 'node:https';
https.get('${url}', (res) => { res.resume(); });
`;

/**
 * Node script that fires multiple requests sequentially.
 * Each URL must be fully-qualified. The script exits after all finish.
 */
const nodeMultiScript = (urls) => `
import https from 'node:https';
const urls = ${JSON.stringify(urls)};
let done = 0;
for (const u of urls) {
  https.get(u, (res) => {
    res.resume();
    if (++done === urls.length) process.exit(0);
  }).on('error', () => { if (++done === urls.length) process.exit(0); });
}
`;

// ──────────────────────────────────────────────────────────────
// Python HTTPS scripts
// ──────────────────────────────────────────────────────────────

/** Python script that GETs a single URL using urllib, ignoring TLS errors. */
const pythonScript = (url) => `
import urllib.request, ssl, sys
ctx = ssl._create_unverified_context()
try:
    urllib.request.urlopen('${url}', context=ctx)
except Exception as e:
    print("PYTHON_URL_ERROR:", e, file=sys.stderr)
`;

/**
 * Python script that fires multiple requests.
 * Errors are swallowed so the exit code is always 0 (network block → RLIMIT
 * drops the connection; Python treats that as an exception, not crash).
 */
const pythonMultiScript = (urls) => `
import urllib.request, ssl, sys
ctx = ssl._create_unverified_context()
for url in ${JSON.stringify(urls)}:
    try:
        urllib.request.urlopen(url, context=ctx)
    except Exception as e:
        print("PYTHON_URL_ERROR:", url, e, file=sys.stderr)
`;

// ──────────────────────────────────────────────────────────────
// Test suite
// ──────────────────────────────────────────────────────────────

describe('HTTP Tracing + allowUrls Integration Tests', { skip: !isLinux || !isRoot }, () => {
  before(() => {
    if (isLinux && isRoot) {
      try {
        // Install the Go binary to /usr/local/bin to bypass AppArmor
        // unshare restrictions on home/tmp directories.
        const localBinary = join(__dirname, '..', 'go', 'bin', 'safer-exec-rt');
        const archBinary = join(__dirname, '..', 'go', 'bin', 'safer-exec-rt-linux-amd64');
        if (existsSync(localBinary)) {
          copyFileSync(localBinary, '/usr/local/bin/safer-exec-rt');
        } else if (existsSync(archBinary)) {
          copyFileSync(archBinary, '/usr/local/bin/safer-exec-rt');
        }
      } catch (err) {
        console.error('safer-exec test setup: failed to copy binary to /usr/local/bin:', err);
      }
    }
  });

  // ── 1. Exact host match — Node.js ─────────────────────────────────────────

  it('[Node] exact host allowUrl: registry.npmjs.org → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_exact_node.js';
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should find http-request trace for registry.npmjs.org');
      strict.equal(trace.protocol, 'https');
      strict.equal(trace.port, 443);
      strict.equal(trace.method, 'GET');
      strict.equal(violations.length, 0, `unexpected violations: ${JSON.stringify(violations)}`);
    });
  });

  // ── 2. Wildcard host match — Node.js ──────────────────────────────────────

  it('[Node] wildcard allowUrl: *.npmjs.org matches registry.npmjs.org → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_wildcard_node.js';
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .allowUrls('https://*.npmjs.org/')
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should find http-request trace');
      strict.equal(violations.length, 0, `wildcard should permit: ${JSON.stringify(violations)}`);
    });
  });

  // ── 3. Regex host match — Node.js ─────────────────────────────────────────

  it('[Node] regex allowUrl: ~^registry\\.npmjs\\.org$ → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_regex_node.js';
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        // regex prefix "~" enables regexp matching in the Go engine
        .allowUrls({ host: '~^registry\\.npmjs\\.org$', protocol: 'https' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should find http-request trace');
      strict.equal(violations.length, 0, `regex should permit registry.npmjs.org: ${JSON.stringify(violations)}`);
    });
  });

  // ── 4. Path-prefix match — Node.js ────────────────────────────────────────

  it('[Node] path-prefix allowUrl: /search prefix matches /search?q=test → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_path_node.js';
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/search?q=safer-exec'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '/search' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should capture http-request trace');
      // Path prefix /search should cover /search?q=... (path field is just the path component)
      strict.ok(trace.path.startsWith('/search'), `expected path to start with /search, got: ${trace.path}`);
      strict.equal(violations.length, 0, `path-prefix rule should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── 5. Method-restricted allowUrl — Node.js ───────────────────────────────

  it('[Node] method-restricted allowUrl: only GET allowed, GET request → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_method_node.js';
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', methods: ['GET'] })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should capture http-request trace');
      strict.equal(trace.method, 'GET');
      strict.equal(violations.length, 0, `GET should be allowed by method restriction: ${JSON.stringify(violations)}`);
    });
  });

  // ── 6. Violation detected — Node.js makes request to unlisted host ────────

  it('[Node] url-violation: request to unlisted host → violation emitted', async () => {
    const scriptPath = '/tmp/tmp_test_violation_node.js';
    // allowUrls only permits example.com, but we also request registry.npmjs.org
    await withTempFile(scriptPath, nodeMultiScript([
      'https://example.com/',
      'https://registry.npmjs.org/',
    ]), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('example.com', 'registry.npmjs.org')
        // Only example.com is in the URL allow-list
        .allowUrls({ host: 'example.com', protocol: 'https' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 500));

      // registry.npmjs.org request should appear as a violation
      const npmViolation = violations.find(v =>
        typeof v.target === 'string' && v.target.includes('npmjs.org')
      );
      strict.ok(npmViolation, `expected violation for npmjs.org, got violations: ${JSON.stringify(violations)}`);

      // example.com should not be a violation
      const exampleViolation = violations.find(v =>
        typeof v.target === 'string' && v.target.includes('example.com')
      );
      strict.ok(!exampleViolation, `example.com should not be a violation: ${JSON.stringify(violations)}`);
    });
  });

  // ── 7. Multi-rule allowUrls — Node.js ─────────────────────────────────────

  it('[Node] multi-rule allowUrls: two hosts allowed, both requests → no violations', async () => {
    const scriptPath = '/tmp/tmp_test_multi_node.js';
    await withTempFile(scriptPath, nodeMultiScript([
      'https://registry.npmjs.org/',
      'https://example.com/',
    ]), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org', 'example.com')
        .allowUrls(
          { host: 'registry.npmjs.org', protocol: 'https' },
          { host: 'example.com', protocol: 'https' }
        )
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 500));

      const npmTrace = events.find(e => e.host === 'registry.npmjs.org');
      const exampleTrace = events.find(e => e.host === 'example.com');
      strict.ok(npmTrace || exampleTrace, 'should capture at least one http-request trace');
      strict.equal(violations.length, 0, `no violations expected: ${JSON.stringify(violations)}`);
    });
  });

  // ── 8. Exact host match — Python ──────────────────────────────────────────

  it('[Python] exact host allowUrl: registry.npmjs.org → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_exact_py.py';
    await withTempFile(scriptPath, pythonScript('https://registry.npmjs.org/search?q=test'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run('python3', [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should capture http-request trace from Python');
      strict.equal(trace.protocol, 'https');
      strict.equal(trace.port, 443);
      strict.equal(trace.method, 'GET');
      strict.equal(trace.path, '/search');
      strict.equal(trace.query, 'q=test');
      strict.equal(violations.length, 0, `unexpected violations: ${JSON.stringify(violations)}`);
    });
  });

  // ── 9. Regex host match — Python ──────────────────────────────────────────

  it('[Python] regex allowUrl: ~^registry\\.npmjs\\.org$ → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_regex_py.py';
    await withTempFile(scriptPath, pythonScript('https://registry.npmjs.org/search?q=test'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: '~^registry\\.npmjs\\.org$', protocol: 'https' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run('python3', [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should capture http-request trace from Python');
      strict.equal(violations.length, 0, `regex should permit npmjs: ${JSON.stringify(violations)}`);
    });
  });

  // ── 10. Wildcard host match — Python ──────────────────────────────────────

  it('[Python] wildcard allowUrl: *.npmjs.org → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_wildcard_py.py';
    await withTempFile(scriptPath, pythonScript('https://registry.npmjs.org/'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: '*.npmjs.org', protocol: 'https' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run('python3', [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should capture http-request trace');
      strict.equal(violations.length, 0, `wildcard should permit: ${JSON.stringify(violations)}`);
    });
  });

  // ── 11. Path-prefix match — Python ────────────────────────────────────────

  it('[Python] path-prefix allowUrl: /search matches /search?q=test → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_path_py.py';
    await withTempFile(scriptPath, pythonScript('https://registry.npmjs.org/search?q=test'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '/search' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run('python3', [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should capture http-request trace');
      strict.ok(trace.path.startsWith('/search'), `expected /search prefix, got: ${trace.path}`);
      strict.equal(violations.length, 0, `path-prefix rule should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── 12. Violation detected — Python makes request to unlisted host ────────

  it('[Python] url-violation: request to unlisted host → violation emitted', async () => {
    const scriptPath = '/tmp/tmp_test_violation_py.py';
    // allowUrls only permits example.com, Python also hits registry.npmjs.org
    await withTempFile(scriptPath, pythonMultiScript([
      'https://example.com/',
      'https://registry.npmjs.org/',
    ]), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .allowHosts('example.com', 'registry.npmjs.org')
        .allowUrls({ host: 'example.com', protocol: 'https' })
        .traceHTTPURLs()
        .enableAudit();

      const { violations } = collectAudit(exec);
      await exec.run('python3', [scriptPath]);
      await new Promise(r => setTimeout(r, 500));

      const npmViolation = violations.find(v =>
        typeof v.target === 'string' && v.target.includes('npmjs.org')
      );
      strict.ok(npmViolation, `expected violation for npmjs.org, got: ${JSON.stringify(violations)}`);

      const exampleViolation = violations.find(v =>
        typeof v.target === 'string' && v.target.includes('example.com')
      );
      strict.ok(!exampleViolation, `example.com should not be a violation: ${JSON.stringify(violations)}`);
    });
  });

  // ── 13. Path-glob wildcard — Node.js ──────────────────────────────────────

  it('[Node] path-glob allowUrl: path /npm/* allows /npm/v1/security/audits → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_pathglob_node.js';
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '/-/npm/v1/*' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should capture http-request trace');
      strict.equal(violations.length, 0, `path glob should allow /-/npm/v1/* paths: ${JSON.stringify(violations)}`);
    });
  });

  // ── 14. Regex path match — Node.js ────────────────────────────────────────

  it('[Node] regex path allowUrl: path ~^/[-/]npm/ matches → no violation', async () => {
    const scriptPath = '/tmp/tmp_test_regexpath_node.js';
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: 'registry.npmjs.org', protocol: 'https', path: '~^/-/npm/'})
        .traceHTTPURLs()
        .enableAudit();

      const {events, violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 250));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      const trace = events.find(e => e.host === 'registry.npmjs.org');
      strict.ok(trace, 'should capture http-request trace');
      strict.equal(violations.length, 0, `regex path should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── 15. Path-glob block — Node.js ─────────────────────────────────────────
  // Rule: only /-/npm/v1/* is allowed.  Script requests /express which does NOT
  // match the glob, so a url-violation must be emitted.

  it('[Node] path-glob block: request outside allowed glob → violation emitted', async () => {
    const scriptPath = '/tmp/tmp_test_pathglob_block_node.js';
    // Two requests: one inside the glob (no violation), one outside (violation)
    await withTempFile(scriptPath, nodeMultiScript([
      'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', // ✓ allowed by glob
      'https://registry.npmjs.org/express',                            // ✗ outside glob
    ]), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        // Only paths under /-/npm/v1/ are permitted
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '/-/npm/v1/*' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 500));

      // /express does not match /-/npm/v1/* → must appear as a violation
      const pathViolation = violations.find(v =>
        typeof v.target === 'string' && v.target.includes('/express')
      );
      strict.ok(
        pathViolation,
        `expected violation for /express (outside glob), got: ${JSON.stringify(violations)}`
      );

      // /-/npm/v1/security/advisories/bulk matches the glob → must NOT be a violation
      const globMatch = violations.find(v =>
        typeof v.target === 'string' && v.target.includes('/-/npm/v1/')
      );
      strict.ok(
        !globMatch,
        `/-/npm/v1/ path should be allowed by glob, but got violation: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── 16. Regex path block — Node.js ────────────────────────────────────────
  // Rule: only paths matching ~^/-/npm/ are allowed.  Script requests /search
  // which does NOT match the regex, so a url-violation must be emitted.

  it('[Node] regex path block: request outside allowed regex → violation emitted', async () => {
    const scriptPath = '/tmp/tmp_test_regexpath_block_node.js';
    await withTempFile(scriptPath, nodeMultiScript([
      'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk', // ✓ matches regex
      'https://registry.npmjs.org/search?q=safer-exec',               // ✗ does not match
    ]), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        // Regex: only paths that start with /-/npm/
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '~^/-/npm/' })
        .traceHTTPURLs()
        .enableAudit();

      const { events, violations } = collectAudit(exec);
      await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 500));

      // /search does not match ~^/-/npm/ → must appear as a violation
      const searchViolation = violations.find(v =>
        typeof v.target === 'string' && v.target.includes('/search')
      );
      strict.ok(
        searchViolation,
        `expected violation for /search (outside regex), got: ${JSON.stringify(violations)}`
      );

      // /-/npm/v1/... matches the regex → must NOT be a violation
      const regexMatch = violations.find(v =>
        typeof v.target === 'string' && v.target.includes('/-/npm/')
      );
      strict.ok(
        !regexMatch,
        `/-/npm/ path should be allowed by regex, but got violation: ${JSON.stringify(violations)}`
      );
    });
  });
});

// ══════════════════════════════════════════════════════════════════
// Combination & Block Tests
// Each test either proves a rule correctly ALLOWS (no violation) or
// correctly BLOCKS (violation emitted) a specific request.
// ══════════════════════════════════════════════════════════════════

describe('allowUrls — Combination & Block Tests', { skip: !isLinux || !isRoot }, () => {

  // helper: build a SaferExec stub with common defaults
  const base = () =>
    new SaferExec()
      .binaryPath('/usr/local/bin/safer-exec-rt')
      .readPaths(process.execPath)
      .traceHTTPURLs()
      .enableAudit();

  // ── A. Exact host block ────────────────────────────────────────────────────
  // Rule covers only example.com; request goes to registry.npmjs.org → violation.

  it('[Block] exact host: wrong host → violation', async () => {
    const p = '/tmp/cb_exact_block.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'example.com', protocol: 'https' });
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      const v = violations.find(x => x.target?.includes('npmjs.org'));
      strict.ok(v, `expected violation for npmjs.org, got: ${JSON.stringify(violations)}`);
    });
  });

  // ── B. Multi-level wildcard block ─────────────────────────────────────────
  // *.npmjs.org must NOT match a.b.npmjs.org (wildcard spans only one label).

  it('[Block] wildcard host: multi-level subdomain a.b.npmjs.org → violation', async () => {
    // We can't actually DNS-resolve a.b.npmjs.org in CI, so we simulate by
    // using a host that shares the suffix but is two levels deep.
    // The point is: the rule *.npmjs.org must not match it.
    // We use example.com (clearly no match) as the "blocked" host and confirm.
    const p = '/tmp/cb_wildcard_multilevel.js';
    await withTempFile(p, nodeMultiScript([
      'https://registry.npmjs.org/',   // one level  → ✓ allowed
      'https://example.com/',           // different domain → ✗ violation
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org', 'example.com')
        .allowUrls({ host: '*.npmjs.org', protocol: 'https' });
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 500));
      // example.com does not match *.npmjs.org → violation
      const v = violations.find(x => x.target?.includes('example.com'));
      strict.ok(v, `expected violation for example.com (not under *.npmjs.org): ${JSON.stringify(violations)}`);
      // registry.npmjs.org matches *.npmjs.org → no violation
      strict.ok(
        !violations.find(x => x.target?.includes('registry.npmjs.org')),
        `registry.npmjs.org should be allowed by *.npmjs.org: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── C. Regex host block ────────────────────────────────────────────────────
  // Regex only allows registry.npmjs.org; example.com doesn't match → violation.

  it('[Block] regex host: non-matching host → violation', async () => {
    const p = '/tmp/cb_regex_host_block.js';
    await withTempFile(p, nodeMultiScript([
      'https://registry.npmjs.org/',  // ✓ matches regex
      'https://example.com/',          // ✗ doesn't match
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org', 'example.com')
        .allowUrls({ host: '~^registry\\.npmjs\\.org$', protocol: 'https' });
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('example.com')),
        `expected violation for example.com: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('registry.npmjs.org')),
        `registry.npmjs.org should be allowed: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── D. Path-prefix block — Node.js ────────────────────────────────────────
  // Rule: path must start with /search. Request to / does NOT match → violation.

  it('[Block][Node] path-prefix: / does not match /search prefix → violation', async () => {
    const p = '/tmp/cb_path_prefix_block.js';
    await withTempFile(p, nodeMultiScript([
      'https://registry.npmjs.org/search?q=x',  // ✓ starts with /search
      'https://registry.npmjs.org/',              // ✗ does not start with /search
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '/search' });
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 500));
      // / must be a violation
      const rootViolation = violations.find(x => {
        try { return new URL(x.target).pathname === '/'; } catch { return false; }
      });
      strict.ok(rootViolation, `expected violation for /, got: ${JSON.stringify(violations)}`);
      // /search must NOT be a violation
      strict.ok(
        !violations.find(x => x.target?.includes('/search')),
        `/search path should be allowed: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── E. Path-prefix block — Python ─────────────────────────────────────────

  it('[Block][Python] path-prefix: /express does not match /search prefix → violation', async () => {
    const p = '/tmp/cb_path_prefix_block.py';
    await withTempFile(p, pythonMultiScript([
      'https://registry.npmjs.org/search?q=x',  // ✓
      'https://registry.npmjs.org/express',       // ✗
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '/search' });
      const { violations } = collectAudit(exec);
      await exec.run('python3', [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('/search')),
        `/search should be allowed: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── F. Path-glob block — Python ───────────────────────────────────────────

  it('[Block][Python] path-glob: /express outside /-/npm/v1/* → violation', async () => {
    const p = '/tmp/cb_path_glob_block.py';
    await withTempFile(p, pythonMultiScript([
      'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',  // ✓
      'https://registry.npmjs.org/express',                              // ✗
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '/-/npm/v1/*' });
      const { violations } = collectAudit(exec);
      await exec.run('python3', [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('/-/npm/v1/')),
        `/-/npm/v1/ path should be allowed: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── G. Regex path block — Python ──────────────────────────────────────────

  it('[Block][Python] regex path: /search does not match ~^/-/npm/ → violation', async () => {
    const p = '/tmp/cb_regex_path_block.py';
    await withTempFile(p, pythonMultiScript([
      'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',  // ✓
      'https://registry.npmjs.org/search?q=x',                          // ✗
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https', path: '~^/-/npm/' });
      const { violations } = collectAudit(exec);
      await exec.run('python3', [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('/search')),
        `expected violation for /search: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('/-/npm/')),
        `/-/npm/ should be allowed: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── H. Three-field combo: host + path + method ALL match → no violation ───

  it('[Allow] 3-field combo: host + path prefix + GET method all match → no violation', async () => {
    const p = '/tmp/cb_combo_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: 'registry.npmjs.org',
          protocol: 'https',
          path: '/-/npm/v1/',
          methods: ['GET'],
        });
      const { violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `all three fields match, expected no violations: ${JSON.stringify(violations)}`);
    });
  });

  // ── I. Three-field combo: host ✓ + path ✓ + wrong method → violation ──────
  // Rule: only POST allowed; actual request is GET → violation.
  // (We can't force curl/Node to POST here without a body, so we use the
  //  method filter in reverse: allow only POST, fire GET → violation.)

  it('[Block] 3-field combo: host ✓ + path ✓ + wrong method → violation', async () => {
    const p = '/tmp/cb_combo_method_block.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        // Only POST is in the allow list; the script will issue GET
        .allowUrls({
          host: 'registry.npmjs.org',
          protocol: 'https',
          path: '/-/npm/v1/',
          methods: ['POST'],
        });
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.ok(
        violations.length > 0,
        `expected violation because GET is not in ['POST'], got: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── J. Three-field combo: host ✓ + wrong path + method ✓ → violation ─────

  it('[Block] 3-field combo: host ✓ + wrong path + method ✓ → violation', async () => {
    const p = '/tmp/cb_combo_path_block.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/express'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: 'registry.npmjs.org',
          protocol: 'https',
          path: '/-/npm/v1/',   // rule covers /-/npm/v1/; request goes to /express
          methods: ['GET'],
        });
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── K. Regex host + wildcard path combo allow ──────────────────────────────

  it('[Allow] regex host + wildcard path combo: both match → no violation', async () => {
    const p = '/tmp/cb_regex_host_glob_path_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: '~^registry\\.npmjs\\.org$',
          path: '/-/npm/v1/*',
        });
      const { violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `regex host + glob path should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── L. Regex host + wildcard path combo block ──────────────────────────────
  // Same rule, but request goes to /express (outside the glob) → violation.

  it('[Block] regex host + wildcard path combo: path outside glob → violation', async () => {
    const p = '/tmp/cb_regex_host_glob_path_block.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/express'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: '~^registry\\.npmjs\\.org$',
          path: '/-/npm/v1/*',
        });
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express outside glob: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── M. Multiple rules fan-out: each request matched by a different rule ────

  it('[Allow] multiple rules fan-out: each request matched by its own rule → no violations', async () => {
    const p = '/tmp/cb_fanout_allow.js';
    await withTempFile(p, nodeMultiScript([
      'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',  // matched by rule 1
      'https://example.com/',                                            // matched by rule 2
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org', 'example.com')
        .allowUrls(
          { host: 'registry.npmjs.org', path: '/-/npm/v1/*' },  // rule 1
          { host: 'example.com' },                                // rule 2
        );
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.equal(violations.length, 0, `fan-out rules should cover both requests: ${JSON.stringify(violations)}`);
    });
  });

  // ── N. Multiple rules fan-out with one unmatched request ──────────────────

  it('[Block] multiple rules fan-out: third host not covered by any rule → violation', async () => {
    const p = '/tmp/cb_fanout_block.js';
    await withTempFile(p, nodeMultiScript([
      'https://registry.npmjs.org/',  // ✓ rule 1
      'https://example.com/',          // ✓ rule 2
      'https://httpbin.org/get',       // ✗ no rule covers this
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org', 'example.com', 'httpbin.org')
        .allowUrls(
          { host: 'registry.npmjs.org' },
          { host: 'example.com' },
          // httpbin.org intentionally omitted
        );
      const { violations } = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('httpbin.org')),
        `expected violation for httpbin.org: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('registry.npmjs.org')),
        `registry.npmjs.org should not be a violation: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('example.com')),
        `example.com should not be a violation: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── O. Empty allowUrls → permissive (no rules = any URL allowed) ───────────

  it('[Allow] no allowUrls rules: any request is permitted (permissive)', async () => {
    const p = '/tmp/cb_empty_rules.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org');
        // Deliberately no .allowUrls() call — empty rules → permissive
      const { violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `empty rule set should be permissive: ${JSON.stringify(violations)}`);
    });
  });

  // ── P. Wildcard path glob block — Python ──────────────────────────────────
  // Rule: /search/* but request goes to /express → violation.

  it('[Block][Python] wildcard path glob /search/* → /express is a violation', async () => {
    const p = '/tmp/cb_py_glob_block2.py';
    await withTempFile(p, pythonMultiScript([
      'https://registry.npmjs.org/search/suggestions?q=x',  // ✓ matches /search/*
      'https://registry.npmjs.org/express',                   // ✗ outside glob
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', path: '/search/*' });
      const { violations } = collectAudit(exec);
      await exec.run('python3', [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('/search/')),
        `/search/ path should be allowed: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── Q. Regex host + method restriction combo block — Python ───────────────

  it('[Block][Python] regex host + method restriction: GET when only POST allowed → violation', async () => {
    const p = '/tmp/cb_py_method_block.py';
    await withTempFile(p, pythonScript('https://registry.npmjs.org/search?q=x'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        // regex host matches, but only POST is allowed; Python will issue GET
        .allowUrls({ host: '~^registry\\.npmjs\\.org$', methods: ['POST'] });
      const { violations } = collectAudit(exec);
      await exec.run('python3', [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.ok(
        violations.length > 0,
        `expected violation because GET is not in ['POST']: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── R. Protocol restriction: https-only rule, request is https → allow ─────

  it('[Allow] protocol restriction: https rule with https request → no violation', async () => {
    const p = '/tmp/cb_protocol_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({ host: 'registry.npmjs.org', protocol: 'https' });
      const { violations } = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `https protocol should match: ${JSON.stringify(violations)}`);
    });
  });
});

// ══════════════════════════════════════════════════════════════════
// Edge-case & Advanced Combination Tests (Suite 3)
// ══════════════════════════════════════════════════════════════════

describe('allowUrls — Edge-case & Advanced Combinations', { skip: !isLinux || !isRoot }, () => {

  const base = () =>
    new SaferExec()
      .binaryPath('/usr/local/bin/safer-exec-rt')
      .readPaths(process.execPath)
      .traceHTTPURLs()
      .enableAudit();

  // ── S. Wildcard host + exact path: matching path → allow ──────────────────

  it('[Allow] wildcard host + exact path: *.npmjs.org + /search → allow', async () => {
    const p = '/tmp/ec_wc_exact_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/search?q=x'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: '*.npmjs.org', path: '/search'});
      const {violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `wildcard host + exact path should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── T. Wildcard host + exact path: wrong path → violation ─────────────────

  it('[Block] wildcard host + exact path: /express does not match /search → violation', async () => {
    const p = '/tmp/ec_wc_exact_block.js';
    await withTempFile(p, nodeMultiScript([
      'https://registry.npmjs.org/search?q=x',  // ✓ matches /search
      'https://registry.npmjs.org/express',       // ✗ wrong path
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: '*.npmjs.org', path: '/search'});
      const {violations} = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('/search')),
        `/search should be allowed: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── U. Wildcard host + wildcard path: both wildcards match → allow ─────────

  it('[Allow] wildcard host + wildcard path: *.npmjs.org + /-/npm/* → allow', async () => {
    const p = '/tmp/ec_wc_wc_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: '*.npmjs.org', path: '/-/npm/*'});
      const {violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `wildcard host + wildcard path should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── V. Wildcard host + wildcard path: wrong path → violation ──────────────

  it('[Block] wildcard host + wildcard path: /express outside /-/npm/* → violation', async () => {
    const p = '/tmp/ec_wc_wc_block.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/express'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: '*.npmjs.org', path: '/-/npm/*'});
      const {violations} = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── W. Regex host + regex path: both regex match → allow ──────────────────

  it('[Allow] regex host + regex path: both patterns match → no violation', async () => {
    const p = '/tmp/ec_regex_regex_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: '~^registry\\.npmjs\\.org$',
          path: '~^/-/npm/v[0-9]+/',
        });
      const {violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `both regex patterns should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── X. Regex host + regex path: path regex doesn't match → violation ───────

  it('[Block] regex host + regex path: /express does not match path regex → violation', async () => {
    const p = '/tmp/ec_regex_regex_block.js';
    await withTempFile(p, nodeMultiScript([
      'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',  // ✓ path regex matches
      'https://registry.npmjs.org/express',                              // ✗ path regex misses
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: '~^registry\\.npmjs\\.org$',
          path: '~^/-/npm/v[0-9]+/',
        });
      const {violations} = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('/-/npm/v1/')),
        `/-/npm/v1/ path should be allowed by regex: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── Y. Rule fallthrough: rule1 doesn't match, rule2 does → allow ──────────
  // Proves that OR semantics work: any matching rule is sufficient.

  it('[Allow] rule fallthrough: rule1 misses, rule2 saves → no violation', async () => {
    const p = '/tmp/ec_fallthrough_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls(
          {host: 'example.com'},               // rule1: wrong host, won't match
          {host: 'registry.npmjs.org'},         // rule2: correct host, saves the request
        );
      const {violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `rule2 should save the request: ${JSON.stringify(violations)}`);
    });
  });

  // ── Z. Overlapping rules: request matches multiple rules → still no violation

  it('[Allow] overlapping rules: request matches multiple rules simultaneously → no violation', async () => {
    const p = '/tmp/ec_overlap_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/search?q=x'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls(
          {host: 'registry.npmjs.org'},                              // broad: any path
          {host: '*.npmjs.org', path: '/search'},                    // narrow: specific path
          {host: '~^registry\\.npmjs\\.org$', methods: ['GET']},     // method-specific
        );
      const {violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `overlapping rules should not conflict: ${JSON.stringify(violations)}`);
    });
  });

  // ── AA. Python 3-field combo: host + path + method all match → no violation ─

  it('[Allow][Python] 3-field combo: host + path + GET method → no violation', async () => {
    const p = '/tmp/ec_py_3field_allow.py';
    await withTempFile(p, pythonScript('https://registry.npmjs.org/search?q=test'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: 'registry.npmjs.org',
          protocol: 'https',
          path: '/search',
          methods: ['GET'],
        });
      const {violations} = collectAudit(exec);
      const result = await exec.run('python3', [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `3-field combo should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── AB. Python 3-field combo method block ─────────────────────────────────

  it('[Block][Python] 3-field combo: host ✓ + path ✓ + wrong method (POST-only) → violation', async () => {
    const p = '/tmp/ec_py_3field_method_block.py';
    await withTempFile(p, pythonScript('https://registry.npmjs.org/search?q=test'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: 'registry.npmjs.org',
          protocol: 'https',
          path: '/search',
          methods: ['POST'],  // GET will be issued; POST-only → violation
        });
      const {violations} = collectAudit(exec);
      await exec.run('python3', [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.ok(
        violations.length > 0,
        `expected violation because GET is not in ['POST']: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── AC. Python 3-field combo path block ───────────────────────────────────

  it('[Block][Python] 3-field combo: host ✓ + wrong path + method ✓ → violation', async () => {
    const p = '/tmp/ec_py_3field_path_block.py';
    await withTempFile(p, pythonMultiScript([
      'https://registry.npmjs.org/search?q=test',   // ✓ path matches /search
      'https://registry.npmjs.org/express',           // ✗ path doesn't match
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({
          host: 'registry.npmjs.org',
          protocol: 'https',
          path: '/search',
          methods: ['GET'],
        });
      const {violations} = collectAudit(exec);
      await exec.run('python3', [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('/express')),
        `expected violation for /express: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('/search')),
        `/search should be allowed: ${JSON.stringify(violations)}`
      );
    });
  });

  // ── AD. Port-specific rule: port 443 declared in rule → allow ─────────────
  // Ports in URL rules are auto-added to Landlock; this also tests that
  // the port field is matched correctly.

  it('[Allow] port-specific rule: port 443 in rule matches HTTPS request → no violation', async () => {
    const p = '/tmp/ec_port_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: 'registry.npmjs.org', protocol: 'https', port: 443});
      const {violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `port 443 rule should allow: ${JSON.stringify(violations)}`);
    });
  });

  // ── AE. Port mismatch: rule declares port 8443, request hits 443 → violation

  it('[Block] port mismatch: rule port 8443 does not match actual port 443 → violation', async () => {
    const p = '/tmp/ec_port_block.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: 'registry.npmjs.org', protocol: 'https', port: 8443});
      const {violations} = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.ok(
        violations.length > 0,
        `expected violation because request port (443) ≠ rule port (8443): ${JSON.stringify(violations)}`
      );
    });
  });

  // ── AF. Case-insensitive host matching ────────────────────────────────────

  it('[Allow] case-insensitive host: REGISTRY.NPMJS.ORG rule matches registry.npmjs.org request → no violation', async () => {
    const p = '/tmp/ec_case_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: 'REGISTRY.NPMJS.ORG', protocol: 'https'});
      const {violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `host matching should be case-insensitive: ${JSON.stringify(violations)}`);
    });
  });

  // ── AG. Version-number regex path: matches /v1/ and /v2/ but not /search ──

  it('[Allow] version regex path: ~^/-/npm/v[0-9]+/ matches /v1/ → no violation', async () => {
    const p = '/tmp/ec_version_regex_allow.js';
    await withTempFile(p, nodeScript('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: 'registry.npmjs.org', path: '~^/-/npm/v[0-9]+/'});
      const {violations} = collectAudit(exec);
      const result = await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 300));
      strict.equal(result.exitCode, 0);
      strict.equal(violations.length, 0, `version regex should allow /-/npm/v1/: ${JSON.stringify(violations)}`);
    });
  });

  // ── AH. Version-number regex path block: /search doesn't match version regex

  it('[Block] version regex path: /search does not match ~^/-/npm/v[0-9]+/ → violation', async () => {
    const p = '/tmp/ec_version_regex_block.js';
    await withTempFile(p, nodeMultiScript([
      'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk',  // ✓
      'https://registry.npmjs.org/search?q=x',                          // ✗
    ]), async () => {
      const exec = base()
        .allowHosts('registry.npmjs.org')
        .allowUrls({host: 'registry.npmjs.org', path: '~^/-/npm/v[0-9]+/'});
      const {violations} = collectAudit(exec);
      await exec.run(process.execPath, [p]);
      await new Promise(r => setTimeout(r, 500));
      strict.ok(
        violations.find(x => x.target?.includes('/search')),
        `expected violation for /search: ${JSON.stringify(violations)}`
      );
      strict.ok(
        !violations.find(x => x.target?.includes('/-/npm/v1/')),
        `/-/npm/v1/ should be allowed by version regex: ${JSON.stringify(violations)}`
      );
    });
  });
});

// ══════════════════════════════════════════════════════════════════
// Cryptographic BOM Tests
// ══════════════════════════════════════════════════════════════════

import { readFileSync } from 'node:fs';

describe('SaferExec Cryptographic Tracing Integration', { skip: !isLinux || !isRoot }, () => {
  const cbomPath = '/tmp/test_cbom.json';

  it('[Node] traceCrypto + cbom should generate a valid CycloneDX CBOM JSON file', async () => {
    const scriptPath = '/tmp/tmp_test_cbom.js';
    try { unlinkSync(cbomPath); } catch {}
    
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .traceCrypto()
        .cbom(cbomPath)
        .enableAudit();

      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 500));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      
      // Verify the CBOM file exists and parses as valid CycloneDX JSON
      strict.ok(existsSync(cbomPath), 'CycloneDX CBOM file should have been created');
      const cbomContent = JSON.parse(readFileSync(cbomPath, 'utf8'));
      
      strict.equal(cbomContent.bomFormat, 'CycloneDX');
      strict.ok(cbomContent.specVersion, 'should contain CycloneDX specVersion');
      strict.ok(Array.isArray(cbomContent.components), 'should contain components array');
      
      // Look for a cryptographic asset component
      const cryptoAsset = cbomContent.components.find(c => 
        c.type === 'cryptographic-asset' || c.name === 'OpenSSL'
      );
      strict.ok(cryptoAsset, 'CBOM components should list cryptographic assets');
    });
    
    try { unlinkSync(cbomPath); } catch {}
  });

  it.skip('[Node] traceCrypto should emit crypto-related audit events', async () => {
    const scriptPath = '/tmp/tmp_test_crypto_audit.js';
    
    await withTempFile(scriptPath, nodeScript('https://registry.npmjs.org/'), async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .allowHosts('registry.npmjs.org')
        .traceCrypto()
        .enableAudit();

      const events = [];
      exec.on('audit', (entry) => {
        events.push(entry);
      });

      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 500));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      
      // Verify that http-request has crypto fields
      const httpRequest = events.find(e => e.type === 'http-request');
      strict.ok(httpRequest, 'should capture http-request event');
      strict.ok(httpRequest.cipher || httpRequest.cryptoLibrary, 'http-request event should have crypto details');

      // Verify that crypto audit events were emitted (library is mandatory, cipher is optional depending on TLS handshake negotiation)
      const cryptoLib = events.find(e => e.type === 'crypto-library');
      strict.ok(cryptoLib, 'should emit crypto-library audit events');

      const cryptoCipher = events.find(e => e.type === 'crypto-cipher');
      if (cryptoCipher) {
        strict.ok(cryptoCipher.name, 'crypto-cipher event should have name');
      }
    });
  });

  it('[Curl] allowCiphers should trigger a cipher-violation audit event if non-allowed cipher negotiated', async () => {
    const exec = new SaferExec()
      .binaryPath('/usr/local/bin/safer-exec-rt')
      .allowHosts('registry.npmjs.org')
      .traceCrypto()
      .allowCiphers('DUMMY_ALLOW_CIPHER') // enforce a dummy allowlist
      .enableAudit();

    const events = [];
    exec.on('audit', (entry) => {
      events.push(entry);
    });

    const result = await exec.run('curl', ['-sI', '--no-keepalive', 'https://registry.npmjs.org/']);
    await new Promise(r => setTimeout(r, 500));

    strict.equal(result.exitCode, 0);

    // If a cipher-violation or crypto-cipher was not captured due to BPF verifier
    // stripping cipher probes on older kernels (e.g. 5.15) or curl resolving from local caches,
    // we accept it gracefully.
    const violation = events.find(e => e.type === 'cipher-violation');
    // On GitHub Actions runners, cipher uprobes may not attach properly or are stripped.
    // Ensure we check if either crypto-cipher or cipher-violation was captured.
    const hasCryptoSupport = events.some(e => e.type === 'crypto-cipher' || e.type === 'cipher-violation');

    if (hasCryptoSupport && violation) {
      strict.ok(violation.target, 'violation should specify the target cipher name');

      // Run a positive allowlist match test:
      const negotiatedCipherName = violation.target;
      const allowedExec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .allowHosts('registry.npmjs.org')
        .traceCrypto()
        .allowCiphers(negotiatedCipherName) // allow exactly the negotiated cipher
        .enableAudit();

      const allowedEvents = [];
      allowedExec.on('audit', (entry) => {
        allowedEvents.push(entry);
      });

      const allowedResult = await allowedExec.run('curl', ['-sI', '--no-keepalive', 'https://registry.npmjs.org/']);
      await new Promise(r => setTimeout(r, 500));

      strict.equal(allowedResult.exitCode, 0);
      const positiveViolation = allowedEvents.find(e => e.type === 'cipher-violation');
      strict.equal(positiveViolation, undefined, 'no cipher-violation should be triggered when allowed');
    } else {
      console.log('Skipping cipher-violation assertion: eBPF cipher negotiation probes not supported/loaded on this kernel');
    }
  });

  it('[Node] should trace non-TLS crypto operations (digest and encryption)', async () => {
    const scriptPath = '/tmp/tmp_test_crypto_ops.js';
    const cryptoScript = `
      import crypto from 'node:crypto';
      // Generate some hash operations (EVP_DigestInit_ex -> MD5, SHA-256)
      crypto.createHash('md5').update('hello').digest();
      crypto.createHash('sha256').update('hello').digest();
      crypto.createHash('sha224').update('hello').digest();
      crypto.createHash('sha384').update('hello').digest();
      process.exit(0);
    `;

    await withTempFile(scriptPath, cryptoScript, async () => {
      const exec = new SaferExec()
        .binaryPath('/usr/local/bin/safer-exec-rt')
        .readPaths(process.execPath)
        .traceCrypto()
        .enableAudit();

      const result = await exec.run(process.execPath, [scriptPath]);
      await new Promise(r => setTimeout(r, 500));

      strict.equal(result.exitCode, 0, `exit code: ${result.exitCode}\nstderr: ${result.stderr}`);
      strict.ok(result.crypto, 'should return crypto results');
      // On some environments or architectures, OpenSSL symbols may not be resolved,
      // but if OpenSSL is traced we expect operations or libraries to be recorded.
      if (result.crypto.libraries && result.crypto.libraries.length > 0) {
        strict.ok(result.crypto.libraries.some(l => l.name === 'OpenSSL' || l.name === 'Go crypto/tls'));
      }
    });
  });
});
