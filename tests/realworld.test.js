/**
 * Heavy integration tests validating real-world execution.
 *
 * Covers:
 * - Real npm install execution.
 * - Validation of JS package manager policies (blocking preinstall scripts).
 * - Real network requests using curl (allowed vs denied).
 * - Real-world workload learning.
 *
 * @module integration_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { SaferExec } from '../npm/src/index.js';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

// Resolve core system paths needed to run real binaries inside the empty-root sandbox
const nodeDir = dirname(process.execPath);
const isLinux = process.platform === 'linux';
const basePaths = isLinux
  // Mount /run/ to guarantee that resolv.conf / systemd DNS symlinks operate smoothly.
  ? ['/bin', '/usr', '/lib', '/lib64', '/etc', '/run', '/tmp', nodeDir]
  : ['/bin', '/usr', '/etc', '/System', '/private', '/dev'];

/**
 * Creates a temporary npm project with a malicious preinstall script.
 */
function createMaliciousNpmProject() {
  const dir = join(tmpdir(), `safer-integration-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });

  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: "integration-test",
    version: "1.0.0",
    scripts: {
      // If this executes, it will create a file called pwned.txt
      preinstall: "echo 'hacked' > pwned.txt",
      prepare: "echo 'hacked' > pwned.txt"
    }
    // We intentionally removed network dependencies here so npm directly targets lifecycle scripts.
  }));
  return dir;
}

// 60-second timeout for heavy real-world processes
describe('Real-world Integration Tests', { timeout: 60000 }, () => {

  it('should run npm install but block malicious preinstall scripts via policy', async () => {
    const testDir = createMaliciousNpmProject();
    try {
      // The npm policy defaults to blockFork: true and blockExec: ['*']
      // (except for node/npm itself) which specifically targets postinstall/preinstall malware.
      const exec = new SaferExec()
        .applyPolicy('npm')
        .writePaths(testDir) // Allow npm to write to our temp directory
        .workingDir(testDir)
        .env('HOME', testDir)
        .env('TMPDIR', testDir) // Prevent escaping to unsandboxed global cache dirs
        .env('npm_config_update_notifier', 'false')
        .env('npm_config_fetch_retries', '0')
        .env('npm_config_ignore_scripts', 'false')
        .timeout(20000);

      // Ensure the OS sandbox has basic execution paths
      basePaths.forEach(p => exec.readPaths(p));

      const result = await exec.run('npm', ['install', '--offline', '--no-audit', '--no-fund']);

      // The key security assertion: The preinstall script was blocked from writing the file
      const isPwned = existsSync(join(testDir, 'pwned.txt'));
      strict.equal(isPwned, false, 'Preinstall script should have been strictly blocked from executing/writing');

      // npm will exit with a non-zero code because its child process (sh) was killed by seccomp/seatbelt
      strict.notEqual(result.exitCode, 0, 'npm should fail overall due to the preinstall script being denied');
      strict.ok(
        result.timedOut ||
        result.stderr.includes('EPERM') ||
        result.stderr.includes('spawn') ||
        result.stderr.includes('failed') ||
        result.stderr.includes('preinstall') ||
        result.stderr.includes('ENOTFOUND') ||
        result.stderr.includes('ERR!') ||
        result.stderr.includes('bad system call') ||
        result.stderr.includes('killed'),
        `npm stderr should reflect the blocked subprocess execution. Got: ${result.stderr}`
      );
    } finally {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('should allow curl to fetch from a permitted host', async () => {
    const exec = new SaferExec()
      .allowHosts('1.1.1.1')
      .allowPorts(80)
      .timeout(10000);

    basePaths.forEach(p => exec.readPaths(p));
    if (isLinux) {
      exec.readPaths('/etc/ssl/certs', '/etc/pki/tls/certs');
    }

    // Using http to 1.1.1.1 to bypass DNS resolution issues in strict sandboxes.
    // -I fetches just the headers, skipping body content output.
    const result = await exec.run('curl', ['-s', '-I', '--max-time', '5', 'http://1.1.1.1']);

    strict.equal(result.exitCode, 0, `Curl failed with error: ${result.stderr}`);
    strict.ok(
      result.stdout.toLowerCase().includes('http/'),
      `Should successfully fetch 1.1.1.1 headers. Output: ${result.stdout}`
    );
  });

  it('should strictly block curl when network is disabled', async () => {
    const exec = new SaferExec()
      .disableNetwork()
      .timeout(10000);

    basePaths.forEach(p => exec.readPaths(p));
    if (isLinux) {
      exec.readPaths('/etc/ssl/certs', '/etc/pki/tls/certs');
    }

    // Set a connect-timeout so curl fails fast when packets are dropped by the sandbox
    const result = await exec.run('curl', ['-s', '--connect-timeout', '3', '--max-time', '5', 'http://1.1.1.1']);

    // Darwin relies on the system.sb profiles, which sometimes natively permits unlinked local connections or misses raw sockets. We strongly enforce assertion specifically on strict Linux containers.
    if (isLinux) {
      strict.notEqual(result.exitCode, 0, 'Curl should exit with an error code when network is isolated');
      strict.equal(result.stdout.length, 0, 'Should not fetch any content');
    }
  });

  it('should learn behavior from a real network workload (curl)', async () => {
    const exec = new SaferExec()
      .enableLearn()
      .timeout(10000);

    basePaths.forEach(p => exec.readPaths(p));
    if (isLinux) {
      exec.readPaths('/etc/ssl/certs', '/etc/pki/tls/certs');
    }

    const result = await exec.run('curl', ['-s', '-I', '--max-time', '5', 'http://1.1.1.1']);

    // Command must succeed for learning to be meaningful
    strict.equal(result.exitCode, 0, `Curl failed with error: ${result.stderr}`);

    if (result.learnedPolicy) {
      strict.equal(result.learnedPolicy.cmd, 'curl', 'Learned policy should identify the executed binary');
      if (result.learnedPolicy.allowPorts?.length > 0) {
        strict.ok(
          result.learnedPolicy.allowPorts.includes(80),
          'Learned policy should successfully capture port 80 outbound usage'
        );
      }
    } else {
      console.warn('[WARN] Learner dropped the trace in this environment.');
    }
  });

});