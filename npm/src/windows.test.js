/**
 * End-to-end tests for the Windows engine through the Node API and CLI:
 * Node.js -> safer-exec-rt.exe -> wxc-exec.exe (MXC) -> workload.
 *
 * Skipped on other platforms, and unless the engine reports MXC's
 * BaseContainer tier: no wxc-exec.exe, no BaseContainer API (older builds,
 * Windows Server), or a host where MXC would fall back to modifying file ACLs,
 * which the engine refuses without consent.
 * Workloads are Windows system tools (cmd.exe, curl.exe), which a container
 * can run without grants.
 *
 * @module windows_test
 */

import { describe, it, before } from 'node:test';
import strict from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SaferExec } from './index.js';
import { findOnWindowsPath } from './runner.js';

const isWindows = process.platform === 'win32';
const cliPath = join(dirname(fileURLToPath(import.meta.url)), 'cli.js');

let skipReason = isWindows ? '' : 'Windows only';

// realpathSync.native expands 8.3 short names (a runner's TEMP is often
// C:\Users\RUNNER~1\...), matching the long names the engine reports.
function workDir() {
  return realpathSync.native(mkdtempSync(join(tmpdir(), 'safer-exec-win-')));
}

function runCli(...args) {
  return new Promise((resolve) => {
    execFile(process.execPath, [cliPath, ...args], { timeout: 60000, windowsHide: true }, (err, stdout, stderr) => {
      resolve({ exitCode: err ? (err.code ?? 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

describe('Windows engine (MXC)', { skip: !isWindows && 'Windows only' }, () => {
  before(async () => {
    try {
      const info = await SaferExec.diagnostics();
      if (!info.features?.base_container || info.capabilities?.host_acl_mutation_required?.available) {
        skipReason = `MXC BaseContainer tier unavailable: ${JSON.stringify(info.capabilities?.mxc_probe ?? info.capabilities?.mxc_executor)}`;
      }
    } catch (err) {
      skipReason = `diagnostics failed: ${err.message}`;
    }
  });

  it('reports Windows diagnostics', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const info = await SaferExec.diagnostics();
    strict.equal(info.platform, 'windows');
    strict.equal(info.capabilities.mxc_executor.available, true);
    strict.equal(info.features.memory_limit, true);
  });

  it('runs a command and returns its output and exit code', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    try {
      const ok = await new SaferExec().workingDir(dir).run('cmd.exe', ['/c', 'echo hello-from-mxc']);
      strict.equal(ok.exitCode, 0, ok.stderr);
      strict.match(ok.stdout, /hello-from-mxc/);
      const fail = await new SaferExec().workingDir(dir).run('cmd.exe', ['/c', 'exit 9']);
      strict.equal(fail.exitCode, 9);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('confines writes to granted paths and diffs them', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    const outside = workDir();
    try {
      const target = join(dir, 'created.txt');
      const res = await new SaferExec()
        .workingDir(dir)
        .writePaths(dir)
        .enableDiff()
        .run('cmd.exe', ['/c', `echo data> "${target}"`]);
      strict.equal(res.exitCode, 0, res.stderr);
      strict.ok(existsSync(target));
      strict.ok(res.fsDiff?.added?.some((e) => e.path.toLowerCase() === target.toLowerCase()), JSON.stringify(res.fsDiff));

      const denied = join(outside, 'denied.txt');
      const blocked = await new SaferExec()
        .workingDir(dir)
        .writePaths(dir)
        .run('cmd.exe', ['/c', `echo data> "${denied}"`]);
      strict.notEqual(blocked.exitCode, 0);
      strict.ok(!existsSync(denied), 'write outside the grants must fail');
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it('hides ungranted files and reads granted ones', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    const data = workDir();
    try {
      const secret = join(data, 'secret.txt');
      writeFileSync(secret, 'top-secret');
      const hidden = await new SaferExec().workingDir(dir).run('cmd.exe', ['/c', `type "${secret}"`]);
      strict.notEqual(hidden.exitCode, 0);
      strict.doesNotMatch(hidden.stdout, /top-secret/);
      const granted = await new SaferExec().workingDir(dir).readPaths(data).run('cmd.exe', ['/c', `type "${secret}"`]);
      strict.equal(granted.exitCode, 0, granted.stderr);
      strict.match(granted.stdout, /top-secret/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(data, { recursive: true, force: true });
    }
  });

  it('blocks the network when disabled', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    const fetch = () => ['-sS', '-m', '10', '-o', 'NUL', 'http://example.com/'];
    try {
      // Control: the same request succeeds when the host is allowed, so the
      // failure below comes from the policy rather than the machine.
      const allowed = await new SaferExec().workingDir(dir).allowHosts('example.com').run('curl.exe', fetch());
      if (allowed.exitCode !== 0) {
        return t.skip(`no internet access for the control request: ${allowed.stderr.trim()}`);
      }
      const res = await new SaferExec().workingDir(dir).disableNetwork().run('curl.exe', fetch());
      // curl: 6 = could not resolve host, 7 = could not connect, 28 = timeout.
      strict.ok([6, 7, 28].includes(res.exitCode), `exit ${res.exitCode}: ${res.stderr}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('forbids child processes with blockFork and reports them with traceExec', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    try {
      const res = await new SaferExec()
        .workingDir(dir)
        .blockFork()
        .traceExec()
        .enableAudit()
        .run('cmd.exe', ['/c', 'cmd.exe /c echo nested-child']);
      strict.doesNotMatch(res.stdout, /nested-child/);
      strict.ok(res.auditLog.some((e) => e.type === 'process-exec'), JSON.stringify(res.auditLog));
      strict.ok(res.auditLog.some((e) => e.type === 'resource-limit'), JSON.stringify(res.auditLog));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('passes batch-file arguments literally', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    try {
      const script = join(dir, 'args.cmd');
      writeFileSync(script, '@echo off\r\necho ARG1=%1\r\necho ARG2=%2\r\n');
      const res = await new SaferExec().workingDir(dir).writePaths(dir).run(script, ['x&echo INJECTED', '%PATH%']);
      strict.equal(res.exitCode, 0, res.stderr);
      strict.doesNotMatch(res.stdout, /^INJECTED/m);
      strict.match(res.stdout, /ARG2="%PATH%"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('emits the MXC request as the profile dump', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    try {
      const res = await new SaferExec()
        .workingDir(dir)
        .writePaths(dir)
        .windowsBlockWin32k()
        .dumpProfile()
        .run('cmd.exe', ['/c', 'echo x']);
      strict.equal(res.exitCode, 0, res.stderr);
      const request = JSON.parse(res.profile);
      strict.equal(request.version, '1.0.0');
      strict.equal(request.containment, 'processcontainer');
      strict.equal(request.ui.disable, true);
      strict.deepEqual(request.filesystem.readwritePaths, [dir]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails strict runs that request unenforceable controls', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    try {
      const res = await new SaferExec().workingDir(dir).blockJIT().strict().run('cmd.exe', ['/c', 'echo x']);
      strict.notEqual(res.exitCode, 0);
      strict.match(res.stderr, /not enforceable on Windows/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('runs through the CLI with a policy file', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    const policyDir = workDir();
    try {
      const policyFile = join(policyDir, 'policy.json');
      writeFileSync(policyFile, JSON.stringify({ writePaths: [dir], windowsBlockWin32k: true }));
      const inside = join(dir, 'cli.txt');
      const res = await runCli('--cwd', dir, '--policy-file', policyFile, '--', 'cmd.exe', '/c', `echo cli-ok& echo x> "${inside}"`);
      strict.equal(res.exitCode, 0, res.stderr);
      strict.match(res.stdout, /cli-ok/);
      strict.ok(existsSync(inside), 'the policy file write grant was not applied');
      // The policy file grants nothing else: its own directory stays closed.
      const outside = join(policyDir, 'cli.txt');
      const denied = await runCli('--cwd', dir, '--policy-file', policyFile, '--', 'cmd.exe', '/c', `echo x> "${outside}"`);
      strict.notEqual(denied.exitCode, 0);
      strict.ok(!existsSync(outside));
    } finally {
      rmSync(dir, { recursive: true, force: true });
      rmSync(policyDir, { recursive: true, force: true });
    }
  });
});

describe('Windows engine lookup', { skip: !isWindows && 'Windows only' }, () => {
  it('never resolves the engine from the current or a relative directory', () => {
    const planted = workDir();
    const real = workDir();
    const cwd = process.cwd();
    try {
      writeFileSync(join(planted, 'safer-exec-rt.exe'), '');
      process.chdir(planted);
      strict.equal(findOnWindowsPath('safer-exec-rt.exe', { Path: `.;;safer;${join(real, 'missing')}` }), undefined);
      writeFileSync(join(real, 'safer-exec-rt.exe'), '');
      strict.equal(findOnWindowsPath('safer-exec-rt.exe', { PATH: `.;"${real}"` }), join(real, 'safer-exec-rt.exe'));
    } finally {
      process.chdir(cwd);
      rmSync(planted, { recursive: true, force: true });
      rmSync(real, { recursive: true, force: true });
    }
  });
});
