/**
 * End-to-end tests for the Windows engine through the Node API and CLI:
 * Node.js -> safer-exec-rt.exe -> wxc-exec.exe (MXC) -> workload.
 *
 * Skipped on other platforms, and when the engine reports that the MXC
 * ProcessContainer is unavailable (no wxc-exec.exe or no BaseContainer API).
 * Workloads are Windows system tools (cmd.exe, curl.exe), which a container
 * can run without grants.
 *
 * @module windows_test
 */

import { describe, it, before } from 'node:test';
import strict from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SaferExec } from './index.js';

const isWindows = process.platform === 'win32';
const cliPath = join(dirname(fileURLToPath(import.meta.url)), 'cli.js');

let skipReason = isWindows ? '' : 'Windows only';

function workDir() {
  return realpathSync(mkdtempSync(join(tmpdir(), 'safer-exec-win-')));
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
      if (!info.features?.mxc_process_container) {
        skipReason = `MXC ProcessContainer unavailable: ${JSON.stringify(info.capabilities?.mxc_probe ?? info.capabilities?.mxc_executor)}`;
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
    try {
      const res = await new SaferExec()
        .workingDir(dir)
        .disableNetwork()
        .run('curl.exe', ['-sS', '-m', '5', '-o', 'NUL', 'http://example.com/']);
      strict.notEqual(res.exitCode, 0);
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

  it('runs through the CLI', async (t) => {
    if (skipReason) return t.skip(skipReason);
    const dir = workDir();
    try {
      const policyFile = join(dir, 'policy.json');
      writeFileSync(policyFile, JSON.stringify({ writePaths: [dir], windowsBlockWin32k: true }));
      const res = await runCli('--cwd', dir, '--policy-file', policyFile, '--', 'cmd.exe', '/c', 'echo cli-ok');
      strict.equal(res.exitCode, 0, res.stderr);
      strict.match(res.stdout, /cli-ok/);
      strict.ok(readFileSync(policyFile, 'utf-8').includes('windowsBlockWin32k'));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
