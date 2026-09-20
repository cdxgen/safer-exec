/**
 * Integration tests for the agentic-harness hook feature.
 *
 * Exercises the full CLI flow against a synthetic project:
 *   harness install (config discovery + policy import + hook registration)
 *   → hook pre (audit / enforce / wrap) via stdin payloads
 *   → wrapped command execution under the real sandbox
 *   → hook audit trail
 *   → harness uninstall (settings restored)
 *
 * @module hooks_integration_test
 */

import { describe, it } from 'node:test';
import strict from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, mkdtempSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', 'npm', 'src', 'cli.js');

function mkProject() {
  const dir = mkdtempSync(join(tmpdir(), 'safer-exec-hooks-e2e-'));
  mkdirSync(join(dir, '.claude'), { recursive: true });
  writeFileSync(join(dir, '.claude', 'settings.json'), JSON.stringify({
    permissions: {
      allow: ['Bash(npm run *)', 'Read(./src/**)'],
      ask: ['Bash(git push *)'],
      deny: ['Bash(curl *)', 'Read(./.env)'],
    },
  }, null, 2));
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(join(dir, 'src', 'app.js'), 'console.log("app");\n');
  return dir;
}

function runCli(args, opts = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || process.cwd(),
    env: { ...process.env, ...(opts.env || {}) },
    input: opts.input || '',
    timeout: opts.timeout || 60000,
  });
}

function hookPayload(dir, overrides = {}) {
  return JSON.stringify({
    session_id: 'itest-session',
    transcript_path: '/dev/null',
    cwd: dir,
    permission_mode: 'default',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command: 'echo hello' },
    ...overrides,
  });
}

describe('harness hook integration', () => {
  it('installs, audits, enforces, and uninstalls for claude-code', () => {
    const dir = mkProject();
    const home = join(dir, 'home');
    mkdirSync(home, { recursive: true });

    // 1. install
    const install = runCli(['harness', 'install', '--harness=claude-code', '--mode=enforce'], { cwd: dir, env: { HOME: home } });
    strict.equal(install.status, 0, install.stderr);
    strict.ok(existsSync(join(dir, '.safer-exec', 'hook-config.json')));
    strict.ok(existsSync(join(dir, '.safer-exec', 'harness-policy.json')));
    const settings = JSON.parse(readFileSync(join(dir, '.claude', 'settings.json'), 'utf8'));
    strict.ok(settings.hooks.PreToolUse[0].hooks[0].command.includes('hook pre'));
    strict.ok(settings.hooks.PostToolUse[0].hooks[0].command.includes('hook post'));
    strict.equal(settings.permissions.deny.length, 2, 'user permissions preserved');

    const auditLog = join(dir, '.safer-exec', 'hooks-audit.jsonl');

    // 2. Read tool call matching an allow rule → enforce answers with allow
    const read = runCli(['hook', 'pre'], {
      cwd: dir,
      input: JSON.stringify({
        session_id: 's', cwd: dir, hook_event_name: 'PreToolUse',
        tool_name: 'Read', tool_input: { file_path: join(dir, 'src', 'app.js') },
      }),
      env: { HOME: home },
    });
    strict.equal(read.status, 0);
    strict.equal(JSON.parse(read.stdout).hookSpecificOutput.permissionDecision, 'allow');

    // 3. enforce: denied command blocks with exit 2
    const denied = runCli(['hook', 'pre'], {
      cwd: dir,
      input: hookPayload(dir, { tool_input: { command: 'curl https://evil.example.com' } }),
      env: { HOME: home },
    });
    strict.equal(denied.status, 2, `expected exit 2, got ${denied.status}: ${denied.stdout} ${denied.stderr}`);
    strict.match(denied.stderr, /curl \*/);

    // 4. enforce: allowed command gets permissionDecision allow
    const allowed = runCli(['hook', 'pre'], {
      cwd: dir,
      input: hookPayload(dir, { tool_input: { command: 'npm run build' } }),
      env: { HOME: home },
    });
    strict.equal(allowed.status, 0);
    strict.equal(JSON.parse(allowed.stdout).hookSpecificOutput.permissionDecision, 'allow');

    // 5. post event records tool_response summary
    const post = runCli(['hook', 'post'], {
      cwd: dir,
      input: JSON.stringify({
        session_id: 's', cwd: dir, hook_event_name: 'PostToolUse',
        tool_name: 'Bash', tool_input: { command: 'echo x' },
        tool_response: { bashEditDiff: { changedFiles: [join(dir, 'out.txt')] } },
        duration_ms: 7,
      }),
      env: { HOME: home },
    });
    strict.equal(post.status, 0);

    // 6. audit trail contains everything
    const trail = runCli(['hook', 'audit', '--json'], { cwd: dir, env: { HOME: home } });
    strict.equal(trail.status, 0);
    const records = JSON.parse(trail.stdout);
    strict.equal(records.length, 4);
    strict.ok(records.every((r) => r.harness === 'claude-code'));
    strict.equal(records[1].decision, 'deny');
    strict.equal(records[3].response.changedFiles[0], join(dir, 'out.txt'));

    // 7. uninstall restores settings
    const uninstall = runCli(['harness', 'uninstall', '--harness=claude-code'], { cwd: dir, env: { HOME: home } });
    strict.equal(uninstall.status, 0);
    const after = JSON.parse(readFileSync(join(dir, '.claude', 'settings.json'), 'utf8'));
    strict.equal(after.hooks, undefined);
    strict.equal(after.permissions.deny.length, 2);

    rmSync(dir, { recursive: true, force: true });
  });

  it('wrap mode executes a Bash command inside the sandbox with fsdiff', () => {
    const bin = runCli(['--version']).stdout.trim();
    strict.match(bin, /safer-exec v/);
    const dir = mkProject();
    const home = join(dir, 'home');
    mkdirSync(home, { recursive: true });

    const res = runCli(['harness', 'install', '--harness=claude-code', '--wrap'], { cwd: dir, env: { HOME: home } });
    strict.equal(res.status, 0, res.stderr);

    const pre = runCli(['hook', 'pre'], {
      cwd: dir,
      input: hookPayload(dir, { tool_input: { command: `echo wrapped-itest > ${join(dir, 'wrapped.txt')}` } }),
      env: { HOME: home },
    });
    strict.equal(pre.status, 0, pre.stderr);
    const out = JSON.parse(pre.stdout);
    const wrapped = out.hookSpecificOutput.updatedInput.command;
    strict.match(wrapped, /safer-exec|cli\.js/);
    strict.match(wrapped, /base64 -d/);

    // Simulate the harness executing the rewritten command
    const run = spawnSync('/bin/bash', ['-c', wrapped], { encoding: 'utf8', cwd: dir, timeout: 60000 });
    strict.equal(run.status, 0, `wrapped command failed: ${run.stderr}`);
    strict.equal(readFileSync(join(dir, 'wrapped.txt'), 'utf8').trim(), 'wrapped-itest');
    // fsdiff summary reaches the harness as stderr — unless the runtime blocks
    // user namespaces (e.g. default Docker seccomp), where the engine degrades
    // to reduced isolation and skips diffing but still audits execs
    const sandboxed =
      /Filesystem diff: \+\d+ added/.test(run.stderr) ||
      /--diff requires mount namespace isolation/.test(run.stderr);
    strict.ok(sandboxed, `expected sandbox execution evidence, stderr: ${run.stderr}`);

    rmSync(dir, { recursive: true, force: true });
  });

  it('imports codex TOML permissions end-to-end', () => {
    const dir = mkdtempSync(join(tmpdir(), 'safer-exec-codex-e2e-'));
    mkdirSync(join(dir, '.codex'), { recursive: true });
    writeFileSync(join(dir, '.codex', 'config.toml'), `
sandbox_mode = "workspace-write"
[sandbox_workspace_write]
network_access = false
writable_roots = ["/tmp/codex-shared"]

[permissions.dev.filesystem]
":root" = "read"
"~/private" = "deny"

[permissions.dev.network.domains]
"api.openai.com" = "allow"
`);
    const imp = runCli(['harness', 'import', '--harness=codex', '--out=' + join(dir, 'policy.json')], {
      cwd: dir,
      env: { HOME: join(dir, 'h') },
    });
    strict.equal(imp.status, 0, imp.stderr);
    const policy = JSON.parse(readFileSync(join(dir, 'policy.json'), 'utf8'));
    strict.equal(policy.disableNetwork, true);
    strict.deepEqual(policy.allowHosts, ['api.openai.com']);
    strict.ok(policy.writePaths.includes('/tmp/codex-shared'));
    rmSync(dir, { recursive: true, force: true });
  });
});
