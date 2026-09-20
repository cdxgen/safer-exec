/**
 * Tests for the safer-exec hook engine (payload normalization, activity
 * extraction, enforce decisions, wrapping, audit trail).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  normalizeHookPayload,
  extractActivity,
  handleHookEvent,
  buildWrapCommand,
  summarizeResponse,
  readAuditTrail,
  loadHookConfig,
} from './hooks.js';
import { resolveBinaryPath } from './runner.js';

const CLI = fileURLToPath(new URL('./cli.js', import.meta.url));

function tmp() {
  return mkdtempSync(join(tmpdir(), 'safer-exec-hooks-'));
}

describe('normalizeHookPayload', () => {
  test('claude-code shape', () => {
    const n = normalizeHookPayload({
      session_id: 's1',
      cwd: '/tmp/p',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'npm test' },
      tool_use_id: 't1',
    });
    assert.equal(n.event, 'PreToolUse');
    assert.equal(n.harness, 'claude-code');
    assert.equal(n.toolName, 'Bash');
    assert.equal(n.toolInput.command, 'npm test');
    assert.equal(n.sessionId, 's1');
  });

  test('gemini BeforeTool shape', () => {
    const n = normalizeHookPayload({
      session_id: 's2',
      cwd: '/tmp/p',
      hook_event_name: 'BeforeTool',
      tool_name: 'run_shell_command',
      tool_input: { command: 'git status' },
    });
    assert.equal(n.event, 'PreToolUse');
    assert.equal(n.harness, 'gemini');
  });

  test('copilot camelCase + stringified toolArgs', () => {
    const n = normalizeHookPayload({
      sessionId: 's3',
      cwd: '/tmp/p',
      hookEvent: 'postToolUse',
      toolName: 'bash',
      toolArgs: JSON.stringify({ command: 'ls -la' }),
    });
    assert.equal(n.event, 'PostToolUse');
    assert.equal(n.harness, 'copilot');
    assert.equal(n.toolInput.command, 'ls -la');
  });

  test('cursor kebab-case event', () => {
    const n = normalizeHookPayload({
      hook_event_name: 'pre-tool-use',
      tool_name: 'Shell',
      tool_input: { command: 'ls' },
      cwd: '/x',
    });
    assert.equal(n.event, 'PreToolUse');
    assert.equal(n.harness, 'cursor');
  });

  test('explicit harness override wins', () => {
    const n = normalizeHookPayload({ hook_event_name: 'PreToolUse', tool_name: 'Bash' }, { harness: 'zcode' });
    assert.equal(n.harness, 'zcode');
  });
});

describe('extractActivity', () => {
  const act = (toolName, toolInput) => extractActivity({ toolName, toolInput });

  test('shell tools map to exec', () => {
    assert.equal(act('Bash', { command: 'ls' }).type, 'exec');
    assert.equal(act('Execute', { command: 'ls' }).type, 'exec');
    assert.equal(act('run_shell_command', { command: 'ls' }).type, 'exec');
  });

  test('file tools', () => {
    assert.equal(act('Write', { file_path: '/a/b' }).type, 'file-write');
    assert.equal(act('Edit', { file_path: '/a/b' }).type, 'file-write');
    assert.equal(act('Read', { file_path: '/a/b' }).type, 'file-read');
    assert.equal(act('read_file', { file_path: '/a/b' }).type, 'file-read');
    assert.equal(act('apply_patch', { file_path: '/a/b' }).type, 'file-write');
  });

  test('network tools', () => {
    const wf = act('WebFetch', { url: 'https://registry.npmjs.org/x' });
    assert.equal(wf.type, 'network-fetch');
    assert.equal(wf.host, 'registry.npmjs.org');
    assert.equal(act('WebSearch', { query: 'hi' }).type, 'network-search');
  });

  test('mcp tools', () => {
    const m = act('mcp__github__create_issue', {});
    assert.equal(m.type, 'mcp-call');
    assert.equal(m.server, 'github');
  });

  test('agent tools', () => {
    assert.equal(act('Agent', { prompt: 'x' }).type, 'agent');
  });
});

describe('handleHookEvent', () => {
  test('audit mode records and passes silently', () => {
    const dir = tmp();
    const auditLog = join(dir, 'audit.jsonl');
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'Bash', tool_input: { command: 'echo hi' },
    }, { config: { mode: 'audit', wrap: false, policyFile: '', auditLog, harness: 'claude-code' } });
    assert.equal(res.exitCode, 0);
    assert.equal(res.stdout, undefined);
    const trail = readAuditTrail(auditLog);
    assert.equal(trail.length, 1);
    assert.equal(trail[0].activity.command, 'echo hi');
    assert.equal(trail[0].decision, 'passthrough');
    rmSync(dir, { recursive: true, force: true });
  });

  test('enforce mode denies on deny rule (exit 2)', () => {
    const dir = tmp();
    const auditLog = join(dir, 'audit.jsonl');
    const policyFile = join(dir, 'policy.json');
    writeFileSync(policyFile, JSON.stringify({
      harnessRules: [
        { tool: 'Bash', kind: 'command', pattern: 'curl *', action: 'deny', source: 'claude-code' },
      ],
    }));
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'Bash', tool_input: { command: 'echo x && curl https://evil.example' },
    }, { config: { mode: 'enforce', wrap: false, policyFile, auditLog, harness: 'claude-code' } });
    assert.equal(res.exitCode, 2);
    assert.match(res.stderr, /curl \*/);
    const trail = readAuditTrail(auditLog);
    assert.equal(trail[0].decision, 'deny');
    rmSync(dir, { recursive: true, force: true });
  });

  test('enforce mode answers allow rules with permissionDecision JSON', () => {
    const dir = tmp();
    const policyFile = join(dir, 'policy.json');
    writeFileSync(policyFile, JSON.stringify({
      harnessRules: [
        { tool: 'Bash', kind: 'command', pattern: 'npm run test *', action: 'allow', source: 'claude-code' },
      ],
    }));
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'Bash', tool_input: { command: 'npm run test unit' },
    }, { config: { mode: 'enforce', wrap: false, policyFile, auditLog: join(dir, 'a.jsonl'), harness: 'claude-code' } });
    assert.equal(res.exitCode, 0);
    const out = JSON.parse(res.stdout);
    assert.equal(out.hookSpecificOutput.permissionDecision, 'allow');
    rmSync(dir, { recursive: true, force: true });
  });

  test('enforce mode emits ask decision', () => {
    const dir = tmp();
    const policyFile = join(dir, 'policy.json');
    writeFileSync(policyFile, JSON.stringify({
      harnessRules: [
        { tool: 'Bash', kind: 'command', pattern: 'git push *', action: 'ask', source: 'claude-code' },
      ],
    }));
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'Bash', tool_input: { command: 'git push origin main' },
    }, { config: { mode: 'enforce', wrap: false, policyFile, auditLog: join(dir, 'a.jsonl'), harness: 'claude-code' } });
    assert.equal(res.exitCode, 0);
    assert.equal(JSON.parse(res.stdout).hookSpecificOutput.permissionDecision, 'ask');
    rmSync(dir, { recursive: true, force: true });
  });

  test('domain deny blocks WebFetch', () => {
    const dir = tmp();
    const policyFile = join(dir, 'policy.json');
    writeFileSync(policyFile, JSON.stringify({
      harnessRules: [
        { tool: 'WebFetch', kind: 'domain', pattern: '*.evil.com', action: 'deny', source: 'claude-code' },
      ],
    }));
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'WebFetch', tool_input: { url: 'https://a.b.evil.com/x' },
    }, { config: { mode: 'enforce', wrap: false, policyFile, auditLog: join(dir, 'a.jsonl'), harness: 'claude-code' } });
    assert.equal(res.exitCode, 2);
    rmSync(dir, { recursive: true, force: true });
  });

  test('post event records changed files and duration', () => {
    const dir = tmp();
    const auditLog = join(dir, 'a.jsonl');
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'PostToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'echo x > f' },
      tool_response: { bashEditDiff: { changedFiles: ['/p/f'] } },
      duration_ms: 42,
    }, { config: { mode: 'audit', wrap: false, policyFile: '', auditLog, harness: 'claude-code' } });
    assert.equal(res.exitCode, 0);
    const rec = readAuditTrail(auditLog)[0];
    assert.deepEqual(rec.response.changedFiles, ['/p/f']);
    assert.equal(rec.durationMs, 42);
    rmSync(dir, { recursive: true, force: true });
  });

  test('wrap mode rewrites Bash command with updatedInput', () => {
    const dir = tmp();
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'Bash', tool_input: { command: 'echo "quotes && pipes" > $HOME/x' },
    }, { config: { mode: 'audit', wrap: true, policyFile: '', auditLog: join(dir, 'a.jsonl'), harness: 'claude-code' } });
    assert.equal(res.exitCode, 0);
    const out = JSON.parse(res.stdout);
    const cmd = out.hookSpecificOutput.updatedInput.command;
    assert.match(cmd, /cli\.js/);
    assert.match(cmd, /--diff --audit --trace-exec/);
    assert.match(cmd, /SAFER_EXEC_WRAPPED_CMD=[A-Za-z0-9+/=]+/);
    assert.match(cmd, /base64 -d/);
    // original command round-trips through the b64 encoding
    const b64 = /SAFER_EXEC_WRAPPED_CMD=([A-Za-z0-9+/=]+)/.exec(cmd)[1];
    assert.equal(Buffer.from(b64, 'base64').toString(), 'echo "quotes && pipes" > $HOME/x');
    rmSync(dir, { recursive: true, force: true });
  });

  test('wrap mode skips background commands and unsupported harnesses', () => {
    const base = {
      session_id: 's1', cwd: '/tmp', hook_event_name: 'PreToolUse',
      tool_name: 'Bash', tool_input: { command: 'sleep 10', run_in_background: true },
    };
    const cfg = { mode: 'audit', wrap: true, policyFile: '', auditLog: '/dev/null', harness: 'claude-code' };
    assert.equal(handleHookEvent(base, { config: cfg }).stdout, undefined);
    const zcodeCfg = { ...cfg, harness: 'zcode' };
    assert.equal(
      handleHookEvent({ ...base, tool_input: { command: 'sleep 10' } }, { config: zcodeCfg }).stdout,
      undefined
    );
  });

  test('gemini wrap output uses tool_input merge shape', () => {
    const dir = tmp();
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'BeforeTool',
      tool_name: 'run_shell_command', tool_input: { command: 'ls' },
    }, { config: { mode: 'audit', wrap: true, policyFile: '', auditLog: join(dir, 'a.jsonl'), harness: 'gemini' } });
    const out = JSON.parse(res.stdout);
    assert.ok(out.hookSpecificOutput.tool_input.command.includes('cli.js'));
    rmSync(dir, { recursive: true, force: true });
  });

  test('fail-open on malformed activity (no crash)', () => {
    const dir = tmp();
    const res = handleHookEvent({
      session_id: 's1', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'Bash', tool_input: null,
    }, { config: { mode: 'audit', wrap: false, policyFile: '', auditLog: join(dir, 'a.jsonl') } });
    assert.equal(res.exitCode, 0);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('buildWrapCommand', () => {
  test('includes policy, audit log, and env transport', () => {
    const cmd = buildWrapCommand('ls -la', { policyFile: '/p.json', auditLog: '/a.jsonl' });
    assert.match(cmd, /--policy-file="\/p\.json"/);
    assert.match(cmd, /--audit-output-file="\/a\.jsonl"/);
    assert.match(cmd, /-- \/bin\/bash -c/);
    assert.ok(!cmd.includes('ls -la'), 'original command must not appear verbatim (quoting hazards)');
  });
});

describe('summarizeResponse', () => {
  test('bounded summary of bash responses', () => {
    const s = summarizeResponse({
      stdout: 'x'.repeat(5000),
      stderr: '',
      interrupted: false,
      bashEditDiff: { changedFiles: Array.from({ length: 80 }, (_, i) => `/f${i}`) },
    });
    assert.equal(s.stdoutBytes, 5000);
    assert.equal(s.changedFiles.length, 50);
    assert.equal(s.changedFilesCount, 80);
  });

  test('empty for null', () => {
    assert.deepEqual(summarizeResponse(null), {});
  });
});

describe('hook CLI end-to-end', () => {
  function runHook(phase, payload, env) {
    return spawnSync(process.execPath, [CLI, 'hook', phase], {
      input: JSON.stringify(payload),
      encoding: 'utf8',
      env: { ...process.env, ...env },
    });
  }

  test('safer-exec hook pre audits via env-config', () => {
    const dir = tmp();
    const auditLog = join(dir, 'a.jsonl');
    const r = runHook('pre', {
      session_id: 'e2e', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'Read', tool_input: { file_path: join(dir, 'f.txt') },
    }, {
      SAFER_EXEC_HOOK_AUDIT_LOG: auditLog,
      SAFER_EXEC_HOOK_MODE: 'audit',
      SAFER_EXEC_HOOK_WRAP: '0',
      SAFER_EXEC_HOOK_CONFIG: '/nonexistent',
    });
    assert.equal(r.status, 0);
    assert.equal(r.stdout, '');
    const trail = readAuditTrail(auditLog);
    assert.equal(trail.length, 1);
    assert.equal(trail[0].tool, 'Read');
    rmSync(dir, { recursive: true, force: true });
  });

  test('invalid JSON payload fails open with exit 0', () => {
    const r = spawnSync(process.execPath, [CLI, 'hook', 'pre'], {
      input: 'this is not json',
      encoding: 'utf8',
    });
    assert.equal(r.status, 0);
    assert.match(r.stderr, /invalid JSON/);
  });

  test('wrapped command executes under the sandbox (requires safer-exec-rt)', { skip: !resolveBinaryPath?.() || !existsSync(resolveBinaryPath()) }, () => {
    const dir = tmp();
    const auditLog = join(dir, 'a.jsonl');
    const r = runHook('pre', {
      session_id: 'w', cwd: dir, hook_event_name: 'PreToolUse',
      tool_name: 'Bash', tool_input: { command: `echo wrapped-e2e-ok > ${join(dir, 'out.txt')}` },
    }, {
      SAFER_EXEC_HOOK_AUDIT_LOG: auditLog,
      SAFER_EXEC_HOOK_WRAP: '1',
      SAFER_EXEC_HOOK_MODE: 'audit',
      SAFER_EXEC_HOOK_CONFIG: '/nonexistent',
    });
    assert.equal(r.status, 0);
    const out = JSON.parse(r.stdout);
    const cmd = out.hookSpecificOutput.updatedInput.command;
    // Simulate the harness running the rewritten command
    const run = spawnSync('/bin/bash', ['-c', cmd], { encoding: 'utf8', cwd: dir });
    assert.equal(run.status, 0, `wrapped command failed: ${run.stderr}`);
    assert.equal(readFileSync(join(dir, 'out.txt'), 'utf8').trim(), 'wrapped-e2e-ok');
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('loadHookConfig', () => {
  test('reads project hook-config.json from cwd', () => {
    const dir = tmp();
    mkdirSync(join(dir, '.safer-exec'), { recursive: true });
    writeFileSync(join(dir, '.safer-exec', 'hook-config.json'), JSON.stringify({ mode: 'enforce', wrap: true }));
    const cfg = loadHookConfig({ cwd: dir, home: join(dir, 'nohome') });
    assert.equal(cfg.mode, 'enforce');
    assert.equal(cfg.wrap, true);
    rmSync(dir, { recursive: true, force: true });
  });

  test('env overrides beat files', () => {
    const dir = tmp();
    mkdirSync(join(dir, '.safer-exec'), { recursive: true });
    writeFileSync(join(dir, '.safer-exec', 'hook-config.json'), JSON.stringify({ mode: 'audit' }));
    const prev = process.env.SAFER_EXEC_HOOK_MODE;
    const prevCfg = process.env.SAFER_EXEC_HOOK_CONFIG;
    process.env.SAFER_EXEC_HOOK_MODE = 'enforce';
    delete process.env.SAFER_EXEC_HOOK_CONFIG;
    try {
      const cfg = loadHookConfig({ cwd: dir, home: dir });
      assert.equal(cfg.mode, 'enforce');
    } finally {
      if (prev === undefined) delete process.env.SAFER_EXEC_HOOK_MODE;
      else process.env.SAFER_EXEC_HOOK_MODE = prev;
      if (prevCfg !== undefined) process.env.SAFER_EXEC_HOOK_CONFIG = prevCfg;
    }
    rmSync(dir, { recursive: true, force: true });
  });
});
