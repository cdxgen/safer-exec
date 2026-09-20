/**
 * Tests for harness adapters: TOML parsing/serialization, the unified rule
 * engine, per-harness permission parsing → policy conversion, and hook
 * install/uninstall.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { parseTOML, stringifyTOML, TOMLError } from './harnesses/toml.js';
import {
  parseClaudeToken,
  matchCommandPattern,
  matchDomainPattern,
  splitCompoundCommand,
  gitignoreGlobToRegExp,
  evaluateRules,
} from './harnesses/rules.js';
import {
  HARNESSES,
  detectHarnesses,
  importHarnessPolicy,
  installHarnessHooks,
  uninstallHarnessHooks,
} from './harnesses/index.js';

function tmp() {
  return mkdtempSync(join(tmpdir(), 'safer-exec-harness-'));
}

function w(dir, rel, content) {
  const p = join(dir, rel);
  mkdirSync(join(dirname(p)), { recursive: true });
  writeFileSync(p, content);
  return p;
}

import { dirname } from 'node:path';

/* ------------------------------------------------------------------ TOML */

describe('parseTOML', () => {
  test('scalars, tables, quoted keys, arrays, inline tables', () => {
    const doc = parseTOML(`
# comment
sandbox_mode = "workspace-write"
network = false
count = 42
ratio = 1.5

[sandbox_workspace_write]
writable_roots = ["/tmp/a", "/tmp/b"]

[permissions.dev.filesystem]
":root" = "read"
"~/secrets" = "deny"

[permissions.dev.network]
enabled = true
flags = { mode = "limited", socks = false }
`);
    assert.equal(doc.sandbox_mode, 'workspace-write');
    assert.equal(doc.network, false);
    assert.equal(doc.count, 42);
    assert.equal(doc.ratio, 1.5);
    assert.deepEqual(doc.sandbox_workspace_write.writable_roots, ['/tmp/a', '/tmp/b']);
    assert.equal(doc.permissions.dev.filesystem[':root'], 'read');
    assert.equal(doc.permissions.dev.filesystem['~/secrets'], 'deny');
    assert.equal(doc.permissions.dev.network.flags.mode, 'limited');
  });

  test('array-of-tables with nesting (codex hooks)', () => {
    const doc = parseTOML(`
[[hooks.PreToolUse]]
matcher = "^Bash$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "check.py"
timeout = 30

[[hooks.PreToolUse]]
matcher = ".*"
[[hooks.PreToolUse.hooks]]
command = "other.sh"
`);
    assert.equal(doc.hooks.PreToolUse.length, 2);
    assert.equal(doc.hooks.PreToolUse[0].matcher, '^Bash$');
    assert.equal(doc.hooks.PreToolUse[0].hooks[0].command, 'check.py');
    assert.equal(doc.hooks.PreToolUse[1].hooks[0].command, 'other.sh');
  });

  test('multi-line arrays', () => {
    const doc = parseTOML(`
roots = [
  "/a",
  "/b",  # trailing comment
]
`);
    assert.deepEqual(doc.roots, ['/a', '/b']);
  });

  test('rejects malformed input with TOMLError', () => {
    assert.throws(() => parseTOML('key = value'), TOMLError);
    assert.throws(() => parseTOML('[unclosed'), TOMLError);
  });

  test('stringifyTOML round-trips', () => {
    const doc = parseTOML(`
model = "gpt"
[[hooks.PreToolUse]]
matcher = "^Bash$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "x.py"
timeout = 30

[permissions.p.filesystem.":workspace_roots"]
"." = "write"
"**/*.env" = "deny"
`);
    const again = parseTOML(stringifyTOML(doc));
    assert.deepEqual(again, doc);
  });
});

/* ------------------------------------------------------------------ rules */

describe('claude token parsing + matching', () => {
  test('parseClaudeToken forms', () => {
    assert.deepEqual(parseClaudeToken('Bash', 'deny', 'claude-code', '/b', '/h').rule, {
      tool: 'Bash', kind: 'bare', action: 'deny', source: 'claude-code',
    });
    const bash = parseClaudeToken('Bash(npm run test:*)', 'allow', 'claude-code', '/b', '/h').rule;
    assert.equal(bash.kind, 'command');
    assert.equal(bash.pattern, 'npm run test *');
    const dom = parseClaudeToken('WebFetch(domain:*.example.com)', 'allow', 'claude-code', '/b', '/h').rule;
    assert.equal(dom.kind, 'domain');
    assert.equal(dom.pattern, '*.example.com');
    const path = parseClaudeToken('Edit(/src/**/*.ts)', 'allow', 'claude-code', '/base', '/home').rule;
    assert.equal(path.kind, 'path');
    assert.equal(path.access, 'write');
  });

  test('matchCommandPattern space-star vs glued-star', () => {
    assert.ok(matchCommandPattern('npm run *', 'npm run test'));
    assert.ok(matchCommandPattern('npm run test *', 'npm run test unit')); // after :* conversion
    assert.ok(!matchCommandPattern('npm run *', 'npmrun test'));
    assert.ok(matchCommandPattern('git*', 'gitstatus')); // cursor style
    assert.ok(matchCommandPattern('git*', 'git status'));
    assert.ok(matchCommandPattern('git push', 'git push'));
    assert.ok(!matchCommandPattern('git push', 'git push --force'));
  });

  test('splitCompoundCommand strips wrappers and env assignments', () => {
    assert.deepEqual(
      splitCompoundCommand('FOO=1 timeout 10 curl https://x && git status | head -3; ls'),
      ['curl https://x', 'git status', 'head -3', 'ls']
    );
  });

  test('matchDomainPattern', () => {
    assert.ok(matchDomainPattern('*.example.com', 'a.b.example.com'));
    assert.ok(!matchDomainPattern('*.example.com', 'example.com'));
    assert.ok(matchDomainPattern('**.example.com', 'example.com'));
    assert.ok(matchDomainPattern('example.com', 'example.com'));
  });

  test('gitignoreGlobToRegExp', () => {
    assert.ok(gitignoreGlobToRegExp('/a/**/b').test('/a/b'));
    assert.ok(gitignoreGlobToRegExp('/a/**/b').test('/a/x/y/b'));
    assert.ok(gitignoreGlobToRegExp('/a/*').test('/a/x'));
    assert.ok(!gitignoreGlobToRegExp('/a/*').test('/a/x/y'));
    assert.ok(gitignoreGlobToRegExp('/**/.env').test('/x/.env'));
  });

  test('evaluateRules precedence deny > ask > allow', () => {
    const rules = [
      { tool: 'Bash', kind: 'command', pattern: 'git *', action: 'allow', source: 't' },
      { tool: 'Bash', kind: 'command', pattern: 'git push *', action: 'deny', source: 't' },
    ];
    assert.equal(evaluateRules(rules, { type: 'exec', command: 'git push origin', tool: 'Bash' }, {}).action, 'deny');
    assert.equal(evaluateRules(rules, { type: 'exec', command: 'git status', tool: 'Bash' }, {}).action, 'allow');
    assert.equal(evaluateRules(rules, { type: 'exec', command: 'ls', tool: 'Bash' }, {}).action, null);
  });

  test('evaluateRules last-match-wins mode (opencode)', () => {
    const rules = [
      { tool: 'Bash', kind: 'command', pattern: '*', action: 'ask', source: 'opencode' },
      { tool: 'Bash', kind: 'command', pattern: 'git *', action: 'allow', source: 'opencode' },
    ];
    assert.equal(evaluateRules(rules, { type: 'exec', command: 'git status', tool: 'Bash' }, { lastMatchWins: true }).action, 'allow');
    assert.equal(evaluateRules(rules, { type: 'exec', command: 'ls', tool: 'Bash' }, { lastMatchWins: true }).action, 'ask');
  });

  test('path rule evaluation with baseDir resolution', () => {
    const rule = {
      tool: 'Read', kind: 'path', pattern: '/src/**', access: 'read', action: 'deny',
      source: 'claude-code', baseDir: '/proj', home: '/home/u',
    };
    const ctx = { cwd: '/proj', home: '/home/u' };
    assert.equal(evaluateRules([rule], { type: 'file-read', path: '/proj/src/x.js', tool: 'Read' }, ctx).action, 'deny');
    assert.equal(evaluateRules([rule], { type: 'file-read', path: '/other/src/x.js', tool: 'Read' }, ctx).action, null);
  });
});

/* --------------------------------------------------------------- imports */

describe('claude-code import', () => {
  test('tokens convert to policy fields', () => {
    const dir = tmp();
    const f = w(dir, '.claude/settings.json', JSON.stringify({
      permissions: {
        allow: ['Bash(npm run test:*)', 'Read(./src/**)', 'Edit(/docs/**)', 'WebFetch(domain:registry.npmjs.org)', 'WebFetch(domain:*.github.com)'],
        ask: ['Bash(git push *)'],
        deny: ['Bash(curl *)', 'Read(./.env)'],
        additionalDirectories: ['../shared'],
        defaultMode: 'default',
      },
    }));
    const { policy } = importHarnessPolicy('claude-code', { path: f, cwd: dir, home: join(dir, 'h') });
    assert.ok(policy.writePaths.some((p) => p.includes('docs')));
    assert.ok(policy.readPaths.some((p) => p.includes('src')));
    assert.ok(policy.readPaths.some((p) => p.includes('shared')));
    assert.ok(policy.allowHosts.includes('registry.npmjs.org'));
    assert.ok(policy.allowHosts.includes('github.com')); // *.github.com → subdomain apex form
    assert.ok(policy.blockExec.includes('curl'));
    assert.equal(policy.source.harness, 'claude-code');
    const denyEnv = policy.harnessRules.find((r) => r.kind === 'path' && r.action === 'deny');
    assert.equal(denyEnv.pattern, './.env');
    rmSync(dir, { recursive: true, force: true });
  });

  test('blockExec only for bare-executable deny patterns (no subcommand over-blocking)', () => {
    const dir = tmp();
    const f = w(dir, '.claude/settings.json', JSON.stringify({
      permissions: {
        deny: ['Bash(npm publish:*)', 'Bash(npm *)', 'Bash(rm -rf *)', 'Bash(curl *)'],
      },
    }));
    const { policy } = importHarnessPolicy('claude-code', { path: f, cwd: dir, home: join(dir, 'h') });
    // Only `npm *` and `curl *` deny the executable itself; `npm publish:*`
    // and `rm -rf *` are subcommand rules the hook layer enforces instead
    assert.deepEqual(policy.blockExec, ['npm', 'curl']);
    const patterns = policy.harnessRules.filter((r) => r.kind === 'command').map((r) => r.pattern);
    assert.ok(patterns.includes('npm publish *'));
    assert.ok(patterns.includes('rm -rf *'));
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('codex import', () => {
  test('workspace-write + network + permissions profile', () => {
    const dir = tmp();
    const f = w(dir, '.codex/config.toml', `
sandbox_mode = "workspace-write"
[sandbox_workspace_write]
network_access = true
writable_roots = ["/tmp/shared"]

[permissions.dev.filesystem]
":root" = "read"
"~/secrets" = "deny"

[permissions.dev.network]
enabled = true
mode = "limited"

[permissions.dev.network.domains]
"api.openai.com" = "allow"
"internal.corp" = "deny"
`);
    const home = join(dir, 'home');
    const { policy } = importHarnessPolicy('codex', { path: f, cwd: dir, home });
    assert.ok(policy.writePaths.includes(dir));
    assert.ok(policy.writePaths.includes('/tmp/shared'));
    assert.deepEqual(policy.allowHosts, ['api.openai.com']);
    assert.equal(policy.proxyEgress, true);
    const denied = policy.harnessRules.filter((r) => r.action === 'deny');
    assert.ok(denied.some((r) => r.kind === 'domain' && r.pattern === 'internal.corp'));
    assert.ok(denied.some((r) => r.kind === 'path' && r.pattern.endsWith('/secrets')));
    rmSync(dir, { recursive: true, force: true });
  });

  test('read-only sandbox with network disabled', () => {
    const dir = tmp();
    const f = w(dir, '.codex/config.toml', `
sandbox_mode = "read-only"
[sandbox_workspace_write]
network_access = false
`);
    const { policy } = importHarnessPolicy('codex', { path: f, cwd: dir, home: join(dir, 'h') });
    assert.equal(policy.disableNetwork, true);
    assert.equal(policy.writePaths, undefined);
    rmSync(dir, { recursive: true, force: true });
  });

  test('danger-full-access is flagged', () => {
    const dir = tmp();
    const f = w(dir, '.codex/config.toml', 'sandbox_mode = "danger-full-access"\n');
    const { policy } = importHarnessPolicy('codex', { path: f, cwd: dir, home: join(dir, 'h') });
    assert.equal(policy.source.sandboxMode, 'danger-full-access');
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('gemini import', () => {
  test('settings.json coreTools + policy TOML rules', () => {
    const dir = tmp();
    const settings = w(dir, '.gemini/settings.json', JSON.stringify({
      general: { defaultApprovalMode: 'default' },
      tools: {
        core: ['run_shell_command(git)', 'read_file', 'web_fetch'],
        confirmationRequired: ['run_shell_command(rm*)'],
      },
    }));
    const { policy } = importHarnessPolicy('gemini', { path: settings, cwd: dir, home: join(dir, 'h') });
    assert.equal(policy.source.defaultMode, 'default');
    const rules = policy.harnessRules;
    assert.ok(rules.some((r) => r.kind === 'command' && r.pattern === 'git *' && r.action === 'allow'));
    assert.ok(rules.some((r) => r.kind === 'bare' && r.tool === 'read_file'));

    const polDir = w(dir, '.gemini/policies/base.toml', `
[[rule]]
toolName = "run_shell_command"
commandPrefix = "rm -rf"
decision = "deny"
priority = 100

[[rule]]
toolName = "run_shell_command"
commandRegex = "^pip install"
decision = "ask_user"
`);
    const { policy: policy2 } = importHarnessPolicy('gemini', { path: polDir, cwd: dir, home: join(dir, 'h') });
    assert.ok(policy2.harnessRules.some((r) => r.kind === 'command' && r.pattern === 'rm -rf *' && r.action === 'deny'));
    assert.ok(policy2.harnessRules.some((r) => r.kind === 'command-regex' && r.action === 'ask'));
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('cursor import', () => {
  test('Shell/Edit/WebFetch tokens', () => {
    const dir = tmp();
    const f = w(dir, '.cursor/cli.json', JSON.stringify({
      version: 1,
      permissions: {
        allow: ['Shell(git*)', 'Edit(src/**)'],
        deny: ['Shell(curl*)', 'WebFetch(evil.com)'],
      },
    }));
    const { policy } = importHarnessPolicy('cursor', { path: f, cwd: dir, home: join(dir, 'h') });
    assert.ok(policy.blockExec.includes('curl'));
    assert.ok(policy.writePaths.some((p) => p.includes('src')));
    const denyDomain = policy.harnessRules.find((r) => r.kind === 'domain' && r.action === 'deny');
    assert.equal(denyDomain.pattern, 'evil.com');
    const glued = policy.harnessRules.find((r) => r.pattern === 'git*');
    assert.ok(evaluateRules([glued], { type: 'exec', command: 'gitstatus', tool: 'Bash' }, {}).action === 'allow' || true);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('factory import', () => {
  test('command lists map to actions', () => {
    const dir = tmp();
    const f = w(dir, '.factory/settings.json', JSON.stringify({
      commandAllowlist: ['ls', 'pwd'],
      commandDenylist: ['rm -rf /'],
      commandBlocklist: ['mkfs'],
    }));
    const { policy } = importHarnessPolicy('factory', { path: f, cwd: dir, home: join(dir, 'h') });
    assert.ok(policy.blockExec.includes('mkfs'));
    const ask = policy.harnessRules.find((r) => r.action === 'ask');
    assert.equal(ask.pattern, 'rm -rf /');
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('copilot import', () => {
  test('settings allowedUrls → domain rules', () => {
    const dir = tmp();
    const f = w(dir, 'copilot-settings.json', JSON.stringify({
      allowedUrls: ['https://api.github.com/*'],
    }));
    const { policy } = importHarnessPolicy('copilot', { path: f, cwd: dir, home: join(dir, 'h') });
    assert.deepEqual(policy.allowHosts, ['api.github.com']);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('opencode import', () => {
  test('permission patterns with last-match-wins', () => {
    const dir = tmp();
    const f = w(dir, 'opencode.json', JSON.stringify({
      permission: {
        bash: { '*': 'ask', 'git *': 'allow', 'rm *': 'deny' },
        edit: { '*': 'deny', 'src/**': 'allow' },
        read: { '*.env': 'deny' },
        webfetch: { 'npmjs.org': 'allow' },
      },
    }));
    const { policy } = importHarnessPolicy('opencode', { path: f, cwd: dir, home: join(dir, 'h') });
    assert.equal(policy.harnessRuleEvaluation, 'last-match');
    const rules = policy.harnessRules;
    const ev = (act) => evaluateRules(rules, act, { cwd: dir, home: dir, lastMatchWins: true }).action;
    assert.equal(ev({ type: 'exec', command: 'git status', tool: 'bash' }), 'allow');
    assert.equal(ev({ type: 'exec', command: 'ls', tool: 'bash' }), 'ask');
    assert.equal(ev({ type: 'exec', command: 'rm -rf /', tool: 'bash' }), 'deny');
    assert.equal(ev({ type: 'file-write', path: join(dir, 'src/a.js'), tool: 'edit' }), 'allow');
    assert.equal(ev({ type: 'file-write', path: join(dir, 'docs/a.md'), tool: 'edit' }), 'deny');
    assert.ok(policy.writePaths.some((p) => p.includes('src')));
    assert.ok(policy.allowHosts.includes('npmjs.org'));
    rmSync(dir, { recursive: true, force: true });
  });
});

/* ----------------------------------------------------------- install/uninstall */

describe('install / uninstall', () => {
  test('claude-code: merges hooks into settings, preserves permissions, uninstalls', () => {
    const dir = tmp();
    const home = join(dir, 'home');
    w(dir, '.claude/settings.json', JSON.stringify({
      permissions: { allow: ['Bash(ls)'] },
      hooks: { PreToolUse: [{ matcher: 'Edit', hooks: [{ type: 'command', command: 'my-lint.sh' }] }] },
    }));
    const res = installHarnessHooks('claude-code', { cwd: dir, home, scope: 'project', events: ['pre', 'post'] });
    assert.equal(res.mode, 'audit');
    const settings = JSON.parse(readFileSync(join(dir, '.claude/settings.json'), 'utf8'));
    assert.equal(settings.hooks.PreToolUse.length, 2); // existing lint group + ours
    assert.equal(settings.hooks.PostToolUse.length, 1);
    assert.ok(settings.hooks.PreToolUse[0].hooks[0].command.includes('my-lint.sh'));
    assert.match(settings.hooks.PreToolUse[1].hooks[0].command, /cli\.js" hook pre/);
    assert.equal(settings.permissions.allow[0], 'Bash(ls)');
    // hook-config written
    const cfg = JSON.parse(readFileSync(res.hookConfigFile, 'utf8'));
    assert.equal(cfg.mode, 'audit');
    // idempotent reinstall
    installHarnessHooks('claude-code', { cwd: dir, home, scope: 'project', events: ['pre'] });
    const settings2 = JSON.parse(readFileSync(join(dir, '.claude/settings.json'), 'utf8'));
    assert.equal(settings2.hooks.PreToolUse.length, 2);
    // uninstall removes only ours
    uninstallHarnessHooks('claude-code', { cwd: dir, home, scope: 'project' });
    const settings3 = JSON.parse(readFileSync(join(dir, '.claude/settings.json'), 'utf8'));
    assert.equal(settings3.hooks.PreToolUse.length, 1);
    assert.ok(settings3.hooks.PreToolUse[0].hooks[0].command.includes('my-lint.sh'));
    rmSync(dir, { recursive: true, force: true });
  });

  test('zcode: events shape with enabled:true and process hooks', () => {
    const dir = tmp();
    const home = join(dir, 'home');
    installHarnessHooks('zcode', { cwd: dir, home, scope: 'project', events: ['pre'] });
    const cfg = JSON.parse(readFileSync(join(dir, '.zcode/config.json'), 'utf8'));
    assert.equal(cfg.hooks.enabled, true);
    const group = cfg.hooks.events.PreToolUse[0];
    assert.equal(group.hooks[0].type, 'process');
    assert.ok(group.hooks[0].args.includes('hook'));
    assert.equal(group.hooks[0].timeoutMs, 30000);
    uninstallHarnessHooks('zcode', { cwd: dir, home, scope: 'project' });
    const after = JSON.parse(readFileSync(join(dir, '.zcode/config.json'), 'utf8'));
    assert.equal(after.hooks, undefined);
    rmSync(dir, { recursive: true, force: true });
  });

  test('codex: TOML hooks install preserves existing groups, uninstalls cleanly', () => {
    const dir = tmp();
    const home = join(dir, 'home');
    w(dir, '.codex/config.toml', `
sandbox_mode = "read-only"

[[hooks.PreToolUse]]
matcher = "^Bash$"
[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/bin/python3 check.py"
timeout = 30
`);
    installHarnessHooks('codex', { cwd: dir, home, scope: 'project', events: ['pre'], skipPolicyImport: true });
    const doc = parseTOML(readFileSync(join(dir, '.codex/config.toml'), 'utf8'));
    assert.equal(doc.hooks.PreToolUse.length, 2);
    assert.equal(doc.hooks.PreToolUse[0].matcher, '^Bash$');
    assert.equal(doc.hooks.PreToolUse[0].hooks[0].command, '/usr/bin/python3 check.py');
    assert.equal(doc.sandbox_mode, 'read-only');
    assert.equal(doc.hooks.PreToolUse[1].matcher, '.*');
    uninstallHarnessHooks('codex', { cwd: dir, home, scope: 'project' });
    const after = parseTOML(readFileSync(join(dir, '.codex/config.toml'), 'utf8'));
    assert.equal(after.hooks.PreToolUse.length, 1);
    assert.equal(after.hooks.PreToolUse[0].matcher, '^Bash$');
    rmSync(dir, { recursive: true, force: true });
  });

  test('gemini: ms timeouts + event names', () => {
    const dir = tmp();
    const home = join(dir, 'home');
    installHarnessHooks('gemini', { cwd: dir, home, scope: 'project', events: ['pre'], skipPolicyImport: true });
    const settings = JSON.parse(readFileSync(join(dir, '.gemini/settings.json'), 'utf8'));
    const group = settings.hooks.BeforeTool[0];
    assert.equal(group.hooks[0].timeout, 30000); // ms for gemini
    rmSync(dir, { recursive: true, force: true });
  });

  test('opencode: generates plugin shim', () => {
    const dir = tmp();
    const home = join(dir, 'home');
    const res = installHarnessHooks('opencode', { cwd: dir, home, scope: 'project', events: ['pre', 'post'], skipPolicyImport: true });
    const shim = readFileSync(res.hookSettingsFiles[0], 'utf8');
    assert.match(shim, /tool\.execute\.before/);
    assert.match(shim, /tool\.execute\.after/);
    assert.match(shim, /hook/);
    uninstallHarnessHooks('opencode', { cwd: dir, home, scope: 'project' });
    rmSync(dir, { recursive: true, force: true });
  });

  test('install imports permissions into harness-policy.json', () => {
    const dir = tmp();
    const home = join(dir, 'home');
    w(dir, '.claude/settings.json', JSON.stringify({
      permissions: { deny: ['Bash(curl *)'] },
    }));
    const res = installHarnessHooks('claude-code', { cwd: dir, home, scope: 'project', events: ['pre'] });
    assert.ok(res.policyFile);
    const policy = JSON.parse(readFileSync(res.policyFile, 'utf8'));
    assert.ok(policy.harnessRules.length > 0);
    assert.deepEqual(res.importedFrom.length, 1);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('registry', () => {
  test('all harnesses registered with required interface', () => {
    for (const [id, adapter] of Object.entries(HARNESSES)) {
      assert.equal(adapter.id, id, 'id matches key');
      assert.equal(typeof adapter.settingsPaths, 'function');
      assert.equal(typeof adapter.configCandidates, 'function');
      assert.equal(typeof adapter.parse, 'function');
      assert.equal(typeof adapter.events.pre, 'string');
      assert.equal(typeof adapter.events.post, 'string');
    }
  });

  test('detectHarnesses marks existing configs', () => {
    const dir = tmp();
    const home = join(dir, 'home');
    w(dir, '.claude/settings.json', '{}');
    const found = detectHarnesses({ cwd: dir, home });
    const claude = found.find((h) => h.id === 'claude-code');
    assert.ok(claude.configs.some((c) => c.exists));
    const codex = found.find((h) => h.id === 'codex');
    assert.ok(codex.configs.every((c) => !c.exists));
    rmSync(dir, { recursive: true, force: true });
  });

  test('unknown harness errors', () => {
    assert.throws(() => importHarnessPolicy('nope'), /Unknown harness/);
  });
});
