/**
 * safer-exec hook engine — run as a pre/post tool hook in agentic harnesses.
 *
 * Contract (Claude-lineage, adopted by Claude Code, ZCode, Cursor, Factory
 * droid, Copilot CLI, Gemini CLI): one JSON payload on stdin; exit 0 passes,
 * exit 2 blocks (stderr = reason); optional structured JSON on stdout for
 * permission decisions and Bash command rewriting.
 *
 * Modes:
 *  - audit (default): append every tool activity (file IO / network / exec)
 *    to a JSONL trail; never interfere.
 *  - enforce: evaluate the converted permission rules; deny blocks the tool
 *    (exit 2), an explicit allow rule answers the permission decision.
 *  - wrap: rewrite Bash tool input so the command executes inside the
 *    safer-exec OS sandbox with filesystem diffing + exec/network auditing.
 *
 * @module hooks
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  FETCH_TOOLS,
  READ_TOOLS,
  SEARCH_TOOLS,
  SHELL_TOOLS,
  WRITE_TOOLS,
  evaluateRules,
  hostFromUrl,
  resolveActivityPath,
} from './harnesses/rules.js';

const CLI_PATH = fileURLToPath(new URL('./cli.js', import.meta.url));

/** Map any harness's event name to the canonical one. */
const EVENT_ALIASES = {
  beforetool: 'PreToolUse',
  aftertool: 'PostToolUse',
  pretooluse: 'PreToolUse',
  posttooluse: 'PostToolUse',
  'pre-tool-use': 'PreToolUse',
  'post-tool-use': 'PostToolUse',
  permissionrequest: 'PermissionRequest',
  posttoolusefailure: 'PostToolUseFailure',
  sessionstart: 'SessionStart',
  sessionend: 'SessionEnd',
  userpromptsubmit: 'UserPromptSubmit',
  usersubmittedprompt: 'UserPromptSubmit',
};

/**
 * Read all of stdin (hook payloads arrive piped).
 *
 * @returns {Promise<string>}
 */
export function readStdinAll() {
  return new Promise((resolve, reject) => {
    if (process.stdin.isTTY) return resolve('');
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

/**
 * Locate the shared hook configuration.
 * Order: $SAFER_EXEC_HOOK_CONFIG → <cwd>/.safer-exec/hook-config.json →
 * ~/.safer-exec/hook-config.json → built-in defaults.
 *
 * @param {{cwd?: string, home?: string}} [opts]
 * @returns {Object}
 */
export function loadHookConfig(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const home = opts.home || process.env.HOME || '';
  const defaults = {
    mode: 'audit',
    wrap: false,
    harness: '',
    policyFile: '',
    auditLog: join(home, '.safer-exec', 'hooks-audit.jsonl'),
  };
  let loaded = null;
  const candidates = [
    process.env.SAFER_EXEC_HOOK_CONFIG,
    join(cwd, '.safer-exec', 'hook-config.json'),
    join(home, '.safer-exec', 'hook-config.json'),
  ].filter(Boolean);
  for (const file of candidates) {
    if (!existsSync(file)) continue;
    try {
      loaded = JSON.parse(readFileSync(file, 'utf-8'));
      break;
    } catch { /* try next */ }
  }
  const config = { ...defaults, ...(loaded || {}) };
  // Environment overrides (per-invocation, no file needed)
  if (process.env.SAFER_EXEC_HOOK_MODE) config.mode = process.env.SAFER_EXEC_HOOK_MODE;
  if (process.env.SAFER_EXEC_HOOK_WRAP) config.wrap = process.env.SAFER_EXEC_HOOK_WRAP === '1' || process.env.SAFER_EXEC_HOOK_WRAP === 'true';
  if (process.env.SAFER_EXEC_HOOK_POLICY) config.policyFile = process.env.SAFER_EXEC_HOOK_POLICY;
  if (process.env.SAFER_EXEC_HOOK_AUDIT_LOG) config.auditLog = process.env.SAFER_EXEC_HOOK_AUDIT_LOG;
  if (process.env.SAFER_EXEC_HOOK_HARNESS) config.harness = process.env.SAFER_EXEC_HOOK_HARNESS;
  return config;
}

/**
 * Normalize any harness's hook payload into a canonical shape.
 *
 * @param {Object} raw parsed stdin JSON
 * @param {{phase?: 'pre'|'post', harness?: string}} [opts]
 */
export function normalizeHookPayload(raw, opts = {}) {
  const rawEvent = raw.hook_event_name || raw.hookEvent || raw.event || raw.type || '';
  let event = EVENT_ALIASES[String(rawEvent).toLowerCase().replace(/[\s_-]/g, '')] ||
    (typeof rawEvent === 'string' && rawEvent ? rawEvent : '');
  if (!event && opts.phase) event = opts.phase === 'pre' ? 'PreToolUse' : 'PostToolUse';

  const harness = opts.harness ||
    raw.__harness ||
    detectHarness(raw, event);

  const toolName = raw.tool_name ?? raw.toolName ?? raw.tool ?? '';
  let toolInput = raw.tool_input ?? raw.toolInput ?? null;
  if (toolInput === null && typeof raw.toolArgs === 'string') {
    // Copilot camelCase payloads stringify the args — parse twice
    try {
      toolInput = JSON.parse(raw.toolArgs);
    } catch {
      toolInput = { command: raw.toolArgs };
    }
  }
  if (toolInput === null && raw.toolInputString) {
    try {
      toolInput = JSON.parse(raw.toolInputString);
    } catch { toolInput = {}; }
  }
  if (toolInput === null || typeof toolInput !== 'object') toolInput = {};

  return {
    harness,
    event,
    sessionId: raw.session_id ?? raw.sessionId ?? '',
    toolUseId: raw.tool_use_id ?? raw.toolUseId ?? '',
    cwd: raw.cwd || process.cwd(),
    permissionMode: raw.permission_mode ?? raw.permissionMode ?? '',
    toolName: String(toolName),
    toolInput,
    toolResponse: raw.tool_response ?? raw.toolResponse ?? raw.toolResult ?? null,
    durationMs: raw.duration_ms ?? raw.durationMs ?? undefined,
    raw,
  };
}

/**
 * Guess the harness from payload shape.
 *
 * @param {Object} raw
 * @param {string} event
 * @returns {string}
 */
function detectHarness(raw, event) {
  if (typeof raw.toolArgs === 'string') return 'copilot';
  const rawEvent = String(raw.hook_event_name || raw.hookEvent || '');
  if (/^(Before|After)Tool$/.test(rawEvent)) return 'gemini';
  if (/^[a-z]+(-[a-z]+)+$/.test(rawEvent)) return 'cursor'; // kebab-case
  if (/^[a-z][a-zA-Z]+$/.test(rawEvent) && /^pre|^post|^session|^agent|^user/.test(rawEvent)) return 'copilot';
  return 'claude-code';
}

/**
 * Extract the tracked activity from a normalized payload.
 *
 * File paths are canonically resolved against the payload cwd (relative,
 * dot-segment and up-level forms all normalize to one absolute path), and a
 * symlink-resolved `realPath` is added when it differs — both are matched
 * against path rules so neither form bypasses a deny rule.
 *
 * @param {{toolName: string, toolInput: Object, event: string, harness: string, cwd: string}} norm
 * @returns {{type: string, command?: string, path?: string, realPath?: string, url?: string, host?: string, query?: string, tool: string}}
 */
export function extractActivity(norm) {
  const tool = norm.toolName;
  const input = norm.toolInput || {};
  const command = input.command ?? input.cmd ?? (typeof input.script === 'string' ? input.script : undefined);
  const rawPath = input.file_path ?? input.filePath ?? input.path ?? input.filename ?? undefined;
  const url = input.url ?? input.URI ?? undefined;

  let filePath;
  let realPath;
  if (typeof rawPath === 'string' && rawPath !== '') {
    filePath = resolveActivityPath(rawPath, norm.cwd);
    try {
      realPath = realpathSync.native(rawPath.startsWith('/') || rawPath.startsWith('~') ? rawPath : filePath);
      if (process.platform === 'win32') realPath = realPath.replace(/\\/g, '/');
      if (realPath === filePath) realPath = undefined;
    } catch {
      realPath = undefined; // file may not exist yet (Write) — lexical path only
    }
  }

  /** @type {{type: string, tool: string}} */
  let activity = { type: 'other', tool };
  if (SHELL_TOOLS.has(tool) && typeof command === 'string') {
    activity = { type: 'exec', tool, command };
  } else if (FETCH_TOOLS.has(tool) && typeof url === 'string') {
    activity = { type: 'network-fetch', tool, url, host: hostFromUrl(url) || url };
  } else if (SEARCH_TOOLS.has(tool) && typeof input.query === 'string') {
    activity = { type: 'network-search', tool, query: input.query, host: 'search' };
  } else if (WRITE_TOOLS.has(tool) && typeof filePath === 'string') {
    activity = realPath ? { type: 'file-write', tool, path: filePath, realPath } : { type: 'file-write', tool, path: filePath };
  } else if (READ_TOOLS.has(tool)) {
    activity = {
      type: 'file-read',
      tool,
      path: filePath,
      ...(realPath ? { realPath } : {}),
      pattern: typeof input.pattern === 'string' ? input.pattern : undefined,
    };
  } else if (/^mcp__/i.test(tool)) {
    const parts = tool.split('__');
    activity = { type: 'mcp-call', tool, server: parts[1] || '', mcpTool: parts.slice(2).join('__') };
  } else if (tool === 'Agent' || tool === 'Task') {
    activity = { type: 'agent', tool, description: input.description, subagent: input.subagent_type || input.subagentType };
  } else if (tool === 'KillShell' || tool === 'KillBash') {
    activity = { type: 'signal', tool };
  } else if (typeof command === 'string') {
    activity = { type: 'exec', tool, command };
  }
  return activity;
}

/**
 * Load the harnessRules + evaluation mode from the configured policy file.
 * Failures are reported (not thrown) so the caller can warn loudly in
 * enforce mode — a silent empty rule set would turn enforcement off.
 *
 * @param {string} policyFile
 * @returns {{rules: Object[], lastMatchWins: boolean, raw: Object|null, error: string|null}}
 */
function loadPolicyRules(policyFile) {
  if (!policyFile) {
    return { rules: [], lastMatchWins: false, raw: null, error: 'no policy file configured' };
  }
  if (!existsSync(policyFile)) {
    return { rules: [], lastMatchWins: false, raw: null, error: `policy file not found: ${policyFile}` };
  }
  try {
    const raw = JSON.parse(readFileSync(policyFile, 'utf-8'));
    return {
      rules: Array.isArray(raw.harnessRules) ? raw.harnessRules : [],
      lastMatchWins: raw.harnessRuleEvaluation === 'last-match',
      raw,
      error: null,
    };
  } catch (err) {
    return { rules: [], lastMatchWins: false, raw: null, error: `invalid policy file ${policyFile}: ${err.message}` };
  }
}

/**
 * Single-quote a value for a POSIX shell. Every character between the quotes
 * is literal — this is the only quoting style without exceptions, so
 * interpolated paths (policy file, audit log — both derived from the
 * workspace directory name, which we do not control) cannot break out or
 * trigger expansions.
 *
 * @param {string} s
 * @returns {string}
 */
function shQuote(s) {
  return `'${String(s).replace(/'/g, "'\\''")}'`;
}

/** Cached POSIX shell used for wrapped commands (bash preferred, sh fallback). */
let wrapShell;

/**
 * Pick the shell for wrapped commands. `/bin/bash` is preferred (harness
 * semantics are bash-flavored); images without bash (Alpine/musl and other
 * minimal containers) fall back to `/bin/sh`, which supports the
 * `eval "$(printf %s "$VAR" | base64 -d)"` transport equally.
 *
 * @returns {string}
 */
export function shellForWrap() {
  if (wrapShell) return wrapShell;
  for (const candidate of ['/bin/bash', '/usr/bin/bash', '/bin/sh']) {
    try {
      if (existsSync(candidate)) {
        wrapShell = candidate;
        return wrapShell;
      }
    } catch { /* try next */ }
  }
  wrapShell = '/bin/sh';
  return wrapShell;
}

/**
 * Build the wrapped safer-exec command for a Bash tool input.
 *
 * The original command travels base64-encoded in an env var (avoids all
 * quoting hazards); the sandbox passes it to the shell verbatim. Every
 * interpolated path is single-quote escaped.
 *
 * @param {string} command
 * @param {{policyFile?: string, auditLog?: string, cwd?: string, sessionId?: string}} [opts]
 * @returns {string}
 */
export function buildWrapCommand(command, opts = {}) {
  const policyFile = opts.policyFile || '';
  const auditLog = opts.auditLog || '';
  const parts = [
    shQuote(process.execPath),
    shQuote(CLI_PATH),
  ];
  if (policyFile) parts.push(`--policy-file=${shQuote(policyFile)}`);
  parts.push('--diff', '--audit', '--trace-exec');
  if (auditLog) parts.push(`--audit-output-file=${shQuote(auditLog)}`);
  const b64 = Buffer.from(command, 'utf8').toString('base64');
  parts.push(`--env=${shQuote(`SAFER_EXEC_WRAPPED_CMD=${b64}`)}`);
  // Decode inside the sandbox — the eval payload is a fixed literal and the
  // transported command never touches the outer quoting layer
  parts.push('--', shQuote(shellForWrap()), '-c', `'eval "$(printf %s "$SAFER_EXEC_WRAPPED_CMD" | base64 -d)"'`);
  return parts.join(' ');
}

/**
 * Summarize a PostToolUse tool_response for the audit trail (bounded size).
 *
 * @param {unknown} resp
 * @returns {Object}
 */
export function summarizeResponse(resp) {
  if (resp === null || resp === undefined) return {};
  if (typeof resp !== 'object') return { value: String(resp).slice(0, 200) };
  /** @type {Record<string, unknown>} */
  const out = {};
  for (const key of ['type', 'filePath', 'file_path', 'error', 'interrupted', 'status', 'exitCode', 'exit_code']) {
    if (resp[key] !== undefined) out[key] = resp[key];
  }
  if (typeof resp.stdout === 'string') out.stdoutBytes = Buffer.byteLength(resp.stdout);
  if (typeof resp.stderr === 'string') out.stderrBytes = Buffer.byteLength(resp.stderr);
  const bed = resp.bashEditDiff;
  if (bed && Array.isArray(bed.changedFiles)) {
    out.changedFiles = bed.changedFiles.slice(0, 50);
    out.changedFilesCount = bed.changedFiles.length;
  }
  return out;
}

/**
 * Append one JSONL audit record.
 *
 * @param {Object} config hook config
 * @param {Object} record
 */
function appendAudit(config, record) {
  const file = config.auditLog;
  if (!file) return;
  try {
    mkdirSync(dirname(file), { recursive: true });
    appendFileSync(file, JSON.stringify(record) + '\n');
  } catch (err) {
    process.stderr.write(`[safer-exec] hook: cannot write audit log: ${err.message}\n`);
  }
}

/**
 * Handle one hook payload. Pure logic — returns the process outcome.
 *
 * @param {Object} raw parsed payload
 * @param {{phase?: 'pre'|'post', harness?: string, config?: Object}} [opts]
 * @returns {{exitCode: number, stdout?: string, stderr?: string, record: Object}}
 */
export function handleHookEvent(raw, opts = {}) {
  const config = opts.config || loadHookConfig({ cwd: raw.cwd });
  const harness = opts.harness || config.harness || undefined;
  const norm = normalizeHookPayload(raw, { phase: opts.phase, harness });
  const activity = extractActivity(norm);
  const phase = norm.event === 'PostToolUse' ? 'post' : 'pre';

  /** @type {Object} */
  const record = {
    ts: new Date().toISOString(),
    harness: norm.harness,
    event: norm.event,
    tool: norm.toolName,
    activity,
    sessionId: norm.sessionId,
    toolUseId: norm.toolUseId,
    cwd: norm.cwd,
    permissionMode: norm.permissionMode,
    pid: process.pid,
    decision: 'passthrough',
  };
  if (norm.durationMs !== undefined) record.durationMs = norm.durationMs;

  // ---- Decision (enforce mode) ----
  let decision = null;
  let decisionReason = '';
  let enforcementWarning = null;
  if (phase === 'pre' && config.mode === 'enforce') {
    const { rules, lastMatchWins, error } = loadPolicyRules(config.policyFile);
    if (error) {
      enforcementWarning = `enforce mode is NOT enforcing rules — ${error}`;
    } else if (rules.length === 0) {
      enforcementWarning = `enforce mode has no rules to enforce (policy ${config.policyFile} carries no harnessRules)`;
    } else {
      const result = evaluateRules(rules, activity, { cwd: norm.cwd, home: process.env.HOME || '', lastMatchWins });
      decision = result.action;
      if (result.rule) {
        decisionReason = ruleDescription(result.rule);
      }
    }
  }

  // ---- Wrapping (Bash exec activities on supporting harnesses) ----
  let wrappedCommand = null;
  const supportsUpdatedInput = ['claude-code', 'cursor', 'factory', 'copilot', 'gemini'].includes(norm.harness);
  if (
    phase === 'pre' &&
    decision !== 'deny' &&
    config.wrap &&
    supportsUpdatedInput &&
    activity.type === 'exec' &&
    typeof activity.command === 'string' &&
    !norm.toolInput.run_in_background
  ) {
    wrappedCommand = buildWrapCommand(activity.command, {
      policyFile: buildWrapPolicy(config, norm.cwd),
      auditLog: config.auditLog,
      cwd: norm.cwd,
      sessionId: norm.sessionId,
    });
  }

  // ---- Audit record ----
  if (decision) record.decision = decision;
  if (decisionReason) record.reason = decisionReason;
  if (enforcementWarning) record.enforcementWarning = enforcementWarning;
  if (wrappedCommand) record.wrapped = true;
  if (phase === 'post') {
    record.response = summarizeResponse(norm.toolResponse);
  }
  appendAudit(config, record);

  // ---- Outcome ----
  if (phase === 'pre' && decision === 'deny') {
    return {
      exitCode: 2,
      stderr: `[safer-exec] Blocked by ${norm.harness} permission rule: ${decisionReason || 'denied'}\n`,
      warning: enforcementWarning,
      record,
    };
  }

  let stdout;
  if (phase === 'pre' && wrappedCommand) {
    const updatedInput = { ...norm.toolInput, command: wrappedCommand };
    if (norm.harness === 'gemini') {
      stdout = JSON.stringify({ hookSpecificOutput: { tool_input: updatedInput } });
    } else {
      const hookSpecificOutput = {
        hookEventName: 'PreToolUse',
        updatedInput,
      };
      if (decision === 'allow') {
        hookSpecificOutput.permissionDecision = 'allow';
        hookSpecificOutput.permissionDecisionReason = 'allowed by converted permission rules; wrapped in safer-exec sandbox';
      }
      stdout = JSON.stringify({ hookSpecificOutput });
    }
  } else if (phase === 'pre' && decision === 'allow' && !wrappedCommand) {
    if (norm.harness === 'gemini') {
      // Gemini's output schema uses a top-level decision
      stdout = JSON.stringify({ decision: 'allow', reason: decisionReason || 'allowed by converted permission rules' });
    } else {
      // Claude-lineage harnesses and ZCode all accept this decision shape
      // (ZCode's output schema also allows hookSpecificOutput.permissionDecision)
      stdout = JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          permissionDecisionReason: decisionReason || 'allowed by converted permission rules',
        },
      });
    }
  } else if (phase === 'pre' && decision === 'ask') {
    if (norm.harness !== 'gemini' && norm.harness !== 'zcode') {
      stdout = JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask',
          permissionDecisionReason: decisionReason || 'requires confirmation (ask rule)',
        },
      });
    }
    // gemini/zcode: stay silent — the harness's default flow already asks
  }

  return { exitCode: 0, stdout, warning: enforcementWarning, record };
}

/**
 * Human description of a matched rule.
 *
 * @param {Object} rule
 * @returns {string}
 */
function ruleDescription(rule) {
  const what = rule.kind === 'command' || rule.kind === 'command-regex'
    ? `${rule.tool}(${rule.pattern})`
    : rule.kind === 'domain'
      ? `${rule.tool}(domain:${rule.pattern})`
      : rule.kind === 'path'
        ? `${rule.tool}(${rule.pattern})`
        : rule.tool;
  return `${rule.action} rule ${what} [${rule.source}]`;
}

/**
 * Derive the sandbox policy used for wrapped commands.
 *
 * Wrapping must preserve the harness's own semantics: agent shells can read
 * broadly and write the workspace, while denials (blocked executables,
 * off-limits hosts) carry over from the imported permission rules. So the
 * wrap policy is: reads open (audited via fsdiff/violations, not confined),
 * writes limited to the workspace + tmp + imported write roots, and network /
 * exec controls from the imported policy when present.
 *
 * The derived policy is cached at `<cwd>/.safer-exec/wrap-policy.json`
 * (rewritten only when its content changes).
 *
 * @param {Object} config hook config
 * @param {string} cwd payload cwd
 * @returns {string} path of the policy to enforce for the wrapped command
 */
function buildWrapPolicy(config, cwd) {
  let realCwd = cwd;
  try {
    realCwd = realpathSync(cwd);
  } catch { /* keep literal */ }

  /** @type {Record<string, unknown>} */
  let policy = {
    name: 'safer-exec-wrap-default',
    version: '1',
    description: 'Permissive wrap policy (audit + fsdiff over the workspace). No harness permission config was found.',
    readPaths: ['/'],
    writePaths: [realCwd],
    allowLoopback: true,
  };
  const imported = loadPolicyRules(config.policyFile).raw;
  if (imported) {
    policy = {
      ...imported,
      name: `${imported.name || 'harness'}-wrap`,
      description: `Derived wrap policy from ${config.policyFile}`,
      readPaths: ['/'],
      writePaths: [...new Set([
        realCwd,
        ...(Array.isArray(imported.writePaths) ? imported.writePaths : []),
      ])],
    };
    delete policy.harnessRules;
    delete policy.harnessRuleEvaluation;
    delete policy.source;
  }

  const dir = join(realCwd, '.safer-exec');
  const path = join(dir, 'wrap-policy.json');
  try {
    mkdirSync(dir, { recursive: true });
    const content = JSON.stringify(policy, null, 2) + '\n';
    if (!existsSync(path) || readFileSync(path, 'utf8') !== content) {
      writeFileSync(path, content);
    }
    return path;
  } catch { /* cwd not writable — fall back to home */ }
  const homeDir = join(process.env.HOME || '.', '.safer-exec');
  const homePath = join(homeDir, 'wrap-policy.json');
  try {
    mkdirSync(homeDir, { recursive: true });
    writeFileSync(homePath, JSON.stringify(policy, null, 2) + '\n');
  } catch { /* best-effort */ }
  return homePath;
}

/**
 * CLI entry: `safer-exec hook <pre|post>`.
 *
 * @param {string} phase
 * @returns {Promise<number>} exit code
 */
export async function runHookCli(phase) {
  const input = await readStdinAll();
  let payload;
  if (input.trim() === '') {
    // No payload (e.g. manual invocation) — nothing to audit
    return 0;
  }
  try {
    payload = JSON.parse(input);
  } catch (err) {
    process.stderr.write(`[safer-exec] hook: invalid JSON payload: ${err.message}\n`);
    return 0; // fail-open: non-blocking error
  }
  if (!payload || typeof payload !== 'object') return 0;

  try {
    const { exitCode, stdout, stderr, warning } = handleHookEvent(payload, { phase });
    if (stdout) process.stdout.write(stdout + '\n');
    if (stderr) process.stderr.write(stderr);
    // Loud signal when enforce mode is degraded — a silent empty rule set
    // would look like enforcement while allowing everything.
    if (warning) process.stderr.write(`[safer-exec] WARNING: ${warning}\n`);
    return exitCode;
  } catch (err) {
    // Fail-open: an audit hook must never break the agent
    process.stderr.write(`[safer-exec] hook error (fail-open): ${err.message}\n`);
    return 0;
  }
}

/**
 * Read the hook audit JSONL trail.
 *
 * @param {string} [file]
 * @param {{last?: number} & Record<string, unknown>} [opts]
 * @returns {Object[]}
 */
export function readAuditTrail(file, opts = {}) {
  const path = file || join(process.env.HOME || '.', '.safer-exec', 'hooks-audit.jsonl');
  if (!existsSync(path)) return [];
  const lines = readFileSync(path, 'utf-8').split('\n').filter(Boolean);
  const records = lines
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
  const last = Number(opts.last || 0);
  return last > 0 ? records.slice(-last) : records;
}
