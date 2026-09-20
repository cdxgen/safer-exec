/**
 * Harness registry — discovery, permission import, and hook install/uninstall
 * across agentic coding harnesses (Claude Code, ZCode, Codex, Gemini CLI,
 * Cursor CLI, Factory droid, GitHub Copilot CLI, OpenCode).
 *
 * The installed hook invokes `safer-exec hook pre|post` which reads the
 * harness payload from stdin, audits every tool activity to a JSONL trail,
 * optionally enforces converted permission rules, and (on Claude-style
 * harnesses) rewrites Bash commands to execute inside the safer-exec sandbox.
 *
 * @module harnesses
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
  copyFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { claudeCode } from './claude-code.js';
import { zcode } from './zcode.js';
import { codex } from './codex.js';
import { gemini } from './gemini.js';
import { cursor } from './cursor.js';
import { factoryDroid } from './factory.js';
import { copilot } from './copilot.js';
import { opencode } from './opencode.js';
import { policyFromRules, deepMerge } from './common.js';
import { parseTOML, stringifyTOML } from './toml.js';

export { parseTOML, stringifyTOML, TOMLError } from './toml.js';

/** All supported harness adapters keyed by id. */
export const HARNESSES = {
  'claude-code': claudeCode,
  zcode,
  codex,
  gemini,
  cursor,
  factory: factoryDroid,
  copilot,
  opencode,
};

const CLI_PATH = fileURLToPath(new URL('../cli.js', import.meta.url));

/**
 * Detect harnesses whose config files exist under cwd/home.
 *
 * @param {{cwd?: string, home?: string}} [opts]
 * @returns {{id: string, label: string, configs: {path: string, exists: boolean}[]}[]}
 */
export function detectHarnesses(opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const home = opts.home || process.env.HOME || '';
  return Object.values(HARNESSES).map((adapter) => {
    const candidates = adapter.configCandidates({ cwd, home });
    return {
      id: adapter.id,
      label: adapter.label,
      configs: candidates.map((path) => ({ path, exists: safeExists(path) })),
    };
  });
}

/**
 * Import a harness's permission config into a safer-exec policy file object.
 *
 * @param {string} harnessId
 * @param {{path?: string, cwd?: string, home?: string}} [opts]
 * @returns {{policy: Record<string, unknown>, sources: string[]}}
 * @throws {Error} unknown harness or no config found
 */
export function importHarnessPolicy(harnessId, opts = {}) {
  const adapter = HARNESSES[harnessId];
  if (!adapter) {
    throw new Error(`Unknown harness: "${harnessId}". Available: ${Object.keys(HARNESSES).join(', ')}`);
  }
  const cwd = opts.cwd || process.cwd();
  const home = opts.home || process.env.HOME || '';

  const candidates = opts.path
    ? [opts.path]
    : adapter.configCandidates({ cwd, home }).filter((p) => !p.endsWith('policies'));
  const files = candidates.filter(safeExists);
  // Gemini policy directories
  if (harnessId === 'gemini' && !opts.path) {
    for (const dir of adapter.configCandidates({ cwd, home })) {
      if (dir.endsWith('policies') && safeExists(dir)) files.push(dir);
    }
  }
  if (files.length === 0) {
    throw new Error(
      `No ${adapter.label} config found (looked in: ${candidates.join(', ')}). ` +
      'Pass --path=<file> to import a specific file.'
    );
  }

  /** @type {Object[]} */
  let rules = [];
  const meta = { files: [] };
  for (const file of files) {
    const parsed = adapter.parse(file, { cwd, home });
    rules = rules.concat(parsed.rules);
    Object.assign(meta, mergeMeta(meta, parsed.meta));
  }
  meta.files = files;
  if (adapter.lastMatchWins) meta.evaluation = 'last-match';

  const policy = policyFromRules({ rules, meta }, { cwd, home, harness: harnessId });
  return { policy, sources: files };
}

/**
 * Merge parsed-meta objects. Candidates are ordered by precedence (highest
 * first), so earlier files win on scalars; arrays concatenate.
 */
function mergeMeta(base, extra) {
  const out = { ...base };
  for (const [k, v] of Object.entries(extra || {})) {
    if (v === undefined) continue;
    if (Array.isArray(v)) {
      const prev = Array.isArray(out[k]) ? out[k] : [];
      out[k] = [...new Set([...prev, ...v])];
    } else if (out[k] === undefined) {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Build the hook command + shared hook config used by install.
 *
 * @param {Object} opts
 * @param {string} opts.harnessId
 * @param {'audit'|'enforce'} [opts.mode]
 * @param {boolean} [opts.wrap]
 * @param {string} [opts.policyFile]
 * @param {string} [opts.auditLog]
 * @param {string} [opts.cwd]
 * @param {string} [opts.home]
 * @param {string} [opts.scope]
 * @param {string[]} [opts.events]
 * @param {number} [opts.timeoutSec]
 * @param {boolean} [opts.skipPolicyImport]
 */
export function installHarnessHooks(harnessId, opts = {}) {
  const adapter = HARNESSES[harnessId];
  if (!adapter) {
    throw new Error(`Unknown harness: "${harnessId}". Available: ${Object.keys(HARNESSES).join(', ')}`);
  }
  const cwd = opts.cwd || process.cwd();
  const home = opts.home || process.env.HOME || '';
  const scope = opts.scope || 'project';
  const events = opts.events || ['pre', 'post'];
  const mode = opts.mode || 'audit';
  const wrap = Boolean(opts.wrap);
  const enforce = mode === 'enforce';

  // 1. Shared hook config (searched by the hook at run time)
  const configDir = scope === 'user' ? join(home, '.safer-exec') : join(cwd, '.safer-exec');
  const configFile = join(configDir, 'hook-config.json');
  mkdirSync(configDir, { recursive: true });

  // 2. Import harness permissions → policy file used for decisions + wrapping
  let policyFile = opts.policyFile || '';
  let imported = [];
  if (!opts.skipPolicyImport) {
    try {
      const { policy, sources } = importHarnessPolicy(harnessId, { cwd, home });
      const pf = join(configDir, 'harness-policy.json');
      writeFileSync(pf, JSON.stringify(policy, null, 2) + '\n');
      policyFile = pf;
      imported = sources;
    } catch {
      // No permission config found — audit mode still works without rules
    }
  }

  const hookConfig = {
    mode: enforce ? 'enforce' : 'audit',
    wrap,
    harness: harnessId,
    policyFile,
    auditLog: opts.auditLog || join(configDir, 'hooks-audit.jsonl'),
    installedAt: new Date().toISOString(),
    scope,
  };
  writeFileSync(configFile, JSON.stringify(hookConfig, null, 2) + '\n');

  // 3. Register hooks in the harness's own settings
  const settingsFiles = adapter.settingsPaths({ scope, cwd, home });
  const target = settingsFiles[0];
  mkdirSync(dirname(target), { recursive: true });
  backupOnce(target);

  const nodeBin = process.execPath;
  const written = [];
  if (adapter.pluginOnly) {
    // OpenCode: generate an in-process plugin that spawns our hook CLI
    for (const f of adapter.settingsPaths({ scope, cwd, home })) {
      writePluginShim(f, nodeBin, CLI_PATH, harnessId);
      written.push(f);
    }
  } else if (adapter.format === 'toml') {
    writeCodexHooks(target, adapter, { nodeBin, events, timeoutSec: opts.timeoutSec || 30 });
    written.push(target);
  } else {
    for (const event of events) {
      const eventName = adapter.events[event];
      if (!eventName) continue;
      const settings = existsSync(target) ? (readJsonOrNull(target) || {}) : {};
      const groups = hookGroupsFor(adapter, settings, eventName);
      // Idempotent: replace any prior safer-exec groups for this event
      for (let i = groups.length - 1; i >= 0; i--) {
        if (groups[i] && Array.isArray(groups[i].hooks) && groups[i].hooks.some(isOurHook)) {
          groups.splice(i, 1);
        }
      }
      groups.push(buildHookGroup(adapter, { nodeBin, phase: event, timeoutSec: opts.timeoutSec || 30 }));
      writeJsonSettings(target, settings);
    }
    written.push(target);
  }

  return {
    harness: harnessId,
    scope,
    mode: hookConfig.mode,
    wrap,
    hookConfigFile: configFile,
    policyFile,
    importedFrom: imported,
    hookSettingsFiles: [...new Set(written)],
    auditLog: hookConfig.auditLog,
  };
}

/**
 * Remove safer-exec hook entries from a harness's settings.
 *
 * @param {string} harnessId
 * @param {{scope?: string, cwd?: string, home?: string}} [opts]
 */
export function uninstallHarnessHooks(harnessId, opts = {}) {
  const adapter = HARNESSES[harnessId];
  if (!adapter) {
    throw new Error(`Unknown harness: "${harnessId}". Available: ${Object.keys(HARNESSES).join(', ')}`);
  }
  const cwd = opts.cwd || process.cwd();
  const home = opts.home || process.env.HOME || '';
  const scope = opts.scope || 'project';
  const removed = [];

  for (const target of adapter.settingsPaths({ scope, cwd, home })) {
    if (!safeExists(target)) continue;
    if (adapter.pluginOnly) {
      try {
        const content = readFileSync(target, 'utf-8');
        if (content.includes('safer-exec')) {
          writeFileSync(target, '// safer-exec audit plugin removed\nexport default async () => ({});\n');
          removed.push(target);
        }
      } catch { /* ignore */ }
      continue;
    }
    if (adapter.format === 'toml') {
      const doc = parseTOML(readFileSync(target, 'utf-8'));
      const hooks = doc.hooks;
      if (hooks && typeof hooks === 'object') {
        let changed = false;
        for (const event of Object.keys(hooks)) {
          const arr = hooks[event];
          if (!Array.isArray(arr)) continue;
          const kept = arr.filter((g) => !(g && Array.isArray(g.hooks) && g.hooks.some(isOurHook)));
          if (kept.length !== arr.length) changed = true;
          if (kept.length === 0) delete hooks[event];
          else hooks[event] = kept;
        }
        if (Object.keys(hooks).length === 0) delete doc.hooks;
        if (changed) {
          writeFileSync(target, stringifyTOML(doc));
          removed.push(target);
        }
      }
      continue;
    }
    const settings = readJsonOrNull(target);
    if (!settings) continue;
    let changed = false;
    const hooksRoot = adapter.hookStyle === 'zcode-events' ? settings.hooks?.events : settings.hooks;
    if (hooksRoot && typeof hooksRoot === 'object') {
      for (const event of Object.keys(hooksRoot)) {
        const arr = hooksRoot[event];
        if (!Array.isArray(arr)) continue;
        const kept = arr.filter((g) => !(g && Array.isArray(g.hooks) && g.hooks.some(isOurHook)));
        if (kept.length !== arr.length) changed = true;
        if (kept.length === 0) delete hooksRoot[event];
        else hooksRoot[event] = kept;
      }
      if (Object.keys(hooksRoot).length === 0) {
        // No hooks remain — drop the whole hooks block (also reverts our
        // ZCode `enabled: true`)
        delete settings.hooks;
      }
    }
    if (changed) {
      writeJsonSettings(target, settings);
      removed.push(target);
    }
  }
  return { harness: harnessId, removed };
}

/**
 * Does a hook entry belong to us? (command or argv mentions safer-exec + hook phase)
 *
 * @param {Object} entry
 * @returns {boolean}
 */
function isOurHook(entry) {
  if (!entry || typeof entry !== 'object') return false;
  const parts = [entry.command, ...(Array.isArray(entry.args) ? entry.args : [])]
    .filter((x) => typeof x === 'string');
  const joined = parts.join(' ');
  return /safer-exec|cli\.js/.test(joined) && /\bhook\s+(pre|post|event)\b/.test(joined);
}

/**
 * Locate (or create) the array of matcher-groups for one event in JSON settings.
 */
function hookGroupsFor(adapter, settings, eventName) {
  if (adapter.hookStyle === 'zcode-events') {
    settings.hooks = settings.hooks || {};
    settings.hooks.enabled = true;
    if (typeof settings.hooks.timeoutMs !== 'number') settings.hooks.timeoutMs = 30000;
    settings.hooks.events = settings.hooks.events || {};
    settings.hooks.events[eventName] = settings.hooks.events[eventName] || [];
    return settings.hooks.events[eventName];
  }
  settings.hooks = settings.hooks || {};
  settings.hooks[eventName] = settings.hooks[eventName] || [];
  return settings.hooks[eventName];
}

/**
 * Build one matcher-group registering our command hook.
 */
function buildHookGroup(adapter, { nodeBin, phase, timeoutSec }) {
  const command = `"${nodeBin}" "${CLI_PATH}" hook ${phase}`;
  if (adapter.hookStyle === 'zcode-events') {
    // ZCode process-style hook: argv vector, timeoutMs in milliseconds
    return {
      hooks: [{
        type: 'process',
        command: nodeBin,
        args: [CLI_PATH, 'hook', phase],
        timeoutMs: timeoutSec * 1000,
        statusMessage: `safer-exec ${phase}-tool audit`,
      }],
    };
  }
  /** @type {Record<string, unknown>} */
  const hook = { type: 'command', command, timeout: timeoutSec };
  if (adapter.timeoutUnit === 'ms') {
    // Gemini expects milliseconds
    hook.timeout = timeoutSec * 1000;
  }
  const group = { hooks: [hook] };
  if (adapter.matchAll && adapter.matchAll !== '') group.matcher = adapter.matchAll;
  return group;
}

/**
 * Codex TOML hook registration ([[hooks.PreToolUse]] array-of-tables).
 */
function writeCodexHooks(target, adapter, { nodeBin, events, timeoutSec }) {
  let doc = {};
  if (safeExists(target)) {
    try {
      doc = parseTOML(readFileSync(target, 'utf-8'));
    } catch (err) {
      throw new Error(`Cannot parse existing ${target}: ${err.message}`);
    }
  }
  doc.hooks = doc.hooks || {};
  for (const event of events) {
    const eventName = adapter.events[event];
    if (!eventName) continue;
    const arr = Array.isArray(doc.hooks[eventName]) ? doc.hooks[eventName] : [];
    const kept = arr.filter((g) => !(g && Array.isArray(g.hooks) && g.hooks.some(isOurHook)));
    kept.push({
      matcher: adapter.matchAll,
      hooks: [{
        type: 'command',
        command: `"${nodeBin}" "${CLI_PATH}" hook ${event}`,
        timeout: timeoutSec,
        statusMessage: `safer-exec ${event}-tool audit`,
      }],
    });
    doc.hooks[eventName] = kept;
  }
  writeFileSync(target, stringifyTOML(doc));
}

/**
 * Generate the OpenCode plugin shim that forwards tool calls to our CLI.
 */
function writePluginShim(file, nodeBin, cliPath, harnessId) {
  mkdirSync(dirname(file), { recursive: true });
  const shim = `// Generated by safer-exec harness install (${harnessId}) — audit/enforce tool calls.
// Remove by deleting this file or running: safer-exec harness uninstall --harness=${harnessId}
import { spawnSync } from "node:child_process";

const NODE = ${JSON.stringify(nodeBin)};
const CLI = ${JSON.stringify(cliPath)};

function runHook(phase, payload) {
  try {
    const res = spawnSync(NODE, [CLI, "hook", phase], {
      input: JSON.stringify(payload),
      encoding: "utf8",
      maxBuffer: 16 * 1024 * 1024,
    });
    if (res.status === 2) {
      throw new Error((res.stderr || "blocked by safer-exec").trim());
    }
    if (res.status !== 0 && res.stderr) {
      console.error("[safer-exec] hook error:", res.stderr.trim());
    }
  } catch (err) {
    if (String(err.message).includes("blocked by safer-exec")) throw err;
    console.error("[safer-exec] hook failed:", err.message);
  }
}

export default async function SaferExecAuditPlugin() {
  return {
    "tool.execute.before": async (input, output) => {
      runHook("pre", {
        hook_event_name: "PreToolUse",
        session_id: input?.sessionID,
        cwd: process.cwd(),
        tool_name: input?.tool,
        tool_input: output?.args ?? {},
      });
    },
    "tool.execute.after": async (input, output) => {
      runHook("post", {
        hook_event_name: "PostToolUse",
        session_id: input?.sessionID,
        cwd: process.cwd(),
        tool_name: input?.tool,
        tool_input: input?.args ?? {},
        tool_response: { title: output?.title },
      });
    },
  };
}
`;
  writeFileSync(file, shim);
}

/**
 * Read JSON settings or null on failure.
 */
function readJsonOrNull(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf-8'));
  } catch {
    return null;
  }
}

/**
 * Write JSON settings with a trailing newline.
 */
function writeJsonSettings(file, settings) {
  writeFileSync(file, JSON.stringify(settings, null, 2) + '\n');
}

/**
 * One-time .bak backup next to a file before we modify it.
 */
function backupOnce(file) {
  if (!safeExists(file)) return;
  const bak = `${file}.safer-exec.bak`;
  if (!safeExists(bak)) {
    try {
      copyFileSync(file, bak);
    } catch { /* best-effort */ }
  }
}

function safeExists(p) {
  try {
    return existsSync(p);
  } catch {
    return false;
  }
}

export { policyFromRules, deepMerge, CLI_PATH };
