/**
 * Gemini CLI adapter — settings.json (tools.core allowlists, approval mode)
 * + policy-engine TOML rules + BeforeTool/AfterTool hooks.
 *
 * @module gemini
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { readJson } from './common.js';
import { parseTOML } from './toml.js';

/**
 * Parse a `tools.core` / `tools.allowed` entry like `run_shell_command(git)`
 * into a unified command rule (prefix match).
 */
function parseCoreToolEntry(entry, action) {
  const m = /^([a-z_][a-z0-9_]*)\((.*)\)$/i.exec(entry.trim());
  if (!m) return null;
  const tool = m[1];
  const arg = m[2];
  if (tool === 'run_shell_command' || tool === 'shell' || tool === 'bash') {
    return { tool: 'Bash', kind: 'command', pattern: `${arg} *`, action, source: 'gemini' };
  }
  if (tool === 'write_file' || tool === 'replace' || tool === 'edit_file') {
    return { tool: 'Edit', kind: 'path', pattern: arg, access: 'write', action, source: 'gemini', baseDir: '.', home: '~' };
  }
  if (tool === 'read_file' || tool === 'read_many_files' || tool === 'glob' || tool === 'grep' || tool === 'search_file_content') {
    return { tool: 'Read', kind: 'path', pattern: arg, access: 'read', action, source: 'gemini', baseDir: '.', home: '~' };
  }
  if (tool === 'web_fetch') {
    return { tool: 'WebFetch', kind: 'domain', pattern: arg.toLowerCase(), action, source: 'gemini' };
  }
  return { tool, kind: 'param', specifier: arg, action, source: 'gemini' };
}

/**
 * Parse one Gemini policy TOML file into unified rules.
 *
 * @param {string} path
 * @returns {{rules: Object[]}}
 */
function parsePolicyToml(path) {
  /** @type {Object[]} */
  const rules = [];
  let doc;
  try {
    doc = parseTOML(readFileSync(path, 'utf8'));
  } catch {
    return { rules }; // skip malformed policy
  }
  for (const rule of doc.rule || []) {
    if (!rule || typeof rule !== 'object') continue;
    const decision = rule.decision === 'ask_user' ? 'ask' : rule.decision;
    if (decision !== 'allow' && decision !== 'deny' && decision !== 'ask') continue;
    if (rule.commandRegex) {
      rules.push({ tool: 'Bash', kind: 'command-regex', pattern: String(rule.commandRegex), action: decision, source: 'gemini-policy' });
    } else if (rule.commandPrefix) {
      rules.push({ tool: 'Bash', kind: 'command', pattern: `${rule.commandPrefix} *`, action: decision, source: 'gemini-policy' });
    } else if (rule.argsPattern && rule.toolName === 'run_shell_command') {
      // argsPattern is a regex over the JSON-stringified args
      rules.push({ tool: 'Bash', kind: 'command-regex', pattern: String(rule.argsPattern), action: decision, source: 'gemini-policy' });
    } else if (rule.toolName) {
      rules.push({ tool: String(rule.toolName), kind: 'bare', action: decision, source: 'gemini-policy' });
    }
  }
  return { rules };
}

export const gemini = {
  id: 'gemini',
  label: 'Gemini CLI',
  format: 'json',
  events: { pre: 'BeforeTool', post: 'AfterTool' },
  matchAll: '',
  timeoutUnit: 'ms', // Gemini hook timeouts are milliseconds
  supportsUpdatedInput: true,
  geminiOutput: true,

  settingsPaths({ scope, cwd, home }) {
    return scope === 'user'
      ? [join(home, '.gemini', 'settings.json')]
      : [join(cwd, '.gemini', 'settings.json')];
  },

  configCandidates({ cwd, home }) {
    return [
      join(cwd, '.gemini', 'settings.json'),
      join(home, '.gemini', 'settings.json'),
      join(cwd, '.gemini', 'policies'),
      join(home, '.gemini', 'policies'),
    ];
  },

  /**
   * @param {string} file settings.json, a single policy .toml, or a policies directory
   * @param {{cwd: string, home: string}} ctx
   */
  parse(file, ctx) {
    /** @type {Object[]} */
    const rules = [];
    const files = [];

    if (file.endsWith('.json')) {
      const settings = readJson(file);
      files.push(file);
      const tools = settings.tools || {};
      for (const entry of tools.core || tools.allowed || []) {
        const str = String(entry);
        const rule = parseCoreToolEntry(str, 'allow') ||
          { tool: str, kind: 'bare', action: 'allow', source: 'gemini' };
        rules.push(rule);
      }
      for (const entry of tools.confirmationRequired || []) {
        const str = String(entry);
        const rule = parseCoreToolEntry(str, 'ask') ||
          { tool: str, kind: 'bare', action: 'ask', source: 'gemini' };
        rules.push(rule);
      }
      return {
        rules,
        meta: { files, defaultMode: settings.general?.defaultApprovalMode },
      };
    }

    if (file.endsWith('.toml')) {
      const { rules: r } = parsePolicyToml(file);
      return { rules: r, meta: { files: [file] } };
    }

    // policies directory of TOML rule files
    if (existsSync(file)) {
      for (const name of readdirSync(file).sort()) {
        if (!name.endsWith('.toml')) continue;
        const path = join(file, name);
        const { rules: r } = parsePolicyToml(path);
        files.push(path);
        rules.push(...r);
      }
    }
    return { rules, meta: { files } };
  },
};
