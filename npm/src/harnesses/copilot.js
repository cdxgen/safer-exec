/**
 * GitHub Copilot CLI adapter — Claude-compatible hooks (camelCase events)
 * plus persisted tool approvals and URL allowlists.
 *
 * Hook files: `.github/hooks/safer-exec.json` (repo), `~/.copilot/hooks/` (user),
 * inline `hooks` blocks in settings. Permission sources: `~/.copilot/settings.json`
 * (`allowedUrls`), `.github/copilot/settings.json`, `~/.copilot/permissions-config.json`
 * (best-effort token collection — shape is undocumented).
 *
 * @module copilot
 */

import { join } from 'node:path';
import { readJson } from './common.js';
import { hostFromUrl } from './rules.js';

/**
 * Map a Copilot tool token (`shell(git:*)`, `write(path)`, `read`) to a unified rule.
 */
function parseCopilotToken(token, action) {
  let tool = token;
  let spec = null;
  const paren = token.indexOf('(');
  if (paren >= 0) {
    if (!token.endsWith(')')) return null;
    tool = token.slice(0, paren);
    spec = token.slice(paren + 1, -1);
  }
  const t = tool.toLowerCase();
  if (spec === null) {
    if (t === 'shell' || t === 'bash') return { tool: 'Bash', kind: 'bare', action, source: 'copilot' };
    if (t === 'read') return { tool: 'Read', kind: 'bare', action, source: 'copilot' };
    if (t === 'write' || t === 'edit') return { tool: 'Edit', kind: 'bare', action, source: 'copilot' };
    return { tool, kind: 'bare', action, source: 'copilot' };
  }
  if (t === 'shell' || t === 'bash') {
    // shell(git:*) — colon-star is the argument wildcard
    const pattern = spec.replace(/:\*$/, ' *');
    return { tool: 'Bash', kind: 'command', pattern: pattern.trim(), action, source: 'copilot' };
  }
  if (t === 'read') {
    return { tool: 'Read', kind: 'path', pattern: spec, access: 'read', action, source: 'copilot', baseDir: '.', home: '~' };
  }
  if (t === 'write' || t === 'edit') {
    return { tool: 'Edit', kind: 'path', pattern: spec, access: 'write', action, source: 'copilot', baseDir: '.', home: '~' };
  }
  if (t === 'webfetch' || t === 'fetch') {
    return { tool: 'WebFetch', kind: 'domain', pattern: spec.toLowerCase(), action, source: 'copilot' };
  }
  return { tool, kind: 'param', specifier: spec, action, source: 'copilot' };
}

/**
 * Recursively collect tool-token-looking strings from an undocumented JSON shape.
 *
 * @param {unknown} node
 * @param {string[]} out
 */
function collectTokens(node, out) {
  if (typeof node === 'string') {
    if (/^[a-z_][a-z0-9_.-]*(\(.*\))?$/i.test(node) && node.length < 256) out.push(node);
    return;
  }
  if (Array.isArray(node)) {
    for (const item of node) collectTokens(item, out);
    return;
  }
  if (node && typeof node === 'object') {
    for (const value of Object.values(node)) collectTokens(value, out);
  }
}

export const copilot = {
  id: 'copilot',
  label: 'GitHub Copilot CLI',
  format: 'json',
  events: { pre: 'preToolUse', post: 'postToolUse' },
  matchAll: '',
  timeoutUnit: 'sec',
  supportsUpdatedInput: true,
  camelEvents: true,
  hookFileVersion: 1,

  settingsPaths({ scope, cwd, home }) {
    return scope === 'user'
      ? [join(home, '.copilot', 'hooks', 'safer-exec.json')]
      : [join(cwd, '.github', 'hooks', 'safer-exec.json')];
  },

  configCandidates({ cwd, home }) {
    return [
      join(cwd, '.github', 'copilot', 'settings.json'),
      join(home, '.copilot', 'settings.json'),
      join(home, '.copilot', 'permissions-config.json'),
    ];
  },

  parse(file) {
    const cfg = readJson(file);
    /** @type {Object[]} */
    const rules = [];
    const files = [file];

    if (file.endsWith('permissions-config.json')) {
      const tokens = [];
      collectTokens(cfg, tokens);
      for (const token of tokens) {
        const rule = parseCopilotToken(token, 'allow');
        if (rule) rules.push(rule);
      }
      return { rules, meta: { files, note: 'permissions-config.json approvals (allow-only, best-effort)' } };
    }

    for (const url of cfg.allowedUrls || []) {
      const host = hostFromUrl(String(url));
      if (host) rules.push({ tool: 'WebFetch', kind: 'domain', pattern: host, action: 'allow', source: 'copilot' });
    }
    for (const token of cfg.allowedTools || []) {
      const rule = parseCopilotToken(String(token), 'allow');
      if (rule) rules.push(rule);
    }
    return { rules, meta: { files } };
  },
};
