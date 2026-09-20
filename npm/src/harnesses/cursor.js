/**
 * Cursor CLI adapter — permission tokens in `cli.json` / `cli-config.json`
 * (`Shell(git*)`, `Edit(src/**)`, `WebFetch(pypi.org)`), kebab-case hook
 * events in `.cursor/hooks.json`.
 *
 * @module cursor
 */

import { dirname, join } from 'node:path';
import { readJson } from './common.js';
import { FETCH_TOOLS, READ_TOOLS, WRITE_TOOLS } from './rules.js';

/**
 * Parse a Cursor permission token into a unified rule.
 * `Shell(git*)` — glued-star prefix; `Edit(src/**)` — gitignore glob;
 * `WebFetch(pypi.org)` — bare domain.
 */
function parseCursorToken(token, action, baseDir, home) {
  let tool = token;
  let spec = null;
  const paren = token.indexOf('(');
  if (paren >= 0) {
    if (!token.endsWith(')')) return null;
    tool = token.slice(0, paren);
    spec = token.slice(paren + 1, -1);
  }
  tool = tool.trim();
  if (spec === null) return { tool, kind: 'bare', action, source: 'cursor' };

  const t = tool.toLowerCase();
  if (t === 'bash' || t === 'shell') {
    return { tool: 'Bash', kind: 'command', pattern: spec.trim(), action, source: 'cursor' };
  }
  if (t === 'webfetch') {
    const domainMatch = /^domain:(.+)$/i.exec(spec);
    return {
      tool: 'WebFetch',
      kind: 'domain',
      pattern: (domainMatch ? domainMatch[1] : spec).trim().toLowerCase(),
      action,
      source: 'cursor',
    };
  }
  if (t === 'edit' || t === 'write') {
    return {
      tool: 'Edit', kind: 'path', pattern: spec, access: 'write', action,
      source: 'cursor', baseDir: baseDir || '.', home,
    };
  }
  if (t === 'read' || t === 'ls' || t === 'grep' || t === 'find') {
    return {
      tool: 'Read', kind: 'path', pattern: spec, access: 'read', action,
      source: 'cursor', baseDir: baseDir || '.', home,
    };
  }
  return { tool, kind: 'param', specifier: spec, action, source: 'cursor' };
}

export const cursor = {
  id: 'cursor',
  label: 'Cursor CLI',
  format: 'json',
  events: { pre: 'pre-tool-use', post: 'post-tool-use' },
  matchAll: '',
  timeoutUnit: 'sec',
  supportsUpdatedInput: true,
  kebabEvents: true,

  settingsPaths({ scope, cwd, home }) {
    return scope === 'user'
      ? [join(home, '.cursor', 'hooks.json')]
      : [join(cwd, '.cursor', 'hooks.json')];
  },

  configCandidates({ cwd, home }) {
    return [
      join(cwd, '.cursor', 'cli.json'),
      join(home, '.cursor', 'cli-config.json'),
    ];
  },

  parse(file, ctx) {
    const cfg = readJson(file);
    const perms = cfg.permissions || {};
    /** @type {Object[]} */
    const rules = [];
    for (const list of ['deny', 'ask', 'allow']) {
      for (const token of perms[list] || []) {
        if (typeof token !== 'string') continue;
        const rule = parseCursorToken(token, list, dirname(file), ctx.home);
        if (rule) rules.push(rule);
      }
    }
    return { rules, meta: { files: [file], version: cfg.version } };
  },
};

export { FETCH_TOOLS, READ_TOOLS, WRITE_TOOLS };
