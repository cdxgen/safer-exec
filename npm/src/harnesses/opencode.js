/**
 * OpenCode adapter — `opencode.json` permission patterns (no native command
 * hooks; install generates a plugin that spawns the safer-exec hook CLI).
 *
 * Permission shape:
 *   { "permission": { "bash": { "git *": "allow", "rm *": "deny" },
 *                     "edit": { "src/**": "allow" },
 *                     "read": { "*.env": "deny" },
 *                     "webfetch": { "example.com": "allow" },
 *                     "external_directory": { "~/x/**": "allow" } } }
 * Evaluation is last-match-wins.
 *
 * @module opencode
 */

import { join } from 'node:path';
import { readJson, expandTilde } from './common.js';

export const opencode = {
  id: 'opencode',
  label: 'OpenCode',
  format: 'json',
  events: { pre: 'PreToolUse', post: 'PostToolUse' },
  matchAll: '',
  timeoutUnit: 'sec',
  supportsUpdatedInput: false,
  pluginOnly: true,
  lastMatchWins: true,

  settingsPaths({ scope, cwd, home }) {
    const configHome = process.env.XDG_CONFIG_HOME || join(home, '.config');
    return scope === 'user'
      ? [join(configHome, 'opencode', 'plugin', 'safer-exec-audit.ts')]
      : [join(cwd, '.opencode', 'plugin', 'safer-exec-audit.ts')];
  },

  configCandidates({ cwd, home }) {
    const configHome = process.env.XDG_CONFIG_HOME || join(home, '.config');
    return [
      join(cwd, 'opencode.json'),
      join(cwd, '.opencode', 'opencode.json'),
      join(configHome, 'opencode', 'opencode.json'),
    ];
  },

  /**
   * @param {string} file opencode.json path
   * @param {{cwd: string, home: string}} ctx
   */
  parse(file, ctx) {
    const cfg = readJson(file);
    const perm = cfg.permission || {};
    /** @type {Object[]} */
    const rules = [];

    for (const [pattern, action] of Object.entries(perm.bash || {})) {
      if (typeof action !== 'string') continue;
      rules.push({ tool: 'Bash', kind: 'command', pattern, action, source: 'opencode' });
    }
    for (const [pattern, action] of Object.entries(perm.edit || {})) {
      if (typeof action !== 'string') continue;
      rules.push({ tool: 'Edit', kind: 'path', pattern, access: 'write', action, source: 'opencode', baseDir: ctx.cwd, home: ctx.home });
    }
    for (const [pattern, action] of Object.entries(perm.read || {})) {
      if (typeof action !== 'string') continue;
      rules.push({ tool: 'Read', kind: 'path', pattern, access: 'read', action, source: 'opencode', baseDir: ctx.cwd, home: ctx.home });
    }
    for (const [pattern, action] of Object.entries(perm.webfetch || {})) {
      if (typeof action !== 'string') continue;
      rules.push({ tool: 'WebFetch', kind: 'domain', pattern: pattern.toLowerCase(), action, source: 'opencode' });
    }
    for (const [pattern, action] of Object.entries(perm.external_directory || {})) {
      if (typeof action !== 'string') continue;
      const abs = expandTilde(pattern, ctx.home);
      rules.push({ tool: 'Read', kind: 'path', pattern: abs.startsWith('/') ? `//${abs.slice(1)}` : abs, access: 'read', action, source: 'opencode', baseDir: ctx.cwd, home: ctx.home });
    }

    return { rules, meta: { files: [file], evaluation: 'last-match' } };
  },
};
