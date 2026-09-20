/**
 * Claude Code adapter — permissions tokens + Claude-style hooks settings.
 *
 * @module claude-code
 */

import { basename, dirname, join } from 'node:path';
import { readJson } from './common.js';
import { parseClaudeToken } from './rules.js';

export const claudeCode = {
  id: 'claude-code',
  label: 'Claude Code',
  format: 'json',
  events: { pre: 'PreToolUse', post: 'PostToolUse' },
  matchAll: '',
  timeoutUnit: 'sec',
  supportsUpdatedInput: true,

  settingsPaths({ scope, cwd, home }) {
    return scope === 'user'
      ? [join(home, '.claude', 'settings.json')]
      : [join(cwd, '.claude', 'settings.json'), join(cwd, '.claude', 'settings.local.json')];
  },

  configCandidates({ cwd, home }) {
    return [
      join(cwd, '.claude', 'settings.local.json'),
      join(cwd, '.claude', 'settings.json'),
      join(home, '.claude', 'settings.json'),
    ];
  },

  /**
   * Claude resolves single-leading-`/` specifiers against the settings
   * source's root: the project dir for `.claude/settings*.json`, home for
   * `~/.claude/settings.json` — i.e. the parent of the `.claude` directory.
   *
   * @param {string} file settings.json path
   * @param {{cwd: string, home: string}} ctx
   */
  parse(file, ctx) {
    const settings = readJson(file);
    const perms = settings.permissions || {};
    // `/path` rules resolve against the directory containing .claude/
    const settingsDir = dirname(file);
    const baseDir = basename(settingsDir) === '.claude' ? dirname(settingsDir) : settingsDir;
    /** @type {Object[]} */
    const rules = [];
    for (const list of ['deny', 'ask', 'allow']) {
      const action = list;
      for (const token of perms[list] || []) {
        if (typeof token !== 'string') continue;
        const { rule } = parseClaudeToken(token, action, 'claude-code', baseDir, ctx.home);
        if (rule) rules.push(rule);
      }
    }
    return {
      rules,
      meta: {
        files: [file],
        defaultMode: perms.defaultMode,
        additionalDirectories: perms.additionalDirectories || [],
      },
    };
  },
};
