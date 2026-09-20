/**
 * Factory droid adapter — Claude-style hooks (`~/.factory/hooks.json` /
 * `.factory/hooks.json`) and command lists in `settings.json`
 * (`commandAllowlist` / `commandDenylist` / `commandBlocklist`).
 *
 * @module factory
 */

import { join } from 'node:path';
import { readJson } from './common.js';

export const factoryDroid = {
  id: 'factory',
  label: 'Factory droid',
  format: 'json',
  events: { pre: 'PreToolUse', post: 'PostToolUse' },
  matchAll: '',
  timeoutUnit: 'sec',
  supportsUpdatedInput: true,

  settingsPaths({ scope, cwd, home }) {
    return scope === 'user'
      ? [join(home, '.factory', 'hooks.json')]
      : [join(cwd, '.factory', 'hooks.json')];
  },

  configCandidates({ cwd, home }) {
    return [
      join(cwd, '.factory', 'settings.local.json'),
      join(cwd, '.factory', 'settings.json'),
      join(home, '.factory', 'settings.json'),
      join(home, '.factory', 'settings.local.json'),
    ];
  },

  parse(file) {
    const settings = readJson(file);
    /** @type {Object[]} */
    const rules = [];
    // deny (block) → ask (deny list requires confirmation) → allow
    for (const [key, action] of [
      ['commandBlocklist', 'deny'],
      ['commandDenylist', 'ask'],
      ['commandAllowlist', 'allow'],
    ]) {
      for (const pattern of settings[key] || []) {
        if (typeof pattern !== 'string') continue;
        rules.push({ tool: 'Bash', kind: 'command', pattern, action, source: 'factory' });
      }
    }
    const sds = settings.sessionDefaultSettings || {};
    return {
      rules,
      meta: {
        files: [file],
        defaultMode: sds.interactionMode,
        autonomyLevel: sds.autonomyLevel,
      },
    };
  },
};
