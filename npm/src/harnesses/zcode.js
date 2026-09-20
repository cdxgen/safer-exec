/**
 * ZCode adapter — Claude-compatible hook payloads, config-file hooks.
 *
 * ZCode has no documented permission-token syntax; this adapter exists for
 * hook install/uninstall and payload normalization (`~/.zcode/cli/config.json`
 * or workspace `.zcode/config.json`, shape
 * `{ hooks: { enabled, events: { <Event>: [ { matcher?, hooks: [...] } ] } } }`).
 *
 * @module zcode
 */

import { join } from 'node:path';
import { readJson } from './common.js';

export const zcode = {
  id: 'zcode',
  label: 'ZCode',
  format: 'json',
  events: { pre: 'PreToolUse', post: 'PostToolUse' },
  matchAll: '', // omitted matcher matches everything
  timeoutUnit: 'ms',
  supportsUpdatedInput: false, // strict output schema — exit codes only
  hookStyle: 'zcode-events',

  settingsPaths({ scope, cwd, home }) {
    return scope === 'user'
      ? [join(home, '.zcode', 'cli', 'config.json')]
      : [join(cwd, '.zcode', 'config.json'), join(cwd, 'zcode.json')];
  },

  configCandidates({ cwd, home }) {
    return [
      join(cwd, '.zcode', 'config.json'),
      join(cwd, 'zcode.json'),
      join(home, '.zcode', 'cli', 'config.json'),
    ];
  },

  /**
   * ZCode exposes no permission model — the parsed result is empty and the
   * converted policy is a sensible default for command wrapping.
   */
  parse(file) {
    const cfg = readJson(file);
    return {
      rules: [],
      meta: {
        files: [file],
        note: 'ZCode has no permission-token config; hooks only',
        hasHooks: Boolean(cfg.hooks),
      },
    };
  },
};
