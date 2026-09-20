/**
 * OpenAI Codex adapter — `config.toml` (sandbox_mode, [sandbox_workspace_write],
 * beta [permissions] profiles, execpolicy rules) and TOML lifecycle hooks.
 *
 * @module codex
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseTOML } from './toml.js';

/**
 * Read and parse a TOML config file.
 *
 * @param {string} file
 * @returns {Record<string, unknown>}
 */
function readToml(file) {
  let text;
  try {
    text = readFileSync(file, 'utf-8');
  } catch (err) {
    throw new Error(`Cannot read ${file}: ${err.message}`);
  }
  return parseTOML(text);
}

/**
 * Convert Codex filesystem permission values to unified rules + path roots.
 *
 * @param {Record<string, string>} fsMap [permissions.X.filesystem] table
 * @param {Object} profile
 * @param {string} home
 * @returns {{rules: Object[], readRoots: string[], writeRoots: string[], deniedPaths: string[]}}
 */
function convertFsMap(fsMap, profile, home) {
  const rules = [];
  const readRoots = [];
  const writeRoots = [];
  const deniedPaths = [];
  const special = new Set([':root', ':minimal', ':workspace_roots', ':tmpdir', ':slash_tmp']);

  for (const [rawPath, mode] of Object.entries(fsMap || {})) {
    if (rawPath === 'glob_scan_max_depth') continue;
    const access = mode === 'write' ? 'write' : mode === 'read' ? 'read' : null; // deny/none
    const abs = expandCodexPath(rawPath, home);
    if (special.has(rawPath)) continue;
    if (!access) {
      deniedPaths.push(abs);
      rules.push({
        tool: 'Read',
        kind: 'path',
        pattern: `//${abs.replace(/^\//, '')}`,
        access: 'read',
        action: 'deny',
        source: 'codex',
        baseDir: '.',
        home,
      });
      continue;
    }
    rules.push({
      tool: access === 'write' ? 'Edit' : 'Read',
      kind: 'path',
      pattern: `//${abs.replace(/^\//, '')}`,
      access,
      action: 'allow',
      source: 'codex',
      baseDir: '.',
      home,
    });
    (access === 'write' ? writeRoots : readRoots).push(abs);
  }

  // workspace_roots subtable: entries relative to the workspace root
  const sub = profile?.filesystem?.[':workspace_roots'];
  for (const [rel, mode] of Object.entries(sub || {})) {
    const access = mode === 'write' ? 'write' : mode === 'read' ? 'read' : null;
    if (!access) {
      rules.push({
        tool: 'Read', kind: 'path', pattern: `//workspace/${rel}`, access: 'read',
        action: 'deny', source: 'codex', baseDir: '.', home,
      });
      continue;
    }
    rules.push({
      tool: access === 'write' ? 'Edit' : 'Read',
      kind: 'path',
      pattern: `//workspace/${rel}`,
      access,
      action: 'allow',
      source: 'codex',
      baseDir: '.',
      home,
    });
  }
  return { rules, readRoots, writeRoots, deniedPaths };
}

/**
 * Expand Codex special/tilde path markers.
 *
 * @param {string} p
 * @param {string} home
 * @returns {string}
 */
function expandCodexPath(p, home) {
  if (p === ':root' || p === ':minimal') return '/';
  if (p === ':tmpdir' || p === ':slash_tmp') return '/tmp';
  if (p === ':workspace_roots') return ':workspace';
  if (p === '~/') return home;
  if (p.startsWith('~/')) return join(home, p.slice(2));
  return p;
}

export const codex = {
  id: 'codex',
  label: 'OpenAI Codex',
  format: 'toml',
  events: { pre: 'PreToolUse', post: 'PostToolUse' },
  matchAll: '.*',
  timeoutUnit: 'sec',
  supportsUpdatedInput: false,

  settingsPaths({ scope, cwd, home }) {
    return scope === 'user'
      ? [join(home, '.codex', 'config.toml')]
      : [join(cwd, '.codex', 'config.toml')];
  },

  configCandidates({ cwd, home }) {
    return [
      join(cwd, '.codex', 'config.toml'),
      join(home, '.codex', 'config.toml'),
    ];
  },

  /**
   * @param {string} file config.toml path
   * @param {{cwd: string, home: string}} ctx
   */
  parse(file, ctx) {
    const cfg = readToml(file);
    /** @type {Object[]} */
    const rules = [];
    const meta = { files: [file], sandboxMode: cfg.sandbox_mode };

    const sww = cfg.sandbox_workspace_write || {};
    if (cfg.sandbox_mode === 'workspace-write') {
      meta.writeRoots = [ctx.cwd, ...(sww.writable_roots || [])];
    }
    meta.disableNetwork = sww.network_access === false;
    meta.enableNetwork = sww.network_access === true;

    // Beta [permissions] profiles
    const profiles = cfg.permissions || {};
    const selected = cfg.default_permissions && typeof cfg.default_permissions === 'string'
      ? cfg.default_permissions.replace(/^:/, '').replace(/^:/, '')
      : Object.keys(profiles)[0];
    const profile = selected ? profiles[selected] : undefined;
    if (profile) {
      meta.permissionsProfile = selected;
      const { rules: fsRules, readRoots, writeRoots } = convertFsMap(profile.filesystem || {}, profile, ctx.home);
      rules.push(...fsRules);
      meta.readRoots = [...new Set([...(meta.readRoots || []), ...readRoots])];
      meta.writeRoots = [...new Set([...(meta.writeRoots || []), ...writeRoots])];
      const net = profile.network || {};
      if (net.enabled === false) meta.disableNetwork = true;
      if (net.domains && typeof net.domains === 'object') {
        for (const [domain, action] of Object.entries(net.domains)) {
          if (action !== 'allow' && action !== 'deny') continue;
          rules.push({ tool: 'WebFetch', kind: 'domain', pattern: domain.toLowerCase(), action, source: 'codex' });
        }
        if (net.mode === 'limited') meta.proxyEgress = true;
      }
    }

    // shell_environment_policy → env passthrough hints
    const sep = cfg.shell_environment_policy;
    if (sep && typeof sep === 'object') {
      if (sep.set && typeof sep.set === 'object') meta.env = { ...sep.set };
      const filters = sep.filters || {};
      meta.envFilters = filters;
    }

    // execpolicy rules: .codex/rules.json / .rules.json
    for (const rulesFile of [join(ctx.cwd, '.codex', 'rules.json'), join(ctx.cwd, '.rules.json')]) {
      if (!existsSync(rulesFile)) continue;
      try {
        const doc = JSON.parse(readFileSync(rulesFile, 'utf-8'));
        for (const entry of doc || []) {
          for (const r of entry.rules || []) {
            const action = r.action === 'forbid' ? 'deny' : r.action === 'prompt' ? 'ask' : 'allow';
            const pattern = Array.isArray(r.command) ? r.command.join(' ') : String(r.command || '');
            if (pattern) rules.push({ tool: 'Bash', kind: 'command', pattern, action, source: 'codex-rules' });
          }
        }
        meta.files = [...(meta.files || []), rulesFile];
      } catch { /* best-effort */ }
    }

    return { rules, meta };
  },
};
