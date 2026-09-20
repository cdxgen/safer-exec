/**
 * Shared conversion from the unified rule model into a safer-exec policy file
 * (PolicyFile JSON), plus shared adapter helpers.
 *
 * @module common
 */

import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * Read and parse a JSON file; throws with the file path in the message.
 *
 * @param {string} file
 * @returns {Record<string, unknown>}
 */
export function readJson(file) {
  let raw;
  try {
    raw = readFileSync(file, 'utf-8');
  } catch (err) {
    throw new Error(`Cannot read ${file}: ${err.message}`);
  }
  // Strip UTF-8 BOM + line comments at top level boundaries (JSONC tolerated
  // for opencode configs — comments inside strings are preserved)
  const stripped = stripJsonComments(raw);
  try {
    return JSON.parse(stripped);
  } catch (err) {
    throw new Error(`Invalid JSON in ${file}: ${err.message}`);
  }
}

/**
 * Remove `// …` and `/* … *\/` comments that are outside string literals.
 *
 * @param {string} text
 * @returns {string}
 */
export function stripJsonComments(text) {
  let out = '';
  let inBasic = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];
    if (inBasic) {
      out += c;
      if (c === '\\') {
        out += next ?? '';
        i++;
      } else if (c === '"') inBasic = false;
      continue;
    }
    if (c === '"') {
      inBasic = true;
      out += c;
      continue;
    }
    if (c === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
      continue;
    }
    if (c === '/' && next === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i++;
      continue;
    }
    out += c;
  }
  return out;
}

/**
 * Deep-merge `patch` into `target` (arrays under `hooks`-style keys are
 * appended rather than replaced when `appendKeys` matches).
 *
 * @param {Record<string, unknown>} target
 * @param {Record<string, unknown>} patch
 * @param {Set<string>} [appendKeys] top-level keys whose arrays append
 * @returns {Record<string, unknown>}
 */
export function deepMerge(target, patch, appendKeys = new Set()) {
  const out = { ...target };
  for (const [k, v] of Object.entries(patch)) {
    const prev = out[k];
    if (appendKeys.has(k) && Array.isArray(prev) && Array.isArray(v)) {
      out[k] = [...prev, ...v];
      continue;
    }
    if (prev && typeof prev === 'object' && !Array.isArray(prev) &&
        v && typeof v === 'object' && !Array.isArray(v)) {
      out[k] = deepMerge(prev, v, appendKeys);
      continue;
    }
    out[k] = v;
  }
  return out;
}

/**
 * First existing file among candidates.
 *
 * @param {string[]} candidates
 * @returns {string|null}
 */
export function firstExisting(candidates) {
  for (const c of candidates) {
    try {
      if (existsSync(c)) return c;
    } catch { /* ignore */ }
  }
  return null;
}

/**
 * Convert a parsed harness config (unified rules + metadata) into a safer-exec
 * PolicyFile JSON.
 *
 * Mapping decisions:
 * - allow path rules → readPaths/writePaths (deny-by-default sandbox)
 * - deny/ask stay in `harnessRules` for the hook engine; deny rules that
 *   block a bare executable additionally map to blockExec
 * - allow domain rules → allowHosts (+ 443); network denies are implicit
 * - additionalDirectories → readPaths
 *
 * @param {{rules: Object[], meta: Record<string, unknown>}} parsed
 * @param {{cwd: string, home: string, harness: string}} ctx
 * @returns {Record<string, unknown>} PolicyFile-compatible JSON
 */
export function policyFromRules(parsed, ctx) {
  const { rules, meta } = parsed;
  /** @type {string[]} */
  const readPaths = [];
  /** @type {string[]} */
  const writePaths = [];
  /** @type {string[]} */
  const allowHosts = [];
  /** @type {string[]} */
  const blockExec = [];
  const seen = new Set();
  const push = (arr, v) => {
    if (v && !seen.has(v)) {
      seen.add(v);
      arr.push(v);
    }
  };

  for (const dir of meta.additionalDirectories || []) {
    push(readPaths, resolve(ctx.cwd, expandTilde(dir, ctx.home)));
  }
  // Codex-style sandbox roots (workspace-write / permissions profiles)
  for (const dir of meta.writeRoots || []) {
    push(writePaths, resolve(ctx.cwd, expandTilde(dir, ctx.home)));
  }
  for (const dir of meta.readRoots || []) {
    if (dir !== '/' && dir !== ':workspace') push(readPaths, resolve(ctx.cwd, expandTilde(dir, ctx.home)));
  }

  for (const rule of rules) {
    if (rule.kind === 'path' && rule.action === 'allow') {
      const abs = resolvePathRule(rule, ctx);
      if (!abs) continue;
      if (rule.access === 'write') push(writePaths, abs);
      else push(readPaths, abs);
    }
    if (rule.kind === 'domain' && rule.action === 'allow') {
      push(allowHosts, domainToHostPattern(rule.pattern));
    }
    // blockExec only for deny rules that block the executable itself
    // (`Bash(npm *)`, `Bash(curl)`). A subcommand deny (`Bash(npm publish:*)`,
    // `Bash(rm -rf *)`) must NOT become blockExec — the sandbox cannot
    // express "block this subcommand" and would block every invocation of
    // the executable; the hook decision layer enforces those instead.
    if (rule.kind === 'command' && rule.action === 'deny') {
      const prefix = rule.pattern.replace(/\s*\*$/, '').trim();
      if (prefix && !prefix.includes(' ') && !prefix.includes('*')) push(blockExec, prefix);
    }
  }

  /** @type {Record<string, unknown>} */
  const policy = {
    name: `${ctx.harness}-imported`,
    version: '1',
    description: `Imported from ${ctx.harness} permissions by safer-exec harness import`,
    source: {
      harness: ctx.harness,
      files: meta.files || [],
      defaultMode: meta.defaultMode,
      sandboxMode: meta.sandboxMode,
    },
    harnessRules: rules,
  };
  if (readPaths.length > 0) policy.readPaths = readPaths;
  if (writePaths.length > 0) policy.writePaths = writePaths;
  if (allowHosts.length > 0) {
    policy.allowHosts = allowHosts;
    policy.allowPorts = [443, 80];
  }
  if (blockExec.length > 0) policy.blockExec = blockExec;
  if (meta.disableNetwork) policy.disableNetwork = true;
  if (meta.allowLoopback) policy.allowLoopback = true;
  if (meta.proxyEgress && allowHosts.length > 0) policy.proxyEgress = true;
  if (meta.maxProcesses) policy.maxProcesses = meta.maxProcesses;
  if (meta.env && Object.keys(meta.env).length > 0) policy.env = meta.env;
  if (meta.evaluation === 'last-match') {
    policy.harnessRuleEvaluation = 'last-match';
  }
  return policy;
}

/**
 * Resolve a path rule to an absolute directory/prefix (no trailing glob parts).
 *
 * @param {Object} rule path rule
 * @param {{cwd: string, home: string}} ctx
 * @returns {string|null} absolute path prefix, or null when the rule is a
 *   negation or too syntactic to resolve
 */
function resolvePathRule(rule, ctx) {
  if (rule.pattern.startsWith('!')) return null;
  // Use the literal prefix of the pattern up to the first wildcard
  const p = rule.pattern;
  let abs;
  if (p.startsWith('//')) abs = p.slice(1);
  else if (p.startsWith('~/')) abs = join(ctx.home, p.slice(2));
  else if (p.startsWith('/') && rule.baseDir) abs = join(rule.baseDir, p.slice(1));
  else if (p.startsWith('./')) abs = join(ctx.cwd, p.slice(2));
  else if (p.includes('/')) abs = join(ctx.cwd, p);
  else return join(ctx.cwd, '.'); // bare filename rule — grant the working dir
  const wildcard = abs.search(/[*?]/);
  const base = wildcard >= 0 ? abs.slice(0, wildcard) : abs;
  const trimmed = base.replace(/\/+$/, '');
  return trimmed || null;
}

/**
 * Convert a domain rule pattern into a hostname usable by allowHosts.
 * safer-exec matches hosts exactly or on dot-boundary suffixes, so both
 * `*.example.com` and `**.example.com` collapse to `example.com`
 * (suffix matching covers subdomains).
 *
 * @param {string} pattern
 * @returns {string}
 */
export function domainToHostPattern(pattern) {
  if (pattern === '*') return '*';
  if (pattern.startsWith('**.')) return pattern.slice(3);
  if (pattern.startsWith('*.')) return pattern.slice(2);
  return pattern;
}

/**
 * Expand `~` in a path.
 *
 * @param {string} p
 * @param {string} home
 * @returns {string}
 */
export function expandTilde(p, home) {
  if (p === '~') return home;
  if (p.startsWith('~/')) return join(home, p.slice(2));
  return p;
}

/**
 * Standard discovery helper used by adapters.
 *
 * @param {string} id harness id
 * @param {(string|{path: string, note?: string})[]} files
 * @returns {{id: string, configs: {path: string, exists: boolean}[]}}
 */
export function discoveryFor(id, files) {
  return {
    id,
    configs: files.map((f) => (typeof f === 'string' ? { path: f, exists: safeExists(f) } : { exists: safeExists(f.path), ...f })),
  };
}

function safeExists(p) {
  try {
    return existsSync(p);
  } catch {
    return false;
  }
}
