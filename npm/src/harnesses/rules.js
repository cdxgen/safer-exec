/**
 * Unified permission-rule model + evaluation engine for harness configs.
 *
 * Every harness adapter parses its native config into Rule objects:
 *
 *   { tool, kind, action, source }
 *     tool: 'Bash' | 'Read' | 'Edit' | 'WebFetch' | 'mcp' | '*' | 'Agent' | …
 *     kind: 'command' | 'path' | 'domain' | 'bare' | 'param'
 *     action: 'allow' | 'deny' | 'ask'
 *     plus kind-specific fields (specifier / pattern / access / negated)
 *
 * Evaluation order mirrors Claude Code (the strictest documented model):
 * deny → ask → allow, first match wins. Path patterns follow gitignore-style
 * semantics; command patterns follow `Bash(prefix *)` prefix semantics with
 * compound-command splitting.
 *
 * @module rules
 */

import { realpathSync } from 'node:fs';
import { resolve } from 'node:path';

/** Tools whose tool_input carries a shell command string. */
export const SHELL_TOOLS = new Set([
  'Bash', 'bash', 'Execute', 'execute', 'Shell', 'shell', 'run_shell_command',
  'PowerShell', 'power_shell_command', 'terminal',
]);

/** Tools that read files (tool_input.file_path / file-filters). */
export const READ_TOOLS = new Set([
  'Read', 'read', 'read_file', 'ReadFile', 'LS', 'ls', 'list_dir', 'Glob', 'glob',
  'Grep', 'grep', 'codebase_search', 'search',
]);

/** Tools that create or modify files (tool_input.file_path). */
export const WRITE_TOOLS = new Set([
  'Write', 'write', 'write_file', 'WriteFile', 'Edit', 'edit', 'edit_file',
  'EditFile', 'replace', 'replace_file_contents', 'apply_patch', 'ApplyPatch',
  'create', 'create_file', 'str_replace_based_edit_tool',
]);

/** Tools that fetch URLs (tool_input.url). */
export const FETCH_TOOLS = new Set([
  'WebFetch', 'webfetch', 'fetch_url', 'FetchUrl', 'fetch', 'open_url', 'requests',
]);

/** Tools that run web searches (tool_input.query). */
export const SEARCH_TOOLS = new Set(['WebSearch', 'websearch', 'google_web_search', 'web_search']);

/** Shell wrappers Claude-style permission matching strips before matching. */
const COMMAND_WRAPPERS = new Set([
  'timeout', 'time', 'nice', 'nohup', 'stdbuf', 'command', 'builtin', 'noglob',
  'xargs', 'env', 'sudo', 'exec',
]);

/**
 * Parse a Claude-style permission token into a Rule.
 * Forms: `Tool`, `Tool(specifier)`, `Tool(param:value)`.
 *
 * @param {string} token e.g. "Bash(npm run test:*)" | "Read(./.env)" | "WebFetch(domain:x.com)" | "Edit"
 * @param {'allow'|'deny'|'ask'} action
 * @param {string} source harness id
 * @param {string} [baseDir] directory the settings file lives in (resolves relative path rules)
 * @param {string} [home] user home directory
 * @returns {{rule: Object|null, kind: string}} parsed rule or null if unparseable
 */
export function parseClaudeToken(token, action, source, baseDir, home) {
  let tool = token;
  let spec = null;
  const paren = token.indexOf('(');
  if (paren >= 0) {
    if (!token.endsWith(')')) return { rule: null, kind: 'invalid' };
    tool = token.slice(0, paren);
    spec = token.slice(paren + 1, -1);
  }
  tool = tool.trim();

  if (spec === null) return { rule: { tool, kind: 'bare', action, source }, kind: 'bare' };

  // WebFetch(domain:example.com)
  const domainMatch = /^domain:(.+)$/i.exec(spec);
  if (domainMatch && (tool === 'WebFetch' || tool === 'FetchUrl' || tool === 'fetch_url')) {
    return {
      rule: { tool, kind: 'domain', pattern: domainMatch[1].trim().toLowerCase(), action, source },
      kind: 'domain',
    };
  }

  // Bash / Shell specifier — a command prefix pattern
  if (SHELL_TOOLS.has(tool) || tool === 'mcp__permissions__exec') {
    const pattern = spec.replace(/:\*$/, ' *');
    return { rule: { tool, kind: 'command', pattern: pattern.trim(), action, source }, kind: 'command' };
  }

  // Read/Edit path specifier (gitignore-style)
  if (READ_TOOLS.has(tool) || WRITE_TOOLS.has(tool)) {
    return {
      rule: {
        tool,
        kind: 'path',
        pattern: spec,
        access: WRITE_TOOLS.has(tool) ? 'write' : 'read',
        action,
        source,
        baseDir: baseDir || '.',
        home: home || '~',
      },
      kind: 'path',
    };
  }

  // Parameter rule (deny/ask only): Agent(model:opus)
  return { rule: { tool, kind: 'param', specifier: spec, action, source }, kind: 'param' };
}

/**
 * Convert a Claude-style path specifier into an absolute glob + RegExp.
 *
 * Semantics (per Claude Code docs):
 *   `//path` — absolute from filesystem root
 *   `~/path` — under home
 *   `/path`  — relative to the settings source directory
 *   `./path` or bare — relative to cwd
 *   `!` prefix — negation
 *   bare filename — matches at any depth (implicit double-star prefix)
 *
 * @param {string} pattern
 * @param {{cwd: string, home: string, baseDir?: string}} ctx
 * @returns {{regex: RegExp, negated: boolean}}
 */
export function pathRuleToRegExp(pattern, ctx) {
  let p = pattern;
  let negated = false;
  if (p.startsWith('!')) {
    negated = true;
    p = p.slice(1);
  }

  let abs;
  if (p.startsWith('//')) abs = p.slice(1); // filesystem-absolute
  else if (p.startsWith('~/')) abs = `${ctx.home}/${p.slice(2)}`;
  else if (p.startsWith('/') && ctx.baseDir) abs = `${ctx.baseDir}/${p.slice(1)}`;
  else if (p.startsWith('./')) abs = `${ctx.cwd}/${p.slice(2)}`;
  else abs = `**/${p}`; // bare name matches at any depth

  return { regex: gitignoreGlobToRegExp(abs), negated };
}

/**
 * Translate a gitignore-style glob (already normalized to an anchored pattern)
 * into a case-sensitive RegExp.
 *
 * @param {string} glob
 * @returns {RegExp}
 */
export function gitignoreGlobToRegExp(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      let j = i;
      while (glob[j] === '*') j++;
      const doubleStar = j > i + 1;
      i = j - 1;
      if (doubleStar) {
        // `**` matches across directory separators; a following '/' is consumed
        // so `a/**/b` also matches `a/b`
        if (glob[i + 1] === '/') i++;
        re += '.*';
      } else {
        re += '[^/]*';
      }
      continue;
    }
    if (c === '?') { re += '[^/]'; continue; }
    re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

/**
 * Split a compound shell command into logical subcommands, mirroring
 * Claude-style permission matching: split on && || ; | & and newlines, strip
 * leading env assignments and well-known wrappers.
 *
 * @param {string} command
 * @returns {string[]}
 */
export function splitCompoundCommand(command) {
  const parts = command
    .split(/&&|\|\||;|\||\|&|&|\n/)
    .map((p) => p.trim())
    .filter(Boolean);
  const out = [];
  for (const part of parts) {
    let tokens = part.split(/\s+/);
    // Strip leading VAR=value assignments (run twice: `FOO=1 cmd` and
    // `env FOO=1 cmd` both occur)
    for (let round = 0; round < 2; round++) {
      while (tokens.length > 1 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) {
        tokens = tokens.slice(1);
      }
      // Strip wrapper commands (like `timeout 10 curl …`)
      while (tokens.length > 1 && COMMAND_WRAPPERS.has(tokens[0])) {
        tokens = tokens.slice(1);
        // `timeout 10`, `nice -n 5` — drop the wrapper's numeric/flag argument
        while (tokens.length > 1 && /^-?[0-9]/.test(tokens[0])) tokens = tokens.slice(1);
      }
    }
    if (tokens.length > 0) out.push(tokens.join(' '));
  }
  return out;
}

/**
 * Extract commands nested inside the given shell command so deny rules can
 * match them: `$( … )` and process substitutions, backtick substitution, and
 * the payload of `sh|bash|… -c '<payload>'`. The payload is matched as a
 * plain subcommand — it is the command the shell will actually run.
 *
 * Obfuscated payloads (built from variables, base64, concatenation) are NOT
 * recovered — those remain a documented enforcement gap; wrap mode's OS
 * sandbox is the backstop there.
 *
 * @param {string} command
 * @returns {string[]}
 */
export function extractNestedCommands(command) {
  /** @type {string[]} */
  const out = [];
  if (typeof command !== 'string' || command.length > 10000) return out;
  let m;
  const substitution = /\$\(([^()]{1,2000})\)/g;
  while ((m = substitution.exec(command))) out.push(m[1]);
  const procSub = /<\(([^()]{1,2000})\)/g;
  while ((m = procSub.exec(command))) out.push(m[1]);
  const backtick = /`([^`]{1,2000})`/g;
  while ((m = backtick.exec(command))) out.push(m[1]);
  const shellDashC = /(?:^|[\s;&|(])(?:[^\s'"]*\/)?(?:bash|zsh|dash|ksh|ash|sh|shell)\s+(?:(?:-{1,2}[^\s]+)\s+)*-c\s+(?:'([^']{0,2000})'|"([^"]{0,2000})"|(\S{1,2000}))/g;
  while ((m = shellDashC.exec(command))) {
    const payload = m[1] ?? m[2] ?? m[3];
    if (payload) out.push(payload);
  }
  return out;
}

/**
 * Normalize the first token of a command string for matching: strip
 * surrounding quotes and reduce a path-qualified executable
 * (`/usr/bin/curl`, `./node_modules/.bin/jest`) to its basename, so a deny
 * rule written as `curl *` also matches `/usr/bin/curl …`.
 *
 * @param {string} s
 * @returns {string}
 */
function normalizeCommandToken(s) {
  const sp = s.indexOf(' ');
  const first = sp === -1 ? s : s.slice(0, sp);
  const rest = sp === -1 ? '' : s.slice(sp);
  let tok = first;
  if (tok.length > 1 && ((tok[0] === '"' && tok.endsWith('"')) || (tok[0] === "'" && tok.endsWith("'")))) {
    tok = tok.slice(1, -1);
  }
  if (tok.includes('/')) tok = tok.slice(tok.lastIndexOf('/') + 1);
  return tok + rest;
}

/**
 * Match a command pattern (`prefix *` / exact / glued `prefix*`) against one
 * subcommand string. A space-separated `prefix *` requires a word boundary;
 * a glued `prefix*` (Cursor style) is a plain startswith. Path-qualified
 * executables on either side are reduced to their basename first.
 *
 * @param {string} pattern e.g. "npm run *" or "git push" or "git*"
 * @param {string} subcommand
 * @returns {boolean}
 */
export function matchCommandPattern(pattern, subcommand) {
  const norm = (s) => s.trim().replace(/\s+/g, ' ');
  const p = normalizeCommandToken(norm(pattern));
  const c = normalizeCommandToken(norm(subcommand));
  if (p === '*') return true;
  if (p.endsWith('*')) {
    const glued = /\S\*$/.test(p); // star attached to the prefix word
    const prefix = p.replace(/\s*\*$/, '').trim();
    if (prefix === '') return true;
    return glued ? c.startsWith(prefix) : (c === prefix || c.startsWith(`${prefix} `));
  }
  return c === p;
}

/**
 * Resolve a tool-supplied file path against the session cwd. Harnesses
 * normally send absolute paths, but relative (`src/a.js`), dot-segment
 * (`/proj/./a.js`) and up-level (`/proj/sub/../a.js`) forms all occur; all
 * resolve to the same canonical absolute path here so path rules match.
 *
 * @param {string|undefined} p
 * @param {string} cwd
 * @returns {string|undefined}
 */
export function resolveActivityPath(p, cwd) {
  if (typeof p !== 'string' || p === '') return p;
  let abs;
  try {
    abs = resolve(cwd || process.cwd(), p);
  } catch {
    return p;
  }
  if (process.platform === 'win32') abs = abs.replace(/\\/g, '/');
  return abs;
}

/**
 * Extract the leading executable from a shell subcommand.
 * Returns the basename (e.g. "curl") and the literal token when it contains a slash.
 *
 * @param {string} subcommand
 * @returns {{base: string, full: string|null}}
 */
export function leadingExecutable(subcommand) {
  let first = subcommand.split(/\s+/)[0] || '';
  if (first.startsWith('"') || first.startsWith("'")) {
    first = first.slice(1, -1);
  }
  if (first.includes('/')) {
    const base = first.split('/').pop() || first;
    return { base, full: first };
  }
  return { base: first, full: null };
}

/**
 * Match a domain rule against a hostname.
 * `example.com` exact (apex), `*.example.com` any-depth subdomains,
 * `**.example.com` apex + subdomains, `*` any host (allow-only).
 *
 * @param {string} pattern
 * @param {string} host
 * @returns {boolean}
 */
export function matchDomainPattern(pattern, host) {
  const p = pattern.toLowerCase().replace(/\.$/, '');
  const h = (host || '').toLowerCase().replace(/\.$/, '');
  if (p === '*') return true;
  if (p.startsWith('**.')) {
    const base = p.slice(3);
    return h === base || h.endsWith(`.${base}`);
  }
  if (p.startsWith('*.')) {
    const base = p.slice(2);
    return h.endsWith(`.${base}`);
  }
  return h === p;
}

/**
 * Match a simple glob (OpenCode-style: `*` any chars, `?` one char) against a
 * string. OpenCode uses last-match-wins semantics — callers handle ordering;
 * this only answers "does it match".
 *
 * @param {string} pattern
 * @param {string} value
 * @returns {boolean}
 */
export function matchSimpleGlob(pattern, value) {
  const re = '^' + pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.') + '$';
  return new RegExp(re).test(value);
}

/**
 * Evaluate a rule set against an activity. Returns the winning action.
 *
 * Default precedence mirrors Claude Code: deny → ask → allow, first match wins.
 * OpenCode semantics differ (last matching rule wins) — pass
 * `lastMatchWins: true` in ctx to use that order instead.
 *
 * @param {Object[]} rules unified rules
 * @param {{type: string, command?: string, path?: string, host?: string, url?: string, tool?: string}} activity
 * @param {{cwd: string, home: string, lastMatchWins?: boolean}} ctx
 * @returns {{action: 'allow'|'deny'|'ask'|null, rule: Object|null}}
 */
export function evaluateRules(rules, activity, ctx) {
  if (ctx && ctx.lastMatchWins) {
    let last = null;
    for (const rule of rules || []) {
      if (ruleMatchesActivity(rule, activity, ctx)) last = { action: rule.action, rule };
    }
    return last || { action: null, rule: null };
  }
  /** @type {{action: 'allow'|'deny'|'ask', rule: Object}[]} */
  const matches = [];
  for (const rule of rules || []) {
    if (!ruleMatchesActivity(rule, activity, ctx)) continue;
    matches.push({ action: rule.action, rule });
  }
  for (const wanted of ['deny', 'ask', 'allow']) {
    const hit = matches.find((m) => m.action === wanted);
    if (hit) return hit;
  }
  return { action: null, rule: null };
}

/**
 * Build the regex variants for a path rule. Each pattern form anchors on
 * exactly one directory (`~/` → home, `/x` → baseDir, `./x` → cwd); when
 * that anchor exists on disk and is a symlink (macOS `/var` →
 * `/private/var`, symlinked project dirs), a second variant is built from
 * the anchor's realpath so rules and activities written in either spelling
 * match.
 *
 * @param {Object} rule
 * @param {{cwd: string, home: string}} ctx
 * @returns {{regex: RegExp, negated: boolean}[]}
 */
function pathRuleRegexVariants(rule, ctx) {
  const home = rule.home === '~' || rule.home === undefined ? ctx.home : rule.home;
  const build = (baseDir, cwd, homeDir) => pathRuleToRegExp(rule.pattern, { cwd, home: homeDir, baseDir });
  const p = rule.pattern.startsWith('!') ? rule.pattern.slice(1) : rule.pattern;

  let anchor = null;
  if (p.startsWith('~/')) anchor = home;
  else if (p.startsWith('/') && !p.startsWith('//')) anchor = rule.baseDir || null;
  else if (p.startsWith('./')) anchor = ctx.cwd;

  const variants = [build(rule.baseDir, ctx.cwd, home)];
  if (anchor && anchor.startsWith('/')) {
    let real = null;
    try {
      real = realpathSync.native(anchor);
    } catch { /* anchor may not exist — lexical variant only */ }
    if (real && real !== anchor) {
      if (p.startsWith('~/')) variants.push(build(rule.baseDir, ctx.cwd, real));
      else if (p.startsWith('/') && !p.startsWith('//')) variants.push(build(real, ctx.cwd, home));
      else variants.push(build(rule.baseDir, real, home));
    }
  }
  return variants;
}

/**
 * Does a single rule match the given activity?
 *
 * @param {Object} rule
 * @param {Object} activity
 * @param {{cwd: string, home: string}} ctx
 * @returns {boolean}
 */
function ruleMatchesActivity(rule, activity, ctx) {
  const tool = activity.tool || '';
  const toolLower = tool.toLowerCase();

  if (rule.kind === 'bare') {
    if (rule.tool === '*') return true;
    if (rule.tool === tool) return true;
    // Edit rules cover all file-editing tools; Read rules cover Grep/Glob
    if (rule.tool === 'Edit' && WRITE_TOOLS.has(tool)) return true;
    if (rule.tool === 'Read' && READ_TOOLS.has(tool)) return true;
    if (rule.tool.toLowerCase() === toolLower) return true;
    return false;
  }

  if (rule.kind === 'command') {
    if (activity.type !== 'exec' || !activity.command) return false;
    if (rule.tool !== '*' && !SHELL_TOOLS.has(rule.tool) && rule.tool !== tool) {
      // droid `Shell(...)` vs Claude `Bash(...)` interop
      if (!(SHELL_TOOLS.has(tool) && SHELL_TOOLS.has(rule.tool))) return false;
    }
    // Subcommands plus anything nested in substitutions / `sh -c` payloads —
    // `echo $(curl …)`, `` x=`curl …` ``, `bash -c "curl …"` must all match
    // a `Bash(curl *)` deny rule.
    const candidates = splitCompoundCommand(activity.command);
    for (const nested of extractNestedCommands(activity.command)) {
      candidates.push(...splitCompoundCommand(nested));
    }
    return candidates.some((s) => matchCommandPattern(rule.pattern, s));
  }

  if (rule.kind === 'command-regex') {
    if (activity.type !== 'exec' || !activity.command) return false;
    try {
      return new RegExp(rule.pattern).test(activity.command);
    } catch {
      return false;
    }
  }

  if (rule.kind === 'path') {
    if (!activity.path && !activity.realPath) return false;
    const applies =
      (rule.access === 'write' && (activity.type === 'file-write' || activity.type === 'file-edit')) ||
      (rule.access === 'read' && (activity.type === 'file-read' || activity.type === 'file-edit' || READ_TOOLS.has(tool)));
    if (!applies) return false;
    // Match the lexically-resolved path (covers relative / dot-segment
    // inputs) and, when the file exists, the symlink-resolved real path
    // (covers a symlink standing in for the denied target), against the
    // rule's anchor in both its lexical and realpath spellings.
    const candidates = [];
    if (activity.path) candidates.push(activity.path);
    if (activity.realPath && activity.realPath !== activity.path) candidates.push(activity.realPath);
    const variants = pathRuleRegexVariants(rule, ctx);
    return candidates.some((p) =>
      variants.some(({ regex, negated }) => (negated ? !regex.test(p) : regex.test(p)))
    );
  }

  if (rule.kind === 'domain') {
    if (activity.type !== 'network-fetch' && activity.type !== 'network-search') return false;
    const host = activity.host || hostFromUrl(activity.url);
    if (!host) return false;
    return matchDomainPattern(rule.pattern, host);
  }

  return false;
}

/**
 * Extract a hostname from a URL-ish string.
 *
 * @param {string|undefined} url
 * @returns {string|null}
 */
export function hostFromUrl(url) {
  if (!url) return null;
  try {
    return new URL(url).hostname;
  } catch {
    const m = /^[a-z][a-z0-9+.-]*:\/\/([^/:?#]+)/i.exec(url);
    return m ? m[1] : null;
  }
}
