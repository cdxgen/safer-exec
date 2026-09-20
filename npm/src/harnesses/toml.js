/**
 * Minimal zero-dependency TOML parser and serializer.
 *
 * Supports the subset of TOML used by agentic harness configs
 * (Codex `config.toml`, Gemini policy `*.toml`): tables, array-of-tables,
 * dotted and quoted keys, strings (basic + literal), integers, floats,
 * booleans, (multi-line) arrays, and inline tables. Multi-line strings and
 * datetimes are rejected with a clear error — harness configs do not use them.
 *
 * @module toml
 */

export class TOMLError extends Error {
  /**
   * @param {string} message
   * @param {number} [line]
   */
  constructor(message, line) {
    super(line !== undefined ? `${message} (line ${line})` : message);
    this.name = 'TOMLError';
  }
}

/**
 * Parse a TOML document into a plain object.
 *
 * @param {string} text
 * @returns {Record<string, unknown>}
 * @throws {TOMLError} on unsupported or malformed syntax
 */
export function parseTOML(text) {
  const root = {};
  /** @type {Record<string, unknown>} */
  let current = root;

  const lines = text.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    let line = lines[i];
    const lineNo = i + 1;
    i++;
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    if (trimmed.startsWith('[[')) {
      // Array of tables: [[ hooks.PreToolUse ]]
      const m = /^\[\[\s*(.+?)\s*\]\]\s*(?:#.*)?$/.exec(trimmed);
      if (!m) throw new TOMLError('Malformed array-of-tables header', lineNo);
      const keys = splitKeyPath(m[1], lineNo);
      current = pushArrayTable(root, keys, lineNo);
      continue;
    }
    if (trimmed.startsWith('[')) {
      // Table: [ sandbox_workspace_write ] or [ permissions.x.filesystem.":root" ]
      const m = /^\[\s*(.+?)\s*\]\s*(?:#.*)?$/.exec(trimmed);
      if (!m) throw new TOMLError('Malformed table header', lineNo);
      const keys = splitKeyPath(m[1], lineNo);
      current = ensureTable(root, keys, lineNo);
      continue;
    }

    // key = value — may span multiple lines for arrays
    const eq = findUnquoted(trimmed, '=');
    if (eq < 0) throw new TOMLError('Expected "key = value"', lineNo);
    const keyPart = trimmed.slice(0, eq).trim();
    let valuePart = trimmed.slice(eq + 1).trim();
    const keys = splitKeyPath(keyPart, lineNo);

    // Accumulate lines until brackets/braces/quotes balance (multi-line arrays)
    while (!isValueComplete(valuePart) && i < lines.length) {
      line = lines[i];
      i++;
      valuePart += '\n' + line;
    }
    if (!isValueComplete(valuePart)) {
      throw new TOMLError('Unterminated value', lineNo);
    }

    const value = parseValue(valuePart, lineNo);
    assign(current, keys, value, lineNo);
  }
  return root;
}

/**
 * Split a dotted key path on unquoted dots. Quoted segments are returned
 * verbatim (minus quotes); bare segments are normalized to strings.
 *
 * @param {string} path
 * @param {number} lineNo
 * @returns {string[]}
 */
function splitKeyPath(path, lineNo) {
  const keys = [];
  let buf = '';
  let inBasic = false;
  let inLiteral = false;
  for (let idx = 0; idx < path.length; idx++) {
    const ch = path[idx];
    if (inBasic) {
      if (ch === '\\') {
        buf += ch + (path[idx + 1] ?? '');
        idx++;
        continue;
      }
      if (ch === '"') inBasic = false;
      buf += ch;
      continue;
    }
    if (inLiteral) {
      if (ch === "'") inLiteral = false;
      buf += ch;
      continue;
    }
    if (ch === '"') {
      inBasic = true;
      buf += ch;
      continue;
    }
    if (ch === "'") {
      inLiteral = true;
      buf += ch;
      continue;
    }
    if (ch === '.') {
      keys.push(normalizeKeySegment(buf.trim(), lineNo));
      buf = '';
      continue;
    }
    buf += ch;
  }
  if (inBasic || inLiteral) throw new TOMLError('Unterminated quoted key', lineNo);
  if (buf.trim() !== '') keys.push(normalizeKeySegment(buf.trim(), lineNo));
  return keys;
}

/**
 * Strip quotes and unescape a single key segment.
 *
 * @param {string} seg
 * @param {number} lineNo
 * @returns {string}
 */
function normalizeKeySegment(seg, lineNo) {
  if (seg === '') throw new TOMLError('Empty key segment', lineNo);
  if (seg.startsWith('"') && seg.endsWith('"') && seg.length >= 2) {
    return unescapeBasic(seg.slice(1, -1), lineNo);
  }
  if (seg.startsWith("'") && seg.endsWith("'") && seg.length >= 2) {
    return seg.slice(1, -1);
  }
  return seg;
}

/**
 * Find the index of `ch` outside quotes.
 *
 * @param {string} s
 * @param {string} ch
 * @returns {number}
 */
function findUnquoted(s, ch) {
  let inBasic = false;
  let inLiteral = false;
  for (let idx = 0; idx < s.length; idx++) {
    const c = s[idx];
    if (inBasic) {
      if (c === '\\') idx++;
      else if (c === '"') inBasic = false;
      continue;
    }
    if (inLiteral) {
      if (c === "'") inLiteral = false;
      continue;
    }
    if (c === '"') { inBasic = true; continue; }
    if (c === "'") { inLiteral = true; continue; }
    if (c === ch) return idx;
  }
  return -1;
}

/**
 * Heuristic: does this raw value text have balanced brackets/quotes and no
 * dangling continuation? Used to gather multi-line arrays.
 *
 * @param {string} v
 * @returns {boolean}
 */
function isValueComplete(v) {
  let depth = 0;
  let inBasic = false;
  let inLiteral = false;
  for (let idx = 0; idx < v.length; idx++) {
    const c = v[idx];
    if (inBasic) {
      if (c === '\\') idx++;
      else if (c === '"') inBasic = false;
      continue;
    }
    if (inLiteral) {
      if (c === "'") inLiteral = false;
      continue;
    }
    if (c === '"') inBasic = true;
    else if (c === "'") inLiteral = true;
    else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') depth--;
    else if (c === '#' && depth === 0) return true; // trailing comment
  }
  return depth <= 0 && !inBasic && !inLiteral;
}

/**
 * Parse a single TOML value.
 *
 * @param {string} raw
 * @param {number} lineNo
 * @returns {unknown}
 */
function parseValue(raw, lineNo) {
  // Strip trailing comment outside quotes
  let text = stripComment(raw).trim();
  if (text === '') throw new TOMLError('Empty value', lineNo);

  if (text.startsWith('"')) {
    const m = /^"((?:[^"\\]|\\.)*)"/s.exec(text);
    if (!m) throw new TOMLError('Malformed basic string', lineNo);
    return unescapeBasic(m[1], lineNo);
  }
  if (text.startsWith("'")) {
    const m = /^'([^']*)'/s.exec(text);
    if (!m) throw new TOMLError('Malformed literal string', lineNo);
    return m[1];
  }
  if (text === 'true' || text === 'false') return text === 'true';
  if (/^[+-]?\d+$/.test(text)) return parseInt(text, 10);
  if (/^[+-]?(\d+\.\d*|\.\d+)([eE][+-]?\d+)?$/.test(text)) return parseFloat(text);

  if (text.startsWith('[')) {
    return parseArray(text, lineNo);
  }
  if (text.startsWith('{')) {
    const obj = {};
    const inner = text.slice(1, text.lastIndexOf('}'));
    for (const part of splitTopLevel(inner)) {
      const t = part.trim();
      if (!t) continue;
      const eq = findUnquoted(t, '=');
      if (eq < 0) throw new TOMLError('Malformed inline table', lineNo);
      const keys = splitKeyPath(t.slice(0, eq).trim(), lineNo);
      assign(obj, keys, parseValue(t.slice(eq + 1).trim(), lineNo), lineNo);
    }
    return obj;
  }
  throw new TOMLError(`Unsupported value: ${text.slice(0, 40)}`, lineNo);
}

/**
 * Remove a trailing `# comment` that sits outside quotes/brackets.
 *
 * @param {string} raw
 * @returns {string}
 */
function stripComment(raw) {
  let inBasic = false;
  let inLiteral = false;
  let depth = 0;
  for (let idx = 0; idx < raw.length; idx++) {
    const c = raw[idx];
    if (inBasic) {
      if (c === '\\') idx++;
      else if (c === '"') inBasic = false;
      continue;
    }
    if (inLiteral) {
      if (c === "'") inLiteral = false;
      continue;
    }
    if (c === '"') inBasic = true;
    else if (c === "'") inLiteral = true;
    else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') depth--;
    else if (c === '#' && depth === 0) return raw.slice(0, idx);
  }
  return raw;
}

/**
 * Parse a (possibly multi-line) TOML array.
 *
 * @param {string} text
 * @param {number} lineNo
 * @returns {unknown[]}
 */
function parseArray(text, lineNo) {
  if (!text.endsWith(']')) throw new TOMLError('Unterminated array', lineNo);
  const inner = text.slice(1, -1);
  const items = splitTopLevel(inner);
  const out = [];
  for (const item of items) {
    const t = stripComment(item).trim();
    if (!t) continue;
    out.push(parseValue(t, lineNo));
  }
  return out;
}

/**
 * Split on top-level commas (outside quotes/brackets).
 *
 * @param {string} s
 * @returns {string[]}
 */
function splitTopLevel(s) {
  const parts = [];
  let buf = '';
  let depth = 0;
  let inBasic = false;
  let inLiteral = false;
  for (let idx = 0; idx < s.length; idx++) {
    const c = s[idx];
    if (inBasic) {
      if (c === '\\') { buf += c + (s[idx + 1] ?? ''); idx++; continue; }
      if (c === '"') inBasic = false;
      buf += c;
      continue;
    }
    if (inLiteral) {
      if (c === "'") inLiteral = false;
      buf += c;
      continue;
    }
    if (c === '"') { inBasic = true; buf += c; continue; }
    if (c === "'") { inLiteral = true; buf += c; continue; }
    if (c === '[' || c === '{') depth++;
    if (c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) {
      parts.push(buf);
      buf = '';
      continue;
    }
    buf += c;
  }
  if (buf.trim() !== '') parts.push(buf);
  return parts;
}

/**
 * Unescape a basic string body.
 *
 * @param {string} s
 * @param {number} lineNo
 * @returns {string}
 */
function unescapeBasic(s, lineNo) {
  return s.replace(/\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[\\"btnfr])/g, (esc) => {
    switch (esc) {
      case '\\\\': return '\\';
      case '\\"': return '"';
      case '\\b': return '\b';
      case '\\t': return '\t';
      case '\\n': return '\n';
      case '\\f': return '\f';
      case '\\r': return '\r';
      default:
        if (esc.startsWith('\\u') || esc.startsWith('\\U')) {
          return String.fromCodePoint(parseInt(esc.slice(2), 16));
        }
        throw new TOMLError(`Invalid escape: ${esc}`, lineNo);
    }
  });
}

/**
 * @param {Record<string, unknown>} obj
 * @param {string[]} keys
 * @param {number} lineNo
 * @returns {Record<string, unknown>}
 */
function ensureTable(obj, keys, lineNo) {
  let cur = obj;
  for (let idx = 0; idx < keys.length; idx++) {
    const k = keys[idx];
    if (cur[k] === undefined) cur[k] = {};
    if (Array.isArray(cur[k])) {
      cur = /** @type {Record<string, unknown>[]} */ (cur[k])[cur[k].length - 1];
      continue;
    }
    if (typeof cur[k] !== 'object' || cur[k] === null) {
      throw new TOMLError(`Key "${k}" is not a table`, lineNo);
    }
    cur = /** @type {Record<string, unknown>} */ (cur[k]);
  }
  return cur;
}

/**
 * @param {Record<string, unknown>} obj
 * @param {string[]} keys
 * @param {number} lineNo
 * @returns {Record<string, unknown>}
 */
function pushArrayTable(obj, keys, lineNo) {
  const parent = ensureTable(obj, keys.slice(0, -1), lineNo);
  const last = keys[keys.length - 1];
  if (parent[last] === undefined) parent[last] = [];
  const arr = /** @type {unknown[]} */ (parent[last]);
  if (!Array.isArray(arr)) throw new TOMLError(`Key "${last}" conflicts with array-of-tables`, lineNo);
  const table = {};
  arr.push(table);
  return table;
}

/**
 * @param {Record<string, unknown>} obj
 * @param {string[]} keys
 * @param {unknown} value
 * @param {number} lineNo
 */
function assign(obj, keys, value, lineNo) {
  const target = ensureTable(obj, keys.slice(0, -1), lineNo);
  target[keys[keys.length - 1]] = value;
}

/**
 * Serialize a plain object to TOML text (for writing hook config into Codex).
 * Supports scalars, arrays of scalars, nested tables, and arrays of tables —
 * always emitting fully-qualified headers so the output round-trips.
 *
 * @param {Record<string, unknown>} obj
 * @returns {string}
 */
export function stringifyTOML(obj) {
  const lines = [];
  emitTable(obj, [], lines);
  return lines.join('\n') + '\n';
}

/**
 * @param {unknown} v
 * @returns {boolean} true when the value serializes inline (`key = …`)
 */
function isInlineValue(v) {
  if (v === null || v === undefined) return true;
  if (Array.isArray(v)) return v.every((x) => x === null || x === undefined || typeof x !== 'object' || x === null);
  return typeof v !== 'object';
}

/**
 * Emit one table's body: inline values first, then sub-tables / array-of-tables
 * with fully-qualified headers.
 *
 * @param {Record<string, unknown>} obj
 * @param {string[]} path
 * @param {string[]} lines
 */
function emitTable(obj, path, lines) {
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (isInlineValue(v)) lines.push(`${quoteKey(k)} = ${serializeValue(v)}`);
  }
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null || isInlineValue(v)) continue;
    if (Array.isArray(v)) {
      for (const item of v) {
        if (item === null || typeof item !== 'object') continue; // scalar items were inline
        lines.push('');
        lines.push(`[[${[...path, k].map(quoteKey).join('.')}]]`);
        emitTable(item, [...path, k], lines);
      }
      continue;
    }
    lines.push('');
    lines.push(`[${[...path, k].map(quoteKey).join('.')}]`);
    emitTable(v, [...path, k], lines);
  }
}

/**
 * @param {string} k
 * @returns {string}
 */
function quoteKey(k) {
  return /^[A-Za-z0-9_-]+$/.test(k) ? k : `"${k.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * @param {unknown} v
 * @returns {string}
 */
function serializeValue(v) {
  if (v === null || v === undefined) return '""';
  if (typeof v === 'string') return `"${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  if (typeof v === 'number' || typeof v === 'bigint') return String(v);
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (Array.isArray(v)) return `[${v.filter((x) => x !== null && x !== undefined).map(serializeValue).join(', ')}]`;
  return JSON.stringify(v);
}
