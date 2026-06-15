/**
 * Environment variable hardening.
 *
 * Loader-control variables change how the dynamic loader or a language runtime
 * resolves and loads code. An attacker who can influence them can hijack
 * library loading (DYLD_INSERT_LIBRARIES, LD_PRELOAD) or inject startup code
 * (NODE_OPTIONS, BASH_ENV) into a binary the sandbox is allowed to run. This
 * module strips them before they reach the sandboxed process. The Go engine
 * performs the same filtering as a backstop.
 *
 * @module env
 */

/** Exact loader/runtime-control variable names that are stripped by default. */
const DANGEROUS_ENV_VARS = new Set([
  'DEVELOPER_DIR',
  'NODE_OPTIONS',
  'NODE_REPL_EXTERNAL_MODULE',
  'BASH_ENV',
  'ENV',
  'PYTHONPATH',
  'PYTHONSTARTUP',
  'RUBYOPT',
  'RUBYLIB',
  'PERL5LIB',
  'PERL5OPT',
  'PERLLIB',
  'CLASSPATH',
  'GIT_SSH',
  'GIT_SSH_COMMAND',
  'GIT_EXTERNAL_DIFF',
  'GIT_PAGER',
  'GCONV_PATH',
  'LOCPATH',
  'NLSPATH',
  'HOSTALIASES',
  'RES_OPTIONS',
]);

/** Variable name prefixes that match whole loader-control families. */
const DANGEROUS_ENV_PREFIXES = ['DYLD_', 'LD_'];

/**
 * Report whether an environment variable name controls dynamic loading or
 * runtime code injection.
 *
 * @param {string} key - Environment variable name.
 * @returns {boolean} True if the variable is a loader/runtime-control vector.
 */
export function isDangerousEnv(key) {
  const uk = String(key).toUpperCase();
  if (DANGEROUS_ENV_VARS.has(uk)) {
    return true;
  }
  return DANGEROUS_ENV_PREFIXES.some((p) => uk.startsWith(p));
}

/**
 * Return a copy of env with loader-control variables removed. A variable is
 * dropped even if it appears in allowEnvs unless it is also listed in
 * allowDangerous, the explicit audited opt-in.
 *
 * @param {Record<string,string>} env - Environment map to filter.
 * @param {string[]} [allowDangerous] - Loader-control names to keep.
 * @returns {Record<string,string>} Filtered environment map.
 */
export function stripDangerousEnv(env, allowDangerous = []) {
  const allow = new Set((allowDangerous || []).map((n) => String(n).toUpperCase()));
  const out = {};
  for (const [k, v] of Object.entries(env || {})) {
    if (isDangerousEnv(k) && !allow.has(String(k).toUpperCase())) {
      continue;
    }
    out[k] = v;
  }
  return out;
}

export default { isDangerousEnv, stripDangerousEnv };
