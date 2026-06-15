package config

import (
	"fmt"
	"os"
	"strings"
)

var sensitivePatterns = []string{"TOKEN", "PASSWORD", "SECRET", "API_KEY", "CLIENT_SECRET", "SESSION", "COOKIE", "AUTH", "KEY"}

// dangerousEnvVars are environment variables that change how the dynamic
// loader or a language runtime resolves and loads code. An attacker who can
// influence them can hijack library loading (e.g. DYLD_INSERT_LIBRARIES,
// LD_PRELOAD) or inject startup code (e.g. NODE_OPTIONS, BASH_ENV) into a
// binary the sandbox is allowed to run, including Apple-signed binaries that
// carry library-validation exemptions. They are stripped unconditionally and
// take precedence over allowEnvs; pass them through only via the explicit
// allowDangerous list.
var dangerousEnvVars = map[string]bool{
	"DEVELOPER_DIR":             true, // CoreSymbolication / xcselect external dylib path
	"NODE_OPTIONS":              true, // injects flags (incl. --require) into node
	"NODE_REPL_EXTERNAL_MODULE": true,
	"BASH_ENV":                  true, // sourced by non-interactive bash
	"ENV":                       true, // sourced by non-interactive sh
	"PYTHONPATH":                true,
	"PYTHONSTARTUP":             true,
	"RUBYOPT":                   true,
	"RUBYLIB":                   true,
	"PERL5LIB":                  true,
	"PERL5OPT":                  true,
	"PERLLIB":                   true,
	"CLASSPATH":                 true, // JVM class loading
	"GIT_SSH":                   true, // executed by git
	"GIT_SSH_COMMAND":           true,
	"GIT_EXTERNAL_DIFF":         true,
	"GIT_PAGER":                 true,
	"GCONV_PATH":                true, // glibc iconv module path (code execution)
	"LOCPATH":                   true,
	"NLSPATH":                   true,
	"HOSTALIASES":               true,
	"RES_OPTIONS":               true,
}

// dangerousEnvPrefixes matches whole families of loader-control variables by
// prefix (every DYLD_* and LD_* variant), so new or platform-specific members
// are covered without enumerating each one.
var dangerousEnvPrefixes = []string{"DYLD_", "LD_"}

// IsDangerousEnv reports whether an environment variable name controls dynamic
// loading or runtime code injection and so must not be inherited by a
// sandboxed process unless explicitly permitted.
func IsDangerousEnv(key string) bool {
	uk := strings.ToUpper(key)
	if dangerousEnvVars[uk] {
		return true
	}
	for _, p := range dangerousEnvPrefixes {
		if strings.HasPrefix(uk, p) {
			return true
		}
	}
	return false
}

// SanitizeEnv removes sensitive and loader-hijacking environment variables from
// the map. Credential-bearing variables and loader-control variables (DYLD_*,
// LD_*, NODE_OPTIONS, DEVELOPER_DIR, ...) are dropped unless their exact name
// is listed in allowEnvs, which is the single opt-in for passing either class
// of variable through. Loader-control variables carry a code-injection risk,
// so allow-list them only deliberately.
func SanitizeEnv(env map[string]string, allowEnvs []string) map[string]string {
	if len(env) == 0 {
		return env
	}
	allowMap := make(map[string]bool)
	for _, ae := range allowEnvs {
		allowMap[ae] = true
	}

	result := make(map[string]string, len(env))
	for k, v := range env {
		// An explicit allowEnvs entry passes the variable through regardless of
		// the credential or loader-control filters.
		if allowMap[k] {
			result[k] = v
			continue
		}
		if IsDangerousEnv(k) {
			continue
		}
		uk := strings.ToUpper(k)
		sensitive := false
		for _, p := range sensitivePatterns {
			if strings.Contains(uk, p) {
				sensitive = true
				break
			}
		}
		if !sensitive {
			result[k] = v
		}
	}
	return result
}

// FilteredEnviron returns a minimal slice of environment variables from the host environment.
// This is used to prevent leakage of credentials (like AWS keys, tokens, etc.) when no
// environment is explicitly specified. It only inherits essential variables:
// - PATH (to locate executables)
// - HOME (for user home directory)
// - TERM (for terminal settings)
// - LANG (for localization/encoding)
// - LC_* (locale settings)
func FilteredEnviron() []string {
	var env []string
	for _, envVar := range os.Environ() {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 0 {
			continue
		}
		key := parts[0]
		if key == "PATH" || key == "HOME" || key == "TERM" || key == "LANG" || strings.HasPrefix(key, "LC_") {
			env = append(env, envVar)
		}
	}
	return env
}

// BuildEnv returns the slice of environment variables to set for the process.
// It merges the specified Env map with host safe variables (PATH, HOME, TERM, LANG, LC_*) if they are not overridden.
// The cfgEnv map is expected to have already passed through SanitizeEnv, which
// drops loader-control variables unless they were explicitly allow-listed.
func BuildEnv(cfgEnv map[string]string) []string {
	var env []string

	// Collect keys present in cfgEnv
	envKeys := make(map[string]bool)
	for k := range cfgEnv {
		envKeys[k] = true
	}

	// Always inherit safe host environment variables if not overridden
	for _, envVar := range os.Environ() {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 0 {
			continue
		}
		key := parts[0]
		if !envKeys[key] {
			if key == "PATH" || key == "HOME" || key == "TERM" || key == "LANG" || strings.HasPrefix(key, "LC_") {
				env = append(env, envVar)
				envKeys[key] = true
			}
		}
	}

	// Append custom environment variables. cfgEnv has already passed through
	// SanitizeEnv, which dropped loader-control variables unless they were
	// explicitly allow-listed, so we must not second-guess it here (doing so
	// would strip an intentionally allow-listed DYLD_*/LD_*/NODE_OPTIONS).
	for k, v := range cfgEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}
