package config

import (
	"fmt"
	"os"
	"strings"
)

var sensitivePatterns = []string{"TOKEN", "PASSWORD", "SECRET", "API_KEY", "CLIENT_SECRET", "SESSION", "COOKIE", "AUTH", "KEY"}

// SanitizeEnv removes sensitive environment variables from the map, except those explicitly allowed.
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
		if allowMap[k] {
			result[k] = v
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

	// Append custom environment variables
	for k, v := range cfgEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}
