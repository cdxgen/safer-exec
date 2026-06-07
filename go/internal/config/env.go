package config

import (
	"fmt"
	"os"
	"strings"
)

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
// It merges the specified Env map with host PATH and HOME if they are not overridden.
// If the Env map is empty, it returns the minimal filtered environment.
func BuildEnv(cfgEnv map[string]string) []string {
	if len(cfgEnv) == 0 {
		return FilteredEnviron()
	}

	var env []string
	hasPath := false
	hasHome := false
	for k := range cfgEnv {
		if k == "PATH" {
			hasPath = true
		} else if k == "HOME" {
			hasHome = true
		}
	}

	if !hasPath {
		if val, ok := os.LookupEnv("PATH"); ok {
			env = append(env, fmt.Sprintf("PATH=%s", val))
		}
	}
	if !hasHome {
		if val, ok := os.LookupEnv("HOME"); ok {
			env = append(env, fmt.Sprintf("HOME=%s", val))
		}
	}

	for k, v := range cfgEnv {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}
	return env
}
