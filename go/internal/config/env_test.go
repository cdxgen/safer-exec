package config

import "testing"

func TestIsDangerousEnv(t *testing.T) {
	dangerous := []string{
		"DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
		"DEVELOPER_DIR", "NODE_OPTIONS", "BASH_ENV", "PYTHONPATH",
		"GCONV_PATH", "GIT_SSH_COMMAND",
	}
	for _, k := range dangerous {
		if !IsDangerousEnv(k) {
			t.Errorf("expected %q to be flagged dangerous", k)
		}
		// Case-insensitive.
		if !IsDangerousEnv(toLowerASCII(k)) {
			t.Errorf("expected lowercase %q to be flagged dangerous", k)
		}
	}
	safe := []string{"PATH", "HOME", "NODE_ENV", "npm_config_loglevel", "TMPDIR", "LANG"}
	for _, k := range safe {
		if IsDangerousEnv(k) {
			t.Errorf("expected %q to be treated as safe", k)
		}
	}
}

func TestSanitizeEnv_StripsDangerousByDefault(t *testing.T) {
	env := map[string]string{
		"PATH":                  "/usr/bin",
		"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
		"LD_PRELOAD":            "/tmp/evil.so",
		"DEVELOPER_DIR":         "/tmp/toolchain",
		"NODE_OPTIONS":          "--require /tmp/x.js",
		"NODE_ENV":              "production",
	}
	// Loader-control vars are dropped unless explicitly allow-listed.
	out := SanitizeEnv(env, nil)
	for _, k := range []string{"DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "DEVELOPER_DIR", "NODE_OPTIONS"} {
		if _, ok := out[k]; ok {
			t.Errorf("dangerous var %q survived sanitization", k)
		}
	}
	if out["PATH"] != "/usr/bin" || out["NODE_ENV"] != "production" {
		t.Errorf("safe vars were unexpectedly stripped: %#v", out)
	}
}

func TestSanitizeEnv_AllowEnvsReadmitsDangerous(t *testing.T) {
	env := map[string]string{
		"DYLD_INSERT_LIBRARIES": "/opt/instrument.dylib",
		"LD_PRELOAD":            "/tmp/evil.so",
	}
	// Naming a loader-control var in allowEnvs is the deliberate opt-in.
	out := SanitizeEnv(env, []string{"DYLD_INSERT_LIBRARIES"})
	if out["DYLD_INSERT_LIBRARIES"] != "/opt/instrument.dylib" {
		t.Errorf("allow-listed loader-control var should pass through, got %#v", out)
	}
	if _, ok := out["LD_PRELOAD"]; ok {
		t.Errorf("non-allowed dangerous var LD_PRELOAD must still be dropped")
	}
}

func TestSanitizeEnv_StillStripsCredentials(t *testing.T) {
	env := map[string]string{"AWS_SECRET_ACCESS_KEY": "x", "GITHUB_TOKEN": "y", "FOO": "bar"}
	out := SanitizeEnv(env, nil)
	if _, ok := out["AWS_SECRET_ACCESS_KEY"]; ok {
		t.Error("credential var survived")
	}
	if _, ok := out["GITHUB_TOKEN"]; ok {
		t.Error("token var survived")
	}
	if out["FOO"] != "bar" {
		t.Error("ordinary var should pass")
	}
}

func TestBuildEnv_PassesThroughSanitizedConfig(t *testing.T) {
	// BuildEnv must not re-filter: gating loader-control variables is
	// SanitizeEnv's job (it honors allowEnvs). A loader-control var present in
	// cfgEnv at this point was already allow-listed, so BuildEnv must emit it.
	built := BuildEnv(map[string]string{"NODE_OPTIONS": "--xx", "FOO": "bar"})
	var sawNodeOptions, sawFoo bool
	for _, kv := range built {
		if kv == "NODE_OPTIONS=--xx" {
			sawNodeOptions = true
		}
		if kv == "FOO=bar" {
			sawFoo = true
		}
	}
	if !sawNodeOptions {
		t.Error("BuildEnv dropped an allow-listed loader-control var that was already in the sanitized config")
	}
	if !sawFoo {
		t.Error("BuildEnv dropped an ordinary config var")
	}
}

// toLowerASCII lowercases an ASCII string for the case-insensitivity check
// without pulling in strings just for the test helper.
func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
