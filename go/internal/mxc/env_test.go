package mxc

import (
	"slices"
	"strings"
	"testing"
)

var testHostEnv = []string{
	`=C:=C:\work`,
	`Path=C:\Windows\system32;C:\Program Files\nodejs`,
	`PATHEXT=.COM;.EXE;.BAT;.CMD`,
	`SystemRoot=C:\Windows`,
	`windir=C:\Windows`,
	`LOCALAPPDATA=C:\Users\u\AppData\Local`,
	`APPDATA=C:\Users\u\AppData\Roaming`,
	`USERPROFILE=C:\Users\u`,
	`ProgramData=C:\ProgramData`,
	`NUMBER_OF_PROCESSORS=8`,
	`USERNAME=u`,
	`COMPUTERNAME=HOST`,
	`AWS_SECRET_ACCESS_KEY=leak`,
	`JAVA_TOOL_OPTIONS=-javaagent:x.jar`,
	`HTTPS_PROXY=http://corp:3128`,
}

func envMap(entries []string) map[string]string {
	m := map[string]string{}
	for _, e := range entries {
		i := strings.IndexByte(e, '=')
		m[strings.ToUpper(e[:i])] = e[i+1:]
	}
	return m
}

func TestBuildEnvInheritsWindowsBaselineOnly(t *testing.T) {
	entries, dropped := BuildEnv(EnvOptions{Host: ParseEnviron(testHostEnv)})
	if len(dropped) != 0 {
		t.Fatalf("unexpected dropped %v", dropped)
	}
	m := envMap(entries)
	for _, want := range []string{"PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "PROGRAMDATA", "NUMBER_OF_PROCESSORS"} {
		if _, ok := m[want]; !ok {
			t.Errorf("%s not inherited: %v", want, entries)
		}
	}
	for _, leak := range []string{"USERNAME", "COMPUTERNAME", "AWS_SECRET_ACCESS_KEY", "JAVA_TOOL_OPTIONS", "HTTPS_PROXY", "=C:"} {
		if _, ok := m[leak]; ok {
			t.Errorf("%s leaked into the sandbox env", leak)
		}
	}
	// Original spelling is preserved and entries are sorted.
	if !slices.Contains(entries, `Path=C:\Windows\system32;C:\Program Files\nodejs`) {
		t.Errorf("Path spelling not preserved: %v", entries)
	}
	if !slices.IsSortedFunc(entries, func(a, b string) int {
		return strings.Compare(strings.ToUpper(a[:strings.IndexByte(a, '=')]), strings.ToUpper(b[:strings.IndexByte(b, '=')]))
	}) {
		t.Errorf("entries not sorted: %v", entries)
	}
}

func TestBuildEnvConfigOverridesCaseInsensitively(t *testing.T) {
	entries, _ := BuildEnv(EnvOptions{
		Host:   ParseEnviron(testHostEnv),
		Config: map[string]string{"PATH": `C:\only`, "npm_config_audit": "false"},
	})
	m := envMap(entries)
	if m["PATH"] != `C:\only` {
		t.Errorf("PATH override lost: %q", m["PATH"])
	}
	count := 0
	for _, e := range entries {
		if strings.HasPrefix(strings.ToUpper(e), "PATH=") {
			count++
		}
	}
	if count != 1 {
		t.Errorf("PATH duplicated across spellings: %v", entries)
	}
	if m["NPM_CONFIG_AUDIT"] != "false" {
		t.Error("config variable missing")
	}
}

func TestBuildEnvWindowsDangerousVariables(t *testing.T) {
	cfg := map[string]string{
		"COR_ENABLE_PROFILING":        "1",
		"COR_PROFILER":                "{guid}",
		"COR_PROFILER_PATH_64":        `C:\evil.dll`,
		"CORECLR_PROFILER_PATH_ARM64": `C:\evil.dll`,
		"DOTNET_STARTUP_HOOKS":        `C:\hook.dll`,
		"__COMPAT_LAYER":              "RunAsInvoker",
		"SAFE":                        "1",
	}
	entries, dropped := BuildEnv(EnvOptions{Host: ParseEnviron(testHostEnv), Config: cfg})
	m := envMap(entries)
	if len(dropped) != 6 {
		t.Errorf("dropped = %v, want the six injection variables", dropped)
	}
	for k := range cfg {
		_, ok := m[strings.ToUpper(k)]
		if k == "SAFE" && !ok {
			t.Error("SAFE dropped")
		}
		if k != "SAFE" && ok {
			t.Errorf("%s passed through", k)
		}
	}
	// allowEnvs is the explicit, case-insensitive opt-in.
	entries, dropped = BuildEnv(EnvOptions{Host: ParseEnviron(testHostEnv), Config: cfg, AllowEnvs: []string{"dotnet_startup_hooks"}})
	if _, ok := envMap(entries)["DOTNET_STARTUP_HOOKS"]; !ok || len(dropped) != 5 {
		t.Errorf("allowEnvs did not admit DOTNET_STARTUP_HOOKS: %v / %v", entries, dropped)
	}
}

func TestBuildEnvAllowEnvsPassesHostValue(t *testing.T) {
	entries, _ := BuildEnv(EnvOptions{Host: ParseEnviron(testHostEnv), AllowEnvs: []string{"USERNAME"}})
	if envMap(entries)["USERNAME"] != "u" {
		t.Errorf("allow-listed host variable missing: %v", entries)
	}
}

func TestBuildEnvProxyReplacesCallerProxy(t *testing.T) {
	entries, _ := BuildEnv(EnvOptions{
		Host:   ParseEnviron(testHostEnv),
		Config: map[string]string{"https_proxy": "http://attacker:1", "no_proxy": "*"},
		Proxy: map[string]string{
			"HTTP_PROXY": "http://127.0.0.1:5000", "http_proxy": "http://127.0.0.1:5000",
			"HTTPS_PROXY": "http://127.0.0.1:5000", "NO_PROXY": "localhost,127.0.0.1,::1",
		},
	})
	m := envMap(entries)
	if m["HTTPS_PROXY"] != "http://127.0.0.1:5000" || m["HTTP_PROXY"] != "http://127.0.0.1:5000" {
		t.Errorf("proxy variables not owned by the engine: %v", entries)
	}
	if m["NO_PROXY"] != "localhost,127.0.0.1,::1" {
		t.Errorf("caller NO_PROXY bypass survived: %q", m["NO_PROXY"])
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(strings.ToUpper(e), "HTTP_PROXY=") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("HTTP_PROXY emitted %d times", n)
	}
}

func TestMissingRequiredEnv(t *testing.T) {
	if m := MissingRequiredEnv([]string{`SystemRoot=C:\Windows`, `LocalAppData=C:\x`}); len(m) != 0 {
		t.Errorf("unexpected missing %v", m)
	}
	if m := MissingRequiredEnv([]string{`SystemRoot=C:\Windows`, `LOCALAPPDATA=`}); !slices.Equal(m, []string{"LOCALAPPDATA"}) {
		t.Errorf("missing = %v", m)
	}
}

func TestEnvSet(t *testing.T) {
	s := ParseEnviron([]string{"Path=a", "PATH=b", "noequals", "=hidden=x"})
	if v, _ := s.Get("path"); v != "b" {
		t.Errorf("later duplicate should win, got %q", v)
	}
	if got := s.Entries(); !slices.Equal(got, []string{"Path=b"}) {
		t.Errorf("entries = %v", got)
	}
	s.Delete("PaTh")
	if _, ok := s.Get("PATH"); ok {
		t.Error("Delete is not case-insensitive")
	}
}
