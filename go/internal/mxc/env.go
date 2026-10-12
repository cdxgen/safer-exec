package mxc

import (
	"sort"
	"strings"
)

// Windows environment construction.
//
// The POSIX engines inherit only PATH, HOME, TERM, LANG and LC_* from the host
// and overlay the caller's sanitized env map. On Windows those names are not
// enough to start most programs (the C runtime, Node, Python and .NET all
// consult SystemRoot, PATHEXT, the profile folders, ...), and environment
// names are case-insensitive, so "Path" and "PATH" are the same variable.
// BuildEnv applies the same minimal-inheritance model with a Windows baseline
// and case-insensitive merging.

// inheritedWindowsEnv lists host variables every sandboxed process receives
// unless the caller overrides them. They describe the OS layout and the
// standard profile folders; none of them carries a credential. Folder
// variables only name locations — the filesystem policy decides access.
var inheritedWindowsEnv = []string{
	"PATH", "PATHEXT",
	"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "COMSPEC",
	"PROGRAMDATA", "ALLUSERSPROFILE", "PUBLIC",
	"PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMFILES(ARM)", "PROGRAMW6432",
	"COMMONPROGRAMFILES", "COMMONPROGRAMFILES(X86)", "COMMONPROGRAMFILES(ARM)", "COMMONPROGRAMW6432",
	"USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
	"OS", "NUMBER_OF_PROCESSORS",
	"PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432", "PROCESSOR_IDENTIFIER",
	"PROCESSOR_LEVEL", "PROCESSOR_REVISION",
	"HOME", "TERM", "LANG",
}

// requiredWindowsEnv must be present for a ProcessContainer launch: MXC
// rejects a caller-owned environment block without them.
var requiredWindowsEnv = []string{"SYSTEMROOT", "LOCALAPPDATA"}

// windowsDangerousEnv lists Windows-specific variables that load code into a
// process the sandbox allows to run:
//
//   - CLR and CoreCLR profilers inject an arbitrary DLL into every .NET
//     process; DOTNET_STARTUP_HOOKS loads managed assemblies before Main;
//     DOTNET_ADDITIONAL_DEPS and DOTNET_SHARED_STORE add assemblies to the
//     resolution set; DOTNET_DiagnosticPorts connects the runtime to an
//     outside diagnostics server that can inject code;
//   - COMPlus_* is the legacy spelling of every CLR configuration knob,
//     profilers included;
//   - __COMPAT_LAYER applies application-compatibility shims;
//   - PSModulePath decides where PowerShell auto-loads modules from.
//
// They are stripped unless named in allowEnvs, on top of the cross-platform
// loader-control filtering config.SanitizeEnv already applied.
var windowsDangerousEnv = map[string]bool{
	"COR_ENABLE_PROFILING":     true,
	"COR_PROFILER":             true,
	"COR_PROFILER_PATH":        true,
	"COR_PROFILER_PATH_32":     true,
	"COR_PROFILER_PATH_64":     true,
	"CORECLR_ENABLE_PROFILING": true,
	"CORECLR_PROFILER":         true,
	"DOTNET_STARTUP_HOOKS":     true,
	"DOTNET_ADDITIONAL_DEPS":   true,
	"DOTNET_SHARED_STORE":      true,
	"DOTNET_DIAGNOSTICPORTS":   true,
	"__COMPAT_LAYER":           true,
	"PSMODULEPATH":             true,
}

var windowsDangerousEnvPrefixes = []string{"CORECLR_PROFILER_PATH", "COR_PROFILER_PATH", "COMPLUS_"}

// noCwdSearchEnv makes CreateProcess, cmd.exe and the C runtime's search skip
// the current directory when resolving a bare command name. The engine
// resolves the program itself without searching the working directory, but
// batch shims (npm.cmd starting node) and the workload's own children would
// otherwise run a node.exe planted in the project before the one on PATH.
const noCwdSearchEnv = "NoDefaultCurrentDirectoryInExePath"

// IsWindowsDangerousEnv reports whether key is a Windows code-injection
// variable (case-insensitive).
func IsWindowsDangerousEnv(key string) bool {
	uk := strings.ToUpper(key)
	if windowsDangerousEnv[uk] {
		return true
	}
	for _, p := range windowsDangerousEnvPrefixes {
		if strings.HasPrefix(uk, p) {
			return true
		}
	}
	return false
}

// proxyEnvNames are the cooperative-proxy variables. In proxy mode the engine
// owns them; any caller value is replaced so the workload cannot be pointed
// at a different (blocked) endpoint or told to bypass the proxy.
var proxyEnvNames = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY"}

// EnvSet is a case-insensitive environment that remembers the spelling of the
// first occurrence of each name.
type EnvSet struct {
	names  map[string]string // upper-case key -> original spelling
	values map[string]string // upper-case key -> value
}

// NewEnvSet returns an empty EnvSet.
func NewEnvSet() *EnvSet {
	return &EnvSet{names: map[string]string{}, values: map[string]string{}}
}

// ParseEnviron builds an EnvSet from "KEY=VALUE" entries (os.Environ form).
// Entries without '=' and the hidden per-drive "=C:" entries are skipped.
func ParseEnviron(environ []string) *EnvSet {
	s := NewEnvSet()
	for _, kv := range environ {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		s.Set(kv[:i], kv[i+1:])
	}
	return s
}

// Get returns the value for key, matched case-insensitively.
func (s *EnvSet) Get(key string) (string, bool) {
	v, ok := s.values[strings.ToUpper(key)]
	return v, ok
}

// Set assigns key, keeping the original spelling of an existing name.
func (s *EnvSet) Set(key, value string) {
	uk := strings.ToUpper(key)
	if _, ok := s.names[uk]; !ok {
		s.names[uk] = key
	}
	s.values[uk] = value
}

// Delete removes key (case-insensitive).
func (s *EnvSet) Delete(key string) {
	uk := strings.ToUpper(key)
	delete(s.names, uk)
	delete(s.values, uk)
}

// Entries returns "KEY=VALUE" strings sorted case-insensitively, the order
// Windows expects in an environment block.
func (s *EnvSet) Entries() []string {
	keys := make([]string, 0, len(s.values))
	for uk := range s.values {
		keys = append(keys, uk)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, uk := range keys {
		out = append(out, s.names[uk]+"="+s.values[uk])
	}
	return out
}

// EnvOptions controls BuildEnv.
type EnvOptions struct {
	// Host is the engine's own environment.
	Host *EnvSet
	// Config is the caller's env map after config.SanitizeEnv.
	Config map[string]string
	// AllowEnvs is the caller's explicit pass-through list; it also exempts
	// names from the Windows-specific dangerous-variable filter.
	AllowEnvs []string
	// Proxy, when set, holds the proxy variables the engine injects; they
	// replace any caller-supplied proxy configuration.
	Proxy map[string]string
}

// BuildEnv returns the workload's environment block entries and the names of
// any caller variables that were dropped by the Windows-specific filter.
func BuildEnv(opts EnvOptions) (entries []string, dropped []string) {
	allow := map[string]bool{}
	for _, a := range opts.AllowEnvs {
		allow[strings.ToUpper(a)] = true
	}

	env := NewEnvSet()
	host := opts.Host
	if host == nil {
		host = NewEnvSet()
	}
	for _, name := range inheritedWindowsEnv {
		if v, ok := host.Get(name); ok {
			env.Set(host.names[strings.ToUpper(name)], v)
		}
	}
	// Explicit pass-through of host variables named in allowEnvs mirrors the
	// Node layer, which copies them into the config map; doing it here as
	// well keeps direct engine callers consistent.
	for _, a := range opts.AllowEnvs {
		if v, ok := host.Get(a); ok {
			if _, set := opts.Config[a]; !set {
				env.Set(a, v)
			}
		}
	}

	cfgKeys := make([]string, 0, len(opts.Config))
	for k := range opts.Config {
		cfgKeys = append(cfgKeys, k)
	}
	sort.Strings(cfgKeys)
	for _, k := range cfgKeys {
		if strings.ContainsRune(k, '=') || k == "" {
			dropped = append(dropped, k)
			continue
		}
		if IsWindowsDangerousEnv(k) && !allow[strings.ToUpper(k)] {
			dropped = append(dropped, k)
			continue
		}
		env.Set(k, opts.Config[k])
	}

	if _, set := env.Get(noCwdSearchEnv); !set {
		env.Set(noCwdSearchEnv, "1")
	}

	if opts.Proxy != nil {
		for _, n := range proxyEnvNames {
			env.Delete(n)
		}
		pk := make([]string, 0, len(opts.Proxy))
		for k := range opts.Proxy {
			pk = append(pk, k)
		}
		sort.Strings(pk)
		for _, k := range pk {
			// Windows names are case-insensitive: "http_proxy" and
			// "HTTP_PROXY" are one variable, so the first spelling wins.
			if _, ok := env.Get(k); !ok {
				env.Set(k, opts.Proxy[k])
			}
		}
	}
	return env.Entries(), dropped
}

// MissingRequiredEnv returns the names MXC requires that entries lacks.
func MissingRequiredEnv(entries []string) []string {
	set := ParseEnviron(entries)
	var missing []string
	for _, n := range requiredWindowsEnv {
		if v, ok := set.Get(n); !ok || v == "" {
			missing = append(missing, n)
		}
	}
	return missing
}
