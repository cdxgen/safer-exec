package mxc

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// Mode selects how a run uses MXC.
type Mode int

const (
	// ModeEnforce runs the workload under the translated policy.
	ModeEnforce Mode = iota
	// ModeLearn runs the workload contained under the policy with denial
	// capture on, and derives a policy from what was recorded. (MXC's
	// permissive capture mode is not used: on BaseContainer hosts it lifts
	// enforcement but records no filesystem accesses.)
	ModeLearn
	// ModeDryRun denies everything except bootstrap reads and records what the
	// workload attempted.
	ModeDryRun
)

// launcherProcesses is the number of job-object processes that are not part
// of the workload: wxc-exec.exe itself. conhost.exe instances created for the
// console are not charged against JOB_OBJECT_LIMIT_ACTIVE_PROCESS (verified on
// Windows 11 25H2), so they are not counted.
const launcherProcesses = 1

// launcherMemoryHeadroom is added to the job-wide memory limit so that the
// caller's MaxMemoryMB budgets the workload rather than the launcher, whose
// committed memory is charged to the same job. wxc-exec commits well under
// this amount.
const launcherMemoryHeadroom = 32 << 20

// batchShimProcesses is the process allowance for a batch command's cmd.exe
// interpreters (the outer one and a FOR /F subshell).
const batchShimProcesses = 2

// defaultEgressPorts mirrors the Linux engine: when egress is restricted but
// no ports are named, only HTTP and HTTPS are allowed.
var defaultEgressPorts = []int{80, 443}

// Host supplies the facts the translator needs about the machine it runs on.
// The Windows engine fills it from the live system; tests inject fixtures.
type Host struct {
	// Env is the engine's own environment.
	Env *EnvSet
	// Cwd is the engine's working directory, used when the config has none.
	Cwd string
	// IsFile reports whether path exists and is a regular file.
	IsFile func(path string) bool
	// Exists reports whether path exists (file or directory).
	Exists func(path string) bool
	// LookupIP resolves a hostname to its addresses.
	LookupIP func(host string) ([]net.IP, error)
	// NumCPU is the number of logical processors.
	NumCPU int
	// LongPath expands 8.3 short names in an existing path (GetLongPathName),
	// so a grant spelled C:\Users\RUNNER~1 is compared as the directory it
	// names. Optional; nil leaves paths as spelled.
	LongPath func(path string) string
	// Documents is the user's Documents known folder, which OneDrive and
	// folder redirection can move away from %USERPROFILE%\Documents.
	// Optional.
	Documents string
}

// Options carries per-run engine decisions into the translation.
type Options struct {
	Mode Mode
	// ProxyPort is the loopback port of the engine's egress proxy for this
	// run, or 0 when no proxy runs.
	ProxyPort int
	// ProxyEnv holds the proxy variables to inject when ProxyPort is set.
	ProxyEnv map[string]string
	// CaptureOutputPath is the denial report path MXC should write; its parent
	// directory must exist. Required for ModeLearn and ModeDryRun and for
	// ModeEnforce with EnableAudit.
	CaptureOutputPath string
	// HostLoopbackSupported reports whether this host's container API can
	// open host loopback for a direct-egress policy (PSEC 1.1 ingress).
	HostLoopbackSupported bool
	// ProtectedPaths are engine-owned locations (the run directories that
	// hold requests and denial reports, MXC's ACL-recovery state) that no
	// workload may touch. Each is denied whenever a grant covers it.
	ProtectedPaths []string
	// CascadingGrants is set when MXC runs on its ACL-modifying tier, where
	// a grant is an inheritable ACE on the target and so covers the whole
	// tree below it, volume roots included.
	CascadingGrants bool
}

// JobLimits are resource limits the engine applies through a job object that
// contains wxc-exec.exe and, through job nesting, every workload process.
type JobLimits struct {
	// MemoryBytes caps the committed memory of the whole job (0 = none).
	MemoryBytes uint64
	// CPURate is a hard CPU cap in hundredths of a percent of total machine
	// CPU time, 1..10000 (0 = none).
	CPURate uint32
	// ActiveProcesses caps the number of live processes in the job,
	// including the launcher (0 = none).
	ActiveProcesses uint32
}

// Plan is the result of translating an ExecConfig.
type Plan struct {
	Request Request
	// Program is the resolved executable, or the batch script for .bat/.cmd.
	Program string
	// IsBatch reports whether Program runs through cmd.exe.
	IsBatch bool
	// Cwd is the workload's working directory.
	Cwd string
	// SystemRoot is the host's %SystemRoot%, which the container can read
	// without a grant.
	SystemRoot string
	// ReadPaths and WritePaths are the effective grants sent to MXC.
	ReadPaths  []string
	WritePaths []string
	// Limits are applied by the engine's job object.
	Limits JobLimits
	// Warnings are printed as "safer-exec: warning: ..." and never fatal.
	Warnings []string
	// Unenforced lists requested restrictions Windows cannot enforce for this
	// run. They are warnings by default and errors under strict mode.
	Unenforced []string
	// Broadened lists places where Windows must grant more than the config
	// asked for (a capability that cannot be scoped as narrowly). Warnings by
	// default, errors under strict mode.
	Broadened []string
	// Skipped lists policy paths that were not sent to MXC and why.
	Skipped []string
	// DroppedEnv lists caller variables removed by the Windows filter.
	DroppedEnv []string
}

// Translate maps an ExecConfig onto an MXC request plus the host-side
// controls the engine applies around it. cfg.Env must already have passed
// through config.SanitizeEnv.
func Translate(cfg config.ExecConfig, host Host, opts Options) (*Plan, error) {
	if host.Env == nil {
		host.Env = NewEnvSet()
	}
	if host.IsFile == nil || host.Exists == nil {
		return nil, errors.New("mxc: host file probes are required")
	}
	p := &Plan{}

	// --- Working directory -------------------------------------------------
	cwd := cfg.WorkingDir
	if cwd == "" {
		cwd = host.Cwd
	}
	if !WinIsAbs(cwd) {
		return nil, fmt.Errorf("working directory %q is not an absolute Windows path", cwd)
	}
	cwd = WinClean(cwd)
	p.Cwd = cwd

	// --- Environment -------------------------------------------------------
	var proxyEnv map[string]string
	if opts.ProxyPort > 0 && opts.Mode != ModeDryRun {
		proxyEnv = opts.ProxyEnv
	}
	envEntries, dropped := BuildEnv(EnvOptions{
		Host:      host.Env,
		Config:    cfg.Env,
		AllowEnvs: cfg.AllowEnvs,
		Proxy:     proxyEnv,
	})
	p.DroppedEnv = dropped
	if missing := MissingRequiredEnv(envEntries); len(missing) > 0 {
		return nil, fmt.Errorf("the Windows process container requires %s in the environment", strings.Join(missing, " and "))
	}
	envSet := ParseEnviron(envEntries)
	if len(dropped) > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("dropped Windows code-injection environment variable(s) %s; name them in allowEnvs to pass them through", strings.Join(dropped, ", ")))
	}

	// --- Command line ------------------------------------------------------
	pathList, _ := envSet.Get("PATH")
	pathExt, _ := envSet.Get("PATHEXT")
	program, err := LookPath(cfg.Cmd, LookPathOptions{
		PathList: pathList,
		PathExt:  pathExt,
		Dir:      cwd,
		IsFile:   host.IsFile,
	})
	if err != nil {
		return nil, err
	}
	p.Program = program
	p.IsBatch = IsBatchFile(program)

	// cmd.exe always comes from the host's own SystemRoot: a caller-supplied
	// SYSTEMROOT must not be able to redirect the batch interpreter.
	systemRoot, _ := host.Env.Get("SYSTEMROOT")
	if !WinIsAbs(systemRoot) {
		return nil, errors.New("cannot determine %SystemRoot% on this host")
	}
	systemRoot = WinClean(systemRoot)
	p.SystemRoot = systemRoot

	var commandLine string
	switch {
	case p.IsBatch:
		commandLine, err = ComposeBatchCommandLine(WinJoin(systemRoot, "System32", "cmd.exe"), program, cfg.Args)
	case IsCmdExe(program):
		commandLine, err = ComposeCmdCommandLine(program, cfg.Args)
	default:
		commandLine, err = ComposeCommandLine(program, cfg.Args)
	}
	if err != nil {
		return nil, err
	}

	// --- Filesystem --------------------------------------------------------
	// Every path that is compared with a grant goes through canon, so 8.3
	// short spellings (an interactive session's %TEMP% is often
	// C:\Users\RUNNER~1\...) compare equal to the long names grants use.
	canon := func(path string) string {
		if host.LongPath != nil && WinIsAbs(path) && host.Exists(path) {
			if long := host.LongPath(path); WinIsAbs(long) {
				return WinClean(long)
			}
		}
		return path
	}
	userProfile, _ := host.Env.Get("USERPROFILE")
	if WinIsAbs(userProfile) {
		userProfile = canon(WinClean(userProfile))
	}
	norm := func(raw string) (string, bool) {
		path, reason := normalizePolicyPath(raw, cwd, userProfile)
		if reason != "" {
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s (%s)", raw, reason))
			return "", false
		}
		if !host.Exists(path) {
			// A grant on a path that does not exist yet is not honored by the
			// OS container API, matching the Linux engine, which skips missing
			// bind-mount sources.
			p.Skipped = append(p.Skipped, fmt.Sprintf("%s (does not exist)", raw))
			return "", false
		}
		return canon(path), true
	}

	var writePaths, readPaths []string
	if opts.Mode != ModeDryRun {
		for _, w := range cfg.WritePaths {
			if path, ok := norm(w); ok {
				writePaths = appendUniquePath(writePaths, path)
			}
		}
		for _, r := range cfg.ReadPaths {
			if path, ok := norm(r); ok && !containsPath(writePaths, path) {
				// MXC resolves an identical ro/rw pair to read-only (strictest
				// wins); safer-exec's write grant implies read, so the read
				// entry is dropped instead.
				readPaths = appendUniquePath(readPaths, path)
			}
		}
	}

	// Bootstrap grants. A BaseContainer cannot read outside its grants
	// (Program Files and the user profile included), so the executable's own
	// directory must be readable for the loader, and the working directory
	// for the process to start at all. Paths under %SystemRoot% are readable
	// by default and need no grant.
	covered := func(path string) bool {
		return WinHasPrefix(path, systemRoot) || coveredBy(path, writePaths) || coveredBy(path, readPaths)
	}
	// The program's directory is granted so the loader can find DLLs next
	// to it, unless that directory is a broad one (the user profile, an
	// ancestor of it, a volume root, Documents, Desktop or Downloads): there
	// only the program file itself is granted, so running a tool stored in
	// the profile root does not expose everything beside it.
	programGrant := canon(WinDir(program))
	if broadDirectory(programGrant, host, userProfile) {
		programGrant = canon(program)
		p.Warnings = append(p.Warnings, fmt.Sprintf("%s is in a broad directory (%s); only the program file is readable, so DLLs or files beside it are not", program, WinDir(program)))
	}
	for _, path := range []string{programGrant, canon(cwd)} {
		if !covered(path) {
			readPaths = appendUniquePath(readPaths, path)
		}
	}

	for _, path := range append(append([]string{}, writePaths...), readPaths...) {
		if !WinIsVolumeRoot(path) {
			continue
		}
		if opts.CascadingGrants {
			return nil, fmt.Errorf("refusing the grant on volume root %s: on MXC's ACL-modifying tier it would apply to the whole drive", path)
		}
		p.Warnings = append(p.Warnings, fmt.Sprintf("the grant on volume root %s does not extend to its subdirectories in a Windows container; grant the specific directories instead", path))
	}

	// Denied paths must exist: the container API refuses to create an
	// environment whose policy denies a missing path (ERROR_PATH_NOT_FOUND).
	var deniedPaths, undeniable []string
	if cfg.DenyPersistenceWrites {
		for _, d := range persistencePaths(host.Env, host.Documents) {
			d = canon(d)
			if !coveredBy(d, writePaths) || containsPath(writePaths, d) {
				continue
			}
			if host.Exists(d) {
				deniedPaths = appendUniquePath(deniedPaths, d)
			} else {
				undeniable = append(undeniable, d)
			}
		}
	}
	if len(undeniable) > 0 {
		p.Unenforced = append(p.Unenforced, fmt.Sprintf("denyPersistenceWrites for %s (they do not exist yet, and a Windows container cannot deny a missing path; the write grant lets the workload create them)", strings.Join(undeniable, ", ")))
	}
	// Engine-owned locations are never reachable, whatever the grants say.
	// The engine creates them before translating.
	for _, raw := range opts.ProtectedPaths {
		if !WinIsAbs(raw) {
			continue
		}
		d := WinClean(raw)
		if !host.Exists(d) {
			continue
		}
		d = canon(d)
		if coveredBy(d, writePaths) || coveredBy(d, readPaths) || grantsInside(d, writePaths, readPaths) {
			deniedPaths = appendUniquePath(deniedPaths, d)
		}
	}

	p.ReadPaths, p.WritePaths = readPaths, writePaths
	if len(p.Skipped) > 0 {
		sort.Strings(p.Skipped)
	}

	// --- Network -----------------------------------------------------------
	network, runtimeCfg := p.translateNetwork(cfg, host, opts)

	// --- Denial capture ----------------------------------------------------
	var capture *CaptureDenials
	// Learning uses deny-and-record, not MXC's permissive mode: on
	// BaseContainer hosts the permissive mode lifts enforcement but records
	// no filesystem accesses, so it would run the workload unconfined while
	// learning nothing. A learning run stays contained and records what the
	// container API reports.
	if opts.Mode != ModeEnforce || cfg.EnableAudit {
		capture = &CaptureDenials{Mode: CaptureBlock, OutputPath: opts.CaptureOutputPath}
	}
	if opts.Mode == ModeLearn {
		p.Warnings = append(p.Warnings, "learning on Windows runs contained: the container API reports conflicts with existing grants and probes of protected directories, "+
			"but not accesses to paths outside every grant; grant such paths explicitly and re-run, or inspect them with dryRun")
	}
	if capture != nil && capture.OutputPath == "" {
		return nil, errors.New("mxc: a denial capture output path is required for audit, learn and dry-run modes")
	}

	// --- Resource limits ---------------------------------------------------
	p.Limits = p.translateLimits(cfg, host)

	// --- Controls Windows cannot enforce -----------------------------------
	p.collectUnenforced(cfg, host, envSet, systemRoot, canon)

	// --- Request -----------------------------------------------------------
	var timeout uint32
	if cfg.TimeoutMs > 0 {
		timeout = uint32(min(int64(cfg.TimeoutMs), math.MaxUint32))
	}
	req := Request{
		Version:     SchemaVersion,
		Containment: Containment,
		Process: Process{
			CommandLine:       commandLine,
			Cwd:               cwd,
			Env:               envEntries,
			InheritDefaultEnv: false,
			Timeout:           timeout,
		},
		Network:       network,
		RuntimeConfig: runtimeCfg,
		// The Win32k kill switch is opt-in: common runtimes (Node.js) cannot
		// start without user32.dll. Clipboard and input injection stay
		// blocked, and MXC's ProcessContainer UI defaults keep handle and
		// atom isolation, desktop, system-settings and IME restrictions.
		UI:        &UI{Disable: cfg.WindowsBlockWin32k, Clipboard: "none", Injection: false},
		Telemetry: &Telemetry{Enabled: false},
		Fallback:  &Fallback{AllowDaclMutation: cfg.WindowsAllowDaclMutation},
	}
	if len(writePaths) > 0 || len(readPaths) > 0 || len(deniedPaths) > 0 {
		req.Filesystem = &Filesystem{
			ReadwritePaths: writePaths,
			ReadonlyPaths:  readPaths,
			DeniedPaths:    deniedPaths,
		}
	}
	if capture != nil {
		req.ProcessContainer = &ProcessContainer{CaptureDenials: capture}
	}
	p.Request = req
	return p, nil
}

// normalizePolicyPath turns a policy path into a clean absolute Windows path,
// or returns a reason it cannot be used.
func normalizePolicyPath(raw, cwd, userProfile string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "empty"
	}
	if strings.ContainsRune(s, 0) {
		return "", "contains NUL"
	}
	if IsDevicePath(s) {
		return "", "device namespace path"
	}
	if s == "~" || strings.HasPrefix(s, `~\`) || strings.HasPrefix(s, "~/") {
		if !WinIsAbs(userProfile) {
			return "", "cannot expand ~ without USERPROFILE"
		}
		s = WinJoin(userProfile, s[1:])
	}
	// Colons are legal only in the drive specifier; any other colon names an
	// NTFS alternate data stream.
	if i := strings.LastIndexByte(s, ':'); i > 1 || (i == 1 && !isASCIILetter(s[0])) {
		return "", "alternate data stream or invalid colon"
	}
	if strings.ContainsAny(s, `*?"<>|`) {
		return "", "wildcards are not supported by the Windows container policy"
	}
	if WinIsRootedWithoutVolume(s) {
		return "", "POSIX-style path without a drive letter"
	}
	if len(s) >= 2 && s[1] == ':' && !WinIsAbs(s) {
		return "", "drive-relative path"
	}
	if !WinIsAbs(s) {
		s = WinJoin(cwd, s)
	}
	return WinClean(trimComponentDots(s)), ""
}

// trimComponentDots drops the trailing dots and spaces Win32 path parsing
// strips from each component, so C:\Users\me. and C:\Users\me are compared
// as the same directory. "." and ".." are left for WinClean.
func trimComponentDots(s string) string {
	parts := strings.Split(strings.ReplaceAll(s, "/", `\`), `\`)
	for i, part := range parts {
		if part == "." || part == ".." || (i == 0 && strings.HasSuffix(part, ":")) {
			continue
		}
		if trimmed := strings.TrimRight(part, ". "); trimmed != "" || part == "" {
			parts[i] = trimmed
		}
	}
	return strings.Join(parts, `\`)
}

func appendUniquePath(list []string, path string) []string {
	if containsPath(list, path) {
		return list
	}
	return append(list, path)
}

func containsPath(list []string, path string) bool {
	return slices.ContainsFunc(list, func(l string) bool { return WinEqual(l, path) })
}

// coveredBy reports whether path equals or lies under any entry of grants.
// Volume-root grants do not cascade in a BaseContainer, so they only cover
// the root itself.
func coveredBy(path string, grants []string) bool {
	for _, g := range grants {
		if WinIsVolumeRoot(g) {
			if WinEqual(path, g) {
				return true
			}
			continue
		}
		if WinHasPrefix(path, g) {
			return true
		}
	}
	return false
}

// persistencePaths lists per-user and machine-wide locations whose contents
// run automatically at logon, at shell or tool start, or ahead of system
// commands on PATH. They are denied when DenyPersistenceWrites is set and a
// broader write grant would cover them. documents is the Documents known
// folder when it has been redirected (OneDrive), else empty.
func persistencePaths(env *EnvSet, documents string) []string {
	var out []string
	add := func(base string, elems ...string) {
		if WinIsAbs(base) {
			out = appendUniquePath(out, WinClean(WinJoin(base, elems...)))
		}
	}
	appData, _ := env.Get("APPDATA")
	localAppData, _ := env.Get("LOCALAPPDATA")
	programData, _ := env.Get("PROGRAMDATA")
	userProfile, _ := env.Get("USERPROFILE")
	// Logon.
	add(appData, `Microsoft\Windows\Start Menu\Programs\Startup`)
	add(programData, `Microsoft\Windows\Start Menu\Programs\StartUp`)
	// PowerShell profiles, under the real Documents folder and the default.
	for _, docs := range []string{documents, WinJoin(userProfile, "Documents")} {
		add(docs, "WindowsPowerShell")
		add(docs, "PowerShell")
	}
	// Per-user directories on PATH: a planted program there shadows or
	// adds commands for every later shell.
	add(localAppData, `Microsoft\WindowsApps`)
	add(appData, "npm")
	// Shell, git, npm and SSH configuration that runs code or grants access.
	for _, f := range []string{".bashrc", ".bash_profile", ".profile", ".gitconfig", ".npmrc", ".ssh"} {
		add(userProfile, f)
	}
	return out
}

// grantsInside reports whether any grant lies strictly inside dir; denying
// dir then also shuts those grants (MXC's strictest-wins rule).
func grantsInside(dir string, lists ...[]string) bool {
	for _, list := range lists {
		for _, g := range list {
			if !WinEqual(g, dir) && WinHasPrefix(g, dir) {
				return true
			}
		}
	}
	return false
}

// broadDirectory reports whether dir is too broad to grant just because a
// program lives there: a volume root, the user profile or one of its
// ancestors, or the profile's Desktop, Documents or Downloads.
func broadDirectory(dir string, host Host, userProfile string) bool {
	if WinIsVolumeRoot(dir) {
		return true
	}
	if !WinIsAbs(userProfile) {
		return false
	}
	userProfile = WinClean(userProfile)
	if WinHasPrefix(userProfile, dir) {
		return true
	}
	for _, sub := range []string{"Desktop", "Documents", "Downloads"} {
		if WinEqual(dir, WinJoin(userProfile, sub)) {
			return true
		}
	}
	return host.Documents != "" && WinEqual(dir, host.Documents)
}

// translateNetwork maps the safer-exec network fields onto MXC's directional
// policy. MXC's ProcessContainer networking has three shapes:
//
//   - blocked: egress and ingress deny;
//   - proxy-only: egress deny with a loopback runtime proxy; WFP confines the
//     container to the proxy endpoint and the proxy enforces hostnames;
//   - direct: numeric CIDR/port allow rules enforced by WFP.
func (p *Plan) translateNetwork(cfg config.ExecConfig, host Host, opts Options) (*Network, *RuntimeConfig) {
	blocked := &Network{
		Egress:  Egress{Default: ActionDeny},
		Ingress: Ingress{Default: ActionDeny, HostLoopback: ActionDeny},
	}

	if opts.Mode == ModeDryRun || cfg.DisableNetwork {
		return blocked, nil
	}

	if opts.ProxyPort > 0 {
		// A ProcessContainer proxy requires the private-network capability
		// (ingress default allow). safer-exec's proxy is an unpackaged process
		// without an AppContainer identity, so MXC also requires host-loopback
		// allow. MXC documents this identity-less mode as its weaker option;
		// on Windows 11 25H2 WFP still confines the container's egress to the
		// proxy endpoint: other loopback listeners, the host's LAN address and
		// allowed hosts dialed directly all stay unreachable (covered by
		// TestWindowsEngineConfinesHostAndProxyBypass).
		if cfg.AllowLoopback {
			p.Warnings = append(p.Warnings, "allowLoopback is not available together with the egress proxy on Windows: the container can reach only the proxy endpoint on loopback")
		}
		if hasURLPathRules(cfg.AllowURLRules) {
			p.Unenforced = append(p.Unenforced, "allowURLRules path/method/protocol constraints (only their hostnames are enforced by the egress proxy on Windows)")
		}
		return &Network{
			Egress:  Egress{Default: ActionDeny},
			Ingress: Ingress{Default: ActionAllow, HostLoopback: ActionAllow},
		}, &RuntimeConfig{
			NetworkProxy: fmt.Sprintf("http://127.0.0.1:%d", opts.ProxyPort),
		}
	}

	if cfg.ProxyEgress {
		p.Warnings = append(p.Warnings, "egress proxy unavailable; falling back to IP-pinned direct egress rules")
	}
	if len(cfg.AllowURLRules) > 0 {
		p.Warnings = append(p.Warnings, "allowURLRules are evaluated by eBPF URL tracing, which is Linux-only; on Windows use proxyEgress to enforce their hostnames")
	}

	// Ports. 0 means "any port" (Landlock and Seatbelt semantics).
	anyPort := false
	var ports []int
	for _, port := range cfg.AllowPorts {
		switch {
		case port == 0:
			anyPort = true
		case port > 0 && port <= 65535:
			if !slices.Contains(ports, port) {
				ports = append(ports, port)
			}
		default:
			p.Warnings = append(p.Warnings, fmt.Sprintf("ignoring invalid port %d", port))
		}
	}
	restrictDest := len(cfg.AllowHosts) > 0 || len(cfg.AllowIPs) > 0
	if (restrictDest || len(ports) > 0) && len(ports) == 0 && !anyPort {
		ports = append(ports, defaultEgressPorts...)
	}
	sort.Ints(ports)
	var portRules []Port
	if !anyPort {
		for _, port := range ports {
			portRules = append(portRules, Port{Protocol: "tcp", Port: port})
		}
	}

	hostLoopback := cfg.AllowLoopback
	privateDest := false
	anyHost := false
	var peers []Peer
	addPrefix := func(pfx netip.Prefix) {
		pfx = pfx.Masked()
		if pfx.Addr().IsLoopback() {
			// Loopback is not an egress destination in MXC's model; it is the
			// separate host-loopback control.
			hostLoopback = true
			return
		}
		if isPrivatePrefix(pfx) {
			privateDest = true
		}
		cidr := pfx.String()
		if !slices.ContainsFunc(peers, func(e Peer) bool { return e.CIDR == cidr }) {
			peers = append(peers, Peer{CIDR: cidr})
		}
	}

	for _, h := range cfg.AllowHosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		switch {
		case h == "":
			continue
		case h == "*":
			anyHost = true
		case strings.HasPrefix(h, "*.") || strings.HasPrefix(h, "~"):
			p.Warnings = append(p.Warnings, fmt.Sprintf("host pattern %q cannot be pinned to addresses; use proxyEgress to allow it on Windows (it stays blocked)", h))
		default:
			if addr, err := netip.ParseAddr(h); err == nil {
				addPrefix(netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
				continue
			}
			if host.LookupIP == nil {
				p.Warnings = append(p.Warnings, fmt.Sprintf("cannot resolve host %q; it stays blocked", h))
				continue
			}
			ips, err := host.LookupIP(h)
			if err != nil || len(ips) == 0 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("cannot resolve host %q (%v); it stays blocked", h, err))
				continue
			}
			for _, ip := range ips {
				if addr, ok := netip.AddrFromSlice(ip); ok {
					addr = addr.Unmap()
					addPrefix(netip.PrefixFrom(addr, addr.BitLen()))
				}
			}
		}
	}
	for _, raw := range cfg.AllowIPs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if s == "*" {
			anyHost = true
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			addPrefix(pfx)
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			addr = addr.Unmap()
			addPrefix(netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		p.Warnings = append(p.Warnings, fmt.Sprintf("ignoring invalid IP address %q", s))
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].CIDR < peers[j].CIDR })

	n := &Network{
		Egress:  Egress{Default: ActionAllow},
		Ingress: Ingress{Default: ActionDeny, HostLoopback: ActionDeny},
	}
	switch {
	case anyHost || (!restrictDest && len(portRules) > 0):
		// Any destination, restricted ports.
		n.Egress = Egress{Default: ActionDeny, Allow: []Rule{{Ports: portRules}}}
		if len(portRules) == 0 {
			n.Egress = Egress{Default: ActionAllow}
		}
	case restrictDest && len(peers) > 0:
		n.Egress = Egress{Default: ActionDeny, Allow: []Rule{{To: peers, Ports: portRules}}}
	case restrictDest:
		// Every requested destination was unresolvable or loopback-only.
		n.Egress = Egress{Default: ActionDeny}
	}

	if privateDest {
		n.Ingress.Default = ActionAllow
		p.Broadened = append(p.Broadened, "private-network destinations need the bidirectional privateNetworkClientServer capability, which also admits private-network inbound connections")
	}
	if len(cfg.AllowListen) > 0 {
		n.Ingress.Default = ActionAllow
		p.Broadened = append(p.Broadened, "allowListen cannot be scoped by address or port; private-network inbound is allowed for this run")
	}
	if hostLoopback {
		if opts.HostLoopbackSupported {
			n.Ingress.HostLoopback = ActionAllow
			p.Broadened = append(p.Broadened, "host loopback cannot be scoped by port; every loopback service on the host is reachable in both directions")
		} else {
			p.Warnings = append(p.Warnings, "host loopback access was requested but this Windows build's container API cannot grant it for direct egress; loopback stays blocked")
		}
	}
	return n, nil
}

func hasURLPathRules(rules []config.AllowURLRule) bool {
	for _, r := range rules {
		if (r.PathPrefix != "" && r.PathPrefix != "/") || len(r.Methods) > 0 || r.Protocol != "" || r.Port != 0 {
			return true
		}
	}
	return false
}

var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// isPrivatePrefix reports whether pfx overlaps private-network address space,
// which Windows gates behind privateNetworkClientServer rather than
// internetClient.
func isPrivatePrefix(pfx netip.Prefix) bool {
	for _, pp := range privatePrefixes {
		if pp.Overlaps(pfx) {
			return true
		}
	}
	return false
}

// translateLimits maps resource limits onto job-object limits.
func (p *Plan) translateLimits(cfg config.ExecConfig, host Host) JobLimits {
	var l JobLimits
	if cfg.MaxMemoryMB > 0 {
		// Saturate rather than wrap: an absurd limit must not become "none".
		const maxMB = (math.MaxUint64 - launcherMemoryHeadroom) >> 20
		if mb := uint64(cfg.MaxMemoryMB); mb > maxMB {
			l.MemoryBytes = math.MaxUint64
		} else {
			l.MemoryBytes = mb<<20 + launcherMemoryHeadroom
		}
	}
	if cfg.MaxCPUCores > 0 {
		ncpu := host.NumCPU
		if ncpu <= 0 {
			ncpu = 1
		}
		if cfg.MaxCPUCores < float64(ncpu) {
			rate := math.Ceil(cfg.MaxCPUCores / float64(ncpu) * 10000)
			l.CPURate = uint32(max(1, min(10000, rate)))
		}
	}

	// A .bat/.cmd command runs as cmd.exe plus the programs it starts — the
	// usual Windows shim pattern. npm's shim, for example, resolves its
	// prefix through FOR /F, which runs a nested cmd.exe and node.exe while
	// the outer cmd.exe is alive. Two processes are budgeted for the shim's
	// interpreters on top of the command's own allowance.
	shim := 0
	if p.IsBatch {
		shim = batchShimProcesses
	}
	workload := 0
	if cfg.BlockFork {
		workload = 1 + shim
	}
	if cfg.MaxProcesses > 0 {
		limit := cfg.MaxProcesses + shim
		if workload == 0 || limit < workload {
			workload = limit
		}
	}
	if workload > 0 {
		l.ActiveProcesses = uint32(min(int64(workload)+launcherProcesses, math.MaxUint32))
	}
	return l
}

// collectUnenforced records requested restrictions that Windows cannot
// enforce for this run, and warns about Linux/macOS-only observability.
func (p *Plan) collectUnenforced(cfg config.ExecConfig, host Host, env *EnvSet, systemRoot string, canon func(string) string) {
	if cfg.MaxReadIOPS > 0 || cfg.MaxWriteIOPS > 0 || cfg.MaxReadBps > 0 || cfg.MaxWriteBps > 0 {
		p.Unenforced = append(p.Unenforced, "I/O rate limits (Windows job objects cannot separate read and write limits)")
	}
	if cfg.BlockJIT {
		p.Unenforced = append(p.Unenforced, "blockJIT (Arbitrary Code Guard cannot be applied to a process created by the container launcher)")
	}
	if len(cfg.SeccompFilters) > 0 {
		p.Unenforced = append(p.Unenforced, "seccompFilters (Linux-only)")
	}
	if cfg.BlockCrypto || cfg.BlockCryptoEntropy {
		p.Unenforced = append(p.Unenforced, "blockCrypto/blockCryptoEntropy (Windows CNG is a system component every process can load)")
	}

	// Exec controls. A Windows container can start only executables it can
	// read, so an entry is enforced when no reachable copy exists; a process
	// limit that leaves room for nothing but the command itself (blockFork)
	// enforces every exec restriction. A batch command is the exception: its
	// interpreter slots can be taken by any program the script starts, so
	// they do not stand in for exec rules.
	execLimited := cfg.BlockFork && p.Limits.ActiveProcesses > 0 && !p.IsBatch
	if cfg.BlockFork && p.IsBatch {
		p.Unenforced = append(p.Unenforced, fmt.Sprintf("blockFork for a batch command (%s runs through cmd.exe, and the %d process slots its interpreters need can be used by any program it starts)", WinBase(p.Program), batchShimProcesses))
	}
	if len(cfg.AllowExec) > 0 && !execLimited {
		p.Unenforced = append(p.Unenforced, "allowExec (Windows has no per-executable exec filter; combine with blockFork to forbid child processes)")
	}
	if len(cfg.BlockExec) > 0 && !execLimited {
		var open []string
		for _, entry := range cfg.BlockExec {
			if !p.execBlocked(entry, env, systemRoot, host, canon) {
				open = append(open, entry)
			}
		}
		if len(open) > 0 {
			p.Unenforced = append(p.Unenforced, fmt.Sprintf("blockExec for %s (reachable inside the container; combine with blockFork to forbid child processes)", strings.Join(open, ", ")))
		}
	}

	if cfg.TraceHTTPURLs || cfg.TraceCrypto || cfg.CBOMOutputPath != "" || len(cfg.AllowCiphers) > 0 {
		p.Warnings = append(p.Warnings, "HTTP URL and crypto tracing use eBPF and are only supported on Linux; these settings are ignored on Windows")
	}
	if len(cfg.TmpOverlayPaths) > 0 {
		p.Warnings = append(p.Warnings, "tmpOverlayPaths are not supported on Windows; those paths are not writable")
	}
	if len(cfg.BindFds) > 0 {
		p.Warnings = append(p.Warnings, "bindFds is not supported on Windows")
	}
	if cfg.SpoofAntiVM {
		p.Warnings = append(p.Warnings, "spoofAntiVM is not supported on Windows")
	}
	if cfg.BlockTPM {
		p.Unenforced = append(p.Unenforced, "blockTPM (the container has no TPM device grant, but access through the TPM Base Services is not verified)")
	}
}

// execBlocked reports whether a blockExec entry is unreachable inside the
// container: an absolute path outside every grant and outside %SystemRoot%,
// or a bare name with no launchable match in any readable PATH directory. A
// bare name means "the program PATH would find", as on macOS (which blocks
// the name in /bin, /usr/bin and /usr/local/bin); a copy stored elsewhere can
// still be started by its full path.
func (p *Plan) execBlocked(entry string, env *EnvSet, systemRoot string, host Host, canon func(string) string) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return true
	}
	if entry == "*" {
		return false
	}
	readable := func(path string) bool {
		return WinHasPrefix(path, systemRoot) || coveredBy(path, p.WritePaths) || coveredBy(path, p.ReadPaths)
	}
	if strings.ContainsAny(entry, `\/:`) {
		if !WinIsAbs(entry) {
			// A POSIX path from a cross-platform policy names nothing here.
			return true
		}
		return !readable(canon(WinClean(entry)))
	}
	pathList, _ := env.Get("PATH")
	pathExt, _ := env.Get("PATHEXT")
	exts := launchableExtsFrom(pathExt)
	for _, dir := range SplitPathList(pathList) {
		if dir == "" || !WinIsAbs(dir) || !readable(canon(WinClean(dir))) {
			continue
		}
		base := WinJoin(dir, entry)
		cands := []string{}
		if isLaunchableExt(WinExt(base)) {
			cands = append(cands, base)
		}
		for _, e := range exts {
			cands = append(cands, base+e)
		}
		for _, c := range cands {
			if host.IsFile(c) {
				return false
			}
		}
	}
	return true
}
