package mxc

import (
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// testHost models a Windows machine with Node.js in Program Files, a tools
// directory on PATH and a project under C:\work\proj.
func testHost() Host {
	files := []string{
		`C:\Windows\system32\cmd.exe`,
		`C:\Windows\system32\curl.exe`,
		`C:\Program Files\nodejs\node.exe`,
		`C:\Program Files\nodejs\npm.cmd`,
		`C:\tools\bin\gcc.exe`,
		`C:\work\proj\package.json`,
		`C:\work\proj\tool.exe`,
		`C:\Users\u\.bashrc`,
	}
	dirs := []string{
		`C:\work\proj\node_modules`,
		`C:\work\proj\out`,
		`C:\work\data`,
		`C:\Users\u\.npm`,
		`C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`,
		`C:\Users\u\Documents\WindowsPowerShell`,
	}
	fileSet, existSet := map[string]bool{}, map[string]bool{}
	addAncestors := func(p string) {
		for d := WinDir(p); ; d = WinDir(d) {
			existSet[strings.ToLower(d)] = true
			if WinIsVolumeRoot(d) {
				break
			}
		}
	}
	for _, f := range files {
		fileSet[strings.ToLower(f)] = true
		existSet[strings.ToLower(f)] = true
		addAncestors(f)
	}
	for _, d := range dirs {
		existSet[strings.ToLower(d)] = true
		addAncestors(d)
	}
	return Host{
		Env: ParseEnviron([]string{
			`Path=C:\Windows\system32;C:\Program Files\nodejs;C:\tools\bin`,
			`PATHEXT=.COM;.EXE;.BAT;.CMD`,
			`SystemRoot=C:\Windows`,
			`LOCALAPPDATA=C:\Users\u\AppData\Local`,
			`APPDATA=C:\Users\u\AppData\Roaming`,
			`USERPROFILE=C:\Users\u`,
			`PROGRAMDATA=C:\ProgramData`,
		}),
		Cwd:    `C:\work\proj`,
		IsFile: func(p string) bool { return fileSet[strings.ToLower(WinClean(p))] },
		Exists: func(p string) bool { return existSet[strings.ToLower(WinClean(p))] },
		LookupIP: func(h string) ([]net.IP, error) {
			switch h {
			case "registry.npmjs.org":
				return []net.IP{net.ParseIP("104.16.1.34"), net.ParseIP("104.16.0.34"), net.ParseIP("2606:4700::6810:22")}, nil
			case "artifactory.corp":
				return []net.IP{net.ParseIP("10.20.30.40")}, nil
			case "localhost":
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return nil, errors.New("no such host")
		},
		NumCPU: 8,
	}
}

func mustTranslate(t *testing.T, cfg config.ExecConfig, opts Options) *Plan {
	t.Helper()
	p, err := Translate(cfg, testHost(), opts)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	// The request must always be valid JSON.
	if _, err := p.Request.Marshal(); err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return p
}

func hasSubstring(list []string, sub string) bool {
	return slices.ContainsFunc(list, func(s string) bool { return strings.Contains(s, sub) })
}

func TestTranslateBasicRequest(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "node", Args: []string{"-e", "console.log('a b')"}}, Options{})
	r := p.Request
	if r.Version != "1.0.0" || r.Containment != "processcontainer" {
		t.Fatalf("version/containment = %q/%q", r.Version, r.Containment)
	}
	if want := `"C:\Program Files\nodejs\node.exe" -e "console.log('a b')"`; r.Process.CommandLine != want {
		t.Errorf("commandLine = %s, want %s", r.Process.CommandLine, want)
	}
	if r.Process.Cwd != `C:\work\proj` || r.Process.InheritDefaultEnv {
		t.Errorf("cwd/inheritDefaultEnv = %q/%v", r.Process.Cwd, r.Process.InheritDefaultEnv)
	}
	if len(r.Process.Env) == 0 || len(MissingRequiredEnv(r.Process.Env)) != 0 {
		t.Errorf("env incomplete: %v", r.Process.Env)
	}
	if r.UI == nil || r.UI.Disable || r.UI.Clipboard != "none" || r.UI.Injection {
		t.Errorf("ui = %+v", r.UI)
	}
	if r.Telemetry == nil || r.Telemetry.Enabled {
		t.Error("telemetry must be explicitly disabled")
	}
	if r.Fallback == nil || r.Fallback.AllowDaclMutation {
		t.Error("DACL mutation must be refused by default")
	}
	if r.ProcessContainer != nil {
		t.Error("no capture requested")
	}
	// Unrestricted network by default (Linux parity), no inbound.
	if r.Network.Egress.Default != ActionAllow || r.Network.Ingress.Default != ActionDeny || r.Network.Ingress.HostLoopback != ActionDeny {
		t.Errorf("network = %+v", r.Network)
	}
	// Bootstrap grants: the program directory and the working directory.
	if !slices.Equal(p.ReadPaths, []string{`C:\Program Files\nodejs`, `C:\work\proj`}) {
		t.Errorf("read paths = %v", p.ReadPaths)
	}
	data, _ := r.Marshal()
	for _, forbidden := range []string{`"lxc"`, `"seatbelt"`, `"wslc"`, `"$schema"`} {
		if strings.Contains(string(data), forbidden) {
			t.Errorf("request contains %s: %s", forbidden, data)
		}
	}
}

func TestTranslateWin32kOptIn(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", WindowsBlockWin32k: true, WindowsAllowDaclMutation: true}, Options{})
	if !p.Request.UI.Disable || !p.Request.Fallback.AllowDaclMutation {
		t.Errorf("ui/fallback = %+v / %+v", p.Request.UI, p.Request.Fallback)
	}
}

func TestTranslateCmdExeTakesCommandVerbatim(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd.exe", Args: []string{"/c", `echo hi> "out file.txt"`}}, Options{})
	if want := `"C:\Windows\system32\cmd.exe" /c echo hi> "out file.txt"`; p.Request.Process.CommandLine != want {
		t.Errorf("commandLine = %s, want %s", p.Request.Process.CommandLine, want)
	}
}

func TestTranslateSystemProgramNeedsNoGrant(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", WorkingDir: `C:\work\proj`, WritePaths: []string{`C:\work\proj`}}, Options{})
	if len(p.ReadPaths) != 0 {
		t.Errorf("unexpected read grants %v", p.ReadPaths)
	}
	if !slices.Equal(p.WritePaths, []string{`C:\work\proj`}) {
		t.Errorf("write grants %v", p.WritePaths)
	}
}

func TestTranslateBatchUsesHostCmd(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "npm",
		Args: []string{"install", "x&calc"},
		// A caller-supplied SYSTEMROOT must not redirect the interpreter.
		Env: map[string]string{"SYSTEMROOT": `C:\evil`},
	}
	p := mustTranslate(t, cfg, Options{})
	if !p.IsBatch || !strings.EqualFold(p.Program, `C:\Program Files\nodejs\npm.cmd`) {
		t.Fatalf("program = %q batch=%v", p.Program, p.IsBatch)
	}
	want := `"C:\Windows\System32\cmd.exe" /d /e:ON /v:OFF /c ""C:\Program Files\nodejs\npm.cmd" install "x&calc""`
	if p.Request.Process.CommandLine != want {
		t.Errorf("commandLine\n got %s\nwant %s", p.Request.Process.CommandLine, want)
	}
}

func TestTranslateFilesystem(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:        "node",
		WorkingDir: `C:\work\proj`,
		WritePaths: []string{`C:\work\proj\node_modules`, `out`, `~/.npm`, `/tmp`, `C:\work\proj\missing`},
		ReadPaths: []string{
			`C:\work\proj\package.json`, `c:\WORK\proj\node_modules\`, `/etc/ssl/certs`, `C:\work\*.json`,
			`\\.\PhysicalDrive0`, `C:\work\proj\package.json:secret`, `D:relative`, `C:\work\data`,
		},
	}
	p := mustTranslate(t, cfg, Options{})
	wantW := []string{`C:\work\proj\node_modules`, `C:\work\proj\out`, `C:\Users\u\.npm`}
	if !slices.Equal(p.WritePaths, wantW) {
		t.Errorf("write = %v, want %v", p.WritePaths, wantW)
	}
	// node_modules is written, so its read entry is dropped (identical ro/rw
	// pairs resolve to read-only in MXC).
	wantR := []string{`C:\work\proj\package.json`, `C:\work\data`, `C:\Program Files\nodejs`, `C:\work\proj`}
	if !slices.Equal(p.ReadPaths, wantR) {
		t.Errorf("read = %v, want %v", p.ReadPaths, wantR)
	}
	for _, s := range []string{"/tmp", "/etc/ssl/certs", `C:\work\*.json`, "PhysicalDrive0", ":secret", "D:relative", "missing"} {
		if !hasSubstring(p.Skipped, s) {
			t.Errorf("%s not reported as skipped: %v", s, p.Skipped)
		}
	}
}

func TestTranslateVolumeRootWarning(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", ReadPaths: []string{`C:\`}}, Options{})
	if !hasSubstring(p.Warnings, `volume root C:\`) {
		t.Errorf("warnings = %v", p.Warnings)
	}
	// A volume-root grant does not cover the working directory.
	if !slices.Contains(p.ReadPaths, `C:\work\proj`) {
		t.Errorf("cwd not granted: %v", p.ReadPaths)
	}
}

func TestTranslateDenyPersistenceWrites(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:                   "cmd",
		WritePaths:            []string{`C:\Users\u`},
		DenyPersistenceWrites: true,
	}
	p := mustTranslate(t, cfg, Options{})
	fs := p.Request.Filesystem
	for _, d := range []string{`C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, `C:\Users\u\Documents\WindowsPowerShell`, `C:\Users\u\.bashrc`} {
		if !slices.Contains(fs.DeniedPaths, d) {
			t.Errorf("%s not denied: %v", d, fs.DeniedPaths)
		}
	}
	for _, d := range fs.DeniedPaths {
		if strings.HasPrefix(d, `C:\ProgramData`) {
			t.Errorf("%s denied without a covering write grant", d)
		}
	}
	// An explicitly granted persistence path stays writable.
	cfg.WritePaths = append(cfg.WritePaths, `C:\Users\u\Documents\WindowsPowerShell`)
	p = mustTranslate(t, cfg, Options{})
	if slices.Contains(p.Request.Filesystem.DeniedPaths, `C:\Users\u\Documents\WindowsPowerShell`) {
		t.Error("explicit write grant was denied")
	}
	cfg.DenyPersistenceWrites = false
	if p = mustTranslate(t, cfg, Options{}); len(p.Request.Filesystem.DeniedPaths) != 0 {
		t.Errorf("denies without the flag: %v", p.Request.Filesystem.DeniedPaths)
	}
}

func TestTranslateNetworkDisabled(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", DisableNetwork: true, AllowHosts: []string{"registry.npmjs.org"}}, Options{ProxyPort: 0})
	n := p.Request.Network
	if n.Egress.Default != ActionDeny || len(n.Egress.Allow) != 0 || n.Ingress.Default != ActionDeny || n.Ingress.HostLoopback != ActionDeny {
		t.Errorf("network = %+v", n)
	}
	if p.Request.RuntimeConfig != nil {
		t.Error("proxy configured with network disabled")
	}
}

func TestTranslateNetworkProxy(t *testing.T) {
	proxyEnv := map[string]string{"HTTPS_PROXY": "http://127.0.0.1:4100", "HTTP_PROXY": "http://127.0.0.1:4100"}
	cfg := config.ExecConfig{
		Cmd: "cmd", ProxyEgress: true, AllowHosts: []string{"registry.npmjs.org"}, AllowLoopback: true,
		AllowURLRules: []config.AllowURLRule{{Host: "registry.npmjs.org", PathPrefix: "/npm/"}},
		Env:           map[string]string{"HTTPS_PROXY": "http://elsewhere:1"},
	}
	p := mustTranslate(t, cfg, Options{ProxyPort: 4100, ProxyEnv: proxyEnv})
	n := p.Request.Network
	if n.Egress.Default != ActionDeny || len(n.Egress.Allow) != 0 {
		t.Errorf("proxy egress = %+v", n.Egress)
	}
	if n.Ingress.Default != ActionAllow || n.Ingress.HostLoopback != ActionAllow {
		t.Errorf("proxy ingress = %+v", n.Ingress)
	}
	if p.Request.RuntimeConfig == nil || p.Request.RuntimeConfig.NetworkProxy != "http://127.0.0.1:4100" {
		t.Errorf("runtimeConfig = %+v", p.Request.RuntimeConfig)
	}
	if v, _ := ParseEnviron(p.Request.Process.Env).Get("https_proxy"); v != "http://127.0.0.1:4100" {
		t.Errorf("HTTPS_PROXY = %q", v)
	}
	if !hasSubstring(p.Warnings, "allowLoopback") || !hasSubstring(p.Unenforced, "allowURLRules") {
		t.Errorf("warnings %v unenforced %v", p.Warnings, p.Unenforced)
	}
}

func TestTranslateNetworkPinnedHosts(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", AllowHosts: []string{"registry.npmjs.org", "*.npmjs.com", "nope.invalid"}}, Options{})
	e := p.Request.Network.Egress
	if e.Default != ActionDeny || len(e.Allow) != 1 {
		t.Fatalf("egress = %+v", e)
	}
	var cidrs []string
	for _, peer := range e.Allow[0].To {
		cidrs = append(cidrs, peer.CIDR)
	}
	want := []string{"104.16.0.34/32", "104.16.1.34/32", "2606:4700::6810:22/128"}
	if !slices.Equal(cidrs, want) {
		t.Errorf("peers = %v, want %v", cidrs, want)
	}
	if got := e.Allow[0].Ports; len(got) != 2 || got[0].Port != 80 || got[1].Port != 443 || got[0].Protocol != "tcp" {
		t.Errorf("ports = %+v", got)
	}
	if !hasSubstring(p.Warnings, "*.npmjs.com") || !hasSubstring(p.Warnings, "nope.invalid") {
		t.Errorf("warnings = %v", p.Warnings)
	}
	if p.Request.Network.Ingress.Default != ActionDeny {
		t.Error("public destinations must not open ingress")
	}
}

func TestTranslateNetworkPorts(t *testing.T) {
	// Ports only: any destination on those ports.
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", AllowPorts: []int{443, 8443, 443, 70000}}, Options{})
	e := p.Request.Network.Egress
	if e.Default != ActionDeny || len(e.Allow) != 1 || e.Allow[0].To != nil || len(e.Allow[0].Ports) != 2 {
		t.Errorf("egress = %+v", e)
	}
	if !hasSubstring(p.Warnings, "70000") {
		t.Errorf("invalid port not reported: %v", p.Warnings)
	}
	// Port 0 means any port.
	p = mustTranslate(t, config.ExecConfig{Cmd: "cmd", AllowIPs: []string{"203.0.113.0/24"}, AllowPorts: []int{0}}, Options{})
	e = p.Request.Network.Egress
	if len(e.Allow) != 1 || e.Allow[0].Ports != nil || e.Allow[0].To[0].CIDR != "203.0.113.0/24" {
		t.Errorf("egress = %+v", e)
	}
	// "*" host with default ports.
	p = mustTranslate(t, config.ExecConfig{Cmd: "cmd", AllowHosts: []string{"*"}}, Options{})
	e = p.Request.Network.Egress
	if len(e.Allow) != 1 || e.Allow[0].To != nil || len(e.Allow[0].Ports) != 2 {
		t.Errorf("wildcard egress = %+v", e)
	}
}

func TestTranslateNetworkPrivateAndLoopback(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", AllowHosts: []string{"artifactory.corp", "localhost"}}, Options{HostLoopbackSupported: true})
	n := p.Request.Network
	if n.Ingress.Default != ActionAllow || n.Ingress.HostLoopback != ActionAllow {
		t.Errorf("ingress = %+v", n.Ingress)
	}
	if len(n.Egress.Allow) != 1 || len(n.Egress.Allow[0].To) != 1 || n.Egress.Allow[0].To[0].CIDR != "10.20.30.40/32" {
		t.Errorf("egress = %+v", n.Egress)
	}
	if !hasSubstring(p.Warnings, "privateNetworkClientServer") {
		t.Errorf("warnings = %v", p.Warnings)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "cmd", AllowLoopback: true}, Options{HostLoopbackSupported: false})
	if p.Request.Network.Ingress.HostLoopback != ActionDeny || !hasSubstring(p.Warnings, "host loopback") {
		t.Errorf("unsupported loopback: %+v %v", p.Request.Network.Ingress, p.Warnings)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "cmd", AllowListen: []string{"127.0.0.1:3000"}}, Options{})
	if p.Request.Network.Ingress.Default != ActionAllow {
		t.Error("allowListen did not open ingress")
	}
}

func TestTranslateLimits(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "node", MaxMemoryMB: 512, MaxCPUCores: 2, MaxProcesses: 10}, Options{})
	if p.Limits.MemoryBytes != 512<<20+launcherMemoryHeadroom {
		t.Errorf("memory = %d", p.Limits.MemoryBytes)
	}
	if p.Limits.CPURate != 2500 {
		t.Errorf("cpu rate = %d, want 2500 (2 of 8 cores)", p.Limits.CPURate)
	}
	if p.Limits.ActiveProcesses != 11 {
		t.Errorf("processes = %d, want 10 + launcher", p.Limits.ActiveProcesses)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "node", MaxCPUCores: 16}, Options{})
	if p.Limits.CPURate != 0 {
		t.Errorf("cpu rate %d for more cores than the host has", p.Limits.CPURate)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "node", MaxCPUCores: 0.0001}, Options{})
	if p.Limits.CPURate != 1 {
		t.Errorf("cpu rate floor = %d", p.Limits.CPURate)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "node", BlockFork: true}, Options{})
	if p.Limits.ActiveProcesses != 2 {
		t.Errorf("blockFork processes = %d, want workload + launcher", p.Limits.ActiveProcesses)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "npm", BlockFork: true, MaxProcesses: 50}, Options{})
	if p.Limits.ActiveProcesses != 4 {
		t.Errorf("batch blockFork processes = %d, want 1 + 2 shim + launcher", p.Limits.ActiveProcesses)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "node", MaxReadIOPS: 100}, Options{})
	if !hasSubstring(p.Unenforced, "I/O rate") {
		t.Errorf("unenforced = %v", p.Unenforced)
	}
}

func TestTranslateExecControls(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:        "node",
		WorkingDir: `C:\work\proj`,
		// gcc lives in C:\tools\bin (ungranted); curl in System32 (readable);
		// tool.exe in the granted project dir; the POSIX entry names nothing.
		BlockExec: []string{"gcc", "curl", `C:\work\proj\tool.exe`, `C:\tools\bin\gcc.exe`, "/usr/bin/make"},
	}
	p := mustTranslate(t, cfg, Options{})
	if len(p.Unenforced) != 1 {
		t.Fatalf("unenforced = %v", p.Unenforced)
	}
	u := p.Unenforced[0]
	for _, open := range []string{"curl", `C:\work\proj\tool.exe`} {
		if !strings.Contains(u, open) {
			t.Errorf("%s should be reported as reachable: %s", open, u)
		}
	}
	for _, closed := range []string{"gcc,", `C:\tools\bin\gcc.exe`, "make"} {
		if strings.Contains(u, closed) {
			t.Errorf("%s is unreachable and should not be reported: %s", closed, u)
		}
	}
	cfg.BlockExec = []string{"*"}
	if p = mustTranslate(t, cfg, Options{}); !hasSubstring(p.Unenforced, "blockExec for *") {
		t.Errorf("wildcard without blockFork: %v", p.Unenforced)
	}
	cfg.BlockFork = true
	cfg.AllowExec = []string{"node"}
	if p = mustTranslate(t, cfg, Options{}); len(p.Unenforced) != 0 {
		t.Errorf("blockFork should enforce exec controls: %v", p.Unenforced)
	}
	cfg.BlockFork = false
	if p = mustTranslate(t, cfg, Options{}); !hasSubstring(p.Unenforced, "allowExec") {
		t.Errorf("allowExec: %v", p.Unenforced)
	}
}

func TestTranslateUnsupportedControls(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd: "cmd", BlockJIT: true, BlockCrypto: true, TraceCrypto: true, TraceLibraries: true,
		SeccompFilters: []config.SeccompFilterSpec{{Policy: "DEFAULT KILL"}}, TmpOverlayPaths: []string{`C:\x`},
		BindFds: []config.BindFdSpec{{Fd: 3, Target: "/x"}}, SpoofAntiVM: true, BlockTPM: true,
		// Linux/macOS-only knobs are ignored without noise.
		ProtectSystem: "strict", ProtectHome: "tmpfs", PrivateTmp: true, UseReaper: true, BlockInterpreters: true,
	}
	p := mustTranslate(t, cfg, Options{})
	for _, s := range []string{"blockJIT", "blockCrypto", "seccompFilters"} {
		if !hasSubstring(p.Unenforced, s) {
			t.Errorf("%s not reported unenforced: %v", s, p.Unenforced)
		}
	}
	for _, s := range []string{"eBPF", "traceLibraries", "tmpOverlayPaths", "bindFds", "spoofAntiVM", "blockTPM"} {
		if !hasSubstring(p.Warnings, s) {
			t.Errorf("%s not warned: %v", s, p.Warnings)
		}
	}
	for _, s := range []string{"protectSystem", "protectHome", "privateTmp", "useReaper", "blockInterpreters"} {
		if hasSubstring(p.Warnings, s) || hasSubstring(p.Unenforced, s) {
			t.Errorf("%s should be silent", s)
		}
	}
}

func TestTranslateCaptureModes(t *testing.T) {
	out := `C:\run\denials.json`
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", EnableAudit: true}, Options{CaptureOutputPath: out})
	if c := p.Request.ProcessContainer.CaptureDenials; c.Mode != CaptureBlock || c.OutputPath != out || c.RetainEtl {
		t.Errorf("audit capture = %+v", c)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "cmd", WritePaths: []string{`C:\work\proj\out`}}, Options{Mode: ModeLearn, CaptureOutputPath: out, ProxyPort: 4100})
	if c := p.Request.ProcessContainer.CaptureDenials; c.Mode != CaptureBlock {
		t.Errorf("learning must stay contained, capture = %+v", c)
	}
	if !hasSubstring(p.Warnings, "learning on Windows runs contained") {
		t.Errorf("warnings = %v", p.Warnings)
	}
	if p.Request.RuntimeConfig == nil {
		t.Error("learning should route through the recording proxy")
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "cmd", WritePaths: []string{`C:\work\proj\out`}, ReadPaths: []string{`C:\work\data`}, ProxyEgress: true},
		Options{Mode: ModeDryRun, CaptureOutputPath: out, ProxyPort: 4100})
	if len(p.WritePaths) != 0 || slices.Contains(p.ReadPaths, `C:\work\data`) {
		t.Errorf("dry-run grants: rw=%v ro=%v", p.WritePaths, p.ReadPaths)
	}
	if p.Request.Network.Egress.Default != ActionDeny || p.Request.RuntimeConfig != nil {
		t.Errorf("dry-run network = %+v", p.Request.Network)
	}
	if _, ok := ParseEnviron(p.Request.Process.Env).Get("HTTPS_PROXY"); ok {
		t.Error("dry-run must not receive proxy variables")
	}
	if _, err := Translate(config.ExecConfig{Cmd: "cmd", EnableAudit: true}, testHost(), Options{}); err == nil {
		t.Error("audit without a capture path accepted")
	}
}

func TestTranslateTimeout(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", TimeoutMs: 1500}, Options{})
	if p.Request.Process.Timeout != 1500 {
		t.Errorf("timeout = %d", p.Request.Process.Timeout)
	}
	p = mustTranslate(t, config.ExecConfig{Cmd: "cmd", TimeoutMs: 1 << 40}, Options{})
	if p.Request.Process.Timeout != 1<<32-1 {
		t.Errorf("timeout not clamped: %d", p.Request.Process.Timeout)
	}
}

func TestTranslateErrors(t *testing.T) {
	host := testHost()
	if _, err := Translate(config.ExecConfig{Cmd: "missing-tool"}, host, Options{}); err == nil {
		t.Error("unknown command accepted")
	}
	if _, err := Translate(config.ExecConfig{Cmd: "cmd", WorkingDir: "relative"}, host, Options{}); err == nil {
		t.Error("relative working dir accepted")
	}
	noLocal := testHost()
	noLocal.Env.Delete("LOCALAPPDATA")
	if _, err := Translate(config.ExecConfig{Cmd: "cmd"}, noLocal, Options{}); err == nil || !strings.Contains(err.Error(), "LOCALAPPDATA") {
		t.Errorf("missing LOCALAPPDATA: %v", err)
	}
	if _, err := Translate(config.ExecConfig{Cmd: "npm", Args: []string{"a\nb"}}, host, Options{}); err == nil {
		t.Error("newline in batch argument accepted")
	}
}

func TestTranslateDroppedEnvWarning(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", Env: map[string]string{"COR_PROFILER": "x"}}, Options{})
	if !slices.Equal(p.DroppedEnv, []string{"COR_PROFILER"}) || !hasSubstring(p.Warnings, "COR_PROFILER") {
		t.Errorf("dropped %v warnings %v", p.DroppedEnv, p.Warnings)
	}
}

func TestRequestJSONShape(t *testing.T) {
	p := mustTranslate(t, config.ExecConfig{Cmd: "cmd", EnableAudit: true, AllowHosts: []string{"registry.npmjs.org"}}, Options{CaptureOutputPath: `C:\r\d.json`})
	data, _ := p.Request.Marshal()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"version": true, "containment": true, "process": true, "filesystem": true, "network": true,
		"runtimeConfig": true, "ui": true, "telemetry": true, "fallback": true, "processContainer": true}
	for k := range m {
		if !allowed[k] {
			t.Errorf("unexpected top-level key %q", k)
		}
	}
	pc := m["processContainer"].(map[string]any)["captureDenials"].(map[string]any)
	if pc["retainEtl"] != false || pc["mode"] != "block" {
		t.Errorf("captureDenials = %v", pc)
	}
}
