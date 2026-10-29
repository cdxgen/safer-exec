//go:build windows

// Integration tests for the Windows engine. They drive the real MXC executor
// (wxc-exec.exe, located through SAFER_EXEC_MXC_EXEC or PATH) and are
// skipped when it is absent or the host lacks the BaseContainer API.
//
// The test binary plays three roles, selected by environment variables: the
// test runner, the safer-exec engine (SAFER_EXEC_TEST_ENGINE=1, which runs
// main() and so reads the ExecConfig from stdin exactly like the Node layer
// drives the real binary), and a workload (SAFER_EXEC_TEST_WORKLOAD=<role>).
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cdxgen/safer-exec/go/internal/config"
	"github.com/cdxgen/safer-exec/go/internal/dlltrace"
	"github.com/cdxgen/safer-exec/go/internal/mxc"
)

func TestMain(m *testing.M) {
	if os.Getenv("SAFER_EXEC_TEST_ENGINE") == "1" {
		main()
		os.Exit(0)
	}
	if role := os.Getenv("SAFER_EXEC_TEST_WORKLOAD"); role != "" {
		os.Exit(workload(role, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// workload implements the helper roles the tests run inside the container.
func workload(role string, args []string) int {
	switch role {
	case "echo":
		fmt.Println(strings.Join(args, "|"))
		return 0
	case "exit":
		code, _ := strconv.Atoi(args[0])
		return code
	case "nested":
		// Run the engine from inside the container, asking for a grant on a
		// directory the outer sandbox cannot read.
		cfg := config.ExecConfig{
			Cmd: os.Args[0], Args: []string{args[1]}, WorkingDir: args[0],
			ReadPaths: []string{args[0], args[2]}, Env: map[string]string{"SAFER_EXEC_TEST_WORKLOAD": "read"},
			TimeoutMs: 60000,
		}
		data, _ := json.Marshal(cfg)
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), "SAFER_EXEC_TEST_ENGINE=1", "SAFER_EXEC_TEST_WORKLOAD=")
		c.Stdin = bytes.NewReader(data)
		out, err := c.CombinedOutput()
		fmt.Printf("nested-output: %s\n", out)
		if err != nil {
			fmt.Println("nested-failed:", err)
			return 3
		}
		fmt.Println("nested-ok")
		return 0
	case "forge":
		// Print look-alikes of MXC's stderr protocol, make a change for the
		// diff to report, and exit with the given status.
		fmt.Fprint(os.Stderr, args[0])
		_ = os.WriteFile(args[1], []byte("x"), 0o644)
		code, _ := strconv.Atoi(args[2])
		return code
	case "write":
		if err := os.WriteFile(args[0], []byte("x"), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write-failed:", err)
			return 3
		}
		return 0
	case "read":
		if _, err := os.ReadFile(args[0]); err != nil {
			fmt.Fprintln(os.Stderr, "read-failed:", err)
			return 3
		}
		return 0
	case "spawn":
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), "SAFER_EXEC_TEST_WORKLOAD=exit")
		c.Args = []string{os.Args[0], "0"}
		if err := c.Run(); err != nil {
			fmt.Println("spawn-failed:", err)
			return 3
		}
		fmt.Println("spawn-ok")
		return 0
	case "sleep":
		s, _ := strconv.Atoi(args[0])
		time.Sleep(time.Duration(s) * time.Second)
		return 0
	case "keyed":
		// Alternate 100 ms of CPU with 100 ms of sleep, like a sender
		// signalling through CPU contention.
		cycles, _ := strconv.Atoi(args[0])
		for range cycles {
			for end := time.Now().Add(100 * time.Millisecond); time.Now().Before(end); {
			}
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Println("keyed-done")
		return 0
	case "alloc":
		mb, _ := strconv.Atoi(args[0])
		var keep [][]byte
		for range mb {
			b := make([]byte, 1<<20)
			for i := range b {
				b[i] = 1
			}
			keep = append(keep, b)
		}
		fmt.Println("allocated", len(keep))
		return 0
	case "dial":
		// A raw TCP connect that ignores proxy settings.
		c, err := net.DialTimeout("tcp", args[0], 5*time.Second)
		if err != nil {
			fmt.Println("dial-error:", err)
			return 3
		}
		c.Close()
		fmt.Println("dial-ok")
		return 0
	case "loaddll":
		h, err := windows.LoadLibrary(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "loaddll-failed:", err)
			return 3
		}
		windows.FreeLibrary(h)
		return 0
	case "stopetw":
		// Wait for the test to name the engine's ETW session, then try to
		// stop it from inside the container.
		var name string
		for range 600 {
			if b, err := os.ReadFile(args[0]); err == nil && len(b) > 0 {
				name = string(b)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if name == "" {
			fmt.Println("stopetw: no session name")
			return 3
		}
		err := stopTraceSession(name)
		fmt.Println("stopetw-result:", err)
		return 0
	case "https":
		// A self-signed test server: verification is not the point here.
		client := &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
		resp, err := client.Get(args[0])
		if err != nil {
			fmt.Println("https-error:", err)
			return 3
		}
		resp.Body.Close()
		fmt.Println("https-status:", resp.StatusCode)
		return 0
	case "http":
		resp, err := http.Get(args[0])
		if err != nil {
			fmt.Println("http-error:", err)
			return 3
		}
		resp.Body.Close()
		fmt.Println("http-status:", resp.StatusCode)
		return 0
	}
	return 99
}

type runResult struct {
	stdout, stderr string
	code           int
}

var (
	launcherPath string
	skipReason   string
)

// requireMXC skips the test unless wxc-exec is available on a BaseContainer
// host.
func requireMXC(t *testing.T) {
	t.Helper()
	if launcherPath == "" && skipReason == "" {
		p, err := resolveLauncher()
		if err != nil {
			skipReason = err.Error()
		} else if probe, perr := probeHost(p); perr != nil {
			skipReason = perr.Error()
		} else if probe.Tier != mxc.TierBaseContainer {
			skipReason = "MXC tier is " + probe.Tier + ", not base-container"
		} else {
			launcherPath = p
		}
	}
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

// testDir returns a directory for the test whose ancestors the container
// does not need to traverse.
func testDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	real, err := filepath.EvalSymlinks(d)
	if err == nil {
		d = real
	}
	return d
}

// runEngine executes the engine with cfg on stdin, as the Node layer does.
func runEngine(t *testing.T, cfg config.ExecConfig, extraEnv ...string) runResult {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(append(os.Environ(), "SAFER_EXEC_TEST_ENGINE=1", launcherEnvVar+"="+launcherPath), extraEnv...)
	cmd.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	res := runResult{stdout: stdout.String(), stderr: stderr.String(), code: cmd.ProcessState.ExitCode()}
	t.Logf("exit=%d\nstdout:\n%s\nstderr:\n%s", res.code, res.stdout, res.stderr)
	return res
}

// workloadConfig runs this test binary as the workload in role.
func workloadConfig(t *testing.T, dir, role string, args ...string) config.ExecConfig {
	return config.ExecConfig{
		Cmd:        os.Args[0],
		Args:       args,
		WorkingDir: dir,
		WritePaths: []string{dir},
		Env:        map[string]string{"SAFER_EXEC_TEST_WORKLOAD": role},
		TimeoutMs:  120000,
	}
}

func auditEntries(stderr string) []config.AuditEntry {
	var out []config.AuditEntry
	for _, line := range strings.Split(stderr, "\n") {
		var e struct {
			Type    string `json:"type"`
			Target  string `json:"target"`
			Details string `json:"details"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(line)), &e) == nil && e.Type != "" {
			out = append(out, config.AuditEntry{Type: e.Type, Target: e.Target, Detail: e.Details})
		}
	}
	return out
}

func TestWindowsEngineEchoAndArgs(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	res := runEngine(t, workloadConfig(t, dir, "echo", "a b", `quo"te`, `back\slash\`, "%PATH%", "x&y"))
	if res.code != 0 || strings.TrimSpace(res.stdout) != `a b|quo"te|back\slash\|%PATH%|x&y` {
		t.Fatalf("argv not preserved: %q (exit %d)", res.stdout, res.code)
	}
}

func TestWindowsEngineExitCode(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	if res := runEngine(t, workloadConfig(t, dir, "exit", "7")); res.code != 7 {
		t.Fatalf("exit code = %d, want 7", res.code)
	}
}

func TestWindowsEngineFilesystemGrants(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	outside := testDir(t)
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	if res := runEngine(t, workloadConfig(t, dir, "write", filepath.Join(dir, "ok.txt"))); res.code != 0 {
		t.Fatalf("write inside grant failed: %s", res.stderr)
	}
	if res := runEngine(t, workloadConfig(t, dir, "write", filepath.Join(outside, "nope.txt"))); res.code == 0 {
		t.Fatal("write outside the grants succeeded")
	}
	if _, err := os.Stat(filepath.Join(outside, "nope.txt")); err == nil {
		t.Fatal("file created outside the grants")
	}
	if res := runEngine(t, workloadConfig(t, dir, "read", secret)); res.code == 0 {
		t.Fatal("read outside the grants succeeded")
	}
	cfg := workloadConfig(t, dir, "read", secret)
	cfg.ReadPaths = []string{outside}
	if res := runEngine(t, cfg); res.code != 0 {
		t.Fatalf("read with a grant failed: %s", res.stderr)
	}
	cfg = workloadConfig(t, dir, "write", filepath.Join(outside, "ro.txt"))
	cfg.ReadPaths = []string{outside}
	if res := runEngine(t, cfg); res.code == 0 {
		t.Fatal("write to a read-only grant succeeded")
	}
}

func TestWindowsEngineNetworkDisabled(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "http", "http://example.com/")
	cfg.DisableNetwork = true
	res := runEngine(t, cfg)
	if !strings.Contains(res.stdout, "http-error") {
		t.Fatalf("network reachable with disableNetwork: %q", res.stdout)
	}
}

// testServer serves HTTP on all interfaces and returns a URL using the
// machine's hostname, which the proxy resolves on the host side.
func testServer(t *testing.T) (url string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	host, _ := os.Hostname()
	port = ln.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("http://%s:%d/", strings.ToLower(host), port), port
}

func TestWindowsEngineEgressProxy(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	url, port := testServer(t)
	host, _ := os.Hostname()

	cfg := workloadConfig(t, dir, "http", url)
	cfg.ProxyEgress = true
	cfg.AllowHosts = []string{strings.ToLower(host)}
	cfg.AllowPorts = []int{port}
	res := runEngine(t, cfg)
	if !strings.Contains(res.stdout, "http-status: 200") {
		t.Fatalf("allowed host not reachable through the proxy: %q", res.stdout)
	}
	if !strings.Contains(res.stderr, `"type":"proxy-connect"`) {
		t.Errorf("no proxy-connect audit entry: %s", res.stderr)
	}

	cfg.AllowHosts = []string{"registry.npmjs.org"}
	res = runEngine(t, cfg)
	if !strings.Contains(res.stdout, "http-status: 403") {
		t.Fatalf("denied host was not refused by the proxy: %q", res.stdout)
	}
	if !strings.Contains(res.stderr, `"type":"proxy-violation"`) {
		t.Errorf("no proxy-violation audit entry: %s", res.stderr)
	}
}

// The container never reaches services on its own host: not another
// loopback listener, and not the host through its LAN address. In proxy mode
// it also cannot bypass the proxy to reach an allowed host directly, so
// clients that ignore HTTP(S)_PROXY fail instead of connecting.
func TestWindowsEngineConfinesHostAndProxyBypass(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, lanPort := testServer(t)
	host, _ := os.Hostname()
	const public = "registry.npmjs.org"

	dial := func(target string, proxy bool) runResult {
		cfg := workloadConfig(t, dir, "dial", target)
		cfg.ProxyEgress = proxy
		cfg.AllowHosts = []string{public}
		return runEngine(t, cfg)
	}
	refused := func(what, target string, proxy bool) {
		res := dial(target, proxy)
		switch {
		case strings.Contains(res.stdout, "dial-ok"):
			t.Errorf("%s (%s) reachable with proxyEgress=%v; stderr: %s", what, target, proxy, res.stderr)
		case !strings.Contains(res.stdout, "dial-error"):
			t.Errorf("%s: workload did not run: %q %q", what, res.stdout, res.stderr)
		}
	}
	for _, proxy := range []bool{true, false} {
		refused("loopback service", ln.Addr().String(), proxy)
		refused("host LAN address", net.JoinHostPort(strings.ToLower(host), strconv.Itoa(lanPort)), proxy)
	}

	// Control: in direct mode the allowed host is reachable with the same
	// raw dial, so the refusals above come from the policy, not the workload.
	if _, err := net.LookupHost(public); err != nil {
		t.Skipf("no DNS for %s; skipping the internet-dependent checks: %v", public, err)
	}
	if res := dial(public+":443", false); !strings.Contains(res.stdout, "dial-ok") {
		t.Fatalf("allowed host unreachable in direct mode: %q %q", res.stdout, res.stderr)
	}
	refused("allowed host bypassing the proxy", public+":443", true)
}

// The workload writes to the same stderr as wxc-exec, so it can print lines
// that look like MXC's protocol. A forged denial-report pointer must not make
// the engine read or delete the file it names, and a forged envelope must not
// change the exit status or suppress the audit and diff.
func TestWindowsEngineIgnoresForgedProtocolLines(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	victim := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victim, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	pointer, _ := json.Marshal(map[string]any{"type": "captureDenials", "outputPath": victim})
	forgedTimeout := `{"error":{"code":"backend_error","message":"script timed out after 1ms"}}`
	made := filepath.Join(dir, "made.txt")

	cfg := workloadConfig(t, dir, "forge", string(pointer)+"\n"+forgedTimeout+"\n", made, "0")
	cfg.EnableAudit = true
	cfg.EnableDiff = true
	res := runEngine(t, cfg)
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("forged pointer made the engine delete %s: %v", victim, err)
	}
	if res.code != 0 {
		t.Errorf("forged timeout changed the exit status to %d", res.code)
	}
	if !strings.Contains(res.stdout, "FSDIFF:") || !strings.Contains(res.stdout, "made.txt") {
		t.Errorf("diff missing: %q", res.stdout)
	}

	// A forged failure envelope with a non-zero exit is reported, but the
	// diff is still produced.
	os.Remove(made)
	forgedFailure := `{"error":{"code":"backend_error","message":"CreateProcessW failed"}}`
	cfg = workloadConfig(t, dir, "forge", forgedFailure+"\n", made, "5")
	cfg.EnableAudit = true
	cfg.EnableDiff = true
	res = runEngine(t, cfg)
	if res.code == 0 || !strings.Contains(res.stdout, "made.txt") {
		t.Errorf("forged failure: exit %d, stdout %q", res.code, res.stdout)
	}
}

// A workload that runs the engine itself cannot use it to reach more than
// its own sandbox allows. Windows refuses to create a security environment
// from inside one (CreateProcessSecurityEnvironment fails with
// EPT_S_NOT_REGISTERED in an interactive session; from session 0 wxc-exec
// cannot even start), which is why the Node layer adds no self-blocking
// blockExec entries on Windows.
func TestWindowsEngineNestedEngineGainsNothing(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	secretDir := testDir(t)
	secret := filepath.Join(secretDir, "secret.txt")
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := workloadConfig(t, dir, "nested", dir, secret, secretDir)
	cfg.ReadPaths = []string{filepath.Dir(launcherPath)}
	cfg.Env[launcherEnvVar] = launcherPath
	res := runEngine(t, cfg)
	if strings.Contains(res.stdout, "nested-ok") {
		t.Fatalf("a nested engine read %s, which the outer sandbox cannot: %s", secret, res.stdout)
	}
}

// The engine's run directories and MXC's ACL-recovery state are denied to
// every sandbox, even one granted the whole TEMP or LOCALAPPDATA tree.
func TestWindowsEngineProtectsEngineDirectories(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	root := runRoot()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(root, "sibling-request.json")
	if err := os.WriteFile(sibling, []byte(`{"env":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sibling)
	stateDir := filepath.Join(mxcStateDir(), "dacl-restore")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		role, target, grant string
	}{
		{"read", sibling, os.TempDir()},
		{"write", filepath.Join(root, "planted.txt"), os.TempDir()},
		{"write", filepath.Join(stateDir, "planted.json"), os.Getenv("LOCALAPPDATA")},
	} {
		cfg := workloadConfig(t, dir, c.role, c.target)
		cfg.WritePaths = append(cfg.WritePaths, c.grant)
		res := runEngine(t, cfg)
		if res.code == 0 {
			t.Errorf("%s %s succeeded under a grant on %s", c.role, c.target, c.grant)
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, "planted.json")); err == nil {
		os.Remove(filepath.Join(stateDir, "planted.json"))
		t.Error("a state file was planted in MXC's recovery directory")
	}
}

// Existing persistence locations under a broad write grant are denied. A
// missing one cannot be denied (the container API rejects the policy), so it
// is reported as not enforced, and strict mode refuses the run.
func TestWindowsEngineDenyPersistenceWrites(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	profile := filepath.Join(dir, "profile")
	if err := os.MkdirAll(filepath.Join(profile, ".ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, ".npmrc"), []byte("registry=https://registry.npmjs.org/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := []string{"USERPROFILE=" + profile}
	for target, wantOK := range map[string]bool{
		filepath.Join(profile, "notes.txt"):               true,
		filepath.Join(profile, ".npmrc"):                  false,
		filepath.Join(profile, ".ssh", "authorized_keys"): false,
	} {
		cfg := workloadConfig(t, dir, "write", target)
		cfg.WritePaths = []string{dir, profile}
		cfg.DenyPersistenceWrites = true
		res := runEngine(t, cfg, env...)
		if ok := res.code == 0; ok != wantOK {
			t.Errorf("write %s: succeeded=%v, want %v", target, ok, wantOK)
		}
		if !strings.Contains(res.stderr, "not enforced on Windows: denyPersistenceWrites") || !strings.Contains(res.stderr, ".bashrc") {
			t.Errorf("missing .bashrc not reported: %s", res.stderr)
		}
	}
	cfg := workloadConfig(t, dir, "write", filepath.Join(profile, "notes.txt"))
	cfg.WritePaths = []string{dir, profile}
	cfg.DenyPersistenceWrites = true
	cfg.Strict = true
	if res := runEngine(t, cfg, env...); res.code == 0 {
		t.Error("strict mode ran with undeniable persistence locations")
	}
}

func TestWindowsEngineTimeout(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "sleep", "60")
	cfg.TimeoutMs = 2000
	start := time.Now()
	res := runEngine(t, cfg)
	if res.code != timeoutExitCode {
		t.Fatalf("exit = %d, want %d", res.code, timeoutExitCode)
	}
	if time.Since(start) > 30*time.Second {
		t.Errorf("timeout took %s", time.Since(start))
	}
}

func TestWindowsEngineBlockForkAndTraceExec(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "spawn")
	cfg.BlockFork = true
	cfg.EnableAudit = true
	cfg.TraceExec = true
	res := runEngine(t, cfg)
	if !strings.Contains(res.stdout, "spawn-failed") {
		t.Fatalf("child process started under blockFork: %q", res.stdout)
	}
	var execs, limits int
	for _, e := range auditEntries(res.stderr) {
		switch e.Type {
		case "process-exec":
			execs++
		case "resource-limit":
			limits++
		}
	}
	if execs != 1 || limits == 0 {
		t.Errorf("audit: %d process-exec, %d resource-limit entries", execs, limits)
	}

	cfg.BlockFork = false
	cfg.MaxProcesses = 2
	if res = runEngine(t, cfg); !strings.Contains(res.stdout, "spawn-ok") {
		t.Fatalf("one child should fit in maxProcesses=2: %q", res.stdout)
	}
}

func TestWindowsEngineTraceLibraries(t *testing.T) {
	requireMXC(t)
	if err := dlltrace.Probe(); err != nil {
		t.Skip(err)
	}
	dir := testDir(t)
	// A copy of a system DLL under a name nothing else on the machine loads.
	dll := filepath.Join(dir, "traced-probe.dll")
	data, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "version.dll"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dll, data, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := workloadConfig(t, dir, "loaddll", dll)
	cfg.TraceLibraries = true
	cfg.EnableAudit = true
	res := runEngine(t, cfg)
	if res.code != 0 {
		t.Fatalf("workload failed: %d", res.code)
	}
	want, err := os.Stat(dll)
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	found, ntdll := false, false
	for _, e := range auditEntries(res.stderr) {
		if e.Type != "lib-load" {
			continue
		}
		lower := strings.ToLower(e.Detail)
		if strings.Contains(lower, "wxc-exec.exe") || strings.Contains(lower, "conhost.exe") {
			t.Errorf("launcher or console host load reported: %+v", e)
		}
		if strings.EqualFold(e.Target, self) {
			t.Errorf("the workload's own executable was reported: %+v", e)
		}
		if fi, err := os.Stat(e.Target); err == nil && os.SameFile(fi, want) {
			found = true
		}
		ntdll = ntdll || strings.EqualFold(filepath.Base(e.Target), "ntdll.dll")
	}
	if !found || !ntdll {
		t.Fatalf("lib-load for the workload's DLL: %v, for ntdll.dll: %v", found, ntdll)
	}
}

// traceProperties returns an EVENT_TRACE_PROPERTIES buffer (64-bit layout)
// with room for the session and log file names.
func traceProperties() []byte {
	const props, names = 120, 2 * 1024 * 2
	b := make([]byte, props+names)
	binary.LittleEndian.PutUint32(b[0:], uint32(len(b)))  // Wnode.BufferSize
	binary.LittleEndian.PutUint32(b[112:], props+names/2) // LogFileNameOffset
	binary.LittleEndian.PutUint32(b[116:], props)         // LoggerNameOffset
	return b
}

var (
	testAdvapi32        = windows.NewLazySystemDLL("advapi32.dll")
	testQueryAllTracesW = testAdvapi32.NewProc("QueryAllTracesW")
	testControlTraceW   = testAdvapi32.NewProc("ControlTraceW")
)

// traceSessions lists the running ETW sessions whose names start with prefix.
func traceSessions(prefix string) []string {
	const max = 64
	bufs := make([][]byte, max)
	ptrs := make([]uintptr, max)
	for i := range bufs {
		bufs[i] = traceProperties()
		ptrs[i] = uintptr(unsafe.Pointer(&bufs[i][0]))
	}
	var count uint32
	testQueryAllTracesW.Call(uintptr(unsafe.Pointer(&ptrs[0])), max, uintptr(unsafe.Pointer(&count)))
	var out []string
	for i := 0; i < int(count) && i < max; i++ {
		raw := bufs[i][120 : 120+2*1024]
		u := unsafe.Slice((*uint16)(unsafe.Pointer(&raw[0])), 1024)
		if name := windows.UTF16ToString(u); strings.HasPrefix(name, prefix) {
			out = append(out, name)
		}
	}
	return out
}

func stopTraceSession(name string) error {
	p := traceProperties()
	n, _ := windows.UTF16PtrFromString(name)
	r, _, _ := testControlTraceW.Call(0, uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&p[0])), 1)
	if r != 0 {
		return windows.Errno(r)
	}
	return nil
}

func TestWindowsEngineWorkloadCannotStopTraceSession(t *testing.T) {
	requireMXC(t)
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the test's ETW structures use the 64-bit layout")
	}
	if err := dlltrace.Probe(); err != nil {
		t.Skip(err)
	}
	dir := testDir(t)
	nameFile := filepath.Join(dir, "session.txt")
	before := map[string]bool{}
	for _, n := range traceSessions("safer-exec-dll-") {
		before[n] = true
	}
	cfg := workloadConfig(t, dir, "stopetw", nameFile)
	cfg.TraceLibraries = true
	done := make(chan runResult, 1)
	go func() { done <- runEngine(t, cfg) }()
	var name string
	for deadline := time.Now().Add(60 * time.Second); name == "" && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, n := range traceSessions("safer-exec-dll-") {
			if !before[n] {
				name = n
			}
		}
	}
	if name == "" {
		t.Fatal("the engine's ETW session never appeared")
	}
	if err := os.WriteFile(nameFile, []byte(name), 0o644); err != nil {
		t.Fatal(err)
	}
	res := <-done
	if !strings.Contains(res.stdout, "stopetw-result:") || strings.Contains(res.stdout, "stopetw-result: <nil>") {
		t.Fatalf("the workload stopped the trace session (or did not try): %q", res.stdout)
	}
	if strings.Contains(res.stderr, "stopped before the run ended") {
		t.Fatalf("the session was stopped during the run: %q", res.stderr)
	}
}

// traceCrypto on Windows: the TLS parameters the egress proxy reads from
// each tunnel's handshake, and the crypto DLLs the ETW session sees.
func TestWindowsEngineTraceCrypto(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	srv.Listener.Close()
	srv.Listener = ln
	srv.StartTLS()
	t.Cleanup(srv.Close)
	port := ln.Addr().(*net.TCPAddr).Port
	host, _ := os.Hostname()
	host = strings.ToLower(host)

	cbom := filepath.Join(dir, "cbom.json")
	cfg := workloadConfig(t, dir, "https", fmt.Sprintf("https://%s:%d/", host, port))
	cfg.ProxyEgress = true
	cfg.AllowHosts = []string{host}
	cfg.AllowPorts = []int{port}
	cfg.TraceCrypto = true
	cfg.EnableAudit = true
	cfg.CBOMOutputPath = cbom
	res := runEngine(t, cfg)
	if !strings.Contains(res.stdout, "https-status: 200") {
		t.Fatalf("TLS request through the proxy failed: %q", res.stdout)
	}
	idx := strings.Index(res.stdout, "CRYPTO:")
	if idx < 0 {
		t.Fatalf("no CRYPTO result: %q", res.stdout)
	}
	var r config.CryptoResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.stdout[idx+len("CRYPTO:"):])), &r); err != nil {
		t.Fatal(err)
	}
	want := net.JoinHostPort(host, strconv.Itoa(port))
	found := false
	for _, c := range r.Ciphers {
		if c.Host == want && c.Protocol == "TLSv1.3" && c.Source == "proxy" && c.Group != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("no proxy-observed TLS 1.3 cipher for %s: %+v", want, r.Ciphers)
	}
	if dlltrace.Probe() == nil {
		cng := false
		for _, l := range r.Libraries {
			cng = cng || (strings.HasPrefix(l.Name, "Windows CNG") && l.Version != "" && l.Source == "etw_image_load")
		}
		if !cng {
			t.Errorf("no Windows CNG library from the ETW session: %+v", r.Libraries)
		}
	}
	if data, err := os.ReadFile(cbom); err != nil || !strings.Contains(string(data), `"cryptographic-asset"`) {
		t.Errorf("CBOM not written: %v", err)
	}
}

func TestWindowsEngineMemoryLimit(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "alloc", "400")
	cfg.MaxMemoryMB = 150
	res := runEngine(t, cfg)
	if res.code != memoryLimitExitCode || !strings.Contains(res.stderr, "exceeded its memory limit") {
		t.Fatalf("exit = %d, stderr %q", res.code, res.stderr)
	}
	cfg = workloadConfig(t, dir, "alloc", "50")
	cfg.MaxMemoryMB = 150
	if res = runEngine(t, cfg); res.code != 0 {
		t.Fatalf("allocation within the limit failed: %d", res.code)
	}
}

func TestWindowsEngineBatchArgumentsAreNotInterpreted(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	script := filepath.Join(dir, "args.cmd")
	body := "@echo off\r\necho ARG1=%1\r\necho ARG2=%2\r\necho ARG3=%3\r\n"
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res := runEngine(t, config.ExecConfig{
		Cmd: script, Args: []string{"x&echo INJECTED1", "%PATH%", `"&echo INJECTED2&"`},
		WorkingDir: dir, WritePaths: []string{dir},
	})
	if strings.Contains(res.stdout, "\nINJECTED") || strings.HasPrefix(res.stdout, "INJECTED") {
		t.Fatalf("argument injected a command: %q", res.stdout)
	}
	if !strings.Contains(res.stdout, `ARG2="%PATH%"`) {
		t.Errorf("%%PATH%% was expanded: %q", res.stdout)
	}
}

func TestWindowsEngineDumpProfile(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "echo")
	cfg.DumpProfile = true
	cfg.AllowHosts = []string{"localhost"}
	res := runEngine(t, cfg)
	payload, ok := strings.CutPrefix(strings.TrimSpace(res.stdout), "PROFILE:")
	if !ok {
		t.Fatalf("no PROFILE marker: %q", res.stdout)
	}
	var req mxc.Request
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		t.Fatalf("profile is not an MXC request: %v", err)
	}
	if req.Version != mxc.SchemaVersion || req.Process.Cwd != dir {
		t.Errorf("request = %+v", req)
	}
}

func TestWindowsEngineValidateProfile(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "echo")
	cfg.ValidateProfile = true
	res := runEngine(t, cfg)
	payload, _ := strings.CutPrefix(strings.TrimSpace(res.stdout), "PROFILE:")
	var v config.ProfileValidationResult
	if err := json.Unmarshal([]byte(payload), &v); err != nil || !v.Valid {
		t.Fatalf("validation = %+v (%v)", v, err)
	}
}

func TestWindowsEngineDryRunHasNoSideEffects(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	target := filepath.Join(dir, "dry.txt")
	cfg := workloadConfig(t, dir, "write", target)
	cfg.EnableDryRun = true
	res := runEngine(t, cfg)
	if res.code != 0 {
		t.Fatalf("dry-run exit = %d", res.code)
	}
	if _, err := os.Stat(target); err == nil {
		t.Fatal("dry-run wrote a file")
	}
	payload, ok := strings.CutPrefix(strings.TrimSpace(res.stdout[strings.Index(res.stdout, "DRYRUN:"):]), "DRYRUN:")
	if !ok {
		t.Fatalf("no DRYRUN marker: %q", res.stdout)
	}
	var dr config.DryRunResult
	if err := json.Unmarshal([]byte(payload), &dr); err != nil {
		t.Fatal(err)
	}
	// MXC's denial capture is best-effort on BaseContainer hosts (the same
	// attempt is not reported on every run), so the events are logged, not
	// asserted. When reported, creating a file appears as a write to its
	// directory.
	for _, e := range dr.Events {
		if e.Type == "file-write" && !strings.EqualFold(e.Path, target) && !mxc.WinEqual(e.Path, dir) {
			t.Errorf("unexpected write event %+v", e)
		}
	}
	t.Logf("dry-run events: %+v", dr.Events)
}

func TestWindowsEngineDiff(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "write", filepath.Join(dir, "created.txt"))
	cfg.EnableDiff = true
	res := runEngine(t, cfg)
	idx := strings.Index(res.stdout, "FSDIFF:")
	if idx < 0 {
		t.Fatalf("no FSDIFF marker: %q", res.stdout)
	}
	var d config.FSDiff
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.stdout[idx+len("FSDIFF:"):])), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Added) != 1 || !strings.EqualFold(d.Added[0].Path, filepath.Join(dir, "created.txt")) {
		t.Errorf("diff = %+v", d)
	}
}

func TestWindowsEngineAuditReportsGrantConflicts(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "write", "denied.txt")
	cfg.WritePaths = nil
	cfg.ReadPaths = []string{dir}
	cfg.EnableAudit = true
	res := runEngine(t, cfg)
	if res.code == 0 {
		t.Fatal("write to a read-only working directory succeeded")
	}
	for _, e := range auditEntries(res.stderr) {
		if e.Type == "ui" && e.Target == "ConvertToGui" {
			t.Errorf("baseline noise reported: %+v", e)
		}
	}
}

func TestWindowsEngineLearnRecordsHosts(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	url, _ := testServer(t)
	cfg := workloadConfig(t, dir, "http", url)
	cfg.EnableLearn = true
	res := runEngine(t, cfg)
	idx := strings.Index(res.stdout, "LEARNED:")
	if idx < 0 {
		t.Fatalf("no LEARNED marker: %q", res.stdout)
	}
	var p config.PolicyFile
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.stdout[idx+len("LEARNED:"):])), &p); err != nil {
		t.Fatal(err)
	}
	host, _ := os.Hostname()
	if len(p.AllowHosts) != 1 || p.AllowHosts[0] != strings.ToLower(host) || !p.ProxyEgress {
		t.Errorf("learned network = hosts %v proxy %v", p.AllowHosts, p.ProxyEgress)
	}
	found := false
	for _, w := range p.WritePaths {
		found = found || strings.EqualFold(w, dir)
	}
	if !found {
		t.Errorf("granted write path not in learned policy: %v", p.WritePaths)
	}
}

func TestWindowsEngineStrictRejectsUnenforceable(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "echo")
	cfg.BlockJIT = true
	cfg.Strict = true
	res := runEngine(t, cfg)
	if res.code == 0 || !strings.Contains(res.stderr, "not enforceable on Windows") {
		t.Fatalf("strict run accepted blockJIT: %d %q", res.code, res.stderr)
	}
}

// t.TempDir() lies in the host's temp directory, which the workload is then
// granted: privateTmp does not hold, and saying nothing hid that
// (cdxgen/safer-exec#4).
func TestWindowsEnginePrivateTmpWithTempGrant(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "echo")
	cfg.PrivateTmp = true
	res := runEngine(t, cfg)
	if res.code != 0 || !strings.Contains(res.stderr, "not enforced on Windows: privateTmp for ") {
		t.Fatalf("privateTmp with a temp grant: %d %q", res.code, res.stderr)
	}
	cfg.Strict = true
	res = runEngine(t, cfg)
	if res.code == 0 || !strings.Contains(res.stderr, "not enforceable on Windows: privateTmp for ") {
		t.Fatalf("strict run accepted privateTmp: %d %q", res.code, res.stderr)
	}
}

func TestWindowsEngineLockFiles(t *testing.T) {
	requireMXC(t)
	dir := testDir(t)
	lock := filepath.Join(dir, "install.lock")
	cfg := workloadConfig(t, dir, "write", lock)
	cfg.LockFiles = []config.LockFileSpec{{Path: lock, Exclusive: true}}
	// The sentinel byte range sits beyond the data, so the workload can still
	// write the lock file itself.
	if res := runEngine(t, cfg); res.code != 0 {
		t.Fatalf("workload blocked by its own lock file: %q", res.stderr)
	}
}

func TestLauncherEnvStripsMXCOverrides(t *testing.T) {
	t.Setenv("MXC_FORCE_TIER", "appcontainer-dacl")
	t.Setenv("wxc_wsb_force_reclaim", "1")
	t.Setenv("SAFER_EXEC_KEEP", "1")
	env := launcherEnv()
	var kept bool
	for _, kv := range env {
		u := strings.ToUpper(kv)
		if strings.HasPrefix(u, "MXC_") || strings.HasPrefix(u, "WXC_") {
			t.Errorf("override variable passed to wxc-exec: %s", kv)
		}
		kept = kept || kv == "SAFER_EXEC_KEEP=1"
	}
	if !kept {
		t.Error("unrelated variable dropped")
	}
}

func TestWindowsDiagnostics(t *testing.T) {
	requireMXC(t)
	cmd := exec.Command(os.Args[0], "--diagnostics")
	cmd.Env = append(os.Environ(), "SAFER_EXEC_TEST_ENGINE=1", launcherEnvVar+"="+launcherPath)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var d config.DiagnosticsResult
	if err := json.Unmarshal(out, &d); err != nil {
		t.Fatal(err)
	}
	if d.Platform != "windows" || !d.Features["mxc_process_container"] || !d.Capabilities["mxc_executor"].Available {
		t.Errorf("diagnostics = %+v", d)
	}
	lib, ok := d.Capabilities["library_tracing"]
	if !ok || lib.Available != d.Features["trace_libraries"] || lib.Available != (dlltrace.Probe() == nil) {
		t.Errorf("library_tracing = %+v, trace_libraries = %v", lib, d.Features["trace_libraries"])
	}
}

// An audited run that alternates CPU bursts with sleep is reported as a
// timing-channel suspect from the job object's counters.
func TestWindowsEngineReportsTimingChannel(t *testing.T) {
	requireMXC(t)
	if testing.Short() {
		t.Skip("takes about 15 s")
	}
	dir := testDir(t)
	cfg := workloadConfig(t, dir, "keyed", "70")
	cfg.EnableAudit = true
	res := runEngine(t, cfg)
	if !strings.Contains(res.stdout, "keyed-done") {
		t.Fatalf("workload did not finish: %q", res.stdout)
	}
	for _, e := range auditEntries(res.stderr) {
		if e.Type == "timing-channel-suspect" && e.Target == "cpu" {
			return
		}
	}
	t.Fatal("no cpu timing-channel-suspect entry")
}
