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
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/config"
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
func runEngine(t *testing.T, cfg config.ExecConfig) runResult {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "SAFER_EXEC_TEST_ENGINE=1", launcherEnvVar+"="+launcherPath)
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
}
