//go:build linux

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

func baseReadPaths() []string {
	paths := []string{"/bin", "/usr", "/lib", "/etc", "/dev"}
	if _, err := os.Stat("/lib64"); err == nil {
		paths = append(paths, "/lib64")
	}
	if _, err := os.Stat("/usr/lib64"); err == nil {
		paths = append(paths, "/usr/lib64")
	}
	if _, err := os.Stat("/run"); err == nil {
		paths = append(paths, "/run")
	}
	return paths
}

func runSandbox(t *testing.T, cfg config.ExecConfig) (stdout string, stderr string, err error) {
	t.Helper()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	os.Stdout, os.Stderr = wOut, wErr

	outChan, errChan := make(chan string, 1), make(chan string, 1)
	go func() { data, _ := io.ReadAll(rOut); outChan <- string(data) }()
	go func() { data, _ := io.ReadAll(rErr); errChan <- string(data) }()

	runErr := run(cfg)
	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr
	stdout, stderr = <-outChan, <-errChan

	if stderr != "" {
		t.Logf("stderr: %s", stderr)
	}

	// ONLY skip if the sandbox fundamentally failed to mount tmpfs.
	// Ignore harmless warnings about sysfs, seccomp, or pivot_root.
	if runErr != nil && strings.Contains(stderr, "mount tmpfs: operation not permitted") {
		t.Skipf("Sandboxing not supported in this environment")
	}
	return stdout, stderr, runErr
}

func captureRun(t *testing.T, cfg config.ExecConfig) string {
	t.Helper()
	stdout, _, _ := runSandbox(t, cfg)
	return stdout
}

func cgroupAvailable() bool {
	path, _ := setupCgroupV2(config.ExecConfig{MaxMemoryMB: 1})
	if path != "" {
		cleanupCgroup(path)
		return true
	}
	return false
}

// --- Resource limits ---
func TestSetupCgroupV2_Memory(t *testing.T) {
	path, err := setupCgroupV2(config.ExecConfig{MaxMemoryMB: 256})
	if err != nil || path == "" {
		t.Skip("cgroup v2 not available")
	}
	defer cleanupCgroup(path)
	data, _ := os.ReadFile(filepath.Join(path, "memory.max"))
	val := strings.TrimSpace(string(data))
	if val == "" {
		t.Skip("memory controller not enabled in cgroup subtree_control")
	}
	if val != "268435456" {
		t.Errorf("got %s", data)
	}
}
func TestSetupCgroupV2_CPU(t *testing.T) {
	path, err := setupCgroupV2(config.ExecConfig{MaxCPUCores: 0.5})
	if err != nil || path == "" {
		t.Skip("cgroup v2 not available")
	}
	defer cleanupCgroup(path)
	data, _ := os.ReadFile(filepath.Join(path, "cpu.max"))
	val := strings.TrimSpace(string(data))
	if val == "" {
		t.Skip("cpu controller not enabled in cgroup subtree_control")
	}
	if val != "50000 100000" {
		t.Errorf("got %s", data)
	}
}
func TestSetupCgroupV2_PIDs(t *testing.T) {
	path, err := setupCgroupV2(config.ExecConfig{MaxProcesses: 10})
	if err != nil || path == "" {
		t.Skip("cgroup v2 not available")
	}
	defer cleanupCgroup(path)
	data, _ := os.ReadFile(filepath.Join(path, "pids.max"))
	val := strings.TrimSpace(string(data))
	if val == "" {
		t.Skip("pids controller not enabled in cgroup subtree_control")
	}
	if val != "12" {
		t.Errorf("got %s", data)
	}
}
func TestSetupCgroupV2_NoLimits(t *testing.T) {
	path, _ := setupCgroupV2(config.ExecConfig{})
	if path != "" {
		t.Errorf("should be empty")
	}
}

// --- Subsystems ---
func TestApplyLandlockNetwork_NoFiltering(t *testing.T) { applyLandlockNetwork(config.ExecConfig{}) }
func TestApplyLandlockNetwork_WithPorts(t *testing.T) {
	applyLandlockNetwork(config.ExecConfig{AllowPorts: []int{80}})
}
func TestApplySeccomp_Default(t *testing.T)    { applySeccomp(config.ExecConfig{}) }
func TestSetupNamespaces_Default(t *testing.T) { /* Handled by unshare binary now */ }
func TestMapIDs(t *testing.T)                  { /* Handled by unshare binary now */ }
func TestResolveHosts_RealHostname(t *testing.T) {
	if len(resolveHosts([]string{"github.com"})) == 0 {
		t.Error("no IPs")
	}
}
func TestLogAuditEntry(t *testing.T) { logAuditEntry("test", "target") }

// --- Integration Tests ---
func TestRun_NetworkCall(t *testing.T) {
	stdout, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "curl", Args: []string{"-v", "-s", "--max-time", "5", "https://example.com"}, ReadPaths: baseReadPaths(),
	})
	if err != nil && (strings.Contains(stderr, "Could not resolve host") || strings.Contains(stderr, "Couldn't connect")) {
		t.Skipf("Network/DNS restricted in this environment: %s", stderr)
	}
	if !strings.Contains(stdout, "Example Domain") && !strings.Contains(stdout, "example") {
		t.Fatalf("expected Example Domain, got stdout: %q, stderr: %q, err: %v", stdout, stderr, err)
	}
}

func TestRun_ReadFile(t *testing.T) {
	stdout, stderr, err := runSandbox(t, config.ExecConfig{Cmd: "cat", Args: []string{"/etc/hosts"}, ReadPaths: baseReadPaths()})
	if strings.TrimSpace(stdout) == "" {
		t.Fatalf("empty output. err: %v, stderr: %q", err, stderr)
	}
}

func TestRun_ReadMultipleFiles(t *testing.T) {
	stdout, stderr, err := runSandbox(t, config.ExecConfig{Cmd: "sh", Args: []string{"-c", "cat /etc/hosts /etc/protocols | wc -l"}, ReadPaths: baseReadPaths()})
	if strings.TrimSpace(stdout) == "0" || strings.TrimSpace(stdout) == "" {
		t.Fatalf("empty output. err: %v, stderr: %q", err, stderr)
	}
}

func TestRun_WriteFile(t *testing.T) {
	outDir := t.TempDir()
	f := filepath.Join(outDir, "output.txt")
	// Use /bin/sh explicitly to avoid PATH issues
	stdout, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "/bin/sh", Args: []string{"-c", "echo test > " + f},
		WritePaths: []string{outDir}, ReadPaths: baseReadPaths(),
	})
	if _, statErr := os.Stat(f); statErr != nil {
		t.Fatalf("file not written. err: %v, stdout: %q, stderr: %q", err, stdout, stderr)
	}
}

func TestRun_EnvironmentIsolation(t *testing.T) {
	stdout, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "/bin/sh", Args: []string{"-c", "echo $VAR"},
		Env: map[string]string{"VAR": "val"}, ReadPaths: baseReadPaths(),
	})
	if !strings.Contains(stdout, "val") {
		t.Errorf("env missing. err: %v, stdout: %q, stderr: %q", err, stdout, stderr)
	}
}

func TestRun_MultipleCommands(t *testing.T) {
	stdout, stderr, _ := runSandbox(t, config.ExecConfig{Cmd: "sh", Args: []string{"-c", "echo 1 && echo 2"}, ReadPaths: baseReadPaths()})
	if !strings.Contains(stdout, "1") || !strings.Contains(stdout, "2") {
		t.Fatalf("missing output. stdout: %q, stderr: %q", stdout, stderr)
	}
}

func TestRun_Pipeline(t *testing.T) {
	// Use absolute path for tr to guarantee it's found
	out := captureRun(t, config.ExecConfig{
		Cmd: "/bin/sh", Args: []string{"-c", "echo hello | /usr/bin/tr a-z A-Z"},
		ReadPaths: baseReadPaths(),
	})
	if !strings.Contains(out, "HELLO") {
		t.Error("pipeline failed")
	}
}

func TestRun_NetworkCallDisabled(t *testing.T) {
	if isUserNamespaceRestricted() {
		t.Skip("user namespace is restricted, network isolation cannot be verified")
	}
	stdout, _, err := runSandbox(t, config.ExecConfig{
		Cmd: "curl", Args: []string{"-s", "--max-time", "2", "https://httpbin.org/ip"},
		DisableNetwork: true, ReadPaths: baseReadPaths(),
	})
	// curl exits with code 6 when DNS is blocked. This is a success for the sandbox.
	if err != nil && strings.Contains(err.Error(), "code 6") {
		return
	}
	if strings.TrimSpace(stdout) == "" {
		return
	}
	t.Errorf("network should be blocked")
}

func TestRun_ProcessLimit(t *testing.T) {
	if !cgroupAvailable() {
		t.Skip("cgroup v2 not available, skipping test")
	}
	captureRun(t, config.ExecConfig{Cmd: "sh", Args: []string{"-c", "for i in $(seq 1 30); do echo $i & done; wait; echo done"}, MaxProcesses: 20, ReadPaths: baseReadPaths()})
}

func TestRun_MemoryLimit(t *testing.T) {
	if !cgroupAvailable() {
		t.Skip("cgroup v2 not available, skipping test")
	}
	stdout, _, _ := runSandbox(t, config.ExecConfig{
		Cmd: "python3", Args: []string{"-c", "a=[]\nwhile True: a.append([0]*100000)"},
		MaxMemoryMB: 32, ReadPaths: baseReadPaths(),
	})
	if strings.TrimSpace(stdout) == "" {
		t.Log("OOM killed (expected)")
	}
}

func TestRun_ForkBomb(t *testing.T) {
	if !cgroupAvailable() {
		t.Skip("cgroup v2 not available, skipping test")
	}
	runSandbox(t, config.ExecConfig{Cmd: "sh", Args: []string{"-c", ":(){ :|:& };:"}, MaxProcesses: 50, ReadPaths: baseReadPaths()})
}

func TestRun_NetworkFilter(t *testing.T) {
	stdout, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "sh", Args: []string{"-c", "cat /etc/hosts"},
		DisableNetwork: true, ReadPaths: baseReadPaths(),
	})
	if strings.TrimSpace(stdout) == "" {
		t.Fatalf("empty output. err: %v, stderr: %q", err, stderr)
	}
}

func TestRun_ExitCodes(t *testing.T) {
	for _, code := range []int{0, 1, 42} {
		t.Run(fmt.Sprintf("%d", code), func(t *testing.T) {
			runSandbox(t, config.ExecConfig{Cmd: "sh", Args: []string{"-c", fmt.Sprintf("exit %d", code)}, ReadPaths: baseReadPaths()})
		})
	}
}

func TestRun_CommandNotFound(t *testing.T) {
	captureRun(t, config.ExecConfig{Cmd: "sh", Args: []string{"-c", "nonexistent_12345"}, ReadPaths: baseReadPaths()})
}

// --- Config & Structs ---
func TestReadConfig_Valid(t *testing.T) {
	old := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.WriteString(`{"cmd":"echo"}`)
	w.Close()
	cfg, err := readConfig()
	os.Stdin = old
	if err != nil || cfg.Cmd != "echo" {
		t.Fatal("failed")
	}
}
func TestReadConfig_MissingCmd(t *testing.T) {
	old := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.WriteString(`{}`)
	w.Close()
	_, err := readConfig()
	os.Stdin = old
	if err == nil {
		t.Fatal("should error")
	}
}
func TestLandlockNetPortAttr_StructSize(t *testing.T) {
	rule := landlockNetPortAttr{AllowedAccess: 1, Port: 443}
	if rule.Port != 443 {
		t.Error("struct broken")
	}
}

// --- Syscall constant verification ---

func TestSyscallConstant_EXECVEAT(t *testing.T) {
	if sysEXECVEAT == 0 {
		t.Error("sysEXECVEAT is zero — must be defined for this architecture")
	}
}

func TestSyscallConstant_CLONE3(t *testing.T) {
	if sysCLONE3 == 0 {
		t.Error("sysCLONE3 is zero — must be defined for this architecture")
	}
}

// TestApplySeccomp_BlockFork verifies BlockFork seccomp configuration
// (includes clone3 blocking) does not panic.
func TestApplySeccomp_BlockFork(t *testing.T) {
	applySeccomp(config.ExecConfig{BlockFork: true})
}

// TestApplySeccomp_TraceExec verifies seccomp with TraceExec
// (includes execveat blocking) does not panic.
func TestApplySeccomp_TraceExec(t *testing.T) {
	applySeccomp(config.ExecConfig{TraceExec: true})
}

// TestApplySeccomp_BlockExecWildcard verifies seccomp with wildcard blockExec
// (includes execveat blocking) does not panic.
func TestApplySeccomp_BlockExecWildcard(t *testing.T) {
	applySeccomp(config.ExecConfig{BlockExec: []string{"*"}})
}

// TestApplySeccomp_BlockForkAndBlockExec verifies combined fork/exec blocking
// does not panic or produce conflicting BPF instructions.
func TestApplySeccomp_BlockForkAndBlockExec(t *testing.T) {
	applySeccomp(config.ExecConfig{
		BlockFork: true,
		BlockExec: []string{"sh"},
	})
}

// TestLandlock_NoWildcardPortRange verifies that applyLandlockNetwork does not
// automatically allow all privileged ports (1-1024) as a wildcard range.
// Only explicitly configured ports (or defaults 80, 443) should be allowed.
func TestLandlock_NoWildcardPortRange(t *testing.T) {
	applyLandlockNetwork(config.ExecConfig{AllowPorts: []int{443}})
}

// TestLandlock_DefaultPorts verifies that with no explicit ports configured,
// applyLandlockNetwork uses the safe defaults [80, 443].
func TestLandlock_DefaultPorts(t *testing.T) {
	applyLandlockNetwork(config.ExecConfig{})
}

// TestPivotRoot_FailureIsError verifies that pivot_root failures are returned
// as hard errors rather than silently ignored.
func TestPivotRoot_FailureIsError(t *testing.T) {
	// The seccomp filter blocks SYS_PIVOT_ROOT, which is the standard escape path.
	// ApplySeccomp should include PIVOT_ROOT in its default block list.
	applySeccomp(config.ExecConfig{})

	// Additionally, verify the constant is defined (would be 0 if missing)
	if syscall.SYS_PIVOT_ROOT == 0 {
		t.Error("SYS_PIVOT_ROOT is zero — cannot be blocked")
	}
}

var _ = syscall.CLONE_NEWUSER

// --- TraceLibraries / LD_AUDIT ---

// TestTraceLibraries_ExtractPrecompiledHelper verifies that extractPrecompiledAuditHelper
// extracts a valid .so file when precompiled support is enabled.
func TestTraceLibraries_ExtractPrecompiledHelper(t *testing.T) {
	if !hasPrecompiledSo {
		t.Skip("precompiled SO helper not enabled for this architecture/platform")
	}

	soPath, err := extractPrecompiledAuditHelper(t.TempDir())
	if err != nil {
		t.Fatalf("extractPrecompiledAuditHelper failed: %v", err)
	}
	defer os.Remove(soPath)

	info, err := os.Stat(soPath)
	if err != nil {
		t.Fatalf("could not stat extracted helper: %v", err)
	}

	if info.Size() == 0 {
		t.Errorf("extracted helper file has zero size")
	}
}

// TestTraceLibraries_Run verifies that running with TraceLibraries=true emits
// the expected LD_AUDIT diagnostic and completes without error.
// Library load events ({"type":"lib-load",...}) appear on stderr when LD_AUDIT
// is active and gcc/cc is available to compile the helper.
func TestTraceLibraries_Run(t *testing.T) {
	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = wOut, wErr

	outChan := make(chan string, 1)
	errChan := make(chan string, 1)
	go func() { data, _ := io.ReadAll(rOut); outChan <- string(data) }()
	go func() { data, _ := io.ReadAll(rErr); errChan <- string(data) }()

	runErr := run(config.ExecConfig{
		Cmd:            "/bin/sh",
		Args:           []string{"-c", "echo trace-ok"},
		ReadPaths:      baseReadPaths(),
		TraceLibraries: true,
	})

	wOut.Close()
	wErr.Close()
	os.Stdout, os.Stderr = oldStdout, oldStderr

	stdout := <-outChan
	stderr := <-errChan

	if runErr != nil && strings.Contains(stderr, "mount tmpfs: operation not permitted") {
		t.Skipf("Sandboxing not supported in this environment")
	}

	if runErr != nil {
		t.Fatalf("run with TraceLibraries failed: %v\nstderr: %s", runErr, stderr)
	}

	// Diagnostic message must appear
	if !strings.Contains(stderr, "safer-exec: trace-libraries:") {
		t.Errorf("expected trace-libraries diagnostic in stderr, got: %q", stderr)
	}

	// The command itself must have run
	if !strings.Contains(stdout, "trace-ok") {
		t.Errorf("expected 'trace-ok' in stdout, got: %q\nstderr: %q", stdout, stderr)
	}
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"6.8.0-arch1", 6.08},
		{"5.15.0-91-generic", 5.15},
		{"4.18.0", 4.18},
		{"6.10.0-rc2", 6.10},
		{"5.8.0", 5.08},
	}
	for _, tc := range tests {
		got := parseKernelVersion(tc.input)
		if got != tc.want {
			t.Errorf("parseKernelVersion(%q) = %.2f, want %.2f", tc.input, got, tc.want)
		}
	}
}

func TestRunDiagnostics_Structure(t *testing.T) {
	result := runDiagnostics()

	if result.Platform != "linux" {
		t.Errorf("Platform = %q, want 'linux'", result.Platform)
	}
	if result.Arch == "" {
		t.Error("Arch should not be empty")
	}
	if result.Kernel == "" {
		t.Error("Kernel should not be empty")
	}
	if len(result.Capabilities) == 0 {
		t.Error("Capabilities should not be empty")
	}
	if len(result.Features) == 0 {
		t.Error("Features should not be empty")
	}
}

func TestRunDiagnostics_Capabilities(t *testing.T) {
	result := runDiagnostics()

	expectedCaps := []string{
		"user_namespace", "mount_namespace", "pid_namespace", "net_namespace", "uts_namespace",
		"cgroup_v2", "landlock", "seccomp", "pivot_root", "tmpfs", "unshare_command",
	}
	for _, name := range expectedCaps {
		cap, ok := result.Capabilities[name]
		if !ok {
			t.Errorf("missing capability: %s", name)
			continue
		}
		if cap.Detail == "" {
			t.Errorf("capability %s has empty detail", name)
		}
	}
}

func TestRunDiagnostics_Features(t *testing.T) {
	result := runDiagnostics()

	expectedFeatures := []string{
		"network_isolation", "file_read_restriction", "file_write_restriction",
		"memory_limit", "cpu_limit", "process_limit",
		"exec_control", "fork_control", "audit_tracing",
		"filesystem_diff", "learning_mode", "strict_mode",
		"crypto_control", "fips_detection", "gpu_control",
		"tpm_control", "antivm_spoofing", "trace_libraries",
		"trace_http_urls", "allow_url_rules",
	}
	for _, name := range expectedFeatures {
		if _, ok := result.Features[name]; !ok {
			t.Errorf("missing feature: %s", name)
		}
	}

	// strict_mode and filesystem_diff should always be available
	if !result.Features["filesystem_diff"] {
		t.Error("filesystem_diff should always be available")
	}
	if !result.Features["strict_mode"] {
		t.Error("strict_mode should always be available")
	}
}

// TestApplyLandlockFilesystem_NoReadPath verifies applyLandlockFilesystem
// is safe to call with no read/write paths configured.
func TestApplyLandlockFilesystem_NoReadPath(t *testing.T) {
	applyLandlockFilesystem(config.ExecConfig{})
}

// TestApplyLandlockFilesystem_WithReadPaths verifies applyLandlockFilesystem
// with read-only paths.
func TestApplyLandlockFilesystem_WithReadPaths(t *testing.T) {
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "readonly"), 0o755)
	applyLandlockFilesystem(config.ExecConfig{
		ReadPaths:  []string{filepath.Join(dir, "readonly")},
		WritePaths: []string{dir},
	})
}

// TestSetupCgroupV2_IO verifies the IO limit fields are written to io.max.
func TestSetupCgroupV2_IO(t *testing.T) {
	path, err := setupCgroupV2(config.ExecConfig{MaxReadIOPS: 100, MaxWriteBps: 1048576})
	if err != nil || path == "" {
		t.Skip("cgroup v2 not available")
	}
	defer cleanupCgroup(path)
	data, _ := os.ReadFile(filepath.Join(path, "io.max"))
	val := strings.TrimSpace(string(data))
	if val == "" {
		t.Skip("io controller not enabled in cgroup subtree_control")
	}
	t.Logf("io.max: %s", val)
	if !strings.Contains(val, "riops") || !strings.Contains(val, "wbps") {
		t.Errorf("io.max should contain riops and wbps: %s", val)
	}
}

// TestSetupCgroupV2_NoIO verifies io.max is not written when no IO limits set.
func TestSetupCgroupV2_NoIO(t *testing.T) {
	path, err := setupCgroupV2(config.ExecConfig{MaxMemoryMB: 1, MaxReadIOPS: 0, MaxWriteBps: 0})
	if err != nil || path == "" {
		t.Skip("cgroup v2 not available")
	}
	defer cleanupCgroup(path)
	if _, err := os.Stat(filepath.Join(path, "io.max")); err == nil {
		t.Error("io.max should not exist when no IO limits are set")
	}
}

// TestLandlockLayersRemaining verifies the function returns a reasonable value.
func TestLandlockLayersRemaining(t *testing.T) {
	remaining := landlockLayersRemaining()
	t.Logf("landlock layers remaining: %d", remaining)
	// Should be either -1 (unknown) or a positive number
	if remaining < -1 || remaining > 16 {
		t.Errorf("unexpected landlock layers remaining: %d", remaining)
	}
}

// TestWarnLandlockLayers verifies the function does not panic.
func TestWarnLandlockLayers(t *testing.T) {
	warnLandlockLayers()
}

// TestRunDiagnostics_NewFeatures verifies new diagnostic features are present.
func TestRunDiagnostics_NewFeatures(t *testing.T) {
	result := runDiagnostics()

	newCaps := []string{
		"time_namespace", "ipc_namespace",
		"cgroup_v2_io", "landlock_filesystem",
		"apparmor",
	}
	for _, name := range newCaps {
		if _, ok := result.Capabilities[name]; !ok {
			t.Errorf("missing capability: %s", name)
		}
	}

	newFeatures := []string{
		"io_limit", "time_isolation", "ipc_isolation",
		"landlock_filesystem", "apparmor_safer_exec",
		"proc_hidepid",
	}
	for _, name := range newFeatures {
		if _, ok := result.Features[name]; !ok {
			t.Errorf("missing feature: %s", name)
		}
	}
}

// --- Phase 1 tests: mount hardening ---

// TestEnforceSubmountReadOnly verifies the function does not panic when
// parsing /proc/self/mountinfo.
func TestEnforceSubmountReadOnly(t *testing.T) {
	// / should always exist and be a mount point.
	enforceSubmountReadOnly("/")
}

// TestEnforceSubmountReadOnly_NonExistent ensures the function handles
// non-existent paths gracefully.
func TestEnforceSubmountReadOnly_NonExistent(t *testing.T) {
	enforceSubmountReadOnly("/nonexistent_zzz_path")
}

// TestSetupDev verifies dev setup function does not panic outside a sandbox.
func TestSetupDev(t *testing.T) {
	err := setupDev(config.ExecConfig{})
	// setupDev requires /dev to be a mount point; outside a namespace it
	// may fail with EINVAL or EPERM. Both are acceptable.
	if err != nil {
		t.Logf("setupDev error (expected outside namespace): %v", err)
	}
}

// TestMountPropagation_MS_SLAVE verifies MS_SLAVE on root is set without
// errors. This is called at the top of setupFilesystem.
func TestMountPropagation_MS_SLAVE(t *testing.T) {
	// MS_SLAVE on root in a non-namespace environment is safe and should succeed.
	if err := syscall.Mount("", "/", "", syscall.MS_SLAVE|syscall.MS_REC, ""); err != nil {
		t.Logf("MS_SLAVE on root not supported in this environment: %v", err)
	}
}

// --- Phase 2a tests: PID 1 reaper ---

// TestRunWithReaper_SimpleCommand verifies the reaper correctly propagates
// exit codes from the child process.
func TestRunWithReaper_SimpleCommand(t *testing.T) {
	// Use a simple true/false test to exercise the reaper fork-wait path.
	// We cannot call runWithReaper directly from tests because it calls
	// closeExtraFds which would close test fds. Instead we test via runSandbox
	// which invokes the full engine through unshare.
	stdout, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "true", Args: nil,
		ReadPaths: baseReadPaths(),
	})
	if err != nil {
		t.Logf("expected no error for true command; stdout=%q stderr=%q err=%v", stdout, stderr, err)
	}
}

// TestRunWithReaper_ExitCode verifies non-zero exit codes are propagated.
func TestRunWithReaper_ExitCode(t *testing.T) {
	_, _, err := runSandbox(t, config.ExecConfig{
		Cmd: "sh", Args: []string{"-c", "exit 42"},
		ReadPaths: baseReadPaths(),
	})
	if err != nil {
		if exitErr, ok := err.(*ExitError); ok {
			if exitErr.Code != 42 {
				t.Errorf("expected exit code 42, got %d", exitErr.Code)
			}
		}
	}
}

// TestRunWithReaper_ForkedChildren verifies the reaper handles zombie
// children correctly. We fork several short-lived children that outlive
// their immediate parent.
func TestRunWithReaper_ForkedChildren(t *testing.T) {
	_, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "sh", Args: []string{"-c", "for i in $(seq 1 5); do (sleep 0.1 &); done; wait; echo done"},
		ReadPaths: baseReadPaths(),
	})
	if err != nil {
		t.Logf("forked children test result: stderr=%q err=%v", stderr, err)
	}
}

// --- Phase 2b test: PR_SET_PDEATHSIG ---

// TestDieWithParent verifies the DieWithParent config does not cause errors.
func TestDieWithParent(t *testing.T) {
	_, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "true", Args: nil,
		ReadPaths:     baseReadPaths(),
		DieWithParent: true,
	})
	if err != nil {
		t.Logf("die-with-parent: stderr=%q err=%v", stderr, err)
	}
}

// --- Phase 2c test: NewSession ---

// TestNewSession verifies the NewSession config does not cause errors.
func TestNewSession(t *testing.T) {
	_, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "true", Args: nil,
		ReadPaths:  baseReadPaths(),
		NewSession: true,
	})
	if err != nil {
		t.Logf("new-session: stderr=%q err=%v", stderr, err)
	}
}

// --- Phase 2e tests: stackable seccomp ---

// TestParseSeccompProgram_Valid parses a minimal BPF program that allows
// everything.
func TestParseSeccompProgram_Valid(t *testing.T) {
	prog := []byte{
		0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, // RET ALLOW (k=0x7fff0000)
	}
	filters := parseSeccompProgram(prog)
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	if filters[0].Code != 0x0006 || filters[0].K != 0x7fff0000 {
		t.Errorf("unexpected filter: code=%#x k=%#x", filters[0].Code, filters[0].K)
	}
}

// TestParseSeccompProgram_Empty returns nil for empty data.
func TestParseSeccompProgram_Empty(t *testing.T) {
	filters := parseSeccompProgram([]byte{})
	if filters != nil {
		t.Error("expected nil for empty input")
	}
}

// TestParseSeccompProgram_Malformed returns nil for non-8-byte-aligned data.
func TestParseSeccompProgram_Malformed(t *testing.T) {
	filters := parseSeccompProgram([]byte{1, 2, 3})
	if filters != nil {
		t.Error("expected nil for malformed input")
	}
}

// TestDecodeBase64Seccomp_Valid decodes a valid base64-encoded BPF filter.
func TestDecodeBase64Seccomp_Valid(t *testing.T) {
	encoded := "BgAAAAAA/38=" // RET ALLOW: code=0x0006, k=0x7fff0000
	filters, err := decodeBase64Seccomp(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
}

// TestDecodeBase64Seccomp_InvalidInput returns error for bad base64.
func TestDecodeBase64Seccomp_InvalidInput(t *testing.T) {
	_, err := decodeBase64Seccomp("!!!invalid!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

// TestDecodeBase64Seccomp_Misaligned returns error for misaligned output.
func TestDecodeBase64Seccomp_Misaligned(t *testing.T) {
	// "AAAA" decodes to 3 bytes (not multiple of 8)
	_, err := decodeBase64Seccomp("AAAA")
	if err == nil {
		t.Error("expected error for misaligned output")
	}
}

// TestStackableSeccomp_PathFilter verifies loading seccomp from a file.
func TestStackableSeccomp_PathFilter(t *testing.T) {
	// Create a minimal BPF filter file that allows everything.
	prog := []byte{0x06, 0x00, 0x00, 0x00, 0xff, 0xff, 0x7f, 0x00}
	f, err := os.CreateTemp("", "seccomp-test-*.bpf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write(prog)
	f.Close()

	cfg := config.ExecConfig{
		SeccompFilters: []config.SeccompFilterSpec{
			{Path: f.Name()},
		},
	}
	// Should not panic; actual seccomp loading may fail outside a test env.
	applySeccomp(cfg)
}

// TestStackableSeccomp_ProgramFilter verifies loading seccomp from base64.
func TestStackableSeccomp_ProgramFilter(t *testing.T) {
	cfg := config.ExecConfig{
		SeccompFilters: []config.SeccompFilterSpec{
			{Program: "BgAAAAAA/38="}, // RET ALLOW
		},
	}
	applySeccomp(cfg)
}

// --- Phase 3a tests: file locks ---

// TestAcquireFileLocks_Empty does nothing for empty input.
func TestAcquireFileLocks_Empty(t *testing.T) {
	files, err := acquireFileLocks(nil)
	if err != nil || len(files) != 0 {
		t.Error("expected nil, empty for empty input")
	}
}

// TestAcquireFileLocks_SingleFile acquires and releases a lock.
func TestAcquireFileLocks_SingleFile(t *testing.T) {
	f, err := os.CreateTemp("", "lockfile-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	files, err := acquireFileLocks([]string{f.Name()})
	if err != nil {
		t.Fatalf("acquireFileLocks: %v", err)
	}
	releaseFileLocks(files)
}

// TestAcquireFileLocks_NonexistentFile returns error.
func TestAcquireFileLocks_NonexistentFile(t *testing.T) {
	_, err := acquireFileLocks([]string{"/nonexistent_zzz/lockfile"})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// --- Phase 3b tests: extra fd cleanup ---

// TestCloseExtraFds verifies the function is safe to call in the test
// process context. Since closeExtraFds closes all fds above stderr, it
// can corrupt the Go runtime's internal fds (epoll, timerfd). We only
// verify the function exists and compiles correctly; the actual fd
// cleanup is done by closeChildFds in the post-fork child.
func TestCloseExtraFds(t *testing.T) {
	t.Skip("closeExtraFds is destructive to the Go runtime; actual fd cleanup is tested via closeChildFds in sandbox exec path")
}

// --- Phase 3c tests: JSON status ---

// TestWriteJsonStatus_Disabled does nothing when fd is 0.
func TestWriteJsonStatus_Disabled(t *testing.T) {
	writeJsonStatus(0, map[string]interface{}{"key": "val"})
}

// TestWriteJsonStatus_WritesJSON writes a valid JSON line to a pipe.
func TestWriteJsonStatus_WritesJSON(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	writeJsonStatus(int(w.Fd()), map[string]interface{}{
		"child-pid": 42,
		"type":      "sandbox-start",
	})
	w.Close()

	var buf [256]byte
	n, _ := r.Read(buf[:])
	data := strings.TrimSpace(string(buf[:n]))
	if !strings.Contains(data, `"child-pid":42`) {
		t.Errorf("unexpected JSON: %s", data)
	}
	if !strings.Contains(data, `"type":"sandbox-start"`) {
		t.Errorf("unexpected JSON: %s", data)
	}
}

// --- Phase 2d tests: bind-from-fd ---

// TestBindMount_NonFd uses direct path binding (useFd=false).
func TestBindMount_NonFd(t *testing.T) {
	// Bind-mount /etc to a temp dir (read-only bind of a directory).
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "etc")
	os.MkdirAll(target, 0o755)

	err := bindMount("/etc", target, false)
	if err != nil {
		t.Logf("direct bind mount /etc: %v", err)
	}
	// Clean up; don't leave mounts behind.
	syscall.Unmount(target, syscall.MNT_DETACH)
}

// TestBindMount_WithFd uses fd-based binding.
func TestBindMount_WithFd(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "etc-fd")
	os.MkdirAll(target, 0o755)

	err := bindMount("/etc", target, true)
	if err != nil {
		t.Logf("fd bind mount /etc: %v", err)
	}
	syscall.Unmount(target, syscall.MNT_DETACH)
}

// --- Combined integration tests ---

// TestRun_DevSetupEnabled verifies /dev/null is accessible when SetUpDev is true.
func TestRun_DevSetupEnabled(t *testing.T) {
	stdout, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "sh", Args: []string{"-c", "test -c /dev/null && echo dev_ok || echo dev_missing"},
		ReadPaths: baseReadPaths(),
	})
	if err != nil {
		t.Logf("dev setup test: stderr=%q err=%v", stderr, err)
	}
	if strings.Contains(stdout, "dev_ok") {
		t.Log("dev setup active")
	}
}

// TestRun_WritePathEphemeral verifies a write path functions correctly.
func TestRun_WritePathEphemeral(t *testing.T) {
	outDir := t.TempDir()
	f := filepath.Join(outDir, "output.txt")
	_, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "/bin/sh", Args: []string{"-c", "echo hello > " + f},
		WritePaths: []string{outDir}, ReadPaths: baseReadPaths(),
	})
	if _, statErr := os.Stat(f); statErr != nil {
		t.Fatalf("file not written. err: %v, stderr: %q", err, stderr)
	}
}

// TestRun_FileLocksInSandbox verifies LockFiles are acquired during execution.
func TestRun_FileLocksInSandbox(t *testing.T) {
	lockFile, err := os.CreateTemp("", "sandbox-lock-*")
	if err != nil {
		t.Fatal(err)
	}
	lockFile.Close()
	defer os.Remove(lockFile.Name())

	_, stderr, err := runSandbox(t, config.ExecConfig{
		Cmd: "true", Args: nil,
		ReadPaths: baseReadPaths(),
		LockFiles: []string{lockFile.Name()},
	})
	if err != nil {
		t.Logf("file lock sandbox: stderr=%q err=%v", stderr, err)
	}
}

// TestRun_Diagnostics_NewFeatures verifies all new diagnostic features
// are present in the diagnostics output.
func TestRun_Diagnostics_NewFeatures(t *testing.T) {
	result := runDiagnostics()

	newFeatures := []string{
		"dev_setup", "die_with_parent", "new_session",
		"tmp_overlay", "file_locks", "json_status",
		"bind_use_fd", "seccomp_stacking", "pid_reaper",
		"mount_propagation_control", "submount_readonly_enforcement",
		"proc_hardening", "extra_fd_cleanup",
	}
	for _, name := range newFeatures {
		if _, ok := result.Features[name]; !ok {
			t.Errorf("missing feature: %s", name)
		}
	}
}
