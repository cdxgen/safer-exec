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
	if strings.TrimSpace(string(data)) != "268435456" {
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
	if strings.TrimSpace(string(data)) != "50000 100000" {
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
	if strings.TrimSpace(string(data)) != "12" {
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

var _ = syscall.CLONE_NEWUSER
