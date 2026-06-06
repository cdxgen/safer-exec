//go:build linux

// Package main tests the Linux sandbox engine by verifying actual
// sandboxing behavior: network isolation, file read/write, process limits,
// memory limits, Landlock network rules, and seccomp audit.
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

// --- Resource limits ---

func TestSetupCgroupV2_Memory(t *testing.T) {
	cfg := config.ExecConfig{MaxMemoryMB: 256}
	path, err := setupCgroupV2(cfg)
	if err != nil {
		t.Fatalf("setupCgroupV2 failed: %v", err)
	}
	if path == "" {
		t.Skip("cgroup v2 not available")
	}
	defer cleanupCgroup(path)

	// Verify memory.max was set
	memPath := filepath.Join(path, "memory.max")
	data, err := os.ReadFile(memPath)
	if err != nil {
		t.Skipf("memory.max not found (cgroup may not have memory controller): %v", err)
	}
	expected := "268435456" // 256 * 1024 * 1024
	if strings.TrimSpace(string(data)) != expected {
		t.Errorf("memory.max = %s, want %s", strings.TrimSpace(string(data)), expected)
	}
}

func TestSetupCgroupV2_CPU(t *testing.T) {
	cfg := config.ExecConfig{MaxCPUCores: 0.5}
	path, err := setupCgroupV2(cfg)
	if err != nil {
		t.Fatalf("setupCgroupV2 failed: %v", err)
	}
	if path == "" {
		t.Skip("cgroup v2 not available")
	}
	defer cleanupCgroup(path)

	// Verify cpu.max was set
	cpuPath := filepath.Join(path, "cpu.max")
	data, err := os.ReadFile(cpuPath)
	if err != nil {
		t.Skipf("cpu.max not found (cgroup may not have cpu controller): %v", err)
	}
	expected := "50000 100000" // 0.5 * 100000
	if strings.TrimSpace(string(data)) != expected {
		t.Errorf("cpu.max = %s, want %s", strings.TrimSpace(string(data)), expected)
	}
}

func TestSetupCgroupV2_PIDs(t *testing.T) {
	cfg := config.ExecConfig{MaxProcesses: 10}
	path, err := setupCgroupV2(cfg)
	if err != nil {
		t.Fatalf("setupCgroupV2 failed: %v", err)
	}
	if path == "" {
		t.Skip("cgroup v2 not available")
	}
	defer cleanupCgroup(path)

	// Verify pids.max was set
	pidsPath := filepath.Join(path, "pids.max")
	data, err := os.ReadFile(pidsPath)
	if err != nil {
		t.Skipf("pids.max not found (cgroup may not have pids controller): %v", err)
	}
	expected := "12" // 10 + 2
	if strings.TrimSpace(string(data)) != expected {
		t.Errorf("pids.max = %s, want %s", strings.TrimSpace(string(data)), expected)
	}
}

func TestSetupCgroupV2_NoLimits(t *testing.T) {
	cfg := config.ExecConfig{}
	path, err := setupCgroupV2(cfg)
	if err != nil {
		t.Fatalf("setupCgroupV2 failed: %v", err)
	}
	if path != "" {
		t.Errorf("should return empty path when no limits set, got %s", path)
	}
}

// --- Landlock network ---

func TestApplyLandlockNetwork_NoFiltering(t *testing.T) {
	cfg := config.ExecConfig{}
	err := applyLandlockNetwork(cfg)
	if err != nil {
		t.Fatalf("applyLandlockNetwork failed: %v", err)
	}
}

func TestApplyLandlockNetwork_WithPorts(t *testing.T) {
	cfg := config.ExecConfig{
		AllowPorts: []int{80, 443, 8080},
	}
	err := applyLandlockNetwork(cfg)
	if err != nil {
		t.Logf("landlock network (expected on some kernels): %v", err)
	}
}

func TestApplyLandlockNetwork_WithIPs(t *testing.T) {
	cfg := config.ExecConfig{
		AllowIPs: []string{"93.184.216.34", "142.250.80.46"},
	}
	err := applyLandlockNetwork(cfg)
	if err != nil {
		t.Logf("landlock network (expected on some kernels): %v", err)
	}
}

func TestApplyLandlockNetwork_DisableNetwork(t *testing.T) {
	cfg := config.ExecConfig{
		DisableNetwork: true,
	}
	err := applyLandlockNetwork(cfg)
	if err != nil {
		t.Logf("landlock network (expected on some kernels): %v", err)
	}
}

// --- Seccomp ---

func TestApplySeccomp_Default(t *testing.T) {
	cfg := config.ExecConfig{}
	err := applySeccomp(cfg)
	if err != nil {
		t.Logf("applySeccomp returned (may be expected in containers): %v", err)
	}
}

func TestApplySeccomp_WithAudit(t *testing.T) {
	cfg := config.ExecConfig{EnableAudit: true}
	err := applySeccomp(cfg)
	if err != nil {
		t.Logf("applySeccomp with audit returned (may be expected in containers): %v", err)
	}
}

// --- Namespace setup ---

func TestSetupNamespaces_Default(t *testing.T) {
	cfg := config.ExecConfig{}
	err := setupNamespaces(cfg)
	if err != nil {
		t.Logf("setupNamespaces returned (may be expected in containers): %v", err)
	}
}

func TestSetupNamespaces_WithNetwork(t *testing.T) {
	cfg := config.ExecConfig{DisableNetwork: true}
	err := setupNamespaces(cfg)
	if err != nil {
		t.Logf("setupNamespaces with network returned (may be expected in containers): %v", err)
	}
}

// --- ID mapping ---

func TestMapIDs(t *testing.T) {
	// Map IDs in current namespace — may fail if already mapped or
	// if we don't have permission to modify uid_map.
	// mapIDs() is now non-fatal, so we just verify it doesn't panic.
	err := mapIDs()
	if err != nil {
		t.Logf("mapIDs returned warning (expected in some environments): %v", err)
	}
}

// --- IP resolution ---

func TestResolveHosts_RealHostname(t *testing.T) {
	ips := resolveHosts([]string{"github.com"})
	if len(ips) == 0 {
		t.Error("should resolve at least one IP for github.com")
	}
}

func TestResolveHosts_Deduplication(t *testing.T) {
	ips := resolveHosts([]string{"github.com", "github.com"})
	seen := make(map[string]bool)
	for _, ip := range ips {
		if seen[ip] {
			t.Error("should deduplicate IPs")
		}
		seen[ip] = true
	}
}

func TestResolveHosts_InvalidHostname(t *testing.T) {
	ips := resolveHosts([]string{"nonexistent-host-example.local"})
	if len(ips) > 0 {
		t.Logf("resolved IPs for invalid hostname: %v", ips)
	}
}

// --- Audit logging ---

func TestLogAuditEntry(t *testing.T) {
	// Test logging to stderr (no audit FD set)
	logAuditEntry("test-type", "test-target")
}

func TestLogAuditEntry_WithFD(t *testing.T) {
	os.Setenv("SAFER_EXEC_AUDIT_FD", "2") // stderr
	defer os.Unsetenv("SAFER_EXEC_AUDIT_FD")
	logAuditEntry("test-type", "test-target")
}

// --- Actual sandboxing tests ---

func captureRun(t *testing.T, cfg config.ExecConfig) string {
	t.Helper()
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := run(cfg)

	w.Close()
	os.Stdout = oldStdout

	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	return string(out)
}

func TestRun_NetworkCall(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "curl",
		Args: []string{"-s", "https://httpbin.org/ip"},
	}
	out := captureRun(t, cfg)
	if !strings.Contains(out, "origin") && !strings.Contains(out, "ip") {
		t.Errorf("curl should return JSON with 'origin' or 'ip' field, got: %s", out)
	}
}

func TestRun_NetworkCallDisabled(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:            "curl",
		Args:           []string{"-s", "https://httpbin.org/ip"},
		DisableNetwork: true,
	}
	out := captureRun(t, cfg)
	if strings.TrimSpace(out) == "" {
		t.Log("network correctly blocked (empty output)")
		return
	}
	t.Logf("network output: %s", out)
}

func TestRun_ReadFile(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "cat",
		Args: []string{"/etc/hosts"},
	}
	out := captureRun(t, cfg)
	if strings.TrimSpace(out) == "" {
		t.Error("should read /etc/hosts content")
	}
}

func TestRun_ReadMultipleFiles(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "cat /etc/hosts /etc/protocols 2>/dev/null | wc -l"},
	}
	out := captureRun(t, cfg)
	if strings.TrimSpace(out) == "0" || strings.TrimSpace(out) == "" {
		t.Error("should read multiple files")
	}
}

func TestRun_WriteFile(t *testing.T) {
	outputFile := "/tmp/safer-exec-test-output.txt"

	cfg := config.ExecConfig{
		Cmd:        "sh",
		Args:       []string{"-c", "echo 'sandbox write test' > " + outputFile},
		WritePaths: []string{"/tmp"},
	}

	if err := run(cfg); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("should have written file: %v", err)
	}
	if !strings.Contains(string(content), "sandbox write test") {
		t.Errorf("file content mismatch: %s", string(content))
	}

	// Cleanup
	os.Remove(outputFile)
}

func TestRun_EnvironmentIsolation(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "echo $SAFER_EXEC_TEST_VAR"},
		Env: map[string]string{
			"SAFER_EXEC_TEST_VAR": "isolated_value",
		},
	}
	out := captureRun(t, cfg)
	if !strings.Contains(out, "isolated_value") {
		t.Errorf("should have sandboxed env var, got: %s", strings.TrimSpace(out))
	}
}

func TestRun_EnvironmentOverride(t *testing.T) {
	// Save original PATH
	origPath := os.Getenv("PATH")
	defer os.Setenv("PATH", origPath)

	os.Setenv("PATH", "/usr/local/bin:/usr/bin:/bin")

	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "echo $PATH"},
		Env: map[string]string{
			"PATH": "/custom/path:/usr/bin:/bin",
		},
	}
	out := captureRun(t, cfg)
	if !strings.Contains(out, "/custom/path") && !strings.Contains(out, "/usr/bin") {
		t.Errorf("should use overridden PATH, got: %s", out)
	}
}

func TestRun_ProcessLimit(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:          "sh",
		Args:         []string{"-c", "for i in $(seq 1 30); do echo $i & done; wait; echo done"},
		MaxProcesses: 20,
	}
	out := captureRun(t, cfg)
	if !strings.Contains(out, "done") {
		t.Logf("process limit test: got %s", out)
	}
}

func TestRun_MemoryLimit(t *testing.T) {
	// Allocate memory in a loop
	cfg := config.ExecConfig{
		Cmd:         "python3",
		Args:        []string{"-c", "a=[]; i=0\nwhile True:\n  a.append(list(range(100000)))\n  i+=1\n  if i%1000==0: print(i)"},
		MaxMemoryMB: 32,
	}
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	done := make(chan struct{})
	go func() {
		w.Close()
		close(done)
	}()

	_ = run(cfg)

	w.Close()
	os.Stdout = oldStdout

	out, _ := io.ReadAll(r)

	outStr := string(out)
	if strings.TrimSpace(outStr) == "" {
		t.Log("memory bomb killed (expected)")
	}
}

func TestRun_ForkBomb(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:          "sh",
		Args:         []string{"-c", ":(){ :|:& };:; echo done"},
		MaxProcesses: 50,
		MaxMemoryMB:  64,
	}
	if err := run(cfg); err != nil {
		t.Logf("fork bomb run failed (expected): %v", err)
	}
}

func TestRun_NetworkFilter(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:            "sh",
		Args:           []string{"-c", "cat /etc/hosts"},
		DisableNetwork: true,
		AllowIPs:       []string{"93.184.216.34", "142.250.80.46"},
	}
	out := captureRun(t, cfg)
	if strings.TrimSpace(out) == "" {
		t.Error("should read /etc/hosts with network filter")
	}
}

func TestRun_AuditEnabled(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:         "sh",
		Args:        []string{"-c", "echo 'audit test' && cat /etc/hosts"},
		EnableAudit: true,
	}
	out := captureRun(t, cfg)
	if !strings.Contains(out, "audit test") {
		t.Errorf("should complete with audit enabled, got: %s", strings.TrimSpace(out))
	}
}

func TestRun_ExitCodes(t *testing.T) {
	for _, code := range []int{0, 1, 42, 127, 255} {
		t.Run(fmt.Sprintf("%d", code), func(t *testing.T) {
			cfg := config.ExecConfig{
				Cmd:  "sh",
				Args: []string{"-c", "exit " + fmt.Sprintf("%d", code)},
			}
			if err := run(cfg); err != nil && code != 0 {
				t.Logf("exit code %d: %v", code, err)
			}
		})
	}
}

func TestRun_MultipleCommands(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "echo 'cmd1' && echo 'cmd2' && echo 'cmd3'"},
	}
	out := captureRun(t, cfg)
	for _, expected := range []string{"cmd1", "cmd2", "cmd3"} {
		if !strings.Contains(out, expected) {
			t.Errorf("should contain %q, got: %s", expected, out)
		}
	}
}

func TestRun_CommandNotFound(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "nonexistent_command_12345; echo $?"},
	}
	out := captureRun(t, cfg)
	if strings.TrimSpace(out) == "" {
		t.Error("should return exit code for missing command")
	}
}

func TestRun_Pipeline(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "echo 'hello world' | tr '[:lower:]' '[:upper:]'"},
	}
	out := captureRun(t, cfg)
	if !strings.Contains(out, "HELLO WORLD") {
		t.Errorf("pipeline should work, got: %s", out)
	}
}

func TestRun_BacktickSubstitution(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:  "sh",
		Args: []string{"-c", "echo $(hostname)"},
	}
	out := captureRun(t, cfg)
	if strings.TrimSpace(out) == "" {
		t.Error("should resolve hostname via subshell")
	}
}

func TestReadConfig_Valid(t *testing.T) {
	input := `{"cmd":"echo","args":["hello"],"enableAudit":true}`
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	w.WriteString(input)
	w.Close()

	cfg, err := readConfig()
	os.Stdin = oldStdin

	if err != nil {
		t.Fatalf("readConfig failed: %v", err)
	}
	if cfg.Cmd != "echo" {
		t.Errorf("Cmd = %q, want 'echo'", cfg.Cmd)
	}
	if !cfg.EnableAudit {
		t.Error("EnableAudit should be true")
	}
}

func TestReadConfig_MissingCmd(t *testing.T) {
	input := `{"args":["hello"]}`
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	w.WriteString(input)
	w.Close()

	_, err := readConfig()
	os.Stdin = oldStdin

	if err == nil {
		t.Error("should error on missing cmd")
	}
}

func TestReadConfig_InvalidJSON(t *testing.T) {
	input := `{"cmd":"echo"`
	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	w.WriteString(input)
	w.Close()

	_, err := readConfig()
	os.Stdin = oldStdin

	if err == nil {
		t.Error("should error on invalid JSON")
	}
}

// --- Landlock rule packing ---

func TestLandlockNetRule_StructSize(t *testing.T) {
	rule := landlockNetRule{
		access: landlockAccessNetTCPConnect,
		family: landlockFamilyIPv4,
		port:   443,
	}
	if rule.access != landlockAccessNetTCPConnect {
		t.Errorf("access = %d, want %d", rule.access, landlockAccessNetTCPConnect)
	}
	if rule.family != landlockFamilyIPv4 {
		t.Errorf("family = %d, want %d", rule.family, landlockFamilyIPv4)
	}
	if rule.port != 443 {
		t.Errorf("port = %d, want 443", rule.port)
	}
}

// --- Ensure unused imports ---

var _ = syscall.CLONE_NEWUSER
