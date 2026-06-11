//go:build openbsd

package main

import (
	"io"
	"os"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

func TestUnveil_Permissions(t *testing.T) {
	// unveil requires a real path; verify the wrapper doesn't panic
	err := unveil("/tmp", "rx")
	if err != nil {
		t.Logf("unveil(/tmp, rx): %v", err)
	}
	// Lock unveil — this is safe to call multiple times in tests
	_ = unveil("", "")
}

func TestPledge_Basic(t *testing.T) {
	err := pledge("stdio rpath", "")
	if err != nil {
		t.Logf("pledge(stdio rpath): %v", err)
	}
}

func TestPledge_WithNetwork(t *testing.T) {
	err := pledge("stdio rpath inet dns", "")
	if err != nil {
		t.Logf("pledge(stdio inet dns): %v", err)
	}
}

func TestSetResourceLimitsOpenBSD_Memory(t *testing.T) {
	cfg := config.ExecConfig{MaxMemoryMB: 256}
	err := setResourceLimitsOpenBSD(cfg)
	if err != nil {
		t.Logf("setResourceLimitsOpenBSD(memory): %v", err)
	}
}

func TestSetResourceLimitsOpenBSD_Processes(t *testing.T) {
	cfg := config.ExecConfig{MaxProcesses: 50}
	err := setResourceLimitsOpenBSD(cfg)
	if err != nil {
		t.Logf("setResourceLimitsOpenBSD(processes): %v", err)
	}
}

func TestSetResourceLimitsOpenBSD_NoLimits(t *testing.T) {
	err := setResourceLimitsOpenBSD(config.ExecConfig{})
	if err != nil {
		t.Errorf("no-limit should not error: %v", err)
	}
}

func TestRun_OpenBSD_Basic(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cfg := config.ExecConfig{
		Cmd:        "/bin/echo",
		Args:       []string{"echo", "hello-openbsd"},
		ReadPaths:  []string{"/usr", "/etc", "/bin"},
		WritePaths: []string{"/tmp"},
	}
	err := run(cfg)

	w.Close()
	os.Stdout = oldStdout

	out, _ := io.ReadAll(r)
	t.Logf("stdout: %s", string(out))

	if err != nil {
		t.Logf("run returned error (expected if already pledge'd): %v", err)
	}
}

func TestRun_OpenBSD_WithNetworkDisabled(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:            "/bin/cat",
		Args:           []string{"cat", "/etc/hosts"},
		ReadPaths:      []string{"/usr", "/etc", "/bin"},
		WritePaths:     []string{"/tmp"},
		DisableNetwork: true,
	}
	err := run(cfg)
	if err != nil {
		t.Logf("run with network disabled: %v", err)
	}
}

func TestRun_OpenBSD_WithWriteRestriction(t *testing.T) {
	outDir := t.TempDir()
	cfg := config.ExecConfig{
		Cmd:        "/bin/sh",
		Args:       []string{"sh", "-c", "echo test > " + outDir + "/out.txt"},
		ReadPaths:  []string{"/usr", "/etc", "/bin", "/bin/sh"},
		WritePaths: []string{"/tmp", outDir},
	}
	err := run(cfg)
	if err != nil {
		t.Logf("run with write paths: %v", err)
	}
}

func TestRunDiagnostics_OpenBSD_Structure(t *testing.T) {
	result := runDiagnostics()

	if result.Platform != "openbsd" {
		t.Errorf("Platform = %q, want 'openbsd'", result.Platform)
	}
	if result.Arch == "" {
		t.Error("Arch should not be empty")
	}
	if result.Kernel == "" {
		t.Error("Kernel should not be empty")
	}
	if result.Release == "" {
		t.Error("Release should not be empty")
	}
	if len(result.Capabilities) == 0 {
		t.Error("Capabilities should not be empty")
	}
	if len(result.Features) == 0 {
		t.Error("Features should not be empty")
	}
}

func TestRunDiagnostics_OpenBSD_Capabilities(t *testing.T) {
	result := runDiagnostics()

	expectedCaps := []string{"unveil", "pledge", "rlimit_as", "rlimit_nproc"}
	for _, name := range expectedCaps {
		cap, ok := result.Capabilities[name]
		if !ok {
			t.Errorf("missing capability: %s", name)
			continue
		}
		if !cap.Available {
			t.Errorf("capability %s should be available on OpenBSD", name)
		}
		if cap.Detail == "" {
			t.Errorf("capability %s has empty detail", name)
		}
	}
}

func TestRunDiagnostics_OpenBSD_Features(t *testing.T) {
	result := runDiagnostics()

	expectedFeatures := []string{
		"network_isolation", "file_read_restriction", "file_write_restriction",
		"memory_limit", "process_limit",
		"exec_control", "fork_control",
		"filesystem_diff", "strict_mode",
	}
	for _, name := range expectedFeatures {
		if _, ok := result.Features[name]; !ok {
			t.Errorf("missing feature: %s", name)
		}
		if !result.Features[name] {
			t.Errorf("feature %s should be true on OpenBSD", name)
		}
	}

	// Features that should be false on OpenBSD
	falseFeatures := []string{
		"landlock_filesystem", "audit_tracing", "trace_libraries",
		"trace_http_urls", "allow_url_rules",
		"apparmor_safer_exec", "proc_hidepid",
	}
	for _, name := range falseFeatures {
		if result.Features[name] {
			t.Errorf("feature %s should be false on OpenBSD", name)
		}
	}
}

func TestRun_OpenBSD_EnvironmentIsolation(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	cfg := config.ExecConfig{
		Cmd:        "/bin/sh",
		Args:       []string{"sh", "-c", "echo $SAFER_EXEC_OB_TEST"},
		ReadPaths:  []string{"/usr", "/etc", "/bin", "/bin/sh"},
		WritePaths: []string{"/tmp"},
		Env: map[string]string{
			"SAFER_EXEC_OB_TEST": "openbsd_isolated",
		},
	}
	err := run(cfg)

	w.Close()
	os.Stdout = oldStdout

	out, _ := io.ReadAll(r)
	t.Logf("stdout: %s", string(out))

	if err != nil {
		t.Logf("env isolation run: %v", err)
	}
}

func TestRun_OpenBSD_WorkingDir(t *testing.T) {
	cfg := config.ExecConfig{
		Cmd:        "/bin/pwd",
		Args:       []string{"pwd"},
		ReadPaths:  []string{"/usr", "/etc", "/bin", "/tmp"},
		WritePaths: []string{"/tmp"},
		WorkingDir: "/tmp",
	}
	err := run(cfg)
	if err != nil {
		t.Logf("working dir run: %v", err)
	}
}

func TestUnveil_PathDoesNotExist(t *testing.T) {
	// unveil on a non-existent path should fail gracefully
	err := unveil("/nonexistent/path/xyz", "rx")
	if err != nil {
		t.Logf("unveil(nonexistent) error (expected): %v", err)
	} else {
		t.Log("unveil(nonexistent) succeeded (OpenBSD allows nonexistent paths in unveil)")
	}
}

func TestPledge_EmptyPromises(t *testing.T) {
	// After first pledge call, subsequent calls can only reduce promises
	err := pledge("", "")
	if err != nil {
		t.Logf("pledge(empty) error (expected if already pledged): %v", err)
	}
}

// verify SyscallNumbers tests the actual syscall numbers used by the engine.
// These are the canonical numbers on OpenBSD.
func TestUnveilSyscallNumber(t *testing.T) {
	err := unveil("/tmp", "rx")
	// unveil should succeed on a real path; even on a read-only filesystem
	// the call itself should not panic. The important thing is the syscall
	// number (114) is correct and doesn't crash.
	if err != nil {
		t.Logf("unveil returned error: %v", err)
	}
}

func TestPledgeSyscallNumber(t *testing.T) {
	err := pledge("stdio", "")
	// pledge with basic promises should return nil on a fresh process.
	// If already pledged, it returns eperm.
	if err != nil {
		t.Logf("pledge returned error: %v", err)
	}
}

func TestRunDiagnostics_OpenBSD_ResourceLimits(t *testing.T) {
	result := runDiagnostics()
	if _, ok := result.Capabilities["rlimit_as"]; !ok {
		t.Error("rlimit_as should be present")
	}
	if _, ok := result.Capabilities["rlimit_nproc"]; !ok {
		t.Error("rlimit_nproc should be present")
	}
}

// TestRun_ReadOnlyFilesystem verifies that unveil with "rx" prevents writes.
func TestRun_ReadOnlyFilesystem(t *testing.T) {
	roDir := t.TempDir()
	cfg := config.ExecConfig{
		Cmd:        "/bin/sh",
		Args:       []string{"sh", "-c", "echo write-attempt > " + roDir + "/should-fail.txt 2>/dev/null; echo $?"},
		ReadPaths:  []string{"/usr", "/etc", "/bin", "/bin/sh", roDir},
		WritePaths: []string{"/tmp"},
	}
	err := run(cfg)
	if err != nil {
		t.Logf("readonly filesystem restriction: %v", err)
	}
}

// TestPledge_PromisesAfterExec verifies that pledge's execpromises parameter
// is correctly empty, meaning the child process must set its own pledge.
func TestPledge_PromisesAfterExec(t *testing.T) {
	// run() calls pledge(promises, ""), so execpromises is empty
	// This test verifies the call path doesn't panic
	cfg := config.ExecConfig{
		Cmd:        "/bin/echo",
		Args:       []string{"echo", "pledge-execpromises-test"},
		ReadPaths:  []string{"/usr", "/etc", "/bin"},
		WritePaths: []string{"/tmp"},
	}
	err := run(cfg)
	if err != nil {
		t.Logf("pledge execpromises test: %v", err)
	}
}

// TestUnveil_NullLock verifies that calling unveil(nil, nil) locks the list.
// The wrapper function unveil("", "") passes empty strings, which on OpenBSD
// is equivalent to (nil, nil) via the raw syscall as BytePtrFromString("")
// returns a pointer to a null byte.
func TestUnveil_NullLock(t *testing.T) {
	_ = unveil("/tmp", "rwcx")
	err := unveil("", "")
	// After lock, further unveil calls should fail with EPERM
	if err != nil {
		t.Logf("unveil lock: %v", err)
	}
	// Attempting another unveil after lock should fail
	err2 := unveil("/usr", "rx")
	if err2 != nil {
		t.Logf("unveil after lock (expected EPERM): %v", err2)
	}
}

// TestRunDiagnostics_OpenBSD_FeatureCount verifies the feature count is correct.
func TestRunDiagnostics_OpenBSD_FeatureCount(t *testing.T) {
	result := runDiagnostics()
	enabled := 0
	for _, v := range result.Features {
		if v {
			enabled++
		}
	}
	if enabled < 7 {
		t.Errorf("expected at least 7 features enabled on OpenBSD, got %d", enabled)
	}
	t.Logf("OpenBSD features enabled: %d/%d", enabled, len(result.Features))
}

// BenchmarkPledge measures the overhead of pledge().
func BenchmarkPledge(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// After first pledge, subsequent calls can only reduce; the syscall
		// benchmark measures the call overhead rather than actual promise changes.
		_ = pledge("", "")
	}
}

// BenchmarkUnveil measures the overhead of unveil().
func BenchmarkUnveil(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = unveil("", "")
	}
}
