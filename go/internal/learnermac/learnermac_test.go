// Package learnermac_test validates macOS Seatbelt trace parsing.
package learnermac_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/learnermac"
)

func TestNewTraceParser(t *testing.T) {
	p := learnermac.NewTraceParser()
	if p == nil {
		t.Fatal("NewTraceParser should return a non-nil parser")
	}
}

func TestParseTraceFile_NonExistent(t *testing.T) {
	p := learnermac.NewTraceParser()
	err := p.ParseTraceFile("/tmp/nonexistent-trace-file-12345")
	if err == nil {
		t.Fatal("ParseTraceFile should return an error for nonexistent file")
	}
}

func TestParseTraceFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	if err := os.WriteFile(traceFile, []byte{}, 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile should not fail for empty file: %v", err)
	}
}

func TestParseTraceFile_FileRead(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (sh): file-read "/usr/lib/libSystem.B.dylib"
sandbox: process 12345 (sh): file-read "/etc/hosts"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("cat", []string{"/etc/hosts"})
	if len(policy.ReadPaths) != 2 {
		t.Errorf("expected 2 read paths, got %d", len(policy.ReadPaths))
	}
	if policy.ReadPaths[0] != "/etc/hosts" {
		t.Errorf("read paths[0]: got %q, want %q", policy.ReadPaths[0], "/etc/hosts")
	}
	if policy.ReadPaths[1] != "/usr/lib/libSystem.B.dylib" {
		t.Errorf("read paths[1]: got %q, want %q", policy.ReadPaths[1], "/usr/lib/libSystem.B.dylib")
	}
}

func TestParseTraceFile_FileWrite(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (sh): file-write "/tmp/output.txt"
sandbox: process 12345 (sh): file-write "/var/log/app.log"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("echo", []string{"hello"})
	if len(policy.WritePaths) != 2 {
		t.Errorf("expected 2 write paths, got %d", len(policy.WritePaths))
	}
}

func TestParseTraceFile_NetworkOutbound(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (curl): network-outbound to "93.184.216.34:443"
sandbox: process 12345 (curl): network-outbound to "1.2.3.4:80"
sandbox: process 12345 (curl): network-outbound to "5.6.7.8"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("curl", []string{"https://example.com"})
	if len(policy.AllowIPs) != 3 {
		t.Errorf("expected 3 IPs, got %d: %v", len(policy.AllowIPs), policy.AllowIPs)
	}
	if len(policy.AllowPorts) != 2 {
		t.Errorf("expected 2 ports, got %d: %v", len(policy.AllowPorts), policy.AllowPorts)
	}
}

func TestParseTraceFile_MixedLines(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (sh): file-read "/usr/lib/libSystem.B.dylib"
sandbox: process 12345 (sh): file-write "/tmp/output.txt"
sandbox: process 12345 (curl): network-outbound to "93.184.216.34:443"
sandbox: process 12345 (sh): file-read "/etc/hosts"
sandbox: process 12345 (curl): network-outbound to "1.2.3.4:80"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("sh", []string{"-c", "cmd"})
	if len(policy.ReadPaths) != 2 {
		t.Errorf("expected 2 read paths, got %d", len(policy.ReadPaths))
	}
	if len(policy.WritePaths) != 1 {
		t.Errorf("expected 1 write path, got %d", len(policy.WritePaths))
	}
	if len(policy.AllowIPs) != 2 {
		t.Errorf("expected 2 IPs, got %d", len(policy.AllowIPs))
	}
	if len(policy.AllowPorts) != 2 {
		t.Errorf("expected 2 ports, got %d", len(policy.AllowPorts))
	}
}

func TestParseTraceFile_BlankLines(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `

sandbox: process 12345 (sh): file-read "/etc/hosts"

`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile should not fail for blank lines: %v", err)
	}

	policy := p.BuildPolicy("cat", []string{"/etc/hosts"})
	if len(policy.ReadPaths) != 1 {
		t.Errorf("expected 1 read path, got %d", len(policy.ReadPaths))
	}
}

func TestParseTraceFile_MalformedLines(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `some random line
sandbox: process 12345 (sh): file-read
sandbox: process 12345 (sh): file-read "/usr/lib/libSystem.B.dylib"
sandbox: process 12345 (sh): network-outbound to "93.184.216.34:443"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile should not fail for malformed lines: %v", err)
	}

	policy := p.BuildPolicy("cat", []string{"/etc/hosts"})
	if len(policy.ReadPaths) != 1 {
		t.Errorf("expected 1 read path (malformed line should be skipped), got %d", len(policy.ReadPaths))
	}
}

func TestBuildPolicy_EmptyTrace(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	if err := os.WriteFile(traceFile, []byte{}, 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("cat", []string{"/etc/hosts"})
	if policy == nil {
		t.Fatal("policy should not be nil")
	}
	if policy.Cmd != "cat" {
		t.Errorf("policy.Cmd: got %q, want %q", policy.Cmd, "cat")
	}
	if policy.Args[0] != "/etc/hosts" {
		t.Errorf("policy.Args[0]: got %q, want %q", policy.Args[0], "/etc/hosts")
	}
	if len(policy.ReadPaths) != 0 {
		t.Errorf("expected empty read paths, got %v", policy.ReadPaths)
	}
	if len(policy.WritePaths) != 0 {
		t.Errorf("expected empty write paths, got %v", policy.WritePaths)
	}
	if len(policy.AllowIPs) != 0 {
		t.Errorf("expected empty allow IPs, got %v", policy.AllowIPs)
	}
	if len(policy.AllowPorts) != 0 {
		t.Errorf("expected empty allow ports, got %v", policy.AllowPorts)
	}
}

func TestBuildPolicy_PolicyHasEmptyArraysNotNil(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (sh): file-read "/etc/hosts"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("cat", []string{"/etc/hosts"})
	if policy.ReadPaths == nil {
		t.Error("policy.ReadPaths should not be nil (should be empty slice)")
	}
	if policy.WritePaths == nil {
		t.Error("policy.WritePaths should not be nil (should be empty slice)")
	}
	if policy.AllowIPs == nil {
		t.Error("policy.AllowIPs should not be nil (should be empty slice)")
	}
	if policy.AllowPorts == nil {
		t.Error("policy.AllowPorts should not be nil (should be empty slice)")
	}
}

func TestParseTraceFile_DuplicatePaths(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (sh): file-read "/etc/hosts"
sandbox: process 12345 (sh): file-read "/etc/hosts"
sandbox: process 12345 (sh): file-read "/etc/hosts"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("cat", []string{"/etc/hosts"})
	if len(policy.ReadPaths) != 1 {
		t.Errorf("expected 1 read path after dedup, got %d", len(policy.ReadPaths))
	}
}

func TestParseTraceFile_NestedPathDedup(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (sh): file-read "/usr/lib"
sandbox: process 12345 (sh): file-read "/usr/lib/libSystem.B.dylib"
sandbox: process 12345 (sh): file-read "/usr/lib/libc.dylib"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("cat", []string{"/etc/hosts"})
	// Should deduplicate: subpaths of "/usr/lib" are removed, keeping only "/usr/lib"
	if len(policy.ReadPaths) != 1 {
		t.Errorf("expected 1 deduplicated read path, got %d: %v", len(policy.ReadPaths), policy.ReadPaths)
	}
	if policy.ReadPaths[0] != "/usr/lib" {
		t.Errorf("deduplicated read path: got %q, want %q", policy.ReadPaths[0], "/usr/lib")
	}
}

func TestParseTraceFile_IPsSorted(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (curl): network-outbound to "1.2.3.4:80"
sandbox: process 12345 (curl): network-outbound to "93.184.216.34:443"
sandbox: process 12345 (curl): network-outbound to "5.6.7.8:443"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("curl", []string{"https://example.com"})
	for i := 1; i < len(policy.AllowIPs); i++ {
		if policy.AllowIPs[i] < policy.AllowIPs[i-1] {
			t.Errorf("IPs should be sorted: %q < %q at indices %d, %d",
				policy.AllowIPs[i], policy.AllowIPs[i-1], i-1, i)
		}
	}
}

func TestParseTraceFile_PortsSorted(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (curl): network-outbound to "1.2.3.4:8080"
sandbox: process 12345 (curl): network-outbound to "93.184.216.34:443"
sandbox: process 12345 (curl): network-outbound to "5.6.7.8:80"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("curl", []string{"https://example.com"})
	for i := 1; i < len(policy.AllowPorts); i++ {
		if policy.AllowPorts[i] < policy.AllowPorts[i-1] {
			t.Errorf("ports should be sorted: %d < %d at indices %d, %d",
				policy.AllowPorts[i], policy.AllowPorts[i-1], i-1, i)
		}
	}
}

func TestParseTraceFile_NetworkNoPort(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (curl): network-outbound to "93.184.216.34"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("curl", []string{"https://example.com"})
	if len(policy.AllowIPs) != 1 {
		t.Errorf("expected 1 IP, got %d", len(policy.AllowIPs))
	}
	if policy.AllowIPs[0] != "93.184.216.34" {
		t.Errorf("IP: got %q, want %q", policy.AllowIPs[0], "93.184.216.34")
	}
	if len(policy.AllowPorts) != 0 {
		t.Errorf("expected 0 ports (no port in trace), got %d", len(policy.AllowPorts))
	}
}

func TestParseTraceFile_NetworkPortOnly(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (curl): network-outbound to ":443"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("curl", []string{"https://example.com"})
	// Should not capture the IP since it's empty after splitting on ":"
	if len(policy.AllowIPs) != 0 {
		t.Errorf("expected 0 IPs (empty IP), got %d: %v", len(policy.AllowIPs), policy.AllowIPs)
	}
}

func TestParseTraceFile_SingleColonIP(t *testing.T) {
	dir := t.TempDir()
	traceFile := filepath.Join(dir, "trace.log")
	content := `sandbox: process 12345 (curl): network-outbound to "93.184.216.34"
`
	if err := os.WriteFile(traceFile, []byte(content), 0o644); err != nil {
		t.Fatalf("write trace file: %v", err)
	}

	p := learnermac.NewTraceParser()
	if err := p.ParseTraceFile(traceFile); err != nil {
		t.Fatalf("ParseTraceFile failed: %v", err)
	}

	policy := p.BuildPolicy("curl", []string{"https://example.com"})
	if len(policy.AllowIPs) != 1 {
		t.Errorf("expected 1 IP, got %d", len(policy.AllowIPs))
	}
	if len(policy.AllowPorts) != 0 {
		t.Errorf("expected 0 ports, got %d", len(policy.AllowPorts))
	}
}
