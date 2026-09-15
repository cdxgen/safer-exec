//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// Linux expanded-encoded dev_t decoding: 8:0 → 2048, NVMe 259:1 → 66305
// under the compact mapping used by `stat`.
func TestUnixMajorMinorDecode(t *testing.T) {
	cases := []struct {
		dev         uint64
		major, minr uint64
	}{
		{0x800, 8, 0},        // SCSI disk 8:0
		{259<<8 | 1, 259, 1}, // NVMe 259:1 (compact form)
		{0, 0, 0},
	}
	for _, tc := range cases {
		if gotMaj := unixMajor(tc.dev); gotMaj != tc.major {
			t.Errorf("unixMajor(%d) = %d, want %d", tc.dev, gotMaj, tc.major)
		}
		if gotMin := unixMinor(tc.dev); gotMin != tc.minr {
			t.Errorf("unixMinor(%d) = %d, want %d", tc.dev, gotMin, tc.minr)
		}
	}
}

func TestIoLimitDevicesUsesWritePathDevices(t *testing.T) {
	dir := t.TempDir()
	cfg := config.ExecConfig{
		WritePaths: []string{dir},
		WorkingDir: dir,
	}
	devices := ioLimitDevices(cfg)
	if len(devices) == 0 {
		t.Fatalf("expected at least one device")
	}
	// The temp dir's backing device must be among them and formatted maj:min.
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	want := fmt.Sprintf("%d:%d", unixMajor(st.Dev), unixMinor(st.Dev))
	found := false
	for _, d := range devices {
		if d == want {
			found = true
		}
	}
	if !found {
		t.Errorf("devices %v missing backing device %q for %s", devices, want, dir)
	}
}

func TestIoLimitDevicesFallback(t *testing.T) {
	// With no resolvable write paths the function must still return a usable
	// device (the legacy 8:0 fallback) so io.max is never written empty —
	// an empty write would silently apply no limits at all. In environments
	// where the process cwd resolves (containers, CI), the real backing
	// device legitimately replaces the fallback, so assert shape.
	cfg := config.ExecConfig{WritePaths: []string{"/definitely/not/a/real/path"}}
	devices := ioLimitDevices(cfg)
	if len(devices) == 0 {
		t.Fatal("expected at least one device")
	}
	deviceRe := regexp.MustCompile(`^\d+:\d+$`)
	for _, d := range devices {
		if !deviceRe.MatchString(d) {
			t.Errorf("device %q not in major:minor form", d)
		}
	}
}

func TestStraceDryRunParsing(t *testing.T) {
	log := filepath.Join(t.TempDir(), "strace.log")
	content := `1234  execve("/usr/bin/curl", ["curl", "https://example.com"], 0x..) = 0
1234  openat(AT_FDCWD, "/etc/ssl/openssl.cnf", O_RDONLY) = 3
1234  openat(AT_FDCWD, "/home/o/project/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EACCES (Permission denied)
1234  openat(AT_FDCWD, "/home/o/project/src/app.js", O_RDONLY) = -1 EACCES (Permission denied)
1234  connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EACCES (Permission denied)
1234  bind(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EACCES (Permission denied)
1234  write(1, "hello", 5) = 5
1234  mmap(NULL, 8192, PROT_READ|PROT_WRITE, ...) = 0x7f..
`
	if err := os.WriteFile(log, []byte(content), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	events := parseStraceDryRunEvents(log)
	result := buildDryRunResult(events, "curl", nil)

	if result.Summary.FileWrites != 1 {
		t.Errorf("file writes = %d, want 1 (O_WRONLY|O_CREAT attempt)", result.Summary.FileWrites)
	}
	if result.Summary.FileReads != 1 {
		t.Errorf("file reads = %d, want 1 (denied read-only open; allowed bootstrap read must not count)", result.Summary.FileReads)
	}
	if result.Summary.NetworkOutbound != 1 {
		t.Errorf("network outbound = %d, want 1", result.Summary.NetworkOutbound)
	}
	if result.Summary.NetworkBind != 1 {
		t.Errorf("network bind = %d, want 1", result.Summary.NetworkBind)
	}
	if result.Summary.ExecAttempts != 1 {
		t.Errorf("exec attempts = %d, want 1", result.Summary.ExecAttempts)
	}

	// Check the connect target details survived.
	var sawConnect bool
	for _, e := range result.Events {
		if e.Type == "network-outbound" {
			sawConnect = true
			if e.Target != "93.184.216.34" || e.Port != 443 {
				t.Errorf("connect event = %+v, want target 93.184.216.34:443", e)
			}
		}
	}
	if !sawConnect {
		t.Errorf("no network-outbound event in report: %+v", result.Events)
	}
}
