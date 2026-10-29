//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

func TestEgressNotifyProgramShape(t *testing.T) {
	prog := egressNotifyProgram()
	for i, ins := range prog {
		if ins.Code == bpfJmpReturn {
			continue
		}
		if ins.Code&0x07 == 0x05 { // BPF_JMP
			for _, off := range []uint8{ins.Jt, ins.Jf} {
				if i+1+int(off) >= len(prog) {
					t.Fatalf("instruction %d jumps past the end", i)
				}
			}
		}
	}
	if last := prog[len(prog)-1]; last.Code != bpfJmpReturn || last.K != seccompRetUserNotif {
		t.Fatalf("last instruction = %+v", last)
	}
}

func TestParseSockaddr(t *testing.T) {
	v4 := []byte{2, 0, 0, 53, 8, 8, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0}
	if dest, lo, port, ok := parseSockaddr(v4); !ok || dest != "8.8.4.4:53" || lo || port != 53 {
		t.Fatalf("v4 = %q %v %d %v", dest, lo, port, ok)
	}
	v6 := make([]byte, 28)
	v6[0] = 10
	v6[3] = 0xbb
	v6[23] = 1
	v6[2] = 0x01
	if dest, lo, _, ok := parseSockaddr(v6); !ok || dest != "[::1]:443" || !lo {
		t.Fatalf("v6 = %q %v %v", dest, lo, ok)
	}
	if _, _, _, ok := parseSockaddr([]byte{1, 0, 'x'}); ok {
		t.Fatal("AF_UNIX parsed as an IP destination")
	}
}

// bashPath returns bash, whose /dev/udp and /dev/tcp redirections make
// sockets without any other tool.
func bashPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	return p
}

// An audited proxy-egress run records UDP and direct TCP that leave outside
// the proxy, and the command still runs to completion.
func TestEgressWatchRecordsBypassAttempts(t *testing.T) {
	if !egressNotifySupported() {
		t.Skip("kernel lacks SECCOMP_USER_NOTIF_FLAG_CONTINUE")
	}
	bash := bashPath(t)
	cfg := config.ExecConfig{
		Cmd:         bash,
		Args:        []string{"-c", "echo x > /dev/udp/192.0.2.1/53; (echo > /dev/tcp/192.0.2.1/443) 2>/dev/null; echo done"},
		ReadPaths:   baseReadPaths(),
		ProxyEgress: true,
		AllowHosts:  []string{"example.com"},
		EnableAudit: true,
	}
	stdout, stderr, _ := runSandbox(t, cfg)
	if !strings.Contains(stdout, "done") {
		t.Fatalf("command did not finish: stdout=%q", stdout)
	}
	if strings.Contains(stderr, "egress watch:") {
		t.Skipf("egress watch unavailable here: %s", stderr)
	}
	for _, want := range []string{`"type":"proxy-bypass-attempt"`, `"target":"udp 192.0.2.1:53"`, `192.0.2.1:443"`} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %s in audit output", want)
		}
	}
}

// Without audit, or without the proxy, no watch is installed.
func TestEgressWatchOnlyForAuditedProxyRuns(t *testing.T) {
	if w := prepareEgressWatch(config.ExecConfig{EnableAudit: true}, 0); w != nil {
		t.Fatal("watch without a proxy")
	}
	if w := prepareEgressWatch(config.ExecConfig{}, 4321); w != nil {
		t.Fatal("watch without audit")
	}
	if w := prepareEgressWatch(config.ExecConfig{EnableAudit: true, DisableNetwork: true}, 4321); w != nil {
		t.Fatal("watch with the network disabled")
	}
}

func TestReadCgroupUsage(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cpu.stat"), []byte("usage_usec 1500\nuser_usec 1000\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "io.stat"), []byte("8:0 rbytes=100 wbytes=50 rios=1 wios=1\n259:0 rbytes=10 wbytes=5\n"), 0o644)
	cpu, io, ok := readCgroupUsage(dir)
	if !ok || cpu != 1500 || io != 165 {
		t.Fatalf("usage = %d %d %v", cpu, io, ok)
	}
	if _, _, ok := readCgroupUsage(filepath.Join(dir, "missing")); ok {
		t.Fatal("a missing cgroup read as ok")
	}
}

// An audited run alternating CPU bursts with sleep is reported as a timing
// channel suspect, and the sampling cgroup is removed afterwards.
func TestCgroupWatchReportsKeyedCPU(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 15 s")
	}
	parent := ownCgroupDir()
	if parent == "" || unix.Access(parent, unix.W_OK) != nil {
		t.Skip("no writable cgroup v2 directory")
	}
	bash := bashPath(t)
	cfg := config.ExecConfig{
		Cmd:         bash,
		Args:        []string{"-c", "for i in $(seq 70); do timeout 0.1 sh -c 'while :; do :; done'; sleep 0.1; done; echo done"},
		ReadPaths:   baseReadPaths(),
		EnableAudit: true,
	}
	stdout, stderr, _ := runSandbox(t, cfg)
	if !strings.Contains(stdout, "done") {
		t.Fatalf("command did not finish: stdout=%q", stdout)
	}
	if strings.Contains(stderr, "cgroup v2 not available") {
		t.Skip("cgroup not delegated")
	}
	if !strings.Contains(stderr, `"type":"timing-channel-suspect"`) || !strings.Contains(stderr, `"target":"cpu"`) {
		t.Errorf("no cpu timing-channel-suspect entry")
	}
	prefix := fmt.Sprintf("safer-exec-%d-", os.Getpid())
	entries, _ := os.ReadDir(parent)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			t.Errorf("sampling cgroup %s left behind", e.Name())
		}
	}
}
