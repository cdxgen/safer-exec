package mxc

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

const sampleReport = `{
  "denials": [
    {"resource": "C:\\WINDOWS", "resourceType": "file", "accessType": "write", "pid": 1, "filetime": "1"},
    {"resource": "\\REGISTRY\\USER\\S-1-5-21-1-2-3-1000\\Console", "resourceType": "other", "accessType": "read", "pid": 1, "filetime": "2"},
    {"resource": "ConvertToGui", "resourceType": "ui", "accessType": "unknown", "pid": 1, "filetime": "3"},
    {"resource": "C:\\work\\proj\\ro\\out.txt", "resourceType": "file", "accessType": "write", "pid": 2, "filetime": "4"},
    {"resource": "C:\\secrets\\key.pem", "resourceType": "file", "accessType": "read", "pid": 2, "filetime": "5"},
    {"resource": "C:\\tools\\helper.exe", "resourceType": "file", "accessType": "execute", "pid": 2, "filetime": "6"},
    {"resource": "internetClient", "resourceType": "capability", "accessType": "unknown", "pid": 2, "filetime": "7"},
    {"resource": "93.184.215.14:443", "resourceType": "network", "accessType": "unknown", "pid": 2, "filetime": "8"},
    {"resource": "Handles", "resourceType": "ui", "accessType": "unknown", "pid": 2, "filetime": "9"}
  ],
  "summary": {"exitCode": 1, "totalDenials": 9, "deniedResourcesTruncated": false}
}`

func loadSample(t *testing.T) *DenialReport {
	t.Helper()
	path := filepath.Join(t.TempDir(), "denials.1_a.json")
	if err := os.WriteFile(path, []byte(sampleReport), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ReadDenialReport(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDenialReportBaselineAndAudit(t *testing.T) {
	r := loadSample(t).WithoutBaseline(`C:\Windows`)
	if r.Summary.TotalDenials != 6 || len(r.Denials) != 6 {
		t.Fatalf("baseline not removed: %+v", r.Denials)
	}
	entries := r.AuditEntries()
	want := []config.AuditEntry{
		{Type: "file-write", Target: `C:\work\proj\ro\out.txt`},
		{Type: "file-read", Target: `C:\secrets\key.pem`},
		{Type: "process-exec", Target: `C:\tools\helper.exe`},
		{Type: "capability", Target: "internetClient"},
		{Type: "network-outbound", Target: "93.184.215.14:443"},
		{Type: "ui", Target: "Handles"},
	}
	if len(entries) != len(want) {
		t.Fatalf("entries = %+v", entries)
	}
	for i := range want {
		if entries[i].Type != want[i].Type || entries[i].Target != want[i].Target || entries[i].Detail == "" {
			t.Errorf("entry %d = %+v, want %+v", i, entries[i], want[i])
		}
	}
}

func TestDenialReportDryRunEvents(t *testing.T) {
	events := loadSample(t).WithoutBaseline(`C:\Windows`).DryRunEvents()
	if events[0].Path != `C:\work\proj\ro\out.txt` || events[0].Type != "file-write" {
		t.Errorf("file event = %+v", events[0])
	}
	if events[4].Target != "93.184.215.14" || events[4].Port != 443 || events[4].Type != "network-outbound" {
		t.Errorf("network event = %+v", events[4])
	}
	if events[3].Target != "internetClient" {
		t.Errorf("capability event = %+v", events[3])
	}
}

func TestIsBaselineNoiseIsNarrow(t *testing.T) {
	keep := []Denial{
		{Resource: `C:\Windows\System32\drivers\etc\hosts`, ResourceType: "file", AccessType: "write"},
		{Resource: `C:\Windows`, ResourceType: "file", AccessType: "read"},
		{Resource: `\REGISTRY\USER\S-1\Software`, ResourceType: "other", AccessType: "read"},
		{Resource: "Clipboard", ResourceType: "ui"},
	}
	for _, d := range keep {
		if IsBaselineNoise(d, `C:\Windows`) {
			t.Errorf("%+v classified as noise", d)
		}
	}
}

func TestVerboseSibling(t *testing.T) {
	if got := VerboseSibling(`C:\r\denials.1_ab.json`); got != `C:\r\denials.1_ab.verbose.json` {
		t.Errorf("got %q", got)
	}
	if got := VerboseSibling(`C:\r\denials`); got != `C:\r\denials.verbose.json` {
		t.Errorf("got %q", got)
	}
}

func TestLearnPolicy(t *testing.T) {
	plan := &Plan{
		Program:    `C:\Program Files\nodejs\node.exe`,
		Cwd:        `C:\Users\u\src\app`,
		SystemRoot: `C:\Windows`,
		ReadPaths:  []string{`C:\Program Files\nodejs`, `C:\Users\u\src\app`},
		WritePaths: []string{`C:\Users\u\src\app\node_modules`},
		Request: Request{Process: Process{Env: []string{
			`Path=C:\Windows\system32;C:\Python314;C:\tools\ruby\bin`,
		}}},
	}
	report := &DenialReport{Denials: []Denial{
		// Path-resolution noise: ancestors of working paths, PATH probes,
		// the volume root and the Windows directory.
		{Resource: `C:\`, ResourceType: "file", AccessType: "read"},
		{Resource: `C:\Users\`, ResourceType: "file", AccessType: "read"},
		{Resource: `C:\Users\u\`, ResourceType: "file", AccessType: "read"},
		{Resource: `C:\Python314\`, ResourceType: "file", AccessType: "read"},
		{Resource: `C:\WINDOWS`, ResourceType: "file", AccessType: "write"},
		{Resource: `C:\Windows\Temp\x.tmp`, ResourceType: "file", AccessType: "write"},
		{Resource: `C:\Users\u\AppData\Local\Packages\sandbox.{abc}\AC\Temp\f`, ResourceType: "file", AccessType: "write"},
		// Real needs.
		{Resource: `C:\Users\u\.npmrc`, ResourceType: "file", AccessType: "read"},
		{Resource: `C:\Users\u\src\app\package-lock.json`, ResourceType: "file", AccessType: "write"},
		{Resource: `C:\Users\u\src\app\node_modules\.bin\x.cmd`, ResourceType: "file", AccessType: "execute"},
		{Resource: `C:\data\fixtures\`, ResourceType: "file", AccessType: "read"},
		{Resource: `C:\data\fixtures\a.json`, ResourceType: "file", AccessType: "read"},
		// A directory listing with no learned path beneath it is learned.
		{Resource: `C:\data\listing\`, ResourceType: "file", AccessType: "read"},
		{Resource: "internetClient", ResourceType: "capability"},
	}}
	policy := LearnPolicy(LearnInput{
		Cmd:          "npm",
		Args:         []string{"ci"},
		Report:       report,
		Plan:         plan,
		ProxyTargets: []string{"registry.npmjs.org:443", "REGISTRY.npmjs.org:443", "93.184.215.14:8443", "bad"},
	})
	// The read of C:\data\fixtures\ is the parent of a learned file, i.e.
	// path resolution on the way to it, so only the file is learned.
	wantRead := []string{`C:\data\fixtures\a.json`, `C:\data\listing`, `C:\Program Files\nodejs`, `C:\Users\u\.npmrc`, `C:\Users\u\src\app`}
	if !slices.Equal(policy.ReadPaths, wantRead) {
		t.Errorf("read = %v, want %v", policy.ReadPaths, wantRead)
	}
	wantWrite := []string{`C:\Users\u\src\app\node_modules`, `C:\Users\u\src\app\package-lock.json`}
	if !slices.Equal(policy.WritePaths, wantWrite) {
		t.Errorf("write = %v, want %v", policy.WritePaths, wantWrite)
	}
	if !slices.Equal(policy.AllowHosts, []string{"registry.npmjs.org"}) || !slices.Equal(policy.AllowIPs, []string{"93.184.215.14"}) {
		t.Errorf("hosts %v ips %v", policy.AllowHosts, policy.AllowIPs)
	}
	if !slices.Equal(policy.AllowPorts, []int{443, 8443}) || !policy.ProxyEgress {
		t.Errorf("ports %v proxy %v", policy.AllowPorts, policy.ProxyEgress)
	}
	if policy.Cmd != "npm" || !slices.Equal(policy.Args, []string{"ci"}) {
		t.Errorf("cmd/args = %q %v", policy.Cmd, policy.Args)
	}

	disabled := LearnPolicy(LearnInput{Plan: plan, NetworkDisabled: true, ProxyTargets: []string{"x:443"}})
	if !disabled.DisableNetwork || len(disabled.AllowHosts) != 0 || disabled.ProxyEgress {
		t.Errorf("network-disabled policy = %+v", disabled)
	}
}

func TestCollapsePaths(t *testing.T) {
	got := collapsePaths([]string{`C:\a\b\c`, `c:\A`, `C:\a\b`, `C:\x`, `relative`, `C:\x\`}, []string{`C:\x`})
	if !slices.Equal(got, []string{`C:\A`}) {
		t.Errorf("collapse = %v", got)
	}
}
