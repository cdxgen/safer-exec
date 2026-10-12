package dlltrace

import (
	"slices"
	"testing"
)

const (
	enginePID   = 100
	launcherPID = 200
	vol         = `\Device\HarddiskVolume3`
)

func start(t int64, pid, ppid uint32, image string) Event {
	return Event{Kind: ProcessStart, Time: t, PID: pid, ParentPID: ppid, Image: vol + image}
}

func stop(t int64, pid uint32) Event {
	return Event{Kind: ProcessStop, Time: t, PID: pid}
}

func load(t int64, pid uint32, image string) Event {
	return Event{Kind: ImageLoad, Time: t, PID: pid, Image: vol + image}
}

func paths(loads []Load) []string {
	var out []string
	for _, l := range loads {
		out = append(out, l.Path[len(vol):])
	}
	return out
}

var root = Root{PID: launcherPID, ParentPID: enginePID}

func TestAttributeTracesDescendantsOnly(t *testing.T) {
	events := []Event{
		start(1, launcherPID, enginePID, `\mxc\wxc-exec.exe`),
		load(2, launcherPID, `\mxc\wxc-exec.exe`),
		load(3, launcherPID, `\Windows\System32\bcrypt.dll`), // the launcher's own
		start(4, 300, launcherPID, `\app\node.exe`),
		load(5, 300, `\app\node.exe`), // the process's own executable
		load(6, 300, `\Windows\System32\ntdll.dll`),
		load(7, 300, `\app\addon.node`),
		start(8, 400, 300, `\Windows\System32\cmd.exe`), // grandchild
		load(9, 400, `\Windows\System32\cmdext.dll`),
		load(10, 400, `\Windows\System32\NTDLL.DLL`), // duplicate, other case
		start(11, 500, 999, `\Windows\explorer.exe`), // unrelated process
		load(12, 500, `\Windows\System32\shell32.dll`),
		load(13, 777, `\Windows\System32\unrelated.dll`), // a process older than the session
	}
	got := Attribute(events, root, nil)
	want := []string{`\Windows\System32\ntdll.dll`, `\app\addon.node`, `\Windows\System32\cmdext.dll`}
	if !slices.Equal(paths(got), want) {
		t.Fatalf("loads = %q, want %q", paths(got), want)
	}
	if got[0].PID != 300 || got[0].Process != vol+`\app\node.exe` || got[2].PID != 400 {
		t.Fatalf("attribution = %+v", got)
	}
}

func TestAttributeOrdersByTimestampNotArrival(t *testing.T) {
	// Real-time ETW delivers each CPU's buffer separately: the child's start
	// can arrive after its first loads, and the kernel logs a new process's
	// executable and ntdll.dll mappings before its start event.
	events := []Event{
		load(6, 300, `\app\late.dll`),
		load(4, 300, `\Windows\System32\ntdll.dll`),
		load(3, 300, `\app\tool.exe`),
		start(5, 300, launcherPID, `\app\tool.exe`),
		start(1, launcherPID, enginePID, `\mxc\wxc-exec.exe`),
	}
	got := paths(Attribute(events, root, nil))
	want := []string{`\Windows\System32\ntdll.dll`, `\app\late.dll`}
	if !slices.Equal(got, want) {
		t.Fatalf("loads = %q, want %q", got, want)
	}
}

func TestAttributeDoesNotFollowReusedPIDs(t *testing.T) {
	events := []Event{
		start(1, launcherPID, enginePID, `\mxc\wxc-exec.exe`),
		start(2, 300, launcherPID, `\app\a.exe`),
		load(3, 300, `\app\a.dll`),
		stop(4, 300),
		// PID 300 reused by an unrelated process, which also starts a child.
		start(5, 300, 999, `\Windows\System32\svchost.exe`),
		load(6, 300, `\Windows\System32\svc.dll`),
		start(7, 301, 300, `\Windows\System32\child.exe`),
		load(8, 301, `\Windows\System32\child.dll`),
		// The launcher's PID reused after it exits.
		stop(9, launcherPID),
		start(10, launcherPID, 999, `\other.exe`),
		start(11, 302, launcherPID, `\other-child.exe`),
		load(12, 302, `\other-child.dll`),
	}
	got := paths(Attribute(events, root, nil))
	if want := []string{`\app\a.dll`}; !slices.Equal(got, want) {
		t.Fatalf("loads = %q, want %q", got, want)
	}
}

func TestAttributeLostStopStartsNewLifetime(t *testing.T) {
	events := []Event{
		start(1, launcherPID, enginePID, `\mxc\wxc-exec.exe`),
		start(2, 300, launcherPID, `\app\a.exe`),
		load(3, 300, `\app\a.dll`),
		// The stop for the first PID 300 was lost.
		start(5, 300, 999, `\Windows\System32\svchost.exe`),
		load(6, 300, `\Windows\System32\svc.dll`),
	}
	got := paths(Attribute(events, root, nil))
	if want := []string{`\app\a.dll`}; !slices.Equal(got, want) {
		t.Fatalf("loads = %q, want %q", got, want)
	}
}

func TestAttributeWithoutRootStart(t *testing.T) {
	// The launcher's start was not recorded; its running lifetime is used.
	events := []Event{
		load(1, launcherPID, `\mxc\launcher.dll`),
		start(2, 300, launcherPID, `\app\a.exe`),
		load(3, 300, `\app\a.dll`),
	}
	got := paths(Attribute(events, root, nil))
	if want := []string{`\app\a.dll`}; !slices.Equal(got, want) {
		t.Fatalf("loads = %q, want %q", got, want)
	}
}

func TestAttributeSkipKeepsChildren(t *testing.T) {
	events := []Event{
		start(1, launcherPID, enginePID, `\mxc\wxc-exec.exe`),
		start(2, 300, launcherPID, `\Windows\System32\conhost.exe`),
		load(3, 300, `\Windows\System32\conhostv2.dll`),
		start(4, 301, 300, `\app\b.exe`),
		load(5, 301, `\app\b.dll`),
	}
	skip := func(image string) bool { return image == vol+`\Windows\System32\conhost.exe` }
	got := paths(Attribute(events, root, skip))
	if want := []string{`\app\b.dll`}; !slices.Equal(got, want) {
		t.Fatalf("loads = %q, want %q", got, want)
	}
}

func TestAttributeEmpty(t *testing.T) {
	if got := Attribute(nil, root, nil); len(got) != 0 {
		t.Fatalf("loads = %v", got)
	}
}

func TestWin32Path(t *testing.T) {
	m := NewPathMapper(map[string]string{
		"C:": `\Device\HarddiskVolume3`,
		"D:": `\Device\HarddiskVolume30`,
		"S:": `\??\C:\subst-target`,
	}, `C:\Windows\`)
	cases := map[string]string{
		`\Device\HarddiskVolume3\Windows\System32\ntdll.dll`:                `C:\Windows\System32\ntdll.dll`,
		`\device\harddiskvolume3\x.dll`:                                     `C:\x.dll`,
		`\Device\HarddiskVolume30\tools\a.dll`:                              `D:\tools\a.dll`,
		`\Device\HarddiskVolume3`:                                           `\Device\HarddiskVolume3`,
		`\Device\HarddiskVolume4\unmapped.dll`:                              `\Device\HarddiskVolume4\unmapped.dll`,
		`\SystemRoot\System32\drivers\x.sys`:                                `C:\Windows\System32\drivers\x.sys`,
		`\??\C:\Program Files\a.dll`:                                        `C:\Program Files\a.dll`,
		`\??\UNC\srv\share\a.dll`:                                           `\\srv\share\a.dll`,
		`\Device\Mup\srv\share\a.dll`:                                       `\\srv\share\a.dll`,
		`\Device\Mup\;LanmanRedirector\;Z:0000000000012345\srv\share\a.dll`: `\\srv\share\a.dll`,
		`\Device\LanmanRedirector\;Z:0000000000012345\srv\share\a.dll`:      `\\srv\share\a.dll`,
	}
	for in, want := range cases {
		if got := m.Win32Path(in); got != want {
			t.Errorf("Win32Path(%q) = %q, want %q", in, got, want)
		}
	}
}
