//go:build windows

package dlltrace

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The test binary doubles as the traced programs: DLLTRACE_TEST_ROLE=spawn
// starts a copy of itself with role load, which loads the DLL named in
// DLLTRACE_TEST_DLL.
func TestMain(m *testing.M) {
	switch os.Getenv("DLLTRACE_TEST_ROLE") {
	case "spawn":
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), "DLLTRACE_TEST_ROLE=load")
		c.Stdout, c.Stderr = os.Stdout, os.Stderr
		if err := c.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "spawn:", err)
			os.Exit(3)
		}
		os.Exit(0)
	case "load":
		h, err := windows.LoadLibrary(os.Getenv("DLLTRACE_TEST_DLL"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "load:", err)
			os.Exit(4)
		}
		windows.FreeLibrary(h)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func startOrSkip(t *testing.T) *Session {
	t.Helper()
	s, err := Start()
	if errors.Is(err, ErrAccessDenied) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStructLayouts(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("layouts are checked on 64-bit Windows")
	}
	for name, got := range map[string]uintptr{
		"EVENT_TRACE_PROPERTIES": unsafe.Sizeof(eventTraceProperties{}),
		"EVENT_HEADER":           unsafe.Sizeof(eventHeader{}),
		"EVENT_RECORD":           unsafe.Sizeof(eventRecord{}),
		"EVENT_TRACE":            unsafe.Sizeof(eventTrace{}),
		"TRACE_LOGFILE_HEADER":   unsafe.Sizeof(traceLogfileHeader{}),
		"EVENT_TRACE_LOGFILEW":   unsafe.Sizeof(eventTraceLogfile{}),
	} {
		want := map[string]uintptr{
			"EVENT_TRACE_PROPERTIES": 120, "EVENT_HEADER": 80, "EVENT_RECORD": 112,
			"EVENT_TRACE": 88, "TRACE_LOGFILE_HEADER": 280, "EVENT_TRACE_LOGFILEW": 448,
		}[name]
		if got != want {
			t.Errorf("sizeof(%s) = %d, want %d", name, got, want)
		}
	}
	if off := unsafe.Offsetof(eventTraceLogfile{}.EventRecordCallback); off != 424 {
		t.Errorf("EventRecordCallback offset = %d, want 424", off)
	}
}

// copyDLL copies a system DLL to a uniquely named file, so only the traced
// grandchild can load anything at that path.
func copyDLL(t *testing.T) string {
	t.Helper()
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(filepath.Join(root, "System32", "version.dll"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst := filepath.Join(t.TempDir(), "dlltrace-probe.dll")
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, src); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestSessionTracesDescendants(t *testing.T) {
	dll := copyDLL(t)
	s := startOrSkip(t)
	defer s.Stop()

	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(), "DLLTRACE_TEST_ROLE=spawn", "DLLTRACE_TEST_DLL="+dll)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("traced program failed: %v\n%s", err, out)
	}
	res := s.Stop()
	if res.Err != nil || res.StoppedEarly {
		t.Fatalf("stop: err=%v early=%v", res.Err, res.StoppedEarly)
	}
	t.Logf("%d events recorded, %d lost", len(res.Events), res.Lost)

	loads := Attribute(res.Events, Root{PID: uint32(c.Process.Pid), ParentPID: uint32(os.Getpid())}, nil)
	mapper := SystemPathMapper()
	want, err := os.Stat(dll)
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	found, sawNtdll := false, false
	for _, l := range loads {
		p := mapper.Win32Path(l.Path)
		if l.PID == uint32(c.Process.Pid) {
			t.Errorf("the root's own load was reported: %s", p)
		}
		if strings.EqualFold(p, self) {
			t.Errorf("a process's own executable was reported: %s", p)
		}
		if strings.EqualFold(filepath.Base(p), "ntdll.dll") {
			sawNtdll = true
		}
		if fi, err := os.Stat(p); err == nil && os.SameFile(fi, want) {
			found = true
		}
	}
	if !found || !sawNtdll {
		for _, l := range loads {
			t.Logf("load: %s (pid %d, %s)", mapper.Win32Path(l.Path), l.PID, l.Process)
		}
		t.Fatalf("grandchild's DLL reported: %v, ntdll.dll reported: %v", found, sawNtdll)
	}
}

func TestEventsBeforeConsumerAreDelivered(t *testing.T) {
	// Start relies on a real-time session holding its buffers until the
	// consumer connects; check it by connecting only after the program ran.
	if err := Probe(); errors.Is(err, ErrAccessDenied) {
		t.Skip(err)
	}
	dll := copyDLL(t)
	s, err := newSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.enable(); err != nil {
		s.abort()
		t.Fatal(err)
	}
	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(), "DLLTRACE_TEST_ROLE=load", "DLLTRACE_TEST_DLL="+dll)
	if out, err := c.CombinedOutput(); err != nil {
		s.abort()
		t.Fatalf("traced program failed: %v\n%s", err, out)
	}
	if err := s.consume(); err != nil {
		s.abort()
		t.Fatal(err)
	}
	if err := s.waitReady(); err != nil {
		s.abort()
		t.Fatal(err)
	}
	res := s.Stop()
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	mapper := SystemPathMapper()
	want, _ := os.Stat(dll)
	for _, e := range res.Events {
		if e.Kind != ImageLoad || e.PID != uint32(c.Process.Pid) {
			continue
		}
		if fi, err := os.Stat(mapper.Win32Path(e.Image)); err == nil && os.SameFile(fi, want) {
			return
		}
	}
	t.Fatalf("the load logged before the consumer connected was not delivered (%d events)", len(res.Events))
}

func TestStopIsIdempotent(t *testing.T) {
	s := startOrSkip(t)
	first := s.Stop()
	second := s.Stop()
	if first.Err != nil || second.Err != nil || len(first.Events) != len(second.Events) {
		t.Fatalf("first=%+v second=%+v", first.Err, second.Err)
	}
}

func TestStopReportsSessionStoppedByOthers(t *testing.T) {
	s := startOrSkip(t)
	if err := controlTrace(0, s.namePtr, newProperties(), controlStop); err != nil {
		t.Fatal(err)
	}
	// Let the consumer see the end of the session.
	if err := <-s.done; err != nil && !errors.Is(err, windows.ERROR_CANCELLED) {
		t.Logf("consumer ended with %v", err)
	}
	s.done <- nil
	if res := s.Stop(); !res.StoppedEarly {
		t.Fatalf("StoppedEarly = false: %+v", res)
	}
}

func TestStaleSessionsAreStopped(t *testing.T) {
	if err := Probe(); errors.Is(err, ErrAccessDenied) {
		t.Skip(err)
	}
	// A session named for a process that has exited.
	c := exec.Command(os.Args[0], "-test.run=^$")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(c.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	created, err := processCreationTime(h)
	windows.CloseHandle(h)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Wait()
	stale := fmt.Sprintf("%s%d-%x-1", sessionPrefix, c.Process.Pid, created)
	live, _ := sessionName()

	for _, name := range []string{stale, live} {
		p := newProperties()
		p.Wnode.Flags = wnodeFlagTracedGUID
		p.LogFileMode = eventTraceRealTimeMode
		ptr, _ := windows.UTF16PtrFromString(name)
		var handle uint64
		r, _, _ := procStartTraceW.Call(uintptr(unsafe.Pointer(&handle)), uintptr(unsafe.Pointer(ptr)), uintptr(unsafe.Pointer(p)))
		if r != 0 {
			t.Fatalf("start %s: %v", name, windows.Errno(r))
		}
	}
	defer func() {
		ptr, _ := windows.UTF16PtrFromString(live)
		_ = controlTrace(0, ptr, newProperties(), controlStop)
	}()

	stopStaleSessions()
	exists := func(name string) bool {
		ptr, _ := windows.UTF16PtrFromString(name)
		return controlTrace(0, ptr, newProperties(), 0) == nil
	}
	if exists(stale) {
		t.Errorf("stale session %s still running", stale)
		ptr, _ := windows.UTF16PtrFromString(stale)
		_ = controlTrace(0, ptr, newProperties(), controlStop)
	}
	if !exists(live) {
		t.Errorf("live session %s was stopped", live)
	}
}

func TestProbe(t *testing.T) {
	err := Probe()
	if errors.Is(err, ErrAccessDenied) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestSystemPathMapperMapsSystemRoot(t *testing.T) {
	root, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	m := SystemPathMapper()
	drive := root[:2]
	var dev [windows.MAX_PATH]uint16
	name, _ := windows.UTF16PtrFromString(drive)
	n, err := windows.QueryDosDevice(name, &dev[0], uint32(len(dev)))
	if err != nil {
		t.Fatal(err)
	}
	kernel := windows.UTF16ToString(dev[:n]) + root[2:] + `\System32\ntdll.dll`
	if got, want := m.Win32Path(kernel), root+`\System32\ntdll.dll`; !strings.EqualFold(got, want) {
		t.Fatalf("Win32Path(%q) = %q, want %q", kernel, got, want)
	}
}
