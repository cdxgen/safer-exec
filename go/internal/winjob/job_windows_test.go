//go:build windows

package winjob

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The test binary doubles as the workload: WINJOB_TEST_HELPER selects a role.
func TestMain(m *testing.M) {
	switch os.Getenv("WINJOB_TEST_HELPER") {
	case "":
		os.Exit(m.Run())
	case "exit":
		code, _ := strconv.Atoi(os.Getenv("WINJOB_TEST_ARG"))
		os.Exit(code)
	case "spawn":
		// Start one child and report whether that succeeded.
		c := exec.Command(os.Args[0])
		c.Env = append(os.Environ(), "WINJOB_TEST_HELPER=sleep", "WINJOB_TEST_ARG=1")
		if err := c.Start(); err != nil {
			os.Exit(3)
		}
		_ = c.Wait()
		os.Exit(0)
	case "sleep":
		s, _ := strconv.Atoi(os.Getenv("WINJOB_TEST_ARG"))
		time.Sleep(time.Duration(s) * time.Second)
		os.Exit(0)
	case "alloc":
		// Commit memory with VirtualAlloc until the job refuses, then wait to
		// be killed. (A Go heap allocation failure aborts the process, which
		// would race the test's own termination.)
		mb, _ := strconv.Atoi(os.Getenv("WINJOB_TEST_ARG"))
		for range mb {
			// The job limit applies to committed memory, so committing is
			// enough; the pages need not be touched.
			if _, err := windows.VirtualAlloc(0, 1<<20, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE); err != nil {
				time.Sleep(time.Minute)
				os.Exit(4)
			}
		}
		os.Exit(0)
	}
	os.Exit(99)
}

func helper(role, arg string) *exec.Cmd {
	c := exec.Command(os.Args[0])
	c.Env = append(os.Environ(), "WINJOB_TEST_HELPER="+role, "WINJOB_TEST_ARG="+arg)
	return c
}

func TestStartRunsInsideJob(t *testing.T) {
	j, err := New(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	c := helper("sleep", "2")
	if err := j.Start(c); err != nil {
		t.Fatal(err)
	}
	pids, err := j.ProcessIDs()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pids {
		if p == uint32(c.Process.Pid) {
			found = true
		}
	}
	if !found {
		t.Fatalf("process %d not in job %v", c.Process.Pid, pids)
	}
	if img := ProcessImage(uint32(c.Process.Pid)); !strings.EqualFold(filepath.Base(img), filepath.Base(os.Args[0])) {
		t.Errorf("ProcessImage = %q", img)
	}
	if ppid := ParentPID(uint32(c.Process.Pid)); ppid != uint32(os.Getpid()) {
		t.Errorf("ParentPID = %d, want %d", ppid, os.Getpid())
	}
	if img, ppid, ok := j.Describe(uint32(c.Process.Pid)); !ok || ppid != uint32(os.Getpid()) || !strings.EqualFold(filepath.Base(img), filepath.Base(os.Args[0])) {
		t.Errorf("Describe(member) = %q %d %v", img, ppid, ok)
	}
	// A process outside the job (this test) is never described or killed
	// through the job, even when its id is offered.
	if _, _, ok := j.Describe(uint32(os.Getpid())); ok {
		t.Error("Describe accepted a process outside the job")
	}
	if err := j.terminateMember(uint32(os.Getpid()), 1); err != nil {
		t.Errorf("terminateMember(outsider) = %v", err)
	}
	if err := j.Terminate(42); err != nil {
		t.Fatal(err)
	}
	_ = c.Wait()
	if c.ProcessState.ExitCode() != 42 {
		t.Errorf("exit code = %d, want 42", c.ProcessState.ExitCode())
	}
}

func TestExitCodePropagates(t *testing.T) {
	j, err := New(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	c := helper("exit", "7")
	if err := j.Start(c); err != nil {
		t.Fatal(err)
	}
	var ee *exec.ExitError
	if err := c.Wait(); !errors.As(err, &ee) || ee.ExitCode() != 7 {
		t.Fatalf("wait = %v", err)
	}
}

func TestActiveProcessLimitAndEvents(t *testing.T) {
	j, err := New(Limits{ActiveProcesses: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	c := helper("spawn", "")
	if err := j.Start(c); err != nil {
		t.Fatal(err)
	}
	_ = c.Wait()
	if code := c.ProcessState.ExitCode(); code != 3 {
		t.Errorf("child creation was not refused (exit %d)", code)
	}
	var sawNew, sawLimit bool
	timeout := time.After(5 * time.Second)
	for !(sawNew && sawLimit) {
		select {
		case ev := <-j.Events():
			switch ev.Message {
			case MsgNewProcess:
				sawNew = sawNew || ev.PID == uint32(c.Process.Pid)
			case MsgActiveProcessLimit:
				sawLimit = true
			}
		case <-timeout:
			t.Fatalf("events: new=%v limit=%v", sawNew, sawLimit)
		}
	}
}

func TestMemoryLimitEventAndTerminateExcept(t *testing.T) {
	j, err := New(Limits{MemoryBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	// The memory limit is job-wide, so the process to keep must not allocate
	// while the hog saturates it, and must have no children of its own: an
	// idle cmd.exe blocked in its built-in "set /p" reading stdin.
	keeper := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/d", "/c", "set /p x=")
	keeperIn, err := keeper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer keeperIn.Close()
	if err := j.Start(keeper); err != nil {
		t.Fatal(err)
	}
	hog := helper("alloc", "256")
	if err := j.Start(hog); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-waitFor(j, MsgJobMemoryLimit):
		_ = ev
	case <-time.After(20 * time.Second):
		t.Fatal("no memory-limit notification")
	}
	if err := j.TerminateExcept(uint32(keeper.Process.Pid), 137); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = hog.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("workload not terminated")
	}
	if code := hog.ProcessState.ExitCode(); code != 137 {
		t.Errorf("hog exit = %d, want 137", code)
	}
	pids, err := j.ProcessIDs()
	if err != nil {
		t.Fatal(err)
	}
	kept := false
	for _, p := range pids {
		kept = kept || p == uint32(keeper.Process.Pid)
	}
	if !kept {
		t.Errorf("kept process %d was terminated (job: %v)", keeper.Process.Pid, pids)
	}
	_ = j.Terminate(1)
	_ = keeper.Wait()
}

func waitFor(j *Job, msg uint32) <-chan Event {
	ch := make(chan Event, 1)
	go func() {
		for ev := range j.Events() {
			if ev.Message == msg {
				ch <- ev
				return
			}
		}
	}()
	return ch
}

func TestCloseKillsRemainingProcesses(t *testing.T) {
	j, err := New(Limits{})
	if err != nil {
		t.Fatal(err)
	}
	c := helper("sleep", "60")
	if err := j.Start(c); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("KILL_ON_JOB_CLOSE did not terminate the process")
	}
	if err := j.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := j.Terminate(1); err == nil {
		t.Error("Terminate after Close succeeded")
	}
	// The event stream ends after Close.
	select {
	case _, open := <-j.Events():
		for open {
			_, open = <-j.Events()
		}
	case <-time.After(5 * time.Second):
		t.Error("Events not closed after Close")
	}
	if j.Dropped() != 0 {
		t.Errorf("dropped %d notifications", j.Dropped())
	}
}

func TestCPURateLimitIsAccepted(t *testing.T) {
	j, err := New(Limits{CPURate: 2500, ActiveProcesses: 4, MemoryBytes: 256 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	c := helper("exit", "0")
	if err := j.Start(c); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, total, err := j.Accounting(); err != nil || total < 1 {
		t.Errorf("accounting total=%d err=%v", total, err)
	}
}
