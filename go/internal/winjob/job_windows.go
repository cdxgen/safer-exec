//go:build windows

// Package winjob wraps the Windows job objects the safer-exec engine uses to
// contain the MXC launcher and, through job nesting, every process of the
// sandboxed workload.
//
// wxc-exec.exe creates the workload with CreateProcessW from inside the job
// and then assigns it to its own job, which Windows nests under ours. Limits
// set on the outer job (committed memory, active process count, CPU rate)
// therefore apply to the whole workload tree, and JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
// tears the tree down if the engine itself dies.
package winjob

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Limits are the job-wide limits. Zero values mean "no limit".
type Limits struct {
	// MemoryBytes caps the committed memory of all processes in the job.
	MemoryBytes uint64
	// CPURate is a hard CPU cap in hundredths of a percent (1..10000) of
	// total machine CPU time.
	CPURate uint32
	// ActiveProcesses caps the number of live processes in the job.
	ActiveProcesses uint32
}

// Job message identifiers (JOB_OBJECT_MSG_*), delivered through the job's
// completion port.
const (
	MsgEndOfJobTime          = 1
	MsgEndOfProcessTime      = 2
	MsgActiveProcessLimit    = 3
	MsgActiveProcessZero     = 4
	MsgNewProcess            = 6
	MsgExitProcess           = 7
	MsgAbnormalExitProcess   = 8
	MsgProcessMemoryLimit    = 9
	MsgJobMemoryLimit        = 10
	MsgNotificationLimit     = 11
	MsgJobCycleTimeLimit     = 12
	MsgSiloTerminated        = 13
	jobObjectCPURateControl  = 15 // JobObjectCpuRateControlInformation
	cpuRateControlEnable     = 0x1
	cpuRateControlHardCap    = 0x4
	quitCompletionKey        = ^uintptr(0)
	jobCompletionKey         = 1
	threadSuspendResume      = 0x0002
	processQueryLimited      = windows.PROCESS_QUERY_LIMITED_INFORMATION
	jobLimitDieOnUnhandledEx = 0x400 // JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
)

// Event is a job notification.
type Event struct {
	// Message is one of the Msg* constants.
	Message uint32
	// PID is the process the message refers to, when it has one.
	PID uint32
}

// Job is a Windows job object with an attached completion port.
type Job struct {
	handle windows.Handle
	port   windows.Handle

	events chan Event
	done   chan struct{}

	closeOnce sync.Once
}

type cpuRateControlInformation struct {
	ControlFlags uint32
	CPURate      uint32
}

// basicAccountingInformation is JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.
type basicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

type associateCompletionPort struct {
	CompletionKey  uintptr
	CompletionPort windows.Handle
}

// New creates a job with the given limits. The job kills every process it
// contains when its last handle is closed.
func New(l Limits) (*Job, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	j := &Job{handle: h, events: make(chan Event, 256), done: make(chan struct{})}

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | jobLimitDieOnUnhandledEx
	if l.ActiveProcesses > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = l.ActiveProcesses
	}
	if l.MemoryBytes > 0 {
		info.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		info.JobMemoryLimit = uintptr(l.MemoryBytes)
	}
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("SetInformationJobObject(limits): %w", err)
	}

	if l.CPURate > 0 {
		rate := cpuRateControlInformation{
			ControlFlags: cpuRateControlEnable | cpuRateControlHardCap,
			CPURate:      min(l.CPURate, 10000),
		}
		if _, err := windows.SetInformationJobObject(h, jobObjectCPURateControl,
			uintptr(unsafe.Pointer(&rate)), uint32(unsafe.Sizeof(rate))); err != nil {
			windows.CloseHandle(h)
			return nil, fmt.Errorf("SetInformationJobObject(cpu rate): %w", err)
		}
	}

	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("CreateIoCompletionPort: %w", err)
	}
	assoc := associateCompletionPort{CompletionKey: jobCompletionKey, CompletionPort: port}
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&assoc)), uint32(unsafe.Sizeof(assoc))); err != nil {
		windows.CloseHandle(port)
		windows.CloseHandle(h)
		return nil, fmt.Errorf("associate job completion port: %w", err)
	}
	j.port = port
	go j.pump()
	return j, nil
}

// Events delivers job notifications until the job is closed. The channel is
// buffered; notifications are dropped rather than blocking the pump if the
// consumer falls behind.
func (j *Job) Events() <-chan Event { return j.events }

func (j *Job) pump() {
	defer close(j.done)
	defer close(j.events)
	for {
		var msg uint32
		var key uintptr
		var ov *windows.Overlapped
		if err := windows.GetQueuedCompletionStatus(j.port, &msg, &key, &ov, windows.INFINITE); err != nil {
			return
		}
		if key == quitCompletionKey {
			return
		}
		if key != jobCompletionKey {
			continue
		}
		// For job messages the OVERLAPPED pointer slot carries the process id.
		ev := Event{Message: msg, PID: uint32(uintptr(unsafe.Pointer(ov)))}
		select {
		case j.events <- ev:
		default:
		}
	}
}

// Start launches cmd inside the job. The process is created suspended,
// assigned to the job, and only then resumed, so neither it nor any child can
// run outside the job's limits.
func (j *Job) Start(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := uint32(cmd.Process.Pid)
	fail := func(err error) error {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return err
	}
	ph, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fail(fmt.Errorf("OpenProcess(%d): %w", pid, err))
	}
	defer windows.CloseHandle(ph)
	if err := windows.AssignProcessToJobObject(j.handle, ph); err != nil {
		return fail(fmt.Errorf("AssignProcessToJobObject: %w", err))
	}
	if err := resumeProcess(pid); err != nil {
		return fail(fmt.Errorf("resume %d: %w", pid, err))
	}
	return nil
}

// resumeProcess resumes every thread of a process created suspended. A new
// process has exactly one (its initial) thread.
func resumeProcess(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snap)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	resumed := 0
	for err = windows.Thread32First(snap, &te); err == nil; err = windows.Thread32Next(snap, &te) {
		if te.OwnerProcessID != pid {
			continue
		}
		th, oerr := windows.OpenThread(threadSuspendResume, false, te.ThreadID)
		if oerr != nil {
			return oerr
		}
		_, rerr := windows.ResumeThread(th)
		windows.CloseHandle(th)
		if rerr != nil {
			return rerr
		}
		resumed++
	}
	if resumed == 0 {
		return errors.New("no threads found")
	}
	return nil
}

// Terminate kills every process in the job with the given exit code.
func (j *Job) Terminate(exitCode uint32) error {
	return windows.TerminateJobObject(j.handle, exitCode)
}

// processIDList is JOBOBJECT_BASIC_PROCESS_ID_LIST with room for a bounded
// number of entries.
type processIDList struct {
	NumberOfAssignedProcesses uint32
	NumberOfProcessIdsInList  uint32
	ProcessIDList             [1024]uintptr
}

// ProcessIDs returns the processes currently in the job, including those of
// nested jobs.
func (j *Job) ProcessIDs() ([]uint32, error) {
	var l processIDList
	if err := windows.QueryInformationJobObject(j.handle, windows.JobObjectBasicProcessIdList,
		uintptr(unsafe.Pointer(&l)), uint32(unsafe.Sizeof(l)), nil); err != nil && err != windows.ERROR_MORE_DATA {
		return nil, err
	}
	n := min(int(l.NumberOfProcessIdsInList), len(l.ProcessIDList))
	out := make([]uint32, 0, n)
	for i := range n {
		out = append(out, uint32(l.ProcessIDList[i]))
	}
	return out, nil
}

// TerminateExcept kills every process in the job except keep and keep's own
// console host, repeating until none remain (a dying parent can still have
// started a child). Leaving the launcher alive lets it observe the
// workload's exit and run its own teardown.
func (j *Job) TerminateExcept(keep uint32, exitCode uint32) error {
	var lastErr error
	for attempt := range 50 {
		pids, err := j.ProcessIDs()
		if err != nil {
			return err
		}
		remaining := 0
		for _, pid := range pids {
			if pid == keep || isConsoleHostOf(pid, keep) {
				continue
			}
			remaining++
			if err := terminateProcess(pid, exitCode); err != nil {
				lastErr = err
			}
		}
		if remaining == 0 {
			return nil
		}
		if attempt > 0 {
			// Processes that are already exiting stay in the job's list
			// until the kernel finishes tearing them down.
			time.Sleep(20 * time.Millisecond)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("processes are still running in the job")
	}
	return lastErr
}

// Accounting returns the job's peak committed memory and total process
// count so far.
func (j *Job) Accounting() (peakJobMemory uint64, totalProcesses uint32, err error) {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err = windows.QueryInformationJobObject(j.handle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		return 0, 0, err
	}
	var basic basicAccountingInformation
	if err = windows.QueryInformationJobObject(j.handle, windows.JobObjectBasicAccountingInformation,
		uintptr(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)), nil); err != nil {
		return uint64(info.PeakJobMemoryUsed), 0, err
	}
	return uint64(info.PeakJobMemoryUsed), basic.TotalProcesses, nil
}

// isConsoleHostOf reports whether pid is the console host (conhost.exe) the
// OS created for parent; killing it would take the parent down with it.
func isConsoleHostOf(pid, parent uint32) bool {
	return ParentPID(pid) == parent && strings.EqualFold(filepath.Base(ProcessImage(pid)), "conhost.exe")
}

// terminateProcess terminates pid. A process that has already exited, or is
// exiting (TerminateProcess then fails with ERROR_ACCESS_DENIED), counts as
// terminated.
func terminateProcess(pid uint32, exitCode uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil // already gone
		}
		return err
	}
	defer windows.CloseHandle(h)
	terr := windows.TerminateProcess(h, exitCode)
	if terr == nil {
		return nil
	}
	if ev, _ := windows.WaitForSingleObject(h, 0); ev == windows.WAIT_OBJECT_0 {
		return nil
	}
	if errors.Is(terr, windows.ERROR_ACCESS_DENIED) {
		// Exiting but not yet signalled; the caller re-checks the job.
		return nil
	}
	return terr
}

// Close releases the job. Any process still inside is killed
// (KILL_ON_JOB_CLOSE). It is safe to call more than once.
func (j *Job) Close() error {
	var err error
	j.closeOnce.Do(func() {
		err = windows.CloseHandle(j.handle)
		if j.port != 0 {
			_ = windows.PostQueuedCompletionStatus(j.port, 0, quitCompletionKey, nil)
			<-j.done
			_ = windows.CloseHandle(j.port)
		}
	})
	return err
}

// ProcessImage returns the full image path of a running process, or "" when
// the process has already exited or cannot be opened.
func ProcessImage(pid uint32) string {
	h, err := windows.OpenProcess(processQueryLimited, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// ParentPID returns the parent process id of a running process, or 0.
func ParentPID(pid uint32) uint32 {
	h, err := windows.OpenProcess(processQueryLimited, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	var pbi windows.PROCESS_BASIC_INFORMATION
	var ret uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &ret); err != nil {
		return 0
	}
	return uint32(pbi.InheritedFromUniqueProcessId)
}
