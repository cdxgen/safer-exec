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

	// hmu guards handle against use after Close: operations hold it shared,
	// Close exclusively.
	hmu    sync.RWMutex
	closed bool

	// Notifications go from the completion port into an in-memory queue, so
	// a slow consumer delays them instead of losing them; only a queue past
	// maxQueuedEvents drops (and counts) further notifications.
	qmu      sync.Mutex
	queue    []Event
	pumpDone bool
	dropped  uint64
	wake     chan struct{}

	events chan Event
	done   chan struct{}

	closeOnce sync.Once
}

// maxQueuedEvents bounds the notification backlog (8 bytes each).
const maxQueuedEvents = 1 << 16

var (
	kernel32                      = windows.NewLazySystemDLL("kernel32.dll")
	procSetInformationJobObject   = kernel32.NewProc("SetInformationJobObject")
	procQueryInformationJobObject = kernel32.NewProc("QueryInformationJobObject")
	procIsProcessInJob            = kernel32.NewProc("IsProcessInJob")
)

// setJobInformation and queryJobInformation call the job APIs through
// LazyProc.Call, whose uintptr arguments are //go:uintptrescapes: the
// structures they point to are moved to the heap and kept alive for the
// call. The x/sys wrappers take a plain uintptr, which lets a stack-allocated
// structure move (stack growth) while the kernel still holds its old address.
func setJobInformation(job windows.Handle, class uint32, info unsafe.Pointer, size uintptr) error {
	r, _, err := procSetInformationJobObject.Call(uintptr(job), uintptr(class), uintptr(info), size)
	if r == 0 {
		return err
	}
	return nil
}

func queryJobInformation(job windows.Handle, class uint32, info unsafe.Pointer, size uintptr) error {
	r, _, err := procQueryInformationJobObject.Call(uintptr(job), uintptr(class), uintptr(info), size, 0)
	if r == 0 {
		return err
	}
	return nil
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
	j := &Job{handle: h, events: make(chan Event), done: make(chan struct{}), wake: make(chan struct{}, 1)}

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
	if err := setJobInformation(h, windows.JobObjectExtendedLimitInformation,
		unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("SetInformationJobObject(limits): %w", err)
	}

	if l.CPURate > 0 {
		rate := cpuRateControlInformation{
			ControlFlags: cpuRateControlEnable | cpuRateControlHardCap,
			CPURate:      min(l.CPURate, 10000),
		}
		if err := setJobInformation(h, jobObjectCPURateControl,
			unsafe.Pointer(&rate), unsafe.Sizeof(rate)); err != nil {
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
	if err := setJobInformation(h, windows.JobObjectAssociateCompletionPortInformation,
		unsafe.Pointer(&assoc), unsafe.Sizeof(assoc)); err != nil {
		windows.CloseHandle(port)
		windows.CloseHandle(h)
		return nil, fmt.Errorf("associate job completion port: %w", err)
	}
	j.port = port
	go j.pump()
	go j.deliver()
	return j, nil
}

// Events delivers job notifications, in order, until the job is closed and
// every queued notification has been delivered. Windows itself does not
// guarantee delivery of every job message; see Dropped for losses here.
func (j *Job) Events() <-chan Event { return j.events }

// Dropped reports how many notifications were discarded because the
// consumer fell more than maxQueuedEvents behind.
func (j *Job) Dropped() uint64 {
	j.qmu.Lock()
	defer j.qmu.Unlock()
	return j.dropped
}

func (j *Job) pump() {
	defer close(j.done)
	defer j.signal(true)
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
		j.qmu.Lock()
		if len(j.queue) < maxQueuedEvents {
			j.queue = append(j.queue, ev)
		} else {
			j.dropped++
		}
		j.qmu.Unlock()
		j.signal(false)
	}
}

// signal wakes deliver; final marks the end of the notification stream.
func (j *Job) signal(final bool) {
	if final {
		j.qmu.Lock()
		j.pumpDone = true
		j.qmu.Unlock()
	}
	select {
	case j.wake <- struct{}{}:
	default:
	}
}

// deliver moves queued notifications to the Events channel, closing it once
// the pump has stopped and the queue is empty.
func (j *Job) deliver() {
	defer close(j.events)
	for {
		j.qmu.Lock()
		batch := j.queue
		j.queue = nil
		done := j.pumpDone
		j.qmu.Unlock()
		for _, ev := range batch {
			j.events <- ev
		}
		if done && len(batch) == 0 {
			return
		}
		if len(batch) == 0 {
			<-j.wake
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

// errClosed is returned by operations on a closed job.
var errClosed = errors.New("job object is closed")

// Terminate kills every process in the job with the given exit code.
func (j *Job) Terminate(exitCode uint32) error {
	j.hmu.RLock()
	defer j.hmu.RUnlock()
	if j.closed {
		return errClosed
	}
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
	j.hmu.RLock()
	defer j.hmu.RUnlock()
	if j.closed {
		return nil, errClosed
	}
	return j.processIDs()
}

func (j *Job) processIDs() ([]uint32, error) {
	l := new(processIDList)
	if err := queryJobInformation(j.handle, windows.JobObjectBasicProcessIdList,
		unsafe.Pointer(l), unsafe.Sizeof(*l)); err != nil && err != windows.ERROR_MORE_DATA {
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
	j.hmu.RLock()
	defer j.hmu.RUnlock()
	if j.closed {
		return errClosed
	}
	var lastErr error
	for attempt := range 50 {
		pids, err := j.processIDs()
		if err != nil {
			return err
		}
		remaining := 0
		for _, pid := range pids {
			if pid == keep || isConsoleHostOf(pid, keep) {
				continue
			}
			remaining++
			if err := j.terminateMember(pid, exitCode); err != nil {
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
	j.hmu.RLock()
	defer j.hmu.RUnlock()
	if j.closed {
		return 0, 0, errClosed
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err = queryJobInformation(j.handle, windows.JobObjectExtendedLimitInformation,
		unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		return 0, 0, err
	}
	var basic basicAccountingInformation
	if err = queryJobInformation(j.handle, windows.JobObjectBasicAccountingInformation,
		unsafe.Pointer(&basic), unsafe.Sizeof(basic)); err != nil {
		return uint64(info.PeakJobMemoryUsed), 0, err
	}
	return uint64(info.PeakJobMemoryUsed), basic.TotalProcesses, nil
}

// basicAndIoAccountingInformation is
// JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION.
type basicAndIoAccountingInformation struct {
	Basic basicAccountingInformation
	IO    windows.IO_COUNTERS
}

// Usage returns the CPU time (user plus kernel, in microseconds) and the IO
// bytes (read, write and other transfers) that every process of the job has
// used so far, including processes that have already exited.
func (j *Job) Usage() (cpuUsec, ioBytes uint64, err error) {
	j.hmu.RLock()
	defer j.hmu.RUnlock()
	if j.closed {
		return 0, 0, errClosed
	}
	var info basicAndIoAccountingInformation
	if err = queryJobInformation(j.handle, windows.JobObjectBasicAndIoAccountingInformation,
		unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		return 0, 0, err
	}
	cpu := uint64(info.Basic.TotalUserTime+info.Basic.TotalKernelTime) / 10
	io := info.IO.ReadTransferCount + info.IO.WriteTransferCount + info.IO.OtherTransferCount
	return cpu, io, nil
}

// isConsoleHostOf reports whether pid is the console host (conhost.exe) the
// OS created for parent; killing it would take the parent down with it.
func isConsoleHostOf(pid, parent uint32) bool {
	return ParentPID(pid) == parent && strings.EqualFold(filepath.Base(ProcessImage(pid)), "conhost.exe")
}

// terminateMember terminates pid if, once opened, it is still a member of
// the job: between listing the job and opening the process its id can be
// reused by an unrelated process. A process that has already exited, or is
// exiting (TerminateProcess then fails with ERROR_ACCESS_DENIED), counts as
// terminated.
func (j *Job) terminateMember(pid uint32, exitCode uint32) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE|processQueryLimited, false, pid)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil // already gone
		}
		return err
	}
	defer windows.CloseHandle(h)
	if !j.contains(h) {
		return nil // the id now belongs to a process outside the job
	}
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

// contains reports whether the process behind h belongs to the job
// (including nested jobs).
func (j *Job) contains(h windows.Handle) bool {
	var in int32 // BOOL
	r, _, _ := procIsProcessInJob.Call(uintptr(h), uintptr(j.handle), uintptr(unsafe.Pointer(&in)))
	return r != 0 && in != 0
}

// Describe returns the image path and parent id of a process that is still a
// member of the job. ok is false when the process has exited or its id now
// belongs to a process outside the job.
func (j *Job) Describe(pid uint32) (image string, ppid uint32, ok bool) {
	j.hmu.RLock()
	defer j.hmu.RUnlock()
	if j.closed {
		return "", 0, false
	}
	h, err := windows.OpenProcess(processQueryLimited, false, pid)
	if err != nil {
		return "", 0, false
	}
	defer windows.CloseHandle(h)
	if !j.contains(h) {
		return "", 0, false
	}
	image = imageOf(h)
	return image, parentOf(h), image != ""
}

// Close releases the job. Any process still inside is killed
// (KILL_ON_JOB_CLOSE). It is safe to call more than once, and concurrently
// with the job's other methods, which then report errClosed.
func (j *Job) Close() error {
	var err error
	j.closeOnce.Do(func() {
		j.hmu.Lock()
		j.closed = true
		err = windows.CloseHandle(j.handle)
		j.hmu.Unlock()
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
	return imageOf(h)
}

func imageOf(h windows.Handle) string {
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
	return parentOf(h)
}

func parentOf(h windows.Handle) uint32 {
	var pbi windows.PROCESS_BASIC_INFORMATION
	var ret uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &ret); err != nil {
		return 0
	}
	return uint32(pbi.InheritedFromUniqueProcessId)
}
