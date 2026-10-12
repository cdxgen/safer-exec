//go:build linux

package main

import "syscall"

// protectReportFd makes the engine non-dumpable, which hands its /proc
// entries to root. A process running as the same user then cannot open the
// report channel through /proc/<engine>/fd/<n>. The sandbox already denies
// that in reduced isolation (the only mode where the workload can see the
// engine's PID), so this is a second line of defense. Children are
// unaffected: execve resets the flag.
func protectReportFd() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0)
}
