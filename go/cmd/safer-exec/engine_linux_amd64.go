//go:build linux && amd64

package main

// Landlock syscall numbers for x86_64 (used directly in RawSyscall).
// Correct numbers from /usr/include/asm/unistd_64.h (Linux 5.13+).
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRules      = 445
	sysLandlockRestrictSelf  = 446
)

// Seccomp syscall number (x86_64).
const sysSeccomp_unified = 317
