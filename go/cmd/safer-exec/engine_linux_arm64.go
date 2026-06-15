//go:build linux && arm64

package main

// Landlock syscall numbers for arm64.
// arm64 uses the asm-generic unistd.h table.
// Correct numbers from /usr/include/asm-generic/unistd.h (Linux 5.13+).
const (
	sysLandlockCreateRuleset = 444
	sysLandlockAddRules      = 445
	sysLandlockRestrictSelf  = 446
)

// Seccomp syscall number (arm64).
const sysSeccomp_unified = 277
