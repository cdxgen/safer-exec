//go:build linux && amd64

package main

// Unified Landlock syscall numbers (x86_64).
// These are referenced by engine_linux.go to populate the generic constants.
const (
	landlockCreateRuleset_unified = 438
	landlockRestrictSelf_unified  = 439
	landlockAddRules_unified      = 442
)

// Landlock syscall numbers for x86_64 (used directly in RawSyscall).
const (
	sysLandlockCreateRuleset = 438
	sysLandlockRestrictSelf  = 439
	sysLandlockAddRules      = 442
)

// Seccomp syscall number (x86_64).
const sysSeccomp_unified = 317
