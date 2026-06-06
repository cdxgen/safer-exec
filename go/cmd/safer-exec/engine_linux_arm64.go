//go:build linux && arm64

package main

// Unified Landlock syscall numbers (arm64).
// These are referenced by engine_linux.go to populate the generic constants.
const (
	landlockCreateRuleset_unified = 441
	landlockRestrictSelf_unified  = 445
	landlockAddRules_unified      = 442
)

// Landlock syscall numbers for arm64 (used directly in RawSyscall).
const (
	sysLandlockCreateRuleset = 441
	sysLandlockRestrictSelf  = 445
	sysLandlockAddRules      = 442
)

// Seccomp syscall number (arm64).
const sysSeccomp_unified = 277
