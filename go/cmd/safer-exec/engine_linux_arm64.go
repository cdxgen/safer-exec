//go:build linux && arm64

package main

// Unified Landlock syscall numbers (arm64).
const (
	landlockCreateRuleset_unified = landlockCreateRuleset_arm64
	landlockRestrictSelf_unified  = landlockRestrictSelf_arm64
	landlockAddRules_unified      = landlockAddRules_arm64
)

// Unified Landlock access flags (arm64).
const (
	landlockAccessNetTCPConnect_unified = landlockAccessNetTCPConnect_arm64
	landlockAccessNetTCPBind_unified    = landlockAccessNetTCPBind_arm64
)

// Seccomp syscall number (arm64).
const sysSeccomp_unified = 277

// Landlock syscall numbers for arm64 (used in RawSyscall).
const (
	sysLandlockCreateRuleset = landlockCreateRuleset_arm64
	sysLandlockRestrictSelf  = landlockRestrictSelf_arm64
	sysLandlockAddRules      = landlockAddRules_arm64
)
