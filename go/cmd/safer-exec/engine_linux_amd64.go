//go:build linux && amd64

package main

// Unified Landlock syscall numbers (x86_64).
const (
	landlockCreateRuleset_unified = landlockCreateRuleset_x86_64
	landlockRestrictSelf_unified  = landlockRestrictSelf_x86_64
	landlockAddRules_unified      = landlockAddRules_x86_64
)

// Unified Landlock access flags (x86_64).
const (
	landlockAccessNetTCPConnect_unified = landlockAccessNetTCPConnect_x86_64
	landlockAccessNetTCPBind_unified    = landlockAccessNetTCPBind_x86_64
)

// Seccomp syscall number (x86_64).
const sysSeccomp_unified = 317

// Landlock syscall numbers for x86_64 (used in RawSyscall).
const (
	sysLandlockCreateRuleset = landlockCreateRuleset_x86_64
	sysLandlockRestrictSelf  = landlockRestrictSelf_x86_64
	sysLandlockAddRules      = landlockAddRules_x86_64
)
