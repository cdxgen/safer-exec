//go:build linux && arm64

package main

// Unified syscall numbers (arm64).
// Go's syscall package doesn't define SYS_KCMP for arm64, so we hardcode it.
// arm64 does not have fork/vfork syscalls (it uses clone), nor a generic syscall wrapper.
// We use 9999 as a dummy value so the seccomp filter doesn't accidentally block valid syscalls.
const (
	sysKCMP_unified        = 272  // __NR_kcmp
	sysSYSCALL_unified     = 9999 // Dummy: no generic syscall wrapper on arm64
	sysFORK_unified        = 9999 // Dummy: arm64 uses clone (220)
	sysVFORK_unified       = 9999 // Dummy: arm64 uses clone (220)
	sysEXECVEAT_unified    = 281
	sysCLONE3_unified      = 436
	sysBPF_unified         = 280
	sysUSERFAULTFD_unified = 282
	sysIOPERM_unified      = 9999
	sysIOPL_unified        = 9999
)
