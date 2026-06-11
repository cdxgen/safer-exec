//go:build linux && amd64

package main

// Unified syscall numbers (x86_64).
// Go's syscall package doesn't define SYS_KCMP or SYS_SYSCALL for amd64,
// so we hardcode them. SYS_FORK and SYS_VFORK are available in the standard
// library but we alias them here for consistency with the arm64 build tag.
const (
	sysKCMP_unified     = 312
	sysSYSCALL_unified  = 9999
	sysFORK_unified     = 57
	sysVFORK_unified    = 58
	sysEXECVEAT_unified = 322
	sysCLONE3_unified   = 435
)
