//go:build linux && arm64

package main

// Unified syscall numbers (arm64).
// Go's syscall package doesn't define these for arm64, so we hardcode them.
const (
	sysKCMP_unified    = 272 // syscall.SYS_KCMP on arm64
	sysSYSCALL_unified = 0   // not available on arm64
	sysFORK_unified    = 2   // clone on arm64 (no separate fork)
	sysVFORK_unified   = 2   // clone on arm64 (no separate vfork, same as fork)
)
