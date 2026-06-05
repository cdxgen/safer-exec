//go:build linux && amd64

package main

// Unified syscall numbers (x86_64).
// Go's syscall package doesn't define SYS_KCMP or SYS_SYSCALL for amd64,
// so we hardcode them. SYS_FORK and SYS_VFORK are available.
const (
	sysKCMP_unified    = 312 // not in Go's syscall package
	sysSYSCALL_unified = 21  // not in Go's syscall package
	sysFORK_unified    = 57  // syscall.SYS_FORK
	sysVFORK_unified   = 58  // syscall.SYS_VFORK
)
