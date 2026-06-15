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

	sysLOOKUP_DCOOKIE_unified    = 18
	sysFANOTIFY_INIT_unified     = 367
	sysINOTIFY_INIT_unified      = 9999
	sysINOTIFY_INIT1_unified     = 26
	sysIO_URING_SETUP_unified    = 425
	sysIO_URING_ENTER_unified    = 426
	sysIO_URING_REGISTER_unified = 427
	sysREQUEST_KEY_unified       = 219
	sysPROCESS_VM_READV_unified  = 270
	sysPROCESS_VM_WRITEV_unified = 271
	sysFINIT_MODULE_unified      = 273

	sysGETRANDOM_unified  = 278
	sysMEMBARRIER_unified = 283
	sysOPENAT2_unified    = 437

	sysMEMFD_CREATE_unified  = 279
	sysPKEY_MPROTECT_unified = 288
)

// seccompAuditArch is the AUDIT_ARCH_* value the seccomp filter pins the
// process to. On arm64 this is AUDIT_ARCH_AARCH64 (EM_AARCH64 0xB7 |
// __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE = 0xC00000B7). Any syscall arriving with
// a different arch (e.g. the 32-bit ARM compat gate, AUDIT_ARCH_ARM 0x40000028)
// is rejected, closing the compat-ABI seccomp bypass.
const seccompAuditArch = 0xC00000B7

// seccompX32SyscallBit is zero on arm64: there is no x32-style ABI, so no
// per-number masking is required (the arch check covers the 32-bit compat gate).
const seccompX32SyscallBit = 0
