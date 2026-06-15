//go:build linux && amd64

package main

// Unified syscall numbers (x86_64).
// Go's syscall package doesn't define SYS_KCMP or SYS_SYSCALL for amd64,
// so we hardcode them. SYS_FORK and SYS_VFORK are available in the standard
// library but we alias them here for consistency with the arm64 build tag.
const (
	sysKCMP_unified        = 312
	sysSYSCALL_unified     = 9999
	sysFORK_unified        = 57
	sysVFORK_unified       = 58
	sysEXECVEAT_unified    = 322
	sysCLONE3_unified      = 435
	sysBPF_unified         = 321
	sysUSERFAULTFD_unified = 323
	sysIOPERM_unified      = 173
	sysIOPL_unified        = 172

	sysLOOKUP_DCOOKIE_unified    = 212
	sysFANOTIFY_INIT_unified     = 300
	sysINOTIFY_INIT_unified      = 253
	sysINOTIFY_INIT1_unified     = 294
	sysIO_URING_SETUP_unified    = 425
	sysIO_URING_ENTER_unified    = 426
	sysIO_URING_REGISTER_unified = 427
	sysREQUEST_KEY_unified       = 249
	sysPROCESS_VM_READV_unified  = 310
	sysPROCESS_VM_WRITEV_unified = 311
	sysFINIT_MODULE_unified      = 313

	sysGETRANDOM_unified  = 318
	sysMEMBARRIER_unified = 324
	sysOPENAT2_unified    = 437
)

// seccompAuditArch is the AUDIT_ARCH_* value the seccomp filter pins the
// process to. On x86_64 this is AUDIT_ARCH_X86_64 (EM_X86_64 | __AUDIT_ARCH_64BIT
// | __AUDIT_ARCH_LE = 0x3E | 0x80000000 | 0x40000000). Any syscall arriving with
// a different arch (e.g. the i386 compat gate via int 0x80, AUDIT_ARCH_I386
// 0x40000003) is rejected, closing the classic compat-ABI seccomp bypass.
const seccompAuditArch = 0xC000003E

// seccompX32SyscallBit is the bit set on x32 ABI syscall numbers
// (__X32_SYSCALL_BIT). x32 syscalls run under AUDIT_ARCH_X86_64, so the arch
// check alone does not catch them; the filter additionally rejects any syscall
// number with this bit set. Zero on architectures without an x32 ABI.
const seccompX32SyscallBit = 0x40000000
