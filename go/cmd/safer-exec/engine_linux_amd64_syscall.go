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
