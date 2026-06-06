//go:build linux && arm64

package main

import (
	"syscall"
	"testing"
)

// TestArm64SyscallConstants verifies that the hardcoded syscall numbers
// match the arm64 Linux ABI. This prevents regressions if the constants
// are accidentally changed or copied from the amd64 file.
func TestArm64SyscallConstants(t *testing.T) {
	// Verify Landlock syscalls match arm64 ABI
	if sysLandlockCreateRuleset != 441 {
		t.Errorf("sysLandlockCreateRuleset = %d, want 441", sysLandlockCreateRuleset)
	}
	if sysLandlockAddRules != 442 {
		t.Errorf("sysLandlockAddRules = %d, want 442", sysLandlockAddRules)
	}
	if sysLandlockRestrictSelf != 445 {
		t.Errorf("sysLandlockRestrictSelf = %d, want 445", sysLandlockRestrictSelf)
	}

	// Verify Seccomp syscall
	if sysSeccomp_unified != 277 {
		t.Errorf("sysSeccomp_unified = %d, want 277", sysSeccomp_unified)
	}

	// Verify KCMP
	if sysKCMP_unified != 272 {
		t.Errorf("sysKCMP_unified = %d, want 272", sysKCMP_unified)
	}

	// Verify CLONE is available in standard library for arm64
	if syscall.SYS_CLONE != 220 {
		t.Errorf("syscall.SYS_CLONE = %d, want 220", syscall.SYS_CLONE)
	}

	// Verify dummies are safely out of the standard syscall range (max is usually ~450)
	// This ensures we don't accidentally block valid arm64 syscalls like io_setup (0)
	if sysFORK_unified < 9000 || sysVFORK_unified < 9000 || sysSYSCALL_unified < 9000 {
		t.Error("Dummy syscalls should be > 9000 to avoid blocking valid arm64 syscalls")
	}
}
