//go:build linux

package main

import "testing"

// TestSyscallConstants verifies that critical seccomp syscall constants
// are defined and non-zero on all supported Linux architectures.
func TestSyscallConstants(t *testing.T) {
	if sysEXECVEAT == 0 {
		t.Error("sysEXECVEAT is zero — likely not defined for this architecture")
	}

	if sysCLONE3 == 0 {
		t.Error("sysCLONE3 is zero — likely not defined for this architecture")
	}
}

// TestSyscallConstants_NonZeroDoubleCheck verifies both the architecture-specific
// constants as well as the aliased package-level constants.
func TestSyscallConstants_NonZeroDoubleCheck(t *testing.T) {
	tests := []struct {
		name string
		val  int
	}{
		{"sysEXECVEAT", sysEXECVEAT},
		{"sysCLONE3", sysCLONE3},
		{"sysFORK", sysFORK},
		{"sysVFORK", sysVFORK},
		{"sysKCMP", sysKCMP},
		{"sysSYSCALL", sysSYSCALL},
	}
	for _, tc := range tests {
		if tc.val == 0 {
			t.Errorf("%s is zero — seccomp filter would be ineffective", tc.name)
		}
	}
}
