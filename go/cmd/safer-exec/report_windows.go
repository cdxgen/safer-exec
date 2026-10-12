//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// crtFOPEN marks an open descriptor in the C runtime's inherited fd table.
const crtFOPEN = 0x01

var procGetStartupInfoW = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetStartupInfoW")

// startupInfo is STARTUPINFOW with the reserved fields x/sys leaves unnamed.
type startupInfo struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	CbReserved2   uint16
	LpReserved2   *byte
	StdInput      windows.Handle
	StdOutput     windows.Handle
	StdErr        windows.Handle
}

// reportFile finds the handle behind C-runtime descriptor fd. Node (libuv)
// passes stdio entries past the first three to a Windows child the way the
// C runtime does: STARTUPINFO.lpReserved2 holds a count, one flag byte per
// descriptor and then one HANDLE per descriptor. The handle is then made
// non-inheritable; Go already passes only explicit handles to the processes
// it starts, so this is a second guard against the launcher or the workload
// receiving it.
func reportFile(fd int) (*os.File, error) {
	var si startupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	procGetStartupInfoW.Call(uintptr(unsafe.Pointer(&si)))
	if si.LpReserved2 == nil || si.CbReserved2 == 0 {
		return nil, fmt.Errorf("no inherited descriptor table (fd %d)", fd)
	}
	table := unsafe.Slice(si.LpReserved2, int(si.CbReserved2))
	h, err := crtHandle(table, fd)
	if err != nil {
		return nil, err
	}
	_ = windows.SetHandleInformation(h, windows.HANDLE_FLAG_INHERIT, 0)
	return os.NewFile(uintptr(h), "report"), nil
}

// crtHandle reads descriptor fd's handle from a C-runtime inheritance table.
func crtHandle(table []byte, fd int) (windows.Handle, error) {
	if len(table) < 4 {
		return 0, fmt.Errorf("no inherited descriptor table (fd %d)", fd)
	}
	count := int(binary.LittleEndian.Uint32(table))
	ptr := int(unsafe.Sizeof(uintptr(0)))
	if count <= fd || count > 4096 || len(table) < 4+count+count*ptr {
		return 0, fmt.Errorf("fd %d is not in the inherited descriptor table", fd)
	}
	if table[4+fd]&crtFOPEN == 0 {
		return 0, fmt.Errorf("fd %d is not open", fd)
	}
	off := 4 + count + fd*ptr
	var v uint64
	if ptr == 8 {
		v = binary.LittleEndian.Uint64(table[off:])
	} else {
		v = uint64(binary.LittleEndian.Uint32(table[off:]))
	}
	h := windows.Handle(v)
	if h == 0 || h == windows.InvalidHandle {
		return 0, fmt.Errorf("fd %d has no handle", fd)
	}
	return h, nil
}
