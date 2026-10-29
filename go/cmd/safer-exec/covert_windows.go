//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// pidAlive reports whether a process with this pid is still running.
func pidAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// Access denied still means the process exists.
		return err == windows.ERROR_ACCESS_DENIED
	}
	defer windows.CloseHandle(h)
	var code uint32
	if windows.GetExitCodeProcess(h, &code) != nil {
		return true
	}
	return code == 259 // STILL_ACTIVE
}

// privateDir reports whether dir is a real directory, not a reparse point.
// The registry lives under the per-user %TEMP%, which other users cannot
// write.
func privateDir(dir string) bool {
	fi, err := os.Lstat(dir)
	return err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 && fi.Mode()&os.ModeIrregular == 0
}
