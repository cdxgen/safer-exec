//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// reportFile adopts the inherited report descriptor and marks it
// close-on-exec, so neither the sandbox launcher nor the workload inherits a
// way to write into it.
func reportFile(fd int) (*os.File, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("fd %d: %w", fd, err)
	}
	syscall.CloseOnExec(fd)
	protectReportFd()
	return os.NewFile(uintptr(fd), "report"), nil
}
