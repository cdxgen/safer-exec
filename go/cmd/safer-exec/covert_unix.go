//go:build !windows

package main

import (
	"os"
	"syscall"
)

// pidAlive reports whether a process with this pid exists. EPERM means it
// exists but belongs to another user.
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// privateDir reports whether dir is a real directory owned by this user and
// closed to everyone else, so another user cannot plant or read records.
func privateDir(dir string) bool {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o077 != 0 {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
