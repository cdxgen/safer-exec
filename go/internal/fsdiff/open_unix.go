//go:build unix

package fsdiff

import (
	"os"
	"syscall"
)

// openForHash opens path for reading without following a final symlink and
// without blocking if it has become a FIFO.
func openForHash(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
