//go:build !unix

package fsdiff

import "os"

// openForHash opens path for reading. Windows has no FIFOs in the file
// namespace, and fileHash rejects a file swapped for a link by comparing it
// with the walk's Lstat result.
func openForHash(path string) (*os.File, error) {
	return os.Open(path)
}
