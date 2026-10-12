//go:build !linux

package main

// setNoNewPrivs is a no-op outside Linux. The --init-dryrun re-exec path that
// calls it is Linux-only; engine_linux.go holds the real implementation.
func setNoNewPrivs() {}
