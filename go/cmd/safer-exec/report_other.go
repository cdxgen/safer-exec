//go:build !windows && !linux

package main

// protectReportFd needs nothing more on macOS and the BSDs: another process
// cannot reach this process's descriptors through the filesystem.
func protectReportFd() {}
