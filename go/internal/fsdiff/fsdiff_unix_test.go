//go:build unix

package fsdiff_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/cdxgen/safer-exec/go/internal/fsdiff"
)

// A FIFO (or device) inside a write root must not be opened for hashing:
// reading a FIFO with no writer blocks forever and would hang the engine.
func TestSnapshotPath_SkipsFIFOs(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan fsdiff.Snapshot, 1)
	go func() {
		snap, _ := fsdiff.SnapshotPath(dir)
		done <- snap
	}()
	select {
	case snap := <-done:
		e, ok := snap[fifo]
		if !ok || e.Hash != "" {
			t.Errorf("fifo entry = %+v (present=%v), want recorded without a hash", e, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot blocked on a FIFO")
	}
}

// A symlink inside a root is recorded, never read through: following one to
// /dev/zero would stream from the device until the engine runs out of memory.
func TestSnapshotPath_DeviceTargetNotRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/dev/zero", filepath.Join(dir, "zero")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	done := make(chan struct{})
	go func() {
		_, _ = fsdiff.SnapshotPath(dir)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot read through a symlink to /dev/zero")
	}
}
