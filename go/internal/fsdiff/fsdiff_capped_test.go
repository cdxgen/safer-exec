// Internal tests for the hash-size cap fallback (mtime-based detection).
package fsdiff

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDiffDetectsCappedFileModification verifies that an in-place
// modification of a file over the hash cap (same size, same mode) is still
// reported via the mtime fallback — the cap must cost hash precision, not
// change detection.
func TestDiffDetectsCappedFileModification(t *testing.T) {
	origCap := maxHashSize
	maxHashSize = 16 // force the capped path for small test files
	defer func() { maxHashSize = origCap }()

	dir := t.TempDir()
	blob := filepath.Join(dir, "blob.bin")
	payload := make([]byte, 64)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := os.WriteFile(blob, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := SnapshotPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before["blob.bin"].Hash != "" {
		t.Fatalf("expected capped file to have empty hash, got %q", before["blob.bin"].Hash)
	}

	// Same size, same mode, different content — with an mtime delta beyond
	// common filesystem timestamp resolution.
	time.Sleep(1100 * time.Millisecond)
	flipped := make([]byte, len(payload))
	for i := range flipped {
		flipped[i] = byte(255 - i)
	}
	if err := os.WriteFile(blob, flipped, 0o644); err != nil {
		t.Fatal(err)
	}

	after, err := SnapshotPath(dir)
	if err != nil {
		t.Fatal(err)
	}

	diff := Diff(before, after)
	if len(diff.Modified) != 1 || diff.Modified[0].Path != blob {
		t.Fatalf("expected in-place modification of capped file to be detected, got %+v", diff.Modified)
	}
	if len(diff.Added) != 0 || len(diff.Deleted) != 0 {
		t.Fatalf("unexpected adds/deletes: %+v %+v", diff.Added, diff.Deleted)
	}
}

// TestDiffCappedFileUnchangedNotReported: two snapshots of an untouched
// capped file must not report a modification just because hashes are empty.
func TestDiffCappedFileUnchangedNotReported(t *testing.T) {
	origCap := maxHashSize
	maxHashSize = 16
	defer func() { maxHashSize = origCap }()

	dir := t.TempDir()
	blob := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(blob, make([]byte, 64), 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := SnapshotPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	after, err := SnapshotPath(dir)
	if err != nil {
		t.Fatal(err)
	}

	diff := Diff(before, after)
	if len(diff.Modified) != 0 {
		t.Fatalf("expected no modifications for untouched capped file, got %+v", diff.Modified)
	}
}
