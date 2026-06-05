// Package fsdiff_test validates filesystem snapshot and diff utilities.
package fsdiff_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cdxgen/safer-exec/go/internal/fsdiff"
)

func TestSnapshotPath_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	snap, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("SnapshotPath failed: %v", err)
	}

	// Should have at least the "." entry
	if _, ok := snap["."]; !ok {
		t.Error("snapshot should contain '.' entry for the root directory")
	}
}

func TestSnapshotPath_WithFiles(t *testing.T) {
	dir := t.TempDir()

	// Create test files
	fileA := filepath.Join(dir, "file_a.txt")
	fileB := filepath.Join(dir, "file_b.txt")
	subdir := filepath.Join(dir, "subdir")
	fileC := filepath.Join(subdir, "file_c.txt")

	if err := os.WriteFile(fileA, []byte("content a"), 0o644); err != nil {
		t.Fatalf("write file_a: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("content b"), 0o644); err != nil {
		t.Fatalf("write file_b: %v", err)
	}
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(fileC, []byte("content c"), 0o644); err != nil {
		t.Fatalf("write file_c: %v", err)
	}

	snap, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("SnapshotPath failed: %v", err)
	}

	// Verify entries
	if _, ok := snap["file_a.txt"]; !ok {
		t.Error("snapshot should contain file_a.txt")
	}
	if _, ok := snap["file_b.txt"]; !ok {
		t.Error("snapshot should contain file_b.txt")
	}
	if _, ok := snap["subdir/file_c.txt"]; !ok {
		t.Error("snapshot should contain subdir/file_c.txt")
	}
	if entry, ok := snap["subdir"]; !ok || !entry.IsDir {
		t.Error("snapshot should contain subdir as a directory")
	}
}

func TestDiff_NoChanges(t *testing.T) {
	dir := t.TempDir()

	fileA := filepath.Join(dir, "file_a.txt")
	if err := os.WriteFile(fileA, []byte("content"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	before, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("before snapshot: %v", err)
	}

	after, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("after snapshot: %v", err)
	}

	diff := fsdiff.Diff(before, after)

	if len(diff.Added) > 0 {
		t.Errorf("expected no added files, got %d", len(diff.Added))
	}
	if len(diff.Modified) > 0 {
		t.Errorf("expected no modified files, got %d", len(diff.Modified))
	}
	if len(diff.Deleted) > 0 {
		t.Errorf("expected no deleted files, got %d", len(diff.Deleted))
	}
}

func TestDiff_AddedFiles(t *testing.T) {
	dir := t.TempDir()

	before, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("before snapshot: %v", err)
	}

	// Add a new file
	newFile := filepath.Join(dir, "new_file.txt")
	if err := os.WriteFile(newFile, []byte("new content"), 0o644); err != nil {
		t.Fatalf("write new file: %v", err)
	}

	after, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("after snapshot: %v", err)
	}

	diff := fsdiff.Diff(before, after)

	if len(diff.Added) != 1 {
		t.Fatalf("expected 1 added file, got %d", len(diff.Added))
	}
	if diff.Added[0].Path != newFile {
		t.Errorf("added file path: got %q, want %q", diff.Added[0].Path, newFile)
	}
}

func TestDiff_ModifiedFiles(t *testing.T) {
	dir := t.TempDir()

	fileA := filepath.Join(dir, "file_a.txt")
	if err := os.WriteFile(fileA, []byte("original"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	before, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("before snapshot: %v", err)
	}

	// Modify the file
	if err := os.WriteFile(fileA, []byte("modified content"), 0o644); err != nil {
		t.Fatalf("modify file: %v", err)
	}

	after, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("after snapshot: %v", err)
	}

	diff := fsdiff.Diff(before, after)

	if len(diff.Modified) != 1 {
		t.Fatalf("expected 1 modified file, got %d", len(diff.Modified))
	}
	if diff.Modified[0].Path != fileA {
		t.Errorf("modified file path: got %q, want %q", diff.Modified[0].Path, fileA)
	}
}

func TestDiff_DeletedFiles(t *testing.T) {
	dir := t.TempDir()

	fileA := filepath.Join(dir, "file_a.txt")
	if err := os.WriteFile(fileA, []byte("content"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	before, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("before snapshot: %v", err)
	}

	// Delete the file
	if err := os.Remove(fileA); err != nil {
		t.Fatalf("remove file: %v", err)
	}

	after, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("after snapshot: %v", err)
	}

	diff := fsdiff.Diff(before, after)

	if len(diff.Deleted) != 1 {
		t.Fatalf("expected 1 deleted file, got %d", len(diff.Deleted))
	}
	if diff.Deleted[0].Path != fileA {
		t.Errorf("deleted file path: got %q, want %q", diff.Deleted[0].Path, fileA)
	}
}

func TestDiff_MixedChanges(t *testing.T) {
	dir := t.TempDir()

	// Create initial files
	fileA := filepath.Join(dir, "file_a.txt")
	fileB := filepath.Join(dir, "file_b.txt")
	if err := os.WriteFile(fileA, []byte("a"), 0o644); err != nil {
		t.Fatalf("write file_a: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("b"), 0o644); err != nil {
		t.Fatalf("write file_b: %v", err)
	}

	before, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("before snapshot: %v", err)
	}

	// Make mixed changes: add, modify, delete
	fileC := filepath.Join(dir, "file_c.txt")
	if err := os.WriteFile(fileC, []byte("c"), 0o644); err != nil {
		t.Fatalf("write file_c: %v", err)
	}
	if err := os.WriteFile(fileA, []byte("a modified"), 0o644); err != nil {
		t.Fatalf("modify file_a: %v", err)
	}
	if err := os.Remove(fileB); err != nil {
		t.Fatalf("remove file_b: %v", err)
	}

	after, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("after snapshot: %v", err)
	}

	diff := fsdiff.Diff(before, after)

	if len(diff.Added) != 1 {
		t.Errorf("expected 1 added file, got %d", len(diff.Added))
	}
	if len(diff.Modified) != 1 {
		t.Errorf("expected 1 modified file, got %d", len(diff.Modified))
	}
	if len(diff.Deleted) != 1 {
		t.Errorf("expected 1 deleted file, got %d", len(diff.Deleted))
	}
}

func TestSnapshotPath_NonexistentPath(t *testing.T) {
	snap, err := fsdiff.SnapshotPath("/tmp/safer-exec-nonexistent-dir-12345")
	if err != nil {
		t.Fatalf("SnapshotPath should not fail for nonexistent paths: %v", err)
	}

	// Should return empty snapshot (just the root)
	if len(snap) > 1 {
		t.Errorf("expected empty snapshot for nonexistent path, got %d entries", len(snap))
	}
}

func TestDiff_SortedOutput(t *testing.T) {
	dir := t.TempDir()

	before, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("before snapshot: %v", err)
	}

	// Add multiple files in non-alphabetical order
	files := []string{"z_file.txt", "a_file.txt", "m_file.txt"}
	for _, name := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	after, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatalf("after snapshot: %v", err)
	}

	diff := fsdiff.Diff(before, after)

	// Verify output is sorted by path
	for i := 1; i < len(diff.Added); i++ {
		if diff.Added[i].Path < diff.Added[i-1].Path {
			t.Errorf("added files should be sorted: %q < %q",
				diff.Added[i].Path, diff.Added[i-1].Path)
		}
	}
}
