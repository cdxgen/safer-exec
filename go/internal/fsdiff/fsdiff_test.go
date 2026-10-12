// Package fsdiff_test validates filesystem snapshot and diff utilities.
package fsdiff_test

import (
	"fmt"
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

	// Should have at least the root's own entry
	if _, ok := snap[dir]; !ok {
		t.Error("snapshot should contain an entry for the root directory")
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
	if _, ok := snap[fileA]; !ok {
		t.Error("snapshot should contain file_a.txt")
	}
	if _, ok := snap[fileB]; !ok {
		t.Error("snapshot should contain file_b.txt")
	}
	if _, ok := snap[fileC]; !ok {
		t.Error("snapshot should contain subdir/file_c.txt")
	}
	if entry, ok := snap[subdir]; !ok || !entry.IsDir {
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

// Two write roots holding files with the same relative path must not shadow
// each other: a change under the first root has to be reported even though
// the second root has an unchanged file (and root entry) of the same name.
func TestDiff_SameRelativePathAcrossRoots(t *testing.T) {
	rootA := t.TempDir()
	rootB := t.TempDir()
	for _, root := range []string{rootA, rootB} {
		if err := os.WriteFile(filepath.Join(root, "package.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "gone.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	before, err := fsdiff.SnapshotPath(rootA, rootB)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{rootA, rootB, filepath.Join(rootA, "package.json"), filepath.Join(rootB, "package.json")} {
		if _, ok := before[p]; !ok {
			t.Errorf("snapshot is missing %s", p)
		}
	}

	modified := filepath.Join(rootA, "package.json")
	if err := os.WriteFile(modified, []byte(`{"name":"changed"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	deleted := filepath.Join(rootA, "gone.txt")
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}
	added := filepath.Join(rootB, "new.txt")
	if err := os.WriteFile(added, []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}

	after, err := fsdiff.SnapshotPath(rootA, rootB)
	if err != nil {
		t.Fatal(err)
	}
	diff := fsdiff.Diff(before, after)

	if len(diff.Modified) != 1 || diff.Modified[0].Path != modified {
		t.Errorf("modified = %+v, want only %s", diff.Modified, modified)
	}
	if len(diff.Deleted) != 1 || diff.Deleted[0].Path != deleted {
		t.Errorf("deleted = %+v, want only %s", diff.Deleted, deleted)
	}
	if len(diff.Added) != 1 || diff.Added[0].Path != added {
		t.Errorf("added = %+v, want only %s", diff.Added, added)
	}
}

// A root nested inside another (or listed twice) is recorded once, under the
// first root that reaches it, so its changes are not reported twice.
func TestSnapshotPath_OverlappingRoots(t *testing.T) {
	outer := t.TempDir()
	inner := filepath.Join(outer, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := fsdiff.SnapshotPath(outer, inner, outer)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 2 {
		t.Errorf("snapshot has %d entries, want 2 (outer, inner): %v", len(before), before)
	}
	if err := os.WriteFile(filepath.Join(inner, "f.txt"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := fsdiff.SnapshotPath(inner, outer)
	if err != nil {
		t.Fatal(err)
	}
	diff := fsdiff.Diff(before, after)
	if len(diff.Added) != 1 || diff.Added[0].Path != filepath.Join(inner, "f.txt") {
		t.Errorf("added = %+v, want only inner/f.txt", diff.Added)
	}
	if len(diff.Modified) != 0 || len(diff.Deleted) != 0 {
		t.Errorf("unexpected modified=%+v deleted=%+v", diff.Modified, diff.Deleted)
	}
}

// A root that is itself a symlink (macOS /tmp → /private/tmp) is walked
// through to its target and reported under the spelling the caller gave.
func TestSnapshotPath_SymlinkedRoot(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	before, err := fsdiff.SnapshotPath(link)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := before[link]; !ok || !e.IsDir {
		t.Fatalf("root entry %s missing or not a directory: %+v", link, before)
	}
	created := filepath.Join(link, "created.txt")
	if err := os.WriteFile(created, []byte("c"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := fsdiff.SnapshotPath(link)
	if err != nil {
		t.Fatal(err)
	}
	diff := fsdiff.Diff(before, after)
	if len(diff.Added) != 1 || diff.Added[0].Path != created {
		t.Errorf("added = %+v, want only %s", diff.Added, created)
	}
}

// Entry churn inside a directory is described by the added/deleted entries;
// the directory itself is modified only when its mode changes.
func TestDiff_DirectoryModifiedOnlyByMode(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%02d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	after, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d := fsdiff.Diff(before, after); len(d.Added) != 20 || len(d.Modified) != 0 {
		t.Errorf("entry churn: added=%d modified=%+v, want 20 added and none modified", len(d.Added), d.Modified)
	}

	if err := os.Chmod(sub, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(sub, 0o755)
	chmodded, err := fsdiff.SnapshotPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d := fsdiff.Diff(after, chmodded); len(d.Modified) != 1 || d.Modified[0].Path != sub {
		t.Errorf("mode change: modified=%+v, want only %s", d.Modified, sub)
	}
}

// The workload can write inside the outer root, so it can replace a nested
// root with a symlink to somewhere it was never granted. The post-run
// snapshot (taken unsandboxed) must not follow it: the swapped root shows up
// as one changed entry and its former contents as deleted, and nothing from
// the link target is read or reported.
func TestSnapshotter_NestedRootSwappedForSymlink(t *testing.T) {
	outer := t.TempDir()
	inner := filepath.Join(outer, "node_modules")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "dep.js"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := t.TempDir()
	if err := os.WriteFile(filepath.Join(secret, "id_ed25519"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := fsdiff.NewSnapshotter(inner, outer)
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(inner); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, inner); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	after, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for p := range after {
		if filepath.Base(p) == "id_ed25519" {
			t.Fatalf("post-run snapshot followed the swapped root into %s", p)
		}
	}
	d := fsdiff.Diff(before, after)
	if len(d.Modified) != 1 || d.Modified[0].Path != inner {
		t.Errorf("modified = %+v, want only the swapped root %s", d.Modified, inner)
	}
	if len(d.Deleted) != 1 || d.Deleted[0].Path != filepath.Join(inner, "dep.js") {
		t.Errorf("deleted = %+v, want the root's former contents", d.Deleted)
	}
	if len(d.Added) != 0 {
		t.Errorf("added = %+v, want none", d.Added)
	}
}

// A directory above a nested root swapped for a symlink redirects the nested
// root too, even though the root's own last component is unchanged.
func TestSnapshotter_IntermediateDirectorySwappedForSymlink(t *testing.T) {
	outer := t.TempDir()
	inner := filepath.Join(outer, "a", "b")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.MkdirAll(filepath.Join(elsewhere, "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "b", "secret.txt"), []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := fsdiff.NewSnapshotter(outer, inner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(outer, "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(outer, "a")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	after, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for p := range after {
		if filepath.Base(p) == "secret.txt" {
			t.Fatalf("snapshot followed a swapped parent directory into %s", p)
		}
	}
}
