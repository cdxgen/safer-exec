// Package fsdiff provides filesystem snapshot and diff utilities.
// It walks directory trees, captures file metadata, and compares
// snapshots to produce an FSDiff report (added, modified, deleted).
package fsdiff

import (
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// SnapshotEntry holds metadata for a single filesystem entry.
type SnapshotEntry struct {
	Path  string
	Mode  uint32
	Size  int64
	IsDir bool
	Hash  string // content hash for regular files
	// ModTime (nanoseconds) backs change detection for files whose content
	// hash is unavailable — over maxHashSize or unreadable.
	ModTime int64
}

// Snapshot represents a point-in-time view of one or more directory trees.
// Keys are absolute paths spelled under the root they were found through
// (the same value as SnapshotEntry.Path), so entries under different roots
// never collide.
type Snapshot map[string]SnapshotEntry

// Snapshotter takes repeated snapshots of a fixed set of roots. Each root is
// resolved once, when the Snapshotter is created: the engine snapshots after
// the sandboxed run with the user's full privileges, and the workload can
// write inside the roots, so it must not be able to redirect a later walk by
// swapping a root (or a directory above a nested root) for a symlink.
type Snapshotter struct {
	roots []snapRoot
}

type snapRoot struct {
	given    string // absolute path as the caller spelled it
	resolved string // symlink-free location pinned at creation
}

// NewSnapshotter pins the roots. A root that is itself a symlink (macOS /tmp
// → /private/tmp) is resolved to its target and reported under the given
// spelling. Roots that do not exist yet are ignored for the Snapshotter's
// lifetime; anything created there is outside what was granted to watch.
func NewSnapshotter(roots ...string) (*Snapshotter, error) {
	s := &Snapshotter{}
	for _, given := range roots {
		abs, err := filepath.Abs(given)
		if err != nil {
			return nil, fmt.Errorf("resolve path %s: %w", given, err)
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			continue
		}
		s.roots = append(s.roots, snapRoot{given: abs, resolved: resolved})
	}
	return s, nil
}

// SnapshotPath is NewSnapshotter(roots...).Snapshot() for a one-off view.
func SnapshotPath(roots ...string) (Snapshot, error) {
	s, err := NewSnapshotter(roots...)
	if err != nil {
		return nil, err
	}
	return s.Snapshot()
}

// Snapshot walks every pinned root and records all files and directories
// under it. Symlinks inside a root are recorded, not followed, and only
// regular files are read for hashing. A tree reachable through more than one
// root (a root nested in or aliasing an earlier one) is recorded once, under
// the first root that reaches it.
//
// A root whose path no longer resolves to its pinned location is recorded as
// a single entry for whatever now sits at the given path and is not walked,
// so its earlier contents show up as deleted. The check is repeated after the
// walk to catch a swap made while walking.
func (s *Snapshotter) Snapshot() (Snapshot, error) {
	snap := make(Snapshot)
	// Resolved locations already recorded, so overlapping roots do not
	// report the same file twice under different spellings.
	seen := make(map[string]struct{})

	for _, r := range s.roots {
		if !r.intact() {
			r.recordRedirected(snap)
			continue
		}
		rootSnap := make(Snapshot)
		rootSeen := make([]string, 0, 64)
		err := filepath.Walk(r.resolved, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip errors during walk
			}
			if _, dup := seen[path]; dup {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			seen[path] = struct{}{}
			rootSeen = append(rootSeen, path)

			reported := path
			if r.resolved != r.given {
				rel, err := filepath.Rel(r.resolved, path)
				if err != nil {
					return nil
				}
				reported = filepath.Join(r.given, rel)
			}

			hash := ""
			if info.Mode().IsRegular() {
				hash = fileHash(path, info)
			}

			rootSnap[reported] = SnapshotEntry{
				Path:    reported,
				Mode:    uint32(info.Mode()),
				Size:    info.Size(),
				IsDir:   info.IsDir(),
				Hash:    hash,
				ModTime: info.ModTime().UnixNano(),
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", r.given, err)
		}
		if !r.intact() {
			for _, p := range rootSeen {
				delete(seen, p)
			}
			r.recordRedirected(snap)
			continue
		}
		maps.Copy(snap, rootSnap)
	}

	return snap, nil
}

// intact reports whether the root's path still leads to its pinned location.
func (r snapRoot) intact() bool {
	cur, err := filepath.EvalSymlinks(r.given)
	return err == nil && cur == r.resolved
}

// recordRedirected records what now sits at a root that no longer leads to
// its pinned location, without following it. A root that vanished records
// nothing.
func (r snapRoot) recordRedirected(snap Snapshot) {
	info, err := os.Lstat(r.given)
	if err != nil {
		return
	}
	snap[r.given] = SnapshotEntry{
		Path:    r.given,
		Mode:    uint32(info.Mode()),
		Size:    info.Size(),
		IsDir:   info.IsDir(),
		ModTime: info.ModTime().UnixNano(),
	}
}

// Diff compares two snapshots and returns an FSDiff report.
// before is the pre-execution state, after is the post-execution state.
func Diff(before, after Snapshot) config.FSDiff {
	var diff config.FSDiff

	// Find added and modified files
	for rel, afterEntry := range after {
		if beforeEntry, exists := before[rel]; exists {
			// Modified when the content hash, size, or mode differs. When the
			// hash is unavailable on both sides (over the size cap, or
			// unreadable), mtime is the fallback signal for regular files —
			// the cap then costs hash precision, not change detection.
			// Directories compare mode only: their mtime and size (APFS,
			// tmpfs, ext4 block growth) track entry churn, which would report
			// every directory containing an add or delete as "modified" when
			// the added/deleted entries already describe the change.
			modified := afterEntry.Mode != beforeEntry.Mode
			if !modified && !afterEntry.IsDir {
				modified = afterEntry.Hash != beforeEntry.Hash ||
					afterEntry.Size != beforeEntry.Size
				if !modified && afterEntry.Hash == "" && beforeEntry.Hash == "" {
					modified = afterEntry.ModTime != beforeEntry.ModTime
				}
			}
			if modified {
				diff.Modified = append(diff.Modified, config.FSDiffEntry{
					Path:  afterEntry.Path,
					Mode:  afterEntry.Mode,
					Size:  afterEntry.Size,
					IsDir: afterEntry.IsDir,
				})
			}
		} else {
			diff.Added = append(diff.Added, config.FSDiffEntry{
				Path:  afterEntry.Path,
				Mode:  afterEntry.Mode,
				Size:  afterEntry.Size,
				IsDir: afterEntry.IsDir,
			})
		}
	}

	// Find deleted files
	for rel, beforeEntry := range before {
		if _, exists := after[rel]; !exists {
			diff.Deleted = append(diff.Deleted, config.FSDiffEntry{
				Path:  beforeEntry.Path,
				Mode:  beforeEntry.Mode,
				Size:  beforeEntry.Size,
				IsDir: beforeEntry.IsDir,
			})
		}
	}

	// Sort for deterministic output
	sortFSDiffEntries(diff.Added)
	sortFSDiffEntries(diff.Modified)
	sortFSDiffEntries(diff.Deleted)

	return diff
}

func sortFSDiffEntries(entries []config.FSDiffEntry) {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
}

// maxHashSize bounds the per-file content hash. Files larger than this are
// compared by size, mode, and mtime: snapshotting a writable root that
// contains multi-gigabyte artifacts (build caches, container layers) would
// otherwise read the entire tree twice per run. Overridable in tests.
var maxHashSize int64 = 64 << 20 // 64 MiB

// fileHash computes the SHA-256 hash of a regular file's contents. info is
// the walk's Lstat result; the opened file must still be that same regular
// file, so an entry swapped for a symlink, FIFO or device after the walk saw
// it is not read (openForHash refuses to follow links or block on FIFOs).
// Returns empty string if the file can't be read or exceeds maxHashSize.
func fileHash(path string, info os.FileInfo) string {
	if info.Size() > maxHashSize {
		return ""
	}
	f, err := openForHash(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > maxHashSize {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxHashSize+1)); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
