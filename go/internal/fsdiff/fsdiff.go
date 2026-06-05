// Package fsdiff provides filesystem snapshot and diff utilities.
// It walks directory trees, captures file metadata, and compares
// snapshots to produce an FSDiff report (added, modified, deleted).
package fsdiff

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cdxgen/safer-exec/go/internal/config"
)

// SnapshotEntry holds metadata for a single filesystem entry.
type SnapshotEntry struct {
	Path  string
	Mode  uint32
	Size  int64
	IsDir bool
	Hash  string // content hash for regular files
}

// Snapshot represents a point-in-time view of a directory tree.
// Keys are relative paths from the root being snapshotted.
type Snapshot map[string]SnapshotEntry

// SnapshotPath walks the given root directory and returns a Snapshot
// of all files and directories. It skips symlinks and special files.
// Only files under [roots] are walked.
func SnapshotPath(roots ...string) (Snapshot, error) {
	snap := make(Snapshot)

	for _, root := range roots {
		root, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("resolve path %s: %w", root, err)
		}

		// Skip if root doesn't exist
		if _, err := os.Stat(root); err != nil {
			continue
		}

		err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // skip errors during walk
			}

			rel := path
			if root != "/" {
				rel = strings.TrimPrefix(path, root)
				rel = strings.TrimPrefix(rel, string(filepath.Separator))
			}
			if rel == "" {
				rel = "."
			}

			hash := ""
			if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
				hash = fileHash(path)
			}

			snap[rel] = SnapshotEntry{
				Path:  path,
				Mode:  uint32(info.Mode()),
				Size:  info.Size(),
				IsDir: info.IsDir(),
				Hash:  hash,
			}

			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk %s: %w", root, err)
		}
	}

	return snap, nil
}

// Diff compares two snapshots and returns an FSDiff report.
// before is the pre-execution state, after is the post-execution state.
func Diff(before, after Snapshot) config.FSDiff {
	var diff config.FSDiff

	// Find added and modified files
	for rel, afterEntry := range after {
		if beforeEntry, exists := before[rel]; exists {
			// Check if modified: different hash, size, or mode
			if afterEntry.Hash != beforeEntry.Hash ||
				afterEntry.Size != beforeEntry.Size ||
				afterEntry.Mode != beforeEntry.Mode {
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

// fileHash computes the SHA-256 hash of a file's contents.
// Returns empty string if the file can't be read.
func fileHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}
