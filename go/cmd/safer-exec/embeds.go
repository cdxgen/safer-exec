package main

import (
	_ "embed"
	"os"
)

// extractPrecompiledAuditHelper writes the precompiled platform-specific library helper to
// a temporary file and returns its path. The lifecycle/cleanup of this temporary file
// is managed automatically by the engine callers (e.g. engine_linux.go).
func extractPrecompiledAuditHelper(dir string) (string, error) {
	// Create temp dir with strict permissions
	tmpDir, err := os.MkdirTemp(dir, "safer-exec-audit-*")
	if err != nil {
		return "", err
	}

	tmpFile, err := os.CreateTemp(tmpDir, "helper-*.so")
	if err != nil {
		os.RemoveAll(tmpDir)
		return "", err
	}

	if _, err := tmpFile.Write(auditHelperSo); err != nil {
		tmpFile.Close()
		os.RemoveAll(tmpDir)
		return "", err
	}

	if err := tmpFile.Chmod(0644); err != nil {
		tmpFile.Close()
		os.RemoveAll(tmpDir)
		return "", err
	}
	tmpFile.Close()

	return tmpFile.Name(), nil
}
