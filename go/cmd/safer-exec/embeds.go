package main

import (
	_ "embed"
	"os"
)

// extractPrecompiledAuditHelper writes the precompiled platform-specific library helper to
// a temporary file and returns its path. The lifecycle/cleanup of this temporary file
// is managed automatically by the engine callers (e.g. engine_linux.go).
func extractPrecompiledAuditHelper() (string, error) {
	tmpFile, err := os.CreateTemp("", "safer-exec-audit-*.so")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(auditHelperSo); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	if err := tmpFile.Chmod(0755); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}
