package main

import (
	_ "embed"
	"os"
	"runtime"
)

//go:embed c/audit_helper_linux.c
var auditHelperLinuxC []byte

//go:embed c/audit_helper_darwin.c
var auditHelperDarwinC []byte

// extractAuditHelper writes the platform-appropriate C audit helper source to
// a temporary file and returns its path. The caller is responsible for removing
// both the .c file and any compiled output.
func extractAuditHelper() (string, error) {
	tmpFile, err := os.CreateTemp("", "safer-exec-audit-*.c")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	content := auditHelperLinuxC
	if runtime.GOOS == "darwin" {
		content = auditHelperDarwinC
	}

	if _, err := tmpFile.Write(content); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}
