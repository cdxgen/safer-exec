//go:build linux && arm64

package main

import _ "embed"

//go:embed c/audit_helper_linux_arm64.so
var auditHelperSo []byte

var hasPrecompiledSo = true
