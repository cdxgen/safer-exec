//go:build linux && amd64

package main

import _ "embed"

//go:embed c/audit_helper_linux_amd64.so
var auditHelperSo []byte

var hasPrecompiledSo = true
