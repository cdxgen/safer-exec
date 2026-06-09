//go:build !linux || (!amd64 && !arm64)

package main

var auditHelperSo []byte
var hasPrecompiledSo = false
