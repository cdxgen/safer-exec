//go:build linux && arm64

package httptrace

import _ "embed"

// bpfObject holds the pre-compiled BPF ELF targeting arm64 pt_regs layout.
// Compiled with: clang -O2 -g -target bpf -D__TARGET_ARCH_arm64
//
//go:embed bpf/ssl_trace_linux_arm64.o
var bpfObject []byte
