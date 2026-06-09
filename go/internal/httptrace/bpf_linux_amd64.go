//go:build linux && amd64

package httptrace

import _ "embed"

// bpfObject holds the pre-compiled BPF ELF targeting x86_64 pt_regs layout.
// Compiled with: clang -O2 -g -target bpf -D__TARGET_ARCH_x86
//
//go:embed bpf/ssl_trace_linux_amd64.o
var bpfObject []byte
