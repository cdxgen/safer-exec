#!/usr/bin/env bash
# Compile BPF uprobe programs for each supported Linux architecture.
# Requires Docker with buildx (multi-arch emulation via QEMU).
#
# Usage:
#   cd go/internal/httptrace/bpf && bash compile.sh
#
# Output:
#   ssl_trace_linux_amd64.o   BPF ELF targeting x86_64 pt_regs layout
#   ssl_trace_linux_arm64.o   BPF ELF targeting arm64 pt_regs layout
#
# The .o files are BPF ELF (not native ELF) and are architecture-portable
# in their instruction encoding, but their pt_regs field offsets are
# architecture-specific. Each .o must only be loaded on its target arch.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

COMPILE_CMD='apt-get update -qq 2>/dev/null \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libbpf-dev linux-libc-dev 2>/dev/null \
  && clang --version \
  && clang -O2 -g -target bpf -D__TARGET_ARCH_${ARCH_FLAG} \
       -I /usr/include/${MULTIARCH_INCLUDE} \
       -I /usr/include \
       -c /src/ssl_trace.c \
       -o /src/ssl_trace_linux_${OUTPUT_SUFFIX}.o \
  && echo "compiled ssl_trace_linux_${OUTPUT_SUFFIX}.o OK"'

compile_for() {
  local output_suffix=$1      # amd64 or arm64
  local arch_flag=$2          # x86 or arm64
  local docker_platform=$3    # linux/amd64 or linux/arm64
  local multiarch_include=$4  # x86_64-linux-gnu or aarch64-linux-gnu

  echo "▶ Compiling BPF for $output_suffix (platform=$docker_platform)..."
  docker run --rm \
    --platform "$docker_platform" \
    -v "$DIR:/src" \
    -w /src \
    -e ARCH_FLAG="$arch_flag" \
    -e OUTPUT_SUFFIX="$output_suffix" \
    -e MULTIARCH_INCLUDE="$multiarch_include" \
    ubuntu:22.04 \
    bash -c "$COMPILE_CMD"
}

compile_for "amd64" "x86"   "linux/amd64" "x86_64-linux-gnu"
compile_for "arm64" "arm64" "linux/arm64" "aarch64-linux-gnu"

echo "✓ Done:"
ls -lh "$DIR"/ssl_trace_linux_*.o
