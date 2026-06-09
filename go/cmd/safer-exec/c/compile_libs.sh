#!/usr/bin/env bash
set -euo pipefail

# Directory of the script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Compiling audit helper for linux/amd64..."
docker run --rm -v "$DIR:/src" -w /src --platform linux/amd64 gcc:12-bookworm \
  gcc -shared -fPIC -O3 -o audit_helper_linux_amd64.so audit_helper_linux.c

echo "Compiling audit helper for linux/arm64..."
docker run --rm -v "$DIR:/src" -w /src --platform linux/arm64 gcc:12-bookworm \
  gcc -shared -fPIC -O3 -o audit_helper_linux_arm64.so audit_helper_linux.c

echo "Successfully built precompiled libraries!"
ls -lh "$DIR"/*.so
