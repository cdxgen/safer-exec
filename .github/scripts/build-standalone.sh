#!/usr/bin/env bash
set -euo pipefail

# Determine target OS and architecture
TARGET_OS="${TARGET_OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
TARGET_ARCH="${TARGET_ARCH:-}"
if [[ -z "$TARGET_ARCH" ]]; then
  ARCH="$(uname -m)"
  if [[ "$ARCH" == "x86_64" ]]; then
    TARGET_ARCH="amd64"
  elif [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    TARGET_ARCH="arm64"
  else
    TARGET_ARCH="$ARCH"
  fi
fi

# Map darwin to macos if needed for caxa, but caxa understands darwin / linux
# Determine binary output name
OUTPUT_BINARY="${OUTPUT_BINARY:-safer-exec}"

if [[ -f go/bin/safer-exec ]]; then
  echo "Go engine already compiled at go/bin/safer-exec, skipping build."
else
  echo "Building Go engine for $TARGET_OS/$TARGET_ARCH..."
  # Compile Go binary statically
  (cd go && CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" go build -trimpath -ldflags="-s -w" -o bin/safer-exec ./cmd/safer-exec/)
fi

# Create staging directory
STAGING_DIR="$(mktemp -d)"
echo "Staging files in $STAGING_DIR..."

mkdir -p "$STAGING_DIR/npm"
cp npm/package.json "$STAGING_DIR/npm/"
cp -R npm/src "$STAGING_DIR/npm/"

mkdir -p "$STAGING_DIR/go/bin"
cp go/bin/safer-exec "$STAGING_DIR/go/bin/"

# Ensure the executable permission is set
chmod +x "$STAGING_DIR/go/bin/safer-exec"

CAXA_PACKAGE="${CAXA_PACKAGE:-@cdxgen/caxa@^3.0.3}"
echo "Running caxa to build standalone binary: $OUTPUT_BINARY"

caxa_args=(
  --input "$STAGING_DIR"
  --output "$OUTPUT_BINARY"
)

if [[ "$TARGET_OS" == "linux" ]]; then
  # On Linux, try to use UPX compression if available
  if command -v upx >/dev/null 2>&1; then
    caxa_args+=(--upx --upx-args '--best' '--lzma')
  fi
fi

caxa_args+=(-- "{{caxa}}/node_modules/.bin/node" "{{caxa}}/npm/src/cli.js")

# Run caxa using npx/pnpm
npx --package="$CAXA_PACKAGE" -y caxa "${caxa_args[@]}"

# Cleanup staging directory
rm -rf "$STAGING_DIR"

chmod +x "$OUTPUT_BINARY"
echo "Standalone binary built successfully: $OUTPUT_BINARY"
