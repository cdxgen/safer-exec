# syntax=docker/dockerfile:1.7
# Multi-platform build: linux/amd64, linux/arm64
# Pre-compiled BPF objects and audit helper .so files are committed to the repo
# and embedded at Go build time — no C compiler or LLVM/clang needed here.

# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Compile Go binary (cross-compile on build host, no CGO)
# ──────────────────────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS build

ARG TARGETARCH

WORKDIR /build
COPY go/go.mod go/go.sum ./
RUN go mod download

COPY go/ ./

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" \
    -o /out/safer-exec ./cmd/safer-exec/

# ──────────────────────────────────────────────────────────────────────────────
# Stage 2: Slim runtime image
# node:24-bookworm-slim gives us the correct arch Node.js with no manual download
# ──────────────────────────────────────────────────────────────────────────────
FROM node:24-bookworm-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# Runtime deps only — no build tools
# util-linux:     unshare, nsenter (namespace isolation)
# iproute2:       ip (network namespace setup)
# strace:         syscall tracing for learn mode
# libcap2-bin:    capsh, getpcaps (capability management for eBPF)
# libssl3:        TLS library probing for eBPF HTTP URL tracing
# libgnutls30:    GnuTLS probing for eBPF HTTP URL tracing
# procps:         ps, top (process inspection in sandboxed environments)
# tini:           proper PID 1 / signal forwarding
RUN apt-get update && apt-get install -y --no-install-recommends \
        util-linux \
        iproute2 \
        strace \
        libcap2-bin \
        libssl3 \
        libgnutls30 \
        procps \
        ca-certificates \
        curl \
        tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/safer-exec /usr/local/bin/safer-exec
RUN chmod +x /usr/local/bin/safer-exec

# Symlink the package into global node_modules so require.resolve("@cdxgen/safer-exec")
# resolves correctly from runner.js — without triggering npm's bin conflict with the
# Go binary already at /usr/local/bin/safer-exec.
COPY npm/ /opt/safer-exec/
RUN mkdir -p /usr/local/lib/node_modules/@cdxgen && \
    ln -sf /opt/safer-exec /usr/local/lib/node_modules/@cdxgen/safer-exec && \
    ln -sf /opt/safer-exec/src/cli.js /usr/local/bin/safer-exec-node && \
    chmod +x /opt/safer-exec/src/cli.js

# Unprivileged sandbox user for running untrusted commands
RUN groupadd -r sandbox && useradd -r -g sandbox -m sandbox
ENV PATH=/usr/local/bin:$PATH
ENTRYPOINT ["/usr/local/bin/safer-exec-node"]

LABEL org.opencontainers.image.title="safer-exec" \
      org.opencontainers.image.description="OS-level sandboxing with tracing, auditing, and learning mode for arbitrary binaries" \
      org.opencontainers.image.source="https://github.com/cdxgen/safer-exec" \
      org.opencontainers.image.vendor="AppThreat"
