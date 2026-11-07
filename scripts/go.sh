#!/usr/bin/env bash
# Run the Go toolchain: local `go` if present, else golang:1.23-alpine via Docker.
# Usage: scripts/go.sh build -o bin/sidecar ./cmd/sidecar   (cwd inside container: /src/sidecar)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CGO_ENABLED=0
export GOFLAGS="${GOFLAGS:--mod=mod}"
if command -v go >/dev/null 2>&1; then
  cd "$ROOT/sidecar"
  exec go "$@"
fi
mkdir -p "$ROOT/sidecar"
exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "$ROOT:/src" -w /src/sidecar \
  -v imap2mcp-gomod:/gocache \
  -e CGO_ENABLED=0 -e GOFLAGS="$GOFLAGS" \
  -e GOCACHE=/gocache/build -e GOMODCACHE=/gocache/mod -e HOME=/tmp \
  ${SIDECAR_BENCH:+-e SIDECAR_BENCH=$SIDECAR_BENCH} \
  ${GO_DOCKER_EXTRA:-} \
  golang:1.23-alpine go "$@"
