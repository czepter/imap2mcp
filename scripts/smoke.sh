#!/usr/bin/env bash
# Docker-based deployment smoke test: builds the image, runs it against the TLS fake IMAP fixture and
# exercises health, bootstrap, OAuth + MCP, restart persistence, upgrade/migration, and fail-closed key handling.
# Set SMOKE_IMAGE=<tag> to reuse an already built image instead of building.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker is not installed; the container smoke test cannot run." >&2
  exit 0
fi
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: the docker daemon is not reachable (docker info failed); the container smoke test cannot run." >&2
  exit 0
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "SKIP: openssl is required to create the fixture certificate." >&2
  exit 0
fi

if ! command -v npx >/dev/null 2>&1; then
  echo "SKIP: node/npx is required to run the smoke harness (npm ci first); the container itself needs only docker." >&2
  exit 0
fi

# The harness (test/smoke/smoke.smoke.ts) builds the image from the Dockerfile unless SMOKE_IMAGE is set, starts
# containers and waits for GET /healthz (or the container exiting, for the fail-closed cases).
exec npx vitest run --config test/smoke/vitest.config.ts "$@"
