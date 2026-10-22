#!/usr/bin/env bash
# Build the Go helper engines for the host platform into engines/bin/.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/engines/bin"
cd "$root/engines/awg-socks"
go build -trimpath -ldflags "-s -w" -o "$root/engines/bin/awg-socks" .
go build -trimpath -ldflags "-s -w" -o "$root/engines/bin/awg-testserver" ./cmd/awg-testserver
echo "built: $root/engines/bin"
