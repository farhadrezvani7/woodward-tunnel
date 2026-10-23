#!/usr/bin/env bash
# Runs inside the builder image: unit + end-to-end tests with a real sing-box.
set -euo pipefail
cd /work/apps/desktop/src-tauri
export WT_SING_BOX=/work/apps/desktop/src-tauri/binaries/wt-sing-box-x86_64-unknown-linux-gnu
export WT_AWG_SOCKS=/work/apps/desktop/src-tauri/binaries/wt-awg-socks-x86_64-unknown-linux-gnu
export WT_AWG_TESTSERVER=/work/engines/bin/awg-testserver
cargo test --release 2>&1 | tail -40
if [ -c /dev/net/tun ] && ip link show >/dev/null 2>&1; then
  echo "== TUN test (needs NET_ADMIN, runs the engine as the container user) =="
  # File capabilities cannot be set without root, so this variant runs as whoever started it.
  WT_TUN_TEST=1 cargo test --release tun_mode -- --nocapture 2>&1 | tail -30 || true
fi
