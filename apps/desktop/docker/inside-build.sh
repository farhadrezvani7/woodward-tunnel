#!/usr/bin/env bash
# Runs inside the builder image: build the Linux bundles and copy them to dist/.
set -euo pipefail
cd /work/apps/desktop
npm ci --no-audit --no-fund
npx tauri build --bundles "${WT_BUNDLES:-deb,appimage}" --target x86_64-unknown-linux-gnu
out=/work/apps/desktop/dist
rm -rf "$out"; mkdir -p "$out"
t="$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release"
cp "$t/woodward-tunnel" "$out/" 
cp "$t"/bundle/deb/*.deb "$out/" 2>/dev/null || true
cp "$t"/bundle/appimage/*.AppImage "$out/" 2>/dev/null || true
ls -la "$out"
