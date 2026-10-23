#!/usr/bin/env bash
# Compile-check the core crates for Windows and macOS from Linux (inside Docker). This proves the
# code type-checks and the C dependencies build for those targets; it does NOT run anything there.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm -e CHECK_TAIL="${CHECK_TAIL:-3}" -v "$root":/src:ro -v wt-cross-cargo:/root/.cargo -v wt-cross-rustup:/root/.rustup -v wt-cross-target:/target -e CARGO_TARGET_DIR=/target ubuntu:24.04 bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq curl ca-certificates build-essential gcc-mingw-w64-x86-64 python3-pip pkg-config >/dev/null
[ -x /root/.cargo/bin/rustup ] || curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
. /root/.cargo/env
rustup target add x86_64-pc-windows-gnu aarch64-apple-darwin x86_64-apple-darwin >/dev/null
pip3 install -q --break-system-packages ziglang >/dev/null 2>&1
ZIG="python3 -m ziglang"
cp -r /src /work && cd /work && rm -rf target apps
CRATES="-p core-model -p core-import -p core-store -p core-engine -p core-session -p core-log -p core-policy -p core-app -p core-keyring -p wt-cli"
echo "== windows-gnu"
CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc cargo check $CRATES --target x86_64-pc-windows-gnu 2>&1 | tail -${CHECK_TAIL:-3}
printf "#!/bin/sh\nexec python3 -m ziglang cc -target aarch64-macos \"\$@\"\n" > /usr/local/bin/zcc-arm64; chmod +x /usr/local/bin/zcc-arm64
printf "#!/bin/sh\nexec python3 -m ziglang cc -target x86_64-macos \"\$@\"\n" > /usr/local/bin/zcc-x64; chmod +x /usr/local/bin/zcc-x64
echo "== macos arm64"
CC_aarch64_apple_darwin=zcc-arm64 cargo check $CRATES --target aarch64-apple-darwin 2>&1 | tail -${CHECK_TAIL:-3}
echo "== macos x86_64"
CC_x86_64_apple_darwin=zcc-x64 cargo check $CRATES --target x86_64-apple-darwin 2>&1 | tail -${CHECK_TAIL:-3}
'
