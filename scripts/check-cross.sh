#!/usr/bin/env bash
# Compile-check the core crates for Windows and macOS from Linux (inside Docker). This proves the
# code type-checks and the C dependencies build for those targets; it does NOT run anything there.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm -e CHECK_TAIL="${CHECK_TAIL:-3}" -v "$root":/src:ro -v wt-cross-cargo:/root/.cargo -v wt-cross-rustup:/root/.rustup -v wt-cross-target:/target -e CARGO_TARGET_DIR=/target ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq curl ca-certificates build-essential gcc-mingw-w64-x86-64 python3-pip pkg-config >/dev/null
if [ ! -x /root/.cargo/bin/rustup ]; then
  # pinned rustup-init, verified against the SHA-256 published by static.rust-lang.org
  curl -fsSL -o /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.29.2/x86_64-unknown-linux-gnu/rustup-init
  echo "5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4  /tmp/rustup-init" | sha256sum -c -
  chmod +x /tmp/rustup-init && /tmp/rustup-init -y --profile minimal >/dev/null
fi
. /root/.cargo/env
rustup target add x86_64-pc-windows-gnu aarch64-apple-darwin x86_64-apple-darwin >/dev/null
printf "ziglang==0.17.0 --hash=sha256:97079827064a7492cce5541ceb438ae8003ce1e54e399676da2d62fb7a5dc08b\n" > /tmp/zig-req.txt
pip3 install -q --break-system-packages --require-hashes -r /tmp/zig-req.txt >/dev/null
ZIG="python3 -m ziglang"
cp -r /src /work && cd /work && rm -rf target apps
CRATES="-p core-model -p core-import -p core-store -p core-engine -p core-session -p core-log -p core-policy -p core-app -p core-keyring -p wt-cli"
echo "== windows-gnu"
CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc cargo check $CRATES --target x86_64-pc-windows-gnu 2>&1 | tail -${CHECK_TAIL:-3}
cat > /usr/local/bin/zcc <<PY
#!/usr/bin/env python3
# zig cc does not understand the --target=arm64-apple-macosx flag the cc crate adds; replace it.
import os, sys
target = sys.argv[1]
args, skip = [], False
for a in sys.argv[2:]:
    if skip:
        skip = False
    elif a.startswith("--target=") or a.startswith("-mmacosx-version-min="):
        pass
    elif a == "-arch":
        skip = True
    else:
        args.append(a)
os.execvp("python3", ["python3", "-m", "ziglang", "cc", "-target", target] + args)
PY
chmod +x /usr/local/bin/zcc
printf "#!/bin/sh\nexec zcc aarch64-macos \"\$@\"\n" > /usr/local/bin/zcc-arm64; chmod +x /usr/local/bin/zcc-arm64
printf "#!/bin/sh\nexec zcc x86_64-macos \"\$@\"\n" > /usr/local/bin/zcc-x64; chmod +x /usr/local/bin/zcc-x64
echo "== macos arm64"
CC_aarch64_apple_darwin=zcc-arm64 cargo check $CRATES --target aarch64-apple-darwin 2>&1 | tail -${CHECK_TAIL:-3}
echo "== macos x86_64"
CC_x86_64_apple_darwin=zcc-x64 cargo check $CRATES --target x86_64-apple-darwin 2>&1 | tail -${CHECK_TAIL:-3}
'
