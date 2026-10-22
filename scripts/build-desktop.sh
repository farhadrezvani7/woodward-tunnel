#!/usr/bin/env bash
# Build the desktop app.
#
#   scripts/build-desktop.sh engines [triple]  fetch+verify sing-box, build awg-socks into src-tauri/binaries
#   scripts/build-desktop.sh linux             full Linux bundle (.deb, AppImage) inside Docker -> apps/desktop/dist
#   scripts/build-desktop.sh native            engines + `tauri build` on this machine (CI: Windows, macOS, Linux)
#   scripts/build-desktop.sh test              cargo tests (incl. sing-box end-to-end) inside Docker
#   scripts/build-desktop.sh shell             interactive shell in the Docker build image
#
# Environment: TARGET=<rust target triple> (default: host), WT_OFFLINE=1 (skip the live digest
# lookup; the pinned engines.lock is still enforced), WT_BUNDLES=deb,appimage (Linux bundle list).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
app="$root/apps/desktop"
tauri_dir="$app/src-tauri"
bin_dir="$tauri_dir/binaries"
lock="$app/engines.lock"
image="wt-desktop-builder"

PY="$(command -v python3 || command -v python || true)"

host_triple() {
  if command -v rustc >/dev/null 2>&1; then rustc -vV | sed -n 's/^host: //p'; return; fi
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) echo x86_64-unknown-linux-gnu ;;
    Linux-aarch64) echo aarch64-unknown-linux-gnu ;;
    Darwin-arm64) echo aarch64-apple-darwin ;;
    Darwin-x86_64) echo x86_64-apple-darwin ;;
    *) echo "unknown host" >&2; exit 1 ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fetch_engines() {
  local triple="${1:-${TARGET:-$(host_triple)}}"
  local goos goarch plat ext exe=""
  case "$triple" in
    x86_64-unknown-linux-gnu)  goos=linux;   goarch=amd64; plat=linux-amd64;   ext=tar.gz ;;
    aarch64-unknown-linux-gnu) goos=linux;   goarch=arm64; plat=linux-arm64;   ext=tar.gz ;;
    x86_64-apple-darwin)       goos=darwin;  goarch=amd64; plat=darwin-amd64;  ext=tar.gz ;;
    aarch64-apple-darwin)      goos=darwin;  goarch=arm64; plat=darwin-arm64;  ext=tar.gz ;;
    x86_64-pc-windows-msvc)    goos=windows; goarch=amd64; plat=windows-amd64; ext=zip; exe=.exe ;;
    aarch64-pc-windows-msvc)   goos=windows; goarch=arm64; plat=windows-arm64; ext=zip; exe=.exe ;;
    *) echo "unsupported target: $triple" >&2; exit 1 ;;
  esac

  # The pinned entry for this platform: "<tag> <asset> <sha256>".
  local entry tag asset want
  entry="$(grep -E " sing-box-[0-9.]+-${plat}\.${ext} " "$lock" | grep -v '^#' | tail -n1 || true)"
  [ -n "$entry" ] || { echo "no pinned sing-box for $plat in $lock" >&2; exit 1; }
  read -r tag asset want <<<"$entry"

  local work; work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  echo "downloading $asset ($tag)"
  curl -fsSL --retry 3 -o "$work/$asset" "https://github.com/SagerNet/sing-box/releases/download/$tag/$asset"
  local got; got="$(sha256_of "$work/$asset")"
  if [ "$got" != "$want" ]; then
    echo "FATAL: $asset sha256 $got does not match engines.lock ($want)" >&2; exit 1
  fi
  if [ "${WT_OFFLINE:-0}" = "1" ]; then
    echo "warning: WT_OFFLINE=1, live digest not checked (engines.lock matched)" >&2
  else
    [ -n "$PY" ] || { echo "python is needed to read the release digest" >&2; exit 1; }
    local live
    live="$(curl -fsSL --retry 3 "https://api.github.com/repos/SagerNet/sing-box/releases/tags/$tag" \
      | "$PY" -I -c 'import json,sys
d=json.load(sys.stdin)
n=sys.argv[1]
for a in d.get("assets",[]):
    if a["name"]==n:
        print((a.get("digest") or "").replace("sha256:",""))' "$asset")"
    if [ -z "$live" ]; then echo "FATAL: GitHub published no digest for $asset" >&2; exit 1; fi
    if [ "$live" != "$got" ]; then
      echo "FATAL: $asset sha256 $got does not match the digest published by the release ($live)" >&2; exit 1
    fi
    echo "sha256 verified against engines.lock and the release digest: $got"
  fi

  mkdir -p "$work/x" "$bin_dir"
  if [ "$ext" = zip ]; then "$PY" -I -m zipfile -e "$work/$asset" "$work/x"; else tar -xzf "$work/$asset" -C "$work/x"; fi
  local found; found="$(find "$work/x" -type f -name "sing-box$exe" | head -n1)"
  [ -n "$found" ] || { echo "sing-box not found in archive" >&2; exit 1; }
  cp "$found" "$bin_dir/wt-sing-box-$triple$exe"
  chmod +x "$bin_dir/wt-sing-box-$triple$exe"
  echo "installed $bin_dir/wt-sing-box-$triple$exe"

  # The AmneziaWG helper is ours: cross-compiled static Go binary.
  command -v go >/dev/null 2>&1 || { echo "go is required to build awg-socks" >&2; exit 1; }
  (cd "$root/engines/awg-socks" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "-s -w" -o "$bin_dir/wt-awg-socks-$triple$exe" .)
  echo "built $bin_dir/wt-awg-socks-$triple$exe"
}

docker_run() {
  mkdir -p "$app/.cache/cargo" "$app/.cache/npm"
  docker build -q -t "$image" "$app/docker" >/dev/null
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp/home -e CARGO_HOME=/work/apps/desktop/.cache/cargo -e npm_config_cache=/work/apps/desktop/.cache/npm \
    -e CARGO_TARGET_DIR=/work/apps/desktop/.cache/target \
    -e APPIMAGE_EXTRACT_AND_RUN=1 -e NO_STRIP=1 -e WT_BUNDLES="${WT_BUNDLES:-deb,appimage}" \
    -v "$root:/work" -w /work/apps/desktop \
    "$@"
}

cmd="${1:-linux}"
case "$cmd" in
  engines) fetch_engines "${2:-}" ;;
  linux)
    TARGET=x86_64-unknown-linux-gnu fetch_engines x86_64-unknown-linux-gnu
    docker_run "$image" bash docker/inside-build.sh
    ;;
  test)
    TARGET=x86_64-unknown-linux-gnu fetch_engines x86_64-unknown-linux-gnu
    docker_run --cap-add NET_ADMIN --device /dev/net/tun "$image" bash docker/inside-test.sh
    ;;
  shell) docker_run -it "$image" bash ;;
  native)
    fetch_engines "${TARGET:-}"
    cd "$app"
    npm ci
    triple="${TARGET:-$(host_triple)}"
    npx tauri build --target "$triple" ${WT_TAURI_ARGS:-}
    ;;
  *) echo "unknown command: $cmd" >&2; exit 2 ;;
esac
