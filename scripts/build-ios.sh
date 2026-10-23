#!/usr/bin/env bash
# Builds everything the iOS app needs and then the app itself. macOS + Xcode only.
#
# Usage: scripts/build-ios.sh [stage ...]
#   stages: rust      Rust core (libwtcore) for device + simulator -> Generated/wtcore.xcframework,
#                     and the UniFFI Swift bindings -> Generated/Bindings
#           libbox    sing-box libbox (gomobile) -> Generated/Libbox.xcframework
#           project   generate WoodwardTunnel.xcodeproj with XcodeGen
#           simulator xcodebuild build for the simulator (unsigned)
#           archive   xcodebuild archive for devices (unsigned)
#           test      pure-Swift logic tests (swift test)
#           all       rust libbox project simulator   (default)
#
# Environment:
#   SING_BOX_TAG   sing-box release tag to build libbox from   (default v1.14.3)
#   LIBBOX_TAGS    go build tags for libbox                    (default: trimmed set, see below)
#   IOS_MIN        minimum iOS version                         (default 17.0)
#
# UNVERIFIED: this script was written on Linux and has never been run on macOS.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
    echo "scripts/build-ios.sh only runs on macOS with Xcode installed (this is $(uname -s))." >&2
    echo "The iOS app cannot be built on this platform; use the macOS runner in .github/workflows/ios.yml." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IOS="$ROOT/apps/ios"
GEN="$IOS/Generated"
SING_BOX_TAG="${SING_BOX_TAG:-v1.14.3}"
IOS_MIN="${IOS_MIN:-17.0}"
# Smaller than the tag set sing-box ships in its own app: no tailscale, openvpn, naive, usbip,
# clash api. The packet tunnel extension has a tight memory limit, so every feature costs.
# Keep with_quic (hysteria2, tuic), with_wireguard, with_utls (reality), with_gvisor (tun stack).
LIBBOX_TAGS="${LIBBOX_TAGS:-with_gvisor,with_quic,with_wireguard,with_utls,with_dhcp,grpcnotrace,badlinkname,tfogo_checklinkname0}"

log() { printf '\n==> %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 ($2)" >&2; exit 1; }; }

stage_rust() {
    need cargo "install Rust from https://rustup.rs"
    need rustup "install Rust from https://rustup.rs"
    need xcodebuild "install Xcode"
    log "Rust targets"
    rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
    export IPHONEOS_DEPLOYMENT_TARGET="$IOS_MIN"
    cd "$ROOT"
    for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
        log "cargo build core-ffi for $t"
        cargo build --release -p core-ffi --target "$t"
    done

    log "xcframework"
    rm -rf "$GEN/wtcore.xcframework" "$GEN/sim"
    mkdir -p "$GEN/sim"
    lipo -create \
        "$ROOT/target/aarch64-apple-ios-sim/release/libwtcore.a" \
        "$ROOT/target/x86_64-apple-ios/release/libwtcore.a" \
        -output "$GEN/sim/libwtcore.a"
    xcodebuild -create-xcframework \
        -library "$ROOT/target/aarch64-apple-ios/release/libwtcore.a" \
        -library "$GEN/sim/libwtcore.a" \
        -output "$GEN/wtcore.xcframework"

    log "UniFFI Swift bindings"
    # Metadata is read from the host build; it is identical for all targets.
    cargo build --release -p core-ffi
    rm -rf "$GEN/Bindings"
    mkdir -p "$GEN/Bindings"
    cargo run --release -p core-ffi --bin uniffi-bindgen -- generate \
        --library "$ROOT/target/release/libwtcore.dylib" \
        --language swift --out-dir "$GEN/Bindings"
    # Xcode finds a Clang module through SWIFT_INCLUDE_PATHS only when the map is named module.modulemap.
    mv "$GEN/Bindings/wtcoreFFI.modulemap" "$GEN/Bindings/module.modulemap"
    ls -l "$GEN/Bindings"
}

stage_libbox() {
    need go "install Go (sing-box ${SING_BOX_TAG} needs a recent toolchain; GOTOOLCHAIN=auto downloads it)"
    need git ""
    need xcodebuild "install Xcode"
    export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"
    local src="$ROOT/build/sing-box-$SING_BOX_TAG"
    if [ ! -d "$src/.git" ]; then
        log "clone sing-box $SING_BOX_TAG"
        mkdir -p "$ROOT/build"
        git clone --depth 1 --branch "$SING_BOX_TAG" https://github.com/SagerNet/sing-box.git "$src"
    fi
    log "install gomobile (SagerNet fork, as in sing-box's Makefile lib_install)"
    go install -v github.com/sagernet/gomobile/cmd/gomobile@v0.1.13
    go install -v github.com/sagernet/gomobile/cmd/gobind@v0.1.13
    local gobin
    gobin="$(go env GOPATH)/bin"
    export PATH="$gobin:$PATH"

    cd "$src"
    local bind_pkgs=("./experimental/libbox")
    local awg_marker="$GEN/awg.enabled"
    mkdir -p "$GEN"
    rm -f "$awg_marker"
    local awg_dir="$ROOT/engines/awg-socks"
    local awg_mod="github.com/farhadrezvani7/woodward-tunnel/engines/awg-socks"
    if [ -d "$awg_dir/mobile" ]; then
        # The AmneziaWG helper must live in the SAME gomobile framework as sing-box: two gomobile
        # frameworks mean two Go runtimes in one process, which does not link. The clone's go.mod is
        # edited for the build and restored afterwards.
        log "adding the AmneziaWG helper package to the libbox framework"
        # A previous failed run may have left the edited files behind: restore the originals first.
        if [ -f go.mod.orig ]; then mv -f go.mod.orig go.mod; mv -f go.sum.orig go.sum; fi
        cp go.mod go.mod.orig; cp go.sum go.sum.orig
        GOFLAGS=-mod=mod go mod edit -require="$awg_mod@v0.0.0" -replace="$awg_mod=$awg_dir"
        bind_pkgs+=("$awg_mod/mobile")
        : > "$awg_marker"
    else
        echo "engines/awg-socks/mobile not found: building libbox without AmneziaWG support"
    fi

    log "gomobile bind libbox (tags: $LIBBOX_TAGS)"
    local version="${SING_BOX_TAG#v}"
    rm -rf Libbox.xcframework
    GOFLAGS=-mod=mod gomobile bind -v \
        -o Libbox.xcframework \
        -target ios,iossimulator \
        -libname=box \
        -tags-not-macos=with_low_memory \
        -iosversion="$IOS_MIN" \
        -trimpath -buildvcs=false \
        -ldflags "-X github.com/sagernet/sing-box/constant.Version=$version -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid=" \
        -tags "$LIBBOX_TAGS" \
        "${bind_pkgs[@]}"
    if [ -f go.mod.orig ]; then mv -f go.mod.orig go.mod; mv -f go.sum.orig go.sum; fi
    rm -rf "$GEN/Libbox.xcframework"
    mkdir -p "$GEN"
    mv Libbox.xcframework "$GEN/Libbox.xcframework"

    log "libbox slices"
    find "$GEN/Libbox.xcframework" -maxdepth 1 -mindepth 1 -type d
    # The project links Libbox statically (embed: false in project.yml). If this prints a dynamic
    # library instead, set embed: true for it in apps/ios/project.yml.
    for bin in "$GEN"/Libbox.xcframework/*/Libbox.framework/Libbox; do
        file "$bin"
    done
}

stage_project() {
    need xcodegen "brew install xcodegen"
    [ -d "$GEN/wtcore.xcframework" ] || { echo "run the 'rust' stage first" >&2; exit 1; }
    [ -d "$GEN/Libbox.xcframework" ] || { echo "run the 'libbox' stage first" >&2; exit 1; }
    log "xcodegen"
    cd "$IOS"
    if [ -f "$GEN/awg.enabled" ]; then export WT_AWG=true; else export WT_AWG=false; fi
    echo "AmneziaWG helper: $WT_AWG"
    xcodegen generate --spec project.yml
}

stage_simulator() {
    cd "$IOS"
    log "xcodebuild build (simulator, unsigned)"
    xcodebuild build \
        -project WoodwardTunnel.xcodeproj \
        -scheme WoodwardTunnel \
        -configuration Debug \
        -destination 'generic/platform=iOS Simulator' \
        -derivedDataPath "$IOS/build/DerivedData" \
        CODE_SIGNING_ALLOWED=NO
}

stage_archive() {
    cd "$IOS"
    log "xcodebuild archive (device, unsigned)"
    xcodebuild archive \
        -project WoodwardTunnel.xcodeproj \
        -scheme WoodwardTunnel \
        -configuration Release \
        -destination 'generic/platform=iOS' \
        -archivePath "$IOS/build/WoodwardTunnel.xcarchive" \
        CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY=""
}

stage_test() {
    need swift "install Xcode"
    "$IOS/scripts/typecheck-linux.sh"
}

stages=("$@")
[ ${#stages[@]} -eq 0 ] && stages=(all)
for s in "${stages[@]}"; do
    case "$s" in
        rust) stage_rust ;;
        libbox) stage_libbox ;;
        project) stage_project ;;
        simulator) stage_simulator ;;
        archive) stage_archive ;;
        test) stage_test ;;
        all) stage_rust; stage_libbox; stage_project; stage_simulator ;;
        *) echo "unknown stage: $s" >&2; exit 2 ;;
    esac
done
log "done"
