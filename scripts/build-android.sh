#!/usr/bin/env bash
# Reproducible Android build: libbox.aar (sing-box) + libwtcore.so (Rust core, 4 ABIs) +
# UniFFI Kotlin bindings + Gradle assembleDebug / assembleRelease.
#
#   scripts/build-android.sh                 # everything
#   scripts/build-android.sh --debug-only    # skip assembleRelease
#   scripts/build-android.sh --skip-libbox   # reuse apps/android/app/libs/libbox.aar
#   scripts/build-android.sh --skip-rust     # reuse existing jniLibs + generated bindings
#
# Nothing is published or signed with a real key. Release builds are signed with a throwaway
# keystore generated locally under apps/android/keystore (git-ignored).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
android="$root/apps/android"
cache="$android/.cache"

# ---- pins -------------------------------------------------------------------------------
SINGBOX_TAG="v1.14.3"
SINGBOX_COMMIT="7054cac5124465ffdb145870d7c01885566711b1"
GOMOBILE_VERSION="v0.1.13"                     # SagerNet fork, as in sing-box's Makefile (lib_install)
NDK_VERSION="${NDK_VERSION:-28.2.13676358}"
ANDROID_API=24                                 # minSdk
# Subset of sing-box's own libbox tags (cmd/internal/build_libbox): without naive/tailscale/
# openvpn/openconnect/usbip, which the app does not need and which pull in extra toolchains.
LIBBOX_TAGS="with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0"
ABIS=(arm64-v8a armeabi-v7a x86_64 x86)

debug_only=0 skip_libbox=0 skip_rust=0
for a in "$@"; do
  case "$a" in
    --debug-only) debug_only=1 ;;
    --skip-libbox) skip_libbox=1 ;;
    --skip-rust) skip_rust=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

export ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/$NDK_VERSION}"
[ -d "$ANDROID_HOME" ] || { echo "Android SDK not found (set ANDROID_HOME)" >&2; exit 1; }
[ -f "$ANDROID_NDK_HOME/source.properties" ] || { echo "NDK $NDK_VERSION not found at $ANDROID_NDK_HOME (sdkmanager \"ndk;$NDK_VERSION\")" >&2; exit 1; }
java -version 2>&1 | grep -q 'version "17\.' || { echo "JDK 17 required (JAVA_HOME)" >&2; exit 1; }
mkdir -p "$cache/tmp" "$cache/gobin"
# Large temp files go to disk, not a size-limited tmpfs.
export TMPDIR="$cache/tmp"

# ---- libbox.aar --------------------------------------------------------------------------
build_libbox() {
  command -v go >/dev/null || { echo "go not found" >&2; exit 1; }
  local src="$cache/sing-box"
  if [ ! -d "$src/.git" ]; then
    git clone --quiet --depth 1 --branch "$SINGBOX_TAG" https://github.com/SagerNet/sing-box.git "$src"
  fi
  local head
  head="$(git -C "$src" rev-parse HEAD)"
  if [ "$head" != "$SINGBOX_COMMIT" ]; then
    echo "sing-box checkout is $head, expected $SINGBOX_COMMIT for $SINGBOX_TAG" >&2
    exit 1
  fi
  local stamp="$SINGBOX_COMMIT|$GOMOBILE_VERSION|$LIBBOX_TAGS|$ANDROID_API|$NDK_VERSION"
  if [ -f "$android/app/libs/libbox.aar" ] && [ "$(cat "$cache/libbox.stamp" 2>/dev/null || true)" = "$stamp" ]; then
    echo "libbox.aar up to date"
    return
  fi
  (
    cd "$src"
    export GOBIN="$cache/gobin" PATH="$cache/gobin:$PATH"
    go install github.com/sagernet/gomobile/cmd/gomobile@"$GOMOBILE_VERSION" \
               github.com/sagernet/gomobile/cmd/gobind@"$GOMOBILE_VERSION"
    mkdir -p "$android/app/libs"
    # Same invocation sing-box's build_libbox uses (javapkg, libname, ldflags), pinned tag, own tag set.
    gomobile bind -v -o "$android/app/libs/libbox.aar" -target android -androidapi "$ANDROID_API" \
      -javapkg=io.nekohasekai -libname=box -trimpath -buildvcs=false \
      -ldflags "-X github.com/sagernet/sing-box/constant.Version=${SINGBOX_TAG#v} -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0 -s -w -buildid=" \
      -tags "$LIBBOX_TAGS" ./experimental/libbox
  )
  echo "$stamp" > "$cache/libbox.stamp"
}

# ---- libwtcore.so + bindings --------------------------------------------------------------
build_rust() {
  command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 1; }
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
  command -v cargo-ndk >/dev/null || cargo install cargo-ndk --locked
  local jni="$android/app/src/main/jniLibs"
  rm -rf "$jni"; mkdir -p "$jni"
  local targets=()
  for a in "${ABIS[@]}"; do targets+=(-t "$a"); done
  (cd "$root" && cargo ndk "${targets[@]}" -P "$ANDROID_API" -o "$jni" build --locked -p core-ffi --release)
  for a in "${ABIS[@]}"; do [ -f "$jni/$a/libwtcore.so" ] || { echo "missing $a/libwtcore.so" >&2; exit 1; }; done

  local gen="$android/app/src/generated/kotlin"
  rm -rf "$gen"; mkdir -p "$gen"
  (cd "$root" && cargo run --locked -q -p core-ffi --bin uniffi-bindgen -- generate \
      --library "$jni/arm64-v8a/libwtcore.so" --language kotlin --out-dir "$gen" --no-format)
  fix_bindings "$gen/uniffi/wtcore/wtcore.kt"
}

# UniFFI 0.29 emits `val message` plus `override val message` for an error field called `message`,
# which Kotlin rejects. Rename the field in the generated file; asserts that the edit applied.
fix_bindings() {
  python3 - "$1" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
if "override val message\n            get() = \"message=${ `message` }\"" in s:
    old = "val `message`: kotlin.String\n        ) : FfiException() {\n        override val message\n            get() = \"message=${ `message` }\""
    assert s.count(old) == 1, "FfiException.Failed pattern not found exactly once"
    s = s.replace(old, "val `reason`: kotlin.String\n        ) : FfiException() {\n        override val message: String\n            get() = `reason`")
    open(p, "w", encoding="utf-8").write(s)
    print("patched FfiException.Failed")
PY
}

# ---- local release keystore ----------------------------------------------------------------
ensure_keystore() {
  local ks="$android/keystore/local-release.jks"
  [ -f "$ks" ] && return
  mkdir -p "$android/keystore"
  keytool -genkeypair -keystore "$ks" -storepass woodward-local -keypass woodward-local \
    -alias local -keyalg RSA -keysize 2048 -validity 3650 -dname "CN=local build, O=woodward-tunnel" >/dev/null 2>&1
}

[ "$skip_libbox" = 1 ] || build_libbox
[ "$skip_rust" = 1 ] || build_rust

cd "$android"
if [ "$debug_only" = 1 ]; then
  ./gradlew --no-daemon --console=plain assembleDebug
else
  ensure_keystore
  ./gradlew --no-daemon --console=plain assembleDebug assembleRelease
fi
echo
ls -1 app/build/outputs/apk/*/*.apk
