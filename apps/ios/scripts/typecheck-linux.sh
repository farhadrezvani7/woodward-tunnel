#!/usr/bin/env bash
# Compiles and tests the pure-Swift logic (Shared/Logic + Tests) with a Swift toolchain on Linux
# (or macOS), and syntax-checks (-parse only) every other Swift file. UIKit, SwiftUI,
# NetworkExtension, Libbox and the generated UniFFI bindings are NOT type-checked here.
#
# Usage: scripts/typecheck-linux.sh [path/to/swift]
set -euo pipefail
# On distributions without libxml2.so.2 put a compatible symlink in LD_LIBRARY_PATH (see README).
here="$(cd "$(dirname "$0")/.." && pwd)"
SWIFT="${1:-${SWIFT:-swift}}"
SWIFTC="$(dirname "$(command -v "$SWIFT")")/swiftc"
[ -x "$SWIFTC" ] || SWIFTC="swiftc"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/Sources/WTSharedLogic" "$tmp/Tests/SharedTests"
ln -s "$here"/Shared/Logic/*.swift "$tmp/Sources/WTSharedLogic/"
ln -s "$here"/Shared/Platform/*.swift "$tmp/Sources/WTSharedLogic/"
ln -s "$here"/Tests/SharedTests/*.swift "$tmp/Tests/SharedTests/"
cat > "$tmp/Package.swift" <<'PKG'
// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "WTSharedLogic",
    targets: [
        .target(name: "WTSharedLogic"),
        .testTarget(name: "SharedTests", dependencies: ["WTSharedLogic"]),
    ]
)
PKG

echo "== swift build + test (pure logic)"
(cd "$tmp" && "$SWIFT" test 2>&1 | { grep -v "no version information available" || true; })

# Optional: type-check the FFI wrapper against freshly generated UniFFI bindings.
#   WT_BINDINGS=<dir with wtcore.swift and wtcoreFFI.h>  (see README, "Checking on Linux")
if [ -n "${WT_BINDINGS:-}" ]; then
    echo "== type-check App/Core against UniFFI bindings in $WT_BINDINGS"
    mkdir -p "$tmp/inc"
    cp "$WT_BINDINGS/wtcoreFFI.h" "$tmp/inc/"
    printf 'module wtcoreFFI {\n    header "wtcoreFFI.h"\n    export *\n}\n' > "$tmp/inc/module.modulemap"
    # Security.framework does not exist on Linux: stand in for the Keychain backend.
    cat > "$tmp/KeychainStub.swift" <<'STUB'
public final class SystemKeychainBackend: SecretBackend {
    public init(service: String, accessGroup: String) {}
    public func write(account: String, data: Data) -> Bool { false }
    public func read(account: String) -> Data? { nil }
    public func remove(account: String) -> Bool { false }
}
STUB
    sed -i '1i import Foundation' "$tmp/KeychainStub.swift"
    "$SWIFTC" -typecheck -swift-version 5 -I "$tmp/inc" \
        "$WT_BINDINGS/wtcore.swift" "$here"/App/Core/*.swift "$tmp/KeychainStub.swift" \
        "$here"/Shared/Logic/*.swift 2>&1 | { grep -v "no version information available" || true; }
    echo "FFI wrapper type-checks"
fi

echo "== syntax-only parse of all Swift files (no type check)"
status=0
while IFS= read -r f; do
    if ! "$SWIFTC" -parse "$f" 2>"$tmp/err.txt"; then
        echo "PARSE ERROR: $f"; cat "$tmp/err.txt"; status=1
    fi
done < <(find "$here/App" "$here/PacketTunnel" "$here/Shared" -name '*.swift' | sort)
[ "$status" = 0 ] && echo "all files parse"
exit $status
