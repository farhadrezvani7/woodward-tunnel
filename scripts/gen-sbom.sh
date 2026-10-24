#!/usr/bin/env bash
# Regenerate the CycloneDX SBOMs under docs/SBOM/.
#
#   scripts/gen-sbom.sh
#
# Needs: cargo-cyclonedx (cargo install cargo-cyclonedx --locked). The Go SBOM additionally needs
# cyclonedx-gomod (go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest) and
# is skipped with a notice when it is missing. Generated from the committed Cargo.lock / go.sum, so
# the output is as reproducible as those files.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/docs/SBOM"
mkdir -p "$out"
command -v cargo-cyclonedx >/dev/null || { echo "cargo-cyclonedx not installed" >&2; exit 1; }

# cargo-cyclonedx writes one file per workspace member next to its Cargo.toml. Generate once per
# cargo workspace under a unique name, collect the members that ship, delete every other copy.
tmpname="sbom-wt-generated"
(cd "$root" && cargo cyclonedx --format json --spec-version 1.5 --all-features --override-filename "$tmpname" -q)
for c in core-ffi core-app wt-cli; do
  mv -f "$root/crates/$c/$tmpname.json" "$out/rust-$c.cdx.json"
  echo "wrote $out/rust-$c.cdx.json"
done
rm -f "$root"/crates/*/"$tmpname.json"
# The desktop app is its own cargo workspace with its own Cargo.lock.
(cd "$root/apps/desktop/src-tauri" && cargo cyclonedx --format json --spec-version 1.5 --all-features --override-filename "$tmpname" -q)
mv -f "$root/apps/desktop/src-tauri/$tmpname.json" "$out/rust-desktop.cdx.json"
echo "wrote $out/rust-desktop.cdx.json"
find "$root/apps/desktop/src-tauri" -maxdepth 2 -name "$tmpname.json" -not -path '*/target/*' -delete

if command -v cyclonedx-gomod >/dev/null; then
  (cd "$root/engines/awg-socks" && cyclonedx-gomod mod -json -licenses -output "$out/go-awg-socks.cdx.json")
  echo "wrote $out/go-awg-socks.cdx.json"
else
  echo "cyclonedx-gomod not installed: skipping the Go SBOM" >&2
fi
echo "Android (Gradle) and the sing-box libbox module graph are not covered here; see docs/audit/upstream-and-supply-chain.md."
