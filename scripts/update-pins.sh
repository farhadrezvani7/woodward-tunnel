#!/usr/bin/env bash
# Update the pinned sing-box release in apps/desktop/engines.lock from the official release
# metadata. It never changes anything silently: without --write it only prints the proposed lock
# file and a diff against the current one.
#
#   scripts/update-pins.sh                  # latest stable release, dry run
#   scripts/update-pins.sh v1.14.3          # a specific tag, dry run
#   scripts/update-pins.sh --write          # latest stable, rewrite engines.lock
#   scripts/update-pins.sh v1.14.4 --write
#
# For every desktop archive it (1) reads the SHA-256 digest GitHub publishes for the release asset,
# (2) downloads the archive and computes the SHA-256 itself, and (3) refuses to continue unless
# both agree. sing-box publishes no signature (no cosign/minisign/GPG assets), so the pinned digest
# in the lock file is the trust anchor from then on: build-desktop.sh checks the download against
# the lock AND the live digest, and any mismatch is fatal.
#
# It refuses pre-releases and downgrades, and then prints the other places that carry the same
# version and must be changed in the same commit (they are owned by the mobile build and are not
# edited here): SINGBOX_TAG / SINGBOX_COMMIT in scripts/build-android.sh and scripts/build-ios.sh,
# SING_BOX_TAG in .github/workflows/ios.yml. Read the release notes and
# https://sing-box.sagernet.org/deprecated/ before bumping, run the full test suite, then commit.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
lock="$root/apps/desktop/engines.lock"
repo="SagerNet/sing-box"
PLATFORMS=(darwin-amd64.tar.gz darwin-arm64.tar.gz linux-amd64.tar.gz linux-arm64.tar.gz windows-amd64.zip windows-arm64.zip)

tag="" write=0 allow_pre=0
for a in "$@"; do
  case "$a" in
    --write) write=1 ;;
    --allow-prerelease) allow_pre=1 ;;
    v[0-9]*) tag="$a" ;;
    *) echo "usage: $0 [vX.Y.Z] [--write] [--allow-prerelease]" >&2; exit 2 ;;
  esac
done

PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || { echo "python3 is required" >&2; exit 1; }
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
api() {
  local auth=()
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  curl -fsSL --retry 3 -H "Accept: application/vnd.github+json" "${auth[@]}" "https://api.github.com/repos/$repo/$1"
}

if [ -z "$tag" ]; then
  # /releases/latest excludes pre-releases and drafts.
  tag="$(api releases/latest | "$PY" -I -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])')"
fi
meta="$(mktemp)"; work="$(mktemp -d)"
trap 'rm -rf "$meta" "$work"' EXIT
api "releases/tags/$tag" > "$meta"

"$PY" -I - "$meta" "$tag" "$allow_pre" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
if d.get("draft"):
    sys.exit("refusing: " + sys.argv[2] + " is a draft")
if d.get("prerelease") and sys.argv[3] != "1":
    sys.exit("refusing: " + sys.argv[2] + " is a pre-release (use --allow-prerelease to override)")
EOF

# Refuse downgrades relative to the current lock.
cur="$(grep -v '^#' "$lock" | awk 'NF{print $1}' | sort -V | tail -n1 || true)"
if [ -n "$cur" ] && [ "$(printf '%s\n%s\n' "${cur#v}" "${tag#v}" | sort -V | head -n1)" != "${cur#v}" ]; then
  echo "refusing: $tag is older than the pinned $cur" >&2; exit 1
fi

new="$work/engines.lock.new"
{
  sed -n '/^#/p' "$lock"
  for p in "${PLATFORMS[@]}"; do
    asset="sing-box-${tag#v}-$p"
    published="$("$PY" -I - "$meta" "$asset" <<'EOF'
import json, sys
d = json.load(open(sys.argv[1]))
for a in d.get("assets", []):
    if a["name"] == sys.argv[2]:
        print((a.get("digest") or "").replace("sha256:", ""))
EOF
)"
    [ -n "$published" ] || { echo "FATAL: release $tag has no asset/digest for $asset" >&2; exit 1; }
    echo "fetching $asset" >&2
    curl -fsSL --retry 5 --retry-all-errors --connect-timeout 20 --speed-limit 10240 --speed-time 60 -o "$work/$asset" "https://github.com/$repo/releases/download/$tag/$asset"
    got="$(sha256_of "$work/$asset")"
    if [ "$got" != "$published" ]; then
      echo "FATAL: $asset downloads as $got but the release publishes $published" >&2; exit 1
    fi
    echo "$tag $asset $got"
  done
} > "$new"

echo "---- proposed $lock ----"
diff -u "$lock" "$new" || true
if [ "$write" = 1 ]; then
  cp "$new" "$lock"
  echo "wrote $lock"
else
  echo "(dry run: pass --write to apply)"
fi

commit="$(git ls-remote "https://github.com/$repo.git" "refs/tags/$tag^{}" "refs/tags/$tag" | tail -n1 | cut -f1)"
cat <<EOF

Same-commit follow-ups (not edited by this script):
  scripts/build-android.sh : SINGBOX_TAG="$tag"  SINGBOX_COMMIT="$commit"
  scripts/build-ios.sh     : the matching SINGBOX_TAG / commit pin
  .github/workflows/ios.yml: SING_BOX_TAG: $tag
Then: read the changelog and deprecated list, run ./scripts/build-engines.sh and the workspace tests.
EOF
