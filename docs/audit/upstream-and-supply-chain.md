# Upstream currency and supply chain audit

Checked 2026-10-23/24 against primary sources (GitHub tags and releases, crates.io, Maven metadata,
go.dev, RustSec, OSV, the OpenVPN community security announcements). Licensing was deliberately
out of scope for this pass.

## Components

| Component | Our pin | Latest stable (date) | Advisories | Action | Status |
|---|---|---|---|---|---|
| sing-box (desktop archives, mobile libbox) | v1.14.3 (engines.lock digests match GitHub's published digests) | v1.14.3 on 2026-10-23; a v1.14.4 appeared on 2026-10-24 | one historical GHSA (SOCKS inbound, fixed 1.4.5), n/a | `scripts/update-pins.sh v1.14.4` after reading its notes; bump the mobile pins in the same commit | follow-up (v1.14.4 digests not yet fetched: network) |
| Generated sing-box config | n/a | n/a | n/a | no option from sing-box `docs/deprecated.md` (1.10 to 1.14) is emitted; new DNS servers, endpoint, rule actions, `default_domain_resolver` already used | ok |
| amneziawg-go | v3.1.20260828 (b5928efb) | same tag, equals repo HEAD | none found | none | ok |
| Go toolchain for `engines/awg-socks` | go 1.25.0 | go1.26.10 / go1.27.3 | 30 reachable stdlib vulns (govulncheck) | `go 1.26.10` in go.mod | applied, govulncheck now 0 reachable |
| golang.org/x/net, crypto, sys, time | 0.44 / 0.42 / 0.36 / 0.9 | 0.61 / 0.58 / 0.49 / 0.16 | GO-2026-6617, 6612, 6611, 6603 (x/net < 0.60) | bumped | applied |
| gVisor (netstack, via amneziawg-go) | 20231202 pseudo-version | go branch commit 333ab1ce (2026-10-09, go 1.26.3); HEAD needs go 1.27.3 | no reachable finding | try the bump on a fast network | follow-up (go get could not finish cloning) |
| SagerNet/gomobile fork | v0.1.13 | v0.1.13 | none | none | ok |
| OpenVPN | system 2.7.0 | 2.7.8 (2026-10-07) | many; see below | minimum 2.7.8 enforced in `scripts/test-openvpn-docker.sh` | applied for tests; runtime check is a follow-up |
| Tauri / CLI | =2.12.1 / 2.12.1 | 2.12.5 / 2.12.4 | none found | bump version lines in apps/desktop | follow-up (app owner) |
| UniFFI | 0.29.5 | 0.32.2 | basic-toml (build tool only) | needs generated-binding and source changes | follow-up |
| keyring | 3.6.3 | 4.2.0 | zbus/zvariant unmaintained (Linux) | needs source changes | follow-up |
| rusqlite / bundled SQLite | 0.37 / SQLite 3.50.2 | 0.40.2 / SQLite 3.53.2 bundled | CVE-2026-11822, CVE-2026-11824 (FTS5, before 3.53.2) | bumped | applied |
| rqrr / lru | 0.9.3 / lru 0.12.5 | 0.11.0 / lru 0.18.5 | RUSTSEC-2026-0253, RUSTSEC-2026-0002 | bumped, no source change | applied, advisories gone |
| serde_yaml_ng / unsafe-libyaml | 0.10.0 / 0.2.11 | no newer release | RUSTSEC-2024-0449 unmaintained | see swap plan | accepted, ignore with reason |
| ureq 3.5.0, rustls 0.23.46, ring 0.17.14, image 0.25.10, flate2 1.1.10 | current | current | none | none | ok |
| Android: AGP / Kotlin / Compose BOM / NDK | 8.13.0 / 2.2.20 / 2025.09.01 / 28.2 | 9.4.1 / 2.4.21 / 2026.09.00 / r30 | not scanned | planned upgrade by the Android owner (AGP 9 needs Gradle 9) | follow-up |
| Gradle | 8.14.3 (sha256 in wrapper) | 9.8.2 | not scanned | with AGP 9 | follow-up |
| XcodeGen | brew (unpinned) | 2.46.0 | none | pinned download with SHA-256 in ios.yml | applied, untestable without a Mac |

## OpenVPN advisories that affect 2.7.0

Source: https://community.openvpn.net/Security%20Announcements and the per-CVE pages.
CVE-2026-84790 (identity/authentication bypass via embedded NUL in a certificate subject, affects
2.3.0 to 2.7.7, fixed 2.7.8), CVE-2026-88964 (underflow on a malicious PUSH_UPDATE, 2.7.8),
CVE-2026-84732 (2.7.7), CVE-2026-84471 (double free, 2.7.7), CVE-2026-63650 (mbedTLS ignores
x509-username-field, 2.7.6), CVE-2026-13117, CVE-2026-12996, CVE-2026-12932, CVE-2026-13122,
CVE-2026-11771 (all 2.7.5), CVE-2026-40215 and CVE-2026-35058 (2.7.2). Decision: minimum 2.7.8.

## Rust advisories after the upgrades (cargo audit, both lock files)

| Advisory | Crate | Decision |
|---|---|---|
| RUSTSEC-2024-0449 | unsafe-libyaml via serde_yaml_ng | accept: Clash YAML input is capped at 256 KiB. Swap plan: move the importer to `serde_norway` or `saphyr`/`serde-saphyr` (pure Rust parsers), keep the same untyped `Value` model, and run the importer fuzz target and import tests against both before switching. |
| RUSTSEC-2026-0370/0371/0372 | zvariant, zbus_names, zvariant_derive via keyring 3 (Linux) | accept until keyring 4 is adopted (needs source changes in core-keyring). |
| RUSTSEC-2026-0374 | basic-toml via uniffi | accept: build-time tool only; goes away with a UniFFI upgrade. |
| RUSTSEC-2024-0370, RUSTSEC-2024-0429 | proc-macro-error, glib 0.18 (desktop only) | accept: Tauri GTK3 stack, not under our control. |

`cargo deny` (`crates/deny.toml`) passes today for both the workspace and the desktop crate. The
lru unsoundness is no longer present.

## Download integrity

- sing-box archives: pinned tag plus SHA-256 in `apps/desktop/engines.lock`; `build-desktop.sh`
  verifies against the lock and the digest GitHub publishes; every mismatch is fatal. sing-box
  publishes no signature, so the lock file is the trust anchor.
- `scripts/update-pins.sh` fetches release metadata, downloads each archive, requires the computed
  hash to equal the published digest, refuses pre-releases and downgrades, prints a diff, and only
  rewrites the lock with `--write`.
- Go toolchain and modules: fetched through the Go module proxy and verified by go.sum and the
  public checksum database.
- Docker: base image pinned by digest; rustup-init pinned and SHA-256 verified (no `curl | sh`);
  same in `scripts/check-cross.sh`, which also installs a hash-pinned ziglang.
- GitHub Actions: all pinned to full commit SHAs (tag recorded in a comment) with
  `permissions: contents: read`. Newer majors exist for several actions (checkout v7, setup-go v7,
  cache v6); moving to them needs a CI run.
- Not pinned by checksum: gomobile and sing-box source (pinned by tag and commit; go install is
  sumdb-verified), Android NDK and SDK packages (sdkmanager verifies), Rust `stable` channel.

## Reproducibility

Both `Cargo.lock` files are committed; tests ran with `--locked`. Go builds use `-trimpath`.
SBOMs: `scripts/gen-sbom.sh` writes CycloneDX 1.5 files to `docs/SBOM/` for core-ffi, core-app,
wt-cli and the desktop crate (and for the Go helper when cyclonedx-gomod is installed).

## Protocol surface not exposed today (sing-box 1.14, assessment only)

| Feature | Value | Effort | Risk | Owner |
|---|---|---|---|---|
| ShadowTLS / shadowsocks plugins | high in restrictive networks | medium (importer, config builder) | low | core-import, core-engine |
| NaiveProxy outbound | medium; only on some platforms, needs libcronet on Windows | high | medium | core-engine, packaging |
| TCP multiplex (smux/yamux), UDP over TCP | medium | low | low | core-import, core-engine |
| ECH, reality already via TLS options | medium | low | low | core-import |
| Hysteria2 brutal/BBR profile, port hopping, Realm NAT traversal | medium | low | low | core-import |
| Snell, OpenVPN and OpenConnect endpoints inside sing-box | high long term, replaces the system OpenVPN dependency | high | medium (new code in upstream) | core-engine |
| Tailscale endpoint | niche | high | medium | none planned |
