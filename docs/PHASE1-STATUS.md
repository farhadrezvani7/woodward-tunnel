# Phase 1 status (core foundation)

Approved scope: Rust core, no engines, no UI, no platform tunnels yet.

| Crate | What it does | Acceptance (all passing) |
|---|---|---|
| core-model | Profile, Protocol, `Secret` (never printed), `ConfigIssue` with plain-language messages | secret redaction test; every issue has a user message |
| core-import | Detects and validates WireGuard/AmneziaWG `.conf`, vless/vmess/trojan/ss/hysteria2 links, multi-line paste; OpenVPN recognized and reported as not yet supported | 15 tests: valid, malformed, oversized, legacy cipher rejected, names sanitized, unknown query keys dropped |
| core-session | Pure connection state machine with backoff; `Connected` only after `TunnelVerified` | 9 tests incl. retry limit, no retry on config/permission errors, network change |

Deferred by decision: OpenVPN, iOS (pending legal/technical review), engines, UI.
Not done yet: secure storage, fuzzing, ovpn/QR import, real-server tests.
Next (Phase 1 remainder): core-store (SQLite + OS secret store), cargo-fuzz targets for core-import, redacted logging crate.
