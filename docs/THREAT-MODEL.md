# Threat model (current state)

Each row says what exists in the code today and where it is tested. Anything not listed here is
not claimed.

| Threat | Control in code | Test |
|---|---|---|
| Malicious imported config reads local files or runs code | OpenVPN: allowlist, dangerous directives rejected, script directives dropped, forced `script-security 0`. sing-box JSON: any `*_path` key rejected, dialer options stripped | `core-import` openvpn and formats tests |
| Imported file opens a listener, API, DNS or routing of its own | Importers take only outbound server definitions; generated engine configs hold exactly one inbound (TUN, or loopback SOCKS), no `experimental`/Clash API, no imported DNS or route rules. Xray configs hold only a loopback SOCKS inbound, no `api`/`stats`/`dns`/`routing` | `core-engine/tests/import_hostile.rs` (hostile sing-box JSON, Xray JSON, Clash YAML) |
| Another app on the phone or machine uses a helper engine's loopback SOCKS port (AmneziaWG helper, Xray) | RFC 1929 username/password on that port, random per session (16 bytes each), shared only with sing-box through the generated config; the helper refuses unauthenticated clients | `awgsocks` Go tests, `core-app` launch-plan test, `e2e_xray` |
| Local control port of the embedded sing-box (Android) | libbox command server listens on a unix socket in the app-private directory with a per-process secret, never on TCP; the generated config has no Clash API | `EngineRuntime.kt` setup (listen port 0), `import_hostile.rs` |
| Xray sockets loop back into the VPN (Android) | every Xray dial goes through `VpnService.protect` (dialer controller; listeners on non-loopback addresses too); a refusal fails the dial | live phone test (all Xray cases) |
| Weaker server verification than the link asked for | `pcs`/`vcn`/`pqv`/finalmask honored by Xray, never dropped; certificate pin mismatch stops the connection; skipping certificate verification is refused for Xray transports (Xray removed it); unencrypted VLESS/Trojan to public servers refused (Xray refuses too) | `e2e_xray` (wrong pin), `xray` unit tests, `xray run -test` check |
| DNS leaks through QUIC/DoQ-style paths | TUN configs reject UDP 443 unless allowed; DNS is hijacked into the tunnel resolver (DoH/DoT/UDP through the proxy); no other resolver is configured | `singbox` unit tests (nothing new in this change) |
| Credentials in logs or issue lists | `Secret` has no Debug/Display; `core-log` redacts known secrets, UUIDs, 32-byte keys, PEM, URL userinfo; issue labels carry scheme and host only | `core-log` tests, loopback e2e asserts UUID absent from logs, AWG e2e asserts private key absent |
| Secrets at rest | OS secure store; the database never receives them; a store failure aborts the import | `core-store` tests |
| Traffic leak when the tunnel drops (Linux) | nftables table with default-drop output, allowed only via the tunnel interface and to the server | `scripts/test-tun-docker.sh` (real TUN, tunnel killed, direct traffic blocked) |
| Leak rules injection | interface names validated against a strict character set | `core-policy` tests |
| Subscription fetch abuse | https only, 5 MB cap, private/loopback/link-local targets refused, no following links found inside a subscription | `core-app` fetch tests |
| Hostile archives/images | size and pixel caps on QR images, zlib output cap on Amnezia links | `core-import` tests |
| Insecure TLS option in a profile | honoured only if the profile asks for it, surfaced as `insecure_tls` for the UI to warn | engine tests |

Not done yet: macOS pf and Windows firewall rule application (generators exist, untested on those
OSes), DNS leak automation per OS, fuzzing, signed updates, third-party security audit.
