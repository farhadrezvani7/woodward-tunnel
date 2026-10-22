# Architecture

One Rust core, many thin front ends. Protocol engines are existing, maintained projects run as
helpers; the core never reimplements a protocol.

```
 front ends            core (Rust)                              engines                  OS tunnel
 ----------            -----------                              -------                  ---------
 Tauri desktop  ->  core-app  ->  core-import  (any config -> Profile)
 wt CLI                 |         core-store   (SQLite + OS secret store)
 Android (UniFFI) ->    |         core-session (state machine, backoff)
 iOS     (UniFFI) ->    |         core-engine  (config generation + runner)  sing-box   TUN / VpnService /
                        |                                                    awg-socks  Network Extension
                        +-------- core-policy  (kill-switch rule generators) openvpn
                        +-------- core-log     (redaction)
```

## Engines
| Protocol family | Engine | Notes |
|---|---|---|
| VLESS, VMess, Trojan, Shadowsocks, Hysteria 1/2, TUIC, AnyTLS, SOCKS, HTTP, SSH, WireGuard | sing-box | one TUN, routing and DNS implementation for all of them |
| AmneziaWG | `engines/awg-socks` (amneziawg-go, user space) -> sing-box | helper exposes a local SOCKS5; sing-box tunnels system traffic into it, so routing, DNS and kill-switch are shared |
| OpenVPN | `openvpn` binary (desktop) | profile is sanitized on import and rendered with `script-security 0` |

## Import
`core_import::analyze` takes any text or bytes and returns profiles, per-entry problems (plain
language, never containing credentials) and subscription URLs (the caller asks before fetching).
Formats: share links, WireGuard/AmneziaWG `.conf`, OpenVPN `.ovpn`, Clash YAML, Xray JSON,
sing-box JSON, Shadowsocks/Outline JSON, base64 subscription blobs, Amnezia `vpn://`, QR images.

## Secrets
Secrets (keys, passwords, UUIDs, inline certificates) are stored in the OS secure store through
the `SecretStore` trait (Keychain, Credential Manager, Secret Service, Android Keystore). SQLite
holds only non-secret metadata. Engine config files are written with mode 0600 and deleted on stop.
