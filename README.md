# woodward-tunnel

One app for all your tunnels. A unified client for V2Ray (VLESS, VMess, Trojan, Shadowsocks), WireGuard,
OpenVPN, AmneziaWG, Hysteria, TUIC and more. Import a config from a file, a QR code or the clipboard;
the protocol is detected automatically; connect with one button.

Status: under construction, not released. See [docs/STATUS.md](docs/STATUS.md) for exactly what has been
run and what has only been written.

## What you can import
Share links (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria://`, `hysteria2://`, `hy2://`, `tuic://`,
`anytls://`, `socks5://`, `http-proxy://`, `ssh://`, `wireguard://`), WireGuard and AmneziaWG `.conf`,
OpenVPN `.ovpn`, Clash YAML, Xray JSON, sing-box JSON, Shadowsocks/Outline JSON, base64 subscriptions,
subscription URLs (downloaded only after you confirm), Amnezia `vpn://` links, and QR images.
Anything else is reported with a plain-language reason. Not supported: ShadowsocksR, Snell, NaiveProxy,
Cloak, IKEv2/IPsec, L2TP, PPTP, SSTP, OpenConnect/AnyConnect.

## Layout
| Path | What |
|---|---|
| `crates/` | Rust core: import, store, session state machine, engine runner, leak-protection rules, FFI, CLI |
| `engines/awg-socks/` | Go helper that runs AmneziaWG in user space (desktop and mobile) |
| `apps/desktop/` | Tauri app for Windows, macOS, Linux |
| `apps/android/` | Android app (Kotlin, VpnService, sing-box libbox) |
| `apps/ios/` | iOS and iPadOS app (SwiftUI, Network Extension) |
| `scripts/` | build and end-to-end test scripts |
| `docs/` | architecture, threat model, dependency audit, status |

## Build and test the core
```
./scripts/build-engines.sh              # Go helpers into engines/bin/
cargo test --workspace                  # unit and loopback end-to-end tests (needs sing-box on PATH)
./scripts/test-tun-docker.sh            # real TUN tunnel, kill switch, recovery (Docker)
./scripts/test-openvpn-docker.sh        # real OpenVPN server and client (Docker)
```
CLI: `cargo run -p wt-cli -- import <file|link>`, `wt list`, `wt connect <name> [--proxy 1080]`.

## Apps
Desktop: `scripts/build-desktop.sh linux` (Docker). Android: `scripts/build-android.sh`. iOS: on a Mac,
`scripts/build-ios.sh`. Details in each app's README.

## License
Apache-2.0 for this repository. Bundled engines have their own licenses (sing-box, amneziawg-go, OpenVPN);
check them before distributing binaries. See docs/STATUS.md.
