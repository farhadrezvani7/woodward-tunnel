# Status (2026-10-23)

"Run" means executed and observed in this environment (Linux x86_64 host, Docker, Android emulator
API 36.1 x86_64). "Written" means source exists but was never executed. Nothing is released or published.

## Protocols
| Protocol | Import | Config generated and accepted by the engine | Carried real traffic in a test |
|---|---|---|---|
| Shadowsocks, VLESS (tcp, ws+tls), VMess, Trojan+TLS, Hysteria1, Hysteria2, TUIC, AnyTLS, SOCKS5 (auth), HTTP proxy (auth) | run | run (`sing-box check`) | run: a loopback sing-box server per protocol; plus Linux TUN (Shadowsocks) and Android emulator (Shadowsocks, Trojan, VLESS+WS, Hysteria2) |
| WireGuard | run | run | run: user-space WireGuard server -> sing-box WireGuard endpoint |
| VLESS Reality, SSH | run | run | not run (Reality needs a real TLS front site; no ssh server in the test setup) |
| AmneziaWG (obfuscated) | run | run | run: user-space server -> helper -> sing-box via the runner; Android emulator; desktop backend test |
| OpenVPN | run (allowlist, hostile directives rejected) | run | run: real OpenVPN server and client in Docker, TUN, traffic through the VPN |
| Amnezia `vpn://` links | run against a link built to the documented format | - | not tested against a real Amnezia export |
| Clash, Xray, sing-box JSON, Outline JSON, base64 subscriptions, QR images | run | run | not run with a real provider's data |

## Platforms
| Platform | Core compiles | App built | App run | Tunnel verified |
|---|---|---|---|---|
| Linux | run | run (.deb, AppImage, binary in Docker) | run (Xvfb screenshots, real keyring) | run: Docker TUN with kill switch and recovery; non-root with file capabilities |
| Windows | run: `cargo check` for windows-gnu, all core crates and CLI | written | not run | not run |
| macOS | run: `cargo check` for aarch64 and x86_64 (zig as C compiler), all core crates and CLI | written | not run | not run |
| Android | run (4 ABIs) | run (debug and release APK) | run (emulator x86_64) | run (emulator, see table above) |
| iOS, iPadOS | not run | not run (no Xcode here) | not run | not run |

## Security controls with automated tests
See docs/THREAT-MODEL.md. Highlights that were found and fixed by testing: credentials leaking into
error labels (found by mutation fuzzing, 4.5 million inputs, none left), clippy-clean with warnings
denied, 0 known vulnerabilities in dependencies (docs/DEPENDENCY-AUDIT.md).

## Known gaps
- No code signing, notarization, installers for Windows/macOS, store packaging: out of scope for now.
- Windows and macOS: privilege handling, firewall rules (generators exist), keychain integration are untested.
- macOS asks for an administrator password at each connect.
- Android: real devices, API below 33 endpoint exclusion, full-tunnel AmneziaWG, TUIC/AnyTLS/SSH/WireGuard/SOCKS/HTTP/VMess/Hysteria1 not run. OpenVPN is not available on Android or iOS.
- iOS: nothing compiled; memory limit of the extension unverified; AmneziaWG shares one Go heap with sing-box.
- Supported only through sing-box: DNS-leak behavior is configured (DNS hijack, bootstrap resolver) but there is no automated per-OS leak test.
- Licenses: sing-box license needs a legal read before distribution (GitHub reports no standard license); OpenVPN is GPL.
- Not supported: ShadowsocksR, Snell, NaiveProxy, Cloak, IKEv2/IPsec, L2TP, PPTP, SSTP, OpenConnect.
