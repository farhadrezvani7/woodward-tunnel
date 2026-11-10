# Status (2026-11-10)

"Run" means executed and observed in this environment (Linux x86_64 host, Docker, Android emulator
API 36.1 x86_64). "Written" means source exists but was never executed. Nothing is released or published.

## Protocols
| Protocol | Import | Config generated and accepted by the engine | Carried real traffic in a test |
|---|---|---|---|
| Shadowsocks, VLESS (tcp, ws+tls), VMess, Trojan+TLS, Hysteria1, Hysteria2, TUIC, AnyTLS, SOCKS5 (auth), HTTP proxy (auth) | run | run (`sing-box check`) | run: a loopback sing-box server per protocol; plus Linux TUN (Shadowsocks) and Android emulator (Shadowsocks, Trojan, VLESS+WS, Hysteria2) |
| WireGuard | run | run | run: user-space WireGuard server -> sing-box WireGuard endpoint |
| VLESS Reality | run | run | run on the phone against a sing-box Reality server (handshake target: a real public site); `pqv` only checked with `xray run -test` |
| SSH (password; with and without a pinned host key) | run | run | run: Go test SSH server (direct-tcpip), real phone |
| Xray-only configs (XHTTP/SplitHTTP, mKCP, TCP HTTP header, VLESS encryption, `pcs`/`vcn`/`pqv`/finalmask) | run (importer accepts them, marks `engine=xray`) | run (`xray run -test` on 20 generated configs) | run: loopback e2e (Xray server and client through the runner, incl. wrong certificate pin refused) and on the phone (XHTTP, VLESS encryption, TCP HTTP header, mKCP over UDP) |
| AmneziaWG (obfuscated) | run | run | run: user-space server -> helper -> sing-box via the runner; Android emulator; desktop backend test; real phone (traffic to a private address that exists only inside the tunnel crosses it, and does not after disconnect) |
| OpenVPN (desktop only) | run (allowlist, hostile directives rejected) | run | run: real OpenVPN server and client in Docker, TUN, traffic through the VPN. Not supported on Android or iOS |
| Amnezia `vpn://` links | run against a link built to the documented format | - | not tested against a real Amnezia export |
| Clash, Xray, sing-box JSON, Outline JSON, base64 subscriptions, QR images | run | run | not run with a real provider's data |

## Platforms
| Platform | Core compiles | App built | App run | Tunnel verified |
|---|---|---|---|---|
| Linux | run | run (.deb, AppImage, binary in Docker) | run (Xvfb screenshots, real keyring) | run: Docker TUN with kill switch and recovery; non-root with file capabilities |
| Windows | run: `cargo check` for windows-gnu, all core crates and CLI | written | not run | not run |
| macOS | run: `cargo check` for aarch64 and x86_64 (zig as C compiler), all core crates and CLI | written | not run | not run |
| Android | run (4 ABIs) | run (debug and release APK; sing-box v1.14.4, Xray-core v26.11.9 in one gomobile library) | run (emulator x86_64, real phone SM-A525F) | run (emulator and phone, see table above) |
| iOS, iPadOS | not run | not run (no Xcode here) | not run | not run |

## Security controls with automated tests
See docs/THREAT-MODEL.md. Highlights that were found and fixed by testing: credentials leaking into
error labels (found by mutation fuzzing, 4.5 million inputs, none left), clippy-clean with warnings
denied, 0 known vulnerabilities in dependencies (docs/DEPENDENCY-AUDIT.md).

## Known gaps
- No code signing, notarization, installers for Windows/macOS, store packaging: out of scope for now.
- Windows and macOS: privilege handling, firewall rules (generators exist), keychain integration are untested.
- macOS asks for an administrator password at each connect.
- Android: the RELEASE apk was installed on a real phone (Samsung SM-A525F, Android 14, arm64) and `scripts/android-live/run.py` ran every case against it on 2026-11-10: Shadowsocks (also UDP), VLESS tcp / ws+tls / Reality, VMess, Trojan, AnyTLS, SOCKS5, HTTP, Hysteria2, TUIC, Hysteria1, WireGuard, SSH (pinned and unpinned host key), and the Xray cases XHTTP, VLESS encryption, TCP HTTP header, mKCP; plus the AmneziaWG phase. UDP-based servers are reached through a UDP-over-TCP relay because `adb reverse` is TCP only. Servers are on the host over USB, so these show the apps and engines work, not how any real network treats them. Not run: Reality post-quantum verification (`pqv`) and finalmask against a real server, API below 33 endpoint exclusion, full-tunnel AmneziaWG with a real internet probe, any provider's real server.
- Xray-core limits (by design of Xray v26): no "skip certificate verification" (removed upstream; links asking for it are refused with a reason, use `pcs`/`vcn`), plain VLESS/Trojan without TLS/Reality/encryption to a public server is refused by Xray itself (we say so), ECH, TLS fragment and `disable_sni` cannot be combined with Xray transports, the HTTP/2 transport no longer exists in Xray. mKCP with both `seed` and a header type applies the two masks in a fixed order that was only verified against Xray itself, not against an older server.
- OpenVPN is not supported on Android and iOS (desktop only). A plan was to use sing-box's `openvpn-client` endpoint; it was dropped by decision, the Android app shows "protocol not supported yet" for OpenVPN profiles.
- iOS: nothing compiled; memory limit of the extension unverified; AmneziaWG shares one Go heap with sing-box.
- Supported only through sing-box: DNS-leak behavior is configured (DNS hijack, bootstrap resolver) but there is no automated per-OS leak test.
- Licenses: sing-box license needs a legal read before distribution (GitHub reports no standard license); OpenVPN is GPL.
- Not supported: ShadowsocksR, Snell, NaiveProxy, Cloak, IKEv2/IPsec, L2TP, PPTP, SSTP, OpenConnect.
