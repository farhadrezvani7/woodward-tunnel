# Woodward Tunnel for Android

Kotlin and Jetpack Compose app (applicationId `app.woodwardtunnel`, minSdk 24, targetSdk 35).
The UI is Persian-first and right-to-left (English is the secondary locale). Everything technical
sits under "تنظیمات تخصصی" (advanced settings).

Layers:

- `bindings/` and `src/generated/kotlin` hold the UniFFI Kotlin bindings to the Rust core
  (`crates/core-ffi`, library `libwtcore.so`): import, profile storage, launch plan.
- `secrets/KeystoreSecretStore.kt` implements `SecretCallbacks`. Values are encrypted with an
  AES-256-GCM key held in AndroidKeyStore (the id is bound in as AAD). Only ciphertext is stored.
- `vpn/TunnelService.kt` is a foreground `VpnService` that runs sing-box through its gomobile
  library (`libbox.aar`). It implements libbox's `PlatformInterface` (TUN fd, `protect`, default
  network monitor). The config comes from the Rust core and goes straight to libbox; it is never put
  in an Intent, a log line or a file we write.
- `ui/` holds the Compose screens: one big connect button, state (not connected, connecting,
  connected with timer, error with plain explanation and retry), a profile list with protocol badge,
  and add by clipboard, file, image or camera QR (zxing-android-embedded, no Play Services).
  Links (`vless://`, `ss://`, ...) and shared text opened from other apps show a confirmation
  before anything is imported.

"Connected" is only shown after an HTTPS request to `cp.cloudflare.com/generate_204` succeeds
through the tunnel (3 tries). Otherwise the user sees an error and the tunnel is torn down.
AmneziaWG runs in-process: the core's launch plan gives a helper config, which is started with
`Awgmobile.start()` (the user-space peer from `engines/awg-socks/mobile`, built into the same gomobile
library as sing-box so there is one Go runtime and one `go.Seq`), then libbox is started with the plan's
sing-box config using the helper's loopback SOCKS5 port as upstream. The peer's endpoint IP is excluded from
the TUN routes (`excludeRoute` on API 33+; on API 24-32 libbox hands over computed route ranges that already
omit it, which `openTun` adds with `addRoute`). OpenVPN profiles show a Persian "not supported on this
device yet" message. Server hostnames are resolved by sing-box's `local` DNS server, implemented by
`vpn/LocalResolver.kt` on the device's real (non-VPN) default network.

Error and import messages come from the core in Persian and English; the app shows the language of the
app locale.

## Build

Requirements: JDK 17, Android SDK with platform 36 and NDK 28.2.13676358, Go (the sing-box
`go.mod` toolchain is fetched automatically), Rust with `rustup`, Python 3, git. Internet access.

```bash
scripts/build-android.sh                 # libbox.aar, libwtcore.so x4 ABIs, bindings, debug + release APK
scripts/build-android.sh --debug-only    # skip assembleRelease
scripts/build-android.sh --skip-libbox   # reuse apps/android/app/libs/libbox.aar
scripts/build-android.sh --skip-rust     # reuse existing .so files and bindings
```

Pins: sing-box tag `v1.14.3` (commit checked), SagerNet gomobile `v0.1.13`, Gradle 8.14.3
(wrapper with checksum), AGP 8.13.0, Kotlin 2.2.20, Compose BOM 2025.09.01, JNA 5.17.0,
zxing-android-embedded 4.3.0. libbox is built with the same `gomobile bind` invocation as
sing-box's `build_libbox` but a smaller tag set (`with_gvisor,with_quic,with_wireguard,with_utls,
with_clash_api`, no naive/tailscale/openvpn/openconnect/usbip). The same bind also includes
`engines/awg-socks/mobile`; a `go.work` file in `.cache/` ties the pinned sing-box checkout and that module together.

Outputs: `app/build/outputs/apk/debug/app-debug.apk` and `app/build/outputs/apk/release/app-release.apk`.
The release APK is signed with a throwaway keystore generated into `apps/android/keystore`
(git-ignored). Real release keys are out of scope and nothing is published.

Generated and git-ignored: `app/libs/`, `app/src/main/jniLibs/`, `app/src/generated/`, `.cache/`.

## Run and test on an emulator

```bash
emulator -avd <name> -no-window -no-audio -gpu swiftshader_indirect
adb install -r apps/android/app/build/outputs/apk/debug/app-debug.apk
adb shell pm grant app.woodwardtunnel android.permission.POST_NOTIFICATIONS
adb shell cmd locale set-app-locales app.woodwardtunnel --locales fa     # or en
```

End-to-end test with a local Shadowsocks server (host side):

```bash
# server.json: inbound {"type":"shadowsocks","listen":"0.0.0.0","listen_port":18388,
#   "method":"aes-256-gcm","password":"<pw>"}, outbound direct
sing-box run -c server.json
# link: ss://base64url(aes-256-gcm:<pw>)@10.0.2.2:18388#Local-SS-Test   (10.0.2.2 = host)
adb shell am start -a android.intent.action.VIEW -d 'ss://...'
```

The app shows the "add configuration?" dialog; tap "افزودن" (or find the button with
`adb shell uiautomator dump /sdcard/ui.xml`). Then tap the big button. The system VPN consent
dialog (`com.vpndialogs`) appears the first time; accept it by tapping OK at the bounds reported
by `uiautomator dump` (`android:id/button1`). `adb shell appops` cannot grant VPN consent here.
Take screenshots with `adb exec-out screencap -p > shot.png`.

## What was verified for real (x86_64 emulator, Android 16 / API 36.1, KVM)

Host servers were local sing-box (Shadowsocks, Trojan, VLESS+WS, Hysteria2) and `engines/bin/awg-testserver`;
the emulator reaches the host at 10.0.2.2. Each "Connected" below means the app's HTTPS probe through the tunnel
succeeded (except AmneziaWG, see there).

- Debug and release (R8) APKs build, install and launch; Persian RTL UI renders (screenshots read back).
- Import through `VIEW` / `SEND` intents with the confirmation dialog. The Shadowsocks password is in neither
  `profiles.db` nor the secret file (grep).
- Shadowsocks (IP server): Connected; `tun0` up; host server saw the connections; disconnect removes `tun0`;
  no `configuration.json` left. With the server stopped: error state with a plain explanation and retry.
- Shadowsocks with a hostname server (`10.0.2.2.nip.io`, resolved by the host and emulator DNS): Connected, and the
  server saw the connections. This exercises the core's `bootstrap` local DNS through `LocalResolver`.
- Trojan (TLS, self-signed from `sing-box generate tls-keypair`, `allowInsecure=1`): Connected, the
  insecure-TLS warning is shown, 3 established connections on the server.
- VLESS + WebSocket (no TLS): Connected, 4 established connections on the server.
- Hysteria2 (QUIC, self-signed, `insecure=1`): Connected. Evidence is indirect: the probe passed while the TCP
  servers (Trojan, VLESS) had zero connections and Hysteria2's UDP socket was the only other path.
- AmneziaWG (obfuscated `awg-testserver`, Endpoint changed to 10.0.2.2:port): imported as AmneziaWG, connect
  works on API 36 (`ip route` shows `throw 10.0.2.2` in the VPN table, so the endpoint bypasses the tunnel).
  With "check internet" turned off in advanced settings (the test config only routes 10.0.0.0/24), an
  `adb shell` request to `10.0.0.1:8080` returned `hello-through-awg`; the same request after disconnect timed out.
- OpenVPN profile shows the "protocol not supported yet" message.
- Settings screen, including the new "check internet after connecting" switch.

## Not verified

- Real devices, other ABIs (armeabi-v7a, x86, arm64-v8a are compiled and packaged, never run), other Android versions
  (including the pre-API-33 route-range path for the AmneziaWG endpoint exclusion).
- English text from the core (`reasonEn`): compiled in, not looked at on screen.
- Camera QR scan, file and image pickers, subscription download, rename / group / delete dialogs.
- Always-on VPN / "block connections without VPN": only the link to the system settings exists.
- Other protocols through libbox (TUIC, AnyTLS, SSH, WireGuard, SOCKS, HTTP, VMess, Hysteria1), IPv6, UDP apps.
- AmneziaWG with a full-tunnel (0.0.0.0/0) config and a real internet probe; the in-process helper has no
  `VpnService.protect` of its own socket and relies on the route exclusion above.
- The CI workflow (`.github/workflows/android.yml`) was not executed.

## Known gaps

- OpenVPN is not available on Android in this phase.
- libbox writes the running config to `files/engine/configuration.json`; the app deletes it right
  after start, on stop and on launch. If the process is killed while connected it stays until the
  next launch (app-private storage, backups disabled).
- The engine's own error text is kept in memory only (advanced screen) and never logged.
- The app does not set per-app routing, split tunnelling or an HTTP system proxy.
