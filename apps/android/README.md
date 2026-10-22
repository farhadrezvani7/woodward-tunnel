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
AmneziaWG and OpenVPN profiles show a Persian "not supported on this device yet" message.

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
with_clash_api`, no naive/tailscale/openvpn/openconnect/usbip).

Outputs: `app/build/outputs/apk/debug/app-debug.apk` and `app/build/outputs/apk/release/app-release.apk`.
The release APK is signed with a throwaway keystore generated into `apps/android/keystore`
(git-ignored). Real release keys are out of scope and nothing is published.

Generated and git-ignored: `app/libs/`, `app/src/main/jniLibs/`, `app/src/generated/`, `.cache/`.

The script patches one line of the generated bindings (UniFFI 0.29 emits an invalid
`message` property for `FfiException.Failed`; it is renamed to `reason`, asserted to match once).

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

- Debug APK builds, installs and launches; Persian RTL UI renders (screenshots read back).
- Import through a `VIEW ss://` intent with the confirmation dialog; profile appears with the
  Shadowsocks badge. The secret is stored encrypted: the password string appears neither in
  `profiles.db` nor in the secret file.
- Connect: VPN consent dialog, then state "connected" after the HTTPS probe through the tunnel.
  `tun0` was up (172.19.0.1/30) and the host-side sing-box server showed established connections
  from the emulator. Disconnect removes `tun0`; no `configuration.json` is left behind.
- Failure path: with the server stopped, the app shows the error state with a plain Persian
  explanation and a retry button after the probe fails.
- OpenVPN profile (imported from shared text) shows the "protocol not supported yet" message.
- Settings screen renders.

## Not verified

- Real devices, other ABIs (armeabi-v7a, x86, arm64-v8a were compiled and packaged, never run),
  Android versions other than 16.
- Other protocols through libbox (only Shadowsocks was run end to end), IPv6, UDP.
- Camera QR scan (compiled only; no camera tested), file and image pickers, subscription download,
  rename / group / delete dialogs (not exercised on the emulator).
- Always-on VPN / "block connections without VPN": only the link to the system settings exists.
- `assembleRelease` signing and shrinking were built by the script but the release APK was not run.
- The CI workflow (`.github/workflows/android.yml`) was not executed.

## Known gaps

- AmneziaWG and OpenVPN are not available on Android in this phase.
- libbox writes the running config to `files/engine/configuration.json`; the app deletes it right
  after start, on stop and on launch. If the process is killed while connected it stays until the
  next launch (app-private storage, backups disabled).
- The engine's own error text is kept in memory only (advanced screen) and never logged.
- The DNS field in advanced settings shows mixed text direction in RTL.
- The app does not set per-app routing, split tunnelling or an HTTP system proxy.
