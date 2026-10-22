# Woodward Tunnel for iOS and iPadOS

SwiftUI app plus a Network Extension (packet tunnel) that runs sing-box (`libbox`). All
protocol parsing, storage and config generation is the shared Rust core (`crates/core-ffi`,
library `wtcore`, UniFFI 0.29).

**Status: written on Linux, never compiled with Xcode.** Read the "UNVERIFIED" section before
trusting anything here. The first real compile will happen on the macOS runner in
`.github/workflows/ios.yml` or on a Mac with `scripts/build-ios.sh`.

## Layout

```
apps/ios/
  project.yml                 XcodeGen spec (the .xcodeproj is generated, never committed)
  App/                        app target (SwiftUI)
    WoodwardTunnelApp.swift   @main
    AppModel.swift            single ObservableObject: profiles, import, connection state
    L10n.swift                L("key") lookup
    Core/                     CoreService (async wrapper over UniFFI WtApp), Keychain bridge
    Tunnel/TunnelController   NETunnelProviderManager: create, start, stop, status, failure reason
    Views/                    ConnectView (one big button), ProfileListView, QR scanner,
                              AdvancedView ("تنظیمات تخصصی"), import sheets
    Resources/{fa,en}.lproj   Localizable.strings and InfoPlist.strings (Persian is the
                              development language, English secondary)
    Assets.xcassets           placeholder icon (scripts/make-icon.py) and accent colour
    Info.plist, PrivacyInfo.xcprivacy
  PacketTunnel/               extension target
    PacketTunnelProvider      reads config, sets up libbox, starts and stops sing-box
    PlatformInterface         LibboxPlatformInterface + CommandServerHandler (TUN, network monitor)
    LibboxHelpers             iterator adapters
    Info.plist, PrivacyInfo.xcprivacy
  Shared/                     compiled into BOTH targets; no UI frameworks
    Logic/                    pure Swift: state machine, failure mapping, secret vault,
                              config handoff files, profile grouping, import summary, DNS parsing
    Platform/                 SystemKeychainBackend (Security.framework)
  Config/*.entitlements       network-extension packet-tunnel-provider, app group, keychain group
  Tests/SharedTests           XCTest for Shared/Logic (run on Linux or macOS, see below)
  scripts/                    typecheck-linux.sh, check-strings.py, make-icon.py
../../scripts/build-ios.sh    builds everything on macOS
../../.github/workflows/ios.yml
```

### How the pieces talk

* The app owns the Rust core. The core stores profiles in `Application Support/WoodwardTunnel`
  (excluded from backup) and secrets through `SecretCallbacks`, implemented over the Keychain
  (`kSecClassGenericPassword`, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, shared
  access group).
* On Connect the app asks the core for a launch plan. `singBox` yields the config JSON. The app
  writes it to `<app group>/tunnel/config.json` (file protection
  `completeUntilFirstUserAuthentication`), creates/refreshes the `NETunnelProviderManager` and
  calls `startVPNTunnel()`. The config is not put into `providerConfiguration` (the system keeps
  that in VPN preferences) and never in logs. The extension deletes the file right after
  reading it; the app deletes it again when the tunnel goes down.
* `amneziaWg` / `openVpn` plans show a Persian explanation (`failure.unsupported_*`). Nothing
  crashes and the extension is not started.
* If the extension fails it writes only a failure code (`last_failure.json`) that the app maps to
  a plain explanation. The text of sing-box errors is never forwarded because it can contain
  server names.
* Subscription URLs found during import trigger a confirmation dialog that shows only the host
  (the URL usually carries a token); only after "Download" is `importSubscription` called.

## Building on a Mac

Requirements: Xcode 16+, Rust (rustup), Go (sing-box 1.14.x needs a recent Go, `GOTOOLCHAIN=auto`
downloads it), `brew install xcodegen`.

```sh
scripts/build-ios.sh            # rust + libbox + project + simulator build
scripts/build-ios.sh archive    # unsigned device archive
scripts/build-ios.sh test       # pure-Swift logic tests
open apps/ios/WoodwardTunnel.xcodeproj
```

Stages produce, under `apps/ios/Generated/` (git-ignored): `wtcore.xcframework` (static Rust
libs: device, and a fat simulator slice), `Bindings/` (UniFFI `wtcore.swift`, header,
`module.modulemap`), `Libbox.xcframework` (gomobile). Identifiers (bundle ids, app group,
keychain group, team) are build settings at the top of `project.yml`; they flow into the
Info.plists and entitlements. To run on a device you must set `DEVELOPMENT_TEAM`, create the
App IDs, the app group and enable the Network Extension capability (see checklist).

`SING_BOX_TAG` (default `v1.14.3`) pins the libbox version. The extension's
`PlatformInterface.swift` is written against that exact version; if you change the tag, expect to
re-sync it (the compiler will tell you).

### Checking on Linux

```sh
apps/ios/scripts/typecheck-linux.sh /path/to/swift          # builds and runs 14 logic tests,
                                                            # syntax-parses every Swift file
WT_BINDINGS=<dir> apps/ios/scripts/typecheck-linux.sh ...   # also type-checks App/Core against
                                                            # freshly generated UniFFI bindings
python3 apps/ios/scripts/check-strings.py                   # fa/en keys and placeholders
```

On very new distributions the Swift 6.0.3 toolchain needs a `libxml2.so.2` symlink on
`LD_LIBRARY_PATH` (pointing at the installed `libxml2.so.16`).

## What was and was not checked

Checked on Linux with Swift 6.0.3:

* `Shared/Logic` and `Shared/Platform` (minus Security) compile, and 14 XCTest cases pass
  (state machine, failure mapping, secret vault round trip, handoff files, grouping, import
  headline, DNS parsing, image sniffing, elapsed formatter).
* `App/Core/CoreService.swift` and `AppSecretCallbacks.swift` type-check against bindings
  generated from the current `core-ffi` (`wtcore.swift`), with a stub for the Keychain backend.
* Every Swift file in the project parses (syntax only).
* `PlatformInterface.swift` implements exactly the 27 + 7 methods of `LibboxPlatformInterface` and
  `LibboxCommandServerHandler` in the Objective-C header that `gobind -lang=objc` generates from
  sing-box v1.14.3 (names compared with a script; signatures converted by hand following gomobile's
  Swift import rules and SagerNet's open-source sing-box-for-apple).
* `fa`/`en` strings are consistent; the workflow is valid YAML.
* `project.yml` was fed to XcodeGen 2.45.4 (built from source on Linux): it generated a project
  with both targets, the extension embedded in the app, both xcframeworks in the link phases,
  `PrivacyInfo.xcprivacy` and the strings/assets in the resource phases, Info.plists out of the
  resource phase, entitlements and include paths set. That only proves the spec is well formed,
  not that Xcode builds it.

## UNVERIFIED (never compiled or run)

* Everything that imports SwiftUI, UIKit, AVFoundation, PhotosUI, NetworkExtension, Network or
  Libbox: all of `App/Views`, `App/AppModel.swift`, `App/Tunnel`, `PacketTunnel/*`. Expect
  compile errors on the first Xcode build (type inference, availability, `Sendable` warnings).
* The exact Swift signatures of the libbox protocol methods (derived by hand from the ObjC header).
* `project.yml` semantics (XcodeGen): optional source path, xcframework dependencies, resource
  phase for `PrivacyInfo.xcprivacy`, extension embedding. Whether `Libbox.xcframework` contains a
  static or dynamic library (the project links it statically; `build-ios.sh` prints `file` output).
* The trimmed libbox tag set (`with_gvisor,with_quic,with_wireguard,with_utls,with_dhcp,...`) and
  the gomobile flags; sing-box's own app uses a larger set via `cmd/internal/build_libbox`.
* The NEVPN / NEVPNConnection error numbers in `FailureMapping`, and `fetchLastDisconnectError`
  availability.
* Keychain access group behaviour, `$(AppIdentifierPrefix)` substitution in Info.plist, app group
  file protection behaviour when the extension starts while the device is locked.
* Required-reason API entries in the privacy manifests (UserDefaults `CA92.1`, file timestamp
  `C617.1`, system boot time `35F9.1`). They are a best guess for what the Rust and Go runtimes
  trigger in a static scan; Apple's upload validation is the judge. Disk-space APIs may also be
  flagged.
* `build-ios.sh` and `ios.yml` as a whole (Xcode image name, `setup-xcode` selector, caching).
* Tunnel behaviour: DNS handling, IPv6, route settings, reconnect on network change, sleep/wake.
* Memory: see risks.

## Risks

1. **Extension memory limit.** Packet tunnel extensions are terminated when they use too much
   memory; ~50 MB is commonly cited (UNVERIFIED, Apple does not publish it and it varies with iOS
   version/device). libbox sets `debug.SetMemoryLimit` to 80 % of 50 MiB and GC percent 50 when
   `oomKillerEnabled` is true on iOS (see `service/oomkiller` in sing-box; verify for your tag).
   The extension turns that on. Protocols with large buffers (hysteria2/tuic over QUIC, many
   concurrent connections, the gVisor stack) are the likeliest to hit it. Test on a real device
   with Instruments. If the extension is killed the app shows "connection ended unexpectedly".
2. **App Store review.** VPN apps get extra scrutiny; see checklist. Circumvention-focused
   apps are rejected in some regions and questioned in others.
3. **Licences.** sing-box is **GPL-3.0-or-later with an extra clause** forbidding use of the name
   or implied association ("no derivative work may use the name ... without prior consent").
   Linking `libbox` statically into an iOS binary and shipping through the App Store is a
   well-known GPL/App Store terms conflict. **Needs a legal read before any distribution**,
   including the effect on the (Apache-2.0) Rust crates when combined in one app, source-offer
   obligations, and whether to distribute only via sideload/TestFlight/another channel. The Rust core
   crates are Apache-2.0. gomobile (BSD), UniFFI (MPL-2.0) and Go's dependencies carry their own
   notices that must be shipped.
4. **Private-API surface.** The extension finds the utun file descriptor with
   `LibboxGetTunnelFileDescriptor()` (scans file descriptors); the KVC lookup
   `packetFlow.value(forKeyPath: "socket.fileDescriptor")` that the reference app uses first was
   deliberately left out to avoid a private-key reference.
5. **Minimum iOS 17** (`NavigationSplitView(preferredCompactColumn:)`, `ContentUnavailableView`).
6. **Export compliance.** `ITSAppUsesNonExemptEncryption` is intentionally not set so App Store
   Connect asks; a VPN app is usually not exempt.

## App Store VPN-app checklist (to verify with Apple's current guidelines)

- [ ] Apple Developer Program **organization** account (VPN apps using NEVPNManager / Network
      Extension must be submitted by an organization, per guideline 5.4 as remembered).
- [ ] Network Extension entitlement `packet-tunnel-provider` approved for both App IDs
      (app and extension), capabilities: App Groups, Keychain Sharing.
- [ ] Only the Network Extension framework / NEVPNManager APIs are used for VPN functionality.
- [ ] Privacy policy URL published and linked in App Store Connect and inside the app
      (placeholder: none yet).
- [ ] Clear disclosure of what data is collected and shared; the app declares **no tracking**
      and collects nothing; user data is never sold, shared with third parties or used for ads.
- [ ] Privacy nutrition label answers match `PrivacyInfo.xcprivacy`.
- [ ] Export compliance documentation (encryption) and any annual self-classification.
- [ ] Does not violate local laws in the countries where it is distributed; availability by
      storefront decided.
- [ ] App review notes with a test configuration or a demo account that works from the review
      location; explanation of what the app is for.
- [ ] Camera usage string (done, Persian and English); no other permission prompts.
- [ ] Review of guideline 2.5.x (no downloading executable code: configs are data) and 4.x
      (design, minimum functionality).
- [ ] Licence compliance for sing-box (GPL) cleared (see risks).
- [ ] Real app icon and screenshots (the icon here is a placeholder).

## Not done / limitations

* AmneziaWG and OpenVPN profiles are listed with a "not supported on iOS" note and refuse to
  connect (by design for this phase).
* No `.onOpenURL` / document types registration (import from Files uses the in-app picker only).
* No Xcode unit-test target; the logic tests run through `scripts/typecheck-linux.sh` (Swift
  Package built in a temporary directory) so they work on Linux CI.
* System proxy settings (`NEProxySettings`), on-demand rules, kill switch (`includeAllNetworks`)
  and Wi-Fi SSID based rules are not implemented. `includeAllNetworks()` returns false.
* The placeholder icon is generated by `scripts/make-icon.py`.
