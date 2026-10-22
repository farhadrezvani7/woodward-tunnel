# Woodward Tunnel desktop (Windows, macOS, Linux)

Tauri 2 shell around the shared Rust core (`crates/core-app`). The Rust backend calls the core
in-process; the UI in `ui/` is plain HTML/CSS/JS (no framework, no CDN, no remote assets, strict
CSP, bundled Vazirmatn font, OFL) and only ever receives summaries: names, protocol badges,
connection state. Profiles and configs never reach the UI; secrets live in the OS keychain
(Keychain / Credential Manager / Secret Service). If the OS store is unavailable the app says so and
keeps profiles for that session only; it never writes secrets to disk.

UI: Persian first (RTL) with an English toggle, dark/light follow the system, one big connect button
(state is shown by icon, border style and text, never colour alone), profile list with protocol badge,
add by file picker, drag and drop, clipboard paste (with a paste box fallback) and QR image,
rename/group/delete, an in-app confirmation before any subscription URL is downloaded, tray menu
(show, connect/disconnect, quit). Technical options live under "تنظیمات تخصصی" (Advanced settings):
connection type (whole system / local SOCKS proxy only), SOCKS port, DNS, system info.

## Layout

- `src-tauri/src/backend.rs` window-independent app layer (what the Tauri commands call, and what the tests drive)
- `src-tauri/src/lib.rs` Tauri commands, drag-drop, quit handling; `tray.rs`; `privilege.rs`
- `src-tauri/tests/e2e.rs` end-to-end tests against a real sing-box
- `src-tauri/resources/macos-elevate-singbox.sh` macOS root launcher
- `src-tauri/linux/postinst` file capabilities for the engine
- `engines.lock` pinned sing-box release archives + SHA256; `../../scripts/build-desktop.sh` builds everything
- `docker/` Linux build and test image and in-container scripts
- `../../.github/workflows/desktop.yml` CI for Linux, Windows, macOS (written, not run)

The Tauri crate has its own `[workspace]` and is not part of the root workspace.

## Build

```
scripts/build-desktop.sh linux     # Docker: .deb, AppImage, raw binary -> apps/desktop/dist/
scripts/build-desktop.sh test      # Docker: cargo tests incl. sing-box end-to-end
scripts/build-desktop.sh native    # on Windows/macOS/Linux with the toolchain installed (used by CI)
```

The script downloads the pinned official sing-box archive for the target, checks its SHA256 against
both `engines.lock` and the digest GitHub publishes for the release asset, and fails on mismatch.
`awg-socks` is cross-compiled with Go (`CGO_ENABLED=0`). Both are bundled as Tauri `externalBin`
sidecars named `wt-sing-box` and `wt-awg-socks` (the prefix avoids clashing with a system sing-box
package). OpenVPN is not bundled: it is used if `openvpn` is next to the app or on PATH, and OpenVPN
profiles need that binary (and root) installed separately.

## Privileges (system tunnel needs them)

| OS | Mechanism | Tradeoff |
|----|-----------|----------|
| Linux | The `.deb` postinst runs `setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep /usr/bin/wt-sing-box`. If capabilities are missing (AppImage, manual install) the app asks once and runs `pkexec setcap ...` on the engine. | Anyone who can run that engine with their own config gets those capabilities. Use "local proxy only" mode to avoid it. AppImage: the setcap fallback applies to the extracted engine path only if it is a real file on a normal filesystem. |
| Windows | App manifest `requireAdministrator` (see `build.rs`): UAC prompt at each launch. | Whole UI runs elevated; simplest and robust, least privilege-separated. |
| macOS | `macos-elevate-singbox.sh` is started in place of sing-box in TUN mode and shows the system administrator prompt (`osascript ... with administrator privileges`) at each connect. The root part stops the engine when the app stops it, when the flag file disappears, or when the wrapper dies. | A password prompt per connect, and the root process runs a config file owned by the user. A launchd-installed privileged helper (one-time install) would be better and is not implemented. |

Code signing and notarization are out of scope; the workflow has marked TODO secrets.

## What was verified (and what was not)

Run for real, Linux x86_64, inside Docker (Ubuntu 24.04, WebKitGTK 4.1):
- Linux bundle build: `.deb`, AppImage, raw binary via `scripts/build-desktop.sh linux`.
- `.deb` install in a container: postinst sets the capabilities, removal clears them; control file dependencies checked.
- Engine download verification: success path, and the mismatch path (failed the build).
- Rust integration tests (`tests/e2e.rs`): import `ss://` through the backend, rename, connect in proxy
  mode against a local sing-box shadowsocks server, status reaches `connected`, traffic through the SOCKS
  port, disconnect releases the port, no secret in the profile DTOs or status events; file import only
  reads regular files and enforces the size cap.
- TUN mode in Docker (`--cap-add NET_ADMIN --device /dev/net/tun`): reaches `connected` as root and as a
  non-root user with the file capabilities set; without capabilities `connect` is refused with
  `needs_privilege`. The probe goes to 1.1.1.1:443, so this proves the engine created the TUN device and
  started, not that probe bytes were observed on the TUN interface.
- GUI under Xvfb with a real keyring (gnome-keyring): screenshots of empty state, paste dialog,
  subscription confirmation, list, connecting, connected with timer, advanced settings, English UI,
  reconnecting with a plain-language reason (Persian shaping and RTL layout were checked in them).
  Importing and connecting through the GUI used the real secure storage and a real sing-box.
- macOS launcher script logic, using a stub `osascript` on Linux (starts the engine, relays its output,
  SIGTERM stops it, SIGKILL of the wrapper still stops it).

Only written, never run: Windows build/manifest/NSIS/MSI, macOS build/dmg and the real `osascript`
prompt, Keychain and Credential Manager use, the GitHub workflow, the `pkexec setcap` fallback dialog
(only the capability check and the refusal path ran), drag-and-drop of files (the Rust handler reads
only dropped regular files; xdotool cannot synthesize a drag from a file manager), QR image import
through the GUI (covered by core tests), AmneziaWG/OpenVPN through the desktop app.

## Known limits

- Plain-language failure texts come from the core in Persian; the English UI maps the four known
  texts and shows import problem messages in Persian.
- Tray icons depend on the desktop environment (AppIndicator on Linux); closing the window quits the app
  and disconnects first.
- Tauri and plugin versions are pinned (`tauri =2.12.1`, `tauri-build =2.7.1`, dialog `=2.8.1`, CLI
  2.12.1); transitive crates follow `src-tauri/Cargo.lock`.
