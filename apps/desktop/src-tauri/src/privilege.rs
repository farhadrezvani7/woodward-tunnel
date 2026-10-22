//! Privilege handling for the system tunnel (TUN), per operating system.
//!
//! - Linux:   the engine carries file capabilities (set by the package postinst). If they are
//!            missing, `grant` applies them once through polkit (`pkexec setcap`).
//! - Windows: the whole app runs elevated (manifest `requireAdministrator`); nothing to do here.
//! - macOS:   the engine is started through `macos-elevate-singbox.sh`, which asks for the
//!            administrator password with the system prompt at each connect.

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivState {
    Ok,
    /// The user must approve a one-time permission step (`grant`).
    NeedsGrant,
}

pub const LINUX_CAPS: &str = "cap_net_admin,cap_net_bind_service,cap_net_raw+ep";

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("Uid:")).map(|l| l.to_string()))
        .map(|l| l.split_whitespace().nth(2) == Some("0")) // effective uid
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn has_caps(engine: &Path) -> bool {
    let real = std::fs::canonicalize(engine).unwrap_or_else(|_| engine.to_path_buf());
    std::process::Command::new("getcap")
        .arg(&real)
        .output()
        .map(|o| {
            let t = String::from_utf8_lossy(&o.stdout);
            t.contains("cap_net_admin") && t.contains("ep")
        })
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
pub fn check(engine: &Path, _elevate_script: bool) -> PrivState {
    if is_root() || has_caps(engine) {
        PrivState::Ok
    } else {
        PrivState::NeedsGrant
    }
}

#[cfg(not(target_os = "linux"))]
pub fn check(_engine: &Path, _elevate_script: bool) -> PrivState {
    PrivState::Ok
}

/// One-time permission step. Returns a short, credential-free error string on failure.
#[cfg(target_os = "linux")]
pub fn grant(engine: &Path) -> Result<(), String> {
    let real = std::fs::canonicalize(engine).map_err(|_| "engine not found".to_string())?;
    let st = std::process::Command::new("pkexec")
        .arg("setcap")
        .arg(LINUX_CAPS)
        .arg(&real)
        .status()
        .map_err(|_| "pkexec is not available".to_string())?;
    // pkexec exits 126 when the user dismisses the dialog and 127 when authorization failed.
    if st.success() && has_caps(&real) {
        Ok(())
    } else {
        Err(format!("pkexec exit {}", st.code().unwrap_or(-1)))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn grant(_engine: &Path) -> Result<(), String> {
    Ok(())
}
