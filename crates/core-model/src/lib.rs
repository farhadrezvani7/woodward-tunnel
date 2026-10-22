//! Shared types: protocols, profiles, secrets and classified config errors.

use std::collections::BTreeMap;
use std::fmt;

/// A value that must never reach logs, panics, or diagnostics.
/// `Debug` and `Display` print a fixed placeholder; use [`Secret::expose`] deliberately.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    WireGuard,
    AmneziaWg,
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    OpenVpn,
    Tuic,
    Hysteria1,
    Socks,
    HttpProxy,
    AnyTls,
    Ssh,
}

impl Protocol {
    pub const ALL: [Protocol; 13] = [
        Protocol::WireGuard,
        Protocol::AmneziaWg,
        Protocol::Vless,
        Protocol::Vmess,
        Protocol::Trojan,
        Protocol::Shadowsocks,
        Protocol::Hysteria2,
        Protocol::OpenVpn,
        Protocol::Tuic,
        Protocol::Hysteria1,
        Protocol::Socks,
        Protocol::HttpProxy,
        Protocol::AnyTls,
    ];

    /// Stable identifier used in storage and APIs. Never change an existing value.
    pub fn id(self) -> &'static str {
        match self {
            Protocol::WireGuard => "wireguard",
            Protocol::AmneziaWg => "amneziawg",
            Protocol::Vless => "vless",
            Protocol::Vmess => "vmess",
            Protocol::Trojan => "trojan",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Hysteria2 => "hysteria2",
            Protocol::OpenVpn => "openvpn",
            Protocol::Tuic => "tuic",
            Protocol::Hysteria1 => "hysteria1",
            Protocol::Socks => "socks",
            Protocol::HttpProxy => "http",
            Protocol::AnyTls => "anytls",
            Protocol::Ssh => "ssh",
        }
    }

    pub fn from_id(id: &str) -> Option<Protocol> {
        Protocol::ALL.iter().copied().chain([Protocol::Ssh]).find(|p| p.id() == id)
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Protocol::WireGuard => "WireGuard",
            Protocol::AmneziaWg => "AmneziaWG",
            Protocol::Vless => "VLESS",
            Protocol::Vmess => "VMess",
            Protocol::Trojan => "Trojan",
            Protocol::Shadowsocks => "Shadowsocks",
            Protocol::Hysteria2 => "Hysteria2",
            Protocol::OpenVpn => "OpenVPN",
            Protocol::Tuic => "TUIC",
            Protocol::Hysteria1 => "Hysteria",
            Protocol::Socks => "SOCKS5",
            Protocol::HttpProxy => "HTTP Proxy",
            Protocol::AnyTls => "AnyTLS",
            Protocol::Ssh => "SSH",
        }
    }
}

/// Which backend runs a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    SingBox,
    OpenVpn,
    AmneziaWg,
}

impl Protocol {
    pub fn engine(self) -> EngineKind {
        match self {
            Protocol::OpenVpn => EngineKind::OpenVpn,
            Protocol::AmneziaWg => EngineKind::AmneziaWg,
            _ => EngineKind::SingBox,
        }
    }
}

/// A parsed, validated connection profile. Secrets are kept apart from plain settings
/// so storage can send them to the OS secure store and keep the rest in the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub settings: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, Secret>,
}

/// Why a config was rejected. Each variant maps to a plain-language message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigIssue {
    #[error("empty input")]
    Empty,
    #[error("input too large ({0} bytes)")]
    TooLarge(usize),
    #[error("unrecognized format")]
    Unrecognized,
    #[error("protocol not supported yet: {0}")]
    Unsupported(&'static str),
    #[error("{protocol}: missing {field}")]
    MissingField {
        protocol: &'static str,
        field: &'static str,
    },
    #[error("{protocol}: invalid {field}")]
    InvalidField {
        protocol: &'static str,
        field: &'static str,
    },
}

impl ConfigIssue {
    /// Message for non-expert users: what happened and what to do next.
    pub fn user_message(&self) -> String {
        match self {
            ConfigIssue::Empty => "چیزی برای افزودن پیدا نشد. فایل، QR یا متن کپی‌شده را دوباره امتحان کنید.".into(),
            ConfigIssue::TooLarge(_) => "این فایل بزرگ‌تر از حد معمول یک کانفیگ است و برای امنیت خوانده نشد.".into(),
            ConfigIssue::Unrecognized => "این کانفیگ شناخته نشد. از ارائه‌دهندهٔ سرویس بخواهید آن را در قالب WireGuard، VLESS، VMess، Trojan، Shadowsocks یا Hysteria2 بفرستد.".into(),
            ConfigIssue::Unsupported(p) => format!("پروتکل {p} هنوز پشتیبانی نمی‌شود."),
            ConfigIssue::MissingField { protocol, field } => {
                format!("کانفیگ {protocol} شناخته شد اما بخش «{field}» را ندارد. از ارائه‌دهندهٔ سرویس بخواهید فایل کامل را دوباره بفرستد.")
            }
            ConfigIssue::InvalidField { protocol, field } => {
                format!("کانفیگ {protocol} شناخته شد اما بخش «{field}» نامعتبر یا ناقص است. از ارائه‌دهندهٔ سرویس بخواهید فایل را دوباره بفرستد.")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_never_prints() {
        let s = Secret::new("hunter2");
        assert!(!format!("{s:?}{s}").contains("hunter2"));
        assert_eq!(s.expose(), "hunter2");
    }
    #[test]
    fn issue_messages_are_nonempty() {
        for i in [
            ConfigIssue::Empty,
            ConfigIssue::TooLarge(1),
            ConfigIssue::Unrecognized,
            ConfigIssue::Unsupported("OpenVPN"),
        ] {
            assert!(!i.user_message().is_empty());
        }
    }
}
