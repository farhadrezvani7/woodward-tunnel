//! Detect the protocol of pasted/loaded config text and parse it into a validated [`Profile`].
//! Parsers never execute or follow anything in the input; they only read and validate.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod analyze;
mod formats;
mod openvpn;
mod qr;
mod uri;
mod wireguard;

pub use analyze::{analyze, Analysis, Issue};
pub use qr::{analyze_bytes, decode_image};
use core_model::{ConfigIssue, Profile};

/// Hard cap on input size; real configs are a few KB.
pub const MAX_INPUT_BYTES: usize = 256 * 1024;
/// Hard cap on profiles taken from one subscription/paste.
pub const MAX_PROFILES: usize = 500;

/// Parse a single config.
pub fn detect(input: &str) -> Result<Profile, ConfigIssue> {
    let text = input.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Err(ConfigIssue::Empty);
    }
    if text.len() > MAX_INPUT_BYTES {
        return Err(ConfigIssue::TooLarge(text.len()));
    }
    if wireguard::looks_like(text) {
        return wireguard::parse(text);
    }
    if looks_like_openvpn(text) {
        return openvpn::parse(text);
    }
    if let Some((scheme, _)) = text.split_once("://") {
        return uri::parse(&scheme.to_ascii_lowercase(), text);
    }
    Err(ConfigIssue::Unrecognized)
}

/// Parse text that may contain several share links (one per line), as in a subscription paste.
/// Each line is reported separately so one bad entry does not hide the good ones.
pub fn detect_many(input: &str) -> Result<Vec<Result<Profile, ConfigIssue>>, ConfigIssue> {
    let text = input.trim();
    if text.is_empty() {
        return Err(ConfigIssue::Empty);
    }
    if text.len() > MAX_INPUT_BYTES {
        return Err(ConfigIssue::TooLarge(text.len()));
    }
    if text.lines().filter(|l| !l.trim().is_empty()).count() <= 1 || wireguard::looks_like(text) {
        return Ok(vec![detect(text)]);
    }
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .take(MAX_PROFILES)
        .map(detect)
        .collect())
}

fn looks_like_openvpn(text: &str) -> bool {
    let has = |key: &str| text.lines().any(|l| l.trim_start().starts_with(key));
    has("remote ") && (has("client") || has("dev ") || has("<ca>"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_model::Protocol;

    #[test]
    fn empty_and_oversized() {
        assert_eq!(detect("  \n"), Err(ConfigIssue::Empty));
        let big = "a".repeat(MAX_INPUT_BYTES + 1);
        assert!(matches!(detect(&big), Err(ConfigIssue::TooLarge(_))));
    }

    #[test]
    fn openvpn_is_detected() {
        let ovpn = "client\ndev tun\nremote vpn.example.com 1194\n<ca>\nX\n</ca>\n";
        assert_eq!(detect(ovpn).unwrap().protocol, Protocol::OpenVpn);
    }

    #[test]
    fn garbage_is_unrecognized() {
        assert_eq!(detect("hello world"), Err(ConfigIssue::Unrecognized));
        assert_eq!(detect("ftp://example.com"), Err(ConfigIssue::Unrecognized));
    }

    #[test]
    fn many_links_report_each_line() {
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let text = format!("vless://{uuid}@a.example.com:443?security=tls#A\nbogus line\ntrojan://pw@b.example.com:443#B\n");
        let r = detect_many(&text).unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].as_ref().unwrap().protocol, Protocol::Vless);
        assert!(r[1].is_err());
        assert_eq!(r[2].as_ref().unwrap().protocol, Protocol::Trojan);
    }
}
