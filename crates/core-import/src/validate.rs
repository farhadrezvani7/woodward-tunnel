#![allow(dead_code)] // consumed incrementally by the importers; remove once uri.rs/formats.rs use every helper
//! Shared validation and normalization used by every importer. Nothing here trusts its input:
//! each function returns `None` for anything that is not unambiguously valid, and callers turn
//! that into a localized `ConfigIssue`. Strings that end up inside JSON fields the engine
//! interprets (hosts, paths, ids, names) go through these first.
//!
//! ## `Profile::settings` key schema (contract between importers and `core-engine::singbox`)
//!
//! Transport / TLS (all share-link, Clash, Xray and Amnezia importers normalize to these):
//! `security` (`tls`|`reality`; absent = none), `sni`, `alpn` (comma list), `fp` (uTLS name),
//! `insecure` (`1`), `pbk`, `sid`, `ech` (base64 ECHConfigList), `disable_sni` (`1`),
//! `tls_fragment` (`record`|`tcp`), `type` (absent = tcp; `ws`|`grpc`|`http`|`httpupgrade`|`quic`),
//! `path`, `host`, `serviceName`, `ed` (WebSocket max early data), `edh` (early data header),
//! `flow`, `packet_encoding` (`xudp`|`packetaddr`|`none`), `mux` (`smux`|`yamux`|`h2mux`),
//! `mux_padding` (`1`), `mux_max_connections`.
//! VMess: `cipher`, `alter_id`, `global_padding`, `authenticated_length`.
//! Shadowsocks: `cipher`, `plugin` (`obfs-local`|`v2ray-plugin`), `plugin_opts`.
//! Hysteria2: `obfs` (`salamander`|`gecko`), `obfs-password`, `server_ports` (`a:b,c:d`),
//! `hop_interval`, `up_mbps`, `down_mbps`, `min_packet_size`, `max_packet_size`.
//! Hysteria1: `obfs`, `up_mbps`, `down_mbps`, `server_ports`, `hop_interval`; the auth string is
//! secret `password`. TUIC: `congestion_control`, `udp_relay_mode`, `zero_rtt`, `heartbeat`,
//! `udp_over_stream`. SOCKS/HTTP/SSH: `username` (setting), `password` (secret); SSH `host_key`.
//! Legacy spellings (`allowInsecure`, `upmbps`, `downmbps`) are still read by the engine for
//! profiles stored by older builds but importers no longer produce them.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const MAX_NAME_CHARS: usize = 100;
pub const MAX_VALUE_CHARS: usize = 512;

/// Characters that can reorder or hide text in a UI (bidi controls) or that are invisible.
fn is_spoofing_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{00AD}' | '\u{180E}' | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// A display name: controls, bidi overrides and zero-width characters removed, whitespace
/// collapsed, at most [`MAX_NAME_CHARS`] characters. Falls back when nothing is left.
pub fn sanitize_name(raw: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    for c in raw.chars() {
        if c.is_control() || is_spoofing_char(c) {
            if c.is_whitespace() {
                pending_space = true;
            }
            continue;
        }
        if c.is_whitespace() {
            pending_space = true;
            continue;
        }
        if pending_space && !out.is_empty() {
            out.push(' ');
        }
        pending_space = false;
        out.push(c);
        if out.chars().count() >= MAX_NAME_CHARS {
            break;
        }
    }
    if out.is_empty() {
        fallback
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_NAME_CHARS)
            .collect()
    } else {
        out
    }
}

/// True for a string without control characters (tab included) and within `max` chars.
pub fn plain_text(s: &str, max: usize) -> bool {
    s.chars().count() <= max && !s.chars().any(|c| c.is_control() || is_spoofing_char(c))
}

/// Normalized server host: IPv4 (strict dotted quad), IPv6 (no zone, brackets removed), or an
/// RFC 1123 hostname (underscores tolerated, IDN converted to punycode, lowercase, no trailing dot).
pub fn host(raw: &str) -> Option<String> {
    let s = raw.trim();
    let s = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    if s.is_empty() || s.len() > 255 {
        return None;
    }
    if s.contains(':') {
        return s.parse::<Ipv6Addr>().ok().map(|a| a.to_string());
    }
    if s.chars()
        .any(|c| c.is_whitespace() || c.is_control() || "/\\@?#%[]<>\"'`{}|^".contains(c))
    {
        return None;
    }
    if s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return s.parse::<Ipv4Addr>().ok().map(|a| a.to_string());
    }
    let s = s.strip_suffix('.').unwrap_or(s);
    let ascii = match url::Host::parse(s) {
        Ok(url::Host::Domain(d)) => d,
        _ => return None,
    };
    if ascii.is_empty() || ascii.len() > 253 {
        return None;
    }
    for label in ascii.split('.') {
        let b = label.as_bytes();
        if b.is_empty()
            || b.len() > 63
            || b[0] == b'-'
            || b[b.len() - 1] == b'-'
            || !b
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        {
            return None;
        }
    }
    Some(ascii)
}

pub fn port(raw: &str) -> Option<u16> {
    raw.trim().parse::<u16>().ok().filter(|p| *p != 0)
}

fn hex_val(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// Canonical lowercase hyphenated UUID from the 36-char or 32-char hex forms.
pub fn uuid(s: &str) -> Option<String> {
    let b = s.trim().as_bytes();
    let hex: Vec<u8> = match b.len() {
        36 => {
            if [8, 13, 18, 23].iter().any(|i| b[*i] != b'-') {
                return None;
            }
            b.iter().copied().filter(|c| *c != b'-').collect()
        }
        32 => b.to_vec(),
        _ => return None,
    };
    if hex.len() != 32 || !hex.iter().all(|c| hex_val(*c).is_some()) {
        return None;
    }
    let h: String = hex
        .iter()
        .map(|c| (*c as char).to_ascii_lowercase())
        .collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// VLESS/VMess user id. Xray accepts any 1..=30 byte string as an id (mapped to a UUIDv5 with the
/// nil namespace, and sing-box applies the same mapping), so those are valid and kept verbatim.
/// Strings that look like a UUID but are malformed are rejected.
pub fn user_id(raw: &str) -> Option<String> {
    let s = raw.trim();
    let l = s.len();
    if !(32..=36).contains(&l) {
        return ((1..=30).contains(&l) && plain_text(s, 30)).then(|| s.to_string());
    }
    uuid(s)
}

/// 32-byte base64 key (WireGuard); returns the canonical standard-padded form.
pub fn key32(s: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let b = STANDARD.decode(s.trim()).ok()?;
    (b.len() == 32).then(|| STANDARD.encode(b))
}

/// Reality public key: 32 bytes, base64url without padding in sing-box and Xray.
pub fn reality_key(s: &str) -> Option<String> {
    use base64::{
        engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
        Engine,
    };
    let s = s.trim();
    [&URL_SAFE_NO_PAD, &URL_SAFE, &STANDARD_NO_PAD, &STANDARD]
        .iter()
        .find_map(|e| e.decode(s).ok())
        .filter(|b| b.len() == 32)
        .map(|b| URL_SAFE_NO_PAD.encode(b))
}

/// Reality short id: empty or 1..=8 bytes of hex (even number of digits).
pub fn short_id(s: &str) -> Option<String> {
    let s = s.trim();
    (s.len() <= 16 && s.len().is_multiple_of(2) && s.bytes().all(|c| c.is_ascii_hexdigit()))
        .then(|| s.to_ascii_lowercase())
}

/// uTLS fingerprint names sing-box accepts; Xray aliases are folded onto them.
pub fn utls_fingerprint(s: &str) -> Option<&'static str> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "chrome" => "chrome",
        "firefox" => "firefox",
        "edge" => "edge",
        "safari" => "safari",
        "360" => "360",
        "qq" => "qq",
        "ios" => "ios",
        "android" => "android",
        "random" => "random",
        "randomized" | "randomizedalpn" | "randomizednoalpn" => "randomized",
        _ => return None,
    })
}

/// ALPN list: comma separated protocol ids of 1..=255 visible ASCII characters each.
pub fn alpn_list(s: &str) -> Option<String> {
    let items: Vec<&str> = s
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .collect();
    if items.is_empty() || items.len() > 8 {
        return None;
    }
    items
        .iter()
        .all(|a| a.len() <= 255 && a.bytes().all(|c| c.is_ascii_graphic()))
        .then(|| items.join(","))
}

/// A URL path or header value that is safe to place in a JSON string the engine puts on the wire.
pub fn http_text(s: &str, max: usize) -> Option<String> {
    (plain_text(s, max)).then(|| s.to_string())
}

/// Boolean flags as spelled by the various ecosystems.
pub fn truthy(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" | "" => Some(false),
        _ => None,
    }
}

/// `a-b` / `a:b` / `a` port or port range list, comma separated; returns sing-box form `a:b`.
pub fn port_ranges(s: &str) -> Option<String> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (lo, hi) = match part.split_once(['-', ':']) {
            Some((a, b)) => (port(a)?, port(b)?),
            None => {
                let p = port(part)?;
                (p, p)
            }
        };
        if lo > hi {
            return None;
        }
        out.push(format!("{lo}:{hi}"));
        if out.len() > 64 {
            return None;
        }
    }
    (!out.is_empty()).then(|| out.join(","))
}

/// A CIDR or bare IP address; bare addresses get /32 or /128. Returns the canonical text.
pub fn cidr(s: &str) -> Option<String> {
    let s = s.trim();
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a.trim(), Some(l.trim().parse::<u8>().ok()?)),
        None => (s, None),
    };
    if let Ok(a) = addr.parse::<Ipv4Addr>() {
        let l = len.unwrap_or(32);
        return (l <= 32).then(|| format!("{a}/{l}"));
    }
    if let Ok(a) = addr.parse::<Ipv6Addr>() {
        let l = len.unwrap_or(128);
        return (l <= 128).then(|| format!("{a}/{l}"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(host("Example.COM").as_deref(), Some("example.com"));
        assert_eq!(host("[2001:db8::1]").as_deref(), Some("2001:db8::1"));
        assert_eq!(host("2001:DB8::1").as_deref(), Some("2001:db8::1"));
        assert_eq!(
            host("bücher.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(host("a_b.example.com.").as_deref(), Some("a_b.example.com"));
        for bad in [
            "",
            "a b",
            "-a.com",
            "a-.com",
            "a..com",
            "999.1.1.1",
            "0x7f.1",
            "fe80::1%eth0",
            "a/b",
            "a@b",
            "ex%41.com",
            "1.2.3",
            "a.com:80",
            "\u{202e}evil.com",
        ] {
            assert_eq!(host(bad), None, "{bad:?}");
        }
        assert_eq!(host(&"a".repeat(64)), None);
        assert!(host(&format!("{}.com", "a".repeat(63))).is_some());
    }

    #[test]
    fn ids() {
        let u = "B831381D-6324-4D53-AD4F-8CDA48B30811";
        assert_eq!(user_id(u).unwrap(), u.to_lowercase());
        assert_eq!(
            user_id("b831381d63244d53ad4f8cda48b30811").unwrap(),
            "b831381d-6324-4d53-ad4f-8cda48b30811"
        );
        assert_eq!(user_id("my-secret-id").as_deref(), Some("my-secret-id"));
        assert_eq!(user_id(""), None);
        assert_eq!(user_id(&"x".repeat(31)), None);
        assert_eq!(user_id("b831381d-6324-4d53-ad4f-8cda48b3081z"), None);
        assert_eq!(user_id("b831381d_6324-4d53-ad4f-8cda48b30811"), None);
    }

    #[test]
    fn names_lose_spoofing_characters() {
        assert_eq!(sanitize_name("a\u{202e}b\u{200b}c\n d", "x"), "abc d");
        assert_eq!(sanitize_name("\u{202e}\u{200f}", "fb"), "fb");
        assert_eq!(sanitize_name("  😀  ok  ", "x"), "😀 ok");
        assert_eq!(sanitize_name(&"é".repeat(300), "x").chars().count(), 100);
    }

    #[test]
    fn keys_and_misc() {
        let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(key32(k).is_some());
        assert!(key32("AAAA").is_none());
        assert!(reality_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_some());
        assert!(reality_key(k).is_some());
        assert!(
            short_id("0123abcd").is_some() && short_id("abc").is_none() && short_id("").is_some()
        );
        assert_eq!(utls_fingerprint("HelloChrome_Auto"), None);
        assert_eq!(utls_fingerprint("randomizedalpn"), Some("randomized"));
        assert_eq!(
            port_ranges("2080-3000, 4000").unwrap(),
            "2080:3000,4000:4000"
        );
        assert_eq!(port_ranges("3000-2080"), None);
        assert_eq!(cidr("10.0.0.2").unwrap(), "10.0.0.2/32");
        assert_eq!(cidr("fd00::2/64").unwrap(), "fd00::2/64");
        assert_eq!(cidr("10.0.0.2/33"), None);
        assert_eq!(truthy("TRUE"), Some(true));
        assert_eq!(truthy("maybe"), None);
    }
}
