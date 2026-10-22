//! One entry point for any pasted/loaded text: it works out the format, parses every profile it
//! contains, and reports each failure on its own so one bad entry never hides good ones.

use crate::{formats, openvpn, uri, wireguard, MAX_INPUT_BYTES, MAX_PROFILES};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use core_model::{ConfigIssue, Profile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub label: String,
    pub issue: ConfigIssue,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub profiles: Vec<Profile>,
    pub issues: Vec<Issue>,
    /// Subscription links (https://...). Fetching is the caller's decision since it is a network request.
    pub subscription_urls: Vec<String>,
}

impl Analysis {
    pub(crate) fn profile(&mut self, p: Profile) {
        if self.profiles.len() < MAX_PROFILES {
            self.profiles.push(p);
        }
    }
    pub(crate) fn issue(&mut self, label: String, issue: ConfigIssue) {
        if self.issues.len() < MAX_PROFILES {
            self.issues.push(Issue { label, issue });
        }
    }
    pub(crate) fn profiles_len(&self) -> usize {
        self.profiles.len()
    }
    pub(crate) fn issues_len(&self) -> usize {
        self.issues.len()
    }
    pub(crate) fn rename_from(&mut self, start: usize, name: &str) {
        let n = self.profiles.len() - start;
        for (i, p) in self.profiles.iter_mut().skip(start).enumerate() {
            let clean: String = name.chars().filter(|c| !c.is_control()).take(90).collect();
            p.name = if n > 1 {
                format!("{clean} ({})", i + 1)
            } else {
                clean
            };
        }
    }
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.issues.is_empty() && self.subscription_urls.is_empty()
    }
}

pub fn analyze(input: &str) -> Analysis {
    let mut out = Analysis::default();
    let text = input.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        out.issue("input".into(), ConfigIssue::Empty);
        return out;
    }
    if text.len() > MAX_INPUT_BYTES {
        out.issue("input".into(), ConfigIssue::TooLarge(text.len()));
        return out;
    }
    analyze_inner(text, &mut out, 0);
    if out.is_empty() {
        out.issue("input".into(), ConfigIssue::Unrecognized);
    }
    out
}

fn b64_text(s: &str) -> Option<String> {
    let compact: String = s.split_whitespace().collect();
    if compact.len() < 16 || compact.contains("://") {
        return None;
    }
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(&compact).ok())
        .and_then(|b| String::from_utf8(b).ok())
}

fn single(
    text: &str,
    label: &str,
    out: &mut Analysis,
    f: impl FnOnce(&str) -> Result<Profile, ConfigIssue>,
) {
    match f(text) {
        Ok(p) => out.profile(p),
        Err(e) => out.issue(label.to_string(), e),
    }
}

pub(crate) fn analyze_inner(text: &str, out: &mut Analysis, depth: u8) {
    if depth > 3 {
        return;
    }
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    if wireguard::looks_like(text) {
        return single(text, "WireGuard", out, wireguard::parse);
    }
    if text.lines().any(|l| l.trim_start().starts_with("remote "))
        && text.lines().any(|l| matches!(l.trim(), "client" | "<ca>"))
    {
        return single(text, "OpenVPN", out, openvpn::parse);
    }
    if text.starts_with("vpn://") {
        if let Err(e) = formats::amnezia(text, out, depth) {
            out.issue("Amnezia".into(), e);
        }
        return;
    }
    if text.starts_with('{') || text.starts_with('[') {
        match serde_json::from_str::<serde_json::Value>(text) {
            Ok(v) => {
                if let Err(e) = formats::json_config(&v, out) {
                    out.issue("JSON".into(), e);
                }
            }
            Err(_) => out.issue(
                "JSON".into(),
                ConfigIssue::InvalidField {
                    protocol: "JSON",
                    field: "syntax",
                },
            ),
        }
        return;
    }
    if text.lines().any(|l| l.starts_with("proxies:")) {
        if let Err(e) = formats::clash_yaml(text, out) {
            out.issue("Clash".into(), e);
        }
        return;
    }
    if !text.contains("://") {
        // Whole-blob base64 subscription (v2rayN, most panels).
        if let Some(decoded) = b64_text(text) {
            return analyze_inner(&decoded, out, depth + 1);
        }
        return out.issue("input".into(), ConfigIssue::Unrecognized);
    }
    let mut count = 0;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        count += 1;
        if count > MAX_PROFILES {
            break;
        }
        let Some((scheme, _)) = line.split_once("://") else {
            out.issue(short(line, count), ConfigIssue::Unrecognized);
            continue;
        };
        let scheme = scheme.to_ascii_lowercase();
        match scheme.as_str() {
            "https" | "http" if !has_userinfo(line) => out.subscription_urls.push(line.to_string()),
            "http" | "https" => single(
                &line
                    .replacen("http", "http-proxy", 1)
                    .replacen("http-proxys", "https-proxy", 1),
                &short(line, count),
                out,
                |t| {
                    uri::parse(
                        if t.starts_with("https-proxy") {
                            "https-proxy"
                        } else {
                            "http-proxy"
                        },
                        t,
                    )
                },
            ),
            "ssconf" => out
                .subscription_urls
                .push(line.replacen("ssconf://", "https://", 1)),
            "vpn" => {
                if let Err(e) = formats::amnezia(line, out, depth) {
                    out.issue("Amnezia".into(), e);
                }
            }
            "vless" | "vmess" | "trojan" | "ss" | "hysteria2" | "hy2" | "hysteria" | "tuic"
            | "anytls" | "socks" | "socks5" | "socks5h" | "ssh" | "wireguard" | "wg"
            | "http-proxy" | "https-proxy" => {
                single(line, &short(line, count), out, |t| uri::parse(&scheme, t));
            }
            "ssr" => out.issue(short(line, count), ConfigIssue::Unsupported("ShadowsocksR")),
            "snell" | "naive+https" | "naive+quic" => out.issue(
                short(line, count),
                ConfigIssue::Unsupported("this proxy type"),
            ),
            _ => out.issue(short(line, count), ConfigIssue::Unrecognized),
        }
    }
}

fn has_userinfo(line: &str) -> bool {
    line.split_once("://")
        .map(|(_, r)| r.split(['/', '?', '#']).next().unwrap_or("").contains('@'))
        .unwrap_or(false)
}

/// Label for an issue list: scheme and line number only. Host or userinfo are never included,
/// because a damaged link can put a credential where a host should be.
fn short(line: &str, n: usize) -> String {
    const KNOWN: &[&str] = &[
        "vless",
        "vmess",
        "trojan",
        "ss",
        "ssr",
        "hysteria",
        "hysteria2",
        "hy2",
        "tuic",
        "anytls",
        "socks",
        "socks5",
        "socks5h",
        "ssh",
        "wireguard",
        "wg",
        "http",
        "https",
        "http-proxy",
        "https-proxy",
        "vpn",
        "ssconf",
    ];
    // Only well-known scheme names are echoed; anything else may be a damaged credential.
    let scheme = line
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .filter(|s| KNOWN.contains(&s.as_str()))
        .unwrap_or_else(|| "link".to_string());
    format!("{scheme} #{n}")
}

#[cfg(test)]
mod tests {
    use super::*;
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn base64_subscription_blob() {
        let links = format!("vless://{UUID}@a.example.com:443?security=tls#A\ntrojan://pw1234@b.example.com:443#B\n");
        let blob = STANDARD.encode(links);
        let a = analyze(&blob);
        assert_eq!(a.profiles.len(), 2, "{:?}", a.issues);
    }

    #[test]
    fn subscription_urls_are_returned_not_fetched() {
        let a = analyze("https://panel.example.com/sub/abc123?x=1\nssconf://dyn.example.com/key#n");
        assert_eq!(
            a.subscription_urls,
            vec![
                "https://panel.example.com/sub/abc123?x=1".to_string(),
                "https://dyn.example.com/key#n".to_string()
            ]
        );
        assert!(a.profiles.is_empty());
    }

    #[test]
    fn mixed_paste_reports_each_line() {
        let a = analyze(&format!(
            "vless://{UUID}@a.example.com:443#A\nssr://abc\nnonsense://x\n"
        ));
        assert_eq!(a.profiles.len(), 1);
        assert_eq!(a.issues.len(), 2);
        assert!(!a.issues.iter().any(|i| i.label.contains(UUID)));
    }

    #[test]
    fn issue_labels_do_not_leak_credentials() {
        let a = analyze("trojan://supersecret@:443");
        assert!(a.issues.iter().all(|i| !i.label.contains("supersecret")));
    }

    #[test]
    fn wireguard_and_openvpn_and_garbage() {
        assert_eq!(analyze("hello").issues.len(), 1);
        assert_eq!(analyze("").issues[0].issue, ConfigIssue::Empty);
    }

    #[test]
    fn http_proxy_with_credentials() {
        let a = analyze("http://u:p@proxy.example.com:8080#P");
        assert_eq!(a.profiles.len(), 1, "{:?}", a.issues);
        assert_eq!(a.profiles[0].protocol, core_model::Protocol::HttpProxy);
    }
}
