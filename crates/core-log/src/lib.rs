//! Log redaction. Two layers: exact known secrets registered from profiles, and pattern
//! scrubbing (UUIDs, 32-byte base64 keys, `user:pass@` in URLs, PEM blocks) as a safety net
//! for secrets the process did not know about, e.g. text echoed by an engine.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use core_model::Profile;
use std::sync::{Arc, RwLock};

const MASK: &str = "<redacted>";

#[derive(Clone, Default)]
pub struct Redactor {
    known: Arc<RwLock<Vec<String>>>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register every secret of a profile. Very short values are skipped to avoid masking ordinary text.
    pub fn register_profile(&self, p: &Profile) {
        if let Ok(mut k) = self.known.write() {
            for s in p.secrets.values() {
                for line in s.expose().lines() {
                    let v = line.trim();
                    if v.len() >= 6 && !k.iter().any(|x| x == v) {
                        k.push(v.to_string());
                    }
                }
            }
            // Longest first so a secret containing another is masked entirely.
            k.sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }

    pub fn redact(&self, input: &str) -> String {
        let mut out = input.to_string();
        if let Ok(k) = self.known.read() {
            for s in k.iter() {
                out = out.replace(s.as_str(), MASK);
            }
        }
        scrub_patterns(&out)
    }
}

fn scrub_patterns(s: &str) -> String {
    let s = scrub_pem(s);
    let s = scrub_userinfo(&s);
    scrub_tokens(&s)
}

fn scrub_pem(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_pem = false;
    for line in s.split_inclusive('\n') {
        if line.contains("-----BEGIN") {
            in_pem = true;
            out.push_str(MASK);
            out.push('\n');
        }
        if !in_pem {
            out.push_str(line);
        }
        if line.contains("-----END") {
            in_pem = false;
        }
    }
    out
}

/// `scheme://user:pass@host` and share links `vless://uuid@host`.
fn scrub_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        let (head, tail) = rest.split_at(i + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c.is_whitespace() || c == '/' || c == '"' || c == '\'')
            .unwrap_or(tail.len());
        match tail[..end].rfind('@') {
            Some(at) => {
                out.push_str(MASK);
                out.push_str(&tail[at..end]);
            }
            None => out.push_str(&tail[..end]),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// UUIDs and long base64-looking tokens (>= 43 chars: a 32-byte key encodes to 44 with padding).
fn scrub_tokens(s: &str) -> String {
    let is_tok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_');
    let mut out = String::with_capacity(s.len());
    let mut tok = String::new();
    let flush = |tok: &mut String, out: &mut String| {
        if !tok.is_empty() {
            if looks_secret(tok) {
                out.push_str(MASK);
            } else {
                out.push_str(tok);
            }
            tok.clear();
        }
    };
    for c in s.chars() {
        if is_tok(c) {
            tok.push(c);
        } else {
            flush(&mut tok, &mut out);
            out.push(c);
        }
    }
    flush(&mut tok, &mut out);
    out
}

fn looks_secret(t: &str) -> bool {
    let b = t.as_bytes();
    let uuid = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    let key = b.len() >= 43
        && t.chars().any(|c| c.is_ascii_digit())
        && t.chars().any(|c| c.is_ascii_uppercase())
        && t.chars().any(|c| c.is_ascii_lowercase());
    uuid || key
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_model::{Protocol, Secret};
    use std::collections::BTreeMap;

    fn profile(secret: &str) -> Profile {
        let mut secrets = BTreeMap::new();
        secrets.insert("password".into(), Secret::new(secret));
        Profile {
            name: "n".into(),
            protocol: Protocol::Trojan,
            host: "h".into(),
            port: 1,
            settings: BTreeMap::new(),
            secrets,
        }
    }

    #[test]
    fn known_secret_is_masked_everywhere() {
        let r = Redactor::new();
        r.register_profile(&profile("correct-horse"));
        let out = r.redact("auth failed for correct-horse; retry correct-horse");
        assert!(!out.contains("correct-horse"));
        assert_eq!(out.matches(MASK).count(), 2);
    }

    #[test]
    fn short_secrets_are_not_registered() {
        let r = Redactor::new();
        r.register_profile(&profile("abc"));
        assert_eq!(r.redact("abc def"), "abc def");
    }

    #[test]
    fn patterns_catch_unknown_secrets() {
        let r = Redactor::new();
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let out = r.redact(&format!(
            "uuid {uuid} key {key} url trojan://hunter22@host:443/x"
        ));
        for leak in [uuid, key, "hunter22"] {
            assert!(!out.contains(leak), "{leak} leaked: {out}");
        }
        assert!(out.contains("@host:443"));
    }

    #[test]
    fn pem_block_is_removed() {
        let r = Redactor::new();
        let out = r.redact("a\n-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\nb\n");
        assert!(!out.contains("QUJD") && out.contains('a') && out.contains('b'));
    }

    #[test]
    fn ordinary_text_is_untouched() {
        let r = Redactor::new();
        let t = "connected to example.com:443 in 48ms (WireGuard)";
        assert_eq!(r.redact(t), t);
    }
}
