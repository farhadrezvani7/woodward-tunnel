//! OpenVPN `.ovpn` parsing with a strict allowlist. Directives that run programs, load external
//! files, or change the process environment are rejected, not ignored, so a hostile profile
//! cannot execute code or read local files when handed to the openvpn binary.

use core_model::{ConfigIssue, Profile, Protocol, Secret};
use std::collections::BTreeMap;

const P: &str = "OpenVPN";

/// Directives that are safe to pass through.
const ALLOWED: &[&str] = &[
    "client",
    "dev",
    "dev-type",
    "proto",
    "remote",
    "remote-random",
    "resolv-retry",
    "nobind",
    "persist-tun",
    "remote-cert-tls",
    "verify-x509-name",
    "cipher",
    "data-ciphers",
    "data-ciphers-fallback",
    "auth",
    "auth-user-pass",
    "auth-nocache",
    "comp-lzo",
    "compress",
    "key-direction",
    "tls-version-min",
    "tls-cipher",
    "tls-ciphersuites",
    "verb",
    "mute",
    "mssfix",
    "tun-mtu",
    "fragment",
    "sndbuf",
    "rcvbuf",
    "keepalive",
    "ping",
    "ping-restart",
    "ping-exit",
    "reneg-sec",
    "explicit-exit-notify",
    "float",
    "redirect-gateway",
    "route-nopull",
    "pull",
    "pull-filter",
    "route",
    "route-ipv6",
    "setenv-safe",
    "ignore-unknown-option",
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "server-poll-timeout",
    "tls-timeout",
    "ns-cert-type",
    "allow-compression",
    "tls-client",
    "pkcs12-no-pass",
    "ifconfig-nowarn",
    "remote-cert-eku",
    "auth-retry",
];
/// Inline blocks that carry certificates/keys. `<connection>` and others are not accepted.
const BLOCKS: &[&str] = &[
    "ca",
    "cert",
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "pkcs12",
    "extra-certs",
    "dh",
    "crl-verify",
];
/// Blocks whose content is secret.
const SECRET_BLOCKS: &[&str] = &["key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12"];
/// Dropped on import: they only matter to scripts or process housekeeping that we never run;
/// the renderer forces `script-security 0` and the app manages DNS and routes itself.
const DROPPED: &[&str] = &[
    "up",
    "down",
    "up-restart",
    "route-up",
    "route-pre-down",
    "ipchange",
    "script-security",
    "setenv",
    "management",
    "writepid",
    "log",
    "log-append",
    "status",
    "tmp-dir",
    "cd",
    "chroot",
    "daemon",
    "syslog",
    "learn-address",
    // Windows-only or removed in 2.7 (fatal there), or ignored: dropped so the profile still imports.
    "key-method",
    "block-outside-dns",
    "ncp-disable",
    "windows-driver",
    "persist-key",
    "fast-io",
    // The app manages DNS; client-side DNS pushes would only matter with an up script.
    "dhcp-option",
    "register-dns",
    "dhcp-renew",
    "dhcp-release",
    "ip-win32",
    "tap-sleep",
    "pause-exit",
    "show-net-up",
    "askpass",
    "genkey",
    "mlock",
    "echo",
    "push-peer-info",
];
/// Rejected: they weaken verification, load code, or read local files named by the profile.
const DANGEROUS: &[&str] = &[
    "tls-verify",
    "auth-user-pass-verify",
    "client-connect",
    "client-disconnect",
    "plugin",
    "config",
    "engine",
    "ca-path",
    "capath",
    "http-proxy",
    "http-proxy-option",
    "http-proxy-user-pass",
    "socks-proxy",
    "management-client-auth",
    "management-external-key",
    "tls-export-cert",
    "auth-gen-token",
    "ifconfig-pool-persist",
    "shaper",
    "tls-crypt-v2-verify",
    "use-prediction-resistance",
    "providers",
    "show-gateway",
    "dev-node",
    "lladdr",
    "iproute",
    "route-gateway",
    "cryptoapicert",
    "pkcs11-providers",
    "pkcs11-id",
    "pkcs11-id-management",
    "secret",
    "tls-verify-cmd",
    "auth-token",
];
const MAX_BLOCK: usize = 64 * 1024;

/// Cheap detection used by `detect` and `analyze`: does this text look like an `.ovpn` profile?
pub(crate) fn looks_like(text: &str) -> bool {
    let has = |key: &str| text.lines().any(|l| l.trim_start().starts_with(key));
    (has("remote ") || has("<connection>"))
        && (has("client") || has("dev ") || has("<ca>") || has("tls-client"))
}

const MAX_LINE: usize = 254;
const MAX_TOKENS: usize = 32;

fn bad(field: &'static str) -> ConfigIssue {
    ConfigIssue::InvalidField { protocol: P, field }
}

/// OpenVPN's `parse_line()` quoting rules: whitespace separates tokens, `"` and `'` quote,
/// backslash escapes `\`, `"` and space outside single quotes, and `#` or `;` at the start of
/// a token begins a comment. Anything ambiguous is rejected instead of guessed.
fn tokenize(line: &str) -> Result<Vec<String>, ConfigIssue> {
    if line.len() > MAX_LINE || line.chars().any(|c| c.is_control() && c != '\t') {
        return Err(bad("line"));
    }
    let mut out: Vec<String> = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '#' || c == ';' {
            break;
        }
        let mut tok = String::new();
        if c == '"' || c == '\'' {
            chars.next();
            let q = c;
            let mut closed = false;
            while let Some(d) = chars.next() {
                if d == q {
                    closed = true;
                    break;
                }
                if d == '\\' && q == '"' {
                    match chars.next() {
                        Some(e @ ('\\' | '"')) => tok.push(e),
                        _ => return Err(bad("escape")),
                    }
                } else {
                    tok.push(d);
                }
            }
            if !closed || chars.peek().is_some_and(|n| !n.is_whitespace()) {
                return Err(bad("quote"));
            }
        } else {
            while let Some(&d) = chars.peek() {
                if d.is_whitespace() {
                    break;
                }
                chars.next();
                if d == '\\' {
                    match chars.next() {
                        Some(e @ ('\\' | '"' | ' ')) => tok.push(e),
                        _ => return Err(bad("escape")),
                    }
                } else {
                    tok.push(d);
                }
            }
        }
        out.push(tok);
        if out.len() > MAX_TOKENS {
            return Err(bad("line"));
        }
    }
    Ok(out)
}

fn quote(tok: &str) -> String {
    let plain = !tok.is_empty()
        && !tok.starts_with(['#', ';', '"', '\''])
        && !tok
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'));
    if plain {
        return tok.to_string();
    }
    let mut s = String::from("\"");
    for c in tok.chars() {
        if matches!(c, '"' | '\\') {
            s.push('\\');
        }
        s.push(c);
    }
    s.push('"');
    s
}

fn is_num(s: &str) -> bool {
    !s.is_empty() && s.len() <= 7 && s.bytes().all(|c| c.is_ascii_digit())
}

const NUMERIC: &[&str] = &[
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "server-poll-timeout",
    "tls-timeout",
    "reneg-sec",
    "ping",
    "ping-restart",
    "ping-exit",
    "mssfix",
    "tun-mtu",
    "fragment",
    "sndbuf",
    "rcvbuf",
    "verb",
    "mute",
    "keepalive",
    "explicit-exit-notify",
    "key-direction",
];
const PROTOS: &[&str] = &[
    "udp",
    "tcp",
    "tcp-client",
    "udp4",
    "udp6",
    "tcp4",
    "tcp6",
    "tcp4-client",
    "tcp6-client",
];
const WEAK_CIPHERS: &[&str] = &[
    "BF-CBC",
    "DES-CBC",
    "DES-EDE3-CBC",
    "RC2-CBC",
    "CAST5-CBC",
    "IDEA-CBC",
    "RC4",
];

/// Validate one directive's arguments; returns the warning label to record, if any.
fn check_args(key: &str, args: &[String]) -> Result<Option<&'static str>, ConfigIssue> {
    let a = |i: usize| args.get(i).map(String::as_str);
    if NUMERIC.contains(&key) {
        let ok = match key {
            "keepalive" => args.len() == 2 && args.iter().all(|x| is_num(x)),
            "explicit-exit-notify" | "mssfix" | "fragment" => {
                args.len() <= 2 && args.iter().all(|x| is_num(x) || x == "mtu")
            }
            _ => args.len() == 1 && is_num(&args[0]),
        };
        if !ok {
            return Err(bad("number"));
        }
    }
    match key {
        "proto" => {
            if args.len() != 1 || !PROTOS.contains(&args[0].as_str()) {
                return Err(bad("proto"));
            }
        }
        "dev" | "dev-type" => {
            let d = a(0).unwrap_or("");
            let digits = d.trim_start_matches(|c: char| c.is_ascii_alphabetic());
            let name = &d[..d.len() - digits.len()];
            if args.len() != 1
                || !matches!(name, "tun" | "tap")
                || digits.len() > 3
                || !digits.bytes().all(|c| c.is_ascii_digit())
            {
                return Err(bad("dev"));
            }
        }
        "remote-cert-tls" if args.len() != 1 || !matches!(a(0), Some("server" | "client")) => {
            return Err(bad("remote-cert-tls"));
        }
        "tls-version-min" => {
            if args.is_empty()
                || args.len() > 2
                || !matches!(args[0].as_str(), "1.0" | "1.1" | "1.2" | "1.3")
                || a(1).is_some_and(|x| x != "or-highest")
            {
                return Err(bad("tls-version-min"));
            }
        }
        "auth-retry"
            if args.len() != 1 || !matches!(a(0), Some("none" | "nointeract" | "interact")) =>
        {
            return Err(bad("auth-retry"));
        }
        "resolv-retry" if args.len() != 1 || !(is_num(&args[0]) || args[0] == "infinite") => {
            return Err(bad("number"));
        }
        "cipher" | "data-ciphers-fallback" if args.len() != 1 => return Err(bad("cipher")),
        "cipher" | "data-ciphers-fallback" | "data-ciphers" | "ncp-ciphers" => {
            let weak = args.iter().flat_map(|x| x.split(':')).any(|c| {
                WEAK_CIPHERS.contains(&c.to_ascii_uppercase().as_str())
                    || c.to_ascii_uppercase().starts_with("DES-")
            });
            if weak {
                return Ok(Some("weak_cipher"));
            }
        }
        "comp-lzo" if a(0) != Some("no") => return Ok(Some("compression")),
        "compress" if !matches!(a(0), Some("migrate")) => return Ok(Some("compression")),
        "allow-compression" if a(0) != Some("no") => return Ok(Some("compression")),
        _ => {}
    }
    Ok(None)
}

fn remote_args(args: &[String]) -> Result<(String, u16), ConfigIssue> {
    let host = args.first().ok_or(ConfigIssue::MissingField {
        protocol: P,
        field: "server",
    })?;
    if args.len() > 3 {
        return Err(bad("server"));
    }
    let host = crate::validate::host(host).ok_or(bad("server"))?;
    let port = match args.get(1) {
        Some(p) => crate::validate::port(p).ok_or(bad("port"))?,
        None => 1194,
    };
    if let Some(proto) = args.get(2) {
        if !PROTOS.contains(&proto.as_str()) {
            return Err(bad("proto"));
        }
    }
    Ok((host, port))
}

/// Directives allowed inside `<connection>`; everything else there is rejected.
const CONNECTION_KEYS: &[&str] = &[
    "remote",
    "proto",
    "port",
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "server-poll-timeout",
    "explicit-exit-notify",
];

/// Reads an inline block body up to its closing tag. OpenVPN closes a block at any line that
/// starts (after whitespace) with the closing tag, so text after the tag is rejected, not kept.
fn read_block<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    tag: &str,
) -> Result<String, ConfigIssue> {
    let close = format!("</{tag}>");
    let mut body = String::new();
    for l in lines {
        if l.len() > MAX_LINE {
            return Err(bad("line"));
        }
        let t = l.trim_start();
        if t.starts_with(&close) {
            return if t[close.len()..].trim().is_empty() {
                Ok(body)
            } else {
                Err(bad("block"))
            };
        }
        if t.starts_with("</") {
            return Err(bad("block"));
        }
        body.push_str(l);
        body.push('\n');
        if body.len() > MAX_BLOCK {
            return Err(bad("block"));
        }
    }
    Err(bad("block"))
}

pub fn parse(text: &str) -> Result<Profile, ConfigIssue> {
    let mut settings: BTreeMap<String, String> = BTreeMap::new();
    let mut secrets: BTreeMap<String, Secret> = BTreeMap::new();
    let mut remote: Option<(String, u16)> = None;
    let mut lines = text.lines();
    let mut ordered: Vec<String> = Vec::new();
    let mut warnings: Vec<&'static str> = Vec::new();
    let mut connections = 0usize;

    while let Some(raw) = lines.next() {
        // Checked before comment skipping: OpenVPN splits long lines, so a padded comment can
        // hide a live directive in its tail.
        if raw.len() > MAX_LINE {
            return Err(bad("line"));
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('<') {
            let tag = rest.strip_suffix('>').ok_or(bad("block"))?;
            if tag.starts_with('/') || tag.contains(['<', '>', ' ']) {
                return Err(bad("block"));
            }
            let body = read_block(&mut lines, tag)?;
            match tag {
                "connection" => {
                    connections += 1;
                    if connections > 16 {
                        return Err(bad("block"));
                    }
                    ordered.push("<connection>".into());
                    for l in body.lines() {
                        let toks = tokenize(l)?;
                        let Some(key) =
                            toks.first().map(|k| k.trim_start_matches("--").to_string())
                        else {
                            continue;
                        };
                        if !CONNECTION_KEYS.contains(&key.as_str()) {
                            return Err(bad("directive"));
                        }
                        let args = &toks[1..];
                        check_args(&key, args)?;
                        if key == "remote" {
                            let hp = remote_args(args)?;
                            remote.get_or_insert(hp);
                        }
                        let q: Vec<String> = std::iter::once(key)
                            .chain(args.iter().map(|x| quote(x)))
                            .collect();
                        ordered.push(q.join(" "));
                    }
                    ordered.push("</connection>".into());
                }
                "auth-user-pass" => {
                    let l: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
                    if l.len() != 2 || l.iter().any(|x| x.chars().any(char::is_control)) {
                        return Err(bad("auth-user-pass"));
                    }
                    secrets.insert("username".into(), Secret::new(l[0].trim_end_matches('\r')));
                    secrets.insert("password".into(), Secret::new(l[1].trim_end_matches('\r')));
                    ordered.push("auth-user-pass".into());
                }
                t if BLOCKS.contains(&t) => {
                    if SECRET_BLOCKS.contains(&t) {
                        secrets.insert(t.to_string(), Secret::new(body));
                    } else {
                        settings.insert(format!("{t}_inline"), body);
                    }
                }
                _ => return Err(bad("block")),
            }
            continue;
        }
        let toks = tokenize(raw)?;
        let Some(first) = toks.first() else { continue };
        let key = first.trim_start_matches("--").to_string();
        if DANGEROUS.contains(&key.as_str()) {
            return Err(bad("script/file directive"));
        }
        if DROPPED.contains(&key.as_str()) {
            continue;
        }
        if !ALLOWED.contains(&key.as_str()) {
            return Err(bad("directive"));
        }
        let mut args: Vec<String> = toks[1..].to_vec();
        // `auth-user-pass <file>` would read a local file; credentials come from the app instead.
        if key == "auth-user-pass" {
            args.clear();
        }
        if let Some(w) = check_args(&key, &args)? {
            if !warnings.contains(&w) {
                warnings.push(w);
            }
        }
        if key == "remote" {
            let hp = remote_args(&args)?;
            remote.get_or_insert(hp);
        }
        let q: Vec<String> = std::iter::once(key)
            .chain(args.iter().map(|x| quote(x)))
            .collect();
        ordered.push(q.join(" "));
    }
    let (host, port) = remote.ok_or(ConfigIssue::MissingField {
        protocol: P,
        field: "server",
    })?;
    if !settings.contains_key("ca_inline") {
        return Err(ConfigIssue::MissingField {
            protocol: P,
            field: "CA certificate",
        });
    }
    settings.insert("directives".into(), ordered.join("\n"));
    if !warnings.is_empty() {
        settings.insert("warnings".into(), warnings.join(","));
    }
    Ok(Profile {
        name: host.clone(),
        protocol: Protocol::OpenVpn,
        host,
        port,
        settings,
        secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nremote-cert-tls server\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n<key>\nPRIVATE-DATA\n</key>\n";

    #[test]
    fn parses_good_profile_and_moves_key_to_secrets() {
        let p = parse(GOOD).unwrap();
        assert_eq!((p.host.as_str(), p.port), ("vpn.example.com", 1194));
        assert!(p.secrets.contains_key("key"));
        assert!(!p.settings.values().any(|v| v.contains("PRIVATE-DATA")));
        assert!(p.settings["directives"].contains("proto udp"));
    }

    #[test]
    fn rejects_every_dangerous_directive() {
        for d in [
            "plugin /lib/x.so",
            "tls-verify x",
            "config /etc/passwd",
            "auth-user-pass-verify x via-env",
            "ca-path /etc/ssl",
            "engine x",
        ] {
            let text = format!("{GOOD}{d}\n");
            assert!(
                matches!(parse(&text), Err(ConfigIssue::InvalidField { .. })),
                "{d}"
            );
        }
    }

    #[test]
    fn script_directives_are_dropped_not_kept() {
        let text = format!("{GOOD}script-security 2\nup /etc/openvpn/update-resolv-conf\ndown /x\nsetenv A B\nlog /tmp/l\nauth-user-pass /etc/shadow\n");
        let p = parse(&text).unwrap();
        let d = &p.settings["directives"];
        for gone in [
            "script-security",
            "update-resolv-conf",
            "setenv",
            "/tmp/l",
            "/etc/shadow",
        ] {
            assert!(!d.contains(gone), "{gone} survived: {d}");
        }
        assert!(d.lines().any(|l| l == "auth-user-pass"));
    }

    #[test]
    fn rejects_unknown_directives_and_blocks() {
        assert!(parse(&format!("{GOOD}frobnicate on\n")).is_err());
        assert!(parse(&format!("{GOOD}<evil>\nremote a 1\n</evil>\n")).is_err());
    }

    #[test]
    fn requires_ca_server_and_closed_blocks() {
        assert!(matches!(
            parse("client\nremote a.example.com 1194\n"),
            Err(ConfigIssue::MissingField { .. })
        ));
        assert!(parse("client\n<ca>\nunterminated").is_err());
        assert!(parse("client\n<ca>\nx\n</ca>\n").is_err());
    }

    #[test]
    fn default_port_and_bad_port() {
        let p =
            parse(&GOOD.replace("remote vpn.example.com 1194", "remote vpn.example.com")).unwrap();
        assert_eq!(p.port, 1194);
        assert!(parse(&GOOD.replace("1194", "70000")).is_err());
    }
}
