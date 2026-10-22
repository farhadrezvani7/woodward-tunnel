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
    "persist-key",
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
    "dhcp-option",
    "block-outside-dns",
    "setenv-safe",
    "ignore-unknown-option",
    "connect-retry",
    "connect-retry-max",
    "connect-timeout",
    "server-poll-timeout",
    "tls-timeout",
    "key-method",
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
/// Rejected with an explicit reason; anything not allowlisted is rejected anyway.
const DANGEROUS: &[&str] = &[
    "up",
    "down",
    "route-up",
    "route-pre-down",
    "ipchange",
    "tls-verify",
    "auth-user-pass-verify",
    "client-connect",
    "client-disconnect",
    "learn-address",
    "plugin",
    "script-security",
    "setenv",
    "management",
    "config",
    "writepid",
    "log",
    "log-append",
    "status",
    "tmp-dir",
    "cd",
    "chroot",
    "daemon",
    "syslog",
    "engine",
    "ca-path",
    "up-restart",
];
const MAX_BLOCK: usize = 64 * 1024;

pub fn parse(text: &str) -> Result<Profile, ConfigIssue> {
    let mut settings: BTreeMap<String, String> = BTreeMap::new();
    let mut secrets: BTreeMap<String, Secret> = BTreeMap::new();
    let mut remote: Option<(String, u16)> = None;
    let mut lines = text.lines();
    let mut ordered: Vec<String> = Vec::new();

    while let Some(raw) = lines.next() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|l| l.strip_suffix('>')) {
            if tag.starts_with('/') {
                return Err(ConfigIssue::InvalidField {
                    protocol: P,
                    field: "block",
                });
            }
            if !BLOCKS.contains(&tag) {
                return Err(ConfigIssue::InvalidField {
                    protocol: P,
                    field: "block",
                });
            }
            let close = format!("</{tag}>");
            let mut body = String::new();
            let mut closed = false;
            for l in lines.by_ref() {
                if l.trim() == close {
                    closed = true;
                    break;
                }
                body.push_str(l);
                body.push('\n');
                if body.len() > MAX_BLOCK {
                    return Err(ConfigIssue::InvalidField {
                        protocol: P,
                        field: "block",
                    });
                }
            }
            if !closed {
                return Err(ConfigIssue::InvalidField {
                    protocol: P,
                    field: "block",
                });
            }
            if SECRET_BLOCKS.contains(&tag) {
                secrets.insert(tag.to_string(), Secret::new(body));
            } else {
                settings.insert(format!("{tag}_inline"), body);
            }
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else { continue };
        let key = key.trim_start_matches("--");
        if DANGEROUS.contains(&key) {
            return Err(ConfigIssue::InvalidField {
                protocol: P,
                field: "script/file directive",
            });
        }
        if !ALLOWED.contains(&key) {
            return Err(ConfigIssue::InvalidField {
                protocol: P,
                field: "directive",
            });
        }
        let args: Vec<&str> = parts.collect();
        // Inline-or-file references to local paths are not allowed: `auth-user-pass <file>` reads a file.
        if key == "auth-user-pass" && !args.is_empty() {
            return Err(ConfigIssue::InvalidField {
                protocol: P,
                field: "script/file directive",
            });
        }
        if key == "remote" && remote.is_none() {
            let host = args.first().ok_or(ConfigIssue::MissingField {
                protocol: P,
                field: "server",
            })?;
            let port: u16 = match args.get(1) {
                Some(p) => p
                    .parse()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or(ConfigIssue::InvalidField {
                        protocol: P,
                        field: "port",
                    })?,
                None => 1194,
            };
            remote = Some((host.to_string(), port));
        }
        ordered.push(format!("{key} {}", args.join(" ")).trim().to_string());
    }
    let (host, port) = remote.ok_or(ConfigIssue::MissingField {
        protocol: P,
        field: "server",
    })?;
    if host.is_empty() || host.contains(['/', '\\']) {
        return Err(ConfigIssue::InvalidField {
            protocol: P,
            field: "server",
        });
    }
    if !settings.contains_key("ca_inline") {
        return Err(ConfigIssue::MissingField {
            protocol: P,
            field: "CA certificate",
        });
    }
    settings.insert("directives".into(), ordered.join("\n"));
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
            "up /tmp/x.sh",
            "down x",
            "script-security 2",
            "plugin /lib/x.so",
            "management 127.0.0.1 7505",
            "auth-user-pass /etc/shadow",
            "log /tmp/l",
            "tls-verify x",
            "setenv A B",
            "config /etc/passwd",
            "writepid /tmp/p",
        ] {
            let text = format!("{GOOD}{d}\n");
            assert!(
                matches!(parse(&text), Err(ConfigIssue::InvalidField { .. })),
                "{d}"
            );
        }
    }

    #[test]
    fn rejects_unknown_directives_and_blocks() {
        assert!(parse(&format!("{GOOD}frobnicate on\n")).is_err());
        assert!(parse(&format!("{GOOD}<connection>\nremote a 1\n</connection>\n")).is_err());
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
