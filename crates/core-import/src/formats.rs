//! Structured formats: sing-box JSON, Xray JSON, Clash YAML, Shadowsocks JSON, Amnezia `vpn://`.

use crate::analyze::{analyze_inner, Analysis};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use core_model::{ConfigIssue, Profile, Protocol, Secret};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;

fn text(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}
fn port_of(v: &Value, k: &str) -> Option<u16> {
    text(v, k)?.parse().ok().filter(|p| *p != 0)
}
fn put(m: &mut BTreeMap<String, String>, k: &str, v: Option<String>) {
    if let Some(v) = v {
        m.insert(k.into(), v.chars().take(512).collect());
    }
}
fn name_of(v: &Value, host: &str) -> String {
    let n: String = text(v, "name")
        .or_else(|| text(v, "tag"))
        .or_else(|| text(v, "remarks"))
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    if n.trim().is_empty() {
        host.to_string()
    } else {
        n.trim().to_string()
    }
}
fn bad(p: &'static str, f: &'static str) -> ConfigIssue {
    ConfigIssue::InvalidField {
        protocol: p,
        field: f,
    }
}
fn miss(p: &'static str, f: &'static str) -> ConfigIssue {
    ConfigIssue::MissingField {
        protocol: p,
        field: f,
    }
}
fn uuid_ok(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

// ---------- sing-box JSON ----------

/// sing-box outbound types we accept; selector/urltest/direct/block/dns are routing, not servers.
const SB_TYPES: &[(&str, Protocol)] = &[
    ("vless", Protocol::Vless),
    ("vmess", Protocol::Vmess),
    ("trojan", Protocol::Trojan),
    ("shadowsocks", Protocol::Shadowsocks),
    ("hysteria", Protocol::Hysteria1),
    ("hysteria2", Protocol::Hysteria2),
    ("tuic", Protocol::Tuic),
    ("anytls", Protocol::AnyTls),
    ("socks", Protocol::Socks),
    ("http", Protocol::HttpProxy),
    ("ssh", Protocol::Ssh),
];
/// Dialer options that reference other outbounds or host interfaces.
const SB_STRIP: &[&str] = &[
    "detour",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    "routing_mark",
    "reuse_addr",
    "netns",
    "domain_resolver",
    "tag",
];

fn has_path_key(v: &Value) -> bool {
    match v {
        Value::Object(m) => m
            .iter()
            .any(|(k, v)| k.ends_with("_path") || has_path_key(v)),
        Value::Array(a) => a.iter().any(has_path_key),
        _ => false,
    }
}

pub fn singbox_outbound(o: &Value, out: &mut Analysis) {
    let Some(ty) = text(o, "type") else { return };
    let Some((_, protocol)) = SB_TYPES.iter().find(|(t, _)| *t == ty) else {
        if !matches!(
            ty.as_str(),
            "direct" | "block" | "dns" | "selector" | "urltest"
        ) {
            out.issue(
                ty.clone(),
                ConfigIssue::Unsupported("sing-box outbound type"),
            );
        }
        return;
    };
    let label = text(o, "tag").unwrap_or_else(|| ty.clone());
    let (Some(host), Some(port)) = (text(o, "server"), port_of(o, "server_port")) else {
        out.issue(label, miss("sing-box", "server"));
        return;
    };
    if has_path_key(o) {
        // `certificate_path`, `key_path`... would make the engine read local files named by an untrusted config.
        out.issue(label, bad("sing-box", "local file reference"));
        return;
    }
    let mut clean = o.clone();
    if let Some(m) = clean.as_object_mut() {
        for k in SB_STRIP {
            m.remove(*k);
        }
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("outbound_json".into(), Secret::new(clean.to_string()));
    out.profile(Profile {
        name: name_of(o, &host),
        protocol: *protocol,
        host,
        port,
        settings: BTreeMap::new(),
        secrets,
    });
}

// ---------- Xray JSON ----------

fn xray_stream(s: Option<&Value>, host: &str, settings: &mut BTreeMap<String, String>) {
    let Some(s) = s else { return };
    let net = text(s, "network").unwrap_or_else(|| "tcp".into());
    let net = if net == "h2" { "http".to_string() } else { net };
    if net != "tcp" {
        settings.insert("type".into(), net.clone());
    }
    let sec = text(s, "security").unwrap_or_default();
    if matches!(sec.as_str(), "tls" | "reality") {
        settings.insert("security".into(), sec.clone());
    }
    let tls_obj = s.get("tlsSettings").or_else(|| s.get("realitySettings"));
    if let Some(t) = tls_obj {
        put(
            settings,
            "sni",
            text(t, "serverName").or_else(|| Some(host.to_string())),
        );
        put(settings, "fp", text(t, "fingerprint"));
        put(settings, "pbk", text(t, "publicKey"));
        put(settings, "sid", text(t, "shortId"));
        if text(t, "allowInsecure").as_deref() == Some("true") {
            settings.insert("allowInsecure".into(), "1".into());
        }
        if let Some(a) = t.get("alpn").and_then(Value::as_array) {
            settings.insert(
                "alpn".into(),
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }
    if let Some(w) = s.get("wsSettings") {
        put(settings, "path", text(w, "path"));
        put(
            settings,
            "host",
            w.get("headers")
                .and_then(|h| text(h, "Host"))
                .or_else(|| text(w, "host")),
        );
    }
    if let Some(g) = s.get("grpcSettings") {
        put(settings, "serviceName", text(g, "serviceName"));
    }
}

pub fn xray_outbound(o: &Value, out: &mut Analysis) {
    let Some(proto) = text(o, "protocol") else {
        return;
    };
    let label = text(o, "tag").unwrap_or_else(|| proto.clone());
    let set = o.get("settings").cloned().unwrap_or(Value::Null);
    let mut settings = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    let first = |key: &str| {
        set.get(key)
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .cloned()
    };
    let (protocol, host, port): (Protocol, String, u16) = match proto.as_str() {
        "vless" | "vmess" => {
            let (p, pn) = if proto == "vless" {
                (Protocol::Vless, "VLESS")
            } else {
                (Protocol::Vmess, "VMess")
            };
            let Some(v) = first("vnext") else {
                return out.issue(label, miss(pn, "server"));
            };
            let Some(u) = v
                .get("users")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .cloned()
            else {
                return out.issue(label, miss(pn, "UUID"));
            };
            let Some(id) = text(&u, "id").filter(|i| uuid_ok(i)) else {
                return out.issue(label, bad(pn, "UUID"));
            };
            secrets.insert("uuid".into(), Secret::new(id));
            put(&mut settings, "flow", text(&u, "flow"));
            if p == Protocol::Vmess {
                put(&mut settings, "cipher", text(&u, "security"));
                put(&mut settings, "alter_id", text(&u, "alterId"));
            }
            let (Some(h), Some(pt)) = (text(&v, "address"), port_of(&v, "port")) else {
                return out.issue(label, miss(pn, "server"));
            };
            (p, h, pt)
        }
        "trojan" | "shadowsocks" => {
            let (p, pn) = if proto == "trojan" {
                (Protocol::Trojan, "Trojan")
            } else {
                (Protocol::Shadowsocks, "Shadowsocks")
            };
            let Some(v) = first("servers") else {
                return out.issue(label, miss(pn, "server"));
            };
            let Some(pw) = text(&v, "password") else {
                return out.issue(label, miss(pn, "password"));
            };
            secrets.insert("password".into(), Secret::new(pw));
            if p == Protocol::Shadowsocks {
                let Some(m) = text(&v, "method") else {
                    return out.issue(label, miss(pn, "cipher"));
                };
                settings.insert("cipher".into(), m);
            }
            let (Some(h), Some(pt)) = (text(&v, "address"), port_of(&v, "port")) else {
                return out.issue(label, miss(pn, "server"));
            };
            (p, h, pt)
        }
        "socks" | "http" => {
            let (p, pn) = if proto == "socks" {
                (Protocol::Socks, "SOCKS5")
            } else {
                (Protocol::HttpProxy, "HTTP Proxy")
            };
            let Some(v) = first("servers") else {
                return out.issue(label, miss(pn, "server"));
            };
            if let Some(u) = v
                .get("users")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
            {
                put(&mut settings, "username", text(u, "user"));
                secrets.insert(
                    "password".into(),
                    Secret::new(text(u, "pass").unwrap_or_default()),
                );
            }
            let (Some(h), Some(pt)) = (text(&v, "address"), port_of(&v, "port")) else {
                return out.issue(label, miss(pn, "server"));
            };
            (p, h, pt)
        }
        "wireguard" => {
            let pn = "WireGuard";
            let Some(sk) = text(&set, "secretKey") else {
                return out.issue(label, miss(pn, "PrivateKey"));
            };
            secrets.insert("private_key".into(), Secret::new(sk));
            let Some(peer) = first("peers") else {
                return out.issue(label, miss(pn, "Peer"));
            };
            let Some(ep) = text(&peer, "endpoint") else {
                return out.issue(label, miss(pn, "Endpoint"));
            };
            let Some((h, pt)) = ep.rsplit_once(':').and_then(|(h, p)| {
                Some((
                    h.trim_matches(['[', ']']).to_string(),
                    p.parse::<u16>().ok().filter(|p| *p != 0)?,
                ))
            }) else {
                return out.issue(label, bad(pn, "Endpoint"));
            };
            put(&mut settings, "peer_public_key", text(&peer, "publicKey"));
            let addr = set
                .get("address")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .or_else(|| text(&set, "address"));
            let Some(addr) = addr else {
                return out.issue(label, miss(pn, "Address"));
            };
            settings.insert("address".into(), addr);
            settings.insert("allowed_ips".into(), "0.0.0.0/0, ::/0".into());
            put(&mut settings, "mtu", text(&set, "mtu"));
            if let Some(r) = set.get("reserved").and_then(Value::as_array) {
                settings.insert(
                    "reserved".into(),
                    r.iter()
                        .filter_map(Value::as_u64)
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            (Protocol::WireGuard, h, pt)
        }
        "freedom" | "blackhole" | "dns" | "loopback" => return,
        _ => return out.issue(label, ConfigIssue::Unsupported("Xray outbound type")),
    };
    xray_stream(o.get("streamSettings"), &host, &mut settings);
    out.profile(Profile {
        name: name_of(o, &host),
        protocol,
        host,
        port,
        settings,
        secrets,
    });
}

// ---------- Clash YAML ----------

fn clash_stream(p: &Value, host: &str, settings: &mut BTreeMap<String, String>) {
    let net = text(p, "network").unwrap_or_default();
    if matches!(net.as_str(), "ws" | "grpc" | "h2" | "http") {
        settings.insert(
            "type".into(),
            if net == "h2" {
                "http".into()
            } else {
                net.clone()
            },
        );
    }
    let reality = p.get("reality-opts");
    if reality.is_some() {
        settings.insert("security".into(), "reality".into());
    } else if text(p, "tls").as_deref() == Some("true") {
        settings.insert("security".into(), "tls".into());
    }
    put(
        settings,
        "sni",
        text(p, "servername")
            .or_else(|| text(p, "sni"))
            .or_else(|| settings.contains_key("security").then(|| host.to_string())),
    );
    put(settings, "fp", text(p, "client-fingerprint"));
    put(settings, "flow", text(p, "flow"));
    if text(p, "skip-cert-verify").as_deref() == Some("true") {
        settings.insert("allowInsecure".into(), "1".into());
    }
    if let Some(a) = p.get("alpn").and_then(Value::as_array) {
        settings.insert(
            "alpn".into(),
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if let Some(r) = reality {
        put(settings, "pbk", text(r, "public-key"));
        put(settings, "sid", text(r, "short-id"));
    }
    if let Some(w) = p.get("ws-opts") {
        put(settings, "path", text(w, "path"));
        put(
            settings,
            "host",
            w.get("headers").and_then(|h| text(h, "Host")),
        );
    }
    if let Some(g) = p.get("grpc-opts") {
        put(settings, "serviceName", text(g, "grpc-service-name"));
    }
}

pub fn clash_proxy(p: &Value, out: &mut Analysis) {
    let Some(ty) = text(p, "type") else { return };
    let label = text(p, "name").unwrap_or_else(|| ty.clone());
    let (Some(host), Some(port)) = (text(p, "server"), port_of(p, "port")) else {
        return out.issue(label, miss("Clash", "server"));
    };
    let mut settings = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    let protocol = match ty.as_str() {
        "ss" => {
            let Some(m) = text(p, "cipher") else {
                return out.issue(label, miss("Shadowsocks", "cipher"));
            };
            let Some(pw) = text(p, "password") else {
                return out.issue(label, miss("Shadowsocks", "password"));
            };
            if text(p, "plugin").is_some() {
                return out.issue(label, ConfigIssue::Unsupported("Shadowsocks plugin"));
            }
            settings.insert("cipher".into(), m);
            secrets.insert("password".into(), Secret::new(pw));
            Protocol::Shadowsocks
        }
        "vmess" | "vless" => {
            let pn = if ty == "vmess" { "VMess" } else { "VLESS" };
            let Some(id) = text(p, "uuid").filter(|i| uuid_ok(i)) else {
                return out.issue(label, bad(pn, "UUID"));
            };
            secrets.insert("uuid".into(), Secret::new(id));
            if ty == "vmess" {
                put(&mut settings, "cipher", text(p, "cipher"));
                put(&mut settings, "alter_id", text(p, "alterId"));
            }
            clash_stream(p, &host, &mut settings);
            if ty == "vmess" {
                Protocol::Vmess
            } else {
                Protocol::Vless
            }
        }
        "trojan" | "hysteria2" | "anytls" => {
            let (pr, pn) = match ty.as_str() {
                "trojan" => (Protocol::Trojan, "Trojan"),
                "hysteria2" => (Protocol::Hysteria2, "Hysteria2"),
                _ => (Protocol::AnyTls, "AnyTLS"),
            };
            let Some(pw) = text(p, "password") else {
                return out.issue(label, miss(pn, "password"));
            };
            secrets.insert("password".into(), Secret::new(pw));
            clash_stream(p, &host, &mut settings);
            put(&mut settings, "sni", text(p, "sni"));
            if pr == Protocol::Hysteria2 {
                put(&mut settings, "obfs", text(p, "obfs"));
                put(&mut settings, "obfs-password", text(p, "obfs-password"));
            }
            pr
        }
        "hysteria" => {
            put(&mut settings, "sni", text(p, "sni"));
            put(&mut settings, "upmbps", text(p, "up"));
            put(&mut settings, "downmbps", text(p, "down"));
            put(&mut settings, "obfs", text(p, "obfs"));
            if text(p, "skip-cert-verify").as_deref() == Some("true") {
                settings.insert("allowInsecure".into(), "1".into());
            }
            if let Some(a) = text(p, "auth-str").or_else(|| text(p, "auth_str")) {
                secrets.insert("password".into(), Secret::new(a));
            }
            Protocol::Hysteria1
        }
        "tuic" => {
            let Some(id) = text(p, "uuid").filter(|i| uuid_ok(i)) else {
                return out.issue(label, bad("TUIC", "UUID"));
            };
            let Some(pw) = text(p, "password") else {
                return out.issue(label, miss("TUIC", "password"));
            };
            secrets.insert("uuid".into(), Secret::new(id));
            secrets.insert("password".into(), Secret::new(pw));
            put(
                &mut settings,
                "congestion_control",
                text(p, "congestion-controller"),
            );
            put(&mut settings, "udp_relay_mode", text(p, "udp-relay-mode"));
            clash_stream(p, &host, &mut settings);
            put(&mut settings, "sni", text(p, "sni"));
            Protocol::Tuic
        }
        "socks5" | "http" => {
            put(&mut settings, "username", text(p, "username"));
            if text(p, "username").is_some() {
                secrets.insert(
                    "password".into(),
                    Secret::new(text(p, "password").unwrap_or_default()),
                );
            }
            if ty == "http" && text(p, "tls").as_deref() == Some("true") {
                settings.insert("security".into(), "tls".into());
            }
            if ty == "socks5" {
                Protocol::Socks
            } else {
                Protocol::HttpProxy
            }
        }
        "wireguard" => {
            let Some(sk) = text(p, "private-key") else {
                return out.issue(label, miss("WireGuard", "PrivateKey"));
            };
            let Some(pk) = text(p, "public-key") else {
                return out.issue(label, miss("WireGuard", "PublicKey"));
            };
            let addr: Vec<String> = [text(p, "ip"), text(p, "ipv6")]
                .into_iter()
                .flatten()
                .map(|a| {
                    if a.contains('/') {
                        a
                    } else if a.contains(':') {
                        format!("{a}/128")
                    } else {
                        format!("{a}/32")
                    }
                })
                .collect();
            if addr.is_empty() {
                return out.issue(label, miss("WireGuard", "Address"));
            }
            secrets.insert("private_key".into(), Secret::new(sk));
            if let Some(psk) = text(p, "pre-shared-key") {
                secrets.insert("preshared_key".into(), Secret::new(psk));
            }
            settings.insert("address".into(), addr.join(", "));
            settings.insert("allowed_ips".into(), "0.0.0.0/0, ::/0".into());
            settings.insert("peer_public_key".into(), pk);
            put(&mut settings, "mtu", text(p, "mtu"));
            if let Some(r) = p.get("reserved").and_then(Value::as_array) {
                settings.insert(
                    "reserved".into(),
                    r.iter()
                        .filter_map(Value::as_u64)
                        .map(|n| n.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            Protocol::WireGuard
        }
        _ => return out.issue(label, ConfigIssue::Unsupported("Clash proxy type")),
    };
    out.profile(Profile {
        name: name_of(p, &host),
        protocol,
        host,
        port,
        settings,
        secrets,
    });
}

pub fn clash_yaml(text: &str, out: &mut Analysis) -> Result<(), ConfigIssue> {
    let v: Value = serde_yaml_ng::from_str(text).map_err(|_| ConfigIssue::Unrecognized)?;
    let list = v
        .get("proxies")
        .and_then(Value::as_array)
        .ok_or(ConfigIssue::Unrecognized)?;
    for p in list.iter().take(crate::MAX_PROFILES) {
        clash_proxy(p, out);
    }
    Ok(())
}

// ---------- JSON dispatcher ----------

pub fn json_config(v: &Value, out: &mut Analysis) -> Result<(), ConfigIssue> {
    // Outline / shadowsocks-libev style
    if v.get("server").is_some()
        && (v.get("method").is_some() || v.get("cipher").is_some())
        && v.get("password").is_some()
    {
        let host = text(v, "server").ok_or(miss("Shadowsocks", "server"))?;
        let port = port_of(v, "server_port")
            .or_else(|| port_of(v, "port"))
            .ok_or(miss("Shadowsocks", "port"))?;
        let method = text(v, "method")
            .or_else(|| text(v, "cipher"))
            .ok_or(miss("Shadowsocks", "cipher"))?;
        let mut settings = BTreeMap::new();
        settings.insert("cipher".into(), method);
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "password".into(),
            Secret::new(text(v, "password").ok_or(miss("Shadowsocks", "password"))?),
        );
        let name = name_of(v, &host);
        out.profile(Profile {
            name,
            protocol: Protocol::Shadowsocks,
            host,
            port,
            settings,
            secrets,
        });
        return Ok(());
    }
    let list: Vec<&Value> = match v {
        Value::Array(a) => a.iter().collect(),
        Value::Object(_) => match v.get("outbounds").or_else(|| v.get("outbound")) {
            Some(Value::Array(a)) => a.iter().collect(),
            Some(o @ Value::Object(_)) => vec![o],
            _ => return Err(ConfigIssue::Unrecognized),
        },
        _ => return Err(ConfigIssue::Unrecognized),
    };
    if list.is_empty() {
        return Err(ConfigIssue::Unrecognized);
    }
    for o in list.into_iter().take(crate::MAX_PROFILES) {
        // Array form may hold whole configs.
        if o.get("outbounds").is_some() {
            json_config(o, out)?;
        } else if o.get("protocol").is_some() {
            xray_outbound(o, out);
        } else if o.get("type").is_some()
            && o.get("server").is_some()
            && o.get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| SB_TYPES.iter().any(|(n, _)| *n == t))
            && v.is_array()
        {
            singbox_outbound(o, out);
        } else if o.get("type").is_some() {
            singbox_outbound(o, out);
        }
    }
    Ok(())
}

// ---------- Amnezia vpn:// ----------

/// `vpn://` + base64url(qCompress(json)); qCompress = u32 big-endian length + zlib stream.
pub fn amnezia(link: &str, out: &mut Analysis, depth: u8) -> Result<(), ConfigIssue> {
    let b64 = link
        .trim()
        .strip_prefix("vpn://")
        .ok_or(ConfigIssue::Unrecognized)?;
    let raw = URL_SAFE_NO_PAD
        .decode(b64.trim_end_matches('='))
        .map_err(|_| bad("Amnezia", "link"))?;
    if raw.len() < 5 {
        return Err(bad("Amnezia", "link"));
    }
    let expected = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if expected > crate::MAX_INPUT_BYTES * 4 {
        return Err(ConfigIssue::TooLarge(expected));
    }
    let mut json = String::new();
    flate2::read::ZlibDecoder::new(&raw[4..])
        .take((crate::MAX_INPUT_BYTES * 4) as u64)
        .read_to_string(&mut json)
        .map_err(|_| bad("Amnezia", "link"))?;
    let v: Value = serde_json::from_str(&json).map_err(|_| bad("Amnezia", "link"))?;
    let containers = v
        .get("containers")
        .and_then(Value::as_array)
        .ok_or(miss("Amnezia", "containers"))?;
    let host_name = text(&v, "hostName");
    let desc = text(&v, "description");
    let before = out.profiles_len();
    for c in containers {
        for key in [
            "awg",
            "wireguard",
            "openvpn",
            "xray",
            "shadowsocks",
            "cloak",
        ] {
            let Some(sub) = c.get(key) else { continue };
            let Some(last) = text(sub, "last_config") else {
                continue;
            };
            let inner: Value = serde_json::from_str(&last).unwrap_or(Value::Null);
            let cfg = text(&inner, "config").unwrap_or(last.clone());
            if key == "cloak" {
                out.issue("Cloak".into(), ConfigIssue::Unsupported("Cloak"));
                continue;
            }
            analyze_inner(&cfg, out, depth + 1);
        }
    }
    // Name profiles after the Amnezia server description when the config itself has none.
    if let Some(n) = desc.or(host_name) {
        out.rename_from(before, &n);
    }
    if out.profiles_len() == before && out.issues_len() == 0 {
        return Err(ConfigIssue::Unrecognized);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const K: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn singbox_json_passthrough_and_rejects_file_refs() {
        let ok = format!(
            r#"{{"outbounds":[{{"type":"vless","tag":"a","server":"h.example.com","server_port":443,"uuid":"{UUID}","detour":"x"}},{{"type":"direct","tag":"d"}},{{"type":"selector","tag":"s"}}]}}"#
        );
        let a = analyze(&ok);
        assert_eq!(a.profiles.len(), 1);
        let json = a.profiles[0].secrets["outbound_json"].expose();
        assert!(!json.contains("detour") && json.contains(UUID));
        let evil = r#"{"outbounds":[{"type":"trojan","server":"h","server_port":1,"password":"x","tls":{"enabled":true,"certificate_path":"/etc/shadow"}}]}"#;
        let a = analyze(evil);
        assert!(a.profiles.is_empty() && a.issues.len() == 1);
    }

    #[test]
    fn xray_json_vless_reality_and_vmess_ws() {
        let x = format!(
            r#"{{"outbounds":[
          {{"protocol":"vless","tag":"r","settings":{{"vnext":[{{"address":"h.example.com","port":443,"users":[{{"id":"{UUID}","flow":"xtls-rprx-vision"}}]}}]}},
            "streamSettings":{{"network":"tcp","security":"reality","realitySettings":{{"serverName":"a.com","fingerprint":"chrome","publicKey":"{k}","shortId":"01"}}}}}},
          {{"protocol":"vmess","tag":"w","settings":{{"vnext":[{{"address":"v.example.com","port":443,"users":[{{"id":"{UUID}","security":"auto"}}]}}]}},
            "streamSettings":{{"network":"ws","security":"tls","wsSettings":{{"path":"/p","headers":{{"Host":"v.example.com"}}}}}}}},
          {{"protocol":"freedom","tag":"direct"}}]}}"#,
            k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        let a = analyze(&x);
        assert_eq!(a.profiles.len(), 2, "{:?}", a.issues);
        assert_eq!(a.profiles[0].settings["security"], "reality");
        assert_eq!(a.profiles[1].settings["type"], "ws");
    }

    #[test]
    fn clash_yaml_many_types() {
        let y = format!("proxies:\n  - {{name: a, type: ss, server: s.example.com, port: 8388, cipher: aes-256-gcm, password: pw1234}}\n  - name: b\n    type: vless\n    server: v.example.com\n    port: 443\n    uuid: {UUID}\n    tls: true\n    network: ws\n    servername: v.example.com\n    ws-opts: {{path: /p, headers: {{Host: v.example.com}}}}\n  - {{name: c, type: hysteria2, server: h.example.com, port: 443, password: pw1234, sni: h.example.com}}\n  - {{name: d, type: wireguard, server: w.example.com, port: 51820, ip: 10.0.0.2, private-key: {K}, public-key: {K}}}\n  - {{name: e, type: snell, server: x, port: 1}}\nproxy-groups: []\n");
        let a = analyze(&y);
        assert_eq!(a.profiles.len(), 4, "{:?}", a.issues);
        assert_eq!(a.issues.len(), 1);
        assert_eq!(a.profiles[3].settings["address"], "10.0.0.2/32");
    }

    #[test]
    fn shadowsocks_json() {
        let a = analyze(
            r#"{"server":"s.example.com","server_port":8388,"password":"pw1234","method":"chacha20-ietf-poly1305"}"#,
        );
        assert_eq!(a.profiles.len(), 1);
    }

    #[test]
    fn amnezia_vpn_link_round_trip() {
        use std::io::Write;
        let conf = format!("[Interface]\nPrivateKey = {K}\nAddress = 10.8.1.2/32\nJc = 5\nS1 = 20\nH1 = 11\n[Peer]\nPublicKey = {K}\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n");
        let last = serde_json::json!({"config": conf}).to_string();
        let doc = serde_json::json!({"containers":[{"container":"amnezia-awg","awg":{"last_config": last}}],"description":"My server","hostName":"203.0.113.9"}).to_string();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(doc.as_bytes()).unwrap();
        let mut raw = (doc.len() as u32).to_be_bytes().to_vec();
        raw.extend(z.finish().unwrap());
        let link = format!("vpn://{}", URL_SAFE_NO_PAD.encode(raw));
        let a = analyze(&link);
        assert_eq!(a.profiles.len(), 1, "{:?}", a.issues);
        assert_eq!(a.profiles[0].protocol, Protocol::AmneziaWg);
        assert_eq!(a.profiles[0].name, "My server");
    }
}
