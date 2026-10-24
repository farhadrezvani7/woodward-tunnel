//! Generate a sing-box configuration from a validated [`Profile`]. Only whitelisted settings
//! reach the output, and TLS verification stays on unless the profile explicitly turns it off
//! (which is reported as a warning for the UI to show).

use crate::{EngineError, Mode};
use core_model::{Profile, Protocol};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// Profile asked to skip TLS certificate verification.
    InsecureTls,
    /// SSH profile without a pinned host key: any server key is accepted.
    SshHostKeyUnverified,
}

pub struct Built {
    pub config: Value,
    pub warnings: Vec<Warning>,
}

fn s(p: &Profile, k: &str) -> Option<String> {
    p.settings.get(k).filter(|v| !v.is_empty()).cloned()
}
fn secret(p: &Profile, k: &'static str) -> Result<String, EngineError> {
    p.secrets
        .get(k)
        .map(|v| v.expose().to_string())
        .ok_or(EngineError::Profile(k))
}
fn truthy(v: Option<String>) -> bool {
    matches!(v.as_deref(), Some("1") | Some("true"))
}

fn tls(p: &Profile, warnings: &mut Vec<Warning>, force: bool, quic: bool) -> Option<Value> {
    let security = s(p, "security").unwrap_or_default();
    let wanted = force || security == "tls" || security == "reality" || security == "xtls";
    if !wanted {
        return None;
    }
    let mut t = Map::new();
    t.insert("enabled".into(), json!(true));
    t.insert(
        "server_name".into(),
        json!(s(p, "sni").unwrap_or_else(|| p.host.clone())),
    );
    if let Some(a) = s(p, "alpn") {
        t.insert(
            "alpn".into(),
            json!(a.split(',').map(str::trim).collect::<Vec<_>>()),
        );
    }
    if truthy(s(p, "insecure")) || truthy(s(p, "allowInsecure")) {
        t.insert("insecure".into(), json!(true));
        warnings.push(Warning::InsecureTls);
    }
    if truthy(s(p, "disable_sni")) {
        t.insert("disable_sni".into(), json!(true));
    }
    if let Some(e) = s(p, "ech") {
        // ECHConfigList (base64) wrapped in the PEM form sing-box expects.
        let mut lines = vec!["-----BEGIN ECH CONFIGS-----".to_string()];
        lines.extend(
            e.as_bytes()
                .chunks(64)
                .map(|c| String::from_utf8_lossy(c).into_owned()),
        );
        lines.push("-----END ECH CONFIGS-----".to_string());
        t.insert("ech".into(), json!({"enabled": true, "config": lines}));
    }
    if s(p, "tls_fragment").is_some() {
        t.insert("record_fragment".into(), json!(true));
    }
    if !quic {
        if security == "reality" {
            let fp = s(p, "fp").unwrap_or_else(|| "chrome".into());
            t.insert("utls".into(), json!({"enabled": true, "fingerprint": fp}));
            t.insert("reality".into(), json!({"enabled": true, "public_key": s(p, "pbk").unwrap_or_default(), "short_id": s(p, "sid").unwrap_or_default()}));
        } else if let Some(fp) = s(p, "fp") {
            t.insert("utls".into(), json!({"enabled": true, "fingerprint": fp}));
        }
    }
    Some(Value::Object(t))
}

fn transport(p: &Profile) -> Result<Option<Value>, EngineError> {
    let path = s(p, "path").unwrap_or_else(|| "/".into());
    Ok(match s(p, "type").as_deref() {
        None | Some("tcp") => None,
        Some("ws") => {
            let mut t = json!({"type": "ws", "path": path});
            if let Some(h) = s(p, "host") {
                t["headers"] = json!({"Host": h});
            }
            if let Some(ed) = s(p, "ed").and_then(|v| v.parse::<u32>().ok()) {
                t["max_early_data"] = json!(ed);
                t["early_data_header_name"] =
                    json!(s(p, "edh").unwrap_or_else(|| "Sec-WebSocket-Protocol".into()));
            }
            Some(t)
        }
        Some("grpc") => {
            Some(json!({"type": "grpc", "service_name": s(p, "serviceName").unwrap_or_default()}))
        }
        Some("http") | Some("h2") => {
            let mut t = json!({"type": "http", "path": path});
            if let Some(h) = s(p, "host") {
                t["host"] = json!(h.split(',').map(str::trim).collect::<Vec<_>>());
            }
            Some(t)
        }
        Some("httpupgrade") => {
            let mut t = json!({"type": "httpupgrade", "path": path});
            if let Some(h) = s(p, "host") {
                t["host"] = json!(h);
            }
            Some(t)
        }
        // A transport we cannot run must stop the connection, never degrade to plain TCP.
        Some(_) => return Err(EngineError::Profile("transport")),
    })
}

fn mbps(p: &Profile, new: &str, legacy: &str) -> Option<u32> {
    s(p, new).or_else(|| s(p, legacy)).and_then(|v| {
        v.trim_end_matches(|c: char| !c.is_ascii_digit())
            .parse::<u32>()
            .ok()
    })
}

fn server_ports(p: &Profile, o: &mut Map<String, Value>) {
    if let Some(r) = s(p, "server_ports") {
        o.insert(
            "server_ports".into(),
            json!(r.split(',').map(str::trim).collect::<Vec<_>>()),
        );
        o.remove("server_port");
        if let Some(h) = s(p, "hop_interval") {
            o.insert("hop_interval".into(), json!(h));
        }
    }
}

fn outbound(p: &Profile, w: &mut Vec<Warning>) -> Result<Value, EngineError> {
    // Imported sing-box JSON is passed through (already stripped of dialer/file options at import).
    if let Some(raw) = p.secrets.get("outbound_json") {
        let mut v: Value = serde_json::from_str(raw.expose())
            .map_err(|_| EngineError::Profile("outbound_json"))?;
        let obj = v
            .as_object_mut()
            .ok_or(EngineError::Profile("outbound_json"))?;
        obj.insert("tag".into(), json!("proxy"));
        if obj
            .get("tls")
            .and_then(|t| t.get("insecure"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            w.push(Warning::InsecureTls);
        }
        return Ok(v);
    }
    let mut o = Map::new();
    o.insert("tag".into(), json!("proxy"));
    o.insert("server".into(), json!(p.host));
    o.insert("server_port".into(), json!(p.port));
    match p.protocol {
        Protocol::Vless | Protocol::Vmess => {
            let vless = p.protocol == Protocol::Vless;
            o.insert("type".into(), json!(if vless { "vless" } else { "vmess" }));
            o.insert("uuid".into(), json!(secret(p, "uuid")?));
            if vless {
                if let Some(f) = s(p, "flow") {
                    o.insert("flow".into(), json!(f));
                }
            } else {
                o.insert(
                    "security".into(),
                    json!(s(p, "cipher").unwrap_or_else(|| "auto".into())),
                );
                o.insert(
                    "alter_id".into(),
                    json!(s(p, "alter_id")
                        .and_then(|a| a.parse::<u32>().ok())
                        .unwrap_or(0)),
                );
            }
            match s(p, "packet_encoding").as_deref() {
                Some("none") => {
                    o.insert("packet_encoding".into(), json!(""));
                }
                Some(e) => {
                    o.insert("packet_encoding".into(), json!(e));
                }
                None => {}
            }
            if let Some(t) = tls(p, w, false, false) {
                o.insert("tls".into(), t);
            }
            if let Some(t) = transport(p)? {
                o.insert("transport".into(), t);
            }
        }
        Protocol::Trojan => {
            o.insert("type".into(), json!("trojan"));
            o.insert("password".into(), json!(secret(p, "password")?));
            // Trojan runs over TLS unless the link said `security=none` explicitly.
            if let Some(t) = tls(p, w, s(p, "security").as_deref() != Some("none"), false) {
                o.insert("tls".into(), t);
            }
            if let Some(t) = transport(p)? {
                o.insert("transport".into(), t);
            }
        }
        Protocol::Shadowsocks => {
            o.insert("type".into(), json!("shadowsocks"));
            o.insert(
                "method".into(),
                json!(s(p, "cipher").ok_or(EngineError::Profile("cipher"))?),
            );
            o.insert("password".into(), json!(secret(p, "password")?));
            if let Some(pl) = s(p, "plugin") {
                o.insert("plugin".into(), json!(pl));
                if let Some(po) = s(p, "plugin_opts") {
                    o.insert("plugin_opts".into(), json!(po));
                }
            }
        }
        Protocol::Hysteria2 => {
            o.insert("type".into(), json!("hysteria2"));
            o.insert("password".into(), json!(secret(p, "password")?));
            if let Some(t) = tls(p, w, true, true) {
                o.insert("tls".into(), t);
            }
            if let Some(kind @ ("salamander" | "gecko")) = s(p, "obfs").as_deref() {
                let mut ob =
                    json!({"type": kind, "password": s(p, "obfs-password").unwrap_or_default()});
                for k in ["min_packet_size", "max_packet_size"] {
                    if let Some(n) = s(p, k).and_then(|v| v.parse::<u32>().ok()) {
                        ob[k] = json!(n);
                    }
                }
                o.insert("obfs".into(), ob);
            }
            if let Some(n) = mbps(p, "up_mbps", "upmbps") {
                o.insert("up_mbps".into(), json!(n));
            }
            if let Some(n) = mbps(p, "down_mbps", "downmbps") {
                o.insert("down_mbps".into(), json!(n));
            }
            server_ports(p, &mut o);
        }
        Protocol::Tuic => {
            o.insert("type".into(), json!("tuic"));
            o.insert("uuid".into(), json!(secret(p, "uuid")?));
            o.insert("password".into(), json!(secret(p, "password")?));
            for k in ["congestion_control", "udp_relay_mode", "heartbeat"] {
                if let Some(v) = s(p, k) {
                    o.insert(k.into(), json!(v));
                }
            }
            if truthy(s(p, "zero_rtt")) {
                o.insert("zero_rtt_handshake".into(), json!(true));
            }
            if truthy(s(p, "udp_over_stream")) {
                o.insert("udp_over_stream".into(), json!(true));
            }
            if let Some(t) = tls(p, w, true, true) {
                o.insert("tls".into(), t);
            }
        }
        Protocol::Hysteria1 => {
            o.insert("type".into(), json!("hysteria"));
            if let Some(a) = p.secrets.get("password") {
                o.insert("auth_str".into(), json!(a.expose()));
            }
            o.insert(
                "up_mbps".into(),
                json!(mbps(p, "up_mbps", "upmbps")
                    .or_else(|| mbps(p, "up", "up"))
                    .unwrap_or(50)),
            );
            o.insert(
                "down_mbps".into(),
                json!(mbps(p, "down_mbps", "downmbps")
                    .or_else(|| mbps(p, "down", "down"))
                    .unwrap_or(100)),
            );
            if let Some(x) = s(p, "obfs") {
                o.insert("obfs".into(), json!(x));
            }
            if let Some(t) = tls(p, w, true, true) {
                o.insert("tls".into(), t);
            }
            server_ports(p, &mut o);
        }
        Protocol::AnyTls => {
            o.insert("type".into(), json!("anytls"));
            o.insert("password".into(), json!(secret(p, "password")?));
            if let Some(t) = tls(p, w, true, false) {
                o.insert("tls".into(), t);
            }
        }
        Protocol::Socks => {
            o.insert("type".into(), json!("socks"));
            o.insert("version".into(), json!("5"));
            if let Some(u) = s(p, "username") {
                o.insert("username".into(), json!(u));
                o.insert("password".into(), json!(secret(p, "password")?));
            }
        }
        Protocol::HttpProxy => {
            o.insert("type".into(), json!("http"));
            if let Some(u) = s(p, "username") {
                o.insert("username".into(), json!(u));
                o.insert("password".into(), json!(secret(p, "password")?));
            }
            if let Some(t) = tls(p, w, false, false) {
                o.insert("tls".into(), t);
            }
        }
        Protocol::Ssh => {
            o.insert("type".into(), json!("ssh"));
            o.insert(
                "user".into(),
                json!(s(p, "username").ok_or(EngineError::Profile("username"))?),
            );
            o.insert("password".into(), json!(secret(p, "password")?));
            if let Some(k) = s(p, "host_key") {
                o.insert("host_key".into(), json!([k]));
            } else {
                // Without a pinned host key sing-box accepts any key: a man in the middle is possible.
                w.push(Warning::SshHostKeyUnverified);
            }
        }
        Protocol::WireGuard | Protocol::AmneziaWg | Protocol::OpenVpn => {
            return Err(EngineError::NotSupported(p.protocol))
        }
    }
    Ok(Value::Object(o))
}

fn wireguard_endpoint(p: &Profile) -> Result<Value, EngineError> {
    let addrs: Vec<String> = s(p, "address")
        .ok_or(EngineError::Profile("address"))?
        .split(',')
        .map(|a| a.trim().to_string())
        .collect();
    let allowed: Vec<String> = s(p, "allowed_ips")
        .unwrap_or_else(|| "0.0.0.0/0, ::/0".into())
        .split(',')
        .map(|a| a.trim().to_string())
        .collect();
    let mut peer = json!({
        "address": p.host, "port": p.port,
        "public_key": s(p, "peer_public_key").ok_or(EngineError::Profile("peer_public_key"))?,
        "allowed_ips": allowed,
    });
    if let Some(psk) = p.secrets.get("preshared_key") {
        peer["pre_shared_key"] = json!(psk.expose());
    }
    if let Some(k) = s(p, "persistent_keepalive").and_then(|k| k.parse::<u32>().ok()) {
        peer["persistent_keepalive_interval"] = json!(k);
    }
    if let Some(r) = s(p, "reserved") {
        let v: Vec<u8> = r.split(',').filter_map(|x| x.trim().parse().ok()).collect();
        if v.len() == 3 {
            peer["reserved"] = json!(v);
        }
    }
    let mut e = json!({"type": "wireguard", "tag": "proxy", "address": addrs, "private_key": secret(p, "private_key")?, "peers": [peer]});
    if let Some(m) = s(p, "mtu").and_then(|m| m.parse::<u32>().ok()) {
        e["mtu"] = json!(m);
    }
    Ok(e)
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub mode: Option<Mode>,
    pub dns: Vec<String>,
    /// Local SOCKS5 listener of a helper engine (AmneziaWG); the "proxy" outbound points here.
    pub upstream_socks: Option<std::net::SocketAddr>,
    /// Addresses that must bypass the tunnel (e.g. a helper engine's server endpoint).
    pub bypass: Vec<std::net::IpAddr>,
    /// Let QUIC (UDP 443) through. Off by default: many proxy servers relay UDP poorly or not at all,
    /// and a silently dropped QUIC flow makes YouTube and other apps hang instead of falling back to TCP.
    pub allow_quic: bool,
}

/// Public resolver addresses known to serve DoH at `/dns-query` with an IP-valid certificate.
const DOH_CAPABLE: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
];

/// One DNS server entry the system's lookups are sent to, always through the proxy.
/// Accepts an IP (plain DNS over UDP), `https://host/path` (DoH) or `tls://host` (DoT).
fn remote_dns_server(spec: Option<&str>) -> Value {
    let base = |ty: &str| json!({"type": ty, "tag": "remote", "detour": "proxy"});
    match spec.map(str::trim).filter(|v| !v.is_empty()) {
        // Default: DNS over HTTPS reaches the resolver over TCP, so it works through every proxy type,
        // including ones that cannot relay UDP (HTTP, many SOCKS and CDN-fronted setups).
        None => {
            let mut v = base("https");
            v["server"] = json!("1.1.1.1");
            v["path"] = json!("/dns-query");
            v
        }
        Some(u) if u.starts_with("https://") => {
            let rest = &u["https://".len()..];
            let (host, path) = rest
                .split_once('/')
                .map(|(h, p)| (h, format!("/{p}")))
                .unwrap_or((rest, "/dns-query".into()));
            let mut v = base("https");
            v["server"] = json!(host);
            v["path"] = json!(path);
            v
        }
        Some(u) if u.starts_with("tls://") => {
            let mut v = base("tls");
            v["server"] = json!(&u["tls://".len()..]);
            v
        }
        // Well-known public resolvers also answer DNS over HTTPS on the same address. Using it keeps DNS
        // working through proxies that cannot relay UDP (this was a real failure: the app listed
        // "1.1.1.1, 8.8.8.8" and every lookup died behind a TCP-only upstream).
        Some(ip) if DOH_CAPABLE.contains(&ip) => {
            let mut v = base("https");
            v["server"] = json!(ip);
            v["path"] = json!("/dns-query");
            v
        }
        Some(ip) => {
            let mut v = base("udp");
            v["server"] = json!(ip);
            v
        }
    }
}

pub fn build(p: &Profile, mode: &Mode, dns: &[String]) -> Result<Built, EngineError> {
    build_with(
        p,
        &Options {
            mode: Some(mode.clone()),
            dns: dns.to_vec(),
            ..Default::default()
        },
    )
}

/// Build the full config. `dns` are resolvers reached through the tunnel (never the system resolver).
pub fn build_with(p: &Profile, opts: &Options) -> Result<Built, EngineError> {
    let mode = opts.mode.as_ref().ok_or(EngineError::Profile("mode"))?;
    let dns = &opts.dns;
    let mut warnings = Vec::new();
    let mut cfg = Map::new();
    cfg.insert("log".into(), json!({"level": "warn", "timestamp": true}));

    let inbound = match mode {
        Mode::Tun => {
            let mut t = json!({
                "type": "tun", "tag": "tun-in",
                // Fixed name on Linux so the kill switch can target it; macOS needs utunN, Windows any name.
                "interface_name": if cfg!(target_os = "linux") { "wt0" } else { "" },
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": true, "strict_route": true,
            });
            if !cfg!(target_os = "linux") {
                if let Some(o) = t.as_object_mut() {
                    o.remove("interface_name");
                }
            }
            if !opts.bypass.is_empty() {
                let ex: Vec<String> = opts
                    .bypass
                    .iter()
                    .map(|ip| {
                        if ip.is_ipv4() {
                            format!("{ip}/32")
                        } else {
                            format!("{ip}/128")
                        }
                    })
                    .collect();
                t["route_exclude_address"] = json!(ex);
            }
            t
        }
        Mode::Proxy { socks_port } => {
            json!({"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socks_port})
        }
    };
    cfg.insert("inbounds".into(), json!([inbound]));

    cfg.insert(
        "dns".into(),
        json!({"servers": [
            // Application lookups go through the tunnel.
            remote_dns_server(dns.first().map(String::as_str)),
            // The VPN server's own hostname cannot be resolved through a tunnel that does not exist yet.
            {"type": "local", "tag": "bootstrap"}
        ],
        "final": "remote",
        // Prefer IPv4 addresses: many servers have no IPv6 egress and apps would otherwise stall on AAAA first.
        "strategy": "prefer_ipv4"}),
    );

    if matches!(p.protocol, Protocol::AmneziaWg) {
        let up = opts
            .upstream_socks
            .ok_or(EngineError::Profile("upstream_socks"))?;
        cfg.insert("outbounds".into(), json!([{"type": "socks", "tag": "proxy", "server": up.ip().to_string(), "server_port": up.port(), "version": "5"}, {"type": "direct", "tag": "direct"}]));
    } else if matches!(p.protocol, Protocol::WireGuard) {
        cfg.insert("endpoints".into(), json!([wireguard_endpoint(p)?]));
        cfg.insert(
            "outbounds".into(),
            json!([{"type": "direct", "tag": "direct"}]),
        );
    } else {
        cfg.insert(
            "outbounds".into(),
            json!([outbound(p, &mut warnings)?, {"type": "direct", "tag": "direct"}]),
        );
    }
    let mut route = json!({"final": "proxy", "default_domain_resolver": "bootstrap"});
    if matches!(mode, Mode::Tun) {
        route["auto_detect_interface"] = json!(true);
        // Send every DNS query the system makes to the engine's resolver, which goes through the tunnel,
        // instead of letting it travel to whatever resolver the network handed out.
        let mut rules = vec![
            json!({"action": "sniff"}),
            json!({"protocol": "dns", "action": "hijack-dns"}),
        ];
        if !opts.allow_quic {
            // Reject QUIC so the app falls back to HTTPS over TCP immediately.
            rules.push(json!({"network": "udp", "port": 443, "action": "reject"}));
        }
        route["rules"] = json!(rules);
    }
    cfg.insert("route".into(), route);
    Ok(Built {
        config: Value::Object(cfg),
        warnings,
    })
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    #[test]
    fn default_and_known_resolvers_use_doh_over_tcp() {
        for spec in [None, Some("1.1.1.1"), Some("8.8.8.8"), Some(" 9.9.9.9 ")] {
            assert_eq!(remote_dns_server(spec)["type"], "https", "{spec:?}");
        }
        assert_eq!(
            remote_dns_server(Some("https://dns.example/q"))["path"],
            "/q"
        );
        assert_eq!(remote_dns_server(Some("tls://dns.example"))["type"], "tls");
    }

    #[test]
    fn unknown_ip_resolver_stays_plain_udp() {
        let v = remote_dns_server(Some("192.168.1.1"));
        assert_eq!(
            (v["type"].as_str(), v["server"].as_str()),
            (Some("udp"), Some("192.168.1.1"))
        );
    }

    #[test]
    fn quic_is_rejected_in_tun_mode_unless_allowed() {
        use core_model::{Profile, Protocol, Secret};
        use std::collections::BTreeMap;
        let mut secrets = BTreeMap::new();
        secrets.insert("password".to_string(), Secret::new("pw-test-1234"));
        let mut settings = BTreeMap::new();
        settings.insert("cipher".to_string(), "aes-256-gcm".to_string());
        let p = Profile {
            name: "n".into(),
            protocol: Protocol::Shadowsocks,
            host: "h.example.com".into(),
            port: 1,
            settings,
            secrets,
        };
        let rules = |allow| {
            build_with(
                &p,
                &Options {
                    mode: Some(Mode::Tun),
                    allow_quic: allow,
                    ..Default::default()
                },
            )
            .unwrap()
            .config["route"]["rules"]
                .to_string()
        };
        assert!(rules(false).contains("\"port\":443") && rules(false).contains("reject"));
        assert!(!rules(true).contains("reject"));
    }
}
