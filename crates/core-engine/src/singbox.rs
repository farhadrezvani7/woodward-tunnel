//! Generate a sing-box configuration from a validated [`Profile`]. Only whitelisted settings
//! reach the output, and TLS verification stays on unless the profile explicitly turns it off
//! (which is reported as a warning for the UI to show).

use crate::{EngineError, Mode};
use core_model::{Profile, Protocol};
use serde_json::{json, Map, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// Profile asked to skip TLS certificate verification.
    InsecureTls,
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

fn tls(p: &Profile, warnings: &mut Vec<Warning>, force: bool) -> Option<Value> {
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
    if security == "reality" {
        let fp = s(p, "fp").unwrap_or_else(|| "chrome".into());
        t.insert("utls".into(), json!({"enabled": true, "fingerprint": fp}));
        t.insert("reality".into(), json!({"enabled": true, "public_key": s(p, "pbk").unwrap_or_default(), "short_id": s(p, "sid").unwrap_or_default()}));
    } else if let Some(fp) = s(p, "fp") {
        t.insert("utls".into(), json!({"enabled": true, "fingerprint": fp}));
    }
    Some(Value::Object(t))
}

fn transport(p: &Profile) -> Option<Value> {
    match s(p, "type").as_deref() {
        Some("ws") => {
            let mut t = json!({"type": "ws", "path": s(p, "path").unwrap_or_else(|| "/".into())});
            if let Some(h) = s(p, "host") {
                t["headers"] = json!({"Host": h});
            }
            Some(t)
        }
        Some("grpc") => {
            Some(json!({"type": "grpc", "service_name": s(p, "serviceName").unwrap_or_default()}))
        }
        Some("http") | Some("h2") => {
            Some(json!({"type": "http", "path": s(p, "path").unwrap_or_else(|| "/".into())}))
        }
        _ => None,
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
        Protocol::Vless => {
            o.insert("type".into(), json!("vless"));
            o.insert("uuid".into(), json!(secret(p, "uuid")?));
            if let Some(f) = s(p, "flow") {
                o.insert("flow".into(), json!(f));
            }
            if let Some(t) = tls(p, w, false) {
                o.insert("tls".into(), t);
            }
            if let Some(t) = transport(p) {
                o.insert("transport".into(), t);
            }
        }
        Protocol::Vmess => {
            o.insert("type".into(), json!("vmess"));
            o.insert("uuid".into(), json!(secret(p, "uuid")?));
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
            if let Some(t) = tls(p, w, false) {
                o.insert("tls".into(), t);
            }
            if let Some(t) = transport(p) {
                o.insert("transport".into(), t);
            }
        }
        Protocol::Trojan => {
            o.insert("type".into(), json!("trojan"));
            o.insert("password".into(), json!(secret(p, "password")?));
            // Trojan always runs over TLS.
            if let Some(t) = tls(p, w, true) {
                o.insert("tls".into(), t);
            }
            if let Some(t) = transport(p) {
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
        }
        Protocol::Hysteria2 => {
            o.insert("type".into(), json!("hysteria2"));
            o.insert("password".into(), json!(secret(p, "password")?));
            if let Some(t) = tls(p, w, true) {
                o.insert("tls".into(), t);
            }
            if s(p, "obfs").as_deref() == Some("salamander") {
                o.insert("obfs".into(), json!({"type": "salamander", "password": s(p, "obfs-password").unwrap_or_default()}));
            }
        }
        Protocol::Tuic => {
            o.insert("type".into(), json!("tuic"));
            o.insert("uuid".into(), json!(secret(p, "uuid")?));
            o.insert("password".into(), json!(secret(p, "password")?));
            o.insert(
                "congestion_control".into(),
                json!(s(p, "congestion_control").unwrap_or_else(|| "bbr".into())),
            );
            if let Some(m) = s(p, "udp_relay_mode") {
                o.insert("udp_relay_mode".into(), json!(m));
            }
            if let Some(t) = tls(p, w, true) {
                o.insert("tls".into(), t);
            }
        }
        Protocol::Hysteria1 => {
            o.insert("type".into(), json!("hysteria"));
            if let Some(a) = p.secrets.get("password") {
                o.insert("auth_str".into(), json!(a.expose()));
            }
            let mbps = |k: &str| {
                s(p, k).and_then(|v| {
                    v.trim_end_matches(|c: char| !c.is_ascii_digit())
                        .parse::<u32>()
                        .ok()
                })
            };
            o.insert(
                "up_mbps".into(),
                json!(mbps("upmbps").or_else(|| mbps("up")).unwrap_or(50)),
            );
            o.insert(
                "down_mbps".into(),
                json!(mbps("downmbps").or_else(|| mbps("down")).unwrap_or(100)),
            );
            if let Some(x) = s(p, "obfs") {
                o.insert("obfs".into(), json!(x));
            }
            if let Some(t) = tls(p, w, true) {
                o.insert("tls".into(), t);
            }
        }
        Protocol::AnyTls => {
            o.insert("type".into(), json!("anytls"));
            o.insert("password".into(), json!(secret(p, "password")?));
            if let Some(t) = tls(p, w, true) {
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
            if let Some(t) = tls(p, w, false) {
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

/// Build the full config. `dns` are resolvers reached through the tunnel (never the system resolver).
pub fn build(p: &Profile, mode: &Mode, dns: &[String]) -> Result<Built, EngineError> {
    let mut warnings = Vec::new();
    let mut cfg = Map::new();
    cfg.insert("log".into(), json!({"level": "warn", "timestamp": true}));

    let inbound = match mode {
        Mode::Tun => json!({
            "type": "tun", "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "auto_route": true, "strict_route": true,
        }),
        Mode::Proxy { socks_port } => {
            json!({"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socks_port})
        }
    };
    cfg.insert("inbounds".into(), json!([inbound]));

    let dns_server = dns.first().cloned().unwrap_or_else(|| "1.1.1.1".into());
    cfg.insert("dns".into(), json!({"servers": [{"type": "udp", "tag": "remote", "server": dns_server, "detour": "proxy"}], "final": "remote"}));

    if matches!(p.protocol, Protocol::WireGuard) {
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
    let mut route = json!({"final": "proxy", "default_domain_resolver": "remote"});
    if matches!(mode, Mode::Tun) {
        route["auto_detect_interface"] = json!(true);
    }
    cfg.insert("route".into(), route);
    Ok(Built {
        config: Value::Object(cfg),
        warnings,
    })
}
