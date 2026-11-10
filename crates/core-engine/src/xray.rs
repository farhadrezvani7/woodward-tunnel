//! Xray-core configuration for profiles sing-box cannot run (XHTTP, mKCP, TCP HTTP header obfuscation,
//! VLESS encryption, Reality post-quantum verification, finalmask, certificate pinning).
//!
//! Xray runs only the outbound: one authenticated loopback SOCKS5 inbound, one outbound with the full
//! stream settings. sing-box keeps the TUN device, DNS and routing and uses that inbound as its upstream.
//! The server address is passed already resolved (so the engine never does a lookup of its own), while the
//! TLS server name and the HTTP host keep the original host name.

use crate::singbox::Built;
use crate::{EngineError, Upstream};
use core_model::{Profile, Protocol};
use serde_json::{json, Map, Value};
use std::net::IpAddr;

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

fn list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// `host_default`: the name used for TLS and HTTP Host when the profile gives none (never the IP).
fn stream_settings(p: &Profile) -> Result<Value, EngineError> {
    let security = s(p, "security").unwrap_or_else(|| {
        if p.protocol == Protocol::Trojan {
            "tls".into()
        } else {
            "none".into()
        }
    });
    let sni = s(p, "sni").unwrap_or_else(|| p.host.clone());
    let mut st = Map::new();
    let network = match s(p, "type").as_deref() {
        None | Some("tcp") => "tcp",
        Some("xhttp") => "xhttp",
        Some("kcp") => "kcp",
        Some("ws") => "ws",
        Some("grpc") => "grpc",
        Some("httpupgrade") => "httpupgrade",
        Some("http") => {
            return Err(EngineError::Unsupported(
                "The HTTP/2 transport is no longer part of Xray; ask the provider for XHTTP, WebSocket or gRPC.",
            ))
        }
        Some(_) => return Err(EngineError::Profile("transport")),
    };
    st.insert("network".into(), json!(network));

    if s(p, "ech").is_some() {
        return Err(EngineError::Unsupported(
            "Encrypted Client Hello cannot be combined with the transport or options of this config.",
        ));
    }
    if truthy(s(p, "disable_sni")) || s(p, "tls_fragment").is_some() {
        return Err(EngineError::Unsupported(
            "TLS fragmentation and disabled SNI cannot be combined with the transport or options of this config.",
        ));
    }
    match security.as_str() {
        "tls" => {
            st.insert("security".into(), json!("tls"));
            let mut t = json!({"serverName": sni});
            if let Some(a) = s(p, "alpn") {
                t["alpn"] = json!(list(&a));
            }
            if let Some(f) = s(p, "fp") {
                t["fingerprint"] = json!(f);
            }
            // Xray-core removed "allowInsecure" (v26.x): there is no way to skip verification, only to
            // pin the certificate (pcs) or its name (vcn). Connecting unverified instead would be wrong.
            if truthy(s(p, "insecure")) || truthy(s(p, "allowInsecure")) {
                return Err(EngineError::Unsupported(
                    "This config asks to skip certificate verification, which Xray-core no longer allows for its transports. Ask the provider for the certificate fingerprint (pinnedPeerCertSha256) or a valid certificate.",
                ));
            }
            if let Some(h) = s(p, "pcs") {
                t["pinnedPeerCertSha256"] = json!(h);
            }
            if let Some(n) = s(p, "vcn") {
                t["verifyPeerCertByName"] = json!(n);
            }
            st.insert("tlsSettings".into(), t);
        }
        "reality" => {
            st.insert("security".into(), json!("reality"));
            let mut r = json!({
                "serverName": sni,
                "fingerprint": s(p, "fp").unwrap_or_else(|| "chrome".into()),
                "publicKey": s(p, "pbk").ok_or(EngineError::Profile("pbk"))?,
                "shortId": s(p, "sid").unwrap_or_default(),
            });
            if let Some(k) = s(p, "pqv") {
                r["mldsa65Verify"] = json!(k);
            }
            st.insert("realitySettings".into(), r);
        }
        "none" => {}
        _ => return Err(EngineError::Profile("security")),
    }

    // Host header and name used by HTTP-based transports.
    let host = s(p, "host").unwrap_or_else(|| sni.clone());
    let path = s(p, "path").unwrap_or_else(|| "/".into());
    match network {
        "xhttp" => {
            let mut x = json!({"host": host, "path": path});
            if let Some(m) = s(p, "mode") {
                x["mode"] = json!(m);
            }
            if let Some(e) = s(p, "extra") {
                x["extra"] = serde_json::from_str(&e).map_err(|_| EngineError::Profile("extra"))?;
            }
            st.insert("xhttpSettings".into(), x);
        }
        "kcp" => {
            st.insert("kcpSettings".into(), json!({}));
            let mut masks = Vec::new();
            if let Some(sd) = s(p, "seed") {
                masks.push(json!({"type": "mkcp-legacy", "settings": {"value": sd}}));
            }
            if let Some(h) = s(p, "header_type") {
                let mut m = json!({"header": h});
                if h == "dns" {
                    m["value"] = json!(host);
                }
                masks.push(json!({"type": "mkcp-legacy", "settings": m}));
            }
            if masks.is_empty() {
                masks.push(json!({"type": "mkcp-legacy", "settings": {}}));
            }
            st.insert("finalmask".into(), json!({"udp": masks}));
        }
        "ws" => {
            st.insert("wsSettings".into(), json!({"path": path, "host": host}));
        }
        "httpupgrade" => {
            st.insert(
                "httpupgradeSettings".into(),
                json!({"path": path, "host": host}),
            );
        }
        "grpc" => {
            st.insert(
                "grpcSettings".into(),
                json!({"serviceName": s(p, "serviceName").unwrap_or_default()}),
            );
        }
        _ => {
            if s(p, "header_type").as_deref() == Some("http") {
                st.insert(
                    "rawSettings".into(),
                    json!({"header": {"type": "http", "request": {
                        "version": "1.1", "method": "GET",
                        "path": list(&path),
                        "headers": {"Host": list(&host)},
                    }}}),
                );
            }
        }
    }
    if let Some(fm) = s(p, "fm") {
        let user: Value = serde_json::from_str(&fm).map_err(|_| EngineError::Profile("fm"))?;
        if network == "kcp" {
            // Both an mKCP header/seed and an explicit finalmask: the explicit one is appended.
            if let (Some(extra), Some(Value::Array(mine))) = (
                user.get("udp").and_then(Value::as_array),
                st.get_mut("finalmask").and_then(|f| f.get_mut("udp")),
            ) {
                mine.extend(extra.iter().cloned());
            }
            if let Some(q) = user.get("quicParams") {
                st["finalmask"]["quicParams"] = q.clone();
            }
        } else {
            st.insert("finalmask".into(), user);
        }
    }
    Ok(Value::Object(st))
}

/// Addresses Xray-core lets an unencrypted VLESS or Trojan outbound talk to (private networks).
fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_loopback() || a.is_link_local(),
        IpAddr::V6(a) => {
            a.is_loopback()
                || (a.segments()[0] & 0xfe00) == 0xfc00
                || (a.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn outbound(p: &Profile, ip: IpAddr) -> Result<Value, EngineError> {
    // Xray-core itself refuses these configs; saying so here gives the user the reason instead of a
    // process that exits at start.
    let plain = s(p, "security")
        .as_deref()
        .unwrap_or(if p.protocol == Protocol::Trojan {
            "tls"
        } else {
            "none"
        })
        == "none";
    let encrypted = s(p, "encryption").is_some();
    if plain
        && !encrypted
        && !is_private(ip)
        && matches!(p.protocol, Protocol::Vless | Protocol::Trojan)
    {
        return Err(EngineError::Unsupported(
            "This config sends VLESS or Trojan traffic without TLS, Reality or encryption to a public server. Xray-core refuses that for safety; ask the provider for a TLS or Reality config.",
        ));
    }
    let address = ip.to_string();
    let settings = match p.protocol {
        Protocol::Vless => {
            let mut v = json!({
                "address": address, "port": p.port,
                "id": secret(p, "uuid")?,
                "encryption": s(p, "encryption").unwrap_or_else(|| "none".into()),
            });
            if let Some(f) = s(p, "flow") {
                v["flow"] = json!(f);
            }
            v
        }
        Protocol::Vmess => json!({
            "address": address, "port": p.port,
            "id": secret(p, "uuid")?,
            "security": s(p, "cipher").unwrap_or_else(|| "auto".into()),
        }),
        Protocol::Trojan => json!({
            "address": address, "port": p.port,
            "password": secret(p, "password")?,
        }),
        other => return Err(EngineError::NotSupported(other)),
    };
    let proto = match p.protocol {
        Protocol::Vless => "vless",
        Protocol::Vmess => "vmess",
        _ => "trojan",
    };
    Ok(json!({
        "tag": "out", "protocol": proto,
        "settings": settings,
        "streamSettings": stream_settings(p)?,
    }))
}

/// Full Xray configuration. `server_ip` is the server address resolved by the caller (outside the tunnel);
/// `inbound` is the loopback SOCKS5 listener sing-box will use, with its random credentials.
pub fn build(p: &Profile, server_ip: IpAddr, inbound: &Upstream) -> Result<Built, EngineError> {
    let out = outbound(p, server_ip)?;
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "in",
            "listen": inbound.addr.ip().to_string(),
            "port": inbound.addr.port(),
            "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [{"user": inbound.username, "pass": inbound.password}],
                "udp": true,
                "ip": inbound.addr.ip().to_string(),
            },
        }],
        "outbounds": [out],
    });
    Ok(Built {
        config,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_import::detect;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn up() -> Upstream {
        Upstream {
            addr: "127.0.0.1:10808".parse().unwrap(),
            username: "u".into(),
            password: "pw".into(),
        }
    }

    fn cfg(link: &str) -> Value {
        cfg_at(link, "203.0.113.7")
    }

    fn cfg_at(link: &str, ip: &str) -> Value {
        let p = detect(link).unwrap();
        build(&p, ip.parse().unwrap(), &up()).unwrap().config
    }

    #[test]
    fn xhttp_keeps_the_hostname_and_uses_the_resolved_address() {
        let c = cfg(&format!("vless://{UUID}@vpn.example.com:443?type=xhttp&security=tls&path=/x&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D"));
        let o = &c["outbounds"][0];
        assert_eq!(o["settings"]["address"], "203.0.113.7");
        assert_eq!(
            o["streamSettings"]["tlsSettings"]["serverName"],
            "vpn.example.com"
        );
        let x = &o["streamSettings"]["xhttpSettings"];
        assert_eq!(x["host"], "vpn.example.com");
        assert_eq!(x["mode"], "stream-up");
        assert_eq!(x["extra"]["xPaddingBytes"], "100-200");
        assert_eq!(c["inbounds"][0]["settings"]["accounts"][0]["pass"], "pw");
        assert_eq!(c["inbounds"][0]["listen"], "127.0.0.1");
        assert!(c.get("api").is_none() && c.get("stats").is_none() && c.get("dns").is_none());
    }

    #[test]
    fn kcp_masks_and_tcp_http_header() {
        let c = cfg(&format!(
            "vless://{UUID}@h.example.com:443?type=kcp&seed=abc&headerType=dns&host=front.example&security=tls"
        ));
        let m = &c["outbounds"][0]["streamSettings"]["finalmask"]["udp"];
        assert_eq!(m[0]["settings"]["value"], "abc");
        assert_eq!(m[1]["settings"]["header"], "dns");
        assert_eq!(m[1]["settings"]["value"], "front.example");
        let c = cfg_at(
            &format!("vless://{UUID}@h.example.com:80?headerType=http&path=/a,/b&host=x.com"),
            "10.1.2.3",
        );
        let h = &c["outbounds"][0]["streamSettings"]["rawSettings"]["header"];
        assert_eq!(h["type"], "http");
        assert_eq!(h["request"]["path"][1], "/b");
        assert_eq!(h["request"]["headers"]["Host"][0], "x.com");
    }

    #[test]
    fn vless_encryption_reality_pqv_and_pins() {
        let e = "mlkem768x25519plus.native.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let c = cfg(&format!("vless://{UUID}@h.example.com:443?encryption={e}"));
        assert_eq!(c["outbounds"][0]["settings"]["encryption"], e);
        let hash = "ab".repeat(32);
        let c = cfg(&format!(
            "trojan://pw@h.example.com:443?pcs={hash}&vcn=a.com,b.com&type=xhttp"
        ));
        let t = &c["outbounds"][0]["streamSettings"]["tlsSettings"];
        assert_eq!(t["pinnedPeerCertSha256"], hash);
        assert_eq!(t["verifyPeerCertByName"], "a.com,b.com");
        let pbk = "A".repeat(43);
        let pqv = "B".repeat(1300);
        let c = cfg(&format!("vless://{UUID}@h.example.com:443?security=reality&sni=front.example&pbk={pbk}&sid=ab&fp=random&pqv={pqv}"));
        let r = &c["outbounds"][0]["streamSettings"]["realitySettings"];
        assert_eq!(r["fingerprint"], "chrome");
        assert_eq!(r["mldsa65Verify"].as_str().map(str::len), Some(1300));
        assert_eq!(r["serverName"], "front.example");
    }

    #[test]
    fn unencrypted_vless_to_a_public_server_is_refused_in_plain_words() {
        let p = detect(&format!("vless://{UUID}@h.example.com:80?headerType=http")).unwrap();
        assert!(matches!(
            build(&p, "203.0.113.7".parse().unwrap(), &up()),
            Err(EngineError::Unsupported(_))
        ));
        // A private address is allowed (and VMess carries its own encryption).
        assert!(build(&p, "10.1.2.3".parse().unwrap(), &up()).is_ok());
        let m = detect(&format!(r#"vmess://{}"#, {
            use base64::{engine::general_purpose::STANDARD, Engine};
            STANDARD.encode(format!(
                r#"{{"add":"h.example.com","port":"80","id":"{UUID}","net":"tcp","type":"http"}}"#
            ))
        }))
        .unwrap();
        assert!(build(&m, "203.0.113.7".parse().unwrap(), &up()).is_ok());
    }

    #[test]
    fn skipping_certificate_verification_and_ech_are_refused() {
        let p = detect(&format!(
            "vless://{UUID}@h.example.com:443?type=xhttp&security=tls&insecure=1"
        ))
        .unwrap();
        assert!(matches!(
            build(&p, "203.0.113.7".parse().unwrap(), &up()),
            Err(EngineError::Unsupported(_))
        ));
        // An ECH link that also needs Xray must not drop ECH silently.
        let ech = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut p = detect(&format!(
            "vless://{UUID}@h.example.com:443?type=xhttp&security=tls"
        ))
        .unwrap();
        p.settings.insert("ech".into(), ech.into());
        assert!(matches!(
            build(&p, "203.0.113.7".parse().unwrap(), &up()),
            Err(EngineError::Unsupported(_))
        ));
    }
}
