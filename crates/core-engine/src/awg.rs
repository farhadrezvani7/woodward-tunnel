//! AmneziaWG: JSON config for the `awg-socks` helper (user-space peer exposing a local SOCKS5).

use crate::EngineError;
use core_model::Profile;
use serde_json::{json, Value};
use std::net::IpAddr;

fn s(p: &Profile, k: &str) -> Option<String> {
    p.settings.get(k).filter(|v| !v.is_empty()).cloned()
}

/// `endpoint_ip`: the peer's address already resolved by the caller (outside the tunnel).
pub fn helper_config(p: &Profile, endpoint_ip: IpAddr, listen: &str) -> Result<Value, EngineError> {
    let list = |v: String| {
        v.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
    };
    let mut awg = serde_json::Map::new();
    for (k, v) in &p.settings {
        if let Some(name) = k.strip_prefix("awg_") {
            awg.insert(name.to_string(), json!(v));
        }
    }
    let endpoint = match endpoint_ip {
        IpAddr::V4(ip) => format!("{ip}:{}", p.port),
        IpAddr::V6(ip) => format!("[{ip}]:{}", p.port),
    };
    let mut peer = json!({
        "public_key": s(p, "peer_public_key").ok_or(EngineError::Profile("peer_public_key"))?,
        "endpoint": endpoint,
        "allowed_ips": list(s(p, "allowed_ips").unwrap_or_else(|| "0.0.0.0/0, ::/0".into())),
    });
    if let Some(k) = p.secrets.get("preshared_key") {
        peer["preshared_key"] = json!(k.expose());
    }
    if let Some(k) = s(p, "persistent_keepalive").and_then(|k| k.parse::<u32>().ok()) {
        peer["keepalive"] = json!(k);
    }
    Ok(json!({
        "private_key": p.secrets.get("private_key").ok_or(EngineError::Profile("private_key"))?.expose(),
        "addresses": list(s(p, "address").ok_or(EngineError::Profile("address"))?),
        "dns": list(s(p, "dns").unwrap_or_default()),
        "mtu": s(p, "mtu").and_then(|m| m.parse::<u32>().ok()).unwrap_or(1280),
        "peer": peer,
        "awg": Value::Object(awg),
        "listen": listen,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_import::detect;

    #[test]
    fn renders_obfuscation_and_resolved_endpoint() {
        let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let conf = format!("[Interface]\nPrivateKey = {k}\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1, 8.8.8.8\nJc = 5\nS1 = 20\nH4 = 99\n[Peer]\nPublicKey = {k}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n");
        let p = detect(&conf).unwrap();
        let v = helper_config(&p, "203.0.113.9".parse().unwrap(), "127.0.0.1:0").unwrap();
        assert_eq!(v["peer"]["endpoint"], "203.0.113.9:51820");
        assert_eq!(v["awg"]["jc"], "5");
        assert_eq!(v["awg"]["h4"], "99");
        assert_eq!(v["dns"].as_array().unwrap().len(), 2);
    }
}
