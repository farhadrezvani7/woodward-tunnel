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

/// Obfuscation/tuning keys accepted by amneziawg-go v3.1.20260828 (`device/uapi.go`).
const UAPI_KEYS: &[&str] = &[
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
    "random_trailers",
    "disable_cookies",
];

/// Everything a platform needs to run WireGuard or AmneziaWG the way the official apps do: the OS hands
/// over a TUN device, amneziawg-go runs on it directly (no user-space network stack, no SOCKS, no
/// second engine). Routes are the peer's AllowedIPs; the endpoint's UDP socket must be protected from
/// the VPN (Android `VpnService.protect`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlan {
    /// UAPI text for `IpcSet` (private key, obfuscation parameters, one peer).
    pub uapi: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub search_domains: Vec<String>,
    pub mtu: u16,
    pub allowed_ips: Vec<String>,
    pub endpoint_ip: IpAddr,
    pub endpoint_port: u16,
}

fn key_hex(b64: &str, what: &'static str) -> Result<String, EngineError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let bytes = STANDARD
        .decode(b64.trim())
        .map_err(|_| EngineError::Profile(what))?;
    if bytes.len() != 32 {
        return Err(EngineError::Profile(what));
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Build the native plan. `endpoint_ip` is the peer address resolved by the caller outside the tunnel.
pub fn native_plan(p: &Profile, endpoint_ip: IpAddr) -> Result<NativePlan, EngineError> {
    let list = |v: String| {
        v.split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let private = p
        .secrets
        .get("private_key")
        .ok_or(EngineError::Profile("private_key"))?;
    let mut u = format!(
        "private_key={}\n",
        key_hex(private.expose(), "private_key")?
    );
    for (k, v) in &p.settings {
        if let Some(name) = k.strip_prefix("awg_") {
            // Only keys amneziawg-go v3.1 understands: an unknown key makes `IpcSet` fail as a whole.
            let ok = UAPI_KEYS.contains(&name);
            if ok && !v.contains(['\n', '\r']) {
                u.push_str(&format!("{name}={v}\n"));
            }
        }
    }
    let public = s(p, "peer_public_key").ok_or(EngineError::Profile("peer_public_key"))?;
    u.push_str("replace_peers=true\n");
    u.push_str(&format!(
        "public_key={}\n",
        key_hex(&public, "peer_public_key")?
    ));
    if let Some(k) = p.secrets.get("preshared_key") {
        u.push_str(&format!(
            "preshared_key={}\n",
            key_hex(k.expose(), "preshared_key")?
        ));
    }
    let endpoint = match endpoint_ip {
        IpAddr::V4(ip) => format!("{ip}:{}", p.port),
        IpAddr::V6(ip) => format!("[{ip}]:{}", p.port),
    };
    u.push_str(&format!("endpoint={endpoint}\n"));
    if let Some(k) = s(p, "persistent_keepalive").and_then(|k| k.parse::<u32>().ok()) {
        u.push_str(&format!("persistent_keepalive_interval={k}\n"));
    }
    let allowed = list(s(p, "allowed_ips").unwrap_or_else(|| "0.0.0.0/0, ::/0".into()));
    u.push_str("replace_allowed_ips=true\n");
    for a in &allowed {
        u.push_str(&format!("allowed_ip={a}\n"));
    }
    let (mut dns, mut search) = (Vec::new(), Vec::new());
    for d in list(s(p, "dns").unwrap_or_default()) {
        if d.parse::<IpAddr>().is_ok() {
            dns.push(d);
        } else {
            search.push(d);
        }
    }
    // The official apps default to 1280 when the config has no MTU.
    let mtu = s(p, "mtu")
        .and_then(|m| m.parse::<u16>().ok())
        .filter(|m| (576..=1500).contains(m))
        .unwrap_or(1280);
    Ok(NativePlan {
        uapi: u,
        addresses: list(s(p, "address").ok_or(EngineError::Profile("address"))?),
        dns,
        search_domains: search,
        mtu,
        allowed_ips: allowed,
        endpoint_ip,
        endpoint_port: p.port,
    })
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

    #[test]
    fn native_plan_matches_official_apps() {
        let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let conf = format!("[Interface]\nPrivateKey = {k}\nAddress = 10.8.1.2/32, fd00::2/128\nDNS = 1.1.1.1, example.lan\nJc = 5\nS1 = 20\nH1 = 100-200\n[Peer]\nPublicKey = {k}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n");
        let mut p = detect(&conf).unwrap();
        // Whatever the importer keeps in `dns`, the plan must split addresses from search domains.
        p.settings
            .insert("dns".into(), "1.1.1.1, example.lan".into());
        let n = native_plan(&p, "203.0.113.9".parse().unwrap()).unwrap();
        assert!(n
            .uapi
            .starts_with(&format!("private_key={}\n", "00".repeat(32))));
        for line in [
            "jc=5",
            "s1=20",
            "h1=100-200",
            "replace_peers=true",
            "endpoint=203.0.113.9:51820",
            "persistent_keepalive_interval=25",
            "allowed_ip=0.0.0.0/0",
            "allowed_ip=::/0",
        ] {
            assert!(
                n.uapi.lines().any(|l| l == line),
                "missing {line}:\n{}",
                n.uapi
            );
        }
        assert_eq!(
            (n.mtu, n.dns.as_slice(), n.search_domains.as_slice()),
            (
                1280,
                &["1.1.1.1".to_string()][..],
                &["example.lan".to_string()][..]
            )
        );
        assert_eq!(n.addresses.len(), 2);
    }

    #[test]
    fn native_plan_rejects_bad_keys() {
        let mut p = detect(&format!("[Interface]\nPrivateKey = {k}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {k}\nEndpoint = h.example.com:1\nAllowedIPs = 0.0.0.0/0\n", k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")).unwrap();
        p.settings.insert("peer_public_key".into(), "short".into());
        assert!(native_plan(&p, "203.0.113.9".parse().unwrap()).is_err());
    }
}
