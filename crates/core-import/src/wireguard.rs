//! WireGuard / AmneziaWG `.conf` (INI) parsing.

use base64::{engine::general_purpose::STANDARD, Engine};
use core_model::{ConfigIssue, Profile, Protocol, Secret};
use std::collections::BTreeMap;

const WG: &str = "WireGuard";
/// Obfuscation parameters that identify AmneziaWG.
const AWG_KEYS: &[&str] = &["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];

pub fn looks_like(text: &str) -> bool {
    text.lines()
        .any(|l| l.trim().eq_ignore_ascii_case("[interface]"))
}

#[derive(Default)]
struct Section {
    kv: BTreeMap<String, String>,
}

fn sections(text: &str) -> Result<(Section, Vec<Section>), ConfigIssue> {
    let mut iface: Option<Section> = None;
    let mut peers: Vec<Section> = Vec::new();
    let mut cur: Option<(bool, Section)> = None; // (is_interface, section)
    let flush = |cur: &mut Option<(bool, Section)>,
                 iface: &mut Option<Section>,
                 peers: &mut Vec<Section>| {
        if let Some((is_if, s)) = cur.take() {
            if is_if {
                *iface = Some(s);
            } else {
                peers.push(s);
            }
        }
    };
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            flush(&mut cur, &mut iface, &mut peers);
            match line[1..line.len() - 1].trim().to_ascii_lowercase().as_str() {
                "interface" => cur = Some((true, Section::default())),
                "peer" => cur = Some((false, Section::default())),
                _ => {
                    return Err(ConfigIssue::InvalidField {
                        protocol: WG,
                        field: "section",
                    })
                }
            }
            continue;
        }
        let Some((_, sec)) = cur.as_mut() else {
            return Err(ConfigIssue::Unrecognized);
        };
        let Some((k, v)) = line.split_once('=') else {
            return Err(ConfigIssue::InvalidField {
                protocol: WG,
                field: "line",
            });
        };
        sec.kv
            .insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    flush(&mut cur, &mut iface, &mut peers);
    Ok((
        iface.ok_or(ConfigIssue::MissingField {
            protocol: WG,
            field: "Interface",
        })?,
        peers,
    ))
}

fn key32(v: &str) -> bool {
    STANDARD.decode(v).map(|b| b.len() == 32).unwrap_or(false)
}

/// Split `host:port`, `[v6]:port`.
fn split_endpoint(ep: &str) -> Option<(String, u16)> {
    let (host, port) = ep.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    (!host.is_empty()).then(|| (host.to_string(), port))
}

pub fn parse(text: &str) -> Result<Profile, ConfigIssue> {
    let (iface, peers) = sections(text)?;
    let peer = peers.first().ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "Peer",
    })?;

    let private = iface
        .kv
        .get("privatekey")
        .ok_or(ConfigIssue::MissingField {
            protocol: WG,
            field: "PrivateKey",
        })?;
    if !key32(private) {
        return Err(ConfigIssue::InvalidField {
            protocol: WG,
            field: "PrivateKey",
        });
    }
    let public = peer.kv.get("publickey").ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "PublicKey",
    })?;
    if !key32(public) {
        return Err(ConfigIssue::InvalidField {
            protocol: WG,
            field: "PublicKey",
        });
    }
    let endpoint = peer.kv.get("endpoint").ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "Endpoint",
    })?;
    let (host, port) = split_endpoint(endpoint).ok_or(ConfigIssue::InvalidField {
        protocol: WG,
        field: "Endpoint",
    })?;
    let allowed = peer.kv.get("allowedips").ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "AllowedIPs",
    })?;
    let address = iface.kv.get("address").ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "Address",
    })?;

    let mut settings = BTreeMap::new();
    settings.insert("address".into(), address.clone());
    settings.insert("allowed_ips".into(), allowed.clone());
    settings.insert("peer_public_key".into(), public.clone());
    for k in ["dns", "mtu"] {
        if let Some(v) = iface.kv.get(k) {
            settings.insert(k.into(), v.clone());
        }
    }
    if let Some(v) = peer.kv.get("persistentkeepalive") {
        settings.insert("persistent_keepalive".into(), v.clone());
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("private_key".into(), Secret::new(private.clone()));
    if let Some(psk) = peer.kv.get("presharedkey") {
        if !key32(psk) {
            return Err(ConfigIssue::InvalidField {
                protocol: WG,
                field: "PresharedKey",
            });
        }
        secrets.insert("preshared_key".into(), Secret::new(psk.clone()));
    }

    let mut protocol = Protocol::WireGuard;
    for k in AWG_KEYS {
        if let Some(v) = iface.kv.get(&k.to_ascii_lowercase()) {
            protocol = Protocol::AmneziaWg;
            settings.insert(format!("awg_{}", k.to_ascii_lowercase()), v.clone());
        }
    }
    Ok(Profile {
        name: host.clone(),
        protocol,
        host,
        port,
        settings,
        secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // 32 zero bytes, base64
    const K: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    fn conf(extra_if: &str) -> String {
        format!("[Interface]\nPrivateKey = {K}\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n{extra_if}\n[Peer]\nPublicKey = {K}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n")
    }

    #[test]
    fn parses_plain_wireguard() {
        let p = parse(&conf("")).unwrap();
        assert_eq!(p.protocol, Protocol::WireGuard);
        assert_eq!((p.host.as_str(), p.port), ("vpn.example.com", 51820));
        assert!(p.secrets.contains_key("private_key"));
        // The public key is a plain setting; only the secrets map must be redacted.
        let dbg = format!("{:?}", p.secrets);
        assert!(dbg.contains("<redacted>") && !dbg.contains(K));
    }

    #[test]
    fn detects_amnezia_by_obfuscation_keys() {
        let p = parse(&conf("Jc = 5\nS1 = 20\nH1 = 123")).unwrap();
        assert_eq!(p.protocol, Protocol::AmneziaWg);
        assert_eq!(p.settings.get("awg_jc").map(String::as_str), Some("5"));
    }

    #[test]
    fn rejects_bad_key_missing_peer_and_bad_port() {
        let bad = conf("").replace(&format!("PrivateKey = {K}"), "PrivateKey = short");
        assert_eq!(
            parse(&bad),
            Err(ConfigIssue::InvalidField {
                protocol: WG,
                field: "PrivateKey"
            })
        );
        assert_eq!(
            parse(&format!(
                "[Interface]\nPrivateKey = {K}\nAddress = 10.0.0.2/32\n"
            )),
            Err(ConfigIssue::MissingField {
                protocol: WG,
                field: "Peer"
            })
        );
        let badport = conf("").replace(":51820", ":99999");
        assert_eq!(
            parse(&badport),
            Err(ConfigIssue::InvalidField {
                protocol: WG,
                field: "Endpoint"
            })
        );
    }

    #[test]
    fn ipv6_endpoint() {
        assert_eq!(
            split_endpoint("[2001:db8::1]:51820"),
            Some(("2001:db8::1".into(), 51820))
        );
    }
}
