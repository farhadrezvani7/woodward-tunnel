//! Share-link parsing: vless://, vmess://, trojan://, ss://, hysteria2:// (hy2://).

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use core_model::{ConfigIssue, Profile, Protocol, Secret};
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;
use url::Url;

/// AEAD / 2022 methods only. Legacy stream ciphers are rejected as insecure.
const SS_METHODS: &[&str] = &[
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];
/// Query keys copied into `settings`. Anything else is ignored rather than passed to an engine.
const KEEP: &[&str] = &[
    "congestion_control",
    "udp_relay_mode",
    "up",
    "down",
    "upmbps",
    "downmbps",
    "peer",
    "reserved",
    "address",
    "mtu",
    "publickey",
    "keepalive",
    "type",
    "security",
    "sni",
    "flow",
    "fp",
    "pbk",
    "sid",
    "path",
    "host",
    "serviceName",
    "alpn",
    "encryption",
    "headerType",
    "mode",
    "obfs",
    "obfs-password",
    "pinSHA256",
    "insecure",
    "allowInsecure",
];

pub fn parse(scheme: &str, text: &str) -> Result<Profile, ConfigIssue> {
    match scheme {
        "vless" => generic(text, Protocol::Vless, "VLESS", true),
        "trojan" => generic(text, Protocol::Trojan, "Trojan", false),
        "hysteria2" | "hy2" => generic(text, Protocol::Hysteria2, "Hysteria2", false),
        "vmess" => vmess(text),
        "tuic" => tuic(text),
        "hysteria" => hysteria1(text),
        "anytls" => generic(text, Protocol::AnyTls, "AnyTLS", false),
        "socks" | "socks5" | "socks5h" => socks(text),
        "http-proxy" | "https-proxy" => http_proxy(text),
        "ssh" => ssh(text),
        "wireguard" | "wg" => wireguard_uri(text),
        "ss" => shadowsocks(text),
        _ => Err(ConfigIssue::Unrecognized),
    }
}

fn clean_name(raw: &str, fallback: &str) -> String {
    let decoded = percent_decode_str(raw).decode_utf8_lossy();
    let n: String = decoded
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    let n = n.trim();
    if n.is_empty() {
        fallback.to_string()
    } else {
        n.to_string()
    }
}

fn host_of(url: &Url, p: &'static str) -> Result<String, ConfigIssue> {
    let h = url.host_str().ok_or(ConfigIssue::MissingField {
        protocol: p,
        field: "server",
    })?;
    Ok(h.trim_start_matches('[').trim_end_matches(']').to_string())
}

fn port_of(url: &Url, p: &'static str) -> Result<u16, ConfigIssue> {
    match url.port() {
        Some(0) => Err(ConfigIssue::InvalidField {
            protocol: p,
            field: "port",
        }),
        Some(v) => Ok(v),
        None => Err(ConfigIssue::MissingField {
            protocol: p,
            field: "port",
        }),
    }
}

fn is_uuid(s: &str) -> bool {
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

fn keep_params(url: &Url) -> BTreeMap<String, String> {
    url.query_pairs()
        .filter(|(k, _)| KEEP.contains(&k.as_ref()))
        .map(|(k, v)| (k.into_owned(), v.chars().take(512).collect()))
        .collect()
}

/// vless / trojan / hysteria2 share the shape `scheme://credential@host:port?params#name`.
fn generic(
    text: &str,
    protocol: Protocol,
    p: &'static str,
    credential_is_uuid: bool,
) -> Result<Profile, ConfigIssue> {
    let url = Url::parse(text).map_err(|_| ConfigIssue::InvalidField {
        protocol: p,
        field: "link",
    })?;
    let host = host_of(&url, p)?;
    let port = port_of(&url, p)?;
    // hysteria2 allows `user:pass@`; the whole userinfo is then the auth string.
    let mut cred = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();
    if let Some(pw) = url.password() {
        cred = format!("{cred}:{}", percent_decode_str(pw).decode_utf8_lossy());
    }
    if cred.is_empty() {
        return Err(ConfigIssue::MissingField {
            protocol: p,
            field: if credential_is_uuid {
                "UUID"
            } else {
                "password"
            },
        });
    }
    if credential_is_uuid && !is_uuid(&cred) {
        return Err(ConfigIssue::InvalidField {
            protocol: p,
            field: "UUID",
        });
    }
    let params = keep_params(&url);
    if params.get("security").map(String::as_str) == Some("reality") {
        let ok = params
            .get("pbk")
            .and_then(|k| URL_SAFE_NO_PAD.decode(k).ok())
            .is_some_and(|b| b.len() == 32);
        if !ok {
            return Err(ConfigIssue::InvalidField {
                protocol: p,
                field: "Reality public key",
            });
        }
    }
    let key = if credential_is_uuid {
        "uuid"
    } else {
        "password"
    };
    let mut secrets = BTreeMap::new();
    secrets.insert(key.to_string(), Secret::new(cred));
    let name = clean_name(url.fragment().unwrap_or(""), &host);
    Ok(Profile {
        name,
        protocol,
        host,
        port,
        settings: params,
        secrets,
    })
}

fn b64_any(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(s).ok())
}

fn vmess(text: &str) -> Result<Profile, ConfigIssue> {
    const P: &str = "VMess";
    let payload = text.strip_prefix("vmess://").unwrap_or("");
    let bytes = b64_any(payload).ok_or(ConfigIssue::InvalidField {
        protocol: P,
        field: "link",
    })?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| ConfigIssue::InvalidField {
            protocol: P,
            field: "link",
        })?;
    // Providers emit numbers as strings or ints inconsistently.
    let get = |k: &str| match v.get(k) {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };
    let host = get("add")
        .filter(|h| !h.is_empty())
        .ok_or(ConfigIssue::MissingField {
            protocol: P,
            field: "server",
        })?;
    let port: u16 = get("port")
        .ok_or(ConfigIssue::MissingField {
            protocol: P,
            field: "port",
        })?
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or(ConfigIssue::InvalidField {
            protocol: P,
            field: "port",
        })?;
    let id = get("id").ok_or(ConfigIssue::MissingField {
        protocol: P,
        field: "UUID",
    })?;
    if !is_uuid(&id) {
        return Err(ConfigIssue::InvalidField {
            protocol: P,
            field: "UUID",
        });
    }
    let mut settings = BTreeMap::new();
    for (src, dst) in [
        ("net", "type"),
        ("tls", "security"),
        ("sni", "sni"),
        ("path", "path"),
        ("host", "host"),
        ("aid", "alter_id"),
        ("scy", "cipher"),
        ("alpn", "alpn"),
    ] {
        if let Some(x) = get(src).filter(|x| !x.is_empty()) {
            settings.insert(dst.to_string(), x.chars().take(512).collect());
        }
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("uuid".into(), Secret::new(id));
    let name = clean_name(&get("ps").unwrap_or_default(), &host);
    Ok(Profile {
        name,
        protocol: Protocol::Vmess,
        host,
        port,
        settings,
        secrets,
    })
}

fn shadowsocks(text: &str) -> Result<Profile, ConfigIssue> {
    const P: &str = "Shadowsocks";
    let rest = text.strip_prefix("ss://").unwrap_or("");
    let (body, frag) = rest.split_once('#').unwrap_or((rest, ""));
    let body = body.split('?').next().unwrap_or("");
    let bad = ConfigIssue::InvalidField {
        protocol: P,
        field: "link",
    };

    // SIP002 `userinfo@host:port` where userinfo is base64 or percent-encoded `method:password`;
    // legacy form is base64(`method:password@host:port`).
    let (userinfo, hostport) = match body.rsplit_once('@') {
        Some((u, h)) => {
            let u = match b64_any(u)
                .and_then(|b| String::from_utf8(b).ok())
                .filter(|s| s.contains(':'))
            {
                Some(s) => s,
                None => percent_decode_str(u).decode_utf8_lossy().into_owned(),
            };
            (u, h.to_string())
        }
        None => {
            let s = b64_any(body)
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or(bad.clone())?;
            let (u, h) = s.rsplit_once('@').ok_or(bad.clone())?;
            (u.to_string(), h.to_string())
        }
    };
    let (method, password) = userinfo.split_once(':').ok_or(bad.clone())?;
    if !SS_METHODS.contains(&method) {
        return Err(ConfigIssue::InvalidField {
            protocol: P,
            field: "cipher",
        });
    }
    if password.is_empty() {
        return Err(ConfigIssue::MissingField {
            protocol: P,
            field: "password",
        });
    }
    let (host, port) = hostport.rsplit_once(':').ok_or(ConfigIssue::MissingField {
        protocol: P,
        field: "port",
    })?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    if host.is_empty() {
        return Err(ConfigIssue::MissingField {
            protocol: P,
            field: "server",
        });
    }
    let port: u16 = port
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or(ConfigIssue::InvalidField {
            protocol: P,
            field: "port",
        })?;
    let mut settings = BTreeMap::new();
    settings.insert("cipher".into(), method.to_string());
    let mut secrets = BTreeMap::new();
    secrets.insert("password".into(), Secret::new(password));
    Ok(Profile {
        name: clean_name(frag, &host),
        protocol: Protocol::Shadowsocks,
        host,
        port,
        settings,
        secrets,
    })
}

fn userinfo_pair(url: &Url) -> (String, Option<String>) {
    let u = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();
    let pw = url
        .password()
        .map(|p| percent_decode_str(p).decode_utf8_lossy().into_owned());
    (u, pw)
}

fn tuic(text: &str) -> Result<Profile, ConfigIssue> {
    const P: &str = "TUIC";
    let url = Url::parse(text).map_err(|_| ConfigIssue::InvalidField {
        protocol: P,
        field: "link",
    })?;
    let (uuid, pw) = userinfo_pair(&url);
    if !is_uuid(&uuid) {
        return Err(ConfigIssue::InvalidField {
            protocol: P,
            field: "UUID",
        });
    }
    let pw = pw
        .filter(|p| !p.is_empty())
        .ok_or(ConfigIssue::MissingField {
            protocol: P,
            field: "password",
        })?;
    let host = host_of(&url, P)?;
    let port = port_of(&url, P)?;
    let mut secrets = BTreeMap::new();
    secrets.insert("uuid".into(), Secret::new(uuid));
    secrets.insert("password".into(), Secret::new(pw));
    let name = clean_name(url.fragment().unwrap_or(""), &host);
    Ok(Profile {
        name,
        protocol: Protocol::Tuic,
        host,
        port,
        settings: keep_params(&url),
        secrets,
    })
}

/// Hysteria v1: `hysteria://host:port?auth=...&peer=sni&insecure=1&upmbps=..&downmbps=..`
fn hysteria1(text: &str) -> Result<Profile, ConfigIssue> {
    const P: &str = "Hysteria";
    let url = Url::parse(text).map_err(|_| ConfigIssue::InvalidField {
        protocol: P,
        field: "link",
    })?;
    let host = host_of(&url, P)?;
    let port = port_of(&url, P)?;
    let auth = url
        .query_pairs()
        .find(|(k, _)| k == "auth")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    let mut settings = keep_params(&url);
    if let Some(peer) = settings.remove("peer") {
        settings.entry("sni".into()).or_insert(peer);
    }
    let mut secrets = BTreeMap::new();
    if !auth.is_empty() {
        secrets.insert("password".into(), Secret::new(auth));
    }
    let name = clean_name(url.fragment().unwrap_or(""), &host);
    Ok(Profile {
        name,
        protocol: Protocol::Hysteria1,
        host,
        port,
        settings,
        secrets,
    })
}

/// `socks5://user:pass@host:port` or v2rayN style `socks://base64(user:pass)@host:port`.
fn socks(text: &str) -> Result<Profile, ConfigIssue> {
    const P: &str = "SOCKS5";
    let url = Url::parse(text).map_err(|_| ConfigIssue::InvalidField {
        protocol: P,
        field: "link",
    })?;
    let host = host_of(&url, P)?;
    let port = port_of(&url, P)?;
    let (mut user, mut pw) = userinfo_pair(&url);
    if pw.is_none() && !user.is_empty() {
        if let Some(d) = b64_any(&user).and_then(|b| String::from_utf8(b).ok()) {
            if let Some((u, p)) = d.split_once(':') {
                user = u.to_string();
                pw = Some(p.to_string());
            }
        }
    }
    let mut settings = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    if !user.is_empty() {
        settings.insert("username".into(), user);
        secrets.insert("password".into(), Secret::new(pw.unwrap_or_default()));
    }
    Ok(Profile {
        name: clean_name(url.fragment().unwrap_or(""), &host),
        protocol: Protocol::Socks,
        host,
        port,
        settings,
        secrets,
    })
}

fn http_proxy(text: &str) -> Result<Profile, ConfigIssue> {
    const P: &str = "HTTP Proxy";
    let tls = text.starts_with("https-proxy");
    let fixed =
        text.replacen("https-proxy://", "https://", 1)
            .replacen("http-proxy://", "http://", 1);
    let url = Url::parse(&fixed).map_err(|_| ConfigIssue::InvalidField {
        protocol: P,
        field: "link",
    })?;
    let host = host_of(&url, P)?;
    let port = url
        .port_or_known_default()
        .ok_or(ConfigIssue::MissingField {
            protocol: P,
            field: "port",
        })?;
    let (user, pw) = userinfo_pair(&url);
    let mut settings = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    if tls {
        settings.insert("security".into(), "tls".into());
    }
    if !user.is_empty() {
        settings.insert("username".into(), user);
        secrets.insert("password".into(), Secret::new(pw.unwrap_or_default()));
    }
    Ok(Profile {
        name: clean_name(url.fragment().unwrap_or(""), &host),
        protocol: Protocol::HttpProxy,
        host,
        port,
        settings,
        secrets,
    })
}

fn ssh(text: &str) -> Result<Profile, ConfigIssue> {
    const P: &str = "SSH";
    let url = Url::parse(text).map_err(|_| ConfigIssue::InvalidField {
        protocol: P,
        field: "link",
    })?;
    let host = host_of(&url, P)?;
    let port = url.port().unwrap_or(22);
    let (user, pw) = userinfo_pair(&url);
    if user.is_empty() {
        return Err(ConfigIssue::MissingField {
            protocol: P,
            field: "user",
        });
    }
    let pw = pw.ok_or(ConfigIssue::MissingField {
        protocol: P,
        field: "password",
    })?;
    let mut settings = BTreeMap::new();
    settings.insert("username".into(), user);
    let mut secrets = BTreeMap::new();
    secrets.insert("password".into(), Secret::new(pw));
    Ok(Profile {
        name: clean_name(url.fragment().unwrap_or(""), &host),
        protocol: Protocol::Ssh,
        host,
        port,
        settings,
        secrets,
    })
}

/// `wireguard://<private key>@host:port?publickey=..&address=..&reserved=1,2,3&mtu=..#name`
fn wireguard_uri(text: &str) -> Result<Profile, ConfigIssue> {
    const P: &str = "WireGuard";
    let url = Url::parse(text).map_err(|_| ConfigIssue::InvalidField {
        protocol: P,
        field: "link",
    })?;
    let host = host_of(&url, P)?;
    let port = port_of(&url, P)?;
    let key32 = |v: &str| STANDARD.decode(v).map(|b| b.len() == 32).unwrap_or(false);
    let private = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .into_owned();
    if private.is_empty() {
        return Err(ConfigIssue::MissingField {
            protocol: P,
            field: "PrivateKey",
        });
    }
    if !key32(&private) {
        return Err(ConfigIssue::InvalidField {
            protocol: P,
            field: "PrivateKey",
        });
    }
    let q = keep_params(&url);
    let public = q.get("publickey").ok_or(ConfigIssue::MissingField {
        protocol: P,
        field: "PublicKey",
    })?;
    if !key32(public) {
        return Err(ConfigIssue::InvalidField {
            protocol: P,
            field: "PublicKey",
        });
    }
    let address = q.get("address").ok_or(ConfigIssue::MissingField {
        protocol: P,
        field: "Address",
    })?;
    let mut settings = BTreeMap::new();
    settings.insert("address".into(), address.clone());
    settings.insert("allowed_ips".into(), "0.0.0.0/0, ::/0".into());
    settings.insert("peer_public_key".into(), public.clone());
    for k in ["mtu", "reserved", "keepalive"] {
        if let Some(v) = q.get(k) {
            settings.insert(
                if k == "keepalive" {
                    "persistent_keepalive".into()
                } else {
                    k.into()
                },
                v.clone(),
            );
        }
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("private_key".into(), Secret::new(private));
    Ok(Profile {
        name: clean_name(url.fragment().unwrap_or(""), &host),
        protocol: Protocol::WireGuard,
        host,
        port,
        settings,
        secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn p(text: &str) -> Result<Profile, ConfigIssue> {
        let scheme = text
            .split_once("://")
            .map(|(s, _)| s.to_ascii_lowercase())
            .unwrap_or_default();
        parse(&scheme, text)
    }

    #[test]
    fn vless_reality() {
        let x = p(&format!("vless://{UUID}@example.com:443?type=tcp&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=1&sni=a.com&flow=xtls-rprx-vision&evil=1#My%20Node")).unwrap();
        assert_eq!(x.protocol, Protocol::Vless);
        assert_eq!(x.name, "My Node");
        assert_eq!(
            x.settings.get("security").map(String::as_str),
            Some("reality")
        );
        assert!(!x.settings.contains_key("evil"));
        assert_eq!(x.secrets["uuid"].expose(), UUID);
    }

    #[test]
    fn reality_requires_valid_public_key() {
        let bad = format!("vless://{UUID}@example.com:443?security=reality&pbk=abc&sid=1");
        assert!(matches!(
            p(&bad),
            Err(ConfigIssue::InvalidField {
                field: "Reality public key",
                ..
            })
        ));
    }

    #[test]
    fn vless_rejects_bad_uuid_and_port() {
        assert_eq!(
            p("vless://nope@example.com:443"),
            Err(ConfigIssue::InvalidField {
                protocol: "VLESS",
                field: "UUID"
            })
        );
        assert_eq!(
            p(&format!("vless://{UUID}@example.com")),
            Err(ConfigIssue::MissingField {
                protocol: "VLESS",
                field: "port"
            })
        );
        assert!(p(&format!("vless://{UUID}@example.com:0")).is_err());
    }

    #[test]
    fn vmess_json_with_string_and_int_ports() {
        for port in [r#""443""#, "443"] {
            let json = format!(
                r#"{{"v":"2","ps":"n1","add":"h.example.com","port":{port},"id":"{UUID}","aid":"0","net":"ws","tls":"tls","path":"/p"}}"#
            );
            let link = format!("vmess://{}", STANDARD.encode(json));
            let x = p(&link).unwrap();
            assert_eq!(
                (x.host.as_str(), x.port, x.name.as_str()),
                ("h.example.com", 443, "n1")
            );
            assert_eq!(x.settings.get("type").map(String::as_str), Some("ws"));
        }
        assert!(p("vmess://!!!notbase64").is_err());
    }

    #[test]
    fn trojan_and_hysteria2() {
        let t = p("trojan://s3cret@t.example.com:443?sni=t.example.com#T").unwrap();
        assert_eq!(t.secrets["password"].expose(), "s3cret");
        for scheme in ["hysteria2", "hy2"] {
            let h = p(&format!(
                "{scheme}://auth@h.example.com:8443?sni=h.example.com&insecure=0#H"
            ))
            .unwrap();
            assert_eq!(h.protocol, Protocol::Hysteria2);
        }
        assert!(p("trojan://@t.example.com:443").is_err());
    }

    #[test]
    fn shadowsocks_sip002_and_legacy() {
        let ui = STANDARD.encode("chacha20-ietf-poly1305:pw");
        let a = p(&format!("ss://{ui}@s.example.com:8388#S")).unwrap();
        assert_eq!((a.host.as_str(), a.port), ("s.example.com", 8388));
        assert_eq!(a.secrets["password"].expose(), "pw");
        let legacy = STANDARD.encode("aes-256-gcm:pw2@l.example.com:1234");
        let b = p(&format!("ss://{legacy}#L")).unwrap();
        assert_eq!(b.host, "l.example.com");
        let c = p("ss://aes-128-gcm:plain@c.example.com:1#C").unwrap();
        assert_eq!(c.secrets["password"].expose(), "plain");
    }

    #[test]
    fn shadowsocks_rejects_legacy_cipher() {
        let ui = STANDARD.encode("rc4-md5:pw");
        assert_eq!(
            p(&format!("ss://{ui}@s.example.com:1")),
            Err(ConfigIssue::InvalidField {
                protocol: "Shadowsocks",
                field: "cipher"
            })
        );
    }

    #[test]
    fn names_are_sanitized() {
        let long = "x".repeat(300);
        let x = p(&format!("trojan://pw@a.example.com:1#%0A{long}")).unwrap();
        assert_eq!(x.name.chars().count(), 100);
        assert!(!x.name.contains('\n'));
    }

    #[test]
    fn extra_protocols_parse() {
        let t = p(&format!("tuic://{UUID}:pw1234@t.example.com:443?congestion_control=bbr&udp_relay_mode=native&sni=t.example.com#T")).unwrap();
        assert_eq!(t.protocol, Protocol::Tuic);
        assert_eq!(t.secrets["password"].expose(), "pw1234");
        let h = p("hysteria://h.example.com:443?auth=secret1&peer=sni.example.com&insecure=0&upmbps=50&downmbps=100#H").unwrap();
        assert_eq!(
            h.settings.get("sni").map(String::as_str),
            Some("sni.example.com")
        );
        let s = p("socks5://u:p@s.example.com:1080#S").unwrap();
        assert_eq!((s.protocol, s.port), (Protocol::Socks, 1080));
        let enc = STANDARD.encode("user:pass");
        assert_eq!(
            p(&format!("socks://{enc}@s.example.com:1080"))
                .unwrap()
                .secrets["password"]
                .expose(),
            "pass"
        );
        assert_eq!(p("ssh://root:pw@h.example.com#x").unwrap().port, 22);
        assert_eq!(
            p("anytls://pw1234@a.example.com:443?sni=a.example.com")
                .unwrap()
                .protocol,
            Protocol::AnyTls
        );
        assert!(p("http-proxy://u:p@h.example.com:8080").is_ok());
    }

    #[test]
    fn wireguard_uri_parses_and_validates() {
        let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let ok = p(&format!("wireguard://{}@w.example.com:51820?publickey={}&address=10.0.0.2/32&reserved=1,2,3&mtu=1280#W", k.replace('=', "%3D"), k.replace('=', "%3D"))).unwrap();
        assert_eq!(
            ok.settings.get("reserved").map(String::as_str),
            Some("1,2,3")
        );
        assert!(p("wireguard://short@w.example.com:1?publickey=x&address=1.1.1.1/32").is_err());
    }
}
