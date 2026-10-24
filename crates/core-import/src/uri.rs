//! Share-link parsing: vless, vmess, trojan, ss, hysteria2, hysteria, tuic, anytls, socks, http,
//! ssh and wireguard links. Every parameter is mapped onto the settings schema documented in
//! `validate.rs` or rejected with a specific issue; parameters that change security or
//! reachability are never silently dropped.

use crate::validate as v;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use core_model::{ConfigIssue, Profile, Protocol, Secret};
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;

/// AEAD and 2022 methods only. Legacy stream ciphers and `none` are rejected as insecure.
const SS_METHODS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

type Settings = BTreeMap<String, String>;
type R<T> = Result<T, ConfigIssue>;

fn bad(protocol: &'static str, field: &'static str) -> ConfigIssue {
    ConfigIssue::InvalidField { protocol, field }
}
fn miss(protocol: &'static str, field: &'static str) -> ConfigIssue {
    ConfigIssue::MissingField { protocol, field }
}
fn unsup(what: &'static str) -> ConfigIssue {
    ConfigIssue::Unsupported(what)
}

// ---------------------------------------------------------------- link splitting

/// Decoded query string. Keys are matched case-insensitively, the first occurrence wins
/// (as in Xray), and `+` stays a literal plus because base64 values contain it.
#[derive(Default)]
pub(crate) struct Query(Vec<(String, String)>);

impl Query {
    fn parse(q: &str) -> R<Query> {
        let mut out: Vec<(String, String)> = Vec::new();
        for part in q.split('&').filter(|p| !p.is_empty()) {
            let (k, val) = part.split_once('=').unwrap_or((part, ""));
            if out.len() >= 64 {
                return Err(bad("link", "query"));
            }
            let dec = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
            let (k, val) = (dec(k), dec(val));
            if val.chars().count() > 2048 {
                return Err(bad("link", "query"));
            }
            if !out.iter().any(|(ek, _)| ek.eq_ignore_ascii_case(&k)) {
                out.push((k, val));
            }
        }
        Ok(Query(out))
    }
    pub(crate) fn from_pairs(pairs: Vec<(&str, String)>) -> Query {
        Query(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    /// Non-empty value.
    fn get(&self, k: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(ek, _)| ek.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
    }
    fn any(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|k| self.get(k))
    }
    fn flag(&self, keys: &[&str], p: &'static str, field: &'static str) -> R<bool> {
        match self.any(keys) {
            None => Ok(false),
            Some(x) => v::truthy(x).ok_or(bad(p, field)),
        }
    }
}

struct Link {
    userinfo: Option<String>,
    host: String,
    /// Raw text after the host's colon (`443`, `443,5000-6000`).
    port_spec: Option<String>,
    query: Query,
    fragment: String,
}

fn after_scheme(text: &str) -> &str {
    text.split_once("://").map(|(_, r)| r).unwrap_or("")
}

fn split_link(text: &str, p: &'static str) -> R<Link> {
    let rest = after_scheme(text);
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let authority = match rest.find('/') {
        Some(i) => &rest[..i],
        None => rest,
    };
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (Some(authority[..i].to_string()), &authority[i + 1..]),
        None => (None, authority),
    };
    let (host_raw, port_spec) = if let Some(r) = hostport.strip_prefix('[') {
        let end = r.find(']').ok_or(bad(p, "server"))?;
        let port = match &r[end + 1..] {
            "" => None,
            a => Some(a.strip_prefix(':').ok_or(bad(p, "server"))?.to_string()),
        };
        (&r[..end], port)
    } else if hostport.matches(':').count() > 1 {
        (hostport, None)
    } else {
        match hostport.split_once(':') {
            Some((h, po)) => (h, Some(po.to_string())),
            None => (hostport, None),
        }
    };
    if host_raw.is_empty() {
        return Err(miss(p, "server"));
    }
    let host = v::host(host_raw).ok_or(bad(p, "server"))?;
    Ok(Link {
        userinfo,
        host,
        port_spec: port_spec.filter(|s| !s.is_empty()),
        query: Query::parse(query)?,
        fragment: percent_decode_str(fragment)
            .decode_utf8_lossy()
            .into_owned(),
    })
}

impl Link {
    fn port(&self, p: &'static str) -> R<u16> {
        let s = self.port_spec.as_deref().ok_or(miss(p, "port"))?;
        v::port(s).ok_or(bad(p, "port"))
    }
    fn name(&self) -> String {
        v::sanitize_name(&self.fragment, &self.host)
    }
    fn user_dec(&self) -> Option<String> {
        self.userinfo
            .as_ref()
            .map(|u| percent_decode_str(u).decode_utf8_lossy().into_owned())
    }
    /// `user:pass` split at the first colon.
    fn user_pass(&self) -> (String, Option<String>) {
        let raw = self.userinfo.clone().unwrap_or_default();
        let dec = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
        match raw.split_once(':') {
            Some((u, pw)) => (dec(u), Some(dec(pw))),
            None => (dec(&raw), None),
        }
    }
}

fn finish(
    link: &Link,
    protocol: Protocol,
    port: u16,
    settings: Settings,
    secrets: BTreeMap<String, Secret>,
) -> Profile {
    Profile {
        name: link.name(),
        protocol,
        host: link.host.clone(),
        port,
        settings,
        secrets,
    }
}

fn put(s: &mut Settings, k: &str, val: impl Into<String>) {
    s.insert(k.to_string(), val.into());
}

// ---------------------------------------------------------------- TLS + transport

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Vless,
    Vmess,
    Trojan,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Kind::Vless => "VLESS",
            Kind::Vmess => "VMess",
            Kind::Trojan => "Trojan",
        }
    }
}

/// Parameters that make the client verify the server in a way sing-box cannot reproduce.
/// Ignoring them would connect with weaker verification than the link asked for.
fn reject_unhonorable(q: &Query) -> R<()> {
    if q.any(&["pcs", "pinSHA256", "pinnedPeerCertSha256"])
        .is_some()
    {
        return Err(unsup(
            "certificate pinning (pinSHA256/pcs); the engine can only pin public keys",
        ));
    }
    if q.any(&["vcn", "verifyPeerCertByName"]).is_some() {
        return Err(unsup("verifyPeerCertByName (vcn)"));
    }
    if q.get("pqv").is_some() {
        return Err(unsup("Reality post-quantum verification (pqv)"));
    }
    if q.get("fm").is_some() {
        return Err(unsup("Xray finalmask (fm)"));
    }
    Ok(())
}

fn ech_value(raw: &str) -> Option<String> {
    let s = raw.trim();
    let bytes = [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(s).ok())?;
    // ECHConfigList starts with a 2-byte length that must match the rest.
    let ok = bytes.len() >= 8
        && bytes.len() <= 4096
        && u16::from_be_bytes([bytes[0], bytes[1]]) as usize == bytes.len() - 2;
    ok.then(|| STANDARD.encode(bytes))
}

/// TLS settings shared by every TLS-capable link type.
fn tls_params(q: &Query, p: &'static str, security: &str, out: &mut Settings) -> R<()> {
    if !matches!(security, "tls" | "reality") {
        return Ok(());
    }
    put(out, "security", security);
    let sni = q.any(&["sni", "peer", "serverName"]);
    if let Some(s) = sni {
        put(out, "sni", v::host(s).ok_or(bad(p, "SNI"))?);
    }
    if let Some(a) = q.get("alpn") {
        put(out, "alpn", v::alpn_list(a).ok_or(bad(p, "ALPN"))?);
    }
    if let Some(f) = q.get("fp") {
        if !f.eq_ignore_ascii_case("none") {
            put(
                out,
                "fp",
                v::utls_fingerprint(f).ok_or(bad(p, "fingerprint"))?,
            );
        }
    }
    if q.flag(
        &["insecure", "allowInsecure", "allow_insecure"],
        p,
        "insecure",
    )? {
        put(out, "insecure", "1");
    }
    if q.flag(&["disable_sni"], p, "disable_sni")? {
        put(out, "disable_sni", "1");
    }
    if let Some(e) = q.get("ech") {
        put(
            out,
            "ech",
            ech_value(e).ok_or(unsup(
                "ECH given as a DNS query string (use a base64 ECHConfigList)",
            ))?,
        );
    }
    if q.get("fragment").is_some() {
        // Value syntax differs per client; any value enables record fragmentation (approximation).
        put(out, "tls_fragment", "record");
    }
    if security == "reality" {
        let pbk = q.get("pbk").ok_or(miss(p, "Reality public key"))?;
        put(
            out,
            "pbk",
            v::reality_key(pbk).ok_or(bad(p, "Reality public key"))?,
        );
        put(
            out,
            "sid",
            v::short_id(q.get("sid").unwrap_or("")).ok_or(bad(p, "Reality short id"))?,
        );
        if sni.is_none() {
            // Reality needs the front-site name; the proxy address is almost never the right one.
            return Err(miss(p, "Reality server name (sni)"));
        }
    }
    Ok(())
}

/// Transport selection and its parameters. `q` follows the Xray share-link vocabulary
/// (`type`, `host`, `path`, `serviceName`, `mode`, `authority`, `headerType`, `seed`).
fn transport_params(
    q: &Query,
    p: &'static str,
    security: &str,
    sni: Option<&str>,
    out: &mut Settings,
) -> R<()> {
    let ty = q.get("type").unwrap_or("tcp").to_ascii_lowercase();
    let header = q.get("headerType").unwrap_or("none").to_ascii_lowercase();
    match ty.as_str() {
        "tcp" | "raw" | "original" => {
            if header != "none" {
                return Err(unsup("TCP HTTP header obfuscation (headerType=http)"));
            }
        }
        "ws" | "websocket" => {
            put(out, "type", "ws");
            let (path, ed) = split_early_data(q.get("path").unwrap_or("/"));
            put(out, "path", v::http_text(&path, 512).ok_or(bad(p, "path"))?);
            if let Some(ed) = ed {
                put(out, "ed", ed.to_string());
                put(out, "edh", "Sec-WebSocket-Protocol");
            }
            if let Some(h) = q.get("host") {
                put(out, "host", v::http_text(h, 253).ok_or(bad(p, "host"))?);
            }
        }
        "httpupgrade" => {
            put(out, "type", "httpupgrade");
            let path = v::http_text(q.get("path").unwrap_or("/"), 512).ok_or(bad(p, "path"))?;
            put(out, "path", path);
            if let Some(h) = q.get("host") {
                put(out, "host", v::http_text(h, 253).ok_or(bad(p, "host"))?);
            }
        }
        "grpc" | "gun" => {
            let mode = q.get("mode").unwrap_or("gun").to_ascii_lowercase();
            if !matches!(mode.as_str(), "gun" | "guna" | "auto") {
                return Err(unsup("gRPC multi mode"));
            }
            if let Some(a) = q.get("authority") {
                let same = [sni, q.get("host")]
                    .into_iter()
                    .flatten()
                    .any(|x| x.eq_ignore_ascii_case(a));
                if !same {
                    return Err(unsup("gRPC authority different from the server name"));
                }
            }
            put(out, "type", "grpc");
            let name = v::http_text(q.get("serviceName").unwrap_or(""), 256)
                .ok_or(bad(p, "serviceName"))?;
            put(out, "serviceName", name);
        }
        "h2" | "http" => {
            if !matches!(security, "tls" | "reality") {
                return Err(bad(p, "HTTP/2 transport without TLS"));
            }
            put(out, "type", "http");
            let path = v::http_text(q.get("path").unwrap_or("/"), 512).ok_or(bad(p, "path"))?;
            put(out, "path", path);
            if let Some(h) = q.get("host") {
                put(out, "host", v::http_text(h, 512).ok_or(bad(p, "host"))?);
            }
        }
        "kcp" | "mkcp" => return Err(unsup("mKCP transport")),
        "quic" => return Err(unsup("QUIC transport")),
        "xhttp" | "splithttp" => return Err(unsup("XHTTP (SplitHTTP) transport")),
        _ => return Err(unsup("unknown transport")),
    }
    Ok(())
}

/// Xray carries WebSocket early data as `?ed=N` on the path.
fn split_early_data(path: &str) -> (String, Option<u32>) {
    if let Some((base, qs)) = path.split_once('?') {
        let mut ed = None;
        let mut rest = Vec::new();
        for part in qs.split('&') {
            match part.strip_prefix("ed=").and_then(|n| n.parse::<u32>().ok()) {
                Some(n) if n > 0 => ed = Some(n),
                _ => rest.push(part),
            }
        }
        if ed.is_some() {
            let mut np = base.to_string();
            if !rest.is_empty() {
                np.push('?');
                np.push_str(&rest.join("&"));
            }
            return (np, ed);
        }
    }
    (path.to_string(), None)
}

fn flow_param(q: &Query, p: &'static str, security: &str, out: &mut Settings) -> R<()> {
    let Some(f) = q.get("flow") else {
        return Ok(());
    };
    // `-udp443` only changes whether UDP/443 is allowed by the server's flow filter.
    if !matches!(f, "xtls-rprx-vision" | "xtls-rprx-vision-udp443") {
        return Err(unsup("VLESS flow other than xtls-rprx-vision"));
    }
    if !matches!(security, "tls" | "reality") || out.contains_key("type") {
        return Err(bad(p, "flow (needs TLS or Reality over plain TCP)"));
    }
    put(out, "flow", "xtls-rprx-vision");
    Ok(())
}

fn packet_encoding(q: &Query, p: &'static str, out: &mut Settings) -> R<()> {
    if let Some(e) = q.any(&["packetEncoding", "pe"]) {
        let m = match e.to_ascii_lowercase().as_str() {
            "xudp" => "xudp",
            "packet" | "packetaddr" => "packetaddr",
            "none" => "none",
            _ => return Err(bad(p, "packetEncoding")),
        };
        put(out, "packet_encoding", m);
    }
    Ok(())
}

/// Shared by VLESS, Trojan and standard-form VMess links.
fn stream_settings(q: &Query, kind: Kind) -> R<Settings> {
    let p = kind.label();
    reject_unhonorable(q)?;
    let security = match q
        .get("security")
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "" if kind == Kind::Trojan => "tls",
        "" | "none" => "none",
        "tls" => "tls",
        "reality" => "reality",
        "xtls" => return Err(unsup("legacy XTLS security")),
        _ => return Err(bad(p, "security")),
    };
    let mut out = Settings::new();
    tls_params(q, p, security, &mut out)?;
    if kind == Kind::Trojan && security == "none" {
        // Trojan is TLS by default; the engine needs to know plain was asked for explicitly.
        put(&mut out, "security", "none");
    }
    let sni = out.get("sni").cloned();
    transport_params(q, p, security, sni.as_deref(), &mut out)?;
    if kind != Kind::Trojan {
        flow_param(q, p, security, &mut out)?;
        packet_encoding(q, p, &mut out)?;
    } else if q
        .get("encryption")
        .is_some_and(|e| !e.eq_ignore_ascii_case("none"))
    {
        return Err(unsup("Trojan-Go Shadowsocks encryption layer"));
    }
    Ok(out)
}

fn vless_like(text: &str, kind: Kind) -> R<Profile> {
    let p = kind.label();
    let link = split_link(text, p)?;
    let port = link.port(p)?;
    let cred = link.user_dec().filter(|c| !c.is_empty()).ok_or(miss(
        p,
        if kind == Kind::Vless {
            "UUID"
        } else {
            "password"
        },
    ))?;
    let mut secrets = BTreeMap::new();
    if kind == Kind::Vless {
        secrets.insert(
            "uuid".into(),
            Secret::new(v::user_id(&cred).ok_or(bad(p, "UUID"))?),
        );
        if let Some(e) = link.query.get("encryption") {
            if !e.eq_ignore_ascii_case("none") {
                return Err(if e.starts_with("mlkem768x25519plus") {
                    unsup("VLESS post-quantum encryption (mlkem768x25519plus)")
                } else {
                    unsup("VLESS encryption other than none")
                });
            }
        }
    } else {
        if cred.chars().count() > 512 || cred.chars().any(char::is_control) {
            return Err(bad(p, "password"));
        }
        secrets.insert("password".into(), Secret::new(cred));
    }
    let settings = stream_settings(&link.query, kind)?;
    let protocol = if kind == Kind::Vless {
        Protocol::Vless
    } else {
        Protocol::Trojan
    };
    Ok(finish(&link, protocol, port, settings, secrets))
}

pub fn parse(scheme: &str, text: &str) -> Result<Profile, ConfigIssue> {
    match scheme {
        "vless" => vless_like(text, Kind::Vless),
        "trojan" => vless_like(text, Kind::Trojan),
        "hysteria2" | "hy2" => hysteria2(text),
        "vmess" => vmess(text),
        "tuic" => tuic(text),
        "hysteria" => hysteria1(text),
        "anytls" => anytls(text),
        "socks" | "socks5" | "socks5h" => socks(text),
        "http-proxy" | "https-proxy" => http_proxy(text),
        "ssh" => ssh(text),
        "wireguard" | "wg" => wireguard_uri(text),
        "ss" => shadowsocks(text),
        _ => Err(ConfigIssue::Unrecognized),
    }
}

// ---------------------------------------------------------------- VMess

const VMESS_CIPHERS: &[&str] = &["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"];

fn vmess_cipher(raw: Option<&str>) -> R<&'static str> {
    let c = raw.unwrap_or("auto").to_ascii_lowercase();
    VMESS_CIPHERS
        .iter()
        .find(|k| **k == c || (c.is_empty() && **k == "auto"))
        .copied()
        .ok_or(bad("VMess", "cipher"))
}

fn vmess(text: &str) -> R<Profile> {
    const P: &str = "VMess";
    let body = after_scheme(text);
    // Standard form `vmess://uuid@host:port?...` (Xray share-link standard).
    if body
        .split(['?', '#'])
        .next()
        .is_some_and(|b| b.contains('@'))
    {
        let link = split_link(text, P)?;
        let port = link.port(P)?;
        let id = link.user_dec().ok_or(miss(P, "UUID"))?;
        let mut settings = stream_settings(&link.query, Kind::Vmess)?;
        put(
            &mut settings,
            "cipher",
            vmess_cipher(link.query.any(&["encryption", "scy"]))?,
        );
        let mut secrets = BTreeMap::new();
        secrets.insert(
            "uuid".into(),
            Secret::new(v::user_id(&id).ok_or(bad(P, "UUID"))?),
        );
        return Ok(finish(&link, Protocol::Vmess, port, settings, secrets));
    }
    // v2rayN form: base64(JSON).
    let payload = body.split('#').next().unwrap_or("");
    let compact: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = b64_any(&compact).ok_or(bad(P, "link"))?;
    let j: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| bad(P, "link"))?;
    let get = |k: &str| {
        match j.get(k) {
            Some(serde_json::Value::String(s)) => Some(s.trim().to_string()),
            Some(serde_json::Value::Number(n)) => Some(n.to_string()),
            _ => None,
        }
        .filter(|s| !s.is_empty())
    };
    let host = v::host(&get("add").ok_or(miss(P, "server"))?).ok_or(bad(P, "server"))?;
    let port = v::port(&get("port").ok_or(miss(P, "port"))?).ok_or(bad(P, "port"))?;
    let id = v::user_id(&get("id").ok_or(miss(P, "UUID"))?).ok_or(bad(P, "UUID"))?;
    let net = get("net")
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    let (ty, h, pa) = (get("type"), get("host"), get("path"));
    // Field meaning depends on the network in the v2rayN format.
    let mut pairs: Vec<(&str, String)> = vec![("type", net.clone())];
    match net.as_str() {
        "grpc" => {
            if let Some(pa) = pa {
                pairs.push(("serviceName", pa));
            }
            if let Some(h) = h {
                pairs.push(("authority", h));
            }
            if let Some(t) = ty {
                pairs.push(("mode", t));
            }
        }
        "kcp" | "mkcp" => {}
        _ => {
            if let Some(t) = ty {
                pairs.push(("headerType", t));
            }
            if let Some(h) = h {
                pairs.push(("host", h));
            }
            if let Some(pa) = pa {
                pairs.push(("path", pa));
            }
        }
    }
    match get("tls").unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "none" => {}
        "tls" => pairs.push(("security", "tls".into())),
        _ => return Err(unsup("VMess with Reality or XTLS")),
    }
    for k in ["sni", "alpn", "fp", "insecure", "vcn", "pcs", "fm"] {
        if let Some(x) = get(k) {
            pairs.push((k, x));
        }
    }
    let q = Query::from_pairs(pairs);
    let mut settings = stream_settings(&q, Kind::Vmess)?;
    put(
        &mut settings,
        "cipher",
        vmess_cipher(get("scy").as_deref())?,
    );
    if let Some(aid) = get("aid") {
        let n: u16 = aid.parse().map_err(|_| bad(P, "alterId"))?;
        if n > 0 {
            put(&mut settings, "alter_id", n.to_string());
        }
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("uuid".into(), Secret::new(id));
    Ok(Profile {
        name: v::sanitize_name(&get("ps").unwrap_or_default(), &host),
        protocol: Protocol::Vmess,
        host,
        port,
        settings,
        secrets,
    })
}

pub(crate) fn b64_any(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(s).ok())
}

// ---------------------------------------------------------------- Shadowsocks

/// SIP003 option string: `name;k=v;k2;...` with backslash escapes.
fn plugin_parts(s: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut esc = false;
    for c in s.chars() {
        if esc {
            if let Some(last) = parts.last_mut() {
                last.push(c);
            }
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == ';' {
            parts.push(String::new());
        } else if let Some(last) = parts.last_mut() {
            last.push(c);
        }
    }
    parts
}

fn push_opt(o: &mut String, k: &str, val: &str) -> R<()> {
    if !v::plain_text(val, 253) {
        return Err(bad("Shadowsocks", "plugin options"));
    }
    o.push(';');
    o.push_str(k);
    o.push('=');
    for c in val.chars() {
        if matches!(c, '\\' | ';' | '=') {
            o.push('\\');
        }
        o.push(c);
    }
    Ok(())
}

fn ss_plugin(raw: &str, settings: &mut Settings) -> R<()> {
    let parts = plugin_parts(raw);
    let name = parts.first().map(String::as_str).unwrap_or("");
    let opts = &parts[1..];
    let kv = |k: &str| opts.iter().find_map(|o| o.strip_prefix(&format!("{k}=")));
    match name {
        "obfs-local" | "simple-obfs" => {
            let mode = kv("obfs").ok_or(bad("Shadowsocks", "plugin options"))?;
            if !matches!(mode, "http" | "tls") {
                return Err(bad("Shadowsocks", "plugin options"));
            }
            let mut o = format!("obfs={mode}");
            if let Some(h) = kv("obfs-host") {
                push_opt(&mut o, "obfs-host", h)?;
            }
            put(settings, "plugin", "obfs-local");
            put(settings, "plugin_opts", o);
        }
        "v2ray-plugin" => {
            if kv("mode").is_some_and(|m| m != "websocket") {
                return Err(unsup("v2ray-plugin mode other than websocket"));
            }
            if kv("mux").is_some_and(|m| m != "0") {
                return Err(unsup("v2ray-plugin mux"));
            }
            if opts
                .iter()
                .any(|x| x.starts_with("certRaw=") || x.starts_with("cert="))
            {
                return Err(unsup("v2ray-plugin with a pinned certificate"));
            }
            let mut o = String::from("mode=websocket");
            if opts.iter().any(|x| x == "tls") {
                o.push_str(";tls");
            }
            for k in ["host", "path"] {
                if let Some(x) = kv(k) {
                    push_opt(&mut o, k, x)?;
                }
            }
            put(settings, "plugin", "v2ray-plugin");
            put(settings, "plugin_opts", o);
        }
        _ => return Err(unsup("Shadowsocks plugin")),
    }
    Ok(())
}

/// Validate a Shadowsocks password for the method (2022 methods need exact-length base64 keys).
pub(crate) fn ss_password_ok(method: &str, password: &str) -> bool {
    if password.is_empty() || password.chars().any(char::is_control) {
        return false;
    }
    let len = match method {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => return password.chars().count() <= 512,
    };
    // Multi-user form: iPSK:uPSK
    password
        .split(':')
        .all(|k| STANDARD.decode(k).map(|b| b.len() == len).unwrap_or(false))
}

pub(crate) fn ss_method_ok(method: &str) -> bool {
    SS_METHODS.contains(&method)
}

fn shadowsocks(text: &str) -> R<Profile> {
    const P: &str = "Shadowsocks";
    let rest = after_scheme(text);
    let (rest, frag) = rest.split_once('#').unwrap_or((rest, ""));
    let (body, query) = rest.split_once('?').unwrap_or((rest, ""));
    let body = body.trim_end_matches('/');
    let q = Query::parse(query)?;
    if q.get("prefix").is_some() {
        return Err(unsup("Outline connection prefix"));
    }
    let dec = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
    // SIP002: `userinfo@host:port`. Legacy: base64(`method:password@host:port`).
    let (userinfo, hostport) = match body.rfind('@') {
        Some(i) => {
            let u = &body[..i];
            let plain = dec(u);
            let info = if plain.contains(':') {
                plain
            } else {
                b64_any(u)
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or(bad(P, "link"))?
            };
            (info, body[i + 1..].to_string())
        }
        None => {
            let s = b64_any(&dec(body))
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or(bad(P, "link"))?;
            let (u, h) = s.rsplit_once('@').ok_or(bad(P, "link"))?;
            (u.to_string(), h.to_string())
        }
    };
    let (method, password) = userinfo.split_once(':').ok_or(bad(P, "link"))?;
    if !ss_method_ok(method) {
        return Err(bad(P, "cipher"));
    }
    if !ss_password_ok(method, password) {
        return Err(bad(
            P,
            if password.is_empty() {
                "password"
            } else {
                "key"
            },
        ));
    }
    let link = split_link(&format!("ss://{hostport}"), P)?;
    let port = link.port(P)?;
    let mut settings = Settings::new();
    put(&mut settings, "cipher", method);
    if let Some(pl) = q.get("plugin") {
        ss_plugin(pl, &mut settings)?;
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("password".into(), Secret::new(password));
    Ok(Profile {
        name: v::sanitize_name(&dec(frag), &link.host),
        protocol: Protocol::Shadowsocks,
        host: link.host,
        port,
        settings,
        secrets,
    })
}

// ---------------------------------------------------------------- QUIC family

/// `443`, `443,5000-6000` or `5000-6000` -> (primary port, optional sing-box `server_ports`).
fn port_spec_multi(spec: &str, p: &'static str) -> R<(u16, Option<String>)> {
    if let Some(single) = v::port(spec) {
        return Ok((single, None));
    }
    let ranges = v::port_ranges(spec).ok_or(bad(p, "port"))?;
    let first = ranges
        .split(',')
        .next()
        .and_then(|r| r.split(':').next())
        .and_then(v::port)
        .ok_or(bad(p, "port"))?;
    Ok((first, Some(ranges)))
}

fn hop_params(q: &Query, p: &'static str, ports: Option<String>, s: &mut Settings) -> R<()> {
    let extra = match q.any(&["mport", "ports"]) {
        Some(b) => Some(v::port_ranges(b).ok_or(bad(p, "port range"))?),
        None => None,
    };
    let ports = match (ports, extra) {
        (Some(a), Some(b)) => Some(format!("{a},{b}")),
        (a, b) => a.or(b),
    };
    if let Some(r) = ports {
        put(s, "server_ports", r);
        if let Some(h) = q.any(&["hop-interval", "hop_interval", "hopInterval"]) {
            let n: u32 = h
                .trim_end_matches('s')
                .parse()
                .map_err(|_| bad(p, "hop interval"))?;
            if !(5..=3600).contains(&n) {
                return Err(bad(p, "hop interval"));
            }
            put(s, "hop_interval", format!("{n}s"));
        }
    }
    Ok(())
}

fn quic_tls(q: &Query, p: &'static str, s: &mut Settings) -> R<()> {
    reject_unhonorable(q)?;
    tls_params(q, p, "tls", s)
}

/// `100`, `100mbps`, `100 Mbps` -> Mbps.
fn mbps(x: &str) -> Option<u32> {
    let t = x.trim().to_ascii_lowercase();
    let digits: String = t.chars().take_while(char::is_ascii_digit).collect();
    let unit = t[digits.len()..].trim();
    if !matches!(unit, "" | "mbps") {
        return None;
    }
    digits
        .parse::<u32>()
        .ok()
        .filter(|n| (1..=100_000).contains(n))
}

fn bandwidth(q: &Query, p: &'static str, s: &mut Settings) -> R<()> {
    for (keys, dst) in [
        (&["upmbps", "up_mbps", "up"][..], "up_mbps"),
        (&["downmbps", "down_mbps", "down"][..], "down_mbps"),
    ] {
        if let Some(x) = q.any(keys) {
            put(s, dst, mbps(x).ok_or(bad(p, "bandwidth"))?.to_string());
        }
    }
    Ok(())
}

fn hysteria2(text: &str) -> R<Profile> {
    const P: &str = "Hysteria2";
    let link = split_link(text, P)?;
    let (port, ports) = port_spec_multi(link.port_spec.as_deref().ok_or(miss(P, "port"))?, P)?;
    let q = &link.query;
    let auth = match link.userinfo.as_deref() {
        Some(_) => match link.user_pass() {
            (u, Some(pw)) => format!("{u}:{pw}"),
            (u, None) => u,
        },
        None => q.get("auth").unwrap_or("").to_string(),
    };
    if auth.is_empty() {
        return Err(miss(P, "password"));
    }
    if auth.chars().count() > 512 || auth.chars().any(char::is_control) {
        return Err(bad(P, "password"));
    }
    let mut s = Settings::new();
    quic_tls(q, P, &mut s)?;
    hop_params(q, P, ports, &mut s)?;
    match q.get("obfs").map(str::to_ascii_lowercase).as_deref() {
        None | Some("none") => {}
        Some(o @ ("salamander" | "gecko")) => {
            let pw = q
                .any(&["obfs-password", "obfs_password"])
                .ok_or(miss(P, "obfs password"))?;
            put(&mut s, "obfs", o);
            put(&mut s, "obfs-password", pw);
            if o == "gecko" {
                for (src, dst) in [
                    ("minPacketSize", "min_packet_size"),
                    ("maxPacketSize", "max_packet_size"),
                ] {
                    if let Some(x) = q.get(src) {
                        let n: u16 = x.parse().map_err(|_| bad(P, "packet size"))?;
                        put(&mut s, dst, n.to_string());
                    }
                }
            }
        }
        Some(_) => {
            return Err(unsup(
                "Hysteria2 obfuscation other than salamander or gecko",
            ))
        }
    }
    bandwidth(q, P, &mut s)?;
    let mut secrets = BTreeMap::new();
    secrets.insert("password".into(), Secret::new(auth));
    Ok(finish(&link, Protocol::Hysteria2, port, s, secrets))
}

fn tuic(text: &str) -> R<Profile> {
    const P: &str = "TUIC";
    let link = split_link(text, P)?;
    let port = link.port(P)?;
    let (uuid, pw) = link.user_pass();
    let Some(pw) = pw.filter(|p| !p.is_empty()) else {
        return Err(if v::uuid(&uuid).is_some() {
            miss(P, "password")
        } else {
            unsup("TUIC v4 token links")
        });
    };
    let uuid = v::uuid(&uuid).ok_or(bad(P, "UUID"))?;
    let q = &link.query;
    let mut s = Settings::new();
    quic_tls(q, P, &mut s)?;
    if let Some(c) = q.any(&["congestion_control", "congestion-controller"]) {
        let c = c.to_ascii_lowercase().replace("newreno", "new_reno");
        if !matches!(c.as_str(), "cubic" | "new_reno" | "bbr") {
            return Err(bad(P, "congestion control"));
        }
        put(&mut s, "congestion_control", c);
    }
    if let Some(m) = q.any(&["udp_relay_mode", "udp-relay-mode"]) {
        let m = m.to_ascii_lowercase();
        if !matches!(m.as_str(), "native" | "quic") {
            return Err(bad(P, "udp relay mode"));
        }
        put(&mut s, "udp_relay_mode", m);
    }
    if q.flag(
        &["zero_rtt_handshake", "zero_rtt", "reduce_rtt"],
        P,
        "zero rtt",
    )? {
        put(&mut s, "zero_rtt", "1");
    }
    if q.flag(&["udp_over_stream"], P, "udp_over_stream")? {
        if s.contains_key("udp_relay_mode") {
            return Err(bad(P, "udp_over_stream with udp_relay_mode"));
        }
        put(&mut s, "udp_over_stream", "1");
    }
    if let Some(h) = q.get("heartbeat") {
        let n: u32 = h
            .trim_end_matches('s')
            .parse()
            .map_err(|_| bad(P, "heartbeat"))?;
        if !(1..=600).contains(&n) {
            return Err(bad(P, "heartbeat"));
        }
        put(&mut s, "heartbeat", format!("{n}s"));
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("uuid".into(), Secret::new(uuid));
    secrets.insert("password".into(), Secret::new(pw));
    Ok(finish(&link, Protocol::Tuic, port, s, secrets))
}

/// Hysteria v1: `hysteria://host:port?protocol=udp&auth=..&peer=sni&insecure=1&upmbps=..&downmbps=..&alpn=..&obfs=xplus&obfsParam=..`
fn hysteria1(text: &str) -> R<Profile> {
    const P: &str = "Hysteria";
    let link = split_link(text, P)?;
    let (port, ports) = port_spec_multi(link.port_spec.as_deref().ok_or(miss(P, "port"))?, P)?;
    let q = &link.query;
    if q.get("protocol")
        .is_some_and(|x| !x.eq_ignore_ascii_case("udp"))
    {
        return Err(unsup(
            "Hysteria transport other than udp (faketcp, wechat-video)",
        ));
    }
    let mut s = Settings::new();
    quic_tls(q, P, &mut s)?;
    hop_params(q, P, ports, &mut s)?;
    if !s.contains_key("alpn") {
        put(&mut s, "alpn", "hysteria");
    }
    if let Some(o) = q.get("obfs") {
        if !o.eq_ignore_ascii_case("xplus") {
            return Err(unsup("Hysteria obfuscation other than xplus"));
        }
        let pw = q
            .any(&["obfsParam", "obfs-password"])
            .ok_or(miss(P, "obfs password"))?;
        put(&mut s, "obfs", pw);
    }
    bandwidth(q, P, &mut s)?;
    let mut secrets = BTreeMap::new();
    if let Some(a) = q.get("auth") {
        secrets.insert("password".into(), Secret::new(a));
    }
    Ok(finish(&link, Protocol::Hysteria1, port, s, secrets))
}

fn anytls(text: &str) -> R<Profile> {
    const P: &str = "AnyTLS";
    let link = split_link(text, P)?;
    let port = link.port(P)?;
    let pw = match link.user_pass() {
        (u, Some(pw)) => format!("{u}:{pw}"),
        (u, None) => u,
    };
    if pw.is_empty() {
        return Err(miss(P, "password"));
    }
    if pw.chars().any(char::is_control) {
        return Err(bad(P, "password"));
    }
    let mut s = Settings::new();
    quic_tls(&link.query, P, &mut s)?;
    let mut secrets = BTreeMap::new();
    secrets.insert("password".into(), Secret::new(pw));
    Ok(finish(&link, Protocol::AnyTls, port, s, secrets))
}

// ---------------------------------------------------------------- plain proxies

fn credentials(
    link: &Link,
    p: &'static str,
    s: &mut Settings,
    secrets: &mut BTreeMap<String, Secret>,
    b64_form: bool,
) -> R<()> {
    let (mut user, mut pw) = link.user_pass();
    if b64_form && pw.is_none() && !user.is_empty() {
        if let Some(d) = b64_any(&user).and_then(|b| String::from_utf8(b).ok()) {
            if let Some((u, pa)) = d.split_once(':') {
                user = u.to_string();
                pw = Some(pa.to_string());
            }
        }
    }
    if user.is_empty() {
        return Ok(());
    }
    let pw = pw.unwrap_or_default();
    if user.chars().any(char::is_control) || pw.chars().any(char::is_control) || user.len() > 255 {
        return Err(bad(p, "credentials"));
    }
    s.insert("username".into(), user);
    secrets.insert("password".into(), Secret::new(pw));
    Ok(())
}

/// `socks5://user:pass@host:port` or v2rayN style `socks://base64(user:pass)@host:port`.
fn socks(text: &str) -> R<Profile> {
    const P: &str = "SOCKS5";
    let link = split_link(text, P)?;
    let port = link.port(P)?;
    let (mut s, mut sec) = (Settings::new(), BTreeMap::new());
    credentials(&link, P, &mut s, &mut sec, true)?;
    Ok(finish(&link, Protocol::Socks, port, s, sec))
}

fn http_proxy(text: &str) -> R<Profile> {
    const P: &str = "HTTP Proxy";
    let tls = text.to_ascii_lowercase().starts_with("https-proxy");
    let link = split_link(text, P)?;
    let port = match link.port_spec {
        Some(_) => link.port(P)?,
        None if tls => 443,
        None => 80,
    };
    let (mut s, mut sec) = (Settings::new(), BTreeMap::new());
    if tls {
        tls_params(&link.query, P, "tls", &mut s)?;
    }
    credentials(&link, P, &mut s, &mut sec, false)?;
    Ok(finish(&link, Protocol::HttpProxy, port, s, sec))
}

fn ssh(text: &str) -> R<Profile> {
    const P: &str = "SSH";
    let link = split_link(text, P)?;
    let port = match link.port_spec {
        Some(_) => link.port(P)?,
        None => 22,
    };
    let (user, pw) = link.user_pass();
    if user.is_empty() {
        return Err(miss(P, "user"));
    }
    let pw = pw.ok_or(miss(P, "password"))?;
    if user.chars().any(char::is_control) || pw.chars().any(char::is_control) {
        return Err(bad(P, "credentials"));
    }
    let mut s = Settings::new();
    s.insert("username".into(), user);
    if let Some(k) = link.query.any(&["host_key", "hostKey"]) {
        // "ssh-ed25519 AAAA..." (a trailing comment is dropped)
        let mut it = k.split_whitespace();
        let (alg, data) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        if !(alg.starts_with("ssh-") || alg.starts_with("ecdsa-")) || STANDARD.decode(data).is_err()
        {
            return Err(bad(P, "host key"));
        }
        put(&mut s, "host_key", format!("{alg} {data}"));
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("password".into(), Secret::new(pw));
    Ok(finish(&link, Protocol::Ssh, port, s, secrets))
}

/// `wireguard://<private key>@host:port?publickey=..&address=..&reserved=1,2,3&mtu=..&presharedkey=..&dns=..#name`
fn wireguard_uri(text: &str) -> R<Profile> {
    const P: &str = "WireGuard";
    let link = split_link(text, P)?;
    let port = link.port(P)?;
    let q = &link.query;
    if q.get("fm").is_some() {
        return Err(unsup("Xray finalmask (fm)"));
    }
    let private = link
        .user_dec()
        .filter(|k| !k.is_empty())
        .ok_or(miss(P, "PrivateKey"))?;
    let private = v::key32(&private).ok_or(bad(P, "PrivateKey"))?;
    let public = q
        .any(&["publickey", "public_key", "peer"])
        .ok_or(miss(P, "PublicKey"))?;
    let public = v::key32(public).ok_or(bad(P, "PublicKey"))?;
    let address = q.get("address").ok_or(miss(P, "Address"))?;
    let addrs: Option<Vec<String>> = address.split(',').map(v::cidr).collect();
    let addrs = addrs.ok_or(bad(P, "Address"))?;
    let mut s = Settings::new();
    put(&mut s, "address", addrs.join(", "));
    put(&mut s, "allowed_ips", "0.0.0.0/0, ::/0");
    put(&mut s, "peer_public_key", public);
    if let Some(m) = q.get("mtu") {
        let n: u16 = m.parse().map_err(|_| bad(P, "MTU"))?;
        if !(576..=9000).contains(&n) {
            return Err(bad(P, "MTU"));
        }
        put(&mut s, "mtu", n.to_string());
    }
    if let Some(r) = q.get("reserved") {
        let nums: Option<Vec<u8>> = r.split(',').map(|x| x.trim().parse().ok()).collect();
        match nums {
            Some(n) if n.len() == 3 => {
                put(&mut s, "reserved", format!("{},{},{}", n[0], n[1], n[2]))
            }
            _ => return Err(bad(P, "reserved")),
        }
    }
    if let Some(k) = q.any(&["keepalive", "persistentkeepalive"]) {
        let n: u16 = k.parse().map_err(|_| bad(P, "PersistentKeepalive"))?;
        put(&mut s, "persistent_keepalive", n.to_string());
    }
    if let Some(d) = q.get("dns") {
        let ips: Option<Vec<String>> = d
            .split(',')
            .map(|x| v::host(x).filter(|h| h.parse::<std::net::IpAddr>().is_ok()))
            .collect();
        put(&mut s, "dns", ips.ok_or(bad(P, "DNS"))?.join(", "));
    }
    let mut secrets = BTreeMap::new();
    secrets.insert("private_key".into(), Secret::new(private));
    if let Some(psk) = q.any(&["presharedkey", "preshared_key", "psk"]) {
        secrets.insert(
            "preshared_key".into(),
            Secret::new(v::key32(psk).ok_or(bad(P, "PresharedKey"))?),
        );
    }
    Ok(finish(&link, Protocol::WireGuard, port, s, secrets))
}

#[cfg(test)]
mod tests {
    use super::*;
    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
    const PBK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn p(text: &str) -> R<Profile> {
        let scheme = text
            .split_once("://")
            .map(|(s, _)| s.to_ascii_lowercase())
            .unwrap_or_default();
        parse(&scheme, text)
    }
    fn set(x: &Profile, k: &str) -> Option<String> {
        x.settings.get(k).cloned()
    }

    #[test]
    fn vless_reality_full() {
        let x = p(&format!("vless://{UUID}@example.com:443?type=tcp&security=reality&pbk={PBK}&sid=0a1b&sni=a.com&flow=xtls-rprx-vision&fp=chrome&spx=%2F&evil=1&encryption=none#My%20Node")).unwrap();
        assert_eq!(x.name, "My Node");
        assert_eq!(set(&x, "security").as_deref(), Some("reality"));
        assert_eq!(set(&x, "sid").as_deref(), Some("0a1b"));
        assert_eq!(set(&x, "flow").as_deref(), Some("xtls-rprx-vision"));
        assert!(!x.settings.contains_key("evil") && !x.settings.contains_key("spx"));
    }

    #[test]
    fn vless_rejects_what_it_cannot_honor() {
        let base = format!("vless://{UUID}@example.com:443?security=tls");
        for (extra, expect) in [
            (
                "&encryption=mlkem768x25519plus.native.0rtt.abc",
                "post-quantum",
            ),
            ("&encryption=aes-128-gcm", "encryption"),
            ("&type=xhttp", "XHTTP"),
            ("&type=kcp", "mKCP"),
            ("&type=quic", "QUIC"),
            ("&type=grpc&mode=multi", "multi"),
            ("&headerType=http", "header"),
            ("&pcs=abcd", "pinning"),
            ("&vcn=x.com", "verifyPeerCertByName"),
            ("&fm=%7B%7D", "finalmask"),
            ("&pqv=abc", "post-quantum verification"),
            ("&flow=xtls-rprx-direct", "flow"),
            ("&ech=cloudflare-ech.com%2Bhttps%3A%2F%2Fdns.example", "ECH"),
        ] {
            match p(&format!("{base}{extra}")) {
                Err(ConfigIssue::Unsupported(m)) => assert!(m.contains(expect), "{extra}: {m}"),
                other => panic!("{extra}: {other:?}"),
            }
        }
        assert!(matches!(
            p(&format!(
                "vless://{UUID}@example.com:443?flow=xtls-rprx-vision"
            )),
            Err(ConfigIssue::InvalidField { .. })
        ));
        assert!(matches!(
            p(&format!(
                "vless://{UUID}@example.com:443?security=reality&pbk={PBK}&sni=a.com&sid=zz"
            )),
            Err(ConfigIssue::InvalidField { .. })
        ));
        assert!(matches!(
            p(&format!(
                "vless://{UUID}@example.com:443?security=reality&pbk={PBK}"
            )),
            Err(ConfigIssue::MissingField { .. })
        ));
    }

    #[test]
    fn vless_transports() {
        let ws = p(&format!("vless://{UUID}@example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com")).unwrap();
        assert_eq!(set(&ws, "path").as_deref(), Some("/ws"));
        assert_eq!(set(&ws, "ed").as_deref(), Some("2048"));
        assert_eq!(set(&ws, "edh").as_deref(), Some("Sec-WebSocket-Protocol"));
        let g = p(&format!("vless://{UUID}@example.com:443?type=grpc&security=tls&serviceName=svc&authority=&mode=gun")).unwrap();
        assert_eq!(set(&g, "serviceName").as_deref(), Some("svc"));
        let h = p(&format!(
            "vless://{UUID}@example.com:443?type=h2&security=tls&host=a.com,b.com&path=/x"
        ))
        .unwrap();
        assert_eq!(set(&h, "type").as_deref(), Some("http"));
        assert!(p(&format!("vless://{UUID}@example.com:443?type=h2")).is_err());
        let u = p(&format!(
            "vless://{UUID}@example.com:443?type=httpupgrade&path=/u"
        ))
        .unwrap();
        assert_eq!(set(&u, "type").as_deref(), Some("httpupgrade"));
    }

    #[test]
    fn non_uuid_ids_ipv6_and_idn() {
        let x = p("vless://my-secret-id@[2001:db8::1]:443?security=tls#v6").unwrap();
        assert_eq!(x.host, "2001:db8::1");
        assert_eq!(x.secrets["uuid"].expose(), "my-secret-id");
        assert!(p("vless://b831381d-6324-4d53-ad4f-8cda48b3081z@example.com:443").is_err());
        let x = p("VLESS://b831381D63244d53ad4f8cda48b30811@bücher.example:443").unwrap();
        assert_eq!(x.host, "xn--bcher-kva.example");
        assert_eq!(x.secrets["uuid"].expose(), UUID);
    }

    #[test]
    fn plus_in_query_is_kept() {
        let q = Query::parse("a=x+y%2Bz").unwrap();
        assert_eq!(q.get("a"), Some("x+y+z"));
    }

    #[test]
    fn vmess_json_and_standard() {
        for port in [r#""443""#, "443"] {
            let json = format!(
                r#"{{"v":"2","ps":"n1","add":"h.example.com","port":{port},"id":"{UUID}","aid":"0","scy":"aes-128-gcm","net":"ws","tls":"tls","path":"/p","host":"h.example.com","insecure":"1"}}"#
            );
            let x = p(&format!("vmess://{}", STANDARD.encode(json))).unwrap();
            assert_eq!(
                (x.host.as_str(), x.port, x.name.as_str()),
                ("h.example.com", 443, "n1")
            );
            assert_eq!(set(&x, "cipher").as_deref(), Some("aes-128-gcm"));
            assert_eq!(set(&x, "insecure").as_deref(), Some("1"));
        }
        let g = format!(
            r#"{{"add":"h.example.com","port":443,"id":"{UUID}","net":"grpc","tls":"tls","path":"svc","host":"","type":"multi"}}"#
        );
        assert!(matches!(
            p(&format!("vmess://{}", URL_SAFE_NO_PAD.encode(g))),
            Err(ConfigIssue::Unsupported(_))
        ));
        let tcp_http = format!(
            r#"{{"add":"h.example.com","port":443,"id":"{UUID}","net":"tcp","type":"http"}}"#
        );
        assert!(matches!(
            p(&format!("vmess://{}", STANDARD.encode(tcp_http))),
            Err(ConfigIssue::Unsupported(_))
        ));
        let std = p(&format!(
            "vmess://{UUID}@h.example.com:443?encryption=zero&security=tls&type=ws&path=/a#S"
        ))
        .unwrap();
        assert_eq!(set(&std, "cipher").as_deref(), Some("zero"));
        assert!(p("vmess://!!!notbase64").is_err());
        let bad_cipher =
            format!(r#"{{"add":"h.example.com","port":443,"id":"{UUID}","scy":"rc4"}}"#);
        assert!(p(&format!("vmess://{}", STANDARD.encode(bad_cipher))).is_err());
        let custom = r#"{"add":"h.example.com","port":443,"id":"not-a-uuid-but-valid"}"#;
        assert!(p(&format!("vmess://{}", STANDARD.encode(custom))).is_ok());
    }

    #[test]
    fn trojan_variants() {
        let t = p(
            "trojan://s3cret%40x@t.example.com:443?sni=t.example.com&type=ws&path=/w&host=h.com#T",
        )
        .unwrap();
        assert_eq!(t.secrets["password"].expose(), "s3cret@x");
        assert_eq!(set(&t, "security").as_deref(), Some("tls"));
        assert!(matches!(
            p("trojan://pw@t.example.com:443?encryption=ss%3Baes-128-gcm%3Apw"),
            Err(ConfigIssue::Unsupported(_))
        ));
        assert!(p("trojan://@t.example.com:443").is_err());
        let n = p("trojan://pw@t.example.com:80?security=none&type=ws").unwrap();
        assert_eq!(set(&n, "security").as_deref(), Some("none"));
    }

    #[test]
    fn hysteria2_forms() {
        let h = p("hysteria2://auth@h.example.com:443,20000-30000/?sni=h.example.com&obfs=salamander&obfs-password=xx&insecure=1&mport=40000-41000#H").unwrap();
        assert_eq!(h.port, 443);
        assert_eq!(
            set(&h, "server_ports").as_deref(),
            Some("443:443,20000:30000,40000:41000")
        );
        assert_eq!(set(&h, "insecure").as_deref(), Some("1"));
        let u = p("hy2://user:pa%3Ass@h.example.com:8443").unwrap();
        assert_eq!(u.secrets["password"].expose(), "user:pa:ss");
        assert!(matches!(
            p("hysteria2://a@h.example.com:443?pinSHA256=AB%3ACD"),
            Err(ConfigIssue::Unsupported(_))
        ));
        assert!(matches!(
            p("hysteria2://a@h.example.com:443?obfs=xplus&obfs-password=x"),
            Err(ConfigIssue::Unsupported(_))
        ));
        assert!(p("hysteria2://a@h.example.com:443?obfs=salamander").is_err());
        let g = p("hysteria2://a@h.example.com:443?obfs=gecko&obfs-password=x&minPacketSize=600")
            .unwrap();
        assert_eq!(set(&g, "min_packet_size").as_deref(), Some("600"));
    }

    #[test]
    fn shadowsocks_forms() {
        let ui = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:pw");
        let a = p(&format!(
            "ss://{ui}@s.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dx.com#S"
        ))
        .unwrap();
        assert_eq!((a.host.as_str(), a.port), ("s.example.com", 8388));
        assert_eq!(
            set(&a, "plugin_opts").as_deref(),
            Some("obfs=http;obfs-host=x.com")
        );
        let legacy = STANDARD.encode("aes-256-gcm:pw2@l.example.com:1234");
        assert_eq!(
            p(&format!("ss://{legacy}#L")).unwrap().host,
            "l.example.com"
        );
        assert_eq!(
            p("ss://aes-128-gcm:plain@c.example.com:1#C")
                .unwrap()
                .secrets["password"]
                .expose(),
            "plain"
        );
        let k16 = STANDARD.encode([7u8; 16]);
        let enc = k16
            .replace('=', "%3D")
            .replace('+', "%2B")
            .replace('/', "%2F");
        assert!(p(&format!("ss://2022-blake3-aes-128-gcm:{enc}@[::1]:8388")).is_ok());
        assert!(matches!(
            p(&format!(
                "ss://2022-blake3-aes-256-gcm:{enc}@h.example.com:1"
            )),
            Err(ConfigIssue::InvalidField { field: "key", .. })
        ));
        assert!(matches!(
            p("ss://aes-128-gcm:x@h.example.com:1/?plugin=kcptun"),
            Err(ConfigIssue::Unsupported(_))
        ));
        assert!(matches!(
            p("ss://aes-128-gcm:x@h.example.com:1/?prefix=%16%03"),
            Err(ConfigIssue::Unsupported(_))
        ));
        let v2 = p("ss://aes-128-gcm:x@h.example.com:1/?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Da.com%3Bpath%3D%2Fp").unwrap();
        assert_eq!(
            set(&v2, "plugin_opts").as_deref(),
            Some("mode=websocket;tls;host=a.com;path=/p")
        );
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
        assert!(p("ss://none:x@s.example.com:1").is_err());
    }

    #[test]
    fn quic_family_and_plain() {
        let t = p(&format!("tuic://{UUID}:pw1234@t.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1&disable_sni=1&zero_rtt_handshake=1&sni=t.example.com#T")).unwrap();
        assert_eq!(set(&t, "zero_rtt").as_deref(), Some("1"));
        assert_eq!(set(&t, "disable_sni").as_deref(), Some("1"));
        let d = p(&format!("tuic://{UUID}:pw1234@t.example.com:443")).unwrap();
        assert!(!d.settings.contains_key("congestion_control"));
        assert!(matches!(
            p("tuic://token@t.example.com:443"),
            Err(ConfigIssue::Unsupported(_))
        ));
        let h = p("hysteria://h.example.com:443?protocol=udp&auth=secret1&peer=sni.example.com&insecure=0&upmbps=50&downmbps=100&obfs=xplus&obfsParam=op#H").unwrap();
        assert_eq!(set(&h, "sni").as_deref(), Some("sni.example.com"));
        assert_eq!(set(&h, "obfs").as_deref(), Some("op"));
        assert!(matches!(
            p("hysteria://h.example.com:443?protocol=faketcp&auth=x"),
            Err(ConfigIssue::Unsupported(_))
        ));
        let enc = STANDARD.encode("user:pass");
        assert_eq!(
            p(&format!("socks://{enc}@s.example.com:1080"))
                .unwrap()
                .secrets["password"]
                .expose(),
            "pass"
        );
        assert_eq!(p("ssh://root:pw@h.example.com#x").unwrap().port, 22);
        let sh =
            p("ssh://root:pw@h.example.com?host_key=ssh-ed25519%20AAAAC3NzaC1lZDI1NTE5").unwrap();
        assert_eq!(
            set(&sh, "host_key").as_deref(),
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")
        );
        assert!(p("anytls://pw1234@a.example.com:443?sni=a.example.com").is_ok());
        let ht = p("https-proxy://u:p@h.example.com#P").unwrap();
        assert_eq!(ht.port, 443);
        assert_eq!(set(&ht, "security").as_deref(), Some("tls"));
    }

    #[test]
    fn names_are_sanitized() {
        let long = "x".repeat(300);
        let x = p(&format!("trojan://pw@a.example.com:1#%0A{long}")).unwrap();
        assert_eq!(x.name.chars().count(), 100);
        let x = p("trojan://pw@a.example.com:1#%E2%80%AEevil%E2%80%8Bname").unwrap();
        assert_eq!(x.name, "evilname");
    }

    #[test]
    fn wireguard_uri_parses_and_validates() {
        let k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".replace('=', "%3D");
        let ok = p(&format!("wireguard://{k}@w.example.com:51820?publickey={k}&presharedkey={k}&address=10.0.0.2/32,fd00::2/128&reserved=1,2,3&mtu=1280&dns=1.1.1.1#W")).unwrap();
        assert_eq!(set(&ok, "reserved").as_deref(), Some("1,2,3"));
        assert_eq!(
            set(&ok, "address").as_deref(),
            Some("10.0.0.2/32, fd00::2/128")
        );
        assert!(ok.secrets.contains_key("preshared_key"));
        assert!(p("wireguard://short@w.example.com:1?publickey=x&address=1.1.1.1/32").is_err());
    }

    #[test]
    fn hosts_and_ports_validated() {
        for bad in [
            "trojan://pw@a b.com:1",
            "trojan://pw@a.com:0",
            "trojan://pw@a.com:70000",
            "trojan://pw@-a.com:1",
            "trojan://pw@a.com",
            "trojan://pw@[::1:1",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }
}
