//! Real end-to-end check: a client config generated from a share link must carry traffic to a
//! local sing-box server of the same protocol and back. Skipped when sing-box is absent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_engine::{probe, sidecar::*, singbox, Mode};
use core_import::detect;
use core_log::Redactor;
use serde_json::{json, Value};
use std::net::{SocketAddr, TcpListener as StdListener};
use std::process::Command;
use std::time::Duration;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const BODY: &str = "hello-through-tunnel";

fn free_port() -> u16 {
    StdListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn have_singbox() -> bool {
    Command::new("sing-box").arg("version").output().is_ok()
}

fn keypair(dir: &std::path::Path) -> (String, String) {
    let out = Command::new("sing-box")
        .args(["generate", "tls-keypair", "example.com"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let key: String = text
        .split("-----BEGIN PRIVATE KEY-----")
        .nth(1)
        .map(|k| {
            format!(
                "-----BEGIN PRIVATE KEY-----{}",
                k.split("-----END PRIVATE KEY-----").next().unwrap()
            ) + "-----END PRIVATE KEY-----\n"
        })
        .unwrap();
    let cert: String = format!(
        "-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----\n",
        text.split("-----BEGIN CERTIFICATE-----")
            .nth(1)
            .unwrap()
            .split("-----END CERTIFICATE-----")
            .next()
            .unwrap()
    );
    let (kp, cp) = (dir.join("k.pem"), dir.join("c.pem"));
    std::fs::write(&kp, key).unwrap();
    std::fs::write(&cp, cert).unwrap();
    (kp.display().to_string(), cp.display().to_string())
}

async fn http_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 512];
                let _ = s.read(&mut b).await;
                let _ = s
                    .write_all(
                        format!(
                            "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{BODY}",
                            BODY.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    port
}

fn server_config(inbound: Value) -> Value {
    json!({"log": {"level": "warn"}, "inbounds": [inbound], "outbounds": [{"type": "direct", "tag": "direct"}]})
}

async fn run_case(name: &str, server_inbound: Value, link: String) {
    let dir = std::env::temp_dir().join(format!("wt-e2e-{name}-{}", std::process::id()));
    let http = http_server().await;
    let srv_file = PrivateFile::write(
        &dir,
        "server.json",
        serde_json::to_string(&server_config(server_inbound))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut server = Sidecar::spawn(SidecarSpec {
        program: "sing-box".into(),
        args: vec!["run".into(), "-c".into(), srv_file.path().into()],
        redactor: Redactor::new(),
    })
    .unwrap();

    let profile = detect(&link).unwrap();
    let socks = free_port();
    let built = singbox::build(&profile, &Mode::Proxy { socks_port: socks }, &[]).unwrap();
    let red = Redactor::new();
    red.register_profile(&profile);
    let cli_file = PrivateFile::write(
        &dir,
        "client.json",
        &serde_json::to_vec(&built.config).unwrap(),
    )
    .unwrap();
    let mut client = Sidecar::spawn(SidecarSpec {
        program: "sing-box".into(),
        args: vec!["run".into(), "-c".into(), cli_file.path().into()],
        redactor: red,
    })
    .unwrap();

    let socks_addr: SocketAddr = format!("127.0.0.1:{socks}").parse().unwrap();
    probe::wait_listening(socks_addr, Duration::from_secs(10))
        .await
        .unwrap_or_else(|e| panic!("{name}: client not up: {e}"));
    // UDP-based protocols may need a moment after the listener is up.
    let mut last = String::new();
    let mut ok = false;
    for _ in 0..20 {
        match probe::http_get_via_socks(socks_addr, "127.0.0.1", http, Duration::from_secs(3)).await
        {
            Ok(r) if r.contains(BODY) => {
                ok = true;
                break;
            }
            Ok(r) => last = r,
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let mut logs = Vec::new();
    while let Ok(l) = client.lines.try_recv() {
        logs.push(l);
    }
    while let Ok(l) = server.lines.try_recv() {
        logs.push(l);
    }
    client.stop(Duration::from_secs(2)).await.unwrap();
    server.stop(Duration::from_secs(2)).await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        ok,
        "{name}: no traffic through tunnel: {last}\n{}",
        logs.join("\n")
    );
    let joined = logs.join("\n");
    assert!(!joined.contains(UUID), "{name}: uuid leaked into logs");
}

macro_rules! case {
    ($t:ident, $body:expr) => {
        #[tokio::test(flavor = "multi_thread")]
        async fn $t() {
            if !have_singbox() {
                eprintln!("sing-box missing; skipping");
                return;
            }
            let f: &dyn Fn(u16, &std::path::Path) -> (Value, String) = &$body;
            let port = free_port();
            let dir = std::env::temp_dir().join(format!(
                "wt-keys-{}-{}",
                stringify!($t),
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let (inb, link) = f(port, &dir);
            run_case(stringify!($t), inb, link).await;
            std::fs::remove_dir_all(&dir).ok();
        }
    };
}

case!(shadowsocks, |p, _| (
    json!({"type":"shadowsocks","listen":"127.0.0.1","listen_port":p,"method":"aes-256-gcm","password":"pw-e2e-1234"}),
    format!("ss://aes-256-gcm:pw-e2e-1234@127.0.0.1:{p}#ss")
));
case!(vless_tcp, |p, _| (
    json!({"type":"vless","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID}]}),
    format!("vless://{UUID}@127.0.0.1:{p}?type=tcp&security=none#v")
));
case!(vmess_tcp, |p, _| {
    let json = format!(r#"{{"add":"127.0.0.1","port":"{p}","id":"{UUID}","aid":"0","net":"tcp"}}"#);
    use std::io::Write;
    let mut enc = String::new();
    {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for c in json.as_bytes().chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            enc.push(T[(n >> 18) as usize & 63] as char);
            enc.push(T[(n >> 12) as usize & 63] as char);
            enc.push(if c.len() > 1 {
                T[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            enc.push(if c.len() > 2 {
                T[n as usize & 63] as char
            } else {
                '='
            });
        }
    }
    let _ = std::io::stdout().flush();
    (
        json!({"type":"vmess","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID,"alterId":0}]}),
        format!("vmess://{enc}"),
    )
});
case!(trojan_tls, |p, d| {
    let (k, c) = keypair(d);
    (
        json!({"type":"trojan","listen":"127.0.0.1","listen_port":p,"users":[{"password":"pw-trojan-1234"}],"tls":{"enabled":true,"server_name":"example.com","key_path":k,"certificate_path":c}}),
        format!("trojan://pw-trojan-1234@127.0.0.1:{p}?sni=example.com&insecure=1#t"),
    )
});
case!(vless_ws_tls, |p, d| {
    let (k, c) = keypair(d);
    (json!({"type":"vless","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID}],"tls":{"enabled":true,"server_name":"example.com","key_path":k,"certificate_path":c},"transport":{"type":"ws","path":"/ws"}}), format!("vless://{UUID}@127.0.0.1:{p}?type=ws&security=tls&sni=example.com&path=%2Fws&insecure=1#w"))
});
case!(hysteria2, |p, d| {
    let (k, c) = keypair(d);
    (
        json!({"type":"hysteria2","listen":"127.0.0.1","listen_port":p,"users":[{"password":"pw-hy2-1234"}],"tls":{"enabled":true,"server_name":"example.com","key_path":k,"certificate_path":c}}),
        format!("hysteria2://pw-hy2-1234@127.0.0.1:{p}?sni=example.com&insecure=1#h"),
    )
});

fn tls_in(d: &std::path::Path, alpn: Option<&str>) -> Value {
    let (k, c) = keypair(d);
    let mut t =
        json!({"enabled":true,"server_name":"example.com","key_path":k,"certificate_path":c});
    if let Some(a) = alpn {
        t["alpn"] = json!([a]);
    }
    t
}

case!(tuic, |p, d| {
    (
    json!({"type":"tuic","listen":"127.0.0.1","listen_port":p,"users":[{"uuid":UUID,"password":"pw-tuic-1234"}],"congestion_control":"bbr","tls":tls_in(d, Some("h3"))}),
    format!("tuic://{UUID}:pw-tuic-1234@127.0.0.1:{p}?sni=example.com&insecure=1&alpn=h3&congestion_control=bbr#tu")
)
});
case!(hysteria1, |p, d| {
    (
    json!({"type":"hysteria","listen":"127.0.0.1","listen_port":p,"up_mbps":100,"down_mbps":100,"users":[{"auth_str":"pw-h1-1234"}],"tls":tls_in(d, None)}),
    format!("hysteria://127.0.0.1:{p}?auth=pw-h1-1234&peer=example.com&insecure=1&upmbps=50&downmbps=100#h1")
)
});
case!(anytls, |p, d| (
    json!({"type":"anytls","listen":"127.0.0.1","listen_port":p,"users":[{"password":"pw-any-1234"}],"tls":tls_in(d, None)}),
    format!("anytls://pw-any-1234@127.0.0.1:{p}?sni=example.com&insecure=1#at")
));
case!(socks_with_auth, |p, _| (
    json!({"type":"socks","listen":"127.0.0.1","listen_port":p,"users":[{"username":"u1","password":"pw-socks-1234"}]}),
    format!("socks5://u1:pw-socks-1234@127.0.0.1:{p}#so")
));
case!(http_proxy_with_auth, |p, _| (
    json!({"type":"http","listen":"127.0.0.1","listen_port":p,"users":[{"username":"u1","password":"pw-http-1234"}]}),
    format!("http-proxy://u1:pw-http-1234@127.0.0.1:{p}#ht")
));
