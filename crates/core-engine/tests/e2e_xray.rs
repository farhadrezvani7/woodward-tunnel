//! Xray-core as the second engine, through the real stack: an Xray server on loopback, a client config
//! generated from a share link, the runner starting Xray and sing-box (proxy mode), real HTTP through it.
//! Needs `xray` and `sing-box`: set WT_XRAY, or have `engines/bin/xray` / `xray` on PATH. Skipped otherwise.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_engine::runner::{start, Binaries, StartOptions};
use core_engine::{probe, sidecar::*, Mode};
use core_log::Redactor;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const BODY: &str = "hello-through-xray";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn xray_bin() -> Option<PathBuf> {
    let candidates = [
        std::env::var("WT_XRAY").ok().map(PathBuf::from),
        Some(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../engines/bin/xray")),
        Some(PathBuf::from("xray")),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|p| Command::new(p).arg("version").output().is_ok())
        .map(|p| p.canonicalize().unwrap_or(p))
}

fn have_singbox() -> bool {
    Command::new("sing-box").arg("version").output().is_ok()
}

/// Self-signed certificate for example.com and its leaf SHA-256 as `xray tls hash` prints it.
fn keypair(dir: &Path, xray: &Path) -> (String, String, String) {
    let out = Command::new("sing-box")
        .args(["generate", "tls-keypair", "example.com"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let part = |b: &str, e: &str| {
        let mid = text
            .split(b)
            .nth(1)
            .unwrap()
            .split(e)
            .next()
            .unwrap()
            .to_string();
        format!("{b}{mid}{e}\n")
    };
    let key = part("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
    let cert = part("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
    let (kp, cp) = (dir.join("k.pem"), dir.join("c.pem"));
    std::fs::write(&kp, key).unwrap();
    std::fs::write(&cp, cert).unwrap();
    let h = Command::new(xray)
        .args(["tls", "hash", "--cert"])
        .arg(&cp)
        .output()
        .unwrap();
    let hash = String::from_utf8(h.stdout)
        .unwrap()
        .split_whitespace()
        .last()
        .unwrap()
        .to_string();
    assert_eq!(hash.len(), 64, "unexpected `xray tls hash` output");
    (kp.display().to_string(), cp.display().to_string(), hash)
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

fn vless_server(port: u16, stream: Value, decryption: &str) -> Value {
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": decryption},
            "streamSettings": stream,
        }],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
    })
}

/// Runs one case; returns whether HTTP got through plus the collected (redacted) logs.
async fn run_case(name: &str, server: Value, link: String, udp: bool) -> (bool, String) {
    let xray = xray_bin().unwrap();
    let dir = std::env::temp_dir().join(format!("wt-xray-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let http = http_server().await;
    let srv_file = PrivateFile::write(
        &dir,
        "server.json",
        serde_json::to_string(&server).unwrap().as_bytes(),
    )
    .unwrap();
    let mut srv = Sidecar::spawn(SidecarSpec {
        program: xray.clone(),
        args: vec!["run".into(), "-c".into(), srv_file.path().into()],
        redactor: Redactor::new(),
    })
    .unwrap();
    let sport = server["inbounds"][0]["port"].as_u64().unwrap() as u16;
    if udp {
        tokio::time::sleep(Duration::from_secs(1)).await;
    } else {
        probe::wait_listening(
            format!("127.0.0.1:{sport}").parse().unwrap(),
            Duration::from_secs(10),
        )
        .await
        .unwrap_or_else(|e| panic!("{name}: server not up: {e}"));
    }

    let profile = core_import::detect(&link).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert_eq!(profile.engine(), core_model::EngineKind::Xray, "{name}");
    let socks = free_port();
    let red = Redactor::new();
    red.register_profile(&profile);
    let opts = StartOptions {
        mode: Mode::Proxy { socks_port: socks },
        dns: vec![],
        work_dir: dir.join("work"),
        bins: Binaries {
            sing_box: "sing-box".into(),
            awg_socks: "awg-socks".into(),
            openvpn: "openvpn".into(),
            xray,
        },
        redactor: red,
        ready_timeout: Duration::from_secs(15),
    };
    let mut t = start(&profile, &opts)
        .await
        .unwrap_or_else(|e| panic!("{name}: start failed: {e} {}", e.tail()));
    let addr: SocketAddr = format!("127.0.0.1:{socks}").parse().unwrap();
    let mut ok = false;
    for _ in 0..6 {
        // mKCP reports the end of a stream about 4 s after the peer closed it, so the probe, which
        // reads until the end of the stream, needs a long limit.
        match probe::http_get_via_socks(addr, "127.0.0.1", http, Duration::from_secs(10)).await {
            Ok(b) if b.contains(BODY) => {
                ok = true;
                break;
            }
            Ok(b) => eprintln!("{name}: unexpected reply {b:?}"),
            Err(e) => eprintln!("{name}: probe error {e}"),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let mut logs: Vec<String> = t
        .drain_lines()
        .into_iter()
        .map(|(n, l)| format!("{n}: {l}"))
        .collect();
    while let Ok(l) = srv.lines.try_recv() {
        logs.push(format!("server: {l}"));
    }
    t.stop().await;
    srv.stop(Duration::from_secs(2)).await.unwrap();
    std::fs::remove_dir_all(&dir).ok();
    (ok, logs.join("\n"))
}

macro_rules! skip_without_engines {
    () => {
        if xray_bin().is_none() || !have_singbox() {
            eprintln!("xray or sing-box missing; skipping");
            return;
        }
    };
}

async fn expect_traffic(name: &str, server: Value, link: String, udp: bool) {
    let (ok, logs) = run_case(name, server, link, udp).await;
    assert!(ok, "{name}: no traffic through the tunnel\n{logs}");
    assert!(!logs.contains(UUID), "{name}: uuid leaked into logs");
}

#[tokio::test(flavor = "multi_thread")]
async fn xhttp_without_tls() {
    skip_without_engines!();
    let p = free_port();
    let s = vless_server(
        p,
        json!({"network": "xhttp", "xhttpSettings": {"path": "/x"}}),
        "none",
    );
    expect_traffic(
        "xhttp-plain",
        s,
        format!("vless://{UUID}@127.0.0.1:{p}?type=xhttp&path=%2Fx#xp"),
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn xhttp_with_tls_and_certificate_pin() {
    skip_without_engines!();
    let dir = std::env::temp_dir().join(format!("wt-xray-keys-xhttp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (key, cert, hash) = keypair(&dir, &xray_bin().unwrap());
    let stream = json!({
        "network": "xhttp", "security": "tls",
        "xhttpSettings": {"path": "/x", "mode": "stream-up"},
        "tlsSettings": {"alpn": ["h2"], "certificates": [{"certificateFile": cert, "keyFile": key}]},
    });
    let p = free_port();
    expect_traffic(
        "xhttp-tls",
        vless_server(p, stream.clone(), "none"),
        format!("vless://{UUID}@127.0.0.1:{p}?type=xhttp&path=%2Fx&mode=stream-up&security=tls&sni=example.com&alpn=h2&pcs={hash}#xt"),
        false,
    )
    .await;
    // A wrong pin must stop the connection.
    let p = free_port();
    let wrong = "00".repeat(32);
    let (ok, _) = run_case(
        "xhttp-wrong-pin",
        vless_server(p, stream, "none"),
        format!("vless://{UUID}@127.0.0.1:{p}?type=xhttp&path=%2Fx&mode=stream-up&security=tls&sni=example.com&alpn=h2&pcs={wrong}#xw"),
        false,
    )
    .await;
    assert!(
        !ok,
        "traffic flowed although the pinned certificate did not match"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn mkcp_with_seed_and_header() {
    skip_without_engines!();
    let mut failed = Vec::new();
    for (name, extra, masks) in [
        (
            "kcp-seed",
            "&seed=pw-kcp-1234",
            json!([{"type": "mkcp-legacy", "settings": {"value": "pw-kcp-1234"}}]),
        ),
        (
            "kcp-seed-header",
            "&seed=pw-kcp-1234&headerType=wechat-video",
            json!([
                {"type": "mkcp-legacy", "settings": {"value": "pw-kcp-1234"}},
                {"type": "mkcp-legacy", "settings": {"header": "wechat"}},
            ]),
        ),
    ] {
        let p = free_port();
        let s = vless_server(
            p,
            json!({"network": "kcp", "kcpSettings": {}, "finalmask": {"udp": masks}}),
            "none",
        );
        let (ok, logs) = run_case(
            name,
            s,
            format!("vless://{UUID}@127.0.0.1:{p}?type=kcp{extra}#k"),
            true,
        )
        .await;
        eprintln!("RESULT {name} {ok}");
        if !ok {
            failed.push(logs);
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n====\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_http_header_obfuscation() {
    skip_without_engines!();
    let p = free_port();
    let header = json!({"type": "http", "request": {
        "version": "1.1", "method": "GET", "path": ["/a"], "headers": {"Host": ["front.example"]}}});
    let s = vless_server(
        p,
        json!({"network": "tcp", "rawSettings": {"header": header}}),
        "none",
    );
    expect_traffic(
        "tcp-http",
        s,
        format!(
            "vless://{UUID}@127.0.0.1:{p}?type=tcp&headerType=http&path=%2Fa&host=front.example#h"
        ),
        false,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vless_post_quantum_encryption() {
    skip_without_engines!();
    let out = Command::new(xray_bin().unwrap())
        .arg("vlessenc")
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    // First pair printed is the X25519 one (shorter), the second is ML-KEM-768 only.
    let pick = |prefix: &str, nth: usize| {
        text.lines()
            .filter(|l| l.trim_start().starts_with(prefix))
            .nth(nth)
            .map(|l| l.split('"').nth(3).unwrap().to_string())
            .unwrap()
    };
    for nth in [0, 1] {
        let (dec, enc) = (pick("\"decryption\"", nth), pick("\"encryption\"", nth));
        let p = free_port();
        let s = vless_server(p, json!({"network": "tcp"}), &dec);
        expect_traffic(
            &format!("vlessenc-{nth}"),
            s,
            format!("vless://{UUID}@127.0.0.1:{p}?type=tcp&encryption={enc}#e"),
            false,
        )
        .await;
    }
}
