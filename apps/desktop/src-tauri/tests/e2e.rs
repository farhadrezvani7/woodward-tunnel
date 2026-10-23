//! The desktop application layer against a real sing-box: import an ss:// link, connect, check
//! that traffic flows, disconnect. This drives `Backend`, the exact code the Tauri commands call.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core_app::HttpFetcher;
use core_engine::runner::Binaries;
use core_engine::{probe, sidecar::*};
use core_log::Redactor;
use core_store::MemorySecretStore;
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wt_desktop::backend::{Backend, BackendConfig, Settings, StatusDto};

fn sing_box() -> PathBuf {
    std::env::var_os("WT_SING_BOX").map(PathBuf::from).unwrap_or_else(|| "sing-box".into())
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn http_server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 256];
                let _ = s.read(&mut b).await;
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            });
        }
    });
    port
}

fn have_engine() -> bool {
    std::process::Command::new(sing_box()).arg("version").output().is_ok()
}

struct Env {
    backend: Arc<Backend>,
    seen: Arc<Mutex<Vec<StatusDto>>>,
    _server: Sidecar,
    _dir: PathBuf,
    ss_port: u16,
}

async fn setup(tag: &str, settings: Settings, probe_addr: Option<SocketAddr>, server_extra: serde_json::Value) -> Env {
    let dir = std::env::temp_dir().join(format!("wt-desktop-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ss_port = free_port();
    let mut direct = json!({"type":"direct","tag":"direct"});
    if let Some(o) = server_extra.as_object() {
        for (k, v) in o {
            direct[k] = v.clone();
        }
    }
    let srv = json!({"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":ss_port,"method":"aes-256-gcm","password":"pw-desktop-1234"}],"outbounds":[direct]});
    let f = PrivateFile::write(&dir.join("srv"), "s.json", srv.to_string().as_bytes()).unwrap();
    let server = Sidecar::spawn(SidecarSpec { program: sing_box(), args: vec!["run".into(), "-c".into(), f.path().into()], redactor: Redactor::new() }).unwrap();
    std::mem::forget(f);
    probe::wait_listening(SocketAddr::from(([127, 0, 0, 1], ss_port)), Duration::from_secs(5)).await.unwrap();

    let mut cfg = BackendConfig::new(
        dir.join("app"),
        Binaries { sing_box: sing_box(), awg_socks: "awg-socks".into(), openvpn: "openvpn".into() },
        "memory",
    );
    if let Some(p) = probe_addr {
        cfg.probe = p;
    }
    cfg.ready_timeout = Duration::from_secs(15);
    cfg.initial = Some(settings);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s2 = seen.clone();
    let backend = Backend::new(cfg, Arc::new(MemorySecretStore::default()), Arc::new(HttpFetcher), Arc::new(move |d| s2.lock().unwrap().push(d))).unwrap();
    Env { backend, seen, _server: server, _dir: dir, ss_port }
}

async fn wait_state(env: &Env, want: &str, secs: u64) -> StatusDto {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let s = env.backend.status();
        if s.state == want {
            return s;
        }
        assert!(tokio::time::Instant::now() < end, "timed out waiting for {want}, now {:?}", s);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn import_connect_proxy_mode_and_disconnect() {
    if !have_engine() {
        eprintln!("sing-box not available; skipping");
        return;
    }
    let http = http_server().await;
    let socks = free_port();
    let s = Settings { mode: "proxy".into(), socks_port: socks, ..Settings::default() };
    let env = setup("proxy", s, Some(SocketAddr::from(([127, 0, 0, 1], http))), json!({})).await;
    let b = &env.backend;

    // Import through the real command path, including a bogus line and a subscription URL.
    let text = format!("ss://aes-256-gcm:pw-desktop-1234@127.0.0.1:{}#local\nbogus://x\nhttps://sub.example.com/feed\n", env.ss_port);
    let r = b.import_text(&text).unwrap();
    assert_eq!(r.added.len(), 1, "{r:?}");
    assert_eq!(r.added[0].protocol, "Shadowsocks");
    assert!(!r.problems.is_empty());
    assert_eq!(r.subscription_urls, vec!["https://sub.example.com/feed".to_string()]);
    // The list DTO carries summaries only: no password anywhere in the serialized form.
    let json = serde_json::to_string(&b.list_profiles().unwrap()).unwrap();
    assert!(!json.contains("pw-desktop-1234"), "{json}");

    let id = r.added[0].id.clone();
    b.rename(&id, "Local test").unwrap();
    assert_eq!(b.list_profiles().unwrap()[0].name, "Local test");
    assert!(b.rename(&id, "   ").is_err());

    b.connect(&id).unwrap();
    let st = wait_state(&env, "connected", 25).await;
    assert!(st.connected_since.is_some() && st.message.is_none());
    let body = probe::http_get_via_socks(SocketAddr::from(([127, 0, 0, 1], socks)), "127.0.0.1", http, Duration::from_secs(5)).await.unwrap();
    assert!(body.ends_with("ok"));

    b.disconnect();
    wait_state(&env, "idle", 10).await;
    assert!(probe::wait_listening(SocketAddr::from(([127, 0, 0, 1], socks)), Duration::from_millis(300)).await.is_err());

    // The sink saw the whole journey, never a config or secret.
    let seen = env.seen.lock().unwrap();
    let states: Vec<&str> = seen.iter().map(|s| s.state).collect();
    assert!(states.contains(&"connecting") && states.contains(&"connected") && states.last() == Some(&"idle"), "{states:?}");
    assert!(!format!("{seen:?}").contains("pw-desktop-1234"));
    drop(seen);

    // The diagnostic report after a full connect/disconnect cycle holds no name, host or password.
    let report = b.diagnostic_report();
    assert!(report.contains("diagnostic report"), "{report}");
    for secret in ["Local test", "127.0.0.1", "pw-desktop-1234", &env.ss_port.to_string()] {
        assert!(!report.contains(secret), "report leaks {secret:?}:\n{report}");
    }
    eprintln!("{report}");

    // Settings round-trip and validation.
    let mut st = b.settings();
    st.dns = vec!["not a dns!".into()];
    assert!(b.set_settings(st).is_err());
    b.delete(&id).unwrap();
    assert!(b.list_profiles().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn import_files_reads_only_chosen_regular_files() {
    let dir = std::env::temp_dir().join(format!("wt-desktop-files-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("one.txt");
    std::fs::write(&f, "trojan://pw12345678@a.example.com:443#A\n").unwrap();
    let cfg = BackendConfig::new(dir.join("app"), Binaries { sing_box: "sing-box".into(), awg_socks: "awg-socks".into(), openvpn: "openvpn".into() }, "memory");
    let b = Backend::new(cfg, Arc::new(MemorySecretStore::default()), Arc::new(HttpFetcher), Arc::new(|_| {})).unwrap();
    let r = b.import_files(&[f.clone(), dir.clone(), dir.join("missing.txt")]).unwrap();
    assert_eq!(r.added.len(), 1);
    assert_eq!(r.problems.len(), 2, "directory and missing file are reported, not read");
    // A file over the cap is refused without being read.
    let big = dir.join("big.bin");
    let h = std::fs::File::create(&big).unwrap();
    h.set_len(wt_desktop::backend::MAX_FILE_BYTES + 1).unwrap();
    let r = b.import_files(&[big]).unwrap();
    assert!(r.added.is_empty() && r.problems.len() == 1);
}

/// System tunnel. Needs CAP_NET_ADMIN and /dev/net/tun plus internet; opt in with WT_TUN_TEST=1.
#[tokio::test(flavor = "multi_thread")]
async fn tun_mode_connects_when_privileged() {
    if std::env::var_os("WT_TUN_TEST").is_none() || !have_engine() {
        eprintln!("WT_TUN_TEST not set or sing-box missing; skipping");
        return;
    }
    let iface = std::env::var("WT_TUN_BIND_IFACE").unwrap_or_else(|_| "eth0".into());
    let s = Settings { mode: "tun".into(), ..Settings::default() };
    let env = setup("tun", s, Some(SocketAddr::from(([1, 1, 1, 1], 443))), json!({"bind_interface": iface})).await;
    let b = &env.backend;
    let id = b.import_text(&format!("ss://aes-256-gcm:pw-desktop-1234@127.0.0.1:{}#tun", env.ss_port)).unwrap().added[0].id.clone();
    match b.connect(&id) {
        Ok(()) => {}
        Err(e) => panic!("connect refused: {} {}", e.code, e.detail),
    }
    let st = wait_state(&env, "connected", 40).await;
    eprintln!("TUN connected: {st:?}");
    b.disconnect();
    wait_state(&env, "idle", 15).await;
}

// ---- AmneziaWG through the Backend ------------------------------------------------------------

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn plain_backend(tag: &str, bins: Binaries, settings: Settings, probe: Option<SocketAddr>) -> (Arc<Backend>, PathBuf) {
    let dir = std::env::temp_dir().join(format!("wt-desktop-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut cfg = BackendConfig::new(dir.join("app"), bins, "memory");
    if let Some(p) = probe {
        cfg.probe = p;
    }
    cfg.ready_timeout = Duration::from_secs(15);
    cfg.initial = Some(settings);
    let b = Backend::new(cfg, Arc::new(MemorySecretStore::default()), Arc::new(HttpFetcher), Arc::new(|_| {})).unwrap();
    (b, dir)
}

async fn wait_backend(b: &Backend, want: &str, secs: u64) {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let s = b.status();
        if s.state == want {
            return;
        }
        assert!(tokio::time::Instant::now() < end, "timed out waiting for {want}, now {s:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Needs WT_AWG_SOCKS (the bundled helper, same file as the `wt-awg-socks` sidecar) and
/// WT_AWG_TESTSERVER (engines/bin/awg-testserver).
#[tokio::test(flavor = "multi_thread")]
async fn amneziawg_conf_through_backend() {
    use std::io::{BufRead, BufReader};
    let (Some(awg), Some(srv)) = (std::env::var_os("WT_AWG_SOCKS"), std::env::var_os("WT_AWG_TESTSERVER")) else {
        eprintln!("WT_AWG_SOCKS / WT_AWG_TESTSERVER not set; skipping");
        return;
    };
    if !have_engine() {
        return;
    }
    let mut child = std::process::Command::new(srv).arg("obfuscated").stdout(std::process::Stdio::piped()).spawn().unwrap();
    let out = child.stdout.take().unwrap();
    let _guard = KillOnDrop(child);
    let line = BufReader::new(out).lines().next().unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    let conf = v["conf"].as_str().unwrap().to_string();

    let socks = free_port();
    let s = Settings { mode: "proxy".into(), socks_port: socks, ..Settings::default() };
    // The probe is the in-tunnel server itself: Connected can only be reached if bytes crossed the tunnel.
    let (b, dir) = plain_backend(
        "awg",
        Binaries { sing_box: sing_box(), awg_socks: awg.into(), openvpn: "openvpn".into() },
        s,
        Some(SocketAddr::from(([10, 0, 0, 1], 8080))),
    );
    let r = b.import_text(&conf).unwrap();
    assert_eq!(r.added.len(), 1, "{:?}", r.problems.iter().map(|p| &p.code).collect::<Vec<_>>());
    assert_eq!(r.added[0].protocol, "AmneziaWG");
    let json = serde_json::to_string(&b.list_profiles().unwrap()).unwrap();
    assert!(!json.contains("PrivateKey") && !json.contains("private_key"));
    b.connect(&r.added[0].id).unwrap();
    wait_backend(&b, "connected", 30).await;
    let body = probe::http_get_via_socks(SocketAddr::from(([127, 0, 0, 1], socks)), "10.0.0.1", 8080, Duration::from_secs(5)).await.unwrap();
    assert!(body.contains("hello-through-awg"), "{body}");
    b.disconnect();
    wait_backend(&b, "idle", 10).await;
    std::fs::remove_dir_all(dir).ok();
}

// ---- QR import --------------------------------------------------------------------------------

fn qr_png(text: &str) -> Vec<u8> {
    let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
    let w = code.width();
    let (scale, quiet) = (8usize, 4usize);
    let side = (w + 2 * quiet) * scale;
    let colors = code.to_colors();
    let mut img = image::GrayImage::from_pixel(side as u32, side as u32, image::Luma([255]));
    for y in 0..w {
        for x in 0..w {
            if colors[y * w + x] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        img.put_pixel(((x + quiet) * scale + dx) as u32, ((y + quiet) * scale + dy) as u32, image::Luma([0]));
                    }
                }
            }
        }
    }
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

#[tokio::test(flavor = "multi_thread")]
async fn qr_image_file_imports_through_backend() {
    let png = qr_png("ss://aes-256-gcm:pw-qr-1234567@qr.example.com:8388#QR-Server");
    let dir = std::env::temp_dir().join(format!("wt-desktop-qr-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("shot.png");
    std::fs::write(&f, &png).unwrap();
    let (b, d2) = plain_backend("qrapp", Binaries { sing_box: "sing-box".into(), awg_socks: "awg-socks".into(), openvpn: "openvpn".into() }, Settings::default(), None);
    // The same entry point the file picker and the drag-drop handler use.
    let r = b.import_files(&[f]).unwrap();
    assert_eq!(r.added.len(), 1, "{:?}", r.problems);
    assert_eq!(r.added[0].name, "QR-Server");
    assert_eq!(r.added[0].protocol, "Shadowsocks");
    // Not a QR: reported with both languages, nothing added.
    let blank = dir.join("blank.png");
    let img = image::GrayImage::from_pixel(64, 64, image::Luma([255]));
    img.save(&blank).unwrap();
    let r = b.import_files(&[blank]).unwrap();
    assert!(r.added.is_empty());
    assert!(!r.problems.is_empty() || r.duplicates == 0);
    std::fs::remove_dir_all(dir).ok();
    std::fs::remove_dir_all(d2).ok();
}

// ---- server given by hostname -------------------------------------------------------------------

/// WT_REMOTE_SS="host:port": a shadowsocks server (password pw-desktop-1234, aes-256-gcm) reachable only
/// by name, e.g. a docker network alias. WT_REMOTE_MODE=tun runs it as a system tunnel.
#[tokio::test(flavor = "multi_thread")]
async fn server_by_hostname() {
    let Ok(remote) = std::env::var("WT_REMOTE_SS") else {
        eprintln!("WT_REMOTE_SS not set; skipping");
        return;
    };
    let tun = std::env::var("WT_REMOTE_MODE").as_deref() == Ok("tun");
    let socks = free_port();
    let s = Settings { mode: if tun { "tun" } else { "proxy" }.into(), socks_port: socks, ..Settings::default() };
    let (b, dir) = plain_backend("host", Binaries { sing_box: sing_box(), awg_socks: "awg-socks".into(), openvpn: "openvpn".into() }, s, Some(SocketAddr::from(([1, 1, 1, 1], 443))));
    let id = b.import_text(&format!("ss://aes-256-gcm:pw-desktop-1234@{remote}#by-name")).unwrap().added[0].id.clone();
    assert!(b.list_profiles().unwrap()[0].host.chars().any(|c| c.is_alphabetic()));
    b.connect(&id).unwrap();
    wait_backend(&b, "connected", 40).await;
    eprintln!("hostname server connected (tun={tun})");
    b.disconnect();
    wait_backend(&b, "idle", 15).await;
    std::fs::remove_dir_all(dir).ok();
}
