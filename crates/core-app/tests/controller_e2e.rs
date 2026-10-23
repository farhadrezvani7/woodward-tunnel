//! The whole app stack against real sing-box processes: import a link, connect, verify, survive a
//! network change, report failures in plain language, and disconnect.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_app::{App, Controller, ControllerConfig, HttpFetcher, UiState};
use core_engine::runner::Binaries;
use core_engine::{probe, sidecar::*, Mode};
use core_log::Redactor;
use core_store::MemorySecretStore;
use serde_json::json;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
                let _ = s
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            });
        }
    });
    port
}

async fn wait_for(
    rx: &mut watch::Receiver<core_app::Status>,
    want: UiState,
    secs: u64,
) -> core_app::Status {
    let r = tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            let s = rx.borrow().clone();
            if s.state == want {
                return s;
            }
            if rx.changed().await.is_err() {
                panic!("controller stopped");
            }
        }
    })
    .await;
    r.unwrap_or_else(|_| {
        panic!(
            "timed out waiting for {want:?}, now {:?}",
            rx.borrow().state
        )
    })
}

fn build_app(tag: &str) -> (Arc<App>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("wt-ctl-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let app = App::new(
        &dir,
        Arc::new(MemorySecretStore::default()),
        Arc::new(HttpFetcher),
    )
    .unwrap();
    (Arc::new(app), dir)
}

fn cfg(dir: &std::path::Path, socks: u16, probe_port: u16) -> ControllerConfig {
    ControllerConfig {
        mode: Mode::Proxy { socks_port: socks },
        dns: vec![],
        bins: Binaries {
            sing_box: "sing-box".into(),
            awg_socks: "awg-socks".into(),
            openvpn: "openvpn".into(),
        },
        probe: SocketAddr::from(([127, 0, 0, 1], probe_port)),
        ready_timeout: Duration::from_secs(10),
        work_dir: dir.join("run"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_reconnect_and_disconnect() {
    if Command::new("sing-box").arg("version").output().is_err() {
        return;
    }
    let http = http_server().await;
    let ss_port = free_port();
    let (app, dir) = build_app("ok");
    let srv_cfg = json!({"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":ss_port,"method":"aes-256-gcm","password":"pw-ctl-1234"}],"outbounds":[{"type":"direct","tag":"direct"}]});
    let f = PrivateFile::write(&dir.join("srv"), "s.json", srv_cfg.to_string().as_bytes()).unwrap();
    let server = Sidecar::spawn(SidecarSpec {
        program: "sing-box".into(),
        args: vec!["run".into(), "-c".into(), f.path().into()],
        redactor: Redactor::new(),
    })
    .unwrap();
    probe::wait_listening(
        SocketAddr::from(([127, 0, 0, 1], ss_port)),
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let report = app
        .import_text(
            &format!("ss://aes-256-gcm:pw-ctl-1234@127.0.0.1:{ss_port}#local"),
            "",
        )
        .unwrap();
    let id = report.added[0].id.clone();
    let socks = free_port();
    let c = Controller::spawn(app.clone(), cfg(&dir, socks, http));
    let mut rx = c.status();

    c.connect(&id);
    let s = wait_for(&mut rx, UiState::Connected, 20).await;
    assert!(s.connected_since.is_some() && s.message.is_none());
    let body = probe::http_get_via_socks(
        SocketAddr::from(([127, 0, 0, 1], socks)),
        "127.0.0.1",
        http,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(body.ends_with("ok"));

    // Network change: tunnel is torn down and rebuilt, ending Connected again.
    c.network_changed();
    wait_for(&mut rx, UiState::Reconnecting, 10).await;
    wait_for(&mut rx, UiState::Connected, 20).await;

    c.disconnect();
    let s = wait_for(&mut rx, UiState::Idle, 10).await;
    assert!(s.connected_since.is_none());
    let log = c.recent_log().join("\n");
    assert!(
        log.contains("sing-box"),
        "engine output should be kept for diagnostics: {log}"
    );
    assert!(
        !log.contains("pw-ctl-1234"),
        "password leaked into the diagnostic log"
    );
    // Port is released after disconnect.
    assert!(probe::wait_listening(
        SocketAddr::from(([127, 0, 0, 1], socks)),
        Duration::from_millis(300)
    )
    .await
    .is_err());
    drop(server);
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_server_is_reported_in_plain_language() {
    if Command::new("sing-box").arg("version").output().is_err() {
        return;
    }
    let http = http_server().await;
    let dead = free_port();
    let (app, dir) = build_app("dead");
    let id = app
        .import_text(
            &format!("ss://aes-256-gcm:pw-ctl-1234@127.0.0.1:{dead}#dead"),
            "",
        )
        .unwrap()
        .added[0]
        .id
        .clone();
    let c = Controller::spawn(app, cfg(&dir, free_port(), http));
    let mut rx = c.status();
    c.connect(&id);
    let s = wait_for(&mut rx, UiState::Reconnecting, 20).await;
    let msg = s.message.expect("message while retrying");
    assert!(msg.contains("سرور"), "{msg}");
    c.disconnect();
    wait_for(&mut rx, UiState::Idle, 10).await;
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_profile_id_fails_without_retry() {
    let (app, dir) = build_app("bad");
    let c = Controller::spawn(app, cfg(&dir, free_port(), 9));
    let mut rx = c.status();
    c.connect("does-not-exist");
    let s = wait_for(&mut rx, UiState::Failed, 5).await;
    assert!(s.message.unwrap().contains("کانفیگ"));
    std::fs::remove_dir_all(dir).ok();
}
