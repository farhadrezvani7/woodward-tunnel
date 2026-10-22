//! Container test driver: real TUN tunnel, proof that traffic leaves through the VPN server,
//! kill-switch behaviour when the tunnel dies, and automatic recovery. Linux, needs NET_ADMIN.
//! usage: tunnel_e2e <share link> <web host:port> <server ip>
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core_app::{App, Controller, ControllerConfig, HttpFetcher, UiState};
use core_engine::runner::Binaries;
use core_engine::Mode;
use core_policy::KillSwitch;
use core_store::MemorySecretStore;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

fn get(web: SocketAddr, limit: Duration) -> Result<String, String> {
    let mut s = TcpStream::connect_timeout(&web, limit).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(limit)).ok();
    s.write_all(b"GET / HTTP/1.0\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut b = String::new();
    s.read_to_string(&mut b).map_err(|e| e.to_string())?;
    Ok(b.rsplit("\r\n\r\n").next().unwrap_or("").trim().to_string())
}

async fn wait(rx: &mut tokio::sync::watch::Receiver<core_app::Status>, want: UiState, secs: u64) {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while rx.borrow().state != want {
            rx.changed().await.unwrap();
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timeout waiting for {want:?}, state {:?} msg {:?}",
            rx.borrow().state,
            rx.borrow().message
        )
    });
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (link, web, server_ip) = (
        &a[1],
        a[2].parse::<SocketAddr>().unwrap(),
        a[3].parse().unwrap(),
    );
    let dir = std::env::temp_dir().join("wt-tun-e2e");
    let app = Arc::new(
        App::new(
            &dir,
            Arc::new(MemorySecretStore::default()),
            Arc::new(HttpFetcher),
        )
        .unwrap(),
    );
    let id = app.import_text(link, "").unwrap().added[0].id.clone();
    let cfg = ControllerConfig {
        mode: Mode::Tun,
        dns: vec![],
        bins: Binaries::discover(),
        probe: web,
        ready_timeout: Duration::from_secs(20),
        work_dir: dir.join("run"),
    };
    let c = Controller::spawn(app, cfg);
    let mut rx = c.status();

    println!(
        "DIRECT_BEFORE_VPN_REACHABLE={}",
        get(web, Duration::from_secs(3)).is_ok()
    );
    c.connect(&id);
    wait(&mut rx, UiState::Connected, 40).await;
    println!("CONNECTED");
    println!(
        "VIA_TUNNEL_SEEN_AS={}",
        get(web, Duration::from_secs(5)).unwrap()
    );

    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    {
        let (seen, mut w) = (seen.clone(), c.status());
        tokio::spawn(async move {
            while w.changed().await.is_ok() {
                let st = w.borrow().clone();
                seen.lock().unwrap().push(st);
            }
        });
    }
    // Leak protection on, then kill the engine as if the tunnel dropped.
    KillSwitch {
        tun_iface: "wt0".into(),
        server_ips: vec![server_ip],
        allow_lan: false,
    }
    .apply()
    .unwrap();
    println!(
        "TUNNEL_STILL_WORKS_WITH_KILLSWITCH={}",
        get(web, Duration::from_secs(5)).is_ok()
    );
    let _ = Command::new("pkill")
        .args(["-9", "-f", "sing-box run"])
        .status();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let leaked = get(web, Duration::from_secs(2));
    println!("KILLSWITCH_BLOCKED={}", leaked.is_err());
    // Recovery can be quick (the server stays reachable under the kill switch), so look at the recorded history.
    wait(&mut rx, UiState::Connected, 60).await;
    {
        let h = seen.lock().unwrap();
        println!(
            "RECONNECTING_SEEN={} messages={:?}",
            h.iter().any(|st| st.state == UiState::Reconnecting),
            h.iter().filter_map(|st| st.message.clone()).next()
        );
    }
    KillSwitch::remove().unwrap();
    println!(
        "RECOVERED VIA_TUNNEL_SEEN_AS={}",
        get(web, Duration::from_secs(5)).unwrap()
    );
    c.disconnect();
    wait(&mut rx, UiState::Idle, 15).await;
    println!(
        "DISCONNECTED DIRECT_REACHABLE={}",
        get(web, Duration::from_secs(3)).is_ok()
    );
}
