//! Container test driver: real TUN tunnel, proof that traffic leaves through the VPN server,
//! kill-switch behaviour when the tunnel dies, and automatic recovery. Linux, needs NET_ADMIN.
//! usage: tunnel_e2e <share link> <web host:port> <server ip>
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_app::{
    App, Controller, ControllerConfig, ControllerOptions, HttpFetcher, ProbeMode, UiState,
};
use core_engine::runner::Binaries;
use core_engine::Mode;
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

fn nft_active() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", "wt_killswitch"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn check(name: &str, ok: bool, fails: &mut u32) {
    println!("CHECK {name}={}", if ok { "PASS" } else { "FAIL" });
    if !ok {
        *fails += 1;
    }
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (link, web) = (&a[1], a[2].parse::<SocketAddr>().unwrap());
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
    // Leak protection is part of the controller now: nothing is applied by hand here.
    let mut opts = ControllerOptions::recommended(&cfg);
    opts.probe_mode = ProbeMode::Tcp; // the test network has no DNS-over-HTTPS reachable
    opts.health_interval = None;
    let c = Controller::spawn_with(app, cfg, opts);
    let mut rx = c.status();
    let mut fails = 0u32;

    check("no_rules_before_connect", !nft_active(), &mut fails);
    c.connect(&id);
    wait(&mut rx, UiState::Connected, 40).await;
    println!("CONNECTED");
    check("rules_after_verified", nft_active(), &mut fails);
    check("status_flag", rx.borrow().kill_switch_active, &mut fails);
    let seen_as = get(web, Duration::from_secs(5));
    println!("VIA_TUNNEL_SEEN_AS={seen_as:?}");
    check(
        "traffic_through_tunnel_with_rules",
        seen_as.is_ok(),
        &mut fails,
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
    // The engine dies without warning (as if the tunnel dropped).
    let _ = Command::new("pkill")
        .args(["-9", "-f", "sing-box run"])
        .status();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let leaked = get(web, Duration::from_secs(2));
    check("blocked_while_tunnel_down", leaked.is_err(), &mut fails);
    check("rules_kept_while_down", nft_active(), &mut fails);
    wait(&mut rx, UiState::Connected, 60).await;
    {
        let h = seen.lock().unwrap();
        check(
            "reconnect_seen_with_rules",
            h.iter()
                .any(|st| st.state == UiState::Reconnecting && st.kill_switch_active),
            &mut fails,
        );
    }
    check("rules_after_recovery", nft_active(), &mut fails);
    let again = get(web, Duration::from_secs(5));
    check("recovered_through_tunnel", again.is_ok(), &mut fails);

    c.disconnect();
    wait(&mut rx, UiState::Idle, 15).await;
    check("rules_removed_on_disconnect", !nft_active(), &mut fails);
    check(
        "status_flag_cleared",
        !rx.borrow().kill_switch_active,
        &mut fails,
    );
    println!("RESULT fails={fails}");
    if fails > 0 {
        std::process::exit(1);
    }
}
