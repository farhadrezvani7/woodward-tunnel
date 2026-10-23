//! Container test driver for OpenVPN: import a real .ovpn through the importer, start it through the
//! runner, prove that a host reachable only through the VPN answers, then stop.
//! usage: ovpn_e2e <profile.ovpn> <web host:port>   (needs NET_ADMIN, /dev/net/tun and the openvpn binary)
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_engine::runner::{start, Binaries, StartOptions};
use core_engine::Mode;
use core_log::Redactor;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

fn get(web: SocketAddr) -> Result<String, String> {
    let mut s =
        TcpStream::connect_timeout(&web, Duration::from_secs(3)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    s.write_all(b"GET / HTTP/1.0\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut b = String::new();
    s.read_to_string(&mut b).map_err(|e| e.to_string())?;
    Ok(b.rsplit("\r\n\r\n").next().unwrap_or("").trim().to_string())
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&a[1]).unwrap();
    let web: SocketAddr = a[2].parse().unwrap();
    let analysis = core_import::analyze(&text);
    let profile = analysis
        .profiles
        .first()
        .unwrap_or_else(|| panic!("import failed: {:?}", analysis.issues))
        .clone();
    println!(
        "IMPORTED protocol={} host={}",
        profile.protocol.display_name(),
        profile.host
    );
    println!("DIRECT_BEFORE_REACHABLE={}", get(web).is_ok());
    let red = Redactor::new();
    red.register_profile(&profile);
    let opts = StartOptions {
        mode: Mode::Tun,
        dns: vec![],
        work_dir: std::env::temp_dir().join("wt-ovpn-e2e"),
        bins: Binaries::discover(),
        redactor: red,
        ready_timeout: Duration::from_secs(40),
    };
    let mut t = start(&profile, &opts)
        .await
        .unwrap_or_else(|e| panic!("start failed: {e}\n--- engine tail ---\n{}", e.tail()));
    println!("CONNECTED");
    println!(
        "VIA_VPN_SEEN_AS={}",
        get(web).unwrap_or_else(|e| format!("ERROR {e}"))
    );
    let logs = t
        .drain_lines()
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    let key = profile
        .secrets
        .get("key")
        .map(|k| k.expose().lines().nth(1).unwrap_or("").to_string())
        .unwrap_or_default();
    println!(
        "PRIVATE_KEY_IN_LOGS={}",
        !key.is_empty() && logs.contains(&key)
    );
    t.stop().await;
    println!("STOPPED");
    println!("DIRECT_AFTER_REACHABLE={}", get(web).is_ok());
}
