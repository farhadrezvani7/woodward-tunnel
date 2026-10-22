//! AmneziaWG through the real stack: Go test server -> awg-socks helper -> sing-box proxy mode.
//! Needs the helper binaries; set WT_AWG_SOCKS and WT_AWG_TESTSERVER (built by `scripts/build-engines.sh`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_engine::runner::{start, Binaries, StartOptions};
use core_engine::{probe, Mode};
use core_log::Redactor;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn run(kind: &str) {
    let (Ok(awg), Ok(srv)) = (
        std::env::var("WT_AWG_SOCKS"),
        std::env::var("WT_AWG_TESTSERVER"),
    ) else {
        eprintln!("helper binaries not configured; skipping");
        return;
    };
    if Command::new("sing-box").arg("version").output().is_err() {
        return;
    }
    let mut child = Command::new(srv)
        .arg(kind)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let _server = KillOnDrop(child);
    let line = BufReader::new(stdout).lines().next().unwrap().unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    let conf = v["conf"].as_str().unwrap();
    let a = core_import::analyze(conf);
    let profile = a
        .profiles
        .first()
        .unwrap_or_else(|| panic!("{:?}", a.issues))
        .clone();
    assert_eq!(profile.protocol, core_model::Protocol::AmneziaWg);

    let socks = free_port();
    let dir = std::env::temp_dir().join(format!("wt-awg-{kind}-{}", std::process::id()));
    let red = Redactor::new();
    red.register_profile(&profile);
    let opts = StartOptions {
        mode: Mode::Proxy { socks_port: socks },
        dns: vec![],
        work_dir: dir.clone(),
        bins: Binaries {
            sing_box: "sing-box".into(),
            awg_socks: awg.into(),
            openvpn: "openvpn".into(),
        },
        redactor: red,
        ready_timeout: Duration::from_secs(15),
    };
    let mut t = start(&profile, &opts).await.unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{socks}").parse().unwrap();
    let mut body = String::new();
    for _ in 0..20 {
        if let Ok(b) =
            probe::http_get_via_socks(addr, "10.0.0.1", 8080, Duration::from_secs(3)).await
        {
            if b.contains("hello-through-awg") {
                body = b;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let logs = t
        .drain_lines()
        .into_iter()
        .map(|(n, l)| format!("{n}: {l}"))
        .collect::<Vec<_>>()
        .join("\n");
    t.stop().await;
    std::fs::remove_dir_all(dir).ok();
    assert!(
        body.contains("hello-through-awg"),
        "no data through tunnel\n{logs}"
    );
    let pk = profile.secrets["private_key"].expose();
    assert!(!logs.contains(pk), "private key leaked in logs");
}

#[tokio::test(flavor = "multi_thread")]
async fn amneziawg_obfuscated_through_runner() {
    run("obfuscated").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_wireguard_conf_over_awg_helper_is_not_used() {
    // A plain WireGuard profile is handled by sing-box directly; this guards the engine selection.
    let a = core_import::analyze("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = 127.0.0.1:1\nAllowedIPs = 0.0.0.0/0\n");
    assert_eq!(
        a.profiles[0].protocol.engine(),
        core_model::EngineKind::SingBox
    );
}
