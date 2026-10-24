//! Controller behaviour under hostile timing, using a scripted fake engine (no root, no network):
//! cancellable start, rapid connect/disconnect, network-change storms, retry sleep, health probe,
//! leak protection lifecycle (through a recording firewall), failure classification.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(unix)]

use core_app::{App, Controller, ControllerConfig, ControllerOptions, ProbeMode, Status, UiState};
use core_engine::runner::Binaries;
use core_engine::Mode;
use core_policy::{CmdOutput, CommandRunner, Firewall, Os, PolicyError};
use core_store::MemorySecretStore;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

struct Fixture {
    dir: PathBuf,
    app: Arc<App>,
    probe: SocketAddr,
    _listener: tokio::task::JoinHandle<()>,
}

/// Fake `sing-box`. Behaviour is chosen by the file `mode` next to the script:
/// `hang` never becomes ready, `ready` prints the ready line and runs until `die` appears
/// (then fails with a refused-connection message), `fail` exits at once with an auth error,
/// `flood` prints 20000 lines before becoming ready.
/// Every start appends a line to `starts` and records its pid in `pids`.
fn write_engine(dir: &Path) -> PathBuf {
    let script = dir.join("fake-sing-box");
    std::fs::write(
        &script,
        r#"#!/bin/sh
D="$(dirname "$0")"
if [ "$1" = version ]; then echo "sing-box version 1.14.2"; exit 0; fi
echo "$$" >> "$D/pids"
echo start >> "$D/starts"
trap 'exit 0' TERM
case "$(cat "$D/mode")" in
  hang) while true; do sleep 0.1; done ;;
  fail) echo "FATAL start service: authentication failed"; exit 1 ;;
  flood) i=0; while [ $i -lt 20000 ]; do echo "noise line $i"; i=$((i+1)); done; echo "sing-box started"; while true; do sleep 0.1; done ;;
  *) echo "sing-box started"
     while [ ! -f "$D/die" ]; do sleep 0.1; done
     echo "ERROR dial tcp 203.0.113.9:443: connect: connection refused"; exit 3 ;;
esac
"#,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("mode"), "ready").unwrap();
    script
}

#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<String>>,
    fail_apply: Mutex<bool>,
    active: Mutex<bool>,
}
impl CommandRunner for Recorder {
    fn run(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&str>,
    ) -> Result<CmdOutput, PolicyError> {
        let text = stdin.unwrap_or("");
        let kind = if args.first().map(|a| a.as_str()) == Some("list") {
            "list"
        } else if text.contains("policy drop") {
            "apply"
        } else {
            "remove"
        };
        self.calls
            .lock()
            .unwrap()
            .push(format!("{program}:{kind}:{}", text.replace('\n', "|")));
        let mut ok = true;
        match kind {
            "apply" => {
                if *self.fail_apply.lock().unwrap() {
                    ok = false;
                } else {
                    *self.active.lock().unwrap() = true;
                }
            }
            "remove" => *self.active.lock().unwrap() = false,
            _ => ok = *self.active.lock().unwrap(),
        }
        Ok(CmdOutput {
            success: ok,
            stdout: String::new(),
            stderr: if ok {
                String::new()
            } else if kind == "list" {
                "Error: No such file or directory".into()
            } else {
                "denied".into()
            },
        })
    }
}
impl Recorder {
    fn kinds(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.split(':').nth(1).unwrap().to_string())
            .filter(|k| k != "list")
            .collect()
    }
    fn last_apply(&self) -> String {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|c| c.contains(":apply:"))
            .cloned()
            .unwrap_or_default()
    }
}

async fn fixture(tag: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("wt-robust-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let app = App::new(
        &dir.join("data"),
        Arc::new(MemorySecretStore::default()),
        Arc::new(core_app::HttpFetcher),
    )
    .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let probe = l.local_addr().unwrap();
    let h = tokio::spawn(async move { while l.accept().await.is_ok() {} });
    Fixture {
        dir,
        app: Arc::new(app),
        probe,
        _listener: h,
    }
}

impl Fixture {
    fn profile(&self, n: u8) -> String {
        self.app
            .import_text(
                &format!("ss://aes-256-gcm:robust-pw-{n}-1234@203.0.113.{n}:8388#p{n}"),
                "",
            )
            .unwrap()
            .added[0]
            .id
            .clone()
    }

    fn spawn(&self, ks: Option<Arc<Recorder>>) -> Controller {
        self.spawn_with(ks, |_, _| {})
    }

    fn spawn_with(
        &self,
        ks: Option<Arc<Recorder>>,
        tweak: impl FnOnce(&mut ControllerConfig, &mut ControllerOptions),
    ) -> Controller {
        let mut cfg = ControllerConfig {
            mode: Mode::Tun,
            dns: vec![],
            bins: Binaries {
                sing_box: self.dir.join("fake-sing-box"),
                awg_socks: "awg-socks".into(),
                openvpn: "openvpn".into(),
            },
            probe: self.probe,
            ready_timeout: Duration::from_secs(30),
            work_dir: self.dir.join("run"),
        };
        let mut o = ControllerOptions::recommended(&cfg);
        o.probe_mode = ProbeMode::Tcp;
        o.health_interval = None;
        match ks {
            Some(r) => {
                o.kill_switch.enabled = true;
                o.kill_switch.bootstrap_dns = vec!["192.0.2.53".parse().unwrap()];
                o.kill_switch.firewall = Some(Arc::new(Firewall::with_runner(
                    Os::Linux,
                    r,
                    self.dir.join("ks"),
                )));
            }
            None => o.kill_switch.enabled = false,
        }
        o.kill_switch.check_leftover = false;
        tweak(&mut cfg, &mut o);
        Controller::spawn_with(self.app.clone(), cfg, o)
    }

    fn starts(&self) -> usize {
        std::fs::read_to_string(self.dir.join("starts"))
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    fn pids(&self) -> Vec<u32> {
        std::fs::read_to_string(self.dir.join("pids"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.parse().ok())
            .collect()
    }

    fn live_engines(&self) -> usize {
        self.pids()
            .into_iter()
            .filter(|p| {
                std::fs::read_to_string(format!("/proc/{p}/stat"))
                    .map(|s| !s.contains(") Z "))
                    .unwrap_or(false)
            })
            .count()
    }

    fn run_files(&self) -> Vec<String> {
        std::fs::read_dir(self.dir.join("run"))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.starts_with('p'))
                    .collect()
            })
            .unwrap_or_default()
    }
}

async fn wait_until(
    rx: &mut watch::Receiver<Status>,
    secs: u64,
    what: &str,
    f: impl Fn(&Status) -> bool,
) -> Status {
    let r = tokio::time::timeout(Duration::from_secs(secs), async {
        loop {
            let s = rx.borrow().clone();
            if f(&s) {
                return s;
            }
            rx.changed().await.expect("controller stopped");
        }
    })
    .await;
    r.unwrap_or_else(|_| {
        panic!(
            "timed out waiting for {what}; now {:?}",
            rx.borrow().clone()
        )
    })
}

async fn wait_state(rx: &mut watch::Receiver<Status>, st: UiState, secs: u64) -> Status {
    wait_until(rx, secs, &format!("{st:?}"), move |s| s.state == st).await
}

async fn settle_processes(fx: &Fixture) {
    for _ in 0..60 {
        if fx.live_engines() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("engine processes still running: {:?}", fx.pids());
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_during_a_hanging_start_is_prompt_and_cleans_up() {
    let fx = fixture("hang").await;
    write_engine(&fx.dir);
    std::fs::write(fx.dir.join("mode"), "hang").unwrap();
    let id = fx.profile(1);
    let c = fx.spawn(None);
    let mut rx = c.status();
    c.connect(&id);
    wait_state(&mut rx, UiState::Connecting, 5).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(fx.live_engines(), 1);
    let t0 = Instant::now();
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
    // ready_timeout is 30 s: before the fix this took that long.
    assert!(t0.elapsed() < Duration::from_secs(6), "{:?}", t0.elapsed());
    settle_processes(&fx).await;
    assert!(fx.run_files().is_empty(), "{:?}", fx.run_files());
}

#[tokio::test(flavor = "multi_thread")]
async fn connecting_to_another_profile_cancels_the_pending_start() {
    let fx = fixture("switch").await;
    write_engine(&fx.dir);
    std::fs::write(fx.dir.join("mode"), "hang").unwrap();
    let (a, b) = (fx.profile(1), fx.profile(2));
    let c = fx.spawn(None);
    let mut rx = c.status();
    c.connect(&a);
    wait_state(&mut rx, UiState::Connecting, 5).await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    std::fs::write(fx.dir.join("mode"), "ready").unwrap();
    c.connect(&b);
    let s = wait_until(&mut rx, 15, "connected to b", |s| {
        s.state == UiState::Connected && s.profile_id.as_deref() == Some(&b)
    })
    .await;
    assert!(s.message.is_none());
    assert_eq!(fx.live_engines(), 1, "the first engine was stopped");
    // Connecting to the same profile again is a no-op, not a restart.
    let starts = fx.starts();
    c.connect(&b);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(fx.starts(), starts);
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
    settle_processes(&fx).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn rapid_connect_disconnect_100_times_leaves_nothing_behind() {
    let fx = fixture("rapid").await;
    write_engine(&fx.dir);
    let id = fx.profile(1);
    let c = fx.spawn(None);
    let mut rx = c.status();
    for i in 0..100u32 {
        c.connect(&id);
        tokio::time::sleep(Duration::from_millis(u64::from(i % 7) * 15)).await;
        c.disconnect();
    }
    wait_state(&mut rx, UiState::Idle, 60).await;
    settle_processes(&fx).await;
    assert!(fx.run_files().is_empty(), "{:?}", fx.run_files());
    c.connect(&id);
    wait_state(&mut rx, UiState::Connected, 20).await;
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
    settle_processes(&fx).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn network_change_storm_causes_one_restart() {
    let fx = fixture("storm").await;
    write_engine(&fx.dir);
    let id = fx.profile(1);
    let c = fx.spawn(None);
    let mut rx = c.status();
    c.connect(&id);
    wait_state(&mut rx, UiState::Connected, 20).await;
    assert_eq!(fx.starts(), 1);
    for _ in 0..500 {
        c.network_changed();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    for _ in 0..500 {
        c.network_changed();
    }
    wait_until(&mut rx, 20, "reconnected", |s| {
        s.state == UiState::Connected
    })
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let starts = fx.starts();
    assert!(
        (2..=3).contains(&starts),
        "1000 events must coalesce into one or two restarts, got {starts} starts"
    );
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_during_retry_sleep_never_starts_again() {
    let fx = fixture("retry").await;
    write_engine(&fx.dir);
    std::fs::write(fx.dir.join("mode"), "fail").unwrap();
    let id = fx.profile(1);
    let c = fx.spawn(None);
    let mut rx = c.status();
    c.connect(&id);
    let s = wait_until(&mut rx, 10, "failure shown", |s| s.failure_code.is_some()).await;
    // The engine said "authentication failed": the user gets the specific reason, and since
    // wrong credentials cannot fix themselves it is not retried.
    assert_eq!(s.failure_code.as_deref(), Some("auth"), "{s:?}");
    assert_eq!(s.state, UiState::Failed);
    let starts = fx.starts();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(fx.starts(), starts, "an auth failure must not be retried");
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_while_waiting_to_retry() {
    let fx = fixture("retry2").await;
    write_engine(&fx.dir);
    let id = fx.profile(1);
    let c = fx.spawn(None);
    let mut rx = c.status();
    c.connect(&id);
    wait_state(&mut rx, UiState::Connected, 20).await;
    // Server side drops: log says connection refused -> retryable -> Reconnecting.
    std::fs::write(fx.dir.join("die"), "").unwrap();
    let s = wait_state(&mut rx, UiState::Reconnecting, 10).await;
    assert_eq!(s.failure_code.as_deref(), Some("server"));
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 5).await;
    let starts = fx.starts();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        fx.starts(),
        starts,
        "a retry fired after the user disconnected"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_lifecycle() {
    let fx = fixture("ks").await;
    write_engine(&fx.dir);
    let id = fx.profile(1);
    let rec = Arc::new(Recorder::default());
    let c = fx.spawn(Some(rec.clone()));
    let mut rx = c.status();
    c.connect(&id);
    let s = wait_state(&mut rx, UiState::Connected, 20).await;
    assert!(s.kill_switch_active);
    let ap = rec.last_apply();
    assert!(ap.contains("oifname \"wt0\" accept"), "{ap}");
    assert!(ap.contains("203.0.113.1"), "server address allowed: {ap}");
    assert!(
        !ap.contains("dport 53"),
        "no DNS exception once connected: {ap}"
    );
    assert_eq!(rec.kinds(), ["apply"]);

    // The tunnel dies on its own: rules stay, and are re-applied with the bootstrap DNS
    // exception while reconnecting, then without it.
    std::fs::write(fx.dir.join("die"), "").unwrap();
    wait_state(&mut rx, UiState::Reconnecting, 10).await;
    assert!(rx.borrow().kill_switch_active);
    std::fs::remove_file(fx.dir.join("die")).unwrap();
    wait_state(&mut rx, UiState::Connected, 20).await;
    assert!(
        !rec.kinds().contains(&"remove".to_string()),
        "{:?}",
        rec.kinds()
    );
    let calls = rec.calls.lock().unwrap().clone();
    // The server is an IP literal here, so no DNS exception is needed or granted.
    assert!(
        !calls.iter().any(|c| c.contains("dport 53")),
        "no DNS exception for an IP literal server: {calls:?}"
    );

    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
    assert_eq!(rec.kinds().last().unwrap(), "remove");
    assert!(!rx.borrow().kill_switch_active);
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_direct_removes_rules_but_keeps_reconnecting() {
    let fx = fixture("allow").await;
    write_engine(&fx.dir);
    let id = fx.profile(1);
    let rec = Arc::new(Recorder::default());
    let c = fx.spawn(Some(rec.clone()));
    let mut rx = c.status();
    c.connect(&id);
    wait_state(&mut rx, UiState::Connected, 20).await;
    std::fs::write(fx.dir.join("die"), "").unwrap();
    wait_state(&mut rx, UiState::Reconnecting, 10).await;
    c.allow_direct();
    wait_until(&mut rx, 5, "rules removed", |s| !s.kill_switch_active).await;
    assert_eq!(rec.kinds().last().unwrap(), "remove");
    std::fs::remove_file(fx.dir.join("die")).unwrap();
    let n_apply = rec.kinds().iter().filter(|k| *k == "apply").count();
    wait_state(&mut rx, UiState::Connected, 20).await;
    assert_eq!(
        rec.kinds().iter().filter(|k| *k == "apply").count(),
        n_apply
    );
    assert!(!rx.borrow().kill_switch_active);
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_switch_survives_a_profile_switch() {
    let fx = fixture("ksswitch").await;
    write_engine(&fx.dir);
    let (a, b) = (fx.profile(1), fx.profile(2));
    let rec = Arc::new(Recorder::default());
    let c = fx.spawn(Some(rec.clone()));
    let mut rx = c.status();
    c.connect(&a);
    wait_state(&mut rx, UiState::Connected, 20).await;
    c.connect(&b);
    wait_until(&mut rx, 20, "connected to b", |s| {
        s.state == UiState::Connected && s.profile_id.as_deref() == Some(&b)
    })
    .await;
    assert!(
        !rec.kinds().contains(&"remove".to_string()),
        "no gap while switching: {:?}",
        rec.kinds()
    );
    assert!(rec.last_apply().contains("203.0.113.2"));
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
    assert_eq!(rec.kinds().last().unwrap(), "remove");
}

#[tokio::test(flavor = "multi_thread")]
async fn required_kill_switch_that_cannot_apply_fails_closed() {
    let fx = fixture("ksfail").await;
    write_engine(&fx.dir);
    let id = fx.profile(1);
    let rec = Arc::new(Recorder::default());
    *rec.fail_apply.lock().unwrap() = true;
    let c = fx.spawn(Some(rec.clone()));
    let mut rx = c.status();
    c.connect(&id);
    let s = wait_state(&mut rx, UiState::Failed, 20).await;
    assert_eq!(s.failure_code.as_deref(), Some("killswitch"));
    settle_processes(&fx).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn leftover_rules_are_reported_and_can_be_cleared() {
    let fx = fixture("left").await;
    write_engine(&fx.dir);
    let rec = Arc::new(Recorder::default());
    *rec.active.lock().unwrap() = true; // as after a crash
    let c = fx.spawn_with(Some(rec.clone()), |_, o| {
        o.kill_switch.check_leftover = true
    });
    let mut rx = c.status();
    let s = wait_until(&mut rx, 5, "leftover flag", |s| s.kill_switch_leftover).await;
    assert_eq!(s.state, UiState::Idle);
    c.clear_leftover_rules();
    wait_until(&mut rx, 5, "cleared", |s| !s.kill_switch_leftover).await;
    assert!(!*rec.active.lock().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn health_probe_replaces_a_dead_tunnel() {
    let fx = fixture("health").await;
    write_engine(&fx.dir);
    let id = fx.profile(1);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = l.local_addr().unwrap();
    let acc = tokio::spawn(async move { while l.accept().await.is_ok() {} });
    let c = fx.spawn_with(None, |cfg, o| {
        cfg.probe = target;
        o.health_interval = Some(Duration::from_millis(400));
    });
    let mut rx = c.status();
    c.connect(&id);
    wait_state(&mut rx, UiState::Connected, 20).await;
    let starts = fx.starts();
    acc.abort();
    let _ = acc.await;
    wait_state(&mut rx, UiState::Reconnecting, 20).await;
    assert!(fx.starts() >= starts);
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 20).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_log_flood_does_not_block_the_engine() {
    let fx = fixture("flood").await;
    write_engine(&fx.dir);
    std::fs::write(fx.dir.join("mode"), "flood").unwrap();
    let id = fx.profile(1);
    let c = fx.spawn(None);
    let mut rx = c.status();
    c.connect(&id);
    wait_state(&mut rx, UiState::Connected, 30).await;
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_engine_binary_is_reported_precisely() {
    let fx = fixture("missing").await;
    let id = fx.profile(1);
    let c = fx.spawn_with(None, |cfg, o| {
        cfg.bins.sing_box = cfg.work_dir.join("does-not-exist");
        o.version_check = Some(cfg.bins.sing_box.clone());
    });
    let mut rx = c.status();
    c.connect(&id);
    let s = wait_state(&mut rx, UiState::Failed, 10).await;
    assert_eq!(s.failure_code.as_deref(), Some("engine_missing"));
}

#[tokio::test(flavor = "multi_thread")]
async fn too_old_engine_is_refused_with_its_own_code() {
    let fx = fixture("old").await;
    let id = fx.profile(1);
    let old = fx.dir.join("old-sing-box");
    std::fs::write(&old, "#!/bin/sh\necho 'sing-box version 1.9.7'\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o755)).unwrap();
    let o2 = old.clone();
    let c = fx.spawn_with(None, move |cfg, o| {
        cfg.bins.sing_box = o2.clone();
        o.version_check = Some(o2);
    });
    let mut rx = c.status();
    c.connect(&id);
    let s = wait_state(&mut rx, UiState::Failed, 10).await;
    assert_eq!(s.failure_code.as_deref(), Some("engine_version"));
}

#[tokio::test(flavor = "multi_thread")]
async fn legacy_spawn_keeps_the_first_versions_behaviour() {
    let fx = fixture("legacy").await;
    write_engine(&fx.dir);
    let id = fx.profile(1);
    let cfg = ControllerConfig {
        mode: Mode::Tun,
        dns: vec![],
        bins: Binaries {
            sing_box: fx.dir.join("fake-sing-box"),
            awg_socks: "awg-socks".into(),
            openvpn: "openvpn".into(),
        },
        probe: fx.probe,
        ready_timeout: Duration::from_secs(30),
        work_dir: fx.dir.join("run"),
    };
    let c = Controller::spawn(fx.app.clone(), cfg);
    let mut rx = c.status();
    c.connect(&id);
    let s = wait_state(&mut rx, UiState::Connected, 20).await;
    assert!(!s.kill_switch_active);
    c.disconnect();
    wait_state(&mut rx, UiState::Idle, 8).await;
}
