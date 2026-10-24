//! Runs the connection state machine against real engines. One task owns the tunnel; front ends
//! send commands and watch [`Status`].
//!
//! Starting an engine takes seconds (up to `ready_timeout`). It runs as a separate task so the
//! command loop stays responsive: disconnect, a different profile, or a network change cancels
//! the start in progress, stops what it had started and cleans its files.
//!
//! Leak protection (see [`KillSwitchConfig`]): applied after the tunnel is verified, kept while
//! the tunnel is down and being rebuilt (that is its purpose), removed only by a user
//! disconnect, [`Controller::allow_direct`], or a graceful shutdown of the controller.

use crate::failure::{classify_log, classify_start_error};
use crate::ks::{KillSwitchConfig, KsHandle};
use crate::App;
use core_engine::runner::{
    cancel_pair, check_sing_box, expected_tun_iface, start_cancellable, Binaries, Cancel, CancelRx,
    StartError, StartOptions, Tunnel,
};
use core_engine::{probe, Mode};
use core_model::{EngineKind, Profile};
use core_policy::KillSwitch;
use core_session::{Action, Event, FailureKind, Session, State};
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiState {
    Idle,
    Preparing,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub state: UiState,
    pub profile_id: Option<String>,
    pub connected_since: Option<SystemTime>,
    /// Plain-language text for the user (set on failure).
    pub message: Option<String>,
    /// English version of `message`.
    pub message_en: Option<String>,
    /// Stable failure code (`network`, `server`, `config`, `permission`, `auth`, `tls`, `dns`,
    /// `port_busy`, `engine_missing`, `engine_version`, `device`, `killswitch`).
    pub failure_code: Option<String>,
    pub attempt: u32,
    pub insecure_tls: bool,
    /// Leak protection rules are loaded by this controller. While `state` is not `Connected`
    /// this means the network is deliberately blocked; offer "allow direct connections".
    pub kill_switch_active: bool,
    /// Rules of a previous run (crash) were found at start-up and nothing is connected; offer
    /// [`Controller::clear_leftover_rules`].
    pub kill_switch_leftover: bool,
    /// English text when removing or checking the rules failed (the user may be offline).
    pub kill_switch_error: Option<String>,
}

impl Status {
    fn idle() -> Self {
        Self {
            state: UiState::Idle,
            profile_id: None,
            connected_since: None,
            message: None,
            message_en: None,
            failure_code: None,
            attempt: 0,
            insecure_tls: false,
            kill_switch_active: false,
            kill_switch_leftover: false,
            kill_switch_error: None,
        }
    }
}

/// How the tunnel is proven to carry traffic, at connect time and periodically afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeMode {
    /// One DNS query (root NS by default) answered by the engine's resolver through the VPN
    /// server. Nothing is sent from the user's address to a third party. Default.
    Dns,
    /// TCP connect to `ControllerConfig::probe`. Contacts that host: choose one you trust.
    Tcp,
}

/// What to run and where. Unchanged since the first version, so existing struct literals keep
/// compiling. Newer settings live in [`ControllerOptions`].
#[derive(Clone)]
pub struct ControllerConfig {
    pub mode: Mode,
    pub dns: Vec<String>,
    pub bins: Binaries,
    /// Endpoint for [`ProbeMode::Tcp`].
    pub probe: SocketAddr,
    pub ready_timeout: Duration,
    pub work_dir: std::path::PathBuf,
}

/// Probe, health and leak-protection settings.
#[derive(Clone)]
pub struct ControllerOptions {
    pub probe_mode: ProbeMode,
    /// Name queried by [`ProbeMode::Dns`]; `.` asks the resolver for the root NS set.
    pub probe_name: String,
    /// Interval of the health probe while connected. `None` disables it (the engine exit is
    /// still noticed). Cost: one small query per interval.
    pub health_interval: Option<Duration>,
    /// sing-box binary to run `version` on before the first start (never an elevation wrapper).
    pub version_check: Option<std::path::PathBuf>,
    pub kill_switch: KillSwitchConfig,
}

impl ControllerOptions {
    /// Recommended settings: DNS probe (no third party contacted), 30 s health probe, version
    /// check of `bins.sing_box`, leak protection on in TUN mode.
    pub fn recommended(cfg: &ControllerConfig) -> Self {
        Self {
            probe_mode: ProbeMode::Dns,
            probe_name: ".".into(),
            health_interval: Some(Duration::from_secs(30)),
            version_check: Some(cfg.bins.sing_box.clone()),
            kill_switch: KillSwitchConfig::for_mode(&cfg.mode),
        }
    }
    /// Behaviour of the first version: TCP probe of `cfg.probe`, no health probe, no version
    /// check, no leak protection. Used by [`Controller::spawn`].
    pub fn legacy(_cfg: &ControllerConfig) -> Self {
        Self {
            probe_mode: ProbeMode::Tcp,
            probe_name: ".".into(),
            health_interval: None,
            version_check: None,
            kill_switch: KillSwitchConfig::disabled(),
        }
    }
}

/// Both halves together, as used internally.
#[derive(Clone)]
struct Cfg {
    mode: Mode,
    dns: Vec<String>,
    bins: Binaries,
    probe: SocketAddr,
    ready_timeout: Duration,
    work_dir: std::path::PathBuf,
    probe_mode: ProbeMode,
    probe_name: String,
    health_interval: Option<Duration>,
    version_check: Option<std::path::PathBuf>,
    kill_switch: KillSwitchConfig,
}

impl Cfg {
    fn new(c: ControllerConfig, o: ControllerOptions) -> Self {
        Self {
            mode: c.mode,
            dns: c.dns,
            bins: c.bins,
            probe: c.probe,
            ready_timeout: c.ready_timeout,
            work_dir: c.work_dir,
            probe_mode: o.probe_mode,
            probe_name: o.probe_name,
            health_interval: o.health_interval,
            version_check: o.version_check,
            kill_switch: o.kill_switch,
        }
    }
}

enum Cmd {
    Connect(String),
    Disconnect,
    NetworkChanged,
    AllowDirect,
    ClearLeftover,
}

#[derive(Clone)]
pub struct Controller {
    tx: mpsc::UnboundedSender<Cmd>,
    status: watch::Receiver<Status>,
    log: LogBuf,
}

/// Recent engine output lines, already redacted. Used for the diagnostic report only.
pub type LogBuf = Arc<std::sync::Mutex<VecDeque<String>>>;
const LOG_LINES: usize = 300;

fn push_lines(buf: &LogBuf, lines: Vec<(&'static str, String)>) {
    if let Ok(mut b) = buf.lock() {
        for (n, l) in lines {
            b.push_back(format!("{n}: {l}"));
        }
        while b.len() > LOG_LINES {
            b.pop_front();
        }
    }
}

fn recent(buf: &LogBuf, n: usize) -> Vec<String> {
    buf.lock()
        .map(|b| b.iter().rev().take(n).cloned().collect())
        .unwrap_or_default()
}

impl Controller {
    /// Start with the settings of the first version (see [`ControllerOptions::legacy`]).
    pub fn spawn(app: Arc<App>, cfg: ControllerConfig) -> Self {
        let o = ControllerOptions::legacy(&cfg);
        Self::spawn_with(app, cfg, o)
    }

    pub fn spawn_with(app: Arc<App>, cfg: ControllerConfig, options: ControllerOptions) -> Self {
        let cfg = Cfg::new(cfg, options);
        let (tx, rx) = mpsc::unbounded_channel();
        let (stx, srx) = watch::channel(Status::idle());
        let log: LogBuf = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        tokio::spawn(run(app, cfg, rx, stx, log.clone()));
        Self {
            tx,
            status: srx,
            log,
        }
    }
    /// Last redacted engine output lines (for a diagnostic report).
    pub fn recent_log(&self) -> Vec<String> {
        self.log
            .lock()
            .map(|b| b.iter().cloned().collect())
            .unwrap_or_default()
    }
    /// Connect to a profile. Safe at any time: a connection or start in progress is cancelled
    /// (or kept, if it is the same profile).
    pub fn connect(&self, profile_id: &str) {
        let _ = self.tx.send(Cmd::Connect(profile_id.to_string()));
    }
    pub fn disconnect(&self) {
        let _ = self.tx.send(Cmd::Disconnect);
    }
    /// Tell the controller the system network changed (Wi-Fi to cellular, sleep/wake, ...).
    /// Bursts are coalesced.
    pub fn network_changed(&self) {
        let _ = self.tx.send(Cmd::NetworkChanged);
    }
    /// App-level "allow direct connections": remove the leak protection rules now and do not
    /// re-apply them until the next `connect`. The tunnel keeps being re-established.
    pub fn allow_direct(&self) {
        let _ = self.tx.send(Cmd::AllowDirect);
    }
    /// Remove leak protection rules found at start-up (left by a crashed run).
    pub fn clear_leftover_rules(&self) {
        let _ = self.tx.send(Cmd::ClearLeftover);
    }
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }
}

// ---------------------------------------------------------------------------------------------
// Start job: runs in its own task and owns everything it starts until it hands over the tunnel.

struct StartJob {
    handle: JoinHandle<Outcome>,
    cancel: Cancel,
}

enum Outcome {
    Up {
        tunnel: Box<Tunnel>,
        ips: Vec<IpAddr>,
    },
    Failed {
        kind: FailureKind,
        tail: Vec<String>,
        ips: Vec<IpAddr>,
    },
    Cancelled,
}

struct JobCtx {
    profile: Profile,
    opts: StartOptions,
    cfg: Cfg,
    ks: Option<KsHandle>,
    /// Apply the final rules after verification.
    ks_enabled: bool,
    /// Rules already exist (reconnect, profile switch, or left by a crash): keep the network
    /// closed while the new tunnel comes up and re-apply with the new profile's addresses.
    ks_present: bool,
    cached_ips: Vec<IpAddr>,
    version_ok: Arc<AtomicBool>,
}

fn dns_probe_server(cfg: &Cfg) -> SocketAddr {
    cfg.dns
        .first()
        .and_then(|d| d.parse::<IpAddr>().ok())
        .map(|ip| SocketAddr::new(ip, 53))
        .unwrap_or_else(|| SocketAddr::from(([1, 1, 1, 1], 53)))
}

async fn verify(cfg: &Cfg, limit: Duration) -> bool {
    match (&cfg.mode, cfg.probe_mode) {
        (Mode::Proxy { socks_port }, ProbeMode::Tcp) => {
            let proxy = SocketAddr::from(([127, 0, 0, 1], *socks_port));
            probe::socks5_connect(proxy, &cfg.probe.ip().to_string(), cfg.probe.port(), limit)
                .await
                .is_ok()
        }
        (Mode::Proxy { socks_port }, ProbeMode::Dns) => {
            let proxy = SocketAddr::from(([127, 0, 0, 1], *socks_port));
            probe::dns_tcp_via_socks(proxy, dns_probe_server(cfg), &cfg.probe_name, limit)
                .await
                .is_ok()
        }
        (Mode::Tun, ProbeMode::Tcp) => probe::tcp_reachable(cfg.probe, limit).await.is_ok(),
        (Mode::Tun, ProbeMode::Dns) => {
            probe::dns_udp(dns_probe_server(cfg), &cfg.probe_name, limit)
                .await
                .is_ok()
        }
    }
}

/// All A/AAAA addresses of the server, looked up with the system resolver (the same path the
/// engine's bootstrap resolver uses), with a hard time limit.
async fn resolve_server(host: &str, port: u16) -> Vec<IpAddr> {
    let h = host.to_string();
    let t = tokio::task::spawn_blocking(move || core_policy::fw::resolve_all(&h, port));
    match tokio::time::timeout(Duration::from_secs(8), t).await {
        Ok(Ok(v)) => v,
        _ => Vec::new(),
    }
}

fn union_ips(into: &mut Vec<IpAddr>, more: Vec<IpAddr>) {
    for ip in more {
        if !into.contains(&ip) && into.len() < 64 {
            into.push(ip);
        }
    }
}

fn ks_for(cfg: &Cfg, iface: &str, ips: &[IpAddr], dns: Vec<IpAddr>) -> KillSwitch {
    KillSwitch {
        tun_iface: iface.to_string(),
        server_ips: ips.to_vec(),
        allow_lan: cfg.kill_switch.allow_lan,
        allow_ifaces: cfg.kill_switch.allow_ifaces.clone(),
        dns_bootstrap: dns,
    }
}

async fn run_job(ctx: JobCtx, mut cancel: CancelRx) -> Outcome {
    let JobCtx {
        profile,
        opts,
        cfg,
        ks,
        ks_enabled,
        ks_present,
        cached_ips,
        version_ok,
    } = ctx;
    let fail = |kind: FailureKind, ips: &Vec<IpAddr>| Outcome::Failed {
        kind,
        tail: Vec::new(),
        ips: ips.clone(),
    };
    let mut ips = cached_ips;

    // 1. Helper binary present and recent enough (once per controller).
    if profile.protocol.engine() != EngineKind::OpenVpn && !version_ok.load(Ordering::SeqCst) {
        if let Some(path) = cfg.version_check.clone() {
            let r = tokio::task::spawn_blocking(move || check_sing_box(&path)).await;
            match r {
                Ok(Ok(_)) => version_ok.store(true, Ordering::SeqCst),
                Ok(Err(e)) => {
                    return Outcome::Failed {
                        kind: classify_start_error(&e),
                        tail: vec![e.to_string()],
                        ips,
                    }
                }
                Err(_) => return fail(FailureKind::EngineMissing, &ips),
            }
        }
    }
    if cancel.is_cancelled() {
        return Outcome::Cancelled;
    }

    // 2. Server addresses, with the network still closed if rules exist.
    let tun = matches!(cfg.mode, Mode::Tun);
    let iface = expected_tun_iface(&profile);
    let literal = profile.host.parse::<IpAddr>().is_ok();
    if tun && (ks_enabled || ks_present) {
        let bootstrap = if literal {
            Vec::new()
        } else if cfg.kill_switch.bootstrap_dns.is_empty() {
            core_policy::fw::system_resolvers()
        } else {
            cfg.kill_switch.bootstrap_dns.clone()
        };
        if literal {
            union_ips(&mut ips, resolve_server(&profile.host, profile.port).await);
        }
        if ks_present {
            let Some(ks) = &ks else {
                return fail(FailureKind::KillSwitch, &ips);
            };
            // Open only the bootstrap resolvers and the addresses known so far, then look up
            // the host name again: records change, and the old ones may be dead.
            if ks
                .apply(ks_for(&cfg, &iface, &ips, bootstrap.clone()))
                .await
                .is_err()
            {
                return fail(FailureKind::KillSwitch, &ips);
            }
        }
        if !literal {
            let fresh = tokio::select! {
                _ = cancel.cancelled() => return Outcome::Cancelled,
                v = resolve_server(&profile.host, profile.port) => v,
            };
            if fresh.is_empty() && ips.is_empty() {
                return fail(FailureKind::Dns, &ips);
            }
            union_ips(&mut ips, fresh);
            if ks_present {
                if let Some(ks) = &ks {
                    if ks
                        .apply(ks_for(&cfg, &iface, &ips, bootstrap))
                        .await
                        .is_err()
                    {
                        return fail(FailureKind::KillSwitch, &ips);
                    }
                }
            }
        }
    }

    // 3. Start the engine(s). Cancel stops them gracefully.
    let mut tunnel = match start_cancellable(&profile, &opts, cancel.clone()).await {
        Ok(t) => t,
        Err(StartError::Cancelled) => return Outcome::Cancelled,
        Err(e) => {
            let tail = e.tail().lines().map(|s| s.to_string()).collect();
            return Outcome::Failed {
                kind: classify_start_error(&e),
                tail,
                ips,
            };
        }
    };

    // 4. Prove that traffic crosses the tunnel.
    let proven = tokio::select! {
        _ = cancel.cancelled() => {
            tunnel.stop().await;
            return Outcome::Cancelled;
        }
        ok = verify(&cfg, Duration::from_secs(8)) => ok,
    };
    if !proven {
        let tail: Vec<String> = tunnel
            .drain_lines()
            .into_iter()
            .map(|(n, l)| format!("{n}: {l}"))
            .collect();
        tunnel.stop().await;
        return Outcome::Failed {
            kind: classify_log(&tail).unwrap_or(FailureKind::Server),
            tail,
            ips,
        };
    }

    // 5. Leak protection, only now that the tunnel works.
    if tun && ks_enabled {
        let iface = tunnel.tun_iface.clone().unwrap_or(iface);
        let applied = match &ks {
            Some(ks) if !ips.is_empty() => ks
                .apply(ks_for(&cfg, &iface, &ips, Vec::new()))
                .await
                .is_ok(),
            _ => false,
        };
        if !applied && cfg.kill_switch.required {
            tunnel.stop().await;
            let kind = if ips.is_empty() {
                FailureKind::Dns
            } else {
                FailureKind::KillSwitch
            };
            return fail(kind, &ips);
        }
    }
    Outcome::Up {
        tunnel: Box::new(tunnel),
        ips,
    }
}

// ---------------------------------------------------------------------------------------------

struct Runner {
    app: Arc<App>,
    cfg: Cfg,
    session: Session,
    profile_id: Option<String>,
    profile: Option<Profile>,
    tunnel: Option<Tunnel>,
    starting: Option<StartJob>,
    retry: Option<Instant>,
    since: Option<SystemTime>,
    last_failure: Option<FailureKind>,
    insecure: bool,
    queue: VecDeque<Event>,
    log: LogBuf,
    ks: Option<KsHandle>,
    /// Leak protection still applies to this session (false after "allow direct").
    ks_session_on: bool,
    /// A profile switch is in progress: keep the rules closed across the restart.
    switching: bool,
    leftover: bool,
    ks_error: Option<String>,
    server_ips: Vec<IpAddr>,
    server_ips_for: Option<String>,
    version_ok: Arc<AtomicBool>,
    next_health: Option<Instant>,
    health: Option<JoinHandle<bool>>,
    health_fail: u32,
    net_deadline: Option<Instant>,
}

/// +-20 % so many clients do not retry in lockstep after a server outage.
fn jitter(d: Duration) -> Duration {
    if d.is_zero() {
        return d;
    }
    use std::hash::{BuildHasher, Hasher};
    let r = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    let f = 0.8 + (r % 4001) as f64 / 10_000.0; // 0.8 ..= 1.2
    d.mul_f64(f)
}

impl Runner {
    fn ks_present(&self) -> bool {
        self.ks.as_ref().map(|k| k.present()).unwrap_or(false)
    }

    fn sync_keep_trying(&mut self) {
        let on = self.ks_present();
        self.session.set_keep_trying(on);
    }

    fn publish(&self, tx: &watch::Sender<Status>) {
        let (state, attempt) = match self.session.state() {
            State::Idle => (UiState::Idle, 0),
            State::Preparing => (UiState::Preparing, 0),
            State::Connecting { attempt } => (UiState::Connecting, attempt),
            State::Connected => (UiState::Connected, 0),
            State::Reconnecting { attempt } => (UiState::Reconnecting, attempt),
            State::Disconnecting => (UiState::Disconnecting, 0),
            State::Failed(_) => (UiState::Failed, 0),
        };
        let kind = match self.session.state() {
            State::Failed(k) => Some(k),
            State::Reconnecting { .. } => self.last_failure,
            _ => None,
        };
        let message = kind.map(|k| k.user_message().to_string());
        let message_en = kind.map(|k| k.user_message_en().to_string());
        let failure_code = kind.map(|k| k.code().to_string());
        let connected_since = if state == UiState::Connected {
            self.since
        } else {
            None
        };
        let _ = tx.send(Status {
            state,
            profile_id: self.profile_id.clone(),
            connected_since,
            message,
            message_en,
            failure_code,
            attempt,
            insecure_tls: self.insecure,
            kill_switch_active: self.ks_present(),
            kill_switch_leftover: self.leftover && self.session.state() == State::Idle,
            kill_switch_error: self.ks_error.clone(),
        });
    }

    async fn remove_ks(&mut self) {
        let Some(ks) = self.ks.clone() else { return };
        match ks.remove().await {
            Ok(()) => {
                self.ks_error = None;
                self.leftover = false;
            }
            Err(e) => {
                self.ks_error = Some(format!(
                    "Could not remove the leak protection rules ({e}). Run `wt killswitch off` with administrator rights."
                ));
            }
        }
        self.sync_keep_trying();
    }

    async fn cancel_start(&mut self) {
        if let Some(job) = self.starting.take() {
            job.cancel.cancel();
            // The job stops what it started (bounded by the engines' stop grace period).
            if let Ok(Outcome::Up { tunnel, .. }) = job.handle.await {
                tunnel.stop().await;
            }
        }
    }

    async fn perform(&mut self, action: Action) {
        match action {
            Action::Prepare => {
                let id = self.profile_id.clone().unwrap_or_default();
                match self.app.profile(&id) {
                    Ok(p) => {
                        if self.server_ips_for.as_deref() != Some(id.as_str()) {
                            self.server_ips.clear();
                            self.server_ips_for = Some(id);
                        }
                        self.profile = Some(p);
                        self.queue.push_back(Event::Prepared);
                    }
                    Err(_) => self
                        .queue
                        .push_back(Event::PrepareFailed(FailureKind::Config)),
                }
            }
            Action::StartEngine => {
                let Some(profile) = self.profile.clone() else {
                    return self
                        .queue
                        .push_back(Event::EngineFailed(FailureKind::Config));
                };
                self.cancel_start().await;
                let opts = StartOptions {
                    mode: self.cfg.mode.clone(),
                    dns: self.cfg.dns.clone(),
                    work_dir: self.cfg.work_dir.clone(),
                    bins: self.cfg.bins.clone(),
                    redactor: self.app.redactor().clone(),
                    ready_timeout: self.cfg.ready_timeout,
                };
                let ctx = JobCtx {
                    profile,
                    opts,
                    cfg: self.cfg.clone(),
                    ks: self.ks.clone(),
                    ks_enabled: self.cfg.kill_switch.enabled
                        && self.ks_session_on
                        && self.ks.is_some(),
                    ks_present: self.ks_present() || self.leftover,
                    cached_ips: self.server_ips.clone(),
                    version_ok: self.version_ok.clone(),
                };
                let (cancel, rx) = cancel_pair();
                let handle = tokio::spawn(run_job(ctx, rx));
                self.starting = Some(StartJob { handle, cancel });
            }
            Action::StopEngine => {
                self.cancel_start().await;
                self.next_health = None;
                if let Some(h) = self.health.take() {
                    h.abort();
                }
                if let Some(mut t) = self.tunnel.take() {
                    push_lines(&self.log, t.drain_lines());
                    t.stop().await;
                }
                self.since = None;
                if matches!(self.session.state(), State::Disconnecting) {
                    self.queue.push_back(Event::Stopped);
                }
            }
            Action::ScheduleRetry(d) => self.retry = Some(Instant::now() + jitter(d)),
            Action::CancelRetry => self.retry = None,
        }
    }

    async fn apply(&mut self, ev: Event, tx: &watch::Sender<Status>) {
        self.queue.push_back(ev);
        while let Some(e) = self.queue.pop_front() {
            if let Event::EngineFailed(k) = e {
                self.last_failure = Some(k);
            }
            let actions = self.session.handle(e);
            // User is done: the rules go before Idle is shown (the UI must never say "not
            // connected" while traffic is still blocked), unless a switch to another profile is
            // about to reuse them.
            if self.session.state() == State::Idle && self.ks_present() && !self.switching {
                self.remove_ks().await;
            }
            self.publish(tx);
            for a in actions {
                self.perform(a).await;
            }
        }
        self.publish(tx);
    }

    async fn on_start_result(
        &mut self,
        res: Result<Outcome, tokio::task::JoinError>,
        tx: &watch::Sender<Status>,
    ) {
        self.starting = None;
        let ev = match res {
            Ok(Outcome::Up { tunnel, ips }) => {
                self.insecure = !tunnel.warnings.is_empty();
                self.tunnel = Some(*tunnel);
                self.server_ips = ips;
                self.since = Some(SystemTime::now());
                self.health_fail = 0;
                self.next_health = self.cfg.health_interval.map(|i| Instant::now() + i);
                self.sync_keep_trying();
                Event::TunnelVerified
            }
            Ok(Outcome::Failed { kind, tail, ips }) => {
                push_lines(&self.log, tail.into_iter().map(|l| ("engine", l)).collect());
                if !ips.is_empty() {
                    self.server_ips = ips;
                }
                self.sync_keep_trying();
                Event::EngineFailed(kind)
            }
            Ok(Outcome::Cancelled) => return,
            Err(_) => Event::EngineFailed(FailureKind::Server),
        };
        self.apply(ev, tx).await;
    }

    /// The tunnel process ended on its own while connected.
    async fn on_engine_exit(&mut self, name: &str, how: String, tx: &watch::Sender<Status>) {
        if let Some(t) = self.tunnel.as_mut() {
            push_lines(&self.log, t.drain_lines());
        }
        push_lines(&self.log, vec![("engine", format!("{name} ended: {how}"))]);
        let tail = recent(&self.log, 30);
        let kind = classify_log(&tail).unwrap_or(FailureKind::Server);
        self.apply(Event::EngineFailed(kind), tx).await;
    }

    async fn on_health(&mut self, ok: bool, tx: &watch::Sender<Status>) {
        self.health = None;
        if self.session.state() != State::Connected {
            return;
        }
        if ok {
            self.health_fail = 0;
        } else {
            self.health_fail += 1;
        }
        self.next_health = self.cfg.health_interval.map(|i| {
            // Re-check sooner after a failure so a dead tunnel is replaced quickly.
            if self.health_fail > 0 {
                Instant::now() + Duration::from_secs(3)
            } else {
                Instant::now() + i
            }
        });
        if self.health_fail >= 2 {
            self.health_fail = 0;
            push_lines(
                &self.log,
                vec![("health", "tunnel did not answer, reconnecting".into())],
            );
            self.apply(Event::EngineFailed(FailureKind::Server), tx)
                .await;
        }
    }
}

async fn run(
    app: Arc<App>,
    cfg: Cfg,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    tx: watch::Sender<Status>,
    log: LogBuf,
) {
    let ks = if cfg.kill_switch.enabled || cfg.kill_switch.check_leftover {
        cfg.kill_switch
            .build_firewall(&cfg.work_dir.join("killswitch"))
            .map(KsHandle::new)
    } else {
        None
    };
    let mut r = Runner {
        app,
        cfg,
        session: Session::default(),
        profile_id: None,
        profile: None,
        tunnel: None,
        starting: None,
        retry: None,
        since: None,
        last_failure: None,
        insecure: false,
        queue: VecDeque::new(),
        log,
        ks,
        ks_session_on: true,
        switching: false,
        leftover: false,
        ks_error: None,
        server_ips: Vec::new(),
        server_ips_for: None,
        version_ok: Arc::new(AtomicBool::new(false)),
        next_health: None,
        health: None,
        health_fail: 0,
        net_deadline: None,
    };
    // Rules from a crashed run: tell the front end instead of leaving the user offline silently.
    if r.cfg.kill_switch.check_leftover {
        if let Some(ks) = r.ks.clone() {
            match ks.is_active().await {
                Ok(true) => r.leftover = true,
                Ok(false) => {}
                Err(_) => {}
            }
        }
    }
    r.publish(&tx);
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_wall = SystemTime::now();
    loop {
        let retry = r.retry;
        let health_at = r.next_health;
        let net_at = r.net_deadline;
        let health_idle = r.health.is_none();
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None => {
                    r.cancel_start().await;
                    if let Some(t) = r.tunnel.take() { t.stop().await; }
                    // Graceful shutdown of the app: do not leave the machine blocked.
                    r.remove_ks().await;
                    return;
                }
                Some(Cmd::Connect(id)) => {
                    let active = !matches!(r.session.state(), State::Idle | State::Failed(_));
                    if active && r.profile_id.as_deref() == Some(id.as_str()) {
                        continue; // already (being) connected to this profile
                    }
                    // Switching profiles: stop the current tunnel first, keep the network closed.
                    if active {
                        r.switching = true;
                        r.apply(Event::UserDisconnect, &tx).await;
                    }
                    r.profile_id = Some(id);
                    r.ks_session_on = true;
                    r.last_failure = None;
                    r.apply(Event::UserConnect, &tx).await;
                    r.switching = false;
                }
                Some(Cmd::Disconnect) => r.apply(Event::UserDisconnect, &tx).await,
                Some(Cmd::NetworkChanged) => {
                    if r.net_deadline.is_none() {
                        r.net_deadline = Some(Instant::now() + Duration::from_millis(700));
                    }
                }
                Some(Cmd::AllowDirect) => {
                    r.ks_session_on = false;
                    r.remove_ks().await;
                    r.publish(&tx);
                }
                Some(Cmd::ClearLeftover) => {
                    if r.session.state() == State::Idle {
                        r.remove_ks().await;
                        r.publish(&tx);
                    }
                }
            },
            res = async {
                match r.starting.as_mut() {
                    Some(j) => (&mut j.handle).await,
                    None => std::future::pending().await,
                }
            } => r.on_start_result(res, &tx).await,
            _ = async { match retry { Some(t) => tokio::time::sleep_until(t).await, None => std::future::pending::<()>().await } } => {
                r.retry = None;
                r.apply(Event::RetryTimerFired, &tx).await;
            }
            _ = async { match net_at { Some(t) => tokio::time::sleep_until(t).await, None => std::future::pending::<()>().await } } => {
                r.net_deadline = None;
                r.apply(Event::NetworkChanged, &tx).await;
            }
            _ = async { match health_at { Some(t) if health_idle => tokio::time::sleep_until(t).await, _ => std::future::pending::<()>().await } } => {
                r.next_health = None;
                let cfg = r.cfg.clone();
                r.health = Some(tokio::spawn(async move { verify(&cfg, Duration::from_secs(5)).await }));
            }
            ok = async {
                match r.health.as_mut() {
                    Some(h) => h.await.unwrap_or(true),
                    None => std::future::pending().await,
                }
            } => r.on_health(ok, &tx).await,
            _ = tick.tick() => {
                // Suspend/resume: monotonic clocks may not advance during sleep, the wall clock does.
                let now = SystemTime::now();
                if let Ok(gap) = now.duration_since(last_wall) {
                    if gap > Duration::from_secs(20) {
                        r.apply(Event::NetworkChanged, &tx).await;
                    }
                }
                last_wall = now;
                if let Some(t) = r.tunnel.as_mut() {
                    push_lines(&r.log, t.drain_lines());
                }
                if r.session.state() == State::Connected {
                    let exited = r.tunnel.as_mut().and_then(|t| t.exited_with());
                    if let Some((name, how)) = exited {
                        r.on_engine_exit(name, how, &tx).await;
                    }
                }
            }
        }
    }
}
