//! Runs the connection state machine against real engines. One task owns the tunnel; front ends
//! send commands and watch [`Status`].

use crate::App;
use core_engine::runner::{start, Binaries, StartError, StartOptions, Tunnel};
use core_engine::{probe, Mode};
use core_session::{Action, Event, FailureKind, Session, State};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, watch};
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
    /// Stable failure code (`network`, `server`, `config`, `permission`).
    pub failure_code: Option<String>,
    pub attempt: u32,
    pub insecure_tls: bool,
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
        }
    }
}

#[derive(Clone)]
pub struct ControllerConfig {
    pub mode: Mode,
    pub dns: Vec<String>,
    pub bins: Binaries,
    /// A TCP endpoint reached through the tunnel to prove it carries traffic.
    pub probe: SocketAddr,
    pub ready_timeout: Duration,
    pub work_dir: std::path::PathBuf,
}

enum Cmd {
    Connect(String),
    Disconnect,
    NetworkChanged,
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

impl Controller {
    pub fn spawn(app: Arc<App>, cfg: ControllerConfig) -> Self {
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
    pub fn connect(&self, profile_id: &str) {
        let _ = self.tx.send(Cmd::Connect(profile_id.to_string()));
    }
    pub fn disconnect(&self) {
        let _ = self.tx.send(Cmd::Disconnect);
    }
    /// Tell the controller the system network changed (Wi-Fi to cellular, sleep/wake, ...).
    pub fn network_changed(&self) {
        let _ = self.tx.send(Cmd::NetworkChanged);
    }
    pub fn status(&self) -> watch::Receiver<Status> {
        self.status.clone()
    }
}

fn classify(e: &StartError) -> FailureKind {
    match e {
        StartError::Resolve => FailureKind::Network,
        StartError::Timeout { .. } | StartError::ExitedEarly { .. } => FailureKind::Server,
        StartError::Engine(_) => FailureKind::Config,
        StartError::Io(k) if k.contains("permission") => FailureKind::Permission,
        StartError::Io(_) => FailureKind::Config,
    }
}

struct Runner {
    app: Arc<App>,
    cfg: ControllerConfig,
    session: Session,
    profile_id: Option<String>,
    profile: Option<core_model::Profile>,
    tunnel: Option<Tunnel>,
    retry: Option<Instant>,
    since: Option<SystemTime>,
    last_failure: Option<FailureKind>,
    insecure: bool,
    queue: VecDeque<Event>,
    log: LogBuf,
}

impl Runner {
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
        });
    }

    async fn verify(&self) -> bool {
        let limit = Duration::from_secs(8);
        match &self.cfg.mode {
            Mode::Proxy { socks_port } => {
                let proxy = SocketAddr::from(([127, 0, 0, 1], *socks_port));
                probe::socks5_connect(
                    proxy,
                    &self.cfg.probe.ip().to_string(),
                    self.cfg.probe.port(),
                    limit,
                )
                .await
                .is_ok()
            }
            Mode::Tun => probe::tcp_reachable(self.cfg.probe, limit).await.is_ok(),
        }
    }

    async fn perform(&mut self, action: Action) {
        match action {
            Action::Prepare => {
                let id = self.profile_id.clone().unwrap_or_default();
                match self.app.profile(&id) {
                    Ok(p) => {
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
                let opts = StartOptions {
                    mode: self.cfg.mode.clone(),
                    dns: self.cfg.dns.clone(),
                    work_dir: self.cfg.work_dir.clone(),
                    bins: self.cfg.bins.clone(),
                    redactor: self.app.redactor().clone(),
                    ready_timeout: self.cfg.ready_timeout,
                };
                match start(&profile, &opts).await {
                    Ok(t) => {
                        self.insecure = !t.warnings.is_empty();
                        self.tunnel = Some(t);
                        if self.verify().await {
                            self.since = Some(SystemTime::now());
                            self.queue.push_back(Event::TunnelVerified);
                        } else {
                            self.last_failure = Some(FailureKind::Server);
                            self.queue
                                .push_back(Event::EngineFailed(FailureKind::Server));
                        }
                    }
                    Err(e) => {
                        let k = classify(&e);
                        self.last_failure = Some(k);
                        self.queue.push_back(Event::EngineFailed(k));
                    }
                }
            }
            Action::StopEngine => {
                if let Some(mut t) = self.tunnel.take() {
                    push_lines(&self.log, t.drain_lines());
                    t.stop().await;
                }
                self.since = None;
                if matches!(self.session.state(), State::Disconnecting) {
                    self.queue.push_back(Event::Stopped);
                }
            }
            Action::ScheduleRetry(d) => self.retry = Some(Instant::now() + d),
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
            self.publish(tx);
            for a in actions {
                self.perform(a).await;
            }
        }
        self.publish(tx);
    }
}

async fn run(
    app: Arc<App>,
    cfg: ControllerConfig,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
    tx: watch::Sender<Status>,
    log: LogBuf,
) {
    let mut r = Runner {
        app,
        cfg,
        session: Session::default(),
        profile_id: None,
        profile: None,
        tunnel: None,
        retry: None,
        since: None,
        last_failure: None,
        insecure: false,
        queue: VecDeque::new(),
        log,
    };
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        let retry = r.retry;
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None => {
                    if let Some(t) = r.tunnel.take() { t.stop().await; }
                    return;
                }
                Some(Cmd::Connect(id)) => {
                    // Switching profiles: stop the current tunnel first.
                    if !matches!(r.session.state(), State::Idle | State::Failed(_)) {
                        r.apply(Event::UserDisconnect, &tx).await;
                    }
                    r.profile_id = Some(id);
                    r.apply(Event::UserConnect, &tx).await;
                }
                Some(Cmd::Disconnect) => r.apply(Event::UserDisconnect, &tx).await,
                Some(Cmd::NetworkChanged) => r.apply(Event::NetworkChanged, &tx).await,
            },
            _ = async { match retry { Some(t) => tokio::time::sleep_until(t).await, None => std::future::pending::<()>().await } } => {
                r.retry = None;
                r.apply(Event::RetryTimerFired, &tx).await;
            }
            _ = tick.tick() => {
                if let Some(t) = r.tunnel.as_mut() {
                    push_lines(&r.log, t.drain_lines());
                }
                if matches!(r.session.state(), State::Connected | State::Connecting { .. }) {
                    if let Some(t) = r.tunnel.as_mut() {
                        if t.exited().is_some() {
                            r.apply(Event::EngineFailed(FailureKind::Server), &tx).await;
                        }
                    }
                }
            }
        }
    }
}
