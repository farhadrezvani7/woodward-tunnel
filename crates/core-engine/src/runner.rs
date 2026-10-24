//! Start and stop a full tunnel for a profile: picks the right engine(s), writes private config
//! files, spawns the processes and waits until they are actually ready.

use crate::sidecar::{
    describe_exit, instance_prefix, sweep_stale, write_pidfile, PrivateFile, Sidecar, SidecarSpec,
};
use crate::singbox::{self, Warning};
use crate::{awg, openvpn, EngineError, Mode};
use core_log::Redactor;
use core_model::{EngineKind, Profile};
use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Binaries {
    pub sing_box: PathBuf,
    pub awg_socks: PathBuf,
    pub openvpn: PathBuf,
}

impl Binaries {
    /// Look the helper binaries up next to the executable first, then on PATH.
    pub fn discover() -> Self {
        let dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let pick = |name: &str| -> PathBuf {
            let exe = if cfg!(windows) {
                format!("{name}.exe")
            } else {
                name.to_string()
            };
            match dir.as_ref().map(|d| d.join(&exe)) {
                Some(p) if p.exists() => p,
                _ => PathBuf::from(exe),
            }
        };
        Self {
            sing_box: pick("sing-box"),
            awg_socks: pick("awg-socks"),
            openvpn: pick("openvpn"),
        }
    }
}

pub struct StartOptions {
    pub mode: Mode,
    pub dns: Vec<String>,
    pub work_dir: PathBuf,
    pub bins: Binaries,
    pub redactor: Redactor,
    pub ready_timeout: Duration,
}

/// Oldest sing-box the generated configuration works with. Derived from the features the config
/// uses: typed DNS servers (`"type": "udp"|"local"`) and `route.default_domain_resolver`, both
/// introduced in 1.12.0; `action` based route rules came in 1.11.0.
pub const MIN_SING_BOX: (u32, u32, u32) = (1, 12, 0);

/// Parse `sing-box version 1.14.2` (or just `1.14.2`, optionally with a `-beta.1` suffix).
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    for tok in text.split_whitespace() {
        let t = tok.trim_start_matches('v');
        let core = t.split(['-', '+']).next().unwrap_or("");
        let mut it = core.split('.');
        if let (Some(a), Some(b), Some(c), None) = (it.next(), it.next(), it.next(), it.next()) {
            if let (Ok(a), Ok(b), Ok(c)) = (a.parse(), b.parse(), c.parse()) {
                return Some((a, b, c));
            }
        }
    }
    None
}

/// Check that the sing-box binary can run and is new enough. Run it on the real (unprivileged)
/// binary, never on an elevation wrapper script.
pub fn check_sing_box(path: &std::path::Path) -> Result<(u32, u32, u32), StartError> {
    let name = "sing-box";
    let mut child = std::process::Command::new(path)
        .arg("version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| StartError::BinaryMissing { name })?;
    let end = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(StartError::BinaryMissing { name });
            }
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|_| StartError::BinaryMissing { name })?;
    let text = String::from_utf8_lossy(&out.stdout);
    let found = parse_version(&text).ok_or(StartError::BinaryMissing { name })?;
    if found < MIN_SING_BOX {
        return Err(StartError::BinaryVersion {
            name,
            found: format!("{}.{}.{}", found.0, found.1, found.2),
            need: format!("{}.{}.{}", MIN_SING_BOX.0, MIN_SING_BOX.1, MIN_SING_BOX.2),
        });
    }
    Ok(found)
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error("io: {0}")]
    Io(String),
    #[error("engine exited before it was ready")]
    ExitedEarly { tail: String },
    #[error("engine did not become ready in time")]
    Timeout { tail: String },
    #[error("could not resolve the server address")]
    Resolve,
    #[error("helper program {name} is missing or cannot be run")]
    BinaryMissing { name: &'static str },
    #[error("helper program {name} {found} is too old (need {need})")]
    BinaryVersion {
        name: &'static str,
        found: String,
        need: String,
    },
    #[error("{what} is already in use")]
    Busy { what: String },
    #[error("start was cancelled")]
    Cancelled,
}

impl StartError {
    /// Last (already redacted) output lines of the engine, for diagnostics. Never shown by default.
    pub fn tail(&self) -> &str {
        match self {
            StartError::ExitedEarly { tail } | StartError::Timeout { tail } => tail,
            _ => "",
        }
    }
}

impl From<std::io::Error> for StartError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => StartError::Io("not found".into()),
            std::io::ErrorKind::AddrInUse => StartError::Busy {
                what: "address".into(),
            },
            // "Exec format error" (wrong architecture) has no stable kind; match the text.
            _ if e.to_string().contains("Exec format") => StartError::Io("not executable".into()),
            k => StartError::Io(k.to_string()),
        }
    }
}

pub struct Tunnel {
    procs: Vec<(&'static str, Sidecar)>,
    _files: Vec<PrivateFile>,
    /// Interface name or pattern the tunnel traffic leaves on (for leak protection). `None` in proxy mode.
    pub tun_iface: Option<String>,
    /// Local SOCKS address when started in proxy mode.
    pub socks: Option<SocketAddr>,
    pub warnings: Vec<Warning>,
}

impl Tunnel {
    /// Redacted output lines produced since the last call, tagged with the engine name.
    pub fn drain_lines(&mut self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        for (name, p) in self.procs.iter_mut() {
            while let Ok(l) = p.lines.try_recv() {
                out.push((*name, l));
            }
        }
        out
    }

    /// Name of the first engine that has exited, if any.
    pub fn exited(&mut self) -> Option<&'static str> {
        self.exited_with().map(|(n, _)| n)
    }

    /// Like [`Tunnel::exited`] with a description of how it ended (exit code or signal).
    pub fn exited_with(&mut self) -> Option<(&'static str, String)> {
        for (name, p) in self.procs.iter_mut() {
            match p.try_exit() {
                Ok(Some(st)) => return Some((*name, describe_exit(&st))),
                Err(_) => return Some((*name, "state unknown".into())),
                Ok(None) => {}
            }
        }
        None
    }

    pub async fn stop(self) {
        // Stop the front engine (last started) first so traffic is not routed into a dead helper.
        for (_, p) in self.procs.into_iter().rev() {
            let _ = p.stop(Duration::from_secs(3)).await;
        }
    }
}

fn spawn(
    program: &std::path::Path,
    args: Vec<OsString>,
    redactor: &Redactor,
    work_dir: &std::path::Path,
    tag: &'static str,
    files: &mut Vec<PrivateFile>,
) -> Result<Sidecar, StartError> {
    let sc = Sidecar::spawn(SidecarSpec {
        program: program.to_path_buf(),
        args,
        redactor: redactor.clone(),
    })
    // Not found, not executable, wrong architecture: all mean the helper cannot run.
    .map_err(|_| StartError::BinaryMissing { name: tag })?;
    // Lets the next run find and stop this engine if this process is killed without cleanup.
    if let Some(pid) = sc.pid() {
        let exe = program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Ok(f) = write_pidfile(work_dir, tag, pid, &exe) {
            files.push(f);
        }
    }
    Ok(sc)
}

fn file_name(name: &str) -> String {
    format!("{}{name}", instance_prefix())
}

async fn wait_line(p: &mut Sidecar, needle: &str, limit: Duration) -> Result<String, StartError> {
    let end = tokio::time::Instant::now() + limit;
    let mut tail: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let join =
        |t: &std::collections::VecDeque<String>| t.iter().cloned().collect::<Vec<_>>().join("\n");
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, p.lines.recv()).await {
            Ok(Some(l)) if l.contains(needle) => return Ok(l),
            Ok(Some(l)) => {
                tail.push_back(l);
                if tail.len() > 20 {
                    tail.pop_front();
                }
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if let Ok(Some(st)) = p.try_exit() {
                    tail.push_back(format!("[engine {}]", describe_exit(&st)));
                }
                return Err(StartError::ExitedEarly { tail: join(&tail) });
            }
            Err(_) => return Err(StartError::Timeout { tail: join(&tail) }),
        }
    }
}

/// Name of the tunnel interface sing-box creates (see `singbox.rs`), as a pattern the firewall
/// can match. macOS names are `utunN` (pf group `utun`).
fn singbox_iface() -> String {
    if cfg!(target_os = "linux") {
        "wt0".into()
    } else if cfg!(target_os = "macos") {
        "utun".into()
    } else {
        "sing-tun".into()
    }
}

/// Tunnel interface name (or pattern) a profile's engine will use in TUN mode. Known before the
/// engine starts, so leak protection can be prepared first.
pub fn expected_tun_iface(profile: &Profile) -> String {
    match profile.protocol.engine() {
        EngineKind::OpenVpn => openvpn_iface(),
        _ => singbox_iface(),
    }
}

fn openvpn_iface() -> String {
    if cfg!(target_os = "linux") {
        "tun*".into()
    } else if cfg!(target_os = "macos") {
        "utun".into()
    } else {
        "OpenVPN*".into()
    }
}

/// Cancels a start in progress. The engine processes already started are stopped gracefully
/// (SIGTERM first) so routes and firewall hooks they installed are removed.
pub struct Cancel(tokio::sync::watch::Sender<bool>);

#[derive(Clone)]
pub struct CancelRx(tokio::sync::watch::Receiver<bool>);

pub fn cancel_pair() -> (Cancel, CancelRx) {
    let (tx, rx) = tokio::sync::watch::channel(false);
    (Cancel(tx), CancelRx(rx))
}

impl Cancel {
    pub fn cancel(&self) {
        let _ = self.0.send(true);
    }
}

impl CancelRx {
    /// A token that is never cancelled.
    pub fn never() -> Self {
        cancel_pair().1
    }
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }
    pub async fn cancelled(&mut self) {
        loop {
            if *self.0.borrow() {
                return;
            }
            if self.0.changed().await.is_err() {
                // Sender gone without cancelling: never cancelled.
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Things that must be free before an engine can start; failing here gives a precise message
/// instead of a timeout. An interface that is still being torn down by a just-stopped engine is
/// given a moment to disappear.
async fn precheck(o: &StartOptions, iface: Option<&str>) -> Result<(), StartError> {
    if let Mode::Proxy { socks_port } = &o.mode {
        if std::net::TcpListener::bind(("127.0.0.1", *socks_port)).is_err() {
            return Err(StartError::Busy {
                what: format!("port {socks_port}"),
            });
        }
    }
    if let (Mode::Tun, Some(name)) = (&o.mode, iface) {
        if cfg!(target_os = "linux") && !name.contains('*') {
            let p = std::path::Path::new("/sys/class/net").join(name);
            for _ in 0..40 {
                if !p.exists() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            return Err(StartError::Busy {
                what: format!("network interface {name}"),
            });
        }
    }
    Ok(())
}

pub async fn start(profile: &Profile, o: &StartOptions) -> Result<Tunnel, StartError> {
    start_cancellable(profile, o, CancelRx::never()).await
}

/// Like [`start`], but returns `Err(StartError::Cancelled)` promptly when `cancel` fires, after
/// stopping whatever was already started.
pub async fn start_cancellable(
    profile: &Profile,
    o: &StartOptions,
    mut cancel: CancelRx,
) -> Result<Tunnel, StartError> {
    // Leftovers of a crashed earlier run: engines still running, config files with secrets.
    let w = o.work_dir.clone();
    let _ = tokio::task::spawn_blocking(move || sweep_stale(&w)).await;
    let mut t = Tunnel {
        procs: Vec::new(),
        _files: Vec::new(),
        tun_iface: None,
        socks: None,
        warnings: Vec::new(),
    };
    let r = tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(StartError::Cancelled),
        r = launch(profile, o, &mut t) => r,
    };
    match r {
        Ok(()) => Ok(t),
        Err(e) => {
            t.stop().await;
            Err(e)
        }
    }
}

async fn launch(profile: &Profile, o: &StartOptions, t: &mut Tunnel) -> Result<(), StartError> {
    match profile.protocol.engine() {
        EngineKind::SingBox => launch_singbox(profile, o, None, Vec::new(), t).await,
        EngineKind::AmneziaWg => launch_awg(profile, o, t).await,
        EngineKind::OpenVpn => launch_openvpn(profile, o, t).await,
    }
}

fn last(t: &mut Tunnel) -> Result<&mut Sidecar, StartError> {
    t.procs
        .last_mut()
        .map(|(_, p)| p)
        .ok_or_else(|| StartError::Io("no engine".into()))
}

/// Wait until the proxy port accepts connections, failing fast if the engine dies meanwhile.
async fn wait_proxy_ready(
    sb: &mut Sidecar,
    addr: SocketAddr,
    limit: Duration,
) -> Result<(), StartError> {
    let end = tokio::time::Instant::now() + limit;
    let mut tail: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    loop {
        while let Ok(l) = sb.lines.try_recv() {
            tail.push_back(l);
            if tail.len() > 20 {
                tail.pop_front();
            }
        }
        let join = |t: &std::collections::VecDeque<String>| {
            t.iter().cloned().collect::<Vec<_>>().join("\n")
        };
        if let Ok(Some(st)) = sb.try_exit() {
            tail.push_back(format!("[engine {}]", describe_exit(&st)));
            return Err(StartError::ExitedEarly { tail: join(&tail) });
        }
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= end {
            return Err(StartError::Timeout { tail: join(&tail) });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn launch_singbox(
    profile: &Profile,
    o: &StartOptions,
    upstream: Option<SocketAddr>,
    bypass: Vec<IpAddr>,
    t: &mut Tunnel,
) -> Result<(), StartError> {
    let iface = singbox_iface();
    t.socks = match &o.mode {
        Mode::Proxy { socks_port } => Some(SocketAddr::from(([127, 0, 0, 1], *socks_port))),
        Mode::Tun => None,
    };
    t.tun_iface = matches!(o.mode, Mode::Tun).then(|| iface.clone());
    precheck(o, Some(&iface)).await?;
    let opts = singbox::Options {
        mode: Some(o.mode.clone()),
        dns: o.dns.clone(),
        upstream_socks: upstream,
        bypass,
        ..Default::default()
    };
    let built = singbox::build_with(profile, &opts)?;
    t.warnings = built.warnings;
    let mut cfg = built.config;
    cfg["log"]["level"] = serde_json::json!("info");
    let bytes = serde_json::to_vec(&cfg).map_err(|e| StartError::Io(e.to_string()))?;
    let file = PrivateFile::write(&o.work_dir, &file_name("sing-box.json"), &bytes)?;
    let sb = spawn(
        &o.bins.sing_box,
        vec!["run".into(), "-c".into(), file.path().into()],
        &o.redactor,
        &o.work_dir,
        "sing-box",
        &mut t._files,
    )?;
    t._files.push(file);
    // Owned by the tunnel from the first instant, so a cancel at any await below stops it.
    t.procs.push(("sing-box", sb));
    let socks = t.socks;
    let sb = last(t)?;
    match socks {
        Some(addr) => wait_proxy_ready(sb, addr, o.ready_timeout).await,
        None => wait_line(sb, "sing-box started", o.ready_timeout)
            .await
            .map(|_| ()),
    }
}

async fn launch_awg(profile: &Profile, o: &StartOptions, t: &mut Tunnel) -> Result<(), StartError> {
    let host = profile.host.clone();
    let port = profile.port;
    let ip = tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .map(|a| a.ip())
    })
    .await
    .map_err(|_| StartError::Resolve)?
    .ok_or(StartError::Resolve)?;
    let cfg = awg::helper_config(profile, ip, "127.0.0.1:0")?;
    let file = PrivateFile::write(
        &o.work_dir,
        &file_name("awg.json"),
        cfg.to_string().as_bytes(),
    )?;
    let helper = spawn(
        &o.bins.awg_socks,
        vec![file.path().into()],
        &o.redactor,
        &o.work_dir,
        "awg-socks",
        &mut t._files,
    )?;
    t._files.push(file);
    t.procs.push(("awg-socks", helper));
    let line = wait_line(last(t)?, "LISTEN ", o.ready_timeout).await?;
    let addr: SocketAddr = line
        .trim()
        .trim_start_matches("LISTEN ")
        .parse()
        .map_err(|_| StartError::Io("bad helper address".into()))?;
    launch_singbox(profile, o, Some(addr), vec![ip], t).await
}

async fn launch_openvpn(
    profile: &Profile,
    o: &StartOptions,
    t: &mut Tunnel,
) -> Result<(), StartError> {
    let text = openvpn::render(profile)?;
    let file = PrivateFile::write(&o.work_dir, &file_name("openvpn.ovpn"), text.as_bytes())?;
    let p = spawn(
        &o.bins.openvpn,
        vec!["--config".into(), file.path().into()],
        &o.redactor,
        &o.work_dir,
        "openvpn",
        &mut t._files,
    )?;
    t._files.push(file);
    t.procs.push(("openvpn", p));
    t.tun_iface = matches!(o.mode, Mode::Tun).then(openvpn_iface);
    wait_line(
        last(t)?,
        "Initialization Sequence Completed",
        o.ready_timeout,
    )
    .await
    .map(|_| ())
}
