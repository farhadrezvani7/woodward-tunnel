//! Start and stop a full tunnel for a profile: picks the right engine(s), writes private config
//! files, spawns the processes and waits until they are actually ready.

use crate::sidecar::{PrivateFile, Sidecar, SidecarSpec};
use crate::singbox::{self, Warning};
use crate::{awg, openvpn, probe, EngineError, Mode};
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

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error("io: {0}")]
    Io(String),
    #[error("engine exited before it was ready")]
    ExitedEarly,
    #[error("engine did not become ready in time")]
    Timeout,
    #[error("could not resolve the server address")]
    Resolve,
}

impl From<std::io::Error> for StartError {
    fn from(e: std::io::Error) -> Self {
        StartError::Io(e.kind().to_string())
    }
}

pub struct Tunnel {
    procs: Vec<(&'static str, Sidecar)>,
    _files: Vec<PrivateFile>,
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
        for (name, p) in self.procs.iter_mut() {
            if matches!(p.try_exit(), Ok(Some(_)) | Err(_)) {
                return Some(*name);
            }
        }
        None
    }

    pub async fn stop(self) {
        // Stop the front engine first so traffic is not routed into a dead helper.
        for (_, p) in self.procs.into_iter() {
            let _ = p.stop(Duration::from_secs(3)).await;
        }
    }
}

fn spawn(
    program: &std::path::Path,
    args: Vec<OsString>,
    redactor: &Redactor,
) -> Result<Sidecar, StartError> {
    Ok(Sidecar::spawn(SidecarSpec {
        program: program.to_path_buf(),
        args,
        redactor: redactor.clone(),
    })?)
}

async fn wait_line(p: &mut Sidecar, needle: &str, limit: Duration) -> Result<String, StartError> {
    let end = tokio::time::Instant::now() + limit;
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, p.lines.recv()).await {
            Ok(Some(l)) if l.contains(needle) => return Ok(l),
            Ok(Some(_)) => {}
            Ok(None) => return Err(StartError::ExitedEarly),
            Err(_) => return Err(StartError::Timeout),
        }
    }
}

pub async fn start(profile: &Profile, o: &StartOptions) -> Result<Tunnel, StartError> {
    match profile.protocol.engine() {
        EngineKind::SingBox => start_singbox(profile, o, None, Vec::new(), None).await,
        EngineKind::AmneziaWg => start_awg(profile, o).await,
        EngineKind::OpenVpn => start_openvpn(profile, o).await,
    }
}

async fn start_singbox(
    profile: &Profile,
    o: &StartOptions,
    upstream: Option<SocketAddr>,
    bypass: Vec<IpAddr>,
    helper: Option<(&'static str, Sidecar, PrivateFile)>,
) -> Result<Tunnel, StartError> {
    let opts = singbox::Options {
        mode: Some(o.mode.clone()),
        dns: o.dns.clone(),
        upstream_socks: upstream,
        bypass,
    };
    let built = singbox::build_with(profile, &opts)?;
    let mut cfg = built.config;
    cfg["log"]["level"] = serde_json::json!("info");
    let bytes = serde_json::to_vec(&cfg).map_err(|e| StartError::Io(e.to_string()))?;
    let file = PrivateFile::write(&o.work_dir, "sing-box.json", &bytes)?;
    let mut sb = spawn(
        &o.bins.sing_box,
        vec!["run".into(), "-c".into(), file.path().into()],
        &o.redactor,
    )?;
    let mut procs = Vec::new();
    let mut files = vec![file];
    if let Some((n, p, f)) = helper {
        procs.push((n, p));
        files.push(f);
    }
    let socks = match &o.mode {
        Mode::Proxy { socks_port } => Some(SocketAddr::from(([127, 0, 0, 1], *socks_port))),
        Mode::Tun => None,
    };
    let ready = match socks {
        Some(addr) => probe::wait_listening(addr, o.ready_timeout)
            .await
            .map_err(|_| StartError::Timeout),
        None => wait_line(&mut sb, "sing-box started", o.ready_timeout)
            .await
            .map(|_| ()),
    };
    procs.push(("sing-box", sb));
    let t = Tunnel {
        procs,
        _files: files,
        socks,
        warnings: built.warnings,
    };
    if let Err(e) = ready {
        t.stop().await;
        return Err(e);
    }
    Ok(t)
}

async fn start_awg(profile: &Profile, o: &StartOptions) -> Result<Tunnel, StartError> {
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
    let file = PrivateFile::write(&o.work_dir, "awg.json", cfg.to_string().as_bytes())?;
    let mut helper = spawn(&o.bins.awg_socks, vec![file.path().into()], &o.redactor)?;
    let line = match wait_line(&mut helper, "LISTEN ", o.ready_timeout).await {
        Ok(l) => l,
        Err(e) => {
            let _ = helper.stop(Duration::from_secs(1)).await;
            return Err(e);
        }
    };
    let addr: SocketAddr = line
        .trim()
        .trim_start_matches("LISTEN ")
        .parse()
        .map_err(|_| StartError::Io("bad helper address".into()))?;
    start_singbox(
        profile,
        o,
        Some(addr),
        vec![ip],
        Some(("awg-socks", helper, file)),
    )
    .await
}

async fn start_openvpn(profile: &Profile, o: &StartOptions) -> Result<Tunnel, StartError> {
    let text = openvpn::render(profile)?;
    let file = PrivateFile::write(&o.work_dir, "openvpn.ovpn", text.as_bytes())?;
    let mut p = spawn(
        &o.bins.openvpn,
        vec!["--config".into(), file.path().into()],
        &o.redactor,
    )?;
    match wait_line(&mut p, "Initialization Sequence Completed", o.ready_timeout).await {
        Ok(_) => Ok(Tunnel {
            procs: vec![("openvpn", p)],
            _files: vec![file],
            socks: None,
            warnings: vec![],
        }),
        Err(e) => {
            let _ = p.stop(Duration::from_secs(2)).await;
            Err(e)
        }
    }
}
