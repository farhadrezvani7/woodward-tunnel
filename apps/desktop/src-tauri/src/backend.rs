//! Window-independent application layer. Tauri commands are thin wrappers over this type, which
//! is also what the integration tests drive.

use crate::privilege::{self, PrivState};
use core_app::{App, AppError, Controller, ControllerConfig, Fetcher, ImportReport, Status, UiState};
use core_engine::runner::Binaries;
use core_engine::Mode;
use core_model::Protocol;
use core_store::{ProfileSummary, SecretStore};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Largest file the app will read for an import (config files are tiny; QR screenshots are small).
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_FILES_PER_IMPORT: usize = 20;

#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    /// Stable machine code the UI maps to a localized sentence.
    pub code: &'static str,
    /// Short, credential-free detail; shown only under advanced settings.
    pub detail: String,
}

impl ApiError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::Fetch(f) => ApiError::new("fetch_failed", f.user_message()),
            AppError::Store(s) => ApiError::new("store", s.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
    /// "fa" or "en".
    pub lang: String,
    /// "tun" (whole system) or "proxy" (local SOCKS only).
    pub mode: String,
    pub socks_port: u16,
    pub dns: Vec<String>,
    pub last_profile: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self { lang: "fa".into(), mode: "tun".into(), socks_port: 10808, dns: vec![], last_profile: None }
    }
}

fn valid_dns(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

impl Settings {
    fn validate(&self) -> Result<(), ApiError> {
        if !matches!(self.lang.as_str(), "fa" | "en") {
            return Err(ApiError::new("bad_settings", "lang"));
        }
        if !matches!(self.mode.as_str(), "tun" | "proxy") {
            return Err(ApiError::new("bad_settings", "mode"));
        }
        if self.socks_port < 1024 {
            return Err(ApiError::new("bad_settings", "port"));
        }
        if self.dns.len() > 3 || !self.dns.iter().all(|d| valid_dns(d)) {
            return Err(ApiError::new("bad_settings", "dns"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileDto {
    pub id: String,
    pub name: String,
    pub protocol: &'static str,
    pub group: String,
    pub host: String,
    pub port: u16,
}

pub fn protocol_label(p: Protocol) -> &'static str {
    match p {
        Protocol::WireGuard => "WireGuard",
        Protocol::AmneziaWg => "AmneziaWG",
        Protocol::Vless => "VLESS",
        Protocol::Vmess => "VMess",
        Protocol::Trojan => "Trojan",
        Protocol::Shadowsocks => "Shadowsocks",
        Protocol::Hysteria2 => "Hysteria2",
        Protocol::OpenVpn => "OpenVPN",
        Protocol::Tuic => "TUIC",
        Protocol::Hysteria1 => "Hysteria",
        Protocol::Socks => "SOCKS",
        Protocol::HttpProxy => "HTTP",
        Protocol::AnyTls => "AnyTLS",
        Protocol::Ssh => "SSH",
    }
}

impl From<ProfileSummary> for ProfileDto {
    fn from(p: ProfileSummary) -> Self {
        Self { id: p.id, name: p.name, protocol: protocol_label(p.protocol), group: p.group, host: p.host, port: p.port }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProblemDto {
    pub label: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ImportDto {
    pub added: Vec<ProfileDto>,
    pub duplicates: usize,
    pub problems: Vec<ProblemDto>,
    pub subscription_urls: Vec<String>,
}

impl From<ImportReport> for ImportDto {
    fn from(r: ImportReport) -> Self {
        Self {
            added: r.added.into_iter().map(Into::into).collect(),
            duplicates: r.duplicates,
            problems: r.problems.into_iter().map(|p| ProblemDto { label: p.label, message: p.message }).collect(),
            subscription_urls: r.subscription_urls,
        }
    }
}

impl ImportDto {
    fn merge(&mut self, o: ImportDto) {
        self.added.extend(o.added);
        self.duplicates += o.duplicates;
        self.problems.extend(o.problems);
        for u in o.subscription_urls {
            if !self.subscription_urls.contains(&u) {
                self.subscription_urls.push(u);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusDto {
    /// idle | preparing | connecting | connected | reconnecting | disconnecting | failed
    pub state: &'static str,
    pub profile_id: Option<String>,
    /// Unix milliseconds.
    pub connected_since: Option<u64>,
    pub message: Option<String>,
    pub attempt: u32,
    pub insecure_tls: bool,
}

impl From<&Status> for StatusDto {
    fn from(s: &Status) -> Self {
        let state = match s.state {
            UiState::Idle => "idle",
            UiState::Preparing => "preparing",
            UiState::Connecting => "connecting",
            UiState::Connected => "connected",
            UiState::Reconnecting => "reconnecting",
            UiState::Disconnecting => "disconnecting",
            UiState::Failed => "failed",
        };
        let since = s.connected_since.and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64);
        Self { state, profile_id: s.profile_id.clone(), connected_since: since, message: s.message.clone(), attempt: s.attempt, insecure_tls: s.insecure_tls }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    pub version: &'static str,
    pub platform: &'static str,
    pub sing_box_found: bool,
    pub awg_found: bool,
    pub openvpn_found: bool,
    /// Secure storage state: "os" (keychain) or "memory" (not remembered after closing).
    pub secrets: String,
    pub privilege: &'static str,
    pub data_dir: String,
}

pub struct BackendConfig {
    pub data_dir: PathBuf,
    pub bins: Binaries,
    /// macOS only: script that starts the engine through a one-time administrator prompt.
    pub elevate_script: Option<PathBuf>,
    /// A TCP endpoint reached through the tunnel to prove it works.
    pub probe: SocketAddr,
    pub ready_timeout: Duration,
    pub secrets_kind: String,
    /// Settings that override the saved ones on first load (tests, packaging checks).
    pub initial: Option<Settings>,
}

impl BackendConfig {
    pub fn new(data_dir: PathBuf, bins: Binaries, secrets_kind: &str) -> Self {
        Self {
            data_dir,
            bins,
            elevate_script: None,
            probe: SocketAddr::from(([1, 1, 1, 1], 443)),
            ready_timeout: Duration::from_secs(20),
            secrets_kind: secrets_kind.into(),
            initial: None,
        }
    }
}

pub type StatusSink = Arc<dyn Fn(StatusDto) + Send + Sync>;

pub struct Backend {
    app: Arc<App>,
    cfg: BackendConfig,
    settings: Mutex<Settings>,
    controller: Mutex<Controller>,
    sink: StatusSink,
    rt: tokio::runtime::Handle,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Backend {
    /// Must be called inside a tokio runtime context (the controller task is spawned on it).
    pub fn new(cfg: BackendConfig, secrets: Arc<dyn SecretStore>, fetcher: Arc<dyn Fetcher>, sink: StatusSink) -> Result<Arc<Self>, ApiError> {
        let app = Arc::new(App::new(&cfg.data_dir.join("data"), secrets, fetcher)?);
        let mut settings = load_settings(&cfg.data_dir);
        if let Some(i) = &cfg.initial {
            settings = i.clone();
        }
        if settings.validate().is_err() {
            settings = Settings::default();
        }
        let rt = tokio::runtime::Handle::current();
        let controller = Self::spawn_controller(&app, &cfg, &settings, &rt, &sink);
        Ok(Arc::new(Self { app, cfg, settings: Mutex::new(settings), controller: Mutex::new(controller), sink, rt }))
    }

    fn engine_program(cfg: &BackendConfig, s: &Settings) -> PathBuf {
        match (&cfg.elevate_script, s.mode.as_str()) {
            (Some(script), "tun") => script.clone(),
            _ => cfg.bins.sing_box.clone(),
        }
    }

    fn spawn_controller(app: &Arc<App>, cfg: &BackendConfig, s: &Settings, rt: &tokio::runtime::Handle, sink: &StatusSink) -> Controller {
        let mode = if s.mode == "proxy" { Mode::Proxy { socks_port: s.socks_port } } else { Mode::Tun };
        let mut bins = cfg.bins.clone();
        bins.sing_box = Self::engine_program(cfg, s);
        let cc = ControllerConfig {
            mode,
            dns: s.dns.clone(),
            bins,
            probe: cfg.probe,
            ready_timeout: cfg.ready_timeout,
            work_dir: cfg.data_dir.join("run"),
        };
        let _g = rt.enter();
        let c = Controller::spawn(app.clone(), cc);
        let mut rx = c.status();
        let sink = sink.clone();
        rt.spawn(async move {
            sink(StatusDto::from(&*rx.borrow()));
            while rx.changed().await.is_ok() {
                let dto = StatusDto::from(&*rx.borrow());
                sink(dto);
            }
        });
        c
    }

    // ---- profiles -------------------------------------------------------------------------

    pub fn list_profiles(&self) -> Result<Vec<ProfileDto>, ApiError> {
        Ok(self.app.list()?.into_iter().map(Into::into).collect())
    }

    pub fn import_text(&self, text: &str) -> Result<ImportDto, ApiError> {
        Ok(self.app.import_text(text, "")?.into())
    }

    /// Import chosen or dropped files. Only the given regular files are read, each size-capped.
    pub fn import_files(&self, paths: &[PathBuf]) -> Result<ImportDto, ApiError> {
        let mut total = ImportDto::default();
        for p in paths.iter().take(MAX_FILES_PER_IMPORT) {
            match read_capped(p) {
                Ok(bytes) => total.merge(self.app.import_bytes(&bytes, "")?.into()),
                Err(why) => total.problems.push(ProblemDto { label: file_label(p), message: why.into() }),
            }
        }
        Ok(total)
    }

    /// Call only after the user confirmed in the UI.
    pub fn import_subscription(&self, url: &str, group: &str) -> Result<ImportDto, ApiError> {
        Ok(self.app.import_subscription(url, group)?.into())
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<(), ApiError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 80 {
            return Err(ApiError::new("bad_name", ""));
        }
        Ok(self.app.rename(id, name)?)
    }

    pub fn set_group(&self, id: &str, group: &str) -> Result<(), ApiError> {
        let group = group.trim();
        if group.chars().count() > 60 {
            return Err(ApiError::new("bad_name", ""));
        }
        Ok(self.app.set_group(id, group)?)
    }

    pub fn delete(&self, id: &str) -> Result<(), ApiError> {
        let st = self.status();
        if st.profile_id.as_deref() == Some(id) && st.state != "idle" && st.state != "failed" {
            self.disconnect();
        }
        Ok(self.app.delete(id)?)
    }

    // ---- connection -----------------------------------------------------------------------

    fn real_engine(&self) -> &Path {
        &self.cfg.bins.sing_box
    }

    pub fn privilege_state(&self) -> PrivState {
        let s = lock(&self.settings);
        if s.mode == "proxy" {
            return PrivState::Ok;
        }
        privilege::check(self.real_engine(), self.cfg.elevate_script.is_some())
    }

    pub fn connect(&self, id: &str) -> Result<(), ApiError> {
        if !self.cfg.bins.sing_box.exists() && self.cfg.bins.sing_box.components().count() > 1 {
            return Err(ApiError::new("engine_missing", "sing-box"));
        }
        if self.privilege_state() == PrivState::NeedsGrant {
            return Err(ApiError::new("needs_privilege", ""));
        }
        {
            let mut s = lock(&self.settings);
            if s.last_profile.as_deref() != Some(id) {
                s.last_profile = Some(id.to_string());
                let _ = save_settings(&self.cfg.data_dir, &s);
            }
        }
        lock(&self.controller).connect(id);
        Ok(())
    }

    /// Connect to the last used profile, or the only/first one (tray button).
    pub fn connect_last(&self) -> Result<(), ApiError> {
        let list = self.app.list()?;
        let last = lock(&self.settings).last_profile.clone();
        let id = last.filter(|l| list.iter().any(|p| &p.id == l)).or_else(|| list.first().map(|p| p.id.clone()));
        match id {
            Some(id) => self.connect(&id),
            None => Err(ApiError::new("no_profile", "")),
        }
    }

    pub fn disconnect(&self) {
        lock(&self.controller).disconnect();
    }

    pub fn network_changed(&self) {
        lock(&self.controller).network_changed();
    }

    pub fn status(&self) -> StatusDto {
        let c = lock(&self.controller).status();
        let s = StatusDto::from(&*c.borrow());
        s
    }

    /// Disconnect and wait (bounded) until the engine process is gone. Used when quitting.
    pub async fn shutdown(&self, limit: Duration) {
        let mut rx = lock(&self.controller).status();
        if matches!(rx.borrow().state, UiState::Idle | UiState::Failed) {
            return;
        }
        self.disconnect();
        let _ = tokio::time::timeout(limit, async {
            loop {
                if matches!(rx.borrow().state, UiState::Idle | UiState::Failed) {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        })
        .await;
    }

    // ---- settings and system --------------------------------------------------------------

    pub fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    pub fn set_settings(&self, new: Settings) -> Result<Settings, ApiError> {
        new.validate()?;
        let (old, mut new) = {
            let mut g = lock(&self.settings);
            let old = g.clone();
            // last_profile is owned by the backend.
            let mut n = new;
            n.last_profile = old.last_profile.clone();
            *g = n.clone();
            (old, n)
        };
        save_settings(&self.cfg.data_dir, &new).map_err(|e| ApiError::new("store", e.to_string()))?;
        if old.mode != new.mode || old.socks_port != new.socks_port || old.dns != new.dns {
            // The engine configuration changed: stop the old tunnel and start a fresh controller.
            let mut c = lock(&self.controller);
            c.disconnect();
            let fresh = Self::spawn_controller(&self.app, &self.cfg, &new, &self.rt, &self.sink);
            // Dropping the old handle closes its command channel; it stops its engine and exits.
            *c = fresh;
        }
        new.last_profile = None;
        Ok(new)
    }

    pub fn grant_privilege(&self) -> Result<(), ApiError> {
        privilege::grant(self.real_engine()).map_err(|e| ApiError::new("grant_failed", e))
    }

    pub fn info(&self) -> AppInfo {
        let exists = |p: &Path| p.exists() || which(p);
        AppInfo {
            version: env!("CARGO_PKG_VERSION"),
            platform: std::env::consts::OS,
            sing_box_found: exists(&self.cfg.bins.sing_box),
            awg_found: exists(&self.cfg.bins.awg_socks),
            openvpn_found: exists(&self.cfg.bins.openvpn),
            secrets: self.cfg.secrets_kind.clone(),
            privilege: match self.privilege_state() {
                PrivState::Ok => "ok",
                PrivState::NeedsGrant => "needs_grant",
            },
            data_dir: self.cfg.data_dir.display().to_string(),
        }
    }
}

fn which(p: &Path) -> bool {
    // Bare program names are resolved through PATH.
    if p.components().count() != 1 {
        return false;
    }
    std::env::var_os("PATH").map(|paths| std::env::split_paths(&paths).any(|d| d.join(p).exists())).unwrap_or(false)
}

fn file_label(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().chars().take(60).collect()).unwrap_or_default()
}

fn read_capped(p: &Path) -> Result<Vec<u8>, &'static str> {
    use std::io::Read;
    let meta = std::fs::metadata(p).map_err(|_| "فایل خوانده نشد.")?;
    if !meta.is_file() {
        return Err("این مورد یک فایل نیست.");
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err("فایل بزرگ‌تر از حد مجاز است.");
    }
    let mut buf = Vec::new();
    std::fs::File::open(p).and_then(|f| f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf)).map_err(|_| "فایل خوانده نشد.")?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err("فایل بزرگ‌تر از حد مجاز است.");
    }
    Ok(buf)
}

fn settings_path(dir: &Path) -> PathBuf {
    dir.join("settings.json")
}

fn load_settings(dir: &Path) -> Settings {
    std::fs::read(settings_path(dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_settings(dir: &Path, s: &Settings) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join("settings.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(s).unwrap_or_default())?;
    std::fs::rename(tmp, settings_path(dir))
}

/// Epoch milliseconds now (exposed for the UI timer baseline).
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
