//! Window-independent application layer. Tauri commands are thin wrappers over this type, which
//! is also what the integration tests drive.

use crate::privilege::{self, PrivState};
use core_app::{App, AppError, Controller, ControllerConfig, ControllerOptions, Fetcher, ImportReport, ProbeMode, Status, UiState};
use core_engine::runner::Binaries;
use core_engine::Mode;
use core_model::Protocol;
use core_store::{ProfileSummary, SecretStore, StoreError};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Largest file the app will read for an import (config files are tiny; QR screenshots are small).
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_FILES_PER_IMPORT: usize = 20;
/// Largest pasted text the app will analyze (500 links are about 100 KB).
pub const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_URL_LEN: usize = 2048;
pub const MAX_NAME_CHARS: usize = 80;
pub const MAX_GROUP_CHARS: usize = 60;

#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    /// Stable machine code the UI maps to a localized sentence.
    pub code: &'static str,
    /// Short, credential-free detail; shown only under advanced settings.
    pub detail: String,
    /// English version of `detail` when the core provides one (empty otherwise).
    pub detail_en: String,
}

impl ApiError {
    pub(crate) fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into(), detail_en: String::new() }
    }
}

impl From<AppError> for ApiError {
    fn from(e: AppError) -> Self {
        match e {
            AppError::Fetch(f) => ApiError { code: "fetch_failed", detail: f.user_message(), detail_en: f.user_message_en() },
            AppError::Store(StoreError::NotFound) => ApiError::new("not_found", ""),
            AppError::Store(StoreError::Secrets(_)) => ApiError::new("secrets", ""),
            // The detail of database errors can contain file paths: keep it out of the UI.
            AppError::Store(_) => ApiError::new("store", ""),
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
    /// Connect to the last used server when the app starts.
    pub connect_on_launch: bool,
    /// Start hidden in the tray (also done when started with `--minimized`).
    pub start_minimized: bool,
    /// Closing the window while connected keeps the app (and the tunnel) running in the tray.
    pub close_to_tray: bool,
    /// Block traffic outside the tunnel while connected and while it is being rebuilt (system
    /// tunnel mode only). On by default.
    pub leak_protection: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lang: "auto".into(),
            mode: "tun".into(),
            socks_port: 10808,
            dns: vec![],
            last_profile: None,
            connect_on_launch: false,
            start_minimized: false,
            close_to_tray: true,
            leak_protection: true,
        }
    }
}

impl Settings {
    /// "fa" or "en": `auto` follows the operating system language (Persian when unknown).
    pub fn resolved_lang(&self) -> &'static str {
        match self.lang.as_str() {
            "en" => "en",
            "fa" => "fa",
            _ => {
                let env = ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"].iter().find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()));
                match env {
                    Some(v) if !v.to_ascii_lowercase().starts_with("fa") && !v.starts_with("C") && !v.starts_with("POSIX") => "en",
                    _ => "fa",
                }
            }
        }
    }
}

fn valid_dns(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // A host name: labels of letters, digits and hyphens.
    s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// Remove characters that can scramble the display or hide text: control characters, bidi
/// overrides/embeddings/isolates, line and paragraph separators, BOM. ZWNJ/ZWJ (needed for
/// Persian) and LRM/RLM are kept. The result is trimmed and limited to `max` characters.
pub fn clean_text(s: &str, max: usize) -> String {
    let kept: String = s
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(*c, '\u{061C}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}' | '\u{FEFF}')
        })
        .collect();
    kept.trim().chars().take(max).collect()
}

/// Profile ids are generated by the store; anything else coming from the UI is rejected early.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

impl Settings {
    fn validate(&self) -> Result<(), ApiError> {
        if !matches!(self.lang.as_str(), "fa" | "en" | "auto") {
            return Err(ApiError::new("bad_settings", "lang"));
        }
        if !matches!(self.mode.as_str(), "tun" | "proxy") {
            return Err(ApiError::new("bad_settings", "mode"));
        }
        if self.socks_port < 1024 || self.socks_port == 0 {
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
        let mut name = clean_text(&p.name, MAX_NAME_CHARS);
        if name.is_empty() {
            name = clean_text(&p.host, MAX_NAME_CHARS);
        }
        Self { id: p.id, name, protocol: protocol_label(p.protocol), group: clean_text(&p.group, MAX_GROUP_CHARS), host: clean_text(&p.host, 253), port: p.port }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProblemDto {
    pub label: String,
    pub message: String,
    pub message_en: String,
    pub code: String,
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
            problems: r.problems.into_iter().map(|p| ProblemDto { label: clean_text(&p.label, 80), message: p.message, message_en: p.message_en, code: p.code }).collect(),
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
    pub message_en: Option<String>,
    /// network | server | config | permission | auth | tls | dns | port_busy | engine_missing | engine_version | device | killswitch
    pub failure_code: Option<String>,
    pub attempt: u32,
    pub insecure_tls: bool,
    /// Leak protection rules are loaded (the network is blocked on purpose unless connected).
    pub kill_switch_active: bool,
    /// Rules of a crashed earlier run were found.
    pub kill_switch_leftover: bool,
    /// English detail when removing or checking the rules failed.
    pub kill_switch_error: Option<String>,
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
        Self { state, profile_id: s.profile_id.clone(), connected_since: since, message: s.message.clone(), message_en: s.message_en.clone(), failure_code: s.failure_code.clone(), attempt: s.attempt, insecure_tls: s.insecure_tls, kill_switch_active: s.kill_switch_active, kill_switch_leftover: s.kill_switch_leftover, kill_switch_error: s.kill_switch_error.clone() }
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
    /// Language the `auto` setting resolves to from the environment.
    pub os_lang: &'static str,
}

pub struct BackendConfig {
    pub data_dir: PathBuf,
    pub bins: Binaries,
    /// macOS only: script that starts the engine through a one-time administrator prompt.
    pub elevate_script: Option<PathBuf>,
    /// A TCP endpoint reached through the tunnel to prove it works; only used when `tcp_probe`
    /// is set (tests). By default the core proves the tunnel with a DNS query answered through it.
    pub probe: SocketAddr,
    pub tcp_probe: bool,
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
            tcp_probe: false,
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
    /// Imports are serialized: the store and the keychain are not meant for concurrent bulk writes.
    import_gate: Mutex<()>,
    startup_connect: std::sync::atomic::AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Backend {
    /// Must be called inside a tokio runtime context (the controller task is spawned on it).
    pub fn new(cfg: BackendConfig, secrets: Arc<dyn SecretStore>, fetcher: Arc<dyn Fetcher>, sink: StatusSink) -> Result<Arc<Self>, ApiError> {
        // Without secure storage the secrets live in memory only. The profile list must not outlive
        // them (it would list servers that can no longer connect), so it goes to a folder that is
        // wiped at every start.
        let store_dir = if cfg.secrets_kind == "os" {
            cfg.data_dir.join("data")
        } else {
            let d = cfg.data_dir.join("session-data");
            let _ = std::fs::remove_dir_all(&d);
            d
        };
        let app = Arc::new(App::new(&store_dir, secrets, fetcher)?);
        let mut settings = load_settings(&cfg.data_dir);
        if let Some(i) = &cfg.initial {
            settings = i.clone();
        }
        if settings.validate().is_err() {
            settings = Settings::default();
        }
        let rt = tokio::runtime::Handle::current();
        let controller = Self::spawn_controller(&app, &cfg, &settings, &rt, &sink);
        let startup_connect = std::sync::atomic::AtomicBool::new(settings.connect_on_launch);
        Ok(Arc::new(Self {
            app,
            cfg,
            settings: Mutex::new(settings),
            controller: Mutex::new(controller),
            sink,
            rt,
            import_gate: Mutex::new(()),
            startup_connect,
        }))
    }

    /// True once, at start-up, when the user asked to connect on launch.
    pub fn take_startup_connect(&self) -> bool {
        self.startup_connect.swap(false, std::sync::atomic::Ordering::SeqCst)
    }

    /// Tell the controller about sleep/wake: a monotonic-vs-wall clock gap means the machine was
    /// suspended. The thread ends when the backend is dropped.
    pub fn start_wake_watch(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let spawned = std::thread::Builder::new().name("wake-watch".into()).spawn(move || {
            let mut last = SystemTime::now();
            loop {
                std::thread::sleep(Duration::from_secs(3));
                let Some(b) = weak.upgrade() else { return };
                let now = SystemTime::now();
                // Sleeping stops `sleep`'s clock on some systems and not on others; the wall clock
                // always jumps by the suspended time, so a large gap is the signal either way.
                let gap = now.duration_since(last).unwrap_or_default();
                last = now;
                if gap > Duration::from_secs(15) {
                    b.network_changed();
                }
            }
        });
        let _ = spawned;
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
        let cc = ControllerConfig { mode, dns: s.dns.clone(), bins, probe: cfg.probe, ready_timeout: cfg.ready_timeout, work_dir: cfg.data_dir.join("run") };
        let mut opts = ControllerOptions::recommended(&cc);
        if cfg.tcp_probe {
            opts.probe_mode = ProbeMode::Tcp;
        }
        // Never run `version` through the macOS elevation wrapper.
        opts.version_check = Some(cfg.bins.sing_box.clone());
        opts.kill_switch.enabled = opts.kill_switch.enabled && s.leak_protection;
        if opts.kill_switch.enabled && !privilege::is_elevated() {
            if cfg!(target_os = "linux") {
                // Firewall rules need root: ask through polkit (the engine's file capabilities do not cover them).
                opts.kill_switch.elevate = vec!["pkexec".into()];
            } else {
                // Without root the rules cannot be loaded (macOS without a helper): do not refuse to
                // connect, but the UI says so in the diagnostic report and README.
                opts.kill_switch.required = false;
            }
        }
        let _g = rt.enter();
        let c = Controller::spawn_with(app.clone(), cc, opts);
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
        if text.len() > MAX_TEXT_BYTES {
            return Err(ApiError::new("too_big", ""));
        }
        let _g = lock(&self.import_gate);
        Ok(self.app.import_text(text, "")?.into())
    }

    /// Import chosen or dropped files. Only the given regular files are read, each size-capped.
    pub fn import_files(&self, paths: &[PathBuf]) -> Result<ImportDto, ApiError> {
        let mut total = ImportDto::default();
        let _g = lock(&self.import_gate);
        for p in paths.iter().take(MAX_FILES_PER_IMPORT) {
            match read_capped(p) {
                Ok(bytes) => total.merge(self.app.import_bytes(&bytes, "")?.into()),
                Err((fa, en)) => total.problems.push(ProblemDto { label: file_label(p), message: fa.into(), message_en: en.into(), code: "file".into() }),
            }
        }
        if paths.len() > MAX_FILES_PER_IMPORT {
            total.problems.push(ProblemDto {
                label: String::new(),
                message: format!("فقط {} فایل اول خوانده شد؛ بقیه نادیده گرفته شدند.", MAX_FILES_PER_IMPORT),
                message_en: format!("Only the first {MAX_FILES_PER_IMPORT} files were read; the rest were ignored."),
                code: "too_many_files".into(),
            });
        }
        Ok(total)
    }

    /// Call only after the user confirmed in the UI.
    pub fn import_subscription(&self, url: &str, group: &str) -> Result<ImportDto, ApiError> {
        if url.len() > MAX_URL_LEN || url.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(ApiError::new("bad_url", ""));
        }
        let _g = lock(&self.import_gate);
        Ok(self.app.import_subscription(url, group)?.into())
    }

    pub fn rename(&self, id: &str, name: &str) -> Result<(), ApiError> {
        if !valid_id(id) {
            return Err(ApiError::new("not_found", ""));
        }
        let name = clean_text(name, MAX_NAME_CHARS);
        if name.is_empty() {
            return Err(ApiError::new("bad_name", ""));
        }
        Ok(self.app.rename(id, &name)?)
    }

    pub fn set_group(&self, id: &str, group: &str) -> Result<(), ApiError> {
        if !valid_id(id) {
            return Err(ApiError::new("not_found", ""));
        }
        let group = clean_text(group, MAX_GROUP_CHARS);
        Ok(self.app.set_group(id, &group)?)
    }

    pub fn delete(&self, id: &str) -> Result<(), ApiError> {
        if !valid_id(id) {
            return Err(ApiError::new("not_found", ""));
        }
        let st = self.status();
        if st.profile_id.as_deref() == Some(id) && st.state != "idle" && st.state != "failed" {
            self.disconnect();
            // Let the engine stop before its secrets disappear (bounded: the controller may be busy starting).
            for _ in 0..60 {
                if matches!(self.status().state, "idle" | "failed") {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
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
        if !valid_id(id) || !self.app.list()?.iter().any(|p| p.id == id) {
            return Err(ApiError::new("not_found", ""));
        }
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

    /// "Allow direct connections": drop the leak protection rules and stop the retry loop.
    pub fn allow_direct(&self) {
        lock(&self.controller).allow_direct();
    }

    /// Remove rules a crashed earlier run left behind.
    pub fn clear_leftover_rules(&self) {
        lock(&self.controller).clear_leftover_rules();
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
            // Persist first: a failed save must not leave the running settings changed.
            save_settings(&self.cfg.data_dir, &n).map_err(|_| ApiError::new("store", ""))?;
            *g = n.clone();
            (old, n)
        };
        if old.mode != new.mode || old.socks_port != new.socks_port || old.dns != new.dns || old.leak_protection != new.leak_protection {
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

    /// Text the user can review and copy; built from counts, versions and the redacted engine log.
    /// It is only shown in the UI, never sent anywhere.
    pub fn diagnostic_report(&self) -> String {
        let (status, log) = {
            let c = lock(&self.controller);
            let s = c.status().borrow().clone();
            (s, c.recent_log())
        };
        core_app::diag::report(&self.app, Some(&status), &log, &self.cfg.bins)
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
            os_lang: lock(&self.settings).resolved_lang(),
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
    p.file_name().map(|n| clean_text(&n.to_string_lossy(), 60)).unwrap_or_default()
}

const READ_FAIL: (&str, &str) = ("فایل خوانده نشد.", "The file could not be read.");
const TOO_BIG: (&str, &str) = ("فایل بزرگ‌تر از حد مجاز است.", "The file is larger than allowed.");

fn read_capped(p: &Path) -> Result<Vec<u8>, (&'static str, &'static str)> {
    use std::io::Read;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    // A FIFO or device must not block the import thread forever: open without waiting.
    #[cfg(target_os = "linux")]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, 0o4000);
    #[cfg(target_os = "macos")]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, 0x0004);
    let f = opts.open(p).map_err(|_| READ_FAIL)?;
    // Check the opened handle, not the path: nothing can be swapped in between.
    let meta = f.metadata().map_err(|_| READ_FAIL)?;
    if !meta.is_file() {
        return Err(("این مورد یک فایل نیست.", "This item is not a file."));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(TOO_BIG);
    }
    let mut buf = Vec::new();
    f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf).map_err(|_| READ_FAIL)?;
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(TOO_BIG);
    }
    Ok(buf)
}

fn settings_path(dir: &Path) -> PathBuf {
    dir.join("settings.json")
}

/// Whether the saved settings ask for a hidden start (read before the backend exists).
pub fn peek_start_minimized(dir: &Path) -> bool {
    load_settings(dir).start_minimized
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
