//! Leak protection settings and the serialised handle the controller uses to apply and remove
//! firewall rules without racing a cancelled start.

use core_engine::Mode;
use core_policy::{Firewall, KillSwitch, PolicyError};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct KillSwitchConfig {
    /// Block all traffic outside the tunnel once it is verified, and keep blocking while the
    /// tunnel is down and being re-established. Default: on in TUN mode, off in proxy mode
    /// (there is no system tunnel to protect).
    pub enabled: bool,
    /// If the rules cannot be applied (no privileges, tool missing) the connection fails with
    /// the `killswitch` failure code instead of silently running unprotected. Default: true.
    pub required: bool,
    /// Keep private LAN ranges reachable (printers, NAS). Also allows LAN DNS resolvers.
    pub allow_lan: bool,
    /// Extra interfaces always allowed (docker0, `br-*`, virbr0). Opt-in.
    pub allow_ifaces: Vec<String>,
    /// Resolvers allowed (port 53) while the tunnel is down so the server host name can be
    /// looked up. Empty: read the system's resolvers at connect time.
    pub bootstrap_dns: Vec<IpAddr>,
    /// Prefix for firewall commands when the front end is not root, e.g. `["pkexec"]`.
    pub elevate: Vec<String>,
    /// Use this firewall instead of the real one (tests).
    pub firewall: Option<Arc<Firewall>>,
    /// Look for rules left by a crashed run when the controller starts. Needs the same
    /// privileges as applying them, so it defaults to off when `elevate` is set.
    pub check_leftover: bool,
}

impl KillSwitchConfig {
    pub fn for_mode(mode: &Mode) -> Self {
        Self {
            enabled: matches!(mode, Mode::Tun),
            required: true,
            allow_lan: false,
            allow_ifaces: Vec::new(),
            bootstrap_dns: Vec::new(),
            elevate: Vec::new(),
            firewall: None,
            check_leftover: true,
        }
    }
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            check_leftover: false,
            ..Self::for_mode(&Mode::Tun)
        }
    }

    pub(crate) fn build_firewall(&self, state_dir: &Path) -> Option<Arc<Firewall>> {
        if let Some(f) = &self.firewall {
            return Some(f.clone());
        }
        Firewall::system(state_dir.to_path_buf(), self.elevate.clone())
            .ok()
            .map(Arc::new)
    }
}

/// Serialises firewall calls. A start that was cancelled may still have an apply queued; the
/// epoch counter makes such a stale apply a no-op once a remove has been requested.
#[derive(Clone)]
pub(crate) struct KsHandle {
    fw: Arc<Firewall>,
    lock: Arc<Mutex<()>>,
    epoch: Arc<AtomicU64>,
    present: Arc<AtomicBool>,
}

impl KsHandle {
    pub fn new(fw: Arc<Firewall>) -> Self {
        Self {
            fw,
            lock: Arc::new(Mutex::new(())),
            epoch: Arc::new(AtomicU64::new(0)),
            present: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Rules loaded by this process are in place.
    pub fn present(&self) -> bool {
        self.present.load(Ordering::SeqCst)
    }

    pub async fn apply(&self, ks: KillSwitch) -> Result<(), PolicyError> {
        let snap = self.epoch.load(Ordering::SeqCst);
        let h = self.clone();
        tokio::task::spawn_blocking(move || {
            let _g = h
                .lock
                .lock()
                .map_err(|_| PolicyError::Tool("lock".into()))?;
            if h.epoch.load(Ordering::SeqCst) != snap {
                return Ok(()); // a remove was requested meanwhile
            }
            h.fw.apply(&ks)?;
            h.present.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .map_err(|_| PolicyError::Tool("task failed".into()))?
    }

    pub async fn remove(&self) -> Result<(), PolicyError> {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        let h = self.clone();
        tokio::task::spawn_blocking(move || {
            let _g = h
                .lock
                .lock()
                .map_err(|_| PolicyError::Tool("lock".into()))?;
            h.fw.remove()?;
            h.present.store(false, Ordering::SeqCst);
            Ok(())
        })
        .await
        .map_err(|_| PolicyError::Tool("task failed".into()))?
    }

    pub async fn is_active(&self) -> Result<bool, PolicyError> {
        let h = self.clone();
        tokio::task::spawn_blocking(move || {
            let _g = h
                .lock
                .lock()
                .map_err(|_| PolicyError::Tool("lock".into()))?;
            h.fw.is_active()
        })
        .await
        .map_err(|_| PolicyError::Tool("task failed".into()))?
    }
}
