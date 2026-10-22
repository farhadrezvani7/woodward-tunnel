//! Application facade used by every front end (desktop UI, CLI, mobile bindings):
//! import configs, manage profiles, and control the connection.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod controller;
mod fetch;

pub use controller::{Controller, ControllerConfig, Status, UiState};
pub use fetch::{Fetcher, FetchError};
#[cfg(feature = "http")]
pub use fetch::HttpFetcher;

use core_engine::singbox::Options;
use core_engine::Mode;
use core_import::Analysis;
use core_log::Redactor;
use core_model::{EngineKind, Profile};
use core_store::{ProfileSummary, SecretStore, Store, StoreError};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Short, credential-free description of which entry failed.
    pub label: String,
    /// Plain-language explanation for the user.
    pub message: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportReport {
    pub added: Vec<ProfileSummary>,
    pub duplicates: usize,
    pub problems: Vec<Problem>,
    /// Subscription URLs found; the UI must ask before fetching them.
    pub subscription_urls: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Fetch(#[from] FetchError),
}

/// What a platform needs to start a tunnel for a profile without running processes itself
/// (mobile apps feed `config_json` to the embedded sing-box library).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchPlan {
    SingBox { config_json: String, insecure_tls: bool },
    /// Needs the AmneziaWG helper and a SOCKS upstream; handled by the desktop runner.
    AmneziaWg,
    /// Needs the OpenVPN binary; handled by the desktop runner.
    OpenVpn,
}

pub struct App {
    store: Store,
    redactor: Redactor,
    fetcher: Arc<dyn Fetcher>,
    data_dir: PathBuf,
}

impl App {
    pub fn new(data_dir: &Path, secrets: Arc<dyn SecretStore>, fetcher: Arc<dyn Fetcher>) -> Result<Self, AppError> {
        std::fs::create_dir_all(data_dir).map_err(|e| StoreError::Db(e.to_string()))?;
        let store = Store::open(&data_dir.join("profiles.db"), secrets)?;
        Ok(Self { store, redactor: Redactor::new(), fetcher, data_dir: data_dir.to_path_buf() })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
    pub fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    fn finish(&self, a: Analysis, group: &str) -> Result<ImportReport, AppError> {
        let problems = a.issues.iter().map(|i| Problem { label: i.label.clone(), message: i.issue.user_message() }).collect();
        let report = self.store.add_many(a.profiles, group)?;
        Ok(ImportReport { added: report.added, duplicates: report.duplicates, problems, subscription_urls: a.subscription_urls })
    }

    /// Text from the clipboard, a pasted block, or a decoded camera QR.
    pub fn import_text(&self, text: &str, group: &str) -> Result<ImportReport, AppError> {
        self.finish(core_import::analyze(text), group)
    }

    /// File contents or image bytes (QR screenshot).
    pub fn import_bytes(&self, bytes: &[u8], group: &str) -> Result<ImportReport, AppError> {
        self.finish(core_import::analyze_bytes(bytes), group)
    }

    /// Download a subscription and import it. Call only after the user agreed to the request.
    pub fn import_subscription(&self, url: &str, group: &str) -> Result<ImportReport, AppError> {
        let body = self.fetcher.get(url)?;
        let mut a = core_import::analyze(&body);
        // A subscription that points to another URL is not followed (no redirect chains driven by remote content).
        a.subscription_urls.clear();
        self.finish(a, group)
    }

    pub fn list(&self) -> Result<Vec<ProfileSummary>, AppError> {
        Ok(self.store.list()?)
    }
    pub fn profile(&self, id: &str) -> Result<Profile, AppError> {
        let p = self.store.get(id)?;
        self.redactor.register_profile(&p);
        Ok(p)
    }
    pub fn rename(&self, id: &str, name: &str) -> Result<(), AppError> {
        Ok(self.store.rename(id, name)?)
    }
    pub fn set_group(&self, id: &str, group: &str) -> Result<(), AppError> {
        Ok(self.store.set_group(id, group)?)
    }
    pub fn delete(&self, id: &str) -> Result<(), AppError> {
        Ok(self.store.delete(id)?)
    }

    pub fn launch_plan(&self, id: &str, mode: Mode, dns: Vec<String>) -> Result<LaunchPlan, AppError> {
        let p = self.profile(id)?;
        Ok(match p.protocol.engine() {
            EngineKind::SingBox => {
                let b = core_engine::singbox::build_with(&p, &Options { mode: Some(mode), dns, ..Default::default() }).map_err(|e| StoreError::Db(e.to_string()))?;
                LaunchPlan::SingBox { config_json: b.config.to_string(), insecure_tls: !b.warnings.is_empty() }
            }
            EngineKind::AmneziaWg => LaunchPlan::AmneziaWg,
            EngineKind::OpenVpn => LaunchPlan::OpenVpn,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_store::MemorySecretStore;

    pub(crate) struct FakeFetcher(pub String);
    impl Fetcher for FakeFetcher {
        fn get(&self, _url: &str) -> Result<String, FetchError> {
            Ok(self.0.clone())
        }
    }

    fn app(body: &str) -> (App, PathBuf) {
        let dir = std::env::temp_dir().join(format!("wt-app-{}-{}", std::process::id(), body.len()));
        let _ = std::fs::remove_dir_all(&dir);
        (App::new(&dir, Arc::new(MemorySecretStore::default()), Arc::new(FakeFetcher(body.into()))).unwrap(), dir)
    }

    #[test]
    fn import_manage_and_plan() {
        let (a, dir) = app("trojan://pw1234@sub.example.com:443#S");
        let r = a.import_text("trojan://pw1234@a.example.com:443#A\nbogus://x\n", "Work").unwrap();
        assert_eq!((r.added.len(), r.problems.len()), (1, 1));
        assert!(!r.problems[0].message.is_empty());
        let id = r.added[0].id.clone();
        a.rename(&id, "Berlin").unwrap();
        assert_eq!(a.list().unwrap()[0].name, "Berlin");
        match a.launch_plan(&id, Mode::Proxy { socks_port: 1080 }, vec![]).unwrap() {
            LaunchPlan::SingBox { config_json, .. } => assert!(config_json.contains("trojan")),
            other => panic!("{other:?}"),
        }
        let s = a.import_subscription("https://x.example.com/sub", "Sub").unwrap();
        assert_eq!(s.added.len(), 1);
        a.delete(&id).unwrap();
        assert_eq!(a.list().unwrap().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }
}
