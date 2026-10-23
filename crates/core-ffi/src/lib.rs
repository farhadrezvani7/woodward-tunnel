//! Mobile bindings (Kotlin and Swift) generated with UniFFI. The platform app implements
//! [`SecretCallbacks`] on top of Android Keystore / iOS Keychain; everything else lives in Rust.

use core_app::{App, FetchError, Fetcher, HttpFetcher, LaunchPlan};
use core_engine::Mode;
use core_store::{SecretStore, StoreError};
use std::path::Path;
use std::sync::Arc;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Plain-language text for the user in Persian (`reason`) and English (`reason_en`).
    #[error("{reason}")]
    Failed { reason: String, reason_en: String },
}

fn fail(fa: impl Into<String>, en: impl Into<String>) -> FfiError {
    FfiError::Failed {
        reason: fa.into(),
        reason_en: en.into(),
    }
}

/// Implemented by the platform app; values are opaque strings to store securely.
#[uniffi::export(with_foreign)]
pub trait SecretCallbacks: Send + Sync {
    fn put(&self, id: String, value: String) -> bool;
    fn get(&self, id: String) -> Option<String>;
    fn delete(&self, id: String) -> bool;
}

struct CallbackStore(Arc<dyn SecretCallbacks>);
impl SecretStore for CallbackStore {
    fn put(&self, id: &str, value: &str) -> Result<(), StoreError> {
        if self.0.put(id.into(), value.into()) {
            Ok(())
        } else {
            Err(StoreError::Secrets(
                "platform store refused the write".into(),
            ))
        }
    }
    fn get(&self, id: &str) -> Result<Option<String>, StoreError> {
        Ok(self.0.get(id.into()))
    }
    fn delete(&self, id: &str) -> Result<(), StoreError> {
        if self.0.delete(id.into()) {
            Ok(())
        } else {
            Err(StoreError::Secrets(
                "platform store refused the delete".into(),
            ))
        }
    }
}

#[derive(uniffi::Record)]
pub struct FfiProfile {
    pub id: String,
    pub name: String,
    pub protocol_id: String,
    pub protocol_name: String,
    pub host: String,
    pub port: u16,
    pub group: String,
    pub created_at: i64,
}

#[derive(uniffi::Record)]
pub struct FfiProblem {
    pub label: String,
    pub message: String,
    pub message_en: String,
    pub code: String,
}

#[derive(uniffi::Record)]
pub struct FfiImportReport {
    pub added: Vec<FfiProfile>,
    pub duplicates: u32,
    pub problems: Vec<FfiProblem>,
    pub subscription_urls: Vec<String>,
}

#[derive(uniffi::Enum)]
pub enum FfiLaunchPlan {
    /// Feed `config_json` to the embedded sing-box (libbox).
    SingBox {
        config_json: String,
        insecure_tls: bool,
    },
    /// Run the AmneziaWG helper with `helper_json` (listens on 127.0.0.1:`socks_port`), then sing-box
    /// with `singbox_config_json`. `endpoint_ip` is the already-resolved peer and is excluded from the
    /// tunnel routes in the sing-box config.
    AmneziaWg {
        helper_json: String,
        singbox_config_json: String,
        socks_port: u16,
        endpoint_ip: String,
    },
    /// Needs the OpenVPN engine (not available on this build).
    OpenVpn,
}

fn conv(s: core_store::ProfileSummary) -> FfiProfile {
    FfiProfile {
        id: s.id,
        name: s.name,
        protocol_id: s.protocol.id().into(),
        protocol_name: s.protocol.display_name().into(),
        host: s.host,
        port: s.port,
        group: s.group,
        created_at: s.created_at,
    }
}

fn conv_report(r: core_app::ImportReport) -> FfiImportReport {
    FfiImportReport {
        added: r.added.into_iter().map(conv).collect(),
        duplicates: r.duplicates as u32,
        problems: r
            .problems
            .into_iter()
            .map(|p| FfiProblem {
                label: p.label,
                message: p.message,
                message_en: p.message_en,
                code: p.code,
            })
            .collect(),
        subscription_urls: r.subscription_urls,
    }
}

struct Http;
impl Fetcher for Http {
    fn get(&self, url: &str) -> Result<String, FetchError> {
        HttpFetcher.get(url)
    }
}

#[derive(uniffi::Object)]
pub struct WtApp {
    app: App,
}

#[uniffi::export]
impl WtApp {
    #[uniffi::constructor]
    pub fn new(data_dir: String, secrets: Arc<dyn SecretCallbacks>) -> Result<Arc<Self>, FfiError> {
        let app = App::new(
            Path::new(&data_dir),
            Arc::new(CallbackStore(secrets)),
            Arc::new(Http),
        )
        .map_err(|_| {
            fail(
                "ذخیره‌سازی برنامه باز نشد.",
                "The app storage could not be opened.",
            )
        })?;
        Ok(Arc::new(Self { app }))
    }

    pub fn import_text(&self, text: String, group: String) -> Result<FfiImportReport, FfiError> {
        self.app
            .import_text(&text, &group)
            .map(conv_report)
            .map_err(|_| fail("ذخیرهٔ کانفیگ ناموفق بود.", "Saving the config failed."))
    }

    /// File contents or image bytes (QR screenshot).
    pub fn import_bytes(&self, bytes: Vec<u8>, group: String) -> Result<FfiImportReport, FfiError> {
        self.app
            .import_bytes(&bytes, &group)
            .map(conv_report)
            .map_err(|_| fail("ذخیرهٔ کانفیگ ناموفق بود.", "Saving the config failed."))
    }

    /// Only after the user confirmed downloading the subscription.
    pub fn import_subscription(
        &self,
        url: String,
        group: String,
    ) -> Result<FfiImportReport, FfiError> {
        self.app
            .import_subscription(&url, &group)
            .map(conv_report)
            .map_err(|e| match e {
                core_app::AppError::Fetch(f) => fail(f.user_message(), f.user_message_en()),
                _ => fail("ذخیرهٔ کانفیگ ناموفق بود.", "Saving the config failed."),
            })
    }

    pub fn list(&self) -> Result<Vec<FfiProfile>, FfiError> {
        self.app
            .list()
            .map(|v| v.into_iter().map(conv).collect())
            .map_err(|_| {
                fail(
                    "خواندن فهرست کانفیگ‌ها ناموفق بود.",
                    "Reading the config list failed.",
                )
            })
    }

    pub fn rename(&self, id: String, name: String) -> Result<(), FfiError> {
        self.app
            .rename(&id, &name)
            .map_err(|_| fail("تغییر نام ناموفق بود.", "Renaming failed."))
    }

    pub fn set_group(&self, id: String, group: String) -> Result<(), FfiError> {
        self.app
            .set_group(&id, &group)
            .map_err(|_| fail("تغییر دسته ناموفق بود.", "Changing the group failed."))
    }

    pub fn delete(&self, id: String) -> Result<(), FfiError> {
        self.app
            .delete(&id)
            .map_err(|_| fail("حذف ناموفق بود.", "Deleting failed."))
    }

    /// Text report for support that is safe to share (no names, servers or secrets). Show it to the
    /// user before they send it. `log_tail` is the app's recent engine output; it is redacted again here.
    pub fn diagnostic_report(&self, log_tail: Vec<String>) -> String {
        core_app::diag::report_embedded(&self.app, None, &log_tail)
    }

    /// `dns`: resolvers reached through the tunnel. Mobile always uses the system TUN.
    pub fn launch_plan(&self, id: String, dns: Vec<String>) -> Result<FfiLaunchPlan, FfiError> {
        match self.app.launch_plan(&id, Mode::Tun, dns).map_err(|_| {
            fail(
                "این کانفیگ آماده اتصال نیست.",
                "This config is not ready to connect.",
            )
        })? {
            LaunchPlan::SingBox {
                config_json,
                insecure_tls,
            } => Ok(FfiLaunchPlan::SingBox {
                config_json,
                insecure_tls,
            }),
            LaunchPlan::AmneziaWg {
                helper_json,
                singbox_config_json,
                socks_port,
                endpoint_ip,
            } => Ok(FfiLaunchPlan::AmneziaWg {
                helper_json,
                singbox_config_json,
                socks_port,
                endpoint_ip,
            }),
            LaunchPlan::OpenVpn => Ok(FfiLaunchPlan::OpenVpn),
        }
    }
}
