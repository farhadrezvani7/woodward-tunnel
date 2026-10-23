//! Woodward Tunnel desktop shell. The Rust side calls the shared core in-process; the web UI in
//! `../ui` only receives summaries (names, protocol badges, state), never configs or secrets.

pub mod backend;
pub mod privilege;
mod tray;

use backend::{ApiError, AppInfo, Backend, BackendConfig, ImportDto, ProfileDto, Settings, StatusDto};
use core_app::HttpFetcher;
use core_engine::runner::Binaries;
use core_store::{MemorySecretStore, SecretStore};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{DragDropEvent, Emitter, Manager, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;

type B<'a> = State<'a, Arc<Backend>>;

async fn blocking<T: Send + 'static>(b: &B<'_>, f: impl FnOnce(&Backend) -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
    let b = b.inner().clone();
    tauri::async_runtime::spawn_blocking(move || f(&b)).await.map_err(|_| ApiError::new("internal", "task"))?
}

#[tauri::command]
async fn list_profiles(b: B<'_>) -> Result<Vec<ProfileDto>, ApiError> {
    blocking(&b, |b| b.list_profiles()).await
}

#[tauri::command]
async fn import_text(b: B<'_>, text: String) -> Result<ImportDto, ApiError> {
    blocking(&b, move |b| b.import_text(&text)).await
}

#[tauri::command]
async fn pick_and_import(app: tauri::AppHandle, b: B<'_>) -> Result<Option<ImportDto>, ApiError> {
    let picked = app.dialog().file().blocking_pick_files();
    let Some(files) = picked else { return Ok(None) };
    let paths: Vec<PathBuf> = files.into_iter().filter_map(|f| f.into_path().ok()).collect();
    blocking(&b, move |b| b.import_files(&paths)).await.map(Some)
}

#[tauri::command]
async fn import_subscription(b: B<'_>, url: String) -> Result<ImportDto, ApiError> {
    blocking(&b, move |b| b.import_subscription(&url, "")).await
}

#[tauri::command]
async fn rename_profile(b: B<'_>, id: String, name: String) -> Result<(), ApiError> {
    blocking(&b, move |b| b.rename(&id, &name)).await
}

#[tauri::command]
async fn set_profile_group(b: B<'_>, id: String, group: String) -> Result<(), ApiError> {
    blocking(&b, move |b| b.set_group(&id, &group)).await
}

#[tauri::command]
async fn delete_profile(b: B<'_>, id: String) -> Result<(), ApiError> {
    blocking(&b, move |b| b.delete(&id)).await
}

#[tauri::command]
async fn connect(b: B<'_>, id: String) -> Result<(), ApiError> {
    blocking(&b, move |b| b.connect(&id)).await
}

#[tauri::command]
async fn disconnect(b: B<'_>) -> Result<(), ApiError> {
    b.disconnect();
    Ok(())
}

#[tauri::command]
async fn get_status(b: B<'_>) -> Result<StatusDto, ApiError> {
    Ok(b.status())
}

#[tauri::command]
async fn get_settings(b: B<'_>) -> Result<Settings, ApiError> {
    Ok(b.settings())
}

#[tauri::command]
async fn set_settings(app: tauri::AppHandle, b: B<'_>, settings: Settings) -> Result<Settings, ApiError> {
    let out = blocking(&b, move |b| b.set_settings(settings)).await?;
    tray::refresh(&app);
    Ok(out)
}

#[tauri::command]
async fn grant_privilege(b: B<'_>) -> Result<(), ApiError> {
    blocking(&b, |b| b.grant_privilege()).await
}

#[tauri::command]
async fn app_info(b: B<'_>) -> Result<AppInfo, ApiError> {
    blocking(&b, |b| Ok(b.info())).await
}

/// Where helper executables live: next to the app first (bundled sidecars), then PATH.
fn discover_binaries() -> Binaries {
    let dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let pick = |names: &[&str]| -> PathBuf {
        for n in names {
            let exe = if cfg!(windows) { format!("{n}.exe") } else { (*n).to_string() };
            if let Some(p) = dir.as_ref().map(|d| d.join(&exe)) {
                if p.exists() {
                    return p;
                }
            }
        }
        let last = names[names.len() - 1];
        PathBuf::from(if cfg!(windows) { format!("{last}.exe") } else { last.to_string() })
    };
    // Bundled sidecars carry a `wt-` prefix so they never collide with a system sing-box package.
    Binaries { sing_box: pick(&["wt-sing-box", "sing-box"]), awg_socks: pick(&["wt-awg-socks", "awg-socks"]), openvpn: pick(&["openvpn"]) }
}

struct Quitting(AtomicBool);

fn emit_import(app: &tauri::AppHandle, r: Result<ImportDto, ApiError>) {
    match r {
        Ok(dto) => {
            let _ = app.emit("imported", dto);
        }
        Err(e) => {
            let _ = app.emit("app-error", e);
        }
    }
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_dir)?;
            let keyring = core_keyring::KeyringStore::new("woodward-tunnel");
            let (secrets, kind): (Arc<dyn SecretStore>, &str) = match keyring.probe() {
                Ok(()) => (Arc::new(keyring), "os"),
                // Never fall back to files: without secure storage, profiles are kept for this session only.
                Err(_) => (Arc::new(MemorySecretStore::default()), "memory"),
            };
            let mut cfg = BackendConfig::new(data_dir, discover_binaries(), kind);
            if cfg!(target_os = "macos") {
                if let Ok(res) = app.path().resource_dir() {
                    let script = res.join("macos-elevate-singbox.sh");
                    if script.exists() {
                        std::env::set_var("WT_REAL_SING_BOX", &cfg.bins.sing_box);
                        cfg.elevate_script = Some(script);
                    }
                }
            }
            let handle = app.handle().clone();
            let sink: backend::StatusSink = Arc::new(move |dto| {
                let _ = handle.emit("status", dto);
                tray::refresh(&handle);
            });
            let backend = tauri::async_runtime::block_on(async { Backend::new(cfg, secrets, Arc::new(HttpFetcher), sink) })
                .map_err(|e| format!("{}: {}", e.code, e.detail))?;
            app.manage(backend);
            app.manage(Quitting(AtomicBool::new(false)));
            tray::build(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            let WindowEvent::DragDrop(d) = event else { return };
            match d {
                DragDropEvent::Enter { .. } => {
                    let _ = window.emit("drag-state", true);
                }
                DragDropEvent::Leave => {
                    let _ = window.emit("drag-state", false);
                }
                DragDropEvent::Drop { paths, .. } => {
                    let _ = window.emit("drag-state", false);
                    let paths = paths.clone();
                    let app = window.app_handle().clone();
                    let b = window.state::<Arc<Backend>>().inner().clone();
                    tauri::async_runtime::spawn_blocking(move || emit_import(&app, b.import_files(&paths)));
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            list_profiles,
            import_text,
            pick_and_import,
            import_subscription,
            rename_profile,
            set_profile_group,
            delete_profile,
            connect,
            disconnect,
            get_status,
            get_settings,
            set_settings,
            grant_privilege,
            app_info
        ])
        .build(tauri::generate_context!());
    let app = match app {
        Ok(a) => a,
        Err(e) => {
            eprintln!("failed to start: {e}");
            std::process::exit(1);
        }
    };
    app.run(|handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let Some(q) = handle.try_state::<Quitting>() else { return };
            if q.0.swap(true, Ordering::SeqCst) {
                return; // already shutting down: let this exit proceed
            }
            api.prevent_exit();
            let h = handle.clone();
            tauri::async_runtime::spawn(async move {
                if let Some(b) = h.try_state::<Arc<Backend>>() {
                    b.shutdown(Duration::from_secs(5)).await;
                }
                h.exit(0);
            });
        }
    });
}
