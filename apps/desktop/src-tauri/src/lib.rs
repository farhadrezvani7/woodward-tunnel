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
use std::sync::mpsc;
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
    // The native dialog blocks its thread until the user answers: keep that off the async workers.
    let picked = tauri::async_runtime::spawn_blocking(move || app.dialog().file().blocking_pick_files())
        .await
        .map_err(|_| ApiError::new("internal", "dialog"))?;
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
    blocking(&b, |b| {
        b.disconnect();
        Ok(())
    })
    .await
}

#[tauri::command]
async fn allow_direct(b: B<'_>) -> Result<(), ApiError> {
    blocking(&b, |b| {
        b.allow_direct();
        Ok(())
    })
    .await
}

#[tauri::command]
async fn clear_leftover_rules(b: B<'_>) -> Result<(), ApiError> {
    blocking(&b, |b| {
        b.clear_leftover_rules();
        Ok(())
    })
    .await
}

/// True once per start when "connect on launch" is on; the UI then connects and shows any problem.
#[tauri::command]
async fn take_startup_connect(b: B<'_>) -> Result<bool, ApiError> {
    Ok(b.take_startup_connect())
}

/// Third-party notices bundled with the app (generated into resources at build time).
#[tauri::command]
async fn licenses_text(app: tauri::AppHandle) -> Result<String, ApiError> {
    let dir = app.path().resource_dir().map_err(|_| ApiError::new("not_found", ""))?;
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        let f = std::fs::File::open(dir.join("THIRD-PARTY-NOTICES.md")).map_err(|_| ApiError::new("not_found", ""))?;
        let mut buf = Vec::new();
        f.take(4 * 1024 * 1024).read_to_end(&mut buf).map_err(|_| ApiError::new("not_found", ""))?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    })
    .await
    .map_err(|_| ApiError::new("internal", "task"))?
}

#[tauri::command]
async fn get_status(b: B<'_>) -> Result<StatusDto, ApiError> {
    blocking(&b, |b| Ok(b.status())).await
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
async fn diagnostic_report(b: B<'_>) -> Result<String, ApiError> {
    blocking(&b, |b| Ok(b.diagnostic_report())).await
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
/// Whether a tray icon exists. Without one, closing the window must quit (nothing could bring it back).
struct TrayOk(AtomicBool);

fn show_main(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Secure-storage check with a deadline: a locked or missing Secret Service can wait for a prompt
/// nobody sees, which would leave the app without a window.
fn secrets_available() -> bool {
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new().name("keyring-probe".into()).spawn(move || {
        let _ = tx.send(core_keyring::KeyringStore::new("woodward-tunnel").probe().is_ok());
    });
    if spawned.is_err() {
        return false;
    }
    rx.recv_timeout(Duration::from_secs(10)).unwrap_or(false)
}

fn fatal(app: &tauri::AppHandle, msg: &str) {
    eprintln!("fatal: {msg}");
    let _ = app
        .dialog()
        .message(format!("Woodward Tunnel could not start.\nووردوارد تانل شروع نشد.\n\n{msg}"))
        .title("Woodward Tunnel")
        .blocking_show();
}

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

/// Opens secure storage and the backend, then builds the tray. Runs off the UI thread.
fn start_backend(app: tauri::AppHandle, data_dir: PathBuf, minimized: bool) {
    let (secrets, kind): (Arc<dyn SecretStore>, &str) = if secrets_available() {
        (Arc::new(core_keyring::KeyringStore::new("woodward-tunnel")), "os")
    } else {
        // Never fall back to files: without secure storage, profiles are kept for this session only.
        (Arc::new(MemorySecretStore::default()), "memory")
    };
    let mut cfg = BackendConfig::new(data_dir.clone(), discover_binaries(), kind);
    if cfg!(target_os = "macos") {
        if let Ok(res) = app.path().resource_dir() {
            let script = res.join("macos-elevate-singbox.sh");
            if script.exists() {
                std::env::set_var("WT_REAL_SING_BOX", &cfg.bins.sing_box);
                cfg.elevate_script = Some(script);
            }
        }
    }
    let sink_app = app.clone();
    let sink: backend::StatusSink = Arc::new(move |dto| {
        let _ = sink_app.emit("status", dto);
        tray::refresh(&sink_app);
    });
    let backend = match tauri::async_runtime::block_on(async { Backend::new(cfg, secrets, Arc::new(HttpFetcher), sink) }) {
        Ok(b) => b,
        Err(e) => {
            fatal(&app, &format!("The app data could not be opened ({}). Check free disk space and permissions of {}", e.code, data_dir.display()));
            app.exit(1);
            return;
        }
    };
    backend.start_wake_watch();
    app.manage(backend);
    let a2 = app.clone();
    let _ = app.run_on_main_thread(move || {
        let tray_ok = match tray::build(&a2) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("tray unavailable: {e}");
                false
            }
        };
        a2.manage(TrayOk(AtomicBool::new(tray_ok)));
        // Hidden start is only allowed when something can bring the window back.
        if minimized && !tray_ok {
            show_main(&a2);
        }
    });
}

pub fn run() {
    let app = tauri::Builder::default()
        // A second launch shows the running window instead of starting a second engine.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            if let Err(e) = std::fs::create_dir_all(&data_dir) {
                eprintln!("The data folder cannot be created: {}", e.kind());
                return Err(e.into());
            }
            app.manage(Quitting(AtomicBool::new(false)));
            // The window must appear at once: the secure-storage check (which can wait for a
            // keyring prompt) and the backend start-up run on their own thread. Until the backend
            // is managed, commands fail and the UI retries.
            let minimized = backend::peek_start_minimized(&data_dir) || std::env::args().any(|a| a == "--minimized");
            if !minimized {
                show_main(app.handle());
            }
            let handle = app.handle().clone();
            let started = std::thread::Builder::new().name("backend-start".into()).spawn(move || start_backend(handle, data_dir, minimized));
            if let Err(e) = started {
                eprintln!("The start-up thread could not be created: {e}");
                return Err(e.into());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                // Closing while a tunnel is up (or coming up) keeps it running from the tray;
                // closing while idle quits. Without a tray icon, closing always quits.
                let app = window.app_handle();
                let tray_ok = app.try_state::<TrayOk>().map(|t| t.0.load(Ordering::SeqCst)).unwrap_or(false);
                if let (true, Some(b)) = (tray_ok, app.try_state::<Arc<Backend>>()) {
                    let active = !matches!(b.status().state, "idle" | "failed");
                    if active && b.settings().close_to_tray {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                }
                return;
            }
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
            take_startup_connect,
            allow_direct,
            clear_leftover_rules,
            licenses_text,
            get_status,
            get_settings,
            set_settings,
            grant_privilege,
            app_info,
            diagnostic_report
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
            // Feedback at once: the engine can take a few seconds to stop.
            if let Some(w) = handle.get_webview_window("main") {
                let _ = w.hide();
            }
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
