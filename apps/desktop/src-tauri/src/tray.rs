//! System tray: show window, connect/disconnect, quit. Labels follow the UI language.

use crate::backend::Backend;
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};

struct Items {
    show: MenuItem<tauri::Wry>,
    toggle: MenuItem<tauri::Wry>,
    quit: MenuItem<tauri::Wry>,
}

fn labels(lang: &str, active: bool) -> (&'static str, &'static str, &'static str, &'static str) {
    match (lang, active) {
        ("en", false) => ("Show window", "Connect", "Quit", "Woodward Tunnel: disconnected"),
        ("en", true) => ("Show window", "Disconnect", "Quit", "Woodward Tunnel: connected"),
        (_, false) => ("نمایش پنجره", "اتصال", "خروج", "Woodward Tunnel: قطع"),
        (_, true) => ("نمایش پنجره", "قطع اتصال", "خروج", "Woodward Tunnel: وصل"),
    }
}

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let (s, t, q, _) = labels("fa", false);
    let show = MenuItem::with_id(app, "show", s, true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", t, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", q, true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &quit])?;
    app.manage(Items { show, toggle, quit });
    let mut b = TrayIconBuilder::with_id("main").menu(&menu).show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        b = b.icon(icon.clone());
    }
    b.on_menu_event(|app, ev| match ev.id().as_ref() {
        "show" => show_window(app),
        "quit" => app.exit(0),
        "toggle" => {
            let Some(backend) = app.try_state::<Arc<Backend>>() else { return };
            let st = backend.status();
            if matches!(st.state, "idle" | "failed") {
                if let Err(e) = backend.connect_last() {
                    show_window(app);
                    let _ = app.emit("app-error", e);
                }
            } else {
                backend.disconnect();
            }
        }
        _ => {}
    })
    .on_tray_icon_event(|tray, ev| {
        if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
            show_window(tray.app_handle());
        }
    })
    .build(app)?;
    refresh(app);
    Ok(())
}

/// Re-label the menu and tooltip from the current state and language.
pub fn refresh(app: &AppHandle) {
    let (Some(items), Some(backend)) = (app.try_state::<Items>(), app.try_state::<Arc<Backend>>()) else { return };
    let st = backend.status();
    let active = !matches!(st.state, "idle" | "failed");
    let lang = backend.settings().lang;
    let (s, t, q, tip) = labels(&lang, active);
    let _ = items.show.set_text(s);
    let _ = items.toggle.set_text(t);
    let _ = items.quit.set_text(q);
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(tip));
    }
}
