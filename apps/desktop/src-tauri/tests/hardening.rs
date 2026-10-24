//! Hostile-input tests for the application layer: every argument the UI (or a dropped file, or a
//! pasted text) can supply is checked here. No engine is needed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use core_app::{FetchError, Fetcher};
use core_engine::runner::Binaries;
use core_store::MemorySecretStore;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wt_desktop::backend::{clean_text, valid_id, Backend, BackendConfig, Settings};

struct NoFetch;
impl Fetcher for NoFetch {
    fn get(&self, _url: &str) -> Result<String, FetchError> {
        Err(FetchError::Failed("offline".into()))
    }
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wt-hard-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn backend_in(dir: &Path, kind: &str) -> Arc<Backend> {
    let cfg = BackendConfig::new(dir.join("app"), Binaries { sing_box: "sing-box".into(), awg_socks: "awg-socks".into(), openvpn: "openvpn".into() }, kind);
    Backend::new(cfg, Arc::new(MemorySecretStore::default()), Arc::new(NoFetch), Arc::new(|_| {})).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_text_removes_bidi_and_control_characters() {
    assert_eq!(clean_text("a\u{202E}b\u{202C}c", 80), "abc");
    assert_eq!(clean_text("x\u{2066}y\u{2069}", 80), "xy");
    assert_eq!(clean_text("line1\nline2\t\u{0007}", 80), "line1line2");
    assert_eq!(clean_text("  padded  ", 80), "padded");
    // Persian needs ZWNJ; it must survive.
    assert_eq!(clean_text("می\u{200C}خواهم", 80), "می\u{200C}خواهم");
    assert_eq!(clean_text(&"é".repeat(200), 80).chars().count(), 80);
    assert_eq!(clean_text("😀😀😀", 2), "😀😀");
    assert_eq!(clean_text("\u{202E}\u{200B}\n", 80), "\u{200B}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ids_are_validated() {
    assert!(valid_id("00ff00ff00ff00ff00ff00ff00ff00ff"));
    for bad in ["", "../x", "a b", "a'b", "x\0y", &"a".repeat(129), "é"] {
        assert!(!valid_id(bad), "{bad:?}");
    }
    let dir = tmp("ids");
    let b = backend_in(&dir, "memory");
    assert_eq!(b.rename("../../etc", "x").unwrap_err().code, "not_found");
    assert_eq!(b.set_group("a b", "x").unwrap_err().code, "not_found");
    assert_eq!(b.delete("'; drop table").unwrap_err().code, "not_found");
    assert_eq!(b.connect("nonexistent").unwrap_err().code, "not_found");
    assert_eq!(b.connect("").unwrap_err().code, "not_found");
}

#[tokio::test(flavor = "multi_thread")]
async fn names_are_sanitized_and_html_stays_text() {
    let dir = tmp("names");
    let b = backend_in(&dir, "memory");
    let r = b.import_text("trojan://pw12345678@a.example.com:443#%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E%E2%80%AEevil").unwrap();
    assert_eq!(r.added.len(), 1);
    let name = &r.added[0].name;
    assert!(!name.contains('\u{202E}'), "bidi override must not reach the UI: {name:?}");
    // Markup is not interpreted by the backend; the UI renders names with textContent.
    assert!(name.contains("<img"));
    let id = r.added[0].id.clone();
    assert_eq!(b.rename(&id, "   ").unwrap_err().code, "bad_name");
    assert_eq!(b.rename(&id, "\u{202E}\u{202C}").unwrap_err().code, "bad_name");
    b.rename(&id, &format!("{}\u{202E}", "ب".repeat(500))).unwrap();
    let p = b.list_profiles().unwrap();
    assert_eq!(p[0].name.chars().count(), 80);
    assert!(!p[0].name.contains('\u{202E}'));
    b.set_group(&id, "گروه\nA").unwrap();
    assert_eq!(b.list_profiles().unwrap()[0].group, "گروهA");
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_text_and_bad_urls_are_refused() {
    let dir = tmp("big");
    let b = backend_in(&dir, "memory");
    let huge = "x".repeat(wt_desktop::backend::MAX_TEXT_BYTES + 1);
    assert_eq!(b.import_text(&huge).unwrap_err().code, "too_big");
    for url in ["https://a.example.com/x y", "https://a.example.com/\nhttps://b", &format!("https://a.example.com/{}", "a".repeat(3000))] {
        assert_eq!(b.import_subscription(url, "").unwrap_err().code, "bad_url");
    }
    // Non-https and private hosts are refused by the core before any request.
    assert_eq!(b.import_subscription("http://a.example.com/x", "").unwrap_err().code, "fetch_failed");
    assert_eq!(b.import_subscription("https://127.0.0.1/x", "").unwrap_err().code, "fetch_failed");
    // Offline: a plain failure with a message in both languages, no panic.
    let e = b.import_subscription("https://sub.example.com/x", "").unwrap_err();
    assert_eq!(e.code, "fetch_failed");
    assert!(!e.detail.is_empty() && !e.detail_en.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn special_files_never_hang_or_get_read() {
    let dir = tmp("special");
    let b = backend_in(&dir, "memory");
    let started = Instant::now();
    let good = dir.join("good.txt");
    std::fs::write(&good, "trojan://pw12345678@a.example.com:443#A\n").unwrap();

    let fifo = dir.join("pipe");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let link_zero = dir.join("zero-link");
    std::os::unix::fs::symlink("/dev/zero", &link_zero).unwrap();
    let link_good = dir.join("good-link");
    std::os::unix::fs::symlink(&good, &link_good).unwrap();
    let dangling = dir.join("dangling");
    std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();

    let r = b.import_files(&[fifo, PathBuf::from("/dev/zero"), PathBuf::from("/dev/null"), link_zero, dangling, dir.clone()]).unwrap();
    assert!(r.added.is_empty());
    assert_eq!(r.problems.len(), 6, "{:?}", r.problems);
    assert!(started.elapsed() < Duration::from_secs(5), "a special file blocked the import");

    // A symlink to a regular file is fine (the user chose it).
    let r = b.import_files(&[link_good]).unwrap();
    assert_eq!(r.added.len(), 1);

    // More files than the limit: the extra ones are reported, not silently dropped.
    let many: Vec<PathBuf> = (0..25).map(|_| good.clone()).collect();
    let r = b.import_files(&many).unwrap();
    assert!(r.problems.iter().any(|p| p.code == "too_many_files"));
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_validation_and_defaults() {
    let dir = tmp("settings");
    let b = backend_in(&dir, "memory");
    let d = b.settings();
    assert_eq!(d.lang, "auto");
    assert!(d.close_to_tray && d.leak_protection && !d.connect_on_launch && !d.start_minimized);
    let ok = Settings { dns: vec!["1.1.1.1".into(), "dns.google".into(), "2606:4700:4700::1111".into()], ..d.clone() };
    b.set_settings(ok).unwrap();
    for bad_dns in [":::", "1.1.1.1:53", "a b", "-x.com", "x..com", "http://x", ""] {
        let s = Settings { dns: vec![bad_dns.into()], ..d.clone() };
        assert_eq!(b.set_settings(s).unwrap_err().code, "bad_settings", "{bad_dns:?}");
    }
    for s in [
        Settings { socks_port: 0, ..d.clone() },
        Settings { socks_port: 80, ..d.clone() },
        Settings { lang: "de".into(), ..d.clone() },
        Settings { mode: "bridge".into(), ..d.clone() },
        Settings { dns: vec!["1.1.1.1".into(); 4], ..d.clone() },
    ] {
        assert_eq!(b.set_settings(s).unwrap_err().code, "bad_settings");
    }
    // A rejected change leaves the running settings alone, and a good one persists.
    assert_eq!(b.settings().socks_port, 10808);
    b.set_settings(Settings { lang: "en".into(), close_to_tray: false, ..d }).unwrap();
    let again = backend_in(&dir, "memory");
    assert_eq!(again.settings().lang, "en");
    assert!(!again.settings().close_to_tray);
    // Corrupt settings file: defaults, no crash.
    std::fs::write(dir.join("app").join("settings.json"), b"{not json").unwrap();
    assert_eq!(backend_in(&dir, "memory").settings().lang, "auto");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_secure_storage_profiles_do_not_outlive_the_session() {
    let dir = tmp("memory");
    {
        let b = backend_in(&dir, "memory");
        b.import_text("trojan://pw12345678@a.example.com:443#A").unwrap();
        assert_eq!(b.list_profiles().unwrap().len(), 1);
    }
    let b = backend_in(&dir, "memory");
    assert!(b.list_profiles().unwrap().is_empty(), "ghost profiles without secrets must not be listed");
    // With real secure storage the list persists.
    {
        let b = backend_in(&dir, "os");
        b.import_text("trojan://pw12345678@a.example.com:443#B").unwrap();
    }
    assert_eq!(backend_in(&dir, "os").list_profiles().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn five_hundred_mixed_links_import_and_report_each_problem() {
    let dir = tmp("500");
    let b = backend_in(&dir, "memory");
    let mut text = String::new();
    for i in 0..300 {
        text.push_str(&format!("trojan://pw{i:010}@h{i}.example.com:443#Server-{i}\n"));
    }
    for i in 0..100 {
        text.push_str(&format!("trojan://pw{i:010}@h{i}.example.com:443#Server-{i}\n")); // duplicates
    }
    for i in 0..60 {
        text.push_str(&format!("vless://not-a-uuid@h{i}.example.com\n")); // broken
    }
    for i in 0..40 {
        text.push_str(&format!("garbage line {i} <script>alert(1)</script>\n"));
    }
    let t = Instant::now();
    let r = b.import_text(&text).unwrap();
    assert_eq!(r.added.len(), 300);
    assert_eq!(r.duplicates, 100);
    assert!(r.problems.len() >= 60, "problems: {}", r.problems.len());
    assert!(r.problems.iter().all(|p| !p.message.is_empty() && !p.message_en.is_empty()));
    eprintln!("500-line import took {:?}", t.elapsed());
    assert_eq!(b.list_profiles().unwrap().len(), 300);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_while_idle_and_unknown_is_clean() {
    let dir = tmp("del");
    let b = backend_in(&dir, "memory");
    let r = b.import_text("trojan://pw12345678@a.example.com:443#A").unwrap();
    let id = r.added[0].id.clone();
    b.delete(&id).unwrap();
    assert_eq!(b.delete(&id).unwrap_err().code, "not_found");
    assert_eq!(b.connect_last().unwrap_err().code, "no_profile");
}

#[tokio::test(flavor = "multi_thread")]
async fn status_dto_carries_leak_protection_state_and_never_invents_connected() {
    use core_app::{Status, UiState};
    use wt_desktop::backend::StatusDto;
    let base = Status {
        state: UiState::Reconnecting,
        profile_id: Some("ab".into()),
        connected_since: Some(std::time::SystemTime::now()),
        message: Some("m".into()),
        message_en: Some("e".into()),
        failure_code: Some("network".into()),
        attempt: 2,
        insecure_tls: false,
        kill_switch_active: true,
        kill_switch_leftover: true,
        kill_switch_error: Some("boom".into()),
    };
    let d = StatusDto::from(&base);
    assert_eq!(d.state, "reconnecting");
    assert!(d.kill_switch_active && d.kill_switch_leftover);
    assert_eq!(d.kill_switch_error.as_deref(), Some("boom"));
    for (s, want) in [(UiState::Idle, "idle"), (UiState::Preparing, "preparing"), (UiState::Connecting, "connecting"), (UiState::Disconnecting, "disconnecting"), (UiState::Failed, "failed"), (UiState::Connected, "connected")] {
        assert_eq!(StatusDto::from(&Status { state: s, ..base.clone() }).state, want);
    }
    // The commands exist and are harmless while idle.
    let dir = tmp("ks");
    let b = backend_in(&dir, "memory");
    b.allow_direct();
    b.clear_leftover_rules();
    assert_eq!(b.status().state, "idle");
}
