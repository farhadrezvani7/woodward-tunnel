//! Process and file hygiene of the sidecar layer: private files, crash leftovers, output floods.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(unix)]

use core_engine::runner::{check_sing_box, parse_version, MIN_SING_BOX};
use core_engine::sidecar::*;
use core_log::Redactor;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wt-hyg-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn private_files_and_dirs_are_tightened_even_if_they_pre_exist() {
    let d = tmp("perm");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A loose file and a symlink planted at the target name.
    std::fs::write(d.join("a.json"), "old").unwrap();
    std::fs::set_permissions(d.join("a.json"), std::fs::Permissions::from_mode(0o666)).unwrap();
    let victim = tmp("victim");
    std::fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, d.join("b.json")).unwrap();
    let a = PrivateFile::write(&d, "a.json", b"secret").unwrap();
    let b = PrivateFile::write(&d, "b.json", b"secret").unwrap();
    assert_eq!(mode(&d), 0o700);
    assert_eq!(mode(a.path()), 0o600);
    assert_eq!(mode(b.path()), 0o600);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    drop((a, b));
    assert!(!d.join("a.json").exists());
    // A new nested dir is created private from the start.
    let n = d.join("x/y");
    private_dir(&n).unwrap();
    assert_eq!(mode(&n), 0o700);
    assert_eq!(mode(&d.join("x")), 0o700);
}

#[tokio::test]
async fn stale_files_and_orphan_engines_of_a_dead_instance_are_swept() {
    let d = tmp("sweep");
    private_dir(&d).unwrap();
    // An "engine" left behind: a process whose command line names `fake-engine`.
    let script = d.join("fake-engine");
    std::fs::write(&script, "#!/bin/sh\nwhile true; do sleep 0.2; done\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = std::process::Command::new(&script).spawn().unwrap();
    let pid = child.id();
    // Files as written by a process (pid 4000000, which does not exist) that was SIGKILLed.
    let dead = 4_000_000u32;
    std::fs::write(
        d.join(format!("p{dead}-sing-box.json")),
        "{\"password\":\"x\"}",
    )
    .unwrap();
    std::fs::write(
        d.join(format!("p{dead}-sing-box.pid")),
        format!("{pid}\nfake-engine\n"),
    )
    .unwrap();
    // Files of this live process must survive.
    let mine = PrivateFile::write(&d, &format!("{}keep.json", instance_prefix()), b"{}").unwrap();
    // A pid file whose pid now belongs to something else must not kill that process.
    let innocent = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    std::fs::write(
        d.join(format!("p{dead}-other.pid")),
        format!("{}\nfake-engine\n", innocent.id()),
    )
    .unwrap();
    let rep = sweep_stale(&d);
    assert_eq!(rep.killed, vec![pid]);
    assert!(rep.removed >= 3, "{rep:?}");
    for _ in 0..30 {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        child.try_wait().unwrap().is_some(),
        "orphan engine still alive"
    );
    assert!(mine.path().exists());
    let mut innocent = innocent;
    assert!(
        innocent.try_wait().unwrap().is_none(),
        "unrelated process was killed"
    );
    innocent.kill().unwrap();
    let _ = innocent.wait();
    assert!(!d.join(format!("p{dead}-sing-box.json")).exists());
}

#[tokio::test]
async fn an_engine_that_floods_output_is_never_blocked_and_keeps_the_newest_lines() {
    let sc = Sidecar::spawn(SidecarSpec {
        program: "sh".into(),
        args: vec![
            "-c".into(),
            "i=0; while [ $i -lt 100000 ]; do echo \"line $i\"; i=$((i+1)); done; echo LAST".into(),
        ],
        redactor: Redactor::new(),
    })
    .unwrap();
    let mut sc = sc;
    // Nobody reads for a while; the process must still finish on its own.
    let mut done = false;
    for _ in 0..200 {
        if sc.try_exit().unwrap().is_some() {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(done, "engine blocked on a full pipe");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(sc.lines.dropped() > 0);
    let mut last = String::new();
    while let Some(l) = sc.lines.recv().await {
        last = l;
    }
    assert_eq!(last, "LAST");
}

#[tokio::test]
async fn very_long_lines_are_truncated() {
    let mut sc = Sidecar::spawn(SidecarSpec {
        program: "sh".into(),
        args: vec![
            "-c".into(),
            "head -c 5000000 /dev/zero | tr '\\0' a; echo; echo after".into(),
        ],
        redactor: Redactor::new(),
    })
    .unwrap();
    let first = sc.lines.recv().await.unwrap();
    assert!(first.len() <= 8 * 1024);
    assert_eq!(sc.lines.recv().await.as_deref(), Some("after"));
}

#[test]
fn version_parsing_and_minimum() {
    assert_eq!(
        parse_version("sing-box version 1.14.2\n\nEnvironment"),
        Some((1, 14, 2))
    );
    assert_eq!(parse_version("v1.12.0-beta.3"), Some((1, 12, 0)));
    assert_eq!(parse_version("nothing here"), None);
    assert!(MIN_SING_BOX >= (1, 12, 0));
    let d = tmp("ver");
    std::fs::create_dir_all(&d).unwrap();
    let old = d.join("old");
    std::fs::write(&old, "#!/bin/sh\necho 'sing-box version 1.11.9'\n").unwrap();
    std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        check_sing_box(&old),
        Err(core_engine::runner::StartError::BinaryVersion { .. })
    ));
    let junk = d.join("junk");
    std::fs::write(&junk, "not a program").unwrap();
    std::fs::set_permissions(&junk, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        check_sing_box(&junk),
        Err(core_engine::runner::StartError::BinaryMissing { .. })
    ));
    let noexec = d.join("noexec");
    std::fs::write(&noexec, "#!/bin/sh\n").unwrap();
    assert!(matches!(
        check_sing_box(&noexec),
        Err(core_engine::runner::StartError::BinaryMissing { .. })
    ));
}
