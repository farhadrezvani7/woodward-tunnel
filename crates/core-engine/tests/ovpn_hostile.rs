//! Hostile `.ovpn` text must never reach the openvpn binary as a live `plugin`/script directive.
//! Each case is fed to the importer; when the real binary is installed the raw text is also run
//! to prove the hole is real (the plugin load is attempted) and the rendered profile is run to
//! prove it is closed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use core_engine::openvpn::render;
use core_import::detect;
use std::process::Command;

const CA: &str = "<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n";

fn base() -> String {
    format!("client\ndev tun\nproto udp\nremote 127.0.0.1 1 udp\nnobind\n{CA}")
}

fn have_openvpn() -> bool {
    Command::new("openvpn").arg("--version").output().is_ok()
}

/// Runs openvpn on `text` and returns combined output; the process is killed by `timeout`.
fn run(text: &str, tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!("wt-ovpn-hostile-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("c.ovpn");
    std::fs::write(&f, text).unwrap();
    let out = Command::new("timeout")
        .args(["5", "openvpn", "--config"])
        .arg(&f)
        .args([
            "--verb",
            "4",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "1",
            "--ifconfig-noexec",
            "--route-noexec",
        ])
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn plugin_attempted(log: &str) -> bool {
    log.contains("PLUGIN") || log.contains("plugin")
}

// long_comment: openvpn 2.7.0 rejects lines over 255 bytes outright, but older releases split them
// and parse the tail as a directive, so the importer rejects them too (importer test only).
fn cases() -> Vec<(&'static str, String)> {
    let long_comment = format!("# {} plugin /tmp/wt-evil.so\n", "a".repeat(253));
    vec![
        ("close_tag_trailer", "client\ndev tun\nremote 127.0.0.1 1 udp\n<ca>\nX\n</ca>x\nplugin /tmp/wt-evil.so\n".to_string()),
        ("close_tag_trailer_space", "client\ndev tun\nremote 127.0.0.1 1 udp\n<ca>\nX\n  </ca> plugin /tmp/wt-evil.so\n".to_string()),
        ("long_comment", format!("{}{long_comment}", base())),
        ("plugin_plain", format!("{}plugin /tmp/wt-evil.so\n", base())),
        ("plugin_dashes", format!("{}--plugin /tmp/wt-evil.so\n", base())),
        ("plugin_tab", format!("{}\tplugin\t/tmp/wt-evil.so\n", base())),
        ("plugin_quoted", format!("{}\"plugin\" /tmp/wt-evil.so\n", base())),
        ("setenv_opt", format!("{}setenv opt plugin /tmp/wt-evil.so\n", base())),
        ("capath", format!("{}capath /etc/ssl/certs\n", base())),
        ("lone_cr", format!("{}nobind\rplugin /tmp/wt-evil.so\n", base())),
        ("up_script", format!("{}script-security 2\nup /bin/true\n", base())),
        ("tls_verify", format!("{}tls-verify /bin/true\n", base())),
        ("connection_plugin", format!("client\n<connection>\nremote 127.0.0.1 1\nplugin /tmp/wt-evil.so\n</connection>\n{CA}")),
    ]
}

#[test]
fn importer_never_keeps_a_plugin_or_script_directive() {
    for (name, text) in cases() {
        match detect(&text) {
            Err(_) => {}
            Ok(p) => {
                let r = render(&p).unwrap();
                for l in r.lines() {
                    let k = l.split_whitespace().next().unwrap_or("");
                    assert!(
                        !matches!(
                            k,
                            "plugin" | "up" | "down" | "tls-verify" | "setenv" | "capath"
                        ),
                        "{name}: live directive in rendered profile: {l}"
                    );
                }
                assert!(r.contains("script-security 0"), "{name}");
                assert!(!r.contains("wt-evil"), "{name}: payload survived: {r}");
            }
        }
    }
}

#[test]
fn real_binary_confirms_holes_are_real_and_rendered_profiles_are_safe() {
    if !have_openvpn() {
        eprintln!("openvpn not installed; skipping");
        return;
    }
    for name in ["close_tag_trailer", "plugin_plain", "setenv_opt"] {
        let text = cases().into_iter().find(|(n, _)| *n == name).unwrap().1;
        let raw_log = run(&text, &format!("raw-{name}"));
        assert!(
            plugin_attempted(&raw_log),
            "{name}: expected the raw hostile text to reach the plugin loader, test is not proving anything:\n{raw_log}"
        );
        if let Ok(p) = detect(&text) {
            let log = run(&render(&p).unwrap(), &format!("safe-{name}"));
            assert!(
                !plugin_attempted(&log),
                "{name}: plugin load attempted from rendered profile:\n{log}"
            );
        }
    }
}

#[test]
fn legit_profile_with_quotes_comments_and_connection_blocks_round_trips() {
    let text = format!(
        "client\ndev tun\n<connection>\nremote a.example.com 443 tcp\n</connection>\n<connection>\nremote b.example.com 1194 udp\n</connection>\nverify-x509-name \"C=US, CN=my server\" subject\nkeepalive 10 60 # trailing comment\nremote-cert-tls server\n{CA}<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\n"
    );
    let p = detect(&text).unwrap();
    assert_eq!(p.host, "a.example.com");
    assert_eq!(p.secrets["username"].expose(), "alice");
    assert_eq!(p.secrets["password"].expose(), "s3cret");
    let r = render(&p).unwrap();
    assert!(
        r.contains("verify-x509-name \"C=US, CN=my server\" subject"),
        "{r}"
    );
    assert!(
        r.contains("<connection>\nremote a.example.com 443 tcp\n</connection>"),
        "{r}"
    );
    assert!(
        !r.contains("s3cret") && !r.contains("keepalive 10 60 #"),
        "{r}"
    );
    assert!(detect(&r).is_ok(), "{r}");
}
