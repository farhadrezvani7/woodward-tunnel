//! Diagnostic report for support. Built to be safe to share: it contains counts, versions and a
//! redacted log tail, but never config names, server addresses, keys or passwords. The user is
//! meant to read it before sending.

use crate::{App, Status};
use core_engine::runner::Binaries;
use std::collections::BTreeMap;

const TAIL_LINES: usize = 80;

fn first_line(program: &std::path::Path, arg: &str) -> String {
    std::process::Command::new(program)
        .arg(arg)
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8(if o.stdout.is_empty() {
                o.stderr
            } else {
                o.stdout
            })
            .ok()
        })
        .and_then(|t| t.lines().next().map(|l| l.trim().to_string()))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "missing".into())
}

/// Replace IPv4 literals with `<ip>`; engine logs often quote server addresses.
fn mask_ips(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut tok = String::new();
    let flush = |tok: &mut String, out: &mut String| {
        let parts: Vec<&str> = tok.split('.').collect();
        let is_ip = parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()));
        out.push_str(if is_ip { "<ip>" } else { tok.as_str() });
        tok.clear();
    };
    for c in line.chars() {
        if c.is_ascii_digit() || c == '.' {
            tok.push(c);
        } else {
            flush(&mut tok, &mut out);
            out.push(c);
        }
    }
    flush(&mut tok, &mut out);
    out
}

/// Report for desktop builds, where engines are separate programs next to the app.
pub fn report(app: &App, status: Option<&Status>, log_tail: &[String], bins: &Binaries) -> String {
    render(app, status, log_tail, Some(bins))
}

/// Report for mobile builds, where sing-box and the AmneziaWG helper are linked into the app.
pub fn report_embedded(app: &App, status: Option<&Status>, log_tail: &[String]) -> String {
    render(app, status, log_tail, None)
}

fn render(
    app: &App,
    status: Option<&Status>,
    log_tail: &[String],
    bins: Option<&Binaries>,
) -> String {
    let mut out = String::new();
    out.push_str("woodward-tunnel diagnostic report (review before sharing)\n");
    out.push_str(&format!(
        "version: {}\nos: {} {}\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    ));

    let list = app.list().unwrap_or_default();
    let mut by_proto: BTreeMap<&str, usize> = BTreeMap::new();
    let mut groups = std::collections::BTreeSet::new();
    let mut hosts: Vec<String> = Vec::new();
    for p in &list {
        *by_proto.entry(p.protocol.id()).or_default() += 1;
        groups.insert(p.group.clone());
        hosts.push(p.host.clone());
    }
    out.push_str(&format!(
        "configs: {} in {} groups\n",
        list.len(),
        groups.len()
    ));
    for (k, v) in by_proto {
        out.push_str(&format!("  {k}: {v}\n"));
    }

    out.push_str("engines:\n");
    match bins {
        Some(bins) => {
            out.push_str(&format!(
                "  sing-box: {}\n",
                first_line(&bins.sing_box, "version")
            ));
            out.push_str(&format!(
                "  openvpn: {}\n",
                first_line(&bins.openvpn, "--version")
            ));
            let awg = std::process::Command::new(&bins.awg_socks)
                .arg("--check")
                .output()
                .is_ok();
            out.push_str(&format!(
                "  awg-socks: {}\n",
                if awg { "present" } else { "missing" }
            ));
        }
        None => out.push_str("  built into the app\n"),
    }

    if let Some(s) = status {
        out.push_str(&format!("state: {:?}\n", s.state));
        if let Some(c) = &s.failure_code {
            out.push_str(&format!("last failure: {c}\n"));
        }
        out.push_str(&format!("insecure tls option in use: {}\n", s.insecure_tls));
    }

    out.push_str("recent engine output (redacted):\n");
    let start = log_tail.len().saturating_sub(TAIL_LINES);
    for l in &log_tail[start..] {
        let mut line = app.redactor().redact(l);
        for h in &hosts {
            if h.len() >= 4 {
                line = line.replace(h.as_str(), "<server>");
            }
        }
        out.push_str("  ");
        out.push_str(&mask_ips(&line));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{App, FetchError, Fetcher};
    use core_store::MemorySecretStore;
    use std::sync::Arc;

    struct NoFetch;
    impl Fetcher for NoFetch {
        fn get(&self, _: &str) -> Result<String, FetchError> {
            Err(FetchError::NotHttps)
        }
    }

    #[test]
    fn report_has_no_names_hosts_or_secrets() {
        let dir = std::env::temp_dir().join(format!("wt-diag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let app = App::new(
            &dir,
            Arc::new(MemorySecretStore::default()),
            Arc::new(NoFetch),
        )
        .unwrap();
        let r = app
            .import_text(
                "trojan://s3cret-pass-99@vpn.private-host.example:443#My Secret Name",
                "Family",
            )
            .unwrap();
        // The redactor only learns secrets when a profile is loaded, as happens when connecting.
        app.profile(&r.added[0].id).unwrap();
        let log = vec![
            "sing-box: dial tcp vpn.private-host.example:443 failed, password s3cret-pass-99"
                .to_string(),
            "sing-box: connected to 203.0.113.77:443 via 10.0.0.2".to_string(),
        ];
        let rep = report(&app, None, &log, &Binaries::discover());
        assert!(report_embedded(&app, None, &log).contains("built into the app"));
        for leak in [
            "s3cret-pass-99",
            "vpn.private-host.example",
            "My Secret Name",
            "203.0.113.77",
            "Family",
        ] {
            assert!(!rep.contains(leak), "{leak} leaked:\n{rep}");
        }
        assert!(rep.contains("trojan: 1") && rep.contains("<server>") && rep.contains("<ip>"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn ip_masking_keeps_other_numbers() {
        assert_eq!(
            mask_ips("took 1.5s to reach 8.8.8.8:53 (v1.14.3)"),
            "took 1.5s to reach <ip>:53 (v1.14.3)"
        );
    }
}
