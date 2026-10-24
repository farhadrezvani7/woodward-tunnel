//! Applying and removing kill switch rules through the OS tools, via an injectable runner so the
//! exact command sequences are unit-testable on any host.
//!
//! State handling per OS:
//! * Linux: one nft table `wt_killswitch`; removal deletes only that table.
//! * macOS: rules live in the pf anchor `com.apple/woodward-tunnel` (Apple's default ruleset
//!   evaluates `com.apple/*`), so `/etc/pf.conf` is never edited. If pf was off we enable it with
//!   `pfctl -E` (reference counted, returns a token) and release exactly that token on removal.
//! * Windows: allow rules in the group `WoodwardTunnel` plus profile default outbound = Block.
//!   The previous per-profile defaults are saved to a state file and restored on removal.
//!
//! All rules persist if the application crashes. That is deliberate (a crash must not open a
//! leak); `wt killswitch off` or [`Firewall::remove`] clears them.

use crate::{KillSwitch, PolicyError};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

pub const NFT_TABLE: &str = "wt_killswitch";
pub const PF_ANCHOR: &str = "com.apple/woodward-tunnel";
pub const WIN_GROUP: &str = "WoodwardTunnel";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner: Send + Sync {
    fn run(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&str>,
    ) -> Result<CmdOutput, PolicyError>;
}

/// Runs real commands. `elevate` is an optional prefix such as `["pkexec"]` or `["sudo", "-n"]`
/// for front ends that are not root themselves.
#[derive(Debug, Clone, Default)]
pub struct SystemRunner {
    pub elevate: Vec<String>,
}

impl CommandRunner for SystemRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&str>,
    ) -> Result<CmdOutput, PolicyError> {
        let (prog, pre): (&str, &[String]) = match self.elevate.split_first() {
            Some((p, rest)) => (p.as_str(), rest),
            None => (program, &[]),
        };
        let mut cmd = Command::new(prog);
        if !self.elevate.is_empty() {
            cmd.args(pre).arg(program);
        }
        cmd.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| PolicyError::Tool(format!("{program}: {e}")))?;
        if let (Some(text), Some(mut si)) = (stdin, child.stdin.take()) {
            si.write_all(text.as_bytes())
                .map_err(|e| PolicyError::Tool(e.to_string()))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| PolicyError::Tool(e.to_string()))?;
        Ok(CmdOutput {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Linux,
    MacOs,
    Windows,
}

impl Os {
    pub fn current() -> Option<Os> {
        if cfg!(target_os = "linux") {
            Some(Os::Linux)
        } else if cfg!(target_os = "macos") {
            Some(Os::MacOs)
        } else if cfg!(windows) {
            Some(Os::Windows)
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct Firewall {
    os: Os,
    runner: Arc<dyn CommandRunner>,
    state_dir: PathBuf,
}

fn tool(out: CmdOutput, what: &str) -> Result<CmdOutput, PolicyError> {
    if out.success {
        Ok(out)
    } else {
        Err(PolicyError::Tool(format!(
            "{what}: {}",
            out.stderr.trim().chars().take(300).collect::<String>()
        )))
    }
}

impl Firewall {
    /// Real firewall of the running OS. `state_dir` holds the small state file used on macOS and
    /// Windows to restore the previous configuration.
    pub fn system(state_dir: PathBuf, elevate: Vec<String>) -> Result<Self, PolicyError> {
        Ok(Self {
            os: Os::current().ok_or(PolicyError::Unsupported)?,
            runner: Arc::new(SystemRunner { elevate }),
            state_dir,
        })
    }

    pub fn with_runner(os: Os, runner: Arc<dyn CommandRunner>, state_dir: PathBuf) -> Self {
        Self {
            os,
            runner,
            state_dir,
        }
    }

    fn state_file(&self) -> PathBuf {
        self.state_dir.join("killswitch.state")
    }

    fn run(&self, p: &str, args: &[&str], stdin: Option<&str>) -> Result<CmdOutput, PolicyError> {
        let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        self.runner.run(p, &a, stdin)
    }

    fn ps(&self, script: &str) -> Result<CmdOutput, PolicyError> {
        self.run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", "-"],
            Some(script),
        )
    }

    /// Apply (or replace) the rules.
    pub fn apply(&self, ks: &KillSwitch) -> Result<(), PolicyError> {
        match self.os {
            Os::Linux => {
                let rules = ks.nftables()?;
                // Declare, delete, recreate in one transaction: atomic replace without a gap.
                let text =
                    format!("table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n{rules}");
                tool(self.run("nft", &["-f", "-"], Some(&text))?, "nft").map(|_| ())
            }
            Os::MacOs => self.apply_macos(ks),
            Os::Windows => self.apply_windows(ks),
        }
    }

    /// Remove the rules and restore what was there before. Safe to call when nothing is active.
    pub fn remove(&self) -> Result<(), PolicyError> {
        match self.os {
            Os::Linux => {
                let text = format!("table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n");
                tool(self.run("nft", &["-f", "-"], Some(&text))?, "nft").map(|_| ())
            }
            Os::MacOs => self.remove_macos(),
            Os::Windows => self.remove_windows(),
        }
    }

    /// Are our rules currently loaded (also after a crash of the app)?
    pub fn is_active(&self) -> Result<bool, PolicyError> {
        match self.os {
            Os::Linux => {
                let o = self.run("nft", &["list", "table", "inet", NFT_TABLE], None)?;
                if o.success {
                    return Ok(true);
                }
                // A missing table is the normal "not active" answer; anything else (no
                // permission, nft missing) means we cannot tell and must say so.
                if o.stderr.contains("No such file") || o.stderr.contains("does not exist") {
                    Ok(false)
                } else {
                    Err(PolicyError::Tool(format!(
                        "nft: {}",
                        o.stderr.trim().chars().take(200).collect::<String>()
                    )))
                }
            }
            Os::MacOs => {
                let o = self.run("pfctl", &["-a", PF_ANCHOR, "-s", "rules"], None)?;
                Ok(o.success && o.stdout.contains("block drop out"))
            }
            Os::Windows => {
                let o = self.ps(&format!(
                    "(Get-NetFirewallRule -Group '{WIN_GROUP}' -ErrorAction SilentlyContinue | Measure-Object).Count"
                ))?;
                Ok(o.success
                    && o.stdout
                        .trim()
                        .parse::<u32>()
                        .map(|n| n > 0)
                        .unwrap_or(false))
            }
        }
    }

    // ---- macOS (UNTESTED ON THE REAL OS) ---------------------------------------------------

    fn apply_macos(&self, ks: &KillSwitch) -> Result<(), PolicyError> {
        let rules = ks.pf()?;
        if !self.state_file().exists() {
            let info = tool(self.run("pfctl", &["-s", "info"], None)?, "pfctl -s info")?;
            let enabled = info.stdout.contains("Status: Enabled");
            let mut token = String::new();
            if !enabled {
                let e = tool(self.run("pfctl", &["-E"], None)?, "pfctl -E")?;
                // The token is printed on stderr: "Token : 1234567890".
                token = parse_pf_token(&format!("{}\n{}", e.stderr, e.stdout)).unwrap_or_default();
            }
            self.save_state(&format!("pf_token={token}\npf_was_enabled={enabled}\n"))?;
        }
        tool(
            self.run("pfctl", &["-a", PF_ANCHOR, "-f", "-"], Some(&rules))?,
            "pfctl -f",
        )?;
        // Verify the anchor really holds our block rule.
        let chk = tool(
            self.run("pfctl", &["-a", PF_ANCHOR, "-s", "rules"], None)?,
            "pfctl -s rules",
        )?;
        if !chk.stdout.contains("block drop out") {
            return Err(PolicyError::Tool("pf anchor did not load".into()));
        }
        Ok(())
    }

    fn remove_macos(&self) -> Result<(), PolicyError> {
        let flush = self.run("pfctl", &["-a", PF_ANCHOR, "-F", "all"], None)?;
        let state = std::fs::read_to_string(self.state_file()).unwrap_or_default();
        let mut release_err = None;
        for l in state.lines() {
            if let Some(tok) = l.strip_prefix("pf_token=") {
                let tok = tok.trim();
                // Only digits can be a token; refuse to pass anything else to pfctl.
                if !tok.is_empty() && tok.chars().all(|c| c.is_ascii_digit()) {
                    if let Err(e) = tool(self.run("pfctl", &["-X", tok], None)?, "pfctl -X") {
                        release_err = Some(e);
                    }
                }
            }
        }
        tool(flush, "pfctl -F")?;
        if let Some(e) = release_err {
            return Err(e);
        }
        let _ = std::fs::remove_file(self.state_file());
        Ok(())
    }

    // ---- Windows (UNTESTED ON THE REAL OS) -------------------------------------------------

    fn apply_windows(&self, ks: &KillSwitch) -> Result<(), PolicyError> {
        let script = ks.windows_powershell()?;
        if !self.state_file().exists() {
            let o = tool(
                self.ps("Get-NetFirewallProfile -All | ForEach-Object { \"$($_.Name)=$($_.DefaultOutboundAction)\" }")?,
                "Get-NetFirewallProfile",
            )?;
            let saved = parse_win_profiles(&o.stdout);
            if saved.is_empty() {
                // Never block blindly: without the old values we could not restore them.
                return Err(PolicyError::Tool("could not read firewall profiles".into()));
            }
            self.save_state(&saved.join("\n"))?;
        }
        tool(self.ps(&script)?, "New-NetFirewallRule").map(|_| ())
    }

    fn remove_windows(&self) -> Result<(), PolicyError> {
        let saved = std::fs::read_to_string(self.state_file())
            .map(|t| parse_win_profiles(&t))
            .unwrap_or_default();
        let mut script =
            format!("Remove-NetFirewallRule -Group '{WIN_GROUP}' -ErrorAction SilentlyContinue\n");
        if saved.is_empty() {
            script.push_str("Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow\n");
        } else {
            for l in &saved {
                if let Some((name, action)) = l.split_once('=') {
                    script.push_str(&format!(
                        "Set-NetFirewallProfile -Name {name} -DefaultOutboundAction {action}\n"
                    ));
                }
            }
        }
        tool(self.ps(&script)?, "Set-NetFirewallProfile")?;
        let _ = std::fs::remove_file(self.state_file());
        Ok(())
    }

    fn save_state(&self, text: &str) -> Result<(), PolicyError> {
        std::fs::create_dir_all(&self.state_dir).map_err(|e| PolicyError::Tool(e.to_string()))?;
        let tmp = self.state_dir.join("killswitch.state.tmp");
        std::fs::write(&tmp, text).map_err(|e| PolicyError::Tool(e.to_string()))?;
        std::fs::rename(&tmp, self.state_file()).map_err(|e| PolicyError::Tool(e.to_string()))
    }
}

fn parse_pf_token(text: &str) -> Option<String> {
    for l in text.lines() {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("token") {
                let t = v.trim();
                if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) {
                    return Some(t.to_string());
                }
            }
        }
    }
    None
}

/// `Name=Action` lines, only accepting the three known profile names and action values.
fn parse_win_profiles(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let (n, a) = l.trim().split_once('=')?;
            let (n, a) = (n.trim(), a.trim());
            let ok_n = matches!(n, "Domain" | "Private" | "Public");
            let ok_a = matches!(a, "NotConfigured" | "Allow" | "Block");
            (ok_n && ok_a).then(|| format!("{n}={a}"))
        })
        .collect()
}

/// All addresses of `host` (A and AAAA). Call again on every reconnect: CDNs rotate records.
pub fn resolve_all(host: &str, port: u16) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip];
    }
    let mut v: Vec<std::net::IpAddr> = (host, port)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

/// Non-loopback DNS servers the system would use, so they can be allowed for host-name
/// bootstrap while the tunnel is down. systemd-resolved's stub (127.0.0.53) forwards to the
/// servers listed in `/run/systemd/resolve/resolv.conf`, which are read instead.
pub fn system_resolvers() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    for path in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        if let Ok(t) = std::fs::read_to_string(path) {
            out.extend(parse_resolv_conf(&t));
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn parse_resolv_conf(text: &str) -> Vec<std::net::IpAddr> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("nameserver")?;
            let tok = rest.split_whitespace().next()?;
            // Scoped link-local addresses look like fe80::1%eth0.
            let tok = tok.split('%').next()?;
            tok.parse::<std::net::IpAddr>().ok()
        })
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    type Call = (String, Vec<String>, Option<String>);

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<Call>>,
        replies: Mutex<Vec<CmdOutput>>,
    }
    impl Fake {
        fn ok(stdout: &str, stderr: &str) -> CmdOutput {
            CmdOutput {
                success: true,
                stdout: stdout.into(),
                stderr: stderr.into(),
            }
        }
        fn queue(&self, o: CmdOutput) {
            self.replies.lock().unwrap().push(o);
        }
        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(p, a, _)| format!("{p} {}", a.join(" ")))
                .collect()
        }
    }
    impl CommandRunner for Fake {
        fn run(
            &self,
            program: &str,
            args: &[String],
            stdin: Option<&str>,
        ) -> Result<CmdOutput, PolicyError> {
            self.calls.lock().unwrap().push((
                program.into(),
                args.to_vec(),
                stdin.map(String::from),
            ));
            let mut r = self.replies.lock().unwrap();
            Ok(if r.is_empty() {
                Fake::ok("", "")
            } else {
                r.remove(0)
            })
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wt-fw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn ks() -> KillSwitch {
        KillSwitch::new("utun", vec!["203.0.113.9".parse().unwrap()])
    }

    #[test]
    fn linux_apply_and_remove_touch_only_our_table() {
        let f = Arc::new(Fake::default());
        let fw = Firewall::with_runner(Os::Linux, f.clone(), tmp("l"));
        fw.apply(&KillSwitch::new(
            "wt0",
            vec!["203.0.113.9".parse().unwrap()],
        ))
        .unwrap();
        fw.remove().unwrap();
        let c = f.calls.lock().unwrap();
        let first = c[0].2.as_deref().unwrap();
        assert!(first.starts_with("table inet wt_killswitch\ndelete table inet wt_killswitch\n"));
        assert!(!first.contains("flush ruleset"));
        let last = c[1].2.as_deref().unwrap();
        assert_eq!(
            last,
            "table inet wt_killswitch\ndelete table inet wt_killswitch\n"
        );
    }

    #[test]
    fn tool_failure_is_an_error_not_silent() {
        let f = Arc::new(Fake::default());
        f.queue(CmdOutput {
            success: false,
            stdout: String::new(),
            stderr: "Operation not permitted".into(),
        });
        let fw = Firewall::with_runner(Os::Linux, f, tmp("e"));
        let e = fw
            .apply(&KillSwitch::new("wt0", vec![]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("Operation not permitted"));
    }

    #[test]
    fn macos_enables_pf_with_token_and_releases_exactly_that_token() {
        let dir = tmp("m");
        let f = Arc::new(Fake::default());
        f.queue(Fake::ok("Status: Disabled\n", "")); // -s info
        f.queue(Fake::ok("", "pf enabled\nToken : 4242\n")); // -E
        f.queue(Fake::ok("", "")); // -f
        f.queue(Fake::ok("block drop out all\n", "")); // -s rules
        let fw = Firewall::with_runner(Os::MacOs, f.clone(), dir.clone());
        fw.apply(&ks()).unwrap();
        let calls = f.calls();
        assert_eq!(calls[0], "pfctl -s info");
        assert_eq!(calls[1], "pfctl -E");
        assert_eq!(calls[2], "pfctl -a com.apple/woodward-tunnel -f -");
        // Second apply must not enable pf again or overwrite the saved state.
        f.queue(Fake::ok("", ""));
        f.queue(Fake::ok("block drop out all\n", ""));
        fw.apply(&ks()).unwrap();
        assert_eq!(f.calls().iter().filter(|c| *c == "pfctl -E").count(), 1);
        fw.remove().unwrap();
        let calls = f.calls();
        assert!(calls.contains(&"pfctl -a com.apple/woodward-tunnel -F all".to_string()));
        assert!(calls.contains(&"pfctl -X 4242".to_string()));
        assert!(!dir.join("killswitch.state").exists());
    }

    #[test]
    fn macos_leaves_pf_alone_if_user_already_runs_it() {
        let dir = tmp("m2");
        let f = Arc::new(Fake::default());
        f.queue(Fake::ok("Status: Enabled\n", ""));
        f.queue(Fake::ok("", ""));
        f.queue(Fake::ok("block drop out all\n", ""));
        let fw = Firewall::with_runner(Os::MacOs, f.clone(), dir);
        fw.apply(&ks()).unwrap();
        fw.remove().unwrap();
        let calls = f.calls();
        assert!(!calls
            .iter()
            .any(|c| c == "pfctl -E" || c.starts_with("pfctl -X")));
        assert!(calls.iter().any(|c| c.contains("-F all")));
    }

    #[test]
    fn macos_rejects_a_non_numeric_token_in_saved_state() {
        let dir = tmp("m3");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("killswitch.state"), "pf_token=1; rm -rf /\n").unwrap();
        let f = Arc::new(Fake::default());
        let fw = Firewall::with_runner(Os::MacOs, f.clone(), dir);
        fw.remove().unwrap();
        assert!(!f.calls().iter().any(|c| c.starts_with("pfctl -X")));
    }

    #[test]
    fn macos_unloaded_anchor_is_an_error() {
        let f = Arc::new(Fake::default());
        f.queue(Fake::ok("Status: Enabled\n", ""));
        f.queue(Fake::ok("", ""));
        f.queue(Fake::ok("", "")); // anchor empty => not loaded
        let fw = Firewall::with_runner(Os::MacOs, f, tmp("m4"));
        assert!(fw.apply(&ks()).is_err());
    }

    #[test]
    fn windows_saves_and_restores_previous_profile_defaults() {
        let dir = tmp("w");
        let f = Arc::new(Fake::default());
        f.queue(Fake::ok(
            "Domain=NotConfigured\r\nPrivate=Block\r\nPublic=Allow\r\n",
            "",
        ));
        let fw = Firewall::with_runner(Os::Windows, f.clone(), dir.clone());
        fw.apply(&KillSwitch::new(
            "wt0",
            vec!["203.0.113.9".parse().unwrap()],
        ))
        .unwrap();
        let script = f.calls.lock().unwrap()[1].2.clone().unwrap();
        assert!(script.contains("-InterfaceAlias 'wt0'") && script.contains("203.0.113.9"));
        // The block default is switched on after the allow rules exist.
        assert!(
            script.find("New-NetFirewallRule").unwrap()
                < script.find("-DefaultOutboundAction Block").unwrap()
        );
        fw.remove().unwrap();
        let rm = f.calls.lock().unwrap().last().unwrap().2.clone().unwrap();
        assert!(
            rm.contains("Set-NetFirewallProfile -Name Domain -DefaultOutboundAction NotConfigured")
        );
        assert!(rm.contains("-Name Private -DefaultOutboundAction Block"));
        assert!(rm.contains("-Name Public -DefaultOutboundAction Allow"));
        assert!(rm.contains("Remove-NetFirewallRule -Group 'WoodwardTunnel'"));
    }

    #[test]
    fn windows_refuses_to_block_when_profiles_cannot_be_read() {
        let f = Arc::new(Fake::default());
        f.queue(Fake::ok("garbage\n", ""));
        let fw = Firewall::with_runner(Os::Windows, f.clone(), tmp("w2"));
        assert!(fw.apply(&KillSwitch::new("wt0", vec![])).is_err());
        assert_eq!(f.calls().len(), 1);
    }

    #[test]
    fn windows_remove_without_state_falls_back_to_allow() {
        let f = Arc::new(Fake::default());
        let fw = Firewall::with_runner(Os::Windows, f.clone(), tmp("w3"));
        fw.remove().unwrap();
        let s = f.calls.lock().unwrap()[0].2.clone().unwrap();
        assert!(s.contains("-DefaultOutboundAction Allow"));
    }

    #[test]
    fn elevation_prefix_is_applied_by_the_system_runner() {
        // `env` stands in for pkexec: it must run `true`.
        let r = SystemRunner {
            elevate: vec!["env".into()],
        };
        if cfg!(unix) {
            assert!(r.run("true", &[], None).unwrap().success);
        }
    }

    #[test]
    fn resolv_conf_parsing_skips_loopback_stub() {
        let t = "# c\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\noptions edns0\n";
        let v = parse_resolv_conf(t);
        assert_eq!(v.len(), 2);
        assert!(v.contains(&"192.168.1.1".parse().unwrap()));
    }
}
