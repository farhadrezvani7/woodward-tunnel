//! Leak protection ("kill switch"). Each OS gets a firewall rule set that only lets traffic out
//! through the tunnel interface, to the VPN server itself, and (optionally) the local network.
//! The generators are pure text so they can be unit-tested; `apply`/`remove` run the OS tools.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct KillSwitch {
    /// Name of the tunnel interface (e.g. `tun0`, or `utun5` on macOS).
    pub tun_iface: String,
    /// VPN server addresses that must stay reachable outside the tunnel.
    pub server_ips: Vec<IpAddr>,
    /// Keep the local network reachable (printers, NAS).
    pub allow_lan: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid interface name")]
    BadInterface,
    #[error("firewall tool failed: {0}")]
    Tool(String),
    #[error("not supported on this platform")]
    Unsupported,
}

impl KillSwitch {
    fn validate(&self) -> Result<(), PolicyError> {
        let ok = !self.tun_iface.is_empty()
            && self.tun_iface.len() <= 15
            && self
                .tun_iface
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        if ok {
            Ok(())
        } else {
            Err(PolicyError::BadInterface)
        }
    }

    /// Linux nftables ruleset in its own table so removal never touches other rules.
    pub fn nftables(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let v4: Vec<String> = self
            .server_ips
            .iter()
            .filter(|i| i.is_ipv4())
            .map(|i| i.to_string())
            .collect();
        let v6: Vec<String> = self
            .server_ips
            .iter()
            .filter(|i| i.is_ipv6())
            .map(|i| i.to_string())
            .collect();
        let mut s = String::new();
        s.push_str("table inet wt_killswitch {\n  chain output {\n    type filter hook output priority -100; policy drop;\n");
        s.push_str("    oifname \"lo\" accept\n");
        s.push_str(&format!("    oifname \"{}\" accept\n", self.tun_iface));
        s.push_str("    ct state established,related accept\n");
        if !v4.is_empty() {
            s.push_str(&format!("    ip daddr {{ {} }} accept\n", v4.join(", ")));
        }
        if !v6.is_empty() {
            s.push_str(&format!("    ip6 daddr {{ {} }} accept\n", v6.join(", ")));
        }
        // DHCP so the machine keeps its address; nothing else leaves outside the tunnel.
        s.push_str(
            "    udp sport 68 udp dport 67 accept\n    ip6 daddr ff02::/16 udp dport 546 accept\n",
        );
        if self.allow_lan {
            s.push_str("    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept\n    ip6 daddr { fc00::/7, fe80::/10 } accept\n");
        }
        s.push_str("  }\n  chain input {\n    type filter hook input priority -100; policy accept;\n  }\n}\n");
        Ok(s)
    }

    /// macOS pf anchor. Load with `pfctl -a wt_killswitch -f -` and enable with `pfctl -e`.
    pub fn pf(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let mut s = String::from("block drop out all\npass out quick on lo0 all\n");
        s.push_str(&format!("pass out quick on {} all\n", self.tun_iface));
        for ip in &self.server_ips {
            s.push_str(&format!("pass out quick to {ip}\n"));
        }
        s.push_str("pass out quick proto udp from any port 68 to any port 67\n");
        if self.allow_lan {
            s.push_str("pass out quick to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fe80::/10, fc00::/7 }\n");
        }
        Ok(s)
    }

    /// Windows: PowerShell that creates a block-all outbound rule plus allow rules, all in the group `WoodwardTunnel`.
    pub fn windows_powershell(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let mut s = String::from("$g='WoodwardTunnel'\n");
        s.push_str(
            "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block\n",
        );
        s.push_str(&format!("New-NetFirewallRule -Group $g -DisplayName 'WT allow tunnel' -Direction Outbound -Action Allow -InterfaceAlias '{}'\n", self.tun_iface));
        for ip in &self.server_ips {
            s.push_str(&format!("New-NetFirewallRule -Group $g -DisplayName 'WT allow server' -Direction Outbound -Action Allow -RemoteAddress {ip}\n"));
        }
        s.push_str("New-NetFirewallRule -Group $g -DisplayName 'WT allow loopback' -Direction Outbound -Action Allow -RemoteAddress 127.0.0.1,::1\n");
        s.push_str("New-NetFirewallRule -Group $g -DisplayName 'WT allow dhcp' -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67\n");
        if self.allow_lan {
            s.push_str("New-NetFirewallRule -Group $g -DisplayName 'WT allow lan' -Direction Outbound -Action Allow -RemoteAddress LocalSubnet\n");
        }
        Ok(s)
    }

    pub fn windows_powershell_remove() -> &'static str {
        "Remove-NetFirewallRule -Group 'WoodwardTunnel' -ErrorAction SilentlyContinue\nSet-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow\n"
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn run(args: &[&str], stdin: Option<&str>) -> Result<(), PolicyError> {
        let mut c = Command::new("nft")
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| PolicyError::Tool(e.to_string()))?;
        if let (Some(text), Some(mut si)) = (stdin, c.stdin.take()) {
            si.write_all(text.as_bytes())
                .map_err(|e| PolicyError::Tool(e.to_string()))?;
        }
        let out = c
            .wait_with_output()
            .map_err(|e| PolicyError::Tool(e.to_string()))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(PolicyError::Tool(
                String::from_utf8_lossy(&out.stderr).trim().to_string(),
            ))
        }
    }

    impl KillSwitch {
        pub fn apply(&self) -> Result<(), PolicyError> {
            let rules = self.nftables()?;
            // Replace atomically: delete the old table (if any) in the same transaction.
            let text =
                format!("table inet wt_killswitch\ndelete table inet wt_killswitch\n{rules}");
            run(&["-f", "-"], Some(&text))
        }
        pub fn remove() -> Result<(), PolicyError> {
            run(
                &["-f", "-"],
                Some("table inet wt_killswitch\ndelete table inet wt_killswitch\n"),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks() -> KillSwitch {
        KillSwitch {
            tun_iface: "tun0".into(),
            server_ips: vec![
                "203.0.113.9".parse().unwrap(),
                "2001:db8::9".parse().unwrap(),
            ],
            allow_lan: false,
        }
    }

    #[test]
    fn nft_default_drop_with_only_tunnel_and_server_allowed() {
        let r = ks().nftables().unwrap();
        assert!(r.contains("policy drop"));
        assert!(
            r.contains("oifname \"tun0\" accept")
                && r.contains("203.0.113.9")
                && r.contains("ip6 daddr { 2001:db8::9 }")
        );
        assert!(!r.contains("192.168.0.0/16"));
    }

    #[test]
    fn lan_rules_only_when_requested() {
        let mut k = ks();
        k.allow_lan = true;
        assert!(k.nftables().unwrap().contains("192.168.0.0/16"));
        assert!(k.pf().unwrap().contains("192.168.0.0/16"));
        assert!(k.windows_powershell().unwrap().contains("LocalSubnet"));
    }

    #[test]
    fn interface_names_are_validated_against_injection() {
        for bad in [
            "",
            "tun0\"; flush ruleset; \"",
            "a b",
            "waytoolonginterfacename",
        ] {
            let mut k = ks();
            k.tun_iface = bad.into();
            assert!(
                k.nftables().is_err() && k.pf().is_err() && k.windows_powershell().is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn pf_blocks_by_default() {
        let r = ks().pf().unwrap();
        assert!(r.starts_with("block drop out all") && r.contains("pass out quick on tun0"));
    }
}
