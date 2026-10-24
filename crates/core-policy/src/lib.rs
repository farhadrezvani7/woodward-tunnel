//! Leak protection ("kill switch"). Each OS gets a firewall rule set that only lets traffic out
//! through the tunnel interface, to the VPN server itself, and (optionally) the local network.
//! The generators are pure text so they can be unit-tested; [`fw::Firewall`] runs the OS tools
//! through an injectable [`fw::CommandRunner`].
//!
//! Status of each platform (see docs/audit/runtime-robustness.md):
//! * Linux (nftables): run in Docker, real traffic.
//! * macOS (pf anchor) and Windows (Windows Defender Firewall): generated text and command
//!   sequences are unit-tested with a fake runner, **never executed on the real OS**.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod fw;

pub use fw::{CmdOutput, CommandRunner, Firewall, Os, SystemRunner};

use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct KillSwitch {
    /// Name (or pattern) of the tunnel interface: `wt0`, `tun*` (OpenVPN), `utun` (macOS group).
    pub tun_iface: String,
    /// VPN server addresses that must stay reachable outside the tunnel (all A and AAAA records).
    pub server_ips: Vec<IpAddr>,
    /// Keep the local network reachable (printers, NAS).
    pub allow_lan: bool,
    /// Extra interfaces whose traffic is always allowed (docker0, `br-*`, virbr0). Opt-in.
    pub allow_ifaces: Vec<String>,
    /// Resolvers that may be queried (port 53, outside the tunnel) so the server host name can be
    /// looked up while the tunnel is down. Empty once the tunnel is verified.
    pub dns_bootstrap: Vec<IpAddr>,
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

pub(crate) fn valid_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '*'))
}

fn split_ips(ips: &[IpAddr]) -> (Vec<String>, Vec<String>) {
    let mut v4: Vec<String> = ips
        .iter()
        .filter(|i| i.is_ipv4())
        .map(|i| i.to_string())
        .collect();
    let mut v6: Vec<String> = ips
        .iter()
        .filter(|i| i.is_ipv6())
        .map(|i| i.to_string())
        .collect();
    v4.sort();
    v4.dedup();
    v6.sort();
    v6.dedup();
    (v4, v6)
}

impl KillSwitch {
    pub fn new(tun_iface: &str, server_ips: Vec<IpAddr>) -> Self {
        Self {
            tun_iface: tun_iface.to_string(),
            server_ips,
            ..Default::default()
        }
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let tun_ok = valid_iface(&self.tun_iface) && self.tun_iface.len() <= 15;
        let extra_ok = self.allow_ifaces.iter().all(|i| valid_iface(i));
        if tun_ok && extra_ok {
            Ok(())
        } else {
            Err(PolicyError::BadInterface)
        }
    }

    /// Linux nftables ruleset in its own table so removal never touches other rules. Covers IPv4
    /// and IPv6; ICMP (v4 and v6 echo) never leaves outside the tunnel.
    pub fn nftables(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let (v4, v6) = split_ips(&self.server_ips);
        let (d4, d6) = split_ips(&self.dns_bootstrap);
        let mut s = String::new();
        s.push_str("table inet wt_killswitch {\n  chain output {\n    type filter hook output priority -100; policy drop;\n");
        s.push_str("    oifname \"lo\" accept\n");
        s.push_str(&format!("    oifname \"{}\" accept\n", self.tun_iface));
        for i in &self.allow_ifaces {
            s.push_str(&format!("    oifname \"{i}\" accept\n"));
        }
        if !v4.is_empty() {
            s.push_str(&format!("    ip daddr {{ {} }} accept\n", v4.join(", ")));
        }
        if !v6.is_empty() {
            s.push_str(&format!("    ip6 daddr {{ {} }} accept\n", v6.join(", ")));
        }
        if !d4.is_empty() {
            s.push_str(&format!(
                "    ip daddr {{ {} }} udp dport 53 accept\n    ip daddr {{ {} }} tcp dport 53 accept\n",
                d4.join(", "),
                d4.join(", ")
            ));
        }
        if !d6.is_empty() {
            s.push_str(&format!(
                "    ip6 daddr {{ {} }} udp dport 53 accept\n    ip6 daddr {{ {} }} tcp dport 53 accept\n",
                d6.join(", "),
                d6.join(", ")
            ));
        }
        // DHCPv4 / DHCPv6 so the machine keeps its address; neighbour discovery so IPv6 on-link
        // addresses (the gateway, the VPN server) can be reached at all.
        s.push_str("    udp sport 68 udp dport 67 accept\n");
        s.push_str("    ip6 daddr { ff02::/16, fe80::/10 } udp sport 546 udp dport 547 accept\n");
        s.push_str("    ip6 daddr { ff02::/16, fe80::/10 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n");
        if self.allow_lan {
            s.push_str("    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/24 } accept\n    ip6 daddr { fc00::/7, fe80::/10, ff02::/16 } accept\n");
        }
        s.push_str("  }\n}\n");
        Ok(s)
    }

    /// macOS pf anchor text. Load with `pfctl -a com.apple/woodward-tunnel -f -`.
    pub fn pf(&self) -> Result<String, PolicyError> {
        self.validate()?;
        // pf names interface groups without a number (`utun`) and does not take globs.
        let pf_if = |i: &str| i.trim_end_matches('*').to_string();
        let (v4, v6) = split_ips(&self.server_ips);
        let (d4, d6) = split_ips(&self.dns_bootstrap);
        let mut s = String::from("pass out quick on lo0 all\n");
        s.push_str(&format!(
            "pass out quick on {} all\n",
            pf_if(&self.tun_iface)
        ));
        for i in &self.allow_ifaces {
            s.push_str(&format!("pass out quick on {} all\n", pf_if(i)));
        }
        for ip in &v4 {
            s.push_str(&format!("pass out quick inet to {ip}\n"));
        }
        for ip in &v6 {
            s.push_str(&format!("pass out quick inet6 to {ip}\n"));
        }
        for ip in &d4 {
            s.push_str(&format!(
                "pass out quick inet proto {{ udp tcp }} to {ip} port 53\n"
            ));
        }
        for ip in &d6 {
            s.push_str(&format!(
                "pass out quick inet6 proto {{ udp tcp }} to {ip} port 53\n"
            ));
        }
        s.push_str("pass out quick inet proto udp from any port 68 to any port 67\n");
        s.push_str("pass out quick inet6 proto udp from any port 546 to any port 547\n");
        s.push_str("pass out quick inet6 proto icmp6 all icmp6-type { routersol, neighbrsol, neighbradv }\n");
        if self.allow_lan {
            s.push_str("pass out quick to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/24, fe80::/10, fc00::/7, ff02::/16 }\n");
        }
        s.push_str("block drop out all\n");
        Ok(s)
    }

    /// Windows: PowerShell that creates allow rules in the group `WoodwardTunnel`, then switches
    /// the outbound default of every profile to Block (block rules would beat allow rules, so the
    /// profile default is the only way to express "deny everything else").
    pub fn windows_powershell(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let (v4, v6) = split_ips(&self.server_ips);
        let (d4, d6) = split_ips(&self.dns_bootstrap);
        let mut s = String::from("$ErrorActionPreference='Stop'\n$g='WoodwardTunnel'\n");
        s.push_str("Remove-NetFirewallRule -Group $g -ErrorAction SilentlyContinue\n");
        let rule = |name: &str, extra: &str| {
            format!("New-NetFirewallRule -Group $g -DisplayName 'WT {name}' -Direction Outbound -Action Allow -Profile Any {extra}\n")
        };
        s.push_str(&rule(
            "allow tunnel",
            &format!("-InterfaceAlias '{}'", self.tun_iface),
        ));
        for i in &self.allow_ifaces {
            s.push_str(&rule("allow iface", &format!("-InterfaceAlias '{i}'")));
        }
        let server: Vec<String> = v4.iter().chain(v6.iter()).cloned().collect();
        if !server.is_empty() {
            s.push_str(&rule(
                "allow server",
                &format!("-RemoteAddress {}", server.join(",")),
            ));
        }
        let dns: Vec<String> = d4.iter().chain(d6.iter()).cloned().collect();
        if !dns.is_empty() {
            s.push_str(&rule(
                "allow bootstrap dns",
                &format!(
                    "-Protocol UDP -RemotePort 53 -RemoteAddress {}",
                    dns.join(",")
                ),
            ));
            s.push_str(&rule(
                "allow bootstrap dns tcp",
                &format!(
                    "-Protocol TCP -RemotePort 53 -RemoteAddress {}",
                    dns.join(",")
                ),
            ));
        }
        s.push_str(&rule("allow loopback", "-RemoteAddress 127.0.0.1,::1"));
        s.push_str(&rule(
            "allow dhcp",
            "-Protocol UDP -LocalPort 68 -RemotePort 67",
        ));
        s.push_str(&rule(
            "allow dhcpv6",
            "-Protocol UDP -LocalPort 546 -RemotePort 547",
        ));
        s.push_str(&rule(
            "allow neighbor discovery",
            "-Protocol ICMPv6 -IcmpType 133,135,136",
        ));
        if self.allow_lan {
            s.push_str(&rule("allow lan", "-RemoteAddress LocalSubnet,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,fe80::/10,fc00::/7"));
        }
        s.push_str(
            "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block\n",
        );
        Ok(s)
    }

    /// Fixed removal script used only when no saved state exists (otherwise the saved defaults are restored).
    pub fn windows_powershell_remove() -> &'static str {
        "Remove-NetFirewallRule -Group 'WoodwardTunnel' -ErrorAction SilentlyContinue\nSet-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ks() -> KillSwitch {
        KillSwitch::new(
            "tun0",
            vec![
                "203.0.113.9".parse().unwrap(),
                "2001:db8::9".parse().unwrap(),
            ],
        )
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
    fn ipv6_plumbing_and_no_established_bypass() {
        let r = ks().nftables().unwrap();
        // Neighbour discovery and DHCPv6 are allowed, echo requests are not.
        assert!(r.contains("nd-neighbor-solicit") && r.contains("dport 547"));
        assert!(!r.contains("echo-request") && !r.contains("ct state"));
        // Only the explicit table is touched.
        assert!(r.starts_with("table inet wt_killswitch"));
    }

    #[test]
    fn many_server_addresses_and_bootstrap_dns() {
        let mut k = ks();
        k.server_ips = (1..=5)
            .map(|i| format!("198.51.100.{i}").parse().unwrap())
            .collect();
        k.dns_bootstrap = vec!["192.168.1.1".parse().unwrap()];
        k.allow_ifaces = vec!["docker0".into(), "br-*".into()];
        let r = k.nftables().unwrap();
        for i in 1..=5 {
            assert!(r.contains(&format!("198.51.100.{i}")));
        }
        assert!(r.contains("ip daddr { 192.168.1.1 } udp dport 53 accept"));
        assert!(r.contains("oifname \"br-*\" accept"));
        // DNS is not opened to anyone else.
        assert!(!r.contains("dport 53 accept\n    udp dport 53"));
        let mut k2 = ks();
        k2.dns_bootstrap = vec![];
        assert!(!k2.nftables().unwrap().contains("dport 53"));
    }

    #[test]
    fn pf_and_windows_include_ipv6_and_dns_rules() {
        let mut k = ks();
        k.dns_bootstrap = vec!["192.168.1.1".parse().unwrap()];
        let pf = k.pf().unwrap();
        assert!(pf.contains("inet6 to 2001:db8::9") && pf.contains("port 53"));
        assert!(pf.trim_end().ends_with("block drop out all"));
        let w = k.windows_powershell().unwrap();
        assert!(w.contains("ICMPv6") && w.contains("-RemotePort 53"));
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
        assert!(
            r.trim_end().ends_with("block drop out all") && r.contains("pass out quick on tun0")
        );
    }
}
