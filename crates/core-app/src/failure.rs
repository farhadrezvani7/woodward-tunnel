//! Turn engine start errors and engine log lines into a [`FailureKind`] with plain guidance.
//! The log lines are already redacted; only lower-cased substrings of well-known messages of
//! sing-box and OpenVPN are matched, nothing is echoed to the user.

use core_engine::runner::StartError;
use core_session::FailureKind;

/// Ordered rules: the first rule with a matching needle wins, so more specific causes come
/// before generic ones (a certificate error also mentions "tls", a bind error also "permission").
const RULES: &[(FailureKind, &[&str])] = &[
    // OpenVPN prints this when the server is silent (UDP blocked or server down), not a TLS fault.
    (
        FailureKind::Server,
        &["tls key negotiation failed to occur"],
    ),
    (
        FailureKind::Auth,
        &[
            "auth_failed",
            "auth failed",
            "authentication failed",
            "authentication error",
            "unable to authenticate",
            "permission denied (publickey",
            "wrong password",
            "invalid password",
            "invalid user",
            "unauthorized",
            "user or password",
        ],
    ),
    (
        FailureKind::Tls,
        &[
            "certificate verify failed",
            "verify error",
            "x509:",
            "unknown authority",
            "certificate has expired",
            "certificate is not valid",
            "bad certificate",
            "failed to verify certificate",
            "handshake failure",
            "tls: ",
            "tls handshake",
            "reality verification failed",
        ],
    ),
    (
        FailureKind::PortBusy,
        &[
            "address already in use",
            "eaddrinuse",
            "only one usage of each socket address",
            "port is already allocated",
            "device or resource busy",
            "file exists",
        ],
    ),
    (
        FailureKind::Device,
        &[
            "no such device",
            "/dev/net/tun",
            "cannot open tun",
            "open tun",
            "wintun",
            "tun: ",
            "unable to open tun",
        ],
    ),
    (
        FailureKind::Permission,
        &[
            "permission denied",
            "operation not permitted",
            "access is denied",
            "requires administrator",
            "not permitted",
        ],
    ),
    (
        FailureKind::Dns,
        &[
            "no such host",
            "could not resolve",
            "cannot resolve",
            "resolve: ",
            "name resolution",
            "server misbehaving",
            "dns: ",
            "lookup ",
            "temporary failure in name resolution",
        ],
    ),
    (
        FailureKind::Network,
        &[
            "network is unreachable",
            "network unreachable",
            "no route to host",
            "host is unreachable",
            "network is down",
        ],
    ),
    (
        FailureKind::Config,
        &[
            "decode config",
            "unknown field",
            "parse config",
            "options error",
            "unknown option",
            "unrecognized option",
            "invalid config",
        ],
    ),
    (
        FailureKind::Server,
        &[
            "connection refused",
            "i/o timeout",
            "timed out",
            "connection reset",
            "unexpected eof",
            "broken pipe",
        ],
    ),
];

/// Best guess from engine output, or `None` when nothing recognisable was printed.
pub fn classify_log<S: AsRef<str>>(lines: &[S]) -> Option<FailureKind> {
    let text: String = lines
        .iter()
        .map(|l| l.as_ref().to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join("\n");
    RULES
        .iter()
        .find(|(_, needles)| needles.iter().any(|n| text.contains(n)))
        .map(|(k, _)| *k)
}

pub fn classify_start_error(e: &StartError) -> FailureKind {
    match e {
        StartError::Resolve => FailureKind::Dns,
        StartError::Timeout { tail } | StartError::ExitedEarly { tail } => {
            let lines: Vec<&str> = tail.lines().collect();
            classify_log(&lines).unwrap_or(FailureKind::Server)
        }
        StartError::Engine(_) => FailureKind::Config,
        StartError::BinaryMissing { .. } => FailureKind::EngineMissing,
        StartError::BinaryVersion { .. } => FailureKind::EngineVersion,
        StartError::Busy { .. } => FailureKind::PortBusy,
        StartError::Io(k) if k.contains("not found") || k.contains("not executable") => {
            FailureKind::EngineMissing
        }
        StartError::Io(k) if k.contains("permission") => FailureKind::Permission,
        StartError::Io(_) | StartError::Cancelled => FailureKind::Config,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use FailureKind::*;

    fn c(s: &str) -> Option<FailureKind> {
        classify_log(&[s])
    }

    #[test]
    fn real_engine_messages_map_to_specific_kinds() {
        assert_eq!(c("AUTH: Received control message: AUTH_FAILED"), Some(Auth));
        assert_eq!(c("ERROR: trojan: authentication failed"), Some(Auth));
        assert_eq!(
            c("tls: failed to verify certificate: x509: certificate signed by unknown authority"),
            Some(Tls)
        );
        assert_eq!(
            c("VERIFY ERROR: depth=0, error=certificate has expired"),
            Some(Tls)
        );
        assert_eq!(
            c("FATAL start service: listen tcp 127.0.0.1:1080: bind: address already in use"),
            Some(PortBusy)
        );
        assert_eq!(
            c("FATAL start inbound/tun[tun-in]: configure tun interface: operation not permitted"),
            Some(Permission)
        );
        assert_eq!(c("FATAL open /dev/net/tun: no such device"), Some(Device));
        assert_eq!(
            c("dial tcp: lookup vpn.example.com on 127.0.0.53:53: no such host"),
            Some(Dns)
        );
        assert_eq!(
            c("dial tcp 203.0.113.9:443: connect: network is unreachable"),
            Some(Network)
        );
        assert_eq!(
            c("dial tcp 203.0.113.9:443: connect: connection refused"),
            Some(Server)
        );
        assert_eq!(
            c("TLS Error: TLS key negotiation failed to occur within 60 seconds"),
            Some(Server)
        );
        assert_eq!(
            c("FATAL decode config at x.json: unknown field \"foo\""),
            Some(Config)
        );
        assert_eq!(c("INFO router: updated default interface eth0"), None);
    }

    #[test]
    fn start_errors_map_without_log_text() {
        assert_eq!(classify_start_error(&StartError::Resolve), Dns);
        assert_eq!(
            classify_start_error(&StartError::BinaryMissing { name: "sing-box" }),
            EngineMissing
        );
        assert_eq!(
            classify_start_error(&StartError::BinaryVersion {
                name: "sing-box",
                found: "1.9.0".into(),
                need: "1.12.0".into()
            }),
            EngineVersion
        );
        assert_eq!(
            classify_start_error(&StartError::Busy {
                what: "port 1".into()
            }),
            PortBusy
        );
        assert_eq!(
            classify_start_error(&StartError::Timeout {
                tail: String::new()
            }),
            Server
        );
        assert_eq!(
            classify_start_error(&StartError::ExitedEarly {
                tail: "FATAL bind: address already in use".into()
            }),
            PortBusy
        );
        assert_eq!(
            classify_start_error(&StartError::Io("permission denied".into())),
            Permission
        );
    }
}
