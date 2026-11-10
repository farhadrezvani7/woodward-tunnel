//! Engines turn a validated profile into a running tunnel. This crate holds config generation
//! for each backend, the sidecar process supervisor, and tunnel-verification probes.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod awg;
pub mod openvpn;
pub mod probe;
pub mod runner;
pub mod sidecar;
pub mod singbox;
pub mod xray;

use core_model::Protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// System-wide tunnel (needs privileges).
    Tun,
    /// Local SOCKS listener only; used for tests and unprivileged use.
    Proxy { socks_port: u16 },
}

/// A helper engine's local SOCKS5 listener that sing-box tunnels into (AmneziaWG, Xray). The credentials
/// are random per session: any other app on the machine can connect to a loopback port, and without them
/// it would get free use of the user's tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub addr: std::net::SocketAddr,
    pub username: String,
    pub password: String,
}

impl Upstream {
    /// Loopback listener on `port` with fresh random credentials.
    pub fn new_random(port: u16) -> Result<Self, EngineError> {
        let (username, password) = session_credentials()?;
        Ok(Self {
            addr: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            username,
            password,
        })
    }
}

/// Random username and password for one session (16 random bytes each, hex).
pub fn session_credentials() -> Result<(String, String), EngineError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| EngineError::Profile("random credentials"))?;
    let hex = |s: &[u8]| s.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Ok((hex(&b[..16]), hex(&b[16..])))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EngineError {
    /// A setting this engine cannot honor; the text is shown to the user, so it is plain language.
    #[error("{0}")]
    Unsupported(&'static str),
    #[error("profile is missing {0}")]
    Profile(&'static str),
    #[error("{0:?} is not handled by this engine")]
    NotSupported(Protocol),
}
