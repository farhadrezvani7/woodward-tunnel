//! Engines turn a validated profile into a running tunnel. This crate holds config generation
//! for each backend, the sidecar process supervisor, and tunnel-verification probes.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod probe;
pub mod sidecar;
pub mod singbox;

use core_model::Protocol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// System-wide tunnel (needs privileges).
    Tun,
    /// Local SOCKS listener only; used for tests and unprivileged use.
    Proxy { socks_port: u16 },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EngineError {
    #[error("profile is missing {0}")]
    Profile(&'static str),
    #[error("{0:?} is not handled by this engine")]
    NotSupported(Protocol),
}
