//! Connection state machine. Pure and synchronous: it turns events into a new state plus
//! actions for the caller to perform, so every transition is unit-testable without a network.
//!
//! `Connected` is reached only on `TunnelVerified` (real evidence, e.g. handshake plus a
//! probe through the tunnel), never merely because an engine process started.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::time::Duration;

pub const MAX_ATTEMPTS: u32 = 5;
const BACKOFF_BASE: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Failure class; selects the user-facing guidance and whether retrying makes sense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Local network down or unreachable.
    Network,
    /// Server did not answer or rejected the handshake.
    Server,
    /// Profile is invalid for the engine; retrying cannot help.
    Config,
    /// OS refused tunnel permission.
    Permission,
}

impl FailureKind {
    pub fn retryable(self) -> bool {
        matches!(self, FailureKind::Network | FailureKind::Server)
    }
    pub fn code(self) -> &'static str {
        match self {
            FailureKind::Network => "network",
            FailureKind::Server => "server",
            FailureKind::Config => "config",
            FailureKind::Permission => "permission",
        }
    }
    pub fn user_message_en(self) -> &'static str {
        match self {
            FailureKind::Network => {
                "Your internet connection is down or unstable. Check your network."
            }
            FailureKind::Server => {
                "The server is not responding. Try again or pick another server."
            }
            FailureKind::Config => "This config does not work. Ask your provider for a new file.",
            FailureKind::Permission => {
                "VPN permission was not granted. Allow it in the system dialog."
            }
        }
    }
    pub fn user_message(self) -> &'static str {
        match self {
            FailureKind::Network => {
                "اینترنت شما قطع است یا ناپایدار است. اتصال شبکه را بررسی کنید."
            }
            FailureKind::Server => "سرور پاسخ نمی‌دهد. دوباره تلاش کنید یا سرور دیگری انتخاب کنید.",
            FailureKind::Config => "این کانفیگ کار نمی‌کند. از ارائه‌دهندهٔ سرویس فایل جدید بخواهید.",
            FailureKind::Permission => {
                "اجازهٔ ساخت VPN داده نشد. در پنجرهٔ سیستم، اجازه را تأیید کنید."
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Preparing,
    Connecting { attempt: u32 },
    Connected,
    Reconnecting { attempt: u32 },
    Disconnecting,
    Failed(FailureKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    UserConnect,
    UserDisconnect,
    Prepared,
    PrepareFailed(FailureKind),
    TunnelVerified,
    EngineFailed(FailureKind),
    NetworkChanged,
    RetryTimerFired,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Prepare,
    StartEngine,
    StopEngine,
    ScheduleRetry(Duration),
    CancelRetry,
}

/// Delay before retry number `attempt` (1-based): 1s, 2s, 4s, ... capped at 30s.
pub fn backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(16);
    BACKOFF_BASE.saturating_mul(1u32 << shift).min(BACKOFF_CAP)
}

#[derive(Debug)]
pub struct Session {
    state: State,
}

impl Default for Session {
    fn default() -> Self {
        Self { state: State::Idle }
    }
}

impl Session {
    pub fn state(&self) -> State {
        self.state
    }

    /// Apply an event. Events that make no sense in the current state are ignored.
    pub fn handle(&mut self, ev: Event) -> Vec<Action> {
        use Action::*;
        use Event as E;
        use State as S;
        let (next, actions) = match (self.state, ev) {
            (S::Idle | S::Failed(_), E::UserConnect) => (S::Preparing, vec![Prepare]),
            (S::Failed(_), E::UserDisconnect) => (S::Idle, vec![]),
            (
                S::Preparing | S::Connecting { .. } | S::Connected | S::Reconnecting { .. },
                E::UserDisconnect,
            ) => (S::Disconnecting, vec![CancelRetry, StopEngine]),
            (S::Disconnecting, E::Stopped) => (S::Idle, vec![]),
            (S::Preparing, E::Prepared) => (S::Connecting { attempt: 1 }, vec![StartEngine]),
            (S::Preparing, E::PrepareFailed(k)) => (S::Failed(k), vec![]),
            (S::Connecting { .. }, E::TunnelVerified) => (S::Connected, vec![]),
            (S::Connecting { attempt }, E::EngineFailed(k)) => {
                if k.retryable() && attempt < MAX_ATTEMPTS {
                    (
                        S::Reconnecting {
                            attempt: attempt + 1,
                        },
                        vec![StopEngine, ScheduleRetry(backoff(attempt))],
                    )
                } else {
                    (S::Failed(k), vec![StopEngine])
                }
            }
            (S::Connected, E::EngineFailed(k)) if k.retryable() => (
                S::Reconnecting { attempt: 2 },
                vec![StopEngine, ScheduleRetry(backoff(1))],
            ),
            (S::Connected, E::EngineFailed(k)) => (S::Failed(k), vec![StopEngine]),
            // Network switch: restart immediately instead of waiting for a timeout.
            (S::Connected, E::NetworkChanged) => (
                S::Reconnecting { attempt: 2 },
                vec![StopEngine, ScheduleRetry(Duration::ZERO)],
            ),
            (S::Reconnecting { attempt }, E::RetryTimerFired) => {
                (S::Connecting { attempt }, vec![StartEngine])
            }
            (s, _) => (s, vec![]),
        };
        self.state = next;
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Event::*;
    use FailureKind::*;

    fn run(events: &[Event]) -> Session {
        let mut s = Session::default();
        for e in events {
            s.handle(*e);
        }
        s
    }

    #[test]
    fn happy_path_reaches_connected_only_after_verification() {
        let mut s = Session::default();
        assert_eq!(s.handle(UserConnect), vec![Action::Prepare]);
        assert_eq!(s.handle(Prepared), vec![Action::StartEngine]);
        assert_eq!(s.state(), State::Connecting { attempt: 1 });
        s.handle(TunnelVerified);
        assert_eq!(s.state(), State::Connected);
    }

    #[test]
    fn engine_started_is_not_connected() {
        assert_ne!(run(&[UserConnect, Prepared]).state(), State::Connected);
    }

    #[test]
    fn disconnect_from_any_active_state_returns_to_idle() {
        let paths: [&[Event]; 4] = [
            &[UserConnect],
            &[UserConnect, Prepared],
            &[UserConnect, Prepared, TunnelVerified],
            &[UserConnect, Prepared, EngineFailed(Server)],
        ];
        for p in paths {
            let mut s = run(p);
            let acts = s.handle(UserDisconnect);
            assert!(acts.contains(&Action::StopEngine) && acts.contains(&Action::CancelRetry));
            s.handle(Stopped);
            assert_eq!(s.state(), State::Idle);
        }
    }

    #[test]
    fn retries_with_backoff_then_gives_up() {
        let mut s = run(&[UserConnect, Prepared]);
        for attempt in 1..MAX_ATTEMPTS {
            let acts = s.handle(EngineFailed(Server));
            assert!(acts.contains(&Action::ScheduleRetry(backoff(attempt))));
            assert_eq!(
                s.state(),
                State::Reconnecting {
                    attempt: attempt + 1
                }
            );
            s.handle(RetryTimerFired);
        }
        s.handle(EngineFailed(Server));
        assert_eq!(s.state(), State::Failed(Server));
    }

    #[test]
    fn config_and_permission_errors_do_not_retry() {
        for k in [Config, Permission] {
            assert_eq!(
                run(&[UserConnect, Prepared, EngineFailed(k)]).state(),
                State::Failed(k)
            );
        }
        assert_eq!(
            run(&[UserConnect, PrepareFailed(Permission)]).state(),
            State::Failed(Permission)
        );
    }

    #[test]
    fn network_change_reconnects_immediately() {
        let mut s = run(&[UserConnect, Prepared, TunnelVerified]);
        let acts = s.handle(NetworkChanged);
        assert!(acts.contains(&Action::ScheduleRetry(Duration::ZERO)));
        assert!(matches!(s.state(), State::Reconnecting { .. }));
    }

    #[test]
    fn failed_can_retry_by_user() {
        let mut s = run(&[UserConnect, PrepareFailed(Config)]);
        assert_eq!(s.handle(UserConnect), vec![Action::Prepare]);
    }

    #[test]
    fn stray_events_are_ignored() {
        let mut s = Session::default();
        assert!(s.handle(TunnelVerified).is_empty());
        assert!(s.handle(RetryTimerFired).is_empty());
        assert_eq!(s.state(), State::Idle);
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(3), Duration::from_secs(4));
        assert_eq!(backoff(40), Duration::from_secs(30));
        assert_eq!(backoff(0), Duration::from_secs(1));
    }
}
