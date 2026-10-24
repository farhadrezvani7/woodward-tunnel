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
    /// The server refused the credentials (wrong or expired password, UUID, key). Retrying cannot help.
    Auth,
    /// TLS handshake or certificate verification failed (wrong certificate, clock, interception).
    Tls,
    /// The server host name could not be resolved.
    Dns,
    /// A local port or address needed by the engine is already in use.
    PortBusy,
    /// A helper program (sing-box, openvpn, awg-socks) is missing or not executable.
    EngineMissing,
    /// A helper program is too old for the generated configuration.
    EngineVersion,
    /// The TUN device could not be created (module missing, no /dev/net/tun, no privileges).
    Device,
    /// Leak protection could not be applied, so the connection was not allowed to proceed.
    KillSwitch,
}

impl FailureKind {
    pub fn retryable(self) -> bool {
        matches!(
            self,
            FailureKind::Network | FailureKind::Server | FailureKind::Dns
        )
    }
    pub fn code(self) -> &'static str {
        match self {
            FailureKind::Network => "network",
            FailureKind::Server => "server",
            FailureKind::Config => "config",
            FailureKind::Permission => "permission",
            FailureKind::Auth => "auth",
            FailureKind::Tls => "tls",
            FailureKind::Dns => "dns",
            FailureKind::PortBusy => "port_busy",
            FailureKind::EngineMissing => "engine_missing",
            FailureKind::EngineVersion => "engine_version",
            FailureKind::Device => "device",
            FailureKind::KillSwitch => "killswitch",
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
            FailureKind::Auth => {
                "The server rejected your credentials. Check the password or key, or ask your provider for a new config."
            }
            FailureKind::Tls => {
                "The secure connection to the server could not be verified. Check your device clock, or ask your provider for a new config."
            }
            FailureKind::Dns => {
                "The server name could not be looked up. Check your internet connection or DNS."
            }
            FailureKind::PortBusy => {
                "A network port needed by the VPN is already in use. Close the other VPN or proxy program, or pick another port."
            }
            FailureKind::EngineMissing => {
                "A required helper program is missing or cannot be started. Reinstall the app."
            }
            FailureKind::EngineVersion => {
                "A helper program is too old for this app. Reinstall or update the app."
            }
            FailureKind::Device => {
                "The system tunnel device could not be created. Run with the needed privileges or enable the TUN driver."
            }
            FailureKind::KillSwitch => {
                "Leak protection could not be turned on, so the VPN was not started. Run with the needed privileges or turn leak protection off in settings."
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
            FailureKind::Auth => {
                "سرور اطلاعات ورود شما را نپذیرفت. گذرواژه یا کلید را بررسی کنید یا از ارائه‌دهنده کانفیگ جدید بخواهید."
            }
            FailureKind::Tls => {
                "اتصال امن به سرور تأیید نشد. ساعت دستگاه را بررسی کنید یا از ارائه‌دهنده کانفیگ جدید بخواهید."
            }
            FailureKind::Dns => {
                "نام سرور پیدا نشد. اتصال اینترنت یا DNS را بررسی کنید."
            }
            FailureKind::PortBusy => {
                "درگاه شبکهٔ مورد نیاز VPN در حال استفاده است. برنامهٔ VPN یا پروکسی دیگر را ببندید یا درگاه دیگری انتخاب کنید."
            }
            FailureKind::EngineMissing => {
                "یک برنامهٔ کمکی لازم پیدا نشد یا اجرا نمی‌شود. برنامه را دوباره نصب کنید."
            }
            FailureKind::EngineVersion => {
                "یک برنامهٔ کمکی برای این نسخه از برنامه قدیمی است. برنامه را به‌روزرسانی کنید."
            }
            FailureKind::Device => {
                "دستگاه تونل سیستم ساخته نشد. با دسترسی لازم اجرا کنید یا درایور TUN را فعال کنید."
            }
            FailureKind::KillSwitch => {
                "محافظ نشت اطلاعات فعال نشد و به همین دلیل VPN شروع نشد. با دسترسی لازم اجرا کنید یا محافظ را در تنظیمات خاموش کنید."
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
    /// Never give up on retryable failures (used while leak protection blocks the direct path:
    /// giving up would strand the user offline for no benefit).
    keep_trying: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            state: State::Idle,
            keep_trying: false,
        }
    }
}

impl Session {
    pub fn state(&self) -> State {
        self.state
    }

    /// Retry forever (backoff stays capped) instead of failing after [`MAX_ATTEMPTS`].
    pub fn set_keep_trying(&mut self, on: bool) {
        self.keep_trying = on;
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
                if k.retryable() && (self.keep_trying || attempt < MAX_ATTEMPTS) {
                    (
                        S::Reconnecting {
                            attempt: attempt.saturating_add(1),
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
            // Network change while an attempt is running: that attempt was bound to the old
            // network, restart it without waiting. Attempt number is kept.
            (S::Connecting { attempt }, E::NetworkChanged) => (
                S::Reconnecting { attempt },
                vec![StopEngine, ScheduleRetry(Duration::ZERO)],
            ),
            // Network came back while waiting for the backoff timer: try now.
            (S::Reconnecting { attempt }, E::NetworkChanged) => (
                S::Reconnecting { attempt },
                vec![CancelRetry, ScheduleRetry(Duration::ZERO)],
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
    fn keep_trying_never_gives_up_on_retryable_failures() {
        let mut s = Session::default();
        s.set_keep_trying(true);
        s.handle(UserConnect);
        s.handle(Prepared);
        for _ in 0..(MAX_ATTEMPTS * 4) {
            s.handle(EngineFailed(Server));
            assert!(matches!(s.state(), State::Reconnecting { .. }));
            s.handle(RetryTimerFired);
        }
        // Non-retryable still stops.
        s.handle(EngineFailed(Auth));
        assert_eq!(s.state(), State::Failed(Auth));
    }

    #[test]
    fn new_kinds_have_unique_codes_and_messages() {
        let all = [
            Network,
            Server,
            Config,
            Permission,
            Auth,
            Tls,
            Dns,
            PortBusy,
            EngineMissing,
            EngineVersion,
            Device,
            KillSwitch,
        ];
        let mut codes: Vec<_> = all.iter().map(|k| k.code()).collect();
        codes.sort();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
        for k in all {
            assert!(!k.user_message().is_empty() && !k.user_message_en().is_empty());
        }
        // Existing codes are a public contract.
        assert_eq!(
            [
                Network.code(),
                Server.code(),
                Config.code(),
                Permission.code()
            ],
            ["network", "server", "config", "permission"]
        );
    }

    #[test]
    fn network_change_while_waiting_skips_the_backoff() {
        let mut s = run(&[UserConnect, Prepared, EngineFailed(Server)]);
        assert!(matches!(s.state(), State::Reconnecting { .. }));
        let acts = s.handle(NetworkChanged);
        assert!(acts.contains(&Action::ScheduleRetry(Duration::ZERO)));
    }

    #[test]
    fn network_change_during_attempt_restarts_it() {
        let mut s = run(&[UserConnect, Prepared]);
        let acts = s.handle(NetworkChanged);
        assert!(acts.contains(&Action::StopEngine));
        assert_eq!(s.state(), State::Reconnecting { attempt: 1 });
    }

    /// Tiny deterministic generator so the random walk needs no extra crates.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    /// Random event sequences must never break the invariants the controller relies on.
    #[test]
    fn random_walk_invariants() {
        let kinds = [
            Network, Server, Config, Permission, Auth, Tls, Dns, KillSwitch,
        ];
        for seed in 0..300u64 {
            let mut rng = Lcg(seed + 1);
            let mut s = Session::default();
            s.set_keep_trying(seed % 3 == 0);
            // Model of what the world looks like to the controller.
            let mut verified_since_start = false;
            let mut engine_running = false;
            for _ in 0..400 {
                let ev = match rng.next() % 9 {
                    0 => UserConnect,
                    1 => UserDisconnect,
                    2 => Prepared,
                    3 => PrepareFailed(kinds[(rng.next() % 8) as usize]),
                    4 => TunnelVerified,
                    5 => EngineFailed(kinds[(rng.next() % 8) as usize]),
                    6 => NetworkChanged,
                    7 => RetryTimerFired,
                    _ => Stopped,
                };
                let before = s.state();
                let acts = s.handle(ev);
                let after = s.state();
                for a in &acts {
                    match a {
                        Action::StartEngine => {
                            engine_running = true;
                            verified_since_start = false;
                        }
                        Action::StopEngine => {
                            engine_running = false;
                            verified_since_start = false;
                        }
                        _ => {}
                    }
                }
                if ev == TunnelVerified && after == State::Connected && before != State::Connected {
                    assert!(matches!(before, State::Connecting { .. }), "{before:?}");
                    verified_since_start = true;
                }
                // Never Connected without verification of the running engine.
                if after == State::Connected {
                    assert!(verified_since_start && engine_running, "seed {seed}");
                }
                // Idle: nothing may be scheduled or started by the event that led here.
                if after == State::Idle {
                    assert!(!acts.contains(&Action::StartEngine), "seed {seed}");
                }
                // A failure while connecting always stops the engine.
                if matches!(before, State::Connecting { .. })
                    && matches!(after, State::Failed(_) | State::Reconnecting { .. })
                    && matches!(ev, EngineFailed(_))
                {
                    assert!(acts.contains(&Action::StopEngine), "seed {seed}");
                }
                // Disconnecting always ends via Stopped; user disconnect always stops the engine.
                if ev == UserDisconnect
                    && matches!(
                        before,
                        State::Preparing
                            | State::Connecting { .. }
                            | State::Connected
                            | State::Reconnecting { .. }
                    )
                {
                    assert_eq!(after, State::Disconnecting);
                    assert!(acts.contains(&Action::StopEngine));
                }
                // Starting an engine only from Preparing or a timer, never from stray events.
                if acts.contains(&Action::StartEngine) {
                    assert!(
                        matches!(ev, Prepared | RetryTimerFired),
                        "seed {seed}: {ev:?}"
                    );
                }
                // Attempts never decrease within one connect cycle except via restart.
                if let (State::Reconnecting { attempt: a }, State::Reconnecting { attempt: b }) =
                    (before, after)
                {
                    assert!(b >= a);
                }
            }
        }
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(3), Duration::from_secs(4));
        assert_eq!(backoff(40), Duration::from_secs(30));
        assert_eq!(backoff(0), Duration::from_secs(1));
    }
}
