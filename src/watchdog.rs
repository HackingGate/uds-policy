//! Minimal `sd_notify(3)` client for the systemd software watchdog.
//!
//! The unit runs `Type=notify` with `WatchdogSec=<N>`, the daemon signals
//! `READY=1` once its socket is bound, and a dedicated heartbeat thread pets
//! the watchdog (`WATCHDOG=1`) every `WatchdogSec/2`.
//!
//! The heartbeat must distinguish **busy** from **wedged**. A privileged
//! request can legitimately outlive the watchdog window — a slow host tool on a
//! loaded board takes minutes, not seconds — so pets cannot come from the serve
//! loop itself: a loop blocked inside a healthy long request goes silent
//! exactly when it is doing the most work, and systemd `SIGABRT`s the daemon
//! mid-operation. Instead the serve loop records what it is doing in a
//! [`ServeActivity`], and the heartbeat thread pets while that record says the
//! loop is either idling normally or making bounded progress on a request.
//! Pets stop — and systemd restarts the unit — when a request overstays
//! `longest_legitimate_request` or the loop stops turning entirely.
//!
//! This is a dependency-free, `unsafe`-free implementation of the protocol (a
//! datagram `key=value` message to `$NOTIFY_SOCKET`); it is a silent no-op when
//! the daemon is not launched under systemd (the env vars are unset).

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Tell systemd the daemon has finished startup and is serving (`Type=notify`).
pub(crate) fn notify_ready() {
    notify("READY=1");
}

/// Pet the watchdog: report that the daemon is still making progress.
fn pet() {
    notify("WATCHDOG=1");
}

/// What the serve loop is doing right now, as seen by the heartbeat thread.
#[derive(Debug)]
pub(crate) struct ServeActivity {
    state: Mutex<ActivityState>,
}

#[derive(Debug)]
struct ActivityState {
    last_tick: Instant,
    request_started_at: Option<Instant>,
}

impl ServeActivity {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ActivityState {
                last_tick: Instant::now(),
                request_started_at: None,
            }),
        })
    }

    /// The serve loop completed a turn (served a request or idled through an
    /// accept timeout).
    pub(crate) fn tick(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.last_tick = Instant::now();
        }
    }

    /// A request handler is about to run on the serve thread.
    pub(crate) fn request_started(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.request_started_at = Some(Instant::now());
        }
    }

    /// The request handler returned (successfully or not).
    pub(crate) fn request_finished(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.request_started_at = None;
            state.last_tick = Instant::now();
        }
    }

    /// Whether the serve loop counts as alive right now.
    ///
    /// `idle_tick_ceiling` is how stale the loop's tick may go while *no*
    /// request is in flight before the loop counts as wedged; `None` means idle
    /// ticks are not expected (the accept timeout could not be armed) and an
    /// idle loop is trusted unconditionally.
    fn is_alive(
        &self,
        now: Instant,
        idle_tick_ceiling: Option<Duration>,
        longest_legitimate_request: Duration,
    ) -> bool {
        let Ok(state) = self.state.lock() else {
            // A poisoned lock means the serve thread panicked mid-update;
            // stop petting and let systemd restart the daemon.
            return false;
        };
        state.request_started_at.map_or_else(
            // Idle: the accept timeout makes the loop turn (and tick) at least
            // once per heartbeat interval, so a stale tick means the loop
            // stopped turning outside any handler.
            || {
                idle_tick_ceiling
                    .is_none_or(|ceiling| now.saturating_duration_since(state.last_tick) <= ceiling)
            },
            // Busy: a progressing privileged operation may legitimately hold
            // the serve thread for minutes; only an overstayed one is wedged.
            |started_at| now.saturating_duration_since(started_at) <= longest_legitimate_request,
        )
    }
}

/// Spawn the dedicated heartbeat thread: pets the watchdog every `interval` for
/// as long as `activity` reports the serve loop alive. Detached — it runs for
/// the life of the process.
pub(crate) fn spawn_heartbeat(
    interval: Duration,
    idle_tick_ceiling: Option<Duration>,
    longest_legitimate_request: Duration,
    activity: Arc<ServeActivity>,
) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            if activity.is_alive(
                Instant::now(),
                idle_tick_ceiling,
                longest_legitimate_request,
            ) {
                pet();
            }
        }
    });
}

/// The interval at which the daemon should pet the watchdog, or `None` when no
/// watchdog is configured (env var unset, malformed, or aimed at a different
/// pid). systemd exposes the full timeout in `WATCHDOG_USEC`; we pet at half
/// that, the interval `sd_notify`'s own documentation recommends.
pub(crate) fn heartbeat_interval() -> Option<Duration> {
    heartbeat_from(
        std::env::var("WATCHDOG_USEC").ok().as_deref(),
        std::env::var("WATCHDOG_PID").ok().as_deref(),
        std::process::id(),
    )
}

/// Pure core of [`heartbeat_interval`], split out for testing without touching
/// process-global env (`std::env::set_var` is `unsafe` under edition 2024).
fn heartbeat_from(
    watchdog_usec: Option<&str>,
    watchdog_pid: Option<&str>,
    current_pid: u32,
) -> Option<Duration> {
    // Only honor the watchdog when systemd aimed it at *this* process. When
    // WATCHDOG_PID is set it must match; when unset, the timeout is ours.
    if let Some(pid) = watchdog_pid
        && pid.parse::<u32>().ok() != Some(current_pid)
    {
        return None;
    }
    let usec: u64 = watchdog_usec?.parse().ok()?;
    (usec > 0).then(|| Duration::from_micros(usec / 2))
}

/// Best-effort send of a single `sd_notify` message to `$NOTIFY_SOCKET`.
///
/// Every failure — no socket, unbindable, unreachable — is swallowed:
/// notification is advisory and must never take down the daemon.
fn notify(message: &str) {
    let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    notify_to(&socket_path, message);
}

/// Pure core of [`notify`]: send `message` to an explicit socket path.
///
/// Supports both filesystem-path sockets (the common systemd case) and the
/// abstract-namespace form (`@name`). Empty paths and every socket error are
/// silently ignored.
fn notify_to(socket_path: &str, message: &str) {
    if socket_path.is_empty() {
        return;
    }
    let Ok(socket) = UnixDatagram::unbound() else {
        return;
    };
    let result = if let Some(name) = socket_path.strip_prefix('@') {
        // Leading '@' selects the Linux abstract namespace.
        match SocketAddr::from_abstract_name(name.as_bytes()) {
            Ok(address) => socket.send_to_addr(message.as_bytes(), &address),
            Err(_bad_address) => return,
        }
    } else {
        socket.send_to(message.as_bytes(), socket_path)
    };
    if let Err(_unreachable) = result {}
}

#[cfg(test)]
mod tests {
    use super::{ServeActivity, heartbeat_from, notify_to};
    use std::os::unix::net::UnixDatagram;
    use std::time::{Duration, Instant};

    const IDLE_CEILING: Duration = Duration::from_secs(90);
    const LONGEST: Duration = Duration::from_secs(600);

    #[test]
    fn idle_loop_with_fresh_tick_is_alive() {
        let activity = ServeActivity::new();
        activity.tick();
        let now = Instant::now() + Duration::from_secs(10);
        assert!(activity.is_alive(now, Some(IDLE_CEILING), LONGEST));
    }

    #[test]
    fn idle_loop_with_stale_tick_is_wedged() {
        let activity = ServeActivity::new();
        activity.tick();
        let now = Instant::now() + IDLE_CEILING + Duration::from_secs(10);
        assert!(!activity.is_alive(now, Some(IDLE_CEILING), LONGEST));
    }

    #[test]
    fn idle_loop_without_accept_timeout_is_trusted() {
        // No idle ceiling: the loop blocks in accept() while idle, so a stale
        // tick is expected and must not stop the pets.
        let activity = ServeActivity::new();
        activity.tick();
        let now = Instant::now() + IDLE_CEILING + Duration::from_secs(3600);
        assert!(activity.is_alive(now, None, LONGEST));
    }

    #[test]
    fn long_running_request_within_ceiling_is_busy_not_wedged() {
        // The regression this module exists to prevent: a handler blocked in a
        // slow privileged tool far past the watchdog window is BUSY — the pets
        // must continue even though the loop has not ticked for minutes.
        let activity = ServeActivity::new();
        activity.request_started();
        let now = Instant::now() + Duration::from_secs(300);
        assert!(activity.is_alive(now, Some(IDLE_CEILING), LONGEST));
    }

    #[test]
    fn request_overstaying_the_ceiling_is_wedged() {
        let activity = ServeActivity::new();
        activity.request_started();
        let now = Instant::now() + LONGEST + Duration::from_secs(10);
        assert!(!activity.is_alive(now, Some(IDLE_CEILING), LONGEST));
    }

    #[test]
    fn finished_request_returns_to_idle_liveness() {
        let activity = ServeActivity::new();
        activity.request_started();
        activity.request_finished();
        let now = Instant::now() + Duration::from_secs(10);
        assert!(activity.is_alive(now, Some(IDLE_CEILING), LONGEST));
        let stale = Instant::now() + IDLE_CEILING + Duration::from_secs(10);
        assert!(!activity.is_alive(stale, Some(IDLE_CEILING), LONGEST));
    }

    #[test]
    fn no_watchdog_env_means_no_heartbeat() {
        assert_eq!(heartbeat_from(None, None, 42), None);
    }

    #[test]
    fn heartbeat_is_half_the_configured_timeout() {
        // WatchdogSec=60 -> WATCHDOG_USEC=60_000_000 -> pet every 30s.
        assert_eq!(
            heartbeat_from(Some("60000000"), None, 42),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn honors_watchdog_pid_when_it_matches() {
        assert_eq!(
            heartbeat_from(Some("2000000"), Some("42"), 42),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn ignores_watchdog_aimed_at_another_pid() {
        assert_eq!(heartbeat_from(Some("2000000"), Some("99"), 42), None);
    }

    #[test]
    fn rejects_zero_and_malformed_timeouts() {
        assert_eq!(heartbeat_from(Some("0"), None, 42), None);
        assert_eq!(heartbeat_from(Some("not-a-number"), None, 42), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn delivers_message_to_a_path_socket() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path)?;
        receiver.set_read_timeout(Some(Duration::from_secs(2)))?;

        let path_str = path.to_str().ok_or("non-utf8 socket path")?;
        notify_to(path_str, "READY=1");

        let mut buf = [0_u8; 32];
        let read = receiver.recv(&mut buf)?;
        assert_eq!(&buf[..read], b"READY=1");
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn empty_and_missing_socket_paths_are_silent_noops() {
        // Must not panic — advisory notifications never take down the daemon.
        notify_to("", "WATCHDOG=1");
        notify_to("/nonexistent/uds-daemon/notify.sock", "WATCHDOG=1");
    }
}
