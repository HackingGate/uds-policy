//! Minimal `sd_notify(3)` client for the systemd software watchdog, and the
//! busy-vs-wedged distinction it needs to be safe.
//!
//! The unit runs `Type=notify` with `WatchdogSec=<N>`, the daemon signals
//! [`notify_ready`] once its socket is bound, and a dedicated heartbeat thread
//! pets the watchdog (`WATCHDOG=1`) every `WatchdogSec/2`.
//!
//! The heartbeat must distinguish **busy** from **wedged**. A privileged call
//! can legitimately outlive the watchdog window — a slow host tool on a loaded
//! board takes minutes, not seconds — so pets cannot come from the accept loop
//! itself: a loop blocked inside a healthy long call goes silent exactly when
//! it is doing the most work, and systemd `SIGABRT`s the daemon mid-operation.
//! Instead the accept loop records what it is doing in a [`ServeActivity`], and
//! the heartbeat thread pets while that record says the loop is either idling
//! normally or making bounded progress.
//!
//! ## Why a call declares its shape
//!
//! There are two honest shapes, and one ceiling cannot cover both:
//!
//! * [`InFlight::Bounded`] — a call expected to return. Wedged once it outstays
//!   [`Liveness::longest_bounded_call`].
//! * [`InFlight::Streaming`] — a call that holds the connection open *by
//!   design*, the way a subscription does. Its total duration says nothing
//!   about its health, so any ceiling on it reads a working subscription as a
//!   permanent wedge. It is judged by [`ServeActivity::progressed`] instead,
//!   and only if the daemon opted into a ceiling at all.
//!
//! This is why [`Liveness::longest_silent_stream`] defaults to `None`. The
//! failure mode of guessing wrong in that direction is killing a healthy
//! subscription every time the thing it watches is quiet, which is precisely
//! when a subscription is most obviously working.
//!
//! This is a dependency-free, `unsafe`-free implementation of the protocol (a
//! datagram `key=value` message to `$NOTIFY_SOCKET`); it is a silent no-op when
//! the daemon is not launched under systemd (the env vars are unset).

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Tell systemd the daemon has finished startup and is serving (`Type=notify`).
///
/// Called once, after the socket is bound and before the accept loop starts.
pub fn notify_ready() {
    notify("READY=1");
}

/// Pet the watchdog: report that the daemon is still making progress.
fn pet() {
    notify("WATCHDOG=1");
}

/// The shape of a call that is holding the serve thread right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InFlight {
    /// A call expected to return. Judged by how long it has been running.
    Bounded,
    /// A call that holds the connection open by design — a subscription, an
    /// event stream. Judged by progress, never by total duration.
    Streaming,
}

/// When the accept loop counts as wedged rather than busy.
///
/// Every ceiling here answers "could a *progressing* daemon plausibly still be
/// in this state?", not "how fast is the fast path?".
#[derive(Debug, Clone, Copy)]
pub struct Liveness {
    /// How stale the loop's tick may go while no call is in flight.
    ///
    /// `None` means idle ticks are not expected — the daemon did not arm an
    /// accept timeout, so an idle loop blocks in `accept()` and a stale tick is
    /// the normal condition rather than evidence of a wedge. Pair a `Some` here
    /// with [`crate::Socket::set_accept_timeout`]; without the timeout the loop
    /// never turns while idle and this ceiling would kill a healthy daemon.
    pub idle_tick_ceiling: Option<Duration>,
    /// The longest a [`InFlight::Bounded`] call may run before the daemon is
    /// treated as wedged.
    pub longest_bounded_call: Duration,
    /// How long a [`InFlight::Streaming`] call may go without stamping
    /// [`ServeActivity::progressed`] before the daemon is treated as wedged.
    ///
    /// `None` — the default — trusts an open stream for as long as it is open.
    /// A daemon sets this only if its streams have a heartbeat of their own to
    /// stamp; without one, a stream that is legitimately quiet is
    /// indistinguishable from a wedged one, and killing it is the worse error.
    pub longest_silent_stream: Option<Duration>,
}

impl Liveness {
    /// Ten minutes for a bounded call, no idle ceiling, and an open stream
    /// trusted for as long as it is open.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            idle_tick_ceiling: None,
            longest_bounded_call: Duration::from_secs(600),
            longest_silent_stream: None,
        }
    }

    /// Expect the accept loop to turn at least this often while idle.
    ///
    /// Only correct alongside [`crate::Socket::set_accept_timeout`]; see the
    /// field.
    #[must_use]
    pub const fn with_idle_tick_ceiling(mut self, ceiling: Duration) -> Self {
        self.idle_tick_ceiling = Some(ceiling);
        self
    }

    /// Set the ceiling on a bounded call.
    #[must_use]
    pub const fn with_longest_bounded_call(mut self, ceiling: Duration) -> Self {
        self.longest_bounded_call = ceiling;
        self
    }

    /// Require an open stream to stamp progress at least this often.
    #[must_use]
    pub const fn with_silent_stream_ceiling(mut self, ceiling: Duration) -> Self {
        self.longest_silent_stream = Some(ceiling);
        self
    }
}

impl Default for Liveness {
    fn default() -> Self {
        Self::new()
    }
}

/// What the accept loop is doing right now, as seen by the heartbeat thread.
///
/// Shared: the loop stamps it, the heartbeat thread reads it. Every method is
/// `&self` so it can live behind the `Arc` [`ServeActivity::new`] returns.
#[derive(Debug)]
pub struct ServeActivity {
    state: Mutex<ActivityState>,
}

#[derive(Debug)]
struct ActivityState {
    last_tick: Instant,
    in_flight: Option<InFlightState>,
}

#[derive(Debug)]
struct InFlightState {
    kind: InFlight,
    started_at: Instant,
    last_progress: Instant,
}

impl ServeActivity {
    /// A record of a loop that has just started and is idle.
    #[must_use]
    pub fn new() -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            state: Mutex::new(ActivityState {
                last_tick: now,
                in_flight: None,
            }),
        })
    }

    /// The accept loop completed a turn (served a call or idled through an
    /// accept timeout).
    pub fn tick(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.last_tick = Instant::now();
        }
    }

    /// A call is about to run on the serve thread.
    pub fn call_started(&self, kind: InFlight) {
        if let Ok(mut state) = self.state.lock() {
            let now = Instant::now();
            state.in_flight = Some(InFlightState {
                kind,
                started_at: now,
                last_progress: now,
            });
        }
    }

    /// A streaming call made progress — it sent a reply, or ran its own
    /// keepalive turn with nothing to send.
    ///
    /// A no-op when nothing is in flight, so a daemon can stamp it
    /// unconditionally from a send path.
    pub fn progressed(&self) {
        if let Ok(mut state) = self.state.lock()
            && let Some(ref mut in_flight) = state.in_flight
        {
            in_flight.last_progress = Instant::now();
        }
    }

    /// The call returned (successfully or not).
    pub fn call_finished(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.in_flight = None;
            state.last_tick = Instant::now();
        }
    }

    /// Whether the accept loop counts as alive at `now`.
    ///
    /// Public so a daemon that drives its own heartbeat — or wants to assert on
    /// the policy in a test — can ask the same question
    /// [`spawn_heartbeat`] asks.
    #[must_use]
    pub fn is_alive(&self, now: Instant, liveness: &Liveness) -> bool {
        let Ok(state) = self.state.lock() else {
            // A poisoned lock means the serve thread panicked mid-update;
            // stop petting and let systemd restart the daemon.
            return false;
        };
        let Some(ref in_flight) = state.in_flight else {
            // Idle: an armed accept timeout makes the loop turn (and tick) at
            // least once per heartbeat interval, so a stale tick means the loop
            // stopped turning outside any call. With no timeout armed, an idle
            // loop blocks in accept() and is trusted unconditionally.
            return liveness
                .idle_tick_ceiling
                .is_none_or(|ceiling| now.saturating_duration_since(state.last_tick) <= ceiling);
        };
        match in_flight.kind {
            // Busy: a progressing privileged operation may legitimately hold
            // the serve thread for minutes; only an overstayed one is wedged.
            InFlight::Bounded => {
                now.saturating_duration_since(in_flight.started_at) <= liveness.longest_bounded_call
            }
            // Open by design: total duration says nothing, so only a daemon
            // that opted into a progress ceiling gets one judged at all.
            InFlight::Streaming => liveness.longest_silent_stream.is_none_or(|ceiling| {
                now.saturating_duration_since(in_flight.last_progress) <= ceiling
            }),
        }
    }
}

/// Spawn the dedicated heartbeat thread: pets the watchdog every `interval` for
/// as long as `activity` reports the accept loop alive. Detached — it runs for
/// the life of the process.
pub fn spawn_heartbeat(interval: Duration, liveness: Liveness, activity: Arc<ServeActivity>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(interval);
            if activity.is_alive(Instant::now(), &liveness) {
                pet();
            }
        }
    });
}

/// The interval at which the daemon should pet the watchdog, or `None` when no
/// watchdog is configured (env var unset, malformed, or aimed at a different
/// pid). systemd exposes the full timeout in `WATCHDOG_USEC`; we pet at half
/// that, the interval `sd_notify`'s own documentation recommends.
#[must_use]
pub fn heartbeat_interval() -> Option<Duration> {
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
    use super::{InFlight, Liveness, ServeActivity, heartbeat_from, notify_to};
    use std::os::unix::net::UnixDatagram;
    use std::time::{Duration, Instant};

    const IDLE_CEILING: Duration = Duration::from_secs(90);

    /// The shape a daemon under a watchdog with an armed accept timeout uses.
    fn watched() -> Liveness {
        Liveness::new().with_idle_tick_ceiling(IDLE_CEILING)
    }

    #[test]
    fn idle_loop_with_fresh_tick_is_alive() {
        let activity = ServeActivity::new();
        activity.tick();
        let now = Instant::now() + Duration::from_secs(10);
        assert!(activity.is_alive(now, &watched()));
    }

    #[test]
    fn idle_loop_with_stale_tick_is_wedged() {
        let activity = ServeActivity::new();
        activity.tick();
        let now = Instant::now() + IDLE_CEILING + Duration::from_secs(10);
        assert!(!activity.is_alive(now, &watched()));
    }

    #[test]
    fn idle_loop_without_accept_timeout_is_trusted() {
        // No idle ceiling: the loop blocks in accept() while idle, so a stale
        // tick is expected and must not stop the pets.
        let activity = ServeActivity::new();
        activity.tick();
        let now = Instant::now() + IDLE_CEILING + Duration::from_secs(3600);
        assert!(activity.is_alive(now, &Liveness::new()));
    }

    #[test]
    fn long_running_bounded_call_within_ceiling_is_busy_not_wedged() {
        // The regression this module exists to prevent: a handler blocked in a
        // slow privileged tool far past the watchdog window is BUSY — the pets
        // must continue even though the loop has not ticked for minutes.
        let activity = ServeActivity::new();
        activity.call_started(InFlight::Bounded);
        let now = Instant::now() + Duration::from_secs(300);
        assert!(activity.is_alive(now, &watched()));
    }

    #[test]
    fn bounded_call_overstaying_the_ceiling_is_wedged() {
        let activity = ServeActivity::new();
        activity.call_started(InFlight::Bounded);
        let now = Instant::now() + Liveness::new().longest_bounded_call + Duration::from_secs(10);
        assert!(!activity.is_alive(now, &watched()));
    }

    /// A subscription holds the connection open by design. Judging it by the
    /// bounded ceiling would `SIGABRT` the daemon for the crime of having a
    /// working event stream — and it would do so on the *quietest* hosts.
    #[test]
    fn an_open_stream_is_not_a_wedge() {
        let activity = ServeActivity::new();
        activity.call_started(InFlight::Streaming);
        let a_whole_day = Instant::now() + Duration::from_secs(86_400);
        assert!(activity.is_alive(a_whole_day, &watched()));
    }

    /// A daemon whose streams do have a keepalive of their own can opt into a
    /// progress ceiling, and then a silent stream is a wedge.
    #[test]
    fn a_stream_that_stops_progressing_is_wedged_once_a_ceiling_is_set() {
        let liveness = watched().with_silent_stream_ceiling(Duration::from_secs(60));
        let activity = ServeActivity::new();
        activity.call_started(InFlight::Streaming);

        let within = Instant::now() + Duration::from_secs(30);
        assert!(activity.is_alive(within, &liveness));

        let past = Instant::now() + Duration::from_secs(90);
        assert!(!activity.is_alive(past, &liveness));
    }

    #[test]
    fn stamping_progress_keeps_a_watched_stream_alive() {
        let liveness = watched().with_silent_stream_ceiling(Duration::from_secs(60));
        let activity = ServeActivity::new();
        activity.call_started(InFlight::Streaming);
        activity.progressed();
        let now = Instant::now() + Duration::from_secs(30);
        assert!(activity.is_alive(now, &liveness));
    }

    /// Progress on a bounded call must not extend its ceiling: a call that
    /// could reset its own deadline could never be wedged.
    #[test]
    fn progress_does_not_extend_a_bounded_call() {
        let activity = ServeActivity::new();
        activity.call_started(InFlight::Bounded);
        activity.progressed();
        let now = Instant::now() + Liveness::new().longest_bounded_call + Duration::from_secs(10);
        assert!(!activity.is_alive(now, &watched()));
    }

    #[test]
    fn finished_call_returns_to_idle_liveness() {
        let activity = ServeActivity::new();
        activity.call_started(InFlight::Bounded);
        activity.call_finished();
        let now = Instant::now() + Duration::from_secs(10);
        assert!(activity.is_alive(now, &watched()));
        let stale = Instant::now() + IDLE_CEILING + Duration::from_secs(10);
        assert!(!activity.is_alive(stale, &watched()));
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
        notify_to("/nonexistent/uds-policy/notify.sock", "WATCHDOG=1");
    }
}
