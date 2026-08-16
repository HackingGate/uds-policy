//! The socket: binding it, giving it away, reclaiming it, and serving on it.

use crate::authorization::Authorizer;
use crate::handler::Handler;
use crate::http::{self, ServeOutcome};
use crate::service::Service;
use crate::watchdog;
use nix::sys::socket::{setsockopt, sockopt::ReceiveTimeout};
use nix::sys::time::{TimeVal, TimeValLike};
use nix::unistd::Group;
use std::fmt;
use std::fs::Permissions;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Everything about the socket and the request budget that a daemon might want
/// to differ on.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Where the socket lives.
    pub socket_path: PathBuf,
    /// The socket's file mode. `0o660` with a group is the shape that lets an
    /// unprivileged front-end talk to a root-owned daemon.
    pub socket_mode: u32,
    /// The group to give the socket to, if any.
    pub socket_group: Option<&'static str>,
    /// The `GET` path the framework answers with `{"ok":{"healthy":true}}`.
    pub health_path: &'static str,
    /// The `GET` path the framework answers with the service's name and
    /// version.
    pub version_path: &'static str,
    /// How long an accepted connection may go without sending the request it
    /// connected to send. See [`crate::ServeOutcome`] and `src/http.rs` for why
    /// this is set on the accepted stream and not inherited.
    pub request_read_timeout: Duration,
    /// The ceiling on the header block.
    pub max_header_bytes: usize,
    /// The ceiling on `content-length`.
    pub max_body_bytes: usize,
    /// The longest a single dispatch may run before the daemon is treated as
    /// wedged rather than busy. Set by "could a progressing operation
    /// plausibly still be inside it", not by the fast path.
    pub longest_legitimate_request: Duration,
}

impl ServerConfig {
    /// A configuration for `socket_path`, with defaults for everything else:
    /// mode `0o660`, no group, `/v1/status` and `/v1/version`, a 30-second
    /// request budget, 16 KiB of headers, 1 MiB of body, and a ten-minute
    /// ceiling on a single dispatch.
    #[must_use]
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            socket_mode: 0o660,
            socket_group: None,
            health_path: "/v1/status",
            version_path: "/v1/version",
            request_read_timeout: Duration::from_secs(30),
            max_header_bytes: 16_384,
            max_body_bytes: 1_048_576,
            longest_legitimate_request: Duration::from_secs(600),
        }
    }

    /// Give the socket to a group, so unprivileged members can connect.
    #[must_use]
    pub const fn with_socket_group(mut self, group: &'static str) -> Self {
        self.socket_group = Some(group);
        self
    }
}

/// Why a socket could not be taken.
#[derive(Debug)]
pub enum BindError {
    /// Something is listening on that path already, and answered.
    AlreadyActive(PathBuf),
    /// The path exists and is not a socket. Removing it would be the framework
    /// deleting a file it does not understand.
    NotASocket(PathBuf),
    /// The path exists, is a socket, and could not be shown to be stale. Not
    /// removed: an unverifiable socket that gets unlinked is a running daemon
    /// that gets silently disconnected from its clients.
    Unverifiable(PathBuf, std::io::Error),
    /// Everything else.
    Io(std::io::Error),
}

impl fmt::Display for BindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::AlreadyActive(ref path) => {
                write!(f, "a daemon is already serving {}", path.display())
            }
            Self::NotASocket(ref path) => write!(
                f,
                "{} exists and is not a socket, so it was left alone",
                path.display()
            ),
            Self::Unverifiable(ref path, ref error) => write!(
                f,
                "{} exists and could not be verified stale, so it was left alone: {error}",
                path.display()
            ),
            Self::Io(ref error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Self::Unverifiable(_, ref error) | Self::Io(ref error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BindError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// A bound socket, a service, and an authorizer.
///
/// Single-threaded on purpose: one connection is accepted, read, dispatched and
/// answered before the next is looked at. A privileged daemon's handlers touch
/// global host state, and a thread pool in front of them buys concurrency for a
/// workload that has none — a handful of front-ends polling — in exchange for
/// every mutation needing its own lock. The watchdog is what makes this safe to
/// keep: see [`crate::ServerConfig::longest_legitimate_request`].
#[derive(Debug)]
pub struct Server {
    listener: UnixListener,
    config: ServerConfig,
    handler: Handler,
}

impl Server {
    /// Take the socket and get ready to serve.
    ///
    /// A stale socket left behind by a crashed predecessor is reclaimed; a live
    /// one is not.
    pub fn bind(
        config: ServerConfig,
        service: Arc<dyn Service>,
        authorizer: Arc<dyn Authorizer>,
    ) -> Result<Self, BindError> {
        let socket_path = config.socket_path.clone();
        if socket_path.exists() {
            reclaim_stale_socket(&socket_path)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        if let Err(error) =
            std::fs::set_permissions(&socket_path, Permissions::from_mode(config.socket_mode))
        {
            // A socket nobody can open is worse than no socket: unlink it so
            // the next start is not blocked by the wreckage of this one.
            if let Err(_cleanup) = std::fs::remove_file(&socket_path) {}
            return Err(BindError::Io(error));
        }

        if let Some(group) = config.socket_group {
            give_socket_to_group(&socket_path, group, service.name());
        }

        let handler = Handler::new(service, authorizer, config.health_path, config.version_path);
        Ok(Self {
            listener,
            config,
            handler,
        })
    }

    /// Where the socket is.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// The request pipeline this server dispatches through.
    #[must_use]
    pub const fn handler(&self) -> &Handler {
        &self.handler
    }

    /// Bound the listener's blocking `accept()` with `SO_RCVTIMEO`, so the
    /// serve loop wakes periodically even when no client connects. On Linux a
    /// listening socket honors the receive timeout for `accept()`.
    ///
    /// [`Self::serve`] arms this itself when a watchdog is configured. It is
    /// public because the option is inherited by accepted sockets, which is a
    /// property worth being able to test from outside.
    pub fn set_accept_timeout(&self, timeout: Duration) -> std::io::Result<()> {
        let micros = i64::try_from(timeout.as_micros())
            .map_err(|error| std::io::Error::other(format!("timeout out of range: {error}")))?;
        setsockopt(
            &self.listener,
            ReceiveTimeout,
            &TimeVal::microseconds(micros),
        )
        .map_err(std::io::Error::from)
    }

    /// Accept and serve exactly one connection.
    ///
    /// The building block [`Self::serve`] loops over, and the one tests use.
    pub fn serve_next(&self) -> std::io::Result<ServeOutcome> {
        let (mut stream, _address) = self.listener.accept()?;
        Ok(http::serve_connection(
            &self.handler,
            &self.config,
            &mut stream,
        ))
    }

    /// Serve until the process ends.
    ///
    /// Signals `READY=1`, arms the watchdog heartbeat if systemd configured
    /// one, and then accepts forever. Returns only if `accept()` fails in a way
    /// that cannot be retried, which in practice does not happen — a single
    /// client failing is logged and the loop continues, because a privileged
    /// daemon that exits on a broken pipe is a management plane that a client
    /// can turn off.
    pub fn serve(self) -> std::io::Result<()> {
        // Signal readiness to systemd (Type=notify) now that the socket is
        // bound and about to accept. A no-op when not run under systemd.
        watchdog::notify_ready();

        // When a systemd WatchdogSec is configured, pets come from a dedicated
        // heartbeat thread, NOT this serve loop: a handler running a slow
        // privileged operation legitimately holds this thread past the watchdog
        // window, and petting from the loop would go silent — and get the
        // daemon SIGABRTed — exactly while it is working. The loop instead
        // records what it is doing in `activity`; the heartbeat thread pets
        // while that record shows normal idling or a request within its time
        // ceiling, and stops when a handler overstays or the loop stops turning
        // (genuinely wedged).
        let heartbeat = watchdog::heartbeat_interval();
        let activity = watchdog::ServeActivity::new();
        if let Some(interval) = heartbeat {
            // Bound `accept()` to the heartbeat interval so an idle loop still
            // turns (and stamps its tick) at least once per interval. If the
            // timeout cannot be armed the loop blocks in accept() while idle,
            // so idle-tick staleness is not evidence of a wedge: pass no idle
            // ceiling and trust the in-flight ceiling alone.
            let idle_tick_ceiling = match self.set_accept_timeout(interval) {
                Ok(()) => Some(interval * 3),
                Err(error) => {
                    eprintln!(
                        "{}: watchdog accept timeout unavailable: {error}",
                        self.service_name()
                    );
                    None
                }
            };
            watchdog::spawn_heartbeat(
                interval,
                idle_tick_ceiling,
                self.config.longest_legitimate_request,
                Arc::clone(&activity),
            );
        }

        loop {
            match self.listener.accept() {
                Ok((mut stream, _address)) => {
                    activity.request_started();
                    let outcome = http::serve_connection(&self.handler, &self.config, &mut stream);
                    activity.request_finished();
                    // A single client failing — early disconnect, broken pipe,
                    // malformed request — must not take down the privileged
                    // daemon. Log and keep serving. A connect-and-drop
                    // reachability probe is not a failure at all and is not
                    // logged: it used to plant two broken-pipe lines on every
                    // front-end launch.
                    if let ServeOutcome::Failed { context, error } = outcome {
                        let name = self.service_name();
                        match context {
                            Some(request) => {
                                eprintln!("{name}: request failed: {request}: {error}");
                            }
                            None => eprintln!("{name}: request failed: {error}"),
                        }
                    }
                }
                // The accept timeout elapsed with no client: an expected idle
                // wakeup, not an error.
                Err(error)
                    if heartbeat.is_some()
                        && matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(error) => {
                    eprintln!("{}: accept failed: {error}", self.service_name());
                }
            }
            // Stamp each loop turn so the heartbeat thread can tell an idle
            // loop (turning through accept timeouts) from a stopped one.
            activity.tick();
        }
    }

    fn service_name(&self) -> &'static str {
        self.handler.service().name()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Err(_already_gone) = std::fs::remove_file(&self.config.socket_path) {}
    }
}

/// Remove a socket only once it has been shown that nothing is behind it.
///
/// The test is a `connect(2)` — the same connect-and-drop probe a client uses
/// to ask whether the daemon is there, which is why that probe has to be
/// answered with silence: a daemon that wrote bytes back would be talking to
/// its own successor's startup check.
///
/// `ECONNREFUSED` on an existing socket file means the listener is gone and the
/// inode outlived it, which is exactly what a crash or a `SIGKILL` leaves
/// behind. Anything else is left alone.
fn reclaim_stale_socket(socket_path: &Path) -> Result<(), BindError> {
    let metadata = std::fs::symlink_metadata(socket_path)?;
    if !metadata.file_type().is_socket() {
        return Err(BindError::NotASocket(socket_path.to_path_buf()));
    }

    match UnixStream::connect(socket_path) {
        Ok(_live) => Err(BindError::AlreadyActive(socket_path.to_path_buf())),
        Err(error) if error.kind() == ErrorKind::ConnectionRefused => {
            std::fs::remove_file(socket_path).map_err(BindError::Io)
        }
        // Someone unlinked it between the metadata read and the connect. The
        // path is free, which is what was wanted.
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(BindError::Unverifiable(socket_path.to_path_buf(), error)),
    }
}

/// Align the socket's group with the one unprivileged clients belong to.
///
/// A daemon running as root would otherwise leave the socket `root:root` mode
/// `0660`, which no front-end can open. Best-effort by design — an absent group
/// is silent, because a host without the package's group still serves root
/// callers fine, and tests bind throwaway sockets.
///
/// The other two outcomes are not silent. Both end with a socket the front-ends
/// cannot open, and a management plane that is simply absent with nothing in
/// the journal is the failure this whole crate keeps paying for.
fn give_socket_to_group(socket_path: &Path, group: &str, service: &str) {
    match lookup_group_gid(group) {
        Ok(Some(gid)) => {
            if let Err(error) = std::os::unix::fs::chown(socket_path, None, Some(gid)) {
                eprintln!(
                    "{service}: could not give {} to the {group} group, \
                     so unprivileged clients cannot connect: {error}",
                    socket_path.display()
                );
            }
        }
        Ok(None) => {}
        Err(error) => eprintln!(
            "{service}: could not resolve the {group} group, so the socket keeps its \
             own group and unprivileged clients cannot connect: {error}"
        ),
    }
}

/// Resolve the numeric GID of a group, through NSS.
///
/// Through NSS rather than by parsing `/etc/group`: the file is only the `files`
/// backend, so a host serving its accounts from `systemd-userdb` or a directory
/// service gets a wrong answer with no error either way.
///
/// The stakes are the socket's group ownership, which is what lets an
/// unprivileged front-end open it. A silently wrong answer here is a front-end
/// that silently cannot connect.
///
/// `Ok(None)` is an absent group — ordinary on a host without the package.
/// `Err` is a lookup that could not be completed, which is a different thing and
/// is said out loud.
fn lookup_group_gid(name: &str) -> std::io::Result<Option<u32>> {
    Group::from_name(name)
        .map(|group| group.map(|found| found.gid.as_raw()))
        .map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::{BindError, ServerConfig, lookup_group_gid, reclaim_stale_socket};
    use std::os::unix::net::UnixListener;

    #[test]
    fn the_default_config_is_the_shape_a_root_daemon_needs() {
        let config = ServerConfig::new("/run/example/api.sock").with_socket_group("example");
        assert_eq!(config.socket_mode, 0o660);
        assert_eq!(config.socket_group, Some("example"));
        assert_eq!(config.health_path, "/v1/status");
    }

    /// The root group exists on every host this daemon runs on, and it is the
    /// one name that can be checked without knowing anything about the machine.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot reach NSS")]
    fn a_group_that_exists_resolves_and_one_that_does_not_is_absent_rather_than_an_error()
    -> Result<(), Box<dyn std::error::Error>> {
        // Either `root` or `wheel` owns gid 0 depending on the distribution;
        // asking for a name that certainly does not exist is the portable half.
        let absent = lookup_group_gid("uds-daemon-no-such-group-9d1f")?;
        assert_eq!(absent, None, "a nonexistent group resolved to something");
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn a_path_that_is_not_a_socket_is_left_alone() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("not-a-socket");
        std::fs::write(&path, b"data someone cares about")?;

        let error =
            reclaim_stale_socket(&path).expect_err("a regular file was accepted as a stale socket");
        assert!(matches!(error, BindError::NotASocket(_)), "{error}");
        assert!(path.exists(), "the framework deleted a file it did not own");
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn a_socket_with_a_live_listener_is_not_reclaimed() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("live.sock");
        let _listener = UnixListener::bind(&path)?;

        let error =
            reclaim_stale_socket(&path).expect_err("a live socket was reclaimed from under it");
        assert!(matches!(error, BindError::AlreadyActive(_)), "{error}");
        assert!(path.exists());
        Ok(())
    }
}
