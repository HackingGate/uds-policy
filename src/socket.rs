//! The socket: binding it, giving it away, reclaiming it, and handing an
//! accepted connection over with the kernel's answer about who is on it.
//!
//! There is no serve loop here and there will not be one. A serve loop has to
//! pick a wire format, and picking one forecloses every consumer that picked
//! differently — which is the whole reason this crate was unbundled. What is
//! left is the part of "own a Unix socket" that is the same whatever is spoken
//! over it, and every line of it is here because it was once absent.

use crate::caller::Caller;
use nix::sys::socket::{setsockopt, sockopt::ReceiveTimeout};
use nix::sys::time::{TimeVal, TimeValLike};
use nix::unistd::Group;
use std::fmt;
use std::fs::Permissions;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Everything about the socket that a daemon might want to differ on.
#[derive(Debug, Clone)]
pub struct SocketConfig {
    /// The daemon's name. Prefixes the log lines this module writes, so a
    /// socket that could not be handed to its group says whose socket it was.
    pub daemon: &'static str,
    /// Where the socket lives.
    pub socket_path: PathBuf,
    /// The socket's file mode. `0o660` with a group is the shape that lets an
    /// unprivileged front-end talk to a root-owned daemon.
    pub socket_mode: u32,
    /// The group to give the socket to, if any.
    pub socket_group: Option<&'static str>,
    /// The read deadline put on each accepted stream by [`Socket::accept`].
    ///
    /// Set explicitly, always, because Linux **inherits** the listener's
    /// `SO_RCVTIMEO` onto accepted sockets — and the listener carries one
    /// whenever [`Socket::set_accept_timeout`] armed it so an idle loop still
    /// turns for the watchdog. Without an explicit deadline the request budget
    /// is silently whatever the heartbeat interval happens to be, a number
    /// chosen for something else entirely.
    ///
    /// `None` clears it rather than leaving the inherited value, so the
    /// accident cannot happen quietly. It is still a decision worth making
    /// deliberately: a daemon that serves one connection at a time and clears
    /// the deadline can be held hostage by a client that connects and never
    /// writes.
    pub request_read_timeout: Option<Duration>,
}

impl SocketConfig {
    /// A configuration for `socket_path`, with defaults for everything else:
    /// mode `0o660`, no group, and a 30-second read deadline on each accepted
    /// connection.
    #[must_use]
    pub fn new(daemon: &'static str, socket_path: impl AsRef<Path>) -> Self {
        Self {
            daemon,
            socket_path: socket_path.as_ref().to_path_buf(),
            socket_mode: 0o660,
            socket_group: None,
            request_read_timeout: Some(Duration::from_secs(30)),
        }
    }

    /// Give the socket to a group, so unprivileged members can connect.
    #[must_use]
    pub const fn with_socket_group(mut self, group: &'static str) -> Self {
        self.socket_group = Some(group);
        self
    }

    /// Use a different file mode.
    #[must_use]
    pub const fn with_socket_mode(mut self, mode: u32) -> Self {
        self.socket_mode = mode;
        self
    }

    /// Change the read deadline put on each accepted connection. `None` clears
    /// it; see the field for why that is a decision rather than a default.
    #[must_use]
    pub const fn with_request_read_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.request_read_timeout = timeout;
        self
    }
}

/// Why a socket could not be taken.
#[derive(Debug)]
pub enum BindError {
    /// Something is listening on that path already, and answered.
    AlreadyActive(PathBuf),
    /// The path exists and is not a socket. Removing it would be this crate
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

/// A bound Unix socket, owned for the life of the daemon.
///
/// Unlinks its path on drop, so a clean shutdown does not leave a stale inode
/// behind for the next start to have to reason about.
#[derive(Debug)]
pub struct Socket {
    listener: UnixListener,
    config: SocketConfig,
}

impl Socket {
    /// Take the socket: reclaim a stale one, bind, set the mode, hand it to the
    /// group.
    ///
    /// A stale socket left behind by a crashed predecessor is reclaimed; a live
    /// one is not.
    pub fn bind(config: SocketConfig) -> Result<Self, BindError> {
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
            give_socket_to_group(&socket_path, group, config.daemon);
        }

        Ok(Self { listener, config })
    }

    /// Where the socket is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.config.socket_path
    }

    /// The configuration this socket was bound with.
    #[must_use]
    pub const fn config(&self) -> &SocketConfig {
        &self.config
    }

    /// The underlying listener, for a daemon that needs something this crate
    /// does not offer.
    ///
    /// Accepting through it skips both the read deadline and the peer
    /// credentials — see [`Self::accept`], which is what you want.
    #[must_use]
    pub const fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Accept one connection, and answer who is on it.
    ///
    /// The [`Caller`] is read from the accepted socket **before any byte of the
    /// request is**, which is the property the whole crate is built around:
    /// nothing a request carries can establish who sent it, so the kernel is
    /// asked first and a malformed or truncated request is still attributable.
    /// Returning the two together is what makes that ordering impossible to get
    /// wrong at a call site.
    ///
    /// The stream also gets [`SocketConfig::request_read_timeout`] applied
    /// here, rather than inherited from the listener. A failure to apply it is
    /// reported as an error rather than swallowed: a connection whose deadline
    /// is silently the watchdog's is the bug that field exists to prevent.
    pub fn accept(&self) -> std::io::Result<(UnixStream, Caller)> {
        let (stream, _address) = self.listener.accept()?;
        // Before the first request byte. Reading it after would mean a client
        // that disconnects mid-request becomes an unattributable audit line.
        let caller = Caller::of_socket(&stream);
        stream.set_read_timeout(self.config.request_read_timeout)?;
        Ok((stream, caller))
    }

    /// Bound the listener's blocking `accept()` with `SO_RCVTIMEO`, so a serve
    /// loop wakes periodically even when no client connects.
    ///
    /// On Linux a listening socket honors the receive timeout for `accept()`.
    /// A daemon that wants the watchdog's idle-tick check
    /// ([`Liveness::idle_tick_ceiling`]) needs this armed, or the loop never
    /// turns while idle and the check kills a healthy daemon.
    ///
    /// The option is inherited by accepted sockets, which is exactly why
    /// [`Self::accept`] overwrites it per connection.
    ///
    /// [`Liveness::idle_tick_ceiling`]: crate::watchdog::Liveness::idle_tick_ceiling
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
}

impl Drop for Socket {
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
/// `0660`, which no front-end can open. Best-effort by design: none of the three
/// outcomes is fatal, because a daemon that refused to start over its socket's
/// group would be trading a reachable-by-root management plane for none at all.
///
/// None of the three is *silent* either. This is only reached when a daemon
/// explicitly asked for a group, so every outcome other than success ends with a
/// socket the front-ends cannot open — and a management plane that is simply
/// absent with nothing in the journal is the failure this whole crate keeps
/// paying for. An absent group used to be swallowed here on the reasoning that a
/// host without the package's group still serves root callers fine; that is
/// true and it is not the operator's question, which is why their front-end
/// cannot connect.
fn give_socket_to_group(socket_path: &Path, group: &str, daemon: &str) {
    match lookup_group_gid(group) {
        Ok(Some(gid)) => {
            if let Err(error) = std::os::unix::fs::chown(socket_path, None, Some(gid)) {
                eprintln!(
                    "{daemon}: could not give {} to the {group} group, \
                     so unprivileged clients cannot connect: {error}",
                    socket_path.display()
                );
            }
        }
        // The group resolved cleanly to "no such group". Ordinary on a host
        // where the package's group was never created, and precisely the case
        // an operator spends an afternoon on if nothing says so.
        Ok(None) => eprintln!(
            "{daemon}: there is no {group} group on this host, so {} keeps its own \
             group and only root can connect",
            socket_path.display()
        ),
        Err(error) => eprintln!(
            "{daemon}: could not resolve the {group} group, so the socket keeps its \
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
    use super::{BindError, SocketConfig, lookup_group_gid, reclaim_stale_socket};
    use std::os::unix::net::UnixListener;
    use std::time::Duration;

    #[test]
    fn the_default_config_is_the_shape_a_root_daemon_needs() {
        let config =
            SocketConfig::new("exampled", "/run/example/api.sock").with_socket_group("example");
        assert_eq!(config.socket_mode, 0o660);
        assert_eq!(config.socket_group, Some("example"));
        // Explicit rather than inherited: see the field.
        assert_eq!(config.request_read_timeout, Some(Duration::from_secs(30)));
    }

    /// The root group exists on every host this daemon runs on, and it is the
    /// one name that can be checked without knowing anything about the machine.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot reach NSS")]
    fn a_group_that_exists_resolves_and_one_that_does_not_is_absent_rather_than_an_error()
    -> Result<(), Box<dyn std::error::Error>> {
        // Either `root` or `wheel` owns gid 0 depending on the distribution;
        // asking for a name that certainly does not exist is the portable half.
        let absent = lookup_group_gid("uds-policy-no-such-group-9d1f")?;
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
        assert!(path.exists(), "a file this crate does not own was deleted");
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
