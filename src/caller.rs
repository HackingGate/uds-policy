//! Who asked.
//!
//! The audit trail ([`crate::Handler`]) records what the daemon did. Naming
//! the operation, the target and the result is not enough when one socket
//! serves several front-ends under several accounts: the journal then says
//! that *something* reconfigured the host, and cannot say which of them.
//!
//! ## Why the kernel's answer and not the request's
//!
//! Nothing in an HTTP request can establish who sent it: a header is a claim by
//! the party being identified. `SO_PEERCRED` is filled in by the kernel from
//! the peer's credentials at `connect(2)` time, so the peer cannot forge it and
//! cannot change it afterwards by changing uid or `exec`ing. The framework
//! reads it once per connection, *before* the first request byte is parsed, so
//! a malformed or truncated request is still attributable.
//!
//! This crate denies `unsafe_code` and `UnixStream::peer_cred` is still
//! nightly-only, so the call goes through `nix`.
//!
//! ## Why an unreadable caller says so
//!
//! A caller that cannot be read is recorded as [`Caller::Unreadable`], with the
//! reason, rather than omitted. An audit line that silently drops `by=` when
//! the lookup fails reads exactly like one written before this existed — and a
//! trail whose gaps are invisible is the failure mode this module is a response
//! to.

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{Uid, User};
use std::collections::HashMap;
use std::fmt;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};

/// How much of an account name reaches the journal.
///
/// A name comes from NSS, which on a directory-joined host is not under this
/// machine's control, so it is bounded and stripped of newlines for the same
/// reason a request target is: a value must not be able to flood a small log
/// or forge an extra audit line.
pub const MAX_CALLER_NAME_CHARS: usize = 64;

/// The party a dispatched call is attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// The peer of a connected socket, as the kernel reports it.
    Peer {
        /// The peer's process id at `connect(2)` time.
        pid: i32,
        /// The peer's effective user id at `connect(2)` time.
        uid: u32,
        /// The peer's effective group id at `connect(2)` time.
        gid: u32,
    },
    /// A socket whose peer could not be read, and why.
    Unreadable(String),
    /// No socket at all: an in-process entry point or a test dispatching
    /// directly against a service.
    InProcess,
}

impl Caller {
    /// Read the peer of an accepted connection.
    ///
    /// Never fails: a daemon that refused to serve a request because it could
    /// not name the requester would trade an incomplete journal for an outage.
    /// The failure is carried into the line instead. A [`crate::PeerGate`] can
    /// still make it fatal — that is a policy decision, and it is made in the
    /// authorizer where policy lives.
    #[must_use]
    pub fn of_socket(stream: &UnixStream) -> Self {
        match getsockopt(stream, PeerCredentials) {
            Ok(peer) => Self::Peer {
                pid: peer.pid(),
                uid: peer.uid(),
                gid: peer.gid(),
            },
            Err(error) => Self::Unreadable(error.to_string()),
        }
    }

    /// The peer's user id, when there is one.
    #[must_use]
    pub const fn uid(&self) -> Option<u32> {
        match self {
            Self::Peer { uid, .. } => Some(*uid),
            _ => None,
        }
    }

    /// The peer's group id, when there is one.
    #[must_use]
    pub const fn gid(&self) -> Option<u32> {
        match self {
            Self::Peer { gid, .. } => Some(*gid),
            _ => None,
        }
    }

    /// The peer's process id, when there is one.
    #[must_use]
    pub const fn pid(&self) -> Option<i32> {
        match self {
            Self::Peer { pid, .. } => Some(*pid),
            _ => None,
        }
    }

    /// The account name behind the peer's uid, through NSS, memoised.
    ///
    /// `None` for a caller with no uid, and for a uid no account owns — which
    /// is an ordinary thing for a live process to hold.
    #[must_use]
    pub fn account_name(&self) -> Option<String> {
        match *self {
            Self::Peer { uid, .. } => name_for_uid(uid),
            _ => None,
        }
    }
}

impl fmt::Display for Caller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Peer { pid, uid, gid } => match name_for_uid(uid) {
                Some(name) => write!(f, "{name}(uid {uid} gid {gid} pid {pid})"),
                // No account owns the uid — a live process can hold one NSS no
                // longer resolves. The numbers are still the answer.
                None => write!(f, "uid {uid} gid {gid} pid {pid}"),
            },
            Self::Unreadable(ref reason) => write!(f, "unreadable ({reason})"),
            Self::InProcess => write!(f, "in-process"),
        }
    }
}

/// The account name for a uid, through NSS, remembered.
///
/// Memoised because the daemon serves one request at a time and NSS can reach a
/// directory service: without this, every audited write would put a blocking
/// lookup in front of the management plane, for an answer that changes about as
/// often as the package's own system accounts do.
///
/// A *failed* lookup is deliberately not cached. Absence is a real answer and
/// is remembered; an unreachable backend is a transient condition, and caching
/// it would make one bad moment permanent for the life of the process.
fn name_for_uid(uid: u32) -> Option<String> {
    static CACHE: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    // Two scoped locks rather than one held across the middle: NSS is the part
    // that can block, and holding the map's mutex through it would make one
    // slow lookup everyone's problem. Two callers racing to resolve the same
    // uid simply both resolve it, and agree on the answer.
    {
        let names = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cached) = names.get(&uid) {
            return cached.clone();
        }
    }

    let looked_up = User::from_uid(Uid::from_raw(uid))
        .ok()
        .map(|user| user.map(|found| sanitize(&found.name)));

    // `and_then` keeps the two `None`s apart: the outer one is a lookup that
    // failed and is not remembered, the inner one is a uid nothing owns and is.
    looked_up.and_then(|resolved| {
        let mut names = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        names.insert(uid, resolved.clone());
        drop(names);
        resolved
    })
}

fn sanitize(name: &str) -> String {
    name.chars()
        .take(MAX_CALLER_NAME_CHARS)
        .collect::<String>()
        .replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::{Caller, sanitize};

    /// The line must name the caller in the shape an operator greps for.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot reach NSS")]
    fn a_peer_is_rendered_with_its_numbers() {
        let caller = Caller::Peer {
            pid: 1421,
            uid: 4_294_967_294,
            gid: 4_294_967_293,
        };
        // A uid no account owns still answers the question, with numbers.
        assert_eq!(caller.to_string(), "uid 4294967294 gid 4294967293 pid 1421");
    }

    /// Reading this process's own socket must produce a real attribution, not
    /// the unreadable fallback: if the happy path silently degraded, every
    /// audit line would say `unreadable` and look like a working feature.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn an_accepted_socket_names_this_process() -> Result<(), Box<dyn std::error::Error>> {
        let (here, _there) = std::os::unix::net::UnixStream::pair()?;
        let caller = Caller::of_socket(&here);
        let Caller::Peer { pid, uid, gid } = caller else {
            return Err(std::io::Error::other(format!(
                "a connected socket was not attributed: {caller:?}"
            ))
            .into());
        };
        if pid != i32::try_from(std::process::id())? {
            return Err(std::io::Error::other(format!(
                "attributed to pid {pid}, but this process is {}",
                std::process::id()
            ))
            .into());
        }
        // The accessors agree with the variant they read.
        let read_back = Caller::Peer { pid, uid, gid };
        if read_back.uid() != Some(uid) || read_back.gid() != Some(gid) {
            return Err(std::io::Error::other("uid/gid accessors disagree").into());
        }
        // And it renders with a name, since uid 0 has an account everywhere.
        let rendered = Caller::Peer {
            pid,
            uid: 0,
            gid: 0,
        }
        .to_string();
        if !rendered.starts_with("root(uid 0 gid 0 pid ") {
            return Err(std::io::Error::other(format!(
                "uid 0 did not resolve to root: {rendered}"
            ))
            .into());
        }
        Ok(())
    }

    /// The framework never claims to know a caller it could not read.
    #[test]
    fn a_callerless_dispatch_has_no_numbers() {
        assert_eq!(Caller::InProcess.uid(), None);
        assert_eq!(Caller::InProcess.gid(), None);
        assert_eq!(Caller::InProcess.pid(), None);
        assert_eq!(Caller::InProcess.account_name(), None);
    }

    /// An unreadable caller says so, with the reason. Omitting `by=` would make
    /// a broken attribution indistinguishable from a line written before this
    /// existed.
    #[test]
    fn an_unreadable_caller_is_recorded_not_dropped() {
        let caller = Caller::Unreadable("Socket operation on non-socket".to_owned());
        assert_eq!(
            caller.to_string(),
            "unreadable (Socket operation on non-socket)"
        );
    }

    #[test]
    fn an_account_name_cannot_forge_a_journal_line() {
        let forged = sanitize(&format!("a\nexampled: audit: ok {}", "x".repeat(200)));
        assert!(!forged.contains('\n'), "a name can forge a journal line");
        assert!(forged.chars().count() <= 64, "a name is unbounded");
    }
}
