//! The gate between a resolved route and the code that runs it.
//!
//! The framework consults the [`Authorizer`] for **every** resolved route, not
//! only the gated ones, and it hands over the [`Caller`] the kernel reported.
//! Both of those are deliberate:
//!
//! * Passing the caller is what makes a uid/gid gate expressible at all. An
//!   authorizer that receives only the route can decide whether a *kind* of
//!   call is allowed and never whether *this* party may make it, which leaves
//!   the socket's file mode as the only identity check the daemon has.
//! * Consulting it for unprivileged routes too means a daemon can refuse an
//!   unknown peer outright rather than serving reads to it. An authorizer that
//!   wants the narrower behaviour writes one arm:
//!   `Authorization::Unprivileged => Ok(())`, which is exactly what
//!   [`AllowSocketPeers`] is.
//!
//! Health and version are answered by the framework and never reach an
//! authorizer: a liveness probe that has to be authorized is a liveness probe
//! that reports the authorizer's health.

use crate::caller::Caller;
use crate::service::{Authorization, Route};
use std::collections::BTreeSet;

/// Why a call was refused.
///
/// A string, because the framework does not classify refusals — it passes the
/// reason to [`Service::encode_framework_error`] with
/// [`FrameworkErrorKind::Unauthorized`] and lets the service phrase the reply.
///
/// [`Service::encode_framework_error`]: crate::Service::encode_framework_error
/// [`FrameworkErrorKind::Unauthorized`]: crate::FrameworkErrorKind::Unauthorized
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// Operator-facing explanation. Reaches the client, so it must not carry
    /// anything the client should not learn.
    pub reason: String,
}

impl Denial {
    /// A refusal with a reason.
    #[must_use]
    pub const fn new(reason: String) -> Self {
        Self { reason }
    }
}

/// Decides whether a caller may make a call.
pub trait Authorizer: core::fmt::Debug + Send + Sync {
    /// Allow or refuse `route` for `caller`.
    ///
    /// Called after the route resolved and before the request body is parsed,
    /// so a refusal costs nothing and reveals nothing about the payload.
    fn authorize(&self, route: Route, caller: &Caller) -> Result<(), Denial>;
}

/// Reaching the socket is the whole gate.
///
/// The socket's own mode and group ownership are the access control; anything
/// that could `connect(2)` may call. This is the right default for a daemon
/// whose socket is `0660 root:<group>` and whose group membership is the
/// deployment's actual policy, and it is the wrong one for a daemon whose
/// socket is world-writable.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowSocketPeers;

impl Authorizer for AllowSocketPeers {
    fn authorize(&self, _route: Route, _caller: &Caller) -> Result<(), Denial> {
        Ok(())
    }
}

/// Refuses everything, naming the action id it would have needed.
///
/// The safe default for a daemon whose real authorizer is not wired yet: a
/// half-built daemon that serves privileged calls to anyone is worse than one
/// that serves nobody, and the refusal message says which action is missing.
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAll;

impl Authorizer for DenyAll {
    fn authorize(&self, route: Route, _caller: &Caller) -> Result<(), Denial> {
        Denial::new(match route.authorization {
            Authorization::Policy(action) => format!(
                "authorization required for {action} before {}.{}",
                route.object, route.method
            ),
            Authorization::Unprivileged => format!(
                "this daemon is not accepting calls: {}.{}",
                route.object, route.method
            ),
        })
        .into_result()
    }
}

impl Denial {
    /// Sugar for the shape every refusing authorizer ends with.
    fn into_result(self) -> Result<(), Self> {
        Err(self)
    }
}

/// Allows only callers whose kernel-reported uid or gid is on a list.
///
/// The socket's group is a coarse gate — it says "a member of this group may
/// talk to the daemon" and nothing more. `PeerGate` is the finer one, and it
/// can only exist because [`Authorizer::authorize`] receives the [`Caller`].
///
/// A caller matches if its uid is in `allowed_uids` **or** its gid is in
/// `allowed_gids`; empty sets match nothing, so a gate configured with neither
/// refuses everyone rather than silently degrading to "allow all".
///
/// `reject_unreadable_caller` decides the one case the kernel would not answer.
/// Defaulting it to `true` is the safe reading — a call the daemon cannot
/// attribute is one it cannot audit — but a daemon that would rather stay
/// reachable than stay attributable can set it to `false` and take the
/// `unreadable (…)` line instead.
#[derive(Debug, Clone, Default)]
pub struct PeerGate {
    /// User ids that may call.
    pub allowed_uids: BTreeSet<u32>,
    /// Group ids that may call. This is the caller's *primary* group as the
    /// kernel reports it, not its full supplementary set: `SO_PEERCRED`
    /// carries one gid.
    pub allowed_gids: BTreeSet<u32>,
    /// Whether a caller the kernel would not report is refused.
    pub reject_unreadable_caller: bool,
}

impl PeerGate {
    /// A gate that admits `uids`, refuses unreadable callers, and names no
    /// groups.
    #[must_use]
    pub fn for_uids(uids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            allowed_uids: uids.into_iter().collect(),
            allowed_gids: BTreeSet::new(),
            reject_unreadable_caller: true,
        }
    }

    /// A gate that admits `gids`, refuses unreadable callers, and names no
    /// users.
    #[must_use]
    pub fn for_gids(gids: impl IntoIterator<Item = u32>) -> Self {
        Self {
            allowed_uids: BTreeSet::new(),
            allowed_gids: gids.into_iter().collect(),
            reject_unreadable_caller: true,
        }
    }
}

impl Authorizer for PeerGate {
    fn authorize(&self, route: Route, caller: &Caller) -> Result<(), Denial> {
        match *caller {
            Caller::Peer { uid, gid, .. } => {
                if self.allowed_uids.contains(&uid) || self.allowed_gids.contains(&gid) {
                    return Ok(());
                }
                Err(Denial::new(format!(
                    "uid {uid} gid {gid} may not call {}.{}",
                    route.object, route.method
                )))
            }
            // In-process dispatch is not a socket peer and never was gated by
            // one: the daemon calling itself has already passed every gate
            // there is by virtue of being the daemon.
            Caller::InProcess => Ok(()),
            Caller::Unreadable(ref reason) => {
                if self.reject_unreadable_caller {
                    Err(Denial::new(format!(
                        "the caller could not be identified ({reason}), \
                         and this daemon does not serve unidentified callers"
                    )))
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AllowSocketPeers, Authorizer, DenyAll, PeerGate};
    use crate::caller::Caller;
    use crate::service::{Authorization, Route};

    const GATED: Route = Route {
        api_path: "/v1/thing/change",
        object: "Thing",
        method: "Change",
        authorization: Authorization::Policy("org.example.thing.change"),
    };

    const OPEN: Route = Route {
        api_path: "/v1/thing/read",
        object: "Thing",
        method: "Read",
        authorization: Authorization::Unprivileged,
    };

    fn peer(uid: u32, gid: u32) -> Caller {
        Caller::Peer { pid: 7, uid, gid }
    }

    #[test]
    fn allow_socket_peers_admits_whatever_reached_the_socket() {
        assert!(AllowSocketPeers.authorize(GATED, &peer(1000, 1000)).is_ok());
        assert!(AllowSocketPeers.authorize(OPEN, &Caller::InProcess).is_ok());
    }

    /// The refusal must name the action, so an operator can see which policy is
    /// missing rather than only that something was denied.
    #[test]
    fn deny_all_names_the_action_it_would_have_needed() {
        let denial = DenyAll
            .authorize(GATED, &peer(1000, 1000))
            .expect_err("DenyAll allowed a gated route");
        assert!(
            denial.reason.contains("org.example.thing.change"),
            "the refusal did not name the action: {}",
            denial.reason
        );
    }

    #[test]
    fn a_peer_gate_admits_a_listed_uid_and_refuses_the_rest() {
        let gate = PeerGate::for_uids([1000]);
        assert!(gate.authorize(GATED, &peer(1000, 4)).is_ok());
        assert!(gate.authorize(GATED, &peer(1001, 4)).is_err());
    }

    #[test]
    fn a_peer_gate_admits_a_listed_gid() {
        let gate = PeerGate::for_gids([970]);
        assert!(gate.authorize(OPEN, &peer(1001, 970)).is_ok());
        assert!(gate.authorize(OPEN, &peer(1001, 971)).is_err());
    }

    /// An empty gate must refuse everyone. The alternative — an empty list
    /// meaning "unrestricted" — turns a configuration mistake into an open
    /// socket, which is the one failure mode a gate exists to prevent.
    #[test]
    fn an_empty_peer_gate_refuses_everyone() {
        let gate = PeerGate::default();
        assert!(gate.authorize(GATED, &peer(0, 0)).is_err());
    }

    #[test]
    fn an_unreadable_caller_is_refused_or_admitted_by_configuration() {
        let unreadable = Caller::Unreadable("Socket operation on non-socket".to_owned());
        let strict = PeerGate::for_uids([1000]);
        assert!(strict.authorize(GATED, &unreadable).is_err());

        let lenient = PeerGate {
            reject_unreadable_caller: false,
            ..PeerGate::for_uids([1000])
        };
        assert!(lenient.authorize(GATED, &unreadable).is_ok());
    }
}
