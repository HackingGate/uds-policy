//! What the daemon was asked to do, in the contract's own words.
//!
//! This is the seam, and it is deliberately data rather than a trait. A crate
//! that owns a daemon's contract must be able to describe its own methods with
//! no knowledge that this crate exists — parameterising over a `Method` trait
//! would make the contract depend on the policy layer, which inverts the
//! dependency direction that splitting this out exists to establish.
//!
//! ## What is not here
//!
//! A [`Call`] carries no path, no verb, no status code and no error envelope.
//! Those were the transport half, and they left with it. What is left is what
//! an authorizer and an audit trail actually need: a name for the call in the
//! vocabulary its own contract uses, and whether it is gated.
//!
//! The consequence, and it is the point: this crate never interprets a call. It
//! compares [`Authorization`] tags, prints action ids into the audit trail, and
//! hands the [`Call`] back to the code that produced it. It cannot make a
//! decision that depends on what a call *means*, because it is not told.

use std::fmt;

/// Whether a call is served to anyone who reached the socket, or gated.
///
/// This crate compares the tag and prints the action id; it never interprets
/// the id. Whatever `Policy("…")` names — a polkit action, a capability, a role
/// — is decided entirely by the [`Authorizer`] the daemon was built with.
///
/// [`Authorizer`]: crate::Authorizer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// Reaching the socket is the whole gate. Not audited: see [`crate::Operation`]
    /// for why reads produce no journal line.
    Unprivileged,
    /// Gated, under this action id. Audited, and the id appears in the line.
    Policy(&'static str),
}

/// One thing the daemon can be asked to do.
///
/// `object` and `method` are the contract's own spelling, so an audit line and
/// an authorizer name the call in the words an operator will grep for. A
/// reverse-DNS interface name in `object` renders as the fully qualified member
/// name a protocol like varlink already uses — `com.example.Thing.Change` —
/// without this crate knowing that is what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    /// The noun the call acts on, in the contract's own spelling.
    pub object: &'static str,
    /// The verb, in the contract's own spelling.
    pub method: &'static str,
    /// Whether the call is gated, and under which action id.
    pub authorization: Authorization,
}

impl Call {
    /// A call that reaching the socket is enough to make.
    #[must_use]
    pub const fn unprivileged(object: &'static str, method: &'static str) -> Self {
        Self {
            object,
            method,
            authorization: Authorization::Unprivileged,
        }
    }

    /// A call gated under `action`, and audited under it.
    #[must_use]
    pub const fn gated(object: &'static str, method: &'static str, action: &'static str) -> Self {
        Self {
            object,
            method,
            authorization: Authorization::Policy(action),
        }
    }

    /// The action id this call is gated by, or `None` if it is unprivileged.
    #[must_use]
    pub const fn action(&self) -> Option<&'static str> {
        match self.authorization {
            Authorization::Policy(action) => Some(action),
            Authorization::Unprivileged => None,
        }
    }
}

impl fmt::Display for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.object, self.method)
    }
}

#[cfg(test)]
mod tests {
    use super::{Authorization, Call};

    const CHANGE: Call = Call::gated("Thing", "Change", "org.example.thing.change");
    const READ: Call = Call::unprivileged("Thing", "Read");

    /// The rendered name is what an operator greps for, and it is assembled
    /// from the contract's vocabulary rather than from anything this crate
    /// chose.
    #[test]
    fn a_call_renders_as_its_contracts_own_name() {
        assert_eq!(CHANGE.to_string(), "Thing.Change");
        assert_eq!(
            Call::unprivileged("com.example.Thing", "Read").to_string(),
            "com.example.Thing.Read"
        );
    }

    #[test]
    fn the_constructors_agree_with_the_tag_they_set() {
        assert_eq!(
            CHANGE.authorization,
            Authorization::Policy("org.example.thing.change")
        );
        assert_eq!(CHANGE.action(), Some("org.example.thing.change"));
        assert_eq!(READ.authorization, Authorization::Unprivileged);
        assert_eq!(READ.action(), None);
    }
}
