//! An audit trail for the calls this daemon runs.
//!
//! The daemon this framework was extracted from once answered "what happened?"
//! with three journal lines for an entire boot, one of which was a broken pipe,
//! while it had in fact deactivated, deleted, recreated, activated and reapplied
//! a live configuration. Reconstructing that took cross-referencing another
//! service's own audit lines against the kernel ring buffer.
//!
//! So: every state-changing call is announced before it runs and reported when
//! it finishes. Two lines per operation, no lines at all for reads.
//!
//! ## Why only state-changing calls
//!
//! A daemon like this often logs to a small volatile store, and front-ends poll
//! status every few seconds. Logging reads would evict the operations worth
//! keeping within minutes — the flood *is* the loss. [`Authorization::Policy`]
//! is already the contract's own statement of "this changes something", so the
//! audit trail and the policy gate cannot drift apart.
//!
//! ## Why the request body is never logged
//!
//! Requests carry secrets. The daemon this came from assembled a target string
//! from an allowlist of identifying keys — which works, and is domain
//! knowledge: the allowlist is a list of *this contract's* field names. A
//! framework that shipped one would either be wrong for its consumer or be
//! carrying a consumer's vocabulary.
//!
//! So the framework logs nothing from the payload at all, and the line is
//! assembled from the [`Route`] instead: the path, the action id, and the
//! caller. A service that wants a target in the trail is the right place to put
//! one, because it is the only party that knows which field names identify
//! rather than expose.

use crate::caller::Caller;
use crate::service::{Authorization, Route, WireError};
use std::time::Instant;

/// How much of a service-supplied failure body reaches the journal.
const MAX_FAILURE_CHARS: usize = 256;

/// An operation in flight. Announces itself on creation and reports its
/// outcome when the caller finishes it.
#[derive(Debug)]
pub(crate) struct Operation {
    service: &'static str,
    label: String,
    started: Instant,
}

impl Operation {
    /// Begin auditing `route` if it changes something; `None` for a read.
    pub(crate) fn begin(service: &'static str, route: Route, caller: &Caller) -> Option<Self> {
        let Authorization::Policy(action) = route.authorization else {
            return None;
        };
        let label = describe(route, action, caller);
        eprintln!("{service}: audit: begin {label}");
        Some(Self {
            service,
            label,
            started: Instant::now(),
        })
    }

    /// Report the outcome. Called for both arms so a failed operation is as
    /// visible as a successful one — the outage that prompted this had no
    /// record of either.
    pub(crate) fn finish(self, error: Option<&WireError>) {
        let millis = self.started.elapsed().as_millis();
        let service = self.service;
        match error {
            None => eprintln!("{service}: audit: ok {} ({millis}ms)", self.label),
            Some(failure) => eprintln!(
                "{service}: audit: failed {} ({millis}ms): status={} {}",
                self.label,
                failure.status,
                bound(&failure.body)
            ),
        }
    }
}

/// `<api path> action=<id> by=<caller>` — the operation, the policy it was
/// gated by, and who asked for it.
///
/// The API path rather than the contract's internal method name: it is what the
/// client sent and what an operator greps for.
///
/// `by=` is always present, including when the caller could not be read
/// ([`crate::Caller`]): a line that quietly loses it reads exactly like one
/// written before the daemon recorded callers at all.
fn describe(route: Route, action: &str, caller: &Caller) -> String {
    format!("{} action={action} by={caller}", route.api_path)
}

/// Bound and flatten a string the service produced.
///
/// A service's error body is not this crate's to trust: it can be long, and it
/// can contain a newline, which is all it takes to forge an extra audit line.
fn bound(value: &str) -> String {
    value
        .chars()
        .take(MAX_FAILURE_CHARS)
        .collect::<String>()
        .replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::{Operation, bound, describe};
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

    /// Reads must produce no audit line at all: front-ends poll every few
    /// seconds, so logging them would evict the operations worth keeping.
    #[test]
    fn only_state_changing_routes_are_audited() {
        assert!(Operation::begin("exampled", OPEN, &Caller::InProcess).is_none());
        let audited = Operation::begin("exampled", GATED, &Caller::InProcess);
        assert!(audited.is_some());
        if let Some(operation) = audited {
            operation.finish(None);
        }
    }

    /// The question the framework exists to keep answerable: one socket serves
    /// several front-ends under several accounts, and a line without `by=` says
    /// only that *someone* changed the host.
    #[test]
    fn the_label_names_the_path_the_action_and_the_caller() {
        assert_eq!(
            describe(GATED, "org.example.thing.change", &Caller::InProcess),
            "/v1/thing/change action=org.example.thing.change by=in-process"
        );
    }

    /// A caller the kernel would not report still produces a `by=`, so a broken
    /// attribution is visible rather than looking like the old format.
    #[test]
    fn an_unreadable_caller_still_produces_a_by_field() {
        let label = describe(
            GATED,
            "org.example.thing.change",
            &Caller::Unreadable("Socket operation on non-socket".to_owned()),
        );
        assert_eq!(
            label,
            "/v1/thing/change action=org.example.thing.change \
             by=unreadable (Socket operation on non-socket)"
        );
    }

    /// A service's own error text is untrusted here for the same reason an
    /// account name is: either can forge a journal line with one newline.
    #[test]
    fn a_service_failure_cannot_forge_a_journal_line() {
        let forged = bound(&format!("a\nexampled: audit: ok {}", "x".repeat(400)));
        assert!(!forged.contains('\n'));
        assert!(forged.chars().count() <= 256);
    }
}
