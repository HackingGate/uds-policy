//! An audit trail for the calls this daemon runs.
//!
//! The daemon this layer was extracted from once answered "what happened?"
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
//! knowledge: the allowlist is a list of *that contract's* field names. A
//! general layer that shipped one would either be wrong for its consumer or be
//! carrying a consumer's vocabulary.
//!
//! So nothing from the payload is logged at all, and the line is assembled from
//! the [`Call`] instead: the name, the action id, and the caller. A daemon that
//! wants a target in the trail is the right place to put one, because it is the
//! only party that knows which field names identify rather than expose.
//!
//! ## Why the failure text is a plain string
//!
//! It used to be the transport's already-encoded error, carrying a status code.
//! There is no transport here to have one. What reaches the journal is whatever
//! the daemon can say about the failure in words, bounded and flattened on the
//! way in — see [`Operation::finish`].
//!
//! [`Authorization::Policy`]: crate::Authorization::Policy

use crate::call::{Authorization, Call};
use crate::caller::Caller;
use std::time::Instant;

/// How much of a daemon-supplied failure description reaches the journal.
pub const MAX_FAILURE_CHARS: usize = 256;

/// An operation in flight. Announces itself on creation and reports its
/// outcome when the daemon finishes it.
///
/// Constructed for every call and audited only for the gated ones: an
/// unprivileged call produces an `Operation` that writes nothing at either end,
/// so a dispatch site needs no `if` around its own audit trail and cannot drift
/// out of step with the policy tag.
#[derive(Debug)]
pub struct Operation {
    service: &'static str,
    /// `Some` for an audited operation, holding the line it announced itself
    /// with. `None` for a read, which is silent at both ends.
    label: Option<String>,
    started: Instant,
}

impl Operation {
    /// Begin auditing `call`, announcing it now if it changes something.
    ///
    /// The announcement is written *before* the work runs, so an operation that
    /// never returns is still on the record.
    #[must_use]
    pub fn begin(service: &'static str, call: Call, caller: &Caller) -> Self {
        let started = Instant::now();
        let Authorization::Policy(action) = call.authorization else {
            return Self {
                service,
                label: None,
                started,
            };
        };
        let label = describe(call, action, caller);
        eprintln!("{service}: audit: begin {label}");
        Self {
            service,
            label: Some(label),
            started,
        }
    }

    /// Whether this operation writes journal lines at all.
    ///
    /// False for an unprivileged call. Exposed so a daemon can assert on the
    /// restraint rather than take it on trust.
    #[must_use]
    pub const fn is_audited(&self) -> bool {
        self.label.is_some()
    }

    /// Report the outcome, with `None` for success.
    ///
    /// Called for both arms so a failed operation is as visible as a successful
    /// one — the outage that prompted this had a record of neither. `failure`
    /// is bounded and flattened: a daemon's own error text is not this crate's
    /// to trust, and one newline is all it takes to forge an extra audit line.
    pub fn finish(self, failure: Option<&str>) {
        let Some(label) = self.label else {
            return;
        };
        let millis = self.started.elapsed().as_millis();
        let service = self.service;
        match failure {
            None => eprintln!("{service}: audit: ok {label} ({millis}ms)"),
            Some(reason) => eprintln!(
                "{service}: audit: failed {label} ({millis}ms): {}",
                bound(reason)
            ),
        }
    }
}

/// `<call> action=<id> by=<caller>` — the operation, the policy it was gated
/// by, and who asked for it.
///
/// The call's own rendered name rather than anything this crate invented: it is
/// what the contract calls the method and what an operator greps for.
///
/// `by=` is always present, including when the caller could not be read
/// ([`Caller`]): a line that quietly loses it reads exactly like one written
/// before the daemon recorded callers at all.
fn describe(call: Call, action: &str, caller: &Caller) -> String {
    format!("{call} action={action} by={caller}")
}

/// Bound and flatten a string the daemon produced.
///
/// A daemon's error text is not this crate's to trust: it can be long, and it
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
    use crate::call::Call;
    use crate::caller::Caller;

    const GATED: Call = Call::gated("Thing", "Change", "org.example.thing.change");
    const OPEN: Call = Call::unprivileged("Thing", "Read");

    /// Reads must produce no audit line at all: front-ends poll every few
    /// seconds, so logging them would evict the operations worth keeping.
    #[test]
    fn only_state_changing_calls_are_audited() {
        let quiet = Operation::begin("exampled", OPEN, &Caller::InProcess);
        assert!(!quiet.is_audited());
        quiet.finish(None);

        let audited = Operation::begin("exampled", GATED, &Caller::InProcess);
        assert!(audited.is_audited());
        audited.finish(None);
    }

    /// The question this layer exists to keep answerable: one socket serves
    /// several front-ends under several accounts, and a line without `by=` says
    /// only that *someone* changed the host.
    #[test]
    fn the_label_names_the_call_the_action_and_the_caller() {
        assert_eq!(
            describe(GATED, "org.example.thing.change", &Caller::InProcess),
            "Thing.Change action=org.example.thing.change by=in-process"
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
            "Thing.Change action=org.example.thing.change \
             by=unreadable (Socket operation on non-socket)"
        );
    }

    /// A daemon's own error text is untrusted here for the same reason an
    /// account name is: either can forge a journal line with one newline.
    #[test]
    fn a_failure_description_cannot_forge_a_journal_line() {
        let forged = bound(&format!("a\nexampled: audit: ok {}", "x".repeat(400)));
        assert!(!forged.contains('\n'));
        assert!(forged.chars().count() <= 256);
    }
}
