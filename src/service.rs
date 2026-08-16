//! The seam between the framework and the daemon that uses it.
//!
//! Everything here is a concrete type. See the crate documentation for why
//! this is a deliberate refusal to be generic: a wire contract must be
//! describable without depending on the server that happens to serve it.

use crate::caller::Caller;
use serde_json::Value;

/// Whether a route is served to anyone who reached the socket, or gated.
///
/// The framework compares this tag and prints the action id; it never
/// interprets the id. Whatever `Policy("…")` names — a polkit action, a
/// capability, a role — is decided entirely by the [`Authorizer`] the server
/// was built with.
///
/// [`Authorizer`]: crate::Authorizer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// Reaching the socket is the whole gate. Not audited: see [`crate::Server`]
    /// for why reads produce no journal line.
    Unprivileged,
    /// Gated, under this action id. Audited, and the id appears in the line.
    Policy(&'static str),
}

/// One thing the daemon can be asked to do.
///
/// Produced by [`Service::resolve`] and handed straight back to
/// [`Service::dispatch`]. `object` and `method` are carried so the audit trail
/// and an authorizer can name the call in the words the contract uses; the
/// framework only ever prints them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The request target this route answers, e.g. `/v1/status`.
    pub api_path: &'static str,
    /// The noun the call acts on, in the contract's own spelling.
    pub object: &'static str,
    /// The verb, in the contract's own spelling.
    pub method: &'static str,
    /// Whether the call is gated, and under which action id.
    pub authorization: Authorization,
}

/// The HTTP method of a request, reduced to what routing needs.
///
/// `Other` covers everything else, including a method the framework refuses to
/// name: a service that resolves nothing for `Other` gets a 405 without the
/// framework having to hold a list of methods it has never heard of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVerb {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// Any other method.
    Other,
}

impl HttpVerb {
    /// Classify a request line's method token.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "GET" => Self::Get,
            "POST" => Self::Post,
            _ => Self::Other,
        }
    }
}

/// A failure, already encoded in the service's own error envelope.
///
/// The framework does not own the error shape. It owns the `{"ok": …}` success
/// envelope, because that one has nowhere else to live, and it asks the service
/// for everything else — including its own failures, through
/// [`Service::encode_framework_error`]. A daemon whose clients decode
/// `{"error":{"kind":…}}` therefore keeps that shape for a 404 the framework
/// generated, and its client does not need a second decoder for the cases the
/// service never saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError {
    /// The HTTP status to answer with.
    pub status: u16,
    /// The response body, already serialized.
    pub body: String,
}

impl WireError {
    /// A failure with a status and an already-encoded body.
    #[must_use]
    pub const fn new(status: u16, body: String) -> Self {
        Self { status, body }
    }
}

/// A failure the framework produced before, or instead of, reaching the
/// service.
///
/// The framework hands the kind and a message to
/// [`Service::encode_framework_error`] rather than choosing a status itself,
/// so a daemon that answers 422 where another answers 400 stays consistent
/// with itself for errors it did not generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameworkErrorKind {
    /// No route answers this target.
    NotFound,
    /// The request could not be read, parsed, or made sense of.
    InvalidInput,
    /// The [`Authorizer`](crate::Authorizer) refused the call.
    Unauthorized,
    /// The target exists but not for this HTTP method.
    MethodNotAllowed,
    /// Headers or body exceeded the configured ceiling.
    PayloadTooLarge,
    /// The framework itself failed, e.g. a reply that would not serialize.
    Internal,
}

impl FrameworkErrorKind {
    /// The status a daemon with no opinion would use. Offered as a default for
    /// [`Service::encode_framework_error`] implementations, and used by nothing
    /// in the framework itself.
    #[must_use]
    pub const fn conventional_status(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::InvalidInput => 400,
            Self::Unauthorized => 403,
            Self::MethodNotAllowed => 405,
            Self::PayloadTooLarge => 413,
            Self::Internal => 500,
        }
    }
}

/// What a daemon built on this framework has to say for itself.
///
/// The framework calls `resolve` to turn a request target into a [`Route`],
/// `dispatch` to run it, and `encode_framework_error` for every failure it
/// produced on its own. It calls nothing else, and it knows nothing else.
pub trait Service: core::fmt::Debug + Send + Sync + 'static {
    /// The daemon's name. Prefixes every audit line, and answers the version
    /// path.
    fn name(&self) -> &'static str;

    /// The daemon's version, as the version path should report it.
    fn version(&self) -> &'static str;

    /// The route for a request target, or `None` if this service serves none.
    ///
    /// `None` becomes a 404 for `GET`/`POST` and a 405 for anything else, so a
    /// service that wants "this path exists but not for this method" can
    /// simply not resolve it.
    fn resolve(&self, verb: HttpVerb, api_path: &str) -> Option<Route>;

    /// Run a resolved, authorized call.
    ///
    /// `request` is the parsed JSON body, or [`Value::Null`] when the request
    /// carried none. `caller` is the kernel's answer, read before the first
    /// request byte — see [`Caller`].
    fn dispatch(&self, route: Route, request: &Value, caller: &Caller) -> Result<Value, WireError>;

    /// Encode a framework-generated failure in this service's error envelope.
    fn encode_framework_error(&self, kind: FrameworkErrorKind, message: &str) -> WireError;
}

#[cfg(test)]
mod tests {
    use super::{FrameworkErrorKind, HttpVerb};

    #[test]
    fn verbs_the_framework_routes_on_are_the_two_it_names() {
        assert_eq!(HttpVerb::parse("GET"), HttpVerb::Get);
        assert_eq!(HttpVerb::parse("POST"), HttpVerb::Post);
        assert_eq!(HttpVerb::parse("DELETE"), HttpVerb::Other);
        // Case-sensitive: HTTP methods are, and a lowercase `get` is a
        // malformed request line rather than a friendlier spelling.
        assert_eq!(HttpVerb::parse("get"), HttpVerb::Other);
    }

    #[test]
    fn conventional_statuses_are_offered_but_not_imposed() {
        assert_eq!(FrameworkErrorKind::NotFound.conventional_status(), 404);
        assert_eq!(FrameworkErrorKind::Unauthorized.conventional_status(), 403);
        assert_eq!(
            FrameworkErrorKind::MethodNotAllowed.conventional_status(),
            405
        );
        assert_eq!(
            FrameworkErrorKind::PayloadTooLarge.conventional_status(),
            413
        );
    }
}
