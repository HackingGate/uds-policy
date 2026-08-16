//! The pipeline: resolve, authorize, parse, audit, dispatch.
//!
//! Split from the socket so a daemon's routing and its policy can be tested
//! without a file descriptor — and so the order below is stated once, in one
//! place, rather than emerging from the order of `if`s in a connection reader.

use crate::audit::Operation;
use crate::authorization::Authorizer;
use crate::caller::Caller;
use crate::service::{FrameworkErrorKind, HttpVerb, Service, WireError};
use serde_json::Value;
use std::sync::Arc;

/// A status and a body, ready to be framed as an HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// The response body, already serialized.
    pub body: String,
}

/// The request pipeline, with no socket attached.
///
/// Cloneable and cheap: both halves are `Arc`s. Construct one directly to
/// exercise a service in tests, or take the server's own with
/// [`Server::handler`](crate::Server::handler).
#[derive(Debug, Clone)]
pub struct Handler {
    service: Arc<dyn Service>,
    authorizer: Arc<dyn Authorizer>,
    health_path: &'static str,
    version_path: &'static str,
}

impl Handler {
    /// Assemble a pipeline.
    #[must_use]
    pub fn new(
        service: Arc<dyn Service>,
        authorizer: Arc<dyn Authorizer>,
        health_path: &'static str,
        version_path: &'static str,
    ) -> Self {
        Self {
            service,
            authorizer,
            health_path,
            version_path,
        }
    }

    /// The service this pipeline dispatches to.
    #[must_use]
    pub fn service(&self) -> &Arc<dyn Service> {
        &self.service
    }

    /// Answer one request.
    ///
    /// `request_body` is the raw body; an empty or blank one dispatches as
    /// [`Value::Null`], so a route that takes no arguments does not have to be
    /// called with `{}`.
    ///
    /// The order is the contract:
    ///
    /// 1. **resolve** — the service turns a target into a route, or does not.
    /// 2. **authorize** — before the body is even parsed, so a refusal costs
    ///    nothing and a malformed payload cannot influence the decision.
    /// 3. **parse** — invalid JSON is the client's error, and it is reported
    ///    without the service ever seeing it.
    /// 4. **audit** — the line is written *before* the call runs, so an
    ///    operation that never returns is still on the record.
    /// 5. **dispatch**.
    #[must_use]
    pub fn respond(
        &self,
        verb: HttpVerb,
        api_path: &str,
        request_body: &str,
        caller: &Caller,
    ) -> Reply {
        // Health and version are the framework's, and they are answered before
        // anything else: a liveness probe that has to resolve, authorize and
        // dispatch is a liveness probe that reports on the router.
        if verb == HttpVerb::Get {
            if api_path == self.health_path {
                return self.ok(&serde_json::json!({ "healthy": true }));
            }
            if api_path == self.version_path {
                return self.ok(&serde_json::json!({
                    "name": self.service.name(),
                    "version": self.service.version(),
                }));
            }
        }

        let Some(route) = self.service.resolve(verb, api_path) else {
            // A verb the framework does not route on is a 405 rather than a
            // 404: the target may well exist, and saying "not found" for
            // `DELETE /v1/thing` sends the client looking for the wrong bug.
            let (kind, message) = if verb == HttpVerb::Other {
                (
                    FrameworkErrorKind::MethodNotAllowed,
                    format!("unsupported method for {api_path}"),
                )
            } else {
                (
                    FrameworkErrorKind::NotFound,
                    format!("unknown API path: {api_path}"),
                )
            };
            return self.framework_error(kind, &message);
        };

        if let Err(denial) = self.authorizer.authorize(route, caller) {
            return self.framework_error(FrameworkErrorKind::Unauthorized, &denial.reason);
        }

        let request = match parse_request(request_body) {
            Ok(value) => value,
            Err(message) => {
                return self.framework_error(FrameworkErrorKind::InvalidInput, &message);
            }
        };

        let operation = Operation::begin(self.service.name(), route, caller);
        let outcome = self.service.dispatch(route, &request, caller);
        if let Some(operation) = operation {
            operation.finish(outcome.as_ref().err());
        }

        match outcome {
            Ok(value) => self.ok(&value),
            Err(failure) => Reply {
                status: failure.status,
                body: failure.body,
            },
        }
    }

    /// Ask the service to encode a failure the framework produced.
    #[must_use]
    pub fn framework_error(&self, kind: FrameworkErrorKind, message: &str) -> Reply {
        let WireError { status, body } = self.service.encode_framework_error(kind, message);
        Reply { status, body }
    }

    /// The `{"ok": …}` envelope — the one piece of wire shape the framework
    /// owns, because a success has no error kind for the service to classify.
    fn ok(&self, value: &Value) -> Reply {
        match serde_json::to_string(&serde_json::json!({ "ok": value })) {
            Ok(body) => Reply { status: 200, body },
            // A reply the daemon built and cannot serialize is the daemon's
            // fault, and it is reported as one rather than as a truncated 200.
            Err(error) => self.framework_error(
                FrameworkErrorKind::Internal,
                &format!("the reply could not be encoded: {error}"),
            ),
        }
    }
}

/// A blank body is `null`, not a parse error.
fn parse_request(request_body: &str) -> Result<Value, String> {
    if request_body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(request_body)
        .map_err(|error| format!("invalid JSON request payload: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{Handler, parse_request};
    use crate::authorization::{AllowSocketPeers, Authorizer, Denial, DenyAll};
    use crate::caller::Caller;
    use crate::service::{Authorization, FrameworkErrorKind, HttpVerb, Route, Service, WireError};
    use serde_json::Value;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const READ: Route = Route {
        api_path: "/v1/thing/read",
        object: "Thing",
        method: "Read",
        authorization: Authorization::Unprivileged,
    };

    const CHANGE: Route = Route {
        api_path: "/v1/thing/change",
        object: "Thing",
        method: "Change",
        authorization: Authorization::Policy("org.example.thing.change"),
    };

    #[derive(Debug, Default)]
    struct EchoService {
        dispatches: AtomicUsize,
    }

    impl Service for EchoService {
        fn name(&self) -> &'static str {
            "exampled"
        }

        fn version(&self) -> &'static str {
            "9.9.9"
        }

        fn resolve(&self, verb: HttpVerb, api_path: &str) -> Option<Route> {
            match (verb, api_path) {
                (HttpVerb::Get, "/v1/thing/read") => Some(READ),
                (HttpVerb::Post, "/v1/thing/change") => Some(CHANGE),
                _ => None,
            }
        }

        fn dispatch(
            &self,
            route: Route,
            request: &Value,
            _caller: &Caller,
        ) -> Result<Value, WireError> {
            self.dispatches.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({ "method": route.method, "request": request }))
        }

        fn encode_framework_error(&self, kind: FrameworkErrorKind, message: &str) -> WireError {
            WireError::new(
                kind.conventional_status(),
                serde_json::json!({ "error": { "message": message } }).to_string(),
            )
        }
    }

    fn handler(authorizer: Arc<dyn Authorizer>) -> (Handler, Arc<EchoService>) {
        let service = Arc::new(EchoService::default());
        let shared: Arc<dyn Service> = service.clone();
        let handler = Handler::new(shared, authorizer, "/v1/status", "/v1/version");
        (handler, service)
    }

    #[test]
    fn health_and_version_are_the_frameworks_own() {
        let (handler, _service) = handler(Arc::new(DenyAll));
        // DenyAll, and they still answer: a probe that has to be authorized
        // reports on the authorizer.
        let health = handler.respond(HttpVerb::Get, "/v1/status", "", &Caller::InProcess);
        assert_eq!(health.status, 200);
        assert_eq!(health.body, r#"{"ok":{"healthy":true}}"#);

        let version = handler.respond(HttpVerb::Get, "/v1/version", "", &Caller::InProcess);
        assert_eq!(version.status, 200);
        assert!(version.body.contains("exampled"), "{}", version.body);
        assert!(version.body.contains("9.9.9"), "{}", version.body);
    }

    #[test]
    fn a_resolved_call_dispatches_inside_the_ok_envelope() {
        let (handler, _service) = handler(Arc::new(AllowSocketPeers));
        let reply = handler.respond(
            HttpVerb::Post,
            "/v1/thing/change",
            r#"{"scope":"all"}"#,
            &Caller::InProcess,
        );
        assert_eq!(reply.status, 200);
        let decoded: Value = serde_json::from_str(&reply.body).expect("reply is not JSON");
        assert_eq!(decoded["ok"]["method"], "Change");
        assert_eq!(decoded["ok"]["request"]["scope"], "all");
    }

    #[test]
    fn an_unresolved_path_is_not_found_and_an_unknown_verb_is_not_allowed() {
        let (handler, _service) = handler(Arc::new(AllowSocketPeers));
        assert_eq!(
            handler
                .respond(HttpVerb::Post, "/v1/thing/nope", "{}", &Caller::InProcess)
                .status,
            404
        );
        assert_eq!(
            handler
                .respond(HttpVerb::Other, "/v1/thing/read", "", &Caller::InProcess)
                .status,
            405
        );
    }

    /// The order matters more than the outcome: a refused call must not reach
    /// the service at all, or a daemon's policy gate is advisory.
    #[test]
    fn a_refused_call_never_reaches_the_service() {
        let (handler, service) = handler(Arc::new(DenyAll));
        let reply = handler.respond(HttpVerb::Post, "/v1/thing/change", "{}", &Caller::InProcess);
        assert_eq!(reply.status, 403);
        assert_eq!(service.dispatches.load(Ordering::SeqCst), 0);
        assert!(
            reply.body.contains("org.example.thing.change"),
            "{}",
            reply.body
        );
    }

    /// Authorization comes before parsing, so a malformed body is refused with
    /// the authorization error rather than the parse error — the client learns
    /// it may not make the call, and learns nothing about the payload.
    #[test]
    fn authorization_precedes_parsing() {
        let (handler, _service) = handler(Arc::new(DenyAll));
        let reply = handler.respond(HttpVerb::Post, "/v1/thing/change", "{", &Caller::InProcess);
        assert_eq!(reply.status, 403);
    }

    #[test]
    fn invalid_json_is_the_clients_error() {
        let (handler, service) = handler(Arc::new(AllowSocketPeers));
        let reply = handler.respond(HttpVerb::Post, "/v1/thing/change", "{", &Caller::InProcess);
        assert_eq!(reply.status, 400);
        assert_eq!(service.dispatches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_blank_body_dispatches_as_null() {
        assert_eq!(parse_request(""), Ok(Value::Null));
        assert_eq!(parse_request("  \r\n "), Ok(Value::Null));
        let (handler, _service) = handler(Arc::new(AllowSocketPeers));
        let reply = handler.respond(HttpVerb::Get, "/v1/thing/read", "", &Caller::InProcess);
        assert_eq!(reply.status, 200);
        let decoded: Value = serde_json::from_str(&reply.body).expect("reply is not JSON");
        assert_eq!(decoded["ok"]["request"], Value::Null);
    }

    /// The authorizer is handed the caller. Without it a uid gate cannot be
    /// written at all, and the socket's file mode is the only identity check
    /// the daemon has.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot reach NSS")]
    fn the_authorizer_sees_the_caller() {
        #[derive(Debug)]
        struct RootOnly;

        impl Authorizer for RootOnly {
            fn authorize(&self, _route: Route, caller: &Caller) -> Result<(), Denial> {
                if caller.uid() == Some(0) {
                    Ok(())
                } else {
                    Err(Denial::new(format!("not root: {caller}")))
                }
            }
        }

        let (handler, _service) = handler(Arc::new(RootOnly));
        let root = Caller::Peer {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let other = Caller::Peer {
            pid: 2,
            uid: 1000,
            gid: 1000,
        };
        assert_eq!(
            handler
                .respond(HttpVerb::Get, "/v1/thing/read", "", &root)
                .status,
            200
        );
        assert_eq!(
            handler
                .respond(HttpVerb::Get, "/v1/thing/read", "", &other)
                .status,
            403
        );
    }
}
