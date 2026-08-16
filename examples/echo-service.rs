//! A complete daemon that knows nothing, to prove the framework needs to know
//! nothing either.
//!
//! ```console
//! $ cargo run --example echo-service
//! $ curl --unix-socket /tmp/uds-daemon-echo.sock -sS http://d/v1/status
//! {"ok":{"healthy":true}}
//! $ curl --unix-socket /tmp/uds-daemon-echo.sock -sS -X POST http://d/v1/echo/say \
//!     -H 'content-type: application/json' -d '{"hello":"world"}'
//! {"ok":{"said":{"hello":"world"},"to":"uid 1000 gid 1000 pid 4711"}}
//! ```
//!
//! The socket path may be given as the first argument.

use serde_json::{Value, json};
use std::sync::Arc;
use uds_daemon::{
    AllowSocketPeers, Authorization, Caller, FrameworkErrorKind, HttpVerb, Route, Server,
    ServerConfig, Service, WireError,
};

const SAY: Route = Route {
    api_path: "/v1/echo/say",
    object: "Echo",
    method: "Say",
    authorization: Authorization::Policy("org.example.echo.say"),
};

#[derive(Debug)]
struct Echo;

impl Service for Echo {
    fn name(&self) -> &'static str {
        "echod"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn resolve(&self, verb: HttpVerb, api_path: &str) -> Option<Route> {
        (verb == HttpVerb::Post && api_path == SAY.api_path).then_some(SAY)
    }

    fn dispatch(
        &self,
        _route: Route,
        request: &Value,
        caller: &Caller,
    ) -> Result<Value, WireError> {
        Ok(json!({ "said": request, "to": caller.to_string() }))
    }

    /// The error envelope is the service's, not the framework's — this one
    /// happens to be `{"error":{"kind":…,"message":…}}`, and a real contract
    /// would encode its own error type here.
    fn encode_framework_error(&self, kind: FrameworkErrorKind, message: &str) -> WireError {
        let body = json!({ "error": { "kind": format!("{kind:?}"), "message": message } });
        WireError::new(kind.conventional_status(), body.to_string())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/uds-daemon-echo.sock".to_owned());
    let config = ServerConfig::new(&socket_path);
    let server = Server::bind(config, Arc::new(Echo), Arc::new(AllowSocketPeers))?;
    eprintln!("echod: serving on {socket_path}");
    server.serve()?;
    Ok(())
}
