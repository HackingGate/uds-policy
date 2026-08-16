//! The framework over a real socket.
//!
//! Everything here that matters happens between two file descriptors, so
//! nothing here can run under Miri — see the `cfg_attr(miri, ignore)` on every
//! test. The two tests that assert on the *journal* run the daemon in a child
//! process and read its stderr, because the audit trail is a side effect on a
//! file descriptor this process cannot otherwise observe, and asserting on a
//! log line by calling the function that formats it would prove only that the
//! formatter formats.
#![cfg_attr(
    test,
    allow(
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::panic_in_result_fn,
        clippy::shadow_unrelated,
        clippy::unwrap_used,
        reason = "Tests use straightforward assertions and setup helpers."
    )
)]

// Cargo compiles an integration test target with `--test`, so `cfg(test)` is
// set here and the crate-wide `tests_outside_test_module` lint applies just as
// it does inside `src/`.
#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use uds_daemon::{
        AllowSocketPeers, Authorization, BindError, Caller, FrameworkErrorKind, HttpVerb, Route,
        ServeOutcome, Server, ServerConfig, Service, WireError,
    };

    /// The env var that turns the ignored fixture test below into a daemon.
    const FIXTURE_SOCKET: &str = "UDS_DAEMON_FIXTURE_SOCKET";

    const CHANGE: Route = Route {
        api_path: "/v1/thing/change",
        object: "Thing",
        method: "Change",
        authorization: Authorization::Policy("org.example.thing.change"),
    };

    const READ: Route = Route {
        api_path: "/v1/thing/read",
        object: "Thing",
        method: "Read",
        authorization: Authorization::Unprivileged,
    };

    /// A service with one gated route and one open one, and no idea what either
    /// means.
    #[derive(Debug)]
    struct TestService;

    impl Service for TestService {
        fn name(&self) -> &'static str {
            "testd"
        }

        fn version(&self) -> &'static str {
            "0.0.1"
        }

        fn resolve(&self, verb: HttpVerb, api_path: &str) -> Option<Route> {
            match (verb, api_path) {
                (HttpVerb::Post, "/v1/thing/change") => Some(CHANGE),
                (HttpVerb::Get, "/v1/thing/read") => Some(READ),
                _ => None,
            }
        }

        fn dispatch(
            &self,
            route: Route,
            request: &Value,
            caller: &Caller,
        ) -> Result<Value, WireError> {
            Ok(json!({
                "method": route.method,
                "request": request,
                "caller": caller.to_string(),
            }))
        }

        fn encode_framework_error(&self, kind: FrameworkErrorKind, message: &str) -> WireError {
            WireError::new(
                kind.conventional_status(),
                json!({ "error": { "kind": format!("{kind:?}"), "message": message } }).to_string(),
            )
        }
    }

    fn server_at(socket_path: &Path) -> Result<Server, BindError> {
        Server::bind(
            ServerConfig::new(socket_path),
            Arc::new(TestService),
            Arc::new(AllowSocketPeers),
        )
    }

    fn request(method: &str, path: &str, body: &str) -> String {
        format!(
            "{method} {path} HTTP/1.1\r\nhost: d\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn split_response(response: &str) -> (&str, &str) {
        response
            .split_once("\r\n\r\n")
            .expect("the response had no header terminator")
    }

    // ---------------------------------------------------------------------------
    // In-process: one thread, one connection at a time, no threads needed because
    // a connect(2) that has not been accepted still sits in the listen backlog.
    // ---------------------------------------------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn serves_over_a_real_socket() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("api.sock");
        let server = server_at(&path)?;

        let mut client = UnixStream::connect(&path)?;
        client.set_read_timeout(Some(Duration::from_secs(10)))?;
        client.write_all(request("POST", "/v1/thing/change", r#"{"id":"one"}"#).as_bytes())?;

        let outcome = server.serve_next()?;
        assert!(
            matches!(outcome, ServeOutcome::Answered),
            "a well-formed request was not answered: {outcome:?}"
        );

        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert!(
            response.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected status line: {response}"
        );
        let (headers, body) = split_response(&response);
        assert!(
            headers.contains("content-type: application/json"),
            "{headers}"
        );

        let decoded: Value = serde_json::from_str(body)?;
        assert_eq!(decoded["ok"]["method"], "Change");
        assert_eq!(decoded["ok"]["request"]["id"], "one");
        // The caller came from the kernel, not from the request, so it names this
        // very process.
        let attributed = decoded["ok"]["caller"]
            .as_str()
            .expect("the caller was not a string");
        assert!(
            attributed.contains(&format!("pid {}", std::process::id())),
            "the socket peer was not this process: {attributed}"
        );

        // And the framework answers health itself, with no route resolved.
        let mut probe = UnixStream::connect(&path)?;
        probe.set_read_timeout(Some(Duration::from_secs(10)))?;
        probe.write_all(request("GET", "/v1/status", "").as_bytes())?;
        server.serve_next()?;
        let mut health = String::new();
        probe.read_to_string(&mut health)?;
        assert_eq!(split_response(&health).1, r#"{"ok":{"healthy":true}}"#);
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn truncated_request_is_400() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("api.sock");
        let server = server_at(&path)?;

        let mut client = UnixStream::connect(&path)?;
        client.set_read_timeout(Some(Duration::from_secs(10)))?;
        // A request line and then EOF: bytes arrived, so the peer is still there
        // and is owed an explanation — unlike the connect-and-drop probe below.
        client.write_all(b"POST /v1/thing/change HTTP/1.1\r\n")?;
        client.shutdown(Shutdown::Write)?;

        let outcome = server.serve_next()?;
        assert!(
            matches!(outcome, ServeOutcome::Failed { .. }),
            "a truncated request was not reported as a failure: {outcome:?}"
        );

        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "a truncated request did not get a 400: {response}"
        );
        // The body is the *service's* error envelope, not one the framework made
        // up: a client needs one decoder, not two.
        let decoded: Value = serde_json::from_str(split_response(&response).1)?;
        assert_eq!(decoded["error"]["kind"], "InvalidInput");
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn probe_is_silent() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("api.sock");
        let server = server_at(&path)?;

        let mut client = UnixStream::connect(&path)?;
        client.set_read_timeout(Some(Duration::from_secs(10)))?;
        client.shutdown(Shutdown::Write)?;

        let outcome = server.serve_next()?;
        assert!(
            matches!(outcome, ServeOutcome::Probe),
            "a connect-and-drop was not recognised as a probe: {outcome:?}"
        );

        // No bytes. Writing a 400 to a peer that has already closed fails EPIPE,
        // and the serve loop then logs a broken pipe for what was a successful
        // reachability check.
        let mut answered = Vec::new();
        client.read_to_end(&mut answered)?;
        assert!(
            answered.is_empty(),
            "the probe was answered with {} bytes",
            answered.len()
        );

        // And no log line either — that half is asserted against a real daemon's
        // stderr, since `Server::serve` is what decides to log.
        let (probed, journal) = daemon_journal(dir.path(), |socket| {
            let quiet = UnixStream::connect(socket)?;
            quiet.shutdown(Shutdown::Write)?;
            drop(quiet);
            // A real request afterwards, so the daemon has demonstrably kept
            // serving and stderr has demonstrably been reachable.
            call(socket, request("GET", "/v1/thing/read", ""))
        })?;
        assert!(probed.starts_with("HTTP/1.1 200 OK\r\n"), "{probed}");
        assert!(
            !journal.contains("request failed"),
            "the probe planted a failure line: {journal}"
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn request_timeout_is_not_inherited_from_the_listener() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("api.sock");
        let mut config = ServerConfig::new(&path);
        config.request_read_timeout = Duration::from_millis(200);
        let server = Server::bind(config, Arc::new(TestService), Arc::new(AllowSocketPeers))?;

        // What `Server::serve` does when systemd configures a watchdog: put
        // SO_RCVTIMEO on the LISTENER so accept() wakes to pet it. On Linux an
        // accepted socket inherits SOL_SOCKET options, so without an explicit
        // deadline on the accepted stream every request read would silently be
        // budgeted at the heartbeat interval — a number picked for something else.
        server.set_accept_timeout(Duration::from_secs(60))?;

        // A client that connects and then says nothing at all.
        let _mute = UnixStream::connect(&path)?;

        let started = Instant::now();
        let outcome = server.serve_next()?;
        let waited = started.elapsed();

        assert!(
            matches!(outcome, ServeOutcome::Failed { .. }),
            "a silent client was not timed out: {outcome:?}"
        );
        assert!(
            waited >= Duration::from_millis(150),
            "the request budget was not honoured at all ({waited:?})"
        );
        assert!(
            waited < Duration::from_secs(10),
            "the accepted socket inherited the listener's 60s timeout ({waited:?})"
        );
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn stale_socket_is_reclaimed() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("api.sock");

        // A crashed predecessor: the listener is gone, the inode is not. std does
        // not unlink on drop, which is exactly the situation being reproduced.
        //
        // Bound in a child that then exits, rather than here, so that no file
        // descriptor for it can exist anywhere — including in the brief window
        // between `fork` and `exec` inside a sibling test's `Command::spawn`, where
        // a descriptor this process holds is briefly held by another process too,
        // and a "stale" socket would answer a connect.
        let mut maker = spawn_ignored("tests::the_stale_socket_maker", &path)?;
        let made = maker.wait()?;
        assert!(made.success(), "the stale-socket fixture failed: {made}");
        assert!(
            path.exists(),
            "the socket file did not outlive its listener"
        );
        assert_eq!(
            UnixStream::connect(&path).map(|_| ()).unwrap_err().kind(),
            std::io::ErrorKind::ConnectionRefused,
            "a stale socket answered a connect"
        );

        let server = server_at(&path)?;
        assert_eq!(server.socket_path(), path);

        // A live one is a different thing, and is left alone.
        let refused = server_at(&path).expect_err("a live socket was taken from under its daemon");
        assert!(
            matches!(refused, BindError::AlreadyActive(_)),
            "the wrong refusal for a live socket: {refused}"
        );
        assert!(path.exists(), "a live socket was unlinked");

        // The reclaim test is a connect(2), so the refusal above left a connection
        // in this daemon's backlog. That is the whole reason a connect-and-drop is
        // answered with silence: the daemon is being asked "are you there" by its
        // own would-be successor, and it must not start a conversation.
        let probe = server.serve_next()?;
        assert!(
            matches!(probe, ServeOutcome::Probe),
            "the reclaim check was not seen as a probe: {probe:?}"
        );

        // The live daemon is still serving after the failed second bind.
        let mut client = UnixStream::connect(&path)?;
        client.set_read_timeout(Some(Duration::from_secs(10)))?;
        client.write_all(request("GET", "/v1/status", "").as_bytes())?;
        server.serve_next()?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        Ok(())
    }

    // ---------------------------------------------------------------------------
    // Out of process: the audit trail is stderr, so a child process is the only
    // honest way to read it.
    // ---------------------------------------------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn audit_names_the_caller() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (response, journal) = daemon_journal(dir.path(), |socket| {
            call(
                socket,
                request("POST", "/v1/thing/change", r#"{"id":"one"}"#),
            )
        })?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");

        // Two lines per operation: announced before it runs, reported when it
        // finishes. One line would leave an operation that never returns invisible.
        assert!(
            journal.contains("testd: audit: begin /v1/thing/change"),
            "no begin line in:\n{journal}"
        );
        assert!(
            journal.contains("testd: audit: ok /v1/thing/change"),
            "no completion line in:\n{journal}"
        );
        // The action id, so an operator can see which policy governed the call.
        assert!(
            journal.contains("action=org.example.thing.change"),
            "the line did not name the action:\n{journal}"
        );
        // And `by=`, naming THIS process — the kernel's answer, taken from the
        // socket, not a claim in the request.
        assert!(journal.contains("by="), "no attribution in:\n{journal}");
        assert!(
            journal.contains(&format!("pid {}", std::process::id())),
            "the trail did not name this process ({}):\n{journal}",
            std::process::id()
        );

        // A read produces no line at all. The restraint is the point: front-ends
        // poll, and a flood evicts the operations worth keeping.
        let (_read, quiet) = daemon_journal(dir.path(), |socket| {
            call(socket, request("GET", "/v1/thing/read", ""))
        })?;
        assert!(
            !quiet.contains("audit:"),
            "an unprivileged read was audited:\n{quiet}"
        );
        Ok(())
    }

    /// Run the daemon in a child process, do something to it, and return what it
    /// said on stderr.
    fn daemon_journal(
        dir: &Path,
        exchange: impl FnOnce(&Path) -> std::io::Result<String>,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        let socket = dir.join(format!("fixture-{}.sock", unique()));
        let mut child = spawn_fixture(&socket)?;
        let outcome = wait_for_socket(&socket).and_then(|()| exchange(&socket));

        // The fixture serves forever, so it is stopped rather than waited on.
        // Killing before reading is safe here: the pipe holds far more than the
        // handful of lines this daemon writes.
        child.kill()?;
        child.wait()?;
        let mut journal = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            stderr.read_to_string(&mut journal)?;
        }
        Ok((outcome?, journal))
    }

    fn spawn_fixture(socket: &Path) -> std::io::Result<Child> {
        spawn_ignored("tests::the_fixture_daemon", socket)
    }

    /// Re-run this very test binary, asking it for one of the ignored fixtures
    /// below.
    fn spawn_ignored(fixture: &str, socket: &Path) -> std::io::Result<Child> {
        Command::new(std::env::current_exe()?)
            .args([
                fixture,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env(FIXTURE_SOCKET, socket)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
    }

    fn wait_for_socket(socket: &Path) -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if socket.exists() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err(std::io::Error::other(format!(
            "the fixture daemon never bound {}",
            socket.display()
        )))
    }

    fn call(socket: &Path, wire: String) -> std::io::Result<String> {
        let mut client = UnixStream::connect(socket)?;
        client.set_read_timeout(Some(Duration::from_secs(20)))?;
        client.write_all(wire.as_bytes())?;
        let mut response = String::new();
        client.read_to_string(&mut response)?;
        Ok(response)
    }

    fn unique() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos())
    }

    /// Not a test: the daemon the tests above spawn.
    ///
    /// It lives in this binary because a library crate should not ship a helper
    /// executable to make its own tests possible, and `#[ignore]` plus an env var
    /// is what keeps it out of an ordinary run — including `--ignored`, where it
    /// returns immediately for want of a socket path.
    #[test]
    #[ignore = "not a test: the daemon fixture the audit and probe tests spawn"]
    fn the_fixture_daemon() {
        let Ok(socket) = std::env::var(FIXTURE_SOCKET) else {
            return;
        };
        let server = server_at(&PathBuf::from(socket)).expect("the fixture daemon could not bind");
        server.serve().expect("the fixture daemon stopped serving");
    }

    /// Not a test: leaves a socket file behind with nothing listening on it, the
    /// way a `SIGKILL`ed daemon does.
    #[test]
    #[ignore = "not a test: the stale socket the reclaim test needs"]
    fn the_stale_socket_maker() {
        let Ok(socket) = std::env::var(FIXTURE_SOCKET) else {
            return;
        };
        let listener =
            UnixListener::bind(&socket).expect("the stale-socket fixture could not bind");
        // Explicit, because the point of this process is what it leaves behind:
        // the descriptor closes here and the inode does not.
        drop(listener);
    }
}
