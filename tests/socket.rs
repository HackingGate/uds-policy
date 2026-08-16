//! The policy layer over a real socket.
//!
//! Everything here that matters happens between two file descriptors, so
//! nothing here can run under Miri — see the `cfg_attr(miri, ignore)` on every
//! test. The test that asserts on the *journal* runs a daemon in a child
//! process and reads its stderr, because the audit trail is a side effect on a
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
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    use uds_policy::{Call, Caller, Operation, Socket, SocketConfig};

    /// The env var that turns the ignored fixtures below into daemons.
    const FIXTURE_SOCKET: &str = "UDS_POLICY_FIXTURE_SOCKET";

    const CHANGE: Call = Call::gated("Thing", "Change", "org.example.thing.change");
    const READ: Call = Call::unprivileged("Thing", "Read");

    fn socket_at(path: &Path) -> Result<Socket, Box<dyn std::error::Error>> {
        Ok(Socket::bind(SocketConfig::new("testd", path))?)
    }

    // -----------------------------------------------------------------------
    // In-process: one thread, one connection at a time. No threads needed,
    // because a connect(2) that has not been accepted still sits in the listen
    // backlog.
    // -----------------------------------------------------------------------

    /// The property the whole crate is built around: the connection arrives
    /// already attributed, so no call site can read a request byte first and
    /// then discover it cannot say who sent it.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn accept_answers_who_is_calling() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let socket = socket_at(&dir.path().join("api.sock"))?;

        let mut client = UnixStream::connect(socket.path())?;
        client.write_all(b"anything at all")?;
        client.shutdown(Shutdown::Write)?;

        let (mut stream, caller) = socket.accept()?;
        let Caller::Peer { pid, .. } = caller else {
            return Err(format!("the connection was not attributed: {caller:?}").into());
        };
        assert_eq!(
            pid,
            i32::try_from(std::process::id())?,
            "attributed to the wrong process"
        );

        // And it is a usable stream, not just an answer about one.
        let mut said = String::new();
        stream.read_to_string(&mut said)?;
        assert_eq!(said, "anything at all");
        Ok(())
    }

    /// Linux inherits the listener's `SO_RCVTIMEO` onto accepted sockets, so a
    /// daemon that arms an accept timeout for the watchdog would silently get
    /// that interval as its request budget — a number chosen for something
    /// else. `accept` overwrites it per connection; this is that assertion.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn the_read_deadline_is_not_inherited_from_the_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let budget = Duration::from_secs(7);
        let socket = Socket::bind(
            SocketConfig::new("testd", dir.path().join("api.sock"))
                .with_request_read_timeout(Some(budget)),
        )?;
        // The listener carries a *different* timeout, the way it does when a
        // watchdog heartbeat armed it.
        socket.set_accept_timeout(Duration::from_secs(2))?;

        let _client = UnixStream::connect(socket.path())?;
        let (stream, _caller) = socket.accept()?;
        assert_eq!(
            stream.read_timeout()?,
            Some(budget),
            "the accepted stream inherited the listener's accept timeout"
        );
        Ok(())
    }

    /// Clearing the deadline has to be explicit, not a leftover: a `None`
    /// config must clear the inherited value rather than leave it in place.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn clearing_the_read_deadline_clears_the_inherited_one()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let socket = Socket::bind(
            SocketConfig::new("testd", dir.path().join("api.sock")).with_request_read_timeout(None),
        )?;
        socket.set_accept_timeout(Duration::from_secs(2))?;

        let _client = UnixStream::connect(socket.path())?;
        let (stream, _caller) = socket.accept()?;
        assert_eq!(
            stream.read_timeout()?,
            None,
            "an explicitly cleared deadline kept the listener's"
        );
        Ok(())
    }

    /// The stale-socket reclaim *is* a connect-and-drop, so every daemon gets
    /// probed by its own successor's startup check. It must arrive as an
    /// ordinary accept that reads zero bytes, never as a failure.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn a_connect_and_drop_probe_is_an_ordinary_accept() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let socket = socket_at(&dir.path().join("api.sock"))?;

        drop(UnixStream::connect(socket.path())?);

        let (mut stream, caller) = socket.accept()?;
        assert!(matches!(caller, Caller::Peer { .. }), "{caller:?}");
        let mut nothing = Vec::new();
        assert_eq!(stream.read_to_end(&mut nothing)?, 0);
        Ok(())
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn the_bound_socket_has_the_mode_an_unprivileged_front_end_needs()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let socket = socket_at(&dir.path().join("api.sock"))?;
        let mode = std::fs::metadata(socket.path())?.permissions().mode();
        assert_eq!(mode & 0o777, 0o660, "the socket was bound {mode:o}");
        Ok(())
    }

    /// A clean shutdown must not leave an inode behind for the next start to
    /// have to reason about.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn the_socket_is_unlinked_on_drop() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("api.sock");
        {
            let socket = socket_at(&path)?;
            assert!(socket.path().exists());
        }
        assert!(!path.exists(), "a dropped socket left its path behind");
        Ok(())
    }

    /// A socket file left by a `SIGKILL`ed predecessor is reclaimed; the
    /// process that left it has to be a real one, because the whole test is
    /// whether an inode that outlived its listener is recognised.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn a_stale_socket_is_reclaimed() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(format!("stale-{}.sock", unique()));

        let mut maker = spawn_ignored("tests::the_stale_socket_maker", &path)?;
        maker.wait()?;
        assert!(path.exists(), "the fixture left no socket behind");

        let socket = socket_at(&path)?;
        assert!(socket.path().exists());
        // And it works, which is the part that proves the old inode is gone
        // rather than merely still present.
        let _client = UnixStream::connect(socket.path())?;
        let (_stream, caller) = socket.accept()?;
        assert!(matches!(caller, Caller::Peer { .. }), "{caller:?}");
        Ok(())
    }

    /// A live daemon must never have its socket taken from under it, because
    /// unlinking one silently disconnects every client it has.
    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn a_live_socket_is_not_reclaimed() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("live.sock");
        let first = socket_at(&path)?;

        let error = socket_at(&path).expect_err("a live socket was taken from under its owner");
        assert!(error.to_string().contains("already serving"), "{error}");
        assert!(first.path().exists());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Out of process: the audit trail is stderr, so a child process is the only
    // honest way to read it.
    // -----------------------------------------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]
    fn audit_names_the_caller() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let (reply, journal) = daemon_journal(dir.path(), |socket| call(socket, "change"))?;
        assert!(reply.contains("Thing.Change"), "{reply}");

        // Two lines per operation: announced before it runs, reported when it
        // finishes. One line would leave an operation that never returns
        // invisible.
        assert!(
            journal.contains("testd: audit: begin Thing.Change"),
            "no begin line in:\n{journal}"
        );
        assert!(
            journal.contains("testd: audit: ok Thing.Change"),
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

        // An unprivileged call produces no line at all. The restraint is the
        // point: front-ends poll, and a flood evicts the operations worth
        // keeping.
        let (_read, quiet) = daemon_journal(dir.path(), |socket| call(socket, "read"))?;
        assert!(
            !quiet.contains("audit:"),
            "an unprivileged call was audited:\n{quiet}"
        );
        Ok(())
    }

    /// Run the daemon in a child process, do something to it, and return what
    /// it said on stderr.
    fn daemon_journal(
        dir: &Path,
        exchange: impl FnOnce(&Path) -> std::io::Result<String>,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        let socket = dir.join(format!("fixture-{}.sock", unique()));
        let mut child = spawn_ignored("tests::the_fixture_daemon", &socket)?;
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

    fn call(socket: &Path, wire: &str) -> std::io::Result<String> {
        let mut client = UnixStream::connect(socket)?;
        client.set_read_timeout(Some(Duration::from_secs(20)))?;
        client.write_all(wire.as_bytes())?;
        client.shutdown(Shutdown::Write)?;
        let mut reply = String::new();
        client.read_to_string(&mut reply)?;
        Ok(reply)
    }

    fn unique() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos())
    }

    /// Not a test: the daemon the audit test spawns.
    ///
    /// It lives in this binary because a library crate should not ship a helper
    /// executable to make its own tests possible, and `#[ignore]` plus an env
    /// var is what keeps it out of an ordinary run — including `--ignored`,
    /// where it returns immediately for want of a socket path.
    ///
    /// The "protocol" is one word, which is the point: this crate has no
    /// opinion about the bytes, so its own tests must not need one either.
    #[test]
    #[ignore = "not a test: the daemon fixture the audit test spawns"]
    fn the_fixture_daemon() {
        let Ok(path) = std::env::var(FIXTURE_SOCKET) else {
            return;
        };
        let socket = Socket::bind(SocketConfig::new("testd", PathBuf::from(path)))
            .expect("the fixture daemon could not bind");
        loop {
            let (mut stream, caller) = socket.accept().expect("the fixture daemon lost its socket");
            let mut asked = String::new();
            let read = stream.read_to_string(&mut asked);
            let call = if asked.trim() == "change" {
                CHANGE
            } else {
                READ
            };
            let audit = Operation::begin("testd", call, &caller);
            let failure = read.err().map(|error| error.to_string());
            if failure.is_none() {
                let _written = writeln!(stream, "{call} ok");
            }
            audit.finish(failure.as_deref());
        }
    }

    /// Not a test: leaves a socket file behind with nothing listening on it,
    /// the way a `SIGKILL`ed daemon does.
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
