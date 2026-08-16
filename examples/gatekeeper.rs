//! A complete policy layer with no protocol under it.
//!
//! The daemon this replaced demonstrated a serve loop, which is exactly the
//! thing this crate no longer has. So this one demonstrates the four questions
//! it *does* answer — whose socket, who is calling, may they, and what
//! happened — and treats the bytes as an implementation detail, because to this
//! crate they are one.
//!
//! **The two lines that move bytes are a placeholder.** `read_to_end` and
//! `write_all` are the least protocol it is possible to have; a real daemon
//! puts varlink, HTTP over a Unix socket, or a length-prefixed frame in their
//! place and changes nothing else on this page.
//!
//! ```console
//! $ cargo run --example gatekeeper -- /tmp/gatekeeper.sock
//! echod: serving on /tmp/gatekeeper.sock
//! ```
//!
//! and from another shell, with anything that can write to a Unix socket:
//!
//! ```console
//! $ printf 'hello' | socat - UNIX-CONNECT:/tmp/gatekeeper.sock
//! Thing.Change said: hello
//! ```
//!
//! `--self-test` runs both halves in one process and exits, which is how CI
//! keeps this file honest without needing a client on the runner.

use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;
use uds_policy::{Authorizer, Call, Caller, Operation, PeerGate, Socket, SocketConfig, watchdog};

/// The daemon's name. One string, used by the socket's log lines and by every
/// audit line, so a journal filter finds both.
const DAEMON: &str = "echod";

/// The one thing this daemon can be asked to do, named in its own vocabulary.
/// It is gated, so it is audited; an `unprivileged` call would be neither.
const CHANGE: Call = Call::gated("Thing", "Change", "org.example.thing.change");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("--self-test") {
        return self_test();
    }
    let socket_path = first.unwrap_or_else(|| "/tmp/uds-policy-gatekeeper.sock".to_owned());
    serve(&socket_path, None)
}

/// Bind, then answer connections until something stops the process.
///
/// `limit` is how many connections to serve before returning; `None` is
/// forever, and is what a real daemon passes.
fn serve(socket_path: &str, limit: Option<usize>) -> Result<(), Box<dyn std::error::Error>> {
    // A real deployment names a group here — `with_socket_group("example")` —
    // so an unprivileged front-end can open a root-owned socket. The example
    // does not, because a throwaway socket in /tmp has no group to be given to.
    let socket = Socket::bind(SocketConfig::new(DAEMON, socket_path))?;

    // The gate. `PeerGate::for_uids` matches the kernel's answer, not a claim
    // in the request; a daemon whose policy is "a member of group g" writes its
    // own `Authorizer` because SO_PEERCRED carries only the primary gid.
    let authorizer = PeerGate::for_uids([nix_uid()]);

    // ONE record, shared: the heartbeat thread reads what this loop stamps.
    // Handing `spawn_heartbeat` a record nobody updates is the shape that kills
    // a healthy daemon — with an idle ceiling armed, the pets stop three
    // intervals after startup and systemd restarts a process that is serving
    // perfectly well.
    let activity = watchdog::ServeActivity::new();

    // A no-op unless systemd started this with Type=notify.
    watchdog::notify_ready();
    if let Some(interval) = watchdog::heartbeat_interval() {
        // Arming the accept timeout is what lets the idle-tick check be safe:
        // without it an idle loop blocks in accept() forever and never stamps a
        // tick, so the ceiling would judge a healthy daemon by a clock it has
        // no way to advance.
        let liveness = match socket.set_accept_timeout(interval) {
            Ok(()) => watchdog::Liveness::new().with_idle_tick_ceiling(interval * 3),
            Err(error) => {
                eprintln!("{DAEMON}: watchdog accept timeout unavailable: {error}");
                watchdog::Liveness::new()
            }
        };
        watchdog::spawn_heartbeat(interval, liveness, Arc::clone(&activity));
    }

    eprintln!("{DAEMON}: serving on {socket_path}");
    let mut served = 0_usize;
    while limit.is_none_or(|max| served < max) {
        match socket.accept() {
            Ok((stream, caller)) => {
                // Bounded: this daemon answers and returns. A subscription
                // would open with `InFlight::Streaming` and stamp
                // `activity.progressed()` per reply, so that holding the
                // connection open reads as working rather than as wedged.
                activity.call_started(watchdog::InFlight::Bounded);
                answer(stream, &caller, &authorizer);
                activity.call_finished();
                served = served.saturating_add(1);
            }
            // A single client failing must never take down a privileged
            // daemon. Log it and keep serving.
            Err(error) => {
                // An expected idle wakeup once the accept timeout is armed, not
                // a failure — but it still turns the loop, and the tick below
                // is what says so.
                if !matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) {
                    eprintln!("{DAEMON}: accept failed: {error}");
                }
            }
        }
        // Stamped every turn, so the heartbeat thread can tell an idle loop
        // (turning through accept timeouts) from one that has stopped.
        activity.tick();
    }
    Ok(())
}

/// Authorize, audit, and answer one connection.
fn answer(mut stream: UnixStream, caller: &Caller, authorizer: &dyn Authorizer) {
    if let Err(denial) = authorizer.authorize(CHANGE, caller) {
        // The refusal is decided before a byte of the request is read, so it
        // costs nothing and reveals nothing about the payload. How it reaches
        // the client is the daemon's business — this one writes the reason.
        eprintln!("{DAEMON}: refused {CHANGE} for {caller}: {}", denial.reason);
        if let Err(_gone) = writeln!(stream, "refused: {}", denial.reason) {}
        return;
    }

    // Announced before the work runs, so an operation that never returns is
    // still on the record. Unprivileged calls produce an Operation that writes
    // nothing, so this line needs no `if` around it.
    let audit = Operation::begin(DAEMON, CHANGE, caller);
    let outcome = exchange(&mut stream, caller);
    audit.finish(outcome.as_ref().err().map(String::as_str));
}

/// The placeholder protocol: read what the client sent, say it back.
fn exchange(stream: &mut UnixStream, caller: &Caller) -> Result<(), String> {
    let mut said = Vec::new();
    // The read deadline came from SocketConfig, applied by Socket::accept —
    // not inherited from the listener, which is the accident that field exists
    // to prevent.
    stream
        .read_to_end(&mut said)
        .map_err(|error| format!("the request could not be read: {error}"))?;
    let said = String::from_utf8_lossy(&said);
    writeln!(stream, "{CHANGE} said: {said}")
        .map_err(|error| format!("the reply could not be written: {error}"))?;
    // Nothing from the payload reaches the journal; the caller does.
    eprintln!("{DAEMON}: answered {caller}");
    Ok(())
}

/// This process's own uid, so the example's gate admits the person running it.
fn nix_uid() -> u32 {
    // A real daemon reads its allow-list from configuration. This one asks the
    // kernel about itself so the example works on any machine.
    UnixStream::pair()
        .ok()
        .and_then(|(here, _there)| Caller::of_socket(&here).uid())
        .unwrap_or(0)
}

/// Serve one connection and drive it from a thread, so `cargo run --example
/// gatekeeper -- --self-test` proves the whole path without a client on the
/// runner.
fn self_test() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("uds-policy-self-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let socket_path = dir.join("gatekeeper.sock");
    let path_string = socket_path
        .to_str()
        .ok_or("non-utf8 temporary directory")?
        .to_owned();

    let client_path = socket_path.clone();
    let client = std::thread::spawn(move || -> std::io::Result<String> {
        // Wait for the daemon thread to bind before connecting.
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while !client_path.exists() {
            if std::time::Instant::now() > deadline {
                return Err(std::io::Error::other("the daemon never bound its socket"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut stream = UnixStream::connect(&client_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(20)))?;
        stream.write_all(b"hello")?;
        // Half-close so the daemon's read_to_end returns. A framed protocol
        // would not need this; the placeholder does.
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut reply = String::new();
        stream.read_to_string(&mut reply)?;
        Ok(reply)
    });

    serve(&path_string, Some(1))?;
    let reply = client
        .join()
        .map_err(|_panicked| "the self-test client panicked")??;
    std::fs::remove_dir_all(&dir)?;

    if !reply.contains("said: hello") {
        return Err(format!("the daemon did not answer: {reply:?}").into());
    }
    // And the gate is real. This has to exercise the SAME authorizer `serve`
    // runs, not a stand-in: a check against `DenyAll` passes whatever `PeerGate`
    // does, so a regression that made the real gate admit unidentified callers
    // would leave the self-test green.
    let gate = PeerGate::for_uids([nix_uid()]);
    let unreadable = Caller::Unreadable("Socket operation on non-socket".to_owned());
    if gate.authorize(CHANGE, &unreadable).is_ok() {
        return Err("the gate admitted a caller the kernel would not report".into());
    }
    let stranger = Caller::Peer {
        pid: 1,
        uid: nix_uid().wrapping_add(1),
        gid: 0,
    };
    if gate.authorize(CHANGE, &stranger).is_ok() {
        return Err("the gate admitted an unlisted uid".into());
    }
    println!("{DAEMON}: self-test ok: {}", reply.trim());
    Ok(())
}
