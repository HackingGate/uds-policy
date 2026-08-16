# uds-policy

The half of a privileged Unix-socket daemon that has nothing to do with the wire
it speaks.

A daemon behind an `AF_UNIX` socket has to answer questions that no protocol
answers for it:

| Question | Here |
| --- | --- |
| Whose socket is this, and is it stale? | `Socket`, `SocketConfig` |
| Who is calling? | `Caller`, read by `Socket::accept` before the first request byte |
| May they? | `Authorizer`, `PeerGate`, `Denial` |
| What happened, and who did it? | `Operation` |
| Is the daemon wedged, or merely busy? | `watchdog` |

One dependency (`nix`), no `unsafe`, no `async`, no runtime, and no opinion
whatsoever about the bytes on the socket.

## There is no serve loop, and there will not be one

This crate used to ship one — an HTTP/1.1 reader, a router, a dispatch pipeline
— and that was the half that made it unusable by its second consumer. A serve
loop has to pick a wire format, and picking one forecloses every consumer that
picked differently.

So the daemon owns its accept loop and speaks whatever it likes over the streams
`Socket::accept` hands it: varlink, HTTP over a Unix socket, a length-prefixed
frame, a line. What is left here is wire-agnostic by construction, which is the
only reason two daemons that disagree about their protocol can share it.

This is not a staging post. The serve loop does not come back later, in any
form, for any consumer.

## Quickstart

```rust
use uds_policy::{Authorizer, Call, Operation, PeerGate, Socket, SocketConfig, watchdog};

const CHANGE: Call = Call::gated("Thing", "Change", "org.example.thing.change");

let socket = Socket::bind(
    SocketConfig::new("exampled", "/run/example/api.sock").with_socket_group("example"),
)?;
let authorizer = PeerGate::for_gids([gid_of_the_example_group]);
watchdog::notify_ready();

loop {
    // The caller comes back with the stream, before a byte is read from it.
    let (mut stream, caller) = socket.accept()?;

    if let Err(denial) = authorizer.authorize(CHANGE, &caller) {
        eprintln!("exampled: refused: {}", denial.reason);
        continue;
    }

    let audit = Operation::begin("exampled", CHANGE, &caller);
    let outcome = speak_your_protocol(&mut stream);   // yours, not this crate's
    audit.finish(outcome.as_ref().err().map(String::as_str));
}
```

On the daemon's stderr:

```text
exampled: audit: begin Thing.Change action=org.example.thing.change by=you(uid 1000 gid 1000 pid 4711)
exampled: audit: ok Thing.Change action=org.example.thing.change by=you(uid 1000 gid 1000 pid 4711) (0ms)
```

`examples/gatekeeper.rs` is that daemon, running. `cargo run --example
gatekeeper -- --self-test` drives it end to end in one process.

## The seam is data, not a trait

The obvious design parameterises a `Service` trait over an associated `Method`
type. It reads better right up to the moment someone tries to implement it: the
crate that owns a daemon's wire contract would have to depend on **this** crate
in order to name the trait — and that inverts the dependency direction that
splitting this out exists to establish. A contract must be describable with no
knowledge that any particular server exists.

So the seam is a struct the contract crate fills in:

```rust
pub struct Call {
    pub object: &'static str,          // the noun, in the contract's spelling
    pub method: &'static str,          // the verb, in the contract's spelling
    pub authorization: Authorization,  // Unprivileged | Policy(&'static str)
}
```

The consequence is the point: this crate never interprets a call. It compares
`Authorization` tags, prints action ids into the audit trail, and hands the
`Call` back to the code that produced it. It cannot make a decision that depends
on what a call *means*, because it is never told.

A reverse-DNS interface name in `object` renders as the fully qualified member
name a protocol like varlink already uses — `com.example.Thing.Change` — without
this crate knowing that is what it did.

## Authorization

`Authorizer::authorize` receives both the call and the caller, and is meant to be
consulted for **every** call rather than only the gated ones. Both halves matter:
an authorizer that sees only the call can decide whether a *kind* of call is
allowed and never whether *this party* may make it, which leaves the socket's
file mode as the daemon's entire identity check.

Three are shipped:

| Authorizer | Decides |
| --- | --- |
| `AllowSocketPeers` | Reaching the socket is the whole gate — right when the gate really is `0660 root:<group>`. |
| `DenyAll` | Nothing, naming the action id it would have needed. The safe default before a real authorizer is wired. |
| `PeerGate` | A uid or gid allow-list, plus what to do about a caller the kernel would not report. |

`PeerGate` matches the caller's **primary** gid, because that is the one gid
`SO_PEERCRED` carries. A deployment whose policy is "a member of group *g*,
including as a supplementary group" writes its own `Authorizer` that resolves the
membership through NSS — a policy this crate has no way to guess and no business
hard-coding. That the seam takes the caller is what makes writing one possible at
all.

## Busy is not wedged

Under `Type=notify` with `WatchdogSec=<N>`, pets come from a dedicated heartbeat
thread that reads a `ServeActivity` the accept loop stamps. Petting from the loop
itself makes a daemon go silent exactly while it is doing the most work, and
systemd `SIGABRT`s it mid-operation.

A call declares its shape, because one ceiling cannot cover both:

| Shape | Judged by |
| --- | --- |
| `InFlight::Bounded` | Total duration, against `longest_bounded_call`. A slow privileged operation is busy, not wedged. |
| `InFlight::Streaming` | Progress, never duration. A subscription holds the connection open by design. |

`longest_silent_stream` therefore defaults to `None`. A ceiling on an open stream
kills a healthy subscription every time the thing it watches is quiet — which is
precisely when the subscription is most obviously working. A daemon whose streams
carry a keepalive of their own can opt in.

## Behaviour that looks redundant and is not

Every item here was once absent, and each reads like a line worth deleting right
up until it is deleted.

- **The caller is read before the request.** Nothing a request carries can
  establish who sent it — a field naming the sender is a claim by the party being
  identified. `SO_PEERCRED` is filled in by the kernel at `connect(2)` time and
  cannot be forged or changed afterwards. `Socket::accept` returns the stream and
  the caller together, so the ordering cannot be got wrong at a call site, and a
  truncated or malformed request is still attributable.
- **An unreadable caller says so.** A `by=` that silently disappears when the
  lookup fails reads exactly like a line written before the daemon recorded
  callers at all, and a trail whose gaps are invisible is worse than no trail.
- **The accepted stream gets its own read deadline.** Linux inherits the
  listener's `SO_RCVTIMEO`, and the listener carries one whenever the watchdog
  armed `set_accept_timeout` so an idle loop still turns — so without an explicit
  deadline the request budget is silently `WatchdogSec/2`, a number chosen for
  something else. `SocketConfig::request_read_timeout` is applied per connection,
  and setting it to `None` *clears* the inherited value rather than leaving it.
- **A stale socket is unlinked only once proven stale.** `ECONNREFUSED` on an
  existing socket file means the listener is gone and the inode outlived it —
  what a crash leaves behind. A live one, a non-socket, and one that could not be
  checked are all left exactly where they are.
- **A connect-and-drop probe is an ordinary accept.** The stale-socket reclaim
  *is* that probe, so every daemon is probed by its own successor's startup
  check. A daemon that wrote bytes back would be answering that check; one that
  logged an error would plant a line on every front-end launch.
- **Reads produce no audit line.** Front-ends poll every few seconds, and the
  flood *is* the loss: it evicts the operations worth keeping. `Operation` is
  constructed for every call and silent for the unprivileged ones, so a dispatch
  site needs no `if` and cannot drift out of step with the policy tag.
- **No payload content reaches the journal.** The daemon this came from built a
  target string from an allowlist of identifying keys, which works and is domain
  knowledge — the allowlist is a list of *that contract's* field names. A general
  layer shipping one would be carrying a consumer's vocabulary. A daemon that
  wants a target in the trail is the only party that can tell an identifying
  field from a revealing one.
- **The uid→name memoisation takes two scoped locks** and never holds one across
  the NSS call; a failed lookup is deliberately not cached while an absent uid is;
  names are bounded and stripped of newlines so a directory-supplied name cannot
  forge a journal line.

## Why `nix`, and not the bridge this code came from

The daemon this was extracted from reaches `SO_PEERCRED` and NSS through a
private in-house bridge. This crate uses
`nix::sys::socket::getsockopt(…, PeerCredentials)` and
`nix::unistd::{User, Group}` instead, for three independent reasons — any one of
which would be enough:

1. The bridge lives in a **private** repository. A public crate cannot depend on
   it, and a public crate that could would be publishing a build failure.
2. It is **Zig-backed**. Depending on it would drag a second toolchain into every
   consumer of a crate whose entire dependency set is otherwise one published
   crate.
3. `nix` satisfies the same constraint the bridge was built for. This crate sets
   `unsafe_code = "deny"`, and `UnixStream::peer_cred` is still nightly-only, so
   *some* safe wrapper is required — `nix` is one, and it is already in the
   ecosystem.

## Building

```console
cargo build --locked
cargo test --locked
cargo run --example gatekeeper -- --self-test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Most tests touch a real socket and are `#[cfg_attr(miri, ignore)]`d; what Miri
still runs is the liveness arithmetic and the sanitisers, where a finding would
be a real one. The test that asserts on the *audit trail* runs a daemon in a
child process and reads its stderr, because a process cannot read its own stderr
without `unsafe`, and asserting on a log line by calling the function that
formats it proves only that the formatter formats.

`Cargo.lock` is committed. The usual advice leaves a library's lock file out, but
that advice is about what downstream builds resolve, and a consumer's own lock
file still wins; committing this one buys a reproducible CI run and a bisectable
history.

## License

Apache-2.0. See [LICENSE](LICENSE).
