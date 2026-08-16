# uds-daemon

A daemon framework for HTTP/JSON over `AF_UNIX`, which knows nothing about what
it serves.

It is the half of a privileged Unix-socket daemon that is the same whatever the
daemon does:

- **Socket lifecycle** — bind, `0660` plus a group so an unprivileged front-end
  can open it, and a stale-socket reclaim that unlinks only what it has proven
  is dead.
- **Caller identity** — `SO_PEERCRED` read from the accepted socket *before the
  first request byte*, so a malformed request is still attributable and no
  header can claim to be someone.
- **A pipeline** — resolve → authorize → parse → audit → dispatch, in that
  order, stated once.
- **An authorization seam** that receives the caller, so a uid/gid gate is
  expressible rather than merely describable.
- **An audit trail** that names the operation, the action id and who asked.
- **A systemd watchdog** that can tell *busy* from *wedged*.
- **The `{"ok"}` / `{"error"}` envelope.**

It contains no client. That is deliberate: a client's framing is a client's
business, and a generic one would immediately need to know what the daemon
serves.

## Quickstart

```console
$ cargo run --example echo-service -- /tmp/echo.sock
echod: serving on /tmp/echo.sock
```

```console
$ curl --unix-socket /tmp/echo.sock -sS http://d/v1/status
{"ok":{"healthy":true}}

$ curl --unix-socket /tmp/echo.sock -sS http://d/v1/version
{"ok":{"name":"echod","version":"0.1.0"}}

$ curl --unix-socket /tmp/echo.sock -sS -X POST http://d/v1/echo/say -d '{"hello":"world"}'
{"ok":{"said":{"hello":"world"},"to":"you(uid 1000 gid 1000 pid 4711)"}}
```

and on the daemon's stderr:

```text
echod: audit: begin /v1/echo/say action=org.example.echo.say by=you(uid 1000 gid 1000 pid 4711)
echod: audit: ok /v1/echo/say action=org.example.echo.say by=you(uid 1000 gid 1000 pid 4711) (0ms)
```

`examples/echo-service.rs` is the whole daemon, in about sixty lines.

## The seam is concrete on purpose

The obvious design parameterises `Service` over an associated `Method` type and
an associated `Error` type. It reads better right up to the moment someone tries
to implement it: the crate that owns a daemon's wire contract would have to
depend on **this** crate in order to name those traits — and that inverts the
dependency direction that splitting the framework out exists to establish. A
contract must be able to describe its own methods and its own error envelope
with no knowledge that any particular server exists.

So the seam is data:

```rust
pub struct Route {
    pub api_path: &'static str,
    pub object: &'static str,
    pub method: &'static str,
    pub authorization: Authorization,   // Unprivileged | Policy(&'static str)
}

pub struct WireError { pub status: u16, pub body: String }   // already encoded
```

The consequence is the point: this crate never interprets a route. It compares
`Authorization` tags, prints action ids into the audit trail, and hands `Route`
back to the code that produced it. It cannot make a decision that depends on
what a route *means*, because it is never told.

The framework owns exactly one piece of wire shape — the `{"ok": …}` success
envelope, which has nowhere else to live. Every error, including the 404s and
405s the framework generates on its own, is encoded by the service through
`Service::encode_framework_error`. A client therefore needs one decoder rather
than two.

## Implementing a service

```rust
pub trait Service: core::fmt::Debug + Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn resolve(&self, verb: HttpVerb, api_path: &str) -> Option<Route>;
    fn dispatch(&self, route: Route, request: &Value, caller: &Caller)
        -> Result<Value, WireError>;
    fn encode_framework_error(&self, kind: FrameworkErrorKind, message: &str) -> WireError;
}
```

`resolve` returning `None` is a 404 for `GET`/`POST` and a 405 for anything
else, so "this path exists but not for that method" needs no extra signalling.
A request with no body dispatches as JSON `null`.

## Authorization

`Authorizer::authorize` receives both the route and the caller, and is consulted
for **every** resolved route rather than only the gated ones. Both halves matter:
an authorizer that sees only the route can decide whether a *kind* of call is
allowed and never whether *this party* may make it, which leaves the socket's
file mode as the daemon's entire identity check.

Three are shipped:

| Authorizer | Decides |
| --- | --- |
| `AllowSocketPeers` | Reaching the socket is the whole gate — right when the gate really is `0660 root:<group>`. |
| `DenyAll` | Nothing, naming the action id it would have needed. The safe default before a real authorizer is wired. |
| `PeerGate` | A uid or gid allow-list, plus what to do about a caller the kernel would not report. |

Health and version never reach an authorizer: a liveness probe that has to be
authorized is a liveness probe that reports on the authorizer.

## Behaviour that looks redundant and is not

Every item here was once absent, and each reads like a line worth deleting right
up until it is deleted.

- **The caller is read before the request.** Nothing in an HTTP request can
  establish who sent it — a header is a claim by the party being identified.
  `SO_PEERCRED` is filled in by the kernel at `connect(2)` time and cannot be
  forged or changed afterwards. Reading it first means a truncated or malformed
  request is still attributable.
- **An unreadable caller says so.** A `by=` that silently disappears when the
  lookup fails reads exactly like a line written before the daemon recorded
  callers at all, and a trail whose gaps are invisible is worse than no trail.
- **The accepted stream gets its own read deadline.** Linux inherits the
  listener's `SO_RCVTIMEO`, and the listener carries one so `accept()` wakes to
  pet the watchdog — so without an explicit deadline the request budget is
  silently `WatchdogSec/2`, a number chosen for something else. Clearing it
  instead would be worse: one connection is served at a time, so a client that
  connects and never writes would hold the management plane hostage.
- **A connect-and-drop probe is answered with silence** — no bytes, no log line.
  Writing a 400 to a peer that has already closed fails `EPIPE`, which a serve
  loop then logs as a broken pipe: two error-level lines per front-end launch,
  in a small log, pattern-matching a real failure. The stale-socket reclaim *is*
  that probe, so a daemon that answered it would be answering its own
  successor's startup check.
- **The watchdog is petted from its own thread.** A privileged request can
  legitimately outlive the watchdog window. Petting from the serve loop makes
  the daemon go silent exactly while it is doing the most work, and systemd
  `SIGABRT`s it mid-operation. The loop records what it is doing instead; the
  heartbeat thread pets while that record shows idling or bounded progress, and
  stops when a request overstays `longest_legitimate_request` or the loop stops
  turning.
- **A stale socket is unlinked only once proven stale.** `ECONNREFUSED` on an
  existing socket file means the listener is gone and the inode outlived it —
  what a crash leaves behind. A live one, a non-socket, and one that could not
  be checked are all left exactly where they are.
- **Reads produce no audit line.** Front-ends poll every few seconds, and the
  flood *is* the loss: it evicts the operations worth keeping.
- **No payload content reaches the journal.** The daemon this came from built a
  target string from an allowlist of identifying keys, which works and is domain
  knowledge — the allowlist is a list of *that contract's* field names. A
  framework shipping one would be carrying a consumer's vocabulary. A service
  that wants a target in the trail is the only party that can tell an
  identifying field from a revealing one.

## Why `nix`, and not the bridge this code came from

The daemon this was extracted from reaches `SO_PEERCRED` and NSS through a
private in-house bridge. This crate uses
`nix::sys::socket::getsockopt(…, PeerCredentials)` and
`nix::unistd::{User, Group}` instead, for three independent reasons — any one of
which would be enough:

1. The bridge lives in a **private** repository. A public crate cannot depend on
   it, and a public crate that could would be publishing a build failure.
2. It is **Zig-backed**. Depending on it would drag a second toolchain into
   every consumer of a crate whose entire dependency set is otherwise two
   published crates.
3. `nix` satisfies the same constraint the bridge was built for. This crate sets
   `unsafe_code = "deny"`, and `UnixStream::peer_cred` is still nightly-only, so
   *some* safe wrapper is required — `nix` is one, and it is already in the
   ecosystem.

## Building

```console
cargo build --locked
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Most tests touch a real socket and are `#[cfg_attr(miri, ignore)]`d; what Miri
still runs is the parsing, the liveness arithmetic and the sanitisers, where a
finding would be a real one. The tests that assert on the *audit trail* run the
daemon in a child process and read its stderr, because a process cannot read its
own stderr without `unsafe`, and asserting on a log line by calling the function
that formats it proves only that the formatter formats.

`Cargo.lock` is committed. The usual advice leaves a library's lock file out,
but that advice is about what downstream builds resolve, and a consumer's own
lock file still wins; committing this one buys a reproducible CI run and a
bisectable history.

## License

Apache-2.0. See [LICENSE](LICENSE).
