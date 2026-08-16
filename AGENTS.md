# uds-policy Rules

This repository owns the wire-agnostic half of a privileged `AF_UNIX` daemon:
socket lifecycle, caller identity, an authorization seam, an audit trail and a
systemd watchdog. It exists so that daemons which agree about nothing except
"there is a Unix socket" can share it, and every rule below exists to keep that
possible.

## The two rules the crate cannot survive breaking

- **No serve loop, in any form, for any consumer.** Not a request pipeline, not
  a router, not a frame reader, not a "tiny helper" that reads a length prefix.
  This crate shipped one once and it was the half that made it unusable by its
  second consumer: a serve loop has to pick a wire format, and picking one
  forecloses everyone who picked differently. `Socket::accept` hands back a
  stream and the caller on it; what happens to the bytes is the daemon's.
- **This crate knows nothing about what it serves.** No product noun, no path
  belonging to a real contract, no error kind belonging to a real contract, no
  field name from a real payload — not in code, not in a doc comment, not in a
  test name. `.pre-commit-config.yaml` enforces the narrow version of this with
  a `grep` over `src/`, `examples/` and `tests/`, and that check is a floor
  rather than the rule: it names the problem domains this workspace happens to
  have, and the rule is about all of them.
- A generalization that leaked one identifier compiles, tests green, and is
  discovered only when a second consumer tries to adopt it. Prefer a slightly
  clumsier abstraction that is provably domain-free to a natural one that is
  not.

## The seam

- **Concrete types, not associated types.** `Call` and `Authorization` are plain
  data. Do not "improve" them into a `Service` trait parameterised over a
  `Method`: a consumer's contract crate would then have to depend on this crate
  in order to name it, which inverts the dependency direction the split exists
  to establish. A contract must be describable with no knowledge that this crate
  exists.
- **No wire shape at all.** Not a status code, not a success envelope, not an
  error kind. `Denial` carries a string because this crate does not classify
  refusals, and `Operation::finish` takes a string because there is no transport
  here to have an encoded error. If a type here would only make sense to
  something that speaks a protocol, it does not belong here.
- **Server side only.** Do not add client framing, a client facade, or a
  "convenience" request builder. A generic client immediately wants to know what
  the daemon serves, which is the one thing this crate must not know.

## Behaviour that is not up for simplification

Each of these is here because it was once absent, and each reads like a
redundant line until it is removed:

- Caller identity comes from `SO_PEERCRED` on the accepted socket, read **before
  the first request byte**, never from anything the request carries — a field
  naming the sender is a claim by the party being identified. `Socket::accept`
  returns the caller *with* the stream precisely so a call site cannot get that
  ordering wrong. A caller that could not be read is recorded as unreadable
  *with the reason* rather than omitted; a `by=` that silently disappears reads
  like a line written before the daemon recorded callers at all.
- The accepted stream gets its **own** read deadline, applied by `accept`. Linux
  inherits the listener's `SO_RCVTIMEO`, so without it the request budget is
  silently whatever the watchdog heartbeat happens to be. A `None` deadline
  *clears* the inherited value rather than leaving it in place, so the accident
  cannot happen quietly.
- A connect-and-drop probe must arrive as an **ordinary accept**. The
  stale-socket reclaim in `src/socket.rs` *is* that probe, so a daemon that
  answered it with bytes would be answering its own successor's startup check.
- The watchdog is petted from its **own thread**, driven by a record of what the
  accept loop is doing. Petting from the loop makes a daemon go silent exactly
  while it is busy, and systemd `SIGABRT`s it mid-operation.
- **A streaming call is judged by progress, never by duration**, and
  `longest_silent_stream` defaults to `None`. A ceiling on an open subscription
  kills it whenever the thing it watches is quiet — which is when it is most
  obviously working. Do not "simplify" `InFlight` back to one ceiling.
- The uid→name memoisation takes **two scoped locks** and never holds one across
  the NSS call; a failed lookup is deliberately not cached while an absent uid
  is; names are bounded and stripped of newlines so a directory-supplied name
  cannot forge a journal line.
- Reads produce no audit line. The restraint is the point: front-ends poll, and
  a flood evicts the operations worth keeping. `Operation` is constructed for
  every call and silent for the unprivileged ones, so a dispatch site needs no
  `if` and cannot drift out of step with the policy tag.
- No payload content reaches the journal. An allowlist of "identifying" field
  names would be this crate carrying a consumer's vocabulary; a daemon that
  wants a target in the trail is the only party that can tell identifying from
  revealing.

## Dependencies

- `nix`, and a strong reason for anything further. This crate is public: every
  dependency it takes is one every consumer takes. `serde_json` left with the
  transport half — a policy layer that reaches for a serializer has started
  growing a wire format again.
- Do not reach for the private, Zig-backed `unix-users` bridge the extracted
  code used. It cannot be depended on from a public crate, it drags a second
  toolchain into every consumer, and `nix` satisfies the same `unsafe_code =
  "deny"` constraint. `README.md` states this so a reviewer does not have to
  rediscover it.

## Lints, tests and documentation

- The lint tables in `Cargo.toml` and the `cfg_attr(test, allow(…))` crate
  header are load-bearing. A crate that drops them compiles fine and silently
  checks less.
- Every test that touches a socket carries
  `#[cfg_attr(miri, ignore = "Miri cannot execute unix sockets")]`.
- A test that asserts on the audit trail runs the daemon in a child process and
  reads its stderr. A process cannot read its own stderr without `unsafe`, and
  asserting on a log line by calling the function that formats it proves only
  that the formatter formats.
- `examples/gatekeeper.rs` carries a `--self-test` mode, and CI runs it. The
  example must stay runnable, not merely compilable — and it must stay
  runnable *without a protocol client*, because needing one would mean the
  crate had grown a protocol.
- Comments say *why*, and name the failure the code is a response to. Do not
  restate a value the build or the configuration already declares — name where
  it is declared instead.
