# uds-daemon Rules

This repository owns a domain-agnostic HTTP/JSON-over-`AF_UNIX` daemon
framework. It was extracted from a working privileged daemon so that daemon can
later be retrofitted onto it, and every rule below exists to keep that retrofit
possible.

## The one rule the crate cannot survive breaking

- **This crate knows nothing about what it serves.** No product noun, no path
  belonging to a real contract, no error kind belonging to a real contract, no
  field name from a real payload — not in code, not in a doc comment, not in a
  test name. `.pre-commit-config.yaml` enforces the narrow version of this with
  a `grep` over `src/`, and that check is a floor rather than the rule: it names
  the two problem domains this workspace happens to have, and the rule is about
  all of them.
- A generalization that leaked one identifier compiles, tests green, and is
  discovered only when a second consumer tries to adopt it. Prefer a slightly
  clumsier abstraction that is provably domain-free to a natural one that is
  not.

## The seam

- **Concrete types, not associated types.** `Route`, `WireError`,
  `FrameworkErrorKind` and `HttpVerb` are plain data. Do not "improve" the
  `Service` trait by parameterising over a `Method` or `WireError` trait: a
  consumer's contract crate would then have to depend on this crate in order to
  name them, which inverts the dependency direction the split exists to
  establish. A contract must be describable with no knowledge that this
  framework exists.
- The framework owns the `{"ok": …}` success envelope and nothing else about the
  wire. Errors — including the ones the framework itself produces — are encoded
  by the service through `Service::encode_framework_error`, so a client needs
  one decoder rather than two.
- **Server side only.** Do not add client framing, a client facade, or a
  "convenience" request builder. A generic client immediately wants to know what
  the daemon serves, which is the one thing this crate must not know.

## Behaviour that is not up for simplification

Each of these is here because it was once absent, and each reads like a
redundant line until it is removed:

- Caller identity comes from `SO_PEERCRED` on the accepted socket, read **before
  the first request byte**, never from a request header — a header is a claim by
  the party being identified. A caller that could not be read is recorded as
  unreadable *with the reason* rather than omitted; a `by=` that silently
  disappears reads like a line written before the daemon recorded callers at
  all.
- The accepted stream gets its **own** read deadline. Linux inherits the
  listener's `SO_RCVTIMEO`, so without it the request budget is silently
  whatever the watchdog heartbeat happens to be.
- A connect-and-drop probe is answered with **silence** — no bytes and no log
  line. The stale-socket reclaim in `src/server.rs` *is* that probe, so a daemon
  that answered it would be answering its own successor's startup check.
- The watchdog is petted from its **own thread**, driven by a record of what the
  serve loop is doing. Petting from the loop makes a daemon go silent exactly
  while it is busy, and systemd `SIGABRT`s it mid-operation.
- The uid→name memoisation takes **two scoped locks** and never holds one across
  the NSS call; a failed lookup is deliberately not cached while an absent uid
  is; names are bounded and stripped of newlines so a directory-supplied name
  cannot forge a journal line.
- Reads produce no audit line. The restraint is the point: front-ends poll, and
  a flood evicts the operations worth keeping.
- No payload content reaches the journal. An allowlist of "identifying" field
  names would be this crate carrying a consumer's vocabulary; a service that
  wants a target in the trail is the only party that can tell identifying from
  revealing.

## Dependencies

- `nix` and `serde_json`, and a strong reason for anything further. This crate
  is public: every dependency it takes is one every consumer takes.
- Do not reach for the private, Zig-backed `unix-users` bridge the extracted
  code used. It cannot be depended on from a public crate, it drags a second
  toolchain into every consumer, and `nix` satisfies the same `unsafe_code =
  "deny"` constraint. `README.md` states this so a reviewer does not have to
  rediscover it.
- The HTTP reader stays hand-rolled. One connection, one request,
  `connection: close`, one header read — a server crate adds a dependency tree
  and behaviours the daemon does not want.

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
- Comments say *why*, and name the failure the code is a response to. Do not
  restate a value the build or the configuration already declares — name where
  it is declared instead.
