//! The half of a privileged Unix-socket daemon that has nothing to do with the
//! wire it speaks: identity, authorization, audit and liveness.
//!
//! A daemon behind an `AF_UNIX` socket has to answer four questions no protocol
//! answers for it:
//!
//! | Question | Here |
//! |---|---|
//! | Whose socket is this, and is it stale? | [`Socket`], [`SocketConfig`] |
//! | Who is calling? | [`Caller`], read from the accepted socket by [`Socket::accept`] |
//! | May they? | [`Authorizer`], [`PeerGate`], [`Denial`] |
//! | What happened, and who did it? | [`Operation`] |
//! | Is the daemon wedged or merely busy? | [`watchdog`] |
//!
//! # There is no serve loop, and there will not be one
//!
//! A serve loop has to pick a wire format, and picking one forecloses every
//! consumer that picked differently. This crate used to own one — an HTTP/1.1
//! reader, a router and a dispatch pipeline — and it was the half that made the
//! crate unusable by its second consumer. It is gone. The daemon owns its
//! accept loop and speaks whatever it likes over the streams
//! [`Socket::accept`] hands it: varlink, HTTP over a Unix socket, a
//! length-prefixed frame, a line.
//!
//! What is left is wire-agnostic by construction, which is the only reason two
//! daemons that disagree about their protocol can share it.
//!
//! # The seam is data, not a trait
//!
//! [`Call`] is a plain struct rather than an associated type on some `Service`
//! trait. Parameterising over a `Method` trait reads better right up to the
//! moment a consumer tries to implement it: the crate that owns a daemon's wire
//! contract would have to depend on *this* crate in order to name the trait,
//! which inverts the dependency direction that splitting this out exists to
//! establish. A contract crate must be able to describe its own methods with no
//! knowledge that this crate exists.
//!
//! The consequence, and it is the point: this crate never interprets a call. It
//! compares [`Authorization`] tags, prints action ids into the audit trail, and
//! hands the [`Call`] back to the code that produced it.
//!
//! # Server side only
//!
//! There is no client here. A client's framing is a client's business, and a
//! generic client facade would immediately want to know what the daemon serves.
//!
//! # Getting started
//!
//! ```no_run
//! # use uds_policy::{AllowSocketPeers, Authorizer, Call, Operation, Socket, SocketConfig, watchdog};
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! const CHANGE: Call = Call::gated("Thing", "Change", "org.example.thing.change");
//!
//! let socket = Socket::bind(
//!     SocketConfig::new("exampled", "/run/example/api.sock").with_socket_group("example"),
//! )?;
//! let authorizer = AllowSocketPeers;
//! watchdog::notify_ready();
//!
//! loop {
//!     // The caller comes back with the stream, before a byte is read from it.
//!     let (stream, caller) = socket.accept()?;
//!     if let Err(denial) = authorizer.authorize(CHANGE, &caller) {
//!         eprintln!("exampled: refused: {}", denial.reason);
//!         continue;
//!     }
//!     let audit = Operation::begin("exampled", CHANGE, &caller);
//!     // ... speak whatever protocol you speak over `stream` ...
//!     audit.finish(None);
//! }
//! # }
//! ```
//!
//! See `examples/gatekeeper.rs` for a daemon that runs.
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

mod audit;
mod authorization;
mod call;
mod caller;
mod socket;

pub mod watchdog;

pub use audit::{MAX_FAILURE_CHARS, Operation};
pub use authorization::{AllowSocketPeers, Authorizer, Denial, DenyAll, PeerGate};
pub use call::{Authorization, Call};
pub use caller::{Caller, MAX_CALLER_NAME_CHARS};
pub use socket::{BindError, Socket, SocketConfig};

/// This crate's name, for a daemon that wants to say what it runs on.
pub const NAME: &str = env!("CARGO_PKG_NAME");

/// This crate's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
