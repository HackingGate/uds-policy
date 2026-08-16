//! An HTTP/JSON-over-`AF_UNIX` daemon framework that knows nothing about what
//! it serves.
//!
//! This crate is the half of a privileged Unix-socket daemon that is the same
//! whatever the daemon does: bind the socket and give it away to a group,
//! reclaim a stale one, read a request, ask the kernel who sent it, authorize
//! it, audit it, hand it to a handler, and stay petted under a systemd
//! watchdog. Everything about *what* the daemon does — the paths it serves, the
//! shape of its errors, what a method means — belongs to the caller's
//! [`Service`] implementation.
//!
//! # The seam is concrete on purpose
//!
//! [`Route`], [`WireError`] and [`FrameworkErrorKind`] are plain types rather
//! than associated types on [`Service`]. Parameterising over a `Method` trait
//! and a `WireError` trait reads better right up to the moment a consumer tries
//! to implement it: the crate that owns a daemon's wire contract would have to
//! depend on this framework in order to name the traits, which inverts the
//! dependency direction that splitting the framework out exists to establish.
//! A contract crate must be able to describe its own methods and its own error
//! envelope with no knowledge that this crate exists. So the seam is a struct
//! of `&'static str`s the contract crate can fill in, and an
//! already-encoded [`WireError`] it can produce.
//!
//! The consequence, and it is the point: this crate never interprets a route.
//! It compares [`Authorization`] tags, prints action ids into the audit trail,
//! and passes [`Route`] back to the code that produced it. It cannot make a
//! decision that depends on what the route means, because it is not told.
//!
//! # Server side only
//!
//! There is no client here. A client's framing is a client's business, and a
//! generic client facade would immediately want to know what the daemon serves.
//!
//! # Getting started
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use uds_daemon::{AllowSocketPeers, Server, ServerConfig, Service};
//! # fn run(service: Arc<dyn Service>) -> Result<(), Box<dyn std::error::Error>> {
//! let config = ServerConfig::new("/run/example/api.sock");
//! Server::bind(config, service, Arc::new(AllowSocketPeers))?.serve()?;
//! # Ok(())
//! # }
//! ```
//!
//! See `examples/echo-service.rs` for a complete [`Service`] in about sixty
//! lines.
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
mod caller;
mod handler;
mod http;
mod server;
mod service;
mod watchdog;

pub use authorization::{AllowSocketPeers, Authorizer, Denial, DenyAll, PeerGate};
pub use caller::{Caller, MAX_CALLER_NAME_CHARS};
pub use handler::{Handler, Reply};
pub use http::ServeOutcome;
pub use server::{BindError, Server, ServerConfig};
pub use service::{Authorization, FrameworkErrorKind, HttpVerb, Route, Service, WireError};

/// This crate's name, for a daemon that wants to say what framework it runs on.
pub const FRAMEWORK_NAME: &str = env!("CARGO_PKG_NAME");

/// This crate's version.
pub const FRAMEWORK_VERSION: &str = env!("CARGO_PKG_VERSION");
