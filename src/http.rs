//! A hand-rolled HTTP/1.1 reader for one connection at a time.
//!
//! Hand-rolled rather than taken from a crate, and it stays that way: this is
//! `AF_UNIX` with one connection in flight, one request per connection and
//! `connection: close`. There is no TLS, no keep-alive, no chunked transfer, no
//! routing, no async runtime and no header the daemon reads other than
//! `content-length`. What a server crate would add here is a dependency tree
//! and a set of behaviours the daemon does not want, in exchange for a parser
//! that fits on two screens.

use crate::caller::Caller;
use crate::handler::{Handler, Reply};
use crate::server::ServerConfig;
use crate::service::{FrameworkErrorKind, HttpVerb};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

/// What one accepted connection amounted to, so the serve loop can tell a
/// failure worth logging from a client that simply asked whether the daemon is
/// there.
#[derive(Debug)]
pub enum ServeOutcome {
    /// A request was answered — whatever HTTP status it got. Nothing to log:
    /// state-changing calls audit themselves.
    Answered,
    /// A connect-and-drop reachability probe. Silent by construction.
    Probe,
    /// The connection failed. `context` names the request when one was parsed,
    /// because `request failed: Broken pipe` with no method and no path is not
    /// a diagnosis.
    Failed {
        /// `METHOD /path`, when the request line had been read.
        context: Option<String>,
        /// What went wrong.
        error: std::io::Error,
    },
}

/// Read one request from `stream` and answer it.
///
/// The caller is read first, before a byte of the request is parsed: the
/// kernel's answer belongs to the socket, not to anything the peer sends, and
/// taking it here means a malformed or truncated request is still attributable.
pub(crate) fn serve_connection(
    handler: &Handler,
    config: &ServerConfig,
    stream: &mut UnixStream,
) -> ServeOutcome {
    let caller = Caller::of_socket(stream);
    match read_and_route(handler, config, stream, &caller) {
        Ok(outcome) => outcome,
        Err(error) => ServeOutcome::Failed {
            context: None,
            error,
        },
    }
}

fn read_and_route(
    handler: &Handler,
    config: &ServerConfig,
    stream: &mut UnixStream,
    caller: &Caller,
) -> std::io::Result<ServeOutcome> {
    // Chosen, not inherited. The listener carries an `SO_RCVTIMEO` so the
    // accept loop wakes to pet the watchdog, and on Linux an accepted socket
    // inherits `SOL_SOCKET` options — so without this line every request read
    // carried a hidden deadline tied to `WatchdogSec/2`, a number picked for
    // something else entirely. Setting it explicitly makes the request budget
    // independent of the heartbeat interval, and gives the same behaviour when
    // no watchdog is configured and the listener has no timeout at all.
    //
    // Clearing it instead would be worse: this server answers one request at a
    // time, so a client that connects and never writes would hold the whole
    // management plane until the watchdog gave up on it.
    stream.set_read_timeout(Some(config.request_read_timeout))?;

    // Read headers until the blank line that terminates them, rather than to
    // EOF: a client using HTTP/1.1 keep-alive does not close, and reading to
    // EOF would block until the request timeout on every well-formed request.
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut headers = String::with_capacity(512);
    loop {
        if headers.len() > config.max_header_bytes {
            return Ok(refuse(
                handler,
                stream,
                FrameworkErrorKind::PayloadTooLarge,
                "HTTP headers exceed maximum size",
            ));
        }
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            // Clean EOF with nothing read at all is a reachability probe: a
            // client that connects and drops on purpose to find out whether
            // the daemon is there. Writing a 400 to a socket the peer has
            // already closed fails EPIPE, and a serve loop that logged that
            // planted two error-level lines on every front-end launch, in a
            // small log, pattern-matching a real failure. Say nothing and
            // close — and note that the stale-socket reclaim in
            // `crate::server` is exactly this probe, so a daemon that answered
            // it would be answering itself.
            if headers.is_empty() {
                return Ok(ServeOutcome::Probe);
            }
            // Bytes read and then EOF is a genuinely truncated request: the
            // peer is still there and the 400 tells it why.
            return Ok(refuse(
                handler,
                stream,
                FrameworkErrorKind::InvalidInput,
                "client closed connection before completing HTTP request",
            ));
        }
        headers.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }

    let content_length = match content_length_of(&headers) {
        Ok(length) => length,
        Err(message) => {
            return Ok(refuse(
                handler,
                stream,
                FrameworkErrorKind::InvalidInput,
                &message,
            ));
        }
    };
    if content_length > config.max_body_bytes {
        return Ok(refuse(
            handler,
            stream,
            FrameworkErrorKind::PayloadTooLarge,
            "HTTP body exceeds maximum size",
        ));
    }

    let mut body_bytes = vec![0_u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body_bytes)?;
    }
    let Ok(body) = String::from_utf8(body_bytes) else {
        return Ok(refuse(
            handler,
            stream,
            FrameworkErrorKind::InvalidInput,
            "HTTP body is not valid UTF-8",
        ));
    };

    let request_line = match RequestLine::parse(&headers) {
        Ok(line) => line,
        Err(message) => {
            return Ok(refuse(
                handler,
                stream,
                FrameworkErrorKind::InvalidInput,
                &message,
            ));
        }
    };

    let reply = handler.respond(request_line.verb, &request_line.path, &body, caller);
    if let Err(error) = write_reply(stream, &reply) {
        // Kept for the failure log: a write that fails after the daemon has
        // done the work needs to name the request it was answering.
        return Ok(ServeOutcome::Failed {
            context: Some(request_line.context()),
            error,
        });
    }
    Ok(ServeOutcome::Answered)
}

/// Answer a request the reader refused, and report the connection as failed.
///
/// The write is best-effort: the reason the request was refused is very often
/// the reason the peer is no longer reading.
fn refuse(
    handler: &Handler,
    stream: &mut UnixStream,
    kind: FrameworkErrorKind,
    message: &str,
) -> ServeOutcome {
    let reply = handler.framework_error(kind, message);
    if let Err(_unreachable) = write_reply(stream, &reply) {}
    ServeOutcome::Failed {
        context: None,
        error: std::io::Error::other(message.to_owned()),
    }
}

/// The `METHOD /path HTTP/1.x` of a request.
#[derive(Debug)]
struct RequestLine {
    method: String,
    verb: HttpVerb,
    path: String,
}

impl RequestLine {
    fn parse(headers: &str) -> Result<Self, String> {
        let line = headers
            .lines()
            .next()
            .ok_or_else(|| "HTTP request line is missing".to_owned())?;
        let mut parts = line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| "HTTP method is missing".to_owned())?;
        let path = parts
            .next()
            .ok_or_else(|| "HTTP path is missing".to_owned())?;
        let version = parts
            .next()
            .ok_or_else(|| "HTTP version is missing".to_owned())?;
        if parts.next().is_some() {
            return Err("HTTP request line has too many fields".to_owned());
        }
        if version != "HTTP/1.1" && version != "HTTP/1.0" {
            return Err(format!("unsupported HTTP version: {version}"));
        }
        Ok(Self {
            method: method.to_owned(),
            verb: HttpVerb::parse(method),
            path: path.to_owned(),
        })
    }

    /// The two fields worth putting in a small journal. The HTTP version and
    /// every header are dropped: headers can carry anything.
    fn context(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

/// `content-length`, or zero when the request declares none.
fn content_length_of(headers: &str) -> Result<usize, String> {
    let mut length = 0_usize;
    for header in headers.lines() {
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        length = value
            .trim()
            .parse::<usize>()
            .map_err(|error| format!("invalid Content-Length header: {error}"))?;
    }
    Ok(length)
}

fn write_reply(stream: &mut UnixStream, reply: &Reply) -> std::io::Result<()> {
    let response = format_response(reply);
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn format_response(reply: &Reply) -> String {
    let status = reply.status;
    let reason = reason_phrase(status);
    let content_length = reply.body.len();
    let body = &reply.body;
    format!(
        "HTTP/1.1 {status} {reason}\r\n\
         content-type: application/json\r\n\
         content-length: {content_length}\r\n\
         connection: close\r\n\
         \r\n\
         {body}"
    )
}

/// Reason phrases for the statuses a daemon on this framework is likely to
/// answer with. Anything else gets `Unknown`, which is a legal reason phrase
/// and is never parsed by anyone: the status code is the answer.
const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{RequestLine, content_length_of, format_response, reason_phrase};
    use crate::handler::Reply;
    use crate::service::HttpVerb;

    #[test]
    fn a_request_line_yields_a_verb_and_a_path() {
        let line = RequestLine::parse("POST /v1/thing/change HTTP/1.1\r\nhost: d\r\n\r\n")
            .expect("a well-formed request line was rejected");
        assert_eq!(line.verb, HttpVerb::Post);
        assert_eq!(line.path, "/v1/thing/change");
        assert_eq!(line.context(), "POST /v1/thing/change");
    }

    #[test]
    fn a_request_line_is_exactly_three_fields_of_a_version_we_speak() {
        assert!(RequestLine::parse("GET /v1/status HTTP/1.0\r\n\r\n").is_ok());
        assert!(RequestLine::parse("GET /v1/status HTTP/2\r\n\r\n").is_err());
        assert!(RequestLine::parse("GET /v1/status HTTP/1.1 extra\r\n\r\n").is_err());
        assert!(RequestLine::parse("GET /v1/status\r\n\r\n").is_err());
    }

    #[test]
    fn content_length_is_read_case_insensitively_and_defaults_to_zero() {
        assert_eq!(
            content_length_of("POST /x HTTP/1.1\r\nContent-Length: 12\r\n\r\n"),
            Ok(12)
        );
        assert_eq!(
            content_length_of("POST /x HTTP/1.1\r\ncontent-length: 3\r\n\r\n"),
            Ok(3)
        );
        assert_eq!(content_length_of("GET /x HTTP/1.1\r\n\r\n"), Ok(0));
        assert!(content_length_of("POST /x HTTP/1.1\r\ncontent-length: n\r\n\r\n").is_err());
    }

    /// `content-length` must be the body's byte count, not its character
    /// count: a client reading exactly that many bytes off a multi-byte reply
    /// would otherwise hang or truncate.
    #[test]
    fn the_response_declares_the_bodys_length_in_bytes() {
        let reply = Reply {
            status: 200,
            body: r#"{"ok":"café"}"#.to_owned(),
        };
        let response = format_response(&reply);
        assert!(response.contains("content-length: 14\r\n"), "{response}");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("connection: close\r\n"));
    }

    #[test]
    fn unlisted_statuses_still_produce_a_legal_response() {
        assert_eq!(reason_phrase(200), "OK");
        assert_eq!(reason_phrase(418), "Unknown");
    }
}
