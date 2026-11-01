//! `postmoth-native-host`: launched by Chromium-family browsers through
//! native messaging (spec §8.5).
//!
//! It is a dumb, strict relay: browser (stdin) → daemon browser socket →
//! browser (stdout). It
//!
//! * refuses to run unless `argv[1]` is the origin of a pinned extension;
//! * forwards only well-formed browser-protocol v1 requests, re-serialized
//!   canonically, and only well-formed responses with a matching id;
//! * writes nothing but protocol frames to stdout; diagnostics go to stderr
//!   and never contain payloads;
//! * holds no state, so a compromised browser gains nothing beyond the
//!   three operations the daemon already exposes.

use postmoth_core::ErrorCode;
use postmoth_ipc::browser::{Request, Response, echo_request_id};
use postmoth_ipc::framing::{self, FrameError};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Development extension (unpacked, fixed via the manifest `key`).
pub const DEV_EXTENSION_ID: &str = "nnbgdhodaoggiiakpcmnlkgalgkoecbk";

/// Published extension IDs. Empty until the store listing exists.
pub const RELEASE_EXTENSION_IDS: &[&str] = &[];

/// How long to wait for the daemon to answer one request.
pub const DAEMON_TIMEOUT: Duration = Duration::from_secs(10);

fn dev_allowed() -> bool {
    cfg!(debug_assertions) || cfg!(feature = "dev-extension")
}

/// Is this `chrome-extension://<id>/` origin one we serve?
#[must_use]
pub fn caller_allowed(origin: &str) -> bool {
    let Some(id) = origin
        .strip_prefix("chrome-extension://")
        .and_then(|r| r.strip_suffix('/'))
    else {
        return false;
    };
    RELEASE_EXTENSION_IDS.contains(&id) || (dev_allowed() && id == DEV_EXTENSION_ID)
}

/// Where the daemon listens. No fallback outside `XDG_RUNTIME_DIR`.
#[must_use]
pub fn socket_path(runtime_dir: Option<&str>) -> Option<PathBuf> {
    let dir = PathBuf::from(runtime_dir?);
    dir.is_absolute()
        .then(|| dir.join("postmoth").join("browser.sock"))
}

/// A request/response channel to the daemon.
pub trait DaemonLink {
    /// Send one frame and read one frame back.
    fn call(&mut self, request: &[u8]) -> io::Result<Vec<u8>>;
}

/// Connects lazily and reconnects after failures.
#[derive(Debug)]
pub struct SocketLink {
    path: Option<PathBuf>,
    stream: Option<UnixStream>,
}

impl SocketLink {
    #[must_use]
    pub fn new(path: Option<PathBuf>) -> Self {
        Self { path, stream: None }
    }

    fn connected(&mut self) -> io::Result<&mut UnixStream> {
        if self.stream.is_none() {
            let path = self
                .path
                .as_ref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "XDG_RUNTIME_DIR unset"))?;
            let s = UnixStream::connect(path)?;
            s.set_read_timeout(Some(DAEMON_TIMEOUT))?;
            s.set_write_timeout(Some(DAEMON_TIMEOUT))?;
            self.stream = Some(s);
        }
        self.stream
            .as_mut()
            .ok_or_else(|| io::Error::other("not connected"))
    }
}

impl DaemonLink for SocketLink {
    fn call(&mut self, request: &[u8]) -> io::Result<Vec<u8>> {
        let result = (|| {
            let s = self.connected()?;
            framing::write_frame(s, request).map_err(frame_io)?;
            framing::read_frame(s)
                .map_err(frame_io)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "daemon closed"))
        })();
        if result.is_err() {
            // Next request starts from a fresh connection.
            self.stream = None;
        }
        result
    }
}

fn frame_io(e: FrameError) -> io::Error {
    match e {
        FrameError::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

/// Handle one browser frame and produce the reply frame.
pub fn relay_one(link: &mut impl DaemonLink, frame: &[u8]) -> Response {
    let req: Request = match serde_json::from_slice(frame) {
        Ok(r) => r,
        Err(_) => return Response::error("", ErrorCode::BadRequest, "malformed request"),
    };
    if let Err((code, msg)) = req.validate() {
        return Response::error(echo_request_id(&req.request_id), code, msg);
    }
    // Canonical re-serialization: the daemon never sees browser bytes.
    let Ok(canonical) = serde_json::to_vec(&req) else {
        return Response::error(&req.request_id, ErrorCode::Internal, "internal");
    };
    let raw = match link.call(&canonical) {
        Ok(r) => r,
        Err(_) => {
            return Response::error(
                &req.request_id,
                ErrorCode::DaemonUnavailable,
                "postmoth daemon is not running",
            );
        }
    };
    match serde_json::from_slice::<Response>(&raw) {
        Ok(resp) if resp.request_id == req.request_id => resp,
        _ => Response::error(&req.request_id, ErrorCode::Internal, "bad daemon response"),
    }
}

/// Main loop: until the browser closes stdin.
pub fn run(
    input: &mut impl Read,
    output: &mut impl Write,
    link: &mut impl DaemonLink,
) -> io::Result<()> {
    loop {
        let frame = match framing::read_frame(input) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(()),
            Err(FrameError::TooLarge(_)) => {
                // Cannot resync the stream after a bogus length: answer, quit.
                let resp = Response::error("", ErrorCode::BadRequest, "frame too large");
                framing::write_json(output, &resp).map_err(frame_io)?;
                return Ok(());
            }
            Err(e) => return Err(frame_io(e)),
        };
        let resp = relay_one(link, &frame);
        framing::write_json(output, &resp).map_err(frame_io)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_pinning() {
        let dev = format!("chrome-extension://{DEV_EXTENSION_ID}/");
        assert!(caller_allowed(&dev), "debug builds accept the dev id");
        for bad in [
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
            &format!("chrome-extension://{DEV_EXTENSION_ID}"),
            &format!("moz-extension://{DEV_EXTENSION_ID}/"),
            &format!("chrome-extension://{DEV_EXTENSION_ID}/x"),
            "",
        ] {
            assert!(!caller_allowed(bad), "{bad}");
        }
    }

    #[test]
    fn socket_path_requires_absolute_runtime_dir() {
        assert_eq!(
            socket_path(Some("/run/user/1")),
            Some(PathBuf::from("/run/user/1/postmoth/browser.sock"))
        );
        assert_eq!(socket_path(Some("rel")), None);
        assert_eq!(socket_path(None), None);
    }
}
