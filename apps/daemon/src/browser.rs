//! The browser capability socket (spec §6.2, §8.5).
//!
//! `$XDG_RUNTIME_DIR/postmoth/browser.sock`, directory `0700`, socket
//! `0600`, and every peer's UID is checked with `SO_PEERCRED`. It speaks
//! only browser protocol v1 (`status`, `find_suggestion`,
//! `consume_suggestion`); nothing else in the daemon is reachable here.

use crate::otp::OtpService;
use postmoth_core::ErrorCode;
use postmoth_ipc::browser::{Op, OtpCode, Request, Response, ResponseBody, echo_request_id};
use postmoth_ipc::framing_async::{read_frame, write_json};
use postmoth_platform::ensure_private_dir;
use secrecy::ExposeSecret;
use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

pub const SUGGESTION_LABEL: &str = "Code from Postmoth";
/// Close connections that stay silent this long.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Concurrent connections (one per browser profile is typical).
const MAX_CONNECTIONS: usize = 16;

/// Create the socket safely. A stale socket from a previous run is
/// replaced; any other file at that path is an error, never deleted.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("socket path has no parent"))?;
    ensure_private_dir(dir).map_err(io::Error::other)?;
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket path exists and is not a socket",
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    // The directory is already 0700, so there is no window where another
    // user could connect before this chmod.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Accept loop. Runs until the task is aborted.
pub async fn serve(listener: UnixListener, otp: Arc<OtpService>) {
    let my_uid = rustix::process::getuid().as_raw();
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                tracing::warn!(error = %e, "browser socket accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        match stream.peer_cred() {
            Ok(c) if c.uid() == my_uid => {}
            _ => {
                tracing::warn!("rejected browser socket peer with foreign or unknown uid");
                continue;
            }
        }
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            tracing::warn!("too many browser connections; dropping one");
            continue;
        };
        let otp = Arc::clone(&otp);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_connection(stream, &otp).await {
                tracing::debug!(error = %e, "browser connection ended with error");
            }
        });
    }
}

async fn handle_connection(stream: UnixStream, otp: &OtpService) -> io::Result<()> {
    let (mut r, mut w) = stream.into_split();
    loop {
        let frame = match tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut r)).await {
            Err(_) | Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(f))) => f,
            Ok(Err(e)) => {
                // Oversize or truncated frame: answer once, then hang up,
                // since we can no longer find the next frame boundary.
                let resp = Response::error("", ErrorCode::BadRequest, "invalid frame");
                let _ = write_json(&mut w, &resp).await;
                return Err(io::Error::other(e.to_string()));
            }
        };
        let resp = handle_request(otp, &frame);
        write_json(&mut w, &resp)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
    }
}

/// Pure request handling, separated from I/O for testing.
pub fn handle_request(otp: &OtpService, raw: &[u8]) -> Response {
    let Ok(req) = serde_json::from_slice::<Request>(raw) else {
        return Response::error("", ErrorCode::BadRequest, "malformed request");
    };
    let rid = echo_request_id(&req.request_id).to_owned();
    if let Err((code, msg)) = req.validate() {
        return Response::error(rid, code, msg);
    }
    let body = match req.op {
        Op::Status => ResponseBody::Ok {
            daemon_version: crate::DAEMON_VERSION.to_owned(),
            paused: otp.is_paused(),
        },
        Op::FindSuggestion { top_origin, tab_id } => match otp.find(&top_origin, tab_id) {
            Ok(Some(found)) => ResponseBody::Available {
                suggestion_id: found.suggestion_id,
                label: SUGGESTION_LABEL.to_owned(),
            },
            Ok(None) => ResponseBody::None,
            Err(code) => error_body(code),
        },
        Op::ConsumeSuggestion {
            suggestion_id,
            top_origin,
            tab_id,
        } => match otp.consume(suggestion_id, &top_origin, tab_id) {
            Ok(code) => {
                tracing::info!("one-time code handed to browser extension");
                ResponseBody::Code {
                    code: OtpCode::new(code.expose_secret().to_owned()),
                }
            }
            Err(code) => error_body(code),
        },
    };
    Response::new(rid, body)
}

fn error_body(code: ErrorCode) -> ResponseBody {
    ResponseBody::Error {
        code,
        message: code.as_str().to_owned(),
    }
}
