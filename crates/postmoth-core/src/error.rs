//! Error type with stable, machine-readable codes (spec §6.2).
//!
//! Codes are part of the IPC contract: never rename an existing variant's
//! wire string, only add new ones.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// No candidate matched the requesting origin (also used for unknown origins).
    NoMatch,
    /// The suggestion existed but its TTL elapsed or it was already consumed.
    Expired,
    /// The user paused OTP suggestions or background mail.
    Paused,
    /// The daemon is not running or not reachable.
    DaemonUnavailable,
    /// Malformed or disallowed request.
    BadRequest,
    /// Caller is not permitted to perform this operation.
    Forbidden,
    /// Protocol version not supported.
    VersionUnsupported,
    /// Internal failure; details only in redacted logs.
    Internal,
}

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMatch => "no_match",
            Self::Expired => "expired",
            Self::Paused => "paused",
            Self::DaemonUnavailable => "daemon_unavailable",
            Self::BadRequest => "bad_request",
            Self::Forbidden => "forbidden",
            Self::VersionUnsupported => "version_unsupported",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error carrying a stable code plus a human-readable message.
///
/// The message must never contain secrets, OTP codes or message bodies.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}: {message}")]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, message)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_strings_match_serde() {
        for code in [
            ErrorCode::NoMatch,
            ErrorCode::Expired,
            ErrorCode::Paused,
            ErrorCode::DaemonUnavailable,
            ErrorCode::BadRequest,
            ErrorCode::Forbidden,
            ErrorCode::VersionUnsupported,
            ErrorCode::Internal,
        ] {
            let json = serde_json::to_string(&code).expect("ser");
            assert_eq!(json, format!("\"{}\"", code.as_str()));
        }
    }
}
