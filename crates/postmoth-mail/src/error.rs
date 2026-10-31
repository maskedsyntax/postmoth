use std::io;

/// Transport errors, classified so the sync scheduler can decide whether
/// to retry, back off, or surface an authentication problem to the user.
///
/// Messages never include credentials or message content.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("network error: {0}")]
    Io(#[from] io::Error),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("server does not offer STARTTLS; refusing cleartext")]
    StartTlsUnavailable,
    #[error("authentication failed")]
    Auth,
    #[error("operation timed out")]
    Timeout,
    #[error("connection lost")]
    ConnectionLost,
    #[error("server rejected command: {0}")]
    Rejected(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl MailError {
    /// Worth retrying later with backoff (vs. needing user action).
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::Timeout | Self::ConnectionLost | Self::Protocol(_)
        )
    }

    #[must_use]
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Auth)
    }
}

impl From<async_imap::error::Error> for MailError {
    fn from(e: async_imap::error::Error) -> Self {
        use async_imap::error::Error as E;
        match e {
            E::Io(io) => Self::Io(io),
            E::ConnectionLost => Self::ConnectionLost,
            // Server text can echo client input; keep it short.
            E::No(s) | E::Bad(s) => Self::Rejected(truncate(&s, 200)),
            other => Self::Protocol(truncate(&other.to_string(), 200)),
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub type Result<T, E = MailError> = std::result::Result<T, E>;
