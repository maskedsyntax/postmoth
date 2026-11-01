//! The Postmoth daemon (spec §6.1): owns accounts, sync, database writes,
//! secret access and the OTP candidate lifecycle.
//!
//! Wiring:
//!
//! ```text
//!  SyncWorker (one per account) ──► ingest (parse) ──► Db actor (single writer)
//!          │                                   └──► OtpService (volatile cache)
//!          ▼                                                 ▲
//!  IMAP over TLS                         browser socket ─────┘ (status/find/consume only)
//!                                        D-Bus control  ──► Daemon (account manager)
//! ```

pub mod browser;
pub mod daemon;
pub mod db;
pub mod dbus;
pub mod ingest;
pub mod logging;
pub mod otp;
pub mod worker;

pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}
