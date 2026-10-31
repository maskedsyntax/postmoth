//! Mail transport for Postmoth (spec §7).
//!
//! * [`tls`] opens TLS connections (implicit TLS or mandatory STARTTLS;
//!   cleartext is not representable).
//! * [`imap`] wraps an authenticated IMAP session: select, incremental UID
//!   fetch, IDLE.
//! * [`sync`] decides what to fetch given stored cursor and server state.
//! * [`backoff`] bounds reconnect storms.
//!
//! The session type is generic over the byte stream so the protocol logic
//! is tested against an in-process scripted server (see `tests/`).

pub mod backoff;
pub mod error;
pub mod imap;
pub mod sync;
pub mod tls;

pub use backoff::Backoff;
pub use error::{MailError, Result};
pub use imap::{
    FetchedMessage, IdleOutcome, ImapConnection, ImapStream, MailboxStatus, ServerCaps,
};
pub use sync::{SyncPlan, plan_folder_sync};
pub use tls::{TlsSettings, connect_imap};
