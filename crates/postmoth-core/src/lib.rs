//! Shared domain types for Postmoth.
//!
//! This crate is deliberately free of I/O, async runtimes and UI toolkits so
//! that every other crate (daemon, native host, desktop UI) can depend on it.

pub mod error;
pub mod ids;
pub mod model;
pub mod redact;

pub use error::{Error, ErrorCode, Result};
pub use ids::{AccountId, FolderId, MessageId, SuggestionId};
pub use redact::Redacted;
