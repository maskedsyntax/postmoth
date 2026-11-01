//! Linux desktop integration for Postmoth.
//!
//! * [`paths`]: XDG base directories, with owner-only permission checks.
//! * [`secrets`]: account credentials in the Secret Service (via `oo7`),
//!   plus an in-memory backend for tests.

pub mod paths;
pub mod secrets;

pub use paths::{PathError, Paths, ensure_private_dir};
pub use secrets::{SecretError, Secrets};
