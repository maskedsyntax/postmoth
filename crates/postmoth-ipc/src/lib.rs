//! IPC protocol definitions.
//!
//! * [`browser`]: the narrow, extension-only surface (spec §6.2, §8.5). The
//!   same JSON flows extension → native host → daemon socket.
//! * [`framing`]: Chromium native-messaging framing (u32 native-endian length
//!   prefix + UTF-8 JSON), reused on the host ↔ daemon socket.

//! * [`control`]: the UI/CLI ↔ daemon control surface on the session bus.

pub mod browser;
pub mod control;
pub mod framing;
#[cfg(feature = "tokio")]
pub mod framing_async;

/// Current browser protocol version.
pub const BROWSER_PROTOCOL_VERSION: u32 = 1;
