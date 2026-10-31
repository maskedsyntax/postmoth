//! Safe MIME handling for Postmoth (spec §7.2, §7.4).
//!
//! * [`parse`] turns raw RFC 5322 bytes into a [`NormalizedMessage`]:
//!   decoded headers, a plain-text body, sanitized HTML, attachment metadata.
//! * [`sanitize`] is the HTML policy: no scripts, forms, frames or active
//!   content; remote resources are blocked by default.
//! * [`auth`] reads `Authentication-Results` stamped by the user's own
//!   provider, which feeds OTP sender trust.
//!
//! Every input is untrusted. Sizes are capped and nothing here panics on
//! malformed mail.

pub mod attach;
pub mod auth;
pub mod parse;
pub mod sanitize;

pub use attach::{AttachmentMeta, AttachmentRisk};
pub use auth::{AuthResults, AuthVerdict};
pub use parse::{Limits, MimeError, NormalizedMessage, ParseOptions, parse};
pub use sanitize::{RemoteContent, SanitizedHtml, sanitize_html};
