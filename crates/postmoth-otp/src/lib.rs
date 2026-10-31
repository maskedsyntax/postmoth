//! One-time-code detection and the volatile candidate lifecycle (spec §8).
//!
//! Pipeline: [`engine::OtpEngine::process_message`] runs eligibility checks,
//! then [`detect::detect`], then binds the result to trusted origins via
//! [`mapping::DomainMatcher`] and stores it in [`cache::CandidateCache`].
//! The browser surface can then only ask "is there a suggestion for this
//! origin?" and redeem a single-use handle.
//!
//! Nothing in this crate persists or logs a code.

pub mod cache;
pub mod clock;
pub mod detect;
pub mod engine;
pub mod mapping;
pub mod origin;

pub use cache::{CacheConfig, CandidateCache};
pub use clock::{Clock, SystemClock, Timestamp};
pub use detect::{Confidence, DetectInput, Detection, detect};
pub use engine::{InboundMessage, OtpEngine, ProcessOutcome};
pub use mapping::{
    AuthRequirement, DomainMapping, DomainMatcher, SenderAuth, SenderPattern, TrustedOrigin,
};
pub use origin::{NormalizedOrigin, OriginError, OriginPolicy};
