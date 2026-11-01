//! Glue: eligibility → detection → trust binding → cache.

use crate::cache::{CacheConfig, CandidateCache, FoundSuggestion};
use crate::clock::Timestamp;
use crate::detect::{Confidence, DetectInput, detect};
use crate::mapping::{DomainMatcher, SenderAuth};
use crate::origin::{NormalizedOrigin, OriginPolicy};
use postmoth_core::{AccountId, ErrorCode, MessageId, SuggestionId};
use secrecy::SecretString;
use std::time::{Duration, SystemTime};

/// Messages older than this (by Date header or by arrival) are not inspected.
pub const MAX_MESSAGE_AGE: Duration = Duration::from_secs(10 * 60);
/// Tolerated clock skew for Date headers in the future.
const MAX_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);

/// Everything the engine needs to know about a newly received message.
/// Built by the daemon from the parsed MIME message.
#[derive(Debug)]
pub struct InboundMessage<'a> {
    pub account_id: AccountId,
    pub message_id: MessageId,
    /// Envelope `From` address (bare `local@domain`), untrusted.
    pub sender_address: &'a str,
    pub subject: &'a str,
    pub text: &'a str,
    /// Parsed `Date:` header.
    pub date: Option<SystemTime>,
    /// When the server received it (IMAP INTERNALDATE).
    pub received_at: SystemTime,
    pub auth: SenderAuth,
    pub is_bulk: bool,
    /// The message is in an inbound folder (not Sent/Drafts/Trash/Junk).
    pub is_inbound: bool,
}

/// Diagnostic outcome; never contains the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOutcome {
    Disabled,
    NotInbound,
    Stale,
    NoCode,
    LowConfidence(Confidence),
    NoTrustedOrigin,
    Stored,
}

#[derive(Debug)]
pub struct OtpEngine {
    matcher: DomainMatcher,
    cache: CandidateCache,
    origin_policy: OriginPolicy,
    paused: bool,
}

impl OtpEngine {
    #[must_use]
    pub fn new(matcher: DomainMatcher, config: CacheConfig, origin_policy: OriginPolicy) -> Self {
        Self {
            matcher,
            cache: CandidateCache::new(config),
            origin_policy,
            paused: false,
        }
    }

    pub fn matcher_mut(&mut self) -> &mut DomainMatcher {
        &mut self.matcher
    }

    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Pausing also drops every live candidate.
    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
        if paused {
            self.cache.clear();
        }
    }

    pub fn remove_account(&mut self, account_id: AccountId) {
        self.cache.remove_account(account_id);
    }

    /// Number of live candidates (diagnostics only; never the codes).
    #[must_use]
    pub fn live_candidates(&self) -> usize {
        self.cache.len()
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    pub fn process_message(&mut self, msg: &InboundMessage<'_>, now: Timestamp) -> ProcessOutcome {
        if self.paused {
            return ProcessOutcome::Disabled;
        }
        if !msg.is_inbound {
            return ProcessOutcome::NotInbound;
        }
        if !is_recent(msg.received_at, now.wall)
            || msg.date.is_some_and(|d| !is_recent(d, now.wall))
        {
            return ProcessOutcome::Stale;
        }
        let Some(det) = detect(&DetectInput {
            subject: msg.subject,
            text: msg.text,
            is_bulk: msg.is_bulk,
        }) else {
            return ProcessOutcome::NoCode;
        };
        if det.confidence < Confidence::High {
            return ProcessOutcome::LowConfidence(det.confidence);
        }
        let origins = self.matcher.origins_for(msg.sender_address, &msg.auth);
        if origins.is_empty() {
            return ProcessOutcome::NoTrustedOrigin;
        }
        if self
            .cache
            .insert(msg.account_id, msg.message_id, origins, det.code, now)
        {
            ProcessOutcome::Stored
        } else {
            ProcessOutcome::NoTrustedOrigin
        }
    }

    /// Browser `find_suggestion`. Errors use stable codes.
    pub fn find(
        &mut self,
        top_origin: &str,
        tab_id: i64,
        now: Timestamp,
    ) -> Result<Option<FoundSuggestion>, ErrorCode> {
        if self.paused {
            return Err(ErrorCode::Paused);
        }
        let Ok(origin) = NormalizedOrigin::parse(top_origin, self.origin_policy) else {
            // Unsupported origins look identical to "no match" to the caller.
            return Ok(None);
        };
        Ok(self.cache.find(&origin, tab_id, now))
    }

    /// Browser `consume_suggestion`.
    pub fn consume(
        &mut self,
        suggestion_id: SuggestionId,
        top_origin: &str,
        tab_id: i64,
        now: Timestamp,
    ) -> Result<SecretString, ErrorCode> {
        if self.paused {
            return Err(ErrorCode::Paused);
        }
        let origin = NormalizedOrigin::parse(top_origin, self.origin_policy)
            .map_err(|_| ErrorCode::NoMatch)?;
        self.cache.consume(suggestion_id, &origin, tab_id, now)
    }

    pub fn purge_expired(&mut self, now: Timestamp) {
        self.cache.purge_expired(&now);
    }
}

fn is_recent(t: SystemTime, now: SystemTime) -> bool {
    match now.duration_since(t) {
        Ok(age) => age <= MAX_MESSAGE_AGE,
        Err(e) => e.duration() <= MAX_FUTURE_SKEW,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::mapping::{
        AuthRequirement, DomainMapping, MappingSource, SenderPattern, TrustedOrigin,
    };
    use secrecy::ExposeSecret;

    fn engine() -> OtpEngine {
        let m = DomainMatcher::new(vec![DomainMapping {
            sender: SenderPattern::parse("no-reply@accounts.example.com").expect("ok"),
            origins: vec![TrustedOrigin::new("login.example.com", false).expect("ok")],
            auth: AuthRequirement::Required,
            source: MappingSource::Catalog,
        }]);
        OtpEngine::new(m, CacheConfig::default(), OriginPolicy::default())
    }

    fn msg<'a>(now: SystemTime, sender: &'a str, text: &'a str) -> InboundMessage<'a> {
        InboundMessage {
            account_id: AccountId::new(),
            message_id: MessageId::new(),
            sender_address: sender,
            subject: "Your sign-in code",
            text,
            date: Some(now),
            received_at: now,
            auth: SenderAuth::Results {
                dmarc_pass: Some(true),
                dkim_pass_domains: vec![],
            },
            is_bulk: false,
            is_inbound: true,
        }
    }

    const BODY: &str = "Your verification code is 482913.";
    const SENDER: &str = "no-reply@accounts.example.com";

    #[test]
    fn end_to_end_in_memory() {
        let mut e = engine();
        let now = SystemClock.now();
        assert_eq!(
            e.process_message(&msg(now.wall, SENDER, BODY), now),
            ProcessOutcome::Stored
        );
        let s = e
            .find("https://login.example.com", 3, now)
            .expect("ok")
            .expect("some");
        let code = e
            .consume(s.suggestion_id, "https://login.example.com", 3, now)
            .expect("code");
        assert_eq!(code.expose_secret(), "482913");
    }

    #[test]
    fn phishing_origin_gets_nothing() {
        let mut e = engine();
        let now = SystemClock.now();
        e.process_message(&msg(now.wall, SENDER, BODY), now);
        for o in [
            "https://login.example.com.evil.net",
            "https://login-example.com",
            "https://example.com",
            "http://login.example.com",
            "https://login.example.com:8443",
            "garbage",
        ] {
            assert_eq!(e.find(o, 3, now), Ok(None), "{o}");
        }
    }

    #[test]
    fn spoofed_sender_without_auth_is_not_bound() {
        let mut e = engine();
        let now = SystemClock.now();
        let mut m = msg(now.wall, SENDER, BODY);
        m.auth = SenderAuth::Unknown;
        assert_eq!(e.process_message(&m, now), ProcessOutcome::NoTrustedOrigin);
        m.auth = SenderAuth::Results {
            dmarc_pass: Some(false),
            dkim_pass_domains: vec![],
        };
        assert_eq!(e.process_message(&m, now), ProcessOutcome::NoTrustedOrigin);
    }

    #[test]
    fn unknown_sender_not_bound() {
        let mut e = engine();
        let now = SystemClock.now();
        assert_eq!(
            e.process_message(&msg(now.wall, "attacker@evil.net", BODY), now),
            ProcessOutcome::NoTrustedOrigin
        );
    }

    #[test]
    fn stale_and_outbound_ignored() {
        let mut e = engine();
        let now = SystemClock.now();
        let old = now.wall - Duration::from_secs(3600);
        assert_eq!(
            e.process_message(&msg(old, SENDER, BODY), now),
            ProcessOutcome::Stale
        );
        let mut m = msg(now.wall, SENDER, BODY);
        m.date = Some(old);
        assert_eq!(e.process_message(&m, now), ProcessOutcome::Stale);
        let mut m = msg(now.wall, SENDER, BODY);
        m.is_inbound = false;
        assert_eq!(e.process_message(&m, now), ProcessOutcome::NotInbound);
    }

    #[test]
    fn pause_clears_and_blocks() {
        let mut e = engine();
        let now = SystemClock.now();
        e.process_message(&msg(now.wall, SENDER, BODY), now);
        e.set_paused(true);
        assert_eq!(
            e.find("https://login.example.com", 1, now),
            Err(ErrorCode::Paused)
        );
        e.set_paused(false);
        assert_eq!(e.find("https://login.example.com", 1, now), Ok(None));
    }
}
