//! Volatile, in-memory OTP candidate cache (spec §8.1, §8.5).
//!
//! * Candidates live only in memory and expire after a short TTL.
//! * `find` issues a fresh, single-use [`SuggestionId`] bound to the exact
//!   origin and tab that asked; it never reveals the code.
//! * `consume` re-validates origin + tab + expiry, returns the code once, and
//!   destroys the candidate. Any mismatch burns the handle (no probing).

use crate::clock::Timestamp;
use crate::mapping::TrustedOrigin;
use crate::origin::NormalizedOrigin;
use postmoth_core::{AccountId, ErrorCode, MessageId, SuggestionId};
use secrecy::SecretString;
use std::time::Duration;

/// Hard bounds on configurable TTL.
pub const MIN_TTL: Duration = Duration::from_secs(30);
pub const MAX_TTL: Duration = Duration::from_secs(10 * 60);
pub const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
/// How long a suggestion handle stays redeemable after `find`.
pub const SUGGESTION_TTL: Duration = Duration::from_secs(60);
/// Bounded memory: oldest candidates are evicted beyond this.
pub const MAX_CANDIDATES: usize = 16;
const MAX_SUGGESTIONS: usize = 64;

#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    ttl: Duration,
}

impl CacheConfig {
    /// TTL is clamped into `[MIN_TTL, MAX_TTL]`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl: ttl.clamp(MIN_TTL, MAX_TTL),
        }
    }

    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

/// An OTP candidate. `Debug` never shows the code (`SecretString` redacts).
#[derive(Debug)]
pub struct OtpCandidate {
    pub id: u64,
    pub account_id: AccountId,
    pub source_message_id: MessageId,
    pub origins: Vec<TrustedOrigin>,
    pub code: SecretString,
    pub created_at: Timestamp,
}

#[derive(Debug)]
struct Suggestion {
    id: SuggestionId,
    candidate_id: u64,
    origin: NormalizedOrigin,
    tab_id: i64,
    created_at: Timestamp,
}

#[derive(Debug, Default)]
pub struct CandidateCache {
    config: CacheConfig,
    next_id: u64,
    candidates: Vec<OtpCandidate>,
    suggestions: Vec<Suggestion>,
}

/// What callers get back from `find`: an opaque handle, no code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FoundSuggestion {
    pub suggestion_id: SuggestionId,
}

impl CandidateCache {
    #[must_use]
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    pub fn set_config(&mut self, config: CacheConfig) {
        self.config = config;
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Store a candidate. Candidates with no trusted origins are refused:
    /// there is nowhere they could ever be offered.
    pub fn insert(
        &mut self,
        account_id: AccountId,
        source_message_id: MessageId,
        origins: Vec<TrustedOrigin>,
        code: SecretString,
        now: Timestamp,
    ) -> bool {
        if origins.is_empty() {
            return false;
        }
        self.purge_expired(&now);
        // A newer message from the same source replaces older candidates
        // that target the same origins (e.g. "resend code").
        self.candidates.retain(|c| c.origins != origins);
        self.next_id += 1;
        self.candidates.push(OtpCandidate {
            id: self.next_id,
            account_id,
            source_message_id,
            origins,
            code,
            created_at: now,
        });
        while self.candidates.len() > MAX_CANDIDATES {
            self.candidates.remove(0);
        }
        self.drop_orphan_suggestions();
        true
    }

    /// Is there exactly one live candidate for this origin? If so, mint a
    /// single-use handle bound to `(origin, tab_id)`.
    pub fn find(
        &mut self,
        origin: &NormalizedOrigin,
        tab_id: i64,
        now: Timestamp,
    ) -> Option<FoundSuggestion> {
        self.purge_expired(&now);
        let mut matching = self
            .candidates
            .iter()
            .filter(|c| c.origins.iter().any(|o| o.matches(origin)));
        let candidate = matching.next()?;
        if matching.next().is_some() {
            // Ambiguous: several live codes for one site. Fail closed.
            return None;
        }
        let candidate_id = candidate.id;
        // One outstanding handle per (candidate, origin, tab).
        self.suggestions.retain(|s| {
            !(s.candidate_id == candidate_id && s.origin == *origin && s.tab_id == tab_id)
        });
        let id = SuggestionId::new();
        self.suggestions.push(Suggestion {
            id,
            candidate_id,
            origin: origin.clone(),
            tab_id,
            created_at: now,
        });
        while self.suggestions.len() > MAX_SUGGESTIONS {
            self.suggestions.remove(0);
        }
        Some(FoundSuggestion { suggestion_id: id })
    }

    /// Redeem a handle. Succeeds at most once per candidate.
    pub fn consume(
        &mut self,
        suggestion_id: SuggestionId,
        origin: &NormalizedOrigin,
        tab_id: i64,
        now: Timestamp,
    ) -> Result<SecretString, ErrorCode> {
        self.purge_expired(&now);
        let pos = self
            .suggestions
            .iter()
            .position(|s| s.id == suggestion_id)
            .ok_or(ErrorCode::Expired)?;
        // Burn the handle no matter what happens next.
        let s = self.suggestions.swap_remove(pos);
        if s.origin != *origin || s.tab_id != tab_id {
            return Err(ErrorCode::NoMatch);
        }
        let cpos = self
            .candidates
            .iter()
            .position(|c| c.id == s.candidate_id)
            .ok_or(ErrorCode::Expired)?;
        // Re-check the binding against the candidate itself.
        if !self.candidates[cpos]
            .origins
            .iter()
            .any(|o| o.matches(origin))
        {
            return Err(ErrorCode::NoMatch);
        }
        let candidate = self.candidates.remove(cpos);
        self.drop_orphan_suggestions();
        Ok(candidate.code)
    }

    pub fn purge_expired(&mut self, now: &Timestamp) {
        let ttl = self.config.ttl;
        self.candidates
            .retain(|c| !c.created_at.elapsed_exceeds(now, ttl));
        self.suggestions
            .retain(|s| !s.created_at.elapsed_exceeds(now, SUGGESTION_TTL));
        self.drop_orphan_suggestions();
    }

    pub fn remove_account(&mut self, account_id: AccountId) {
        self.candidates.retain(|c| c.account_id != account_id);
        self.drop_orphan_suggestions();
    }

    /// Drop everything (pause, lock screen, shutdown).
    pub fn clear(&mut self) {
        self.candidates.clear();
        self.suggestions.clear();
    }

    fn drop_orphan_suggestions(&mut self) {
        let live: Vec<u64> = self.candidates.iter().map(|c| c.id).collect();
        self.suggestions.retain(|s| live.contains(&s.candidate_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{Clock, SystemClock};
    use crate::origin::OriginPolicy;
    use secrecy::ExposeSecret;

    fn origin(s: &str) -> NormalizedOrigin {
        NormalizedOrigin::parse(s, OriginPolicy::default()).expect("valid")
    }

    fn trusted(h: &str) -> Vec<TrustedOrigin> {
        vec![TrustedOrigin::new(h, false).expect("valid")]
    }

    fn setup() -> (CandidateCache, Timestamp, AccountId) {
        let mut c = CandidateCache::new(CacheConfig::default());
        let now = SystemClock.now();
        let acct = AccountId::new();
        assert!(c.insert(
            acct,
            MessageId::new(),
            trusted("login.example.com"),
            SecretString::from("482913"),
            now
        ));
        (c, now, acct)
    }

    #[test]
    fn happy_path_single_use() {
        let (mut c, now, _) = setup();
        let o = origin("https://login.example.com");
        let s = c.find(&o, 7, now).expect("found");
        let code = c.consume(s.suggestion_id, &o, 7, now).expect("code");
        assert_eq!(code.expose_secret(), "482913");
        assert_eq!(
            c.consume(s.suggestion_id, &o, 7, now).err(),
            Some(ErrorCode::Expired)
        );
        assert!(
            c.find(&o, 7, now).is_none(),
            "candidate destroyed after use"
        );
    }

    #[test]
    fn unrelated_origin_gets_nothing() {
        let (mut c, now, _) = setup();
        assert!(
            c.find(&origin("https://evil.example.net"), 7, now)
                .is_none()
        );
        assert!(
            c.find(&origin("https://login.example.com.evil.net"), 7, now)
                .is_none()
        );
    }

    #[test]
    fn handle_is_bound_to_origin_and_tab_and_burns_on_mismatch() {
        let (mut c, now, _) = setup();
        let o = origin("https://login.example.com");
        let s = c.find(&o, 7, now).expect("found");
        assert_eq!(
            c.consume(s.suggestion_id, &origin("https://evil.example.net"), 7, now)
                .err(),
            Some(ErrorCode::NoMatch)
        );
        // Handle burned; even the right caller must ask again.
        assert_eq!(
            c.consume(s.suggestion_id, &o, 7, now).err(),
            Some(ErrorCode::Expired)
        );
        let s2 = c.find(&o, 7, now).expect("found again");
        assert_eq!(
            c.consume(s2.suggestion_id, &o, 8, now).err(),
            Some(ErrorCode::NoMatch)
        );
    }

    #[test]
    fn expiry() {
        let (mut c, now, _) = setup();
        let o = origin("https://login.example.com");
        let later = now.plus(DEFAULT_TTL + Duration::from_secs(1));
        assert!(c.find(&o, 7, later).is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn suggestion_handle_expires_before_candidate() {
        let (mut c, now, _) = setup();
        let o = origin("https://login.example.com");
        let s = c.find(&o, 7, now).expect("found");
        let later = now.plus(SUGGESTION_TTL + Duration::from_secs(1));
        assert_eq!(
            c.consume(s.suggestion_id, &o, 7, later).err(),
            Some(ErrorCode::Expired)
        );
        assert!(c.find(&o, 7, later).is_some(), "candidate still alive");
    }

    #[test]
    fn ambiguity_fails_closed() {
        let (mut c, now, acct) = setup();
        c.insert(
            acct,
            MessageId::new(),
            vec![
                TrustedOrigin::new("login.example.com", false).expect("ok"),
                TrustedOrigin::new("other.example.com", false).expect("ok"),
            ],
            SecretString::from("111111"),
            now,
        );
        assert!(
            c.find(&origin("https://login.example.com"), 7, now)
                .is_none()
        );
    }

    #[test]
    fn newer_code_for_same_site_replaces_older() {
        let (mut c, now, acct) = setup();
        c.insert(
            acct,
            MessageId::new(),
            trusted("login.example.com"),
            SecretString::from("999999"),
            now,
        );
        let o = origin("https://login.example.com");
        let s = c.find(&o, 1, now).expect("found");
        assert_eq!(
            c.consume(s.suggestion_id, &o, 1, now)
                .expect("code")
                .expose_secret(),
            "999999"
        );
    }

    #[test]
    fn account_removal_and_clear() {
        let (mut c, now, acct) = setup();
        let o = origin("https://login.example.com");
        let s = c.find(&o, 1, now).expect("found");
        c.remove_account(acct);
        assert!(c.is_empty());
        assert_eq!(
            c.consume(s.suggestion_id, &o, 1, now).err(),
            Some(ErrorCode::Expired)
        );
    }

    #[test]
    fn no_origins_no_insert() {
        let mut c = CandidateCache::default();
        assert!(!c.insert(
            AccountId::new(),
            MessageId::new(),
            vec![],
            SecretString::from("1"),
            SystemClock.now()
        ));
    }

    #[test]
    fn ttl_is_clamped() {
        assert_eq!(CacheConfig::new(Duration::from_secs(1)).ttl(), MIN_TTL);
        assert_eq!(CacheConfig::new(Duration::from_secs(86400)).ttl(), MAX_TTL);
    }

    #[test]
    fn debug_does_not_leak_code() {
        let (c, _, _) = setup();
        assert!(!format!("{c:?}").contains("482913"));
    }
}
