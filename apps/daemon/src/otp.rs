//! The OTP service: the daemon-wide [`OtpEngine`] plus its trust mappings.

use postmoth_core::{AccountId, ErrorCode, SuggestionId};
use postmoth_otp::cache::FoundSuggestion;
use postmoth_otp::mapping::MappingSource;
use postmoth_otp::origin::normalize_host;
use postmoth_otp::{
    AuthRequirement, CacheConfig, Clock, DomainMapping, DomainMatcher, InboundMessage,
    NormalizedOrigin, OriginPolicy, OtpEngine, ProcessOutcome, SenderPattern, TrustedOrigin,
};
use postmoth_store::StoredMapping;
use secrecy::SecretString;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// The reviewed catalog shipped with this build.
pub const BUILTIN_CATALOG: &str = include_str!("../../../rules/otp-domains.toml");

pub struct OtpService {
    engine: Mutex<OtpEngine>,
    clock: Box<dyn Clock>,
    policy: OriginPolicy,
}

impl std::fmt::Debug for OtpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OtpService")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl OtpService {
    #[must_use]
    pub fn new(mappings: Vec<DomainMapping>, policy: OriginPolicy, clock: Box<dyn Clock>) -> Self {
        Self {
            engine: Mutex::new(OtpEngine::new(
                DomainMatcher::new(mappings),
                CacheConfig::default(),
                policy,
            )),
            clock,
            policy,
        }
    }

    fn engine(&self) -> MutexGuard<'_, OtpEngine> {
        // The engine's invariants hold between calls; recover from poison.
        self.engine.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn process(&self, msg: &InboundMessage<'_>) -> ProcessOutcome {
        let now = self.clock.now();
        self.engine().process_message(msg, now)
    }

    pub fn find(
        &self,
        top_origin: &str,
        tab_id: i64,
    ) -> Result<Option<FoundSuggestion>, ErrorCode> {
        let now = self.clock.now();
        self.engine().find(top_origin, tab_id, now)
    }

    pub fn consume(
        &self,
        id: SuggestionId,
        top_origin: &str,
        tab_id: i64,
    ) -> Result<SecretString, ErrorCode> {
        let now = self.clock.now();
        self.engine().consume(id, top_origin, tab_id, now)
    }

    pub fn purge_expired(&self) {
        let now = self.clock.now();
        self.engine().purge_expired(now);
    }

    pub fn set_paused(&self, paused: bool) {
        self.engine().set_paused(paused);
    }

    pub fn is_paused(&self) -> bool {
        self.engine().is_paused()
    }

    pub fn remove_account(&self, id: AccountId) {
        self.engine().remove_account(id);
    }

    pub fn clear(&self) {
        self.engine().clear();
    }

    pub fn live_candidates(&self) -> usize {
        self.engine().live_candidates()
    }

    pub fn replace_mappings(&self, mappings: Vec<DomainMapping>) {
        *self.engine().matcher_mut() = DomainMatcher::new(mappings);
    }

    #[must_use]
    pub fn origin_policy(&self) -> OriginPolicy {
        self.policy
    }
}

/// Normalize a user-supplied site (`https://login.example.com` or a bare
/// host) to the host string we store and match on.
pub fn normalize_site(input: &str, policy: OriginPolicy) -> Option<String> {
    let input = input.trim();
    if input.contains("://") {
        NormalizedOrigin::parse(input, policy)
            .ok()
            .map(|o| o.host().to_owned())
    } else {
        normalize_host(input)
    }
}

/// Validate a user mapping and convert it for the matcher.
pub fn user_mapping(
    sender_pattern: &str,
    host: &str,
    include_subdomains: bool,
) -> Option<DomainMapping> {
    Some(DomainMapping {
        sender: SenderPattern::parse(sender_pattern).ok()?,
        origins: vec![TrustedOrigin::new(host, include_subdomains).ok()?],
        // User confirmed this pairing; still reject an explicit DMARC fail.
        auth: AuthRequirement::IfAvailable,
        source: MappingSource::User,
    })
}

/// Catalog rules (built-in, then optional user file) followed by stored
/// mappings. Invalid stored rows are skipped and logged, never trusted.
pub fn build_mappings(user_catalog: Option<&str>, stored: &[StoredMapping]) -> Vec<DomainMapping> {
    let mut out = match DomainMatcher::load_catalog(BUILTIN_CATALOG) {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(error = %e, "built-in OTP catalog is invalid; ignoring it");
            Vec::new()
        }
    };
    if let Some(src) = user_catalog {
        match DomainMatcher::load_catalog(src) {
            Ok(m) => out.extend(m),
            Err(e) => tracing::warn!(error = %e, "user OTP rules file rejected"),
        }
    }
    for m in stored {
        match user_mapping(&m.sender_pattern, &m.trusted_origin, m.include_subdomains) {
            Some(dm) => out.push(dm),
            None => tracing::warn!(id = m.id, "skipping invalid stored domain mapping"),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_catalog_parses() {
        DomainMatcher::load_catalog(BUILTIN_CATALOG).expect("catalog");
    }

    #[test]
    fn site_normalization() {
        let p = OriginPolicy::default();
        assert_eq!(
            normalize_site("https://Login.Example.com", p).as_deref(),
            Some("login.example.com")
        );
        assert_eq!(
            normalize_site("login.example.com", p).as_deref(),
            Some("login.example.com")
        );
        assert_eq!(normalize_site("http://login.example.com", p), None);
        assert!(
            user_mapping("@example.com", "com", false).is_none(),
            "public suffix"
        );
        assert!(user_mapping("not an address", "example.com", false).is_none());
        assert!(user_mapping("@example.com", "login.example.com", true).is_some());
    }
}
