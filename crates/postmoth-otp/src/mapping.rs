//! Sender ↔ website trust mappings (spec §8.3).
//!
//! A code may only ever be offered on an origin that a *vetted rule* or an
//! *explicit user confirmation* associates with the message's sender. Email
//! content, display names and DNS resemblance are never consulted.

use crate::origin::{NormalizedOrigin, normalize_host};
use serde::Deserialize;

/// A website a mapping trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedOrigin {
    host: String,
    include_subdomains: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MappingError {
    #[error("invalid host")]
    InvalidHost,
    #[error("host is a public suffix and cannot be trusted")]
    PublicSuffix,
    #[error("invalid sender pattern")]
    InvalidSender,
    #[error("catalog parse error: {0}")]
    Catalog(String),
}

impl TrustedOrigin {
    pub fn new(host: &str, include_subdomains: bool) -> Result<Self, MappingError> {
        let host = normalize_host(host).ok_or(MappingError::InvalidHost)?;
        // The host must contain a registrable domain; refuse `com`,
        // `co.uk`, `github.io`, etc.
        match psl::domain_str(&host) {
            Some(_) => {}
            None => return Err(MappingError::PublicSuffix),
        }
        Ok(Self {
            host,
            include_subdomains,
        })
    }

    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Exact host match, or a strict subdomain when explicitly enabled.
    /// Never substring or suffix-without-dot matching.
    #[must_use]
    pub fn matches(&self, origin: &NormalizedOrigin) -> bool {
        let host = origin.host();
        if host == self.host {
            return true;
        }
        if !self.include_subdomains {
            return false;
        }
        let Some(prefix) = host.strip_suffix(self.host.as_str()) else {
            return false;
        };
        if !prefix.ends_with('.') || prefix.len() < 2 {
            return false;
        }
        // Belt and braces: both must share one registrable domain.
        matches!(
            (psl::domain_str(host), psl::domain_str(&self.host)),
            (Some(a), Some(b)) if a == b
        )
    }
}

/// Which senders a mapping covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SenderPattern {
    /// Exactly this address (case-insensitive).
    Address(String),
    /// Any address at exactly this domain (no subdomains).
    Domain(String),
}

impl SenderPattern {
    pub fn parse(pattern: &str) -> Result<Self, MappingError> {
        let pattern = pattern.trim().to_ascii_lowercase();
        if let Some(domain) = pattern.strip_prefix('@') {
            let d = normalize_host(domain).ok_or(MappingError::InvalidSender)?;
            psl::domain_str(&d).ok_or(MappingError::InvalidSender)?;
            return Ok(Self::Domain(d));
        }
        let (local, domain) = split_address(&pattern).ok_or(MappingError::InvalidSender)?;
        let d = normalize_host(domain).ok_or(MappingError::InvalidSender)?;
        Ok(Self::Address(format!("{local}@{d}")))
    }

    fn domain(&self) -> &str {
        match self {
            Self::Address(a) => split_address(a).map_or("", |(_, d)| d),
            Self::Domain(d) => d,
        }
    }

    fn matches_sender(&self, sender: &str) -> bool {
        let Some(norm) = normalize_address(sender) else {
            return false;
        };
        match self {
            Self::Address(a) => *a == norm,
            Self::Domain(d) => split_address(&norm).is_some_and(|(_, sd)| sd == d),
        }
    }
}

fn split_address(addr: &str) -> Option<(&str, &str)> {
    let (local, domain) = addr.rsplit_once('@')?;
    if local.is_empty() || domain.is_empty() || local.contains(char::is_whitespace) {
        return None;
    }
    Some((local, domain))
}

/// Lowercase an address and IDNA-normalize its domain.
#[must_use]
pub fn normalize_address(addr: &str) -> Option<String> {
    let addr = addr.trim().to_ascii_lowercase();
    let (local, domain) = split_address(&addr)?;
    let d = normalize_host(domain)?;
    Some(format!("{local}@{d}"))
}

/// Sender authentication as reported by the receiving provider's
/// `Authentication-Results` header. Postmoth does not re-verify DKIM itself
/// in v1; it only trusts results stamped by the user's own provider.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SenderAuth {
    /// No trustworthy results available.
    #[default]
    Unknown,
    Results {
        dmarc_pass: Option<bool>,
        /// `header.d=` domains of passing DKIM signatures.
        dkim_pass_domains: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequirement {
    /// DMARC pass, or a DKIM pass aligned (same registrable domain) with
    /// the sender domain, must be present. Default for catalog rules.
    #[default]
    Required,
    /// Accept when results are missing; reject an explicit DMARC fail.
    /// Used for user-confirmed mappings.
    IfAvailable,
}

impl AuthRequirement {
    fn satisfied(self, sender_domain: &str, auth: &SenderAuth) -> bool {
        match (self, auth) {
            (Self::IfAvailable, SenderAuth::Unknown) => true,
            (Self::Required, SenderAuth::Unknown) => false,
            (
                req,
                SenderAuth::Results {
                    dmarc_pass,
                    dkim_pass_domains,
                },
            ) => {
                if *dmarc_pass == Some(false) {
                    return false;
                }
                if *dmarc_pass == Some(true) {
                    return true;
                }
                let org = psl::domain_str(sender_domain);
                let aligned = dkim_pass_domains.iter().any(|d| {
                    let d = d.to_ascii_lowercase();
                    d == sender_domain || (org.is_some() && psl::domain_str(&d) == org)
                });
                aligned || req == Self::IfAvailable
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingSource {
    /// Shipped, reviewed rule catalog.
    Catalog,
    /// Confirmed by the user in the UI.
    User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMapping {
    pub sender: SenderPattern,
    pub origins: Vec<TrustedOrigin>,
    pub auth: AuthRequirement,
    pub source: MappingSource,
}

/// Resolves which origins (if any) a sender's codes may be offered on.
#[derive(Debug, Default, Clone)]
pub struct DomainMatcher {
    mappings: Vec<DomainMapping>,
}

impl DomainMatcher {
    #[must_use]
    pub fn new(mappings: Vec<DomainMapping>) -> Self {
        Self { mappings }
    }

    pub fn add(&mut self, mapping: DomainMapping) {
        self.mappings.push(mapping);
    }

    #[must_use]
    pub fn mappings(&self) -> &[DomainMapping] {
        &self.mappings
    }

    /// All origins trusted for this sender given its authentication state.
    /// Empty means: never offer this code anywhere.
    #[must_use]
    pub fn origins_for(&self, sender: &str, auth: &SenderAuth) -> Vec<TrustedOrigin> {
        let mut out: Vec<TrustedOrigin> = Vec::new();
        for m in &self.mappings {
            if m.sender.matches_sender(sender) && m.auth.satisfied(m.sender.domain(), auth) {
                for o in &m.origins {
                    if !out.contains(o) {
                        out.push(o.clone());
                    }
                }
            }
        }
        out
    }

    /// Load the reviewed rule catalog (TOML). Every entry is validated; one
    /// bad entry rejects the whole catalog so mistakes are noticed.
    pub fn load_catalog(toml_src: &str) -> Result<Vec<DomainMapping>, MappingError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Catalog {
            #[serde(default)]
            rule: Vec<Rule>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Rule {
            senders: Vec<String>,
            origins: Vec<String>,
            #[serde(default)]
            include_subdomains: bool,
            #[serde(default)]
            auth: AuthRequirement,
        }
        let cat: Catalog =
            toml::from_str(toml_src).map_err(|e| MappingError::Catalog(e.to_string()))?;
        let mut out = Vec::new();
        for r in cat.rule {
            let origins = r
                .origins
                .iter()
                .map(|h| TrustedOrigin::new(h, r.include_subdomains))
                .collect::<Result<Vec<_>, _>>()?;
            if origins.is_empty() {
                return Err(MappingError::InvalidHost);
            }
            for s in &r.senders {
                out.push(DomainMapping {
                    sender: SenderPattern::parse(s)?,
                    origins: origins.clone(),
                    auth: r.auth,
                    source: MappingSource::Catalog,
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::OriginPolicy;

    fn origin(s: &str) -> NormalizedOrigin {
        NormalizedOrigin::parse(s, OriginPolicy::default()).expect("valid origin")
    }

    fn dmarc_pass() -> SenderAuth {
        SenderAuth::Results {
            dmarc_pass: Some(true),
            dkim_pass_domains: vec![],
        }
    }

    #[test]
    fn exact_origin_matching() {
        let t = TrustedOrigin::new("login.example.com", false).expect("ok");
        assert!(t.matches(&origin("https://login.example.com")));
        assert!(!t.matches(&origin("https://example.com")));
        assert!(!t.matches(&origin("https://evil.login.example.com")));
    }

    #[test]
    fn lookalikes_never_match() {
        let t = TrustedOrigin::new("example.com", true).expect("ok");
        for bad in [
            "https://example.com.evil.net",
            "https://evilexample.com",
            "https://exarnple.com",
            "https://example.co",
            "https://example.com-login.net",
            "https://xn--exmple-cua.com", // exämple.com
            "https://еxample.com",        // Cyrillic е
        ] {
            assert!(!t.matches(&origin(bad)), "{bad} must not match");
        }
        assert!(t.matches(&origin("https://accounts.example.com")));
        assert!(t.matches(&origin("https://a.b.example.com")));
    }

    #[test]
    fn public_suffixes_cannot_be_trusted() {
        assert_eq!(
            TrustedOrigin::new("com", true),
            Err(MappingError::PublicSuffix)
        );
        assert_eq!(
            TrustedOrigin::new("co.uk", true),
            Err(MappingError::PublicSuffix)
        );
        assert_eq!(
            TrustedOrigin::new("github.io", true),
            Err(MappingError::PublicSuffix)
        );
    }

    #[test]
    fn subdomain_of_private_suffix_does_not_spread() {
        // alice.github.io trusted with subdomains must not cover bob.github.io.
        let t = TrustedOrigin::new("alice.github.io", true).expect("ok");
        assert!(!t.matches(&origin("https://bob.github.io")));
        assert!(t.matches(&origin("https://www.alice.github.io")));
    }

    #[test]
    fn sender_patterns() {
        let m = DomainMatcher::new(vec![DomainMapping {
            sender: SenderPattern::parse("no-reply@Accounts.Example.com").expect("ok"),
            origins: vec![TrustedOrigin::new("login.example.com", false).expect("ok")],
            auth: AuthRequirement::Required,
            source: MappingSource::Catalog,
        }]);
        assert_eq!(
            m.origins_for("NO-REPLY@accounts.example.com", &dmarc_pass())
                .len(),
            1
        );
        assert!(
            m.origins_for("no-reply@example.com", &dmarc_pass())
                .is_empty()
        );
        assert!(
            m.origins_for("no-reply@accounts.example.com.evil.net", &dmarc_pass())
                .is_empty()
        );
    }

    #[test]
    fn domain_pattern_is_exact_domain() {
        assert_eq!(
            SenderPattern::parse("@example.com").expect("ok"),
            SenderPattern::Domain("example.com".into())
        );
        let p = SenderPattern::parse("@example.com").expect("ok");
        assert!(p.matches_sender("a@example.com"));
        assert!(!p.matches_sender("a@mail.example.com"));
        assert!(!p.matches_sender("a@notexample.com"));
        assert!(SenderPattern::parse("@com").is_err());
    }

    #[test]
    fn auth_requirements() {
        let req = AuthRequirement::Required;
        assert!(!req.satisfied("example.com", &SenderAuth::Unknown));
        assert!(req.satisfied("example.com", &dmarc_pass()));
        let dkim_aligned = SenderAuth::Results {
            dmarc_pass: None,
            dkim_pass_domains: vec!["mail.example.com".into()],
        };
        assert!(req.satisfied("example.com", &dkim_aligned));
        let dkim_other = SenderAuth::Results {
            dmarc_pass: None,
            dkim_pass_domains: vec!["sendgrid.net".into()],
        };
        assert!(!req.satisfied("example.com", &dkim_other));
        let dmarc_fail = SenderAuth::Results {
            dmarc_pass: Some(false),
            dkim_pass_domains: vec!["example.com".into()],
        };
        assert!(!req.satisfied("example.com", &dmarc_fail));

        let lax = AuthRequirement::IfAvailable;
        assert!(lax.satisfied("example.com", &SenderAuth::Unknown));
        assert!(!lax.satisfied("example.com", &dmarc_fail));
    }

    #[test]
    fn shipped_catalog_is_valid() {
        DomainMatcher::load_catalog(include_str!("../../../rules/otp-domains.toml"))
            .expect("rules/otp-domains.toml must load");
    }

    #[test]
    fn catalog_loading_validates() {
        let ok = r#"
            [[rule]]
            senders = ["no-reply@accounts.example.com"]
            origins = ["login.example.com"]
        "#;
        let maps = DomainMatcher::load_catalog(ok).expect("ok");
        assert_eq!(maps.len(), 1);
        assert_eq!(maps[0].auth, AuthRequirement::Required);

        let bad = r#"
            [[rule]]
            senders = ["a@example.com"]
            origins = ["com"]
            include_subdomains = true
        "#;
        assert!(DomainMatcher::load_catalog(bad).is_err());

        let unknown_field = r#"
            [[rule]]
            senders = ["a@example.com"]
            origins = ["example.com"]
            wildcard = true
        "#;
        assert!(DomainMatcher::load_catalog(unknown_field).is_err());
    }
}
