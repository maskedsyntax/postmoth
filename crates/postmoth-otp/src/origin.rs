//! Strict normalization of the browser's top-level origin (spec §8.3).

use url::{Host, Url};

/// A validated, normalized top-level origin. Only the host is retained:
/// scheme is always `https` (or `http` for an opted-in localhost), and only
/// the default port is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NormalizedOrigin {
    /// Lowercase ASCII (punycode) host, no trailing dot.
    host: String,
}

impl NormalizedOrigin {
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OriginPolicy {
    /// Allow `http://localhost` / `https://localhost` for development.
    /// Off by default; must be an explicit user setting.
    pub allow_localhost_dev: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OriginError {
    #[error("not a valid URL")]
    Invalid,
    #[error("scheme must be https")]
    Scheme,
    #[error("non-default ports are not supported")]
    Port,
    #[error("origins with credentials or IP-literal hosts are not supported")]
    Host,
    #[error("localhost requires the development setting")]
    Localhost,
}

impl NormalizedOrigin {
    /// Parse an origin as supplied by the extension service worker.
    ///
    /// Accepts a bare origin or a full URL (path/query are ignored). Rejects
    /// anything that is not plain HTTPS on a DNS name with the default port.
    pub fn parse(input: &str, policy: OriginPolicy) -> Result<Self, OriginError> {
        let url = Url::parse(input.trim()).map_err(|_| OriginError::Invalid)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(OriginError::Host);
        }
        let host = match url.host() {
            Some(Host::Domain(d)) => d.to_owned(),
            // IP literals cannot be meaningfully bound to a sender domain.
            Some(Host::Ipv4(_) | Host::Ipv6(_)) | None => return Err(OriginError::Host),
        };
        // `url` lowercases and IDNA-encodes special-scheme hosts. A trailing
        // dot is a distinct origin in browsers; refuse it, don't guess.
        if host.ends_with('.') || host.is_empty() {
            return Err(OriginError::Host);
        }
        let is_localhost = host == "localhost" || host.ends_with(".localhost");
        match url.scheme() {
            "https" => {}
            "http" if is_localhost => {}
            _ => return Err(OriginError::Scheme),
        }
        if is_localhost {
            if !policy.allow_localhost_dev {
                return Err(OriginError::Localhost);
            }
        } else if url.port().is_some() {
            // `Url::port()` is None for the scheme default.
            return Err(OriginError::Port);
        }
        Ok(Self { host })
    }
}

/// Normalize a host name from configuration (rule catalog / user mapping)
/// using the same rules the browser origin goes through.
pub fn normalize_host(host: &str) -> Option<String> {
    let url = Url::parse(&format!("https://{}/", host.trim())).ok()?;
    match url.host() {
        Some(Host::Domain(d)) if !d.ends_with('.') && !d.is_empty() && url.port().is_none() => {
            // Reject anything that smuggled in a path/userinfo.
            if url.path() != "/" || !url.username().is_empty() {
                return None;
            }
            Some(d.to_owned())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<String, OriginError> {
        NormalizedOrigin::parse(s, OriginPolicy::default()).map(|o| o.host)
    }

    #[test]
    fn accepts_plain_https() {
        assert_eq!(
            p("https://login.example.com").as_deref(),
            Ok("login.example.com")
        );
        assert_eq!(
            p("https://Login.EXAMPLE.com/path?q=1").as_deref(),
            Ok("login.example.com")
        );
        assert_eq!(
            p("https://login.example.com:443").as_deref(),
            Ok("login.example.com")
        );
    }

    #[test]
    fn idn_becomes_punycode() {
        assert_eq!(
            p("https://bücher.example").as_deref(),
            Ok("xn--bcher-kva.example")
        );
    }

    #[test]
    fn rejects_non_https_and_weird_forms() {
        assert_eq!(p("http://example.com"), Err(OriginError::Scheme));
        assert!(p("chrome://settings").is_err());
        assert!(p("file:///etc/passwd").is_err());
        assert_eq!(p("https://example.com:8443"), Err(OriginError::Port));
        assert_eq!(p("https://user:pw@example.com"), Err(OriginError::Host));
        assert_eq!(p("https://127.0.0.1"), Err(OriginError::Host));
        assert_eq!(p("https://[::1]"), Err(OriginError::Host));
        assert_eq!(p("https://example.com."), Err(OriginError::Host));
        assert_eq!(p("not a url"), Err(OriginError::Invalid));
        assert!(p("data:text/html,hi").is_err());
        assert!(p("blob:https://example.com/uuid").is_err());
    }

    #[test]
    fn localhost_needs_opt_in() {
        assert_eq!(p("https://localhost"), Err(OriginError::Localhost));
        let dev = OriginPolicy {
            allow_localhost_dev: true,
        };
        assert!(NormalizedOrigin::parse("http://localhost:8080", dev).is_ok());
        assert!(NormalizedOrigin::parse("https://app.localhost:3000", dev).is_ok());
    }

    #[test]
    fn normalize_host_rules() {
        assert_eq!(
            normalize_host("Login.Example.COM").as_deref(),
            Some("login.example.com")
        );
        assert_eq!(normalize_host("example.com/evil"), None);
        assert_eq!(normalize_host("a@example.com"), None);
        assert_eq!(normalize_host("example.com:8443"), None);
        assert_eq!(normalize_host("example.com."), None);
        assert_eq!(normalize_host("10.0.0.1"), None);
    }
}
