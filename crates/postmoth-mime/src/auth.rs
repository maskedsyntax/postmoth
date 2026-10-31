//! `Authentication-Results` (RFC 8601) parsing.
//!
//! Anyone can put an `Authentication-Results` header in a message they
//! send, so we trust **only the topmost** instance, and only when its
//! `authserv-id` is one the account is configured to trust (e.g.
//! `mx.google.com`). Well-behaved receiving MTAs strip forged headers that
//! carry their own id, and the topmost header is always the final hop's.

/// Parsed results from one trusted `Authentication-Results` header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthResults {
    pub authserv_id: String,
    /// `(passed, header.d)` for each DKIM result.
    pub dkim: Vec<(bool, Option<String>)>,
    /// `(passed, header.from)` for the DMARC result, if any.
    pub dmarc: Option<(bool, Option<String>)>,
}

/// Summary used by the OTP trust layer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthVerdict {
    pub dmarc_pass: Option<bool>,
    pub dkim_pass_domains: Vec<String>,
}

impl AuthResults {
    /// Reduce to a verdict for a message whose `From` domain is
    /// `from_domain`. A DMARC result for a different `header.from` is
    /// ignored rather than trusted.
    #[must_use]
    pub fn verdict(&self, from_domain: &str) -> AuthVerdict {
        let from_domain = from_domain.to_ascii_lowercase();
        let dmarc_pass = self.dmarc.as_ref().and_then(|(pass, hf)| match hf {
            Some(hf) if *hf != from_domain => None,
            _ => Some(*pass),
        });
        let dkim_pass_domains = self
            .dkim
            .iter()
            .filter_map(|(pass, d)| if *pass { d.clone() } else { None })
            .collect();
        AuthVerdict {
            dmarc_pass,
            dkim_pass_domains,
        }
    }
}

/// Parse the topmost header value if its authserv-id is trusted.
///
/// `values` are raw header values in document order (topmost first).
#[must_use]
pub fn trusted_results(values: &[&str], trusted_ids: &[String]) -> Option<AuthResults> {
    let top = values.first()?;
    let parsed = parse_value(top)?;
    trusted_ids
        .iter()
        .any(|id| id.eq_ignore_ascii_case(&parsed.authserv_id))
        .then_some(parsed)
}

/// Parse one `Authentication-Results` value. Lenient about unknown
/// methods, strict about structure; returns `None` if unusable.
#[must_use]
pub fn parse_value(value: &str) -> Option<AuthResults> {
    let unfolded = strip_comments(&value.replace(['\r', '\n'], " "));
    let mut clauses = unfolded.split(';');
    let authserv_id = clauses
        .next()?
        .split_whitespace()
        .next()?
        .to_ascii_lowercase();
    if authserv_id.is_empty() || authserv_id.contains('=') {
        return None;
    }
    let mut out = AuthResults {
        authserv_id,
        ..AuthResults::default()
    };
    for clause in clauses {
        let mut tokens = clause.split_whitespace();
        let Some(first) = tokens.next() else { continue };
        let Some((method, result)) = first.split_once('=') else {
            continue;
        };
        let method = method.to_ascii_lowercase();
        let pass = result.eq_ignore_ascii_case("pass");
        let mut header_d = None;
        let mut header_from = None;
        for t in tokens {
            if let Some((k, v)) = t.split_once('=') {
                let v = v.trim_matches('"').to_ascii_lowercase();
                match k.to_ascii_lowercase().as_str() {
                    "header.d" => header_d = Some(v),
                    "header.from" => header_from = Some(v),
                    _ => {}
                }
            }
        }
        match method.as_str() {
            "dkim" => out.dkim.push((pass, header_d)),
            // First DMARC result wins; duplicates are suspicious, fail closed.
            "dmarc" => {
                if out.dmarc.is_some() {
                    out.dmarc = Some((false, None));
                } else {
                    out.dmarc = Some((pass, header_from));
                }
            }
            _ => {}
        }
    }
    Some(out)
}

/// Remove RFC 5322 comments `( ... )`, honoring nesting and `\` escapes.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0usize;
    let mut escaped = false;
    let mut in_quote = false;
    for c in s.chars() {
        if escaped {
            escaped = false;
            if depth == 0 {
                out.push(c);
            }
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' if depth == 0 => {
                in_quote = !in_quote;
                out.push(c);
            }
            '(' if !in_quote => depth += 1,
            ')' if !in_quote && depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const GMAIL: &str = "mx.google.com;\r\n       dkim=pass header.i=@accounts.example.com header.s=s1 header.b=abc;\r\n       spf=pass (google.com: domain of x@accounts.example.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=x@accounts.example.com;\r\n       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=accounts.example.com";

    fn trusted() -> Vec<String> {
        vec!["mx.google.com".into()]
    }

    #[test]
    fn parses_gmail_style() {
        let r = parse_value(GMAIL).expect("parsed");
        assert_eq!(r.authserv_id, "mx.google.com");
        assert_eq!(r.dmarc, Some((true, Some("accounts.example.com".into()))));
        assert_eq!(r.dkim.len(), 1);
        let v = r.verdict("accounts.example.com");
        assert_eq!(v.dmarc_pass, Some(true));
    }

    #[test]
    fn dkim_domain_from_header_d() {
        let r = parse_value("mx.example.net; dkim=pass header.d=example.com header.s=k; dkim=fail header.d=other.com")
            .expect("parsed");
        assert_eq!(
            r.verdict("example.com").dkim_pass_domains,
            vec!["example.com"]
        );
    }

    #[test]
    fn only_topmost_and_only_trusted() {
        let forged = "mx.google.com; dmarc=pass header.from=bank.example";
        let real = "mx.google.com; dmarc=fail header.from=bank.example";
        // Real (topmost) says fail; the forged one below is ignored.
        let r = trusted_results(&[real, forged], &trusted()).expect("trusted");
        assert_eq!(r.verdict("bank.example").dmarc_pass, Some(false));
        // Untrusted authserv-id on top → nothing.
        assert!(trusted_results(&["evil.example; dmarc=pass", real], &trusted()).is_none());
        assert!(trusted_results(&[], &trusted()).is_none());
    }

    #[test]
    fn dmarc_for_other_domain_is_ignored() {
        let r = parse_value("mx.google.com; dmarc=pass header.from=evil.example").expect("parsed");
        assert_eq!(r.verdict("bank.example").dmarc_pass, None);
    }

    #[test]
    fn duplicate_dmarc_fails_closed() {
        let r = parse_value(
            "mx.google.com; dmarc=fail header.from=a.example; dmarc=pass header.from=a.example",
        )
        .expect("parsed");
        assert_eq!(r.verdict("a.example").dmarc_pass, Some(false));
    }

    #[test]
    fn comments_cannot_inject_results() {
        let r = parse_value("mx.google.com; dmarc=fail (dmarc=pass; dkim=pass header.d=a.example) header.from=a.example")
            .expect("parsed");
        assert_eq!(r.verdict("a.example").dmarc_pass, Some(false));
        assert!(r.dkim.is_empty());
    }

    #[test]
    fn garbage_is_none() {
        assert!(parse_value("").is_none());
        assert!(parse_value("dkim=pass").is_none());
    }
}
