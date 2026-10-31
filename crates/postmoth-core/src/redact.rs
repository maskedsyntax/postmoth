//! Redaction wrapper so sensitive values cannot accidentally reach logs.

use std::fmt;

/// Wraps a value whose `Debug` and `Display` output is always `[REDACTED]`.
///
/// Use for message bodies, email addresses in logs, tokens, and anything else
/// that must not appear in diagnostics. (OTP codes use `secrecy::SecretString`,
/// which additionally zeroizes on drop.)
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Redacted<T>(pub T);

impl<T> Redacted<T> {
    pub fn into_inner(self) -> T {
        self.0
    }

    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints_inner() {
        let r = Redacted("hunter2".to_owned());
        assert_eq!(format!("{r:?} {r}"), "[REDACTED] [REDACTED]");
        assert_eq!(r.expose(), "hunter2");
    }
}
