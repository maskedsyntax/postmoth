//! Strongly typed identifiers. Each is a UUID newtype so IDs of different
//! kinds cannot be mixed up at compile time.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generate a new random identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.hyphenated().fmt(f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0.hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }
    };
}

id_type!(
    /// A configured mail account.
    AccountId
);
id_type!(
    /// A mailbox / folder within an account.
    FolderId
);
id_type!(
    /// A locally cached message (not the RFC 5322 Message-ID header).
    MessageId
);
id_type!(
    /// Opaque, single-use handle the browser extension uses to redeem an OTP.
    /// Revealing it does not reveal the code.
    SuggestionId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_display_parse() {
        let id = AccountId::new();
        let parsed: AccountId = id.to_string().parse().expect("parse");
        assert_eq!(id, parsed);
    }

    #[test]
    fn serde_is_transparent_string() {
        let id = SuggestionId::new();
        let json = serde_json::to_string(&id).expect("ser");
        assert_eq!(json, format!("\"{id}\""));
    }
}
