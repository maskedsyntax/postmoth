//! Browser-facing protocol v1.
//!
//! Only three operations exist. There is intentionally no way to list
//! candidates, read mail or change settings through this surface.

use postmoth_core::{ErrorCode, SuggestionId};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

/// Max length of a request id we echo back.
pub const MAX_REQUEST_ID_LEN: usize = 64;
/// Max length of an origin string we accept.
pub const MAX_ORIGIN_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawRequest")]
pub struct Request {
    pub v: u32,
    pub request_id: String,
    #[serde(flatten)]
    pub op: Op,
}

/// Strict wire form: every field the protocol knows, nothing else.
/// (`deny_unknown_fields` does not compose with `flatten`, hence this shim.)
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest {
    v: u32,
    request_id: String,
    op: String,
    top_origin: Option<String>,
    tab_id: Option<i64>,
    suggestion_id: Option<SuggestionId>,
}

impl TryFrom<RawRequest> for Request {
    type Error = String;

    fn try_from(r: RawRequest) -> Result<Self, Self::Error> {
        let op = match (r.op.as_str(), r.top_origin, r.tab_id, r.suggestion_id) {
            ("status", None, None, None) => Op::Status,
            ("find_suggestion", Some(top_origin), Some(tab_id), None) => {
                Op::FindSuggestion { top_origin, tab_id }
            }
            ("consume_suggestion", Some(top_origin), Some(tab_id), Some(suggestion_id)) => {
                Op::ConsumeSuggestion {
                    suggestion_id,
                    top_origin,
                    tab_id,
                }
            }
            _ => return Err("unknown op or invalid fields for op".to_owned()),
        };
        Ok(Self {
            v: r.v,
            request_id: r.request_id,
            op,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Health check: is the daemon up and are suggestions enabled?
    Status,
    /// Is there a suggestion for this top-level origin? Never returns a code.
    FindSuggestion { top_origin: String, tab_id: i64 },
    /// Redeem a suggestion after an explicit user action. The origin is
    /// re-validated against the candidate's binding.
    ConsumeSuggestion {
        suggestion_id: SuggestionId,
        top_origin: String,
        tab_id: i64,
    },
}

impl Request {
    /// Structural validation independent of daemon state.
    pub fn validate(&self) -> Result<(), (ErrorCode, &'static str)> {
        if self.v != crate::BROWSER_PROTOCOL_VERSION {
            return Err((
                ErrorCode::VersionUnsupported,
                "unsupported protocol version",
            ));
        }
        if self.request_id.is_empty()
            || self.request_id.len() > MAX_REQUEST_ID_LEN
            || !self
                .request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err((ErrorCode::BadRequest, "invalid request_id"));
        }
        match &self.op {
            Op::Status => {}
            Op::FindSuggestion { top_origin, tab_id }
            | Op::ConsumeSuggestion {
                top_origin, tab_id, ..
            } => {
                if top_origin.is_empty() || top_origin.len() > MAX_ORIGIN_LEN {
                    return Err((ErrorCode::BadRequest, "invalid top_origin"));
                }
                if *tab_id < 0 {
                    return Err((ErrorCode::BadRequest, "invalid tab_id"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub v: u32,
    pub request_id: String,
    #[serde(flatten)]
    pub body: ResponseBody,
}

impl Response {
    pub fn new(request_id: impl Into<String>, body: ResponseBody) -> Self {
        Self {
            v: crate::BROWSER_PROTOCOL_VERSION,
            request_id: request_id.into(),
            body,
        }
    }

    pub fn error(request_id: impl Into<String>, code: ErrorCode, message: &str) -> Self {
        Self::new(
            request_id,
            ResponseBody::Error {
                code,
                message: message.to_owned(),
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ResponseBody {
    /// Reply to `status`.
    Ok {
        daemon_version: String,
        paused: bool,
    },
    /// A suggestion matches; the code itself is not included.
    Available {
        suggestion_id: SuggestionId,
        label: String,
    },
    /// Nothing to offer for this origin (also covers unknown/mismatched origins).
    None,
    /// Reply to a successful `consume_suggestion`. Single use.
    Code {
        code: OtpCode,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

/// A one-time code in transit. Zeroized on drop; `Debug` is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct OtpCode(Zeroizing<String>);

impl Serialize for OtpCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OtpCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(Self::new)
    }
}

impl OtpCode {
    pub fn new(code: String) -> Self {
        Self(Zeroizing::new(code))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpCode([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_spec_example_request() {
        let json = r#"{"v":1,"request_id":"r-1","op":"find_suggestion","top_origin":"https://login.example.com","tab_id":123}"#;
        let req: Request = serde_json::from_str(json).expect("parse");
        assert_eq!(
            req.op,
            Op::FindSuggestion {
                top_origin: "https://login.example.com".into(),
                tab_id: 123
            }
        );
        assert!(req.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_fields() {
        let json = r#"{"v":1,"request_id":"r","op":"status","list_all":true}"#;
        assert!(serde_json::from_str::<Request>(json).is_err());
    }

    #[test]
    fn rejects_unknown_ops() {
        let json = r#"{"v":1,"request_id":"r","op":"list_candidates"}"#;
        assert!(serde_json::from_str::<Request>(json).is_err());
    }

    #[test]
    fn rejects_fields_belonging_to_other_ops() {
        let json = r#"{"v":1,"request_id":"r","op":"status","tab_id":1}"#;
        assert!(serde_json::from_str::<Request>(json).is_err());
    }

    #[test]
    fn request_roundtrips() {
        let req = Request {
            v: 1,
            request_id: "r".into(),
            op: Op::ConsumeSuggestion {
                suggestion_id: SuggestionId::new(),
                top_origin: "https://a.example".into(),
                tab_id: 7,
            },
        };
        let json = serde_json::to_string(&req).expect("ser");
        assert_eq!(serde_json::from_str::<Request>(&json).expect("de"), req);
    }

    #[test]
    fn rejects_wrong_version() {
        let req = Request {
            v: 2,
            request_id: "r".into(),
            op: Op::Status,
        };
        assert_eq!(
            req.validate().map_err(|e| e.0),
            Err(ErrorCode::VersionUnsupported)
        );
    }

    #[test]
    fn rejects_weird_request_ids() {
        let req = Request {
            v: 1,
            request_id: "a\nb".into(),
            op: Op::Status,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn available_response_shape_has_no_code() {
        let id = SuggestionId::new();
        let resp = Response::new(
            "r",
            ResponseBody::Available {
                suggestion_id: id,
                label: "Code from Postmoth".into(),
            },
        );
        let v: serde_json::Value = serde_json::to_value(&resp).expect("ser");
        assert_eq!(v["status"], "available");
        assert_eq!(v["suggestion_id"], id.to_string());
        assert!(v.get("code").is_none());
    }

    #[test]
    fn otp_code_debug_is_redacted() {
        let body = ResponseBody::Code {
            code: OtpCode::new("123456".into()),
        };
        assert!(!format!("{body:?}").contains("123456"));
    }
}
