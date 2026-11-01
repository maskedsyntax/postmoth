//! Control surface between the UI / `postmothctl` and the daemon.
//!
//! Transported over the D-Bus session bus. Structured payloads travel as
//! JSON strings of these types so they are versioned in one place. This
//! surface is **not** reachable from the browser: the native host only
//! speaks [`crate::browser`] on its own socket.

use postmoth_core::AccountId;
use postmoth_core::model::{ProviderType, ServerEndpoint};
use serde::{Deserialize, Serialize};

pub const BUS_NAME: &str = "dev.postmoth.Daemon1";
pub const OBJECT_PATH: &str = "/dev/postmoth/Daemon1";
pub const INTERFACE: &str = "dev.postmoth.Daemon1";
pub const CONTROL_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusReport {
    pub daemon_version: String,
    pub protocol: u32,
    /// "Pause background mail" is on.
    pub paused: bool,
    pub accounts: Vec<AccountStatus>,
    /// How many OTP candidates are live. Never the codes.
    pub otp_live_candidates: usize,
    pub browser_socket: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountStatus {
    pub id: AccountId,
    pub address: String,
    pub otp_enabled: bool,
    pub state: SyncState,
    pub last_sync_at: Option<i64>,
    /// Human-readable, already redacted.
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SyncState {
    Starting,
    Connecting,
    Syncing,
    /// Connected, waiting for push (IDLE).
    Idle,
    /// Connected, server lacks IDLE; polling.
    Polling,
    /// Disconnected, retrying later.
    Backoff {
        retry_in_secs: u64,
    },
    /// Credentials rejected; waits for the user.
    AuthFailed,
    /// No secret in the keyring for this account.
    MissingSecret,
    Paused,
    Stopped,
}

/// `AddAccount` payload. The password travels as a separate argument and
/// goes straight to the Secret Service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewAccount {
    pub address: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub login: String,
    #[serde(default = "default_provider")]
    pub provider: ProviderType,
    pub imap: ServerEndpoint,
    pub smtp: ServerEndpoint,
    #[serde(default = "default_true")]
    pub otp_enabled: bool,
    #[serde(default)]
    pub trusted_authserv_ids: Vec<String>,
}

fn default_provider() -> ProviderType {
    ProviderType::GenericImap
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingInfo {
    pub id: i64,
    pub sender_pattern: String,
    pub trusted_origin: String,
    pub include_subdomains: bool,
    pub user_confirmed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_state_wire_form() {
        let s = serde_json::to_string(&SyncState::Backoff { retry_in_secs: 5 }).expect("ser");
        assert_eq!(s, r#"{"state":"backoff","retry_in_secs":5}"#);
    }

    #[test]
    fn new_account_rejects_unknown_fields() {
        let ok = r#"{"address":"a@b.c","login":"a","imap":{"host":"h","port":993,"tls":"implicit"},
                    "smtp":{"host":"h","port":465,"tls":"implicit"}}"#;
        let a: NewAccount = serde_json::from_str(ok).expect("parse");
        assert!(a.otp_enabled);
        let bad = ok.replacen('{', r#"{"password":"x","#, 1);
        assert!(serde_json::from_str::<NewAccount>(&bad).is_err());
    }
}
