//! Core domain models shared across process boundaries.

use crate::ids::{AccountId, FolderId, MessageId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    GenericImap,
    Gmail,
    Microsoft,
}

/// How a connection is secured. Cleartext is intentionally not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// TLS from the first byte (IMAPS 993, SMTPS 465).
    Implicit,
    /// STARTTLS upgrade, which is mandatory: the connection fails if the
    /// server does not offer it.
    StartTls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerEndpoint {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub provider: ProviderType,
    pub address: String,
    pub display_name: Option<String>,
    pub imap: ServerEndpoint,
    pub smtp: ServerEndpoint,
    pub login: String,
    /// Opaque key into the Secret Service; never the secret itself.
    pub auth_secret_ref: String,
    pub otp_enabled: bool,
    /// `authserv-id`s of this account's own provider whose
    /// `Authentication-Results` headers are believed (spec §8.6). Empty
    /// means no results are trusted.
    #[serde(default)]
    pub trusted_authserv_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderRole {
    Inbox,
    Sent,
    Drafts,
    Archive,
    Trash,
    Junk,
    All,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Folder {
    pub id: FolderId,
    pub account_id: AccountId,
    pub remote_id: String,
    pub role: FolderRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MessageFlags {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mailbox {
    pub name: Option<String>,
    pub address: String,
}

/// Summary row for message lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSummary {
    pub id: MessageId,
    pub account_id: AccountId,
    pub subject: Option<String>,
    pub from: Option<Mailbox>,
    /// Unix timestamp, seconds.
    pub date: i64,
    pub snippet: String,
    pub flags: MessageFlags,
    pub has_attachments: bool,
}

/// Outbox lifecycle (spec §7.3). `Uncertain` is never auto-retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxState {
    Draft,
    Queued,
    Sending,
    Sent,
    Uncertain,
    Failed,
}

impl OutboxState {
    /// Whether moving from `self` to `next` is a legal transition.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        use OutboxState::{Draft, Failed, Queued, Sending, Sent, Uncertain};
        matches!(
            (self, next),
            (Draft, Queued)
                | (Queued, Draft | Sending)
                | (Sending, Sent | Failed | Uncertain)
                // Failed: the user may retry. Uncertain: only an explicit
                // user reconciliation can resolve it.
                | (Failed, Queued | Draft)
                | (Uncertain, Sent | Queued | Draft)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::OutboxState::*;

    #[test]
    fn outbox_never_resends_sent() {
        for s in [Draft, Queued, Sending, Uncertain, Failed] {
            assert!(!Sent.can_transition_to(s));
        }
    }

    #[test]
    fn sending_cannot_jump_back_to_queued() {
        assert!(!Sending.can_transition_to(Queued));
        assert!(Sending.can_transition_to(Uncertain));
    }
}
