//! Authenticated IMAP session operations.

use crate::error::{MailError, Result};
use async_imap::extensions::idle::IdleResponse;
use async_imap::types::{Fetch, Flag};
use async_imap::{Client, Session};
use futures::TryStreamExt;
use postmoth_core::model::MessageFlags;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;

/// Any byte stream an IMAP session can run over.
pub trait ImapStream: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + fmt::Debug + Send> ImapStream for T {}

/// Per-command timeout (IDLE has its own).
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
/// RFC 2177: re-issue IDLE at least every 29 minutes.
pub const IDLE_MAX: Duration = Duration::from_secs(29 * 60);
/// UIDs fetched per body request.
const BODY_BATCH: usize = 25;
/// Max messages fetched per `fetch_new` call; callers loop.
pub const MAX_PER_FETCH: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServerCaps {
    pub idle: bool,
    pub condstore: bool,
    pub uidplus: bool,
    pub move_: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxStatus {
    pub uid_validity: Option<u32>,
    pub uid_next: Option<u32>,
    pub exists: u32,
    pub highest_modseq: Option<u64>,
}

/// One message as fetched from the server. `raw` is untrusted bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchedMessage {
    pub uid: u32,
    pub modseq: Option<u64>,
    pub flags: MessageFlags,
    /// INTERNALDATE as Unix seconds.
    pub internal_date: Option<i64>,
    pub size: Option<u32>,
    pub raw: Vec<u8>,
    /// Only the header was fetched because the message exceeded the body
    /// size policy.
    pub headers_only: bool,
}

impl fmt::Debug for FetchedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print message content.
        f.debug_struct("FetchedMessage")
            .field("uid", &self.uid)
            .field("size", &self.size)
            .field("raw_len", &self.raw.len())
            .field("headers_only", &self.headers_only)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleOutcome {
    /// The server pushed something (EXISTS, EXPUNGE, FETCH).
    Changed,
    /// Timed out with nothing new; caller should re-IDLE or poll.
    Timeout,
}

#[derive(Debug)]
pub struct ImapConnection<S: ImapStream> {
    session: Session<S>,
    caps: ServerCaps,
}

async fn with_timeout<T>(fut: impl Future<Output = Result<T>>) -> Result<T> {
    timeout(COMMAND_TIMEOUT, fut)
        .await
        .map_err(|_| MailError::Timeout)?
}

impl<S: ImapStream> ImapConnection<S> {
    /// Read the greeting (unless already consumed before STARTTLS),
    /// LOGIN, and fetch capabilities.
    pub async fn login(
        stream: S,
        read_greeting: bool,
        login: &str,
        password: &SecretString,
    ) -> Result<Self> {
        let mut client = Client::new(stream);
        if read_greeting {
            with_timeout(async {
                client
                    .read_response()
                    .await?
                    .ok_or(MailError::ConnectionLost)
            })
            .await?;
        }
        let session = with_timeout(async {
            client
                .login(login, password.expose_secret())
                .await
                .map_err(|(e, _)| match e {
                    async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_) => {
                        MailError::Auth
                    }
                    other => other.into(),
                })
        })
        .await?;
        let mut conn = Self {
            session,
            caps: ServerCaps::default(),
        };
        conn.refresh_capabilities().await?;
        tracing::debug!(caps = ?conn.caps, "imap logged in");
        Ok(conn)
    }

    async fn refresh_capabilities(&mut self) -> Result<()> {
        let caps = with_timeout(async { Ok(self.session.capabilities().await?) }).await?;
        self.caps = ServerCaps {
            idle: caps.has_str("IDLE"),
            condstore: caps.has_str("CONDSTORE") || caps.has_str("QRESYNC"),
            uidplus: caps.has_str("UIDPLUS"),
            move_: caps.has_str("MOVE"),
        };
        Ok(())
    }

    #[must_use]
    pub fn caps(&self) -> ServerCaps {
        self.caps
    }

    pub async fn select(&mut self, mailbox: &str) -> Result<MailboxStatus> {
        validate_mailbox_name(mailbox)?;
        let condstore = self.caps.condstore;
        let mb = with_timeout(async {
            Ok(if condstore {
                self.session.select_condstore(mailbox).await?
            } else {
                self.session.select(mailbox).await?
            })
        })
        .await?;
        Ok(MailboxStatus {
            uid_validity: mb.uid_validity,
            uid_next: mb.uid_next,
            exists: mb.exists,
            highest_modseq: mb.highest_modseq,
        })
    }

    /// Fetch up to [`MAX_PER_FETCH`] messages with UID > `after_uid`,
    /// oldest first. Bodies above `max_body_bytes` are fetched headers-only.
    pub async fn fetch_new(
        &mut self,
        after_uid: u32,
        max_body_bytes: u32,
    ) -> Result<Vec<FetchedMessage>> {
        let range = format!("{}:*", after_uid.saturating_add(1));
        let metas: Vec<Fetch> = with_timeout(async {
            Ok(self
                .session
                .uid_fetch(&range, "(UID FLAGS INTERNALDATE RFC822.SIZE)")
                .await?
                .try_collect()
                .await?)
        })
        .await?;

        // `N:*` always returns at least the highest message, even when its
        // UID is below N (RFC 3501 §6.4.8); filter those out.
        let mut out: Vec<FetchedMessage> = metas
            .iter()
            .filter_map(|f| {
                let uid = f.uid?;
                (uid > after_uid).then(|| FetchedMessage {
                    uid,
                    modseq: f.modseq,
                    flags: convert_flags(f.flags()),
                    internal_date: f.internal_date().map(|d| d.timestamp()),
                    size: f.size,
                    raw: Vec::new(),
                    headers_only: f.size.is_some_and(|s| s > max_body_bytes),
                })
            })
            .collect();
        out.sort_by_key(|m| m.uid);
        out.dedup_by_key(|m| m.uid);
        out.truncate(MAX_PER_FETCH);

        let index: HashMap<u32, usize> = out.iter().enumerate().map(|(i, m)| (m.uid, i)).collect();
        for headers_only in [false, true] {
            let uids: Vec<u32> = out
                .iter()
                .filter(|m| m.headers_only == headers_only)
                .map(|m| m.uid)
                .collect();
            let query = if headers_only {
                "(UID BODY.PEEK[HEADER])"
            } else {
                "(UID BODY.PEEK[])"
            };
            for chunk in uids.chunks(BODY_BATCH) {
                let set = chunk
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                let bodies: Vec<Fetch> = with_timeout(async {
                    Ok(self
                        .session
                        .uid_fetch(&set, query)
                        .await?
                        .try_collect()
                        .await?)
                })
                .await?;
                for f in bodies {
                    let Some(&i) = f.uid.and_then(|u| index.get(&u)) else {
                        continue;
                    };
                    let bytes = if headers_only { f.header() } else { f.body() };
                    if let Some(b) = bytes {
                        out[i].raw = b.to_vec();
                    }
                }
            }
        }
        // A message that vanished between the two fetches has no bytes.
        out.retain(|m| !m.raw.is_empty());
        self.drain_unsolicited();
        Ok(out)
    }

    /// Wait for server push with IDLE, up to `max_wait` (capped at 29 min).
    /// Consumes and returns the connection because IDLE takes the session.
    pub async fn idle(self, max_wait: Duration) -> Result<(Self, IdleOutcome)> {
        let caps = self.caps;
        let mut handle = self.session.idle();
        with_timeout(async { Ok(handle.init().await?) }).await?;
        let (fut, _stop) = handle.wait_with_timeout(max_wait.min(IDLE_MAX));
        let outcome = match fut.await? {
            IdleResponse::NewData(_) => IdleOutcome::Changed,
            IdleResponse::Timeout | IdleResponse::ManualInterrupt => IdleOutcome::Timeout,
        };
        let session = with_timeout(async { Ok(handle.done().await?) }).await?;
        let mut conn = Self { session, caps };
        conn.drain_unsolicited();
        Ok((conn, outcome))
    }

    pub async fn noop(&mut self) -> Result<()> {
        with_timeout(async { Ok(self.session.noop().await?) }).await?;
        self.drain_unsolicited();
        Ok(())
    }

    pub async fn logout(mut self) -> Result<()> {
        with_timeout(async { Ok(self.session.logout().await?) }).await
    }

    fn drain_unsolicited(&mut self) {
        while self.session.unsolicited_responses.try_recv().is_ok() {}
    }
}

fn convert_flags<'a>(flags: impl Iterator<Item = Flag<'a>>) -> MessageFlags {
    let mut f = MessageFlags::default();
    for flag in flags {
        match flag {
            Flag::Seen => f.seen = true,
            Flag::Flagged => f.flagged = true,
            Flag::Answered => f.answered = true,
            Flag::Draft => f.draft = true,
            Flag::Deleted => f.deleted = true,
            _ => {}
        }
    }
    f
}

/// async-imap quotes mailbox names but does not reject CR/LF; refuse them
/// so a hostile folder name from LIST can't inject commands.
fn validate_mailbox_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 1024 || name.contains(['\r', '\n', '\0']) {
        return Err(MailError::Protocol("invalid mailbox name".into()));
    }
    Ok(())
}
