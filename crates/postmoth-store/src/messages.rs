use crate::accounts::parse_id;
use crate::{Result, Store, StoreError};
use postmoth_core::model::{Mailbox, MessageFlags, MessageSummary};
use postmoth_core::{AccountId, FolderId, MessageId};
use rusqlite::{OptionalExtension, Row, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAttachment {
    pub part_index: u32,
    pub filename: String,
    pub mime_type: String,
    pub size: u64,
    pub content_id: Option<String>,
    pub is_inline: bool,
    pub is_executable: bool,
}

/// A message to cache. Built by the daemon from a parsed MIME message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMessage {
    pub account_id: AccountId,
    pub internet_message_id: Option<String>,
    pub thread_id: Option<String>,
    pub subject: Option<String>,
    pub from: Option<Mailbox>,
    pub recipients: Vec<Mailbox>,
    pub date: i64,
    pub received_at: i64,
    pub snippet: String,
    pub flags: MessageFlags,
    /// `None` when only headers were fetched.
    pub body_plain: Option<String>,
    pub body_html_sanitized: Option<String>,
    pub blocked_remote: u32,
    pub is_bulk: bool,
    pub attachments: Vec<NewAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDetail {
    pub summary: MessageSummary,
    pub recipients: Vec<Mailbox>,
    pub internet_message_id: Option<String>,
    pub body_plain: Option<String>,
    pub body_html_sanitized: Option<String>,
    pub blocked_remote: u32,
    pub attachments: Vec<NewAttachment>,
}

/// Keyset pagination position (stable while new mail arrives).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageCursor {
    pub date: i64,
    pub seq: i64,
}

const FLAG_SEEN: i64 = 1;
const FLAG_FLAGGED: i64 = 2;
const FLAG_ANSWERED: i64 = 4;
const FLAG_DRAFT: i64 = 8;
const FLAG_DELETED: i64 = 16;

fn flags_to_bits(f: MessageFlags) -> i64 {
    let mut b = 0;
    if f.seen {
        b |= FLAG_SEEN;
    }
    if f.flagged {
        b |= FLAG_FLAGGED;
    }
    if f.answered {
        b |= FLAG_ANSWERED;
    }
    if f.draft {
        b |= FLAG_DRAFT;
    }
    if f.deleted {
        b |= FLAG_DELETED;
    }
    b
}

fn bits_to_flags(b: i64) -> MessageFlags {
    MessageFlags {
        seen: b & FLAG_SEEN != 0,
        flagged: b & FLAG_FLAGGED != 0,
        answered: b & FLAG_ANSWERED != 0,
        draft: b & FLAG_DRAFT != 0,
        deleted: b & FLAG_DELETED != 0,
    }
}

const SUMMARY_COLS: &str = "m.id, m.account_id, m.subject, m.sender_name, m.sender_address, \
     m.date, m.snippet, m.flags, m.has_attachments, m.seq";

fn row_to_summary(r: &Row<'_>) -> Result<(MessageSummary, i64)> {
    let id: String = r.get(0)?;
    let account: String = r.get(1)?;
    let sender_address: Option<String> = r.get(4)?;
    let summary = MessageSummary {
        id: parse_id(&id)?,
        account_id: parse_id(&account)?,
        subject: r.get(2)?,
        from: sender_address.map(|address| Mailbox {
            name: r.get(3).ok().flatten(),
            address,
        }),
        date: r.get(5)?,
        snippet: r.get(6)?,
        flags: bits_to_flags(r.get(7)?),
        has_attachments: r.get::<_, i64>(8)? != 0,
    };
    Ok((summary, r.get(9)?))
}

/// Turn free text into a safe FTS5 query: every term is quoted (so FTS
/// operators and column filters in user input are inert), terms are
/// AND-ed, and the last term gets prefix matching.
fn fts_query(input: &str) -> Option<String> {
    let terms: Vec<String> = input
        .split_whitespace()
        .take(16)
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect();
    if terms.is_empty() {
        return None;
    }
    let mut q = terms.join(" ");
    q.push('*');
    Some(q)
}

impl Store {
    /// Cache a message seen at `(folder, remote_uid)`. Idempotent: if that
    /// UID is already mapped, returns the existing id and `false`.
    ///
    /// Messages are deliberately not de-duplicated by `Message-ID`: that
    /// header is sender-controlled, and merging on it would let a crafted
    /// message shadow a legitimate one.
    pub fn insert_message(
        &mut self,
        folder_id: FolderId,
        remote_uid: u32,
        modseq: Option<u64>,
        m: &NewMessage,
    ) -> Result<(MessageId, bool)> {
        self.transaction(|tx| {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT message_id FROM folder_messages WHERE folder_id = ?1 AND remote_uid = ?2",
                    (folder_id.to_string(), remote_uid),
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = existing {
                return Ok((parse_id(&id)?, false));
            }
            let id = MessageId::new();
            let body_state = if m.body_plain.is_some() { "full" } else { "headers" };
            tx.execute(
                "INSERT INTO messages (id, account_id, internet_message_id, thread_id, subject,
                    sender_name, sender_address, recipients_json, date, received_at, snippet,
                    flags, body_plain, body_html_sanitized, blocked_remote, has_attachments,
                    is_bulk, body_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
                params![
                    id.to_string(),
                    m.account_id.to_string(),
                    m.internet_message_id,
                    m.thread_id,
                    m.subject,
                    m.from.as_ref().and_then(|f| f.name.clone()),
                    m.from.as_ref().map(|f| f.address.clone()),
                    serde_json::to_string(&m.recipients)?,
                    m.date,
                    m.received_at,
                    m.snippet,
                    flags_to_bits(m.flags),
                    m.body_plain,
                    m.body_html_sanitized,
                    m.blocked_remote,
                    !m.attachments.is_empty(),
                    m.is_bulk,
                    body_state,
                ],
            )?;
            tx.execute(
                "INSERT INTO folder_messages (folder_id, message_id, remote_uid, modseq)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    folder_id.to_string(),
                    id.to_string(),
                    remote_uid,
                    modseq.and_then(|v| i64::try_from(v).ok())
                ],
            )?;
            for a in &m.attachments {
                tx.execute(
                    "INSERT INTO attachments (id, message_id, part_index, filename, mime_type, size,
                        content_id, is_inline, is_executable)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        id.to_string(),
                        a.part_index,
                        a.filename,
                        a.mime_type,
                        i64::try_from(a.size).unwrap_or(i64::MAX),
                        a.content_id,
                        a.is_inline,
                        a.is_executable,
                    ],
                )?;
            }
            Ok((id, true))
        })
    }

    /// Newest-first page of a folder.
    pub fn page_folder(
        &self,
        folder_id: FolderId,
        after: Option<PageCursor>,
        limit: u32,
    ) -> Result<(Vec<MessageSummary>, Option<PageCursor>)> {
        let limit = limit.clamp(1, 500);
        let (d, s) = after.map_or((i64::MAX, i64::MAX), |c| (c.date, c.seq));
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {SUMMARY_COLS} FROM messages m
             JOIN folder_messages fm ON fm.message_id = m.id
             WHERE fm.folder_id = ?1 AND (m.date < ?2 OR (m.date = ?2 AND m.seq < ?3))
             ORDER BY m.date DESC, m.seq DESC
             LIMIT ?4"
        ))?;
        let mut rows = stmt.query(params![folder_id.to_string(), d, s, limit])?;
        let mut out = Vec::new();
        let mut last = None;
        while let Some(r) = rows.next()? {
            let (summary, seq) = row_to_summary(r)?;
            last = Some(PageCursor {
                date: summary.date,
                seq,
            });
            out.push(summary);
        }
        let next = if out.len() == limit as usize {
            last
        } else {
            None
        };
        Ok((out, next))
    }

    pub fn get_message(&self, id: MessageId) -> Result<Option<MessageDetail>> {
        let row = self
            .conn
            .query_row(
                &format!(
                    "SELECT {SUMMARY_COLS}, m.recipients_json, m.internet_message_id, m.body_plain,
                            m.body_html_sanitized, m.blocked_remote
                     FROM messages m WHERE m.id = ?1"
                ),
                [id.to_string()],
                |r| {
                    Ok((
                        row_to_summary(r),
                        r.get::<_, String>(10)?,
                        r.get::<_, Option<String>>(11)?,
                        r.get::<_, Option<String>>(12)?,
                        r.get::<_, Option<String>>(13)?,
                        r.get::<_, u32>(14)?,
                    ))
                },
            )
            .optional()?;
        let Some((summary, recipients, imid, plain, html, blocked)) = row else {
            return Ok(None);
        };
        let (summary, _) = summary?;
        let mut stmt = self.conn.prepare(
            "SELECT part_index, filename, mime_type, size, content_id, is_inline, is_executable
             FROM attachments WHERE message_id = ?1 ORDER BY part_index",
        )?;
        let attachments = stmt
            .query_map([id.to_string()], |r| {
                Ok(NewAttachment {
                    part_index: r.get(0)?,
                    filename: r.get(1)?,
                    mime_type: r.get(2)?,
                    size: u64::try_from(r.get::<_, i64>(3)?).unwrap_or(0),
                    content_id: r.get(4)?,
                    is_inline: r.get(5)?,
                    is_executable: r.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(MessageDetail {
            summary,
            recipients: serde_json::from_str(&recipients)?,
            internet_message_id: imid,
            body_plain: plain,
            body_html_sanitized: html,
            blocked_remote: blocked,
            attachments,
        }))
    }

    pub fn set_flags(&self, id: MessageId, flags: MessageFlags) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE messages SET flags = ?2 WHERE id = ?1",
            (id.to_string(), flags_to_bits(flags)),
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Fill in bodies for a message first cached headers-only.
    pub fn set_body(
        &self,
        id: MessageId,
        plain: &str,
        html: Option<&str>,
        blocked_remote: u32,
    ) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE messages SET body_plain = ?2, body_html_sanitized = ?3, blocked_remote = ?4,
                body_state = 'full' WHERE id = ?1",
            params![id.to_string(), plain, html, blocked_remote],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    pub fn max_uid(&self, folder_id: FolderId) -> Result<u32> {
        Ok(self.conn.query_row(
            "SELECT coalesce(max(remote_uid), 0) FROM folder_messages WHERE folder_id = ?1",
            [folder_id.to_string()],
            |r| r.get(0),
        )?)
    }

    /// The server expunged `remote_uid`. Drops the mapping, and the message
    /// itself if no other folder references it.
    pub fn remove_from_folder(&mut self, folder_id: FolderId, remote_uid: u32) -> Result<bool> {
        self.transaction(|tx| {
            let mid: Option<String> = tx
                .query_row(
                    "DELETE FROM folder_messages WHERE folder_id = ?1 AND remote_uid = ?2
                     RETURNING message_id",
                    (folder_id.to_string(), remote_uid),
                    |r| r.get(0),
                )
                .optional()?;
            let Some(mid) = mid else { return Ok(false) };
            tx.execute(
                "DELETE FROM messages WHERE id = ?1
                 AND NOT EXISTS (SELECT 1 FROM folder_messages WHERE message_id = ?1)",
                [&mid],
            )?;
            Ok(true)
        })
    }

    pub fn unread_count(&self, folder_id: FolderId) -> Result<u32> {
        Ok(self.conn.query_row(
            "SELECT count(*) FROM messages m JOIN folder_messages fm ON fm.message_id = m.id
             WHERE fm.folder_id = ?1 AND (m.flags & ?2) = 0",
            params![folder_id.to_string(), FLAG_SEEN],
            |r| r.get(0),
        )?)
    }

    /// Local full-text search, newest first.
    pub fn search(
        &self,
        query: &str,
        account: Option<AccountId>,
        limit: u32,
    ) -> Result<Vec<MessageSummary>> {
        let Some(q) = fts_query(query) else {
            return Ok(Vec::new());
        };
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {SUMMARY_COLS} FROM messages_fts f
             JOIN messages m ON m.seq = f.rowid
             WHERE messages_fts MATCH ?1 AND (?2 IS NULL OR m.account_id = ?2)
             ORDER BY m.date DESC, m.seq DESC
             LIMIT ?3"
        ))?;
        let mut rows = stmt.query(params![
            q,
            account.map(|a| a.to_string()),
            limit.clamp(1, 500)
        ])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_summary(r)?.0);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::sample_account;
    use postmoth_core::model::FolderRole;

    fn msg(account: AccountId, subject: &str, body: &str, date: i64) -> NewMessage {
        NewMessage {
            account_id: account,
            internet_message_id: Some(format!("{subject}@x")),
            thread_id: None,
            subject: Some(subject.into()),
            from: Some(Mailbox {
                name: Some("Alice".into()),
                address: "alice@example.com".into(),
            }),
            recipients: vec![Mailbox {
                name: None,
                address: "user@example.org".into(),
            }],
            date,
            received_at: date,
            snippet: body.chars().take(50).collect(),
            flags: MessageFlags::default(),
            body_plain: Some(body.into()),
            body_html_sanitized: None,
            blocked_remote: 0,
            is_bulk: false,
            attachments: vec![],
        }
    }

    fn setup() -> (Store, AccountId, FolderId) {
        let s = Store::open_in_memory().expect("open");
        let a = sample_account();
        s.insert_account(&a).expect("acct");
        let f = s
            .upsert_folder(a.id, "INBOX", FolderRole::Inbox)
            .expect("f");
        (s, a.id, f)
    }

    #[test]
    fn insert_is_idempotent_per_uid() {
        let (mut s, a, f) = setup();
        let m = msg(a, "Hello", "body", 100);
        let (id1, new1) = s.insert_message(f, 1, None, &m).expect("ins");
        let (id2, new2) = s.insert_message(f, 1, None, &m).expect("ins");
        assert!(new1 && !new2);
        assert_eq!(id1, id2);
        assert_eq!(s.max_uid(f).expect("max"), 1);
    }

    #[test]
    fn same_message_id_header_is_not_merged() {
        let (mut s, a, f) = setup();
        let m = msg(a, "Hello", "legit", 100);
        let (id1, _) = s.insert_message(f, 1, None, &m).expect("ins");
        let mut forged = msg(a, "Hello", "forged", 101);
        forged.internet_message_id = m.internet_message_id.clone();
        let (id2, new) = s.insert_message(f, 2, None, &forged).expect("ins");
        assert!(new);
        assert_ne!(id1, id2);
    }

    #[test]
    fn keyset_pagination() {
        let (mut s, a, f) = setup();
        for i in 0..25 {
            s.insert_message(
                f,
                i + 1,
                None,
                &msg(a, &format!("m{i}"), "x", i64::from(i) * 10),
            )
            .expect("ins");
        }
        let (p1, c1) = s.page_folder(f, None, 10).expect("p1");
        assert_eq!(p1.len(), 10);
        assert_eq!(p1[0].subject.as_deref(), Some("m24"));
        let (p2, c2) = s.page_folder(f, c1, 10).expect("p2");
        assert_eq!(p2[0].subject.as_deref(), Some("m14"));
        let (p3, c3) = s.page_folder(f, c2, 10).expect("p3");
        assert_eq!(p3.len(), 5);
        assert!(c3.is_none());
    }

    #[test]
    fn detail_flags_and_attachments() {
        let (mut s, a, f) = setup();
        let mut m = msg(a, "Report", "see attached", 5);
        m.attachments.push(NewAttachment {
            part_index: 2,
            filename: "r.pdf".into(),
            mime_type: "application/pdf".into(),
            size: 1234,
            content_id: None,
            is_inline: false,
            is_executable: false,
        });
        let (id, _) = s.insert_message(f, 9, Some(3), &m).expect("ins");
        let d = s.get_message(id).expect("get").expect("some");
        assert_eq!(d.attachments.len(), 1);
        assert!(d.summary.has_attachments);
        assert_eq!(d.recipients.len(), 1);
        assert_eq!(s.unread_count(f).expect("unread"), 1);
        s.set_flags(
            id,
            MessageFlags {
                seen: true,
                ..MessageFlags::default()
            },
        )
        .expect("flags");
        assert_eq!(s.unread_count(f).expect("unread"), 0);
    }

    #[test]
    fn search_works_and_is_injection_safe() {
        let (mut s, a, f) = setup();
        s.insert_message(
            f,
            1,
            None,
            &msg(a, "Quarterly report", "numbers attached", 1),
        )
        .expect("ins");
        s.insert_message(f, 2, None, &msg(a, "Lunch", "café on friday", 2))
            .expect("ins");
        assert_eq!(s.search("quarterly", None, 10).expect("q").len(), 1);
        assert_eq!(s.search("quart", None, 10).expect("prefix").len(), 1);
        assert_eq!(s.search("cafe", None, 10).expect("diacritics").len(), 1);
        assert_eq!(s.search("alice", None, 10).expect("sender").len(), 2);
        assert_eq!(s.search("lunch numbers", None, 10).expect("and").len(), 0);
        // FTS syntax in user input must not error or widen the match.
        for evil in [
            "\"",
            "subject:lunch OR *",
            "NEAR(a b)",
            "a\" OR \"b",
            "-x",
            "^",
        ] {
            assert!(s.search(evil, None, 10).is_ok(), "{evil}");
        }
        assert!(s.search("   ", None, 10).expect("empty").is_empty());
        assert_eq!(
            s.search("quarterly", Some(AccountId::new()), 10)
                .expect("other acct")
                .len(),
            0
        );
    }

    #[test]
    fn deletes_clear_search_index() {
        let (mut s, a, f) = setup();
        s.insert_message(f, 1, None, &msg(a, "Secret plans", "zebra", 1))
            .expect("ins");
        assert_eq!(s.search("zebra", None, 10).expect("q").len(), 1);
        assert!(s.remove_from_folder(f, 1).expect("rm"));
        assert_eq!(s.search("zebra", None, 10).expect("q").len(), 0);
        assert!(!s.remove_from_folder(f, 1).expect("rm again"));
    }

    #[test]
    fn uidvalidity_reset_drops_folder_mail_only() {
        let (mut s, a, f) = setup();
        let other = s
            .upsert_folder(a, "Archive", FolderRole::Archive)
            .expect("f");
        s.insert_message(f, 1, None, &msg(a, "a", "x", 1))
            .expect("ins");
        s.insert_message(other, 1, None, &msg(a, "b", "y", 2))
            .expect("ins");
        s.save_draft(None, a, "{}").expect("draft");
        let removed = s.reset_folder_for_uidvalidity(f, 99).expect("reset");
        assert_eq!(removed, 1);
        assert_eq!(s.max_uid(f).expect("max"), 0);
        assert_eq!(s.max_uid(other).expect("max"), 1);
        assert_eq!(s.folder_sync_state(f).expect("st").uidvalidity, Some(99));
        assert_eq!(s.list_drafts(a).expect("drafts").len(), 1);
    }

    #[test]
    fn account_delete_cascades_everything() {
        let (mut s, a, f) = setup();
        s.insert_message(f, 1, None, &msg(a, "a", "uniqueword", 1))
            .expect("ins");
        s.save_draft(None, a, "{}").expect("draft");
        s.delete_account(a).expect("del");
        let n: i64 = s
            .conn
            .query_row("SELECT count(*) FROM messages", [], |r| r.get(0))
            .expect("count");
        assert_eq!(n, 0);
        assert!(s.search("uniqueword", None, 10).expect("q").is_empty());
        assert!(s.list_drafts(a).expect("drafts").is_empty());
    }
}
