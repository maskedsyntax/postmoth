use crate::accounts::{enum_parse, enum_str, parse_id};
use crate::{Result, Store, StoreError, now_unix};
use postmoth_core::AccountId;
use postmoth_core::model::OutboxState;
use rusqlite::{OptionalExtension, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    pub id: String,
    pub account_id: AccountId,
    pub draft_id: Option<String>,
    pub internet_message_id: String,
    pub state: OutboxState,
    pub attempt_count: u32,
    pub last_error: Option<String>,
}

impl Store {
    /// Create or update a draft; returns its id.
    pub fn save_draft(
        &self,
        id: Option<&str>,
        account_id: AccountId,
        composition_json: &str,
    ) -> Result<String> {
        let id = id.map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned);
        self.conn.execute(
            "INSERT INTO drafts (id, account_id, composition_json, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (id) DO UPDATE SET composition_json = excluded.composition_json,
                                            updated_at = excluded.updated_at",
            (&id, account_id.to_string(), composition_json, now_unix()),
        )?;
        Ok(id)
    }

    pub fn get_draft(&self, id: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT composition_json FROM drafts WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// `(id, composition_json)` newest first.
    pub fn list_drafts(&self, account_id: AccountId) -> Result<Vec<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, composition_json FROM drafts WHERE account_id = ?1 ORDER BY updated_at DESC",
        )?;
        let rows = stmt
            .query_map([account_id.to_string()], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_draft(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM drafts WHERE id = ?1", [id])?;
        Ok(())
    }

    /// Queue a message for sending. `internet_message_id` must be generated
    /// by the caller now and reused for every attempt.
    pub fn enqueue_outbox(
        &self,
        account_id: AccountId,
        draft_id: Option<&str>,
        internet_message_id: &str,
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = now_unix();
        self.conn.execute(
            "INSERT INTO outbox (id, account_id, draft_id, internet_message_id, state, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, 'queued', ?5, ?5)",
            params![id, account_id.to_string(), draft_id, internet_message_id, now],
        )?;
        Ok(id)
    }

    /// Compare-and-set state transition, validated against the outbox state
    /// machine. Fails if the entry is not currently in `from` (another
    /// worker moved it) or the transition is illegal.
    pub fn transition_outbox(
        &self,
        id: &str,
        from: OutboxState,
        to: OutboxState,
        last_error: Option<&str>,
    ) -> Result<()> {
        if !from.can_transition_to(to) {
            return Err(StoreError::InvalidTransition);
        }
        let bump = i64::from(to == OutboxState::Sending);
        let n = self.conn.execute(
            "UPDATE outbox SET state = ?3, last_error = ?4, updated_at = ?5,
                attempt_count = attempt_count + ?6
             WHERE id = ?1 AND state = ?2",
            params![
                id,
                enum_str(&from)?,
                enum_str(&to)?,
                last_error,
                now_unix(),
                bump
            ],
        )?;
        if n == 0 {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    pub fn outbox_in_state(&self, state: OutboxState) -> Result<Vec<OutboxEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, account_id, draft_id, internet_message_id, state, attempt_count, last_error
             FROM outbox WHERE state = ?1 ORDER BY created_at",
        )?;
        let mut rows = stmt.query([enum_str(&state)?])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            let account: String = r.get(1)?;
            let st: String = r.get(4)?;
            out.push(OutboxEntry {
                id: r.get(0)?,
                account_id: parse_id(&account)?,
                draft_id: r.get(2)?,
                internet_message_id: r.get(3)?,
                state: enum_parse(&st)?,
                attempt_count: r.get(5)?,
                last_error: r.get(6)?,
            });
        }
        Ok(out)
    }

    /// After a crash, anything left in `sending` may or may not have been
    /// delivered. Mark it `uncertain` so it is never retried blindly.
    pub fn recover_interrupted_sends(&self) -> Result<usize> {
        Ok(self.conn.execute(
            "UPDATE outbox SET state = 'uncertain', updated_at = ?1,
                last_error = 'interrupted while sending'
             WHERE state = 'sending'",
            [now_unix()],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::sample_account;
    use OutboxState::*;

    #[test]
    fn drafts_upsert() {
        let s = Store::open_in_memory().expect("open");
        let a = sample_account();
        s.insert_account(&a).expect("acct");
        let id = s.save_draft(None, a.id, r#"{"v":1}"#).expect("save");
        s.save_draft(Some(&id), a.id, r#"{"v":2}"#).expect("update");
        assert_eq!(
            s.get_draft(&id).expect("get").as_deref(),
            Some(r#"{"v":2}"#)
        );
        assert_eq!(s.list_drafts(a.id).expect("list").len(), 1);
        s.delete_draft(&id).expect("del");
        assert!(s.get_draft(&id).expect("get").is_none());
    }

    #[test]
    fn outbox_state_machine_enforced() {
        let s = Store::open_in_memory().expect("open");
        let a = sample_account();
        s.insert_account(&a).expect("acct");
        let id = s
            .enqueue_outbox(a.id, None, "abc@postmoth")
            .expect("enqueue");
        s.transition_outbox(&id, Queued, Sending, None)
            .expect("send");
        // Stale CAS: someone else already moved it.
        assert!(matches!(
            s.transition_outbox(&id, Queued, Sending, None),
            Err(StoreError::InvalidTransition)
        ));
        // Illegal: sending → queued (would risk duplicate send).
        assert!(matches!(
            s.transition_outbox(&id, Sending, Queued, None),
            Err(StoreError::InvalidTransition)
        ));
        s.transition_outbox(&id, Sending, Sent, None).expect("sent");
        assert!(s.transition_outbox(&id, Sent, Queued, None).is_err());
        let sent = s.outbox_in_state(Sent).expect("list");
        assert_eq!(sent[0].attempt_count, 1);
        assert_eq!(sent[0].internet_message_id, "abc@postmoth");
    }

    #[test]
    fn crash_during_send_becomes_uncertain() {
        let s = Store::open_in_memory().expect("open");
        let a = sample_account();
        s.insert_account(&a).expect("acct");
        let id = s.enqueue_outbox(a.id, None, "x@y").expect("enqueue");
        s.transition_outbox(&id, Queued, Sending, None)
            .expect("send");
        assert_eq!(s.recover_interrupted_sends().expect("recover"), 1);
        let u = s.outbox_in_state(Uncertain).expect("list");
        assert_eq!(u.len(), 1);
        assert!(s.outbox_in_state(Queued).expect("list").is_empty());
    }
}
