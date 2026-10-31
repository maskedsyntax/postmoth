use crate::accounts::{enum_parse, enum_str, parse_id};
use crate::{Result, Store, StoreError, now_unix};
use postmoth_core::model::{Folder, FolderRole};
use postmoth_core::{AccountId, FolderId};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

/// Per-folder IMAP sync position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FolderSyncState {
    pub uidvalidity: Option<u32>,
    pub highest_uid: u32,
    pub highest_modseq: Option<u64>,
    pub last_sync_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Default)]
struct Cursor {
    highest_uid: u32,
    highest_modseq: Option<u64>,
}

impl Store {
    /// Create the folder if missing (updating its role if it changed) and
    /// return its id.
    pub fn upsert_folder(
        &self,
        account_id: AccountId,
        remote_id: &str,
        role: FolderRole,
    ) -> Result<FolderId> {
        let role = enum_str(&role)?;
        let existing: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM folders WHERE account_id = ?1 AND remote_id = ?2",
                (account_id.to_string(), remote_id),
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = existing {
            self.conn
                .execute("UPDATE folders SET role = ?2 WHERE id = ?1", (&id, &role))?;
            return parse_id(&id);
        }
        let id = FolderId::new();
        self.conn.execute(
            "INSERT INTO folders (id, account_id, remote_id, role) VALUES (?1, ?2, ?3, ?4)",
            (id.to_string(), account_id.to_string(), remote_id, role),
        )?;
        Ok(id)
    }

    pub fn list_folders(&self, account_id: AccountId) -> Result<Vec<Folder>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, remote_id, role FROM folders WHERE account_id = ?1 ORDER BY remote_id",
        )?;
        let mut rows = stmt.query([account_id.to_string()])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            let id: String = r.get(0)?;
            let role: String = r.get(2)?;
            out.push(Folder {
                id: parse_id(&id)?,
                account_id,
                remote_id: r.get(1)?,
                role: enum_parse(&role)?,
            });
        }
        Ok(out)
    }

    pub fn folder_sync_state(&self, folder_id: FolderId) -> Result<FolderSyncState> {
        let (uidvalidity, cursor, last): (Option<i64>, Option<String>, Option<i64>) = self
            .conn
            .query_row(
                "SELECT uidvalidity, cursor, last_sync_at FROM folders WHERE id = ?1",
                [folder_id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let cursor: Cursor = match cursor {
            Some(c) => serde_json::from_str(&c)?,
            None => Cursor::default(),
        };
        Ok(FolderSyncState {
            uidvalidity: uidvalidity.and_then(|v| u32::try_from(v).ok()),
            highest_uid: cursor.highest_uid,
            highest_modseq: cursor.highest_modseq,
            last_sync_at: last,
        })
    }

    pub fn set_folder_sync_state(&self, folder_id: FolderId, st: &FolderSyncState) -> Result<()> {
        let cursor = serde_json::to_string(&Cursor {
            highest_uid: st.highest_uid,
            highest_modseq: st.highest_modseq,
        })?;
        let n = self.conn.execute(
            "UPDATE folders SET uidvalidity = ?2, cursor = ?3, last_sync_at = ?4 WHERE id = ?1",
            (
                folder_id.to_string(),
                st.uidvalidity.map(i64::from),
                cursor,
                st.last_sync_at.unwrap_or_else(now_unix),
            ),
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// The server changed UIDVALIDITY: every UID mapping in this folder is
    /// meaningless. Drop the mappings and any messages no longer in any
    /// folder, then reset the cursor. Drafts (separate table) are untouched.
    /// Returns the number of messages removed.
    pub fn reset_folder_for_uidvalidity(
        &mut self,
        folder_id: FolderId,
        new_uidvalidity: u32,
    ) -> Result<usize> {
        self.transaction(|tx| {
            let fid = folder_id.to_string();
            let account: String = tx
                .query_row(
                    "SELECT account_id FROM folders WHERE id = ?1",
                    [&fid],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(StoreError::NotFound)?;
            tx.execute("DELETE FROM folder_messages WHERE folder_id = ?1", [&fid])?;
            let removed = tx.execute(
                "DELETE FROM messages WHERE account_id = ?1
                 AND id NOT IN (SELECT message_id FROM folder_messages)",
                [&account],
            )?;
            let cursor = serde_json::to_string(&Cursor::default())?;
            tx.execute(
                "UPDATE folders SET uidvalidity = ?2, cursor = ?3 WHERE id = ?1",
                (&fid, i64::from(new_uidvalidity), cursor),
            )?;
            Ok(removed)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::tests::sample_account;

    #[test]
    fn upsert_is_idempotent_and_updates_role() {
        let s = Store::open_in_memory().expect("open");
        let a = sample_account();
        s.insert_account(&a).expect("acct");
        let f1 = s
            .upsert_folder(a.id, "INBOX", FolderRole::Inbox)
            .expect("f");
        let f2 = s
            .upsert_folder(a.id, "INBOX", FolderRole::Inbox)
            .expect("f");
        assert_eq!(f1, f2);
        s.upsert_folder(a.id, "Archive", FolderRole::Other)
            .expect("f");
        s.upsert_folder(a.id, "Archive", FolderRole::Archive)
            .expect("f");
        let folders = s.list_folders(a.id).expect("list");
        assert_eq!(folders.len(), 2);
        assert!(folders.iter().any(|f| f.role == FolderRole::Archive));
    }

    #[test]
    fn sync_state_roundtrip() {
        let s = Store::open_in_memory().expect("open");
        let a = sample_account();
        s.insert_account(&a).expect("acct");
        let f = s
            .upsert_folder(a.id, "INBOX", FolderRole::Inbox)
            .expect("f");
        assert_eq!(s.folder_sync_state(f).expect("st").highest_uid, 0);
        let st = FolderSyncState {
            uidvalidity: Some(42),
            highest_uid: 1000,
            highest_modseq: Some(77),
            last_sync_at: Some(5),
        };
        s.set_folder_sync_state(f, &st).expect("set");
        assert_eq!(s.folder_sync_state(f).expect("st"), st);
    }
}
