//! Pure sync planning: compare the stored cursor with what the server
//! reports on SELECT and decide what to do. No I/O here.

use crate::imap::MailboxStatus;

/// What the stored state knows about a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoredCursor {
    pub uidvalidity: Option<u32>,
    pub highest_uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPlan {
    /// UIDVALIDITY changed (or first sync after a reset): discard UID
    /// mappings, then fetch everything above UID 0.
    Reset { new_uidvalidity: u32 },
    /// Fetch UIDs strictly greater than `after_uid`.
    FetchNew { after_uid: u32 },
    /// `UIDNEXT` says nothing new arrived.
    UpToDate,
}

/// Decide the sync action for one folder.
///
/// A server that does not report UIDVALIDITY violates RFC 3501; we treat
/// that as "cannot trust UIDs" and fail rather than guess.
pub fn plan_folder_sync(
    stored: StoredCursor,
    server: &MailboxStatus,
) -> Result<SyncPlan, &'static str> {
    let Some(server_validity) = server.uid_validity else {
        return Err("server did not report UIDVALIDITY");
    };
    match stored.uidvalidity {
        Some(v) if v == server_validity => {}
        // First sync, or a change: either way existing mappings are void.
        _ => {
            return Ok(SyncPlan::Reset {
                new_uidvalidity: server_validity,
            });
        }
    }
    if let Some(next) = server.uid_next
        && next <= stored.highest_uid.saturating_add(1)
    {
        return Ok(SyncPlan::UpToDate);
    }
    Ok(SyncPlan::FetchNew {
        after_uid: stored.highest_uid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(validity: Option<u32>, next: Option<u32>) -> MailboxStatus {
        MailboxStatus {
            uid_validity: validity,
            uid_next: next,
            exists: 0,
            highest_modseq: None,
        }
    }

    #[test]
    fn first_sync_resets() {
        let p = plan_folder_sync(StoredCursor::default(), &status(Some(7), Some(10)));
        assert_eq!(p, Ok(SyncPlan::Reset { new_uidvalidity: 7 }));
    }

    #[test]
    fn changed_validity_resets() {
        let stored = StoredCursor {
            uidvalidity: Some(7),
            highest_uid: 500,
        };
        assert_eq!(
            plan_folder_sync(stored, &status(Some(8), Some(3))),
            Ok(SyncPlan::Reset { new_uidvalidity: 8 })
        );
    }

    #[test]
    fn incremental_and_up_to_date() {
        let stored = StoredCursor {
            uidvalidity: Some(7),
            highest_uid: 41,
        };
        assert_eq!(
            plan_folder_sync(stored, &status(Some(7), Some(42))),
            Ok(SyncPlan::UpToDate)
        );
        assert_eq!(
            plan_folder_sync(stored, &status(Some(7), Some(50))),
            Ok(SyncPlan::FetchNew { after_uid: 41 })
        );
        // No UIDNEXT: must look.
        assert_eq!(
            plan_folder_sync(stored, &status(Some(7), None)),
            Ok(SyncPlan::FetchNew { after_uid: 41 })
        );
    }

    #[test]
    fn missing_validity_is_error() {
        assert!(plan_folder_sync(StoredCursor::default(), &status(None, Some(1))).is_err());
    }
}
