//! Local mail cache (spec §9).
//!
//! * One SQLite database under the XDG data dir, owner-only permissions,
//!   WAL mode, foreign keys on, `secure_delete` on so removed mail is
//!   overwritten rather than left in free pages.
//! * Versioned migrations recorded in `schema_migrations`; a database
//!   written by a newer Postmoth is refused rather than silently misread.
//! * Contentless FTS5 index for local search.
//! * Never stores secrets or OTP codes. Standard SQLite is **not**
//!   encrypted at rest; UI copy must say so.
//!
//! The API is synchronous. The daemon owns the single [`Store`] on a
//! dedicated thread (the DB actor) and is its only writer.

mod accounts;
mod folders;
mod messages;
mod migrate;
mod outbox;
mod settings;

pub use accounts::NewAccount;
pub use folders::FolderSyncState;
pub use messages::{MessageDetail, NewAttachment, NewMessage, PageCursor};
pub use migrate::SCHEMA_VERSION;
pub use outbox::OutboxEntry;
pub use settings::StoredMapping;

use rusqlite::Connection;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database schema version {found} is newer than supported {supported}")]
    NewerSchema { found: i64, supported: i64 },
    #[error("not found")]
    NotFound,
    #[error("invalid state transition")]
    InvalidTransition,
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("corrupt row: {0}")]
    Corrupt(&'static str),
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct Store {
    conn: Connection,
    path: Option<PathBuf>,
}

impl Store {
    /// Open (creating if needed) the database at `path`. The parent
    /// directory is created `0700`, the file `0600`.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        // Create the file ourselves so it never exists with default perms.
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;

        let conn = Connection::open(path)?;
        let store = Self::init(conn, Some(path.to_owned()))?;
        store.tighten_sidecar_permissions()?;
        Ok(store)
    }

    /// In-memory database for tests and diagnostics.
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?, None)
    }

    fn init(mut conn: Connection, path: Option<PathBuf>) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA secure_delete = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA busy_timeout = 5000;",
        )?;
        migrate::run(&mut conn)?;
        Ok(Self { conn, path })
    }

    /// SQLite creates `-wal`/`-shm` with the main file's mode, but make
    /// sure regardless.
    fn tighten_sidecar_permissions(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        for suffix in ["-wal", "-shm"] {
            let mut p = path.clone().into_os_string();
            p.push(suffix);
            let p = PathBuf::from(p);
            if p.exists() {
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn schema_version(&self) -> i64 {
        migrate::current_version(&self.conn).unwrap_or(0)
    }

    /// Run `f` inside a transaction (rolled back on error).
    pub fn transaction<T>(
        &mut self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T>,
    ) -> Result<T> {
        let tx = self.conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// Integrity check (diagnostics, after crash).
    pub fn integrity_ok(&self) -> Result<bool> {
        let r: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        Ok(r == "ok")
    }
}

pub(crate) fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_permissions_are_owner_only() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("sub/postmoth.db");
        let s = Store::open(&path).expect("open");
        // Force WAL files into existence.
        s.set_setting("k", &serde_json::json!(1)).expect("write");
        drop(s);
        let s = Store::open(&path).expect("reopen");
        let mode = |p: &Path| fs::metadata(p).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().expect("parent")), 0o700);
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        if wal.exists() {
            assert_eq!(mode(&wal), 0o600);
        }
        assert!(s.integrity_ok().expect("check"));
    }

    #[test]
    fn wal_enabled_on_disk() {
        let dir = tempfile::tempdir().expect("tmp");
        let s = Store::open(&dir.path().join("p.db")).expect("open");
        let mode: String = s
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(mode, "wal");
        let fk: i64 = s
            .conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .expect("pragma");
        assert_eq!(fk, 1);
    }
}
