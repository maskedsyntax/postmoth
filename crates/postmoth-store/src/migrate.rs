//! Forward-only schema migrations tracked in `schema_migrations`.
//!
//! Each migration runs in its own transaction together with its
//! bookkeeping row, so a crash mid-upgrade leaves the previous version
//! intact. Never edit a shipped migration; add a new one.

use crate::{Result, StoreError, now_unix};
use rusqlite::{Connection, OptionalExtension};

const MIGRATIONS: &[(i64, &str)] = &[(1, include_str!("migrations/0001_initial.sql"))];

/// Latest schema version this build understands.
pub const SCHEMA_VERSION: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;

pub(crate) fn current_version(conn: &Connection) -> Result<i64> {
    let v: Option<i64> = conn
        .query_row("SELECT max(version) FROM schema_migrations", [], |r| {
            r.get(0)
        })
        .optional()?
        .flatten();
    Ok(v.unwrap_or(0))
}

pub(crate) fn run(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY,
             applied_at INTEGER NOT NULL
         );",
    )?;
    let current = current_version(conn)?;
    if current > SCHEMA_VERSION {
        return Err(StoreError::NewerSchema {
            found: current,
            supported: SCHEMA_VERSION,
        });
    }
    for (version, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
            (version, now_unix()),
        )?;
        tx.commit()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn applies_all_and_is_idempotent() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("m.db");
        let s = Store::open(&path).expect("open");
        assert_eq!(s.schema_version(), SCHEMA_VERSION);
        drop(s);
        let s = Store::open(&path).expect("reopen");
        assert_eq!(s.schema_version(), SCHEMA_VERSION);
    }

    #[test]
    fn refuses_newer_schema() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("m.db");
        drop(Store::open(&path).expect("open"));
        let conn = Connection::open(&path).expect("raw");
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (9999, 0)",
            [],
        )
        .expect("insert");
        drop(conn);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::NewerSchema { found: 9999, .. })
        ));
    }

    #[test]
    fn fts5_available() {
        let s = Store::open_in_memory().expect("open");
        let n: i64 = s
            .conn
            .query_row("SELECT count(*) FROM messages_fts", [], |r| r.get(0))
            .expect("fts");
        assert_eq!(n, 0);
    }
}
