use crate::{Result, Store, now_unix};
use rusqlite::OptionalExtension;

/// A persisted sender ↔ origin trust mapping (user-confirmed or catalog).
/// Validation happens in `postmoth-otp` before anything is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMapping {
    pub id: i64,
    pub sender_pattern: String,
    pub trusted_origin: String,
    pub include_subdomains: bool,
    pub user_confirmed: bool,
    pub confirmed_at: i64,
}

impl Store {
    pub fn get_setting(&self, key: &str) -> Result<Option<serde_json::Value>> {
        let v: Option<String> = self
            .conn
            .query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [key],
                |r| r.get(0),
            )
            .optional()?;
        v.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }

    pub fn set_setting(&self, key: &str, value: &serde_json::Value) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value_json) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json",
            (key, serde_json::to_string(value)?),
        )?;
        Ok(())
    }

    pub fn add_domain_mapping(
        &self,
        sender_pattern: &str,
        trusted_origin: &str,
        include_subdomains: bool,
        user_confirmed: bool,
    ) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO domain_mappings (sender_pattern, trusted_origin, include_subdomains, source, confirmed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (sender_pattern, trusted_origin) DO UPDATE SET
                include_subdomains = excluded.include_subdomains,
                confirmed_at = excluded.confirmed_at",
            (
                sender_pattern,
                trusted_origin,
                include_subdomains,
                if user_confirmed { "user" } else { "catalog" },
                now_unix(),
            ),
        )?;
        Ok(self.conn.query_row(
            "SELECT id FROM domain_mappings WHERE sender_pattern = ?1 AND trusted_origin = ?2",
            (sender_pattern, trusted_origin),
            |r| r.get(0),
        )?)
    }

    pub fn list_domain_mappings(&self) -> Result<Vec<StoredMapping>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, sender_pattern, trusted_origin, include_subdomains, source, confirmed_at
             FROM domain_mappings ORDER BY sender_pattern, trusted_origin",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(StoredMapping {
                    id: r.get(0)?,
                    sender_pattern: r.get(1)?,
                    trusted_origin: r.get(2)?,
                    include_subdomains: r.get(3)?,
                    user_confirmed: r.get::<_, String>(4)? == "user",
                    confirmed_at: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn delete_domain_mapping(&self, id: i64) -> Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM domain_mappings WHERE id = ?1", [id])?
            > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip() {
        let s = Store::open_in_memory().expect("open");
        assert!(s.get_setting("otp.ttl").expect("get").is_none());
        s.set_setting("otp.ttl", &serde_json::json!(300))
            .expect("set");
        s.set_setting("otp.ttl", &serde_json::json!(120))
            .expect("set");
        assert_eq!(
            s.get_setting("otp.ttl").expect("get"),
            Some(serde_json::json!(120))
        );
    }

    #[test]
    fn mappings_crud_and_unique() {
        let s = Store::open_in_memory().expect("open");
        let id = s
            .add_domain_mapping("no-reply@a.example", "login.a.example", false, true)
            .expect("add");
        let id2 = s
            .add_domain_mapping("no-reply@a.example", "login.a.example", true, true)
            .expect("re-add");
        assert_eq!(id, id2);
        let all = s.list_domain_mappings().expect("list");
        assert_eq!(all.len(), 1);
        assert!(all[0].include_subdomains && all[0].user_confirmed);
        assert!(s.delete_domain_mapping(id).expect("del"));
        assert!(s.list_domain_mappings().expect("list").is_empty());
    }
}
