use crate::{Result, Store, StoreError, now_unix};
use postmoth_core::AccountId;
use postmoth_core::model::{Account, ProviderType, ServerEndpoint};
use rusqlite::{OptionalExtension, Row};
use serde::{Deserialize, Serialize};

/// Alias kept for API symmetry with other `New*` types.
pub type NewAccount = Account;

/// Non-secret account configuration stored as JSON.
#[derive(Serialize, Deserialize)]
struct AccountConfig {
    imap: ServerEndpoint,
    smtp: ServerEndpoint,
    login: String,
    otp_enabled: bool,
    #[serde(default)]
    trusted_authserv_ids: Vec<String>,
}

pub(crate) fn enum_str<T: Serialize>(v: &T) -> Result<String> {
    match serde_json::to_value(v)? {
        serde_json::Value::String(s) => Ok(s),
        _ => Err(StoreError::Corrupt("enum did not serialize to string")),
    }
}

pub(crate) fn enum_parse<T: for<'de> Deserialize<'de>>(s: &str) -> Result<T> {
    Ok(serde_json::from_value(serde_json::Value::String(
        s.to_owned(),
    ))?)
}

pub(crate) fn parse_id<T: std::str::FromStr>(s: &str) -> Result<T> {
    s.parse().map_err(|_| StoreError::Corrupt("bad id"))
}

fn row_to_account(r: &Row<'_>) -> Result<Account> {
    let id: String = r.get(0)?;
    let provider: String = r.get(1)?;
    let config: String = r.get(4)?;
    let config: AccountConfig = serde_json::from_str(&config)?;
    Ok(Account {
        id: parse_id(&id)?,
        provider: enum_parse::<ProviderType>(&provider)?,
        address: r.get(2)?,
        display_name: r.get(3)?,
        imap: config.imap,
        smtp: config.smtp,
        login: config.login,
        auth_secret_ref: r.get(5)?,
        otp_enabled: config.otp_enabled,
        trusted_authserv_ids: config.trusted_authserv_ids,
    })
}

const ACCOUNT_COLS: &str = "id, provider_type, address, display_name, config_json, auth_secret_ref";

impl Store {
    pub fn insert_account(&self, a: &Account) -> Result<()> {
        let config = serde_json::to_string(&AccountConfig {
            imap: a.imap.clone(),
            smtp: a.smtp.clone(),
            login: a.login.clone(),
            otp_enabled: a.otp_enabled,
            trusted_authserv_ids: a.trusted_authserv_ids.clone(),
        })?;
        self.conn.execute(
            "INSERT INTO accounts (id, provider_type, address, display_name, created_at, config_json, auth_secret_ref)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                a.id.to_string(),
                enum_str(&a.provider)?,
                &a.address,
                &a.display_name,
                now_unix(),
                config,
                &a.auth_secret_ref,
            ),
        )?;
        Ok(())
    }

    pub fn get_account(&self, id: AccountId) -> Result<Option<Account>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ACCOUNT_COLS} FROM accounts WHERE id = ?1"
        ))?;
        let mut rows = stmt.query([id.to_string()])?;
        match rows.next()? {
            Some(r) => Ok(Some(row_to_account(r)?)),
            None => Ok(None),
        }
    }

    pub fn list_accounts(&self) -> Result<Vec<Account>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {ACCOUNT_COLS} FROM accounts ORDER BY created_at, address"
        ))?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            out.push(row_to_account(r)?);
        }
        Ok(out)
    }

    pub fn set_account_otp_enabled(&self, id: AccountId, enabled: bool) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE accounts SET config_json = json_set(config_json, '$.otp_enabled', json(?2))
             WHERE id = ?1",
            (id.to_string(), if enabled { "true" } else { "false" }),
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Delete an account and (via cascades) all of its cached mail,
    /// folders, drafts and outbox. Returns the Secret Service reference so
    /// the caller can delete the credential too.
    pub fn delete_account(&mut self, id: AccountId) -> Result<String> {
        self.transaction(|tx| {
            let secret_ref: Option<String> = tx
                .query_row(
                    "SELECT auth_secret_ref FROM accounts WHERE id = ?1",
                    [id.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            let secret_ref = secret_ref.ok_or(StoreError::NotFound)?;
            tx.execute("DELETE FROM accounts WHERE id = ?1", [id.to_string()])?;
            Ok(secret_ref)
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use postmoth_core::model::TlsMode;

    pub(crate) fn sample_account() -> Account {
        Account {
            id: AccountId::new(),
            provider: ProviderType::GenericImap,
            address: "user@example.org".into(),
            display_name: Some("User".into()),
            imap: ServerEndpoint {
                host: "imap.example.org".into(),
                port: 993,
                tls: TlsMode::Implicit,
            },
            smtp: ServerEndpoint {
                host: "smtp.example.org".into(),
                port: 465,
                tls: TlsMode::Implicit,
            },
            login: "user@example.org".into(),
            auth_secret_ref: "postmoth:acct:1".into(),
            otp_enabled: true,
            trusted_authserv_ids: vec!["mx.example.com".into()],
        }
    }

    #[test]
    fn crud() {
        let mut s = Store::open_in_memory().expect("open");
        let a = sample_account();
        s.insert_account(&a).expect("insert");
        assert_eq!(s.get_account(a.id).expect("get"), Some(a.clone()));
        assert_eq!(s.list_accounts().expect("list").len(), 1);
        s.set_account_otp_enabled(a.id, false).expect("toggle");
        assert!(!s.get_account(a.id).expect("get").expect("some").otp_enabled);
        assert_eq!(s.delete_account(a.id).expect("delete"), "postmoth:acct:1");
        assert!(s.get_account(a.id).expect("get").is_none());
        assert!(matches!(s.delete_account(a.id), Err(StoreError::NotFound)));
    }
}
