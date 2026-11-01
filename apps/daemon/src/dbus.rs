//! D-Bus control interface `dev.postmoth.Daemon1` on the session bus, used
//! by the GTK app and `postmothctl`. Never reachable from the browser.

use crate::daemon::{ApiError, Daemon};
use crate::worker::TlsConnector;
use postmoth_core::AccountId;
use postmoth_ipc::control::NewAccount;
use secrecy::SecretString;
use std::sync::Arc;
use zbus::fdo;

#[derive(Debug)]
pub struct ControlIface {
    pub daemon: Arc<Daemon<TlsConnector>>,
}

fn map_err(e: ApiError) -> fdo::Error {
    match e {
        ApiError::Invalid(m) => fdo::Error::InvalidArgs(m),
        ApiError::NotFound => fdo::Error::UnknownObject("not found".into()),
        e => fdo::Error::Failed(e.to_string()),
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> fdo::Result<String> {
    serde_json::to_string(v).map_err(|e| fdo::Error::Failed(e.to_string()))
}

fn parse_id(id: &str) -> fdo::Result<AccountId> {
    id.parse()
        .map_err(|_| fdo::Error::InvalidArgs("invalid account id".into()))
}

#[zbus::interface(name = "dev.postmoth.Daemon1")]
impl ControlIface {
    /// JSON `StatusReport`.
    async fn status(&self) -> fdo::Result<String> {
        to_json(&self.daemon.status().await)
    }

    /// `config_json` is a `NewAccount`; returns the new account id.
    async fn add_account(&self, config_json: &str, password: String) -> fdo::Result<String> {
        let password = SecretString::from(password);
        let new: NewAccount = serde_json::from_str(config_json)
            .map_err(|e| fdo::Error::InvalidArgs(format!("bad account config: {e}")))?;
        self.daemon
            .add_account(new, password)
            .await
            .map(|id| id.to_string())
            .map_err(map_err)
    }

    async fn remove_account(&self, id: &str) -> fdo::Result<()> {
        self.daemon
            .remove_account(parse_id(id)?)
            .await
            .map_err(map_err)
    }

    /// Empty id means all accounts.
    async fn sync_now(&self, id: &str) -> fdo::Result<()> {
        let id = if id.is_empty() {
            None
        } else {
            Some(parse_id(id)?)
        };
        self.daemon.sync_now(id).await.map_err(map_err)
    }

    async fn set_paused(&self, paused: bool) -> fdo::Result<()> {
        self.daemon.set_paused(paused).await.map_err(map_err)
    }

    async fn trust_sender(
        &self,
        sender: &str,
        site: &str,
        include_subdomains: bool,
    ) -> fdo::Result<i64> {
        self.daemon
            .trust_sender(sender, site, include_subdomains)
            .await
            .map_err(map_err)
    }

    /// JSON array of `MappingInfo`.
    async fn list_mappings(&self) -> fdo::Result<String> {
        to_json(&self.daemon.list_mappings().await.map_err(map_err)?)
    }

    async fn remove_mapping(&self, id: i64) -> fdo::Result<()> {
        self.daemon.remove_mapping(id).await.map_err(map_err)
    }

    #[zbus(property)]
    fn protocol_version(&self) -> u32 {
        postmoth_ipc::control::CONTROL_PROTOCOL_VERSION
    }
}
