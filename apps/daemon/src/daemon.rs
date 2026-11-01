//! The account manager and control logic behind the D-Bus interface.

use crate::db::{Db, DbError};
use crate::otp::{self, OtpService};
use crate::worker::{self, Connector, WorkerCmd, WorkerCtx, WorkerHandle};
use postmoth_core::AccountId;
use postmoth_core::model::Account;
use postmoth_ipc::control::{
    AccountStatus, CONTROL_PROTOCOL_VERSION, MappingInfo, NewAccount, StatusReport, SyncState,
};
use postmoth_platform::{SecretError, Secrets};
use postmoth_store::StoreError;
use secrecy::SecretString;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, watch};

const PAUSED_SETTING: &str = "paused";

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("invalid argument: {0}")]
    Invalid(String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Secret(#[from] SecretError),
    #[error("internal error")]
    Internal(#[source] DbError),
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        match e {
            DbError::Store(StoreError::NotFound) => Self::NotFound,
            e => {
                tracing::error!(error = %e, "database error");
                Self::Internal(e)
            }
        }
    }
}

#[derive(Debug)]
pub struct Daemon<C: Connector> {
    ctx: Arc<WorkerCtx>,
    connector: Arc<C>,
    workers: Mutex<HashMap<AccountId, (Account, WorkerHandle)>>,
    paused_tx: watch::Sender<bool>,
    user_catalog: Option<String>,
    browser_socket: PathBuf,
}

impl<C: Connector> Daemon<C> {
    /// Load persisted state and start a worker per account.
    pub async fn start(
        db: Db,
        secrets: Arc<Secrets>,
        otp: Arc<OtpService>,
        connector: C,
        user_catalog: Option<String>,
        browser_socket: PathBuf,
    ) -> Result<Arc<Self>, ApiError> {
        let paused = db
            .call(|s| s.get_setting(PAUSED_SETTING))
            .await?
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        otp.set_paused(paused);
        let (paused_tx, paused_rx) = watch::channel(paused);
        let d = Arc::new(Self {
            ctx: Arc::new(WorkerCtx {
                db,
                secrets,
                otp,
                paused: paused_rx,
            }),
            connector: Arc::new(connector),
            workers: Mutex::new(HashMap::new()),
            paused_tx,
            user_catalog,
            browser_socket,
        });
        d.reload_mappings().await?;
        let accounts = d.ctx.db.call(|s| s.list_accounts()).await?;
        let mut workers = d.workers.lock().await;
        for a in accounts {
            let h = worker::spawn(Arc::clone(&d.ctx), Arc::clone(&d.connector), a.clone());
            workers.insert(a.id, (a, h));
        }
        drop(workers);
        Ok(d)
    }

    pub fn otp(&self) -> &Arc<OtpService> {
        &self.ctx.otp
    }

    async fn reload_mappings(&self) -> Result<(), ApiError> {
        let stored = self.ctx.db.call(|s| s.list_domain_mappings()).await?;
        self.ctx
            .otp
            .replace_mappings(otp::build_mappings(self.user_catalog.as_deref(), &stored));
        Ok(())
    }

    pub async fn status(&self) -> StatusReport {
        let workers = self.workers.lock().await;
        let mut accounts: Vec<AccountStatus> = workers
            .values()
            .map(|(a, h)| {
                let st = h.status.borrow().clone();
                AccountStatus {
                    id: a.id,
                    address: a.address.clone(),
                    otp_enabled: a.otp_enabled,
                    state: st.state,
                    last_sync_at: st.last_sync_at,
                    last_error: st.last_error,
                }
            })
            .collect();
        accounts.sort_by(|a, b| a.address.cmp(&b.address));
        StatusReport {
            daemon_version: crate::DAEMON_VERSION.to_owned(),
            protocol: CONTROL_PROTOCOL_VERSION,
            paused: *self.paused_tx.borrow(),
            accounts,
            otp_live_candidates: self.ctx.otp.live_candidates(),
            browser_socket: self.browser_socket.display().to_string(),
        }
    }

    pub async fn add_account(
        &self,
        new: NewAccount,
        password: SecretString,
    ) -> Result<AccountId, ApiError> {
        validate_new_account(&new)?;
        let id = AccountId::new();
        let secret_ref = format!("account/{id}");
        let account = Account {
            id,
            provider: new.provider,
            address: new.address.trim().to_owned(),
            display_name: new.display_name,
            imap: new.imap,
            smtp: new.smtp,
            login: new.login,
            auth_secret_ref: secret_ref.clone(),
            otp_enabled: new.otp_enabled,
            trusted_authserv_ids: new.trusted_authserv_ids,
        };
        self.ctx
            .secrets
            .store(
                &secret_ref,
                &format!("Postmoth: {}", account.address),
                &password,
            )
            .await?;
        drop(password);
        let to_insert = account.clone();
        if let Err(e) = self
            .ctx
            .db
            .call(move |s| s.insert_account(&to_insert))
            .await
        {
            // Do not leave an orphaned secret behind.
            let _ = self.ctx.secrets.delete(&secret_ref).await;
            return Err(e.into());
        }
        let h = worker::spawn(
            Arc::clone(&self.ctx),
            Arc::clone(&self.connector),
            account.clone(),
        );
        self.workers.lock().await.insert(id, (account, h));
        tracing::info!(account = %id, "account added");
        Ok(id)
    }

    /// Stop sync, delete cached mail, the keyring item and any live codes.
    pub async fn remove_account(&self, id: AccountId) -> Result<(), ApiError> {
        let entry = self.workers.lock().await.remove(&id);
        if let Some((_, h)) = entry {
            stop_worker(h).await;
        }
        self.ctx.otp.remove_account(id);
        let secret_ref = self.ctx.db.call(move |s| s.delete_account(id)).await?;
        self.ctx.secrets.delete(&secret_ref).await?;
        tracing::info!(account = %id, "account removed");
        Ok(())
    }

    /// `None` means every account.
    pub async fn sync_now(&self, id: Option<AccountId>) -> Result<(), ApiError> {
        let workers = self.workers.lock().await;
        match id {
            Some(id) => {
                let (_, h) = workers.get(&id).ok_or(ApiError::NotFound)?;
                let _ = h.cmd.try_send(WorkerCmd::SyncNow);
            }
            None => {
                for (_, h) in workers.values() {
                    let _ = h.cmd.try_send(WorkerCmd::SyncNow);
                }
            }
        }
        Ok(())
    }

    /// "Pause background mail": stops sync and drops every live code.
    pub async fn set_paused(&self, paused: bool) -> Result<(), ApiError> {
        self.ctx.otp.set_paused(paused);
        self.paused_tx.send_replace(paused);
        self.ctx
            .db
            .call(move |s| s.set_setting(PAUSED_SETTING, &serde_json::Value::Bool(paused)))
            .await?;
        tracing::info!(paused, "background mail pause changed");
        Ok(())
    }

    /// Record a user-confirmed sender → site trust mapping.
    pub async fn trust_sender(
        &self,
        sender: &str,
        site: &str,
        include_subdomains: bool,
    ) -> Result<i64, ApiError> {
        let host = otp::normalize_site(site, self.ctx.otp.origin_policy())
            .ok_or_else(|| ApiError::Invalid("site must be an https origin or host".into()))?;
        let mapping = otp::user_mapping(sender, &host, include_subdomains).ok_or_else(|| {
            ApiError::Invalid("invalid sender pattern, or site is a public suffix".into())
        })?;
        let pattern = match &mapping.sender {
            postmoth_otp::SenderPattern::Address(a) => a.clone(),
            postmoth_otp::SenderPattern::Domain(d) => format!("@{d}"),
        };
        let id = self
            .ctx
            .db
            .call(move |s| s.add_domain_mapping(&pattern, &host, include_subdomains, true))
            .await?;
        self.reload_mappings().await?;
        Ok(id)
    }

    pub async fn list_mappings(&self) -> Result<Vec<MappingInfo>, ApiError> {
        let rows = self.ctx.db.call(|s| s.list_domain_mappings()).await?;
        Ok(rows
            .into_iter()
            .map(|m| MappingInfo {
                id: m.id,
                sender_pattern: m.sender_pattern,
                trusted_origin: m.trusted_origin,
                include_subdomains: m.include_subdomains,
                user_confirmed: m.user_confirmed,
            })
            .collect())
    }

    pub async fn remove_mapping(&self, id: i64) -> Result<(), ApiError> {
        let removed = self
            .ctx
            .db
            .call(move |s| s.delete_domain_mapping(id))
            .await?;
        if !removed {
            return Err(ApiError::NotFound);
        }
        self.reload_mappings().await
    }

    /// Stop workers and wipe volatile state.
    pub async fn shutdown(&self) {
        let workers: Vec<_> = self.workers.lock().await.drain().collect();
        for (_, (_, h)) in workers {
            stop_worker(h).await;
        }
        self.ctx.otp.clear();
    }

    /// For tests: current state of one worker.
    pub async fn account_state(&self, id: AccountId) -> Option<SyncState> {
        self.workers
            .lock()
            .await
            .get(&id)
            .map(|(_, h)| h.status.borrow().state)
    }
}

async fn stop_worker(h: WorkerHandle) {
    let _ = h.cmd.send(WorkerCmd::Stop).await;
    let abort = h.task.abort_handle();
    if tokio::time::timeout(Duration::from_secs(5), h.task)
        .await
        .is_err()
    {
        abort.abort();
    }
}

fn validate_new_account(a: &NewAccount) -> Result<(), ApiError> {
    let bad = |m: &str| Err(ApiError::Invalid(m.to_owned()));
    let addr = a.address.trim();
    match addr.rsplit_once('@') {
        Some((l, d)) if !l.is_empty() && d.contains('.') && !addr.contains(char::is_whitespace) => {
        }
        _ => return bad("address must look like user@example.com"),
    }
    if a.login.is_empty() || a.login.contains(['\r', '\n', '\0']) {
        return bad("login must be non-empty and single-line");
    }
    for (name, ep) in [("imap", &a.imap), ("smtp", &a.smtp)] {
        if ep.host.is_empty()
            || ep.host.len() > 253
            || !ep
                .host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return bad(&format!("{name} host is invalid"));
        }
        if ep.port == 0 {
            return bad(&format!("{name} port is invalid"));
        }
    }
    Ok(())
}
