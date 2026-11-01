//! One sync worker per account: connect, sync INBOX, wait (IDLE or poll),
//! repeat, with backoff on failure. M0 scope: INBOX only.

use crate::db::{Db, DbError};
use crate::ingest;
use crate::otp::OtpService;
use postmoth_core::FolderId;
use postmoth_core::model::{Account, FolderRole};
use postmoth_ipc::control::SyncState;
use postmoth_mail::imap::MAX_PER_FETCH;
use postmoth_mail::sync::StoredCursor;
use postmoth_mail::{
    Backoff, FetchedMessage, IdleOutcome, ImapConnection, ImapStream, MailError, SyncPlan,
    TlsSettings, plan_folder_sync,
};
use postmoth_otp::InboundMessage;
use postmoth_platform::Secrets;
use postmoth_store::FolderSyncState;
use secrecy::SecretString;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Re-issue IDLE well before the 30-minute server timeout.
const IDLE_REFRESH: Duration = Duration::from_secs(25 * 60);
/// Poll interval for servers without IDLE.
const POLL_INTERVAL: Duration = Duration::from_secs(3 * 60);
/// On first sync (or a UIDVALIDITY reset) only look at roughly the newest
/// this-many UIDs. Full history is an M1 concern.
const INITIAL_UID_WINDOW: u32 = 500;
/// Larger messages are fetched headers-only.
const MAX_BODY_BYTES: u32 = 25 * 1024 * 1024;
const INBOX: &str = "INBOX";

/// Opens authenticated IMAP sessions. Abstracted so tests can use an
/// in-process server.
pub trait Connector: Send + Sync + 'static {
    type Stream: ImapStream + 'static;
    fn connect(
        &self,
        account: &Account,
        password: &SecretString,
    ) -> impl Future<Output = Result<ImapConnection<Self::Stream>, MailError>> + Send;
}

/// Real connections: TLS (implicit or mandatory STARTTLS) + LOGIN.
#[derive(Debug, Clone, Default)]
pub struct TlsConnector {
    pub tls: TlsSettings,
}

impl Connector for TlsConnector {
    type Stream = postmoth_mail::tls::ImapTls;
    fn connect(
        &self,
        account: &Account,
        password: &SecretString,
    ) -> impl Future<Output = Result<ImapConnection<Self::Stream>, MailError>> + Send {
        postmoth_mail::connect_imap(&account.imap, &self.tls, &account.login, password)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCmd {
    SyncNow,
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerStatus {
    pub state: SyncState,
    pub last_sync_at: Option<i64>,
    pub last_error: Option<String>,
}

impl Default for WorkerStatus {
    fn default() -> Self {
        Self {
            state: SyncState::Starting,
            last_sync_at: None,
            last_error: None,
        }
    }
}

/// Shared by all workers.
#[derive(Debug)]
pub struct WorkerCtx {
    pub db: Db,
    pub secrets: Arc<Secrets>,
    pub otp: Arc<OtpService>,
    pub paused: watch::Receiver<bool>,
}

#[derive(Debug)]
pub struct WorkerHandle {
    pub cmd: mpsc::Sender<WorkerCmd>,
    pub status: watch::Receiver<WorkerStatus>,
    pub task: JoinHandle<()>,
}

#[derive(Debug, thiserror::Error)]
enum WorkerError {
    #[error(transparent)]
    Mail(#[from] MailError),
    #[error(transparent)]
    Db(#[from] DbError),
}

enum SessionEnd {
    Stop,
    Paused,
}

/// Why a wait ended.
enum Wake {
    Cmd(WorkerCmd),
    Paused,
    Elapsed,
}

pub fn spawn<C: Connector>(
    ctx: Arc<WorkerCtx>,
    connector: Arc<C>,
    account: Account,
) -> WorkerHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (status_tx, status_rx) = watch::channel(WorkerStatus::default());
    let task = tokio::spawn(async move {
        let mut w = Worker {
            paused: ctx.paused.clone(),
            ctx,
            account,
            cmd_rx,
            status: status_tx,
        };
        w.run(connector.as_ref()).await;
        w.set_state(SyncState::Stopped);
    });
    WorkerHandle {
        cmd: cmd_tx,
        status: status_rx,
        task,
    }
}

struct Worker {
    ctx: Arc<WorkerCtx>,
    account: Account,
    cmd_rx: mpsc::Receiver<WorkerCmd>,
    paused: watch::Receiver<bool>,
    status: watch::Sender<WorkerStatus>,
}

impl Worker {
    fn set_state(&self, state: SyncState) {
        self.status.send_modify(|s| s.state = state);
    }

    fn set_error(&self, err: Option<String>) {
        self.status.send_modify(|s| s.last_error = err);
    }

    /// Wait for a command, a pause change, or `limit`.
    async fn wait(&mut self, limit: Option<Duration>, wake_on_pause: bool) -> Wake {
        let sleep = async {
            match limit {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending().await,
            }
        };
        let want = wake_on_pause;
        tokio::select! {
            c = self.cmd_rx.recv() => Wake::Cmd(c.unwrap_or(WorkerCmd::Stop)),
            r = self.paused.wait_for(|p| *p == want) => match r {
                Ok(_) => Wake::Paused,
                Err(_) => Wake::Cmd(WorkerCmd::Stop),
            },
            () = sleep => Wake::Elapsed,
        }
    }

    async fn run<C: Connector>(&mut self, connector: &C) {
        let mut backoff = Backoff::for_reconnect();
        loop {
            if *self.paused.borrow() {
                self.set_state(SyncState::Paused);
                // Wake when un-paused.
                if let Wake::Cmd(WorkerCmd::Stop) = self.wait(None, false).await {
                    return;
                }
                continue;
            }

            self.set_state(SyncState::Connecting);
            let password = match self.ctx.secrets.load(&self.account.auth_secret_ref).await {
                Ok(Some(p)) => p,
                Ok(None) => {
                    self.set_state(SyncState::MissingSecret);
                    self.set_error(Some("no password in the keyring".into()));
                    if self.wait_for_user().await {
                        return;
                    }
                    continue;
                }
                Err(e) => {
                    self.set_error(Some(e.to_string()));
                    if self.back_off(&mut backoff).await {
                        return;
                    }
                    continue;
                }
            };
            let conn = connector.connect(&self.account, &password).await;
            drop(password);
            let conn = match conn {
                Ok(c) => c,
                Err(e) if e.is_auth() => {
                    tracing::warn!(account = %self.account.id, "IMAP login rejected");
                    self.set_state(SyncState::AuthFailed);
                    self.set_error(Some(e.to_string()));
                    if self.wait_for_user().await {
                        return;
                    }
                    continue;
                }
                Err(e) => {
                    tracing::info!(account = %self.account.id, error = %e, "IMAP connect failed");
                    self.set_error(Some(e.to_string()));
                    if self.back_off(&mut backoff).await {
                        return;
                    }
                    continue;
                }
            };
            backoff.reset();
            self.set_error(None);
            match self.session(conn).await {
                Ok(SessionEnd::Stop) => return,
                Ok(SessionEnd::Paused) => {}
                Err(e) => {
                    tracing::info!(account = %self.account.id, error = %e, "IMAP session ended");
                    self.set_error(Some(e.to_string()));
                    if matches!(e, WorkerError::Db(DbError::Gone)) {
                        return;
                    }
                    if self.back_off(&mut backoff).await {
                        return;
                    }
                }
            }
        }
    }

    /// Returns `true` if the worker should stop.
    async fn wait_for_user(&mut self) -> bool {
        // Retry on "sync now", on resume, or after a long while.
        matches!(
            self.wait(Some(Duration::from_secs(6 * 3600)), true).await,
            Wake::Cmd(WorkerCmd::Stop)
        )
    }

    /// Returns `true` if the worker should stop.
    async fn back_off(&mut self, backoff: &mut Backoff) -> bool {
        let delay = backoff.next_delay();
        self.set_state(SyncState::Backoff {
            retry_in_secs: delay.as_secs(),
        });
        matches!(
            self.wait(Some(delay), true).await,
            Wake::Cmd(WorkerCmd::Stop)
        )
    }

    async fn session<S: ImapStream>(
        &mut self,
        mut conn: ImapConnection<S>,
    ) -> Result<SessionEnd, WorkerError> {
        let account_id = self.account.id;
        let folder = self
            .ctx
            .db
            .call(move |s| s.upsert_folder(account_id, INBOX, FolderRole::Inbox))
            .await?;
        loop {
            self.set_state(SyncState::Syncing);
            let n = self.sync_inbox(&mut conn, folder).await?;
            if n > 0 {
                tracing::info!(account = %account_id, new = n, "synced INBOX");
            }
            let now = crate::now_unix();
            self.status.send_modify(|s| s.last_sync_at = Some(now));

            let wake = if conn.caps().idle {
                self.set_state(SyncState::Idle);
                let mut wake = Wake::Elapsed;
                let (c, outcome) = {
                    let cmd_rx = &mut self.cmd_rx;
                    let paused = &mut self.paused;
                    let wake = &mut wake;
                    conn.idle_until(IDLE_REFRESH, async move {
                        tokio::select! {
                            c = cmd_rx.recv() => *wake = Wake::Cmd(c.unwrap_or(WorkerCmd::Stop)),
                            r = paused.wait_for(|p| *p) => {
                                *wake = if r.is_ok() { Wake::Paused } else { Wake::Cmd(WorkerCmd::Stop) };
                            }
                        }
                    })
                    .await?
                };
                conn = c;
                if outcome != IdleOutcome::Interrupted {
                    wake = Wake::Elapsed;
                }
                wake
            } else {
                self.set_state(SyncState::Polling);
                let w = self.wait(Some(POLL_INTERVAL), true).await;
                if matches!(w, Wake::Elapsed) {
                    conn.noop().await?;
                }
                w
            };
            match wake {
                Wake::Cmd(WorkerCmd::Stop) => {
                    let _ = conn.logout().await;
                    return Ok(SessionEnd::Stop);
                }
                Wake::Paused => {
                    let _ = conn.logout().await;
                    return Ok(SessionEnd::Paused);
                }
                Wake::Cmd(WorkerCmd::SyncNow) | Wake::Elapsed => {}
            }
        }
    }

    /// Fetch everything new in INBOX. Returns how many messages were stored.
    async fn sync_inbox<S: ImapStream>(
        &mut self,
        conn: &mut ImapConnection<S>,
        folder: FolderId,
    ) -> Result<usize, WorkerError> {
        let server = conn.select(INBOX).await?;
        let stored = self
            .ctx
            .db
            .call(move |s| s.folder_sync_state(folder))
            .await?;
        let plan = plan_folder_sync(
            StoredCursor {
                uidvalidity: stored.uidvalidity,
                highest_uid: stored.highest_uid,
            },
            &server,
        )
        .map_err(|m| MailError::Protocol(m.to_owned()))?;
        // `plan_folder_sync` fails without UIDVALIDITY, so this is set.
        let uidvalidity = server.uid_validity;
        let mut after = match plan {
            SyncPlan::UpToDate => return Ok(0),
            SyncPlan::FetchNew { after_uid } => after_uid,
            SyncPlan::Reset { new_uidvalidity } => {
                if stored.uidvalidity.is_some() {
                    tracing::warn!(account = %self.account.id, "UIDVALIDITY changed; resetting INBOX cache");
                }
                self.ctx
                    .db
                    .call(move |s| s.reset_folder_for_uidvalidity(folder, new_uidvalidity))
                    .await?;
                server.uid_next.map_or(0, |n| {
                    n.saturating_sub(1).saturating_sub(INITIAL_UID_WINDOW)
                })
            }
        };
        let mut stored_count = 0;
        loop {
            let batch = conn.fetch_new(after, MAX_BODY_BYTES).await?;
            let n = batch.len();
            for m in batch {
                after = after.max(m.uid);
                if self.ingest(folder, m).await? {
                    stored_count += 1;
                }
            }
            let st = FolderSyncState {
                uidvalidity,
                highest_uid: after,
                highest_modseq: server.highest_modseq,
                last_sync_at: Some(crate::now_unix()),
            };
            self.ctx
                .db
                .call(move |s| s.set_folder_sync_state(folder, &st))
                .await?;
            if n < MAX_PER_FETCH {
                return Ok(stored_count);
            }
        }
    }

    /// Store one message and, if it is new, offer it to the OTP engine.
    async fn ingest(&self, folder: FolderId, m: FetchedMessage) -> Result<bool, WorkerError> {
        let account = self.account.clone();
        let uid = m.uid;
        let modseq = m.modseq;
        let full = !m.headers_only;
        let now = crate::now_unix();
        let parsed = tokio::task::spawn_blocking(move || ingest::build(&account, &m, now))
            .await
            .ok()
            .flatten();
        let Some((new, norm)) = parsed else {
            tracing::warn!(account = %self.account.id, uid, "skipping unparseable message");
            return Ok(false);
        };
        let received_at = new.received_at;
        let (message_id, inserted) = self
            .ctx
            .db
            .call(move |s| s.insert_message(folder, uid, modseq, &new))
            .await?;
        if inserted && full && self.account.otp_enabled {
            let sender = norm.from.as_ref().map_or("", |f| f.address.as_str());
            let outcome = self.ctx.otp.process(&InboundMessage {
                account_id: self.account.id,
                message_id,
                sender_address: sender,
                subject: norm.subject.as_deref().unwrap_or(""),
                text: &norm.text,
                date: norm.date.map(ingest::unix_to_system),
                received_at: ingest::unix_to_system(received_at),
                auth: ingest::sender_auth(&norm),
                is_bulk: norm.is_bulk,
                is_inbound: true,
            });
            tracing::debug!(account = %self.account.id, uid, ?outcome, "otp check");
        }
        Ok(inserted)
    }
}
