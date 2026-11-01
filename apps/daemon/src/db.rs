//! The database actor: one thread owns the SQLite connection and runs every
//! read and write in order. Async code sends it closures.

use postmoth_store::{Store, StoreError};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use tokio::sync::oneshot;

type Job = Box<dyn FnOnce(&mut Store) + Send>;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("database actor stopped")]
    Gone,
}

#[derive(Debug, Clone)]
pub struct Db {
    tx: mpsc::Sender<Job>,
}

impl Db {
    /// Move `store` onto its own thread. The thread exits when every `Db`
    /// handle is dropped.
    pub fn spawn(store: Store) -> std::io::Result<(Self, JoinHandle<()>)> {
        let (tx, rx) = mpsc::channel::<Job>();
        let handle = thread::Builder::new()
            .name("postmoth-db".into())
            .spawn(move || {
                let mut store = store;
                for job in rx {
                    // A panicking job must not take the actor down; its
                    // caller sees `Gone` because the reply sender is dropped.
                    if catch_unwind(AssertUnwindSafe(|| job(&mut store))).is_err() {
                        tracing::error!("database job panicked");
                    }
                }
            })?;
        Ok((Self { tx }, handle))
    }

    pub async fn call<R, F>(&self, f: F) -> Result<R, DbError>
    where
        R: Send + 'static,
        F: FnOnce(&mut Store) -> Result<R, StoreError> + Send + 'static,
    {
        let (otx, orx) = oneshot::channel();
        self.tx
            .send(Box::new(move |s| {
                let _ = otx.send(f(s));
            }))
            .map_err(|_| DbError::Gone)?;
        Ok(orx.await.map_err(|_| DbError::Gone)??)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runs_jobs_and_survives_panics() {
        let (db, _h) = Db::spawn(Store::open_in_memory().expect("store")).expect("spawn");
        let v = db.call(|s| Ok(s.schema_version())).await.expect("call");
        assert!(v >= 1);
        let r: Result<(), _> = db.call(|_| panic!("boom")).await;
        assert!(matches!(r, Err(DbError::Gone)));
        assert!(db.call(|s| s.integrity_ok()).await.expect("alive"));
    }
}
