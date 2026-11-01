//! Account credentials. Production uses the Secret Service (GNOME Keyring,
//! KWallet) through `oo7`; the database only ever holds the opaque
//! `secret_ref`. Tests use an in-memory map.

use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

/// Attribute that scopes our items in the keyring.
const APP_ATTR: (&str, &str) = ("application", "dev.postmoth.Postmoth");
const REF_ATTR: &str = "postmoth-secret-ref";

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret service unavailable: {0}")]
    Unavailable(String),
    #[error("secret service error: {0}")]
    Backend(String),
    #[error("stored secret is not valid UTF-8")]
    NotText,
}

impl SecretError {
    fn backend(e: oo7::Error) -> Self {
        // oo7 errors never include secret material.
        Self::Backend(e.to_string())
    }
}

enum Backend {
    Keyring(oo7::Keyring),
    Memory(Mutex<HashMap<String, SecretString>>),
}

pub struct Secrets {
    backend: Backend,
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.backend {
            Backend::Keyring(_) => "keyring",
            Backend::Memory(_) => "memory",
        };
        f.debug_struct("Secrets").field("backend", &kind).finish()
    }
}

fn attrs(secret_ref: &str) -> HashMap<&str, &str> {
    HashMap::from([APP_ATTR, (REF_ATTR, secret_ref)])
}

impl Secrets {
    /// Connect to the user's keyring (Secret Service, or the portal inside a
    /// sandbox).
    pub async fn keyring() -> Result<Self, SecretError> {
        let k = oo7::Keyring::new()
            .await
            .map_err(|e| SecretError::Unavailable(e.to_string()))?;
        Ok(Self {
            backend: Backend::Keyring(k),
        })
    }

    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            backend: Backend::Memory(Mutex::new(HashMap::new())),
        }
    }

    /// Store (or replace) the secret under `secret_ref`.
    pub async fn store(
        &self,
        secret_ref: &str,
        label: &str,
        secret: &SecretString,
    ) -> Result<(), SecretError> {
        match &self.backend {
            Backend::Keyring(k) => {
                k.unlock().await.map_err(SecretError::backend)?;
                k.create_item(
                    label,
                    &attrs(secret_ref),
                    secret.expose_secret().as_bytes(),
                    true,
                )
                .await
                .map_err(SecretError::backend)
            }
            Backend::Memory(m) => {
                lock(m).insert(secret_ref.to_owned(), secret.clone());
                Ok(())
            }
        }
    }

    pub async fn load(&self, secret_ref: &str) -> Result<Option<SecretString>, SecretError> {
        match &self.backend {
            Backend::Keyring(k) => {
                let items = k
                    .search_items(&attrs(secret_ref))
                    .await
                    .map_err(SecretError::backend)?;
                let Some(item) = items.first() else {
                    return Ok(None);
                };
                if item.is_locked().await.map_err(SecretError::backend)? {
                    item.unlock().await.map_err(SecretError::backend)?;
                }
                let secret = item.secret().await.map_err(SecretError::backend)?;
                let text =
                    std::str::from_utf8(secret.as_bytes()).map_err(|_| SecretError::NotText)?;
                Ok(Some(SecretString::from(text.to_owned())))
            }
            Backend::Memory(m) => Ok(lock(m).get(secret_ref).cloned()),
        }
    }

    pub async fn delete(&self, secret_ref: &str) -> Result<(), SecretError> {
        match &self.backend {
            Backend::Keyring(k) => k
                .delete(&attrs(secret_ref))
                .await
                .map_err(SecretError::backend),
            Backend::Memory(m) => {
                lock(m).remove(secret_ref);
                Ok(())
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A poisoned map is still a valid map.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_roundtrip() {
        let s = Secrets::in_memory();
        assert!(s.load("a").await.expect("load").is_none());
        s.store("a", "label", &SecretString::from("pw".to_owned()))
            .await
            .expect("store");
        let got = s.load("a").await.expect("load").expect("some");
        assert_eq!(got.expose_secret(), "pw");
        s.delete("a").await.expect("delete");
        assert!(s.load("a").await.expect("load").is_none());
        assert_eq!(format!("{s:?}"), "Secrets { backend: \"memory\" }");
    }
}
