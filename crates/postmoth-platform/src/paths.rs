//! XDG paths. Every directory Postmoth creates is `0700` and must be owned
//! by the current user; we refuse to use one that is not.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const APP_DIR: &str = "postmoth";

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("neither {0} nor HOME is set to an absolute path")]
    NoBase(&'static str),
    #[error("XDG_RUNTIME_DIR is not set; refusing to fall back to a shared directory")]
    NoRuntimeDir,
    #[error("{path}: {reason}")]
    Unsafe { path: PathBuf, reason: &'static str },
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// `$XDG_DATA_HOME/postmoth`: database and cached mail.
    pub data_dir: PathBuf,
    /// `$XDG_CONFIG_HOME/postmoth`: user configuration.
    pub config_dir: PathBuf,
    /// `$XDG_RUNTIME_DIR/postmoth`: sockets. tmpfs, per user, wiped at logout.
    pub runtime_dir: PathBuf,
}

/// Only absolute values count, per the XDG Base Directory spec.
fn abs_env(get: &impl Fn(&str) -> Option<String>, key: &str) -> Option<PathBuf> {
    get(key).map(PathBuf::from).filter(|p| p.is_absolute())
}

impl Paths {
    pub fn from_env() -> Result<Self, PathError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Resolve with an injectable environment (for tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, PathError> {
        let home = abs_env(&get, "HOME");
        let base = |key: &'static str, fallback: &str| -> Result<PathBuf, PathError> {
            abs_env(&get, key)
                .or_else(|| home.as_ref().map(|h| h.join(fallback)))
                .ok_or(PathError::NoBase(key))
        };
        Ok(Self {
            data_dir: base("XDG_DATA_HOME", ".local/share")?.join(APP_DIR),
            config_dir: base("XDG_CONFIG_HOME", ".config")?.join(APP_DIR),
            runtime_dir: abs_env(&get, "XDG_RUNTIME_DIR")
                .ok_or(PathError::NoRuntimeDir)?
                .join(APP_DIR),
        })
    }

    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("postmoth.sqlite3")
    }

    /// The browser-only capability socket (spec §6.2).
    #[must_use]
    pub fn browser_socket(&self) -> PathBuf {
        self.runtime_dir.join("browser.sock")
    }

    /// Optional user-maintained catalog of extra sender → origin rules.
    #[must_use]
    pub fn user_rules(&self) -> PathBuf {
        self.config_dir.join("otp-domains.toml")
    }
}

/// Create `dir` (and parents) if needed, then verify it is a real directory
/// (not a symlink) owned by us, and force its mode to `0700`.
pub fn ensure_private_dir(dir: &Path) -> Result<(), PathError> {
    let io_err = |source| PathError::Io {
        path: dir.to_owned(),
        source,
    };
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io_err)?;
    let meta = fs::symlink_metadata(dir).map_err(io_err)?;
    if !meta.file_type().is_dir() {
        return Err(PathError::Unsafe {
            path: dir.to_owned(),
            reason: "not a directory (or a symlink)",
        });
    }
    if meta.uid() != rustix::process::getuid().as_raw() {
        return Err(PathError::Unsafe {
            path: dir.to_owned(),
            reason: "owned by another user",
        });
    }
    if meta.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(io_err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| m.get(k).cloned()
    }

    #[test]
    fn xdg_values_win_and_relative_ones_are_ignored() {
        let p = Paths::from_lookup(env(&[
            ("HOME", "/home/u"),
            ("XDG_DATA_HOME", "/d"),
            ("XDG_CONFIG_HOME", "relative/cfg"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ]))
        .expect("paths");
        assert_eq!(p.data_dir, PathBuf::from("/d/postmoth"));
        assert_eq!(p.config_dir, PathBuf::from("/home/u/.config/postmoth"));
        assert_eq!(
            p.browser_socket(),
            PathBuf::from("/run/user/1000/postmoth/browser.sock")
        );
    }

    #[test]
    fn missing_runtime_dir_is_an_error() {
        let r = Paths::from_lookup(env(&[("HOME", "/home/u")]));
        assert!(matches!(r, Err(PathError::NoRuntimeDir)));
    }

    #[test]
    fn private_dir_is_created_and_tightened() {
        let t = tempfile::tempdir().expect("tmp");
        let d = t.path().join("a/b");
        ensure_private_dir(&d).expect("create");
        assert_eq!(fs::metadata(&d).expect("meta").mode() & 0o777, 0o700);
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).expect("chmod");
        ensure_private_dir(&d).expect("again");
        assert_eq!(fs::metadata(&d).expect("meta").mode() & 0o777, 0o700);
    }

    #[test]
    fn symlinked_dir_is_refused() {
        let t = tempfile::tempdir().expect("tmp");
        let real = t.path().join("real");
        fs::create_dir(&real).expect("mkdir");
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(matches!(
            ensure_private_dir(&link),
            Err(PathError::Unsafe { .. })
        ));
    }
}
