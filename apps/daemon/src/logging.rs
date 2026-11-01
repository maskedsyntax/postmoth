//! Logging setup shared by the binary and the redaction tests.
//!
//! Logs go to stderr (journald under systemd). Our own code never logs
//! codes, passwords or bodies. Dependencies are the risk: async-imap logs
//! raw protocol bytes, **including the LOGIN command and message bodies**,
//! at `log::trace`. Records from the `log` facade are therefore bridged
//! into tracing but hard-capped at INFO, whatever `POSTMOTH_LOG` says.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

/// Highest verbosity accepted from `log`-based dependencies.
pub const LOG_CRATE_MAX: log::LevelFilter = log::LevelFilter::Info;

pub fn init<W>(make_writer: W, filter: EnvFilter)
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    let _ = tracing_log::LogTracer::builder()
        .with_max_level(LOG_CRATE_MAX)
        .init();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(make_writer)
        .with_ansi(false)
        .with_target(false)
        .try_init();
}
