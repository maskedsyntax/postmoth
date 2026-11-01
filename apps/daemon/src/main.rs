//! `postmoth-daemon`: runs as a systemd user service.

use clap::Parser;
use postmoth_daemon::browser;
use postmoth_daemon::daemon::Daemon;
use postmoth_daemon::db::Db;
use postmoth_daemon::dbus::ControlIface;
use postmoth_daemon::otp::OtpService;
use postmoth_daemon::worker::TlsConnector;
use postmoth_ipc::control::{BUS_NAME, OBJECT_PATH};
use postmoth_mail::TlsSettings;
use postmoth_otp::{OriginPolicy, SystemClock};
use postmoth_platform::{Paths, Secrets};
use postmoth_store::Store;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Debug, Parser)]
#[command(version, about = "Postmoth background mail and OTP daemon")]
struct Args {
    /// DEVELOPMENT ONLY: accept http(s)://localhost origins for OTP
    /// suggestions (local test sites).
    #[arg(long)]
    dev_allow_localhost: bool,
    /// Extra PEM trust anchor for IMAP/SMTP servers (self-hosted or test
    /// servers). May be repeated. There is no "skip verification" option.
    #[arg(long = "extra-ca", value_name = "PEM")]
    extra_ca: Vec<PathBuf>,
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("POSTMOTH_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    postmoth_daemon::logging::init(std::io::stderr, filter);
}

/// Codes and passwords live in this process's memory: keep it out of core
/// dumps and away from same-user ptrace.
fn harden_process() {
    if let Err(e) =
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
    {
        tracing::warn!(error = %e, "could not disable core dumps");
    }
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
}

#[tokio::main]
async fn main() -> ExitCode {
    init_logging();
    harden_process();
    let args = Args::parse();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    let paths = Paths::from_env().map_err(|e| e.to_string())?;
    postmoth_platform::ensure_private_dir(&paths.data_dir).map_err(|e| e.to_string())?;

    let mut extra_roots_pem = Vec::new();
    for p in &args.extra_ca {
        extra_roots_pem.push(std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?);
    }
    let tls = TlsSettings { extra_roots_pem };
    // Fail fast on a bad CA file rather than on first connect.
    tls.client_config().map_err(|e| e.to_string())?;

    let policy = OriginPolicy {
        allow_localhost_dev: args.dev_allow_localhost,
    };
    if policy.allow_localhost_dev {
        tracing::warn!("DEVELOPMENT MODE: localhost origins accepted for OTP suggestions");
    }

    let store = Store::open(&paths.db_path()).map_err(|e| format!("database: {e}"))?;
    let (db, db_thread) = Db::spawn(store).map_err(|e| e.to_string())?;
    let secrets = Arc::new(
        Secrets::keyring()
            .await
            .map_err(|e| format!("keyring: {e}"))?,
    );
    let user_catalog = match std::fs::read_to_string(paths.user_rules()) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", paths.user_rules().display())),
    };
    let otp = Arc::new(OtpService::new(Vec::new(), policy, Box::new(SystemClock)));
    let daemon = Daemon::start(
        db,
        secrets,
        Arc::clone(&otp),
        TlsConnector { tls },
        user_catalog,
        paths.browser_socket(),
    )
    .await
    .map_err(|e| e.to_string())?;

    // Claim the bus name first: if another daemon owns it, we must not
    // touch its socket.
    let bus = zbus::connection::Builder::session()
        .and_then(|b| b.name(BUS_NAME))
        .and_then(|b| {
            b.serve_at(
                OBJECT_PATH,
                ControlIface {
                    daemon: Arc::clone(&daemon),
                },
            )
        })
        .map_err(|e| format!("D-Bus: {e}"))?
        .build()
        .await
        .map_err(|e| format!("D-Bus (is another daemon running?): {e}"))?;

    let listener = browser::bind(&paths.browser_socket())
        .map_err(|e| format!("{}: {e}", paths.browser_socket().display()))?;
    let browser_task = tokio::spawn(browser::serve(listener, Arc::clone(&otp)));
    let purge_task = tokio::spawn({
        let otp = Arc::clone(&otp);
        async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                otp.purge_expired();
            }
        }
    });
    tracing::info!(
        version = postmoth_daemon::DAEMON_VERSION,
        "postmoth-daemon ready"
    );

    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    tracing::info!("shutting down");
    browser_task.abort();
    purge_task.abort();
    let _ = std::fs::remove_file(paths.browser_socket());
    daemon.shutdown().await;
    // The bus connection holds a daemon reference; drop it first so the
    // database actor sees its last handle go away and exits.
    drop(bus);
    drop(daemon);
    let _ = tokio::task::spawn_blocking(move || db_thread.join()).await;
    Ok(())
}
