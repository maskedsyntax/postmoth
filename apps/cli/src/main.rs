//! `postmothctl`: control and diagnostics for the Postmoth daemon.
//!
//! Talks to `dev.postmoth.Daemon1` on the session bus. There is no command
//! that prints a one-time code or a password; the daemon offers none.
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand, ValueEnum};
use postmoth_core::model::{ProviderType, ServerEndpoint, TlsMode};
use postmoth_ipc::control::{MappingInfo, NewAccount, StatusReport, SyncState};
use std::io::BufRead;
use std::process::ExitCode;

#[zbus::proxy(
    interface = "dev.postmoth.Daemon1",
    default_service = "dev.postmoth.Daemon1",
    default_path = "/dev/postmoth/Daemon1"
)]
trait Daemon1 {
    fn status(&self) -> zbus::Result<String>;
    fn add_account(&self, config_json: &str, password: &str) -> zbus::Result<String>;
    fn remove_account(&self, id: &str) -> zbus::Result<()>;
    fn sync_now(&self, id: &str) -> zbus::Result<()>;
    fn set_paused(&self, paused: bool) -> zbus::Result<()>;
    fn trust_sender(&self, sender: &str, site: &str, include_subdomains: bool)
    -> zbus::Result<i64>;
    fn list_mappings(&self) -> zbus::Result<String>;
    fn remove_mapping(&self, id: i64) -> zbus::Result<()>;
}

#[derive(Debug, Parser)]
#[command(version, about = "Control the Postmoth mail daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Tls {
    Implicit,
    Starttls,
}

impl From<Tls> for TlsMode {
    fn from(t: Tls) -> Self {
        match t {
            Tls::Implicit => Self::Implicit,
            Tls::Starttls => Self::StartTls,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Daemon and account health.
    Status {
        /// Print the raw JSON report.
        #[arg(long)]
        json: bool,
    },
    /// Add an IMAP account. The password is read from the terminal (or
    /// stdin with --password-stdin) and stored in the keyring by the daemon.
    AddAccount {
        #[arg(long)]
        address: String,
        /// Defaults to the address.
        #[arg(long)]
        login: Option<String>,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        imap_host: String,
        #[arg(long, default_value_t = 993)]
        imap_port: u16,
        #[arg(long, value_enum, default_value_t = Tls::Implicit)]
        imap_tls: Tls,
        /// Defaults to the IMAP host.
        #[arg(long)]
        smtp_host: Option<String>,
        #[arg(long, default_value_t = 465)]
        smtp_port: u16,
        #[arg(long, value_enum, default_value_t = Tls::Implicit)]
        smtp_tls: Tls,
        /// `authserv-id` of your provider's Authentication-Results headers
        /// (e.g. mx.google.com). Repeatable. Without it, sender
        /// authentication results are ignored.
        #[arg(long = "authserv-id")]
        authserv_ids: Vec<String>,
        /// Do not look for one-time codes in this account.
        #[arg(long)]
        no_otp: bool,
        /// Read the password from the first line of stdin.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove an account, its cached mail and its keyring entry.
    RemoveAccount { id: String },
    /// Sync now (all accounts if no id is given).
    SyncNow { id: Option<String> },
    /// Pause background mail and OTP suggestions.
    Pause,
    /// Resume background mail.
    Resume,
    /// Trust codes from SENDER (`user@domain` or `@domain`) on SITE
    /// (`https://login.example.com` or a host).
    Trust {
        sender: String,
        site: String,
        /// Also offer on subdomains of SITE (same registrable domain only).
        #[arg(long)]
        include_subdomains: bool,
    },
    /// List trusted sender → site mappings.
    Mappings,
    /// Remove a mapping by id.
    Untrust { id: i64 },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("postmothctl: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(cli.cmd)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("postmothctl: {e}");
            ExitCode::FAILURE
        }
    }
}

fn friendly(e: zbus::Error) -> String {
    match &e {
        zbus::Error::MethodError(name, msg, _) => {
            let n = name.as_str();
            if n.ends_with("ServiceUnknown") || n.ends_with("NameHasNoOwner") {
                "the daemon is not running (systemctl --user start postmoth-daemon)".into()
            } else {
                msg.clone().unwrap_or_else(|| n.to_owned())
            }
        }
        _ => e.to_string(),
    }
}

fn read_password(from_stdin: bool) -> Result<String, String> {
    let pw = if from_stdin {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        line.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        rpassword::prompt_password("Password: ").map_err(|e| e.to_string())?
    };
    if pw.is_empty() {
        return Err("empty password".into());
    }
    Ok(pw)
}

async fn run(cmd: Cmd) -> Result<(), String> {
    let conn = zbus::Connection::session()
        .await
        .map_err(|e| format!("session bus: {e}"))?;
    let p = Daemon1Proxy::new(&conn).await.map_err(friendly)?;
    match cmd {
        Cmd::Status { json } => {
            let raw = p.status().await.map_err(friendly)?;
            if json {
                println!("{raw}");
            } else {
                let st: StatusReport = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
                print_status(&st);
            }
        }
        Cmd::AddAccount {
            address,
            login,
            display_name,
            imap_host,
            imap_port,
            imap_tls,
            smtp_host,
            smtp_port,
            smtp_tls,
            authserv_ids,
            no_otp,
            password_stdin,
        } => {
            let new = NewAccount {
                login: login.unwrap_or_else(|| address.clone()),
                address,
                display_name,
                provider: ProviderType::GenericImap,
                smtp: ServerEndpoint {
                    host: smtp_host.unwrap_or_else(|| imap_host.clone()),
                    port: smtp_port,
                    tls: smtp_tls.into(),
                },
                imap: ServerEndpoint {
                    host: imap_host,
                    port: imap_port,
                    tls: imap_tls.into(),
                },
                otp_enabled: !no_otp,
                trusted_authserv_ids: authserv_ids,
            };
            let json = serde_json::to_string(&new).map_err(|e| e.to_string())?;
            let pw = read_password(password_stdin)?;
            let id = p.add_account(&json, &pw).await.map_err(friendly)?;
            drop(pw);
            println!("added account {id}");
        }
        Cmd::RemoveAccount { id } => {
            p.remove_account(&id).await.map_err(friendly)?;
            println!("removed {id}");
        }
        Cmd::SyncNow { id } => p
            .sync_now(id.as_deref().unwrap_or(""))
            .await
            .map_err(friendly)?,
        Cmd::Pause => {
            p.set_paused(true).await.map_err(friendly)?;
            println!("background mail paused; live codes discarded");
        }
        Cmd::Resume => {
            p.set_paused(false).await.map_err(friendly)?;
            println!("background mail resumed");
        }
        Cmd::Trust {
            sender,
            site,
            include_subdomains,
        } => {
            let id = p
                .trust_sender(&sender, &site, include_subdomains)
                .await
                .map_err(friendly)?;
            println!("mapping {id}: codes from {sender} may be offered on {site}");
        }
        Cmd::Mappings => {
            let raw = p.list_mappings().await.map_err(friendly)?;
            let rows: Vec<MappingInfo> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            if rows.is_empty() {
                println!("no mappings");
            }
            for m in rows {
                println!(
                    "{:>4}  {}  →  {}{}{}",
                    m.id,
                    m.sender_pattern,
                    m.trusted_origin,
                    if m.include_subdomains {
                        " (+subdomains)"
                    } else {
                        ""
                    },
                    if m.user_confirmed { "" } else { " [catalog]" },
                );
            }
        }
        Cmd::Untrust { id } => {
            p.remove_mapping(id).await.map_err(friendly)?;
            println!("removed mapping {id}");
        }
    }
    Ok(())
}

fn state_label(s: SyncState) -> String {
    match s {
        SyncState::Starting => "starting".into(),
        SyncState::Connecting => "connecting".into(),
        SyncState::Syncing => "syncing".into(),
        SyncState::Idle => "up to date (push)".into(),
        SyncState::Polling => "up to date (polling)".into(),
        SyncState::Backoff { retry_in_secs } => format!("offline, retry in {retry_in_secs}s"),
        SyncState::AuthFailed => "login rejected".into(),
        SyncState::MissingSecret => "password missing from keyring".into(),
        SyncState::Paused => "paused".into(),
        SyncState::Stopped => "stopped".into(),
    }
}

fn print_status(st: &StatusReport) {
    println!(
        "postmoth-daemon {} (protocol {})",
        st.daemon_version, st.protocol
    );
    println!(
        "background mail: {}",
        if st.paused { "PAUSED" } else { "running" }
    );
    println!("browser socket:  {}", st.browser_socket);
    println!("live OTP suggestions: {}", st.otp_live_candidates);
    if st.accounts.is_empty() {
        println!("no accounts (postmothctl add-account --help)");
    }
    for a in &st.accounts {
        println!();
        println!("{}  {}", a.id, a.address);
        println!("  state: {}", state_label(a.state));
        if let Some(t) = a.last_sync_at {
            println!("  last sync: {t} (unix)");
        }
        if let Some(e) = &a.last_error {
            println!("  last error: {e}");
        }
        println!("  otp: {}", if a.otp_enabled { "on" } else { "off" });
    }
}
