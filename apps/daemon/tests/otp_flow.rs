//! End to end inside one process: fake IMAP server → sync worker → parser →
//! store → OTP engine → browser socket (real Unix socket, real framing).

use postmoth_core::model::{ServerEndpoint, TlsMode};
use postmoth_core::{AccountId, ErrorCode};
use postmoth_daemon::browser;
use postmoth_daemon::daemon::Daemon;
use postmoth_daemon::db::Db;
use postmoth_daemon::otp::OtpService;
use postmoth_daemon::worker::Connector;
use postmoth_ipc::browser::{Response, ResponseBody};
use postmoth_ipc::control::{NewAccount, SyncState};
use postmoth_ipc::framing_async::{read_json, write_frame};
use postmoth_mail::testing::{self, PASSWORD, Shared};
use postmoth_mail::{ImapConnection, MailError};
use postmoth_otp::{OriginPolicy, SystemClock};
use postmoth_platform::Secrets;
use postmoth_store::Store;
use secrecy::{ExposeSecret, SecretString};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::DuplexStream;
use tokio::net::UnixStream;

/// Every log line from every test in this binary, at TRACE, including
/// dependencies (async-imap, rustls, ...). Codes must never appear.
static LOGS: std::sync::OnceLock<Arc<std::sync::Mutex<Vec<u8>>>> = std::sync::OnceLock::new();

#[derive(Clone)]
struct LogSink(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogSink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_logs() {
    LOGS.get_or_init(|| {
        let buf = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = LogSink(Arc::clone(&buf));
        // The production setup, asked for maximum verbosity.
        postmoth_daemon::logging::init(
            move || sink.clone(),
            tracing_subscriber::EnvFilter::new("trace"),
        );
        buf
    });
}

fn assert_not_logged(needle: &str) {
    let logs = LOGS.get().expect("logs").lock().expect("lock");
    let text = String::from_utf8_lossy(&logs);
    assert!(!text.is_empty(), "log capture is not working");
    assert!(!text.contains(needle), "secret {needle:?} appeared in logs");
}

struct FakeConnector(Shared);

impl Connector for FakeConnector {
    type Stream = DuplexStream;
    async fn connect(
        &self,
        _account: &postmoth_core::model::Account,
        password: &SecretString,
    ) -> Result<ImapConnection<DuplexStream>, MailError> {
        testing::connect(&self.0, password.expose_secret()).await
    }
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("fits")
}

fn otp_mail(from: &str, code: &str) -> Vec<u8> {
    format!(
        "From: Example Security <{from}>\r\nTo: me@example.org\r\nSubject: Your sign-in code\r\n\
         Message-ID: <{code}@example.com>\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\
         Hi,\r\n\r\nYour verification code is {code}. It expires in 10 minutes.\r\n\r\n\
         If you did not request this, ignore this email.\r\n"
    )
    .into_bytes()
}

fn new_account() -> NewAccount {
    let ep = |port| ServerEndpoint {
        host: "imap.example.org".into(),
        port,
        tls: TlsMode::Implicit,
    };
    NewAccount {
        address: "me@example.org".into(),
        display_name: None,
        login: "me".into(),
        provider: postmoth_core::model::ProviderType::GenericImap,
        imap: ep(993),
        smtp: ep(465),
        otp_enabled: true,
        trusted_authserv_ids: vec![],
    }
}

struct Harness {
    daemon: Arc<Daemon<FakeConnector>>,
    mb: Shared,
    secrets: Arc<Secrets>,
    socket: std::path::PathBuf,
    _dir: tempfile::TempDir,
    _server: tokio::task::JoinHandle<()>,
}

async fn harness() -> Harness {
    init_logs();
    let mb = testing::mailbox(2);
    mb.lock().expect("lock").internal_date = now_unix();
    let (db, _t) = Db::spawn(Store::open_in_memory().expect("store")).expect("db");
    let secrets = Arc::new(Secrets::in_memory());
    let otp = Arc::new(OtpService::new(
        Vec::new(),
        OriginPolicy::default(),
        Box::new(SystemClock),
    ));
    let dir = tempfile::tempdir().expect("tmp");
    let socket = dir.path().join("rt/postmoth/browser.sock");
    let daemon = Daemon::start(
        db,
        Arc::clone(&secrets),
        Arc::clone(&otp),
        FakeConnector(Arc::clone(&mb)),
        None,
        socket.clone(),
    )
    .await
    .expect("start");
    let listener = browser::bind(&socket).expect("bind");
    let server = tokio::spawn(browser::serve(listener, otp));
    Harness {
        daemon,
        mb,
        secrets,
        socket,
        _dir: dir,
        _server: server,
    }
}

async fn wait_state(d: &Daemon<FakeConnector>, id: AccountId, want: SyncState) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let st = d.account_state(id).await;
        if st == Some(want) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {want:?}, at {st:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct Client(UnixStream);

impl Client {
    async fn connect(path: &std::path::Path) -> Self {
        Self(UnixStream::connect(path).await.expect("connect"))
    }

    async fn call(&mut self, req: serde_json::Value) -> Response {
        write_frame(&mut self.0, &serde_json::to_vec(&req).expect("ser"))
            .await
            .expect("write");
        read_json(&mut self.0).await.expect("read").expect("reply")
    }

    async fn find(&mut self, origin: &str, tab: i64) -> ResponseBody {
        self.call(serde_json::json!({
            "v": 1, "request_id": "f1", "op": "find_suggestion",
            "top_origin": origin, "tab_id": tab
        }))
        .await
        .body
    }

    async fn consume(&mut self, id: &str, origin: &str, tab: i64) -> ResponseBody {
        self.call(serde_json::json!({
            "v": 1, "request_id": "c1", "op": "consume_suggestion",
            "suggestion_id": id, "top_origin": origin, "tab_id": tab
        }))
        .await
        .body
    }
}

/// Wait until the daemon has a live candidate (the worker is async).
async fn wait_candidate(d: &Daemon<FakeConnector>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while d.otp().live_candidates() == 0 {
        assert!(tokio::time::Instant::now() < deadline, "no candidate");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otp_reaches_only_the_trusted_origin_once() {
    let h = harness().await;
    h.daemon
        .trust_sender("@example.com", "https://login.example.com", false)
        .await
        .expect("trust");
    let id = h
        .daemon
        .add_account(new_account(), SecretString::from(PASSWORD.to_owned()))
        .await
        .expect("add");
    wait_state(&h.daemon, id, SyncState::Idle).await;
    assert_eq!(h.daemon.otp().live_candidates(), 0, "old mail has no codes");

    // New mail arrives while IDLE.
    testing::deliver(&h.mb, otp_mail("security@example.com", "482913"));
    wait_candidate(&h.daemon).await;

    let mut c = Client::connect(&h.socket).await;
    let status = c
        .call(serde_json::json!({"v": 1, "request_id": "s", "op": "status"}))
        .await;
    assert!(matches!(
        status.body,
        ResponseBody::Ok { paused: false, .. }
    ));

    // Lookalike, sibling and plain-http origins get nothing.
    for o in [
        "https://login.example.com.evil.net",
        "https://evil.example.com",
        "https://example.com",
        "http://login.example.com",
    ] {
        assert_eq!(c.find(o, 7).await, ResponseBody::None, "{o}");
    }

    let ResponseBody::Available {
        suggestion_id,
        label,
    } = c.find("https://login.example.com", 7).await
    else {
        panic!("expected a suggestion");
    };
    assert_eq!(label, browser::SUGGESTION_LABEL);
    let sid = suggestion_id.to_string();

    // Wrong tab or wrong origin cannot redeem (and burns the handle).
    let wrong = c.consume(&sid, "https://login.example.com", 8).await;
    assert!(matches!(
        wrong,
        ResponseBody::Error {
            code: ErrorCode::NoMatch,
            ..
        }
    ));
    let again = c.consume(&sid, "https://login.example.com", 7).await;
    assert!(
        matches!(again, ResponseBody::Error { .. }),
        "handle is single-use"
    );

    // A fresh handle redeems exactly once.
    let ResponseBody::Available { suggestion_id, .. } =
        c.find("https://login.example.com", 7).await
    else {
        panic!("candidate survives a failed redeem");
    };
    let sid = suggestion_id.to_string();
    match c.consume(&sid, "https://login.example.com", 7).await {
        ResponseBody::Code { code } => assert_eq!(code.expose(), "482913"),
        other => panic!("expected code, got {other:?}"),
    }
    assert!(matches!(
        c.consume(&sid, "https://login.example.com", 7).await,
        ResponseBody::Error { .. }
    ));
    assert_eq!(
        c.find("https://login.example.com", 7).await,
        ResponseBody::None
    );

    // The message itself is cached.
    let status = h.daemon.status().await;
    assert_eq!(status.accounts.len(), 1);
    assert!(status.accounts[0].last_sync_at.is_some());
    h.daemon.shutdown().await;
    assert_not_logged("482913");
    assert_not_logged(PASSWORD);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_sender_yields_nothing_and_pause_blocks() {
    let h = harness().await;
    h.daemon
        .trust_sender("@example.com", "login.example.com", false)
        .await
        .expect("trust");
    let id = h
        .daemon
        .add_account(new_account(), SecretString::from(PASSWORD.to_owned()))
        .await
        .expect("add");
    wait_state(&h.daemon, id, SyncState::Idle).await;

    // Spoof-ish sender on another domain: not mapped.
    testing::deliver(&h.mb, otp_mail("security@examp1e.com", "111222"));
    // Then a trusted one, so we know the first was processed.
    testing::deliver(&h.mb, otp_mail("security@example.com", "333444"));
    wait_candidate(&h.daemon).await;
    assert_eq!(h.daemon.otp().live_candidates(), 1);

    h.daemon.set_paused(true).await.expect("pause");
    wait_state(&h.daemon, id, SyncState::Paused).await;
    assert_eq!(h.daemon.otp().live_candidates(), 0, "pause wipes codes");
    let mut c = Client::connect(&h.socket).await;
    assert!(matches!(
        c.find("https://login.example.com", 1).await,
        ResponseBody::Error {
            code: ErrorCode::Paused,
            ..
        }
    ));

    h.daemon.set_paused(false).await.expect("resume");
    wait_state(&h.daemon, id, SyncState::Idle).await;
    h.daemon.shutdown().await;
    assert_not_logged("111222");
    assert_not_logged("333444");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_then_removal_cleans_up() {
    let h = harness().await;
    let id = h
        .daemon
        .add_account(new_account(), SecretString::from("nope".to_owned()))
        .await
        .expect("add");
    wait_state(&h.daemon, id, SyncState::AuthFailed).await;
    let st = h.daemon.status().await;
    assert!(st.accounts[0].last_error.is_some());

    let secret_ref = format!("account/{id}");
    assert!(h.secrets.load(&secret_ref).await.expect("load").is_some());
    h.daemon.remove_account(id).await.expect("remove");
    assert!(h.secrets.load(&secret_ref).await.expect("load").is_none());
    assert!(h.daemon.status().await.accounts.is_empty());
    assert!(h.daemon.remove_account(id).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_socket_input_is_rejected() {
    let h = harness().await;
    let mut c = Client::connect(&h.socket).await;
    let r = c
        .call(serde_json::json!({"v": 1, "request_id": "x", "op": "list_codes"}))
        .await;
    assert!(matches!(
        r.body,
        ResponseBody::Error {
            code: ErrorCode::BadRequest,
            ..
        }
    ));
    let r = c
        .call(serde_json::json!({"v": 2, "request_id": "x", "op": "status"}))
        .await;
    assert!(matches!(
        r.body,
        ResponseBody::Error {
            code: ErrorCode::VersionUnsupported,
            ..
        }
    ));
    let r = c
        .call(serde_json::json!({"v": 1, "request_id": "bad id!", "op": "status"}))
        .await;
    assert_eq!(r.request_id, "", "invalid ids are not echoed");

    // Oversize frame: one error reply, then the daemon hangs up.
    use tokio::io::AsyncWriteExt;
    c.0.write_all(&(1u32 << 20).to_ne_bytes())
        .await
        .expect("write");
    let r: Response = read_json(&mut c.0).await.expect("read").expect("reply");
    assert!(matches!(
        r.body,
        ResponseBody::Error {
            code: ErrorCode::BadRequest,
            ..
        }
    ));
    assert!(
        read_json::<_, Response>(&mut c.0)
            .await
            .expect("eof")
            .is_none()
    );

    // Socket and its directory are owner-only.
    use std::os::unix::fs::PermissionsExt;
    let mode =
        |p: &std::path::Path| std::fs::metadata(p).expect("meta").permissions().mode() & 0o777;
    assert_eq!(mode(&h.socket), 0o600);
    assert_eq!(mode(h.socket.parent().expect("dir")), 0o700);
}
