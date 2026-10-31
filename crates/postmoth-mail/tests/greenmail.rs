//! Real-network test against a GreenMail (or any) IMAPS server.
//!
//! Ignored by default. Run with `scripts/greenmail.sh test`, or set:
//!   POSTMOTH_TEST_IMAP_HOST, POSTMOTH_TEST_IMAP_PORT (IMAPS),
//!   POSTMOTH_TEST_IMAP_USER, POSTMOTH_TEST_IMAP_PASS,
//!   POSTMOTH_TEST_IMAP_CA (path to the server's PEM certificate)
//! and `cargo test -p postmoth-mail --test greenmail -- --ignored`.

use postmoth_core::model::{ServerEndpoint, TlsMode};
use postmoth_mail::{TlsSettings, connect_imap};
use secrecy::SecretString;

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"))
}

#[tokio::test]
#[ignore = "needs a running IMAPS server; see module docs"]
async fn imaps_login_select_fetch() {
    let endpoint = ServerEndpoint {
        host: env("POSTMOTH_TEST_IMAP_HOST"),
        port: env("POSTMOTH_TEST_IMAP_PORT").parse().expect("port"),
        tls: TlsMode::Implicit,
    };
    let tls = TlsSettings {
        extra_roots_pem: vec![std::fs::read(env("POSTMOTH_TEST_IMAP_CA")).expect("ca")],
    };
    let mut c = connect_imap(
        &endpoint,
        &tls,
        &env("POSTMOTH_TEST_IMAP_USER"),
        &SecretString::from(env("POSTMOTH_TEST_IMAP_PASS")),
    )
    .await
    .expect("connect");
    let st = c.select("INBOX").await.expect("select");
    assert!(st.uid_validity.is_some());
    let _ = c.fetch_new(0, 1 << 20).await.expect("fetch");
    c.logout().await.expect("logout");
}

#[tokio::test]
#[ignore = "needs a running IMAPS server; see module docs"]
async fn untrusted_certificate_is_rejected() {
    let endpoint = ServerEndpoint {
        host: env("POSTMOTH_TEST_IMAP_HOST"),
        port: env("POSTMOTH_TEST_IMAP_PORT").parse().expect("port"),
        tls: TlsMode::Implicit,
    };
    // System roots only: a self-signed test server must be refused.
    let err = connect_imap(
        &endpoint,
        &TlsSettings::default(),
        "u",
        &SecretString::from("p".to_owned()),
    )
    .await
    .expect_err("must reject");
    assert!(matches!(err, postmoth_mail::MailError::Tls(_)), "{err:?}");
}
