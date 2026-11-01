//! Protocol tests against the scripted in-process IMAP server in
//! `postmoth_mail::testing`.

use postmoth_mail::sync::StoredCursor;
use postmoth_mail::testing::{PASSWORD, connect, mailbox};
use postmoth_mail::{IdleOutcome, SyncPlan, plan_folder_sync};
use std::time::Duration;

#[tokio::test]
async fn wrong_password_is_auth_error() {
    let mb = mailbox(0);
    let err = connect(&mb, "wrong").await.expect_err("must fail");
    assert!(err.is_auth(), "{err:?}");
}

#[tokio::test]
async fn select_and_incremental_fetch() {
    let mb = mailbox(3);
    let mut c = connect(&mb, PASSWORD).await.expect("login");
    assert!(c.caps().idle);
    let st = c.select("INBOX").await.expect("select");
    assert_eq!(st.uid_validity, Some(7));
    assert_eq!(st.exists, 3);

    let plan = plan_folder_sync(StoredCursor::default(), &st).expect("plan");
    assert_eq!(plan, SyncPlan::Reset { new_uidvalidity: 7 });

    let all = c.fetch_new(0, 1 << 20).await.expect("fetch");
    assert_eq!(
        all.iter().map(|m| m.uid).collect::<Vec<_>>(),
        vec![10, 20, 30]
    );
    assert!(all.iter().all(|m| !m.flags.seen && !m.headers_only));
    assert!(all[0].raw.starts_with(b"From: a@example.com"));
    assert_eq!(all[0].internal_date, Some(1_793_527_200));

    // Nothing new: server still returns UID 30 for `31:*`; we filter it.
    let none = c.fetch_new(30, 1 << 20).await.expect("fetch");
    assert!(none.is_empty());

    let stored = StoredCursor {
        uidvalidity: Some(7),
        highest_uid: 30,
    };
    assert_eq!(plan_folder_sync(stored, &st), Ok(SyncPlan::UpToDate));

    // UIDVALIDITY changes on the server.
    mb.lock().expect("lock").uidvalidity = 8;
    let st2 = c.select("INBOX").await.expect("select");
    assert_eq!(
        plan_folder_sync(stored, &st2),
        Ok(SyncPlan::Reset { new_uidvalidity: 8 })
    );
    c.logout().await.expect("logout");
}

#[tokio::test]
async fn oversized_messages_are_headers_only() {
    let mb = mailbox(1);
    mb.lock().expect("lock").messages.push((99, {
        let mut m = b"From: big@example.com\r\nSubject: big\r\n\r\n".to_vec();
        m.extend(vec![b'x'; 5000]);
        m
    }));
    let mut c = connect(&mb, PASSWORD).await.expect("login");
    c.select("INBOX").await.expect("select");
    let got = c.fetch_new(0, 1000).await.expect("fetch");
    let big = got.iter().find(|m| m.uid == 99).expect("big");
    assert!(big.headers_only);
    assert!(big.raw.ends_with(b"\r\n\r\n"));
    assert!(big.raw.len() < 100);
    let small = got.iter().find(|m| m.uid == 10).expect("small");
    assert!(!small.headers_only);
}

#[tokio::test]
async fn idle_reports_push_and_timeout() {
    let mb = mailbox(1);
    let mut c = connect(&mb, PASSWORD).await.expect("login");
    c.select("INBOX").await.expect("select");

    let (c2, outcome) = c.idle(Duration::from_millis(300)).await.expect("idle");
    assert_eq!(outcome, IdleOutcome::Timeout);
    c = c2;

    mb.lock().expect("lock").push_on_idle = true;
    let (mut c3, outcome) = c.idle(Duration::from_secs(5)).await.expect("idle");
    assert_eq!(outcome, IdleOutcome::Changed);
    let new = c3.fetch_new(10, 1 << 20).await.expect("fetch");
    assert_eq!(new.len(), 1);
    assert!(new[0].raw.windows(6).any(|w| w == b"pushed"));
}

#[tokio::test]
async fn mailbox_names_with_crlf_rejected() {
    let mb = mailbox(0);
    let mut c = connect(&mb, PASSWORD).await.expect("login");
    assert!(c.select("INBOX\r\nA9 DELETE INBOX").await.is_err());
}

#[tokio::test]
async fn debug_never_shows_content() {
    let mb = mailbox(1);
    let mut c = connect(&mb, PASSWORD).await.expect("login");
    c.select("INBOX").await.expect("select");
    let got = c.fetch_new(0, 1 << 20).await.expect("fetch");
    assert!(!format!("{got:?}").contains("Hello"));
}

#[tokio::test]
async fn idle_can_be_interrupted_cleanly() {
    let mb = mailbox(1);
    let mut c = connect(&mb, PASSWORD).await.expect("login");
    c.select("INBOX").await.expect("select");
    let (mut c, outcome) = c
        .idle_until(
            Duration::from_secs(30),
            tokio::time::sleep(Duration::from_millis(50)),
        )
        .await
        .expect("idle");
    assert_eq!(outcome, IdleOutcome::Interrupted);
    // The session is still usable after DONE.
    c.noop().await.expect("noop");
}
