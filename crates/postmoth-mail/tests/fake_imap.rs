//! Protocol tests against a scripted in-process IMAP server.
//!
//! The fake implements just enough of RFC 3501 + IDLE for the client:
//! greeting, LOGIN, CAPABILITY, SELECT, UID FETCH (meta / BODY[] /
//! BODY[HEADER]), IDLE/DONE, NOOP, LOGOUT. It reproduces the `N:*` quirk
//! (always returns the highest message) so filtering is exercised.

use postmoth_mail::sync::StoredCursor;
use postmoth_mail::{IdleOutcome, ImapConnection, MailError, SyncPlan, plan_folder_sync};
use secrecy::SecretString;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

#[derive(Debug, Default)]
struct Mailbox {
    uidvalidity: u32,
    /// (uid, raw message)
    messages: Vec<(u32, Vec<u8>)>,
    /// Push this many new-mail notifications while IDLE.
    push_on_idle: bool,
}

type Shared = Arc<Mutex<Mailbox>>;

const PASSWORD: &str = "correct horse";

fn msg(subject: &str) -> Vec<u8> {
    format!("From: a@example.com\r\nSubject: {subject}\r\n\r\nHello {subject}\r\n").into_bytes()
}

async fn serve(stream: DuplexStream, mb: Shared) {
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();
    w.write_all(b"* OK [CAPABILITY IMAP4rev1 IDLE] fake ready\r\n")
        .await
        .expect("greet");
    while let Ok(Some(line)) = lines.next_line().await {
        let (tag, rest) = line.split_once(' ').unwrap_or((&line, ""));
        let upper = rest.to_ascii_uppercase();
        let mut out = String::new();
        if upper.starts_with("LOGIN") {
            if rest.contains(&format!("\"{PASSWORD}\"")) {
                out.push_str(&format!("{tag} OK LOGIN completed\r\n"));
            } else {
                out.push_str(&format!("{tag} NO [AUTHENTICATIONFAILED] invalid\r\n"));
            }
        } else if upper.starts_with("CAPABILITY") {
            out.push_str("* CAPABILITY IMAP4rev1 IDLE UIDPLUS\r\n");
            out.push_str(&format!("{tag} OK done\r\n"));
        } else if upper.starts_with("SELECT") {
            let m = mb.lock().expect("lock");
            let next = m.messages.iter().map(|(u, _)| u + 1).max().unwrap_or(1);
            out.push_str(&format!(
                "* {} EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n* OK [UIDVALIDITY {}] ok\r\n* OK [UIDNEXT {next}] ok\r\n{tag} OK [READ-WRITE] SELECT completed\r\n",
                m.messages.len(),
                m.uidvalidity
            ));
        } else if upper.starts_with("UID FETCH") {
            let parts: Vec<&str> = rest.splitn(4, ' ').collect();
            let set = parts[2];
            let query = parts[3].to_ascii_uppercase();
            let selected: Vec<(usize, u32, Vec<u8>)> = {
                let m = mb.lock().expect("lock");
                select_uids(&m, set)
            };
            let mut bytes: Vec<u8> = Vec::new();
            for (seq, uid, raw) in selected {
                if query.contains("BODY.PEEK[HEADER]") {
                    let end = find_header_end(&raw);
                    let hdr = &raw[..end];
                    bytes.extend(
                        format!(
                            "* {seq} FETCH (UID {uid} BODY[HEADER] {{{}}}\r\n",
                            hdr.len()
                        )
                        .as_bytes(),
                    );
                    bytes.extend(hdr);
                    bytes.extend(b")\r\n");
                } else if query.contains("BODY.PEEK[]") {
                    bytes.extend(
                        format!("* {seq} FETCH (UID {uid} BODY[] {{{}}}\r\n", raw.len()).as_bytes(),
                    );
                    bytes.extend(&raw);
                    bytes.extend(b")\r\n");
                } else {
                    bytes.extend(
                        format!(
                            "* {seq} FETCH (UID {uid} FLAGS (\\Seen) INTERNALDATE \"01-Nov-2026 10:00:00 +0000\" RFC822.SIZE {})\r\n",
                            raw.len()
                        )
                        .as_bytes(),
                    );
                }
            }
            bytes.extend(format!("{tag} OK FETCH completed\r\n").as_bytes());
            w.write_all(&bytes).await.expect("write");
            continue;
        } else if upper.starts_with("IDLE") {
            w.write_all(b"+ idling\r\n").await.expect("write");
            let push = mb.lock().expect("lock").push_on_idle;
            if push {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let n = {
                    let mut m = mb.lock().expect("lock");
                    let uid = m.messages.iter().map(|(u, _)| *u).max().unwrap_or(0) + 1;
                    m.messages.push((uid, msg("pushed")));
                    m.messages.len()
                };
                w.write_all(format!("* {n} EXISTS\r\n").as_bytes())
                    .await
                    .expect("write");
            }
            // Wait for DONE.
            match lines.next_line().await {
                Ok(Some(l)) if l.eq_ignore_ascii_case("DONE") => {
                    out.push_str(&format!("{tag} OK IDLE terminated\r\n"));
                }
                _ => return,
            }
        } else if upper.starts_with("NOOP") {
            out.push_str(&format!("{tag} OK NOOP\r\n"));
        } else if upper.starts_with("LOGOUT") {
            w.write_all(format!("* BYE bye\r\n{tag} OK LOGOUT\r\n").as_bytes())
                .await
                .expect("write");
            return;
        } else {
            out.push_str(&format!("{tag} BAD unknown command\r\n"));
        }
        w.write_all(out.as_bytes()).await.expect("write");
    }
}

/// Resolve a UID set like `5:*` or `1,2,3`, with RFC `N:*` semantics.
fn select_uids(m: &Mailbox, set: &str) -> Vec<(usize, u32, Vec<u8>)> {
    let mut with_seq = m
        .messages
        .iter()
        .enumerate()
        .map(|(i, (u, raw))| (i + 1, *u, raw.clone()));
    if let Some(start) = set.strip_suffix(":*") {
        let start: u32 = start.parse().expect("num");
        let hits: Vec<_> = with_seq.clone().filter(|(_, u, _)| *u >= start).collect();
        if hits.is_empty() {
            // `N:*` with N > max UID still matches the highest message.
            return with_seq.next_back().into_iter().collect();
        }
        return hits;
    }
    let wanted: Vec<u32> = set.split(',').map(|s| s.parse().expect("num")).collect();
    with_seq.filter(|(_, u, _)| wanted.contains(u)).collect()
}

fn find_header_end(raw: &[u8]) -> usize {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |p| p + 4)
}

async fn connect(mb: &Shared, password: &str) -> Result<ImapConnection<DuplexStream>, MailError> {
    let (client, server) = tokio::io::duplex(1 << 20);
    tokio::spawn(serve(server, Arc::clone(mb)));
    ImapConnection::login(
        client,
        true,
        "user",
        &SecretString::from(password.to_owned()),
    )
    .await
}

fn mailbox(n: u32) -> Shared {
    Arc::new(Mutex::new(Mailbox {
        uidvalidity: 7,
        messages: (1..=n).map(|u| (u * 10, msg(&format!("m{u}")))).collect(),
        push_on_idle: false,
    }))
}

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
    assert!(all.iter().all(|m| m.flags.seen && !m.headers_only));
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
