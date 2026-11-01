//! A scripted in-process IMAP server for tests (feature `test-util`).
//!
//! Implements just enough of RFC 3501 + IDLE for this crate's client:
//! greeting, LOGIN, CAPABILITY, SELECT, UID FETCH (meta / BODY[] /
//! BODY[HEADER]), IDLE/DONE, NOOP, LOGOUT. It reproduces the `N:*` quirk
//! (always returns the highest message) so filtering is exercised.
#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use crate::{ImapConnection, MailError};
use secrecy::SecretString;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::Notify;

pub const PASSWORD: &str = "correct horse";
/// 01-Nov-2026 10:00:00 +0000.
pub const DEFAULT_INTERNAL_DATE: i64 = 1_793_527_200;

#[derive(Debug)]
pub struct FakeMailbox {
    pub uidvalidity: u32,
    /// (uid, raw message)
    pub messages: Vec<(u32, Vec<u8>)>,
    /// Inject one generated message shortly after each IDLE starts.
    pub push_on_idle: bool,
    /// INTERNALDATE reported for every message (Unix seconds).
    pub internal_date: i64,
    /// Advertise IDLE.
    pub idle_capable: bool,
    notify: Arc<Notify>,
}

impl Default for FakeMailbox {
    fn default() -> Self {
        Self {
            uidvalidity: 7,
            messages: Vec::new(),
            push_on_idle: false,
            internal_date: DEFAULT_INTERNAL_DATE,
            idle_capable: true,
            notify: Arc::new(Notify::new()),
        }
    }
}

pub type Shared = Arc<Mutex<FakeMailbox>>;

#[must_use]
pub fn msg(subject: &str) -> Vec<u8> {
    format!("From: a@example.com\r\nSubject: {subject}\r\n\r\nHello {subject}\r\n").into_bytes()
}

/// Mailbox with `n` simple messages at UIDs 10, 20, ….
#[must_use]
pub fn mailbox(n: u32) -> Shared {
    Arc::new(Mutex::new(FakeMailbox {
        messages: (1..=n).map(|u| (u * 10, msg(&format!("m{u}")))).collect(),
        ..FakeMailbox::default()
    }))
}

/// Deliver a message; an IDLEing client is notified. Returns its UID.
pub fn deliver(mb: &Shared, raw: Vec<u8>) -> u32 {
    let mut m = mb.lock().expect("lock");
    let uid = m.messages.iter().map(|(u, _)| *u).max().unwrap_or(0) + 1;
    m.messages.push((uid, raw));
    m.notify.notify_one();
    uid
}

/// Format Unix seconds as an IMAP date-time (`01-Nov-2026 10:00:00 +0000`).
#[must_use]
pub fn imap_date(unix: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    let month = MONTHS[usize::try_from(m - 1).expect("month")];
    format!(
        "{d:02}-{month}-{y} {:02}:{:02}:{:02} +0000",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Serve one client connection.
pub async fn serve(stream: DuplexStream, mb: Shared) {
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r).lines();
    let idle_cap = if mb.lock().expect("lock").idle_capable {
        " IDLE"
    } else {
        ""
    };
    w.write_all(format!("* OK [CAPABILITY IMAP4rev1{idle_cap}] fake ready\r\n").as_bytes())
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
            out.push_str(&format!("* CAPABILITY IMAP4rev1{idle_cap} UIDPLUS\r\n"));
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
            let (selected, date) = {
                let m = mb.lock().expect("lock");
                (select_uids(&m, set), imap_date(m.internal_date))
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
                            "* {seq} FETCH (UID {uid} FLAGS () INTERNALDATE \"{date}\" RFC822.SIZE {})\r\n",
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
            let (push, notify) = {
                let m = mb.lock().expect("lock");
                (m.push_on_idle, Arc::clone(&m.notify))
            };
            if push {
                tokio::time::sleep(Duration::from_millis(50)).await;
                deliver(&mb, msg("pushed"));
            }
            loop {
                tokio::select! {
                    l = lines.next_line() => match l {
                        Ok(Some(l)) if l.eq_ignore_ascii_case("DONE") => {
                            out.push_str(&format!("{tag} OK IDLE terminated\r\n"));
                            break;
                        }
                        _ => return,
                    },
                    () = notify.notified() => {
                        let n = mb.lock().expect("lock").messages.len();
                        w.write_all(format!("* {n} EXISTS\r\n").as_bytes())
                            .await
                            .expect("write");
                    }
                }
            }
        } else if upper.starts_with("NOOP") {
            out.push_str(&format!("{tag} OK NOOP\r\n"));
        } else if upper.starts_with("LOGOUT") {
            let _ = w
                .write_all(format!("* BYE bye\r\n{tag} OK LOGOUT\r\n").as_bytes())
                .await;
            return;
        } else {
            out.push_str(&format!("{tag} BAD unknown command\r\n"));
        }
        if w.write_all(out.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// Resolve a UID set like `5:*` or `1,2,3`, with RFC `N:*` semantics.
fn select_uids(m: &FakeMailbox, set: &str) -> Vec<(usize, u32, Vec<u8>)> {
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

/// Start a server task for `mb` and log in with `password`.
pub async fn connect(
    mb: &Shared,
    password: &str,
) -> Result<ImapConnection<DuplexStream>, MailError> {
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

#[cfg(test)]
mod tests {
    #[test]
    fn imap_date_format() {
        assert_eq!(
            super::imap_date(super::DEFAULT_INTERNAL_DATE),
            "01-Nov-2026 10:00:00 +0000"
        );
        assert_eq!(super::imap_date(0), "01-Jan-1970 00:00:00 +0000");
        assert_eq!(super::imap_date(951_782_400), "29-Feb-2000 00:00:00 +0000");
    }
}
