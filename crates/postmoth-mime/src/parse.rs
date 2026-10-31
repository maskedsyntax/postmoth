//! Raw message → [`NormalizedMessage`].

use crate::attach::{AttachmentMeta, classify, sanitize_filename};
use crate::auth::{self, AuthResults};
use crate::sanitize::{RemoteContent, SanitizedHtml, sanitize_html};
use mail_parser::{AddressList, HeaderName, MessageParser, PartKind};
use postmoth_core::model::Mailbox;

/// Resource limits for untrusted input.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Raw messages larger than this are rejected outright.
    pub max_message_bytes: usize,
    /// Plain-text body is truncated to this many bytes.
    pub max_text_bytes: usize,
    /// HTML is truncated to this many bytes before sanitizing.
    pub max_html_bytes: usize,
    pub max_parts: usize,
    pub max_depth: usize,
    pub max_attachments: usize,
    pub max_recipients: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message_bytes: 64 * 1024 * 1024,
            max_text_bytes: 1024 * 1024,
            max_html_bytes: 4 * 1024 * 1024,
            max_parts: 1000,
            max_depth: 16,
            max_attachments: 256,
            max_recipients: 1000,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParseOptions {
    pub limits: Limits,
    pub remote_content: RemoteContent,
    /// `authserv-id`s whose `Authentication-Results` we believe (the
    /// account's own provider). Empty means: trust none.
    pub trusted_authserv_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MimeError {
    #[error("message exceeds size limit")]
    TooLarge,
    #[error("message could not be parsed")]
    Unparseable,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NormalizedMessage {
    /// RFC 5322 `Message-ID` without angle brackets.
    pub message_id: Option<String>,
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub subject: Option<String>,
    pub from: Option<Mailbox>,
    pub sender: Option<Mailbox>,
    pub reply_to: Vec<Mailbox>,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    /// Unix seconds from the `Date` header, if valid.
    pub date: Option<i64>,
    /// Decoded plain text: the text/plain body, or text rendered from
    /// HTML when the message is HTML-only.
    pub text: String,
    pub html: Option<SanitizedHtml>,
    pub snippet: String,
    pub attachments: Vec<AttachmentMeta>,
    /// Mailing list / bulk mail (`List-Id`, `List-Unsubscribe`,
    /// `Precedence: bulk|list|junk`).
    pub is_bulk: bool,
    /// Results from the trusted, topmost `Authentication-Results`.
    pub auth: Option<AuthResults>,
    /// Some content was cut by limits.
    pub truncated: bool,
}

impl NormalizedMessage {
    /// Bare lowercase domain of the `From` address.
    #[must_use]
    pub fn from_domain(&self) -> Option<String> {
        self.from
            .as_ref()
            .and_then(|m| m.address.rsplit_once('@'))
            .map(|(_, d)| d.to_ascii_lowercase())
    }
}

const SNIPPET_CHARS: usize = 200;

pub fn parse(raw: &[u8], opts: &ParseOptions) -> Result<NormalizedMessage, MimeError> {
    let limits = &opts.limits;
    if raw.len() > limits.max_message_bytes {
        return Err(MimeError::TooLarge);
    }
    let parser = MessageParser::new()
        .max_parts(limits.max_parts)
        .max_depth(limits.max_depth);
    let msg = parser.parse(raw).ok_or(MimeError::Unparseable)?;
    let mut out = NormalizedMessage {
        message_id: msg.message_id().map(str::to_owned),
        in_reply_to: text_list(msg.in_reply_to()),
        references: text_list(msg.references()),
        subject: msg.subject().map(str::to_owned),
        from: msg.from().and_then(|l| l.first()).and_then(to_mailbox),
        sender: msg
            .headers()
            .get(HeaderName::Sender)
            .and_then(|h| h.value().as_address())
            .and_then(|l| l.first())
            .and_then(to_mailbox),
        reply_to: mailboxes(msg.reply_to(), limits.max_recipients),
        to: mailboxes(msg.to(), limits.max_recipients),
        cc: mailboxes(msg.cc(), limits.max_recipients),
        date: msg
            .date()
            .filter(mail_parser::DateTime::is_valid)
            .map(|d| d.to_timestamp()),
        ..NormalizedMessage::default()
    };

    // Bulk detection.
    let headers = msg.headers();
    let precedence_bulk = headers
        .get(HeaderName::Precedence)
        .and_then(|h| h.value().as_text().map(str::to_ascii_lowercase))
        .is_some_and(|p| matches!(p.trim(), "bulk" | "list" | "junk"));
    out.is_bulk = precedence_bulk
        || headers.get(HeaderName::ListId).is_some()
        || headers.get(HeaderName::ListUnsubscribe).is_some();

    // Authentication-Results: topmost only, trusted ids only.
    let ar_values: Vec<String> = headers
        .iter()
        .filter(|h| h.raw_name().eq_ignore_ascii_case("authentication-results"))
        .map(|h| String::from_utf8_lossy(h.raw_value()).into_owned())
        .collect();
    let ar_refs: Vec<&str> = ar_values.iter().map(String::as_str).collect();
    out.auth = auth::trusted_results(&ar_refs, &opts.trusted_authserv_ids);

    // Bodies. Prefer genuine text/plain parts for `text`; fall back to text
    // rendered from HTML.
    let mut text = String::new();
    let mut html = String::new();
    for part in msg.text_body() {
        if matches!(part.kind(), PartKind::Text)
            && let Some(t) = part.text()
        {
            push_capped(&mut text, &t, limits.max_text_bytes, &mut out.truncated);
        }
    }
    for part in msg.html_body() {
        if matches!(part.kind(), PartKind::Html)
            && let Some(h) = part.html_utf8()
        {
            push_capped(&mut html, &h, limits.max_html_bytes, &mut out.truncated);
        }
    }
    if !html.is_empty() {
        out.html = Some(sanitize_html(&html, opts.remote_content));
    }
    if text.trim().is_empty()
        && let Some(h) = &out.html
    {
        text.clear();
        let rendered = html_to_plain(&h.html);
        push_capped(
            &mut text,
            &rendered,
            limits.max_text_bytes,
            &mut out.truncated,
        );
    }
    out.snippet = make_snippet(&text);
    out.text = text;

    // Attachments.
    for (n, part) in msg.attachments().enumerate() {
        if n >= limits.max_attachments {
            out.truncated = true;
            break;
        }
        let mime_type = part
            .content_type()
            .map(|ct| match ct.subtype() {
                Some(st) => format!("{}/{}", ct.ctype(), st),
                None => ct.ctype().to_owned(),
            })
            .unwrap_or_else(|| "application/octet-stream".to_owned())
            .to_ascii_lowercase();
        let fallback = if part.is_message() {
            "message.eml"
        } else {
            "attachment"
        };
        let filename = sanitize_filename(part.attachment_name(), fallback);
        let risk = classify(&filename, &mime_type);
        out.attachments.push(AttachmentMeta {
            part_index: part.id(),
            filename,
            size: part.decoded_len() as u64,
            content_id: part.content_id().map(str::to_owned),
            is_inline: part.is_inline(),
            mime_type,
            risk,
        });
    }
    Ok(out)
}

/// Block-level closing tags after which a line break is forced. The
/// converter otherwise glues adjacent table cells ("550129Copyright"),
/// which destroys word boundaries the OTP detector relies on.
const BLOCK_CLOSERS: &[&str] = &[
    "</td>",
    "</th>",
    "</tr>",
    "</p>",
    "</div>",
    "</li>",
    "</table>",
    "</h1>",
    "</h2>",
    "</h3>",
    "</h4>",
    "</h5>",
    "</h6>",
    "</blockquote>",
    "</section>",
    "</header>",
    "</footer>",
    "</center>",
];

/// Render sanitized HTML (lowercase tags, as ammonia emits) to text.
fn html_to_plain(html: &str) -> String {
    let mut s = html.to_owned();
    for tag in BLOCK_CLOSERS {
        s = s.replace(tag, &format!("{tag}<br>"));
    }
    mail_parser::html_to_text(&s)
}

fn to_mailbox(m: mail_parser::Mailbox<'_>) -> Option<Mailbox> {
    let address = m.address()?.trim();
    if address.is_empty() {
        return None;
    }
    Some(Mailbox {
        name: m.name().map(str::to_owned).filter(|n| !n.trim().is_empty()),
        address: address.to_owned(),
    })
}

fn mailboxes(list: Option<AddressList<'_>>, max: usize) -> Vec<Mailbox> {
    list.map(|l| l.mailboxes().filter_map(to_mailbox).take(max).collect())
        .unwrap_or_default()
}

fn text_list(list: Option<mail_parser::TextList<'_>>) -> Vec<String> {
    list.map(|l| l.iter().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn push_capped(buf: &mut String, s: &str, max: usize, truncated: &mut bool) {
    if !buf.is_empty() {
        buf.push('\n');
    }
    let room = max.saturating_sub(buf.len());
    if s.len() <= room {
        buf.push_str(s);
        return;
    }
    *truncated = true;
    let mut end = room;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    buf.push_str(&s[..end]);
}

fn make_snippet(text: &str) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut last_space = true;
    for line in text.lines() {
        // Skip quoted lines in previews.
        if line.trim_start().starts_with('>') {
            continue;
        }
        for c in line.chars().chain(std::iter::once(' ')) {
            if count >= SNIPPET_CHARS {
                return out.trim_end().to_owned();
            }
            if c.is_whitespace() {
                if !last_space {
                    out.push(' ');
                    count += 1;
                }
                last_space = true;
            } else if !c.is_control() {
                out.push(c);
                count += 1;
                last_space = false;
            }
        }
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::AttachmentRisk;

    fn p(raw: &str) -> NormalizedMessage {
        parse(raw.as_bytes(), &ParseOptions::default()).expect("parse")
    }

    #[test]
    fn simple_plain() {
        let m = p(
            "From: \"Alice\" <alice@example.com>\r\nTo: bob@example.org\r\nSubject: Hi\r\nDate: Sun, 1 Nov 2026 10:00:00 +0000\r\nMessage-ID: <abc@example.com>\r\n\r\nHello Bob,\r\nhow are you?\r\n",
        );
        assert_eq!(m.subject.as_deref(), Some("Hi"));
        assert_eq!(
            m.from.as_ref().map(|f| f.address.as_str()),
            Some("alice@example.com")
        );
        assert_eq!(
            m.from.as_ref().and_then(|f| f.name.as_deref()),
            Some("Alice")
        );
        assert_eq!(m.to.len(), 1);
        assert_eq!(m.message_id.as_deref(), Some("abc@example.com"));
        assert_eq!(m.date, Some(1_793_527_200));
        assert!(m.text.contains("how are you?"));
        assert_eq!(m.snippet, "Hello Bob, how are you?");
        assert!(m.html.is_none());
        assert!(!m.is_bulk);
    }

    #[test]
    fn too_large_rejected() {
        let opts = ParseOptions {
            limits: Limits {
                max_message_bytes: 10,
                ..Limits::default()
            },
            ..ParseOptions::default()
        };
        assert_eq!(
            parse(b"Subject: way too long\r\n\r\nbody", &opts),
            Err(MimeError::TooLarge)
        );
    }

    #[test]
    fn encoded_word_subject_and_charset() {
        let m = p(
            "Subject: =?UTF-8?B?w4lsw6hWZQ==?=\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=E9\r\n",
        );
        assert_eq!(m.subject.as_deref(), Some("ÉlèVe"));
        assert!(m.text.contains("Café"));
    }

    #[test]
    fn html_only_gets_text_and_sanitized_html() {
        let m = p(
            "Subject: x\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><p>Your code is <b>123456</b></p><script>steal()</script><img src=\"https://t.example/x.gif\"></body></html>",
        );
        let h = m.html.as_ref().expect("html");
        assert!(!h.html.contains("script"));
        assert_eq!(h.blocked_remote, 1);
        assert!(m.text.contains("123456"), "text: {:?}", m.text);
        assert!(!m.text.contains("steal"));
    }

    #[test]
    fn multipart_alternative_prefers_plain() {
        let raw = "Subject: alt\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nplain version\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>html version</p>\r\n--b--\r\n";
        let m = p(raw);
        assert!(m.text.contains("plain version"));
        assert!(!m.text.contains("html version"));
        assert!(
            m.html
                .as_ref()
                .is_some_and(|h| h.html.contains("html version"))
        );
    }

    #[test]
    fn attachments_metadata() {
        let raw = "Subject: att\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n--b\r\nContent-Type: application/pdf; name=\"../../r.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"../../r.pdf.exe\"\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8gV29ybGQ=\r\n--b--\r\n";
        let m = p(raw);
        assert_eq!(m.attachments.len(), 1);
        let a = &m.attachments[0];
        assert_eq!(a.filename, "r.pdf.exe");
        assert_eq!(a.mime_type, "application/pdf");
        assert_eq!(a.size, 11);
        assert_eq!(a.risk, AttachmentRisk::Executable);
    }

    #[test]
    fn bulk_detection() {
        assert!(p("List-Unsubscribe: <mailto:u@x>\r\nSubject: n\r\n\r\nx").is_bulk);
        assert!(p("List-Id: <news.example.com>\r\nSubject: n\r\n\r\nx").is_bulk);
        assert!(p("Precedence: bulk\r\nSubject: n\r\n\r\nx").is_bulk);
        assert!(!p("Precedence: first-class\r\nSubject: n\r\n\r\nx").is_bulk);
    }

    #[test]
    fn auth_results_trusted_only_when_configured() {
        let raw = "Authentication-Results: mx.google.com; dmarc=pass header.from=example.com\r\nFrom: a@example.com\r\nSubject: s\r\n\r\nb";
        assert!(p(raw).auth.is_none(), "no trusted ids configured");
        let opts = ParseOptions {
            trusted_authserv_ids: vec!["mx.google.com".into()],
            ..ParseOptions::default()
        };
        let m = parse(raw.as_bytes(), &opts).expect("parse");
        let v = m
            .auth
            .as_ref()
            .expect("auth")
            .verdict(&m.from_domain().expect("domain"));
        assert_eq!(v.dmarc_pass, Some(true));
    }

    #[test]
    fn threading_headers() {
        let m = p("In-Reply-To: <a@x>\r\nReferences: <r1@x> <a@x>\r\nSubject: Re: t\r\n\r\nb");
        assert_eq!(m.in_reply_to, vec!["a@x"]);
        assert_eq!(m.references, vec!["r1@x", "a@x"]);
    }

    #[test]
    fn text_is_capped() {
        let opts = ParseOptions {
            limits: Limits {
                max_text_bytes: 16,
                ..Limits::default()
            },
            ..ParseOptions::default()
        };
        let body = "é".repeat(100);
        let raw = format!("Subject: s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}");
        let m = parse(raw.as_bytes(), &opts).expect("parse");
        assert!(m.text.len() <= 16);
        assert!(m.truncated);
    }

    #[test]
    fn table_cells_do_not_glue() {
        let t = html_to_plain(
            "<table><tr><td>123456</td><td>Copyright</td></tr></table><p>a</p><p>b</p>",
        );
        assert!(!t.contains("123456Copyright"), "{t:?}");
        assert!(!t.contains("ab"), "{t:?}");
    }

    #[test]
    fn snippet_skips_quotes_and_collapses_space() {
        assert_eq!(
            make_snippet("> quoted\nHello\n\n\tworld  !"),
            "Hello world !"
        );
    }

    #[test]
    fn garbage_never_panics() {
        // Deterministic xorshift "fuzz" over random and structured junk.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for len in [0usize, 1, 2, 17, 255, 4096] {
            for _ in 0..50 {
                let bytes: Vec<u8> = (0..len)
                    .map(|_| {
                        x ^= x << 13;
                        x ^= x >> 7;
                        x ^= x << 17;
                        (x & 0xff) as u8
                    })
                    .collect();
                let _ = parse(&bytes, &ParseOptions::default());
                let mut framed =
                    b"Content-Type: multipart/mixed; boundary=z\r\n\r\n--z\r\n".to_vec();
                framed.extend_from_slice(&bytes);
                let _ = parse(&framed, &ParseOptions::default());
            }
        }
    }
}
