//! Turn fetched bytes into what the store and the OTP engine need.

use postmoth_core::model::Account;
use postmoth_mail::FetchedMessage;
use postmoth_mime::{AttachmentRisk, NormalizedMessage, ParseOptions, parse};
use postmoth_otp::SenderAuth;
use postmoth_store::{NewAttachment, NewMessage};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Parse one message. `None` when it cannot be parsed at all; the caller
/// skips it (and still advances its UID cursor).
#[must_use]
pub fn build(
    account: &Account,
    fetched: &FetchedMessage,
    now_unix: i64,
) -> Option<(NewMessage, NormalizedMessage)> {
    let opts = ParseOptions {
        trusted_authserv_ids: account.trusted_authserv_ids.clone(),
        ..ParseOptions::default()
    };
    let norm = parse(&fetched.raw, &opts).ok()?;
    let received = fetched.internal_date.unwrap_or(now_unix);
    let full = !fetched.headers_only;
    let new = NewMessage {
        account_id: account.id,
        internet_message_id: norm.message_id.clone(),
        thread_id: None,
        subject: norm.subject.clone(),
        from: norm.from.clone(),
        recipients: norm.to.iter().chain(&norm.cc).cloned().collect(),
        date: norm.date.unwrap_or(received),
        received_at: received,
        snippet: norm.snippet.clone(),
        flags: fetched.flags,
        body_plain: full.then(|| norm.text.clone()),
        body_html_sanitized: if full {
            norm.html.as_ref().map(|h| h.html.clone())
        } else {
            None
        },
        blocked_remote: norm
            .html
            .as_ref()
            .map_or(0, |h| u32::try_from(h.blocked_remote).unwrap_or(u32::MAX)),
        is_bulk: norm.is_bulk,
        attachments: norm
            .attachments
            .iter()
            .map(|a| NewAttachment {
                part_index: a.part_index,
                filename: a.filename.clone(),
                mime_type: a.mime_type.clone(),
                size: a.size,
                content_id: a.content_id.clone(),
                is_inline: a.is_inline,
                is_executable: a.risk == AttachmentRisk::Executable,
            })
            .collect(),
    };
    Some((new, norm))
}

/// Sender authentication for OTP trust, from the provider's own
/// `Authentication-Results` (already filtered by authserv-id).
#[must_use]
pub fn sender_auth(norm: &NormalizedMessage) -> SenderAuth {
    match (&norm.auth, norm.from_domain()) {
        (Some(a), Some(domain)) => {
            let v = a.verdict(&domain);
            SenderAuth::Results {
                dmarc_pass: v.dmarc_pass,
                dkim_pass_domains: v.dkim_pass_domains,
            }
        }
        _ => SenderAuth::Unknown,
    }
}

#[must_use]
pub fn unix_to_system(t: i64) -> SystemTime {
    match u64::try_from(t) {
        Ok(s) => UNIX_EPOCH + Duration::from_secs(s),
        Err(_) => UNIX_EPOCH,
    }
}
