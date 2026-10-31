//! One-time-code detection from plain text (spec §8.2).
//!
//! The detector is conservative by design: it returns `High` confidence only
//! when exactly one plausible code sits next to explicit OTP wording, and
//! nothing on ambiguity. Thresholds are driven by the corpus in
//! `tests/fixtures/otp`.
//!
//! Resource bounds: input is truncated to [`MAX_INPUT_BYTES`], and the
//! `regex` crate guarantees linear-time matching, so the cost is bounded by
//! input size.

use regex::Regex;
use secrecy::SecretString;
use std::sync::LazyLock;

/// Max bytes of message text inspected.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
/// How far (in bytes) before a token we look for OTP wording.
const CONTEXT_BEFORE: usize = 160;
/// How far after a token we look for OTP wording.
const CONTEXT_AFTER: usize = 80;
/// How far before a token we look for non-OTP number wording.
const NEGATIVE_BEFORE: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug)]
pub struct Detection {
    pub code: SecretString,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Default)]
pub struct DetectInput<'a> {
    pub subject: &'a str,
    /// Decoded plain text (or text rendered from sanitized HTML).
    pub text: &'a str,
    /// `List-Unsubscribe` or `Precedence: bulk/list` present.
    pub is_bulk: bool,
}

static OTP_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)(",
        r"verification\s+code|verify|security\s+code|sign[\s-]?in\s+code|log[\s-]?in\s+code|",
        r"one[\s-]time\s+(?:pass(?:word|code)|code|pin)|\botp\b|pass\s?code|",
        r"authentication\s+code|confirmation\s+code|access\s+code|2fa|two[\s-]factor|",
        r"your\s+code|code\s+is|code:|",
        // es / pt
        r"c[oó]digo\s+de\s+(?:verificaci[oó]n|verifica[cç][aã]o|seguridad|seguran[cç]a|acceso|acesso)|",
        // fr
        r"code\s+de\s+(?:v[ée]rification|s[ée]curit[ée]|connexion|confirmation)|",
        // de
        r"best[äa]tigungscode|verifizierungscode|sicherheitscode|anmeldecode|einmalcode|",
        // it / nl / pl
        r"codice\s+di\s+(?:verifica|sicurezza|accesso)|verificatiecode|beveiligingscode|",
        r"kod\s+(?:weryfikacyjny|bezpiecze[nń]stwa)|",
        // ru / ja / zh / ko
        r"код\s+подтверждения|проверочный\s+код|認証コード|確認コード|验证码|驗證碼|인증\s*코드|인증\s*번호",
        r")"
    ))
    .expect("static regex")
});

static NEGATIVE_CONTEXT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(order|invoice|receipt|tracking|shipment|account\s+(?:no|number|ending)|reference|\bref\b|ticket|case\s+(?:no|number|#)|zip|postal|phone|call\s+us|tel\b|fax|booking|confirmation\s+(?:no|number|#)|transaction\s+id|\bid\b\s*[:#]|customer\s+(?:no|number|id)|ending\s+in|serial|\$|€|£|¥|usd|eur)",
    )
    .expect("static regex")
});

/// Candidate tokens: grouped digits (`123 456`, `123-456`), digit runs of
/// 4–8, or 6–8 uppercase alphanumerics. Order matters: grouped first.
static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{3,4}[ \-]\d{3,4})\b|\b(\d{4,8})\b|\b([A-Z0-9]{6,8})\b")
        .expect("static regex")
});

static FORWARD_SUBJECT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*(fwd?|tr|wg|rv|enc)\s*:").expect("static regex"));

static QUOTE_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?im)^(?:on\s.+\swrote:\s*$|-{2,}\s*(?:original\s+message|forwarded\s+message)\s*-{2,}|from:\s.+$\n^(?:sent|date):)",
    )
    .expect("static regex")
});

struct Scored {
    code: String,
    score: i32,
}

/// Detect a single one-time code. Returns `None` when nothing plausible or
/// ambiguous; callers should act only on [`Confidence::High`].
#[must_use]
pub fn detect(input: &DetectInput<'_>) -> Option<Detection> {
    if FORWARD_SUBJECT.is_match(input.subject) {
        return None;
    }
    let text = strip_quoted(truncate(input.text, MAX_INPUT_BYTES));
    let subject_has_context = OTP_CONTEXT.is_match(input.subject);

    let mut scored: Vec<Scored> = Vec::new();
    for caps in TOKEN.captures_iter(&text) {
        let Some(m) = caps.get(0) else { continue };
        let (start, end) = (m.start(), m.end());
        let raw = m.as_str();
        let is_grouped = caps.get(1).is_some();
        let is_alnum = caps.get(3).is_some();

        if is_alnum && !is_mixed_alnum(raw) {
            // Pure-letter words (`IMPORTANT`) or pure-digit runs already
            // covered by the digit branch.
            continue;
        }
        if looks_embedded(&text, start, end) {
            continue;
        }

        let code: String = raw.chars().filter(char::is_ascii_alphanumeric).collect();
        if !(4..=8).contains(&code.len()) {
            continue;
        }

        let mut score = 0;
        let before = window_before(&text, start, CONTEXT_BEFORE);
        let after = window_after(&text, end, CONTEXT_AFTER);
        let near_before = window_before(&text, start, NEGATIVE_BEFORE);
        if OTP_CONTEXT.is_match(before) {
            score += 3;
            if OTP_CONTEXT.is_match(near_before) {
                // Wording immediately precedes the token ("code is 123456").
                score += 1;
            }
        } else if OTP_CONTEXT.is_match(after) {
            score += 2;
        }
        if subject_has_context {
            score += 1;
        }
        if stands_alone(&text, start, end) {
            score += 1;
        }
        if NEGATIVE_CONTEXT.is_match(near_before) {
            score -= 4;
        }
        if !is_alnum && !is_grouped && looks_like_year(&code) {
            score -= 3;
        }
        if is_grouped && raw.contains('-') && code.len() == 7 {
            // 555-1234 style: phone-shaped.
            score -= 2;
        }
        scored.push(Scored { code, score });
    }

    let mut plausible: Vec<&Scored> = scored.iter().filter(|s| s.score >= 3).collect();
    plausible.sort_by_key(|s| std::cmp::Reverse(s.score));
    let best = plausible.first()?;
    // Same code repeated (e.g., in subject line and body) is fine; two
    // different plausible codes is ambiguous.
    if plausible.iter().any(|s| s.code != best.code) {
        return None;
    }

    let mut confidence = if best.score >= 4 {
        Confidence::High
    } else {
        Confidence::Medium
    };
    if input.is_bulk && confidence == Confidence::High {
        confidence = Confidence::Medium;
    }
    Some(Detection {
        code: SecretString::from(best.code.clone()),
        confidence,
    })
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Drop `>`-quoted lines and everything after a reply/forward header.
fn strip_quoted(text: &str) -> String {
    let cut = QUOTE_HEADER.find(text).map_or(text.len(), |m| m.start());
    text[..cut]
        .lines()
        .filter(|l| !l.trim_start().starts_with('>'))
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_mixed_alnum(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_digit()) && s.bytes().any(|b| b.is_ascii_uppercase())
}

fn looks_like_year(code: &str) -> bool {
    code.len() == 4 && (code.starts_with("19") || code.starts_with("20"))
}

/// Reject tokens that are part of a larger structure: dates, times,
/// decimals, phone numbers, URLs, identifiers, prices.
fn looks_embedded(text: &str, start: usize, end: usize) -> bool {
    let prev = text[..start].chars().next_back();
    let prev2 = text[..start].chars().rev().nth(1);
    let next = text[end..].chars().next();
    let next2 = text[end..].chars().nth(1);

    let joiner = |c: Option<char>| matches!(c, Some('/' | '.' | ':' | ',' | '-' | '_' | '='));
    let digit = |c: Option<char>| c.is_some_and(|c| c.is_ascii_digit());
    let alnum = |c: Option<char>| c.is_some_and(char::is_alphanumeric);

    // 12/05/2026, 10:30, 1.234, 4-8-15 — joiner flanked by more digits/letters.
    if joiner(prev) && (digit(prev2) || alnum(prev2)) {
        return true;
    }
    if joiner(next) && (digit(next2) || alnum(next2)) {
        return true;
    }
    // +1 555..., #1234, $1234, @user1234, ?id=1234, /path/1234
    if matches!(
        prev,
        Some('+' | '#' | '$' | '€' | '£' | '¥' | '@' | '&' | '?' | '/' | '\\')
    ) {
        return true;
    }
    // (555) 123...
    if prev == Some(' ') && prev2 == Some(')') {
        return true;
    }
    // 1234% or 1234€
    if matches!(next, Some('%' | '€' | '$' | '£')) {
        return true;
    }
    false
}

/// Is the token alone on its line (common OTP layout)?
fn stands_alone(text: &str, start: usize, end: usize) -> bool {
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = text[end..].find('\n').map_or(text.len(), |i| end + i);
    text[line_start..start].trim().is_empty() && text[end..line_end].trim().is_empty()
}

fn window_before(text: &str, start: usize, n: usize) -> &str {
    let mut from = start.saturating_sub(n);
    while !text.is_char_boundary(from) {
        from += 1;
    }
    &text[from..start]
}

fn window_after(text: &str, end: usize, n: usize) -> &str {
    let mut to = (end + n).min(text.len());
    while !text.is_char_boundary(to) {
        to -= 1;
    }
    &text[end..to]
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    fn run(subject: &str, text: &str) -> Option<(String, Confidence)> {
        detect(&DetectInput {
            subject,
            text,
            is_bulk: false,
        })
        .map(|d| (d.code.expose_secret().to_owned(), d.confidence))
    }

    fn high(subject: &str, text: &str) -> Option<String> {
        run(subject, text).and_then(|(c, conf)| (conf == Confidence::High).then_some(c))
    }

    #[test]
    fn simple_numeric() {
        assert_eq!(
            high(
                "Your sign-in code",
                "Your verification code is 482913. It expires in 10 minutes."
            )
            .as_deref(),
            Some("482913")
        );
    }

    #[test]
    fn code_on_own_line() {
        let body = "Hi,\n\nUse the following one-time password to log in:\n\n    739204\n\nIf you didn't request this, ignore this email.";
        assert_eq!(high("Login attempt", body).as_deref(), Some("739204"));
    }

    #[test]
    fn grouped_digits_are_joined() {
        assert_eq!(
            high("", "Your security code: 123 456").as_deref(),
            Some("123456")
        );
        assert_eq!(
            high("", "Verification code: 381-552").as_deref(),
            Some("381552")
        );
    }

    #[test]
    fn alphanumeric_code() {
        assert_eq!(
            high("Verify your email", "Your code is: K7Q2XP").as_deref(),
            Some("K7Q2XP")
        );
    }

    #[test]
    fn multilingual() {
        assert_eq!(
            high("", "Tu código de verificación es 551204").as_deref(),
            Some("551204")
        );
        assert_eq!(
            high("", "Votre code de vérification : 908172").as_deref(),
            Some("908172")
        );
        assert_eq!(
            high("", "Ihr Bestätigungscode lautet 640215").as_deref(),
            Some("640215")
        );
        assert_eq!(high("", "您的验证码是 773019").as_deref(), Some("773019"));
        assert_eq!(
            high("", "Ваш код подтверждения: 118834").as_deref(),
            Some("118834")
        );
    }

    #[test]
    fn no_context_no_code() {
        assert_eq!(run("Lunch?", "Let's meet at room 4021 tomorrow."), None);
    }

    #[test]
    fn order_numbers_rejected() {
        assert_eq!(
            high(
                "Your order",
                "Thanks! Your order number 58213904 has shipped. Use code 4411 for 10% off"
            ),
            None
        );
        assert_eq!(run("Receipt", "Order #882134 total $1234"), None);
    }

    #[test]
    fn dates_times_prices_phones_rejected() {
        assert_eq!(run("", "Your code is valid until 12/05/2026 10:30"), None);
        assert_eq!(
            run(
                "",
                "Your verification code was requested from +1 5551234567"
            ),
            None
        );
        assert_eq!(run("", "Verification code fee: $1500"), None);
        assert_eq!(
            run("", "Verification code sent. Call (555) 1234567 for help."),
            None
        );
    }

    #[test]
    fn year_alone_is_not_a_code() {
        assert_eq!(
            high("", "Your verification code policy changed in 2026."),
            None
        );
    }

    #[test]
    fn two_different_codes_are_ambiguous() {
        assert_eq!(
            run(
                "",
                "Your verification code is 123456. Your backup code is 654321."
            ),
            None
        );
    }

    #[test]
    fn same_code_twice_is_fine() {
        assert_eq!(
            high("Your code is 482913", "Your verification code is 482913.").as_deref(),
            Some("482913")
        );
    }

    #[test]
    fn quoted_reply_ignored() {
        let body = "Thanks, that worked!\n\nOn Mon, 1 Nov 2026, Bob <b@example.com> wrote:\n> Your verification code is 482913\n";
        assert_eq!(run("Re: help", body), None);
        assert_eq!(run("", "> Your verification code is 482913"), None);
    }

    #[test]
    fn forwarded_ignored() {
        assert_eq!(
            run("Fwd: Your sign-in code", "Your verification code is 482913"),
            None
        );
    }

    #[test]
    fn bulk_mail_capped_at_medium() {
        let d = detect(&DetectInput {
            subject: "Your code",
            text: "Your verification code is 482913",
            is_bulk: true,
        })
        .expect("detected");
        assert_eq!(d.confidence, Confidence::Medium);
    }

    #[test]
    fn urls_and_ids_rejected() {
        assert_eq!(
            run("", "Verify at https://example.com/verify?token=482913"),
            None
        );
        assert_eq!(run("", "Verify your account id=482913"), None);
    }

    #[test]
    fn plain_words_not_alnum_codes() {
        assert_eq!(run("", "VERIFY YOUR ACCOUNT NOW"), None);
    }

    #[test]
    fn huge_input_is_bounded() {
        let mut s = "x ".repeat(MAX_INPUT_BYTES);
        s.push_str("Your verification code is 482913");
        assert_eq!(run("", &s), None, "content past the cap is not inspected");
    }

    #[test]
    fn unicode_boundaries_safe() {
        let s = "é".repeat(MAX_INPUT_BYTES);
        let _ = run("", &s);
        let _ = run("", "認証コード 123456 認証コード");
    }
}
