//! Attachment metadata and filename hygiene (spec §7.4).

/// Coarse risk classification shown in the UI before opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentRisk {
    /// Documents, images, archives: still untrusted, opened only on request.
    Normal,
    /// Executable or launcher formats: never opened directly; save only,
    /// with a warning.
    Executable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMeta {
    /// Index among the message's MIME parts (stable for re-fetching).
    pub part_index: u32,
    /// Sanitized, safe-to-display, safe-to-save basename.
    pub filename: String,
    /// Declared MIME type (untrusted), lowercase.
    pub mime_type: String,
    /// Decoded size in bytes.
    pub size: u64,
    pub content_id: Option<String>,
    pub is_inline: bool,
    pub risk: AttachmentRisk,
}

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "appimage",
    "bat",
    "bin",
    "cmd",
    "com",
    "cpl",
    "deb",
    "desktop",
    "dll",
    "exe",
    "flatpakref",
    "hta",
    "jar",
    "js",
    "jse",
    "lnk",
    "msi",
    "msp",
    "pif",
    "ps1",
    "py",
    "rpm",
    "run",
    "scr",
    "sh",
    "snap",
    "so",
    "vbe",
    "vbs",
    "ws",
    "wsf",
    "elf",
    "pl",
    "rb",
    "command",
    "action",
    "apk",
    "iso",
    "img",
];

const EXECUTABLE_MIME: &[&str] = &[
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-elf",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-sh",
    "application/x-shellscript",
    "application/x-desktop",
    "application/vnd.microsoft.portable-executable",
    "application/java-archive",
    "application/x-debian-package",
    "application/x-rpm",
    "application/vnd.appimage",
    "text/x-shellscript",
    "application/javascript",
];

const MAX_FILENAME_BYTES: usize = 200;

/// Produce a safe basename: no directories, no control or reserved
/// characters, no leading dots, bounded length (extension preserved).
#[must_use]
pub fn sanitize_filename(name: Option<&str>, fallback: &str) -> String {
    let raw = name.unwrap_or("");
    // Basename only: drop anything up to the last path separator.
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
        // Bidi overrides can disguise extensions ("gpj.exe" shown as "exe.jpg").
        .filter(|c| !matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'))
        .collect();
    let trimmed = cleaned
        .trim()
        .trim_start_matches(['.', ' '])
        .trim_end_matches(['.', ' ']);
    if trimmed.is_empty() {
        return fallback.to_owned();
    }
    truncate_keeping_extension(trimmed, MAX_FILENAME_BYTES)
}

fn truncate_keeping_extension(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_owned();
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() && e.len() <= 16 => (s, Some(e)),
        _ => (name, None),
    };
    let budget = max - ext.map_or(0, |e| e.len() + 1);
    let mut end = budget.min(stem.len());
    while !stem.is_char_boundary(end) {
        end -= 1;
    }
    match ext {
        Some(e) => format!("{}.{e}", &stem[..end]),
        None => stem[..end].to_owned(),
    }
}

/// Classify by **both** extension and declared type; either can be a lie,
/// so either one flagging executable is enough.
#[must_use]
pub fn classify(filename: &str, mime_type: &str) -> AttachmentRisk {
    let lower = filename.to_ascii_lowercase();
    // Check every dotted segment: "invoice.pdf.exe" and "x.tar.sh".
    let ext_hit = lower
        .rsplit('.')
        .next()
        .is_some_and(|ext| EXECUTABLE_EXTENSIONS.contains(&ext) && lower.contains('.'));
    let mime_hit = EXECUTABLE_MIME.contains(&mime_type);
    if ext_hit || mime_hit {
        AttachmentRisk::Executable
    } else {
        AttachmentRisk::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_paths_and_traversal() {
        assert_eq!(sanitize_filename(Some("../../etc/passwd"), "a"), "passwd");
        assert_eq!(
            sanitize_filename(Some("C:\\Users\\x\\evil.exe"), "a"),
            "evil.exe"
        );
        assert_eq!(sanitize_filename(Some(".bashrc"), "a"), "bashrc");
        assert_eq!(sanitize_filename(Some(".."), "attachment"), "attachment");
        assert_eq!(sanitize_filename(None, "attachment"), "attachment");
        assert_eq!(sanitize_filename(Some("a\0b\nc.txt"), "x"), "abc.txt");
    }

    #[test]
    fn strips_bidi_overrides() {
        let tricky = "invoice\u{202E}fdp.exe";
        let s = sanitize_filename(Some(tricky), "x");
        assert_eq!(s, "invoicefdp.exe");
        assert_eq!(classify(&s, "application/pdf"), AttachmentRisk::Executable);
    }

    #[test]
    fn long_names_keep_extension() {
        let long = format!("{}.pdf", "a".repeat(500));
        let s = sanitize_filename(Some(&long), "x");
        assert!(s.len() <= MAX_FILENAME_BYTES);
        assert!(s.ends_with(".pdf"));
        let uni = format!("{}.pdf", "é".repeat(300));
        assert!(sanitize_filename(Some(&uni), "x").ends_with(".pdf"));
    }

    #[test]
    fn classification() {
        assert_eq!(
            classify("report.pdf", "application/pdf"),
            AttachmentRisk::Normal
        );
        assert_eq!(
            classify("report.pdf.exe", "application/pdf"),
            AttachmentRisk::Executable
        );
        assert_eq!(
            classify("photo.jpg", "application/x-executable"),
            AttachmentRisk::Executable
        );
        assert_eq!(
            classify("install.SH", "text/plain"),
            AttachmentRisk::Executable
        );
        assert_eq!(
            classify("app.desktop", "text/plain"),
            AttachmentRisk::Executable
        );
        assert_eq!(classify("README", "text/plain"), AttachmentRisk::Normal);
    }
}
