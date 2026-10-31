//! HTML sanitization policy for the message viewer (spec §7.4).
//!
//! Defense in depth: the GTK viewer also runs with JavaScript disabled and
//! a network policy that refuses remote loads. This layer makes sure the
//! stored HTML is already inert.

use ammonia::{Builder, UrlRelative};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Whether remote resources (images, CSS `url()`) may stay in the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RemoteContent {
    /// Default: strip remote references and count them.
    #[default]
    Block,
    /// The user allowed remote content for this message or sender.
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedHtml {
    pub html: String,
    /// How many remote references were removed (drives the
    /// "Load remote images" banner).
    pub blocked_remote: usize,
}

/// CSS fragments that are never allowed in a `style` attribute.
const DANGEROUS_CSS: &[&str] = &[
    "expression",
    "javascript:",
    "vbscript:",
    "@import",
    "behavior",
    "-moz-binding",
    "</",
];

/// Image MIME types allowed in `data:` URIs. SVG is excluded (it can carry
/// script and external references).
const DATA_IMAGE_TYPES: &[&str] = &[
    "data:image/png",
    "data:image/jpeg",
    "data:image/jpg",
    "data:image/gif",
    "data:image/webp",
];

#[must_use]
pub fn sanitize_html(html: &str, remote: RemoteContent) -> SanitizedHtml {
    let blocked = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&blocked);

    let mut b = Builder::default();
    b.add_tags([
        "font", "center", "span", "div", "section", "header", "footer",
    ])
    .add_generic_attributes([
        "style", "align", "valign", "width", "height", "bgcolor", "dir", "color",
    ])
    .add_tag_attributes("table", ["border", "cellpadding", "cellspacing"])
    .add_tag_attributes("td", ["colspan", "rowspan", "nowrap"])
    .add_tag_attributes("th", ["colspan", "rowspan", "nowrap"])
    .add_tag_attributes("font", ["face", "size"])
    .url_schemes(HashSet::from(["http", "https", "mailto", "cid", "data"]))
    .url_relative(UrlRelative::Deny)
    .link_rel(Some("noopener noreferrer nofollow"))
    .strip_comments(true)
    .attribute_filter(move |element, attribute, value| {
        filter_attribute(element, attribute, value, remote, &counter)
    });

    let html = b.clean(html).to_string();
    SanitizedHtml {
        html,
        blocked_remote: blocked.load(Ordering::Relaxed),
    }
}

fn filter_attribute<'u>(
    element: &str,
    attribute: &str,
    value: &'u str,
    remote: RemoteContent,
    blocked: &AtomicUsize,
) -> Option<Cow<'u, str>> {
    let lower = value.trim().to_ascii_lowercase();
    match attribute {
        "style" => {
            if DANGEROUS_CSS.iter().any(|d| lower.contains(d)) {
                return None;
            }
            if lower.contains("url(") {
                // Any url() in inline CSS may fetch a remote resource.
                if remote == RemoteContent::Block {
                    blocked.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
            Some(Cow::Borrowed(value))
        }
        "src" | "href" if lower.starts_with("data:") => {
            // data: only for raster images in <img src>.
            (element == "img"
                && attribute == "src"
                && DATA_IMAGE_TYPES.iter().any(|t| lower.starts_with(t)))
            .then_some(Cow::Borrowed(value))
        }
        "src" => {
            if lower.starts_with("cid:") {
                return Some(Cow::Borrowed(value));
            }
            if remote == RemoteContent::Block {
                blocked.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            Some(Cow::Borrowed(value))
        }
        "href" if lower.starts_with("cid:") => None,
        _ => Some(Cow::Borrowed(value)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(html: &str) -> SanitizedHtml {
        sanitize_html(html, RemoteContent::Block)
    }

    #[test]
    fn removes_scripts_and_handlers() {
        let s = block(
            r#"<p onclick="evil()">hi</p><script>alert(1)</script><img src=x onerror=alert(1)>"#,
        );
        assert!(!s.html.contains("script"));
        assert!(!s.html.contains("onclick"));
        assert!(!s.html.contains("onerror"));
        assert!(s.html.contains("<p>hi</p>"));
    }

    #[test]
    fn removes_active_content() {
        let s = block(
            r#"<form action="https://evil"><input name=pw></form><iframe src="https://x"></iframe><object data=x></object><embed src=x><svg><script>1</script></svg><meta http-equiv="refresh" content="0;url=https://evil"><base href="https://evil/"><link rel=stylesheet href=https://x>"#,
        );
        for bad in [
            "<form", "<input", "<iframe", "<object", "<embed", "<svg", "<meta", "<base", "<link",
        ] {
            assert!(!s.html.contains(bad), "{bad} survived: {}", s.html);
        }
    }

    #[test]
    fn javascript_urls_removed() {
        let s = block(r#"<a href="javascript:alert(1)">x</a><a href=" JaVaScRiPt:alert(1)">y</a>"#);
        assert!(!s.html.to_ascii_lowercase().contains("javascript"));
    }

    #[test]
    fn remote_images_blocked_and_counted() {
        let s = block(
            r#"<img src="https://tracker.example/p.gif"><img src="http://x/y.png"><img src="cid:logo@x">"#,
        );
        assert_eq!(s.blocked_remote, 2);
        assert!(!s.html.contains("tracker"));
        assert!(s.html.contains("cid:logo@x"));
    }

    #[test]
    fn remote_images_allowed_when_opted_in() {
        let s = sanitize_html(
            r#"<img src="https://img.example/a.png">"#,
            RemoteContent::Allow,
        );
        assert_eq!(s.blocked_remote, 0);
        assert!(s.html.contains("https://img.example/a.png"));
    }

    #[test]
    fn css_urls_and_expressions() {
        let s = block(
            r#"<div style="background:url(https://t.example/p)">a</div><p style="width:expression(alert(1))">b</p><p style="color:red">c</p>"#,
        );
        assert_eq!(s.blocked_remote, 1);
        assert!(!s.html.contains("url("));
        assert!(!s.html.contains("expression"));
        assert!(s.html.contains(r#"style="color:red""#));
    }

    #[test]
    fn style_blocks_are_dropped() {
        let s = block("<style>@import url(https://x);</style><p>ok</p>");
        assert!(!s.html.contains("@import"));
        assert!(s.html.contains("<p>ok</p>"));
    }

    #[test]
    fn links_get_safe_rel_and_relative_urls_dropped() {
        let s = block(r#"<a href="https://example.com">a</a><a href="/relative">b</a>"#);
        assert!(s.html.contains(r#"rel="noopener noreferrer nofollow""#));
        assert!(!s.html.contains("/relative"));
    }

    #[test]
    fn data_uris() {
        let s = block(
            r#"<img src="data:image/png;base64,AAAA"><img src="data:image/svg+xml;base64,AAAA"><a href="data:text/html,hi">x</a>"#,
        );
        assert!(s.html.contains("data:image/png"));
        assert!(!s.html.contains("svg"));
        assert!(!s.html.contains("text/html"));
    }

    #[test]
    fn keeps_basic_email_layout() {
        let s = block(
            r#"<table border="0" cellpadding="4"><tr><td colspan="2" align="center"><font face="Arial">Hi</font></td></tr></table>"#,
        );
        assert!(s.html.contains("cellpadding"));
        assert!(s.html.contains("colspan"));
        assert!(s.html.contains("<font"));
    }
}
