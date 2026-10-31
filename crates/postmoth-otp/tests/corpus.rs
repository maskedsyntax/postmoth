//! Runs every `tests/fixtures/otp/*.eml` through the real MIME parser and
//! the detector, and compares against the `.expect` sidecar:
//! `code=<value>` means a High-confidence detection of exactly that code;
//! `none` means no High-confidence detection.

use postmoth_mime::{ParseOptions, parse};
use postmoth_otp::{Confidence, DetectInput, detect};
use secrecy::ExposeSecret;
use std::fs;
use std::path::PathBuf;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/otp")
}

#[test]
fn otp_corpus() {
    let mut entries: Vec<_> = fs::read_dir(corpus_dir())
        .expect("corpus dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "eml"))
        .collect();
    entries.sort();
    assert!(entries.len() >= 10, "corpus unexpectedly small");

    let mut failures = Vec::new();
    for eml in &entries {
        let name = eml
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_owned();
        let raw = fs::read(eml).expect("read eml");
        let expect = fs::read_to_string(eml.with_extension("expect")).expect("sidecar");
        let expect = expect.trim();
        let msg = parse(&raw, &ParseOptions::default()).expect("parse fixture");
        let got = detect(&DetectInput {
            subject: msg.subject.as_deref().unwrap_or(""),
            text: &msg.text,
            is_bulk: msg.is_bulk,
        });
        let got = match got {
            Some(d) if d.confidence == Confidence::High => {
                format!("code={}", d.code.expose_secret())
            }
            _ => "none".to_owned(),
        };
        if got != expect {
            failures.push(format!(
                "{name}: expected {expect}, got {got}\n  text: {:?}",
                msg.text
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "corpus failures:\n{}",
        failures.join("\n")
    );
}
