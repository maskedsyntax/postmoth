//! Run the real binary the way Chromium does, against a fake daemon.

use postmoth_ipc::framing::{read_frame, read_json, write_frame};
use serde_json::{Value, json};
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;

const DEV_ORIGIN: &str = "chrome-extension://nnbgdhodaoggiiakpcmnlkgalgkoecbk/";

/// What the fake daemon does with each request it receives.
#[derive(Clone, Copy)]
enum Daemon {
    Echo,
    WrongId,
}

/// Start a fake daemon under `<rt>/postmoth/browser.sock`; returns a
/// channel of the raw requests it saw.
fn fake_daemon(rt: &Path, mode: Daemon) -> mpsc::Receiver<Value> {
    std::fs::create_dir_all(rt.join("postmoth")).expect("mkdir");
    let listener = UnixListener::bind(rt.join("postmoth/browser.sock")).expect("bind");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut s) = conn else { return };
            while let Ok(Some(frame)) = read_frame(&mut s) {
                let req: Value = serde_json::from_slice(&frame).expect("json");
                let id = match mode {
                    Daemon::Echo => req["request_id"].clone(),
                    Daemon::WrongId => json!("someone-else"),
                };
                let _ = tx.send(req);
                let resp = json!({"v": 1, "request_id": id, "status": "ok",
                                  "daemon_version": "test", "paused": false});
                write_frame(&mut s, &serde_json::to_vec(&resp).expect("ser")).expect("write");
            }
        }
    });
    rx
}

/// Feed raw stdin bytes to the host; return (exit code, response frames).
fn run_host(rt: &Path, origin: &str, stdin: &[u8]) -> (i32, Vec<Value>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_postmoth-native-host"))
        .arg(origin)
        .env("XDG_RUNTIME_DIR", rt)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin)
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    let mut cur = out.stdout.as_slice();
    let mut frames = Vec::new();
    while let Some(v) = read_json::<_, Value>(&mut cur).expect("frame") {
        frames.push(v);
    }
    (out.status.code().unwrap_or(-1), frames)
}

fn frame(v: &Value) -> Vec<u8> {
    let mut b = Vec::new();
    write_frame(&mut b, &serde_json::to_vec(v).expect("ser")).expect("frame");
    b
}

#[test]
fn unpinned_caller_gets_nothing() {
    let rt = tempfile::tempdir().expect("tmp");
    let seen = fake_daemon(rt.path(), Daemon::Echo);
    let req = frame(&json!({"v":1,"request_id":"a","op":"status"}));
    for origin in [
        "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
        "",
        "https://evil.example",
    ] {
        let (code, frames) = run_host(rt.path(), origin, &req);
        assert_eq!(code, 2, "{origin}");
        assert!(frames.is_empty(), "no stdout for {origin}");
    }
    assert!(seen.try_recv().is_err(), "daemon never contacted");
}

#[test]
fn relays_valid_requests_canonically() {
    let rt = tempfile::tempdir().expect("tmp");
    let seen = fake_daemon(rt.path(), Daemon::Echo);
    let mut input = frame(&json!({"v":1,"request_id":"a1","op":"status"}));
    input.extend(frame(&json!({"op":"find_suggestion","tab_id":3,"v":1,
        "request_id":"a2","top_origin":"https://login.example.com"})));
    let (code, frames) = run_host(rt.path(), DEV_ORIGIN, &input);
    assert_eq!(code, 0);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["request_id"], "a1");
    assert_eq!(frames[0]["status"], "ok");
    assert_eq!(frames[1]["request_id"], "a2");
    let r1 = seen.recv().expect("req");
    assert_eq!(r1, json!({"v":1,"request_id":"a1","op":"status"}));
    let r2 = seen.recv().expect("req");
    assert_eq!(r2["top_origin"], "https://login.example.com");
    assert_eq!(r2["tab_id"], 3);
}

#[test]
fn bad_requests_are_answered_locally() {
    let rt = tempfile::tempdir().expect("tmp");
    let seen = fake_daemon(rt.path(), Daemon::Echo);
    let mut input = Vec::new();
    for v in [
        json!({"v":1,"request_id":"b1","op":"list_codes"}),
        json!({"v":1,"request_id":"b2","op":"status","extra":true}),
        json!({"v":9,"request_id":"b3","op":"status"}),
        json!({"v":1,"request_id":"b4","op":"find_suggestion","top_origin":"https://x.test","tab_id":-1}),
    ] {
        input.extend(frame(&v));
    }
    input.extend({
        let mut b = Vec::new();
        write_frame(&mut b, b"{not json").expect("frame");
        b
    });
    let (code, frames) = run_host(rt.path(), DEV_ORIGIN, &input);
    assert_eq!(code, 0);
    let codes: Vec<&str> = frames
        .iter()
        .map(|f| f["code"].as_str().unwrap_or("?"))
        .collect();
    assert_eq!(
        codes,
        [
            "bad_request",
            "bad_request",
            "version_unsupported",
            "bad_request",
            "bad_request"
        ]
    );
    assert!(
        seen.try_recv().is_err(),
        "nothing invalid reaches the daemon"
    );
}

#[test]
fn daemon_down_and_bad_daemon_replies() {
    let rt = tempfile::tempdir().expect("tmp");
    let req = frame(&json!({"v":1,"request_id":"c1","op":"status"}));
    let (_, frames) = run_host(rt.path(), DEV_ORIGIN, &req);
    assert_eq!(frames[0]["code"], "daemon_unavailable");
    assert_eq!(frames[0]["request_id"], "c1");

    let _seen = fake_daemon(rt.path(), Daemon::WrongId);
    let (_, frames) = run_host(rt.path(), DEV_ORIGIN, &req);
    assert_eq!(
        frames[0]["code"], "internal",
        "mismatched id is not relayed"
    );
}

#[test]
fn oversize_frame_ends_session() {
    let rt = tempfile::tempdir().expect("tmp");
    let _seen = fake_daemon(rt.path(), Daemon::Echo);
    let mut input = (1u32 << 30).to_ne_bytes().to_vec();
    input.extend(frame(&json!({"v":1,"request_id":"d1","op":"status"})));
    let (code, frames) = run_host(rt.path(), DEV_ORIGIN, &input);
    assert_eq!(code, 0);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["code"], "bad_request");
}
