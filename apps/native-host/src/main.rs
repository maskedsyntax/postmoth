//! Entry point. Chromium runs `postmoth-native-host chrome-extension://<id>/`.

use postmoth_native_host::{SocketLink, caller_allowed, run, socket_path};
use std::process::ExitCode;

fn main() -> ExitCode {
    let origin = std::env::args().nth(1).unwrap_or_default();
    if !caller_allowed(&origin) {
        // Not a protocol message: stderr only. Do not echo the caller.
        eprintln!("postmoth-native-host: caller is not a pinned Postmoth extension");
        return ExitCode::from(2);
    }
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok();
    let mut link = SocketLink::new(socket_path(runtime.as_deref()));
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    match run(&mut stdin, &mut stdout, &mut link) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("postmoth-native-host: {}", e.kind());
            ExitCode::FAILURE
        }
    }
}
