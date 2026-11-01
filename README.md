# postmoth
Your mail, right at home on Linux.

> **Status: pre-alpha (M0, OTP feasibility).** Not ready for real mail yet.
> See [`spec.md`](spec.md) for the product and engineering specification.

## Layout

| Path | What |
|---|---|
| `crates/postmoth-core` | IDs, models, stable error codes |
| `crates/postmoth-ipc` | Browser protocol v1, control API types, framing |
| `crates/postmoth-mime` | Safe MIME parsing and HTML sanitization |
| `crates/postmoth-otp` | OTP detection, domain trust, volatile candidate cache |
| `crates/postmoth-store` | SQLite cache, migrations, FTS5 |
| `crates/postmoth-mail` | IMAP over TLS, sync planning, IDLE |
| `crates/postmoth-platform` | XDG paths, Secret Service |
| `apps/daemon` | `postmoth-daemon` (systemd user service) |
| `apps/cli` | `postmothctl` |
| `apps/native-host` | `postmoth-native-host` (Chromium native messaging relay) |
| `extensions/chromium` | MV3 browser extension (TypeScript) |
| `tests/e2e` | Browser end-to-end test: GreenMail → daemon → host → extension |

## Development

```sh
cargo test --workspace
cargo run -p postmoth-daemon            # needs a session bus and a Secret Service
cargo run -p postmothctl -- status
cargo run -p postmothctl -- add-account --address you@example.org --imap-host imap.example.org
cargo run -p postmothctl -- trust @example.com https://login.example.com
```

The daemon logs to stderr (`POSTMOTH_LOG=debug` for more). It never logs
one-time codes, passwords or message bodies; a test enforces this at TRACE.

Browser bridge (dev): `scripts/dev-native-host.sh install` registers the debug
host for Chrome, Chromium and Brave; see `packaging/native-messaging/`.

Integration tests against a real IMAPS server: `scripts/greenmail.sh test`.
Full browser end-to-end: `tests/e2e/run.sh` (Docker + Playwright Chromium).

To run as a user service, copy `packaging/systemd/postmoth-daemon.service`
to `~/.config/systemd/user/` (adjust `ExecStart`) and
`systemctl --user enable --now postmoth-daemon`.
