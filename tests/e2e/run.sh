#!/usr/bin/env bash
# Full end-to-end OTP test (spec §14 E2E 3–5):
#   GreenMail (SMTP + IMAPS)  ->  postmoth-daemon  ->  native host  ->
#   extension in Playwright's Chromium  ->  HTTPS test site on :443.
#
# Requires docker and `npx playwright install chromium` in
# extensions/chromium. Touches nothing in your real browser profile; the
# daemon does register on your session bus and keyring while running.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK="$ROOT/target/e2e"
RT="/run/user/$(id -u)/pm-e2e"   # short: socket paths are limited to 108 bytes
SITE=postmoth-e2e-site
NGINX=nginx:1.30.6-alpine
DAEMON_PID=

cleanup() {
  [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null || true
  docker rm -f "$SITE" >/dev/null 2>&1 || true
  "$ROOT/scripts/greenmail.sh" stop >/dev/null
  rm -rf "$RT"
}
trap cleanup EXIT

rm -rf "$WORK" && mkdir -p "$WORK/certs" "$WORK/profile/NativeMessagingHosts"
mkdir -p -m 700 "$RT"

echo "== build"
cargo build -q -p postmoth-daemon -p postmothctl -p postmoth-native-host --manifest-path "$ROOT/Cargo.toml"
(cd "$ROOT/extensions/chromium" && node build.mjs --dev >/dev/null)
BIN="$ROOT/target/debug"

echo "== mail server"
"$ROOT/scripts/greenmail.sh" start
eval "$("$ROOT/scripts/greenmail.sh" env)"

echo "== test site"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=postmoth e2e" \
  -addext "subjectAltName=DNS:login.postmoth.test,DNS:evil.postmoth.test,DNS:login.postmoth.test.evil.test" \
  -keyout "$WORK/certs/site.key" -out "$WORK/certs/site.pem" 2>/dev/null
chmod 0644 "$WORK/certs/site.key"
docker rm -f "$SITE" >/dev/null 2>&1 || true
docker run -d --name "$SITE" -p 127.0.0.1:443:443 \
  -v "$ROOT/tests/e2e/site:/site:ro" -v "$WORK/certs:/certs:ro" \
  -v "$ROOT/tests/e2e/nginx.conf:/etc/nginx/conf.d/default.conf:ro" "$NGINX" >/dev/null

echo "== daemon"
export XDG_DATA_HOME="$WORK/data" XDG_CONFIG_HOME="$WORK/config" XDG_RUNTIME_DIR="$RT"
POSTMOTH_LOG=info "$BIN/postmoth-daemon" --extra-ca "$POSTMOTH_TEST_IMAP_CA" 2>"$WORK/daemon.log" &
DAEMON_PID=$!
for _ in $(seq 1 50); do [ -S "$RT/postmoth/browser.sock" ] && break; sleep 0.1; done
CTL="$BIN/postmothctl"
echo "$POSTMOTH_TEST_IMAP_PASS" | "$CTL" add-account --address "$POSTMOTH_TEST_IMAP_USER" \
  --imap-host localhost --imap-port "$POSTMOTH_TEST_IMAP_PORT" --password-stdin
"$CTL" trust @example.com https://login.postmoth.test

# Native host manifest inside the throwaway browser profile only.
sed -e "s|@HOST_PATH@|$BIN/postmoth-native-host|" \
    -e "s|@ALLOWED_ORIGINS@|\"chrome-extension://nnbgdhodaoggiiakpcmnlkgalgkoecbk/\"|" \
    "$ROOT/packaging/native-messaging/dev.postmoth.native_host.json.in" \
    > "$WORK/profile/NativeMessagingHosts/dev.postmoth.native_host.json"

echo "== browser tests"
export E2E_PROFILE="$WORK/profile" E2E_EXTENSION="$ROOT/extensions/chromium/dist" E2E_CTL="$CTL"
(cd "$ROOT/extensions/chromium" && npx playwright test "$@")

echo "== redaction check"
if grep -E "482913|246810|551234|$POSTMOTH_TEST_IMAP_PASS" "$WORK/daemon.log"; then
  echo "secret material found in daemon log" >&2; exit 1
fi
echo "ok: no codes or passwords in daemon log"
